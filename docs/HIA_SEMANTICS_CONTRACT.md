# HIA execution, resources and public-interface contract

This contract fixes the meaning of the **implemented standalone HIA profiles**.
It reconciles their verifier, interpreter, LLVM consumer and cooperative task
elaboration; it does not extend an accepted profile by documentation. The
starting source snapshot for this review is
`a32ad51250b905bb4729168f4d8f9328880b44db`.

The accompanying implementation change rejects an explicit public interface
that the native ABI cannot completely represent. It does not remove an integer,
resource, trap, effect or proof obligation to obtain acceptance.

## 1. One execution meaning, versioned consumers

`hepta.hia_program.verify_program` checks the actual operations and all control
flow edges. Immutable canonical Core bytes are the execution input. A public
`VerifiedProgram` constructor, producer digest, JSON receipt, model confidence,
NDU score or successful source compilation cannot bypass that check.

| Representation | Actual semantic path |
| --- | --- |
| Primitive HIA v1–v7 | Parse, check types/resources/effects, execute the checked operations |
| Composite v1 | Check nominal structure and elaborate to primitive v6, then check again |
| Composite v2 | Check nominal structure and elaborate to primitive v7, then check again |
| `hia-asm.v1` | Deterministically assemble primitive v6/v7 and use the same verifier |
| Supported Hepta/C/C++ sources | Execute their explicit, bounded source adapter and then independently admit the resulting Core |
| Legacy IR | Use the registered adapter with its required source/version identity; no schema guessing |

Retained composite bytes must re-elaborate to exactly the retained Core. Text
rendering and reassembly preserve canonical Core, including exports. Source
and Core identity are separate: preserving Core bytes does not by itself prove
that arbitrary C/C++ source was translated correctly. The source profiles in
`hia_routes.py` remain finite, and unsupported languages remain rejected.

The Python interpreter and direct LLVM backend consume the same Core. Native
target support, ABI support, finite runtime budgets and independent Rust shadow
profiles are additional restrictions. A registered opcode is not automatically
supported by every consumer. See [HIA_PROGRAM.md](HIA_PROGRAM.md) and the actual
registry in `hepta/hia_schema.py`.

## 2. Exact scalar and control-flow semantics

The standalone Core supports signed and unsigned **8, 16, 32 and 64 bit**
integers, `usize`/`isize` with **64 bit** width, `bool`, and `unit`. `unit` is
represented by JSON `null`; it is not an arbitrary integer. Python booleans are
not admitted as integer arguments. Floating-point values, wider integers, raw
pointers and foreign calls are outside this primitive profile. Broader types
accepted by a different source/reference backend do not widen standalone Core.

Each block is closed SSA: incoming values are explicit block parameters,
instructions execute in order, and an edge evaluates all of its arguments
before rebinding the destination parameters. Branches execute exactly one
successor. The first actual trapping instruction stops that execution; later
arithmetic, reads, writes and cleanup do not run.

For an integer width `w`, checked results must remain in the exact signed or
unsigned range. Wrapping results retain the low `w` bits; signed results then
interpret those bits in two's complement.

| Operation | Required result and trap behavior |
| --- | --- |
| `int.add/sub/mul.checked` | Mathematical operation, followed by exact result-range check; overflow traps |
| `int.add/sub/mul.wrap` | Mathematical operation modulo `2^w`; no overflow trap |
| `int.div.checked` | Truncation toward zero; zero divisor traps; signed minimum divided by `-1` traps |
| `int.rem.checked` | `a - trunc(a/b) * b`; the same zero-divisor and signed minimum/`-1` traps apply |
| `int.shl.checked` | Check `0 <= count < w`, then shift and retain low `w` bits; the value is not separately range checked |
| `int.shr.checked` | Same count check; arithmetic right shift for signed values, logical right shift for unsigned values |
| `int.neg.checked` | Negate mathematically, then range check; nonzero unsigned values therefore trap |
| Checked cast | Preserve the mathematical integer only if it fits the destination range |
| Wrapping cast | Reduce to the destination width and interpret destination signedness |
| Integer comparisons | Compare according to the declared signedness; Boolean comparison permits equality/inequality only |
| `select` | Select between already computed compatible scalar values; it does not defer either defining instruction |

In particular, "checked shift" checks the **count**, and signed remainder is
not Python's floor-modulo operation. Optimizers and source importers must retain
these distinctions. A source language with different overflow, exception,
evaluation-order or pointer rules requires an explicit admitted translation;
it cannot inherit these meanings merely by renaming operations.

## 3. Public interface and native ABI

An explicit `exports` list is a **complete public interface contract**. The
verifier requires unique existing scalar-signature functions. Owners, views
and nominal resource descriptors cannot cross this public boundary.

The interpreter accepts exactly typed scalar parameters and multiple scalar
results. The current native C wrappers accept integer/Boolean parameters and
zero or one scalar result; a `unit` result maps to C `void`. A `unit` parameter
and multiple results are outside that native wrapper profile. Their use by
internal functions is still supported where the Core permits it.

**When `exports` is explicit, every requested export must be representable by
the selected native ABI. Otherwise the entire native emission/build rejects
with `E_HIA_PROGRAM_ABI`, before the compiler is invoked or an artifact is
published.** Publishing just the compatible subset would silently change the
program's declared interface. This refusal applies to the existing x86-64,
AArch64 and RV64 target emitters; emission checks alone do not qualify execution
on the latter two targets.

For historical Core without `exports`, the existing native signature discovery
continues to expose its documented narrower subset and records the actual
exports. Callers requiring an exact interface should supply `exports`. An
unrequested internal function with an unsupported public signature need not be
rejected merely because it appears in the same module.

Target-specific sign/zero extension, calling convention and linker behavior
remain ABI obligations. This contract does not imply a universal C ABI or
preservation of C++ class, mangling or exception ABI.

## 4. Owner, loan, memory and effects

Owners are linear capabilities. A successful normal path must move, return or
drop each local owner exactly once, and end each local loan. A scalar public
return cannot retain owners or local loans. A return used to encode an ordinary
application error is still a normal return and has the same cleanup duties.

Byte buffers and v7 chains have distinct types. New byte storage is zero
initialized. A zero-length buffer is a real logical owner but makes no native
allocation request. A failed `buffer.try_new` yields an empty owner and `false`;
that empty owner must also be consumed. An oversized request outside the
64-bit object-size model is an allocation failure, while an evaluator's own
heap budget is a different outcome.

The capability checker records loan roots, parents and permissions. Shared
loans can coexist. An exclusive loan excludes other conflicting loans, and a
parent view is suspended while a child reborrow is active. An owner cannot be
moved, returned or dropped while borrowed. A call cannot duplicate an owner or
pass conflicting exclusive views of one root. Call-scoped loans cannot escape
as return values, and a callee cannot end its caller's loan.

Every CFG edge carries all live local resources, without duplication; joining
predecessors must agree on root/parent/permission identities. A scalar result
that happens to have the right numeric value cannot excuse invalid resource
flow. Bounds are checked before byte accesses and before any partial mutation
by a bounded copy, move, fill or swap. Cross-owner copy and same-owner
overlapping move have separate operations and obligations.

Effects are conservative upper bounds drawn from `alloc`, `read`, `write` and
`trap`. Call effects must be covered by the caller. `alloc` includes release as
well as acquisition; it is not a claim about total process RSS. These effects
do not supply general I/O, atomic, threading, real-time or device protocols.

Resource safety and source behavior remain separate obligations. For example,
two C++ translations may balance every allocation and release while changing
observable destructor order. The independent source/native lifecycle checks
must still reject the wrong behavior.

## 5. Return, trap, budget stop and cancellation are distinct

| Outcome | Core/VM meaning | Resource claim |
| --- | --- | --- |
| Normal return, including an error encoded as a value | `returned` with the actual result | Local owners/loans discharged; scalar public entry has no remaining live Core resources |
| Explicit or arithmetic/bounds/allocation trap | `HIAProgramTrap`, `trapped`, exact VM trap code | Report the state at interruption; no fabricated destructor cleanup |
| Evaluator step, heap or call-depth limit | `HIAProgramBudgetExceeded`, `budget_exceeded` | Analysis/runtime budget stop; neither an ordinary allocation failure nor a termination proof |
| Successful cooperative `task.cancel` | Synchronous state-consuming cancellation procedure returns and the task becomes cancelled | The checked cancellation procedure discharges its state; the cancelled task token still requires `task.close` |
| Cancellation procedure traps or exceeds a budget | The corresponding trap/budget outcome propagates | No `returned` result and no claim that cancellation cleanup completed |

Native semantic traps call `abort`; they are not recoverable C++ exceptions.
The process aborts before later operations. The current native ABI does not
return the VM's exact trap code, and the native program does not automatically
inherit the interpreter's step/heap/call-depth limits. External process limits
and isolation have their own evidence and cannot be relabeled as Core cleanup.

Stopped ledgers count the state at the stop. They do not claim that an OS process
leak is permanent, nor that OS reclamation performed language destructors. An
aborted computation's external effects cannot be undone by editing a ledger.

## 6. Supported cooperative task scope

Composite task declarations supply a concrete state, result, poll function and
cancellation function. Poll consumes one state and returns either pending state
or a completed result. Cancellation consumes one state and returns no value.
An additional empty owner token keeps even scalar-only tasks linear.

| Operation | State transition |
| --- | --- |
| Create | Initial state becomes pending (`0`) |
| Start | Pending becomes running (`1`) |
| Poll | A synchronous call while running; yields running or succeeded (`2`) |
| Cancel pending/running | Calls cancellation once; on successful return becomes cancelled (`3`) |
| Cancel cancelled/succeeded | Does not call cancellation again; completed result remains available |
| Join | Consumes a succeeded task and returns its result |
| Close | Consumes a cancelled task and its empty token |

Illegal state transitions trap. Pending/running cancellation is synchronous:
there is no concurrently executing worker to preempt. The implemented protocol
has no detached/background threads, general async runtime, I/O wakeups, shared
memory atomics or preemptive cancellation. A protocol check is therefore not a
data-race-freedom proof for an unimplemented concurrent runtime. Proposed
parallelism must first add a memory model, synchronization and cancellation
contract and their actual checked execution path.

## 7. Optimization and assurance boundary

An admitted transformation must retain the behavior of the specified profile:
values, actual first-trap behavior, ordered effects, ownership and the public
interface. The current scalar validator preserves CFG/call/resource skeletons
and proves the supported scalar segments. Guarded reductions additionally
prove entry/edge/check obligations and retain the complete checked fallback.
Later stages must bind the verified Core to the actual final native artifact.

The optimizer or NDU may propose an action; they do not issue safety or
deployment authority. SAT counterexamples, `unknown`, timeout, exhausted proof
budget, unsupported structure and identity drift continue to reject. A model's
expected speedup cannot waive a semantic obligation. Conversely, a valid
semantic proof does not show that proving, compiling or selecting the candidate
will recover its cost.

| Established mechanism | Remaining boundary |
| --- | --- |
| Executable Core type/ownership/effect checking | No machine-checked soundness theorem for the whole implementation |
| Finite interpreter/native differential observations | No proof for every input, target, operating system or foreign environment |
| Supported scalar/guarded SMT obligations | Trusted encoding and solver; no general heap/CFG/concurrency equivalence theorem |
| Canonical bytes and sealed artifact identity | Trusted verifier, backend, compiler/linker, loader, host, OS and hardware |
| Captured C/C++ profiles | No arbitrary C/C++ source refinement or universal binary compatibility |

Neither "memory safe" nor "no live resources at normal return" proves
termination, bounded response time, deadlock freedom, full functional
correctness, universally bounded memory consumption or cleanup after abort.
These distinctions are acceptance boundaries, not permissions to weaken the
existing checks.

## 8. Executable checks

`tests/test_hia_semantics_contract.py` adds the mixed-export counterexample,
whole-interface refusal before compilation/publication, supported native
exports, trapping/budget-limited cancellation and successful late cancellation.
The native controls compile and load real LLVM output and run the abort case in
a child with core dumps disabled. A missing Clang is reported as a skip and
must not count as native qualification.

```sh
CLANG=/absolute/path/to/clang-20 python -B -m unittest \
  tests.test_hia_semantics_contract \
  tests.test_hia_program \
  tests.test_hia_program_composite \
  tests.test_hia_program_llvm -v
```

The existing scalar tests exercise every admitted integer width, wrapping and
checked limits, signed division/remainder, shifts and evaluator budgets. The
composite/native tests cover owner flow, stored loans and ordinary cooperative
task outcomes. These tests retain the distinction between an executed finite
contract and an unproved whole-toolchain refinement claim.
