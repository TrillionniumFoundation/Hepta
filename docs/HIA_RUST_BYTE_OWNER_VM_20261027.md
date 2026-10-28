# Executed Rust byte-owner shadow: finite profile

This document records the byte-owner v3 and returned-loan v4 boundaries and
historical evidence. The same Machine has a separately identified
[v5 chain capability set](HIA_RUST_RETURNED_CHAINS_V8.md), including the
[owned-memory corpus](HIA_RUST_OWNED_MEMORY_VM_20261028.md) for source/nominal
lowering, actual observations and negative controls. Modules without chains
retain the v3/v4 profiles described below. Historical counts do not qualify
the expanded implementation or a later integrated revision.

The existing Rust scalar `Machine` now has an explicitly enabled, bounded byte
storage component. `--owned-run` executes a finite primitive HIA buffer/loan
profile after the existing `verify_owned` admission check. This does not change
Python Core authority, the production CLI or the native backend. The opt-in
v8 verifier crosscheck uses its own versioned receipt. `--scalar-run` still rejects resource
programs.

## Execution boundary

The input must be a primitive `hepta.hia.program.v1` through `v8` document.
The v3 execution profile for v1–v7 supports multiple functions/blocks, verified CFG
branches and loops, and internal scalar/owner/loan calls. The selected public
entry's parameters and return types must be scalars, including when no explicit
export list exists. Blocks use `jump`, `branch`, `ret` or `trap`.
The existing strict schema, ownership/loan rules, effect checks, explicit
exports policy, and scalar argument validation apply before execution.

The complete document is checked against the execution capability profile
before constructing the `Machine`. An unsupported operation after a possible
allocation failure is still rejected before any instruction executes.

| Supported resource operation | Runtime behavior |
| --- | --- |
| `buffer.new`, `buffer.try_new` | Zero-initialized bytes, bounded live heap, deterministic allocation-failure injection |
| `buffer.len` | Underlying byte length; no byte access through a suspended parent |
| `borrow.read`, `borrow.mut` | Internal loan handles with root and parent identity, including admitted reborrows |
| `loan.end` | Ends the local loan after its children have ended |
| `owner.move`, `owner.drop` | Consumes the old SSA name; move preserves storage identity; drop records explicit cleanup |
| `buffer.load`, `buffer.store` | Checked `usize` offset and `u8` value, with bounds traps |
| `buffer.fill`, `buffer.copy` (v2+) | Whole-buffer fill and checked distinct-owner prefix copy |
| `buffer.move_within` (v3+) | Checked overlap-safe byte movement within one mutable view |
| `buffer.swap` (v4+) | Both offsets checked before swapping bytes |
| `buffer.copy_range` (v5+) | Both source and destination extents checked before distinct-owner offset copy |
| `buffer.fill_range` (v6+) | Checked offset/count and exact `u8` fill value |

The existing scalar operation implementation and `Machine` are reused. Internal
calls may consume/return byte owners and borrow nonescaping views. Primitive
v8 additionally supports parameter-bound internal returned loans under the
separate v4 profile described in [HIA_RUST_RETURNED_LOANS_V8.md](HIA_RUST_RETURNED_LOANS_V8.md). Owning call
arguments are consumed before entering the callee. Read-only formal parameters
may alias one actual caller loan; shared reborrows permit those shared reads,
while mutable-child suspension, parent writes and early loan-end still reject.
Chain types/operations, resource **public** entry/return
types, and direct nominal/composite documents are outside this execution
profile. Primitive operations outside the profile produce
`E_HIA_RUST_UNSUPPORTED`. A direct nominal document fails the existing strict
primitive-schema check with `E_HIA_FORMAT`; no new schema fallback is installed.

Version admission still belongs to the existing verifier: an operation is
not accepted under a schema older than its introduction. v7 inherits the bulk
operations without authorizing chain execution. v8 requires independent
returned-loan contract validation before execution. Offset/count checks use subtraction before addition,
integer conversion or slicing. Zero extents accept exact-end offsets while
refusing offsets beyond the end, and never relax distinct-owner copying.

Overlap movement uses Rust's snapshot-equivalent `copy_within`. Distinct-owner
copies use fixed 4096-byte stack scratch, including when a range crosses
multiple chunks. The scratch is not a Hepta resource allocation and does not
add ledger events. This bounds that temporary buffer, not whole-process
memory. Bulk instructions retain Python's one-operation tick convention;
their CPU work still depends on the byte extent.

Resource handles cannot be supplied or returned through JSON. Runtime owner
and loan maps supplement the existing static admission check; they are not a
replacement verifier or a second source of language rules.

## Explicit invocation and report

```text
hia-core-shadow --owned-run FUNCTION JSON_ARGS
hia-core-shadow --owned-run FUNCTION JSON_ARGS MAX_STEPS MAX_HEAP_BYTES FAIL_AT|none
```

Both forms read the complete document from standard input. The shorter form
uses 100,000 steps, a 1 MiB live-byte heap, and no injected allocation failure.
The longer form requires all three policy arguments. The profile accepts
1–1,000,000 steps, 0–16 MiB of live byte storage, and either `none` or a positive
allocation-attempt number. A zero-byte owner is a logical owner that does not
call the allocator. Object sizes above the canonical signed 64-bit limit fail
before a heap or allocator attempt. The heap budget is checked before an
injected allocation failure.

Execution reports use the new schema
`hepta.hia.rust-byte-owner-execution.v1` and profile
`bounded-cfg-byte-owner-bulk-v3` for v1–v7, or
`bounded-cfg-byte-owner-loan-returns-v4` for v8. They include the source digest, entry function,
execution policy, status, steps, scalar values or error code, and the complete
resource ledger. The general-resource, production-admission, whole-language,
native-refinement, and ABI/hardware claims remain false.

The call-depth bound admits 32 simultaneously live frames, including the root,
and rejects the next frame before its entry tick or side effects. All frames
share the same heap, allocation-failure counter and resource ledger.

The ledger records allocations, frees, allocator attempts, owners created and
dropped, live owners/bytes, peak bytes, loans started and ended, and live local
loans. For v7 and v8, the canonical six chain counters are present and zero because no
chain opcode is admitted.

Successful returns require the explicit resource ledger to be clean. A trap
or exhausted budget reports the resources still live at that stop point,
matching Python Core. The shadow does not invent unwind drops. Rust eventually
reclaims its host containers when the execution function exits; that host
cleanup is not reported as an executed Hepta `owner.drop` or `loan.end`.

## Executed evidence

### CFG/call and bulk extension qualification

`tests/test_hia_rust_owned_cfg.py` runs the real Rust executable against the
canonical Python interpreter. Its finite corpus covers loop-carried owner/loan
identity, failure branches, owner replacement/recovery across calls, aliased
shared formals and reborrows, owner-returning recursion, every executed step cut,
and precise heap/call-budget stops. Unsupported hidden helpers, resource public
signatures, duplicated transfers and conflicting loan joins remain negative
controls. The original single-block differential corpus remains active.

`tests/test_hia_rust_bulk_vm.py` adds actual execution of each versioned bulk
operation, independent expected byte values, zero/end/overflow bounds, copies
across 4096-byte chunks, allocation failures and heap stops. Every bulk opcode
also executes through an internal borrowed helper with a mutable reborrow;
each executed step boundary is compared. A loop-carried view and its fallible
construction branch exercise composition with the existing CFG Machine.

`tools/qualify_hia_rust_owned_cfg.py --output REPORT.json` retains the actual
programs, complete paired VM reports, source before/after hashes, binary and
toolchain identity, and non-skipped test counts. A report qualifies its recorded
source inventory only. The historical counts below do not qualify this expanded
profile or establish production authority, native refinement or whole-language
soundness.

### Historical implementation before workspace recovery

The initial local implementation commit was
`44e586d728cb637f91c149e856db5d741ab7cc85`, based on
`ddac4e3de71794853ccef2d012a43eb40a97d39e`. Its earlier development run recorded
52 passing Rust tests, 45 passing Python tests and 124 full-ledger differential
observations. The original scratch logs and manifest were lost when the
workspace was reclaimed. Those counts describe that historical source only;
they are not retained execution evidence for a recovered or integrated SHA.

### Recovered implementation: fresh execution

The recovered implementation was actually rerun from clean commit
`79e5dbc8916a3e426e0bf97cfcc94216a5856de5` on 2026-10-27, from
13:53:52 UTC to 13:54:05 UTC. Rust 1.90.0
(`1159e78c4 2025-09-14`), Cargo 1.90.0
(`840b83a10 2025-07-30`) and `/usr/bin/python3` 3.12.3 executed these two
commands with `CARGO_NET_OFFLINE=true` and the external
`CARGO_TARGET_DIR=/workspace/scratch/d930f2b45e07/rust-recovery-target`:

```bash
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
/usr/bin/python3 -m unittest \
  tests.test_hia_rust_shadow tests.test_hia_rust_owned_shadow \
  tests.test_hia_rust_calls_shadow tests.test_hia_rust_chain_shadow \
  tests.test_hia_rust_scalar_vm tests.test_hia_rust_crosscheck \
  tests.test_hia_rust_crosscheck_cli tests.test_hia_rust_owned_vm -v
```

Results: **52 Rust tests passed; 45 Python tests passed; zero skipped tests**.
The tracked source was clean before and after execution; HEAD and every
recorded implementation/authority source hash remained unchanged. These are
scoped development results for the exact recovered commit above. They do not
qualify the later integrated source SHA or substitute for its 35-gate run.

The new dedicated Python module contributed 10 tests and **124 actual
Rust/Python full-ledger parity observations**. It builds the real binary using
Cargo's compiler-artifact executable path, verifies each positive document
with Python Core, executes both implementations, and compares every resource
field and its exact key inventory, steps, status, return values or error code.
Five additional Rust tests exercise the new public execution entry point.

The differential observations cover v1–v7 owner/move/drop execution, all small
byte read/write offsets, zero initialization, mutable and read reborrows,
suspended-parent length observation, zero-size and optional allocation,
failure at successive allocation attempts, heap/failure precedence, every
step boundary of the owner fixture, extreme offsets, oversized objects,
scalar overflow while an owner is live, and explicit traps with live loans.
Negative tests cover illegal aliases/loan lifetimes, fabricated public
handles, explicit non-exported entries, policies outside the finite bounds,
and hidden or unsupported program content.

The fresh logs and manifest are retained under
`/workspace/scratch/d930f2b45e07/hepta-rust-recovery-validation`. The manifest
records the tested HEAD, toolchain versions, complete command arguments,
process results, timestamps, source hashes and unchanged-source checks.

| Artifact | SHA-256 |
| --- | --- |
| `cargo.log` | `b6bc7151a8b325081d8e3818f1bcd26b087c6317e5dd90e52ada19cc26c1192b` |
| `python.log` | `4840162da1ac456eb87b1d1a4248d958d36aa0e0c52d89de6b9fc11b740ec3f8` |
| `validation.json` | `c8e159dbc12846c148e8494c390c6d26befb4a68bfa1a4abda6afaf1b97e0a9b` |

This historical evidence establishes the tested finite interpreter correspondence. It
does not establish general resource execution, recursive resource calls,
chain execution, unwinding semantics, LLVM refinement, broad target support,
or production qualification. Future support must extend the same execution
profile deliberately and retain canonical Python differential evidence.
