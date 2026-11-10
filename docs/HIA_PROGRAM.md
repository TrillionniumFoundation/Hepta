# HIA standalone programs: executable Core profiles

HIA Core is the sole language product. `hepta.hia_program.verify_program`
independently validates typed primitive SSA/control flow, effects, ownership,
loans and structural nominal input. The `hepta` namespace is a stable identifier,
not a retained high-level source language. There are no source-to-Core or legacy
source-envelope import routes in the product.

The installed `hia` entry provides Agent admission, assembly, local editing and
direct x86-64 ELF-object construction. The separate
`python -m tools.hia_core_reference` tool exposes explicit research/reference
operations. Reference LLVM/Rust/interpreter operations are not an installed
Agent fallback or evidence of native product closure.

## Wire format and immutable identity

`hepta/hia_schema.py` is the shared version registry. A schema selects an
instruction grammar; it is never a safety receipt or permission to skip
verification. Primitive schemas remain exact, cumulative capabilities:

| Input schema | Additional capability | Executable identity |
| --- | --- | --- |
| `hepta.hia.program.v1` | Typed scalar SSA, owners, loans and byte access | Original v1 bytes |
| `hepta.hia.program.v2` | Bulk byte copy and fill | Original v2 bytes |
| `hepta.hia.program.v3` | Overlapping in-place byte movement | Original v3 bytes |
| `hepta.hia.program.v4` | Byte swap | Original v4 bytes |
| `hepta.hia.program.v5` | Copy with source and destination offsets | Original v5 bytes |
| `hepta.hia.program.v6` | Fill a checked subrange | Original v6 bytes |
| `hepta.hia.program.v7` | Runtime-sized linear chains of owned byte buffers | Original v7 bytes |
| `hepta.hia.program.v8` | Parameter-bound internal returned loans | Original v8 bytes |
| `hepta.hia.composite.v1` | Generic nominal products, enums, stored local loans and cooperative tasks over all v6 operations | Independently checked primitive v6 normalization |
| `hepta.hia.composite.v2` | The same nominal operations over v7, including primitive chain fields and task state | Independently checked primitive v7 normalization |
| `hepta.hia.composite.v3` | Explicit linear partial-record initialized-field states over the v2 capabilities | Independently checked primitive v7 normalization |

The registry deliberately distinguishes `CANONICAL_CORE_SCHEMA` (v6, the
existing composite-v1 normalization target) from `LATEST_CORE_SCHEMA` (v8).
`composite_core_schema(input_schema)` selects the exact target; no consumer
may replace that selection with an unconditional latest-version upgrade.
The registry's legacy singular `composite` entry describes v1; the full
`composite_versions` list describes all three versions. Primitive input retains
its declared version and canonical identity during ordinary verification.
The explicit reference `upgrade-v7` operation changes the schema only after checking the old and
new programs; it does not add operations or prove source/native equivalence.


Programs use UTF-8 JSON. Whitespace and key order are accepted on input; the
verified snapshot canonicalizes keys and separators. Duplicate object keys,
nonfinite values, floating JSON numbers, invalid identifiers, unknown fields
and unsupported schemas reject. Limits include 8 MiB encoded input, nesting
depth 64, 262,144 structural nodes, 1,024 functions and 4,096 blocks per function.

The primitive top-level shape is:

```json
{"schema":"hepta.hia.program.v1","module":"example","functions":[]}
```

An optional `exports` list declares the exact public scalar entrypoints. It
must contain unique existing function names with primitive scalar parameters
and results. When absent, the original v1 rule exposes scalar-signature
functions; existing canonical v1 identities do not change. Composite normalization
always emits `exports`. Both the interpreter and native backend obey the core's
list after serialization and reload; source origin is not needed to preserve
the public boundary. Exporting an owner/view descriptor is forbidden. Native
C wrappers additionally require at most one scalar result.

The example above illustrates fields only: a real program must have at least
one function. A function has exactly `name`, `params`, `returns`, `effects`,
`entry`, and `blocks`. Primitive v8 additionally permits `return_loans`, an
arity-matched list binding borrowed results to original loan parameters and
using `null` at nonloan positions. See [the v8 contract](HIA_PARAMETER_LOAN_RETURNS_V8.md).
A parameter is `{"name":"value","type":"u32"}`.
`returns` is an ordered list of types, including an empty list for no result.
Each block has exactly `id`, `params`, `ops`, and `term`.

Every instruction has exactly:

```json
{"op":"int.add.checked","args":["x","one"],
 "out":[{"name":"answer","type":"u32"}],"attrs":{}}
```

Identifiers are bounded ASCII letters/digits/underscores with a non-digit
first character. `__hia_` is reserved, and runtime symbol collisions such as
`calloc`, `free`, and `abort` cannot be function names. The verifier rejects
duplicate SSA definitions across the whole function, including block inputs.

`VerifiedProgram` holds immutable canonical bytes. Public construction of that
Python dataclass is possible and is not a trust boundary: inspection,
interpretation, emission and native compilation reverify its exact content.
`as_dict()` returns a detached copy. SHA-256 identifies bytes, not truth,
authorship, equivalence or authorization.

## Values, blocks and effects

| Component | v1 semantics |
| --- | --- |
| Integer values | Signed and unsigned 8/16/32/64-bit integers; `isize`/`usize` are fixed at 64 bits |
| Other scalar values | `bool`, `unit`; unit's JSON constant is `null` |
| Resource values | `buffer`, `readbuf`, `mutbuf` |
| Block visibility | Only explicit block parameters and earlier local instructions are visible |
| Entry | Entry parameters exactly equal the function signature; incoming entry edges reject |
| Edges | Exact argument count/types; every live local owner and loan travels or is consumed |
| Branches | Exclusive alternatives; each edge checked independently |
| Joins/loops | Normalized ownership/loan origin/parent/permission state must agree for all predecessors |
| Effects | `alloc`, `read`, `write`, `trap`; every operation and callee effect must be covered |
| Calls | Statically named module functions; no foreign calls or indirect function pointers |
| Reachability | Every declared block must be statically reachable; unreachable payloads reject |

Extra declared effects are allowed; missing required effects reject. Recursion
is permitted in the core and is not a proof of termination or stack bounds.
The interpreter has an independent depth limit. A native caller must provide
ordinary platform stack resources.

### Scalar instruction set

| Instructions | Rules |
| --- | --- |
| `const` | One exactly typed scalar output; attributes contain only `value` |
| `int.add/sub/mul.checked` | Equal integer types; overflow aborts |
| `int.add/sub/mul.wrap` | Equal integer types; modulo word width |
| `int.div/rem.checked` | Division truncates toward zero; divisor zero and signed minimum divided by -1 abort |
| `int.shl/shr.checked` | Shift count must be in `[0,width)`; left shift wraps discarded bits; signed right shift is arithmetic |
| `int.neg.checked` | Result must fit the output integer type |
| `bit.and/or/xor/not` | Fixed-width bit operations |
| `compare.eq/ne/lt/le/gt/ge` | Equal integer types; equality/inequality also admit booleans |
| `bool.not/and/or` | Boolean values; both argument values already exist, so these are not source short-circuit expressions |
| `int.cast` | Attribute `mode` is `checked` or `wrap`; checked range violation aborts |
| `select` | Boolean condition and two equal scalar types; cannot duplicate/select owners |
| `call` | Attribute `function` names a checked function; outputs exactly match all return types |

Source short-circuit Boolean operators lower to branches. In particular the
unselected side of a source `||` is not eagerly executed by `bool.or`.

### Terminators

```json
{"op":"ret","values":["answer"]}
{"op":"jump","target":"loop","args":["next"]}
{"op":"branch","cond":"condition",
 "then":{"target":"yes","args":[]},"else":{"target":"no","args":[]}}
{"op":"trap","code":"bounds"}
```

Trap codes are `user`, `overflow`, `division_by_zero`, `bounds`, `allocation`.
Native traps abort the process. No destructor cleanup after an abort is
promised. Normal return, including errors represented as returned values,
must consume or explicitly return every owned capability and end local loans.

## Resource semantics

`buffer` is a linear owner of initialized bytes. An empty owner is still a
capability and must be consumed exactly once. Native runtime metadata is a
pointer and length; it is private to the implementation and is not an external
safe C aggregate API.

| Instruction | Resource transition and dynamic behavior |
| --- | --- |
| `buffer.new(size)` | Creates one zeroed byte owner; allocation refusal aborts |
| `buffer.try_new(size)` | Returns `(buffer,bool)`; refusal returns an empty owner and false |
| `buffer.len(value)` | Reads a buffer/view's length without copying ownership |
| `borrow.read(value)` | Creates a shared child view; conflicting mutable loans reject |
| `borrow.mut(value)` | Creates an exclusive child view from an owner/mutable view; aliases reject |
| `loan.end(view)` | Ends a locally created view after its child loans have ended |
| `owner.move(owner)` | Consumes the old name and creates a new owner name; outstanding loans reject |
| `owner.drop(owner)` | Consumes/free the owner; outstanding loans reject |
| `buffer.load(view,index)` | Requires read/mutable access; checks index before loading an initialized byte |
| `buffer.store(view,index,byte)` | Requires mutable access; checks index before writing |

Zero-size allocation succeeds without invoking the allocator. Sizes above
`2^63-1` are rejected by the 64-bit object-size model before allocation.
`try_new` maps that rejection to `(empty,false)`. Any other allocator refusal
also yields `(empty,false)` for `try_new`; `new` aborts. Empty owners are consumed
logically without invoking native `free`; no allocation or deallocation event
is recorded. A non-null native allocation retains its actual release call.

Allocation/refusal and release are observable core effects. The LLVM backend
preserves calls through declaration-level `"no-builtins"` plus call-site
`nobuiltin`; merely applying the call-site marker did not preserve events under
the measured LLVM optimizer. Native evidence separately intercepts allocator
calls and NULL returns, including a missing-free machine-code negative control.

The backend may omit zero writes only when the complete verified function has
scalar parameters/results and every block uses an explicit closed whitelist
that excludes all calls, byte loads and byte stores. Unknown instructions,
unknown boundary types and unknown terminators disable this optimization.
These local owners cannot escape or expose their byte contents; `malloc`
replaces `calloc` while preserving the allocation attempt, NULL branch, live
storage and explicit free. All functions that can observe bytes retain zeroed
allocation. This is an implementation optimization, not an uninitialized-buffer
operation in Core. The allocator must supply a fresh, nonaliasing region or
NULL, and free must accept either allocation family or NULL. It does not promise
that different allocator implementations fail on the same physical request.

Native allocation lowering also exposes the helper's exact length invariant:
the owner length is the requested size on success and zero on failure. For an
infallible constructor, the requested length is used only after its success
guard; for a fallible constructor an explicit success-dependent select is
used. This is true for zero, oversized and NULL-refused requests too. Every
byte access still emits a bounds guard. LLVM may eliminate a redundant guard
when it derives the same length relation, without an unchecked operation,
`llvm.assume`, or recognition of a particular benchmark loop.

Loans carry a root owner or external borrowed parameter and a parent loan.
Reborrowing suspends use of the parent until the child ends. A view can cross
blocks and loop iterations only with its root and parent capability. Incoming
loan graphs must normalize to the same graph at a join. This supports local
stored capabilities in the executable CFG; it does not enable arbitrary
source-level lifetime records, self-referential objects or escaping borrows.

Owned call arguments are consumed. Borrowed call arguments remain with the
caller. A callee cannot end its caller's loan. Primitive v1–v7 prohibit borrowed
results. Primitive v8 admits declared parameter-bound results: the caller gets
a child loan and its parent remains suspended until that child ends. Aliased exclusive arguments reject. Owned results may
return; returning an owner with outstanding loans rejects. Multiple internal
results are permitted.

### Recursive byte-owner chains in v7

Primitive v7 adds `chain = Nil | Node(buffer, chain)`. Each node exclusively
owns one byte-buffer payload and its successor. Runtime node count may grow
through a loop; the representation is not a statically expanded nominal
layout. Composite v2 can store this primitive capability in its existing
record, enum and task forms. Earlier primitive versions reject the type and
operations, and composite v1 keeps its previous grammar. A composite-v1 nominal type
or generic parameter already named `chain` keeps its old meaning; composite
v2 reserves that name for the primitive.

| Instruction | Resource transition |
| --- | --- |
| `chain.empty()` | Produces a linear Nil capability without allocating |
| `chain.try_push(tail,payload)` | Consumes both inputs; returns `(chain,buffer,bool)`. Success returns the new node and an empty buffer; header refusal returns the unchanged tail and payload with false |
| `chain.pop(chain)` | Consumes the chain; returns `(tail,payload,true)` and frees its header, or `(Nil,empty,false)` for Nil |
| `chain.is_empty(chain)` | Observes emptiness without consuming the capability |
| `chain.head_read/mut(chain)` | Borrows the first payload with chain-root provenance; Nil traps before dereference |
| `owner.move/drop(chain)` | Transfers or consumes the whole owner; live head loans forbid either operation |

Both owners returned by `try_push` or `pop` must be consumed on every ordinary
path, including refusal/empty paths. Live head loans also forbid consuming
calls, returns, push and pop until those loans end. Destruction traverses and
releases nodes iteratively in the VM and native lowering; data depth does not
add one call frame per node. The VM charges each destruction step and each
24-byte node header to its evaluator budgets, together with payload bytes.
These are requested live object bytes, not process RSS or allocator overhead.

This extension does not admit arbitrary recursive nominal layouts, a generic
`List<T>`, shared/cyclic graphs, raw pointers or a public chain ABI. Complete
operation/effect rules, fallible construction semantics and executable inputs
are in [HIA_RECURSIVE_CHAIN_V7.md](HIA_RECURSIVE_CHAIN_V7.md).

## Nominal products, enums and cooperative tasks

Standalone `hepta.hia.composite.v1`, `hepta.hia.composite.v2` and
`hepta.hia.composite.v3` inputs have
exactly `schema`, `module`, `types`, and `functions`. Each automatically exports
original scalar-signature functions. An explicit narrower export list can be expressed in its normalized
primitive Core; the nominal input itself does not accept `exports`.
Function/block/instruction
structure follows the primitive grammar. Composite v1 admits primitive v1
through v6 instructions; composite v2/v3 admit v1 through v7. Their checked
resource rules still apply. Parameter,
result and instruction-output types may additionally name declared nominal
types. A generic application is `{"name":"Pair","args":["buffer","usize"]}`.
A declared type has `name`, a unique `params` list and `kind`:

| Kind | Additional declaration fields | Executable meaning |
| --- | --- | --- |
| `record` | `fields`, each with `name` and `type` | Product of primitive values and capabilities |
| `enum` | `variants`, each with `name` and `fields` | Checked discriminant plus variant payloads |
| `task` | `state`, `result`, `poll`, `cancel` | Concrete, linear cooperative protocol |

Named record/enum types are nominal even when layouts match. Type and layout
resolution rejects unknown names, wrong generic arity, recursive by-value
layouts and resource-budget expansion. Type definitions, instantiations,
nesting and flattened fields have explicit finite limits. Unused declarations
are checked for shape, type references and cycles; generic layouts are fully
checked at concrete instantiation. Composite input provides generic nominal type parameters;
bounded generic function specialization belongs to the existing source adapter.

`record.make` consumes linear fields into a record. `record.unpack` consumes a
linear record and returns all fields. `record.get` may copy a non-linear field;
it cannot duplicate an owner, loan or nested task. Stored owner/parent/child
loans retain their primitive provenance through packing, branches and
unpacking. The parent remains suspended while its child exists and owner drop
still requires all loans ended. These are local records; stored loans cannot
escape a function or be kept in task state/results. Enum payloads containing
loans are also rejected in this profile.

`record.borrow` accesses a primitive `buffer`, `readbuf` or `mutbuf` field without
unpacking the record. It takes one record argument,
`attrs: {"field": "name", "mode": "read"}`
or mode `mut`, and one `readbuf` or `mutbuf` output respectively. The record
remains live. Elaboration borrows the original field capability, preserving
its owner and parent identities; it does not copy an owner or manufacture an
address. The ordinary primitive loan checker rejects competing mutable loans,
use of a suspended parent and destruction while a child loan remains live.
A record can therefore contain two byte-buffer owners while one is read and
the other is mutated by checked bulk-memory instructions. Borrowing an aggregate field
recursively or treating a `chain` field as a byte view is outside this
operation's finite profile. Chain head access uses the explicit v7 operations.

`enum.make` selects a declared variant. Inactive owner slots contain real
empty buffers or, in composite v2, Nil chains, with no allocator call, so
every control-flow edge can account for them. `enum.tag` observes the tag
without consuming the enum.
The `match` terminator must list every variant exactly once; each case has
`variant`, `target`, and `args`. Its target receives the selected payload fields
followed by explicit case arguments. Inactive owners are consumed on that edge.
An invalid erased tag takes a real trap edge, including the final case; it is
never interpreted as an arbitrary valid variant.

Task declarations are concrete. Their poll function consumes one state and
returns an enum of exactly `pending(state)` or `ready(result)`; cancellation
consumes one state and returns nothing. Each task also carries a zero-length
owner token. The primitive verifier therefore retains linear transfer/drop
obligations even when both state and result are scalar after normalization.

| Operation | Required state and result |
| --- | --- |
| `task.create` | Consumes initial state; produces pending task (`0`) |
| `task.start` | Pending → running (`1`); consumes/replaces the task value |
| `task.poll` | Calls the checked poll function only while running; yields running or succeeded (`2`) |
| `task.state` | Returns the state tag while preserving the task |
| `task.cancel` | Pending/running executes cancellation once and yields cancelled (`3`); cancelled/succeeded is unchanged |
| `task.join` | Consumes a succeeded task and yields its result |
| `task.close` | Consumes a cancelled task and its empty token |

Static checks establish nominal type agreement, exhaustive cases, linear
consumption, call signatures, effects and loan provenance. State transitions
use runtime guards: a type-correct second start or premature join traps.
Cancellation after success retains the completed result for an explicit join.
There are no detached threads, preemptive scheduling, I/O wakeups or cleanup
guarantees after abort/budget exhaustion. The allocator, ABI and compiler
assumptions remain the same as the primitive core.

`verify_core` elaborates composite input, verifies every primitive operation
and edge, and stores the canonical primitive v6 core for composite v1 or v7
core for composite v2/v3, as selected by the registry. A `VerifiedProgram` may
additionally retain canonical composite bytes for audit identity. Public
consumers re-elaborate such retained bytes
and require exact core equality; a forged origin/core pair rejects even if a
caller recomputes a digest. `input_sha256` and `program_sha256` distinguish the
input representation from the executable core. `hia normalize` publishes the
core, including its export policy, as a self-contained program in that selected
primitive version. Later semantic patches operate on that core and report
this edit domain explicitly.

The checked examples are `generic_owned_enum.hia`, `stored_loan_record.hia`
and `cooperative_task.hia` in `examples/hia_program/`. The task example composes
generic records/enums, owner transfer, nested stored loans, byte reads/writes,
ordinary allocation failure, polling, success, cancellation and final cleanup.
These examples retain composite v1. The separate
`examples/hia_recursive_chain/composite_v2.json` exercises chains in generic
records/enums, stored local head loans and cooperative task state.

Composite v3 additionally admits explicit partial record types with an exact
initialized-field set, and `record.begin`, `record.insert`, `record.finish`,
`record.take`, and `record.abandon`. A zero-byte owner token makes every
partial state linear, including empty states and records containing only
Copy fields. Missing fields have no fabricated default values. A partial
record cannot contain a stored loan; v3 normalization stays on primitive v7
and does not acquire v8 returned-loan contracts. See
[HIA_PARTIAL_RECORDS_V3.md](HIA_PARTIAL_RECORDS_V3.md) for exact operation,
effect, error and cooperative-cleanup rules and
`examples/hia_program/partial_record.hia` for a checked input.

The source adapter separately preserves original scalar export eligibility
before specialization and scalarization. A record that flattens to one scalar
does not thereby become a C scalar entrypoint. Checked source field restoration
uses the existing primitive v1 path; it does not silently upgrade a source
program or declare a general uninitialized-memory model.

## Interpreter, native code and external conditions

`execute_program` admits scalar arguments and scalar return values at its
external entry; resources can be created and passed within the program.
Outcomes are `returned`, `trapped`, and `budget_exceeded`. The last two carry
reports via distinct exception classes; the CLI prints the reports as JSON
and exits nonzero. A step, heap or call-depth budget is an evaluator limit,
not a language allocation failure or proof of nontermination. Counters report
the state at the stop and do not invent cleanup after an aborted computation.

Additional consumers have their own closed support sets. A registered schema
does not automatically qualify every analyzer or shadow implementation:

| Consumer | Accepted scope | Meaning of acceptance |
| --- | --- | --- |
| Python `verify_core`, direct interpreter and direct LLVM | Primitive v1–v8; composite v1/v2/v3 via their exact normalization | Static executable admission; interpreter/native operations still obey dynamic checks and their separate runtime/target limits |
| `hia_incremental.IncrementalVerifier` | Session-local primitive v1–v8 checking under the v2 closed-body/callee-interface contract; nominal inputs receive a full check | Complete global shape validation on every candidate; body reuse requires unchanged body bytes, callee parameter identities/types, return types/origins, effects and checker policy. Execution and native consumers still fully reverify. No behavioral-equivalence or model-efficiency claim. |
| `hia_static_budget.analyze_static_budget` | Original finite acyclic primitive v1–v6 profile; separate byte-owner v8 profile | Structural VM-tick, allocator-interaction and call-depth bounds. v8 uses receipt v2, excludes chains, and does not silently inherit the old optional heap/native meaning; v7 remains unsupported |
| Legacy `hia_heap_bound.analyze_constant_live_heap` / `qualify_live_heap_budget` | Audited primitive v1–v6 live-heap profiles, including bounded same-block owner lifetimes in admitted CFG cycles | Requested live payload bytes; rejects v7/v8 and unsupported allocator cycles/ownership flows |
| `hia_heap_bound.qualify_entry_live_heap_budget` | Separate v8 public-scalar-entry, byte-owner borrowed-call profile | Total requested live payload for that entry; private summaries count only additional local payload. Rejects chain, recursive calls, owner-valued call boundaries and unknown allocation extents |
| `hia_static_budget.qualify_vm_call_depth` | Primitive v1–v8 with a closed acyclic call graph; CFG loops may remain | Root-inclusive synchronous VM frames only; v8 uses receipt v2. No tick, allocation, recursive-chain destruction cost, native stack-byte, CPU-time or RSS bound |
| Rust shadow default checker and `--scalar-run` | Resource-free scalar subset of primitive v1–v7 | Independent finite scalar checking/execution; rejects owner, loan and chain programs |
| Rust `--owned-shadow` | Primitive v1–v8 typed owner/loan CFG subset, including chain transitions and v8 parameter-bound returned loans | Opt-in independent static cross-check; v8 receipt v2. Static acceptance is separate from an execution profile, native refinement proof and production admission authority |
| Rust `--owned-run` | Primitive v1–v8 resource CFG/loops, internal owner/loan/chain calls, versioned bulk operations, chains and v8 parameter-bound returned loans; scalar public entry/results | Modules without chains retain `bounded-cfg-byte-owner-bulk-v3` (v1–v7) or `bounded-cfg-byte-owner-loan-returns-v4` (v8). Chain modules use `bounded-cfg-owned-memory-v5` in the same Machine with shared step/live-byte/32-frame limits. Direct nominal input and production authority remain outside this scope; see [returned chain execution](HIA_RUST_RETURNED_CHAINS_V8.md) |

The Rust routes consume primitive Core, so nominal input must first undergo
the canonical normalization. The Python verifier remains mandatory for
standalone/native admission. See
[HIA_RUST_V7_CHAIN_SHADOW_20261027.md](HIA_RUST_V7_CHAIN_SHADOW_20261027.md) for
the exact chain shadow scope. Analyzer acceptance and Rust shadow success do
not replace a target execution receipt or extend a source frontend.
The distinct [v8 budget contracts](HIA_V8_RESOURCE_BUDGETS.md) explain the
external-root versus local-payload distinction and each preserved refusal.

The native backend exposes only functions with integer/Boolean parameters and
at most one scalar result as external C wrappers; a unit result maps to void,
and a unit parameter is not exported. Owned/borrowed parameters and
multi-result functions are internal LLVM functions. Small signed/unsigned
integer and Boolean ABI extension rules are target-specific. Cross-target
object generation, emulator execution and physical hardware acceptance are
separate qualifications; a host success cannot qualify a new target.
The finite [v8 returned-loan cross-target qualifier](HIA_RETURNED_LOAN_CROSS_EXECUTION.md)
links the direct objects with a bounded runtime and executes AArch64 and RV64
under QEMU, retaining allocator and trap observations. This does not alter the
object-only cross-target publication API or establish physical-device timing.

The direct LLVM emitter has separate per-version profiles for these targets:

| Target | Publication kinds | Object/ABI boundary |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | Shared library or object | ELF64 x86-64; shared publication requires the admitted Linux x86-64 host |
| `aarch64-unknown-linux-gnu` | Object only | ELF64 AArch64; shared-library publication rejects |
| `riscv64-unknown-linux-gnu` | Object only | ELF64 RV64GC / LP64D, explicit `-march=rv64gc -mabi=lp64d`, reviewed ELF flags; shared-library publication rejects |

These targets admit primitive v1–v8 through the same standalone verification
entry, including version-correct composite normalization. LP64D names the
RISC-V ABI and does not introduce floating-point HIA operations. The checked
source bridge in `hia_source_bridge.py` still admits only its x86-64/AArch64
profiles; direct standalone RV64 support does not widen that bridge.

Primitive v8 additionally emits on Linux x86-64. AArch64 and RV64 v8 emission
explicitly rejects; the older target receipts do not establish returned-loan
native behavior there. V8 borrowed returns remain private internal calls and
do not create external C/C++ borrowed-result ABI contracts.

The original finite AArch64 execution gate links the independently emitted
object to a reviewed 4096-byte, one-live-allocation runtime and executes it
with the pinned QEMU user-mode binary. That runtime's abort exits with code
134; the host libc abort controls instead observe SIGABRT. Neither result is
a physical board, DMA, interrupt, GPU or device-timing qualification. The
separate Cortex-M4 reference/BSP gate continues to use the historical Rust
path and is not evidence that standalone HIA supports a 32-bit word model or
MMIO.

The separate `composite_bulk` AArch64 profile uses eight fixed 4096-byte slots
to exercise two simultaneous owners and their loans. It is an explicitly
bounded test runtime, not a general heap implementation. Its qualifier executes
both nominal and serialized/reloaded v6 inputs on the host and AArch64/QEMU,
observes allocation/refusal/free counts, and runs wrong-result, missing-free
and bounds-trap controls. These observations do not broaden the historical
one-live-allocation profile or qualify physical devices.

The independent RV64 qualifier uses a different finite runtime with 64
4096-byte slots. It exercises scalar C entry/return conventions, actual
allocator/memory imports, both nominal and normalized bulk-resource programs,
and primitive-v7/composite-v2 chain fixtures under Linux userspace QEMU.
This does not add arbitrary C function imports, callbacks, foreign owner
descriptors or physical-device acceptance. Its target rules and finite
execution denominator are in [HIA_RISCV64_LP64D.md](HIA_RISCV64_LP64D.md).

Native publication regenerates the expected LLVM from the exact reverified
core and target and compares it with the proposed IR. Rehashing changed LLVM
does not admit it. Compiler invocation, output capture and artifact reads are
bounded; artifact symbol/ELF inventories and actual tool digests are recorded.
Publication creates a new file without replacing an existing path.

| Layer | What is established | What remains outside it |
| --- | --- | --- |
| Static checker | Typed closed SSA, complete local linear flows, nonconflicting loan graph, effect coverage | Whole-language soundness theorem, frontend/backend refinement theorem |
| Runtime checks | Integer overflow/division/shift/cast guards, byte bounds, fallible allocation | All program logic, termination, performance, operating-system isolation |
| Native qualification | Actual finite outputs, aborts, allocation/refusal/cleanup traces, artifact inventory | Exhaustive input equivalence or all machine/optimizer behaviors |
| External conditions | Allocators return fresh disjoint live regions or NULL; calloc initializes bytes, while malloc is used only when bytes cannot be observed; free accepts either family or NULL; platform ABI holds | Arbitrary foreign callers, malicious same-user artifact modification, device protocol correctness |

The compiler and Python checker, LLVM/Clang, the native runtime, libc and the
platform are part of the present trusted implementation. Foreign code has no
privilege to forge a `buffer` in the standalone public ABI. Hash checks and
no-replace publication do not defend against a malicious same-user process
changing executable bytes after acceptance.


## Agent operations

```sh
hia capabilities
hia verify examples/hia_program/counter.hia
hia inspect examples/hia_program/counter.hia
hia build examples/hia_program/counter.hia -o /var/tmp/new-counter.o
hia catalog --schema hepta.hia.program.v8
```

For compact text and snapshot-bound local edits see
[HIA_AGENT_ASSEMBLY.md](HIA_AGENT_ASSEMBLY.md) and the current tool catalog.
Verification and successful native controls do not prove a requested edit correct;
independent application tests remain necessary. The hosted Agent and durable
publication still require native replacement; see [scope](HIA_CORE_ONLY_SCOPE.md).
