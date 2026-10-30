# OwnedExit: actual Core transfer, cleanup and trap semantics

This increment adds a phase-indexed resource model and an explicit
source-to-candidate relation for a selected, actual HIA Core program. The
qualification command requires the pinned Lean 4.19.0 executable; a missing
toolchain, missing theorem, failed positive proof or surviving negative control
fails the command. There is no optional proof skip.

The theorem concerns the independent mathematical model. The Python projection,
production checker, production VM and backend have separate, explicitly bounded
evidence. No statement here extends to whole-language soundness or LLVM/machine
refinement.

## Selected actual Core

The fixture is `formal/selected_owned_exit.hia.json`, explicit v8 Core. It has a
closed allocator leaf and a public scalar entry:

- `make(size: usize) -> (buffer, bool)` performs exactly one `buffer.try_new`
  and returns that actual owner and success flag.
- `run(size: usize, cancel: bool, abort: bool) -> u8` calls the leaf and transfers
  its owner across CFG block parameters. A refused allocation is dropped before
  return code 1. A successful allocation with `cancel = true` is dropped before
  return code 2. If successful, not cancelled and `abort = true`, the entry
  executes an explicit `division_by_zero` trap. Otherwise it drops the owner and
  returns code 0.

The existing leaf-call proposer generates a candidate. Both source and candidate
pass the production checker independently. The new projection reads the actual
checked operations, SSA operands, block arguments and return values. It does not
copy a producer-supplied resource model or accept the proposer's receipt as proof.
The fixed selected exit contracts are proved separately from the rewrite.

The selected source SHA-256 is
`f5761f737b922ed83cc5d36978dcb5a089036109b3931c3ec8369ebaa2839718`.
The generated candidate SHA-256 is
`42822cd202525b21cf7ba6340d4b230baf48c767620332889f07d347c26591ab`.
These are canonical checked-Core identities, not Git commit IDs.

## Resource and failure contract

An empty owner is still a linear capability. Payload allocation counters and
owner capability counters must not be conflated.

| Situation at allocation | Owner created | Success flag | Attempt consumed | Exit at allocation |
| --- | --- | --- | --- | --- |
| Size 0, including quota 0 | Empty owner | true | No | Continue |
| Size greater than 2^63 − 1 | Empty owner | false | No | Continue |
| Positive legal size exceeds remaining payload quota | None | No result | No | Heap budget stop |
| Positive legal size fits, allocator refuses | Empty owner | false | Yes | Continue |
| Positive legal size fits, allocator accepts | Owner with payload | true | Yes | Continue |

The ordering matters: an oversized fallible request becomes refusal before the
quota check. A legal positive request that exceeds quota is a budget stop, even
if an injected allocator refusal would have occurred at the next attempt.
The selected phase guarantees zero existing payload before each allocation;
the small model's quota comparison therefore agrees with remaining quota in
this profile.

Dropping an empty owner increments `owners_dropped`, but not `frees`. Dropping a
nonempty owner increments both. The model preserves:

\[
\text{created}=\text{dropped}+\text{live owners},\qquad
\text{allocations}=\text{frees}+\text{live nonempty owners}.
\]

It also preserves `live payload ≤ peak payload ≤ quota`. This is a payload
bound, not a host RSS bound; allocator headers, Python objects, call frames and
VM metadata are not charged by these counters.

Cancellation in this fixture is cooperative: the boolean is checked after a
successful allocation. Refusal takes precedence over cancellation, and
cancellation takes precedence over the explicit trap. This does not model an
asynchronous interrupt or promise destructor execution after process failure.

An explicit trap retains the stopped store. For size 8, no cancellation and an
abort request, the actual VM report has one live owner, eight live bytes,
zero drops and zero frees. For size 0, that same trap retains one empty owner
with zero live payload and zero physical allocation count. Ordinary returns
must have no live owner.

## Minimized formal model and relation

`formal/HiaOwnedExit.lean` distinguishes `Program .empty` and `Program .owned`.

| Constructor | Input phase | Continuation phase |
| --- | --- | --- |
| Return a literal | Empty | Terminal |
| Fallible allocation | Empty | Owned |
| Closed allocator call | Empty | Owned |
| Explicit drop | Owned | Empty |
| Boolean branch | Either | Same phase on both arms |
| Explicit trap | Either | Terminal, stopped store retained |

The generic model supports finite sequential allocation/drop cycles. Allocation
failure is an arbitrary fixed function of attempt ordinal. Source and candidate
use the same inputs, quota and failure function. This assumption preserves the
ordered failure decisions; it does not assert that unrelated executions in a
changing external allocator environment see identical failures.

Twenty generic theorems cover owner creation/freshness, ledger preservation,
empty/payload distinctions, exact zero/oversize/quota/refusal/success transitions,
ordinary exit cleanup, payload bound, trap state and call erasure. Eleven
selected theorems instantiate safety and balanced exits, establish the actual
source/candidate relation, and prove the fixture's normal, refusal, cancellation
and trap contracts. The qualifier checks the exact 31-theorem dependency
inventory. Positive results admit only the explicitly listed Lean library
axioms and reject `sorryAx`, unreviewed imports and executable declarations.

The transform recursively replaces `callAllocate` with `allocate`.
Its observation removes only administrative `callEnter` and `callReturn`
events. Exit, full modeled store and ordered allocation/drop/heap-stop events
remain equal. The generic proof is by structural induction. A separate
definitional equality proves that the actual exported candidate is exactly
that transform of the actual exported source.

`hepta/hia_owned_exit_core.py` is the deliberately restrictive Python
projection. It accepts explicit v7/v8 Core with exactly the two selected
interfaces, one live byte-owner at a time, literal extents/results, supported
booleans, finite CFG and the specified trap. It checks each CFG edge transfers
the current actual owner exactly once. An older allocation's success flag
cannot silently denote a newer allocation's result. Unsupported operations,
extra simultaneous owners, cycles, open calls and hidden blocks are rejected.
SSA alpha-renaming does not change the imported semantics. The complete module,
including the closed allocator body and the canonical opcode catalog, is
bound into the qualification identity.

The projection is auditable and exercised; its refinement is not itself a Lean
theorem. The phase type prevents constructing an ordinary return with a live
owner in the imported model. Whether a production Core document was projected
faithfully remains part of the Python boundary, tested against actual execution.

## Executed positive and negative evidence

The qualification executes the following, with no model requests:

1. Pinned Lean checks the 31 positive theorems and reports every dependency.
2. Three modified inputs must be rejected by the kernel at their intended
   theorem: freeing a nonexistent payload when dropping an empty owner,
   treating quota stop as allocator refusal, and changing the actual
   candidate's cancellation result from 2 to 3. The last mutant remains valid
   production Core; the failed property is the source/candidate relation.
3. A fixed 192-case matrix runs both actual Core versions through the public VM
   boundary. It covers eight lengths, two quotas, four cancellation/abort
   combinations and three failure schedules. Huge lengths are rejected by
   oversize/quota semantics before any large allocation.
4. Temporary observing subclasses call the production VM's actual `allocate`,
   `drop` and nested `invoke` implementations. The resulting operation trace,
   result/trap/budget exit and all resource fields are compared with the
   independent executable model. All loan/chain counters must remain zero.
   This is a synchronous, single-threaded qualification.
5. Retained evidence validation reprojects checked Core, reconstructs generated
   Lean and mutations, checks exact identities and scope, and replays all VM
   observations. It does not infer execution authority from a JSON receipt.

The ordinary unit suite has 24 tests with no skips. It exercises valid
alpha-renaming and sequential owner cycles, rejects a stale success flag,
rejects valid Core outside the selected profile, and demonstrates the actual
zero/oversize/quota/refusal/cancel/trap distinctions. A missing or duplicate drop
and wrong callee result order fail the production checker before projection.
These dependency-free unit tests do not claim to execute Lean; the separate
mandatory qualification command supplies that evidence.

## Budgets that must be recomputed

For `[size=8, cancel=false, abort=false]`, the actual source uses 11 VM ticks
and the candidate uses 8. With a step limit of 8, the source stops at tick 9
with its eight-byte owner still live; the candidate returns after cleanup.
With maximum call depth 1, the source stops before entering the allocator
callee, while the candidate returns.

These are retained counterexamples to exact evaluator-budget preservation.
Both variants are also executed under sufficient fresh limits: 256 steps,
call depth 2 and the case's payload quota. The mathematical relation preserves
heap quota stops and resource/failure order under the shared allocation oracle.
It does not preserve step-budget or call-depth stopping behavior. A scheduler
must recompute those budgets before admitting the transformed candidate.

## Guarantees along the implementation path

| Boundary | What this increment establishes | What remains outside |
| --- | --- | --- |
| Actual Core input | Production verification, strict selected-profile projection, canonical identity and instruction map | Proof of production checker soundness |
| Imported Core model | Generic lifetime/ledger/quota safety; fixed selected exits | Arbitrary HIA ownership, borrowing, loops or concurrency |
| Source to candidate | All-input resource observation equality in Lean under the shared failure oracle; actual before/after Core relation | Preserving step/depth stops or external allocator timing |
| Actual VM | 192 finite cases, complete resource dictionaries, observed operation order and explicit budget counterexamples | Universal VM refinement |
| Backend and machine | No claim added by this qualification | LLVM correctness, machine-code refinement, native RSS, ABI or hardware behavior |
| Retained report | Fresh byte bindings, strict scope/inventory checks and VM replay | Attestation of a hostile producer or authorization to execute arbitrary code |

Lean's kernel, its measured support libraries, the fixed source and the host
remain trusted. The qualification checks the executable against
`formal/toolchain-lock.json` before executing it and records support-file
identities before and after proof execution. The immutable prior scalar,
resource-contract, CI and negative performance studies remain separate.

## Reproduce

From a checkout containing these six new files:

```sh
python3 -B -m unittest tests.test_hia_owned_exit -v
python3 -B tools/qualify_hia_owned_exit.py \
  --lean /path/to/pinned/lean-4.19.0/bin/lean \
  --output-directory /path/to/new/owned-exit-evidence
```

The output directory must be new. It retains original input, canonical source
and candidate Core, generated positive and negative Lean files, instruction
mapping, support manifest and the full qualification report. The report binds
`hia_opcodes.py` along with the actual checker, schema, runtime, JSON preflight,
call proposer and new projection. An independent reviewer should run the
command against the integrated source before using the evidence.
