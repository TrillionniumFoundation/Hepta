# A nontrivial scalar specification through native adoption

This qualification connects a precisely stated unsigned capped-add function to
the same Core, explicit block-layout plan, original object, final ELF, ABI,
independent machine proof and actual adopted consumer calls. It uses the existing
local HIA Agent service and its real native children. It does not select a public
release, activate the online worker or claim a fresh model learned the language.

> V2 follow-up status: the current source was recovered after the local executor
> became unavailable. Its final qualification is pending. The earlier four-width
> archive below remains historical v1 evidence. See
> [the recovery record](../review-evidence/hia-scalar-chain-replay-recovery-20261109-728f/README.md)
> for the completed earlier checks, interrupted final suite and required gates.

## Program family and mathematical contract

For `u8`, `u32`, `u64` and `usize`, the specification is

\[
f(x,y,c)=\min(x+y,c),
\]

where the addition is mathematical, without modular wraparound. Four Core blocks
first return `c` when `x >= c`; otherwise they calculate `c - x`, return `c` when
`y` exceeds that room, and return checked `x + y` in the remaining branch. Both
subtraction and addition use the existing checked operations. The all-input
specification proof must establish that neither can abort on a reachable path.
The boundary includes `x > c`, zero limits and a mathematical sum exceeding the
largest representable input. No precondition such as `x <= c` is silently added.

The existing independent Core model receives arbitrary 64-bit argument-register
words and applies the declared unsigned normalization. The specification is
written separately using **65-bit** addition before comparison with the limit.
Three retained solver obligations check nonvacuity, total return with unchanged
caller bytes, and equality to the mathematical result. These are identified Z3
results in the independent Python Core model. They are not a Lean-kernel proof
of that model or a new runtime acceptance claim.

## One actual artifact chain

The client freezes 125 boundary vectors and an objective requiring Core
admission, Core behavior equivalence, actual encoding identity and lowering
refinement. Its candidate and baseline have identical Core, so this experiment
changes only explicit machine layout. One image uses source block order; the
other uses `entry, limited, room, sum`. The qualifier refuses a run in which the
two resulting final-image identities are equal.

The plan checker retains its conditional producer assumptions. Separately,
**both** supplied object/final pairs must satisfy the independent Safe Core
checker's five existing obligations. Only the independent final-image proof is
supplied to satisfy the adoption objective's lowering claim; the conditional
plan receipt is required for emission and is not substituted for that proof.
The native workload must complete under the existing service budgets before
conditional adoption. Eight actual owner-lease calls then check outputs and
adopted artifact/generation identity. Rollback preserves an already acquired
lease and selects the independently checked canonical image for a new lease;
one actual call through each lease verifies the result, for ten owner calls in
total per type.

The machine proof's `artifact_binding` now presents target profile, backend
profile, ABI signatures, plan reference and plan digest explicitly beside
Core/object/final/build identities. Those facts were already bound transitively
by the immutable build receipt. This is an explicit evidence-contract improvement,
not a claim that the preceding release admitted an unbound artifact. Consumption
reconstructs the binding from the original retained build inputs and rejects a
differing or missing identity. No proof or adoption gate is relaxed.

## Reproduction and retained evidence

Use Linux x86-64, GNU ld, the existing `jsonschema` dependency and pinned
`z3-solver==4.15.4.0`. The output directory must be new:

```sh
python -B -m unittest tests.test_hia_scalar_adoption_chain -v
python -B tools/qualify_hia_scalar_adoption_chain.py \
  --output /absolute/new/capped-add-chain \
  --campaign-id capped-add-chain-20261109
```

The default matrix contains four types. `--types u8` explicitly selects a smaller
run; its report cannot qualify omitted types. Each type retains its original
Core JSON, plan, both objects and final images, exact build/proof/assumption
records, all 13 specification/machine SMT queries, native measurements, owner
observations, cost ledger and fsynced request/response journal. `report.json`
records the exact Git commit/tree, dirty status, worker identity and client hash;
the source must remain unchanged throughout execution. Failed attempts keep their
partial report, phase and files. `original-files.json` identifies every retained
file by complete byte count and SHA256. The private transient service database
is closed and removed after the qualification; these exported reports grant no
execution authority.

The focused test independently replays all 13 saved queries in fresh solver
contexts and rehashes the planned artifact chain. It also checks u64 carry
coverage and that an ordinary valid-Core implementation with the wrong capped
result fails the mathematical specification.

The qualifier now exports a **v2 packet**. Besides the original objects, images
and queries, it retains the admitted canonical Core bytes, seven complete profile
definitions, context/workload/objective/cost-policy originals, every proof's
evidence and assumptions, and the actual adoption and rollback receipt bytes.
Every exported artifact retains its full original ID, URI and SHA-256 in the
family's `exports` map. The private service database is still unnecessary for
independent reading.

`tools/replay_hia_scalar_adoption_chain.py` accepts the complete four-type v2
packet, an independently selected `--expected-manifest-sha256`, and a new
`--output` file. Its default acceptance requires all of the following:

1. Read and hash the selected manifest and all evidence members, retaining the
   same immutable bytes for every subsequent comparison. A report or dependency
   missing from that manifest cannot supply evidence.
2. Reconstruct the exact Core, complete profiles, plan, two original objects and
   final images, ABI, proof subjects and assumptions, evaluation, adopted
   generation and rollback from their original receipts. Check all 125 native
   workload observations per image, eight initial owner calls and both rollback
   owner calls, plus the complete intent/response journal. The summary identity
   chain must equal this reconstruction. When the separately reviewed adoption
   identity projection is present, its complete contents must agree as well.
3. Recompute the mathematical specification and both independent machine-model
   validations from the original Core/object/image bytes. Require the same
   checker and actual solver identities and byte-identical regenerated queries.
   Retain these new queries and results beside the replay JSON in a new
   `.recomputed` directory. This path never calls an emitter, linker, native
   runner or service owner.
4. Replay the 52 original queries once more in fresh solver contexts. These are
   the **same 52 obligations** checked by the regeneration stage; the two passes
   are not 104 different mathematical obligations.

The v2 replay reports `complete_artifact_chain_checked=true` only after the
whole selected matrix passes. `--types u32`, for example, explicitly requests a
single-type replay and cannot qualify the omitted types. The default remains
`u8 u32 u64 usize`. The nine added regression methods check missing originals,
complete artifact references, ABI and generation inconsistencies, every owner
result, journal completeness, query inventories, changed bytes, solver identity,
and historical scope; one method also verifies that fresh model checks never
invoke emission, linkage or native execution.

Historical v1 evidence remains unchanged. It did not export all of the receipt
dependencies needed for the new complete-chain reader. It therefore requires
the explicit `--legacy-query-only` option and returns
`status=passed_saved_queries_only` with `complete_artifact_chain_checked=false`.
Its saved-query result cannot satisfy the v2 gate. The exact-source CI runs both
focused test modules without skips, then requires a fresh full v2 qualification,
four complete reconstructed chains and both 52-query passes.

This read-only replay does not create a second native execution or authenticate
the original machine operator independently. The caller-selected manifest and
the original qualification provenance remain necessary. Matching references,
recorded observations and freshly solved independent models do not prove the
Python checker, hardware ISA, operating-system loader or foreign resource
liveness in a proof-assistant kernel. All such flags remain false, as do
execution authority, complete compiler-buffer refinement and economic benefit.

## Acceptance boundary

The [original local packet](../review-evidence/hia-scalar-adoption-chain-20261109/README.md)
binds clean source `b78868a85c9a59ab31bc9344581c01b17a501d37`. All four types
passed in 17.153 seconds, including 12 specification obligations, 40 machine
obligations, 1,000 measured native workload calls and 40 owner calls. The eight
focused tests passed without skips in 10.041 seconds. Separate read-only replay
rehashes 157 original files and reproduces all 52 solver answers. These are
overlapping, scoped observations; their counts are not additional language
features or a general proof. The final publication head still requires its own
new CI step. Both images are 13,720 bytes and the selected metric is unchanged.

| Question | Established by a complete passing run |
| --- | --- |
| Same Core, plan, object, final image, ABI and proof? | Exact original-byte references are reconstructed and retained. |
| Mathematical capped addition for all typed inputs? | Three SMT obligations in the identified independent Core model. |
| Final machine bytes refine that Core? | Five independent model obligations per image, including ABI and modeled memory bounds. |
| Does the owner use the adopted image? | Finite real native calls through artifact/generation-bound leases, including rollback. |
| Full compiler buffer workload? | **Not qualified.** Agent machine proof remains the existing scalar profile. |
| Kernel-checked Core/ISA/loader soundness? | **Not proved.** Python models, Z3, loader/libc and the declared live stack remain trusted. |
| General resource liveness or arbitrary caller safety? | **Not proved.** No borrowed/owned resource entry is introduced. |
| Performance, NDU or economic improvement? | **Not established.** `unchanged` size is acceptable; all missing provider/future costs remain incomplete. |

The existing 600-second context ceiling, native-execution budget and per-proof
limits are reused. Source/model checks, tool wall times and actual native calls
are retained. The original evaluation ledger still has incomplete external,
adoption and future cost fields; the qualifier does not relabel it as complete.
This closes a scoped specification-to-adoption integration observation. The
broader kernel proof chain, whole compiler refinement and production acceptance
remain separate obligations.
