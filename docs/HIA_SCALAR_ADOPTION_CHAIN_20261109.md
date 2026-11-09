# A nontrivial scalar specification through native adoption

This qualification connects a precisely stated unsigned capped-add function to
the same Core, explicit block-layout plan, original object, final ELF, ABI,
independent machine proof and actual adopted consumer calls. It uses the existing
local HIA Agent service and its real native children. It does not select a public
release, activate the online worker or claim a fresh model learned the language.

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

`tools/replay_hia_scalar_adoption_chain.py` accepts the complete four-type packet,
an independently selected `--expected-manifest-sha256`, and a new `--output`
file. It rehashes the original packet and replays all 52 retained queries in
fresh solver contexts. This read-only replay does not load native code or create
a second adoption observation. The exact-source CI adds the new focused tests,
the full four-type qualification and this replay as an independent step; all
original steps remain. The existing upload step retains the new receipts and
failure logs inside its original output root.

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
