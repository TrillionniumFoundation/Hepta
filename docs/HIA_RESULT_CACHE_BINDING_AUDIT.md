# Result-cache follow-up: matched models and source binding

The retained first pilot executed source `b89e881a51eed933e93ee79bdace91bb5433848f`.
This follow-up does not rewrite its protocol, clocks, service totals or evidence.
The negative NDU economics and `p1_closed:false` remain valid descriptions of
that finite observation. A new unified run must register its own new source.

## Required preceding source

Between the combined baseline `b47ce924c5941b42448e9da0b07a2bcedaf75d1f` and the
pilot parent `cd5361b57faafea6f98d42066687bb81dab98d7e`, the only relevant runtime
change is the preparation/epoch-aware gate in `hepta/hia_ndu_dynamic.py`:

- `d236c807329570fe6e95fedf362b96589e47fb8d`: bound, gate, tests and explanation;
- `09dc91a8d506d64aecacea16202e30f6e182bb48`: matching protocol wording.

The HIA source frontend, LLVM emitter, native image sealer, dynamic qualification
driver and Rust adapter are unchanged across those bases. The API would import
with the old gate, but its decisions and the declared preparation-aware protocol
would differ. Include the two source commits for an honest composition. The old
26 MB `cd5361b` evidence commit is not a source dependency. The unchanged native
adapter can reuse its pinned binary only while its complete adapter inventory
and build manifest still match; its historical build cost remains charged.

## What identical candidates means here

The pilot's original paired control tested one training model. Online beam and
NDU models have separate measured controller estimates and elapsed costs, and
may have different ready states. Their independently materialized candidate
sets are not automatically identical merely because the candidate grammar and
executor are shared.

`audit_hia_result_cache_matched_models.py` reads all actually submitted NDU
models and their original raw request/response frame bindings. For each model,
it invokes beam using that exact model and the original pinned native image.
It independently validates the original NDU response and compares complete
plan dictionaries and selected first actions. This is a counterfactual pairing
for every actual NDU request, not a claim about identical original online arms.

The new runner also performs this audit after service and the exact-state audit.
Its time is included in total campaign cost but never fed back into execution.
The standalone audit reports its own interval and the sum of the two measured
work intervals; that sum is not elapsed time between separate runs. It also
reports one allocated full historical bridge build separately. No source,
workload, cost calibration, old output or old timing is rerun or overwritten.

## Original identity limits and the next-run correction

| Item | Original pilot | Strengthened runner |
| --- | --- | --- |
| Git state | Clean tracked status at registration; no final HEAD/tree/status observation | Complete status including untracked files; HEAD/tree and status checked before work, before holdout, after audits and after close |
| Source bytes | Selected driver/protocol and entire flat Hepta Python package plus Rust adapter before/after | Same source inventory plus complete clean Git state at all checkpoints |
| Protocol | Parsed object and file inventory recorded separately | Exact parsed raw-byte digest tied to registered file identity |
| Planner | Exact sealed image checked against each process's build manifest | Actual image also compared with the registered image; binary and manifest paths/bytes rechecked at all checkpoints |
| Clang/Python | Initial Python identity; Clang receipt; no final combined tool check | Registered tool identities rechecked; compiler receipt path/hash must match registered Clang |
| Registration/training/ELF | Registration hash recorded; final ELF checked | All three rechecked through an append-only observation history; an observed mismatch cannot be erased by restoring bytes later |
| Full dependency closure | Not established | Still not established for transitive Python packages, loader, libc or host |

The first pilot cannot retroactively acquire missing checks. Archive hashes
bind the evidence retained now; they are not a historical proof that HEAD,
protocol or a tool path was continuously unchanged. `sources_unchanged` from
the old report must be read in its selected-inventory scope.

The stronger checks are observations on an isolated trusted host, not atomic
custody against concurrent mutation followed by restoration between checks.
Use a separate worktree that no other process advances. Keep output outside
that checkout. A changed binding is a failed qualification even if all workload
outputs happen to match.
