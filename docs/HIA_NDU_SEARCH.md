# Finite HIA proposals and native NDU comparison

## Candidate construction

`hepta.hia_finite_actions.propose_candidates(document, function=..., max_candidates=8)`
reuses the canonical HIA verifier and accepts a public total scalar function with
acyclic control flow. It emits a finite deterministic recipe list:

1. Remove scalar identities.
2. Fold scalar constants using the existing executable HIA semantics.
3. Reassociate one wrapping-add chain with constant operands.
4. Remove dead total operations.
5. Apply the frozen combinations of those recipes.

Duplicate canonical programs and unchanged-baseline proposals are removed.
The input and all unselected functions are preserved. Block-edge arguments and
return uses are updated with local substitutions. Trapping operations, resource
effects, calls, and loops reject this proposal profile. In particular an unused
checked addition cannot be silently removed because its trap is observable.

Each result contains only `id`, `action`, and `program`. A candidate is not an
approval, behavior proof, or predicted performance improvement. The independent
translation validator must prove the actual program pair before admission.

## Actual native paired comparison

`tools/qualify_hia_ndu_search.py` freezes its protocol before running builds. The
fixed control workload computes wrapping `x + 12` and contains identities,
constant expressions, a reassociable chain, and dead total operations. Modern
LLVM may already remove these redundancies; identical optimized artifacts and
no incremental gain are valid outcomes.

The harness:

- Builds actual shared libraries with the existing direct LLVM/Clang path.
- Independently proves every candidate before measuring it.
- Compiles a C driver that repeatedly invokes the u64-to-u64 function in a
  native loop, avoiding Python-per-call overhead.
- Checks native checksums against a frozen independent formula oracle.
- Retains wall/CPU timing, context switches, page faults, checksums, stderr,
  failure rows, exact artifact hashes, proof receipts, and source identities.
- Uses seven counterbalanced training trials and seven holdout trials, fixed
  seeds, 200,000 measured calls and 20,000 warm-up calls per sample.
- Gives fixed-recipe, seeded-random, exhaustive-observed and native-NDU selectors
  the exact same finite candidate table, trial inventory, and 60-second search
  budget. This is **paired replay of one shared observation table**, not an
  evaluation of sequential learning or adaptive sample acquisition.
- Charges all losing-candidate generation, compilation, proof, and measurement
  costs. Shared costs are divided with upward rounding, so a few nanoseconds
  can be overcharged; they are never silently omitted. Policy overhead is
  separately measured. The incumbent already exists.
- Uses a conservative no-regression gate: incumbent runtime lower bound versus
  candidate upper bound plus search cost. A policy may select the incumbent.

The empirical uncertainty radius is the maximum absolute per-call deviation
from the observed median, rounded upward to integer nanoseconds, with a
one-nanosecond minimum. It covers observed asymmetric outliers. It is a
conservative operating rule, **not a statistical confidence guarantee**. The
raw samples remain available for independent analysis. Failed samples are not
removed and there are no best-of-retry measurements.

The NDU decision comes from the pinned original native evaluator through
`hia_ndu_optimizer.rank_candidates`; the harness does not replace it with a
Python scoring imitation. `selected_id` is checked against the returned exact
program before the selected artifact is measured on holdout inputs.

```sh
python tools/qualify_hia_ndu_search.py \
  --clang /absolute/path/to/clang \
  --bridge /absolute/path/to/hia-ndu-bridge \
  --bridge-build-receipt /absolute/path/to/build-receipt.json \
  --artifacts /new/artifact-directory \
  --output /new/search-evidence.json
```

`qualified_for_finite_paired_replay` means the specified mechanism ran on actual
native artifacts, with all required proofs and samples. It does not establish
general NDU advantage, superiority over Rust/LLVM, or global optimality. A
single frozen control workload is insufficient for those claims. The report
retains negative results and explicitly withholds them.
