# HIA P0–P7 full-cost comparison — research-only gate

This independent, bounded arithmetic gate compares observed execution cost of
four complete strategies on the same registered trial set and candidate-bank
identity: `baseline`, `fixed`, `dp` and `ndu`.

## Reproduce

Run `python -B -m unittest tests.test_hia_full_cost_gate -v`.

For an independently collected JSON file, run:

```sh
python -B tools/qualify_hia_full_cost_gate.py \
  --input /path/to/registered-observations.json \
  --output /new/report.json --require-positive
```

Input is strict immutable UTF-8 JSON of at most 256 KiB. The output path must
be new; no overwrite is permitted. Without `--require-positive`, a *negative*
valid result is still preserved and exits zero for evidence collection.
With that flag, a negative economic result exits nonzero.

## Exact contract

The input schema is `hepta.hia.full-cost-comparison.v1`. Require a frozen
source, objective, hardware, workload and candidate-bank digest; a generation;
8–128 ordered registered trials with input and reference-result digests; and
exactly four strategy arms. Every arm must contain all registered trials,
matching inputs/results and candidate-bank ID. Every arm also records the
same nonzero observer identity.

Each arm must supply the exact integer nanosecond costs
`toolchain`, `dependencies`, `controller_build`, `candidate_build`,
`calibration`, `search`, `verification`, `measurement`, `publication`,
`switch`, `rollback`, plus each trial's `execution_ns`,
`controller_ns`, `failed_attempt_ns`, `peak_rss_bytes`, `p99_ns`,
and `completed=true`. These are not independently authenticated
measurements. A cost of zero is only valid if genuinely non-applicable and
established by external evidence. Unmeasured categories belong in
`unknown_costs` and block economic admission. Missing, malformed, duplicate,
skipped or result-mismatched trials reject the entire comparison.

Observed complete cost is one-time cost plus all execution, controller and
failed-attempt costs for all registered trials (no sample trimming). NDU
must beat the *cheapest* of baseline, fixed and DP by both registered positive
absolute and relative margins, and remain within observed RSS/p99 limits.
Otherwise `economic_scope_positive=false`. Observed-scope positivity is
**not** a confidence interval, future amortization guarantee or independent
NDU scientific advantage: the gate cannot establish preregistration,
independent observation identity, proof validity, hidden-test generalization,
safety or development-time economics by itself.

Every report contains `authority=DENY_ALL`,
`safety_certificate=false` and `production_activation_allowed=false`.
The new gate does not alter the canonical HIA verifier, LLVM emission,
native approval, NDU Rust algorithms or artifacts.

## Production blocker ledger

| Phase | Remaining blocker | Status |
| --- | --- | --- |
| P0 | Whole HIA Core / checker / independent Rust / LLVM semantics refinement and exact-head integration | OPEN |
| P1 | General owner, loan, cancellation, host failure and resource proof beyond existing finite profiles | OPEN |
| P2 | Native target ABI, lowering, actual independent machine code and external hardware evidence | OPEN |
| P3 | General C pointer/alias/ABI translation and representative maintenance costs | OPEN |
| P4 | Complex C++ exception/RAII/ABI and a representative library maintenance cycle | OPEN |
| P5 | Repeatable **positive** complete net optimization benefit against strong compiler controls | OPEN |
| P6 | Genuine positive NDU incremental advantage under equal candidate bank, information and total budget | OPEN |
| P7 | Hidden Agent tasks, human time, physical CPU/RSS/p99, generation/rollback and production qualification | OPEN |

A green synthetic unit test is not a real P5/P6 benefit observation. Historical
negative HIA optimization and NDU controls remain negative and must be retained.
This branch is additive and must not bypass the already existing, independent
safety, source-binding, native and execution gates.
