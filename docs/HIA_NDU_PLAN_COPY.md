# Finite NDU plan-witness copying

## Scope

The full-cost v2 request builder previously used generic `deepcopy` for every
internally generated witness. A local profile across three sweeps of the 256
registered finite models attributed 0.309 of 0.748 instrumented seconds to
`deepcopy` (profiling is diagnostic, not the timing result below).

`_copy_plan` now copies the plan/action dictionaries, all five action string
lists, and each scalar cost dictionary directly. Other generated fields are
immutable scalars. Runtime shape/type guards fall back to `deepcopy` for new
structural fields or mutable leaves, avoiding silent aliases after schema evolution. This helper is private and receives only internally generated
plans, never raw input. Bounded public model admission is unchanged. Each plan
has independent mutable containers, including when continuation actions were
shared inside the planner. Tests guard the generated schema's mutable fields
and mutate a returned witness while checking sibling plans and planner reuse.

No recurrence, search counters, tie order, model limits, request fields, native
selection, deadline checks, performance threshold or production authority changes.
The existing controller-budget work remains separate.

## Retained observation

The registered baseline is PR #564 source
`68c04f9168ee3ce2176c64b1f6fb4b431a6043aa`, with `hepta/hia_ndu_cost.py` SHA-256
`e5ba69bcb9ac9fa78c6cd216e76e9abaa3bd850df1a8c8add7ce160bdfae0142`.
The benchmark refuses any other baseline bytes before executing them. Registration
pins the seed, 256 cases, one warmup sweep, eleven alternating-order rounds and
no sample exclusions. It does not specify a speed threshold or establish a
confidence interval. It was registered before the comparison/timing run.

For all 256 supplied finite models, complete snapshots, exact witnesses/search
counters and complete request/plan/support bytes match the baseline. Independent
exhaustive schedule enumeration also matches every committed and uncommitted
first-action minimum. Caller inputs are unchanged.

Observed medians per 256 complete public request-building calls were
76,169,932 ns baseline and 62,448,277 ns candidate: **18.01% lower preparation
wall time**. Total sweep time fell 14.20%. All 22 raw samples, source hashes,
per-case checks, host/Python identity and registration are under
`evidence/hia_ndu_plan_copy/final/`. The deterministic corpus is generated from the
pinned protocol and its canonical digest is retained in the result; rerunning
also writes the full corpus. Timing is host-dependent and needs replication.

Two development observations are retained separately: `development-unguarded`
measured the initial schema-dependent implementation (24.75% median reduction),
and `development-guarded` measured the guarded implementation before the final
fallback tests were added (16.85%). Neither is substituted for the final
source-bound observation above; no samples were discarded from any run.

The focused NDU suite ran 257 tests: 164 passed and 93 existing native-dependent
skips, no failures or errors. This is not a complete native qualification.

These are genuine Python wall-clock measurements over supplied model fixtures,
not native Rust timings, real application workloads, Agent productivity or
positive full-lifecycle NDU value. No native invocation occurs in this study.
All P0–P7 qualification gaps remain open; `authority=DENY_ALL`,
`safety_certificate=false`, and production activation remain unchanged.

## Reproduce

From a checkout with the baseline commit available:

```sh
git show 68c04f9168ee3ce2176c64b1f6fb4b431a6043aa:hepta/hia_ndu_cost.py > /tmp/ndu-cost-baseline.py
python tools/qualify_hia_ndu_plan_copy.py --baseline /tmp/ndu-cost-baseline.py --output /tmp/ndu-plan-copy-new-run
python -m unittest discover -s tests -p 'test_hia_ndu*.py'
```

Use a new output directory per run; never overwrite a previous observation.

## Latest-base compatibility check

Before publication, #564 advanced to
`ab1c1a50b77a0d9f2da14a86b418f60985fbfe28`. Its nine changed provider/experiment
paths do not overlap this patch; the NDU baseline implementation remains
byte-identical to the registered baseline. The change rebased without conflict.
A complete repeat on that rebased source again passed all 256 model comparisons
and the same 257-test suite (164 pass, 93 native-dependent skips). Its separately
retained `rebased/` observation measured 82,363,551 ns versus 65,466,957 ns per
256-call sweep, a 20.51% median reduction. This repeat does not replace earlier
observations. Independent review also found no blocking issue and reproduced
the bounded Python-preparation improvement. Native/full-lifecycle claims remain
excluded.

## Regression registration

The plan-copy module is explicitly included in `qualify_hia_composition.CORE_TESTS`
and the PR-triggered verified-optimization workflow's no-skip planning controls.
A composition identity regression checks that the module is registered exactly
once and resolves at least its four controls. The focused composition/cost/copy/
snapshot checks pass 31/31 with pinned Z3; the final NDU discovery again reports
164 pass and 93 native-dependent skips. Logs are in `registration/`.

This registration does not retroactively qualify earlier workflow runs. The PR
workflow still requires its native bridge setup before reaching those controls;
a prior setup failure means the controls did not execute. Full composition is
separately triggered and requires its complete native/formal toolchain.
