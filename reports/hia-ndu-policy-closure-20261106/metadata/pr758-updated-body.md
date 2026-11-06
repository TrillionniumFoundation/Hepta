## Problem

Round 6's unit-discount linear cost experiment correctly tied after ordinary planning. That experiment cannot distinguish numeric preference wiring, feedback modeling, solver error, and runtime costs.

## Changes

- Preserve the degeneration control and add hand-calculated non-dominated action reversals.
- Use unchanged source-pinned native NDU at every Bellman decision backup, before action selection, with explicit eligible abstention.
- Add an immutable observed-state interface, hidden future request generation, a physical one-slot native cache executor, and complete partial-failure/cleanup cost records.
- Compare fixed, state-greedy, ordinary MPC, same-objective, fixed-preference NDU, dynamic NDU, and an independently encoded exact oracle. Add a bounded compute gate.
- Freeze three environments and 288 primary cells, retain all model/real-workload observations and every failed denominator, and diagnose deliberate model errors separately.
- Add independent adversarial tests and a native CI workflow that fails if original-source access or native execution is unavailable.

## Completed validation and immutable evidence

This PR head is `78c0b951adc08b02be60d64b386620c5ac9faf99`, tree `a96e501429fa0482330c7d5d477f8549a132bd52`. The original feedback cohort remains bound to `b1746d3e436f001ea5c69d154d766fadf7231136`; the coverage, physical witness and compute-price cohorts are bound to `78c0b951`. Their original identities have not been rewritten.

- Original feedback cohort: 288 episodes / 864 requests completed. Preserve the 216 zero-change numerical-preference counterfactuals and other negative controls.
- Finite state coverage: 5,736 / 5,736 registered states passed, with 167,976 retained original-native calls. Dynamic NDU, the ordinary same-objective controller and exact oracle agree.
- Physical witness cohort: 43 / 43 actual native-cache executions passed. The two numerical-preference triples consumed different selected actions and checked all workload outputs.
- Compute-price cohort: 120 episodes / 360 requests completed. The priced dynamic arm skipped native planning on all 72 decisions and performed zero original-native value calls. This is a stopping result, not an NDU-exclusive gain.
- [Native feedback CI run 42198653917](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42198653917): success on this exact head, 158 unique tests, zero failures/errors/skips, real upstream builds, native reversals, actual workload execution, and identical clean source before/after.

[Complete evidence and verified restoration instructions](https://github.com/TrillionniumFoundation/Hepta/blob/e51de7a422988e69ddecaceba595e62b7d051507/reports/hia-ndu-four-gates-20261106/README.md) retain the raw cohorts, original CI artifact/log, source and build bindings, independent reviews, and historical failures. Evidence commit `e51de7a422988e69ddecaceba595e62b7d051507` has this source head as its sole parent and does not change this PR's source.

## Findings and follow-up

All 24 strict numerical-preference action reversals are in the supplied-boundary grid; none occur in the 2,716 natural states collected under the registered owner policy. Supplied witnesses establish wiring and dispatch, not a natural-distribution benefit. The historical no-adaptation arm changes belief and numerical preference together; its original state-information label must be interpreted as a joint ablation.

[Follow-up draft #761](https://github.com/TrillionniumFoundation/Hepta/pull/761) preserves these results and adds all-legal-action reachability, complete-policy evaluation, a pure belief-only intervention, and one ex-ante strongest fixed policy per profile. It has a separate source freeze and evidence boundary.

This PR remains Draft with research authority `DENY_ALL`. Numerical wiring success does not establish unique NDU benefit, physical net benefit, production admission, a parameter-gradient method, or FBSDE training. Repository-wide Actions are not certified all-green here; the unresolved host-run status is recorded separately from the successful NDU feedback workflow.

