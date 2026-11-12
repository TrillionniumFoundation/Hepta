# Complete-policy attribution after the NDU feedback gates

This follow-up preserves the original feedback model, protocols and negative
physical results. It fixes three interpretation gaps using a separate,
prospectively frozen finite-model audit. It does not change production routing.

## Why the extra audit is needed

The earlier natural-support inventory enumerated every request/signal tape
under one registered owner policy. A different controller can take a different
action, consume different resources and reach states outside that inventory.
The new graph branches over **every legal action prefix** for the same 54
initial profiles. Explicit abstention terminates a prefix. Distinct states are
deduplicated while each action retains its complete observation distribution.
The structure-only preflight found 10,224 states and 18,624 observation edges;
no policy values or timing results were used to change the profiles.

Action alternatives do not have probabilities until a policy chooses one.
Summing probability mass across those alternatives would create a fictitious
distribution. These state counts are coverage counts, not independent samples.

The earlier `no-adaptation` controller jointly resets the posterior and freezes
numerical preferences. Consequently its historical `state_information_value`
flag measures a **joint ablation**, not an isolated information effect. The
original evidence and v1 schema remain unchanged. This audit adds a
`prior-belief-only` controller which resets only the posterior and keeps the
dynamic numerical preference rule. It records the full two-by-two comparison:

| Belief used by the controller | Dynamic numerical preferences | Fixed numerical preferences |
| --- | --- | --- |
| Current public posterior | Dynamic NDU | Fixed-preference NDU |
| Initial prior | Prior-belief-only | Historical joint no-adaptation |

The evaluation environment always uses its original law and the same external
dynamic objective. An incorrect controller forecast never changes the law used
to judge that controller. Belief effects, preference effects and their
interaction are reported separately.

## Full-policy value and the fixed comparator

First-action conditional regret answers what happens if the controller chooses
the current action and the oracle takes over afterwards. The new evaluator
instead continues to use **the same controller at every subsequent state**.
It computes the external reward, discount and conditional downside functional
independently from the planner. Exact rational probabilities and integer Q32
rounding preserve the original finite objective. Before the first observation,
all controllers use the same probability mean of the conditional root values;
there is no extra root risk transform.

Both forms of regret remain available. A zero first-action regret does not
imply a zero whole-policy regret. Expected deliveries and resource cost are
also reported, including missing requests after abstention.

All three fixed actions are evaluated as complete policies, including their
existing feasibility fallback. The strongest fixed comparator selects one of
these policies once per initial profile by its ex-ante external value. It never
selects a different fixed policy for each observed state. This is an exact
known-law model reference, distinct from the earlier fixed policy selected by
training-sample pathwise reward. Every candidate's selection and evaluation
work is retained.

## Source, execution and costs

The protocol is `benchmarks/hia_ndu_feedback_state_coverage/POLICY_PROTOCOL.json`.
The runner is `tools/qualify_hia_ndu_policy_audit.py`. Freeze requires clean,
committed source and the admitted original-native binary and build receipt.
The complete scenario, graph and denominator inventory is checked again before
the formal run. Per-decision and per-arm search allowances remain 20,000 and
20,000,000 expansions respectively.

Both native arms call the original source-bound NDU backend for every
registered state and every Bellman backup. A scalar substitute cannot qualify
as native execution. Raw native exchanges, attempt journals, complete state
tables, source identities and failed or unexecuted cells are retained. The
independent whole-policy evaluator never supplies values to an online decision.

Measured audit wall includes graph construction, planning, validation, logs,
whole-policy evaluation, fixed selection and native startup/cleanup. Nested
components must not be added again. This audit is not a new physical latency
cohort; it reuses the original admitted binary and preserves its build receipt.
Historical failed build and measurement costs remain in the earlier evidence.
Unknown historical engineering, physical energy and monetary costs remain
unknown.

The earlier compute-price bound keeps model workload resource transitions and
subtracts forecast future computation from utility. Its future resource bound
does **not** deduct that computation from budget/deadline states. It is therefore
a forecast admission model, not a hard real-time guarantee. Its observed
all-greedy stopping result is preserved and cannot establish unique NDU value.

## Acceptance boundary

Passing this audit establishes complete finite reachability, correct attribution
and complete-policy arithmetic for the declared profiles. Any zero preference
effect, ordinary-controller tie, loss or incomplete delivery remains a result.
It does not establish unknown-kernel learning, trained continuation accuracy,
parameter gradients, a general FBSDE solution, physical net benefit or
production admission. `U` and `Z` are not used as parameter gradients.

All research authority remains `DENY_ALL`. A negative result resolves the
decision about this candidate; it does not satisfy an unproved superiority
claim.
