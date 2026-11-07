# Explicit HIA Agent macro policy

## Implemented boundary

`hepta.hia_agent_macro_policy.advise_macro` is an explicit **caller-side**
controller. An Agent supplies its context, a bounded cost ledger and complete
macro-action plans. The controller calls the existing original native NDU value
entry point through `hia_ndu_optimizer._native_rank`. That adapter verifies the
build receipt and executable identity and runs the sealed native image. The
response binds the exact request and upstream implementation.

The available macro actions are `discover`, `propose`, `verify`, `emit`,
`evaluate`, `adopt`, `use`, `rollback` and `stop`. The controller recommends only
the first action of a supplied finite plan. It does not generate source, run
compiler optimizations, execute a tool, or grant adoption permission. Every
actual `hia_*` tool still owns its existing proof, budget and state checks.
This sidecar is deliberately not called from `hia_emit` or native lowering.

The native bridge is **required** for NDU advice. Missing or rejected bridges
produce a retained `BLOCKED` outcome; there is no ordinary-planner fallback
labelled as NDU. The existing bridge is a scalar cost evaluator. This integration
does not establish a new multiobjective, risk-sensitive or stochastic NDU model.

## Reproducible state and cost accounting

The immutable input uses schema `hepta.hia.agent.macro-state.v1`:

| Field | Meaning |
| --- | --- |
| `context_sha256`, `objective_sha256` | Frozen tool context and optimization objective |
| `agent_sha256` | Model, prompt, tools and generation settings identity |
| `installation` | Exact worker, backend and catalog SHA-256 identities |
| `generation` | Nonzero bounded policy generation |
| `budget` | Original lifecycle wall-time and model-token allowances |
| `ledger` | Every completed, failed, rejected or uncertain attempt |
| `stop_remaining_ns` | Forecast remaining cost of retaining the incumbent |
| `plans` | At most sixteen explicit plans, each ending in `stop` |

Each plan contains `id`, `actions`, `remaining_cost_ns`, `uncertainty_ns`,
`model_tokens` and `support_sha256`. The forecast covers the complete remaining
sequence; uncertainty is added conservatively. The full state and each plan
are bound into the native request. A forecast is never counted as observed
future benefit.

Each ledger entry contains `id`, `phase`, `status`, `wall_ns`, `model_tokens`
and `receipt_sha256`. The finite phases are:

`setup`, `discovery`, `model`, `search`, `verification`, `emission`, `evaluation`,
`adoption`, `rollback`, `future_use`, `controller`.

Use one entry per disjoint attempt in a serialized experiment. Charge the
outer elapsed interval once; keep nested native/checker timings in the source
receipt instead of charging them again. Losing search, malformed submissions,
timeouts and refused adoption remain charged. Token usage must come from the
actual Agent/provider receipt. Unknown values remain `null` and block advice;
they cannot become zero. Duplicate event IDs or receipt hashes are rejected.
Caller reports are evidence inputs, not authenticated measurement attestations.

Every invocation returns a new state with its actual controller cost appended,
including blocked/rejected native attempts. Callers must continue from that
`next_state`. The function subtracts spent costs before native admission and
checks the remaining budget again after the native call. It does not renew the
original allowance. These are measured admission guards, not hard physical
real-time guarantees or an unforgeable server quota; the runtime remains the
authority for actual execution and adoption.

The existing `hia_evaluate` cost-ledger v1 is a **prefix**, not a complete input
to this policy. It explicitly leaves model/adoption/future-use costs unknown and
includes unattributed discovery reads. A client must retain and attribute those
actual external receipts. Do not copy expected invocations into measured
`future_use` or silently set missing model costs to zero.

## Explicit execution

```sh
python tools/hia_agent_macro_policy.py advise \
  --input /absolute/state.json \
  --native-binary /absolute/source-bound-ndu \
  --native-build-receipt /absolute/build-receipt.json \
  --output /absolute/new-advice.json
```

The native executable and receipt follow the existing
`tools/build_hia_ndu_bridge.py` interface and unchanged upstream pin. Passing no
native image writes a `native_bridge_unavailable` result and exits 2. Output
creation is exclusive and mode 0600. Advice never triggers its recommended
action automatically. Installing this sidecar does not deploy a new MCP tool or
make any tool available in a hosted Agent gateway.

## Same-Agent, same-budget real-task acceptance

`assess_macro_comparison` consumes a separately frozen
`hepta.hia.agent.macro-comparison.v1` report with four arms:

- `fixed`: fixed macro-action schedule;
- `greedy`: one-step value/cost scheduling;
- `ordinary`: ordinary learned/router/search controller;
- `ndu`: original native NDU macro controller.

All arms bind the same Agent identity, task registration and original budgets.
Register at least eight tasks in canonical ID order. Each task binds an input,
a qualification kind and a qualification receipt. The registration SHA-256 is
the canonical digest of `agent_sha256`, `objective_sha256`, `budget`,
`task_inventory` and `minimum_gain_ns`; changing the task inventory invalidates
it. Retain an observation for **every planned task**, including failures.

Each observation retains status, correctness, result evidence, the full ledger,
a declaration for every cost phase and native NDU receipt hashes. A phase that
was not performed needs an explicit evidence-backed declaration; absence is
not zero. Actual Agent model calls and downstream execution must be observed.
Every NDU task needs a native value-evaluation receipt. Full observed cost must
beat the best of all three controls by the registered absolute margin, while
all task and budget checks pass. Budget overruns and failures remain visible in
the verdict rather than disappearing from its denominator.

```sh
python tools/hia_agent_macro_policy.py assess \
  --input /absolute/registered-observations.json \
  --output /absolute/new-comparison-verdict.json
```

Synthetic fixtures always produce a nonpositive real-task verdict, even if
their arithmetic makes NDU cheaper. A successful NDU call, process exit or
advice receipt is never a benefit claim. A positive reported arithmetic result
is kept separately as `reported_arithmetic_positive`. This hash-only assessor
always emits `observed_scope_positive=false`, `economic_benefit_established=false`
and `p1_acceptance=HOLD`, because it cannot authenticate the original provider,
task and native receipts. Merely relabelling a synthetic fixture as a real task
cannot turn its CLI exit into a P1 pass. Independent review of the actual
referenced receipts and task outcomes remains necessary; this assessor cannot
establish statistical generalization or authorize production adoption.

## Current qualification

Unit tests exercise admissions, original native-adapter invocation plumbing,
rejection accounting, same-Agent/budget/task binding and adversarial comparison
inputs. Process-boundary mocks in those tests are explicitly fixtures. The unit
test count does not establish a native value or task-value campaign. A separate
source-bound native smoke receipt, when present, establishes only the actual
adapter mechanism. This change includes no measured real-task NDU win. P1
economic closure remains open until actual
qualified Agent tasks, source-bound native executions and complete external
costs are supplied and independently checked.
