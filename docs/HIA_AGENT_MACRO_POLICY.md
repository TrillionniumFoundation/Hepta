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

## Executable four-arm campaign

`tools/qualify_hia_macro_campaign.py` now runs a frozen eight-task, four-arm
campaign through the actual `HIAAgentService` tool domain. Its checked-in task
author is a **deterministic fixture**, not an Agent or provider. The task corpus
is eight wrapping-u8 programs with independently specified expected results on
all 256 inputs. All arms use the same constructor, registered task input bytes,
original wall/token allowances, installed worker and tool catalog. A fixed
rotation counterbalances execution order. Every planned task remains in the
result, including refusal, timeout, partial execution and exhausted budget.

The decision occurs **before candidate search**. Each arm has observed the
incumbent's complete native batch and the measured baseline import, proof and
emission costs. It then chooses between retaining that incumbent and the finite
`propose → verify → emit → evaluate → adopt → use → rollback → stop` continuation.
An invalid search attempt is recorded before the decision, so losing-search
costs remain visible even when the controller stops. Every selected continuation
still passes the original tool admission, proof, evaluation and adoption checks.
A separate subsequent native batch verifies actual future use against every
registered expected result. Forecasts never replace that observation.

| Arm | Implemented probe policy |
| --- | --- |
| `fixed` | Search and evaluate the registered candidate, then adopt if permitted |
| `greedy` | Compare the next import cost with incumbent use, ignoring later stages |
| `ordinary` | Deterministic argmin of the complete supplied conservative costs |
| `ndu` | Use the original source-bound native NDU value ABI on those costs |

The ordinary arm is a strong scalar-cost heuristic for this narrow probe, but
it is **not the requested ordinary learned/model controller baseline**. Search
forecasts extrapolate measured baseline stages. Candidate-use cost uses the
previous incumbent batch as a proxy, while transition cost and uncertainty are
explicit uncalibrated fixture estimates. This preserves a falsifiable native
mechanism experiment; it does not establish learned dynamics, useful task
selection, real Agent search behavior or a measured NDU economic advantage.

```sh
python tools/qualify_hia_macro_campaign.py run \
  --output /absolute/new-campaign-directory \
  --native-binary /absolute/source-bound-ndu \
  --native-build-receipt /absolute/build-receipt.json

python tools/qualify_hia_macro_campaign.py verify \
  --bundle /absolute/campaign-directory
```

The destination must not already exist. No tool deploys a gateway, changes a
production adoption slot, invokes a provider or pushes a repository. Each task
uses a private disposable worker state. The source-bound NDU executable and its
original build receipt are retained as bounded original bytes. The existing
adapter still performs build/source/binary admission before executing a sealed
image. A missing bridge yields retained blocked advice with zero native NDU
evaluations; there is no Python substitute labelled as NDU.

`run` exits zero only when every planned native task arm is correct and every
NDU arm actually evaluated natively. That outcome is `native_mechanism_complete`,
not P1 acceptance. `verify` exits zero for valid original evidence and explicitly
reports failed/incomplete task arms. Both commands always report
`p1_acceptance: HOLD` and `economic_benefit_established: false` for this fixture.

### Original evidence and cost boundary

The directory contains an immutable `registration.json`, `campaign.json`,
`verdict.json` and a content-addressed `objects/` store. Objects retain exact
artifact bytes, canonical application request/response receipts, task inputs,
source snapshots, controller state, native advice and normalized native child
reports. This in-process experiment does not claim to retain raw hosted MCP
transport streams or child stderr streams that the existing runner API does not
expose. Local object hashes establish byte integrity, not independent author
or provider authentication.

Each event records its task/arm/phase, original tool calls, output or exception,
monotonic start/operation-start/end offsets, status and cost. Intervals are
contiguous and nonoverlapping. Time spent serializing an event is charged to the
following interval. The final close event ends at worker closure; result export,
campaign setup and worker-directory cleanup are reconciled separately as
campaign overhead. Final manifest/verdict export and module imports preceding
the campaign clock are explicitly excluded. Historical NDU provisioning is
retained as a build receipt, not silently charged as new current-budget spend.
These bounds are disclosed rather than called complete real-Agent economics.

The journal records no provider invocation for this fixture. Its measured
script model-token consumption is zero; real Agent tokens and provider cost are
separately **unknown**. Phase inventory declares model work not performed and
the real-task comparison assessor therefore refuses qualification. Session or
chat token estimates are not provider usage receipts.

The verifier checks all original lengths and hashes, registration, the frozen
execution order, task provenance, complete worker-source binding, event/ledger
cost equality, timeline continuity, phase inventories, the exact ledger prefix
consumed by each decision, candidate-search ordering, forecast support from
preceding observations, NDU request/response/build/executable bindings and all
actual native output values. Rehashing edited event costs cannot bypass the
cross-receipt checks. Symlinked, hardlinked, missing or changed objects are
rejected. Individual objects are capped at 8 MiB and the complete original-byte
store at 256 MiB. This is an evidence-consistency check, not remote attestation.

### Remaining real-Agent gate

The existing provider diagnostics remain separate:
`tools/qualify_hia_agent_provider.py catalog` / `probe` require a real configured
`--codex` executable and explicit model selectors. An available catalog is not
entitlement or a task success. A real campaign needs original provider event
streams, provider-reported usage validated through
`hia_agent_codex_transport.checked_usage`, exact model/prompt/tool/settings
identity, independent real-task qualification and the same frozen budget in
all four arms. Unknown usage must stay unknown. Old fresh-Agent runs with
`null` costs cannot be substituted into this campaign.

Native campaign success closes the executable mechanism/evidence gap only.
P1 still requires real qualified Agent tasks, calibrated full-cost forecasts,
a strong ordinary Agent controller, repeated measurements and observed
advantage over **every** control under the registered budgets. Unit tests,
source CI, native advice, a favorable one-run timing or a successful process
exit do not close that gate.

### Actual provider mode

`qualify_hia_macro_campaign.py run` also accepts `--codex ABSOLUTE_EXECUTABLE
--model OBSERVED_SELECTOR --model-tokens ORIGINAL_ALLOWANCE`. The same provider
identity, selector, reasoning configuration and prompt constructor are frozen
for all four arms. Each arm makes one fresh ephemeral call that returns both a
complete candidate and an ordinary macro choice. The ordinary arm follows that
original choice; the fixed, greedy and native NDU arms apply their respective
policies to the same disclosed information. Candidate bytes are admitted and
checked by the actual tools only if that policy searches. The reference fixture
candidate and future results never enter the prompt. This is one-step model
proposal/control integration, not an unconstrained multi-step autonomous Agent.

The model phase owns exact `stdin.raw`, `stdout.raw`, `stderr.raw`, complete
process metadata, the original request, configuration and all five reported
usage fields. Raw streams are retained as bounded content-addressed chunks.
The verifier reconstructs those original bytes, reparses their event order,
rejects model-created tools, binds the actual invoked executable/selector to
the frozen provider, compares the returned proposal/choice with the receipt,
and reconciles usage and process time with the outer chargeable interval.
Unknown usage stays null even on a failed response. A provider quota error or
uncertain process cleanup stops subsequent provider launches; the planned task
rows remain in the denominator. There is no model/account selection search,
provider retry, prompt repair or guessed startup-warning exception.

The token allowance uses the inherited conservative convention `input_tokens
+ output_tokens + reasoning_output_tokens`; original counters are retained,
and overlap is not asserted. The CLI's usage is only available after generation,
so this is an observed budget check rather than a claimed hard token-generation
cap. An observed overrun fails the task and remains charged. Provider wall time
is nested evidence inside the model phase and is never added twice. Prices,
invoices, real task qualification and independent origin authentication remain
unknown; actual provider integration cannot by itself turn P1 into PASS.

A complete campaign invocation is:

```sh
python tools/qualify_hia_macro_campaign.py run \
  --output /absolute/fresh/provider-campaign \
  --native-binary /absolute/hia-ndu-bridge \
  --native-build-receipt /absolute/build-receipt.json \
  --codex /absolute/codex --model OBSERVED_SELECTOR \
  --model-tokens 32768 --wall-ns 180000000000
```

Use the selected model only after a current independent availability probe.
If that probe observed allowed startup warnings, provide their exact JSON
array using `--registered-warnings`; do not invent a warning or change user
configuration to silence it. This mode currently uses the existing owned-process
transport on the same host as the coordinator. That transport requires
`waitid(..., WNOWAIT)` and fails closed before launching when it cannot guarantee
ownership. A remote shell wrapper or a copied old provider result does not
satisfy the same-run time/cleanup contract.

`tools/hia_macro_codex_provider.py` can execute a single provider transport
smoke request from explicit task and prior-state JSON files. It writes a separate
registration and actual raw response; it never appends that diagnostic to an old
campaign or calls it a real task outcome. Its inputs are `--task`, `--state`,
`--codex`, `--model`, `--output`, `--wall-seconds` and `--tokens`.
