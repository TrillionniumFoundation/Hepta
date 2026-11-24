# Agent planning, budgets and complete cost evidence

The native Agent executes explicit caller requests under frozen context,
objective, workload and resource policies. Its cost, journal, evaluation and
adoption owners retain their own checks. Planning advice cannot execute a tool,
change Core, satisfy a proof obligation or grant adoption authority.

The former `advise_macro` and `advise_ordinary` sidecars and provider campaigns
were research controllers. Their hosted implementation is not an installed
native product entry. Native cost-ledger support does not imply that those
controllers were translated or that an NDU benefit was established. Their
observations belong to the single
[historical qualification provenance](HIA_HISTORICAL_QUALIFICATION_PROVENANCE.json).
The contracts below preserve the decision and evidence boundaries relevant to
native callers without advertising a retired command.

## Explicit plans and authority

A caller may plan `discover`, `propose`, `verify`, `emit`, `evaluate`, `adopt`,
`use`, `rollback`, `keep_existing`, `no_adopt` and `stop`. Each actual operation
must pass its current native admission, proof, resource and generation checks.
The direct backend validates explicit machine choices; it does not perform an
implicit profitability search. Core remains the immutable semantic anchor.

Retaining the incumbent, declining adoption and stopping optimization are valid
outcomes. A plan cannot combine refusal or retention with adoption. Stopping
optimization does not establish delivery of the original task: the selected
artifact still requires actual authorized use and all required task outputs.

If a caller uses an independent native NDU evaluator, it must bind its exact
source, image, request and receipt. Missing or refused native advice remains
blocked. An ordinary decision cannot be relabelled as a native NDU evaluation.
Advice itself never establishes a model, economic or performance advantage.

## Frozen state and ledger

The research interchange schema `hepta.hia.agent.macro-state.v1` specifies:

| Field | Required meaning |
| --- | --- |
| `context_sha256`, `objective_sha256` | Frozen context and optimization objective |
| `agent_sha256` | Model, prompt, tools and generation-settings identity |
| `installation` | Exact Worker, backend and catalog identities |
| `generation` | Nonzero bounded policy generation |
| `budget` | Original lifecycle wall-time and model-token allowances |
| `ledger` | Every completed, failed, rejected, timed out, cancelled or uncertain attempt |
| `stop_remaining_ns` | Forecast remaining cost of retaining the incumbent |
| `plans` | Zero to sixteen explicit plans, each ending in `stop` |

Each plan retains `id`, `actions`, `remaining_cost_ns`, `uncertainty_ns`,
`model_tokens` and `support_sha256`. Its forecast covers the complete remaining
sequence; uncertainty is added conservatively. Forecasts never become observed
benefit merely because they were hashed into a request.

Each ledger entry retains `id`, `phase`, `status`, `wall_ns`, `model_tokens` and
`receipt_sha256`. The phases are setup, discovery, model, search, verification,
emission, evaluation, adoption, rollback, future use and controller work.
Charge each disjoint outer interval once. Keep nested checker and native timings
in their source receipt without charging them twice. Failed search, malformed
submissions, timeout and refused adoption remain charged to the original
allowance. A retry does not reset that allowance.

Unknown costs or termination remain unknown and block a conclusion requiring
them. Provider usage must come from actual provider receipts; chat estimates
are not substitutes. Duplicate event IDs or receipts are rejected. Caller
reports establish neither authenticated measurement nor physical real-time
guarantees. Actual runtime budgets and adoption authority remain independent.

The evaluation ledger is a prefix of complete task cost. Missing model,
adoption, future-use or unattributed discovery costs cannot silently become
zero. Native cost owners include context cost, journal cost and evaluation
cost-ledger construction and flow. Their result scope is the actual native
receipt, not every field a historical controller could accept.

## Ordinary comparison and stopping

For the disclosed finite scalar-cost comparison, a strong ordinary control
examines every supplied plan, excludes continuations outside the remaining
wall/token allowances, and minimizes conservative remaining cost. Keeping the
incumbent wins ties; stable plan IDs settle other ties. Its own controller cost
must be included. This finite argmin does not prove calibrated forecasts,
general search optimality or useful task selection.

A caller-side dominated-choice guard may retain the incumbent only when no
feasible supplied continuation has strictly lower scalar cost under that exact
profile. A feasible improvement, including a zero-cost improvement, still needs
the selected evaluator and final budget check. Skipping an evaluator records
no native evaluation and no admission of the configured image. It does not
prove future task delivery or count toward an evaluation-required campaign.

## Same-Agent, same-budget evidence

The comparison schema `hepta.hia.agent.macro-comparison.v1` separates fixed,
greedy, ordinary and NDU arms. Freeze the same Agent identity, task registration,
original budgets and absolute improvement threshold for every arm. Register at
least eight tasks in canonical ID order, each with input and independent task
qualification evidence. Changing the inventory changes the registration hash.

Retain every planned task, including failure and incomplete execution. Each
observation needs correctness, actual result evidence, the full ledger and an
evidence-backed declaration for every cost phase. A phase not performed needs
an explicit declaration; absence is not zero. Every required NDU evaluation
needs its actual native receipt. A claimed improvement must beat the best of
all three controls by the registered margin while satisfying every task and
budget gate.

Hash consistency alone cannot authenticate provider, task or native receipts.
A positive reported arithmetic comparison is distinct from observed acceptance
and from established economic benefit. Synthetic fixtures, process exit zero,
native advice and one favorable timing cannot close that gate. Actual provider
streams, usage, complete failed attempts, qualified task outputs and repeated
measurements are needed for a real-task claim.

The native rewrite's build and installation gates concern implementation and
custody. They neither launch an external provider campaign nor claim an NDU
economic result. Current product acceptance is indexed by [CURRENT.md](CURRENT.md).
