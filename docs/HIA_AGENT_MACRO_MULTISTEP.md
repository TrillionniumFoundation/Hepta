# Matched multistep maintenance comparison

`tools/qualify_hia_macro_multistep.py` is a separate v2 experiment. The v1
campaign, its original malformed model output, incomplete Fixed cells, costs,
and verdict remain historical evidence. V2 does not rewrite them or turn their
raw time difference into an NDU gain.

## What is compared

Every arm receives the same public synthetic maintenance task, original
baseline, scalar ABI, full u8 domain, strict shared-artifact size objective,
normative assembly grammar, provider identity and original cell budget. Each
has at most three scheduled proposal rounds. A round receives its own earlier
proposal text and actual parser/checker/verification/native measurements. Failed
rounds consume their scheduled slot, wall time and observed tokens. There is no
automatic JSON repair, teacher fallback, replacement task or refund.

All four arms have the same two calibration tasks followed by the same four
heldout tasks. No arm receives external training or extra prompt tuning. Each
uses the same prescribed estimator over its own prior calibration receipts.
Heldout outcomes do not become another arm's training set. Task order and arm
rotation are fixed before execution.

| Arm | Selection after the bounded proposal rounds |
| --- | --- |
| Fixed | First actual candidate that passes the complete maintenance goal |
| Greedy | Lowest immediate measured native-call time among candidates that pass |
| Strong Ordinary | Enumerate every feasible candidate and minimize its complete conservative remaining lifecycle cost |
| Native NDU | Give the identical feasible candidates, conservative costs and remaining resource allowance to the original source-bound native evaluator |

The complete cost forecast includes selected-artifact use and estimated
adoption/rollback. All proposal, rejection, model, verification, emission and
earlier measurement costs have already been incurred and stay in the cell
ledger. The estimator uses the median observed calibration transition cost and
the observed range plus one millisecond as uncertainty. Before any successful
calibration, every arm uses the same explicitly registered two-millisecond
transition prior and ten-millisecond uncertainty. These estimates are not
substituted for actual measured costs in the final comparison.

The native value ABI requires a feasible `abstain` alternative. V2 therefore
uses the first **actual candidate from this cell** that already passes full
correctness and strict size as the selection incumbent. Native `abstain` means
keep that exact checked candidate. The unchanged task baseline does not fulfill
the maintenance request and is never relabelled as success. If no candidate is
qualified, the cell remains undelivered and no fake incumbent is sent to NDU.
The private feasibility program is never an Agent candidate or an incumbent.

This measures bounded feedback-driven proposal generation followed by selection
from a checked pool. It does not claim that the current scalar NDU interface
learns search dynamics, invents transformations or supplies a general planning
advantage. Strong Ordinary has the same information and can match the scalar
ranking objective without invoking NDU.

## Fixed allowances and outcome gates

The registered matrix has 24 cells: six tasks times four arms. Each cell keeps
the existing 180-second wall allowance and 32,768-token conservative accounting
threshold. It permits at most three provider sessions and three candidate
imports. The matrix therefore permits at most 72 CLI sessions and 4,320 seconds
of cell wall allowances. Setup, final export and verification are separately
measured. A CLI session can contain provider-internal requests that this JSONL
interface does not count.

The token convention remains input + output + reasoning output, conservatively
preserving the previous overlap-unknown convention. Original cached-input and
cache-write counters are retained and are not added again. The threshold is
checked from actual terminal usage; it is **not** a guaranteed mid-turn token
cap. Unknown usage, uncertain cleanup, protocol violations, quota errors and
executable drift fail closed. Content rejection with known usage and a settled
process can be shown in a later already scheduled round. An overrun remains in
the ledger and cannot become an eligible cheap cell.

Before another proposal, every arm reserves at least the **preceding settled
actual input + output + reasoning bill** from its remaining token allowance.
This is a disclosed estimate: repeated baseline/grammar and growing feedback
can make the next bill larger, and it is not a hard mid-turn cap. If the known
remaining allowance is smaller than that estimate, the controller records
`stop_proposals` and makes no further provider call. It can still select an
already qualified candidate and complete adoption, use and rollback inside the
original cell allowance. Unknown usage or unsettled execution instead freezes
the provider across subsequent cells. Each reservation and stopping reason is
retained in the contiguous cost ledger and checked against the original prior
receipt; no failure is converted to a zero bill or refunded.

Success requires actual selected native bytes that return all 256 independent
oracle results, preserve the scalar ABI, are strictly smaller than the exact
baseline, and have the original verification, evaluation, adoption, downstream
use and rollback receipts. Each arm's completion count must be shown with its
cost. A cheap incomplete arm cannot become the strongest completed control.
The inherited `completed_comparison` gate keeps the qualified NDU saving `null`
until all four registered arms have delivered every task within their original
allowances. Raw arithmetic remains separately labelled.

The v2 comparison uses `tools/hia_macro_multistep_assessment.py`, an explicit
six-task entry point with exactly two calibration and four heldout purposes.
It checks the same closed ledgers, four complete arms and original allowances.
The separate v1 assessor still requires eight to 128 registered tasks. No task
padding or denominator reduction is used to make either contract pass. A new
offline verifier can check an earlier v2 bundle without editing its original
failed verifier receipts. Such an integrity observation does not turn an
undelivered task into a pass. If any dispatched model event lacks usage, total
usage fields remain `null`; known counters are reported only as a partial sum.

Billing, response-echoed model identity, generalization and statistical
confidence are separate missing evidence. This single synthetic campaign keeps
`economic_benefit_established: false` and `p1_acceptance: HOLD`, including after a
positive observed cost difference. It is a local HIA domain-service experiment;
it does not replace formal MCP first-use acceptance.

## Prepare and qualify new tasks

The generator creates a new nonce and seven private synthetic tasks: two
calibration, four heldout and one separately namespaced first-use task. It
records provenance, complete source hashes and an independent Python arithmetic
oracle. It runs baseline/teacher interpreter controls only. The public task
contains the requirement, specification and baseline; the hidden directory
contains oracle values and a feasibility program. Generated instances are not
real user repository tickets, nor proof that a model has never seen similar
algebra.

```sh
python -B tools/prepare_hia_followup_tasks.py --output /absolute/new-private-tasks
python -B tools/qualify_hia_followup_tasks.py \
  --registration /absolute/new-private-tasks/REGISTRATION.json \
  --output /absolute/new-native-feasibility
```

The second command emits baseline and private feasibility artifacts with the
same GNU `ld` profile used by `HIAAgentService`, executes each on all 256 inputs
under the existing native bounds, and measures actual whole-file size. It
retains objects, shared images, linker commands, observations and costs. An
interpreter result alone is insufficient: ELF alignment can leave a shortened
program's entire file size unchanged. A failed registration is retained and
excluded before a new registration is created; no learner result is retried.

The qualifier's complete source/catalog/backend identity must match the final
source used to prepare a campaign. If integration changes those bytes, rerun
this bounded qualifier in a new output directory. Do not overwrite an earlier
receipt.

## Freeze, then run explicitly

The provider's `--output-schema` requests a closed object containing one
assembly string. The parser still checks the original complete JSONL and strict
JSON response, then the existing assembly parser and full Core checker admit
the program. The option is not treated as proof that a particular provider
accepted the schema. A provider rejection is retained; the harness does not
switch accounts or fall back to an unregistered prompt.

```sh
python -B tools/prepare_hia_macro_launcher.py \
  --registration /absolute/new-private-tasks/REGISTRATION.json \
  --feature-list /absolute/original-features-list.stdout \
  --real-cli /absolute/qualified-codex \
  --model explicitly-qualified-model \
  --campaign-root /absolute/new-campaign \
  --output /absolute/new-launcher
python -B tools/qualify_hia_macro_multistep.py prepare \
  --registration /absolute/new-private-tasks/REGISTRATION.json \
  --feasibility /absolute/new-native-feasibility/QUALIFICATION.json \
  --codex /absolute/new-launcher/codex_exec_v2.py \
  --launcher-binding /absolute/new-launcher/BINDING.json \
  --registered-warnings /absolute/new-launcher/REGISTERED_WARNINGS.json \
  --model explicitly-qualified-model \
  --native-binary /absolute/hia-ndu-bridge \
  --native-build-receipt /absolute/build-receipt.json \
  --output /absolute/new-plan.json
```

Preparation calls no model and executes no native evaluator. It verifies the
existing native binary's source-bound receipt, original task files, per-task
feasibility originals and current source identities. The coordinator separately
qualifies effective CLI isolation, underlying CLI versus launcher identities,
the model selector and account access. An executable hash does not prove that
all non-task capabilities are disabled. Actual foreign tool items cause strict
protocol failure.

The generated launcher pins a separate underlying CLI hash, its own source
module and executable hashes, the exact output schema, one campaign directory
and the 72 registered task/arm/round paths. It records the original and actual
inner argv before replacing itself with the CLI in the same owned process
group. Per-invocation restrictions include an empty MCP/plugin configuration,
read-only sandbox and the registered tool-feature disable list. No global
configuration, credential or network setting is changed. Registered feature
names and requested flags alone do not attest the effective tool inventory.

Launch configuration v3 keeps the existing `code_mode_host` dependency enabled
and records the sibling host binary's identity before exec. An actual Linux
pre-turn failure showed that disabling this host prevents the selected path
from starting. Its presence and requested flag do not prove which resolver
the CLI used or that the host has no capabilities. Historical v2 flags remain
reconstructable for offline receipt checks; new v3 execution requires the new
dependency binding. The only registered startup warning is the exact, once
observed `skip_host_skill_discovery` development warning. A different or repeated
warning, host-unavailable error, tool item, missing usage or unsettled process
still fails closed.

`tools/qualify_hia_cli_public_capability.py` can separately prepare a tiny public
compatibility pilot. Its prompt requests only `{"assembly":"READY"}` and loads
no private maintenance task. The frozen allowance is one CLI session, at most
60 seconds and an 8,192 input+output+reasoning terminal token review. It retains
all original streams and cleanup, and never changes unknown prior usage to
zero. Preparation calls no model; the `run` subcommand requires the exact plan
SHA after separate review. A pilot result authorizes neither a campaign restart
nor a formal MCP first-use claim.

After that concrete plan and its budget are reviewed and frozen:

```sh
python -B tools/qualify_hia_macro_multistep.py run \
  --plan /absolute/new-plan.json --output /absolute/new-campaign
python -B tools/qualify_hia_macro_multistep.py verify \
  --bundle /absolute/new-campaign
```

The `run` command creates output exclusively and has no resume-as-new-run
behavior. `verify` reads original objects, model byte streams, proposal/receipt
bindings, full native observations and contiguous cost intervals without
calling a provider or executing an image. Local hashes demonstrate integrity,
not independent authorship or provider authentication.

Native evaluator observations retain the exact request and original stdout and
stderr before response admission. A nonzero exit or malformed response keeps
those bytes and its original error. Timeout, output-limit and cleanup failures
retain only the bytes actually read and explicitly mark incomplete streams as
bounded prefixes. Their costs remain in the original controller interval;
they never become successful evaluator or task receipts.

The `control` subcommand uses an explicitly authored invalid entry block and
private feasibility programs on the first calibration task, with zero model
calls. It tests the actual Ordinary and native NDU paths and retains every
rejection. Its fixture proposals and any success are labelled as no-model
controls and must never be added to real-Agent success counts.

## Delivery scope

Retain the plan, source identities, task-registration hashes, raw model stdin
and stdout, response schema, model-process receipts, cost events, native objects
and final verdict. Keep provider cwd/state/log directories out of a public
delivery. An empty original stderr may be included. Nonempty provider stderr
remains private until separately reviewed; include its original byte count and
SHA in the public manifest without copying or encoding potentially private
content. No provider token, global configuration or credential belongs in the
evidence package.
