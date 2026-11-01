# Fixed three-model repository repair pilot

Protocol `benchmarks/hia_agent_repository_maintenance/PROTOCOL-v2.json` is an
independent registration. It inherits the exact v1 tasks, native oracle, public
information, hidden cases and two-attempt budget. The original protocol and its
historical provider-unavailable observation remain unchanged. An availability
probe in the restored environment actually completed; it is not a task answer.

## Cohort and scope

All three preregistered models receive the same two tasks in full-module and
structured-patch forms, with task order fixed and arm order alternating:

| Model selector | Provider | Immutable identity |
| --- | --- | --- |
| `qwen_coder1_5b` | local Qwen2.5-Coder-1.5B-Instruct Q4_K_M | official repository revision, bytes and SHA-256 in v2 protocol |
| `qwen_coder7b` | local Qwen2.5-Coder-7B-Instruct Q4_K_M | official repository revision, bytes and SHA-256 in v2 protocol |
| `codex_gpt61_sol` | Codex CLI requesting `gpt-6.1-sol` | local CLI hash and actual raw response/usage; remote weights and routing are not independently attested |

The local models are two sizes of the same family. This is not evidence from
three independent model families. Each task is a **registered defect injection
into a source-identified repository resource module**. The historical path query
did not identify a genuine before/after maintenance pair. These two tasks cannot
establish industrial migration productivity or historical maintenance benefits.

For each arm the model receives the entire same faulty module, contract, repair
site, public cases and structured-edit schema. Only the response representation
differs. Only the disclosed operation may change. Public validation failure can
trigger one feedback request; hidden evaluation is terminal and never enters a
model prompt. Reference controls are infrastructure checks, never model successes.

## Budget and provider differences

The local engines use 8192 context tokens, at most 2048 generated tokens, a
120-second whole-generation deadline, four CPU threads, greedy decoding and no
prompt caching. A generic JSON-object grammar supplies syntax only. Exact model
and runtime hashes are checked before launch and after execution, with owned
Unix-socket peer identity and explicit reaping.

Codex uses one fresh owned ephemeral read-only CLI for each response, the same
public conversation and maximum two response attempts. A strict event parser
rejects observable tool events, unregistered messages, duplicate JSON fields, missing usage
and multiple answers. Typed reasoning text is retained as a non-answer event;
it cannot admit a candidate. The CLI's extra system context and cache usage are
reported rather than subtracted. The CLI currently provides no equivalent hard
`n_predict` argument: output plus reported reasoning is checked against 2048
after completion, with actual over-budget usage retained and the answer refused.
Reasoning tokens are a detail of reported output, so that admission proxy is
deliberately conservative. The cost ledger counts actual input plus output and
does not add reasoning a second time; cached input is likewise a subset.
The same rule applies to both arms. This is not an assertion of equal provider
contexts or equivalent token prices.

An incomplete transport or timeout terminates that cell. The exact available
usage, partial raw evidence and lifecycle remain recorded. After confirmed local
cleanup, the next distinct cell can run with a new engine; the timed-out cell is
not retried. Actual provider unavailability stops that provider cohort. Any
uncertain cleanup or identity stops the study. Missing or unknown usage never
produces a claimed complete cost per successful task.
Compiler, linker, runtime/file errors and native execution timeouts are recorded
as infrastructure failures, never model repair feedback. Accepted Codex event
streams contain no observable tool events; this is not a claim that the OS can
prevent the first read-only command from starting before its event is emitted.

## Cost ledger

The final top-level `REPORT.json` and each model's `FINAL-ACCOUNTING.json` are the
complete internal ledgers. Intermediate per-model `REPORT.json` is written before
campaign-wide admission/aggregation allocation and is labeled by its position in
that workflow. Raw records retain generation, validation, hidden evaluation,
retries, output/cache/reasoning tokens, all cell wall time and all model lifecycle
wall time. Startup, restart, final hashes and shutdown are outside the cell clocks
and their measured noncell wall is divided equally between the two arms, by a
rule fixed before requests. Remaining campaign admission/aggregation wall is
divided across the three planned models and then their two arms.

For a standalone-arm cost comparison, every arm also carries one full native
controls campaign and the measured service wall of its model/runtime downloads.
Codex arms carry the current availability probe wall and separately itemized
probe usage. Task token-per-success excludes that separately visible probe.
These conservative acquisition allocations repeat shared costs and must not be
summed to claim actual campaign elapsed time: the asset downloads overlapped.
An outer process receipt is required to include interpreter startup and final
JSON serialization. Monetary cost, model training cost and human maintenance
labor are not estimated.

## Execution

The runtime and model archives must first match the registered download receipts.
Set `LLAMA_ARG_REPACK=0`. The v2 runner also binds its inherited evaluator, all
compiler modules, runtime adapter, Codex transport and the transport's protocol.
No benchmark request can start unless all these files match actual committed Git
blobs and fresh controls from that exact commit and Clang binary.

```bash
python3 tools/qualify_hia_agent_repository_maintenance_v2.py controls \
  --clang /absolute/path/to/clang --output /new/controls

LLAMA_ARG_REPACK=0 python3 tools/qualify_hia_agent_repository_maintenance_v2.py run \
  --clang /absolute/path/to/clang --expected-head FROZEN_COMMIT \
  --controls /new/controls/CONTROLS-v2.json --assets /restored/assets \
  --downloads /download/receipts --availability /probe/RESULT.json \
  --output /new/results
```

The three models execute sequentially. No model replacement, best-model-only
reporting, human answer repair or result-dependent task/threshold selection is
part of this protocol.
