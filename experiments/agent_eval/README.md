# Paired Hepta / Rust agent coding pilot

This directory contains an executable evaluator and four frozen paired tasks.
It contains **zero measured AI model runs**. Its deterministic adapters and known
solutions qualify the evaluator, not a model and not Hepta's productivity.

No provider, endpoint, API key, paid call, or model revision is selected by this
project. An operator must supply a standalone adapter and at least two exact
model identities before a provider comparison is possible. Production provider
runs require a working namespace sandbox; they fail closed when it is unavailable.

## What is frozen

| Task | Required change | Held-out cases per language |
| --- | --- | ---: |
| `compact_runs` | Adjacent-run compaction with truncated output, full required-length reporting, and exact in-place aliasing | 600 |
| `rolling_sum` | Bounded rolling windows, signed wrapping arithmetic, zero/invalid windows, untouched output tail | 194 |
| `lower_bound` | First position at least the key, duplicates, empty inputs, full signed 64-bit range | 414 |
| `parse_decimal` | Strict unsigned parsing with `+`, constrained separators, exact syntax/overflow positions, and C struct return | 220 |

Each task has identical behavioral instructions and two public examples for
Hepta and Rust. Only one marked function body may change. ABI types, signatures,
export names, the wrapper, and Hepta's effect upper bound are frozen. Scaffolds
start with deliberately incomplete implementations. Both languages use their
standard library only; no package installation or repository browsing tool is
provided. Each request includes a concise reference for its language.

`manifest.json` hashes the task instructions, both starter sources, public
examples, language references, public C wrapper, hidden-case generator, and
trusted oracle solutions. A canonical hash of this manifest identifies the whole
task set. Every request and response also carries the task and original source
hashes. Edited frozen content fails verification; an intentionally revised task
set needs a new manifest identity and a new evaluation plan. The evaluator never
silently refreezes the tasks. Evaluator Python code and compiler identity are
recorded separately in every run.

Run reports retain the submitted body, reconstructed-source hash, every public
tool's candidate body and feedback, terminal usage receipts, adapter bundle and
executable hashes, and request identity. This makes a saved native candidate
replayable without repeating a model call. Replay refuses changed task, evaluator,
compiler, or candidate identities. It never becomes a new independent model
attempt. Remote model nondeterminism is not made deterministic by a replay.

The complete paired matrix is preregistered: four tasks × two languages × each
model × replicates. A deterministic shuffled schedule is included in the plan.
Use that schedule without task-dependent retries or selective reporting. The
comparison rejects missing cells, duplicates, stale identities, different
budgets, mixed evaluators/compilers, and fixture reports. Failed solutions with
valid metering remain failed attempts; invalid or unmetered runs make the
comparison incomplete instead of disappearing from its denominator.

## Native scoring and held-out tests

The trusted coordinator reconstructs the frozen source and compiles it. Hepta's
frontend runs in its own bounded subprocess; it receives only a copy of the
compiler package and the candidate. Both languages ultimately use the same
pinned Rust toolchain, Rust edition 2021, optimization level 3, enabled integer
overflow checks, `panic=abort`, and one codegen unit. A frozen C11 wrapper links
the static library and calls the C ABI.

The candidate process receives input values only. It returns actual output
values, counts, error positions, input contents, and buffer guard observations.
An independent Python specification in the coordinator compares them. Expected
answers are never linked into the candidate executable. The scorer checks the
number and order of responses, duplicate case IDs, exact values, input mutation,
untouched output, guard corruption, nonzero exit, timeouts, and output overflow.
A task is solved only if **every** hidden case passes. Per-case details are not
returned to the adapter after final submission; public-test tools return only
public-case feedback. Merely exiting successfully or printing `PASS` cannot
produce a success score.

This is functional testing on valid caller-provided memory regions. It does not
prove memory safety for arbitrary pointers, full language soundness, asymptotic
complexity, or universal correctness. In particular, a quadratic rolling sum or
linear lower bound may pass the finite functional suite. The task set focuses on
small ABI-facing kernels. It does not measure large-repository maintenance,
package search, ADT design, ownership-heavy APIs, or structured concurrency.

### Isolation and its explicit boundary

Production mode uses separate Bubblewrap namespaces for the adapter, frontend,
native compilation, and candidate execution. The filesystem contains a temporary
capsule and allowlisted system/toolchain paths. It does not contain this evaluator
tree or `_private`. Processes receive a sanitized environment. Candidate and
compiler capsules have no network; only an explicitly configured adapter may
request network access. Core dumps are disabled, address space is capped at
2 GiB per subprocess, output/file sizes are bounded, and process groups are
killed on timeout. These local process limits are not global host quotas or
provider-side compute limits.

`probe` checks whether namespace creation works. The current qualification
environment cannot establish the required sandbox. Production `run` therefore
returns `environment_blocked` **before invoking the adapter**. No insecure fallback
qualifies as provider evidence. `qualify-fixtures` uses explicitly trusted scripts
and solutions with process separation only; its reports always say
`ai_comparison_eligible: false` and
`strict_hidden_test_isolation_exercised: false`. Do not run an untrusted adapter or
untrusted candidate through fixture mode.

Hidden means withheld from the adapter and candidate capsules during a run.
These files are shipped in the repository so the evaluator can be reviewed and
reproduced. They are not secret from anyone given the whole repository, and an
adapter could be deliberately preloaded with them. A serious future study must
audit adapter bundles, prevent solution contamination, freeze an independently
prepared unpublished task revision before collecting results, and record its
identity. This harness does not certify an adversarial adapter's honesty.

## Uniform budgets and what enforcement means

The default caps per attempt are 12,000 input tokens, 4,000 output tokens,
16,000 total tokens, 180 seconds, 12 protocol tool calls, and 2 MiB of adapter
stdout/stderr. The same `Budget` object applies to every planned model/language
cell. Operators can freeze different values before starting. These are nominal
provider token units: different tokenizers do not make one token the same amount
of text or computation. Wall time includes adapter startup, model latency, and
public compiler/test tools. Final hidden scoring occurs after the adapter stops
and is outside the agent's wall budget for both languages.

| Limit | Enforcement |
| --- | --- |
| Agent wall time | Deadline checked during JSONL exchange and tools; overrun kills the local adapter process group and rejects the run |
| Public tools | Only `check` and `public_test`; the coordinator observes and caps every protocol call before executing it |
| Token totals | Every frame needs cumulative receipts; missing counts, changed/removed receipts, inconsistent sums, or an overrun reject the run |
| Output bytes | Combined adapter stdout/stderr cap; overflow kills the adapter |
| Candidate work | One shared deadline across frontend, Rust compilation, linking, and execution; bounded I/O and memory |

Token receipts are **adapter-attested**, not independently authenticated with a
provider billing service. The harness does not turn a post-call token rejection
into a pre-call spending cap. The adapter must set provider output limits, count
all calls including retries, include reasoning/cached tokens according to the
provider's usage semantics, and refuse new calls that cannot fit its remaining
budget. An interrupted remote request may still incur provider work after the
local process is killed. Rejected attempts cannot claim complete metering.

The tool cap covers the coordinator's protocol tools. An adapter is executable
code and can perform internal work; provider-native tools, its own subprocesses,
and off-protocol tools are not independently counted. Reports explicitly set
`off_protocol_adapter_tool_calls_verified: false`. A published comparison needs a
reviewed thin adapter with such tools disabled, consistent sampling/decoding
settings, and the same model context policy. Network latency, different model
training exposure, language-reference lengths, and tokenizer differences remain
confounders. Four tasks are a pilot, not sufficient evidence of a general
productivity advantage.

## Adapter JSONL protocol

An adapter is a standalone directory, at most 5 MiB, with no symlinks. It is copied
into a fresh capsule. Supply its command as a JSON argv array; `{adapter}` expands
to the copied directory. For example, the command file can contain
`["/usr/bin/python3", "{adapter}/adapter.py"]`. The evaluator records the bundle
hash, command, executable hash, and names of explicitly passed environment
variables. It never records their values. Do not put credentials in command
arguments or response metadata. Use only `--pass-env NAME` for explicitly needed
provider configuration, and `--network` only for an intentionally configured
provider run.

The evaluator sends one JSON line with schema `hepta.agent_request.v1`, exact
`model: {provider, name, revision}`, `adapter_kind`, a fresh `request_id`, task and
source identities, instructions, starter source, public cases, language reference,
budget, and allowed tools. It does not send private solutions or hidden cases.

Every adapter frame must echo `request_id`, `task_sha256`, `base_sha256`, `model`,
and `adapter_kind`. A tool frame has `kind: "tool_call"`, a unique `call_id`,
`tool: "check"` or `"public_test"`, and a complete replacement `body`. The evaluator
returns `hepta.agent_tool_result.v1` with the same call ID, compiler/test feedback,
and remaining wall/tool/total-token budgets. A final frame has `kind: "final"` and
the complete replacement block including braces. Extra declarations outside the
block, oversized edits, malformed frames, or stale identities are rejected.

Every frame also contains cumulative `usage`:

```json
{
  "input_tokens": 120,
  "output_tokens": 45,
  "total_tokens": 165,
  "tool_calls": 1,
  "provider_calls": [
    {
      "request_id": "provider-returned-request-id",
      "model": {"provider": "supplied-provider", "name": "supplied-model", "revision": "exact-revision"},
      "input_tokens": 120,
      "output_tokens": 45,
      "raw_usage": {"input_tokens": 120, "output_tokens": 45}
    }
  ]
}
```

This is a schema example, not a recorded call. Each receipt needs a unique actual
provider request ID, the exact planned model identity, nonnegative integer token
counts, and the provider's nonempty usage object. Aggregate totals must equal the
sum of receipts. Prior receipts cannot disappear or change on later frames.
`tool_calls` must equal the coordinator's observed requests including the current
frame. Fixtures use empty receipts and zero model tokens; they cannot claim
provider usage. Provider frames cannot use fixture zero-token receipts.

## Running it

From the repository root, with the pinned Rust compiler and a C compiler:

```bash
python -m experiments.agent_eval verify
python -m experiments.agent_eval probe
python -m unittest tests.test_agent_eval -v
python -m experiments.agent_eval qualify-fixtures --output /tmp/hepta-fixture-qualification.json
```

Set `RUSTC` or pass `--rustc` if toolchain discovery needs help. Output files are
append-only: an existing path is rejected before running the adapter. The checked-in
`evidence/fixture_qualification.json` records deterministic native qualification
only. Rerun qualification after compiler/evaluator changes; its identities must
match the code for which a claim is being made.

For a future **explicitly configured** provider study, write `models.json` as a
list of at least two real provider/name/revision objects. Write an optional budget
JSON object. Do not use the synthetic identities in unit tests as model names.

```bash
python -m experiments.agent_eval plan --models /path/to/models.json --budget /path/to/budget.json --replicates 3 --output /path/to/plan.json
python -m experiments.agent_eval run --plan /path/to/plan.json --model-index 0 --task compact_runs --language hepta --replicate 0 --adapter-dir /path/to/standalone_adapter --command /path/to/command.json --output /path/to/run-0001.json
python -m experiments.agent_eval compare --plan /path/to/plan.json /path/to/run-*.json --output /path/to/comparison.json
```

Add explicit network/environment options only when that adapter needs them and
the operator has configured a provider. Execute every cell in the frozen schedule.
The evaluator does not automatically retry, choose providers, install an SDK, or
contact anything. A complete comparison is labelled
`complete_adapter_attested_pilot`, with raw per-model/per-language solved counts.
It still sets `general_productivity_advantage_established: false` and
`provider_receipts_independently_verified: false`. There are no multimodel results
to report until actual metered runs have been supplied and the isolation blocker
has been resolved.

To re-score a saved individual provider run with identical task/compiler code,
use `python -m experiments.agent_eval replay --run /path/to/run.json --output
/path/to/replay.json`. Only trusted fixture bodies may use `--trusted-fixture`;
this explicit option retains the fixture isolation and provenance limitations.
