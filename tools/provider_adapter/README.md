# OpenAI reference adapter for the four-arm study

This directory supplies a standalone, standard-library-only provider adapter for
`experiments.crossfile_eval`. It is executable integration code, **not a recorded
AI experiment**. Its tests substitute deterministic HTTP responses; their model
labels, request IDs and token counts are synthetic unit-test data. No API call,
provider access, model availability, price, or productivity result is established
by those tests.

The adapter requires the coordinator to advertise
`capabilities.abort_frame: true`. It supports the cross-file study v2 public
tools and explicit failure frames. It does not support the older single-body
`experiments.agent_eval` protocol.

## Scope and provider contract

The only endpoint is `https://api.openai.com/v1/chat/completions`. Requests use
non-streaming text Chat Completions, `n=1`, `store=false`, ordinary function
tools, and `max_completion_tokens`. There are no endpoint overrides, SDKs,
proxy settings, automatic retries, redirects, provider-native tools, local
shell tools, or alternate-provider fallbacks.

OpenAI documents the function-call exchange as assistant tool calls followed
by tool messages carrying the corresponding `tool_call_id`. This adapter returns
the complete coordinator feedback for every tool call to that conversation,
including failed validation and stale-version responses. Multiple function
calls in one completion execute sequentially and each consumes one coordinator
tool call. The adapter never rewrites a model's stale version or node ID.
[Official function calling guide](https://developers.openai.com/api/docs/guides/function-calling).

`max_completion_tokens` includes visible output and reasoning tokens. The adapter
sets it to the remaining output allowance, additionally limited by remaining
total tokens after an input reservation. It records the server's
`prompt_tokens`, `completion_tokens`, `total_tokens`, and original numeric usage
breakdowns; cached and reasoning counts are not counted a second time.
[Official Chat Completions reference](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create).

The API key comes exclusively from the explicit `OPENAI_API_KEY` environment
variable. It is used only in the HTTPS Authorization header, never written to a
file, printed, embedded in prompts, or included in receipts. HTTP error bodies,
arbitrary headers and exception strings are withheld. TLS uses Python's default
certificate verification. The fixed-origin `http.client` transport does not
consult HTTP proxy variables or follow redirects.

Each valid receipt uses the server's actual `x-request-id` header. A generated
`X-Client-Request-Id` is only an investigation aid for an interrupted request;
it never substitutes for a server receipt. OpenAI documents these distinct IDs
and recommends pinning model versions for evals.
[Official API overview](https://developers.openai.com/api/reference/overview).
These pages were checked on 2026-10-24; the code makes no claim about unlisted
model support or account access.

## Explicit model and budget configuration

Supply a JSON array of at least two **distinct, operator-verified dated model
revisions**, each with exactly `provider`, `name`, and `revision`:

- `provider` must be `openai`.
- `name` is the operator's model-family identifier in the frozen plan.
- `revision` is the exact API model ID, ending in a valid `YYYY-MM-DD` date.

There is no default model, alias resolution, fictional snapshot, or price list.
An exact revision must support text Chat Completions, function tools and
`max_completion_tokens`. This intentionally narrow adapter does not accept
moving aliases, fine-tuned IDs, or models only available through another API.
The requested revision must also appear in the exported model allowlist, and
the response's actual `model` must equal it byte for byte. A mismatch aborts;
the adapter cannot relabel a drifted response as the planned model.

The input admission reservation is the UTF-8 size of serialized messages/tools,
plus a fixed protocol margin. This is a conservative **heuristic, not a tokenizer
or a proved provider input bound**. It can reject a call that would have fit.
Actual accounting always uses returned usage. Input/total overrun is still
possible, is retained as known cost, and makes the attempt fail. No monetary
hard cap, price conversion or provider billing authentication is claimed.

The absolute wall deadline spans requests, tool waits and feedback. The initial
remaining-time report accounts for coordinator/workspace setup; later tool
reports can only shorten the deadline. The frozen task's `interface_policy` and
initial remaining limits are also included in the model's public context.
The adapter reserves protocol space
for a subsequent receipt-bearing abort before each HTTP request. A locally
terminated request can still have unknown remote cost. No retry is attempted.

## Export and freeze before planning

Export a standalone directory **outside the source repository**, containing only
the adapter, this README, the explicit model allowlist, command, and manifest.
No evaluator module, hidden oracle, solution, compiler package or credential is
copied. Choose an installed Python under `/usr` or `/bin`, which are the existing
namespace's read-only runtime mounts.

The commands below are a future operator workflow. They have not been run
against an API. First set an absolute `HEPTA_STUDY_DIR`, an absolute `RUSTC`, and
the four model values from official model documentation and your account's
available snapshots. Do not use invented example IDs.

```bash
: "${HEPTA_STUDY_DIR:?set an absolute new study output directory outside the repository}"
: "${RUSTC:?set the exact qualified Rust compiler path}"
: "${MODEL_NAME_1:?set the first verified model family}"
: "${MODEL_REVISION_1:?set the first exact dated API model ID}"
: "${MODEL_NAME_2:?set the second verified model family}"
: "${MODEL_REVISION_2:?set a different exact dated API model ID}"
mkdir -p "$HEPTA_STUDY_DIR"
python3 - "$HEPTA_STUDY_DIR/models.json" "$MODEL_NAME_1" "$MODEL_REVISION_1" "$MODEL_NAME_2" "$MODEL_REVISION_2" <<'PY'
import json, pathlib, sys
models = [dict(provider='openai', name=sys.argv[i], revision=sys.argv[i+1]) for i in (2, 4)]
with pathlib.Path(sys.argv[1]).open('x') as f:
    json.dump(models, f, indent=2)
PY
python3 tools/provider_adapter/export.py \
  --models "$HEPTA_STUDY_DIR/models.json" \
  --output "$HEPTA_STUDY_DIR/openai-adapter" \
  --metadata-out "$HEPTA_STUDY_DIR/adapter-configs.json"
python3 -m experiments.crossfile_eval probe
python3 -m experiments.crossfile_eval plan \
  --models "$HEPTA_STUDY_DIR/models.json" \
  --adapter-configs "$HEPTA_STUDY_DIR/adapter-configs.json" \
  --rustc "$RUSTC" --replicates 1 \
  --output "$HEPTA_STUDY_DIR/plan.json"
```

An unavailable namespace is a blocker for provider evaluation. There is no
adapter option that converts it into fixture mode. An unavailable or incompatible
model also fails; the adapter does not select a replacement.

`adapter-configs.json` is outside the bundle, avoiding a self-referential hash.
For every configured model it contains the same bundle digest, exact argv,
interpreter executable hash, `passed_environment_names: ["OPENAI_API_KEY"]`, and
`network_requested: true`. The plan binds these fields. The coordinator recomputes
them at startup and comparison checks them again. **One model uses the same
frozen adapter configuration in all four arms.** Modifying any bundle file or
interpreter requires a new plan; do not splice results from different versions.

## Execute the complete planned matrix

Only after an operator explicitly configures the API credential and authorizes
the frozen budget, make it available as `OPENAI_API_KEY` in the process
environment. Do not put its value in JSON files, commands, receipts or logs.

For one cell, the current CLI is:

```bash
: "${OPENAI_API_KEY:?configure the API key through the process environment}"
python3 -m experiments.crossfile_eval run \
  --plan "$HEPTA_STUDY_DIR/plan.json" --model-index 0 \
  --task api_migration --arm rust_plain --replicate 0 \
  --adapter-dir "$HEPTA_STUDY_DIR/openai-adapter" \
  --command "$HEPTA_STUDY_DIR/openai-adapter/command.json" \
  --pass-env OPENAI_API_KEY --network --rustc "$RUSTC" \
  --output "$HEPTA_STUDY_DIR/run-0000.json"
```

For an actual study, execute **every cell in `plan.schedule`**, rather than
selecting successes. The following launcher keeps failed process exit codes as
recorded samples and does not retry. Start with a new output directory and do
not run the single-cell example first with the same output names.

```bash
python3 - "$HEPTA_STUDY_DIR" "$RUSTC" <<'PY'
import json, pathlib, subprocess, sys
root, rustc = pathlib.Path(sys.argv[1]), sys.argv[2]
plan = json.loads((root / 'plan.json').read_text())
for i, cell in enumerate(plan['schedule']):
    argv = [sys.executable, '-m', 'experiments.crossfile_eval', 'run',
            '--plan', str(root / 'plan.json'),
            '--model-index', str(cell['model_index']), '--task', cell['task'],
            '--arm', cell['arm'], '--replicate', str(cell['replicate']),
            '--adapter-dir', str(root / 'openai-adapter'),
            '--command', str(root / 'openai-adapter/command.json'),
            '--pass-env', 'OPENAI_API_KEY', '--network', '--rustc', rustc,
            '--output', str(root / ('run-%04d.json' % i))]
    subprocess.run(argv, check=False)
reports = [str(p) for p in sorted(root.glob('run-*.json'))]
subprocess.run([sys.executable, '-m', 'experiments.crossfile_eval', 'compare',
                '--plan', str(root / 'plan.json'), '--reports', *reports,
                '--output', str(root / 'comparison.json')], check=False)
PY
```

The comparison's planned denominator still includes missing, failed and timed-out
cells. Prices and observed human time must be supplied separately through the
existing cost-record CLI using attributable evidence; the adapter cannot infer
them from a model name.

## Receipt and failure semantics

Every emitted tool/final frame echoes all frozen identities. Its cumulative
`usage.provider_calls` contains each accepted HTTP receipt once, with the exact
planned model, server request ID, prompt/completion counters, and unchanged
numeric raw usage. `usage.tool_calls` counts actual coordinator requests,
including the emitted frame, not HTTP requests or tool results. Duplicate
provider request IDs or tool-call IDs cause failure.

An explicit `abort` contains a stable error code and fixed non-secret message.
`usage` is the last valid receipt prefix, or `null` if none was obtained.
`usage_complete` is true only when at least one valid receipt exists and no
request remains unverified: a failed or truncated completion can have completely
known cost. It is false when a response or usage is missing, a model drifted,
or there is no metered receipt. A current unverified request can include
`pending_provider_request: {client_request_id, request_id, receipt_verified:false}`.
It is audit information, **not a token receipt or evidence of zero cost**.
Server usage exceeding a frozen cap is appended before the abort, preserving
the known charge. A response with a mismatched model, missing ID, or invalid
usage is not relabeled or converted into a receipt.

The coordinator marks every abort as a failed planned attempt and does not run
the hidden oracle, including failures with completely known cost. A killed
process may prevent delivery of its newest receipt;
earlier observed receipts remain only a lower bound and total cost remains
unknown. No synthetic receipt is manufactured to fill that gap. The adapter and
coordinator receipts remain adapter-attested, not independently verified billing
records.

## Offline qualification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_openai_provider_adapter -v
```

The tests replace the HTTPS connection before any transport request. They cover
real request serialization and response handling, tool feedback across all four
arms, unique IDs, exact model matching, budgets, complete receipt prefixes,
redacted errors, export identity, and an exported subprocess's missing-key abort.
They do not set a real key, contact an endpoint, or produce provider-run evidence.
