# Local open-weight provider for the existing four-arm study

The optional local provider removes the requirement for a commercial API key.
It does **not** remove the existing two-model, five-task, four-arm design,
native checking, complete planned denominator, production workspace v4, token
accounting or strict namespace requirements. The evaluator itself is unchanged.

## Components and trust boundary

`tools/provider_adapter/local_model_common.py` locks the exact model weights,
tokenizer and generation settings. The lock includes the operator-supplied
immutable upstream repository commit and a SHA-256/size inventory of every
regular file in the model directory. Moving revision aliases, symlinks,
undeclared extra files, Python model code and pickle `.bin` weights reject.
File hashes establish local input identity; they do not independently prove
that the bytes came from the claimed upstream author.

`local_model_service.py` loads only local safetensors through
`AutoModelForCausalLM` with `local_files_only=True` and
`trust_remote_code=False`. The supported engine is greedy CPU generation in
explicit float32 or bfloat16, with a fixed thread count. The service exposes
only `POST /generate` on `127.0.0.1`. It has no shell, filesystem-query or code
execution tool. It is a trusted inference process, analogous to a provider
endpoint; it is not a hostile-host attestation mechanism. Start it with a
dedicated model directory and evidence directory, without evaluator secrets.

The post-study policy revision rejects different Torch intraop thread counts
within one service **before** loading any model: Torch's setting is process
global. It checks the effective generation strategy after `do_sample=False`,
requiring one greedy sequence, one beam/group, tensor output, unchanged prompt
prefixes, and the declared EOS/length/deadline stopping policy. Encoder-decoder
models, token healing, custom stop strings/time limits, contrastive/constrained
strategies, multiple return sequences and dictionary generation output reject.
The returned tensor must contain one sequence beginning with the complete input
IDs before its suffix can become an output-token receipt. Unexpected output
shapes remain unknown-cost runtime failures rather than zero-token successes.
The verified generation-config copy is passed to every actual `generate` call
with `use_model_defaults=False`, and the same copy determines EOS accounting.
This prevents Transformers' model-default merging or legacy `config.json`
reconstruction from silently restoring a beam/contrastive policy after checking.

The 2026-10-26 study used frozen provider v1 with two identical thread settings
and ordinary greedy Llama configurations. Its original source, logs and runtime
identity remain in `experiments/crossfile_eval/local_study_20261026`; later policy
hardening is a different service/code identity and does not relabel those runs.

Prompt rendering is also frozen. `tokenizer_chat_template` uses the locked
tokenizer's own template and never silently falls back. `chatml_v1` explicitly
serializes every message as `<|im_start|>ROLE\nCONTENT<|im_end|>\n`, then appends
the assistant prefix. It can be selected for a base model without a chat
template; selecting it for both models preserves the same wrapper. This does
not turn a base model into an instruction-tuned model. The full task/reference
is retained and the model's native context limit is never enlarged.

The service records its Python executable hash, Python/package versions and
engine/common source hashes. That identity is frozen in the client bundle and
every receipt. Shared system libraries and the running host are not completely
attested by this metadata. Model loading is a preparation cost outside the
per-task budget; each request's measured inference time and token counts are
retained separately. Greedy decoding does not guarantee identical outputs on
different hardware/runtime implementations.

`local_model_adapter.py` is a standard-library-only client exported into the
existing namespace capsule. It has no model files or evaluator implementation
and receives no credentials. Its only inference address is the frozen
loopback service; no redirects, environment proxy, retries or fallback are
used. It sends the complete public task, current files, advertised tools and
language reference. Each completion must be exactly one JSON action:

```json
{"tool":"check","arguments":{}}
```

or the exact current version at completion:

```json
{"version":"CURRENT_CHECKED_SNAPSHOT_ID"}
```

These are protocol shapes, not model-generated observations. The adapter does
not repair markdown, guess versions or node IDs, invent tool requests, or
convert malformed output into a successful submission. Full coordinator
feedback, including failed edits, returns to the same conversation. Both
languages and both editing modes use the same local prompt/action protocol.

## Actual token accounting and failures

The service applies the frozen tokenizer/chat template, checks the **actual**
input token length against remaining input and total allowances, and bounds
generation by the remaining output allowance, model context limit and frozen
per-completion cap. Input IDs and generated output IDs (including EOS) are
retained in append-only inference evidence. Receipts include their hashes,
exact lengths, generated text hash, request hash, model lock and service hash.
Retokenizing visible text is not used as a substitute for generated token IDs.

Incomplete generation and malformed model actions retain measured usage.
Unknown transport or runtime failure retains only the last verified prefix
and reports incomplete cost coverage. Rejected input admission does not
manufacture a zero-token model receipt. A request ID is minted by the service;
the adapter requires the HTTP header/body IDs to agree and rejects duplicate
receipts and model/service/request drift.

The coordinator's existing deadline still kills its adapter. The service checks
a decoding stop condition between generation steps. A long model prefill or an
in-flight inference can finish after the client disconnects; the service ledger
retains that outcome, while the client correctly marks unreceived usage as
unknown. This is not a hard real-time inference or process-wide CPU budget.
Local token counts are resource observations, not provider billing receipts;
electricity, hardware amortization and human time are not assigned invented
prices.

After running, reconcile the raw service ledger against the coordinator's
sealed reports using the separate read-only auditor:

```sh
python -m tools.provider_adapter.local_model_audit \
  --evidence-dir /absolute/inference-evidence \
  --reports-dir /absolute/run-reports --output /new/ledger-audit.json
```

The auditor checks every stored token ID, count, text hash, model/service/request
binding and cumulative receipt. It also binds receipts back to the public task,
initial source snapshot, tools and budget. Unfinished requests, runtime failures
with unknown usage and completed generations the client never received remain
separate visible entries. Consistent local logs remain an observation from a
trusted inference host, without independent model-execution attestation.
For a stronger reconstruction check, run the auditor in the model runtime with
one `--model-dir` for each model in the original service order. It verifies the
complete original asset inventory and rendering source, retokenizes every
recorded prompt and decodes every output ID sequence using the locked tokenizer.
This verifies the text/ID correspondence without substituting retokenized text
for the generator's original output-token count.

## Operator workflow

First provision model directories using public model distributions and retain
their licenses. This adapter never downloads or silently selects a model. A
complete study requires at least two distinct exact model identities. Changing
only generation settings for the same upstream/weights cannot qualify as a
second model in the exporter. Single-model exports are useful for transport
qualification, but the existing study plan rejects them as incomplete studies.
Weight deduplication compares the sorted `(SHA-256, byte length)` multiset of
declared safetensors files, so renaming/reordering identical shards does not
produce a second model. This is file-inventory identity, not a proof against
semantically identical weights repacked into different safetensors bytes.

Freeze each model **before** inference:

```sh
python tools/provider_adapter/local_model_service.py freeze \
  --model-dir /absolute/model-directory \
  --repository OWNER/REPOSITORY --revision EXACT_40_HEX_COMMIT \
  --max-input-tokens 16384 --max-new-tokens 1024 --threads 2 \
  --prompt-format tokenizer_chat_template \
  --output /new/model-lock.json
```

The repository/revision placeholders must be replaced with actual immutable
model provenance; they are not usable model IDs. Run the inference service in
an environment with installed `torch`, `transformers`, `tokenizers` and
`safetensors`. Supply matching pairs of `--lock` and `--model-dir` arguments:

```sh
python tools/provider_adapter/local_model_service.py serve \
  --lock /absolute/model-a-lock.json --model-dir /absolute/model-a \
  --lock /absolute/model-b-lock.json --model-dir /absolute/model-b \
  --port 19073 --evidence-dir /new/inference-evidence
```

After the service starts, export the exact public client configuration outside
the repository:

```sh
python tools/provider_adapter/local_model_export.py \
  --service /absolute/inference-evidence/service.json --port 19073 \
  --output /new/local-adapter --metadata-out /new/adapter-configs.json
```

The models array for the normal `experiments.crossfile_eval plan` command is
the `models` array in `service.json`. Pass the exported `adapter-configs.json`
and a qualified Rust compiler. Use the existing complete plan/schedule runner,
the exported `command.json`, `--network` for loopback access, and **no**
`--pass-env` credentials. All four arms for a model use the same exported
bundle and frozen service identity. Every planned failed/missing/timed-out cell
remains in the denominator. Replacing a model, tokenizer, engine, budget or
adapter requires a new plan; it cannot relabel old runs.

Only real receipt-bearing, isolated attempts can enter the existing study
comparison. The `network_requested` flag is true because loopback access uses
the existing shared-network adapter profile. The client code itself restricts
the endpoint; the namespace is not a network firewall against a malicious
replacement adapter. Generated program execution retains its separate network
namespace and existing compiler/oracle boundary.

## Qualification

```sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest tests.test_local_model_adapter -v
python -m experiments.crossfile_eval probe
```

The unit tests exercise synthetic completions and dummy data files. They do not
load a pretrained model, claim real token observations, or establish Hepta
productivity. They cover all four public tool arms, stale final versions,
invalid actions, receipt drift/reuse, incomplete generation, metered overruns,
unknown-cost failures, file identity, model path rejection, and frozen bundle
compatibility with the existing evaluator.

Real model execution additionally needs appropriate model assets, runtime RAM,
disk space and a working strict namespace. A failed nested-host probe does not
authorize disabling namespaces; execute the same probe in an independently
authorized outer environment if available. A native protocol or model transport
qualification is separate from the full two-model study and from a positive
language productivity result.
