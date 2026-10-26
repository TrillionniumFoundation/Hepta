# Independent read-only review of the local model adapter

Reviewed on 2026-10-26 while the real 40-cell matrix was running. The review did
not change provider code, plans, model files or service state, restart a process,
or send inference requests. Existing synthetic protocol tests and additional
pure-Python control-flow checks ran in separate processes and temporary
directories. They are not model-execution evidence.

**The current two-model configuration is unaffected by the two generation
configuration gaps identified below.** The existing four-arm coordinator,
namespace, source/version validation, token accounting and native scoring gates
remain in place. No finding requires changing or discarding this running plan.
This review does not establish complete correctness of the inference runtime or
hostile-host execution attestation.

## Reviewed implementation and evidence

The review covered `local_model_common.py`, `local_model_service.py`,
`local_model_adapter.py`, `local_model_export.py`, `local_model_audit.py`, their
two test modules, and the inherited public protocol/coordinator boundaries in
`openai_chat.py`, `experiments/crossfile_eval/{adapter_binding,runner,reporting}.py`
and `experiments/agent_eval/harness.py`.

The actual service record was
`/tmp/hepta-local-study-20261026/inference-evidence/service.json`, with service
identity:

```text
c3fdf8e008a231f099cfa5fec19168d446f98a9229928e153a9d22685a601a9d
```

Both the repository files and the frozen copies under
`/tmp/hepta-local-study-20261026/service-source/` matched these recorded hashes:

| File | SHA-256 |
| --- | --- |
| `local_model_service.py` | `a2e2672d0950ebe683d22eec2b3c8e28d27f44c91397448d5f37334c8c4111f4` |
| `local_model_common.py` | `c5631ea61cddb53d2349880d40b8ca99b0132852a4b0a421d294181de8b4ff82` |

All files named by the actual exported adapter manifest were hashed and matched.
Its three Python client files also matched the repository copies byte for byte.
The client bundle contains neither model weights nor evaluator/oracle code.

The service records Python 3.12.14, Transformers 4.57.1, Torch 2.10.0+cpu,
Tokenizers 0.22.1 and Safetensors 0.6.2. Its Python executable hash is
`fa67443527ed9647f760d807e2a38f26340757123e643c4639cf273ed15d5ea7`.
The separate provisioning record `runtime-wheels.lock.json` retains wheel
hashes. Runtime metadata is explicitly scoped to versions, executable and
engine/common sources; it is not a complete attestation of loaded native shared
libraries or a proof of which model computation a hostile host performed.

## Actual model configuration checks

The review read the real files, including the base model in the actual shared
memory filesystem. It checked the size and SHA-256 of each model's `config.json`,
`generation_config.json` and `tokenizer_config.json` against its frozen lock.
The weight inventory was read from the locks; this review did not rehash the
large weight files during the running study. The service's startup loader
separately verifies the complete inventory before and after loading.

| Model | Lock SHA-256 |
| --- | --- |
| HuggingFaceTB/SmolLM2-135M-Instruct | `346671a617262a07e66bcb23b08d32c31f4dd243aef0a4c9e922135ebc3287b4` |
| HuggingFaceTB/SmolLM2-135M | `07f283586c6dc9a185375c1531d520db910860dba33ffccb6739648fb1a3af11` |

| Model | File | Verified SHA-256 |
| --- | --- | --- |
| Instruct | `config.json` | `8eb740e8bbe4cff95ea7b4588d17a2432deb16e8075bc5828ff7ba9be94d982a` |
| Instruct | `generation_config.json` | `87b916edaaab66b3899b9d0dd0752727dff6666686da0504d89ae0a6e055a013` |
| Instruct | `tokenizer_config.json` | `4ec77d44f62efeb38d7e044a1db318f6a939438425312dfa333b8382dbad98df` |
| Base | `config.json` | `1d556eab73b69c7f11f64c557a2f9c6f440bd4c6b89bb2584a6b498c92603843` |
| Base | `generation_config.json` | `2056c988e990b0d13670f63f2f3b87b3b6d07edaf7a3416998ba27dab2d8a059` |
| Base | `tokenizer_config.json` | `4bb9af56a342753d39374f4016a16574cab299fe088e896f425ce3c433f61424` |

Both locks specify CPU, bfloat16, **2 threads**, `do_sample=false`,
`chatml_v1`, at most 8,192 input tokens and 512 generated tokens. Both actual
model configurations declare `LlamaForCausalLM` and 8,192 positions. Both
tokenizer configurations have `model_max_length=8192` and disable cleanup of
tokenization spaces. Neither model configuration contains custom `auto_map`
code or a beam/contrastive decoding override.

The Instruct generation configuration contains only `_from_model_config`, BOS 1,
EOS 2, PAD 2 and an upstream Transformers version label. The Base configuration
contains `_from_model_config`, BOS/EOS 0 and its upstream version label. These
labels do not select the runtime: the actual loaded distribution is 4.57.1.

The fixed installed `transformers/generation/configuration_utils.py` was read
directly; its SHA-256 is
`d83f2281f939402be1633a29f3c760e29f5d2f284258d8ed99693b873744074b`.
The reviewed `generation/utils.py` hash is
`a20024b1e82ed5361a524d238d2197be5407abc91297dd9888c57e8284d63fef`.
Their relevant defaults are:

| Setting | Fixed 4.57.1 default |
| --- | --- |
| `num_beams` | 1 |
| `num_beam_groups` | 1 |
| `num_return_sequences` | 1 |
| `penalty_alpha` | `None` |
| `constraints`, `force_words_ids` | `None` |
| `return_dict_in_generate` | `False` |

With those defaults and the service's explicit `do_sample=False`, this exact
pair uses the intended single-beam greedy path. Both models have the same thread
setting, so the process-global thread-setting issue below also has no effect
on this study. These models are two distinct weight artifacts from one model
family; the study does not establish representativeness across model families.

## Findings requiring a future version, not changes during this run

### 1. Heterogeneous thread locks are currently accepted

`TransformersEngine.__init__` calls process-global `torch.set_num_threads` for
each model. It does not restore each model's value during generation. If future
locks request different values, the last loaded value becomes the process
setting for all engines, while their individual locks still claim different
settings. The current values are both 2, so this is a configuration-generalization
defect, not a discrepancy in the running matrix.

The smallest future fix is to reject heterogeneous `generation.threads` values
before loading any engine or publishing a service identity. The service is
single-process, so that rejection accurately describes its supported profile.
Setting one common value once is then sufficient. A per-model dynamic policy
would need explicit serialization and effective-setting recording.

Suggested tests: locks with 2/2 pass; locks with 2/3 reject before any engine
constructor is invoked; reversed lock order still rejects. The rejected case
must not publish `service.json` or load a model. These can be pure-Python
configuration tests and must not be counted as model observations.

### 2. Greedy mode is not fully constrained for arbitrary future assets

The generation call explicitly fixes `do_sample=False`, but inherits other
settings from the asset's generation configuration. For example, an admitted
configuration with `num_beams=2` can select deterministic beam search. A
`penalty_alpha`/`top_k` combination can select a different decoding path, while
`return_dict_in_generate=True` is incompatible with the current tensor slicing
assumption. The complete asset bytes remain locked, but the generic claim
"greedy CPU generation" is broader than the enforced configuration profile.

The smallest future fix is to validate the **effective** generation
configuration after loading, applying the service's already explicit
`do_sample=False` override, and require single-beam greedy mode, one returned
sequence and tensor output. In the current fixed distribution, reject nondefault
beam groups, positive contrastive penalty or constraints/force-words settings
before serving. Alternatively, explicitly set every mode-determining field in
the call and bind that full effective policy into the next service identity;
do not silently describe inherited settings as uniform greedy behavior.

Suggested tests: current Base and Instruct generation configurations pass;
`num_beams=2`, constrained decoding, positive contrastive penalty, multiple return
sequences and dictionary output each reject or are explicitly normalized by a
new documented policy. Tests should inspect the exact effective call arguments
and rejection point. No fallback or partially successful model load may publish
a service record. Any source/policy change requires a new bundle and plan for
future runs; it must not relabel current receipts.

### 3. Multi-shard duplicate-weight detection depends on filename order

The exporter builds its duplicate-weight key as a tuple ordered by file name.
A pure-Python synthetic test supplied two model locks with the same multiset of
weight-file `(sha256, bytes)` identities but exchanged shard names. Export
accepted them as two models. This checks a real inventory-comparison gap; the
synthetic byte files were not models and no inference was performed.

The minimal future correction is to sort the `(sha256, bytes)` tuples before
building each weight-identity key. Test identical multisets with reordered
shard names as a rejection, and a genuinely different content multiset as an
acceptance. This does not prove semantic distinctness under arbitrary re-sharding
or transformations. The present Base/Instruct locks each contain one weight
file with a different content hash, so the order issue does not affect them.

## Identity, isolation, costs and budget conclusions

- **Model inputs:** sorted complete file inventories and immutable commit labels
  bind the supplied bytes and generation settings. Extra files, symlinks,
  traversal paths, Python model files and pickle weights reject. Both model and
  tokenizer loading are local-only and use `trust_remote_code=False`; model
  loading requires safetensors. Claimed repository provenance remains an
  operator assertion rather than proof of upstream authorship.
- **Inference host:** the service and client use literal IPv4 loopback. The
  client has no redirect/proxy/retry path. Loopback is not authentication: a
  hostile local process or host is outside this trusted-service boundary.
  Client capsules intentionally share networking for loopback access; they
  are not a network firewall against replacement adapter code. Bundle and
  executable hashes still bind the exact approved adapter.
- **Token records:** the real engine retains input IDs and the generated suffix
  IDs directly, including EOS, and hashes those arrays. It does not estimate
  generated tokens by retokenizing visible text. The optional full tokenizer
  audit reconstructs prompts and decodes outputs with the locked assets. This
  establishes recorded text/ID correspondence, not independent proof that model
  logits produced the IDs on an untrusted host.
- **Unknown cost:** incomplete generation and malformed actions preserve known
  usage. Transport/runtime failures preserve an unverified pending request or
  the last verified prefix. Missing ledger responses, runtime failures and
  measured-but-unreceived generations remain separate audit categories. Unknown
  work is not assigned zero usage or invented monetary prices.
- **Budgets:** source inspection and four separate synthetic control-flow checks
  confirmed pre-inference refusal for excess input, exhausted total allowance
  and exhausted context, plus minimum output-cap calculation. No input ID array
  was sliced or silently shortened. All 12 synthetic input IDs reached the
  accepted fake call unchanged, with its output cap correctly reduced to 3.
  These are control tests, not real-token measurements. Prefill, HTTP queueing,
  startup and in-flight inference still have the documented wall-time limits;
  this is not a hard real-time or process-wide CPU budget.
- **Replay and four-arm boundaries:** header/body request IDs, payload hashes,
  exact model/service identities and per-session duplicate checks remain.
  Ledger reconciliation forbids reusing a measured receipt across supplied
  reports and verifies task, language, source snapshot, budget and allowed tool
  set. The original coordinator still validates the frozen plan, adapter,
  replicate/sample identity, strict namespace, fresh edit versions, native
  candidate checks and hidden scoring. The local auditor is a consistency
  checker; it does not independently authenticate a host or bind identical
  repeated-task prompts to a fresh coordinator nonce. It cannot replace those
  coordinator and trusted-host requirements.

The existing local-adapter and local-audit suites passed **35/35 tests** in
0.108 seconds. Their synthetic completions and dummy assets are explicitly
excluded from AI evidence. Review results neither award productivity credit nor
drop failed or timed-out cells from the planned denominator. The running
matrix's actual outcomes must be reported separately after its ledger closes.
