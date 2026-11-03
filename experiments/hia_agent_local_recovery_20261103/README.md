# Independent local-model recovery cohort, 2026-11-03

This directory prepares a new cohort after the measured host startup and
account-availability diagnostics. It is not completion of the unavailable
frontier-model cohort. Its presence is not a result of an inference experiment.

`PROTOCOL.json` is byte-for-byte identical to the three-arm v4 protocol. The
adapter imports the original fixture, evaluator, owned model engine and scoring
implementation. It does not change any task, prompt, answer schema, model file,
family/cell order, budget, hidden-feedback rule, timeout handling or gate. The
original source directory, registration and result artifacts remain unchanged.

The two fixed families are Qwen2.5-Coder 1.5B Instruct Q4_K_M and Granite 3.3 2B
Instruct Q4_K_M with the original official revisions and SHA-256 values. Each
receives four authored arithmetic maintenance/upgrade tasks in HIA JSON,
compact HIA assembly and Rust: 24 cells total. Each cell has at most two
submissions, 2,048 output tokens and a 180-second whole-generation deadline;
context is 8,192 tokens, CPU threads four, greedy seed zero, prompt cache off
and `LLAMA_ARG_REPACK=0`. A transport timeout ends that cell. Hidden evaluation
is terminal. No answer is repaired by a human or rerun to obtain a better score.

## New registration and owner evidence

The registry and all raw artifacts are new absolute directories outside the
source checkout. Before freezing, 30 orchestration/admission controls, the
inherited 36 reference/partial-migration controls, nine hostile-provider
controls and two non-generative tokenizer-capacity checks must pass. Test
fixture output is explicitly not model output. The adapter binds the complete
`hepta/*.py` inventory in addition to the loaded dependency closure, both
protocol files, inherited study sources and its own source. Every source must
already be committed. The new registration includes the exact Git commit and
tree; validation at each original cell boundary also checks those identities.

`freeze` publishes the inherited registration and recovery metadata together in
one exclusive write. It refuses an existing registration and requires the exact preparation
commit/tree, an integer zero model-request count, and unchanged identities for
all four recorded control/capacity receipts. Replacing a receipt after preparation
requires a new preparation rather than silently adopting it into registration.
These hashes detect drift; they are not independent attestation of the receipt
contents or a defense against concurrent mutation during registration.
Actual generation additionally
requires an independent review of that exact source commit, protocol hash and
registration hash, with zero task requests by the reviewer. The original runner
enforces fixed family order and refuses an existing family output directory.
This adapter does not relax a frozen protocol or revive an old result.

```sh
LLAMA_ARG_REPACK=0 python -B experiments/hia_agent_local_recovery_20261103/run_study.py \
  --registry /absolute/new/owner-registry prepare --output /absolute/new/controls \
  --binary /absolute/pinned/llama-server --qwen /absolute/pinned/qwen.gguf \
  --granite /absolute/pinned/granite.gguf --clang /absolute/clang --rustc /absolute/rustc
python -B experiments/hia_agent_local_recovery_20261103/run_study.py \
  --registry /absolute/new/owner-registry freeze
```

After exact-registration review, use `run` for `qwen_coder1_5b` and then
`granite2b`, with `--review`, `--expected-head`, all pinned tool/model paths and
the same new `--output`. Use `summarize --output` only against that registry.
Full commands, requests, responses, token IDs, validation costs and terminal
failures remain in owner evidence. Public summaries may cite their hashes.
Model acquisition, extraction, source preparation, native controls, engine
startup/restart/hash/shutdown and whole-run wall remain separate recorded costs;
overlapping acquisition intervals are not summed as elapsed time.

The finite descriptive gate is inherited unchanged. These small quantized
models and authored arithmetic tasks cannot establish frontier-model coding
productivity, representative historical maintenance, full human/economic
costs, unrestricted C++ migration or globally optimal instructions. A passed
local cohort cannot turn an unsupported selector, account quota error or
missing provider usage into a successful frontier observation.
