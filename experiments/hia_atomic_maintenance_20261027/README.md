# Frozen atomic maintenance experiment

This is a new protocol, `hepta.hia.atomic-maintenance-study.v1`. It preserves
both earlier studies, including failed preflights and unsuccessful edits.
The publisher revisions, file sizes, SHA-256 identities and quantizations of
Qwen2.5-Coder 7B and IBM Granite 3.3 2B are fixed in `models.lock.json`.
Comparison is within each model; the differently sized/quantized models are
not treated as equal-compute models or a representative population.

## Task and interface changes

Four tasks each contain two called helpers and an unchanged caller. The caller
returns `part_0 * 31 + part_1` modulo 2^32. Both helper contracts require an
edit; changing only either site must fail the independent native oracle.
The eight helper specifications come from the earlier disclosed arithmetic
study. Their compositions and paired-input cases are new, but they are not
eight new independent task sources or production maintenance projects.

| Task | First helper | Second helper |
| --- | --- | --- |
| capacity_roundup | strict capacity predicate | overflow-safe ceiling half |
| tagged_octet | low-byte mask | XOR tag |
| epoch_delta | modular distance | wrapping epoch increment |
| weighted_minimum | wrapping multiplication by three | unsigned minimum |

The four arms are full HIA, atomic HIA query, full Rust and Rust query.
All responses use the same batch envelope, containing two site numbers and
their changed fields. HIA uses the real `hia_edit_batch` API, which captures
one immutable snapshot and rechecks the entire module after both replacements.
Rust candidates are selected from fixed expression/operator alternatives and
compiled with `#![forbid(unsafe_code)]`. Model output cannot introduce arbitrary
executable code into either arm.

HIA has three functions in one module; Rust has two helper modules and a caller
source. This is cross-function multi-site editing, not evidence of HIA
cross-module linking. Full/query changes representation and context together.
The query includes closed local dependencies and consumers; omitted code is
still reverified. Cases, expected results and enumerated allowed answers are
not included in prompts. The complete plan retains them for review.

## Fixed execution and acceptance

- Two families, four tasks, four arms: **32 task generations** plus four format
  preflights. There is one greedy attempt per cell, seed zero, 512 output tokens,
  8,192 context tokens and four inference threads. Arm order rotates by task
  and model index. A timeout or lost response remains an incomplete cell.
- Every generation uses only `json_schema={"type":"object"}`. No task keys,
  answer fields, instruction options or correct values enter the decoder.
- Before inference, **32 native controls** run: each task and language with
  neither edit, only the first edit, only the second edit, and both edits.
  The first three must actually execute and fail behavior; the last must pass.
  Compiler/loader errors or unrecognized crashes cannot count as detection.
- Per model, HIA query must solve **all four tasks**. The primary criterion also
  requires success at least as high as Rust query and no more total task tokens.
  The secondary criterion requires success at least as high as full HIA and
  strictly fewer task tokens. An incomplete study cannot pass either criterion.
- Every request, raw response, parse rejection, accepted-but-wrong candidate,
  native artifact, source/tool identity and unfinished cell is retained.
  No retries, fence extraction, answer repair, clipping or later rescoring.

Token totals compare actual task input plus output. Preflight costs remain in
the generation ledger and must be included when reporting total experiment
cost. Inference and native evaluation time are separate. Model loading,
training, human labor, integration and real upstream upgrade costs are not
measured. General productivity and total-development-cost flags remain false.

## Run

Commit all implementation before inference. Finish native performance timing
before starting a model; inference and timing may not overlap.

```sh
python tools/qualify_hia_batch_study.py \
  --output /tmp/hepta-atomic-study-new \
  --models-lock experiments/hia_atomic_maintenance_20261027/models.lock.json \
  --binary /absolute/path/to/llama-server \
  --clang /absolute/path/to/clang \
  --rustc /absolute/path/to/rustc --threads 4
```

`--controls-only` runs a separately labeled development check without model
inference. It cannot establish any agent benefit. The final run writes its
complete plan before controls or generation and binds the exact source commit.
