# Frozen atomic maintenance experiment with disclosed choices

The prospective protocol is `hepta.hia.atomic-maintenance-study.v2`. It repairs
a prompt/parser contract defect in v1: the parser required exact per-site
candidate values, but the prompts did not disclose those closed inventories.
V2 exposes the unchanged candidates in every task prompt. The previous studies
and frozen v1 attempts retain their own identities, raw responses and failures.
The publisher revisions, file sizes, SHA-256 identities and quantizations of
Qwen2.5-Coder 7B and IBM Granite 3.3 2B are fixed in `models.lock.json`.
Comparison is within each model; the differently sized/quantized models are
not treated as equal-compute models or a representative population.

The v1 attempt on `32efbbea6bc2140a95482415bafbba66b2bc0680` was interrupted
after this disclosure defect was identified. Its retained observations are
exploratory and invalid as evidence of a comparison with publicly disclosed
candidate restrictions. They must not be rescored, relabeled as v2, completed
with selected v2 cells, or used to change this corpus's candidates. V2 requires
a new source freeze and a fresh complete study in a new output directory.

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
still reverified. Cases, expected results and gold-answer labels remain outside
the prompts. Every candidate, including unsuccessful alternatives, is now
public. The complete plan retains both the corpus and the disclosed inventories.

## Exact candidate contract

Each of the four arms receives an `Allowed replacements (closed set)` JSON
array. Each site identifies its integer `site`, editable `field`, and complete
`allowed_values` list. The instruction explicitly requires selecting one exact
JSON value for `changes[field]` and preserving its JSON type and structure.
For example, HIA `attrs` alternatives remain JSON objects, while Rust numeric
replacement alternatives remain JSON strings. Embedded quotes in Rust
expressions are JSON-escaped, not flattened or rewritten.

The list comes directly from the same `allowed` or `rust_allowed` inventory
that the existing parser enforces. Its order is lexicographic by canonical JSON
bytes, independent of `good`, `rust_good`, test inputs, expected outputs and
prior model responses. No candidate is labeled, promoted or filtered using a
correctness label. Full and query arms within each language receive identical
candidate arrays; their source/context views still differ as before.

The original candidate counts are unchanged for both languages:

| Task | Site 0 choices | Site 1 choices |
| --- | ---: | ---: |
| capacity_roundup | 6 | 3 |
| tagged_octet | 3 | 3 |
| epoch_delta | 3 | 3 |
| weighted_minimum | 8 | 6 |

The response example still contains the current unrepaired values. The parser,
candidate inventories, task contracts, test cases, expected outputs and native
controls are unchanged. `E_BATCH_STUDY_ALTERNATIVE` means a study candidate
contract violation; it does not establish that an operation is absent from HIA
or Rust, nor that native execution observed an incorrect result. Accepted
candidates continue to require the existing native behavioral evaluation.

Before inference, the plan records `candidate_disclosure`, its revision
rationale and `disclosed_choices`, then binds them into `plan_sha256`. The final
report retains the protocol identifier and disclosure policy. The task is a
finite candidate-selection repair experiment, not unrestricted code synthesis.

## Fixed execution and acceptance

- Two families, four tasks, four arms: **32 task generations** plus four format
  preflights. There is one greedy attempt per cell, seed zero, 512 output tokens,
  8,192 context tokens, a 180-second completion deadline and four inference
  threads. Arm order rotates by task
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
before starting a model; inference and timing may not overlap. Keep v1 artifacts
unchanged and use a fresh v2 output directory; this revision supplies no v2 model
result by itself.

```sh
python tools/qualify_hia_batch_study.py \
  --output /tmp/hepta-atomic-study-v2-new \
  --models-lock experiments/hia_atomic_maintenance_20261027/models.lock.json \
  --binary /absolute/path/to/llama-server \
  --clang /absolute/path/to/clang \
  --rustc /absolute/path/to/rustc --threads 4
```

`--controls-only` runs a separately labeled development check without model
inference. It cannot establish any agent benefit. The final run writes its
complete plan before controls or generation and binds the exact source commit.
