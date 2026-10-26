# Frozen HIA editing-interface microstudy

This study compares an actual agent editing interface on eight fixed unsigned
integer repair tasks. It is a new experiment, independent of the historical
four-task GGUF pilot. That pilot's failures and unfavorable token result remain
in the repository; this experiment does not relabel them.

## Design fixed before generation

Two official Qwen2.5-Coder Instruct GGUF models, 0.5B and 1.5B Q8_0, are identified
by repository revision and exact model-file SHA-256 in `models.lock.json`.
They are two sizes of one model family, not independent model-family coverage.
The runner owns one offline llama.cpp server at a time, validates its private
Unix-socket peer, and retains its executable/shared-library identities,
tokenizer inputs, raw completions, token IDs and actual generation settings.

| Arm | Context | Response and admission |
| --- | --- | --- |
| HIA full | Complete canonical program with implementation and caller functions | Strict JSON edit of one declared instruction field; whole-module verification |
| HIA query | Deterministic typed view of the selected instruction and local dependencies | Same strict JSON edit and same whole-module verification |
| Rust full | `kernel.rs` and its actual `main.rs` caller | Strict JSON replacement of one declared expression/operator slot |
| Rust query | Function signature, expression template and current slot | Same strict JSON replacement and compiler/native validation |

HIA has two functions in one module. Rust has two source modules. This is not
evidence of multi-module HIA maintenance. The full/query comparison changes
both representation and context, so it does not isolate a pure context-slicing
effect. Both languages have frozen admissible alternatives; arbitrary Rust
source is not executed. The cases and oracle answers are absent from prompts.

Tasks cover a strict capacity bound, low-byte masking, XOR, multiplication,
modular subtraction, overflowing increment, unsigned minimum and ceiling half.
Each task includes boundary inputs. There is one greedy attempt per cell,
seed zero, and a 256-token response budget. Arms rotate by task and model index.
There are 64 planned comparative generations and four format-eligibility
probes. No retry, Markdown extraction or later rescoring is permitted.

Before inference, 32 original/fixed native controls must exercise both
languages. A load or execution infrastructure failure does not count as
detection of a semantic bug. Every accepted model edit is compiled and actually
executed against an independent arithmetic oracle, not merely checked for
type validity or compared to another generated implementation.

## Prespecified comparisons and limits

Per model, the HIA query arm must solve at least seven of eight tasks before
any finite comparison criterion can pass. The primary criterion additionally
requires at least as many successful tasks as Rust query and no more total
task input/output tokens. The secondary criterion requires at least as many
successful tasks as HIA full and strictly fewer task tokens. Incomplete
execution, missing responses, changed source/tool/model identities, or failed
native controls cannot pass a comparison.

The report retains inference and evaluation elapsed time separately. Missing
usage or elapsed measurements make the corresponding attempted-task total
unknown (`null`); separate known subtotals and unknown counts are retained.
An incomplete generation never becomes zero total cost. Token
comparisons cover comparative task requests; setup/eligibility requests remain
in the raw inventory and are not silently removed from execution records.
These measurements do not establish human maintenance effort, model-training
cost, integration cost, general agent productivity or total economic benefit.
General productivity and total-development-cost claim flags remain false even
if both finite criteria pass.

## Reproduction

Commit the implementation and run the functional/performance gates before this
study. Do not run inference concurrently with performance measurement. The
output directory must be new; preserve failed or interrupted runs.

```sh
python tools/qualify_hia_edit_study.py \
  --output /tmp/hepta-edit-study-new \
  --models-lock experiments/hia_edit_study_20261026/models.lock.json \
  --binary /absolute/path/to/llama-server \
  --clang /absolute/path/to/clang \
  --rustc /absolute/path/to/rustc --threads 4
```

The runner writes the complete hashed plan before controls or generation.
Source/model/tool hashes, every request and response, accepted candidate
sources, native artifacts, failure records and terminal reports are retained
under the selected directory. Exact results belong in the associated evidence
bundle, not in this preregistration.
