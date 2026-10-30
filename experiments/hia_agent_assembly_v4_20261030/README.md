# Three-arm Agent maintenance and upgrade study, v4

This is a new study after the retained v3 negative result. It compares **HIA
JSON**, **compact HIA assembly**, and **Rust**. It never repairs or rescores an
old response. `PROTOCOL.json` fixes four new tasks, two original pinned model
families, the three arms, budgets, order, provider obligations, cost fields and
descriptive gates. A successful `register` writes the immutable registration
before any completion request. Results must be read from actual run artifacts;
the presence of this protocol is not a completed experiment.

## New tasks and matching

| Stratum | Task | Requirement |
| --- | --- | --- |
| Maintenance | `average_floor_stamp` | Correct mathematical floor average without losing the u32 carry; preserve the tagged caller |
| Maintenance | `clamped_delta_bias` | Clamp negative differences to zero and retain the complete caller bias |
| API upgrade | `stride_span_v2` | Widen both arguments/result, compute the full `a*(b+1)`, and update the caller tag |
| API upgrade | `floor_multiple_v2` | Widen inputs, introduce validity/count results, and handle zero divisor without trapping |

Both HIA views render exactly the same original and reference canonical Core.
The same mathematical oracle and public/hidden cases apply to all three arms.
Each arm receives its complete two-file workspace and the required public
interfaces. The model must supply complete replacements for both files. No
edit selection, operator choice, or task answer is supplied by a grammar.

The assembly files contain one complete function apiece. The host uses the
explicit immutable manifest shown in the prompt to concatenate them and invokes
the real assembly frontend. It then applies the existing whole-module atomic
patch and scalar source admission. No candidate is repaired, no missing cast or
cleanup is inferred, and incomplete interface migration is rejected.

The Rust prompt enumerates the actual scalar method whitelist. The reused
closed source gate remains a restricted scanner followed by actual rustc; it
does not admit all valid Rust expressions. For example callable-looking `} (`
syntax is refused even when a human could rewrite it as an explicit let binding.
This limitation is retained, not advertised as a Rust language deficiency.

## Fixed execution protocol

Qwen2.5-Coder 1.5B Instruct Q4_K_M and Granite 3.3 2B Instruct Q4_K_M retain the
same exact official revision, file size, and SHA-256 as the prior study. The
llama.cpp b11669 archive identity also stays pinned. Each model has 12 cells
(four tasks by three arms), two attempts at most per cell, 2,048 output tokens,
180 seconds for the entire generation call (template, tokenization and all response I/O), 8,192 context tokens, four CPU threads, greedy seed-0
decoding and disabled prompt cache. The owned process uses `LLAMA_ARG_REPACK=0`.

For each task, arm order rotates `[hia, assembly, rust]` by
`(task_index + model_index) mod 3`. A timeout ends that cell; the next distinct
cell uses a fresh owned server. Source/runtime/model identity or native
infrastructure failure halts the study. No unfavorable cell is rerun. A Linux main-thread SIGALRM enforces the whole-call
deadline; an existing timer or blocked signal fails closed. Constructor errors
after server startup close the still-unassigned owner.

The three public examples supply feedback after the first failed submission.
The 255/254/254/256 hidden cases combine a new boundary grid and new fixed LCG
seed. They run once after the first public pass; hidden failure is terminal and
never goes back to inference. Providers must independently satisfy their output
contract, and the consumer must invoke the provider once with original a,b.
Rust uses a native wrapper counter/direct provider call; HIA uses the same-hash
Core VM trace plus separate native entry execution, not a native HIA call counter.

## Controls, registration and integrity

Before registration, 36 reference/partial-migration controls (24 actual native
builds/executions and 12 expected source/compile refusals), nine native
hostile-provider controls, orchestration tests and tokenizer-only capacity
checks must pass. The hostile controls deliberately compute the right entry
answer with wrong call arguments, a bypassed wrong provider, or an unexecuted
provider. The output alone is insufficient. None of these controls is scored
as a model answer.

Registration binds every study source, loaded implementation dependency,
protocol, fixture, prompt, answer-free schema, and control artifact. Generation
requires the same actual Clang/Rust compiler identities as the reference
controls and the same runner/library identities as the tokenizer capacity
checks. Each scheduled descriptor binds task, stratum, arm and model; duplicate cells or
missing identity costs cannot pass. Cohort readout rebinds the model/source/tool/
runtime/registration identities and recomputes gates from raw cell records.
Tool, model, protocol and source identities are checked at cell
boundaries. Raw requests/responses, native artifacts, execution results and
failures are retained under new output directories.

```bash
python -B -m unittest discover -s experiments/hia_agent_assembly_v4_20261030 -p test_protocol.py -v
python -B experiments/hia_agent_assembly_v4_20261030/run_study.py register
python -B experiments/hia_agent_assembly_v4_20261030/run_study.py validate
LLAMA_ARG_REPACK=0 python -B experiments/hia_agent_assembly_v4_20261030/run_study.py run \
  --output /tmp/new-agent-suite --model-id qwen_coder1_5b \
  --model-path /absolute/pinned/qwen.gguf --binary /absolute/pinned/llama-server \
  --clang /absolute/clang --rustc /absolute/rustc
```

Run the second registered family into that same suite only after the first
family has a terminal result, then use `summarize --output /tmp/new-agent-suite`.
Actual inference runs from a separately frozen source snapshot so unrelated
development cannot change measured code mid-study.

## Gates and limits

For each family and stratum, compact HIA must finish both tasks correctly, have
at least as many successes as Rust, no more complete input/output tokens or
submissions, and no more compilation/public/hidden/identity validation time.
Missing token usage fails the gate. The same gate against JSON HIA is reported
separately to distinguish representation contribution from the Rust comparison.
Both families must pass for a cross-family gate to pass. These are finite
descriptive conjunctions, not population significance or universal superiority.

Known token lower bounds remain separate from unknown full totals. Every failed
attempt and timed-out request counts. Download, extraction, hash/start/stop,
restart, controls, registration, inference, native validation, boundary identity,
whole-run and archive costs are retained with nesting. Parallel preparation
durations cannot be summed as wall time. Human repair is zero in the experiment;
human engineering time and total economic costs remain unknown.

The scalar candidate resource envelope is not a general hostile-code OS
sandbox. Compiler, linker, solver when used, loader, OS and hardware remain
trusted. Small quantized models and four arithmetic tasks do not establish
large-project productivity, complete C++ migration or instruction optimality.
