# V8 prospective Agent study: complete files versus real node edits

This study builds on the independently reviewed V7 structured editor at original
commit `677a15928c1dd3b236c7bee8cf4b3e6041177f6c`. The V5 and V6 model failures,
their raw outputs, tool restrictions and costs remain unchanged. V7's engineering
controls are not model successes. V8 starts with a fresh, three-task Rust-node
qualification; the four-arm main experiment is forbidden unless all three tasks
pass the unchanged native, public, resource and terminal hidden gates.

## Fixed experiment

The pinned local Qwen2.5-Coder 7B Q4_K_M model receives at most three submissions
per task, 1536 output tokens per submission and 900 seconds per generation, with
an 8192-token context, four threads and greedy seed-zero decoding. The four arms
are HIA full, HIA node, Rust full and Rust node; their order rotates by task index.
All qualification and main cells use the same limits. No whole-function response
is counted as a structured node edit.

The node tool binds the complete original query and source revision captured
before generation. HIA edits invoke the production batch/patch interfaces; a
signature or insertion/deletion edit can require an explicitly reported selected-
field container rebuild. Rust edits use the finite ASCII parser's real expression
and type spans, preserve unselected syntax and then undergo actual rustc and
bounded execution. Full Rust uses that same finite parser. Full HIA preserves the
original entry, block identities and effects. The task's functional/resource gates
are unchanged. This compares tool bundles; presentation and edit granularity
change together, so results cannot isolate context size or language syntax.

## Capacity and reference controls before any generation

`tools/qualify_hia_agent_tool_capacity.py` checks all three qualification responses
and all sixteen main reference responses with real compilers and terminal hidden
observations. It counts complete initial and repair prompts using the owned
server's actual chat template and tokenizer, and checks every reference response's
token IDs against the pinned `llama-tokenize` binary. The server performs no
generation in these controls. Reference implementations and edit selections live
only in the control path; the model runner never imports the reference helper,
reads reference edit lists or puts reference outputs into generation prompts.

Each repair retains the unchanged initial prompt, complete last response and
public feedback. The complete previous response has a 1664-token admission cap;
feedback has a 1024-token cap. Only a diagnostic's displayed prefix may be halved,
with a clipping marker and the complete original retained. Public cases and
resource fields are never removed. If a complete previous response or remaining
feedback cannot fit, the cell ends as a budget failure and keeps all costs.

The allocation table includes an additional 256 tokens for repair framing. This
arithmetic allocation is not a proof for arbitrary BPE concatenations: the actual
complete rendered request is always tokenized again and checked with the entire
1536-token output reserve. No code is truncated, answers merged, hidden feedback
returned, or budgets raised during a cell. Any rejected edit, including public
wrong values, leaves the original project unchanged; a retry must submit its
entire necessary edit set against the same original query.

## Measurements and interpretation

The runner retains exact requests, responses, token IDs, received SSE, compiler
diagnostics, public/native/resource observations, terminal hidden results, source
snapshots, tool/model hashes and process shutdown. Timeout receipts distinguish
known input and received output lower bounds from unknown residual output. A
pre-generation context rejection counts zero new generation requests, while
preserving all earlier consumed tokens and elapsed time. Qualification, references,
startup, hashing and all failed attempts are reported separately from main cells.

The registered descriptive advantage gate requires a complete qualified 16-cell
cohort, complete usage, four correct HIA-node tasks, no lower success rate than
Rust-node or HIA-full, no more total tokens than Rust-node and fewer than HIA-full.
All contrasts are reported even when that gate fails. Four tasks and one adaptively
selected model cannot establish general Agent productivity, whole-language
superiority, verified compilation or actual long-term maintenance costs. This is
a shared development host; `dot` identity is not observable.

## Entrypoints

- `tools/qualify_hia_agent_tool_capacity.py`: actual no-generation reference and
  tokenizer/capacity controls.
- `tools/qualify_hia_agent_toolstudy.py calibration`: fresh Rust-node qualification.
- `tools/qualify_hia_agent_toolstudy.py main`: checks exact new qualification,
  capacity, source, prompt, protocol, model and tool identities before generation.

The machine-readable prospective contract is `PROTOCOL.json`. Original source
commit identity and measured snapshots remain attached to their own records;
later fixes or documentation commits do not relabel earlier observations.
