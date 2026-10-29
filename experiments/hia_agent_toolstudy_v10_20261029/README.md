# V10: one prospectively pinned Qwen3 model and official template

This is a separate adaptive study after the old Qwen2.5-Coder 7B qualification
failures. It retains every previous source, result and cost. Only one distinct
candidate is selected: **Qwen3-4B-Instruct-2507**, measured as Unsloth's fixed
**Q4_K_M GGUF**, 2,497,281,120 bytes, SHA256
`3605803b982cb64aead44f6c1b2ae36e3acdb41d8e46c8a94c6533bc4c67e597`, quantizer
revision `a06e946bb6b655725eafa393f4a9745d460374c9`.

The official model is described as non-thinking. The study does not add a
reasoning channel, thinking-control instruction, task hint, example, target node
or reference response. If this candidate fails the fresh complete qualification,
main stays unstarted; no further same-task prompt tuning, pointless rerun or
search through models until one wins follows from this registration.

## What stays identical

`prompts.py` re-exports the exact V9 task prompt, catalogue, message-construction
and repair-text objects. All nineteen task/arm initial messages and queries are
compared byte-for-byte in static controls. The tasks and hidden cases, actual HIA
batch/patch and finite Rust edit authority, parser/ownership/compiler/resource
checks, references, decoder schema and source rollback rules are unchanged.

The single model still receives 8192 context tokens, at most three submissions per
cell, 1536 output tokens and 900 seconds per generation, four threads, greedy
seed-zero decoding and no prompt cache. Previous response and public feedback
caps remain 1664 and 1024 tokens. Complete code is never truncated, reconstructed
or repaired by the host. Three submissions remain a maximum rather than a promise
after an arbitrary over-budget history. Hidden evaluation is terminal.

The same fresh **3/3 Rust-node** qualification is required before the same frozen
**16-cell, four-arm** main order. V9 or any earlier capacity/eligibility cannot
satisfy V10's source, protocol, prompt, model, runtime and capacity bindings.
Reference and CI controls do not qualify the model or measure Agent success.

## The explicit model-template adaptation

Official `tokenizer_config.json` is retained verbatim from revision
`cdbee75f17c01a7cc42f958dc650907174af0554`, 9,377 bytes, SHA256
`a62ff0a2472a0fa1b8eaabcb57c59b58afa42a22831dc141400b6e0cf2b65ce3`.
Its plain user/assistant branch does **not** synthesize the older Qwen2 default
system message. V10's independent plain renderer therefore concatenates the
unchanged user/assistant messages and generation prefix without that system
message. No message content changes.

A small `ToolStudyEngine` subclass inherits V8's generation, grammar, sampling,
SSE retention, tokenization and exact context guard as the same methods. It wraps
only the existing `/apply-template` call: every actual server rendering, including
complete previous-answer/public-feedback repair history, must byte-match this
frozen plain renderer before generation. Both successful and mismatched renderings
are retained. A mismatch fails closed; it does not trigger template fallback,
answer repair, new messages or a different model. This adds no inference/API call.
Startup failures close any owned process.

## Fresh tokenizer and capacity controls

Before any new generation, nineteen human reference responses must pass actual
public/native/resource and terminal hidden controls. Every complete reference
response and every initial, second-repair, third-repair and complete-reference
history rendering receives an independent CLI/server ID comparison: **95 CLI
controls** in total. They are preparation controls with zero model generations;
all call receipts, exact IDs, elapsed time, stderr and failures are retained.

The fixed b11669 source is bound in `provenance/TOKENIZER_CLI_SOURCE_REVIEW.json`.
It shows that the tokenizer executable parses special tokens by default and
processes stdin escapes unless disabled. V10 explicitly supplies `--no-escape`
so literal JSON backslashes survive unchanged. Reference responses use `--no-bos`
to match server `add_special=false`. Rendered prompts use the model's default BOS
behavior and are compared with server `add_special=true`. No special IDs are
removed, inserted or synthesized to manufacture agreement. Any mismatch refuses
the capacity gate with its original evidence and consumed cost.

The CLI loads vocabulary metadata, not inference weight tensors. Both CLI and
server nevertheless use the exact pinned GGUF, binary and companion-library
inventory. These controls verify this measured artifact's internal tokenization
consistency. They do not prove that the whole upstream tokenizer vocabulary or
quantization pipeline was reconstructed correctly.

## Provenance and limits

The selected official and quantizer API metadata, official config/template bytes,
retrieval receipts and pinned runtime source identities are retained under
`provenance/`. Unsloth declares the base model, but no complete reconstruction
attestation from the pinned upstream revision was supplied or verified. The
measured model is the fixed GGUF above. The separately pinned official template
revision is not presented as a proven source-weight revision for that GGUF.

Independent review precedes fresh capacity and generation. Acquisition/model-load
work waits for V9's full result and owned-process exit, with separate disk/runtime
preparation; the active V9 source and model remain unchanged. Source freezing and
all completed preconditions are recorded before the first V10 model answer.

This is an adaptive single-candidate follow-up on a shared development host.
All prior failures and qualification/preparation costs remain attributed to their
original sources. The results do not establish whole-language soundness,
universal AI productivity, long-term maintenance cost, or performance on a
verified `dot` host. `LOCAL_RUNTIME_NOT_OBSERVABLE` remains the location scope.

## Additive entrypoints for CI and reproduction

- `tools/qualify_hia_agent_tool_capacity_v10.py`: nineteen fresh reference/native
  controls and ninety-five exact tokenizer comparisons, zero generations.
- `tools/qualify_hia_agent_toolstudy_v10.py calibration`: one fresh qualification.
- `tools/qualify_hia_agent_toolstudy_v10.py main`: source/model/runtime/capacity/
  qualification gate before any model construction.
- `tests/test_hia_agent_toolstudy_v10.py`: thirteen pure static/mock controls;
  no model, tokenizer, compiler or native execution.

A unified native-only CI wrapper may explicitly select this new support/prompt
binding while reusing the existing nineteen references. Such current-source CI
records are separate from tokenizer capacity and real model qualification.
