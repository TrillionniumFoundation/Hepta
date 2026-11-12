# V9: one prospective disclosure-only amendment

V9 adds the independently reviewed, generic node-tool contract information that
was missing from the V8 initial prompt. It does not change the model, budgets,
tasks, examples, hidden gates, accepted programs, edit authority or host behavior.
The original V8 implementation and evidence remain unchanged.

## Exactly what changes

The new `prompts.py` is the V8 prompt implementation with only two strings changed:

1. Both node interfaces state that every node ID occurs at most once per batch.
2. Rust states that a type node receives one allowed type expression, an expression
   node receives one complete expression, and same-file edit spans must be
   pairwise disjoint: choose a parent or its descendants, never both.

The complete source catalogues, source/query revisions, public examples, full-file
prompts and retry/history behavior are unchanged. No target node, answer, extra
example, host repair or overlap deletion is added. New entrypoints explicitly
import V9 prompts and source/protocol bindings; they do not call V8's initial
prompt function. V8's generation transport, response grammar, history budgeting,
validation and reference construction are reused without modification. Transport
generation receipts retain their existing V8 format; the study and capacity
schemas and their provenance are explicitly V9.

## Why this is prospective and adaptive

V8 source `33c46cdef12c60faf0c1dbef02ea20caa3ad7d56` completed fresh qualification
with 1/3 tasks correct, eight complete requests, 22,412 tokens and
2,059.597590950 seconds of experiment wall time. Its result SHA256 is
`7f411804f0c161b5ffbc7d54d4065504074e0a3e2acfafac1ba4b1fe009567fe`.
API responses placed whole functions into type nodes; ownership responses placed
statements into expression nodes. Those were actual earlier fragment rejections,
not overlap rejections. Each failed task repeated the same answer three times.
The disclosure omission does not erase or reclassify those failures and costs.

Independent addendum `0201a6e56f334106c56134f350a3689f74c7ab7a` found that the
catalogue's spans did not adequately disclose the API's duplicate/overlap policy.
This amendment follows those observations and review, so it is explicitly an
adaptive follow-up rather than an unbiased sample of models or prompt designs.
It does not assume that the two extra rules will make the pinned model competent.

## Unchanged gates and stopping rule

The fixed 7B Q4_K_M model still has an 8192-token context, at most three submissions
per cell, 1536 output tokens and 900 seconds per generation, four threads and
greedy seed-zero decoding. Previous-response and feedback caps remain 1664 and
1024 tokens, with the same diagnostic-only clipping and full-code retention.
The protocol loader rejects changes to model, runtime, arms, tasks, generation,
history, native/resource budgets or the fixed qualification task list.

Before any model generation, the final frozen diff and protocol receive independent
review. All nineteen reference responses then undergo fresh native/public/resource/
terminal hidden and actual tokenizer/template capacity controls bound to the V9
source and prompts. Old V8 capacity and qualification records cannot be reused.
Main is allowed only after a fresh 3/3 V9 qualification and a clear independent
review. The sixteen main cells, ordering, budgets and acceptance requirements are
already frozen before qualification.

If this V9 qualification fails, no further prompt changes against these same tasks
or pointless repetition of the same 7B run will follow. Its failure and all costs
will be retained, main will remain unstarted, and an independently capable model
will be reported as the remaining empirical requirement. Reference and CI controls
never count as model successes. No general language, Agent-efficiency, long-term
maintenance or whole-language safety claim follows from these finite controls.

## Separate entrypoints and CI surface

- `tools/qualify_hia_agent_tool_capacity_v9.py`: fresh nineteen-row capacity and
  reference controls, with zero generation requests.
- `tools/qualify_hia_agent_toolstudy_v9.py calibration`: fresh Rust-node qualification.
- `tools/qualify_hia_agent_toolstudy_v9.py main`: checks V9 capacity, protocol,
  prompts, source, model, companion runtime files and qualification before generation.
- `tests/test_hia_agent_toolstudy_v9.py`: seven no-model checks for exactly the
  registered prompt changes, unchanged query/catalogue and retry behavior, immutable
  conditions, reused acceptance code and rejection of old eligibility.

The new CLI control-flow copies differ from V8 only in the explicit V9 prompt/
support imports and capacity schema. Shared finite parser, production HIA batch/
patch, type/ownership, compiler, public/resource and terminal hidden gates remain
the same objects. Unified CI may exercise that shared reference-validation path
with explicit current provenance; such CI records are neither tokenizer capacity
controls nor model qualification.
