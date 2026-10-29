# Addendum: node-batch disclosure in frozen V8

## Decision

Frozen source `33c46cdef12c60faf0c1dbef02ea20caa3ad7d56` does not explicitly
tell the model that node IDs must be unique within a batch, or that selected
Rust byte spans in the same file must be pairwise disjoint. The catalogue shows
the spans, but does not define whether overlapping requests are rejected,
ordered, or composed. This is a tool-contract disclosure omission, not a
failure of the validator's safety boundary.

For the intended fair four-arm tool comparison, **hold the unstarted V8 main
and make a minimal prospective registration before a new main**. Retain the
already started V8 qualification under its original rules, exact outcomes, and
full cost. Do not alter its source, inject a new rule into a repair request,
replay a repaired answer, or use its eligibility for a changed prompt.

The old observations remain valid descriptions of that exact deployed tool
bundle. They do not become invalid files or disappear from the development
cost merely because a better disclosure is now proposed. Even with complete
disclosure, this finite study compares tool bundles, not the causal effect of
Rust versus HIA language syntax in isolation.

This addendum records an additional issue found after review `f52d459`.
It does not relabel or withdraw that review's source/hash checks, 19 successful
human-reference controls, or scoped capacity arithmetic. Those engineering
results did not test every user-facing rule for explicit disclosure.

## Two distinct findings

| Observation | Classification | Consequence |
| --- | --- | --- |
| The model supplies an entire `pub fn` definition to a node labelled `type`. | Normal misuse of an already disclosed interface. The prompt requires expression/type fragments and explicitly forbids whole functions. | Preserve the actual rejection. No functional or Agent success may be inferred from an apparently plausible function in the rejected text. |
| The prompt does not state the unique-ID or pairwise-disjoint-span rule. | An independent missing part of the tool contract. | Disclose it in a new prospective prompt before using a main cohort for a fair comparison. Do not claim it caused a different earlier rejection. |
| A complete Rust catalogue contains enclosing expressions and their descendants, while HIA's instruction catalogue usually does not create the same nested-span choice. | The information omission has an asymmetric practical burden. | Equal token limits and a correct host rejection alone do not make the API instructions equally complete. |
| The host can return an overlap diagnostic after a submitted batch reaches that gate. | A useful public repair mechanism, not prior disclosure. | It can consume an attempt to discover the rule; it does not retroactively place the rule in the initial prompt. |

The operative source is `editing.checked_edits`, which rejects duplicate IDs,
and `editing.propose_rust`, which first validates each fragment and then rejects
intersecting same-file ranges with `left.end > right.start`. The latter permits
adjacent ranges and edits in different files. Whole function definitions are
not accepted as type fragments, so such an answer fails before the overlap
check.

## What the two completed responses actually show

Only completed `attempt-0` and `attempt-1` from the Rust-node
`two_file_signature_repair` cell were examined. No partial third response or
later result is classified here. The source remained frozen and no validator,
parser, compiler, VM, tokenizer, or model was run by this reviewer.

Both completed answers contain 16 distinct node IDs, with **no duplicate ID**.
Seven selected type nodes receive a complete function definition. Both actual
evaluation records report `response_rejected` with
`E_STRUCTURED_RUST: only disclosed scalar/Vec<u8> types`.
They did **not** reach the overlap rejection.

Counting intervals directly from the captured original query finds 18
overlapping selected pairs in each answer. This is a static description of the
submitted IDs; it is not a replay of a modified answer. Removing the invalid
type fragments and then evaluating the remainder would be a different answer.
No such modification or counterfactual execution was performed, and no result
is credited to it.

Accordingly, the current two failures must not be attributed to the missing
overlap sentence. They also cannot establish weaker Rust language capability:
they primarily show this model's failure to follow the specified node interface
on those submissions. The separate disclosure omission is a reason to improve
the prospective comparison, not an explanation invented for these failures.

## Minimal prospective change

The reviewed, **unapplied** candidate patch changes two generic strings:

- For both node arms, say that every node ID appears at most once in a batch.
- For Rust nodes, say explicitly that a type node receives one allowed type
  expression, an expression node receives one expression, and same-file edit
  spans must be disjoint: choose a parent expression or its descendants, never
  both.

These sentences describe existing acceptance rules. They do not introduce
reference answers, target node IDs, task-specific examples, extra repair
attempts, a weaker validator, automatic overlap removal, or inferred casts and
parentheses. Existing captured-query and all-or-nothing retry rules remain.
No new parser/editor authority is necessary for this correction.

If adopted, publish it as a new prospective registration, retain V8 as the
preceding adaptive attempt, rebind actual prompt/template capacities, and use
fresh qualification under the new source/prompt identity. The new main must
still meet its own qualification gate. Keep the task set, hidden cases,
model, acceptance rules, and generation/repair budget unchanged unless a
separately justified revision is registered before inference. Do not tune node
selection or examples from these observed answers.

## Evidence attribution

Completed producer files were read from:

`/tmp/hepta-next-agent-v7-toolstudy-v8-qwen7b-01/two_file_signature_repair_rust_node/`

The evidence receipt under
`experiments/hia_next_safety/toolstudy_overlap_review_20261029/` records the exact
query, completed response/evaluation/request digests, frozen source digests,
unapplied candidate patch digest, and static interval counts. The completed
producer records are copied unchanged. The receipt intentionally makes no
claim about the whole ongoing qualification, any third response, or a main
result.
