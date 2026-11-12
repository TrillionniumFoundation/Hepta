# V13: select the public node before generating its replacement

V12's retained actual b11669 grammar generates `changes` before `node`. The
schema constructor declared node first, but the common canonical request
serializer sorted object keys. The pinned server uses ordered JSON, preserves
schema property iteration order and emits required object properties in that
order. This is a concrete interface defect; it is not evidence that correcting
the order will make the model solve the tasks.

This explicit followup retains the same model, three calibration tasks, four
main tasks/arms, examples, hidden/native/resource gates, 8192-token context,
1536-token output, three-submission limit and model service owner. V12's 0/3
results and cost remain historical failures. There is no fresh-model or new
independent-holdout claim.

## Changes

- Node completion requests retain schema insertion order; each edit selects
  its public node before generating its changes. Exact transmitted bytes and
  returned server grammar are recorded and checked. Historical profiles keep
  their original canonical completion bytes; full arms keep those bytes too.
- Rust type nodes admit the entire already-disclosed scalar/Vec<u8> type
  grammar in canonical spelling. Every editable expression and type ID remains
  present. Expression text and HIA replacement values remain open and untrusted.
- All arms get the same generic instruction to check the full specification
  and resubmit complete rejected transactions. Both node arms get public node
  selection/disjointness guidance. No task answer or selected repair site is
  added. The unchanged initial task content and examples remain present.
- Fragment errors name the selected public node, expected category and original
  span. No replacement text or suggested answer is supplied in diagnostics.
- Capacity controls are rendered in schema grammar order, with their JSON
  values exactly unchanged. This control-only rendering is never called on a
  model answer and never enters generation or program admission.

`contracts_v2.py` has no task/reference import. Query digests still bind the
complete public catalogue, and the tool reconstructs it from actual source.
Duplicate/overlapping edits, stale identities, syntax, type, ownership, native
and behavior checks continue to run independently. Public decoder constraints
are not a source of program admission authority.

## Frozen experiment discipline

Run capacity, then one fresh calibration, from a clean fixed source commit.
Main requires 3/3 calibration with complete known usage and actual ordered-wire
checks. A failed calibration is terminal for that frozen experiment. Do not
adjust prompts/budgets or merge model edits after observing the output.

The versioned runners are `tools/qualify_hia_agent_tool_capacity_v13.py` and
`tools/qualify_hia_agent_toolstudy_v13.py`. They retain the previous owned-process,
raw SSE, tokenizer, identity, finalization and resource accounting mechanisms.
Every main comparison remains descriptive and limited to these tool bundles.
General AI development or long-term maintenance superiority is unproved.

The exact upstream source paths used for the order analysis are recorded in
`UPSTREAM_WIRE_ORDER.json`; the retained V12 actual grammar regression is in
`tests/fixtures/hia_agent_toolstudy_v13/v12-selection-after-changes.json`.
