# HIA P5: fail-closed display boundary for untrusted Agent edit contexts

## Exact dependency

Parent PR #302 HEAD `2ea66706d4b0ba307680fffd3995455dbd6b8999`.
This is an incremental API contract repair on the existing P5 Agent editing
code. It adds NO compiler, parser, HIA schema, verifier or LLVM backend.

## Defect

The compact renderers called the existing bounded JSON encoder but then
dereferenced user-supplied nested dictionaries directly. Inputs such as a
missing `context.function`, a list instead of an operation record, or a
boolean batch-site ID could raise `KeyError`, `TypeError`, etc., or
produce plausible-looking but noncanonical site markers (e.g. `@True`).

The public apply APIs already reverified canonical queries and whole-program
patches, so this is a display/input-handling defect, **not proof of a
native code-execution or ownership bypass**.

## Change

- Keep the existing `bounded_json_wire` byte/type/depth gate unchanged.
- Require the precise existing query-envelope field sets before display.
- Require batch site numbers to be strictly typed consecutive integers and
  nested edit-query schemas/record shapes to match the existing protocol.
- Convert malformed nested-rendering exceptions to `HIAEditRejected` while
  preserving ordinary `HIAEditRejected` refusals and valid output bytes.
- Add positive actual-query rendering controls and negative boolean, float,
  duplicate-shaped, missing-context, malformed-operation and oversized-input
  regression cases.

No forged presentation is authorized for application; application continues
to reconstruct source-bound queries and perform whole-Module verification.

## Exact-head execution required

```sh
python -m unittest tests.test_hia_context_render_input \
  tests.test_hia_edit_transitive_context tests.test_hia_edit_query \
  tests.test_hia_edit_batch tests.test_hia_bounded_agent_json -v
```

The code and tests are committed to a draft branch, but full exact-head
Hepta tests cannot run in this isolated environment (GitHub clone DNS and
pinned Rust/Cargo unavailable). This does not claim any P0–P7 production gate
or model-efficiency benefit is closed. `whole_project_blockers_closed=false`.
