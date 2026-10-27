# HIA P5: strict Agent presentation identifiers (single and atomic batch)

**Exact parent:** PR #308 `8dec804bcaa747c8fba90e80043541e5a91d9869`.

`render_edit_context` previously interpolated untrusted in-process query
function/block/SSA/opcode/effect fields into raw newline-delimited text.
An attacker-controlled forged view could display additional prompt-like lines
even though the host's later `apply_edit` correctly reconstructs its frozen
query and reverifies the whole module. `render_batch_context` separately
interpolated the same raw fields without using the single-view gate.

The existing display renderer now reuses canonical `hepta.hia_program._ident`
for each source/SSA/name/type/effect identifier. Dotted HIA opcodes are
validated segment by segment with the same canonical lexer. It refuses
malformed selector/output relations, noncanonical edited fields, Boolean or
duplicate operation indexes and oversized context operation counts.

The atomic batch display calls that same already-existing single-edit
presentation guard on every nested query before composing a combined view.
This does **not** introduce a second HIA verifier, AST, LLVM backend or
semantic authority. All actual edit admission still goes through immutable
snapshot replay and the full `verify_program` resource checker.

New tests mutate actual prepared single/batch queries to inject multiline
function/block/output/opcode/effect text, Boolean index aliases and forged
field selectors; the public `HIAEditRejected` gate must refuse. Valid
generated display text is unchanged.

```sh
python -m unittest tests.test_hia_context_render_input tests.test_hia_edit_query \
  tests.test_hia_edit_batch tests.test_hia_edit_transitive_context -v
```

An independent CPython lexical-control probe exercised canonical names/opcodes
and invalid control/punctuation strings (2 isolated tests passed). Full
exact-head Hepta, Cargo and LLVM suites remain **NOT RUN** in this local
environment, so neither native readiness nor a measured AI agent benefit
is claimed.

This is presentation hardening only. Functional equivalence, general
prompt-injection immunity, end-to-end Core→machine refinement, real-agent
A/B, C/C++ L2–L3, hardware and production P0–P7 remain OPEN.
`whole_project_blockers_closed=false`.
