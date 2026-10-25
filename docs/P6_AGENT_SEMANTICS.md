# P6: Agent semantic snapshot pinned to v4 workspace

This read-only API extends existing PR #14 `hepta.patch.v4`; it is **not**
a second patcher and cannot alter the live project.

`hepta.agent_semantics.inspect_pinned_semantics(store, expected_version=...)`
calls `hepta.workspace.inspect_workspace` once, binding the version and
patchable node IDs to one immutable published tree. It rechecks the current
compiler identity, originally recorded successful real rustc gate, and
fresh frontend semantics on the pinned entry/import closure. The exact
workspace version is fed into `semantic_ir.lower_checked_program`.
Before returning, it confirms the graph remained unchanged.

Result `hepta.agent-semantics.v1` exposes the canonical HSIR digest,
function types, parameter ownership modes, declared/inferred Effects,
resource contracts, spans, v4 node IDs, foreign assumptions and raw pointer
boundary obligations. Agents can formulate a v4 patch against this frozen
contract with an explicit requested interface policy; the usual complete
native validation must still occur on the **candidate** before publication.

No new rustc run occurs during a read-only query. The published version
must have already been qualified; it is not legitimate to relabel this
read as a formal soundness or functional-equivalence proof. Unknown
project, mismatched compiler, stale expected version, unsupported layout,
modified pin or checker rejection fails closed.

Real provider/model A/B trials, cost, human editing time, project-scale
task success and stable public API compatibility remain open.
