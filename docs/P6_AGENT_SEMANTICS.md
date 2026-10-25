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

## P6 addendum: pinned two-version contract comparison

`hepta.agent_contract_diff.compare_pinned_contracts(before_store, after_store,
expected_before_version=..., expected_after_version=...)` compares two immutable
published v4 workspace pins using the existing `inspect_pinned_semantics` query.
Both exact version digests are required, both published native receipts must
still qualify, and compiler identities must match. It detects function additions,
removals, and changes in return type, parameter ownership, declared/inferred
Effects, and resources, plus project-level interface and foreign-obligation
differences. The output has a canonical SHA-256 receipt.

**This is strictly a contract diff**. Existing v1 inspection does not export
complete function-body IR or proof of functional equivalence. A pair of sources
that has unchanged signatures, Effects and resources may still have changed
function results. The diff explicitly says `function_bodies_compared=false`
and `functional_equivalence_proved=false`. A successful comparison neither
re-runs rustc nor authorizes a v4 write. See
`tests/test_agent_contract_diff.py` for positive and forged-receipt negatives.

No production P6 blocker (real models, multiple seeds, agent labor/economics
and large-project edits) is closed by this additive read-only API.


## P6 stable source identity across v4 workspace versions

The canonical checked frontend preserves absolute file paths within immutable
`versions/<content-hash>/tree` directories. These change whenever a workspace
version changes. Agent semantic inspection now reports both the original
`path` (for diagnostics) and a normalized `source_relative_path`, computed
against the **single pinned workspace root** and checked for exact membership
in `manifest.validated_sources`. Unknown and escaped paths fail closed.

`compare_pinned_contracts` uses the tuple
`(source_relative_path, function_name)` as its cross-version identity.
It must not mistake a new immutable version root for removing and re-adding
all unchanged functions. Tests cover two differing absolute roots, forged
relative paths, missing origins, escapes, and unknown source inventories.
This is still a contract diff, not a behavior comparison or a new permission
to modify the workspace.

The pinned import graph is rechecked after path normalization as well as before
and after semantic lowering, narrowing the remaining window for noncooperating
filesystem writers. Such repeated reads are not a filesystem atomic
compare-and-swap or a proof against fully adversarial same-user mutation.
