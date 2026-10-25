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

## P6 semantic contract completeness hardening

Version v1 read-only inspection additionally exposes the checked, canonical
function visibility and ABI flags (public / extern C / export C), return
loan mode and origin, per-parameter lifetime names, named lifetimes, and
generic type parameters/bounds. It does not infer unproved aliases.

The two-pin contract diff now treats these attributes as per-function
tracked contract fields; previously it could see only a coarse project
interface hash change. Both source and semantic hashes are retained,
and elevated or incomplete foreign-qualification proof flags reject.
Unchanged metadata never proves unchanged behavior; no live project is edited.

## Snapshot-stable module origin (2026-10-25)

The canonical loader reports absolute paths inside the pinned
`versions/<version>/tree` directory; they legitimately change after each
publication. Read-only Agent inspection now validates each function origin
against the same pinned tree root and `validated_sources` manifest, then
publishes its function path (and declaration span path) as a portable
project-relative module path. Unbound, escaped, missing or inconsistent spans
fail closed rather than appearing as an unrelated added/removed function in a
cross-version contract diff. The canonical HSIR hash continues to authenticate
the actual source-bound input, not the normalized presentation metadata.

The consumer independently rejects nonportable or non-manifest paths. This
fixes a contract-identity false positive; it is not a source equivalence,
workspace integrity or compiler soundness proof. Physical hardware, performance
and real-model Agent qualification remain open.
