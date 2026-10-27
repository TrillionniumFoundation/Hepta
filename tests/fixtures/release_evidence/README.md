# Release evidence validator fixtures

These are historical native report structures used only to test acceptance and
rejection by `tools.release_check.require_qualification`. They are not current
qualification results and cannot establish performance, AI productivity, or a
release claim. `provenance.json` records the original reports and byte hashes.

The representative benchmark fixture retains its four profiles, actual samples,
build reports, and text-section comparisons; unrelated command logs were removed.
The resources fixture retains all three independent graph/native reports, with
only retained-graph paths adjusted to these byte-identical test copies. The group
fixture retains its five native scenarios. Tests mutate copies of these fixtures.

Stateful C tests use the already retained historical report under
`evidence/next_blockers_audits/c-ring-fixed-feature/report.json`. Its source
snapshot is mocked to its originally recorded value solely during validator unit
tests. No historical report is relabeled as qualification of current sources.
