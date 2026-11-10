# Core-only Agent snapshot component acceptance

Qualified implementation: `60745101c2b073510901ab2f8483d3d37093e5b7`.
Profile: `selfhost-core-linux-x86_64-v39-core-agent-snapshot`.

The optional HIA kernel now validates and materializes Agent byte snapshots.
It preserves exact error/type/range behavior in the finite checks, including
1 MiB outputs, Unicode refusals, output canaries and private concurrency. The
real Agent callers run with both Python snapshot routines disabled. Hosted
object decoding, transport and dispatch remain foreign. Default selection is
unchanged; invalid selected artifacts/results never silently use a fallback.

This Core-only source also repairs two missing live HIA discovery documents and
binds all 11 runtime discovery resources in the actual cold source closure.
These are Core documents, not a restored high-level source-language package.

## Exact-source observations

- Source workflow: 128 tests; clean before/after all six shell steps.
- Fresh isolated original/modified cold compiler: 11 outer and 5,049 native
  checks; all prior witness names retained, compiler limits/ABI unchanged.
- Language: 1,242 native checks plus 10 report assertions.
- Snapshot: 9 native/VM tests, 27 default Agent callers and 21 selected callers
  with both foreign snapshot routines disabled.
- Core safety/editing: 93 tests. Native JSON/linker/stdio/hash compatibility:
  91 tests. All 10 formal stages passed. These finite suites are not a new
  repository-wide regression or an all-input correctness proof.

Formal execution took 329.918 seconds; prior source CI took 157.565 seconds
separately. The retained local archive contains 1,243 regular outer members,
308,179,993 unpacked bytes, 38,504,385 packed bytes; every outer hash/mode was
replayed. All 40 nested lossless stage archives were independently replayed
(54,857 raw members). Earlier development and default-caller failures remain
retained, not rewritten as passes. Archive SHA-256:
`055c626eec460fc8eefcf8a6201365b075dfa8322ea42ca202a0559ab6f28526`.

See `review-evidence/hia-agent-snapshot-20261110/summary.json` and the exact
274-input source manifest for the bounded acceptance and byte-equivalence
boundary of metadata-only descendants. The archive is retained locally, not
a published GitHub attachment.

## Still open

The current source retains 126 package Python files and 235 Python tools. This
is a source census, not a completion percentage. Native module/build integration,
full runtime/library, Agent editing and persistence, installation/release, artifact
lifecycle/recovery and clean-machine real projects remain open. The separate
module-graph and installed-resource candidates are not qualified by this report.
No production/default/service, release lock, Mac or BIOS operation occurred.
