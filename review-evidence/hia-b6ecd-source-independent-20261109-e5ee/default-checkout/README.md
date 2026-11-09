# Final B: actual default-checkout provenance

This package reviews original successful jobs from PR817 head 6ecd8023615a6e0b2dc269379fb059c656b38b6f. It does not claim the entire B workflow cohort is qualified. Failures in other workflows are retained and investigated separately; none is replaced by these successful receipts.

## Actual executed identity

All three original job logs identify checkout 16add3df22d58fd5486541837cdaf73a21317c49 from refs/pull/817/merge. The official commit API identifies parents 20eace37747fde9aa0fc9c14cdb0159db30f5161 and 6ecd8023615a6e0b2dc269379fb059c656b38b6f, with tree 4c51962e030e9ea39c6498224c99eb40fbdd2f35.

The actual checkout commit is not B itself. Its tree is exactly B's tree, independently checked against the official B commit API and all retained source identities. This is the result of these jobs' original logs and reports, not an assumption from a prospective PR merge.

| Original run / job | Artifact | ZIP bytes | SHA-256 |
| --- | --- | ---: | --- |
| Linux 42565815367 / 128991967620 | 13652647208 | 3297 | a063080744c087a53f6e3dbaa583da97b3af4ded9b34777edc19d40f40864a9f |
| Safe Core v1 42565815350 / 128991967644 | 13652870106 | 132319 | c4946b010c01edda638db83bc82ea7c686993851c61392c41d3c3d3a57820b4b |
| Safe Core v2 42565815350 / 128991967369 | 13652591429 | 387660 | 2dd90b5248b628f8e6432bbf92ad9e94d0c7248685ec24654bb1070ac7929e02 |

Both runs are original attempt 1. Each compressed ZIP matches the official artifact digest and size.

## Linux receipt

The original receipt's before and after identities both equal actual checkout 16add3d / tree 4c51962e, and source status after the run is clean. Planned, started and finished inventories each contain 83 unique IDs with identical sets. The original job log's 83 successful test IDs match that receipt. The inventory digest also matches the producer's canonical JSON encoding.

Errors, failures, skips, expected failures and unexpected successes are all absent in this job. Its scope remains source contracts and real native leaf regressions. The receipt explicitly denies kernel boot, whole-kernel rewriting, completed global comparison and established NDU benefit.

## Safe Core reports

The original manifests bind 153 and 488 members respectively; every member's size and SHA-256 was checked directly inside its ZIP. Both reports identify the actual checkout and unchanged source. Qualification source manifests contain 22 and 17 entries; all qualification, report and checker source identities match exact Git blobs. Their union contains 24 distinct paths.

All 35 successful validation or independent recheck reports retain subject, property, profile, assumptions, checker and unproved_obligations. Canonical Core identities and exact object/final-image identities match the retained members. Independent consumer records retain compiler_invoked=false, linker_invoked=false, native_execution_observed=false and adopted=false.

The v1 evidence contains three original positive programs, three independent rechecks, five expected rejections and 45 recorded tests. Its 29 retained query replay records preserve the original outcomes. The five negative cases' sat counterexamples remain rejections of the original unsat properties; their consistent sat replay is not promoted into a proof of those rejected properties.

The v2 evidence contains 26 programs, 130 original obligations, replay of those same 130 obligations and three independent artifact rechecks. The program set is the 25 unsigned type-pair cases plus prior-write-before-narrowing. Replaying an obligation does not create another distinct obligation or expand the profile.

These reports do not establish general Core, universal compiler correctness, full hardware ISA refinement, pointer provenance/liveness, concurrency or side-channel guarantees, live activation or Agent adoption. They do not authorize loading or execution.

## Local audit boundary

The two included audit programs use only the Python standard library and ordinary Git reads over original metadata, decoded logs, ZIP/JSON data and hashes. Their exact execution records and output logs are retained. No project code, compiler, native artifact, solver or project test was executed locally. Previous ff456 or 6a CI outputs were not used as evidence for these runs.

Original ZIPs, exact decoded job-log text, API metadata and reports are retained in this package. files.json binds its bytes. The exact-source workflow and broader CI cohort are separate subjects; a later fix or merged commit needs its own qualification.
