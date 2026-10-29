# Hepta Core continuation evidence

## Explicit-frame continuation on public source `699de39`

The [component collection](next-699de39/README.md) preserves the explicit Rust frame implementation, versioned bound-v3 policy, strict result collector, independent native differential review, and the original CI failures with their finite repairs. Its [archive](next-699de39/hia_core_next_components_20261029.tar.gz) is 8,461,568 bytes, SHA-256 `c255ce520b57f0ee1adf0085ae0fdbb266202934cd8ad9262d4c8bfd81f0b6d0`, containing 486 members. The [receipt](next-699de39/archive-receipt.json) and [member inventory](next-699de39/retention.json) bind the original bytes and distinct component source identities.

The [publication receipt](next-699de39/source-publication-699de39.json) binds local `421ae80` and public [`699de39a8e92e0f083df316ecc5333fb3ecf8571`](https://github.com/TrillionniumFoundation/Hepta/commit/699de39a8e92e0f083df316ecc5333fb3ecf8571) to the same tree `592b6114f659fb18b13ad3fa5ed5e213ecdb92b5`. Component executions are not presented as qualification of a different commit. The new exact-source safety and integrated records are published as a separate continuation after completion.

At this component-publication checkpoint, the exact public source has passed its local 95-method safety contract; the full local eight-gate run is in progress. The archived official CI snapshot is explicitly fixed to 2026-10-29 11:15:39 UTC, with seven ABI and seven C++ host jobs successful, both source/application jobs successful, and NDU/full release still running. This collection contains metadata for the new CI jobs, without claiming their artifact contents have been audited.

Python remains production authority. Optimization policy remains `no_change`; all eight broad P0–P7 stages retain open obligations. Publication of raw evidence does not close general semantics, human productivity, physical-device or refinement-proof requirements.

---

## Original CI artifact recovery after workspace cleanup

This directory restores original GitHub Actions bytes after automatic workspace cleanup interrupted evidence publication. It records recovery and read-only consistency checks. It is **not a new execution qualification**, and recovered observations retain their original source commits.

## Retained original archives

The 31 original ZIPs contain 98,862,709 bytes and 3,530 members (461,999,311 uncompressed bytes). Every ZIP matched its official Actions SHA-256 digest and passed ZIP CRC inspection. The exact metadata is in `original-official-metadata.json`; the full member inventory is in `recovered-archives.json`.

| Original source | Original artifacts | Scope |
| --- | ---: | --- |
| `1669ddc05a918e7c01b17e9262d4461130d44aaa` | 16 | Seven ABI host ZIPs, seven C++ upstream host ZIPs, two source/application preparation ZIPs |
| `5c57fdac77d632a3f3736fba9878b3c16542bae8` | 14 | Seven ABI host ZIPs and seven C++ upstream host ZIPs |
| `3d5401cf9bacddfd6d8f14c806b29ce13bb04eed` | 1 | Original source/application SIGILL failure artifact |

The seven original workflow runs, their job metadata, and all 31 original job logs were fetched again. They appear under `workflow-metadata/` and `job-logs/`. The 1669 and 5c matrix jobs and both 1669 source/application jobs succeeded. The original 3d source/application run failed; its failure is retained unchanged. This collection does not contain the separate full-release run `40799429611`.

## Byte representation and restoration

`raw-artifacts/` contains 41 physical files: 29 whole ZIPs and twelve ordered 4 MiB parts representing the two larger source/application ZIPs. Each of the two large ZIPs has six parts; its last part is shorter. These are lossless original bytes, not re-created ZIPs. Each concatenation was compared byte-for-byte with the complete original ZIP and checked against the official digest.

`recovered-publication-payloads.json` supplies each physical path, byte length, SHA-256 and Git blob SHA. The Git identities reproduce the previously uploaded objects despite loss of the upload receipt. No assertion that a remote ref already contains an object is inferred from its identity.

From a complete published copy of this directory, reconstruct every original ZIP into a new destination with:

```bash
python restore_original_zips.py --evidence-directory . --output-directory restored-zips
```

The destination must not already exist. The helper checks part order, offsets, regular-file status, byte lengths, SHA-256, Git blob identities and official whole-ZIP digests. It does not execute or unpack archive members.

`original-zips/` is a local recovery copy and need not be republished alongside `raw-artifacts/`; it contains no otherwise missing original ZIP bytes.

## Read-only report review

`recovered-report-inspection.json` is authoritative for the final inspection status. It checks all sixteen 1669 qualification artifacts against their embedded source identity, compares their source bindings with raw Git blobs at that exact source commit, explicitly recording Windows CRLF checkout differences, and validates retained report-to-artifact byte identities. Unmodified convenient report copies are under `reports/`.

For each source/application report, the scope is eight routes, 96 inputs and 768 native calls, 48 resource cases, four maintenance cases and two whole applications. Both reports explicitly say `prepared_not_measured`; both have empty measurement sample arrays. Preparation/maintenance observations do not establish representative performance or human productivity improvement. Each Windows C++ report has 150 source bindings identical to raw Git bytes and seven ordinary text inputs matching the exact CRLF checkout conversion. The other five C++ reports have 157 exact raw Git byte matches. These checkout differences are retained explicitly and do not establish universal exact-byte source identity across hosts. Current Python production authority, `no_change`, and all broad P0–P7 proof/qualification limits remain unchanged.

The inspection also scans original ZIP member bytes and job logs for ten specified credential patterns. The scan result and counts are retained, without printing matched values. This finite scan is not a general absence-of-secrets proof.

The first inspection attempts had a report-schema integer/list assumption and Windows path-separator handling and raw-Git-versus-CRLF assumptions in the recovery inspector itself. Their stderr is retained under `inspection-initial-*.stderr.log`. Correcting those read-only parsing errors does not change any original artifact or establish a new source-code qualification.

## Explicit recovery gap

This recovery does **not** restore the old local 3,614-test integrated-run raw files or the frozen supplemental archive with SHA-256 `f393f5872d4b602f523ff35268a658d5c3b81f59e5cfcdcb9f267bef8712fb67`. The former run was reported complete before cleanup, but its original local raw records cannot be reconstituted from summary text. They must not be represented as present in this recovered collection.

The separate older fixed component archive can be restored from its already known Git blob `89389af82be94b692cb0f4a3d0e2c93a4f9ba5e3` and checked against SHA-256 `ee9767816854b0742ef1db5773a40ecf0ac0c7fb4ab6bd34a4272179e0ac6abe`; it is outside this directory's recovery scope.

## Preserved component archive and public recovery checkpoint

The original [component archive](hia_core_components_20261029.tar.gz) is retained byte-for-byte: 2,491,006 bytes, SHA-256 `ee9767816854b0742ef1db5773a40ecf0ac0c7fb4ab6bd34a4272179e0ac6abe`. It contains 364 members, retaining original component source identities. It is not a combined-source qualification.

The [recovery summary](final-recovery-summary.json), [report inspection](recovered-report-inspection.json), [metadata archive](recovered-metadata-20261029.tar.gz), [retention inventory](recovered-metadata-retention.json) and [archive receipt](recovered-metadata-receipt.json) preserve the read-only recovery conclusions. The metadata archive contains the original job logs, official metadata, unmodified report copies, exact inventories and recovery scripts. It is 1,071,659 bytes with SHA-256 `b449f11289f5738e695c6e959385655ffe7b9de5be838a9b751ceb1dbe412578`.

The 41 physical payloads were anchored at evidence commit `b982dbf149492806f889d3f755f7948ed63306da`; the component archive was anchored at `f84ee559074db87898a5004c9b1bdab325668d42`. These evidence commits do not change the qualified source tree. Later source increments retain separate qualifications. The missing local supplement is a recovery gap and is not represented as a successful public raw-evidence closure.
