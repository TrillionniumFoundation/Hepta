# Exact native cold caller predecessors for the original Source2 controls

Base: b990efc55bb53129f158bde67adbc792fe61f8ab.

The original CallerTerminalAdmissionSourceTests and CallerQualifierSuccessorSourceTests could not enter their existing controls after the native cold caller migration. The original GitHub run 46042870632, job 140654746834, rejected the CostLedger and build-inventory test sources at their complete-file identity guards. The two original artifact ZIPs are preserved in the raw archive.

This change captures the actual physical sources and fixed cold history before recovering the exact old caller bytes. It then invokes the existing installed and legacy inverses. Transport, Delivery and Evaluation keep their existing current-source readers, which already perform the cold inverse. No predecessor bytes replace files on disk.

The qualifier control tree also captures the installed-distribution and component-authoring authorities now required by its existing delivery reader. A dependency already equal to the complete fixed QUALIFIER_DEPENDENCY_CURRENT bytes keeps the original capture boundary. Every other dependency still takes the existing current-source history and complete-file checks. The additional control observes both this fixed case and a same-length unknown dependency refusal.

## Actual final validation

All 12 methods completed with zero skips on the exact source projection recorded in qualification.json:

- Eight independent new source methods: current and exact predecessor inputs; same-length unknown bytes; mixed physical captures; missing or changed authorities; terminal readback drift; no cache reuse; unlisted inputs without source exceptions; and the fixed qualifier dependency boundary.
- The original two Terminal methods completed all 140 ordered rows: 15 acceptances and 125 refusals.
- The original two Qualifier methods completed all 278 ordered rows: the original 152 plus the existing 126 dependency controls.

Every original test method AST is unchanged from the base commit. No original fixture, method inventory, assertion, refusal, scope count, or timeout was changed.

The baseline complete-source runs reproduced the original two complete-file refusals. Earlier attempts during this repair are retained, including the rejected double inverse, missing private-tree authorities, and the 12 capture-shape failures that motivated the exact dependency check. Only controls-v4 is the final passing candidate.

## Raw evidence

raw-source-controls.tar.gz is 1,634,423 bytes, SHA256 ba9e6bb513cb3ca6138e90f2a778595ccab32aacad2e4e35d71d55fbec654577. It contains 911 members and 12,799,590 uncompressed bytes: original CI artifacts, local baseline failures, each intermediate source proposal and raw result, and final complete ordered reports. Every archived member was reopened and compared byte for byte with the captured file. archive.json records every member.

This is source-control qualification. It does not grant compiler, VM, native image, full cold, release, installation, or retirement qualification. The source projection uses complete Git blobs from the stated base and is not an ancestry proof. No source or Git metadata in the concurrent owner's repository was changed.
