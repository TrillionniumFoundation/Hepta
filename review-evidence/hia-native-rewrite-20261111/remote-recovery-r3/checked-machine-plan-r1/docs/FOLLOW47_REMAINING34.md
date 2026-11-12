# Checked-plan FOLLOW47: preserved failure and remaining 34 groups

This is a development component, not the public backend, an installed route, or a cold qualification.

## Actual FOLLOW47 observation

Run 43208616674, job 131150085710 failed. All five production HIA sources compiled with the exact original 35ee B3 and the unchanged 10 CPU second / 20 wall second / 256 MiB compiler limits.

Twenty-one complete groups passed: 355 cases and 15,886 actual native entries. The next group, intervals-0, completed 20 cases and 928 entries before a test call raised TypeError while setting Python's integer digit limit. That next fixture had not called native code. The failed run therefore observed 375 cases and 16,814 entries; it is not a 55-group pass.

The test's error-text string occupied the digits positional argument in two calls. The repair adds only expected_text= at those two locations. Removing those two keywords restores the complete original test byte for byte. Error code 22, both complete error strings, the signature, the 55-group schedule, all original assertions, and every production source remain unchanged.

## New execution boundary

The new driver first runs an independent, target-free reader on artifact 13939673135. It requires the exact 172,872,844-byte archive and 39,747,455-byte JSONL ledger. It copies and completely compares both originals before semantic checks, then verifies every one of the 83,803 members and all 1,350,967,814 original bytes, modes, and SHA256 identities. Input after-checks are attempted separately on success and failure.

The reader restores every CAS page, reconstructs and hashes complete before/after operands, and correlates original entry records, readonly claims, command events, actual ACKs, source/image copies, case results, and canonical/reference records. This is a readback of actual stored bytes. It neither runs the target nor substitutes a new oracle. Source and output documents are never imported.

Only after that reader succeeds does the driver build the same five production images again. Every new HIA source and image must match the original actual bytes and mode, before and after the tests. A production difference stops the directed run.

The new actual test scope is the remaining 34 complete groups: 324 cases and 119 private controls. It reruns the entire original 23-case intervals group, not just its three uncompleted cases. The old partial 20 are preserved as observations and excluded from completed-group credit. The old 21 plus the new 34 must equal the entire original 55-group / 679-case / 119-control inventory with no duplicate group. Any resulting union is explicitly reported as observations from separate runs.

Each reader, builder, and group retains 90 CPU seconds, 180 wall seconds, and 1 GiB. B3 retains 10/20/256 MiB. The outer job remains 110 minutes. No old successful component is reclassified as a new whole public backend result.

## CI input

Use the existing checked-machine-plan tag and job, with actions: read for downloading the exact earlier artifact:

- repository: TrillionniumFoundation/Hepta
- run-id: 43208616674
- artifact-ids: 13939673135
- path: a dedicated directory exported as HIA_CHECKED_PLAN47_ORIGINALS
- HIA_CI_COMMON and HIA_CI_OUTPUT keep their existing exact common and output contracts
- driver: ci/ci_checked_machine_plan_r1.py
- source prefix: review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/checked-machine-plan-r1/

The reader and its input manifest are explicit source-index members. The complete failed job log and all 27 original build/group JSON strings are durable independently. U64 event data is retained in its original JSON text; derived counts do not rewrite those values.

## Status of this revision

The new reader, directed driver, and two-keyword test correction have been created and read back as exact Git blobs. They have not yet undergone Python AST, generation, B3, VM, or native execution. FOLLOW48's independently authored backend-join tests do not include this old checked-plan test file and do not contain the faulty calls. Its actual result remains separate.
