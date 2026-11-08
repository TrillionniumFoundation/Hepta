# Independent copied-byte lifecycle review — 2026-11-08

This review binds the actual runtime and qualifier bytes from source `1d1e1f9c069df06b6518d319708d180ab11df215`, tree `77e6cf88787be6769328736aedeb4e99c6426bbb`. It adds one independent byte-adoption restart test without changing the runtime implementation or public release lock.

## Observed results

- Original dedicated copied-byte suite: 12/12, zero skips, 30.999 seconds.
- Added actual adoption/restart/native-consumer test: 1/1, 2.442 seconds.
- Final dedicated suite including the new test: 13/13, zero skips, 17.456 seconds.
- Actual compiler lifecycle qualifier: PASS, all eight recorded checks, 130.607513337 seconds. Its frozen valid, invalid-source and short-output cases completed evaluation and unchanged-artifact adoption.
- The generation-1 leased `f0` compiled the sample to 1,636 native bytes, SHA256 `373a052b3b1e94546b3112ba922854bbe048b1dd33044ee296feb40a82432f9c`. A stdlib-only child executed those actual bytes against three independent recurrence outputs. All three passed without importing compiler modules.

The added test executes actual copied-byte native calls before and after closing/reopening the service. It checks exact idempotent adoption replay, rejection of a fresh request using stale generation/epoch, rollback, old and current generation leases, and rejection of released leases after a second restart.

The compiler qualifier started with the clean baseline tree. During that run the only source-tree edit added the restart test; it does not enter the installation manifest. The runtime, discovery files and qualifier identities remained unchanged, as retained in `REPORT.json`. This is a local manifest-bound engineering qualification, not whole-checkout exact-head CI. The published PR must run its own source CI.

## Audit and restoration

`RAW.tar.gz` (696,868 bytes; SHA256 `b2874efa9f1711fb024903c2a45bf0f74312ee15c6d999d521d20dd30f9cdae8`) retains all 81 original files listed in `MANIFEST.json`: tool intent/response journal, fixture SQLite service state, complete compiler/workload inputs, measurements and cost ledger, adoption receipt, generated image, and all three raw consumer inputs/requests/stdout/stderr. No original file was redacted or omitted. Extract to a new empty directory and verify each manifest size/digest before reading or replaying it. Retained state is data, not executable authority.

The standalone logs and `REPORT.json` duplicate key raw archive members for convenient review. `PUBLICATION_REVIEW.json` records the bounded credential/content check. Artifact and lease IDs refer only to a closed local fixture service; no live account credentials, remote configuration or provider interaction was used.

## Scope

This is scripted compiler/service qualification with an unchanged objective and exact Core reflexivity. It does not create a fresh unfamiliar Agent session, replace its missing provider interaction or invoices, prove behavior equivalence for arbitrary compiler changes, establish borrowed-byte machine refinement, or demonstrate incremental/economic benefit. Required stronger claims continue to fail closed. The six overall project gates remain separately qualified.
