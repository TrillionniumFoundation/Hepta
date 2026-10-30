# Public b121 original-execution audit

**PASS for the retained public-source execution records.** This is an additive audit of public `b121c9b4a57a8a58e53360d1d67387d953348f57`, tree `8e39b41544b5fde725a6ed57cc104bfa2f3fa257`, parent `e0b9012a249167b5bc5b0f3bd243899344621080`. The earlier local `40ae7fa8c8d8c82cec0861e4f946e264329a984a` shares this tree, but its executions and independent review remain separately identified and unchanged.

The auditor completed **139,769 read-only conditions**, including both actual filesystem comparisons to all **7,697 raw Git blobs and modes** before and after review. The tracked source contains 447,806,489 bytes. These are audit conditions, not extra test executions. The auditor ran no project tests, native programs or builds.

## Original results checked

| Original public b121 population | Independently read result |
| --- | --- |
| Canonical safety contract | Exactly 340 distinct methods, each appearing once with an ordinary pass, across 36 capabilities. Raw verbose events, terminal count and status, result dictionary, declaration set and reviewed canonical digest all agree. |
| Related native child and linker guards | 13 actual ordinary method passes. Exact selection, raw event order, result dictionary and source snapshots agree. |
| Controlled startup delay | One actual method passes; original child exits are `[-31, -31, -9]`; all three recorded marker checks are absent, with zero reserved children and zero unconfirmed reaps. |

These method populations overlap and must not be added together as independent coverage. The safety execution ran from `2026-10-30T13:01:00.816603+00:00` through `2026-10-30T13:05:30.752551+00:00`. The original canonical contract SHA-256 is `a60ea8fd8014500d6874f2eddb52ea4499a218063a13f2e98691dfd7a2957ae8`; the raw qualification JSON SHA-256 is `34a0bd45116478d74666ab781fa2cab9a0937bec21654730e51446bfbb8b4a69`.

The qualifier's own 1,071-file source subset and the wrapper's full 7,697-file before/after inventories are checked separately against original Git bytes. Reported compiler, linker, Rust, Python, QEMU and Z3 identities match the retained files. All 168 explicitly recorded external inputs remain byte and mode identical: 108 original NDU files, three path-only NDU transport receipts, 56 retained Z3 files and the existing Rust executable. This does not establish complete transitive toolchain or sysroot closure, and does not represent a new Rust build.

The controlled delay record retains the unchanged worker as the exact suffix of the delayed worker. Both fork symbols have actual before-delay and before-original-worker trace events at least 0.35 seconds apart. Their timeouts remain 3.0 seconds; the stall-only timeout remains 0.2 seconds. The original ELF bytes, actual child statuses, observation errors and trace are preserved in the separate complete guard evidence package. This audit reads those original records; it does not reconstruct the official host scheduler timeline.

## Retention and boundaries

`audit/input-manifest.json` binds 206 original input files by byte count, SHA-256, Git blob and mode. The archive retains the audit script, exact source-byte reader, source inventory, method-event readback, input manifest, review, logs and this README. Original owner execution payloads remain in the already-frozen complete guard evidence package; they are not duplicated into this supplement. The source-byte reader is retained exactly as used, and the audit script explicitly selects b121 before calling its read-only functions.

The original official e0 result remains **339 passes and one failed subtest**. This new public b121 evidence does not reclassify that result, modify the original 40ae review, or audit subsequent hosted b121 workflow artifacts. Later P0 sources require their own public execution evidence. Production authority remains Python; optimization policy remains `no_change`; none of the 27 broad P0–P7 obligations is closed by this finite audit.
