# Unified native source freeze, 2026-11-27

This commit freezes the ordinary merge of the retained exact `2f4ff98` cold failure, explicit Slot observer capture, bound executable-alias capture, and native journal pre-encode reuse. The parent is `bd89c4b6b50ed0b93833799527b291c24fd4923b`. All merged source commits remain parents in the Git history.

The native HIA contract producer was freshly constructed from the independent native roots. The preparation executed 53 native calls, independently compared the complete qualification-driver bytes, serialized the seven-stage and one-stage recipes twice to identical bytes, and verified the resulting native contract against the full source closure. The authority retains 1,282 native files, 60 phase plans, and 479,882 qualification nodes. The qualification/cleanup limits remain 180/3 seconds and scheduler capacities remain 2/1/2/4.

Only `docs/HIA_SELFHOST_CORE_SUPPORT.json` changes in this freeze: the new contract captures the changed `job_launch.hepta` and `cold_qualification_driver.hepta` bytes. The two regenerated development plan indexes remain external build inputs and are excluded from the native source authority.

All 20 existing release-contract, cold-admission-authority, and dependency tests passed. The same working tree also retained a separate unsuccessful invocation of the historical hosted-contract test module: 23 tests with 7 errors and 2 failures, caused by its V1 validator being called on the explicit native domain. A console-backed result summary is archived; the original complete console log was not written to disk. This failure remains open for the explicit CI source-domain migration; it is not reclassified as a native success.

`native-freeze-evidence.tar.gz` preserves the exact native-producer input/output, before/after source identities, physical manifest, complete construction and preparation reports, and the 20-test logs. `MANIFEST.json` pins each original evidence member. This freeze is source preparation only. It does not claim full cold, release, installation, installed rebuild, or whole-stack qualification. Those must execute using this exact source and the freshly matched native roots.

The earlier timed-out cold, including the owner deadline receipt and trace, is retained under `../20261127-2f4ff98-cold-v1`. In its resource samples, the first 25 rows contained cgroup counters showing no quota and no recorded throttling; the later rows lack those counters, so absence of throttling cannot be asserted for the entire interval.
