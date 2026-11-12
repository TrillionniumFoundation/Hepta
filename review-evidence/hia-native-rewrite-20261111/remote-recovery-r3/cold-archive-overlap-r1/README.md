# Isolated cold archive admission candidate

The default production source is not changed or activated by this candidate. The original compiler HIA, direct seed, native generation checks, all original and modified semantic phases, two host reference workers, and the owned 180-second qualification plus 3-second cleanup deadline are preserved.

## Observed predecessor failure

Follow16 head 0363c98ea5d24a4f01772b811bb548ce453d30fb, Core run 43126608864 job 130880172461 failed the unchanged cold gate. Read-only follow17 job 130888829114 streamed all 4,575 ZIP members (347,970,610 raw bytes), verified all 580 exported source-manifest members, and preserved the exact original texts. The source archive ZIP is artifact 13903402515, 47,455,748 bytes, SHA-256 214b913ece705de2c8cd15921f09dc5bc64691eedd5e6d341599fa8afadbd869.

The original phase index records 34 completed phases, zero recorded phase exceptions and four pending phases: names/original, names/modified, exports/original and exports/modified. The global result is still FAIL (6 of 11 checks) at 180.145730722 seconds, with owned cleanup complete. B1/B2/B3 and M1/M2/M3 individual receipts exist; an incomplete qualification is not promoted from those receipts. The index does not establish which later allocator check was reached or prove the cause of the timeout.

## Candidate change

The current qualifier seals a stopped phase while occupying one of two oracle slots. This candidate moves only the unchanged complete evidence archive operation to one archiver thread with at most two admitted archive futures. Each phase stays pending until its archive has verified every retained original byte. Archive or native errors remain failures, all outstanding results are collected, and a reused archive future is rejected.

The candidate is built in a separate detached worktree. Its support contract must be identical to the submitted contract except the single exact qualifier source hash. All 579 source identities, compiler HIA bytes, and default submitted inputs are checked. The source-only export still executes the unchanged owned cold supervisor; the driver calls that supervisor directly so an extra outer subprocess timeout cannot kill it before cleanup.

Four new admission controls cover delayed sealing, simultaneous native/archive failures, duplicate archive-future rejection and actual single-worker full-archive backpressure. All original archive controls run alongside them. These host controls contain zero native application entries. A new cold success is admitted only if the unchanged complete 11 checks pass and owned completion is confirmed before the original deadline.

## Status at publication

Source authored and hash verified; zero new AST, control, cold or native executions observed for this candidate. Earlier failures and limits remain unchanged. This source does not qualify the complete native stack, activate the installed CLI or authorize deleting the old implementation.

Source candidate: 0bc5eb3dc49ee79faa67d3ff0d2e504689bab1f8. Controls: 04c3a14e03bafad93b21d5976fad14d73d8dbb38. Driver r2: 8a577f90a566ffd8b71494eb11244a42e404423b. Unexecuted driver r1 d2f833bf8620ab6794f85c8db0725ff1d4be454c is superseded because its outer 200-second subprocess timeout could bypass nested process ownership and its success literal did not match the cold schema.
