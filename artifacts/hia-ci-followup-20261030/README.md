# Late complete-CI findings and native compiler binding

This follow-up retains findings that completed after the original publication
snapshot was frozen. It does not modify that snapshot or any registered e223
Ring, NDU or Agent result. Full final-head workflow conclusions are recorded
in [PR #405](https://github.com/TrillionniumFoundation/Hepta/pull/405).

## Actual zero-skip refusal and one-line repair

The original `000acac3` verified-integration run
[41036215329](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41036215329)
completed 1,117 regression tests with zero failures/errors but **two skips**.
The zero-skip gate correctly rejected the run. Both skipped tests exercise real
native NDU composition and separately owned sessions/caches; they require
`HEPTA_NDU_STREAM_IDENTITY`, `HEPTA_CLANG` and the pinned solver. The workflow
had already built/exported the actual stream bridge and installed Z3, but
exported only `CLANG`, not `HEPTA_CLANG`.

The only production/CI change in this follow-up adds
`HEPTA_CLANG: /usr/bin/clang-20` beside the unchanged `CLANG` environment entry
in `.github/workflows/hepta-verified-optimization.yml`. No test, identity check,
skip condition, budget or gate is removed. With actual pinned stream identity,
Clang and Z3, both previously skipped tests execute locally and pass without
skips in 6.266447064 seconds. Identity bytes are unchanged before/after, and
there are zero model requests. This is a regression check, not another formal
NDU/Agent study or a substitute for final full CI.

`OLD_000ac_VERIFIED_FINAL.json`, the complete original job log and original
2,061,325-byte ZIP retain the failed result. ZIP SHA-256 is
`ba6e182e37928199ee2f69aafc7280aea6ce5f7c1e82073aedc4a075ee549295`, matching
GitHub's official digest. `VERIFIED_ENV_REPAIR.json` and its log retain the
actual two-test execution and patched workflow identity.

## Complete CRC replay on c4fe: qualification passes, economics do not

The distinct source run
[41038692291](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41038692291)
on `c4fe3fa00e9ba9356dc99a98cf43f0a8385be5c5` passes its unchanged protocol:
210 observations, 2,856 contexts and a 120-second deadline. Actual study wall
time is 90.105057232 seconds. All 54 controls pass without failures or skips.
The result remains `qualified_no_cold_opportunity`, with `economic_gate=false`.

The retained `crc-c4fe/AUDIT.json` records an independent read-only check of
all 210 plans, 2,856 context files/trace digests and 13,440 native request results
covering 13,762,560 CRC calls. An independent byte-wise CRC/checksum oracle
matches every recorded response. Six economic-ledger rows are independently
recomputed, all retaining the negative gate. Native image/driver hashes,
source stability and cleanup records also agree. No binary or model was
executed during that artifact audit.

The original successful ZIP remains in GitHub
[artifact 12968099978](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41038692291/artifacts/12968099978)
and in the recorded local audit path. It is 15,229,686 bytes with SHA-256
`6907e821e521b2f8536293df1b60d8088cef8dd3ffabee7976ea658bbf7db649`.
This follow-up includes the audit, API metadata, summary, controls log and audit
script, not another copy of that ZIP or the complete large study RESULT.

The original `000acac3` 121.031788701-second timeout remains failed and its
original archive is retained in the preceding CI evidence directory. New and
old runs complete different work and use distinct source/host observations;
their total times are not divided into a purported controlled speedup ratio.
The successful c4fe qualification is not relabeled as execution of a later
commit and does not establish net optimization, NDU benefit or release fitness.
