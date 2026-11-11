# Frozen v67 source: all three original CI observations and independent audit

The frozen source is `608157e52b0b94e0d294f6b99c4e809869f183aa`, tree `e7c29a60796a1a78946a2c667aa80df86529e532`. This checkpoint adds evidence only. It preserves two original successful runs and one original cold failure, without replacing any observation or rerunning a product gate for custody.

| Original run | Actual source tests | Original cold | Remaining original native workflow |
| --- | --- | --- | --- |
| [Head push 43055732930](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43055732930) | 354 PASS, 547.839 s | PASS, 99.255905195 s, 38/38 phases | PASS |
| [Source export branch 43055736686](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43055736686) | 354 PASS, 317.882 s | FAIL, 180.178098861 s, 34/38 phases | SKIPPED after cold failure |
| [Same-tree PR 43055748691](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43055748691) | 354 PASS, 532.898 s | PASS, 130.805543727 s, 38/38 phases | PASS |

The PR actually checked out merge commit `d1a26b4a63f93ec6f54805da75f960226ac5d0eb`, whose complete source tree equals the frozen source tree. The original 180-second limit, two workers, 38 cold phases, all original method IDs and three/five-second caller limits remain unchanged. The failed execution retains its partial phase evidence and process timeout; successful cleanup does not convert it to PASS.

## Exact original retention

The three official ZIPs were downloaded, individually hashed and fully audited. Every outer member and every completed cold-stage nested ZIP was read against original CRC, SHA256, length and mode records. All 682 cold source files were independently bound to the frozen Git leaves. Each ZIP has checked numbered lossless parts and a restorer. An actual reconstruction of each original ZIP was completed and independently reread; working duplicates were reclaimed only after byte comparison. Original audit refusals, scripts and outputs remain available.

`ALL-THREE-OBSERVATIONS.json` holds the machine-readable comparison. Each run has its own subdirectory; successful run archives have a final `audit-originals-r2.tar.xz` and `AUDIT-ORIGINALS-r2.json`, including the first archive and its completed output. The failed export-branch originals remain in their existing `export-branch-43055736686` directory. All three complete raw artifacts are reconstructable from their parts. These are execution records, not newly invented tests.

## Full source and owner audit

The independent source-owner audit is included unchanged from commit `fe2d5e928277a8f189951a3e22f7b7d12347989a`, under `experiments/hia_v67_independent_source_owner_audit_20261111/`. It verifies the actual source package and 4,194 raw Git objects, 4,462 tree entries and 3,925 complete file leaves. It inventories all 161 production Python modules, 481 nonexperimental Python files and 48 in-tree Rust files. It explicitly leaves the separate deployed `hepta-runtime` repository outside this tree's audit.

The `local-source-transport` records additionally retain the actual reviewed source-package consumer and a real independent Git clone: exact commit/tree, strict object integrity, all leaf bytes/modes, separate object inodes and unchanged source states. This local transport observation used its original 900-second process-group budget; it does not claim full descendant/ECHILD supervision or any product qualification. The original ZIP and full source checkout were retained after verified redundant work copies were removed.

## Remaining closure

These results do not establish complete native delivery or complete retained unittest discovery. General backend decisions, mutable assembler labels/fixups/relocations, hosted runtime/storage/installation work and other retained Python/Rust owners still require migration and ordinary-caller proof. The user's requested eventual removal remains contingent on actual complete replacement and verification. No supported old owner is removed by this evidence checkpoint.
