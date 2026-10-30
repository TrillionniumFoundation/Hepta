# Restore archived CI dependencies after the #399/#400 integration

The exact historical head `46d88bd18b1b3dadb246e92eb22c49fe44ec2d72` completed four workflows successfully. Its verified-optimization workflow passed the 1,119-test zero-skip regression, planning boundaries, guarded opportunity and captured-C application gates, then failed at the first archived-validator discovery command. That failure remains a failure; this directory does not relabel any old execution.

## Cause and minimal source repair

GitHub identifies `0e1f5dd9bf0f54c492d96bd5dd1ae52e8c804997` as the common ancestor of #399 (`e0ab595468d67bcf95485eacd22cea8ff332520c`) and #400 (`1bdb305fc5c6706c0e41ed66a4d43772c297d00e`). The three affected historical directories contained 49 files at that ancestor. #400 kept all 49 unchanged, while #399 deleted all 49. The integration retained those deletions while also admitting the workflow and later fixtures that still depend on the validators. This was an unresolved dependency closure in the integrated tree, not a publication/upload loss. The shallow local history does not identify the individual deleting commit or its intent.

The repair restores only 12 original files (133,205 bytes), each byte-identical to its #400 Git blob:

- The original runner and control tests in `experiments/hia_optimizer_eval/upgrade_continuation_20261028/`.
- The original runner and control tests in `experiments/hia_optimizer_eval/primary_continuation_20261028/`.
- The original protocol and seven Python sources in `experiments/hia_agent_matched_v3_20261028/`.

Existing `next_20261028`, v4, readout and recovery sources retain the integrated 46d content. Historical model archives are not restored or regenerated. The workflow, compiler, production checker, test assertions and acceptance gates are unchanged by this repair.

[Restore manifest](restore/ARCHIVED_VALIDATOR_RESTORE_MANIFEST.json), [ancestry](restore/ARCHIVED_VALIDATOR_ANCESTRY.json), [GitHub compare](restore/ARCHIVED_VALIDATOR_GITHUB_COMPARE.json) and [dependency closure](restore/ARCHIVED_VALIDATOR_DEPENDENCY_CLOSURE.json) record the exact source identities. The dependency inventory covers 28 validator modules and three protocol-data dependencies.

## Actual restored-validator execution

The workflow's six original `unittest discover` commands ran first in an isolated snapshot and again in the restored main tree. Each run retained its own original log and result.

| Original suite | Tests | Failures / errors / skips |
| --- | ---: | --- |
| Upgrade continuation | 3 | 0 / 0 / 0 |
| Primary continuation | 4 | 0 / 0 / 0 |
| Matched v3 | 12 | 0 / 0 / 0 |
| Assembly v4 | 20 | 0 / 0 / 0 |
| Assembly v4 readout | 24 | 0 / 0 / 0 |
| Assembly recovery | 11 | 0 / 0 / 0 |
| Total in each execution | 74 | 0 / 0 / 0 |

These are existing protocol, orchestration, failure and evidence controls. Both executions made **zero real model requests**. The original recovery discovery command does not descend into an unrelated nested directory without a package initializer; its 11 tests are the unmodified gate, not a reduced selection. See [isolated result](restore/ARCHIVED_VALIDATOR_ISOLATED_RESULT.json) and [applied result](restore/ARCHIVED_VALIDATOR_APPLIED_RESULT.json).

## Remaining gates preflighted on fixed 46d source

All ten qualification commands in the subsequent workflow step ran once on separate clean, Git-bound 46d checkouts. Their compiler/build and output paths reflect the local environment. These are existing CI qualification replays, separate from both the pending repaired-head CI and the prospective e223 Ring/NDU/Agent experiments.

| Gate | Actual coverage | Result |
| --- | --- | --- |
| C++ scoped ownership | 1,121 cases across original C++, Rust, C and direct LLVM; leak and destructor-order controls | Pass |
| C++ composed project | 437 cases in each of two configurations; missing-drop rejection | Pass |
| C++ unique ownership | 437 cases in each of two configurations; missing-drop rejection | Pass |
| C++ unique assignment | 789 cases in each of two configurations; missing-drop and cleanup-order controls | Pass |
| Original recursive NDU loop | 30 episodes; actual outputs and budgets checked | Pass |
| Adaptive execution | Eight switching, sealing, tamper, active-call and expiry controls | Pass |
| Owned state | Seven owner, alias, queue, cancellation and allocation-refusal controls | Pass |
| Narrowing | 288 native observations | Finite qualification passes; performance remains unqualified |
| Owned continuation | Ten controls, including actual cancelled prefix, verified switch, unique suffix and release | Pass |
| Agent assembly | 81 VM and 24 native observations; zero model requests | Qualification passes; Agent advantage remains unqualified |

[C++ result](cpp-preflight/RESULT.json) and [runtime summary](runtime-preflight/SUMMARY.json) link to exact commands, source bindings, reports and complete archives. C++ binds 550 source files; the other six gates bind 356. Original setup failures from unrelated missing partial-clone history objects are preserved. No qualification command was retried or weakened.

The recursive NDU executable is the retained original source pin `2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b`, built with Rust 1.90.0, SHA-256 `04b6c861af5dd119a566f9cf1d43f5524f0fa148beeccd2e9fee5bb9bcc518b7`. Its unmodified manifest and actual identity were checked. No finite or stream-profile substitute was used.

The C++ archive retains all four complete reports and generated native products (689 payload members); the runtime archive retains all six products, native binaries and sources (734 members). Two large C++ report extracts were byte-compared with their archive members and removed only as redundant copies; [cleanup receipt](cpp-preflight/REDUNDANT_REPORT_CLEANUP.json) identifies their retained raw members. Archive member checks and execution records remain separate facts.

## Historical remote 46d outcomes

| Workflow | Exact historical run | Actual terminal result |
| --- | --- | --- |
| Six outcomes | [41039944794](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41039944794) | Success |
| Verified optimization | [41039944835](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41039944835) | **Failure at archived validators; step 21 did not run** |
| Assembly closure | [41039944858](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41039944858) | Main job success; optional unrequested NDU job skipped |
| Finite CRC | [41039944804](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41039944804) | Success; economic gate false |
| Native hosts | [41039944865](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41039944865) | Both x86_64 and AArch64 jobs successful |

The [verified failure review](historical-46d/FINAL_46D_VERIFIED_REVIEW.json) and original official ZIP retain the 1,119 executed tests, zero failures/errors/skips, actual source stability and subsequent dependency failure. The [closure review](historical-46d/FINAL_46D_CLOSURE_REVIEW.json) retains 174 zero-skip unit tests, 14 Lean theorem reports, three rejected proof controls, 272 VM comparisons and scoped resource/C++/call-expansion results. The [native review](historical-46d/FINAL_46D_NATIVE_REVIEW.json) retains actual direct-host scalar ABI profiles; no physical-device, RSS or tail-latency result is inferred for those profiles.

The [CRC readout](historical-46d-crc/VERIFICATION.json) checks official archive identity, source/protocol identity, 210 observations, all 2,856 context receipts and economic arithmetic. Study time was 92.733215298 seconds under the unchanged 120-second limit. Its status remains `qualified_no_cold_opportunity`. A full independent bytewise-output audit of an earlier c4fe cohort is not reassigned to this cohort.

## Evidence boundaries

[MANIFEST.json](MANIFEST.json) inventories byte-preserved payloads and explicitly identifies official archives not copied into this addition. Original absolute paths are execution provenance; the manifest maps them to the retained relative files. The six-outcome full archive was not downloaded, so no whole-archive digest verification is claimed. The historical CRC original ZIP was checked and retained in the local workspace and GitHub artifact, while this addition publishes its primary report, controls and checked receipt.

The prospective e223 study results remain immutable. These CI controls do not establish net-positive optimization, NDU superiority, Agent productivity, general C++ equivalence, complete production-checker soundness or end-to-end machine-code safety. The eight-track acceptance ledger remains `all_user_completion_conditions_met=false` and `release_qualified=false`. A new full CI execution must bind the repaired commit before remote integration success can be claimed.
