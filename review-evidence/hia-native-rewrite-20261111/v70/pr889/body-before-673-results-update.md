## Current results for published source `8aadee8b8bfc1bda940c9c32b2964429be358e1c`

This remains a draft integration PR. Whole native delivery, default/native selection, live migration, and removal of the previous owners remain **false**.

| Gate / observation | Exact current result |
| --- | --- |
| GitHub push run [43098596489](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43098596489), source job | PASS: regeneration/diff gates and 527 original source controls. Both job logs show checkout of the full commit above. |
| Same run, cold replay | Reported PASS, 11/11 original checks. Original and modified compiler fixed points are preserved. |
| Same run, language coverage | PASS, 1,242/1,242 checks and all 10 original report assertions. |
| Same run, native pipeline | FAIL at step 21: two `setUpClass` errors before the program-execution candidate is built. The explicitly configured evidence parents are missing. The later structural-budget and remaining native stages were skipped by this original run. |
| Independent remote clean-source gate on the same tree | 8/8 stages PASS; 527 source controls plus the three original scalar-proof controls passed. Source, harness, and interpreter identity stayed unchanged. This is a separate observation from GitHub CI. |
| Minimal fixture repair | Authored as blob `7cb722438350ec818f8713515bd83699dc769a28`; pending a new isolated source revision, regeneration and qualification. It creates only the evidence parent **after** cold admission; the original builder still creates the candidate exclusively. |

The complete original source/native job logs, failed setup traces, and authored fixture repair are retained in [audit commit 09b7d595](https://github.com/TrillionniumFoundation/Hepta/commit/09b7d5952017accddf29ba96fb599b521e2bc671). No failing run was replaced by a later run.

### Parallel implementation work, outside this published source

- Public heap revision r5 now compiles its controller under the original compiler limits. A new development comparison passed 9 of 11 controls, including the seven public entry examples with complete report/hash comparisons and poisoned old heap/static callbacks. Two actual payload-report string-alias comparisons failed despite equal values; their original observations are retained and are being fixed. This is not whole-domain qualification.
- The original normalization baseline process completed with exit 1: its reporting harness attempted to JSON-serialize a `bytes` value in an exception cause. Original logs and products are retained. A new observation scope rechecks and reuses the existing products; it does not overwrite the failed original run.
- The new four-case deadline phase diagnostic on unchanged `e03c82d1b5b7026ead9a5942336d54273b1a6931` completed with 2 PASS and 2 ERROR, exit 1, no supervisor timeout. The original 3,000/1,000 ms limits and test bodies are unchanged. Within each failing context window, 158 fresh complete-source digest calls took 2.3915 s / 2.3387 s. All four original event streams were transferred and independently hash-checked; timings are instrumented and CPU overlap is unknown. This is diagnosis, not a replacement qualification or a source-cache optimization.

The earlier published-source snapshot below is preserved as historical context.

<details>
<summary>Earlier v70 publication and prior qualification records</summary>

## Current v70 candidate: structural budgets, full native closure pending

Current commit: **8aadee8b8bfc1bda940c9c32b2964429be358e1c**. Exact tree: **6b1c399fcdfcc38e89b0291a56b2ea2560646dfe**. Parent: **8ca2197693c98e48d0d16ab3c077efc7cd535653**.

Structural resource budgeting still depended on hosted policy, and the previous published candidate had a stale generated coverage identity that the original CI correctly rejected. This commit integrates the selected HIA structural budget owner, its installation and checker bindings, and the original source/native gates. It regenerates the complete support and coverage records and repairs the scalar-proof fixture to patch the actual checker identity source.

**This remains a draft. Whole-native qualification, default activation, live migration and legacy deletion are false.** The retained production owners stay until their actual replacements, ordinary installed callers and complete retained regression are qualified.

### What changed

- Add the complete selected HIA policy for VM call-depth qualification, static event/allocator budgets and bounded-resource composition, with the full-module resource-profile audit.
- Add native graph and arbitrary-precision integer support, preserve the original public signatures, report schemas, rejection ordering and limits, and retain the original reference bodies for independent comparison.
- Register the new HIA source, builder route, helper assets, checker identity, packaging and required test groups.
- Regenerate support, language coverage and the machine inventory. The source contract binds **771 files**; the repository tree contains **3,005 tracked paths** and **96 HIA assets** (84 assembly sources and 12 JSON sources). The separate machine inventory excludes its two generated report files and lists 3,003 paths. These counts are not a completion percentage.
- Preserve the original e03 HOLD and all three failed 8ca CI observations. Correct the scalar-proof fixture without changing its original three test names or assertions.

This is a **new reconstruction from saved owner source files**, based on the exact published 8ca tree, the 14 complete files from the verified 9028 source archive and the preserved registration recipe. It does not restore or inherit the lost 92fbc Git identity or its unknown gate outcome.

### Exact source and current gates

All 32 changed files (11 additions, 21 modifications, no deletions) were read as exact bytes and independently checked for byte count, SHA-256, Git blob SHA-1 and lossless UTF-8. The complete 3,005-path Git tree was independently recomputed, then GitHub returned the same frozen tree identity. The branch advanced with an expected-8ca lease and without force.

| Gate for this exact candidate | Current observation |
| --- | --- |
| Precommit source generation and static checks | 7/7 recorded stages completed successfully, including the original CI generation body, support/coverage regeneration, support check, original inventory validation and full file inventory. This occurred before the clean commit. |
| Clean-commit source gate | Pending execution/result on the exact published commit. Includes the original CI source group and all three scalar-proof fixture controls. |
| Matching-source cold replay | Pending; original 180-second execution and three-second owned-cleanup limits remain unchanged. |
| Installed/native composition | Pending; old component images and passes do not qualify this source. |
| Complete retained regression | Pending for this source. |
| New GitHub Core runs | [Push 43098596489](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43098596489) and [PR 43098602054](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43098602054); outcomes pending. |

The generated support profile remains the explicit pending-integration profile; a version label is not a qualification receipt.

### Original failures remain part of the audit

The unchanged e03 run completed all 32 stages with **HOLD** in 6,760.128471507 seconds. Full retained discovery executed **4,583 tests, four failures and one error**, with zero skipped, expected-failure or unexpected-success cases. The five top-level cases were the worker identity fixture, namespace and ledger caller panels, and two scalar-proof identity fixtures.

The original namespace and ledger reference-loop failures are now traced to their test callback's original positive-remaining-budget assertion, at approximately -0.729 and -0.745 seconds remaining. Their outer `RequestJournalUnknown` acknowledgement classification is preserved. The other expired-context paths also remain failed. No request was replayed or reclassified as a pass. A new four-case phase diagnostic has been authored but has not run; its original test bodies and 3,000/1,000 ms limits are unchanged.

All three original 8ca Core CI runs failed. Two native cold runs reached the original 180-second deadline; the other cold run passed all eleven checks but then failed the original language inventory assertion before language cases executed. The source generator diff also rejected the stale coverage hash. A later fixture or component pass does not replace these observations.

Exact originals, reconstruction evidence and the separate read-only diagnostics are retained on the [recovery evidence branch](https://github.com/TrillionniumFoundation/Hepta/tree/codex/hia-static-budget-recovery-v69-20261111-dda7/review-evidence/hia-native-rewrite-20261111).

### Implementation still in progress

The public heap controller, finite invocation/payload analyses and full public normalization continue in separate development trees. Their source and machine observations remain distinct from this published static-budget candidate. Heap review is preserving double-verification order, exact argument capture and public wrapper lifetimes; normalization still requires complete exception-cause, physical-recursion and Python 3.14 note behavior. Component controls do not authorize default selection or deletion.

General compiler/backend profiles, ordinary Agent/service/worker behavior, CLI/project/build orchestration, proof/runtime owners, native installation/recovery and actual deployed cutover also remain open. The current ownership boundaries and original results are recorded in [the execution status](https://github.com/TrillionniumFoundation/Hepta/blob/8aadee8b8bfc1bda940c9c32b2964429be358e1c/docs/HIA_NATIVE_REWRITE_STATUS_20261111.md) and [the audit](https://github.com/TrillionniumFoundation/Hepta/blob/8aadee8b8bfc1bda940c9c32b2964429be358e1c/docs/HIA_NATIVE_SELF_REWRITE_AUDIT_20261111.md).

## Earlier description retained

<details>
<summary>Previous 8ca candidate description and its historical source-specific observations</summary>

## Current candidate and incomplete qualification

Current PR head: **8ca2197693c98e48d0d16ab3c077efc7cd535653**. Exact tree: **d9a0a779301d25ffbfdc1601ed86ce0d76a9236b**. All 2,994 published paths, modes, object types and blob identities were compared with the frozen local tree.

This draft continues the HIA self-rewrite. Hosted semantic owners remain until their real native replacements, public interfaces, installation paths and complete retained regression are qualified. **Whole native qualification, default activation and legacy deletion remain false.** No merge or production switch has occurred.

### What this published candidate changes

The current tree integrates the native program-execution and scalar work, direct HIA slot-ledger routes with retained object/exception lifetimes, and the worker identity fixture's correct nested relative manifest path. It updates source custody, checker registration and the explicit remaining-work inventory. The inventory is evidence of files and static dependencies; it is not a claim that every production semantic path has been ported.

### Original results for this exact head

The narrow source/custody panel passed 26/26, but it omitted the original language inventory validation and therefore missed a real generated-file defect. The coverage manifest still contains semantic-support hash `22f0d66f…0202`; the correct regeneration yields `0b68ae9d…3939`. The original CI generator loop and `git diff --exit-code` rejected this mismatch. This failure is retained.

| Original GitHub run | Source and native result |
| --- | --- |
| [43070250214](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43070250214) | Source generated-file diff failed. Native cold reached the original 180-second deadline: 180.185358450 seconds, return code -9; owned cleanup completed in 0.085999238 seconds. No final nested qualification report. |
| [43070309546](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43070309546) | Source generated-file diff failed. Native cold passed all 11 checks in 135.457622031 seconds. The subsequent language step failed at the original `validate_inventory` assertion, before language cases executed. |
| [43070317835](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43070317835) | PR merge checkout `348389d9ab2c7b0f757b6d0542d945406964ca56`. Source generated-file diff failed. Native cold reached the original deadline: 180.210550521 seconds, return code -9; owned cleanup completed in 0.086574747 seconds. No final nested qualification report. |

The three original ZIP artifacts were preserved after full size, SHA-256 and ZIP CRC verification. A successful cold run does not replace either timeout. Missing nested reports do not establish an isolation violation. The original 180+3-second limits were not extended.

### Prior published source: complete retained run

The independent unchanged v5 run for **e03c82d1b5b7026ead9a5942336d54273b1a6931**, tree **bac117a8b24c506b60a65562cf81587ee0ec0c31**, completed all 32 stages with **HOLD**, return code 1, and no outer timeout. Total wall time was 6,760.128471507 seconds. Its full retained-regression stage completed in 3,468.475736124 seconds with return code 1. Native applications, artifact namespace and slot ledger also returned 1; all other stage commands returned 0. Exact source and bound runtime prerequisites were preserved. This is a distinct source and is not a qualification of 8ca21976.

Original final qualification report: 640,171 bytes, SHA-256 `b9fb54957843ef695f89aafab7d672b53a28096871fbdc902d034ef373d0e82b`. Original custody report SHA-256: `b83b7273a6091b4818636282d16c75604ff3553f4b56e06dd63bc4ee52433e2d`. The full unittest result is **4,583 tests, four failures and one error**, with zero skipped, expected-failure or unexpected-success cases; unittest wall time was 3,464.998 seconds. The five top-level cases are the identity worker JSON decode error, namespace and slot-ledger integration failures, and two scalar-proof identity controls that expected `unknown` but received `proved`. Nested deadline failures remain part of their outer integration cases. The exact original failure index is preserved in [recovery commit 378d60da](https://github.com/TrillionniumFoundation/Hepta/blob/378d60da59ada59690768757849d2ac3fa836510/review-evidence/hia-native-rewrite-20261111/v69/recovery/e03-final-failure-index.json); no tests were rerun during extraction.

### Work after this PR head

These component results belong to later development snapshots and are **not yet in this PR head**:

- Private HIA live-heap engine `26de5efeca0cdc2d7689e8bb5160a69290f6d149`: 20/20 development tests, 319 complete original-oracle comparisons, 324 actual native entries and 6 independent VM full-buffer comparisons. Original 1,024-context, 64-depth and 32,768-transfer limits were exercised on both sides. Public heap controller and installed/cold qualification remain pending.
- Public static-budget owner `9028d1817f83908137cf24930dcdf3c8f6465392`: 29/29 development controls; integration was frozen locally at `92fbc134f522c9cff616419b9555056e7cdd7d51`. Its first six original CI source checks passed, including regenerated language inventory and explicit `validate_inventory`. The final source-test command's outcome is unknown after the execution environment became unavailable. The planned installed/native integration gate did not start.
- Public normalization snapshot `541a1df0a50921b626220b9eb4e2220749b5fcbf`: complete Unicode error-object and output-arena controls passed. Two exception-cause mismatches, physical recursion/callback behavior and Python 3.14 ancestor notes remain open. No public selector is connected; a C compatibility prototype is not counted as HIA closure.

The workspace is currently unavailable. Frozen component source/evidence archives have been confirmed saved. Unpublished static-budget registration changes and root custody are preserved in [recovery commit 70bc0a6c](https://github.com/TrillionniumFoundation/Hepta/commit/70bc0a6c57d9536664c7cba4bc665a3dc8ada854), with both JSON files read back byte-for-byte. The original local Git identity and unknown test outcome remain explicitly separated from anything that can be reconstructed. No unknown test has been relabeled or retried.

## Historical description

The following is the original description for the older ac0089d8-era candidate. Its source-specific passes remain historical observations and do not qualify the current head.

<details>
<summary>Original description retained verbatim</summary>

## Current candidate and purpose

Head **ac0089d83f5ec1989f6c573b7e12f52ba4989599**, exact source tree **44f1234b45be3c7aaff3e783f934e6f9e3fae9d9**.

This continues the full native self-rewrite while preserving the original production owners until their actual replacements are qualified. The v65 implementation adds complete HIA owners for enum.make/tag, all nine record operations, all seven task operations, and retained in-process retirement decisions with real descriptor/library custody through interruption. Two compiler traversals use already admitted live-state bounds; language limits, rejection order and 180+3-second cold budgets remain unchanged.

The latest commit fixes a concrete retained-regression fixture error: two compiler invocations assumed /usr/bin/clang-20 even when the exact validated Clang 20.1.8 was installed under a private prefix. The fixture now resolves the required clang-20 from the qualified environment and uses that exact executable for real compilation and linking. The copied application still runs with empty PATH, all object/identity/execution assertions remain intact, and an absent compiler still fails. The affected actual-machine test passed locally in 7.280 seconds. The new source's independent ai395 cold passed all eleven checks in 70.863087 seconds under the unchanged 180+3-second budgets; its original retained regression completed **4,188/4,188 PASS** in 1,567.277167 seconds, with zero errors, failures, skips, expected failures or unexpected successes. Source and prerequisite inputs remained unchanged, and owned cleanup completed. The genuine original cold-replay unittest remained in discovery and its raw result was `ok`. GitHub run 42989657354 passed the source job but its native cold hit the unchanged 180-second deadline, retaining 34 of 38 phase archives. Actual owned cleanup completed in 0.083297 seconds with no remaining direct/adopted children. This original timeout remains failed; later native/language workflow steps did not execute. Artifact 13841013394 was downloaded and ZIP/SHA-256 checked: a41139d86be09cf34e68e8ca0cfea5d6e53812db61aa341f8d2fe7586fb244cf, 48,976,040 bytes. No retry or increased timeout has been used.

## Source-bound observations

| Exact source | Observation |
| --- | --- |
| ac0089d8 / tree 44f1234b | Independent ai395 cold passed 11/11 in 70.863087 seconds; full retained regression passed 4,188/4,188 in 1,567.277167 seconds with zero anomalies and unchanged source/inputs. Original full job 1a1c9cefa71-2564-2e9; summary SHA-256 731e3a3440e3590ee0c1003bb9ec785ddbb327f8f7b8e84ca546c730fd042c62; result SHA-256 05e6a8d8d79a4bfd3bc23f449fd7d7b25f456248851397ac24e54134e295e21c. The separate GitHub native cold timeout remains failed. |
| e80eacab / tree 7e7091f5 | GitHub run 42984401718 passed both jobs: source 351/351 in 422.559 seconds; native cold 11/11 in 105.989258 seconds, 5,049 nested checks and all 38 phase archives; language 1,242/1,242; 706 unittest executions in nineteen overlapping groups. |
| e80eacab | Independent ai395 cold passed all eleven checks in 71.480926 seconds, preserving exact source and prerequisite inputs. |
| e80eacab | Complete retained discovery is **HOLD**: all 4,188 tests ran in 1,579.995599 seconds, with one error and zero failures/skips/expected failures/unexpected successes. The hardcoded Clang path caused FileNotFoundError before its independent object compilation. Source/input identities and owned cleanup passed. This original result remains failed; it is not relabelled as an environment pass. |
| 2ecda852 / tree 13def586 | Fresh local cold passed in 150.028493 seconds, and 171/171 selected native controls passed with unchanged source. Its 350-test source panel had two failing subtest records in one historical compiler-fixture method. Exact old v64 source/Core digest and 769,584-byte assertions were preserved with their original fixture; a separate current-source transformation comparison was added. All fourteen affected controls passed before e80eacab. |
| f313af44 / tree b8758007 | Prior v64 PR CI and independent-host cold passed. Full retained discovery passed 4,089/4,089 in 1,697.631 seconds with zero anomalies and unchanged source/inputs. This result qualifies only v64. The separate local and push cold timeouts remain failed observations. |

The e80eacab GitHub artifact 13839103463 was downloaded, ZIP-checked and SHA-256 verified: **c2174bcc30f9e8fc5de96f9e6607eced26ab978ac13694f32fd4a26d10521b11**, 59,667,124 bytes. The independent full-regression original summary SHA-256 is **d70f624a0fb6b3306acb8790c71cd48009fa09f85b5d9cd27470bee1716d5e0d**, original result SHA-256 **b74e15f82f9de0bfa09d91aba538b77f453fafb7708c5c31fe7738542bb2f8cc**.

The full-discovery runner retains the genuine original cold-replay unittest, every discovered test and the original 5,400-second outer limit. Its standalone-cold flag does not mean that nested replay was removed. Original failures, interrupted/unknown operations and cleanup receipts remain separately retained.

## Scope and subsequent work

This PR preserves main f50b375 and prior native closure history from #888. It also includes the already qualified native enum-match owner, complete release selection/rollback policy, and source/compiler/packer custody fixes across standalone builders.

Subsequent isolated development is completing nominal call/primitive lowering, terminators, function orchestration, module aggregation/export and durable Agent budget/request ownership. These unintegrated development observations are not current-PR qualification.

**Whole-native delivery and old-stack deletion remain unfinished.** Ordinary CLI/project orchestration, remaining Agent/store/journal policy, compiler/runtime/proof/toolchain responsibilities, native default installation and live worker migration still need closure. Selected components retain fixed hosted transport/custody adapters. No live/default switch or deletion is inferred from component tests. The original live worker observation remains a failed launch caused by its absent pinned Python interpreter.

The exact inventory, original failure distinctions and remaining owner boundaries are maintained in docs/HIA_NATIVE_REWRITE_STATUS_20261111.md and docs/HIA_NATIVE_SELF_REWRITE_AUDIT_20261111.md.

</details>


</details>

</details>
