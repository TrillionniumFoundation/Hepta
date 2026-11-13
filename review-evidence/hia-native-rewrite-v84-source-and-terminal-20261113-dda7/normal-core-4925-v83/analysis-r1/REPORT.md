# 4925 Normal Core: original custody and four-run phase addendum

## Original outcome

The sole normal Core run **43340452551**, head **4925e72d9f51f4dc3e8f4d1d2a7b24cce2f5772b**, failed its original cold qualification after **180.216654570 seconds**. The process owner recorded `QUALIFICATION_TIMEOUT`, return code -9, and complete cleanup in 0.068560303 seconds with no remaining children or cleanup errors. The original execution/cleanup bounds remain **180 + 3 seconds**. The source job independently passed **973 tests in 1015.041 seconds**. Later native business steps were skipped after cold failure.

The unique Actions artifact is **61,437,617 bytes**, SHA256 **4486a0a6eabb9be43aae5515053213c889c44c814584f1cce014cabd2f2bbf96**, artifact **13999216954**. Full streamed verification read all **4,965 outer members**, all **39,058 members of 35 complete phase archives**, and all **443 members of a tracked historical source ZIP**. The last item is source data, not a 36th phase archive. Sizes, CRCs, SHA256 and Git blob identities were checked; phase archive manifests and original member modes were separately admitted.

The cold export contains **1,138 source files**, all equal by bytes, SHA256 and Git blob to the frozen **3,324-file** manifest for tree **bc276bc832a7d6f04a21d63f55645859b75a01ee**. The artifact does not export all 3,324 files. ZIP transport modes are retained as transport metadata, not substituted for live Git source modes.

B1/B2/B3 are each present at 669,494 bytes with SHA256 **81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109**. The final nested `qualification.json` is absent and the cold report has an empty `generation_sha256`. The partial fixed point does not supply the missing accepted report.

## Exact unfinished tail

There are **36 completed phase process receipts**, all exit 0, and **35 completed phase ZIPs**. `names-modified` finished its worker and saved the checked report, but has no final archive completion receipt. Its **2,354 original files** remain directly in the outer artifact. `names-original` has both its process receipt and complete archive.

Both exports requests were issued. `exports-original` has **585 partial members / 31,620,670 raw bytes**; `exports-modified` has **3 partial members / 13,170 raw bytes**, consisting of ownership marker, first input and request. Neither has a final process receipt, phase report or archive. This was unfinished business execution as well as an unfinished archive tail; it was not solely a final-report packing delay.

Relative to the original owner `qualification_started` event, the first phase started at **62.189467976 seconds**. The final names worker ended at **179.552959169 seconds**. Cleanup began at **179.935523400 seconds**, only **0.382564231 seconds** later. These are differences of retained monotonic timestamps, not estimates from ZIP times. Owner-event offsets and total outer cold elapsed have distinct setup/cleanup boundaries.

## Four original runs

| Run | Cold result / wall s | First phase after owner event s | Completed workers | Cold source files |
|---|---:|---:|---:|---:|
| 65ce_normal (43306363597) | COLD_SELFHOST_REPLAY_PASS / 97.558019 | 30.288087 | 38 / 38 | 1071 |
| r4_normal (43330392476) | FAIL / 180.224382 | 63.518424 | 34 / 38 | 1120 |
| 65ce_retained_full (43308827101) | FAIL / 180.207335 | 69.582569 | 32 / 38 | 1071 |
| 4925_normal (43340452551) | FAIL / 180.216655 | 62.189468 | 36 / 38 | 1138 |

Two phase workers run concurrently. Original / modified worker wall seconds appear below; they overlap and cannot be summed into cold critical-path time. A missing terminal receipt remains missing, not zero. Archive duration includes scheduling and queue effects and may overlap later business workers.

| Family | 65ce normal PASS | R4 normal FAIL | 65ce retained-full FAIL | 4925 normal FAIL |
|---|---:|---:|---:|---:|
| capacity | 4.042824 / 4.059150 | 9.253037 / 9.249406 | 9.508023 / 9.475591 | 9.176913 / 9.176223 |
| cfg | 0.936439 / 0.979962 | 2.260530 / 2.263362 | 2.545178 / 2.548132 | 2.194950 / 2.270806 |
| elf | 1.675087 / 1.617659 | 3.637338 / 3.629579 | 3.950744 / 3.928865 | 3.576071 / 3.608780 |
| chain | 9.767543 / 9.760542 | 16.818069 / 16.799179 | 25.360116 / 25.739456 | 14.560094 / 14.465666 |
| owned | 5.009825 / 4.835465 | 7.181827 / 7.463488 | 12.528762 / 12.699921 | 7.213263 / 7.452425 |
| bulk | 1.512100 / 1.456912 | 2.221182 / 2.094011 | 2.472648 / 2.427583 | 2.195133 / 2.013439 |
| loan | 1.054649 / 1.060749 | 1.622715 / 1.500769 | 1.875368 / 1.819206 | 1.449100 / 1.583610 |
| resource | 0.483993 / 0.430069 | 0.743356 / 0.774049 | 1.077438 / 0.999896 | 0.750372 / 0.601973 |
| tail | 0.428752 / 0.395787 | 0.676306 / 0.584474 | 0.922408 / 0.917135 | 0.659859 / 0.577853 |
| select | 0.799026 / 0.835066 | 1.313840 / 1.306333 | 1.571781 / 1.590544 | 1.316612 / 1.222470 |
| effects | 1.459924 / 1.467762 | 2.145553 / 2.368294 | 2.440820 / 2.725424 | 2.132717 / 2.276143 |
| multi | 2.740296 / 2.756352 | 4.003018 / 3.998215 | 4.139406 / 4.272315 | 3.840079 / 4.181233 |
| keyword | 0.617125 / 0.649434 | 1.090313 / 1.150039 | 1.497218 / 1.576291 | 1.103438 / 1.122113 |
| signed | 8.470215 / 8.908269 | 16.680271 / 17.010750 | 17.187569 / 17.029606 | 16.530870 / 16.926735 |
| scalar-casts | 7.963196 / 7.968037 | 14.847155 / 13.970686 | 14.871076 / 15.067773 | 13.911549 / 13.663463 |
| explicit-traps | 0.978389 / 0.944999 | 1.405029 / 1.254765 | 1.763209 / 1.789312 | 1.385288 / 1.160289 |
| cli | 7.386131 / 5.357668 | 13.641962 / 9.647751 | unfinished / unfinished | 13.542397 / 9.609938 |
| names | 9.029648 / 9.081752 | unfinished / unfinished | unfinished / unfinished | 20.352250 / 20.661598 |
| exports | 1.677860 / 1.487454 | unfinished / unfinished | unfinished / unfinished | unfinished / unfinished |

## Independent references and real compiler entries

All 17 original independent reference envelopes are retained. Their body wall times sum to **78.331077631 seconds**. With the unchanged maximum two worker slots, **39.1655388155 seconds** is a rigorous lower bound for their concurrent body span, excluding startup and checks outside those body boundaries. There is no final parent scheduling report for this failed run, so the exact absolute reference timeline is not recoverable from those envelopes alone.

| Original run | 17 reference body wall sum s | Two-slot lower bound s |
|---|---:|---:|
| 65ce_normal | 36.924319 | 18.462160 |
| r4_normal | 79.999296 | 39.999648 |
| 65ce_retained_full | 67.487681 | 33.743840 |
| 4925_normal | 78.331078 | 39.165539 |

The successful 65ce parent report additionally retained the actual reference span, 20.098956418 seconds. That exact span must not be substituted for the bounds of the other runs. The prior separately authorized same-host Python 3.12.14 ABBA observed greater actual child CPU cost in the newer reference path with identical complete canonical payloads; this addendum runs no second ABBA and does not transfer that diagnostic to Python 3.14 or to a cold pass.

All **5,383 / 5,383** current recorded native calls match a retained 65ce call by phase, compiler label, case, format, complete input SHA256 and actual image SHA256. This identifies the calls; it is not a new full-buffer execution comparison. The 86 top-level receipts have 7.949580055 seconds summed f0 wall and 11.470967409 seconds summed subprocess wall. Those intervals also do not replace the complete pre-phase wall boundary.

| Current completed family | Original: phase wall / summed f0 wall s | Modified: phase wall / summed f0 wall s | Native receipts per side |
|---|---:|---:|---:|
| capacity | 9.176913 / 8.333599 | 9.176223 / 8.331778 | 13 / 13 |
| signed | 16.530870 / 12.190022 | 16.926735 / 12.412267 | 358 / 358 |
| scalar-casts | 13.911549 / 10.125043 | 13.663463 / 9.849386 | 340 / 340 |
| names | 20.352250 / 11.531705 | 20.661598 / 11.817295 | 338 / 338 |
| chain | 14.560094 / 0.278060 | 14.465666 / 0.277060 | 277 / 277 |
| owned | 7.213263 / 0.102098 | 7.452425 / 0.097710 | 152 / 152 |
| cli | 13.542397 / 2.398120 | 9.609938 / 2.503032 | 4 / 4 |

The native-entry field is elapsed wall around f0. There are **no retained actual user/system CPU usage fields in these 5,383 native receipts**. Resource ceilings in requests are not measured CPU. On matched calls, current names compiler entries total 11.530671318 / 11.816277347 seconds (126 per side); signed has 254 compiler entries per side, casts 224, capacity 10. The chain and owned workers spend most of their wall outside recorded f0. These facts locate separate compiler and host-orchestration costs without assigning cross-run variation to hardware.

## Exact source changes and next action

The qualifier, cold wrapper, process owner, archive worker, ordinary-reference worker, signed/casts/capacity/names case modules, runtime VM, child loader, linked observer, selfhost generator and complete selfhost HIA are byte-identical to all three prior runs. Assembly/Core verification front modules equal the R4 versions, while they differ from the original 65ce front. In contrast, 4925 `hia_selfhost_contract.py` contains the later guarded lexical source-reading path and support inventory updates; its `file_digests` is no longer byte-identical to R4. SOURCE-COMPARISON.json records every checked source and named AST difference. The earlier three-run statement that file_digests was unchanged remains true for that earlier scope and is not extended to this run.

The narrow assembly default-scope candidate has separately completed its original function/exception/capture/caller controls and has been published by the parent as a new source. That new Normal Core run is a separate observation; this report does not include or anticipate its terminal status. The neutral private-emit expansion was semantically checked by independent native and VM controls, but parent same-host CPU measurements showed no stable benefit; it is excluded from the next source. Nothing here increases compiler limits, changes the independent oracle, skips a phase, caches source contents, or converts a timeout into a pass.

## Preservation and corrections

The first read-only verification session lost its terminal channel before a final report; VERIFICATION-INTERRUPTION.json records that gap. The next retained verifier failed on its own assumption that every ZIP in the artifact was a phase ZIP. Its stderr and source remain intact. Revision 3 independently completed full verification in 10.008251564 seconds, exit 0. No business or qualification test was replayed.

The first native entry-kind derivation accidentally read prior run-label keys as compiler hashes. All raw timings and all 5,383 exact pair identities were correct; only compile/other-entry grouping was wrong. MATCHED-NATIVE-CALLS-R2.json and CLASSIFICATION-CORRECTION.json retain the narrow correction, with a separate reproducibility assertion over the actual B3/M3 receipt hashes. The erroneous derived file remains preserved.

The compact evidence archive preserves both complete job logs, API receipts, all 621 selected original control/reference/process/report members, complete outer/nested integrity manifests, exact relevant source files, phase tables, native timing pairs, verifier code, authoritative terminals, and the above errors. The unique 61,437,617-byte complete outer artifact remains local plus Actions-retained; it is explicitly not claimed as Git-persisted by the compact capsule. Its full member identities and whole hash are included. All original pass/fail, current-cold, whole-native, default-selection and legacy-deletion boundaries remain unchanged.
