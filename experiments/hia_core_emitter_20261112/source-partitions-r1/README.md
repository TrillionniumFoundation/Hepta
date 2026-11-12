# Fixed small recovery of the original Core source bytes

This is an unexecuted, read-only custody controller. It does not generate HIA, import the project, compile a native image, or run product tests. The failed provider run 43152508792 remains failure. Its actual stored RESULT and natural worker receipts are preserved in 0b5fffce79ea2cb10ea32edbbc520625e91e380c; this new control reads the same sealed artifact 13915070523.

## Exact originals and partitions

The fixed artifact is 7,381,515 bytes, SHA256 57e3f0db194d961e64dd4773b04dddf373fe5ca02ea2763924d0ec5040d2a2f8. All 60 actual members are read to EOF with CRC and full SHA256/Git blob verification in both the worker and the post-cleanup reader. The 54 historical pins and their main/partial aliases are unchanged. Every job verifies the complete known inventory, then copies only its two fixed source files.

The 39 original HIA files and one ABI JSON total 7,089,249 bytes. partitions.json fixes 20 groups using deterministic first-fit decreasing by byte size, with original source ordinal as the tie breaker. Group members are ordered by original ordinal. All 40 ordinals occur exactly once. This changes only how already sealed bytes are delivered; it does not change any product evaluation or compiler order.

Each job has an independent unchanged 900-second owner and 3-second cleanup. The workflow permits at most two concurrent jobs and does not stop later groups after one group fails. Each job makes one official metadata GET, one official download-redirect GET, and one anonymous storage GET, with no retry or automatic redirect. The authentication and original module/guardian mechanisms are retained byte for byte. Signed URLs and tokens are never serialized.

## Bounded complete output

Each job permits at most 384 KiB of whole source files and 128 KiB total for the five current guardian/stdout/stderr/report/setup originals. The combined raw limit is 512 KiB; the complete application log, including END, is at most 1 MiB. There are at most seven framed files, 8 KiB per frame. Oversized originals cause HOLD; no file is shortened and no budget is raised.

BUDGET.json derives a conservative maximum 812,674-byte framed application stream under the actual fixed path/field limits. BUDGET-MODEL.json is a separate V8-only model based on the actual prior small-diagnostic receipts. It first reproduces all three reference JSON wire formats exactly, including unsafe integer digits, then applies the new source/control fields and 21 input identities to each group. Its largest modeled current-control set is 45,210 bytes; its largest source-plus-controls set is 438,258 bytes. This model is not a future runtime receipt. Changed runner paths/version strings or unexpected stderr still consume the actual enforced limits and may produce HOLD.

The original failed artifact's complete/partial download aliases are retained only after a bound closed ECHILD receipt, under the existing fixed-name/two-link checks. The new seven selected originals are independently copied and read back before framing. A complete END is emitted only after source stability checks and writing, reading, and syncing the final RESULT. A group cannot claim that all 20 groups succeeded. Final recovery requires the actual 20 distinct job/run/partition identities, all complete END records, and complete reconstructed byte/SHA256/Git blob equality for all 40 originals.

## Checkout and source scope

The pinned checkout action 11d5960a326750d5838078e36cf38b85af677262 was read from its official repository. action.yml and its actual input/provider implementation support non-cone sparse checkout; the provider selects blob:none when sparse paths are present and no overriding filter is supplied. The workflow requests only this control prefix and the three original workflow files checked by policy_and_context. It still verifies the exact detached .git/HEAD and every required control byte. It does not claim to materialize or audit the whole product repository.

The upload path is the exact current matrix partition's new public root, not a wildcard over other jobs. Root-only creation of the unique execution ref remains a separate step after static review. The template has no active workflow until B is frozen and the root agent chooses to trigger it.

## Validation boundary

STATIC-DERIVATION.json records 31 unchanged function bodies, all three unchanged full historical control modules, all 54 historical pins/aliases, the actual 60-member inventory, complete 40-source coverage, and the official checkout input sources. No Python parse, network execution, h process, native compile, or product test has been performed for this new controller. The first V8-only budget renderer's compact-versus-pretty guardian mismatch is preserved separately; after the correction all three actual reference JSON formats match exactly.
