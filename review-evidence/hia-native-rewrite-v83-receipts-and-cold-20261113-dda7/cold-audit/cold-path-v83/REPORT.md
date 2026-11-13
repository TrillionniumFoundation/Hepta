# Cold-path audit: three original runs and one bounded source comparison

## Scope and result

The historical 65ce normal Core cold run passed in **97.558018818 s**. The later R4 normal Core run failed after **180.224381637 s**, and the retained-full run failed after **180.207334888 s**. Those outcomes remain unchanged. This audit re-read original ZIP members and receipts; it did not re-run any historical CI or native compiler. The only new execution was the separately approved eight-worker ordinary-CoreVM ABBA diagnostic, on Python 3.12.14, with the original 180 + 3 second process-owner bounds.

There are three distinguishable costs: independent host VM references before B0; genuine compiler-entry execution during the native phases; and phase orchestration/host validation outside f0. Both failed runs were still executing phase workers at the deadline, not merely waiting to pack a finished final report. Historical native_elapsed_ns measures elapsed wall around f0; the original cpu_seconds=10 values are resource ceilings, not CPU observations.

| Original run | Cold result / wall s | First phase after owner start s | Completed phase receipts | Unfinished tail |
|---|---:|---:|---:|---|
| 65ce_normal (43306363597) | COLD_SELFHOST_REPLAY_PASS / 97.558018818 | 30.288086686 | 38 / 38 | All 38 completed; final qualification report retained. |
| r4_normal (43330392476) | FAIL / 180.224381637 | 63.518423837 | 34 / 38 | Both names requests and partial raw outputs exist; no names final report/process receipt/archive. Exports never requested. |
| 65ce_retained_full (43308827101) | FAIL / 180.207334888 | 69.582568680 | 32 / 38 | Both CLI requests and partial raw outputs exist; no CLI final report/process receipt/archive. Names and exports never requested. |

The successful report records all 38 final phase results. The R4 timeout has only 34, and retained-full only 32. B1/B2/B3 partial products are present and byte-identical (669,494 B, SHA256 81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109); their existence does not supply the absent accepted qualification report. All three used the original cold 180 second execution limit and 3 second cleanup limit.

## Exact phase comparison

Each cell is original / modified compiler worker wall seconds. Two qualification workers run concurrently; summing these durations does not produce total cold elapsed time. Archive elapsed also contains queue time and overlaps later workers. Missing cells are missing original terminal phase receipts, not zero time.

| Family | 65ce normal PASS | R4 normal FAIL | 65ce retained-full FAIL |
|---|---:|---:|---:|
| capacity | 4.042824 / 4.059150 | 9.253037 / 9.249406 | 9.508023 / 9.475591 |
| cfg | 0.936439 / 0.979962 | 2.260530 / 2.263362 | 2.545178 / 2.548132 |
| elf | 1.675087 / 1.617659 | 3.637338 / 3.629579 | 3.950744 / 3.928865 |
| chain | 9.767543 / 9.760542 | 16.818069 / 16.799179 | 25.360116 / 25.739456 |
| owned | 5.009825 / 4.835465 | 7.181827 / 7.463488 | 12.528762 / 12.699921 |
| bulk | 1.512100 / 1.456912 | 2.221182 / 2.094011 | 2.472648 / 2.427583 |
| loan | 1.054649 / 1.060749 | 1.622715 / 1.500769 | 1.875368 / 1.819206 |
| resource | 0.483993 / 0.430069 | 0.743356 / 0.774049 | 1.077438 / 0.999896 |
| tail | 0.428752 / 0.395787 | 0.676306 / 0.584474 | 0.922408 / 0.917135 |
| select | 0.799026 / 0.835066 | 1.313840 / 1.306333 | 1.571781 / 1.590544 |
| effects | 1.459924 / 1.467762 | 2.145553 / 2.368294 | 2.440820 / 2.725424 |
| multi | 2.740296 / 2.756352 | 4.003018 / 3.998215 | 4.139406 / 4.272315 |
| keyword | 0.617125 / 0.649434 | 1.090313 / 1.150039 | 1.497218 / 1.576291 |
| signed | 8.470215 / 8.908269 | 16.680271 / 17.010750 | 17.187569 / 17.029606 |
| scalar-casts | 7.963196 / 7.968037 | 14.847155 / 13.970686 | 14.871076 / 15.067773 |
| explicit-traps | 0.978389 / 0.944999 | 1.405029 / 1.254765 | 1.763209 / 1.789312 |
| cli | 7.386131 / 5.357668 | 13.641962 / 9.647751 | unfinished / absent / unfinished / absent |
| names | 9.029648 / 9.081752 | unfinished / absent / unfinished / absent | unfinished / absent / unfinished / absent |
| exports | 1.677860 / 1.487454 | unfinished / absent / unfinished / absent | unfinished / absent / unfinished / absent |

## What the original native receipts support

Every recorded R4 native call (5,313 / 5,313) and retained-full native call (4,636 / 4,636) matches a 65ce PASS call by family, compiler label, case, format, input SHA256 and actual image SHA256. This is an exact match of those identities, not a claim that this audit newly executed or re-compared every output/workspace. See MATCHED-NATIVE-CALLS.json for the fixed denominator and grouping.

| R4 completed family | Original: phase wall / f0 sum s | Modified: phase wall / f0 sum s | Native receipt count per side |
|---|---:|---:|---:|
| capacity | 9.253037 / 8.378435 | 9.249406 / 8.371984 | 13 / 13 |
| signed | 16.680271 / 12.215781 | 17.010750 / 12.390358 | 358 / 358 |
| scalar-casts | 14.847155 / 10.414794 | 13.970686 / 10.051386 | 340 / 340 |
| chain | 16.818069 / 0.278492 | 16.799179 / 0.283102 | 277 / 277 |
| owned | 7.181827 / 0.098691 | 7.463488 / 0.103980 | 152 / 152 |
| cli | 13.641962 / 2.417967 | 9.647751 / 2.523305 | 4 / 4 |

The capacity, signed and scalar-casts phases contain substantial actual compiler execution. Specifically, R4 signed uses 254 compiler-image entries on each side, totaling 24.6027 s of f0 wall across the two sides; scalar-casts uses 224 per side totaling 20.4634 s; capacity uses 10 per side totaling 16.7499 s. These two-worker totals overlap and must not be added to claim that much cold critical-path wall time. The remaining calls execute emitted programs. Chain and owned phases show the opposite profile: most phase wall lies outside recorded f0 calls. CLI additionally performs real linked/executable controls.

Identical compiler/input bytes with different f0 wall times do not establish a source regression in that machine code, or a hardware explanation. Scheduling, concurrent work, system-call/loader costs and machine conditions are not separately measured by the historical receipts. No CPU user/system statistics were retained for those historical child invocations.

## Pre-B0 references

The original qualifier validates the source, starts 17 independent reference subprocesses with exactly two worker slots, waits for all of them, then executes independent observer CoreVM references and creates B0. B1/B2/B3 and M1/M2/M3 remain sequential afterward. Thus first-phase start is not a measure of the six self-compilations alone.

The 65ce successful parent report retains exact reference start/end receipts: first reference starts owner + 0.123463045 s; the complete two-worker reference interval spans **20.098956418 s**; B0 seed starts owner + **21.420210106 s**. Failed parent qualification reports do not exist, so their absolute reference start/end receipts were not saved. All 17 individual worker reports still exist and contain original body wall elapsed values.

| Original run | Sum of 17 body wall s | Rigorous two-slot lower bound s |
|---|---:|---:|
| 65ce_normal | 36.924319097 | 18.462159549 |
| r4_normal | 79.999295878 | 39.999647939 |
| 65ce_retained_full | 67.487680736 | 33.743840368 |

The lower bound is the sum divided by the maximum simultaneous worker count of two; it excludes startup and source checks outside each recorded body. It is not an invented exact failed-run reference timeline. The top-level prephase native receipt inventory is 86 in each run: f0 sums 3.2571 / 7.9612 / 7.9491 s for 65ce / R4 / retained-full; their subprocess wall sums are 5.6186 / 11.7198 / 22.3630 s. B0 host build and independent observer VM work have no complete comparable standalone timing boundary in the failed final reports.

## One approved same-host ABBA diagnostic

A was restored from the actual 65ce cold ZIP: 1,071 exact files, each original byte and 0400 mode verified against the cold report and ZIP. B was the frozen 3,324-file source under v83-native-receipt-union-r1/source; FINAL-SOURCE-MANIFEST.json was exactly 815,692 B / SHA256 129db14408a555a7ff72f64fc45d4145eeda2e9884d42fb426541c259a0f0f3a, and its independently reconstructed tree was bc276bc832a7d6f04a21d63f55645859b75a01ee. This was not a fake Git checkout.

The reference worker, signed/scalar-cast case modules, original process owner, and selfhost HIA bytes are identical between A and B. Commands used the actual Python 3.12.14 executable, -I -S -B, the original worker --family / --output interface, original minimal cold environment, fresh private output/home/tmp directories, CPU affinity {0}, and sequential A-B-B-A per family. The unchanged process-owner supervised the whole diagnostic with 180 + 3 seconds. os.wait4 supplied real direct-child user and system CPU measurements; no worker body was instrumented or edited.

The run completed exit 0 with complete cleanup, all eight original payloads exact, and all A/B input bytes/modes preserved. Full canonical reference payloads were 3,138,026 B for signed and 2,670,450 B for casts. Full original envelopes, their differing source identity/PID/timing fields, stdout/stderr, requests and rusage are retained. No case was filtered or normalized away.

| Family | A mean wall / child CPU s | B mean wall / child CPU s | B/A CPU |
|---|---:|---:|---:|
| scalar-casts | 7.503906 / 7.365900 | 9.272111 / 9.035346 | 1.226645 |
| signed | 8.500357 / 8.381336 | 10.191935 / 10.019402 | 1.195442 |

This sample demonstrates additional actual CPU cost in the newer complete source path on this same host/interpreter, with equal reference results. It does not identify an individual function or explain all historical cross-run variation. There are only two observations per source/family. The newer default assembly front adds per-entry capture/context-manager and argument-custody routing absent in 65ce; its repeated _parameters/_items/_attrs calls are a specific source-level candidate for attribution, not a measured function-level conclusion. No production change or second profiling run was made.

## Exact source/call boundaries

The three original runs have byte-identical qualify_hia_selfhost.py, replay_hia_selfhost_cold.py, hia_selfhost_process_owner.py, hia_evidence_archive.py, both observer bridges, hia_selfhost_child.py, generate_hia_selfhost.py, selfhost.hiaasm and hia_selfhost_references.py. The original 65ce and retained-full contract modules also match. R4 contract AST differs only at SOURCE_FILES and support_contract: it adds Requests/Artifacts source inventory and two descriptive native_service_requests/native_service_artifacts objects. file_digests and validate_contract are unchanged. Full exact diff and source hashes are retained; the larger closure was not silently removed in this audit.

1. cold_replay freshly validates/copies every contract source, then starts the isolated qualifier via run_owned. The 180 second clock surrounds that owner execution; source-export preparation occurs before it. Final post-run hash checks and confirmed cleanup are required before accepting the nested report.
2. qualify does fresh admission, all independent VM references, B0, six sequential HIA self-compilations, actual HIA observer packer builds, and top-level controls before starting 38 phase subprocesses.
3. Each phase checks exact request/source/input identities before its body, uses fresh HIA-emitted observer children, then repeats source/input checks before writing its report. The native compiler ABI, output hashes and persisted receipts are admitted strictly.
4. The phase coordinator validates each exited child and queues its complete original raw directory for one verified archive worker, with two pending archive slots. Receipt archive duration includes queue time. An unfinished phase lacking final report/process receipt is not an archive-only delay.

## Concrete next optimization and required proof

The best supported HIA optimization target is the actual bootstrap compiler path exercised heavily by capacity/signed/casts/names, while keeping the independent reference side independent. No oracle replacement, warm child reuse, cross-call source cache, reduced source list, removed case, altered limit, changed timeout, or inference from a partial fixed point is proposed.

A narrow candidate is **owner-local expansion of the existing state_get32/state_put32 operations inside emit**, retaining precisely the original byte loads/stores and their order. emit is used by mem and the fixed instruction templates; the current HIA crosses helper-call boundaries to read/write its private output cursor on these emissions. Expanding those exact operations can remove fixed call/argument/frame overhead while keeping original byte arithmetic, reads, prefix stores, traps and cursor updates. It must not turn sequential byte accesses into a host hash, a foreign compiler, a new word-load intrinsic, or an unchecked multi-byte store. This is an unmeasured candidate, not an asserted speedup.

The existing compiler already has unrolled generic get/put, byte/narrow private-header lowering, packed keyword buckets, worklist CFG validation, and batched emit_bytes with a short-capacity fallback. Those existing optimizations must not be proposed as new work. B0 receipts show **125 functions, 1,459 blocks, 8,104 instructions**, only 88 instructions below the original 8,192 total ceiling. Any expansion must first fit that ceiling and the original per-function SSA, function count, buffer, stack and source limits without changing them. If it does not fit, reject that candidate; do not relax admission.

For a new candidate, generate separate exact source/image identities. Before any timing claim, compare ordinary CoreVM and original/new actual machine execution on complete source, output and workspace buffers with canaries, including malformed source, original first-error precedence, insufficient output at every affected prefix, workspace-fill variants, resource/capability paths, names/collisions, maximum capacity and modified compiler generation. Do not batch cursor stores or hoist memory reads across writes merely because the happy path looks equal; overlapping/borrow rules and trap-prefix semantics need an explicit proof. Then run the original native self-rewrite and all unchanged cold phases under the same original bounds. Performance must be measured on the same host with exact input/output preservation, and is distinct from current-source cold qualification.

The measured default-host reference cost is a separate work item. Attribution can use an independently labelled instrumented observation, but its timing cannot replace the unchanged worker ABBA or cold result. Skipping front scopes/custody without proving captured-None, dynamic globals, exception and destructor behavior would trade semantics for speed and is not authorized by this report.

## Evidence and limitations

checkpoint-r1/INDEX.json (Git b70e9e9ad7cd5dfc464acdf3ad15c4b7043cca25) roots 16 fully read-back chunks of the 11,905,459-byte ZIP, SHA256 c316779e512fd0c000c1680789d370535973cb2007af52fb32e91555a0ed71b5. All 1,051 archived member bytes, modes and CRCs were independently checked. It includes selected original controls/reports, native receipt timing derivations, exact sources and the preserved first audit classification/authoring errors. It does not contain or claim to replace the three unique full original ZIPs.

The approved diagnostic source was Git-ACKed before execution as c0464868185c6da140006d9b3aa6ce6d74e5d3a1. The complete post-checkpoint addendum retains MATCHED-NATIVE-CALLS.json, the exact support contract diff, this report, source guards, all eight raw worker outputs and owner evidence. Root-owned product/main/PR/audit refs and original source directories were not modified. Historical pass/fail status, current-source cold status, whole-native/default/legacy-deletion status are not upgraded by this audit.
