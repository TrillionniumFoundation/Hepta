# Native clean-builder self reconstruction: development evidence and fresh CI entry

## Result and scope

The new HIA builder compiles its own complete HIA controller, the original decoder, and its own HIA ELF packer from the supplied source kit. The resulting HIA packer writes the entire new builder ELF. The prior action that copied the running builder is not used. The original seven compilation recipes and two application packers remain present.

Local development has completed the nominal full build, installation and installed second generation, an actual own-source mutation, the changed builder's second generation, and the changed rejection behavior. The fresh Ubuntu 24 CI entry is provided but has not run. These local results do not activate an installed default, qualify the new source under the old cold report, or close the full 15-action CLI, 11-tool Worker, or namespace.

The compiler is the exact R13 seed, 669,556 bytes, SHA256 `35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b`. The 644-file kit inventory is recovered from the original R13 kit. It is not relabeled as a complete current or 0ef Git checkout.

## Runtime changes

The explicit version-2 kit retains the complete original base source inventory, compiler and matching cold report. It appends thirteen ordered owner-source records. The complete actual kit digest covers these records; the old cold report does not purport to qualify the added source.

The owner-source records contain the original authoring and generator files, exact executor assembly, the new self-rebuild author, the complete new HIA driver, and complete HIA builder packer. The decoder HIA is selected from its exact existing base-inventory path. Runtime work is performed by HIA. Python authors and test scripts are development inputs and independent oracles.

The thirteen recipe receipts are:

| Rows | Actual work |
| --- | --- |
| 0–6 | The seven unchanged original compiler recipes |
| 7–8 | The two unchanged application packers |
| 9 | Compile the complete builder HIA from the supplied kit |
| 10 | Compile the exact original decoder HIA |
| 11 | Compile the complete builder HIA packer |
| 12 | Run that HIA packer on the actual freshly compiled driver and decoder |

The actual executor template and its syscall implementation remain byte-identical. The new HIA packer constructs every output byte, including the original fixed prefix, table, images and padding. Independent complete-byte comparisons cover the generated builder, the six-file HIAREL01 package, every receipt, and the complete source kit.

The active author is `01b610aec25453ae7dd714e2335ac027556fda6b`. Its generated driver is 381,320 bytes, SHA256 `4087a7ef00b5a17a254eefea73e46889b021fb36bf6ffef36a8faa4a474a4138`, with 124 functions, 1,511 blocks, 7,045 operations, maximum SSA suffix 1,312, and maximum 16 parameters. Existing compiler limits are unchanged.

## Actual local observations

All CPU figures below are aggregate parent plus observed/reaped children. The original raw summaries, receipts, complete outputs and source identities are retained.

| Observation | Actual result | Post-output CPU / wall seconds |
| --- | --- | --- |
| Original HIA source regeneration | Complete 319,403-byte original HIA equality | PASS |
| Five fixed-word helpers | 116 pairs, 232 actual native entries, 57 pairs of real SIGILL; 10 fresh B3 compilations | PASS |
| Fresh optimized builder | Three B3 compilations and one actual HIA packer; complete ELF equality | PASS |
| Nominal full generation 1 | Full six-file package, all 13 receipts, complete actual self ELF | 26.908064 / 26.939527577 |
| Whole installed group | Three install/no-replace/verify calls, eleven original stdio cases, one installed builder reconstruction; all 15 processes | 72.456394 / 72.723232164 |
| Changed-source generation 1 | Nominal builder consumes changed HIA source and produces the changed builder, without copying itself | 26.749737 / 26.855953811 |
| Changed-source generation 2 | The builder actually produced by generation 1 consumes the same changed kit; full package fixed point | 26.969167 / 27.170730839 |
| Actual mutation rejection | Four real decoders, eighteen actual native entries, two fixed-ELF refusals, two poisoned reentries | 51.101163 / 51.434259741 |

Each new complete runtime group retains a strict 90 CPU / 150 wall / 1 GiB gate. Each external native compiler or packer retains its original 10 CPU / 20 wall / 256 MiB gate. The earlier R13 whole test's 120 CPU / 150 wall source is unchanged and is not rerun to replace these gates.

The earlier unoptimized installed group completed its semantic comparisons but exceeded the new 90-CPU budget. Its final failure observation was 104.510899 CPU seconds. It remains FAIL, with its source, full outputs and finalization failure preserved. The later pass uses a different HIA identity. No limit was raised and the installed group was not split.

The optimization expands five fixed eight-byte accesses (`uint/get/put/hget/hput`) into the same ordered byte accesses. Complete inverse source proof is retained. Native pairing covers each byte boundary, partial writes, wrap behavior, returned values and real traps. These observations do not automatically qualify unrelated word helpers.

## Observable own-source mutation

Exactly one typed HIA constant in the owner-source header check changes from 130 to 137. The check rejects an incomplete 32-byte owner record after the full original source/cold gates. The input used for the rejection retains the complete valid old inventory, compiler, cold report and actual kit-digest binding, then ends before the first new owner record.

The actual original controller returns private reason 130; the actual changed controller returns private reason 137 on the same invalid kit. Both unchanged public fixed-ELF envelopes return exit 126 with empty stdout/stderr. The evidence therefore demonstrates changed native semantics and preserves the public envelope; it does not invent public reason text.

The independently compiled changed reference is compared against generation 1. Generation 2 executes the builder emitted by generation 1, rather than the independent reference.

| Identity | SHA256 |
| --- | --- |
| Nominal builder, 602,233 bytes | `6210dbb2cd2be63f2e58f1e57650bbd1a4643f23b2dddb547e43242b084cc5e0` |
| Changed builder, 602,233 bytes | `da991ec3b29a01eec28c803d2119f5629d49f0dd2d2acf58c4a4f72f0a5428cc` |
| Nominal whole package, 20,123,571 bytes | `e1b452937730100e740efad1251ef588dde2d4481ebeceabc01b5aaf45238a97` |
| Changed whole package, 20,123,571 bytes | `674e3fb912b5e9c200e8f906218ec3e6dd35e15cb5354b92ca2006fe1f0dc3a1` |

## Fresh formal CI

The exact opt-in entry is `ci/ci_self_rebuild_entry_r2.py` (Git `d13bbfcedf134332f4c5bc8d1893311fbfaf11ef`). It binds `ci_self_rebuild_r4.py` (Git `fed8c50796a4b9b5f4a0de9195bfdffda70ebe2d`) and `source-index-r2.json` (Git `b9b54267541ea4a02643caafe041ddab4977b75c`) before and after execution. The index names seventeen complete inputs. The entry adds no 180-second wrapper around the whole qualification.

Suggested existing carrier: `namespace_engine_original_sources_r1`; explicit selector `[hia-ci:clean-builder-self-rebuild]` together with the existing carrier selector `[hia-ci:namespace-engine-original-sources]`. Root owns the shared router and source selection. No workflow or ref is changed by this delivery.

The CI requires actual Ubuntu 24.04, x86-64 and Python 3.12.14. It restores all 814 original R13 members, verifies complete bytes/modes, extracts the complete 644-file source kit, and verifies the actual 35ee compiler. It then performs twelve fresh source/runtime stages with the original per-stage gates. It does not inherit local pass counts.

There are fourteen process receipts: one original readback (90 CPU / 180 wall), twelve source/runtime stages (90 CPU / 150 wall each), and one independent complete seal (90 CPU / 180 wall). The whole driver's outer wall ceiling is 2,700 seconds. It does not put the sum of twelve independent groups under one 90-CPU limit.

Actual external B3 counts are derived from native receipts, not a handwritten total: word pairing 10, fresh builder 3, mutation preparation 1, total 14. Two separate HIA packer invocations are counted separately. The internal thirteen recipe receipts of each complete native build are a different count. The exact CI counting suffix was executed read-only against the existing receipts and returned 14 and 2.

## Process cleanup and first-error preservation

The CI becomes a verified child subreaper. Each stage is a separate session, has parent-death SIGKILL and a parent-PID check, and is bounded independently. The original generic compiler child has no parent-death prctl; it inherits its stage process group. The original fixed-ELF Gate and the actual fixed executor's native child both have parent-death and parent-identity checks.

After the direct stage child terminates, cleanup does not infer that all descendants have exited. It drains `wait4(-1)`, discovers only actual children whose PPid is this process, maps PID namespaces, checks starttime/PPid/namespace identity before and after opening a pidfd, and signals only that pinned owned process. Only kernel ECHILD proves complete retirement. Any unexpected adopted descendant is retained as a failure, even if successfully cleaned up. Its CPU is added to the stage receipt. Cleanup time remains inside the strict stage wall budget.

Five actual local mechanical controls cover normal exit, a same-group orphan, a detached orphan, timeout with a detached child, and a receipt-write failure after exit 7. All were reaped and the primary error was preserved. These are zero-HIA/zero-B3 controls.

The initial cleanup draft assumed `/proc/self/task/<pid>/children`; that file is absent on this local host. The first normal toy control failed and its original receipt/source are preserved. The final implementation uses PPid verification and ECHILD instead. It does not silently downgrade cleanup.

## Independent sealing

The dedicated sealer is Git `c2c3506c35322632d7f4be1fba7f9193bf4b2257`. It runs in its own 90-CPU / 180-wall / 1-GiB process, reads every completed member, hashes bytes, preserves modes, writes the archive, reads all members back, checks every source again, writes custody, and checks budgets after complete output and final receipt readback. The running seal's own stdout/stderr/process receipt and final summary stay in the outer artifact to avoid self-inclusion.

An actual local full-size read-only control processed 4,294 members / 3,871 files / 776,067,288 raw bytes. It passed at 46.639768 aggregate CPU and 46.796009337 wall seconds with no remaining descendants. The complete member index, custody, full process output and post-output budget are delivered. This is development sealing evidence, not target qualification.

Two local precheck fixture errors occurred before the sealer ran: selecting the count instead of the ledger's rows, and applying a read-only directory mode before restoring its children. Both drafts and original tracebacks remain. Only the local restoration fixture changed; the formal sealer did not.

The full-size seal's data is a deterministic projection of the already durable complete development archive, two exact original-R13 copies, and the exact 644-reference source extraction. A complete member reconstruction proof is supplied. No duplicate 776-MB binary transport is claimed.

## Complete original custody

The main development archive contains 1,989 members, 1,905 files and 417,224,059 raw file bytes, including old failures and all completed native originals. The compact archive is 10,616,512 bytes, SHA256 `d377a923d147933837fe42c1d916ee5418eafd0516cdf66c0149c5d2eec5807e`, Git blob identity `776164b710fdb3dc47626fccc68f7e511438f2d2`.

Eleven base64 text parts were each fetched in full from Git, decoded, and checked against the exact corresponding binary part identity. The complete concatenation was checked against the archive SHA256 and Git blob identity. `originals/text-parts.json` and `originals/git-text-decode-proof.json` contain the full evidence. Creation of binary blobs is distinguished from full text-derived readback; unsupported binary fetch is not claimed.

The complete original R13 archive remains a separate exact dependency (57,162,628 bytes, SHA256 `721d89da963f863e3760d9577f3585b0cd9d6f3c71a36ee597d975baf12e388b`). Its previously completed 814-member readback is not counted as a fresh execution of the new CI.

## Outstanding boundary

The provided CI must run on the required Ubuntu domain. New-source cold qualification, general CLI/Worker/namespace completion, installation activation and removal of old paths remain open. The development result closes the concrete self-reconstruction mechanism and its local fixed points; it does not substitute for those independent gates.
