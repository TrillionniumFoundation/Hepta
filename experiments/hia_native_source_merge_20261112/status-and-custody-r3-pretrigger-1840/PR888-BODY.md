## Current status — 2026-11-12 18:33 UTC

**The v89 standard workflow is passed, and its complete original artifact has now been transported and read. Local integer source/Core VM qualification also passed. The new full32 run failed during dependency supply before the original 32 groups started; numeric83 and the new CLI scalar component have separate actual failures under repair. The whole HIA rewrite remains open, with no merge, default activation or legacy-runtime removal.**

The current findings below distinguish completed execution from source drafts, preparation failures, and unexecuted gates. The [earlier full status history](https://github.com/TrillionniumFoundation/Hepta/blob/0b04f68e9d91592ccd59aab898573b615e76ecf3/experiments/hia_native_source_merge_20261112/combined-v89-ci-running-and-native-review-r1/PR888-BODY.md) remains byte-for-byte preserved. The preceding 17:16 status body and this checkpoint's original readbacks are retained at [af99babc](https://github.com/TrillionniumFoundation/Hepta/commit/af99babc105d411db97d56dbbd4a73d0c98400bb). Historical failures and unknown operations are not superseded by later successes.

### Source identities and actual results

| Item | Exact identity and scope |
| --- | --- |
| This draft PR head | `acffa9262f31d073f8f0a6f0201eae201039f619`; unchanged |
| Main/base | `5831f52fada45e076f8f68f198a15c0585e6104f`; unchanged |
| Latest product candidate with standard CI success | [v89 `e4fc00a`](https://github.com/TrillionniumFoundation/Hepta/commit/e4fc00a775dab323758d77a2ef4918fd35585cdc), tree `d9e8407c70e44a3ea0152b8b4c5eb2ed3833d790` |
| v89 tree | 4,076 regular leaves, 410,622,569 bytes |
| v89 standard workflow | [run 43247845814, attempt 1](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43247845814), same-tree CI child `784f088fcc5ad81c65de541d54e26d380c86293c`, SUCCESS at 16:11:19 UTC |
| New CLI source qualification | [run 43264350911, attempt 1](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43264350911), head `a1715cbc26b71f9226e1d3c60582e5063e40bb07`, SUCCESS at 16:58:32 UTC |
| First numeric83 source qualification | [run 43261208151, attempt 1](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43261208151), head `cde3642d238f7f89e8e0a7608b7a1542cc5f598a`, FAILED at generator 32 |
| Numeric integration on v89 | Draft [`cc51db1`](https://github.com/TrillionniumFoundation/Hepta/commit/cc51db1c74c082572ae6183ebfa0c81cd36b0648), tree `01bcbef40c31bd9aaf9f359ffca4ffa557fc8cd3`; no CI qualification |
| Integer source candidate | [`1ee5445`](https://github.com/TrillionniumFoundation/Hepta/commit/1ee54450e1d17bd241dfa09a84bc17aa2cec8190); local CPython 3.12 source/VM PASS, actual native execution pending |
| Complete v89 artifact transport | [43274640670](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43274640670), compact carrier `f41f9122e536d8a86b4a74428caae963ff4a95bd`, SUCCESS |
| New full32 preparation | [43276914721](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43276914721), head `fa614c492b7b382b6f3b825098b61e22c1b5b212`, FAILED before full32 |
| Second complete numeric83 source run | [43272140755](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43272140755), head `2f73340a8ec74a648e0e47f299be0449f77ea0cd`, all 83 executed; actual FAIL |

The v89 seven-file change fixes publication-custody observation when product `os.fsync` is deliberately poisoned, initializes failed-call summaries before I/O, and adds sixteen controls. It preserves the original publication population and limits. The newer numeric, integer and CLI drafts are separate; their results do not modify the v89 tree or this PR head.

### Completed v89 qualification

| Validation | Actual result and unchanged limit |
| --- | --- |
| Local source integration | 118 expected/loaded/executed; zero failures, errors, skips, expected failures, unexpected successes and loader errors; 107.233 s under 180 s + 3 s cleanup |
| Original local publication controls | Original 19 tests, three scripts and eight probes; 1.858 s under 20/3 |
| Standard source job | 469 tests, 360.452 s, SUCCESS |
| Current cold self-host replay | 11/11 checks; all three generations SHA-256 `9de8606c153e50f2e742a18d4eb9f3b7c210b404f005346e95b550648d8f2892`; original 180 s, two workers, 38 phases |
| Native applications | 245 tests, 254.505 s, PASS |
| Original publication and actual kernel races | All 39 tests, 48.029 s, PASS; archive step SUCCESS |
| Core lowering and callers | Original 39-image component and original 51 + 50 caller gates passed |
| ELF | Complete source/lifecycle/wheel/11-boundary component and original 51 callers passed |
| Matching-cold UNPACK | Complete Core116 caller phase, original 18 composition checks and independent two-gate conjunction passed |

[Terminal originals and root review](https://github.com/TrillionniumFoundation/Hepta/commit/b5acfe4f4e21d4fc974d920a66ed0b43d620f25a) retain both complete job logs and official metadata.

The official v89 artifact is **13960883405**, **652,195,421 bytes**, SHA-256 **`477587001905c3f6e63c2c15fa94a6200777b6b477cf7d98a68d024d65e6a332`**. The complete archive has now been reconstructed byte for byte from the successful two-part transport; both outer artifact ZIPs, all shared metadata, raw ordered ranges and the final digest were independently verified. The transfer worker completed naturally in **63.807066416 s**, within the unchanged 900/3 owner and 720-second transfer allowance.

Root fully streamed all **21,844 outer members / 1,972,278,771 uncompressed bytes**, checking CRC, SHA-256 and Git blob identity. This outer read alone does not prove nested qualification semantics. Two nested audits are now also complete:

- **Cold:** all **38 phases**, **42,899 original phase files / 2,447,476,154 bytes**, 169,419 joins, and the full names compile/runtime bodies verified. Actual cold elapsed time was **112.596083185 s** within the original 180 seconds/two workers/3-second cleanup. B1=B2=B3 remains `9de8606c153e50f2e742a18d4eb9f3b7c210b404f005346e95b550648d8f2892`. The complete current 62-file compiler capsule is retained with its original receipts at [cf49fc44](https://github.com/TrillionniumFoundation/Hepta/commit/cf49fc44665d89f239f6cf6b63149d1fd1d61f27); it is the compiler input for the next integer-native request.
- **Publication:** all **39 expected/loaded/executed tests** and **97 original calls** verified, with zero five anomaly classes and complete **1,166 regular originals / 391,974,546 bytes**. The typed manifest also preserves **152 directories, three FIFOs and three symlinks**; special nodes were never activated. Source-before/after matches all 841 inputs. The original publication archive explicitly makes no global process-tree cleanup claim; known-child reaping and before/after quiescence are the verified boundaries.

The upload's ENTRYNOTSUPPORTED warning is therefore not silently treated as complete ordinary-file transport of special nodes: their original types are established by the explicit typed archive. Original archive readback and the narrow audit conclusions are retained at [af99babc](https://github.com/TrillionniumFoundation/Hepta/commit/af99babc105d411db97d56dbbd4a73d0c98400bb).

The transport carrier also emitted a separate standard push run, [43274637363](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43274637363). Its source job passed and native job was still running at this checkpoint. This is a different carrier tree and is not combined with original v89 run 43247845814.

### CLI: all four source components now pass

Source [`62ac511`](https://github.com/TrillionniumFoundation/Hepta/commit/62ac5111cd6316c7815e9c6f7d80f77e083decb7) extracts HIA frame access helpers. The original common limits remain: 1 MiB source, 8,192 instructions, 1,536 blocks, 256 blocks per function, 2,048 SSA names per function, 128 functions, 16 parameters/arguments and three results.

| Component | Source bytes | Instructions | Functions | Total blocks | Maximum blocks per function |
| --- | ---: | ---: | ---: | ---: | ---: |
| text | 95,920 | 1,540 | 31 | 362 | 96 |
| sort | 273,335 | **5,254** | 36 | 720 | 69 |
| note | 26,525 | 481 | 13 | 123 | 67 |
| cgraph | 103,470 | 1,872 | 29 | 418 | 101 |

All four source generation/Core roundtrips and all nine structural caps passed together on observed CPython 3.14.4. Worker elapsed time was **3.871837218 s**, owner elapsed time **3.918299711 s**, under the original **180/3**. Four natural lifecycle events, zero exit status, ECHILD and no remaining children were independently checked.

The complete official **1,498,067-byte ZIP** (artifact **13964912684**, SHA-256 `73971a4a092757767c037d65c9e7646c4e9d8efb52c7c647efc1d0c00b970731`) was fully read. Both agent and root independently verified all 18 outer members, all **197 regular originals / 11,896,687 bytes** in the typed tar, and all **160 source files / 2,498,584 bytes** before and after. Complete originals and the four generated HIA sources are retained at [`ef2f597`](https://github.com/TrillionniumFoundation/Hepta/commit/ef2f5971a9032af2afc2c7c805eff10908e81ebf).

The preceding sort failure **8,381 > 8,192** remains preserved. **Native execution, the original 17 CLI cases, all 46 trace identities and the compiler's 16,384-line gate were not executed by this source request.** The raw scalar object entry and complete CPython 3.12 continuation path remain implementation work.

The new [r4b source draft](https://github.com/TrillionniumFoundation/Hepta/commit/6ae4d8765678fe1e8c54c365c595d1528655ea62) adds scalar and Python 3.12 chunk source components, a versioned owned-CALL C adapter and the associated runtime binding. Eleven Python files and five embedded source strings passed syntax parsing; that is not C compilation or native qualification. The CALL adapter's seven copied CPython functions have explicit source/license and mechanical-derivation records. Generator resume/parent-frame activation, evaluator recursion/monitoring semantics and large-number foreign `_pylong` execution remain open.

The new two-component source request was executed exactly once on local CPython 3.12.14. It **FAILED** in **0.781812532 s** under unchanged 180/3: the scalar authoring document raised `KeyError: ast.Div`; `py312_chunks` passed its actual Core roundtrip and all nine caps, producing **28,497 bytes** of HIA assembly. Both components were attempted, 174 input pins were stable, and the original owner exited naturally with rc1 and ECHILD. No native execution, original CLI case or trace case was run. The root wrapper then encountered a separate atime-sensitive check while recording its own launcher log; the complete original worker/guardian reports were reconciled read-only and the request was not rerun. The scalar generator is being repaired for a new full two-component request.

### Numeric83: repaired generation passes; full83 exposed fixture/control failures

The first source run failed at generator 32 because the source-only process restriction rejected external `as`. Its 31 completed generators, remaining unexecuted stages, complete original artifact and natural nonzero closure remain preserved. Two generators were then repaired to derive fixed transport bytes from the already pinned HIA packer, retain original assembly-source/relocation checks and keep the independent assembler oracle. The separate four repair controls passed locally in **2.179762102 s**; they did not execute the native assembler oracle.

The second complete request uses repaired product source [545e7814](https://github.com/TrillionniumFoundation/Hepta/commit/545e7814b97bc767a15810dd99534aaccc23adf4), with the original **62 generators, four derivations, four idempotence checks, 83 methods and 180/3** unchanged. [Run 43272140755](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43272140755) actually completed all **70 generation/derivation/idempotence commands**, then executed **83 expected/loaded/executed methods**. It failed with **four failing subtests and five error subtests across two methods**:

- One original test requires five exact historical v67 harness helpers absent from the 1,653-file source closure.
- One original store-page test intentionally runs four real negative-admission Python commands. The broad source-only Popen prohibition rejected those commands before they could verify the intended bad-input refusals.

Worker elapsed time was **167.277860626 s**, below the original 180 seconds; the owner observed natural nonzero exit and complete ECHILD cleanup. This was not a timeout. The complete **12,878,630-byte artifact**, SHA-256 `d88ae1b7f649f0e78ceef094c184950488152e9b94a0f1034ed6081c2268b6eb`, contains **1,910 members / 47,885,373 bytes**. Every original source body and all 71 command records were fully audited and preserved losslessly at [5af9ae52](https://github.com/TrillionniumFoundation/Hepta/commit/5af9ae52de56d257f2c80f91e14b4cb24cecf7be).

The next request is being prepared with the five exact helpers added and only the four original negative-admission commands permitted under their original timeout, order, argv, environment and input pins. Every other external/native/compiler entry remains prohibited. The original 83 tests and all 62 generators remain required; no selective retry or population reduction is authorized. Generated support/coverage outputs from the failed run are retained as failed-run originals, not published as a passed candidate.

### Integer: actual local source/Core VM pass; native request being frozen

The new local CPython **3.12.14** source request passed **10 methods, 90 arithmetic cases and 37 negative rows**, producing **119 VM images and 439 actual entry returns**. Worker time was **17.805472006 s**, owner time **17.931011582 s**, under original **180/3** with zero anomalies, natural exit and ECHILD. The generated HIA is **51,898 bytes**, SHA-256 `56f86dc443f72655a9713eff24fadad121ab1157a858552e19c19dc53220c63c`. All 30 complete original files and before/after source identity checks are preserved at [7a2aac7d](https://github.com/TrillionniumFoundation/Hepta/commit/7a2aac7d59f69b3f9ae98f90dd72ffb603f471a7); independent root readback is at [af99babc](https://github.com/TrillionniumFoundation/Hepta/commit/af99babc105d411db97d56dbbd4a73d0c98400bb).

The next finite native request is being bound to the complete **current v89 B3 compiler**, not a historical compiler. Its declared population is four methods / 107 cases, covering all 90 arithmetic cases, the original 15 ACK rejection/replay cases, one caught-DONE case and one carry case beyond 8 MiB; planned totals are 131,475 native entry returns and 319,747,200 complete PRE/POST trace bytes. Original compiler and native limits remain unchanged. These native totals are plans, not observed execution. Remote CPython 3.14 integer qualification and complete Core116 integration also remain open.

### Three independent Git ref failures: no execution

Each of the following was fully frozen and reviewed before one branch-create call. Each returned **GitHub 422: Reference update failed**; read-only reconciliation found exact-ref 404, no matching refs and zero runs. None was resent or moved to another branch. The cause remains undetermined; it is not recorded as a source, test, native or approval-review failure.

| Intended operation | Fixed trigger commit | Actual status |
| --- | --- | --- |
| v89 complete retained qualification | `9add582c3faaabe6c2c2d31eab6cfa0724ab341a` | Not started |
| v89 complete original artifact transport | `1b8ef3ea43bde954295f249e764d17a3557d4150` | Not started |
| Integer r2 source and Core VM qualification | `9c3a2a53d83c99848bb7797c10ad68d6f67c3d71` | Not started |

Those three original ref failures remain unchanged. New compact source contexts have different immutable identities: their later success does not prove a cause for the older 422 responses.

### Full32: actual supply failure, incomplete custody; original tests not reached

The new compact [full32 run 43276914721](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43276914721) started successfully. Python 3.14.4, the four exact package pins, bootstrap and source preparation completed, but `fresh-prerequisite-supply` returned nonzero. **The original full32/5,400-second qualification was not reached.** Its exact internal supplier failure cause remains unknown: the independent custody process subsequently raised `PermissionError 13` while reading a regular file named `lock`, before it archived the internal supply reports and stderr. The basename alone does not establish which lock or why ownership return failed.

The full owner exited naturally with rc1 after **31.442472393 s**, and reaped its three adopted children; the custody owner exited naturally with rc1 after **1.420238677 s**. Both proved ECHILD closure and preserved input identities. Final status is **HOLD**, `complete_custody:false`, original qualification report absent. The complete official uploaded artifact **13970522337**, **31,428,886 bytes**, SHA-256 `8f9797d5fdb141162095befad189bd2e56684e3aada83ee8d15430821156b417`, has been fully read: **45 originals**. All 36 uploaded non-wheel diagnostic bodies, the complete job log and the manifest of all 45 members are preserved at [af99babc](https://github.com/TrillionniumFoundation/Hepta/commit/af99babc105d411db97d56dbbd4a73d0c98400bb). This complete uploaded-artifact read does not fill the missing private-root originals.

A custody-only repair is under review. It retains explicit unreadable-file/unlisted-directory metadata, continues archiving every readable original, never changes permissions or ownership, and keeps partial custody in HOLD. Five meaningful local controls have passed with actual unprivileged mode-000 file/directory refusals, readable supply-error preservation, typed FIFO/symlink custody, propagation of nonpermission I/O/identity errors and a finalizer check preventing partial custody from qualifying. The supplier itself is unchanged pending its actual internal error evidence.

The next full32 request must retain the original **32 groups / 5,400 s full / 10,800 s outer / 180 s cold / two workers / 38 phases / 3 s cleanup**, fresh 8 GiB admission and all fixed dependency requirements. No prior failed run is automatically replayed or reclassified. Actual LLVM/Lean/QEMU/Rust/vendor/NDU preparation and complete qualification remain open.

The older unconfirmed local `launch.py` write and all other historical UNKNOWN operations remain untouched.

### Remaining runtime ownership and removal conditions

The passed v89 product still has **172 Python package modules / 2,691,545 bytes**, **19 hosted Core operation families**, and **41 hosted CLI effects**. Its inventory is 840 declared inputs plus the contract, 92 native resources and 107 installed resources.

CPython still owns object representation, identity/registry, allocation, reference and exception lifetimes, and parts of FFI. UNPACK still uses a CPython transaction shim. Optional SQL/Z3/Rust/build owners remain. Stable native identity and reference/exception ownership must precede replacing aliased containers, iteration, hashing/equality, descriptors/calls, globals/imports and raising. Fixed foreign syscall transport and HIA policy images do not themselves remove those owners.

No legacy product source has been deleted. The only cleanup removed **430 duplicate historical transport archive copies**, 677,131,360 logical bytes, from five inactive validation caches. All 86 unique archives remain in the current source cache and Git. The complete original 223,515-byte cleanup ACTUAL.json has now been independently read and retained at [`31c0266`](https://github.com/TrillionniumFoundation/Hepta/commit/31c026602c188ab03c737051ce2a4d91fd9fafee), with zero product-source or original-execution files removed. Those five incomplete caches require rehydration before future qualification.

### Preserved historical outcomes

- v83 Core116: original 180-second timeout; 94 complete, 22 unobserved.
- v87 publication: oversized evidence ingress was refused before the original 39-test run; remains HOLD.
- v88 publication: original39 ran with 38 pass / one observer-interference failure; absent per-call originals were not reconstructed. Complete available originals remain at [`789c404`](https://github.com/TrillionniumFoundation/Hepta/commit/789c4044270277c3f98a9be39f5ec35785fafba2).
- Earlier CLI borrow/type and instruction-cap failures, numeric generator-32 failure, three ref rejections and every old UNKNOWN remain separate immutable records.

Merge, default activation and removal of the old stack require completion of the remaining implementations, current source/native/full qualification, complete original evidence custody and elimination of the hosted runtime dependencies. This status update claims none of those unfinished outcomes.
