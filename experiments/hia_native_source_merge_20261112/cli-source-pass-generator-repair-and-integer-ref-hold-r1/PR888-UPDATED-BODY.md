## Current status — 2026-11-12 17:16 UTC

**The v89 standard workflow and the new four-component CLI source qualification passed. The full HIA rewrite remains open: this draft is not ready for merge, default activation, or removal of the existing runtime.**

The current findings below distinguish completed execution from source drafts, preparation failures, and unexecuted gates. The [earlier full status history](https://github.com/TrillionniumFoundation/Hepta/blob/0b04f68e9d91592ccd59aab898573b615e76ecf3/experiments/hia_native_source_merge_20261112/combined-v89-ci-running-and-native-review-r1/PR888-BODY.md) remains byte-for-byte preserved. The immediately preceding 16:24 status body is also retained with this update. Historical failures and unknown operations are not superseded by later successes.

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
| Integer source candidate | [`1ee5445`](https://github.com/TrillionniumFoundation/Hepta/commit/1ee54450e1d17bd241dfa09a84bc17aa2cec8190); source/VM/native execution remains unexecuted |

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

The official v89 artifact is **13960883405**, **652,195,421 bytes**, SHA-256 **`477587001905c3f6e63c2c15fa94a6200777b6b477cf7d98a68d024d65e6a332`**. The entire ZIP has not yet been independently transported and audited. Its upload log contains ENTRYNOTSUPPORTED; workflow success alone does not establish custody of every original node.

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

### Numeric83: actual failure identified; two generator repairs validated separately

The first complete remote source request retained the original **62 generators / 83 methods / 180 s + 3 s cleanup**. It passed generators 1–31. Generator 32, `generate_hia_artifact_publication`, attempted to execute external `as`; the pre-existing source-only subprocess poison correctly rejected that operation.

This was an actual dependency failure, **not a timeout**. The worker ended after **29.260002612 s**, with nonzero status, four natural events and confirmed ECHILD closure. The remaining 30 generators, four derivations, four idempotence checks and **all 83 tests were unexecuted**.

The complete official **12,162,315-byte ZIP** (artifact **13963368322**, SHA-256 `4dabb0b7ddcf5c0cc8d4582c2da1ca5fa55e347a95fb010ea14cea4ef3b984d3`) was independently read: all 1,781 members, every generator report/stdout/stderr, and all 1,652 original source bodies. Source content remained unchanged; 32 files changed physical modification identity only. All 129 non-source original bodies are preserved losslessly at [`31c0266`](https://github.com/TrillionniumFoundation/Hepta/commit/31c026602c188ab03c737051ce2a4d91fd9fafee).

Static dependency review found a second corresponding assembler call in the release-install generator. [The two-generator repair](https://github.com/TrillionniumFoundation/Hepta/commit/8c8506c76c9cf9ea85972ba091354a4fceb84720) derives fixed transport bytes from the already pinned HIA packer literals, checks the original assembly-source hash and relocation holes, and preserves the independent assembler oracle. Three native-test import substitutions continue to use that original oracle; those native tests were not executed here.

The separately frozen **four repair controls** actually passed on local CPython **3.12.14**, in **2.179762102 s**, under unchanged **180/3**. They reproduced all four HIA outputs byte for byte, preserved the original generation algorithms/oracle, and verified drift refusal while external process/compiler/native entries were poisoned. All 1,685 input pins were stable, all 32 indexed original files were read, and natural closure was confirmed. This narrow result does **not** certify numeric83, remote CPython 3.14.4, native execution or the assembler oracle. A new complete 62/83 request against the repaired source is being prepared.

The numeric-on-v89 draft combines the original comparison integration with the v89 observation fixes. Its 1,653-file local source subset matches the corresponding Git leaves exactly; it is not a full checkout. Derived support/coverage files still await fresh generation. The draft contains 174 Python package modules and 62 generator modules; v89's passed inventory remains unchanged.

### Three independent Git ref failures: no execution

Each of the following was fully frozen and reviewed before one branch-create call. Each returned **GitHub 422: Reference update failed**; read-only reconciliation found exact-ref 404, no matching refs and zero runs. None was resent or moved to another branch. The cause remains undetermined; it is not recorded as a source, test, native or approval-review failure.

| Intended operation | Fixed trigger commit | Actual status |
| --- | --- | --- |
| v89 complete retained qualification | `9add582c3faaabe6c2c2d31eab6cfa0724ab341a` | Not started |
| v89 complete original artifact transport | `1b8ef3ea43bde954295f249e764d17a3557d4150` | Not started |
| Integer r2 source and Core VM qualification | `9c3a2a53d83c99848bb7797c10ad68d6f67c3d71` | Not started |

The complete retained request still requires the original **32 gates / 5,400 s full / 10,800 s outer / 180 s cold / two workers / 38 phases / 3 s cleanup**, fresh 8 GiB admission and the fixed runtime/dependency supply. Actual LLVM/Lean/QEMU/Rust/vendor/NDU preparation and execution remain open.

The artifact transport request binds artifact 13960883405 exactly, retains original **900/3 owner, 720 s transfer, 8 GiB admission, 3 GiB archive maximum**, and two fixed parts of 327,155,712 and 325,039,709 bytes. Its 21 filesystem/transport controls passed earlier; their synthetic HTTP observations do not qualify actual network transfer.

The [integer A2/B2 root review](https://github.com/TrillionniumFoundation/Hepta/commit/9c8366f2d31a4a1b42edd7e31652cdbfb7ce2930) verifies all 32 control/workflow originals, both complete trees, the unchanged four execution controls, fixed Actions revisions and a bounded complete failure channel. The original **10 methods / 90 arithmetic VM cases / 37 negative rows** (including 17 caught-reentry and one normal terminal row) and **180/3** are unchanged. Only AST and eight synthetic diagnostic-I/O controls have executed; no integer source, VM or native qualification is claimed.

The local execution environment is available again. The older unconfirmed local `launch.py` write and other historical UNKNOWN operations remain untouched.

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
