## Latest verified status: V75 source closure repaired; V76 integration in progress

This draft remains blocked on complete native qualification and the remaining hosted owners. The current product commit is `5f7f95367e8e395863801487e969d286b9091110`, tree `4f4e58e06a6e03adcd6548bd8ea4ef591c20359f`, parent `f8d9680a9b0ae609850c006480a7d1f68ea00979`.

### Published source repair

The previous native heap fixture required `tests/test_hia_rust_finite_heap.py`, but that real input was missing from the cold source closure. This commit adds the dependency, adds an assertion covering all 38 fixture inputs, and regenerates the support and static migration inventories. Exactly four files changed; no files were added or deleted. The original heap test bodies and input list remain unchanged.

- [Source-generation run 43177736387](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43177736387): all 77 generators and 690 source controls across 147 selectors passed, with no failures, errors, skips, expected failures, unexpected successes, or duplicate IDs. All 118 commands completed within their original limits.
- All 3,120 final source files were independently checked for complete bytes, mode, SHA-256 and Git blob identity. The independently computed full tree equals the actual CI `git write-tree`. The support closure now contains 928 files.
- [Current Core push run 43183737274](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43183737274): the source job completed with 625 tests in 869.531 seconds. The source-generation run additionally retains 65 original candidate, publication, and release controls. The fresh cold replay and native public heap workflow steps have succeeded; later native steps are still running. Their final raw artifact has not yet been admitted as complete qualification.
- [Current candidate bindings run 43183747214](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43183747214): the original artifact records 179 tests passed in 115.518175051 seconds, zero anomaly categories, exact product head and tree. This does not claim whole-worker qualification.

### Original full regression is still HOLD

[V9 run 43155966434](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43155966434) ran the older exact `7e9c5a7` source and ended in failure. Its complete artifact was recovered and verified at 512,188,640 bytes, SHA-256 `cbf6c0a3bdbf44b03513388730541fc1f329d746e23313502a4e2b23f84ce4ff`.

The original record retains 27 wheel-resource failure events, the heap source-closure error, the original heap 134-test/150-second failure, four 3-second namespace/ledger failures, and the full retained discovery timeout at 5,400 seconds. The partial 4,479 completed test records are not a final tests-run count. Later source repairs do not relabel any of these historical failures. A33 and P6 passed; the old compiler produced the wrong 261-byte B reference, so the original B35 was not executed.

The evidence-retention caller also placed its output inside the prepared tree. The unchanged retention helper correctly rejected that path. The next harness will use a separate sibling destination. The separately demonstrated real GCC 15.2.0 setup will let the original B test compile and check its own reference under its original limit; no prebuilt reference will be injected.

### Unpublished V76 component work

| Candidate | Actual observed scope | Remaining integration work |
| --- | --- | --- |
| Machine ELF | Independent Python 3.14.4 CI passed all 37 component controls and all 51 original callers; original bytes and logs are retained. | The narrow delta is merged locally onto current source; a new combined cold build and complete gates are required. |
| Machine plan | Separate actual development runs passed 5, 12, 9 and 44 controls, including full frames, object lifetimes, exception identity and poisoned retained owners. | Native policy sources are merged locally; the component and original caller gates must run on the combined source. |
| Service context | Original CI passed 48 Agent callers; its 46-component run had 45 passes and one installed-wheel resource failure. | Literal wheel registration and explicit held-image proof binding are being corrected. The initial identity counterexamples and subsequent repair controls are retained. |
| Live heap | Separate development measurements reduced the two maximum-transfer inner-kernel calls from about 30 seconds to about 7 seconds. The original selected 134 tests passed in 76.125 seconds under the unchanged 150-second limit on Python 3.12.14. | CFG, map-lifetime and VM controls plus independent Python 3.14.4 qualification are required before publishing the optimization. |

Loader-only checks found an additional integration defect: importing a `TestCase` into another module made the CLI suite collect 52 instances for 38 unique IDs, and the new plan suite collect 29 for 21 unique IDs. Local narrow fixes use the original fixture class through a module import. All original test-method ASTs and unique IDs are preserved; the 38/21 assertions remain unchanged. These are collection observations, not new native test results.

### Recovery and evidence custody

The managed environment reset removed unpersisted local files. Complete `f8` source was recovered through a read-only exact-checkout exporter and independently verified before work resumed. Published source and sealed evidence remain intact. The lost unpublished V10 draft is being recreated as a new V10r2 revision; an earlier unsealed plan R2 raw-evidence gap remains explicitly recorded.

[Audit checkpoint `3c52dc2cd4db0cc52cd36f4e636113e7be65b0ae`](https://github.com/TrillionniumFoundation/Hepta/tree/3c52dc2cd4db0cc52cd36f4e636113e7be65b0ae/review-evidence/hia-native-rewrite-v76-20261112-dda7) preserves all older audit subtrees and adds 210 reachable evidence blobs. It includes the complete source-generation R3 observations, source recovery and publication records, original V9 failure triage, full ELF CI artifact/log parts, context originals, plan failure/fix originals, and the heap boundary baseline. Every archive part is a real tree entry.

### Closure conditions remain unmet

The published static inventory still includes 193 production Python modules and 365 hosted tools. It explicitly does not establish every-line semantic audit, dynamic caller closure, whole-language qualification, or live-worker migration. Defaults remain unchanged. No remaining legacy stack is deleted, and this draft is not ready to merge. The next product revision must regenerate the complete source contract and pass fresh combined cold, component, original-caller, and full-retained gates with the original assertions and time limits.

---

## Earlier verification record

## Latest verified status: V75 published; one new Core prerequisite failure

**Whole HIA-native closure remains incomplete.** Current product commit:
f8d9680a9b0ae609850c006480a7d1f68ea00979, tree
473404cdccc38a7e6bba633ef4a894877540d70e, parent
7e9c5a796a29746d169f9db97392ec774f627c03.

### Changes and resulting behavior

V75 integrates explicit HIA CLI control/formatting and composed machine
encoding/state/instruction owners. It repairs 27 installed-wheel resource
inventories, the complete macro-campaign source/resource identity, and the two
CLI asset bindings to their actual shared runtime module. Original test
methods, assertions, and execution limits are preserved. The published tree
contains 3,120 files: 79 changed paths, 36 additions, and no deletions.

### Actual verification

| Execution | Observed result |
| --- | --- |
| [First source run 43164226506](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43164226506) | 77 generators passed; 689 controls had one CLI resource-binding error. Complete original failure retained. |
| [Corrected source run 43169308480](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43169308480) | All 77 generators and 689 controls under 147 selectors passed, without skips or expected failures. |
| Independent publication readback | All 3,120 final file bytes, modes, SHA-256, and Git blob bindings match the CI source packet. The independently calculated complete tree equals the actual CI Git write-tree and the published remote tree. |
| [Exact-f8 candidate bindings 43173973917](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43173973917) | **179 tests passed in 74.945 seconds**, zero errors/failures/skips/expected failures/unexpected successes. |
| [Exact-f8 Core push 43173965316](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43173965316) | Source job passed. Fresh cold replay and language steps passed; raw current-cold artifact admission is still separate. Core patch's 27 tests now pass. The native job subsequently failed during live-heap class setup; later CLI/Code groups were skipped. |

The live-heap failure is explicit: HeapLiveEngineNativeTests.setUpClass rejects
a changed source-bound input, tests/test_hia_rust_finite_heap.py. The heap group
ran 23 tests in 119.442 seconds with one setup error. This source binding is
under review; no old fixture identity, limit, or result is silently changed.
The original observed native job log is Git blob
366b9fbae0cb3b14473f9306f95244b46170f4ac; the complete candidate-binding log is
da13bdd4205a8ce839c3acc23266fbc870631e4e.

The corrected source artifact is 31,922,136 bytes, SHA-256
b09e26dfc43e7130df91f2f895d5e55a5f35b49684c76a698801c56850450fa6.
All 513 inner evidence members were independently checked by original bytes,
mode, CRC, SHA-256, and Git blob identity before product publication.

### Independent mechanism and reference evidence

[CPython 3.14.4 exception run 43170086685](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43170086685)
passed 19 full-frame VM/native cases and 18 mechanism controls on complete 7e9
source plus two frozen development overlays. It is not a whole-runtime or
current-f8 Code/context qualification.

[Real-host GCC15 reproduction 43167896880](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43167896880)
used the unchanged frozen C, linker script, original flags, and 30-second limit.
The real cc lookup reproduced exactly 260 bytes, SHA-256
e82fd51964ce25990f24e723fb0b3270b2e8b69c7fdc2e1b3999648df070db61.
These are newly compiled bytes; the original 35 runtime controls must still run
for the current product.

V10 preparation preserves all old retained groups, A/P/B, unfiltered discovery,
and original limits. It adds complete CLI 38, Code 44, and original-caller
12+51 groups with all new cold selectors. A pinned real GCC15 private cc alias
leaves the original reference source, flags, required hash, and test unchanged.
The prepared local static review passed 68 checks; V10 has not been launched.

### Durable evidence and remaining work

[Audit checkpoint 30b86144369ee907d97f34faa6a363c16c2a1807](https://github.com/TrillionniumFoundation/Hepta/commit/30b86144369ee907d97f34faa6a363c16c2a1807)
preserves all 3,471 prior audit files and adds 181 evidence files. Code R4 has
all 90 chunks, resources all 21, and the first source failure all 20. Every
chunk is an actual tree entry; all six archives were independently reconstructed
byte for byte. The earlier Code R3 missing archive suffix remains unrecovered.

The shared development environment became unavailable after f8 and this audit
checkpoint were confirmed. GitHub and the existing CI remain accessible.
Unpublished local revisions and unavailable raw logs are not counted as durable
or current-source qualification. Subsequent reconstruction is labeled as new
work and must pass its own execution checks.

ELF, context, machine-plan, and remaining owners are still being completed.
Their separate development observations do not transfer to f8. The current
branch remains draft; defaults and remaining legacy implementations are retained
until actual replacement and qualification close.

The earlier observations below retain their original source and execution
context. They are history, not the current product-head status.

---

## Prior V75 observation before the generated product commit

**Whole HIA-native closure and legacy deletion remain unfinished.** The product
head of this draft PR is still 7e9c5a796a29746d169f9db97392ec774f627c03.
The new CLI/Code/resource integration is being generated and checked in a
separate exact-source harness before a product commit is created.

### Concrete problem and changes

The current product's Core patch and worker-request installed-wheel tests fail
because their fixtures copy the old three resource groups and omit the newly
required source-build/compiler resources. Complete inspection of all 60
packaging/resource candidates found 27 affected fixtures. Each repair changes
only the import and resource-union lines, preserving every other test byte.

The same audit found a separate macro-campaign identity defect: its helper
recorded 198 files while the actual worker installation identity covered 267.
It omitted 69 native/build/publication paths. The repaired helper reads all five
resource groups, retains the original bounded reads/evidence operations, and
rejects disagreement when one file is observed in both module and resource
roles. All nineteen original macro test methods remain unchanged.

The v75 candidate also integrates the explicit HIA CLI owner for all fifteen
existing actions within its documented ordinary-string argv profile, and the
three composed Code owners for byte encoding, state and instructions. A
shared HIA-emitted CPython exception mechanism fixes the observed temporary
destructor/handled-exception difference. This remains an explicit hosted
boundary, with separate owner and target-interpreter qualification required.

The finite overlay has 76 changed paths, 36 new files and no deletions.
The combined complete source snapshot has 3,120 files. Its resource registry
contains 86 distinct paths across all five groups; SOURCE_FILES explicitly
lists 747 paths and retains the fresh package-source closure.

### Actual evidence and limits

| Scope | Observed result |
| --- | --- |
| Published v74 source generation | [43153009209](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43153009209): 72 generators and 660 tests under 138 selectors passed. |
| Current product Core | [43155631133](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43155631133): source 595 passed; cold replay passed all 11 outer checks; native later failed the original Core patch wheel method. |
| Current candidate bindings | [43155639437](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43155639437): original worker-request wheel failure. Original failed jobs are preserved. |
| Complete read-only source audit | [43161178877](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43161178877): all 3,084 tracked files, all 1,269 Python files and all 60 packaging candidates; exact Git bytes/modes unchanged and zero syntax errors. |
| New component development | CLI 38/38; final Code 44/44; original Code callers 51/51. The qualifier's repeated 12 component methods are not additional coverage beyond the 44. |
| Resource development | Both original failed wheel methods passed separately with original B0/B1/B2 setup and actual wheels. Macro bounded panel 9/9 passed; it does not replace the thirteen retained campaign-integrity methods. |
| Root combined source/VM controls | 29/29 passed on the actual combined 3,120-file snapshot; every source byte and mode remained unchanged. |
| Target interpreter mechanism | [43162197253](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43162197253) remains queued at this update. No terminal success is claimed. |
| New full source generation | [43164226506](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43164226506) is running: all original work plus 77 generators and 147 source selectors, with the original process supervisor and 1,800-second command limits. |
| Retained unfiltered qualification | [43155966434](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43155966434) is still running against exact earlier 7e9 with its six bridge prerequisites. It cannot qualify the new source. |

The new component observations used Python 3.12.14. Their exact raw reports and
original failure chains are preserved. The current-source CI uses Python
3.14.4. The workflow retains all thirty-two original native steps and adds
three new native groups; every original source selector, generator, assertion
and time limit is kept.

### Current source and custody

The source-generation harness is d9d9ac6c0d89e81b25d2e19a0b571b7d4c33a1f3,
tree cfded1615fd9b12a2eab720c0fa73fab8fe740ad. It checks out exact 7e9 and
applies the 3,311,116-byte overlay, SHA-256
3d11c8bafa93e8920354cc7bd3bf113a28538b6fb4a12fc91d2382676e2dc99e.
Its generated source tree and original evidence must be checked before
updating the product ref.

Frozen source packets are CLI 1cd7b1c7136e760ba1f9da7b650d0dd884f332c7,
Code R4 93eae21429bed2d3e2f529be4de683a6153f8920, shared exception delivery
538b30f50a052130c5c84c82bb50062e83f6a030, and final resource repair
cf09a4438ca3897c6475325576dc94f00f02bb53. Final Code 44-method and original
caller raw reports are independently retained in 094955faaeae93a03aadb0f9ffbd4b5b0fd05d04
and a562d7632f34f72f2ba512de9acebab9a30d68c1. Two root whitespace-only fixes
preserve both Python ASTs and will be qualified as the actual integrated bytes.

Service context, remaining backend/ELF owners, hosted authoring and physical
service boundaries remain active work. The older Code R3 archive's missing
suffix and historical 260-byte B reference remain explicit custody gaps; a
new report or differently hashed 261-byte image does not reconstruct them.
No default/live migration or old-owner deletion has occurred.


<details>
<summary>Earlier status snapshots and original evidence</summary>

## v74 generated-source integration — 2026-11-12

The native source-build, source-admission, release-selection and publication paths now have their complete source/asset registrations and strict image/source receipt handling in the product branch.

- Product commit: [7e9c5a796a29746d169f9db97392ec774f627c03](https://github.com/TrillionniumFoundation/Hepta/commit/7e9c5a796a29746d169f9db97392ec774f627c03), parent `ac3fb576419d9ec36841822b4be0fca420268f1b`.
- Exact generated tree: `79843bddc6df7306299f0be6475a2fcd187b4d97`; 3,084 files, 46 changed, zero deletions. Every original base entry and every changed file's full bytes, mode, SHA-256 and Git blob identity were independently checked, and the complete tree was independently recomputed.
- [Complete source harness 43153009209](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43153009209): **PASS** on CPython 3.14.4. All 72 generators, generated-source reproduction, original checks, and 660 tests from 138 selectors passed; zero failures, errors, skips, expected failures or unexpected successes. The source controls took 886.198 seconds under their unchanged 1,800-second limit.
- The original first harness run [43149993963](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43149993963) remains a recorded failure: one old recording fixture lacked the newly required strict native image/frame receipt. The correction preserves all 13 original test method ASTs and adds one method with 17 missing/malformed/misbound-receipt cases. The strict product validation was retained.
- All 479 raw members of the successful run's original evidence archive were recovered and independently checked. Artifact 13915631777: 28,380,723 bytes, SHA-256 `be82ac8ddcd81b4753224a17e434ddbfde4da9a53ecd69df89eb9bbc54024c2f`.
- Fresh product [Core CI 43155631133](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43155631133) and exact-product [full v9 qualification 43155966434](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43155966434) have started. Their terminal results are **pending**; the source-harness result does not grant cold or whole-stack qualification.

The full qualification uses an independent workflow-only branch and checks out the complete exact product commit above. Its retained runner, original product limits, complete discovery and pinned prerequisite sources are unchanged. The six-bridge retention helper includes the executed FIFO-open correction and preserves actual binary bytes and original receipts even after a failure.

**Whole native closure remains false.** Defaults, live state and legacy owners are retained. The historical 260-byte normalization B reference is still unrecovered. CLI, Code and service-context work in the next isolated candidate remains development work until separately integrated and qualified.

### Previously retained checkpoints

# HIA native self-rewrite — current integration and acceptance

Current source: `ac3fb576419d9ec36841822b4be0fca420268f1b`  
Tree: `8231abac1bb2f30d7a8da8eb08a79ce92c50eb25`  
Integrated owner checkpoint: `490d44778263f5a01d5a6cc54493a8d8e8a80d4b`

**Draft: whole native delivery, default activation, live migration and legacy deletion remain unqualified.** The current work closes concrete native owners and their source/image/installed-resource custody while retaining the original controls and original failures.

## What changed

The combined checkpoint integrates 33 permanent normalization owner files, nine unified linked-observer files and six strict compiler/select/identity receipt files. The shared qualifier was merged by function, preserving the original generation loops, all 19 families / 38 phases, original named checks and time limits. The complete generated support union contains 864 files.

The linked observer gives HIA the admission, continuation, limit, response and snapshot decisions while retaining actual libc lifecycle and complete dynamic loading. Compiler receipts bind exact ABI status, original return encoding, complete output bytes and image/source/input identities.

Core CI now pins CPython 3.14.4, retains the previous groups and adds the actual 37-control linked-loader/receipt panel. The latest two-file repair resolves checkout and installed-wheel source assertions through the real live-heap and normalization source bindings; all 21 existing resource tests and their assertions remain. The support document changes only the repaired test's source digest.

## Actual verification and failures

| Exact source / scope | Actual result | Limit of the result |
| --- | --- | --- |
| 490 combined local development, CPython 3.12.14, retained compiler | All nine generation/check commands exited zero; 71/71 component tests passed with no skips/errors/failures; all 3,067 source hashes and compiler held unchanged | Development only. Original combined raw logs are temporarily unavailable after executor disconnection; their exact report hashes and the gap are recorded. |
| [490 Core CI run 43140636311](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43140636311) | Fresh cold **11/11 PASS**; language coverage **1242/1242 PASS**; new bindings **37/37 PASS** | Native job subsequently failed: applications panel 244 tests, 1 failure + 1 error, both the old inferred live-heap resource-module name. |
| Same 490 source job | 569 tests, 1 failure + 1 error | Resource-name error is repaired in ac3. A separate release-freeze assertion exposes the old bootstrap/package distinction after explicit normalization Python-source registration; it is under repair. |
| [aa801 Core CI run 43136468788](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43136468788) | Cold **FAIL 6/11** under the original 180-second bound; source 541 tests with 1 error | Original failure, raw job logs and artifact identity are retained. No success from a later source replaces this outcome. |
| ac3 resource-binding repair | Source prepared and published; dedicated recovery/source-control CI queued | No fresh ac3 cold/full pass is claimed. |

B1/B2/B3 in the successful 490 cold replay all have SHA256 `81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109`. Modified M1 differs from M2, and M2/M3 match. Byte identity with an older compiler does not transfer qualification across source snapshots.

## Preserved evidence

[Continuation index at audit commit c1c460dc](https://github.com/TrillionniumFoundation/Hepta/blob/c1c460dcfe3c67dc8c536402d514dcae95a4fd14/review-evidence/hia-native-rewrite-20261111/v73/continuation-evidence-index-r1.json) binds 30 artifacts, including the exact combined-source capsule, complete unified-observer and receipt archives, standalone HIA source-admission r1–r3 originals, original prepared v8 harness, aa801 failures, and explicit recovery gaps. Earlier audit checkpoints remain unchanged.

The original v8 harness was never launched: review found its inherited assumption of two workflow groups would fail against the new third group. A distinct r2 selects exact step names and preserves the complete original groups, full unfiltered discovery, original limits and original normalization P child. It still requires execution and complete prerequisites.

[Original-evidence recovery run 43144133802](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43144133802) uses a separate exact ac3 checkout to recover immutable original artifacts, scan all retained test prerequisite/skip conditions and execute the four resource source checks. It does not replay the original unknown remote operations or stand in for native/installed/full qualification.

## Work still required

- Repair and qualify complete package/bootstrap/data-resource closure without dropping source custody or assertions.
- Run the full retained discovery on an exact clean source with actual pinned prerequisites. Earlier remote terminal acknowledgements remain UNKNOWN until recovered.
- Execute normalization A/P independently of B. B still requires the actual historical 260-byte C reference; the different 261-byte GCC14 output remains a mismatch. Physical C-stack compatibility remains open.
- Integrate and actually regenerate the new source-build/compiler/install/publisher owners, then run their original controls. Their newly reconstructed authoring packets are explicitly unexecuted, with original raw-log gaps retained.
- Execute the permanent HIA source-admission component's full freshness/error/warm/installed-resource controls. Its standalone r3 results do not establish default integration or a stable speedup.
- Close the remaining CLI, general backend, proof and orchestration ownership, then qualify public defaults and live migration before retiring the old implementations.

<details>
<summary>Earlier checkpoint description retained for history</summary>

# HIA native self-rewrite — current integration and acceptance

Published source: `67382498b9d60bfecf3696d8c2cb632d8f20281b`  
Tree: `4412879c31f0a9fe489a76f123b919936f8bed67`  
Parent: `8aadee8b8bfc1bda940c9c32b2964429be358e1c`

**This is a draft. Whole native delivery, default selection, live migration and retirement of previous owners remain false.** The public heap, normalization and linked-observer work described below is separate development until integrated and qualified against its own complete source.

## Published change

The structural-budget policy has an HIA controller and native value-graph/bigint transport. The latest source commit fixes the two program-execution fixture setup errors found on its parent: after cold admission, the fixture creates the explicitly selected evidence parent; the builder retains exclusive candidate creation.

That fixture revision changes only its test file and the genuinely regenerated support contract/inventory. All three files and the complete 3,005-file Git tree were independently verified. It does not relax a deadline, analysis limit or admission check.

## Results bound to actual source

| Source and gate | Recorded result |
| --- | --- |
| Exact `67382498`, original precommit generation/static checks | 7/7 PASS. |
| Exact `67382498`, independent clean-source gate | 8/8 stages PASS in 447.586 s, including 527 source tests and three scalar-proof identity tests. Source, harness and prerequisites stayed unchanged. Root verified the complete original archive and all 3,005 source hashes. |
| Exact `67382498`, [GitHub push run 43107212082](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43107212082) | Source job 130813541472 passed 527 tests in 1,182.155 s. Native job 130813542162 **failed** cold replay at 180.192985790 s, 6/11 checks, return -9. Owned cleanup completed within the original 3 s allowance; later native steps did not run. |
| Associated [PR run 43107221239](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43107221239), actual merge checkout `89dfe6899f48fc1e2b7c10d2760ac9915584dc5d` | Source passed 527 tests in 935.095 s. Native cold replay independently **failed** at 180.181247886 s, 6/11 checks, with owned cleanup complete. This is not an exact-673 observation. |
| Exact `67382498`, independent remote cold/full job `1a1ccbc6da5-2564-1044` | Cold actually passed **11/11** in **72.668517861 s**, with B1=B2=B3, M2=M3 and complete cleanup. The last retrieved authoritative full-job state was running. At the preserved progress snapshot, 33 stages had completed: 30 exit-zero and three exit-one; full retained regression had started. No completed full PASS is claimed. |

The three completed-stage failures are retained: static-budget fixture setup lacked its selected evidence parent; artifact namespace and slot ledger retained their original nested reference-loop deadline errors and RequestJournalUnknown outcomes. The narrow static fixture fix is reviewed but is not part of the frozen 673 run.

Preparation first returned HOLD because it expected the CI jsonschema version. The original remote 4.25.1 installation was proved unchanged; corrected preparation returned READY without any installation or upgrade. The original 7,200 s outer limit, nice 0, 180+3 s cold allowance and all internal stage limits remain unchanged.

The prior [8aade push run 43098596489](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43098596489) passed source, cold and 1,242 language checks before failing two execution-fixture setups. Its later skipped steps and all original failures remain unchanged.

## Cold and deadline investigation

The original three CI archives, complete cold reports, 109 phase/index files and three phase analyses remain preserved. Both failed new CI cold runs completed 34 of 38 phases; original/modified names and exports remained pending. The passing predecessor completed all 38. The cause beyond recorded timing remains unresolved. A successful remote cold result does not replace either CI failure.

The original e03 deadline diagnostic retained the original test bodies and 3,000/1,000 ms limits: two PASS, two ERROR. Each failing context performed 158 fresh whole-source digest calls, accounting for 2.3915 s / 2.3387 s of the recorded nested timing.

A new read-only decomposition of the exact 673 function confirmed **771 files and 21,419,885 bytes freshly read per call**; all three complete maps and source identities matched. Baseline calls took 16.607 ms and 14.938 ms. Hashing and reading dominated the measured cost. These are diagnostic observations, not a performance qualification. No cross-call source/digest/mtime cache or reduced source closure was introduced.

## Development outside the published tree

- **Public heap:** the frozen r8 delta covers 29 paths on exact 673. Root independently decoded and checked every source ZIP member and its old/new identity. Ten source/adapter tests and nine actual native/installed outer tests passed, including reference and selected-native 134-test groups, all seven installed APIs, nested static composition, dependency/source-drift controls and worker/checker identities. The selected path made no retained heap/static policy calls. Original r6 failures and the first composition-fixture failure remain alongside later passes. Permanent workflow/source registration and matching-source cold/full qualification are still required.
- **Normalization:** r7 passed its original 78 comparisons, then a separate extension exposed nine differences among 14 late-error cases. The r8 coordinator actually passed the unchanged 78+14 plus 16 new controls, **108/108**, using one newly compiled coordinator and the actual HIA-produced 298-byte exception mechanism. Its production path used no C compiler. Original r5/r6/r7 failures remain. Fixed CPython APIs and diagnostics are still dependencies; only the pinned CPython 3.14.4 mechanism is covered. Physical recursion, near-limit Python frame behavior, the full foreign-object domain and current-source cold/full acceptance remain open.
- **HIA exception packer:** independent ordinary-VM/reference comparisons preceded native compilation; six actual emission cases and a fresh execution of all 35 mechanism controls passed on the emitted HIA bytes. The older 302-byte C result was not inherited.
- **Linked observer:** the first actual development smoke matched 19 ordinary-VM windows and six complete shared-library observations, with malformed ELF and missing-entry refusals. It uses the system loader on the complete target. Destructor, allocator, resource, signal and framing controls continue; no whole observer or cold-timeout resolution is claimed.

The first isolated heap integration stopped before applying the delta because its fresh Git index did not reproduce the original tree. The original failure and both MCP acknowledgement timeouts are retained. The exact 673 source stayed clean; a bounded index comparison is investigating the staging method. This is not a heap product test failure.

## Evidence and remaining work

[Audit commit 5372196d](https://github.com/TrillionniumFoundation/Hepta/commit/5372196d014b753e0fceefdc0c73b7d9150f864b) adds 79 preserved artifacts with an independently reconstructed Git tree. Its [r7 index](https://github.com/TrillionniumFoundation/Hepta/blob/5372196d014b753e0fceefdc0c73b7d9150f864b/review-evidence/hia-native-rewrite-20261111/v70/continuation-evidence-index-r7.json) and [scope/readme](https://github.com/TrillionniumFoundation/Hepta/blob/5372196d014b753e0fceefdc0c73b7d9150f864b/review-evidence/hia-native-rewrite-20261111/v70/continuation-r7/README.md) link original reports, complete archives, source packages, failures, terminal records and explicit unknown outcomes. Prior audit `285a5fdb` and older failed qualifications remain in its ancestry.

Finish the original full run truthfully, integrate new owners with real generated contracts/inventory, then run matching-source source/cold/native/installed/full gates. Remaining language surfaces, CLI, service/worker/runtime, build/release delivery and final removal conditions are still open. This PR does not perform or claim default/live migration or legacy deletion.


</details>

</details>
