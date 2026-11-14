# HIA: current implementation and acceptance

This is the current-state index for `TrillionniumFoundation/Hepta`. The language
is HIA; the canonical source suffix is lowercase `.hepta`.

**The suffix migration is complete. Whole-product native replacement is not.**
`whole_native_delivery_qualified=false`, `old_stack_can_be_removed=false`, and
`production_activated=false`. The ordinary `hia` executable still enters
`hepta.cli:hia_main`. Selected HIA machine-code owners do not replace the
remaining hosted service, storage, proof, process and runtime owners.

## Source naming and inventory

Main was independently read at
[`f33d8da316de8fdf27b504371f1a5310997ff548`](https://github.com/TrillionniumFoundation/Hepta/commit/f33d8da316de8fdf27b504371f1a5310997ff548),
tree `378bc0dc613befc7006f1514bd2229357ae0d07c`, on 2026-11-14 UTC.
The canonical suffix entered main at
[`51bc24b8b03e5adc3da1b2b3490ad5cc7357e8d8`](https://github.com/TrillionniumFoundation/Hepta/commit/51bc24b8b03e5adc3da1b2b3490ad5cc7357e8d8).

| Current inventory | Count |
| --- | ---: |
| Physical HIA sources ending in `.hepta` | 196 |
| Physical legacy `.hia`, `.HIA`, `.hiaasm`, `.hia.json`, including case variants | 0 |
| Production Python modules directly under `hepta/` | 213 |
| Registered native helper selectors | 39 |

These counts describe files, not percentages of behavior. The additional
Python modules are explicit adapters for new native owners; their existence is
part of the remaining hosted boundary. The complete
[indexed-source inventory](HIA_NATIVE_REWRITE_INVENTORY.json) records every
retained file, Python module, static import edge, native selector and source
identity. Its explicit parent HEAD/index/worktree context is not the later
commit's identity. Dynamic and external callers still require separate review.

The [suffix contract](HIA_SOURCE_SUFFIX.md) and
[migration map](HIA_SOURCE_SUFFIX_MIGRATION.json) preserve rename provenance.
Assembly keeps `hia-asm.v1`; structured Core keeps its schema; paired structured
projections use `.core.hepta`. The `hia` command, `hepta.hia.*` schemas, Git
objects and historical receipt bytes retain their original identities.

## Implemented HIA ownership

The current components below execute HIA policy within their declared profiles.
Their linked contracts retain detailed original fixtures, caller scope and
source-bound evidence. The host dependencies remain explicit.

| Area | HIA-owned behavior | Retained host boundary |
| --- | --- | --- |
| [Compile and emission](HIA_EMISSION_NATIVE.md) | Both complete original methods: branch/loop control, dynamic compile calls, context-manager cleanup and suppression, generator iteration and publication order | Core emitter/compiler/linker, filesystem, Store/SQLite/clock/hash providers and opaque Python object protocols |
| [Store artifact and profile](HIA_STORE_ARTIFACT_PROFILE_NATIVE.md) | All eight original put/json/reference/get/get-json/URI/profile/check-profile methods: original guard and dynamic global reads, short circuits, ordered reference iteration, argument evaluation, publication and cleanup control | Original filesystem, SQLite, hash, JSON and native-artifact providers, opaque object protocols and the separate transaction context manager |
| [Native artifact and build receipt](HIA_NATIVE_BUILD_ADMISSION.md) | All four original signature/native/build-input/build-receipt methods, including ordered loops, composite checks, short circuits and nested admission | Opaque Python object protocols, original Core/context/ABI providers, Store/SQLite and SHA-256 |
| [Evaluation](HIA_EVALUATION_NATIVE.md) | Complete original evaluation branches, case/arm iteration, correctness and completeness flags, six-outcome precedence, budget/effect order and exact integer deadlines | Original reference VM and native runner, Store/SQLite/clock providers, object protocols, integer-to-binary64 division and threshold comparison |
| [Cost ledger](HIA_COST_LEDGER_NATIVE.md) | Original query/decode/policy ordering, 10,001-row truncation, context/unscoped selection, exact signed sums and output construction order | SQLite query/fetch, JSON decoding, row/object allocation and the original integer/string conversions |
| [Service context](HIA_SERVICE_CONTEXT_NATIVE.md) | Context freeze/lookup, workload and budget loops, complete effect ordering, exact signed deadline arithmetic and remaining-time floor | Schema/profile/buffer providers, object/time protocols, artifact/SQLite effects and the original candidate-consumption provider |
| [Static resources](HIA_STATIC_BUDGET_NATIVE.md) | Stable graph order, exact allocator/tick arithmetic, synchronous call depth, v7/v8 resource profile and ordered numerical policy decisions | Sole Core verification, primitive/policy shape validation, fact projection, independent heap analysis and final report hashing |
| [Store lifecycle](HIA_STORE_LIFECYCLE_NATIVE.md) | Complete constructor and close control, effect ordering, short-circuit/loop branches, original cleanup and exception propagation | Path/OS/SQLite effects, execution-budget provider, Python object protocols and exception delivery |
| [Full cost](HIA_FULL_COST_NATIVE.md) | Eleven one-time cost fields and execution/controller/failure sums, RSS/p99 peaks, ordered baseline/dp/fixed selection, exact signed floor-ppm savings and six ordered refusals | Immutable JSON observation, field validation, identities and final report construction |
| [Patch impact](HIA_PATCH_IMPACT_NATIVE.md) | Direct function/interface changes, old and new call graphs, duplicate elimination and transitive caller closure, including cycles and self calls | Fresh Core/patch verification, receipt checks, canonical fact projection and final report digest |
| [CLI discovery JSON](HIA_CLI_DISCOVERY_JSON.md) | Complete capabilities/catalog JSON, pretty/canonical encoding, schema selection, metadata ordering and catalog SHA-256 | Original CLI entry, explicit selector loading, I/O and other action effects |
| [Primitive Core diagnostics](HIA_CORE_ADMISSION_NATIVE.md) | Full semantic error text and dynamic names, complete return-type lists and corrected edge closure before predecessor comparison | Strict input snapshot/JSON decoding, composite normalization, trailer/UTF-8 transport and the original exception type |
| [Mapping admission](../review-evidence/hia-native-cleanup-20261111/native-mapping-integration.json) | Raw mapping grammar, interval ordering, permissions, file extent, unique-match admission and first refusal | Kernel snapshot, Python function objects, descriptor/seal readback and dynamic loader |
| [Publication measurement](../review-evidence/hia-native-cleanup-20261111/publication-measurement-integration.json) | Paired medians/deviations, ordered refusal and exact cost projections, including large intermediate integers | Clock observations, locks/cancellation/CAS, proof/build/load effects and resource custody |
| [Scalar profile](../review-evidence/hia-native-cleanup-20261111/scalar-profile-integration.json) | v1-v7 profile restrictions, explicit/implicit exports, whole-CFG acyclicity and ordered ABI | Fresh Core verification, unchanged per-export Z3 proofs and native compilation |
| [Generation retention](hia-generation-retention-native.md) | Registered-generation exact reference count, one-close lease cells, retired state and unique retirement-task claim | Selection/epoch/CAS, locks, preparation failures before registration, invocation and foreign cleanup |
| [Bounded byte memory](HIA_BOUNDED_MEMORY_NATIVE.md) | Original fill/move admission and refusals, actual in-place fill and overlapping move | Exact Python object facts, buffer export lifetime, allocator and GIL custody |
| [SHA stream](HIA_SHA256_STREAM_NATIVE.md) | Original full-width state transitions with fixed eight-byte word accesses expanded | Original bounded adapter and foreign object lifetime |
| [Execution budget](HIA_EXECUTION_BUDGET_NATIVE.md) and [journal](HIA_AGENT_JOURNAL_NATIVE.md) | Original budget transitions and complete per-request catalog hashing, with fixed word accesses expanded | Actual clock observations, SQLite transactions, durable journal and request dispatch |


## Current admission repair

Native artifact admission preserves the four complete `aac7550` originals and
the separate behavior-equivalence caller as byte-frozen fixtures. Its repaired
HIA continuation contains 21 functions, 347 blocks and 1,168 operations, with
103 fixed foreign ports; no profile limit increases. Actual method calls preserve
descriptor lookup and exception metadata. Canonical nested calls enter selected
HIA child frames without returning to the four retained policies. An actual
child native loss fences its active causal ancestors; a genuine foreign
exception preserves its identity and each caller's confirmed-error handling.
That admission execution used 37 source-bound single-image selectors; the
current registry count, including subsequent owners, is recorded above.

The separately frozen 205-case dynamic/runtime matrix and the original 303-case
matrix match their original observations on Python 3.12.14, 3.13.5 and 3.14.10.
All three runtime checks used the same development image, SHA-256
`26476dde0f409c9c59a6ab0d44ed985835b375693497e979d4f2b39397ce016a`.
They also passed 30 explicit-override lost acknowledgements, 30 causal nested
losses and 30 matched foreign exceptions per runtime. Three private probes
observe comprehension-entry behavior; HIA owns the six entry/reiteration loops
and ordered iterator releases. This covers the observed 3.13 differences
without a version threshold or a new input restriction. Python 3.11 and
all-input equivalence remain unproved.

The complete original nine-module caller gate passed all 112 methods in
151.138 unittest seconds (151.299 outer seconds), with 1,256 actual frames,
112,276 native entries, 15 confirmed foreign-exception events and zero calls to
the four retained bodies. All planned, started and stopped IDs match, with zero
anomalies and unchanged source/bundle pins. The unchanged 17-module inventory
separately records another 128 scope IDs; they are not counted as executed by
the 112-caller gate. The execution tree is
`be66b5e2d3b115a5066511d390c5dfc631b68f9b`; subsequent CURRENT/inventory
updates retain their separate documentation identity.

The installed seven-owner composition executes emit, verify, evaluate, adopt
and replay. The complete seven-method native component gate passed in 44.187
seconds. Normal first verification uses 506 entries in six frames; its read-only
revalidation replay uses 253 entries in three frames, with no new request,
artifact or cost record. Lost acknowledgement/process-exit controls use
238/237 entries and retain two unfinished ancestors. Unknown durable-intent
replays and changed-installed-source refusals execute zero admission entries.
The six original VM/native full-buffer comparisons now use 665 entries.

Two earlier candidate failures remain recorded: the first capture implementation
changed descriptor-raised AttributeError metadata; a later 14/15 component run
still expected the published single-frame counts. Five physical-count assertions
in that new component test were updated for the actual nested route. All original
caller bodies, the eight original fixture files, 205/303 inputs, semantic/DB/replay
assertions and original limits remain intact. These local results explicitly use
a development compiler and do not establish matching-source cold acceptance.


## Qualification and open performance gates

The qualification unit is the exact source tree and its admitted inputs. A
component development build, a current cold build, a real installed worker,
and the complete retained regression are separate observations. No earlier
success below qualifies this successor automatically.

| Scope | Observed result and remaining gate |
| --- | --- |
| Shared-delivery metadata successor `04492c2` | The [push Source job](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43620919130) passed generated-source cleanliness, then ran the complete original 684-method suite in 656.568 seconds with one failure: the release-freeze inventory compared its non-package bootstrap set with a mistakenly repeated `hepta/hia_native_delivery.py` entry. This successor removes only that repeated explicit entry; `file_digests` still binds the module through its unchanged complete `hepta/**/*.py` discovery. Original assertions and all production/HIA sources remain unchanged. The repair passed all 36 original related controls in 136.899 unittest seconds, including the complete selfhost-contract module with its unchanged 180-second cold fixed-point test, language-coverage Source checks, both delivery Source classes and suffix controls. This local scoped result does not replace the complete 684-method CI suite. The [complete retained run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43621466530), exact harness `e40723c6eda02c888444059cad98189a65b284bb`, targets 04492 and was still in original v4 step 12 at the latest observation; its outcome cannot qualify this later source identity. |
| First shared-delivery integration `5da589f` | Both [push](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43619719425) and [PR](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43619852126) Source jobs failed the unchanged generated-file cleanliness step before the complete Source suite ran. Every regenerated HIA source, Core-only and support check had passed; the sole diff was the stale `semantic_support_sha256` in the language coverage inventory. The metadata successor `04492c2` regenerated that inventory and its support/source ledgers, with production code, HIA graphs, original tests and CI unchanged. At the latest observation the push Native job was in the complete 152-component gate and the PR Native job had advanced to the complete six-caller gate; no final Native or current-cold acceptance is claimed. |
| Published Store parent `c019564` | Both Source jobs passed all 678 methods (1,043.489 and 853.576 seconds). The [push Native job](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43604415976) succeeded, including all original 130 Store callers and 91 wire callers. The [PR Native job](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43604589399) passed Store 130 but failed the original wire 5-second assertion at 5.730544 seconds; its complete 91 took 350.253 seconds. The PR checkout `0ead562e07fe6af5c99accbd7e09d24e60aa0e20` independently has the same `7a37b1ced47251fdc58e50624a5f77be56af374a` tree as c019. These runs contain neither the new shared delivery adapter nor its controls. The [complete retained run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43607286167), pinned by harness `dd55bb5c9a7af5fe0f33910c43461e4d01cdd1d1`, finished with strict-wrapper success for original v4 step 12 and supplemental step 13, but failed later at the separate lossless audit-copy step. Its primary 626,031,818-byte artifact exceeds the transfer limit; the redirected inner reports have not been independently read, so no complete inner qualification is asserted. |
| Earlier emission parent `7076ec1` | Both Source jobs passed all 675 methods (505.290 and 741.047 seconds). Both Native jobs subsequently failed the original wire caller step; the push log reports the original 5-second assertion at 6.487631 seconds, complete 91 in 392.244 seconds. [Push](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43600841563), [PR](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43600938346). Its [complete retained run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43603610027), exact harness `1e0231dd4cf8821ccae67a96de86ba6e986e6ae5`, finished with both the unchanged original v4 step 12 and supplemental step 13 reporting strict-wrapper success. The job failed later at the added lossless audit-copy step because its check reported changed original modes or nanosecond timestamps. The original 603,131,483-byte artifact remains above the current transfer limit; its redirected inner reports have not been independently read. The complete small status archive and job log were read back, so the outer successes and separate archival failure are retained without promoting them to independently verified inner qualification. |
| Shared D0–D3 delivery candidate | The exact local R6 tree `4ffb97a9c62077888dcb268588a09ce41b8dcac7` passed all 11 new source/native controls (20.401 seconds), the complete original 24-combination method (6.227 seconds), all 152 methods in the eleven original component modules (450.781 seconds), and all 112 methods in the nine original emission caller modules (131.049 qualifier seconds; 216 actual frames). Every planned/started/stopped identity matched; no failure, error, skip or retained-body call was accepted. This is CPython 3.12.14 development evidence with actual LLVM 20.1.8 / Z3 dependencies, before this integration's CI and documentation changes. Other caller owners, Store D4, matching-current-cold and whole-product delivery retain separate gates. |
| Shared Store D4 delivery candidate | The exact development tree `5f15785fbac278ffbf6bc5efc2c24874488afa62` passed all 11 new controls in 20.416 outer seconds. Its complete original Store 11 remains HOLD: ten methods passed; the literal-call method has three warm AttributeError metadata subtest failures. Its complete original 130 remains HOLD at 124 PASS / 6 FAIL, with all 130 ordered methods started and stopped, no errors/skips/retained-body calls, 95,924 frames and 1,755,792 entries in 258.934 qualifier seconds. Three failures explicitly report ptrace permission refusal; the others report two unreached link checkpoints and one missing injected EIO trace. All 112 ordinary methods form the passing ordered subset. A fresh single-method comparison passes both adapters; the full original 11 with an immutable c019 adapter overlay has the same three failures and identical complete 320 comparison records. A subsequent separate, clean checkout of the complete c019 tree, using the same CPython 3.12.14, verified prerequisites and development compiler, also failed exactly those three warm subtests (39.702 unittest / 40.048 outer seconds); all 320 observation records were byte-identical to D4, and every tracked source matched c019 before and after. This establishes reproduction in the unchanged parent under this runtime; it does not waive either complete gate or prove the interpreter mechanism. |
| Earlier parent `727edb4` | Both Source jobs passed all 672 methods (539.107 and 518.983 seconds). Both Native jobs subsequently failed the original 5-second wire assertion at 6.483813 and 6.502349 seconds; their complete 91-method gates took 390.784 and 390.018 seconds. All 97 earlier steps passed. [Push](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43592319767), [PR](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43592454060). Its [full retained run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43592977558) subsequently failed original v4 step 12 and the dependent supplemental step 13. The inner failure has not been read back; it is not assumed to be the same timeout as the older 73 run. |
| Complete emission owner | Source3, Native8 and all original nine-module 112 callers passed. The 112 runner took 167.838 seconds, entered 216 native frames and forbade both retained bodies. All 954 frozen original observations matched on observed CPython 3.12, 3.13 and 3.14; 512 complete buffers matched the independent VM. These are development results for the emission component inputs, before this integration's changed composite sources. |
| Installed emission and composition | The actual fresh-wheel emission worker exercised normal publication, lost ACK, process loss, replay and source-drift refusal. A separate source-process eight-owner evaluation/adoption composition preserved original 3000/1000 ms limits and replay with no new entries or database changes. The latter was not an installed eight-owner worker and does not prove cross-owner loss delivery. |
| Composite allocator | Replaced only the original zeroing loop with the existing checked HIA range fill; six generated owners changed. All 9,816 entries across 16 original documents matched complete input/output/workspace bytes and returns; 48 independent allocator boundary cases matched. The original 1024-function case passed A/B/A at 210.356 / 22.349 / 207.940 seconds with identical complete 385,050-byte observations. This is one measured case, not a full-regression speed claim. |
| Composite original callers | The complete original 122-method gate was attempted: 120 passed, no test failed or skipped, and one class setup refused development manifests because two joint-composition methods require matching-current-source cold. Those two methods never started. All original 64 methods are an exact ordered subset of the 120 actual passes. Full122 remains HOLD until the unchanged joint-cold gate runs. |
| Store artifact/profile component | Source3 and Native8 passed together in 64.625 seconds. The original 463 cases, 160 literal-call inputs in both cold and warm profiles, and 41 separately frozen dynamic-global guard cases matched on observed CPython 3.12, 3.13 and 3.14. The final image matched the independent VM at 533 complete buffer entries across six cases. These are development results, with filesystem/SQL and object providers still hosted. |
| Store original callers | The historical local development run remains 124 PASS / 6 FAIL: all 130 started and stopped, no errors/skips/retained-body calls, 95,924 frames and 1,755,792 entries in 287.638 seconds. Three failures directly report ptrace refusal; three report missed checkpoints or empty traces. The later exact c019 push and PR strict qualifier summaries both report the complete original 130 PASS with 95,925 frames, in 232.822 and 294.433 seconds. Their inner per-method artifacts have not been independently read. This later source-bound evidence does not rewrite the local failures or qualify the new delivery changes. |
| Installed Store worker | The actual fresh-wheel worker covered all eight modes, normal publication and URI reads, lost ACK, process exit 73, unknown replay and source-drift refusal. Its first request used 250 entries; replay used zero request entries and separately recorded 3,714 startup entries. Same-owner child-loss controls passed; cross-owner delivery and native-artifact-provider post-effect loss remain open. |
| Earlier complete runs | The [73f1634 full run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43585323484) is fully read back: 30,209 original files and 31,854 tar members preserve bytes, modes and nanosecond metadata. Its first 34 stages passed; original stage35 exhausted the cumulative 5,400-second limit. Of 5,001 planned methods, 4,561 ended `ok`, one had started without a terminal observation, and 439 never started. No supplemental commands ran because the later same-run prerequisites were incomplete. The [aac7550 full workflow](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43579990844) succeeded, but its 556,659,914-byte artifact exceeds the current 512 MiB transfer limit, so its inner qualification is not asserted. Both belong to their own source. |

The original 5-second JSON-wire timeout assertion remains open. The c019
push passed all 91 original wire methods in 276.193 seconds; the passing
method's individual elapsed time was not printed. Its same-tree PR run failed
that assertion at 5.730544 seconds. The earlier `73f1634` Native push failed
it at 5.499958 seconds while the separate PR run passed. Two local value-cache candidates also failed the unchanged assertion;
neither is integrated here. Their successful finite semantic controls cannot
turn those failures into performance acceptance. The next optimization must be
based on the actual original workload. A diagnostic profile of the original
`7076ec1` evaluation observed 383,542 native steps and 382,418 observations in
the timed call. Profiling overhead makes its elapsed time diagnostic only.
The original caller accounting and per-request source admission remain intact;
neither may be bypassed to meet the performance assertion.

The independent Store handoff readback verified 1,264 source/evidence files and
preserved a reporting defect: the three dynamic-limit comparison reports pair
a `report.json` path with the `first.json` observation digest. The original
freeze separately binds both files. Readback checked those independent pins,
both original observation repeats and the complete candidate observations;
the original reports were not rewritten. This correction does not turn the
six failing original caller methods into passes.

The new [shared delivery adapter](HIA_NATIVE_DELIVERY_CAUSALITY.md) connects
six continuation families, three arithmetic transports, both request-journal
lanes and the execution/candidate-budget boundaries. It records an actual
pending native handoff or undelivered observation, follows live process/thread
ancestry, and keeps a child loss visible through swallowing, replacement and
suppression. Ordinary confirmed foreign failures retain their original paths;
exception names alone do not prove native loss. Original SQL and argument
ordering remain intact. This is retained host transport custody, not another
HIA policy owner or removal of the Python runtime.

Its actual installed controls exercise an emission/context/native-journal
bundle of three owners. The observed original 24 combinations, 152 components
and emission 112 callers do not prove all owner combinations. The
[Store adapter](HIA_STORE_NATIVE_DELIVERY.md) now participates through its
actual native handoffs, all 138 foreign ports and implicit object release,
with the original HIA graph and literal effect definitions unchanged. Its own
new 11 controls pass; the complete original Store component and 130 callers
retain the failures described above. The real artifact-provider handoff and
receipt, the worker's later independent close, opaque provider internals and
matching-current-cold acceptance remain separate open boundaries. A previous R5 run remains 150 PASS / 1 FAIL / 1 ERROR: the
strict nested original test refused missing Clang/Z3, and an added fixture
used the wrong journal compilation label. R6 fixes the actual prerequisites
and that new fixture, with production bytes unchanged from R5 and all original
assertions, workloads and timeouts preserved.

Cold keeps **180 seconds plus three seconds cleanup**, the complete original
regression keeps **5,400 seconds**, and supplemental gates keep their original
limits. The original 3-second context, 5-second wire and 64 MiB artifact controls
remain intact. No failure is erased, no original method filtered out, and no
development manifest is relabelled as a current cold report.

The [published parent index](https://github.com/TrillionniumFoundation/Hepta/blob/727edb47cd98a41c0fcc4c494cf85422aa879937/docs/CURRENT.md#source-bound-qualification)
preserves the full earlier source-by-source evidence, original timeouts, skipped
steps, exact hashes and recovery references. Its older pending statuses are
historical observations; only the explicitly refreshed rows above supersede them.


## Public entry-point audit

The complete [15-action CLI matrix](HIA_CLI_NATIVE.md#all-15-ordinary-actions)
identifies each remaining action owner. `pyproject.toml` still installs
`hepta.cli:hia_main`; selected CLI control executes 42 foreign effect operations
through the Python bridge. Its declared CPython profiles do not cover the entire
portable package's Python >=3.11 declaration. The six standalone
[stdio commands](HIA_AGENT_STDIO_NATIVE.md) have a separate protocol and bounded
primitive profile; they cannot substitute for all ordinary CLI actions.

The worker starts through `hia_agent_worker`, constructs `HIAAgentService`, and
dispatches these eleven public tools. Native subcomponents do not replace the
remaining service methods listed here.

| Worker tool | Remaining service ownership |
| --- | --- |
| `hia_describe` | Profile/resource/page discovery; CLI discovery JSON does not automatically replace this API |
| `hia_artifact` | Profile, capture, source kind/digest and artifact admission |
| `hia_read` | Cursor paging, UTF-8/base64 limits and durable cursor records |
| `hia_context` | Hosted schema/profile/buffer providers, clock/object protocols and persistence effects; selected freeze/lookup/deadline control now has the HIA owner above |
| `hia_inspect` | View/selector/query/lowering coordination |
| `hia_candidate` | Import/patch routing, retention and complete diagnostics |
| `hia_verify` | Claims, independent proofs, deadlines and replay verification; selected native artifact/build-receipt control has the HIA owner above, with Core/ABI/Store/object providers retained |
| `hia_emit` | Selected HIA compile/emission control above; original Core emitter/compiler/linker, filesystem, Store/SQLite/clock/hash and opaque object providers remain |
| `hia_evaluate` | Original reference VM/native runner, clock/object protocols, integer-to-binary64 division and threshold comparison, plus SQLite/artifact effects; selected complete evaluation control and ledger policy now have the HIA owners above |
| `hia_adopt` | Receipt/objective/ABI admission and the outer adoption transaction |
| `hia_rollback` | Request, retained-image and receipt coordination |

`hia_resource_read` remains a supported alias, not a twelfth catalog tool.
`AgentStore` still owns transaction begin/commit/rollback and foreign SQLite
effects. Its eight artifact/profile methods have the selected HIA owner above;
their unselected original bodies and original providers remain. The service cost ledger has its
own selected HIA policy and retained foreign primitives, separate from full-cost
comparison. The native child runner still starts
through Python. These live dependencies prevent deleting the hosted stack.


## Remaining product acceptance

| Area | Existing owner that still requires complete replacement and real caller qualification |
| --- | --- |
| Ordinary CLI and build | `cli.hia_main`, remaining semantic action effects, `verify_program`, default emitter/build routing and complete diagnostics |
| Reference runtime | Complete VM, allocator, object transport, general backend behavior and default machine/plan implementation |
| Eleven-tool worker | `hia_agent_worker`, `HIAAgentService.call`, catalog/dispatch and backend admission |
| Durable state | `AgentStore` SQLite/WAL, atomic multi-table transactions, replay and unknown outcomes |
| Proof authority | Fresh Core verification and original Z3/Lean obligations; component admission does not replace these proofs |
| Native process ownership | Runner setup, environment/limits, snapshots, termination and complete report checking |
| Resident resources | Selection/CAS, actual invocation, libraries, sealed descriptors and confirmed cleanup of outstanding generations |
| Final cutover | Clean install/default startup, old context/request migration, worker restart/handoff, running-image readback and confirmed retirement |

The [selfhost object build](HIA_PROGRAM_SELFHOST_BUILD.md) consumes pinned
native frontend/compiler bytes without a Python-emitter fallback. It remains
a declared bounded Linux x86-64 profile. Default build and `hia_emit` retain
the Python emitter; `hia_evaluate` retains the Python reference VM. The
[native stdio entry](HIA_AGENT_STDIO_NATIVE.md) implements six commands, while
the ordinary CLI has fifteen actions and the service eleven tools.

Source generation, matching-source cold qualification, installed native caller
tests, full retained regression and actual worker adoption are separate gates.
Production Python modules still have live consumers and participate in install
identity. Deleting them now would remove working behavior and break durable
identities. They are retained until replacement and cutover are established.


## Repository cleanup

The active tree keeps current source, contracts, consumed fixtures and recovery
ledgers. Numbered source units may be parts of one multi-image program; names
alone do not make them obsolete versions. Independent original fixtures, the
three consumed NDU archives, acquisition locks and original failure records
remain necessary acceptance evidence.

The recorded historical cleanup retired 424 members: **423 paths deleted and
one README replaced**, containing **19,714,542 original bytes**. Separately, the
cumulative process-document ledger records **32 retired members and 200,246
original bytes**. These are the ledgers' respective scopes, not a new deletion
count for this update. This index now consolidates the current state and links
the complete prior narrative at its exact published Git revision.

Every retired member retains its Git blob, mode, size, SHA-256 and a published
recovery revision in the existing ledgers:

- [Development versions](../review-evidence/hia-native-cleanup-20261111/retired-development-versions.json).
- [Process documents](../review-evidence/hia-native-cleanup-20261111/retired-process-documents.json).
- [Historical bundles](../review-evidence/hia-native-cleanup-20261111/retired-historical-bundles.json).
- [Rewrite observations](../review-evidence/hia-native-cleanup-20261111/retired-rewrite-observations.json).

The live original v4 qualification and process supervisor remain unchanged.
Active hosted implementations and consumed tests are retained until their full
replacement and cutover are qualified. Separate PRs
[#888](https://github.com/TrillionniumFoundation/Hepta/pull/888),
[#889](https://github.com/TrillionniumFoundation/Hepta/pull/889) and
[#893](https://github.com/TrillionniumFoundation/Hepta/pull/893) retain their own
source identities and are not imported wholesale into this tree.
