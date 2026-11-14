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
| Physical HIA sources ending in `.hepta` | 195 |
| Physical legacy `.hia`, `.HIA`, `.hiaasm`, `.hia.json`, including case variants | 0 |
| Production Python modules directly under `hepta/` | 210 |
| Registered native helper selectors | 38 |

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
The worker registry remains 37 source-bound single-image selectors.

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
| Published parent `727edb4` | Both Source jobs passed all 672 methods (539.107 and 518.983 seconds). At 2026-11-14 13:33 UTC both Native jobs had passed through step 87 and were running execution-budget step 88. [Push](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43592319767), [PR](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43592454060). The [full retained run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43592977558) was still running the original v4 step. |
| Complete emission owner | Source3, Native8 and all original nine-module 112 callers passed. The 112 runner took 167.838 seconds, entered 216 native frames and forbade both retained bodies. All 954 frozen original observations matched on observed CPython 3.12, 3.13 and 3.14; 512 complete buffers matched the independent VM. These are development results for the emission component inputs, before this integration's changed composite sources. |
| Installed emission and composition | The actual fresh-wheel emission worker exercised normal publication, lost ACK, process loss, replay and source-drift refusal. A separate source-process eight-owner evaluation/adoption composition preserved original 3000/1000 ms limits and replay with no new entries or database changes. The latter was not an installed eight-owner worker and does not prove cross-owner loss delivery. |
| Composite allocator | Replaced only the original zeroing loop with the existing checked HIA range fill; six generated owners changed. All 9,816 entries across 16 original documents matched complete input/output/workspace bytes and returns; 48 independent allocator boundary cases matched. The original 1024-function case passed A/B/A at 210.356 / 22.349 / 207.940 seconds with identical complete 385,050-byte observations. This is one measured case, not a full-regression speed claim. |
| Composite original callers | The complete original 122-method gate was attempted: 120 passed, no test failed or skipped, and one class setup refused development manifests because two joint-composition methods require matching-current-source cold. Those two methods never started. All original 64 methods are an exact ordered subset of the 120 actual passes. Full122 remains HOLD until the unchanged joint-cold gate runs. |
| Earlier complete runs | The [73f1634 full run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43585323484) failed its original v4 and supplemental steps; its complete inner artifact still requires readback. The [aac7550 full workflow](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43579990844) succeeded, but its 556,659,914-byte artifact exceeds the current 512 MiB transfer limit, so its inner qualification is not asserted. Both belong to their own source. |

The original 5-second JSON-wire timeout assertion remains open. The earlier
`73f1634` Native push failed it at 5.499958 seconds while the separate PR run
passed. Two local value-cache candidates also failed the unchanged assertion;
neither is integrated here. Their successful finite semantic controls cannot
turn those failures into performance acceptance. The next optimization must be
based on the actual original workload.

Cross-owner native delivery is also open: the selected owners retain their own
unknown-outcome custody, but a provider can swallow or replace a child owner's
loss before its parent sees it. Same-owner loss controls and successful normal
composition do not close this gap. Shared causal tracking and both durable
request-journal boundaries require separate implementation and qualification.

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
`AgentStore` still owns transaction begin/commit/rollback, artifact get/put and
profiles in addition to foreign SQLite effects. The service cost ledger has its
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
