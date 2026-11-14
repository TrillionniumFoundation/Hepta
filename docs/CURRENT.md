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
| Physical HIA sources ending in `.hepta` | 197 |
| Physical legacy `.hia`, `.HIA`, `.hiaasm`, `.hia.json`, including case variants | 0 |
| Production Python modules directly under `hepta/` | 218 |
| Registered native helper selectors | 40 |

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
| [Store artifact and profile](HIA_STORE_ARTIFACT_PROFILE_NATIVE.md) | All eight original put/json/reference/get/get-json/URI/profile/check-profile methods: original guard and dynamic global reads, short circuits, ordered reference iteration, argument evaluation, publication and cleanup control | Original filesystem, SQLite, hash, JSON and native-artifact providers, opaque object protocols and actual SQLite/generator effects; selected transaction control has its separate owner below |
| [Native artifact and build receipt](HIA_NATIVE_BUILD_ADMISSION.md) | All four original signature/native/build-input/build-receipt methods, including ordered loops, composite checks, short circuits and nested admission | Opaque Python object protocols, original Core/context/ABI providers, Store/SQLite and SHA-256 |
| [Evaluation](HIA_EVALUATION_NATIVE.md) | Complete original evaluation branches, case/arm iteration, correctness and completeness flags, six-outcome precedence, budget/effect order and exact integer deadlines | Original reference VM and native runner, Store/SQLite/clock providers, object protocols, integer-to-binary64 division and threshold comparison |
| [Cost ledger](HIA_COST_LEDGER_NATIVE.md) | Original query/decode/policy ordering, 10,001-row truncation, context/unscoped selection, exact signed sums and output construction order | SQLite query/fetch, JSON decoding, row/object allocation and the original integer/string conversions |
| [Service context](HIA_SERVICE_CONTEXT_NATIVE.md) | Context freeze/lookup, workload and budget loops, complete effect ordering, exact signed deadline arithmetic and remaining-time floor | Schema/profile/buffer providers, object/time protocols, artifact/SQLite effects and the original candidate-consumption provider |
| [Static resources](HIA_STATIC_BUDGET_NATIVE.md) | Stable graph order, exact allocator/tick arithmetic, synchronous call depth, v7/v8 resource profile and ordered numerical policy decisions | Sole Core verification, primitive/policy shape validation, fact projection, independent heap analysis and final report hashing |
| [Store transaction](HIA_STORE_TRANSACTION_NATIVE.md) | Original lock/BEGIN, yielded body, COMMIT/ROLLBACK, exception matching, suppression and release control | CPython generator suspension/resumption, opaque protocols, SQLite effects and host delivery custody |
| [Artifact delivery](HIA_ARTIFACT_DELIVERY.md) | Six native artifact operations with a separate private entry, nonce-bound terminal acknowledgement and original effect/cleanup order | Python process/descriptor transport, fresh source admission, filesystem effects and uncertain-delivery fencing |
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


## Current transaction and artifact integration

This successor combines complete Store transaction control with the artifact
delivery protocol. The transaction's HIA graph owns the original policy across
a suspended body and later resumption; SQLite and CPython generator/object
protocols remain foreign providers. Each actual advance has a fresh delivery
record within the shared resource lifetime.

All six artifact operations retain their public input domain. A separate
private entry accepts a nonce outside public input and returns a fixed
128-byte receipt tied to the actual operation, outcome, exit, phase and byte
counts. Missing or inconsistent receipts leave the dependent resource unknown.
The explicit v4 worker capsule binds this provider separately from the helper
registry. Every selected public use and normal terminal attestation still
checks the complete current source and installed inventory.

Five changed shared production files have frozen successor provenance. The
original inventory remains unchanged. Admission accepts all five original
whole files or all five exact successors, validates reversible byte changes,
and rejects all 30 mixed combinations. The other 86 source pins, 20 shared pins
and 21 original definitions retain their checks. This is source provenance,
not runtime qualification.

## Custody lock and workflow repair

The shared custody lock is now reentrant at initialization and after fork.
A separate forced-GC diagnostic reproduced the old weak-reference callback
attempting to acquire the same lock while its thread already held it. Changing
exactly those two lock constructions allowed cleanup to complete, while the
new independent checks retain cross-thread exclusion and child-process reset.
This mechanism experiment does not establish the cause of the interrupted
61-method run, whose stack was not observed. The exact five-file successor
provenance now binds the revised shared file; the original inventory and all
other original pins remain unchanged.

The raw-diagnostic upload still contains the same 535 ordered owned paths in
one artifact. A 6,081-character preparation step expands repeated patterns
using the unchanged raw runner temporary path and writes one multiline output.
Four actual output controls preserve spaces, trailing separators, Unicode,
quotes and existing output bytes. All original CI commands, conditions,
artifacts and budgets remain; the new three-test lock module is added to Source.

The new fsync diagnostic reran the unchanged negative helper and read its
traceback only after the original assertion failed. Its own captured child
stderr confirms a local ptrace permission refusal. That observation does not
replace the earlier R9 attempt's unavailable stderr or turn its failure into
a pass. The actual syscall-injection gate still requires its original CI run.

## Source-bound qualification

The qualification unit is one exact source tree and its admitted inputs.
Development compilation, current-source cold, installed workers, full original
regression and product cutover remain separate gates. CI observations below
were read on 2026-11-14 UTC; no parent success qualifies this successor.

| Exact scope | Actual result and remaining gate |
| --- | --- |
| Published parent 5bf69586b890706290c5fbfe93065ec0d3af40b1, tree 9008d431cf28b51edd8a5de589081090e3a19916 | Both complete Source suites passed all 684 methods, in 949.132 and 877.339 seconds. Generation and cleanliness passed. This parent lacks the new transaction/artifact changes. |
| Parent [push Native](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43623240537) | Terminal success, including printed strict summaries for build 112, emission 112 and wire 91. The full raw job log was retrieved. Its 1,330,554,873-byte artifact exceeds the transfer limit; redirected inner reports remain unread. |
| Same-tree [PR Native](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43623383081) | Original emission 112 failed at step 34, with 125.751839 seconds and 216 frames in the strict summary. Later steps were skipped. The whole artifact was retrieved but omitted the emission report directories. Internal cause remains unknown; the passing push does not erase this failure. |
| Exact-parent [full harness](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43623372620) | The complete lossless archive has now been independently read: all 42,180 members and 40,175 original files match bytes, modes and nanosecond timestamps. All 35 original stages passed, including Source 684 and full retained 5,050 with no anomaly. The original verbose-log reader reproduces every planned/started/stopped ID. Full discovery took 4,298.019502398 seconds within its original 5,400-second limit. Supplemental step 13 still failed before starting any command because its emission build reader required an obsolete scope; the whole workflow remains failed. This is parent 5bf evidence, not qualification of this successor. |
| Metadata parent 04492c20356b459d003152fc8b71b4c7d90e4244 | Both Native jobs succeeded. Its [full run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43621466530) was independently read from the complete lossless archive: all 5,050 planned methods started and stopped in order, with exactly one failure, the same release-freeze inventory assertion as Source 684; no other errors or skips. Supplemental validation stopped before running its commands because its emission build reader still required the old single-frame scope. The actual build declared integrated D0-D3 while test custody still declared its original narrower scope. These two sources must be checked separately. Both failures remain recorded. |
| Transaction R2 development component | Source 3 and Native 8 passed. Two fresh interpreters each froze all 521 originals before selected execution under the same explicit history: 1,042 full comparisons matched. Installed normal/replay, lost COMMIT and unknown replay passed. These are DEV inputs, with a recorded unused HEPTA_CLANG path error, not current-cold or dual-Clang configuration qualification. |
| Artifact R6 development component | Source 3 passed; complete Native 8 finished with 6 PASS, 1 FAIL and 1 ERROR. Actual fsync injection met local ptrace refusal, and installed execution hit its unchanged 60-second limit. Neither was waived. Original bridge 96 and terminal 44 fixtures remain unchanged; five independent cases cover the withdrawal receipt-count repair. |
| Artifact R7 installed observer repair | Removing an extra observer scan preserved all production checks. The targeted run still timed out at 60 seconds after six actual workers. Remaining scenarios were not counted; prior passing methods were not combined into a fictitious full success. |
| Published combination 91bbd077ce5f7ff7b5236b1b14b7989b6e90a8a6, tree 4bd3aa1dd78c89c70136f527188d23a04c8dab27 | Local complete Source 9 and transaction Native 8 passed; original transaction callers passed 112/112/112 in 138.923437730 seconds. Full artifact Native 8 remains HOLD with seven passes and one fsync-negative failure. Its installed method passed both standalone and within the complete run, under the unchanged 60-second limits. These are explicit DEV results for that exact earlier tree. |
| Original transaction 61 on that combination | INDETERMINATE after executor/session interruption. A start record exists but no terminal execution/report, observed timeout or complete module count. The session became inaccessible; an unobservable process namespace is not evidence of termination. The original cumulative 1,800-second allowance is unchanged. |
| [91bb push workflow](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43640050050) | Failed before creating any job. Independent analysis found that the new diagnostic path expansion exceeded Actions expression limits. The exact server annotation is unavailable. This successor replaces that expression with one prepared output while preserving all 535 ordered paths; actual server admission still requires a new run. |
| This custody/workflow repair | Three newly added lock checks passed with the exact two-line RLock module in fresh Python 3.12 and 3.13 processes. New complete Source/Native, Store 130, transaction 112/61, artifact 132, matching-current-cold and full retained results must bind this successor independently. Earlier component results are not reused as its qualification. |

The transaction histories are finite checks, not all-history equivalence.
The original R1 mixed-history failure remains preserved. A separate original-
only experiment reproduced its five AttributeError differences under the
declared history without proving the old process's adaptive-cache cause.

Artifact 132 retains all seven original modules: 63 direct fixtures, 37 complete
NDU/assembly methods under the generic selector, and 32 complete NativeTools
methods under their supported Store selector. Real NDU prerequisites are
mandatory. Transaction 61 retains all 21 journal, 25 execution-budget and 15
slot-ledger methods. Neither replaces Store 130, delivery 152 or its six caller
gates. Product CI adds the complete new component modules and transaction
112/61. The separate full harness adds artifact 132. Explicitly owned raw-text
outputs supplement the original complete upload, including emission diagnostics.

Cold retains **180 seconds plus three seconds cleanup**, the original full
regression **5,400 seconds**, and all supplemental limits remain unchanged.
The original 3-second context, 5-second wire and 64 MiB artifact controls remain.
Earlier timeouts, ptrace failures, incomplete groups and archival failures keep
their original status for their own inputs.

The complete previous component, failure, performance and cleanup narrative is
preserved at the [exact published parent index](https://github.com/TrillionniumFoundation/Hepta/blob/5bf69586b890706290c5fbfe93065ec0d3af40b1/docs/CURRENT.md).
Its old pending statuses are historical observations. The dated rows above
supersede only those same source/run identities.


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
`AgentStore` now has a selected HIA owner for complete transaction control,
including begin/commit/rollback sequencing. Actual SQLite effects, generator
and object protocols remain hosted. Its eight artifact/profile methods likewise
retain their unselected original bodies and explicit foreign providers. The service cost ledger has its
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
