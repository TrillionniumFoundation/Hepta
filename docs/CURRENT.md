# HIA: current implementation and acceptance

This is the current-state index for `TrillionniumFoundation/Hepta`. The language
is HIA; the canonical source suffix is lowercase `.hepta`.

**The suffix migration is complete. Whole-product native replacement remains
incomplete.** `whole_native_delivery_qualified=false`,
`old_stack_can_be_removed=false`, and `production_activated=false`.
The ordinary `hia` executable still enters `hepta.cli:hia_main`. The remaining
hosted service, storage, proof, process and runtime owners have live consumers.

## Source naming and audited inventory

| Current source inventory | Count |
| --- | ---: |
| Physical HIA sources ending in `.hepta` | 199 |
| Physical legacy `.hia`, `.HIA`, `.hiaasm`, `.hia.json`, including case variants | 0 |
| Production Python modules directly under `hepta/` | 222 |
| Registered native helper selectors | 42 |

The complete [indexed-source inventory](HIA_NATIVE_REWRITE_INVENTORY.json)
records every retained indexed file, Python module, static import edge, native
selector literal and source identity. It explicitly identifies its parent
HEAD, index changes and worktree bytes; it does not claim the later commit's
identity. Inventory coverage is not a claim that every line or dynamic/external
caller has been semantically audited. File counts are not percentages of
native behavior. The added Python modules are explicit host adapters and are
part of the remaining boundary.

The canonical suffix entered main at
[`51bc24b8b03e5adc3da1b2b3490ad5cc7357e8d8`](https://github.com/TrillionniumFoundation/Hepta/commit/51bc24b8b03e5adc3da1b2b3490ad5cc7357e8d8).
The main revision independently read for this audit was
[`f33d8da316de8fdf27b504371f1a5310997ff548`](https://github.com/TrillionniumFoundation/Hepta/commit/f33d8da316de8fdf27b504371f1a5310997ff548).
The [suffix contract](HIA_SOURCE_SUFFIX.md) and
[migration map](HIA_SOURCE_SUFFIX_MIGRATION.json) retain rename provenance.
Assembly keeps `hia-asm.v1`; structured Core keeps its schema; paired structured
projections use `.core.hepta`. The `hia` command, `hepta.hia.*` schemas, Git
objects and historical receipt bytes retain their original identities.

## Current implementation change

The complete `HIAAgentService._hia_describe` control graph now has an
independent, explicitly selected HIA owner in `service_describe.hepta`.
The image owns effect order, cursor and backend-profile branches, continuation
after a returning rejection provider, acknowledgements and termination. The
adapter never invokes the retained handler on the selected route.

The complete original six-section resource dictionary is still eagerly
constructed as one foreign expression before section lookup. Catalog loading,
object protocols and Store/SQLite remain hosted. The original method's exact
1,992 bytes remain the independent reference and unselected route. The
[component contract](HIA_SERVICE_DESCRIBE_NATIVE.md) defines all thirteen ports,
the ABI, custody rules, local lifetime and matching-source build requirements.

The independent test fixture fixes 291 original cases before candidate output.
Qualification requires full original/VM and original/Native observations,
all 170 provider/ABI/resource fault controls, actual installed-wheel use of all
six sections, and the separate complete original 112-caller scope. Initial
failed attempts remain preserved. Neither a finite component comparison nor
adding an authored HIA source establishes whole-product replacement.

## Implemented HIA ownership

The components below have authored HIA control within their declared profiles.
Their linked contracts identify original fixtures, caller scopes and source-bound
evidence. Their foreign providers and current-source qualification remain explicit.

| Area | HIA-owned behavior | Retained host boundary |
| --- | --- | --- |
| [Service discovery](HIA_SERVICE_DESCRIBE_NATIVE.md) | Complete original handler control: catalog import ordering, cursor/profile branches, language/profile calls, eager resource selection, result and local release | Module loading, catalog implementation, complete eager resource expression, opaque Python objects and Store/SQLite profile effects |
| [Compile and emission](HIA_EMISSION_NATIVE.md) | Both complete original methods: branch/loop control, dynamic compile calls, context-manager cleanup and suppression, generator iteration and publication order | Core emitter/compiler/linker, filesystem, Store/SQLite/clock/hash providers and opaque Python object protocols |
| [Store artifact and profile](HIA_STORE_ARTIFACT_PROFILE_NATIVE.md) | All eight original put/json/reference/get/get-json/URI/profile/check-profile methods: original guard and dynamic global reads, short circuits, ordered reference iteration, argument evaluation, publication and cleanup control | Original filesystem, SQLite, hash, JSON and native-artifact providers, opaque object protocols and actual SQLite/generator effects; selected transaction control has its separate owner below |
| [Native artifact and build receipt](HIA_NATIVE_BUILD_ADMISSION.md) | All four original signature/native/build-input/build-receipt methods, including ordered loops, composite checks, short circuits and nested admission | Opaque Python object protocols, original Core/context/ABI providers, Store/SQLite and SHA-256 |
| [Evaluation](HIA_EVALUATION_NATIVE.md) | Complete original evaluation branches, case/arm iteration, correctness and completeness flags, six-outcome precedence, budget/effect order and exact integer deadlines | Original reference VM and native runner, Store/SQLite/clock providers, object protocols, integer-to-binary64 division and threshold comparison |
| [Cost ledger](HIA_COST_LEDGER_NATIVE.md) | Original query/decode/policy ordering, 10,001-row truncation, context/unscoped selection, exact signed sums and output construction order | SQLite query/fetch, JSON decoding, row/object allocation and the original integer/string conversions |
| [Service context](HIA_SERVICE_CONTEXT_NATIVE.md) | Context freeze/lookup, workload and budget loops, complete effect ordering, exact signed deadline arithmetic and remaining-time floor | Schema/profile/buffer providers, object/time protocols, artifact/SQLite effects and the original candidate-consumption provider |
| [Static resources](HIA_STATIC_BUDGET_NATIVE.md) | Stable graph order, exact allocator/tick arithmetic, synchronous call depth, v7/v8 resource profile and ordered numerical policy decisions | Sole Core verification, primitive/policy shape validation, fact projection, independent heap analysis and final report hashing |
| [Service artifact](HIA_SERVICE_ARTIFACT_NATIVE.md) | Complete original handler: profile/source branching, capture and digest checks, rejection, Store publication and ordered result construction | Original path capture, filesystem/hash/SQLite providers, opaque Python object protocols and delivery/resource custody |
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


## Exact composed source provenance

Eight production paths retain a single exact successor composition:
`artifact_publication_native.py`, `hia_agent_store.py`,
`hia_store_lifecycle_selection.py`, `hia_native_delivery.py`,
`hia_store_lifecycle_native.py`, `hia_agent_service.py`,
`hia_emission_native.py` and `hia_store_artifact_profile_native.py` under
`hepta/`. Each complete byte patch reconstructs an independently pinned
original Git blob. Admission permits only the complete old or complete new
composition, rereads the files and rejects mixtures or changed bytes.

The immutable c019 inventory retains its 21 complete definition checks:
20 exact original definitions and one explicitly pinned `_context_special`
successor. The new service-discovery dispatch is an explicit appended hunk in
the service source's reconstruction. No original method, fixture identity,
source check or caller scope is broadly normalized.

The independent provenance gate covers all 256 old/new compositions, eight
single-byte mutations and two actual reread races. Only the all-old and all-new
compositions may accept. These are source-admission controls; they do not
establish behavioral, cold-bootstrap or release qualification.

## Validation and retained failures

Execution evidence belongs to its exact source bytes and runtime. Current-tree
CI, matching-source compiler admission, installed readback, complete original
caller scopes and full retained regression remain distinct requirements.

| Published reference | Retained result and limit |
| --- | --- |
| [3424f6d](https://github.com/TrillionniumFoundation/Hepta/commit/3424f6d116a087373b161b9970cad07c65a9e4c4), [integration PR #897](https://github.com/TrillionniumFoundation/Hepta/pull/897) | Parent of this candidate. Its complete 59-component and original 112-caller DEV runs passed on actual CPython 3.13.5 and 3.14.10. They do not qualify this later source or current-source cold. |
| Same parent's [push Core run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43662800655) and [PR Core run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43662810818) | Source passed. Native failed at the complete transaction-journal, execution-budget and SlotLedger caller gate. The journal UNKNOWN/cleanup behavior and the selected-route scope in the SlotLedger original remain open. |
| Parent's [full audit](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43665223497) | Independently retained full-run evidence targets exactly 3424f6d. Its terminal result must be read from that run; it cannot qualify later source bytes. |
| Earlier [e7 full audit](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43650082174) | All 5,080 tests ran and six subcases failed. Its complete failure evidence and source-bound cold report remain part of the record. |
| Earlier [bb3120 full audit](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43644981418) | The 5,075-test invocation reached its original 5,400-second limit without a complete result. It is not a passing suite. |

The immutable [3424 current-state record](https://github.com/TrillionniumFoundation/Hepta/blob/3424f6d116a087373b161b9970cad07c65a9e4c4/docs/CURRENT.md)
and PR #897 retain complete earlier runtime comparisons, exact source identities,
raw-evidence references and unsuccessful attempts. The current index does not
duplicate those process narratives. Historical successes do not erase the
recorded Python 3.12 Store diagnostics, original full-suite failures or
indeterminate operations.

Original limits remain: cold **180 seconds plus three seconds cleanup**, full
retained **5,400 seconds**, context **three seconds**, wire **five seconds**,
artifact **64 MiB**, and every original caller/subprocess budget. The complete
112, separate 61, artifact 132, Store 130, delivery 152 and separate 128 scopes
retain their original modules. Overlap is not added together as coverage, and
no partial run substitutes for a complete scope.

## Public entry-point audit

The complete [15-action CLI matrix](HIA_CLI_NATIVE.md#all-15-ordinary-actions)
identifies each remaining action owner. `pyproject.toml` still installs
`hepta.cli:hia_main`; selected CLI control executes 42 foreign effect operations
through the Python bridge. Its declared CPython profiles do not cover the entire
portable package's Python >=3.11 declaration. The six standalone
[stdio commands](HIA_AGENT_STDIO_NATIVE.md) have a separate protocol and bounded
primitive profile; they cannot substitute for all ordinary CLI actions.

The worker starts through `hia_agent_worker`, constructs `HIAAgentService`, and
dispatches these eleven public tools. The table states the hosted boundary that remains for each tool; selected
HIA policy ownership is recorded separately above.

| Worker tool | Remaining service ownership |
| --- | --- |
| `hia_describe` | Selected HIA branch/sequence/termination control; module loading, catalog construction, eager resource table, opaque objects and persistent profile effects remain hosted |
| `hia_artifact` | Complete selected HIA handler above; path capture, hash/Store/SQLite effects and opaque object protocols remain hosted |
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

The candidate retires **19 historical queue-experiment files / 47,321 bytes**
from `experiments/hia_legacy_queue/`. Active source, test, package and source
contracts do not consume those files. The
[remaining queue example index](../examples/hia_legacy_queue/README.md) points
to the exact published 3424 protocols and negative results.

The existing [development-version ledger](../review-evidence/hia-native-cleanup-20261111/retired-development-versions.json)
records every retired path, Git mode/blob, original size and SHA-256, plus the
published recovery revision. Older ledger rounds remain unchanged. Recovery
restores the nineteen actual files; payloads already absent at the recovery
revision are not reconstructed from their historical index entries.

The active tree retains current source, contracts, consumed fixtures and
recovery ledgers. Numbered source units can belong to one multi-image program;
their names alone do not identify obsolete versions. Independent original
fixtures, the three consumed NDU archives, acquisition locks and original
failure evidence remain required by current acceptance.

Other historical recovery indexes are retained in the
[process-document ledger](../review-evidence/hia-native-cleanup-20261111/retired-process-documents.json),
[historical-bundle ledger](../review-evidence/hia-native-cleanup-20261111/retired-historical-bundles.json)
and [rewrite-observation ledger](../review-evidence/hia-native-cleanup-20261111/retired-rewrite-observations.json).
The original v4 qualification and process supervisor remain intact.

Separate PRs [#888](https://github.com/TrillionniumFoundation/Hepta/pull/888),
[#889](https://github.com/TrillionniumFoundation/Hepta/pull/889) and
[#893](https://github.com/TrillionniumFoundation/Hepta/pull/893) retain independent
source identities. They are not imported wholesale into this candidate.
