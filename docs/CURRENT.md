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
| Physical HIA sources ending in `.hepta` | 198 |
| Physical legacy `.hia`, `.HIA`, `.hiaasm`, `.hia.json`, including case variants | 0 |
| Production Python modules directly under `hepta/` | 220 |
| Registered native helper selectors | 41 |

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

## Latest implemented changes

The complete original `HIAAgentService._hia_artifact` control graph now has an
explicitly selected HIA owner. The image chooses source-kind branches,
expected-digest short circuits, rejection and publication order, result
construction and normal/error continuations. Original opaque provider
expressions preserve method binding, temporary receiver lifetimes and dynamic
global lookup. Selection never calls the retained handler. The original
method and unselected fallback remain available until the full product cutover.
See [the complete service artifact contract](HIA_SERVICE_ARTIFACT_NATIVE.md).

The service-artifact adapter also preserves the running interpreter's local
release order. Fixed private probes observe frame and builtin-dict destruction;
the six original handler locals occupy preordered builtin storage. This keeps
normal release and the caller's eventual traceback release consistent without
creating a per-invocation finalizer or clearing an exceptional frame early.
The need was observed on actual CPython 3.14.10 and independently traced to
[`_PyFrame_ClearLocals` in 3.14](https://github.com/python/cpython/blob/v3.14.10/Python/frame.c)
and its [3.13 implementation](https://github.com/python/cpython/blob/v3.13.5/Python/frame.c).
The original 146 finite inputs, original test methods and all budgets remain
unchanged; the new local-lifetime controls supplement them.

Pending resource observations are reserved before the actual foreign effect.
Only a real downstream native handoff or an explicitly completed resource
scope supplies the corresponding occurrence and resource. A complete matching
parent acknowledgement retires its own healthy observations before the next
provider. Actual unconfirmed resources remain held and cannot be closed or
silently replayed. This does not infer a resource from a service getter, an
exception class, a matching-looking path or a native process exit code.

The shared context-manager boundary now follows the running interpreter's
actual type-name and missing-special diagnostics. Direct type descriptors
avoid metaclass/string hooks; async suggestions inspect descriptor presence
without binding user descriptors. Five fixed private probe types remain
strongly held by the module, and the diagnostic caches retain no user type or
instance. Creating a temporary surrogate type per user error was rejected
because it changed observable cyclic garbage. The actual descriptor binding
and the caller's active exception chain remain separate from error formatting.

The preceding resource-retirement exception-context repair and the initial/
after-fork reentrant custody locks remain. Production artifact descriptor
admission remains strict; the old standalone mock supplies a valid static,
nonexecuting private-entry descriptor without changing any original test method.

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

Eight previously pinned production paths have a single complete successor:
`artifact_publication_native.py`, `hia_agent_store.py`,
`hia_store_lifecycle_selection.py`, `hia_native_delivery.py`,
`hia_store_lifecycle_native.py`, `hia_agent_service.py`,
`hia_emission_native.py`, and `hia_store_artifact_profile_native.py` under
`hepta/`. Each full byte patch reconstructs its independently pinned original
Git blob. Admission accepts only the complete old composition or the complete
new composition, rereads the files and rejects mixed or changed bytes.

The original c019 inventory JSON remains unchanged. Its 21 adapter definition
checks keep 20 exact original definitions and one explicitly pinned, reviewed
`_context_special` successor. The other old source/shared checks remain active;
there is no broad AST normalization or partial fallback. The existing
helper-count literal adjustment is explicit and narrowly scoped.

Independent static review and all 256 old/new combinations were completed for
the frozen integration: exactly the all-old and all-new combinations were
accepted, while the 254 mixtures, eight single-file byte mutations and two
actual reread races were rejected. These checks establish exact provenance,
not whole-program behavior or current-source cold qualification.

## Observed validation and remaining acceptance

The records below identify their exact source and runtime. They were observed
before this documentation/inventory freeze. They do not
qualify later changed source bytes; current-tree CI, compiler admission and
installed readback remain independently required.

| Exact source and scope | Observed result |
| --- | --- |
| Published e7c1729345d5d06757b38a6ae1ce54ae9790fd85, complete Source CI | Push [43648362345](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43648362345) passed 698 tests in 947.650 seconds; PR [43648548723](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43648548723) passed 698 in 760.416 seconds. Actual CPython 3.14.10. |
| Same e7 push and PR Native transaction modules | Both complete eleven-test modules failed one method with H0/H1 subtest failures. Each history completed all 521 originals. Independent full-table comparison identifies only two diagnostic-string leaves, for missing enter and exit; the remaining observations, histories and source identities agree. Push took 16.556 seconds and PR 12.483. Later Native steps were skipped. These runs remain HOLD. |
| Exact R3 four-file context repair, complete nine-method Source module | PASS on CPython 3.12.14, 3.13.5 and actual 3.14.10, in 2.410, 2.330 and 2.755 seconds respectively. The independent [3.14 run 43653988056](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43653988056), harness a2c6647d421dced8d7dc0c306b8a5ab010ed9d41, has complete raw logs and exact four-file readback. This is Source-only qualification. |
| Local service-artifact composition a01e2473bc7972eb4d4780f557d427bbae99d3d3 | Complete Source 3, Native 8 and all nine original caller modules / 112 methods passed on its exact source. This earlier DEV composition does not qualify the later context repair. |
| Local combined tree 8ffb7cb5fea162bcfb7f65bd417d48778258bc0e at 593e2358d43567d44fa6afa35836c53c0fe23ad0 | Complete context 9, original D4 Source 3, original transaction 11, Store profile 11, emission 11, service artifact Source 3 and Native 8: all 56 passed on CPython 3.13.5. The complete original 112 callers then passed in 138.5493 seconds (139.0689 outer seconds), with 469 actual service-artifact frames and zero retained-body calls. All 1,253 admitted source identities match before/after; no owned process groups remain. This is explicit DEV qualification before the documentation freeze. |
| Unpublished 10b5347e287cd617ebc7bfdde0a5f7f439b421de, tree cbb1db307e8053d6c147e38400ebef28ed6cc0c6, actual CPython 3.14.10 | All 56 component methods started and stopped; 55 passed. The full 146-case service-artifact comparison found exactly 26 event-order leaves in 13 exception cases: the original released the issued reference before data, while the adapter released data first. Values, errors and all other observations matched. The complete Native8 module therefore remained HOLD, and the original 112 caller gate did not start. The invocation exited naturally with status 1, no signals and no remaining owned groups. This failure is retained and is the direct reason for the local-storage repair above; earlier 3.13 success does not qualify the repair. |
| Exact local-release adapter `6e4a57398080eebb614711954baa79465a5d0b3e35c997aba98fdc63fd141495`, before metadata/commit freeze | Complete original Source 3 plus additive local-release Source 3 passed **6/6 in each runtime**: 3.12.14 in 43.928008 unittest seconds (44.241036 outer); 3.13.5 in 43.557761 unittest seconds (43.791527 outer); 3.14.10 in 56.367979 unittest seconds (56.931763 outer). Each fresh child formed all 146 original observations before candidate imports and then completed all 146 independent-VM observations; complete raw bytes matched, with 1,850 VM entries (146 initialize, 852 claim, 758 successful and 94 exceptional acknowledgements). Independent readback checked all 2,407 worktree source identities, all method events, all raw rows and the absence of owned process groups. This is Source/VM qualification, not Native, matching-cold or whole-product qualification. |
| Current-source cold and complete retained acceptance | Separate gates remain required. The e7-bound full harness [43650082174](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43650082174) and bb3120-bound parent [43644981418](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43644981418) were still running at this observation. Neither can qualify the new source composition. |

The completed 593 DEV readback includes both transaction histories of
521 originals each; Store 463 ordinary, 41 dynamic-limit and 160 cold plus
160 warm literal observations; emission 954 observations; service artifact
146 observations, 134 complete VM/native buffer records and 24 resource
controls; and two real installed wheels, each with 390 file/RECORD identities.
The development compiler remains explicitly identified as B3
`bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`.
No unchanged expected field was normalized, no original method was filtered,
and no partial result was combined into a passing run.

Earlier failures remain part of the record. The first context diagnostic
round failed C-created heap-type naming; the next eight-test round exposed
additional GC objects in a separate 16-process diagnostic (original zero,
candidate 13 on first use and seven after its name probe). R3 retains all eight
prior method ASTs and adds 32 fresh-process lifetime/GC comparisons. The first
service-artifact fixture round also remains HOLD; only two new fixtures were
corrected after proving the real Store budget back-reference cycle through the
original route. The production cycle and all original finite inputs remained.

The initial additive local-release Source round is also retained: all three
runtimes completed six methods, with five successes and one GC-observation
failure. The preceding independent-VM fixture left its image, program and
closure cycle for the next method to collect. An isolated fixture diagnostic
identified all six objects without executing any VM instruction or original
handler. The final third control runs all 146 originals and VM candidates in
one fresh child, saving the original bytes before any candidate import. It
does not collect or normalize garbage itself. Every invocation has a distinct
evidence directory, complete original/actual rows and supervision records;
the first two new methods and all original tests remain unchanged. Its new
child budget is 180 seconds plus three seconds cleanup; no original budget
has changed.

The recorded complete Python 3.12 Store runs retain three warm
`AttributeError.name`/`obj` differences. Python 3.13 success does not erase that
open compatibility gap. The earlier full D5 fsync-negative failure remains; a later
independent ptrace refusal is not invented as its missing historical stderr.
The interrupted 61-method transaction invocation remains INDETERMINATE, with
no captured terminal result or established cause. Complete earlier records
remain at the [published e7 index](https://github.com/TrillionniumFoundation/Hepta/blob/e7c1729345d5d06757b38a6ae1ce54ae9790fd85/docs/CURRENT.md)
and [draft integration PR](https://github.com/TrillionniumFoundation/Hepta/pull/897).

Original cold **180 seconds plus three seconds cleanup**, full retained
**5,400 seconds**, context **three seconds**, wire **five seconds**, artifact
**64 MiB**, and all original caller/subprocess budgets remain unchanged.
The complete 112, separate 61, artifact 132, Store 130, delivery 152 and all
existing integration gates retain their distinct scopes. Finite observations
are not all-input, all-history or all-Python-version equivalence.

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
| `hia_describe` | Profile/resource/page discovery; CLI discovery JSON does not automatically replace this API |
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
