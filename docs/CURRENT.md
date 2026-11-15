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
| Physical HIA sources ending in `.hepta` | 205 |
| Physical legacy `.hia`, `.HIA`, `.hiaasm`, `.hia.json`, including case variants | 0 |
| Production Python modules directly under `hepta/` | 239 |
| Registered native helper selectors | 48 |

The complete [indexed-source inventory](HIA_NATIVE_REWRITE_INVENTORY.json)
records every retained indexed file, Python module, static import edge, native
selector literal and source identity. It explicitly identifies its parent
HEAD, index changes and worktree bytes; it does not claim the later commit's
identity. Inventory coverage is not a claim that every line or dynamic/external
caller has been semantically audited. File counts are not percentages of
native behavior. The added Python modules are explicit host adapters and are
part of the remaining boundary.

### R12 source reconciliation; qualification remains separate

The frozen R12 index `fb016dbeb5c666dd43627f9a25bc58fda5f56c92`
contains 2,651 tracked files including the inventory. All 2,650 inventory
members match the complete freeze by path, size and SHA256; the excluded item
is the inventory itself. Its recorded checkout HEAD and composition base are
not the R12 index identity. These counts and source checks do not establish
dynamic caller closure, native equivalence, current cold completion or release
activation. The actual production registry has 48 single-image selectors,
not 48 automatically activated or fully qualified whole-product owners.

The earlier fourteen-scope audit was anchored at 0e36 with 226 production Python
modules and 43 helpers. The source state has changed as follows; this table
does not relabel its old results or the original full-suite failures.

| Earlier owner group | Current source state and remaining boundary |
| --- | --- |
| Service bootstrap/discovery | Discovery now has complete selected `_hia_describe` and static `_examples` graphs; constructor, close, profiles, profile/program loading and installation/catalog assembly remain hosted |
| Inspection/candidate | Both complete selected graphs exist; their actual program/edit/Store providers, Python object protocol and absent-selector originals remain |
| Proof admission | Nine complete subject/verification/replay/refinement/required-claim methods remain Python workflow owners; native proof leaves do not replace the group |
| Adopt/rollback | Complete selected Service Slot graphs exist; original ledger and transaction providers and independent multi-SQL qualification remain |
| Lease/invocation | Complete selected acquire_slot, _lease, invoke_lease and release_slot graphs exist; native runner, buffer/Store providers and original defaults remain |
| Filesystem capture | Complete selected stable_read/capture_path graphs exist; actual os/fdopen/stat effects remain hosted; raw descriptor ABI is separately optional |
| Store/SQL | Multiple selected lifecycle/artifact/profile/transaction/journal/budget/Slot controllers exist; actual SQLite durability, object providers and delivery/retirement remain separate |
| Compiler/publication | Bounded selected native compiler/backend control exists; default compiler/object/admission/link/publication orchestration and general profile gaps remain |
| Worker/process | Selected request/report/wire/scheduling control exists; Python entry, Service construction, process/IO/limits and installed identity remain |
| Delivery/mapping/retirement | Selected decisions exist; real mapping/loader references, PID/thread/Context authority, unknown-resource custody and close/unlink remain hosted |
| Adaptive/queue/optimization | Selected retention/publication/budget subpolicies exist; complete resident runtime, queue and optimization loops remain |
| Contract/edit/standard objects | Selected admission/composite/task/patch/JSON primitives exist; default schema/Core/edit objects and independent VM remain Python |
| Public Python compatibility | Dynamic lookups/imports/exception identity, with/iteration, temporary lifetimes and traceback/GC remain observable contracts |
| Default entry/distribution | Ordinary hia is Python and RELEASE_PIN is None; the candidate default wheel only owns FULL_COST, not the full helper registry |

The source contains the graphs just listed, but every component's execution,
original-input equivalence, full caller coverage, same-source cold, installation
and default activation require their own completed records. Historical
observations below retain their original source identities. In particular the
older read-qualification narrative is not a new R12 result and does not override
later raw results or outstanding failures.

The canonical suffix entered main at
[`51bc24b8b03e5adc3da1b2b3490ad5cc7357e8d8`](https://github.com/TrillionniumFoundation/Hepta/commit/51bc24b8b03e5adc3da1b2b3490ad5cc7357e8d8).
The main revision independently read for this audit was
[`f33d8da316de8fdf27b504371f1a5310997ff548`](https://github.com/TrillionniumFoundation/Hepta/commit/f33d8da316de8fdf27b504371f1a5310997ff548).
The [suffix contract](HIA_SOURCE_SUFFIX.md) and
[migration map](HIA_SOURCE_SUFFIX_MIGRATION.json) retain rename provenance.
Assembly keeps `hia-asm.v1`; structured Core keeps its schema; paired structured
projections use `.core.hepta`. The `hia` command, `hepta.hia.*` schemas, Git
objects and historical receipt bytes retain their original identities.

## Service read implementation and retained qualification history

The complete retained `_hia_read` body has a generated HIA control graph in
`service_read.hepta`, with 32 foreign ports. Cursor, decoding and budget loops,
exception transitions and result construction are represented in HIA.
The original twelve local slots and retained traceback custody remain
observable. The original 6,372 finite inputs, separate 86-case SQL scope,
installed worker checks and original caller gates retain their full domains.

The earlier successful and failing executions are preserved at the
[exact published index](https://github.com/TrillionniumFoundation/Hepta/blob/2b52d1665aaa476b5c0f50891b3c0328795a1dc9/docs/CURRENT.md).
Those source-specific results do not qualify this later source composition.
See [read ownership](HIA_SERVICE_READ_NATIVE.md) and
[complete read validation scopes](HIA_SERVICE_READ_VALIDATION.md).

## Transaction and journal candidates under qualification

An explicit transaction-owner scope admits the complete pinned manifest,
source and image before selection. Selection occurs at the generator's
first advance, with process and thread ownership checks for a new
transaction. An already started transaction retains its captured image and
can complete after the selecting scope exits. Nested scope, lazy selection,
manifest/source/image drift, stale copied contexts, thread/fork refusal,
legitimate resumed execution and an actual installed helper binding have
six complete new Native controls. This scope is used for the complete
original SlotLedger caller module, including its intentionally cleared
environment. The original retained-body poison and original method remain.

Journal pre-entry acknowledgement exceptions can require the original SQL
transaction cleanup before loss is published. The candidate keeps that
exception pending only while the real transaction cleanup runs. A real
native acknowledgement loss remains immediate; suppression or cleanup
failure cannot turn an unconfirmed SQL acknowledgement into success or
permit the next business phase. Four complete new Native methods cover
14 declared controls, 16 initial faulted requests and two original replay
checks, with actual journal/TX images and SQLite.

These changes remain candidates. The original complete journal 21,
execution-budget 25 and SlotLedger 15 methods form their unchanged TX61
gate; the new six and four methods supplement that gate. The product
workflow gives both new complete modules their own same-cold inputs and
owned evidence directories. Whole-suite environment wiring, matching
current-source cold, all separate retained caller scopes and installed
entry-point closure remain required. See
[the transaction contract](HIA_STORE_TRANSACTION_NATIVE.md).

## Latest implemented changes

Complete selected Inspection/Candidate, Service Slot adopt/rollback, four Lease,
Capture and Discovery controllers are now present. Their actual providers and
absent-selector originals remain explicit. The fourteen historical owner
groups are not fourteen wholly missing implementations.

The current successor contains four narrowly reviewed corrections:

- Capture's existing HIA-issued search-unwind port releases the root iterator
  under the invocation caller's handled-exception state. The normal release,
  71-port protocol, graph, original inputs and budgets remain unchanged.
- Discovery restores 29 fixed attribute accesses in five mechanical effect
  methods to their original syntax. It does not clear, replace or normalize
  `AttributeError.name` or `obj`.
- The import observer accepts and records actual unmaterialized `locals=None`.
  Globals identity, actual mapping key order, all twenty inputs, four explicit
  namespace controls and the full raw comparison remain.
- Capture's real-OS observer records existing descriptor sets and context only
  after the original comparison fails. Its original assertion still raises,
  including when diagnostic recording fails.

Whole-file reverse transformations were checked against the preceding source.
These changes remain under complete component qualification. Four independent
GC differences in Capture and four in Discovery remain unresolved; source
changes alone do not establish a repair.

The Slot observer uses weak exception identity and explicitly scoped builtin
borrowing. Its fifteen independent controls passed, then all twelve original
handled-traceback cases passed after two fresh complete original runs. The
separate full Slot finite domain still fails.

The existing complete service-artifact, context cleanup and pending-resource
ownership contracts remain. A resource is not inferred from a matching path,
getter, exception class or process exit code; actual unknown effects stay
unconfirmed. See [artifact ownership](HIA_SERVICE_ARTIFACT_NATIVE.md) and the
component contracts below.

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

The latest completed development composition used frozen R12 index
`fb016dbeb5c666dd43627f9a25bc58fda5f56c92`. Its complete 2,651-file freeze is
440,748 bytes / SHA256
`ec0fbddf2b227ced5b300bf40c776667f397cefc526a7a92738cf4d1374e5162`.

All 35 composition commands exited naturally with their owned groups gone.
Core passed in 72.996 seconds on actual CPython 3.14.10. Contract, clean-diff
and three identical final metadata rounds passed. Both new HIA outputs were
generated twice with identical bytes.

The strict nine-source reconstruction preserves independently pinned
originals, all-old/all-new admission and the original exact adapter definition
checks. All 574 ordered controls passed using the actual R12 roots: two
accepted and 572 rejected. This is source-custody evidence, not Native execution.
The actual helper registry has 48 entries.

The explicitly identified development compiler is B3
`bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`.
It is not matching-current-source cold acceptance. The current successor's
source, documentation and cleanup changes receive their own freeze and gates;
the R12 observations below remain evidence of R12.

## Observed validation and remaining acceptance

All 62 original methods in the R12 seven-scope series started and stopped in
order: **56 PASS, two failures, four errors, zero skips**. Sources remained
unchanged; every recorded owned process group was gone and no command path
was unbound. Overall status is HOLD.

| Frozen R12 complete scope | Observed result |
| --- | --- |
| Prepared Source 3 | 3 PASS |
| Arithmetic Source 7 | 7 PASS |
| Generic VM Source 21 | 21 PASS |
| Lease Native 8 + Resource 4, one shared authority/process | 12 PASS |
| Discovery Source 3 | 1 PASS, 2 errors |
| Discovery Native 8 | 6 PASS, 1 failure, 1 error |
| Capture Native 8 | 6 PASS, 1 failure, 1 error |
| Separate Store delivery Source 3 | 3 PASS |
| Separate strict nine-source 574 controls | Expected 2 accept / 572 reject |
| Separate Slot identity helper 15 controls | 15 PASS, auxiliary scope only |
| Separate Slot Native 6 | 5 PASS, 1 failure; all six completed |

The separate scopes do not combine into a whole-product pass.

| Complete comparison | Actual remaining difference |
| --- | --- |
| Capture Native 4,885 inputs | Both complete originals byte-identical; 4,717 candidate rows equal. 164 cases differ only at iterator-destruction handled-exception labels in two event views; four other cases differ only at explicit-GC counts. |
| Discovery Native 11,016 inputs | Both complete originals byte-identical; 10,568 candidate rows equal. 444 cases differ at AttributeError name/obj fields, and four at explicit-GC counts. |
| Discovery Source 56 inputs, VM and unselected | Each complete lane differs only at four explicit-GC scalar fields. |
| Slot finite 248 base + 7,574 derived | Six base cases / 24 leaves and 290 derived cases / 1,785 leaves differ. |
| Slot handled-traceback 12 | PASS with two fresh complete originals before candidate; this does not replace the finite domain. |

Capture's complete 124-input VM/native packet comparison and the other six
Native methods passed. Its real-OS method failed while observing the original
provider, before candidate execution. The old failure did not save its label
or descriptor sets, so neither the exact case nor leak/closure direction is
invented. The failure-only successor preserves that assertion while recording
those facts on a future failure.

The original Discovery import helper rejected before finishing its fresh
original controls. The failed row was not saved. Its two-site successor fixes
the source-demonstrable None-locals prerequisite; all raw original/candidate
fields still have to match.

Root independently re-read the complete Capture and Discovery observation and
traceback streams, compared every original1/original2/candidate observation
row, verified all ordered IDs and re-read all consumed bytes unchanged.
Selected complete rows retain original byte offsets and hashes. Readback:
708,412 bytes / SHA256
`770985313daa8c4dd6f4bba9f5125e132098768cc57977a8264e9d8dd37e347a`.
This corroborates the failures; it does not qualify a correction.

The Slot explicit-GC 16 versus 88 difference remains open. Extra retained
Python driver frames and a provider exception cycle are visible in static
traceback analysis. This is not proof that clearing frames, tracebacks or
dictionaries would preserve original semantics.

R11 arithmetic diagnostics showed no demonstrated speedup: B was 33.680%
slower in the original instrumented diagnostic and 0.542% slower in an
independent unprofiled diagnostic. All original thirty inputs matched full
output/state/resource records. Those diagnostics do not close the full
7,822-case budget.

Published
[`2b52d166`](https://github.com/TrillionniumFoundation/Hepta/commit/2b52d1665aaa476b5c0f50891b3c0328795a1dc9)
has successful complete Source and Native push/PR jobs, including 716 Source
tests and all 122 reported Native steps. They bind their actual published or
merge checkout, not this later composition.
[PR 897](https://github.com/TrillionniumFoundation/Hepta/pull/897) records the
actual current source/run identities and remaining acceptance.

All earlier detailed outcomes, including complete retained-suite failures and
timeouts, remain at the immutable published index linked above and in original
raw records. They are not relabelled or silently retried as passes.

Original complete domains, IDs/order, assertions, poison, GC, traceback,
adaptive histories and exception fields remain intact. Cold **180 seconds
plus three seconds cleanup**, full retained **5,400 seconds**, component
**1,800-second** outer gates and original caller/subprocess limits remain.
No normalized field, favorable repeat or selected subset replaces a gate.

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
| `hia_describe` | Complete explicitly selected Service Discovery graph; original schema/resource/import/object providers remain; no default activation is implied |
| `hia_artifact` | Complete selected HIA handler; Capture has a separate selected graph, while actual filesystem/hash/Store/SQLite effects and opaque object protocols retain their declared providers |
| `hia_read` | Complete selected HIA control candidate above; original filesystem/SQLite/codec providers, opaque object protocols and source-bound qualification remain |
| `hia_context` | Hosted schema/profile/buffer providers, clock/object protocols and persistence effects; selected freeze/lookup/deadline control now has the HIA owner above |
| `hia_inspect` | Complete explicitly selected Inspection graph; original program/query/lowering/Store providers and object/exception lifetime compatibility remain |
| `hia_candidate` | Complete explicitly selected Candidate graph; original import/edit/verification/Store providers and lifetime compatibility remain |
| `hia_verify` | Claims, independent proofs, deadlines and replay verification; selected native artifact/build-receipt control has the HIA owner above, with Core/ABI/Store/object providers retained |
| `hia_emit` | Selected HIA compile/emission control above; original Core emitter/compiler/linker, filesystem, Store/SQLite/clock/hash and opaque object providers remain |
| `hia_evaluate` | Original reference VM/native runner, clock/object protocols, integer-to-binary64 division and threshold comparison, plus SQLite/artifact effects; selected complete evaluation control and ledger policy now have the HIA owners above |
| `hia_adopt` | Complete explicitly selected Service Slot graph; verification claims, original ledger/transaction providers and the independently qualified multi-SQL layer remain |
| `hia_rollback` | Complete explicitly selected Service Slot graph; original retained-image/ledger/transaction providers and multi-SQL delivery custody remain |

`hia_resource_read` remains a supported alias, not a twelfth catalog tool.
`AgentStore` now has a selected HIA owner for complete transaction control,
including begin/commit/rollback sequencing. Actual SQLite effects, generator
and object protocols remain hosted. Its eight artifact/profile methods likewise
retain their unselected original bodies and explicit foreign providers. Complete selected Capture and the four Service Lease graphs are now controllers under separate qualification; actual filesystem, runner and SQLite effects remain declared providers. The service cost ledger has its
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
| Proof authority | Nine complete Service subject/verification/replay/refinement/required-claim methods, fresh Core verification and original Z3/Lean obligations; component admission does not replace these workflows or proofs |
| Native process ownership | Runner setup, environment/limits, snapshots, termination and complete report checking |
| Resident resources | Selection/CAS, actual invocation, libraries, sealed descriptors and confirmed cleanup of outstanding generations |
| Final cutover | Clean install/default startup, old context/request migration, worker restart/handoff, running-image readback and confirmed retirement |

The next full business units are nine subject/behavior/verification/replay/
refinement/required-claim methods, then Service constructor, close and profile/
program loading. Native proof leaves do not own these complete workflows.

The selfhost contract explicitly retains general Core checking, arbitrary
external symbols/relocations, a general linker and additional target gaps.
`whole_HIA_language_self_hosted=false` remains accurate. Its original fixed
points require B1=B2=B3; M1!=M2, M2=M3, M3!=B3; and reservation 64→80.
A bounded fixed point is not complete language or installed worker closure.

The package default remains `RELEASE_PIN=None`. The default-native candidate
admits only FULL_COST, and neither 48 registry entries nor an old administrator
bundle is silently expanded into a complete native worker.

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

The active tree retains current implementations, contracts, consumed fixtures
and recovery ledgers. Numbered HIA units can be parts of one composed program;
names do not make them obsolete versions. Independent original fixtures,
three consumed NDU archives, acquisition locks and the live original v4
qualification/process supervisor still have actual consumers.

This update retires two unreferenced historical narratives, **6,096 bytes**:
`HIA_TEST_GATE_HARDENING_20261031.md` and
`HIA_RELEASE_AND_TRIAL_OBSERVATIONS.md`. Their complete bytes were read from
published commit `2b52d1665aaa476b5c0f50891b3c0328795a1dc9` and matched local
Git blob, mode, size and SHA256. The existing process-document ledger now
records **34 files / 206,342 original bytes**. Original gate implementations,
test IDs and raw execution evidence remain.

The separate development ledger records **1,045 files / 60 directories /
91,641,221 original bytes** across its prior rounds. Those are its own scope,
not new deletions performed here. A bounded search's absence of filename
references is not a claim about arbitrary undeclared external consumers.

Every retired member retains an exact published recovery identity:

- [Development versions](../review-evidence/hia-native-cleanup-20261111/retired-development-versions.json).
- [Process documents](../review-evidence/hia-native-cleanup-20261111/retired-process-documents.json).
- [Historical bundles](../review-evidence/hia-native-cleanup-20261111/retired-historical-bundles.json).
- [Rewrite observations](../review-evidence/hia-native-cleanup-20261111/retired-rewrite-observations.json).

This index consolidates the current state. Its prior detailed chronological
narrative remains at the
[immutable published revision](https://github.com/TrillionniumFoundation/Hepta/blob/2b52d1665aaa476b5c0f50891b3c0328795a1dc9/docs/CURRENT.md).
No old failed observation is rewritten. Active hosted implementations and
consumed tests remain until their full replacement and cutover are qualified.
Separate PRs [#888](https://github.com/TrillionniumFoundation/Hepta/pull/888),
[#889](https://github.com/TrillionniumFoundation/Hepta/pull/889) and
[#893](https://github.com/TrillionniumFoundation/Hepta/pull/893) retain their
own source identities and are not imported wholesale.
