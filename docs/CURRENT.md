# HIA: current implementation and acceptance

HIA is the language; its canonical source suffix is lowercase `.hepta`.
**Source naming migration is complete. Whole-product native replacement remains incomplete.**
`whole_native_delivery_qualified=false`, `old_stack_can_be_removed=false`,
and `production_activated=false`. The ordinary executable still enters
`hepta.cli:hia_main`; the default release pin is `None`.

This index describes the current implementation and the latest completed
source-bound observations. Detailed chronological development accounts remain
in Git history and the [active draft PR](https://github.com/TrillionniumFoundation/Hepta/pull/897).
A result on an earlier tree does not qualify this source successor.

## Audited inventory and dependencies

The current source tree contains 2,789 indexed files. The complete predecessor
R20 audit bound its 2,787 files to tree
`daeaeab048c2953b6d60c2892fb946f94c955186`, published as
[`8c2c212d974e2b0d510164e6012e609997b76c4b`](https://github.com/TrillionniumFoundation/Hepta/commit/8c2c212d974e2b0d510164e6012e609997b76c4b).
This successor adds one exact-source admission helper and its provenance fixture;
production modules and existing HIA source bytes remain the same inventory.
There are 207 HIA source files: 182 assembly and 25 structured files.
No physical `.hia`, `.hiaasm` or `.hia.json` source files remain.
Assembly still uses the `hia-asm.v1` header; paired structured projections use
`.core.hepta`. Command names and protocol schemas retain their existing identities.
See [source naming](HIA_SOURCE_SUFFIX.md).

There are 1,493 Python files in the indexed tree, of which 249 are recursive
production modules under `hepta/`. The source contract registers 1,388 paths,
and the native helper registry contains 50 entries. Module, helper and HIA-file
counts measure inventory, not replacement completeness.

| Remaining production module role | Modules |
| --- | ---: |
| CLI, worker and execution entry | 13 |
| Compiler, lowering and code generation | 35 |
| Frontend, Core admission and editing | 28 |
| VM, finite execution and proof runtime | 29 |
| Service, Store, scheduling and optimization | 65 |
| Protocols, schemas, wire and codecs | 43 |
| OS, SQL, loading and runtime providers | 36 |
| **Total** | **249** |

The classification covers the actual production directory set exactly.
The static audit records 904 package import edges plus 50 explicit helper
registry edges. This is a static dependency inventory; it does not establish
dynamic caller closure. The machine-readable
[rewrite inventory](HIA_NATIVE_REWRITE_INVENTORY.json),
[selfhost contract](HIA_SELFHOST_CORE_SUPPORT.json), and
[language coverage](HIA_SELFHOST_LANGUAGE_COVERAGE.json) retain per-source
identities and declared boundaries.

## Latest completed source-bound observations

The following product results belong to the exact R20 predecessor above. Its
full source freeze is 464,161 bytes with SHA256
`848a64ee2c1907e7faf99c779fb1c6e0c979c6e34673b2c4d273518fb2161b46`.
The current successor requires its own complete qualification.

| Complete R20 scope | Actual outcome |
| --- | --- |
| Core structure, source contract and metadata | PASS; all 26 composition commands completed naturally; three identical final metadata rounds |
| Source58 | All 58 ordered methods PASS, no skips; three independent Worker source readers agree |
| WorkerReport Native22 plus manifest Native2 | All 24 ordered methods PASS, no errors or skips; the fixture namespace collision is resolved |
| Mechanical runtime boundary | Fresh eleven-source compilation PASS_BUILD_ONLY; this is not GC or whole-native qualification |
| Bootstrap Native12 | All twelve methods completed: eleven PASS, one ERROR; the complete 15,830-case comparison retains one different case |
| Bootstrap Source6 | HOLD at the unchanged 1,800-second deadline plus three-second cleanup; four methods completed PASS, fifth full VM comparison incomplete, sixth not started |
| Current-source cold | HOLD at the original inner 180-second deadline; B1/B2/B3 are byte-identical, but full qualification did not finish |
| Complete cold DATA readback | Evidence integrity PASS, qualification HOLD; all 17 references and the full 38-phase inventory read, all retained files and explicitly sealed archive members consumed; incomplete phases remain incomplete |

Bootstrap's complete Native result contains 1,358,722 entries and the remaining
difference `generator_protocol.throw-instance.outer1`. Its original 150-event
prefix matches exactly, followed by two additional post-seal destructor events.
The R20 relay removes additional adapter traceback frames, but does not resolve
this lifetime difference. No unraisable exceptions were recorded.

The timed-out Source6 candidate started 1,051 cases and completed 1,050 of the
required 15,830, with 46,374 VM entries and the same one completed differing
case. Its candidate has no natural terminal receipt; no full-domain PASS is
inferred. The supervisor's recorded candidate cleanup completed, and a fresh
independent process scan found all seven recorded groups gone. The original
failure record and raw partial rows remain unchanged.

Earlier R19 Budget B4, Context15, Ordinary112, Journal21, installed Worker2 and
13-source provenance10928 results remain bound to R19; they are not current-tree
qualification. Remote R20 Native CI also recorded real route-report, v5 SQL
argument and private-resource failures. A CI cold-step success alone does not
replace complete source-and-raw-evidence admission of that distinct attempt.

The earlier Verification/Slot GC and four-real-function closure boundaries
remain unresolved. Mechanical C transport currently depends on CPython;
build success does not replace the Python object, exception or GC runtime.

## Current source successor

Three reviewed corrections address the actual R20 failures.

The worker-transport control now observes the existing UNKNOWN terminal return
and its real error identity, causal origin, retained custody, fencing, missing
ACK, empty stdout and actual diagnostic. Its ordinary foreign-error branch and
the full original methods remain unchanged. The new exact admission helper
accepts only the complete old source pair or the complete reviewed successor
pair, verifies full inverse source bytes, and rereads every consumed source.
Mixed pairs, unknown bytes, boolean aliases and terminal drift refuse. The two
original inventory fixtures and the complete production-composition domain
remain immutable.

The [17-route report codec](HIA_SLOT_MECHANICAL_DUAL_ROUTE.md) preserves bytes,
tuple/list/dict types, dictionary order and exact scalar types after the real
route and its original assertions complete. Its independent reader checks the
typed values against the original raw report pins. The actual empty-byte
witness remains `b''`. The complete original `run_case` body, all 17 route IDs,
60-second child limits and five-second cleanup/thread/fork controls remain.

The [v5 mechanical boundary](HIA_SLOT_MECHANICAL_V5.md) passes an existing tuple
as one object with `PyObject_CallMethod(..., "(O)", arg)`; it no longer expands
that tuple as the entire argument list. The original SQL identity guard and all
seven single-object call sites remain. Its admission fixture copies both real
HIA source resources into the private installed-layout package, verifies them
again, and leaves all 25 original controls and expected refusals unchanged.

The new pure-data checks have actually completed: exact admission30 (four
acceptances, 26 refusals) and trace codec41 (14 acceptances, 27 refusals), with
independent complete raw readback and unchanged input bytes. Their combined
readback SHA256 is
`783edaf5e320210bbf5aa803bc7d54c6ed45e7ca8b5d67b29911e70dcdb4e3ad`.
These checks do not replace any complete Source, Native, installed, finite,
resource or caller gate. Every affected executable and receipt must be rebuilt
against the current source, and current-tree product qualification is pending.

No ordinary entry is activated, no live provider is removed, and no original
case ID, observation field or budget is relaxed. Tracebacks and GC observations
remain part of the required equivalence.


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
| `hia_read` | Complete selected [Service Read control](HIA_SERVICE_READ_NATIVE.md); original filesystem/SQLite/codec providers, opaque object protocols and source-bound qualification remain |
| `hia_context` | Hosted schema/profile/buffer providers, clock/object protocols and persistence effects; selected freeze/lookup/deadline control now has the HIA owner above |
| `hia_inspect` | Complete explicitly selected Inspection graph; original program/query/lowering/Store providers and object/exception lifetime compatibility remain |
| `hia_candidate` | Complete explicitly selected Candidate graph; original import/edit/verification/Store providers and lifetime compatibility remain |
| `hia_verify` | Complete explicitly selected [nine-method Service Verification controller](HIA_SERVICE_VERIFICATION_NATIVE.md); Core/ABI/solver/Store/object providers and complete source-bound qualification remain |
| `hia_emit` | Selected HIA compile/emission control above; original Core emitter/compiler/linker, filesystem, Store/SQLite/clock/hash and opaque object providers remain |
| `hia_evaluate` | Original reference VM/native runner, clock/object protocols, integer-to-binary64 division and threshold comparison, plus SQLite/artifact effects; selected complete evaluation control and ledger policy now have the HIA owners above |
| `hia_adopt` | Complete explicitly selected Service Slot graph; verification claims, original ledger/transaction providers and the multi-SQL layer under separate qualification remain |
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

Original complete domains, IDs/order, poison, GC, traceback and exception fields remain required. The original cold deadline is 180 seconds plus three seconds cleanup; full retained regression retains 5,400 seconds and component gates retain 1,800 seconds. No normalized field or selected subset replaces a complete gate.

The [Service Read contract](HIA_SERVICE_READ_NATIVE.md) retains the complete 6,372-case finite domain and separate 86-case SQL domain; the detailed historical observations remain in Git history.

| Area | Existing owner that still requires complete replacement and real caller qualification |
| --- | --- |
| Ordinary CLI and build | `cli.hia_main`, remaining semantic action effects, `verify_program`, default emitter/build routing and complete diagnostics |
| Reference runtime | Complete VM, allocator, object transport, general backend behavior and default machine/plan implementation |
| Eleven-tool worker | `hia_agent_worker`, `HIAAgentService.call`, catalog/dispatch and backend admission |
| Durable state | `AgentStore` SQLite/WAL, atomic multi-table transactions, replay and unknown outcomes |
| Proof authority | The new nine-method controller requires its complete finite, lazy, resource, installed and caller qualifications; fresh Core verification and original Z3/Lean obligations remain separate |
| Native process ownership | Runner setup, environment/limits, snapshots, termination and complete report checking |
| Resident resources | Selection/CAS, actual invocation, libraries, sealed descriptors and confirmed cleanup of outstanding generations |
| Final cutover | Clean install/default startup, old context/request migration, worker restart/handoff, running-image readback and confirmed retirement |

The nine-method verification controller and the selected Service
constructor/close/profile/program, admission-I/O and mechanical-call-boundary
candidates remain subject to their complete qualification gates. Their presence is not complete native replacement or qualification;
original routes and actual foreign providers remain.
Complete caller, finite, resource, installation and matching-source cold gates
remain necessary; native proof leaves alone do not own these workflows.

The selfhost contract explicitly retains general Core checking, arbitrary
external symbols/relocations, a general linker and additional target gaps.
`whole_HIA_language_self_hosted=false` remains accurate. Its original fixed
points require B1=B2=B3; M1!=M2, M2=M3, M3!=B3; and reservation 64→80.
A bounded fixed point is not complete language or installed worker closure.

The package default remains `RELEASE_PIN=None`. The default-native candidate
admits only FULL_COST, and neither 50 registry entries nor an old administrator
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

The current tree retains active implementations, contracts, consumed original
fixtures and recovery ledgers. Numbered HIA units can belong to one composed
program. Native images and raw syscall, publication, descriptor and retirement
primitives already exist; the remaining work is the complete non-Python path
from public entry points through semantic and effect owners.

This index consolidates current state and removes repeated chronological
narratives. Its complete previous text remains at
[the exact R20 revision](https://github.com/TrillionniumFoundation/Hepta/blob/8c2c212d974e2b0d510164e6012e609997b76c4b/docs/CURRENT.md).
Failed observations and their original source identities are retained.

Earlier cleanup ledgers record their own deletions: 34 process documents with
206,342 original bytes, and a separate development scope of 1,045 files,
60 directories and 91,641,221 original bytes. These are historical totals,
not new deletions in this successor:

- [Development versions](../review-evidence/hia-native-cleanup-20261111/retired-development-versions.json).
- [Process documents](../review-evidence/hia-native-cleanup-20261111/retired-process-documents.json).
- [Historical bundles](../review-evidence/hia-native-cleanup-20261111/retired-historical-bundles.json).
- [Rewrite observations](../review-evidence/hia-native-cleanup-20261111/retired-rewrite-observations.json).

The 249 production Python modules, consumed original fixtures and live
qualification/process supervisors still have consumers. Their removal awaits
complete replacement, clean installation, default startup, durable-state
migration, real worker handoff and confirmed retirement.
