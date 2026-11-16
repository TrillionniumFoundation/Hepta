# HIA: current implementation and acceptance

HIA is the language; its canonical source suffix is lowercase `.hepta`.
**The source naming migration is complete. Whole-product native replacement is incomplete.**
The ordinary executable still enters `hepta.cli:hia_main`, the default release
pin is `None`, and `whole_native_delivery_qualified`,
`old_stack_can_be_removed` and `production_activated` remain false.

This is the current implementation index. Earlier complete source versions
and status narratives remain in Git history and [draft PR #897](https://github.com/TrillionniumFoundation/Hepta/pull/897).
A result belongs to the exact source snapshot on which it ran. New source,
a completed diagnostic, or a narrower observer does not inherit an older PASS.

## Source format and actual entry points

Physical `.hia`, `.hiaasm` and `.hia.json` source files have been migrated.
Assembly retains the `hia-asm.v1` protocol; paired structured projections use
`.core.hepta`. Language, command and protocol names retain their identities.
See the [source naming contract](HIA_SOURCE_SUFFIX.md).

The generated [rewrite inventory](HIA_NATIVE_REWRITE_INVENTORY.json),
[selfhost contract](HIA_SELFHOST_CORE_SUPPORT.json) and
[language coverage](HIA_SELFHOST_LANGUAGE_COVERAGE.json) contain the exact
current counts, classifications, identities and declared limits.
The R24 predecessor source snapshot had 2,839 indexed files, 210 HIA sources,
253 production Python modules, 1,526 total Python files, SOURCE_FILES 1,435
and the original 50 ordered native helper entries.
These are inventory counts, not a measure of replacement completeness.
Arithmetic and scalar profiles reuse the three existing transport modules;
they add no production Python module or worker helper.

| Public surface | Actual ownership and remaining dependency |
| --- | --- |
| Ordinary CLI | [All 15 actions](HIA_CLI_NATIVE.md#all-15-ordinary-actions) still enter Python; selected HIA control retains 42 declared foreign effects |
| Standalone native frontend | [Six bounded commands](HIA_AGENT_STDIO_NATIVE.md) use the HIA frontend/compiler and mechanical syscall/ABI transport; their scope is distinct from the ordinary CLI |
| Native source build and installation | HIA source-build, release and selection programs exist; initial construction, cold qualification and some package orchestration still use host tools |
| Worker | `hia_agent_worker` constructs `HIAAgentService` and dispatches eleven public tools; `hia_resource_read` is an alias |
| Reference VM | Ordinary `execute_program`, Prepared and Arithmetic remain hosted; explicit native integer profiles do not replace the complete VM |
| Durable state and evaluation | Store/SQLite/WAL, transactions, replay, UNKNOWN custody, clocks and foreign object providers remain |
| Final adoption | Complete same-source qualification, clean default installation, durable-state migration, worker handoff and confirmed retirement remain incomplete |

## Latest completed source-bound evidence

The current changes follow the actually frozen R24 tree
`49cc48d3d295052491ce4170759f004670d6d71c`.
Its complete 472,739-byte source freeze has SHA256
`d758ed4fc9ba30ad2ff7f1e313d1e182f55c02aed57f9975fa495e51d0e9b143`.
**These results belong to R24 and do not qualify this subsequent source change.**

| R24 gate | Actual completed result |
| --- | --- |
| Original Core: 151 selectors, 718 methods | All 718 ended: 716 OK, two FAIL; 1,872.648 seconds, natural exit 1, no cleanup intervention |
| Complete Source20 | All twenty PASS, including caller qualification's 152 controls, arithmetic Source3, emitter Source2 and explicit matched admission Source5 |
| Same-source cold | Original 180-second deadline exceeded; qualification HOLD, all observed owned processes reaped |
| Independent full cold DATA | Integrity PASS; seven of 38 phases sealed, 31 unsealed; the eighth checks finished but its incomplete archive remains incomplete |
| Div/rem and arithmetic construction | Both PASS_BUILD_ONLY using this attempt's actual, explicitly selected development compiler |
| Complete div/rem Native8 | All eight PASS, full 2,500 inputs, original/selected generic21, complete controls and real installed wheel |
| Complete arithmetic Native8 | All eight PASS, full 11,200 inputs, original/selected generic21, complete controls and real installed wheel |
| Separate full DATA readers | Complete value/trap/report domain PASS; raw traceback differences retained: 230 div/rem and 1,751 arithmetic |
| Matched descriptor DATA controls | All 24 groups and 114 variants completed: five actual positives and 109 expected refusals; DATA-only PASS, FD semantics different, whole admission HOLD |

R23's five Delivery source-admission failures passed in the complete R24 Core
run after exact qualifier successor proof. R24's two failures are different:
twenty declared sdist paths were absent from the strict support tuple, and
emitter output used a scanner-private narrowed writer at a dynamic offset.
This source synchronizes the support tuple and uses explicit ordered output
byte stores. Original test methods, dependency closures and limits remain.
Fresh complete qualification is required.

R24 Core readback: 239,762 bytes, SHA256
`beb09201ff2885b69160ff1b596b1965b7be49a7ffb1eec26f9fa1b1734a09c3`.
Terminal: 1,229 bytes, SHA256
`3c9b989f0372ab9f8a31a8559143c30479b79b5be265d6eb03614fab4d8e9709`.
All original method output and four owner/suite logs were read completely.

The original combined Source24 again reached its 1,800-second budget:
five methods ended, all five OK. The sixth method, Capture's full 5,101-input
independent-VM comparison, did not complete; eighteen later methods did not
start. The actual owner recorded timeout cleanup and all observed groups were
reaped. Root elapsed time was 1,804.579 seconds. Its 10,776-byte readback has
SHA256 `7f0c3a64c695c4c60abc0fefc1f98fb6a53c3fadd537f64f4be7d6c10906816e`;
the original source, partial evidence and failure remain unchanged.

R24 B1, B2 and B3 were actually regenerated and read in full: all are
675,046 bytes, SHA256
`25d79bbe8bed4bdfbc07d6d8c4739914394bd1666bd28ec58aeeceeca10155c5`.
Their full source and execution receipts support explicit development
construction, not completed cold qualification.

The independent cold reader consumed all seventeen reference envelopes,
retained raw evidence and all sealed archives. Its 46,069-byte report has SHA256
`a9d5854ce0b6a996d7c747329eecc37dd12fafcb727acc2bdb3c3fe8967f570b`.
The complete 16,076,971-byte consumption ledger has SHA256
`818d782a68b8f902f7b5b4a3a545c73f87e1874cea33c0a83b289c50e74d8efb`.
The reader naturally exited 1 because cold qualification remains incomplete.

Earlier attempts and their exact receipts remain in Git history and the
[review record](https://github.com/TrillionniumFoundation/Hepta/pull/897).
R23's published predecessor is
[`8175a64221a43e02c6b56044b2d5cb489fe4cf00`](https://github.com/TrillionniumFoundation/Hepta/commit/8175a64221a43e02c6b56044b2d5cb489fe4cf00),
tree `bdf4c1cbd17464839c46559d49b7640d2e86c010`.
Its five Core failures, incomplete Source24, cold timeout and raw resource
differences retain their original results.

### Preserved lifetime, traceback and resource failures

R22's original Slot v5 Native4 timed out at 1,800 seconds with no complete
method terminal. Two complete originals agree in the 248-case and 7,574-case
domains. Native completed all 248 base cases with two handler differences;
the derived lane stopped 3,540 of 7,574 cases with 147 handler differences.
All handler differences concern actual `alive_at_seal` or `events`.
Raw traceback and post-seal differences remain verbatim, and the missing
4,034 derived terminals remain missing. Public84/handled12, complete admission
and installed use were not supplied by that incomplete gate.

R22's complete Evaluation10 had nine PASS and one FAIL. The additional
complete diagnostic retained the original 3,000ms total and 1,000ms native
budgets and observed `planned_workload_complete=false` with
`outcome=budget_exceeded`. Neither native run started. The extra diagnostic
frames and post-return reads do not qualify the original method.

Definition controls recorded an actual public reflection counterexample:
selected function type, repeated lookup identity, globals, closure,
annotations and class lookup differ. The control successfully recording
that counterexample does not establish transparency.
Earlier Bootstrap, Discovery, Verification and Capture GC/traceback failures,
incomplete domains and budget failures remain in their original evidence.
No exception field, raw traceback, locals, object identity, destructor or
resource event is normalized.

## Latest R25 source validation and corrective successor

The first R25 snapshot actually completed all 26 Source methods in their
original order: 26 OK, no skips, natural exit, 43.449 seconds. This included
the complete new scalar Source3 (19,118 transport inputs and 600 independent
VM witnesses) and executable-release Source3, alongside all earlier Source20.
Its 13,400-byte readback has SHA256
`0b8d925e1dcdefc2805739ecd3bb4bf044270c99163b4e4c2bcc09c0ad6b67ad`.
The full source remained stable and all observed groups ended naturally.

Actual double generation also exposed 8,230 operations in the first R25
compiler, above the original 8,192-operation bound. That graph is not accepted
for selfhosting. This successor removes the unrolled eight-store branch;
eight-byte output reuses the existing ordered loop, while four-byte output,
phase/capacity decisions and short-capacity prefix/exception behavior remain.
The original operation bound and original tests are unchanged. Fresh complete
generation, Source, Core, cold and Native/DATA qualification are required on
this corrected snapshot; the preceding 26-method PASS is not transferred.

## Current implementation changes and required validation

### Explicit native integer profiles

[Checked division and remainder](HIA_VM_INTEGER_DIVREM.md) are implemented in
`vm_integer_divrem.hepta` for ten integer types. HIA owns zero-divisor,
signed-minimum overflow, truncation and remainder decisions.
The host modules provide typed request/receipt transport and explicit
integration; they do not supply a Python quotient/remainder fallback.

The independent [eight-operation arithmetic profile](HIA_VM_INTEGER_ARITHMETIC.md)
adds checked and wrapping add, subtract and multiply in
`vm_integer_arithmetic.hepta`. It has a separate closed schema, source/image
identity and explicit factory. The complete original 2,500 inputs remain the
ordered prefix of its 11,200-input domain. Three Source and eight Native
methods include 320 typed HIA VM witnesses, complete original/selected
generic21, 144 resource/tick/depth observations and twelve installed inputs.

The explicit [fifteen-operation scalar profile](HIA_VM_INTEGER_SCALAR.md)
adds shifts, bitwise operations, negation and complement. Its complete
19,118-input plan retains the original 11,200-input prefix. Source3 and Native8
include 600 typed VM witnesses, 270 resource/tick/depth observations and
25 installed inputs, retaining the older ordered prefixes.
These are required full gates, not claimed results.

All three profiles retain nonzero invocation identity, exact operand and result
echoes, canaries, checksums, complete NativeCall custody and terminal ACK.
Fresh complete manifest/image/component bytes are required before and after
delivery. The original div/rem HIA, old two-operation factory and ordinary
VM remain available. Since their shared host modules change, all three component
images and manifests must be rebuilt on this source snapshot.
Neither a new profile nor a shared-host change inherits earlier qualification.

### HIA compiler and Capture source successors

The compiler generator and its HIA source use explicit ordered byte stores
for four-byte output after the original phase/capacity checks. Eight-byte
output uses the existing ordered loop inside the same complete-capacity guard.
Scanner-private state helpers retain literal offsets; the original emitter
test dependency closure gains no new helper.
Other compiler functions, helper targets, original failure paths and the
8,192-operation/128-function/1,536-block limits remain.
The reviewed textual candidate must match two actual complete generator runs.
Changed tick, call, allocation and exceptional histories remain observable.

Capture's `valid_state` reuses eleven complete words already read in the
same read-only validation call. The fifteen rotate/XOR folds keep the original
checksum order; previously unread words 3, 6, 7 and 8 remain first read at their
original fold positions. Early rejection order, the later port/resume checks,
all 73 business ports, public checksum/seal helpers and host providers remain.
Nothing is cached across entries or effect boundaries. Allocation, GC,
exceptional and VM-budget observations still require actual qualification.
The generated HIA successor must be produced twice from the actual generator,
frozen, freshly built and tested at the original limits. This is not a
measured performance claim or a waiver of the incomplete Source24 gate.

### Explicit matched descriptor observer

The legacy same-process original8→candidate8 observer and its strict reader
remain available as `legacy-v1`; its failure remains recorded.
The declared `matched-v2` successor uses three fresh complete lanes:
original A, original B, then candidate, with identical private inputs and
inherited descriptors. It observes actual starting descriptor/runtime facts
and refuses a mismatch; it does not renumber descriptors, close unknown
descriptors or normalize exception filenames.

The full original eight calls remain ordered within each lane. No descriptor
observation is inserted between calls. Complete ordinary observations from
both originals and the candidate must agree. Actual end-of-sequence
descriptor facts retain the separate resource difference.
The only positive status is `PASS_MATCHED_FINITE_OBSERVER`;
`whole_admission_qualification=HOLD` and
`all_input_equivalence=false` remain explicit.
The single original total budget and cleanup allowance are unchanged.
Its declared Source method successor is not retroactive qualification of
the old Source5 or Source24 attempt.

The matched reader passes its one captured raw snapshot to every child
validator and retains terminal rereads. This fixes the reviewed aggregate-A/
child-B binding defect; the earlier reader candidate remains rejected. The
legacy-v1 default checks and limits are retained, with the shared reader
signature/read-expression change explicitly declared. R24's complete matched evidence and all 24 groups / 114 data variants were
actually consumed and finally reread. Its 286,557-byte owner report has SHA256
`8d468a022756933f7541957566273e238912ec6cc604c14885b0b3aff408fb21`.
The supervised owner read and finally reread all 1,237 raw output artifacts.
This finite DATA validation does not qualify resource transparency or the
complete Native admission gate.

### Native source-to-installed-executable path

The [explicit executable release builder](HIA_EXEC_RELEASE_NATIVE.md) uses one
native process to verify source identity, invoke the embedded HIA
frontend/compiler, check the complete ET_EXEC image, hash and package the
original source and executable as HIAREL01. The existing native installer
installs and verifies that package against an independently supplied digest.
Executing the installed program is a separate explicit action.

HIA owns argument/source policy, I/O progress, compiler sequencing, image
checks, package layout, modes, SHA and receipts. Fixed assembly implements
the buffer ABI and mechanical syscalls. The builder executable does not spawn
Python or a compiler process. Hosted bootstrap/qualification tools remain
outside it; formal matching-cold construction and explicit development
construction are separate choices.

Both new HIA graphs require actual double generation and complete byte
equality. Complete Source3, Native5, all 44 owned commands, nine original
compile/pack API invocations, twelve installed executable runs and a separate
full DATA reader are required. The reader binds full commands, current source
inventory, fourteen ordered inputs, eleven independently derived refusals,
exact executable paths and owner/request/source identity. Static review is
not runtime qualification.

The full admitted source release supplies the bootstrap closure. The existing
Python sdist/wheel are not complete cold build environments. This source
preserves eleven new sdist inputs, repairs twenty pre-existing support
declarations and separately registers scalar resources. Ordinary CLI and
worker selection retain their actual current ownership.

## HIA ownership and retained providers

| HIA-owned control | Still required boundary |
| --- | --- |
| [Compile/emission](HIA_EMISSION_NATIVE.md), [artifact/build admission](HIA_NATIVE_BUILD_ADMISSION.md) | General Core verification, linker/relocation support, object protocols, filesystem and Store effects |
| [Store profile](HIA_STORE_ARTIFACT_PROFILE_NATIVE.md), [lifecycle](HIA_STORE_LIFECYCLE_NATIVE.md), [transactions](HIA_STORE_TRANSACTION_NATIVE.md) | SQLite/JSON/hash providers, generators, exceptions and foreign object semantics |
| [Evaluation](HIA_EVALUATION_NATIVE.md), [cost ledger](HIA_COST_LEDGER_NATIVE.md), [context](HIA_SERVICE_CONTEXT_NATIVE.md) | Reference/native execution, clocks, schemas, complete reports and durable state |
| [Service read](HIA_SERVICE_READ_NATIVE.md), [inspection](HIA_SERVICE_INSPECTION_OWNER.md), [lease](HIA_SERVICE_LEASE_OWNER.md) | Filesystem/capture, runner, Store, imports and object providers |
| [Discovery](HIA_SERVICE_DISCOVERY_NATIVE.md), [verification](HIA_SERVICE_VERIFICATION_NATIVE.md), [bootstrap](HIA_SERVICE_BOOTSTRAP_NATIVE.md) | Original schemas, import/Core/solver providers and lifetime qualification |
| [Byte memory](HIA_BOUNDED_MEMORY_NATIVE.md), [SHA stream](HIA_SHA256_STREAM_NATIVE.md) | Buffer/allocator/GIL transport and foreign-object lifetime |
| [Artifact delivery](HIA_ARTIFACT_DELIVERY.md), [retention](hia-generation-retention-native.md) | Actual selection/CAS/invocation, descriptors, process ownership and confirmed retirement |

Selected HIA control does not own its listed foreign providers.
A standalone native executable is a distinct declared surface; it does not
automatically replace the ordinary CLI, worker or resource-reporting VM.

## Final acceptance and cleanup

Final acceptance requires one actual current source snapshot to pass generation,
matching-source cold, complete retained regression, original finite/resource/
caller scopes, clean installed use, default startup, durable-state migration,
real worker handoff and confirmed retirement.
The original cold deadline is 180 seconds plus three seconds cleanup;
retained regression keeps 5,400 seconds and complete component gates
keep 1,800 seconds. Prefixes, static reviews and narrower observers are not
complete gates.

The selfhost contract still records general Core checking, arbitrary external
symbols/relocations, general linker and additional target gaps.
`whole_HIA_language_self_hosted=false` remains accurate.
Its fixed-point conditions remain B1=B2=B3; M1!=M2, M2=M3, M3!=B3;
and reservation 64→80. The [bounded selfhost build](HIA_PROGRAM_SELFHOST_BUILD.md)
does not admit a Python-emitter fallback within its declared profile.

The tracked repository keeps this current index, active implementations,
consumed original fixtures, contracts and recovery ledgers. Numbered HIA
units can compose one current program and are not removed solely by name.
Build outputs and isolated development attempts stay outside the product tree.
Previous versions remain recoverable through Git history.

Historical cleanup ledgers record their own completed retirements:

- [Development versions](../review-evidence/hia-native-cleanup-20261111/retired-development-versions.json).
- [Process documents](../review-evidence/hia-native-cleanup-20261111/retired-process-documents.json).
- [Historical bundles](../review-evidence/hia-native-cleanup-20261111/retired-historical-bundles.json).
- [Rewrite observations](../review-evidence/hia-native-cleanup-20261111/retired-rewrite-observations.json).

R23 additionally retired one dated macro-campaign narrative after a complete
consumer scan found only its regenerated inventory reference. Its exact
2,727-byte original, SHA256
`51bf9733474de26913ff32725adaf9f7ed66f4f8888f9dbb03d7a5fa9cf633df`,
remains in
[the prior Git tree](https://github.com/TrillionniumFoundation/Hepta/blob/2f816a710e617aed43c09265eb8fadd4a4f5037d/docs/HIA_AGENT_MACRO_CAMPAIGN_RESULTS_20261107.md).
Six additional dated October process notes were retired after exact full
before-byte and complete source-consumer checks. They covered old tool/startup
identity, executed-test identity, receipt publication, token admission and clone
completion work. Their current implementations and original tests remain;
none was a required source, package resource or oracle. The generic Markdown
checker did read these files when present; retirement is not described as a
zero-reader claim. Full prior bytes remain recoverable in Git history.

Active production Python modules and supervisors still have consumers.
Their removal requires verified replacement and actual adoption.
