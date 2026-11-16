# HIA: current implementation and acceptance

HIA is the language; its canonical source suffix is lowercase `.hepta`.
**Source naming migration is complete. Whole-product native replacement remains incomplete.**
The ordinary executable still enters `hepta.cli:hia_main`, and the default
release pin is `None`. The current values remain
`whole_native_delivery_qualified=false`, `old_stack_can_be_removed=false`
and `production_activated=false`.

This index describes the active implementation, the actual evidence and the
remaining acceptance boundaries. Earlier complete versions remain in Git
history and [draft PR #897](https://github.com/TrillionniumFoundation/Hepta/pull/897).
An earlier result does not qualify a changed source snapshot.

## Inventory and entry points

The generated inventory records the exact current HIA source count and format
split. The completed R22 predecessor contained 208 sources, and the new explicit
VM div/rem controller adds one assembly source. Physical `.hia`, `.hiaasm` and
`.hia.json` sources have been migrated.
Assembly retains its `hia-asm.v1` identity; paired structured projections use
`.core.hepta`. Commands and protocol schemas retain their original identities.
The [source naming contract](HIA_SOURCE_SUFFIX.md) covers their consumers.

The completed R22 predecessor retained **250 production Python modules**.
The explicit div/rem slice adds three host transport/integration modules; these
are remaining dependencies and are counted in the generated inventory.
The capture adapter is also an explicit remaining host boundary.
The **50 native helper entries** retain their exact original order; capture is
a separately selected component, not an implicit worker-capsule extension.
These counts measure inventory, not replacement completeness.

The generated [rewrite inventory](HIA_NATIVE_REWRITE_INVENTORY.json),
[selfhost contract](HIA_SELFHOST_CORE_SUPPORT.json), and
[language coverage](HIA_SELFHOST_LANGUAGE_COVERAGE.json) contain the complete
indexed counts, module classifications, source identities and declared limits.

| Public surface | Current ownership and remaining dependency |
| --- | --- |
| Ordinary CLI | [All 15 actions](HIA_CLI_NATIVE.md#all-15-ordinary-actions) still enter the Python CLI; selected control has 42 declared foreign effects |
| Worker | `hia_agent_worker` constructs `HIAAgentService` and dispatches eleven public tools; `hia_resource_read` is an alias |
| Standalone native stdio | [Six bounded commands](HIA_AGENT_STDIO_NATIVE.md), a distinct protocol and scope |
| Build and emit | The bounded native selfhost build exists; ordinary build and `hia_emit` still retain the Python emitter |
| Evaluate | Selected evaluation control exists; original reference VM/native runner, object/time and Store providers remain |
| Durable state | Store/SQLite/WAL, multi-table transactions, replay and UNKNOWN custody still require their real foreign providers |
| Final adoption | Clean installation, default startup, durable-state migration, worker handoff and confirmed retirement remain incomplete |

## Completed source-bound evidence

The latest completed broad attempt recorded here is R22, exact index tree
`e6090c22b778a63aed4f6576c82908ba87a0ecd7`. It had 2,813 indexed
files, 208 HIA sources, 250 production Python modules, SOURCE_FILES 1,411
and the original 50 ordered helper entries. Its complete source freeze is
468,492 bytes, SHA256
`fd6ef8780d42f8d488207363c25ef3937fe4eb67d8b251394eab031b8b28e888`.
**These results qualify only their original scopes on that tree. They do not
qualify the subsequent source changes described below.**

| Complete R22 gate | Actual result |
| --- | --- |
| Original Core: 151 selectors, 718 methods | 713 OK, five ERROR; every original method completed |
| Source14 | All 14 PASS |
| Source58 and its three original independent readers | All 58 PASS; reader domains 40, 15 and 13 complete |
| Source10 successors | All ten PASS |
| Mechanical extension build | PASS_BUILD_ONLY |
| Dual-route Native1 | All 17 actual route controls PASS |
| Original v5 Native4 | Original 1,800-second timeout; zero complete method terminals |
| Delivery Native23 | All 23 PASS, including the actual installed Store/worker paths |
| Evaluation10 | Nine PASS, one FAIL; all ten original methods completed |
| Capture build | PASS_BUILD_ONLY; original compiler profile limits unchanged |
| Capture Native5 | All five PASS, including the complete 218 structured observations and installed package |
| Capture Receipt Native4 | All four PASS; all 72 controls and three valid extents covered |
| Definition Native1 | All 23 controls started and stopped; 20 completed and three dependency HOLDs; the gate failed |
| Current-source cold | Original 180-second timeout; incomplete qualification |

Core's five errors consist of one retained-Git missing-blob metadata error
classification and four exact caller-source admission refusals. The two earlier
inventory errors did not recur. The caller successors below address the exact
changed test sources; they do not exempt production files from admission.

### Cold readback and development compiler

The independent complete cold DATA reader reports evidence integrity PASS and
no reader errors, while qualification remains HOLD: eight of 38 phases completed
and 30 remain incomplete. All 17 actual references, their raw outputs and eight
sealed archives were consumed. Its report is 47,114 bytes, SHA256
`04bb4f677a24d12b221ac5e5676abf794ce249acce4390716579b1f056263332`.
The complete consumption ledger is 16,119,460 bytes, SHA256
`d77c37d4437043a15721772032901ef52ae9413a8a0829c0af647de3f7f17e5b`.

Actual B1, B2 and B3 agree at 673,413 bytes, SHA256
`bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`.
Their native returns and input receipts support explicitly marked development
component construction. They do not establish the complete matching-source
cold result. Scalar-casts had actually started when the original deadline
expired; its missing terminal is not filled in from another run.

### Slot lifetime and reflection

A complete independent DATA readback consumed all six retained lanes, the full
source freeze, ordered progress, handler observations and raw exceptions.
The two complete originals match in both the 248-case and 7,574-case domains.
The native base completed 248 cases: 246 exact handler matches and two
differences. The derived native lane started 3,541 and stopped 3,540 cases:
3,393 matches, 147 differences and 4,034 cases not completed.

Every retained handler difference was fully read and lies in
`alive_at_seal` or `events`; object lifetime and destructor timing remain
observable. The base has 176 raw traceback differences and 434 post-seal
difference entries. The recorded derived prefix has 3,379 raw traceback
differences. No GC, traceback, exception, object identity or locals are
normalized. Missing derived terminal, controller and final source receipts
remain missing. All nine observed process groups were independently confirmed
absent after the original timeout and cleanup.

The DATA report is 2,183,774 bytes, SHA256
`838d8ec644d31286dd5d914ca007138c2a3dfb590a57729864589b226454a9f5`.
Its evidence integrity is PASS, its qualification status is HOLD and its
actual exit is 1. Recording a prefix does not qualify the complete Native4
class; public84/handled12, complete admission and the installed method were
not reached.

The 23 definition controls all have actual starts and stops. DEF-15, DEF-16
and DEF-20 refuse the actual HOLD Native4 dependency. DEF-14 records an actual
public reflection counterexample: selected function type and repeated lookup
identity, globals, closure, annotations and class lookup do not match.
`public_reflection_closed=false`. A control that successfully records this
counterexample is not a proof of public transparency.

### Evaluation budget diagnosis

The uninstrumented complete Evaluation10 attempt remains nine PASS and one
FAIL. Its installed-worker method passes; the six-owner public evaluation
method fails a completion assertion. An additional full ten-method diagnostic
also has nine PASS and one FAIL, with the original input, order, assertions,
3,000ms total budget and 1,000ms native budget unchanged.

Only after the public evaluation returned, a diagnostic wrapper captured the
actual result and three Store artifacts before the original assertion. It
adds wrapper frames and post-return reads and cannot qualify the original
suite. Actual `report_complete` and `termination_confirmed` are true;
`planned_workload_complete` is false with `outcome=budget_exceeded`.
The baseline reference completed in 364,416,454ns. The candidate reference
was terminated with return -9 after 63,276,028ns. Neither native run started.
The prior context-tool cost was 1,986,050,801ns and the evaluation ledger
recorded 580,463,006ns through report construction.

The captured result is 23,244 bytes, SHA256
`512133f262978ce7834130ac0274600b35417f8c5f128615d3fb2ae877c850de`.
This locates the observed failure in the budget path; it does not justify
raising a limit or declaring an unexplained intermittent failure harmless.

### Historical boundaries remain

R21's actual remote Core, inspection and native-job failures remain attached
to their original source. Earlier Bootstrap Native12 completed with eleven
PASS and one ERROR, retaining the case-209 destructor difference over its full
15,830-case domain. Bootstrap Source6 timed out with four methods complete and
its fifth incomplete. Discovery and verification retain actual GC differences,
including differences on their unselected routes.

Capture's earlier complete structured 218-row comparison did not consume raw
tracebacks. A later full DATA comparison found 198 candidate raw traceback
records different. It preserves those differences and cannot retroactively
supply missing pre-candidate raw authority. R22's structured and native
component passes do not prove arbitrary traceback, locals or lifetime
equivalence.

The full attempts, original failures and complete readback references are
retained outside the product tree and summarized in
[draft PR #897](https://github.com/TrillionniumFoundation/Hepta/pull/897).
The original domains and deadlines are still mandatory.

## Current changes

### Executable capture

The [new capture controller](HIA_EXECUTABLE_CAPTURE.md) owns its declared branch,
loop, retry, audit/signal dispatch, seal/readback and cleanup decisions.
Seven fixed raw Linux syscall operations supply the kernel effects.
Before confirmation, the adapter binds the action to the exact current request,
accepted workspace, sequence, kind, descriptor transition and error handle.
A known-error terminal must carry the actual handled exception.

Before any buffer write, admission checks the actual ctypes allocations,
header/payload/canary extents, seven action operands, PREAD's extra byte and
destination capacity. Missing or inconsistent receipts retain UNKNOWN custody
and refuse replay. The explicit CPython 3.14.10 GIL/Linux x86-64/LP64 profile
does not widen package or platform claims. Ordinary `_sealed_executable`
still retains its existing route.

### Slot fixed words and definition ownership

Only the three fixed eight-byte Slot word helpers change. The original
parameter-forwarding loop entry remains, followed by one iteration containing
all eight ordered byte operations. The complete supplemental observations
preserve first argument errors, partial stores, wrapping and loan refusals.
This reduces loop control; it does not claim equivalence for arbitrary smaller
tick limits or a measured whole-gate time improvement.

Each class descriptor owns one internal mechanical function definition, using
the real original global namespace and declared defaults. Each selected lookup
still creates a fresh captured owner and C method. Every invocation retains
admission and session checks. Complete source/receipt/executable/export reads
are not cached away. Independent review verified all six exact splices and full
inverse restoration of the original source pair.

The public C method still differs from a Python function and does not supply
the original repeated-lookup `__func__` identity. Reflection, mutation,
fork/scope behavior and full GC/traceback/lifetime observations remain open
until their complete gates pass. The actual two base and 147 recorded derived handler differences are not
closed by changing internal definition ownership alone. See the
[v5 executable custody contract](HIA_SLOT_MECHANICAL_V5.md).

### Installed terminal and inventory contracts

Store and Evaluation controls have explicit versioned UNKNOWN successors:
strict exit 2, empty stdout, actual diagnostic and causal error identities,
one close attempt, retained loss/custody, and original replay/poison/source drift.
Original method IDs, requests and budgets remain. Added observation frames are
not proof of GC or traceback neutrality. Releasing an observer's own duplicate
arguments does not remove original frames or original locals.

Resource-inventory successors retain exact sets and exact installed bytes.
Mechanical wheel package data and separately selected capture data are distinct
from sdist-only support files. The release contract includes non-Python
`hepta/` resources such as the mechanical C source while separately accounting
for automatically collected Python modules. Wildcards and subset checks do not
replace complete source admission.

### Explicit integer div/rem execution

The new `vm_integer_divrem.hepta` owns checked division and remainder decisions
for i8/u8/i16/u16/i32/u32/i64/u64/isize/usize. It checks division by zero before
signed-minimum divided by minus one, and computes signed truncation and remainder
in HIA. The host protocol encodes exact typed operands and decodes complete
receipts; it has no Python quotient/remainder fallback.

The 64-byte request and 96-byte reply bind a nonzero invocation nonce, operation,
width, signedness, both operands, status, value, checksum and completion marker.
The actual loader admits an explicitly supplied manifest digest, all 13 component
inputs and the image. Complete source, manifest and image bytes are re-read
before and after native delivery. Private buffer canaries, original delivery
custody and terminal acknowledgement remain required.

`NativeDivRemExecutor` is an explicit experimental entry. It derives only the
division/remainder branch from the byte-pinned original interpreter and checks
live code, closures, builtins and construction ownership. The original
`hia_program_runtime.py`, Prepared, Arithmetic and default `execute_program`
remain unchanged. Other opcodes, resource transitions, validation and report
construction remain hosted. Compilation, the 2,500-case original-first
comparison, independent readback and complete installed controls must bind
the actual final source. Extra construction/validation frames and host
allocation/GC observations do not establish all-input VM equivalence.

### Source admission and first-use dependencies

The retained-Git successor distinguishes an actual nonzero Git command from
malformed metadata, size limits, deadlines and payload errors. Only the former
becomes a missing-object metadata refusal; the complete original denominator
is preserved and no implicit fetch is introduced.

Five caller qualifiers and the independent file-capture caller reader admit
only the exact declared Transport, Delivery and Evaluation test successors.
They replay fixed forward/inverse byte changes, retain full source sets,
original helpers and final rereads, and add explicit refusal/drift controls.
Production-source exceptions, wildcard hashes and acceptance of arbitrary
exit 1-or-2 are not introduced.

The admission I/O correction restores the observed directory
`IsADirectoryError` before the unchanged regular-file check and keeps the
original single close. Two FFI boundary files defer real ctypes initialization,
fixed ABI classes and the five actual emission protocol objects until they
are needed. Emission/lifecycle and the original fixed 13-source guard remain
unchanged. No failed import, admission result or user object is cached as a
successful binding. First-use imports, reflection, exceptions, allocation and
concurrent/fork behavior remain visible qualification obligations; no prewarming
is added to the original controls.

## HIA ownership and retained providers

The linked contracts retain complete original domains and source-bound evidence.

| HIA-owned control | Retained boundary |
| --- | --- |
| [Compile/emission](HIA_EMISSION_NATIVE.md), [artifact/build admission](HIA_NATIVE_BUILD_ADMISSION.md) | Core verifier/compiler/linker, object protocols, filesystem, Store/SQLite/clock/hash effects |
| [Store artifact/profile](HIA_STORE_ARTIFACT_PROFILE_NATIVE.md), [lifecycle](HIA_STORE_LIFECYCLE_NATIVE.md), [transaction](HIA_STORE_TRANSACTION_NATIVE.md) | Filesystem/SQLite/JSON and hash providers, Python generator/exception/object semantics |
| [Evaluation](HIA_EVALUATION_NATIVE.md), [cost ledger](HIA_COST_LEDGER_NATIVE.md), [context](HIA_SERVICE_CONTEXT_NATIVE.md) | Reference/native execution, clocks, schemas, opaque object protocols and durable state |
| [Static resources](HIA_STATIC_BUDGET_NATIVE.md), [patch impact](HIA_PATCH_IMPACT_NATIVE.md) | Fresh Core/patch verification, independent heap analysis, proof authority and canonical reports |
| [Service artifact](HIA_SERVICE_ARTIFACT_NATIVE.md), [Read](HIA_SERVICE_READ_NATIVE.md), [Inspection](HIA_SERVICE_INSPECTION_OWNER.md), [Lease](HIA_SERVICE_LEASE_OWNER.md) | Actual filesystem, capture, runner, Store/SQLite, imports and object providers |
| [Discovery](HIA_SERVICE_DISCOVERY_NATIVE.md), [Verification](HIA_SERVICE_VERIFICATION_NATIVE.md), [Bootstrap](HIA_SERVICE_BOOTSTRAP_NATIVE.md) | Original schema/import/Core/solver/object providers and full lifetime qualification |
| [CLI discovery](HIA_CLI_DISCOVERY_JSON.md), [Core diagnostics](HIA_CORE_ADMISSION_NATIVE.md) | Ordinary entry/I/O, selected loader, strict Core admission and original exception types |
| [Artifact delivery](HIA_ARTIFACT_DELIVERY.md), [retention](hia-generation-retention-native.md) | Process/descriptor transport, actual selection/CAS/invocation, confirmed retirement and foreign cleanup |
| [Byte memory](HIA_BOUNDED_MEMORY_NATIVE.md), [SHA stream](HIA_SHA256_STREAM_NATIVE.md) | Buffer export/allocator/GIL and foreign-object lifetime |
| [Full cost](HIA_FULL_COST_NATIVE.md), [execution budget](HIA_EXECUTION_BUDGET_NATIVE.md), [journal](HIA_AGENT_JOURNAL_NATIVE.md) | Actual clocks, observations, locks, cancellation, SQLite and request dispatch |

A selected controller does not own its listed providers. Existing native proof
leaves, images and bounded components do not constitute the complete path from
ordinary public entry through semantic owners and physical effects.

## Remaining acceptance

Complete original domains, IDs/order, poison, GC, traceback and exception
observations remain required. The original cold deadline is 180 seconds plus
three seconds cleanup; retained regression retains 5,400 seconds; complete
component gates retain 1,800 seconds. Passing prefixes are not full gates.

The selfhost contract still retains general Core checking, arbitrary external
symbols/relocations, general linker and additional target gaps.
`whole_HIA_language_self_hosted=false` remains accurate. Its fixed-point
conditions remain B1=B2=B3; M1!=M2, M2=M3, M3!=B3; and reservation 64→80.
A bounded compiler fixed point does not establish the whole language or worker.

The [bounded selfhost object build](HIA_PROGRAM_SELFHOST_BUILD.md) consumes
pinned native compiler bytes without a Python-emitter fallback within its
declared Linux x86-64 profile. The default-native candidate admits only FULL_COST.
Neither the registry count nor a historical administrator bundle is widened
into a complete native worker.

Final acceptance requires one actual current source snapshot to pass generation,
matching-source cold, complete retained regression, original finite/resource/
caller scopes, clean installed use, default startup, durable-state migration,
real worker handoff and confirmed retirement. Missing/failed scopes remain HOLD.

## Repository cleanup

This single current index replaces repeated status narratives; previous full
text remains in Git history. Active implementations, consumed original fixtures,
contracts and recovery ledgers remain. Numbered HIA units may compose one
program and are not deleted solely for their names. Temporary build products
and isolated development attempts stay outside the tracked product tree.

Earlier ledgers recorded 34 process documents (206,342 bytes) and, separately,
1,045 development files, 60 directories and 91,641,221 bytes. These are historical
totals, not new deletion claims:

- [Development versions](../review-evidence/hia-native-cleanup-20261111/retired-development-versions.json).
- [Process documents](../review-evidence/hia-native-cleanup-20261111/retired-process-documents.json).
- [Historical bundles](../review-evidence/hia-native-cleanup-20261111/retired-historical-bundles.json).
- [Rewrite observations](../review-evidence/hia-native-cleanup-20261111/retired-rewrite-observations.json).

Production Python modules and active supervisors still have consumers. Their
removal awaits verified replacement and actual adoption.

One additional dated macro-campaign report is retired by the current source
cleanup after its only generated inventory reference is regenerated. Its exact
2,727 bytes (SHA256
`51bf9733474de26913ff32725adaf9f7ed66f4f8888f9dbb03d7a5fa9cf633df`)
remain available in the
[R21 Git history](https://github.com/TrillionniumFoundation/Hepta/blob/2f816a710e617aed43c09265eb8fadd4a4f5037d/docs/HIA_AGENT_MACRO_CAMPAIGN_RESULTS_20261107.md).
This narrative retirement does not remove a runtime owner or original oracle.
