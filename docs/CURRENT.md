# HIA: current implementation and acceptance

HIA uses lowercase `.hepta` source files. **The source naming migration is
complete; whole-product native implementation and qualification remain incomplete.**
The ordinary command enters `hepta.cli:hia_main`, the default release pin is
`None`, and `whole_native_delivery_qualified`, `old_stack_can_be_removed`
and `production_activated` remain false.

This is the single current-state entry. Component contracts describe their
interfaces; the [source inventory](HIA_NATIVE_REWRITE_INVENTORY.json),
[selfhost contract](HIA_SELFHOST_CORE_SUPPORT.json) and
[language coverage](HIA_SELFHOST_LANGUAGE_COVERAGE.json) identify the actual
inputs and supported domains. Execution results must identify the complete
source tree on which they ran.

## Unified source and qualification status

The current candidate combines the native product continuation and the newer
verified-kernel work:

| Input | Exact identity | Integrated work |
| --- | --- | --- |
| Native product continuation | Frozen R29 tree `caa44fe5f5647eb24aac9d1daf724bf5fa6c2d53`, following [published `192be0c`](https://github.com/TrillionniumFoundation/Hepta/commit/192be0c277a6971dc956326372fe4e48a007ae26) in [PR #897](https://github.com/TrillionniumFoundation/Hepta/pull/897) | HIA component owners, native release construction, cold transport and original product callers |
| Verified-kernel continuation | [`e9de97c`](https://github.com/TrillionniumFoundation/Hepta/commit/e9de97cee2a44cfbe044b245f2cf344c2cc3ef47), [PR #914](https://github.com/TrillionniumFoundation/Hepta/pull/914) | Register kernels, SSE2/AVX2/AVX-512 validation, CPU admission, immutable loading and ordinary shared-library builds |
| Word-memory continuation | [`d998554`](https://github.com/TrillionniumFoundation/Hepta/commit/d99855451c8140899c85cf264b330a81a1c00362), [PR #903](https://github.com/TrillionniumFoundation/Hepta/pull/903) | Explicit v9 u64 word memory, matching compiler/frontend/resource profiles, preserved v8 semantics and cross-backend controls |

The integration also corrects concrete source and execution defects:

- Include the actual `review-evidence/hia-native-rewrite-20261111/workflow_process.py`
  supervisor in cold source identity. Builder controls check the complete
  declared input tuples against that identity.
- Count production Python files from the same recursive source inventory used
  by the checker, including nested package files and excluding cache entries.
- Validate native observer frames without constructing a discarded large
  serialization, and read workspace header words directly from the retained
  response buffer. The frame ABI, original buffers, field boundaries and
  limits remain the contract.
- Regenerate discovery metadata for the verified shared build choices while
  preserving the original R5 input domain and complete buffer controls.
- Reuse the same-case Core input after its independent VM observation; direct
  emission and publication continue their independent verification.
- Decode already validated, unescaped JSON keys without a second JSON parse.
  Escaped keys, duplicate-key identity, grammar and resource limits retain
  their original checks.

### Latest completed ROG checks of published source

The completed current source is [`b2ba900`](https://github.com/TrillionniumFoundation/Hepta/commit/b2ba90090929472d4a336a058aeb3e1e9c74ed8d),
tree `a156df56ccd5053c05d166548293dc9a57444d27`, with 2,970 tracked
file byte/mode identities. ROG used CPython 3.14.4 and Clang 20.1.8.
Completed stages reread the complete frozen tree and matching cold inputs.
The CI merge commit `73aa79b7f2a0e0961194aaa5356981a0198cce23` has
that same tree. Its CI outcomes are recorded separately from ROG outcomes.

| Complete scope on that source | Actual outcome |
| --- | --- |
| Ordinary fresh-source cold | PASS: 11 outer checks and all 5,060 nested checks; 70.078 seconds producer wall time under the original 180+3 and 240-second limits |
| Complete cold image readback | All six images read; B1=B2=B3, M1!=M2, M2=M3 and M3!=B3 |
| Complete Core workflow inventory | PASS: 754/754; 510.912 seconds outer process |
| v9 scalar and word-memory group | PASS: 21/21; 77.558 seconds outer process |
| Complete static-budget module | PASS: 13/13; 7.827 seconds outer process |
| Artifact Source/preparation/Native group | All 15 methods ran; 13 PASS, two Native failures retained; 12.788 seconds outer process |
| Explicit native-parent cold producer | PASS on ROG in 125.852 seconds; its separate complete phase/raw readback remains required |
| Actual REF18, FD18 and CT36 | Complete original controls and their independent readers passed |
| Native transport's first unselected observer lane | All 47 methods ran; 46 PASS and one linked-compiler preparation ERROR. No candidate-lane PASS was inferred |
| Same-source CI | Kernel and NDU workflows PASS; native cold exceeded the original 180-second deadline; the same linked preparation failed. Full Slot Native4 and its dependent definition gate remain HOLD |

Cold B1=B2=B3 are the same 637,172-byte image with SHA256
`f81c42138a259286492e46f221010574d629a4eeea775815bd59ee7d71d66843`.
Raw ROG evidence remains under
`/home/qian-qi/hia-unified-v9-fixed-evidence-20261120/`.
The CI native-cold archive is 69,707,231 bytes, SHA256
`5952fdfca46a0e8b009aa17e5a5d4c6744dd4a8ca36a053e79af86d22f6d2f00`.
Its deadline owner killed and reaped the unfinished process at the original
limit; 32 phase reports were complete PASS and six index entries remained
pending. ROG PASS does not replace this CI HOLD.

The first external ROG regression supervisor rejected its own 125-minute
workflow argument before spawning a product child because that archival
wrapper accepts at most 120 minutes. Its failed attempt remains recorded.
The successor operator uses the existing owned-process primitive for the
workflow's original 7,500-second total and retains every original
1,800-second lane bound. It completed the actual first original lane and
recorded the linked preparation error above. No product limit was raised.

### Current reviewed source corrections

The current successor carries two additional corrections. Their complete
Source and isolated development results do not transfer earlier cold
qualification to newly edited source bytes.

**Journal installed preparation.** The original test copied 176 Agent
resources while the unchanged package policy additionally requires 17
executable-capture resources and three integer resources. Preparation v2
retains the complete original 48,482-byte test and changes exactly two
staging blocks. It reads the fixed policy as data, stages all 196 resources,
and verifies every staged byte before the original wheel build. All 21
original methods, business assertions, NoTools installed probes and
120/120/30/1,800-second build/install/probe/scope bounds remain.

Bootstrap's producer and independent reader, Discovery, Verification,
StoreTransaction and both Delivery admission layers verify the complete
old/current source relation. Old scope fixtures, literal predecessors,
method order, original controls and terminal source rereads remain intact.
The independent Bootstrap reader reconstructs the relation itself. All
actual proof dependencies are included in source, builder and sdist inputs.
Discovery/Verification also retain the already reviewed exact NativeTools
diagnostic-source successor for their original ordinary caller scopes.

The isolated complete Source34 passed in 19.520 seconds. A real sdist build
then staged 715 paths with 275 exact support files and all 451 declared
resources; all thirteen new Source methods passed from its extracted source
in 8.839 seconds. Its 6,810,639-byte archive SHA256 is
`002f09dd21ef822028d139b42afab31569695e3e995b0aaa723a4919c71d2f6f`.
The independent DATA receipt SHA256 is
`629592ece2a6a5bcb90a6702d77bff7b6c96366327a15cf49f96990b0c328b87`.
A fresh complete Journal21 Native/caller run and reader are still required.

**Linked compiler preparation.** The existing full linked-compiler method
silently tried to replace a v8 header in the actual v9 compiler source.
Consequently the compiler emitted flat bytes and the unchanged ET_REL
inspection correctly rejected them. The correction first asserts the exact
current v9 flat header, then converts it to v9 `selfhost_elf`. Producer and
independent reader each admit one exact whole-source inverse to the retained
original test. All original44/current47 methods, complete success/refusal
inputs, loader comparisons and budgets remain unchanged.

An isolated ROG development build ran Source13, built the actual transport,
then ran original47 twice, selected47 and all eight actual handoff controls.
The complete regression passed in 26.053 seconds, and its separate DATA
reader passed in 0.158 seconds. It used the explicitly declared development
compiler; it is not a fresh-source cold qualification of this successor.
The receipt is retained under
`/home/qian-qi/hia-linked-profile-v9-20261120/evidence/`.

After composing both corrections, all 69 complete Source/contract/language
methods passed in 78.580 seconds. All 2,977 source file bytes and modes
remained stable; two generations produced identical support and language
inventories. The original Source34 controls and complete current transport
Source groups were included. No Native Journal PASS is inferred.

### Preserved Artifact Native failures

The v2 original preparation removed the two discarded temporary classes
without executing business or changing GC policy. On `b2ba900`, two complete
original146 runs and the VM comparison now agree, and the full Core gate
passes. The old original-only 14-versus-0 failure remains attached to v1.

Native Artifact still has a separate complete-domain difference. All
146 original/actual records were independently consumed and compared; the
only leaf difference is `$[143].trace[14].collected`, original 0 versus native
41. All other fields, including exception identity/context, event order,
resource deletion and weak-reference observations, agree. The original
report is 430,668 bytes, SHA256
`23871f9c292b2a0487093ae70d43b22f99b5827be9f7b1af05284dfc9ec225f3`.
The installed worker additionally still encounters an old exit-code-1
expectation against the current UNKNOWN terminal's actual exit code 2.
Both are retained Native failures until their own full successor runs pass.

A separate preparation-only diagnostic on the same CPython 3.14.4 creates
no Artifact Frame, invokes no HIA entry and does not run the original
observer. Its five import prefixes collect 0/10/36/41/41 objects. The complete
saved graphs attribute the 41 to two overwritten ctypes classes (10),
signal Enum preparation (15), ast.literal_eval closures (11), and uuid Enum
preparation (5). There were no automatic collections inside those diagnostic
windows, and all original source/report/image bytes remained stable.
This identifies a preparation source for the full count; it does not prove
identity with already-collected objects in the earlier process or change
that process's qualification. No extra collection, field normalization,
candidate pre-import into the original authority, or hidden strong root is
used as a product repair. Diagnostic receipt SHA256:
`39a6f9eae9b7420f8c0e20ca86885b078e73cd1523db9a8898b0ad6c6fecfe94`.

A single final source still needs fresh cold, complete Core, affected
native/installed domains and full retained regression. Earlier Store Capture,
Discovery, Verification and Slot raw lifetime/GC observations remain HOLD
unless their own complete current domains establish otherwise. The complete
preceding `1a4f220` qualification and source-correction records are preserved
in the historical links below. No aggregate count is a native completion
percentage; old provider removal remains false.

## Source format and actual entry points

Active `.hia`, `.HIA`, `.hiaasm` and `.hia.json` files have been migrated
to `.hepta`; paired structured projections use `.core.hepta`. Assembly
retains `hia-asm.v1`, structured Core retains its explicit schema, and the
`hia` command and `hepta.hia.*` protocol names keep their identities.
The [source naming contract](HIA_SOURCE_SUFFIX.md) also covers generators,
package resources and historical path mappings.

The [ordinary CLI](HIA_CLI_NATIVE.md#all-15-ordinary-actions) has fifteen
actions; selected HIA control still uses its declared foreign effects.
The ordinary worker constructs `HIAAgentService` and dispatches eleven
public tools, with `hia_resource_read` as an alias.
The [standalone native frontend](HIA_AGENT_STDIO_NATIVE.md) supplies six
bounded commands through HIA and mechanical syscall/ABI transport.
Each entry retains its own admission and installed-resource requirements.

## Current implementation changes and required validation

### Explicit v9 word memory

The [v9 memory profile](HIA_WORD_MEMORY_V9.md) adds four unsigned 64-bit
buffer operations: load and store, each with explicit little-endian or
big-endian order. Unaligned offsets are permitted after checking the complete
eight-byte range. VM, direct native, LLVM and selfhost qualification must
retain the complete shared input domain. The generated compiler uses word
access for its fixed records, while SHA, JSON wire and structured Core
consumers retain their checked extents.

Slot's `read_word`, `get` and `set` helpers preserve the original first byte
operation, then use a little-endian word access after proving the complete
eight-byte extent. Their full original byte paths
remain for short tails and high offsets, preserving the original trap and
partial-store order. The retained generator reproduces the complete original
v8 source; every other function is unchanged. The added controls compare
890 helper inputs and 239 complete packet inputs against that source. The
original 248/7,574 input groups, 4,000,000 VM steps, 16 MiB heap, call depth 128
and 1,800-second owner remain required. A word operation costs one VM tick;
identical interruptions under arbitrary smaller step budgets are not claimed.

The optional Python VM preparation admits the exact v9 interpreter by a
whole-source inverse to its fixed v8 predecessor. It derives the operation
from the actual current source, keeps all word operations and binds its
cache to that source digest. It remains a reference execution optimization,
with the original fallback, semantic, stopped-storage and failure controls;
it is not an HIA implementation or native qualification.

The v8 catalog, original generated owners, frozen integer references and
original CLI Discovery inputs remain independent regression authorities.
Strict whole-source inverse/forward checks identify reviewed successor edits;
they do not treat an old result as a current execution. Discovery now serves
nine schemas and 54 instruction records, with 71 current native and VM
frames plus the original R5 61 frames and six VM controls. Static resource
admission preserves original modes 0–4 and adds explicit v9 mode 5; all
original seven caller modules must exercise their complete current domain.

The native transport selects the actual running Python library, including
distribution multiarch and relocated-runtime layouts, and validates its
resolved bytes under the existing ABI rules. Its current observer suite
requires 47 methods in each full lane, including the original ordered 44 and
three additional frame/workspace boundary controls. Historical 44-method
reports cannot qualify the current 47-method scope.

### Explicit native integer profiles

The selected integer implementations preserve the original ordered input
domains and callers:

| Profile | Complete declared input domain | Required controls |
| --- | ---: | --- |
| [Division/remainder](HIA_VM_INTEGER_DIVREM.md) | 2,500 inputs | Source3, Native8, original/selected generic21 and installed use |
| [Eight-operation arithmetic](HIA_VM_INTEGER_ARITHMETIC.md) | 11,200 inputs, including the div/rem prefix | Source3, Native8, 320 VM witnesses, 144 resource/tick/depth observations and twelve installed inputs |
| [Fifteen-operation scalar](HIA_VM_INTEGER_SCALAR.md) | 19,118 inputs, including the arithmetic prefix | Source3, Native8, 600 VM witnesses, 270 resource/tick/depth observations and 25 installed inputs |

Request identities, operand/result echoes, canaries, checksums, native-call
ownership and terminal acknowledgements remain required. Shared transport
changes require fresh images and manifests for every affected profile.
The ordinary VM and its full resource/exception behavior remain part of
product acceptance.

### HIA compiler and Capture source successors

The [bounded selfhost compiler](HIA_SELF_HOSTING_CORE.md) retains the declared
8,192-operation, 128-function and 1,536-block limits. Complete generator
reproduction, original and modified-source fixed points, independent
references and resource refusals remain required.

[Capture](HIA_STORE_FILE_CAPTURE_NATIVE.md) retains its full 5,101-input
comparison, all 73 business ports and complete state checks. The reviewed
source reuses words within one read-only validation call; actual allocation,
GC, exceptions, traceback, locals and budget observations still require
matching-source qualification. Original incomplete domains and differences
remain recorded.

### Explicit matched descriptor observer

The `matched-v2` observer uses complete original A, original B and candidate
lanes with identical declared inputs and inherited descriptors. It checks
actual initial conditions and the complete original eight-call sequence.
The reader binds all validators to the same captured bytes and retains final
rereads. The original `legacy-v1` observer remains available.

`PASS_MATCHED_FINITE_OBSERVER` concerns that finite observation domain.
Complete descriptor and resource behavior remains an independent requirement;
the original total budget and cleanup allowance remain unchanged.

### Native source-to-installed-executable path

The [native executable release builder](HIA_EXEC_RELEASE_NATIVE.md) combines
source admission, the embedded HIA frontend/compiler, complete ET_EXEC checks,
hashing and HIAREL01 packaging in one native process. Fixed assembly supplies
the buffer ABI and mechanical syscalls. Bootstrap and qualification still
have hosted tools.

The complete release gate retains Source3, Native5, all 44 managed commands,
nine original compile/pack API invocations, twelve installed executable runs,
the independent DATA reader and all sixty negative DATA controls.
The cold transport runs two complete current47 baseline lanes and selected47,
retaining every original44 method in each lane, plus HOF8, REF18, FD18 and
CT36 with complete DATA consumption.
These gates run against the same frozen source and their declared compiler.

### Verified register and SIMD kernels

[Verified kernels](HIA_VERIFIED_KERNELS.md) add direct register scalars and
borrowed-byte sum, zero-scan and nonoverlapping copy for SSE2, AVX2 and AVX-512.
Independent consumers check the actual final ELF; CPU/OS admission and sealed
loading bind the selected bytes to the executable mapping.

`hia build --kind shared` now selects the verified `auto` route and
host-native ISA by default. The ordinary object build and explicit native
module ABI keep their existing contracts. The standard and selected HIA CLI,
installed wheel, final-code proof and native guard-page/failure controls all
require current-source qualification.

The registered performance protocol retains all 671 cases, 21 measured
batches per case and three warmups, with all arms, raw samples and checksums.
Earlier campaign outcomes remain attached to their original sources.
The [broader language and project work](HIA_RUST_COMPARISON.md) tracks general
calls, loops, ownership, concurrency, foreign lifetimes and application cost.

## HIA ownership and retained providers

| Surface | HIA implementation and remaining owner |
| --- | --- |
| CLI and compilation | Selected HIA control, lowering, emission and verified kernels; ordinary entry, general Core verification, foreign objects, compiler/solver/linker tools and publication still have hosted owners |
| Worker and service | Native request/report, discovery, verification, bootstrap, context and read policies; `HIAAgentService`, imports, tool dispatch and foreign providers remain |
| Store and evaluation | Native lifecycle, transaction, profile, cost and evaluation controls; SQLite/WAL durability, JSON/hash providers, clocks, exceptions and replay remain |
| Execution and VM | Explicit integer and observation components; general VM, runner setup, limits, child termination, complete reports and foreign lifetime semantics remain |
| Resident runtime | Native generation/retention decisions; `ScalarMultiversionRuntime`, `GenerationLease`, library mappings, descriptors and pending cleanup still have actual owners |
| Release and adoption | Native construction, immutable installation, selection and rollback; complete default installation, durable-state migration, worker handoff and outstanding-reference retirement remain |

These providers are dependencies of the current product. Their replacements
must take the actual callers, state and effects through the gates below.

## Final acceptance and cleanup

### Remaining product acceptance

One frozen source tree must satisfy the complete existing requirements.
The original test identities, ordering, domains, negative controls and
budgets remain in force.

| Gate | Required complete scope |
| --- | --- |
| Source and generation | Full workflow Source/Core inventory, all existing and added controls, complete registered source bytes/modes and double-generation equality |
| Matching-source cold | All eleven outer checks and 38 phases; original 180 seconds plus three seconds for owned cleanup, within the existing 240-second outer owner |
| Native components and callers | Complete affected original/selected, installed, FD, GC, resource, exception, raw traceback/locals and public-reflection scopes; the existing 1,800-second component owner limits remain |
| Retained regression | Complete planned/started/finished test inventory within 5,400 seconds; zero failures, errors, skips, expected failures or unexpected successes |
| Installation and ordinary entry | Actual sdist/wheel/native resources, clean installed execution, all ordinary commands/tools and default startup against the final source and image identities |
| Durable state and adoption | Original request/generation identity, replay and UNKNOWN custody, rollback, real worker handoff, running-image readback and confirmed retirement of old references |

Cold fixed points remain B1=B2=B3; M1!=M2, M2=M3 and M3!=B3, with the
64-to-80 reservation control. General Core checking, external symbols,
relocations, linker support and additional targets retain their separate
obligations; `whole_HIA_language_self_hosted=false` remains accurate.

Complete DATA verification establishes the integrity of the consumed evidence.
The recorded execution outcome, original budgets and complete test domain
determine whether its qualification passed.

<a name="repository-ownership-and-cleanup"></a>

### Repository cleanup

The active tree keeps one current implementation, its component contracts,
consumed original fixtures, independent references and recovery ledgers.
Numbered HIA units may compose one current program. Build output and isolated
development attempts stay outside the product tree.

Retired process narratives remain recoverable from fixed Git objects through
the existing [process-document ledger](../review-evidence/hia-native-cleanup-20261111/retired-process-documents.json).
The [development-version](../review-evidence/hia-native-cleanup-20261111/retired-development-versions.json),
[historical-bundle](../review-evidence/hia-native-cleanup-20261111/retired-historical-bundles.json)
and [rewrite-observation](../review-evidence/hia-native-cleanup-20261111/retired-rewrite-observations.json)
ledgers retain their actual completed retirements.

Active Python modules and qualification supervisors remain until replacement,
state migration and observed adoption are complete. The supervisor under
`review-evidence/hia-native-rewrite-20261111/` is an active build dependency;
its directory name does not make it disposable evidence.

<a name="latest-completed-source-bound-evidence"></a>
<a name="latest-completed-source-bound-observations"></a>
<a name="preserved-lifetime-traceback-and-resource-failures"></a>
<a name="latest-r25-source-validation-and-corrective-successor"></a>

## Historical source-bound evidence

Earlier narratives and exact outcomes are available at fixed revisions:

- [Completed preceding v9 ROG scopes and Artifact preparation records at `b2ba900`](https://github.com/TrillionniumFoundation/Hepta/blob/b2ba90090929472d4a336a058aeb3e1e9c74ed8d/docs/CURRENT.md).
- [Published v9 integration and pre-v9 qualification records at `1a4f220`](https://github.com/TrillionniumFoundation/Hepta/blob/1a4f2202a6c7ffbad373329ddcd9451cc59c9401/docs/CURRENT.md).
- [Published R24/R25-era status and preserved lifetime/resource failures at `192be0c`](https://github.com/TrillionniumFoundation/Hepta/blob/192be0c277a6971dc956326372fe4e48a007ae26/docs/CURRENT.md).
- [v75–v77 status at `f33d8da`](https://github.com/TrillionniumFoundation/Hepta/blob/f33d8da316de8fdf27b504371f1a5310997ff548/docs/CURRENT.md).
- [Original suffix failure and repair records at `f33d8da`](https://github.com/TrillionniumFoundation/Hepta/tree/f33d8da316de8fdf27b504371f1a5310997ff548/review-evidence/hia-native-rewrite-20261111/suffix-20838-r2).
- [Kernel implementation and original campaigns at `633feee`](https://github.com/TrillionniumFoundation/Hepta/blob/633feee656f000e2a9b683b366e391b5eefe3ce1/docs/HIA_VERIFIED_KERNELS.md).

These records preserve incomplete Source/Core/cold runs, Capture and Slot
lifetime/traceback differences, resource observations and performance
regressions. Qualification of the unified source requires its own complete
execution and readback.
