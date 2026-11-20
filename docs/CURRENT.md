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

### Completed ROG qualification of the published v9 source

The independently checked source is [`1a4f220`](https://github.com/TrillionniumFoundation/Hepta/commit/1a4f2202a6c7ffbad373329ddcd9451cc59c9401),
tree `af73ce774cbb69fc6a799425a236b48fefd5fc29`, with 2,966 complete tracked
file byte/mode identities. ROG ran CPython 3.14.4 and Clang 20.1.8. Every
stage reread that full freeze and the actual matching cold inputs. The
published CI merge commit `55c64f2a99a6cda956b74026a0ad54417fc9d1da`
has this same tree.

| Complete scope on that source | Actual outcome |
| --- | --- |
| Fixed-Core cold replay | Eleven outer checks, all 38 original/modified phases and 5,060 nested checks passed; 64.014 seconds outer, 63.038 seconds nested under the original 180+3 and 240-second limits |
| v9 word memory | All four backends, 1,824 scalar comparisons, two cross-target objects and nine refusals passed; direct and selfhost raw lanes each completed 576 valid inputs, 72 traps and eight guard pages |
| Rust shadow reference | Complete locked, offline Cargo test command passed |
| Native integer profiles | Full Native8 for each div/rem, arithmetic and scalar profile, including each profile's original full domain, generic/installed/resource controls, plus separate independent readers passed |
| Worker UNKNOWN | Both complete installed v1 and actual v2 loss/cleanup/replacement methods passed |
| Executable release | All five Native methods and the independent DATA reader passed; its report retains all 44 commands and the separate installed runs |
| Service bootstrap | All eight Native and four resource methods, and the independent DATA reader passed |
| Budget resource retirement | All four Native methods, 22 complete resource cases and the independent DATA reader passed |
| Bootstrap ordinary callers | All 112 original methods and independent readback passed |
| Bootstrap context callers | All 15 original methods and independent readback passed |
| Core source/reference gate | All 750 methods finished in 553.819 seconds; 749 passed and one original preparation/VM comparison failed |
| Bootstrap journal callers | All 21 original methods finished in 37.750 seconds; 20 passed and the installed-wheel preparation failed on a missing current package resource |
| v9 scalar combined gate | Nineteen actual methods passed; static-budget class setup failed because one generated function contained 257 blocks, above the unchanged 256-block limit |
| CI Slot mechanical Native4 | All four methods finished in 1,538.762 seconds. Complete public84/handled12, admission and installed-worker/UNKNOWN groups passed; full original248/derived7574 retained 2 cases/14 leaf differences and 286 cases/1,804 leaf differences respectively |

Cold B1=B2=B3 are the same 637,172-byte image with SHA256
`f81c42138a259286492e46f221010574d629a4eeea775815bd59ee7d71d66843`.
The ROG stage aggregate is
`/home/qian-qi/hia-unified-v9-evidence-20261120/operator-completed-stages-r6.json`
(23,490 bytes, SHA256
`008368061e754a1e72cfbf71fda94923d0e246894d0ed1960c7624d1696ecdc0`).
Its 27 recorded stages include all failures and dependent-reader failures.
The old source and raw observations remain unchanged.

### Reviewed successor fixes

The current working successor corrects four concrete defects discovered by
those complete runs and CI. Its source and sdist qualification do not
transfer the preceding source's native results to these edited bytes.

- Static budget retains all 197 original profile words and the zero result
  outside the table. It splits the constant dispatcher into bounded helpers;
  the generated owner has 30 functions and at most 127 blocks per function.
  The compiler's 256-block limit and original modes remain unchanged. All
  39 combined Source/contract/language/transport methods passed.
- Slot executes the original first byte read or write before entering its
  full-range word fast path. This preserves original argument lookup,
  permission checks, shift errors, exception order and short-buffer partial
  writes. All original 270 helper, 41 argument/borrow-shape and 360 packet
  cases passed, with the complete original expectation bytes identical to
  the failed attempt; the six actual shape differences are fixed. All eight
  Source methods, including the additional 890/239 v9 domains and exact
  generator-admission refusals, passed. Arbitrary smaller VM-tick budgets
  and concurrent eight-byte atomicity remain outside this finite claim.
- Cold-transport Source controls now apply the same existing exact
  old-to-current observer-source admission as the complete native gate.
  All 17 methods passed. Original44/current47 and CT36 domains are preserved.
- Arithmetic CI loads all ten current Source methods while preserving the
  original seven IDs and the three registered successor methods. The exact
  corrected workflow block completed all ten.

Artifact preparation is a separately versioned correction. The unchanged
v1 oracle executed two temporary classes while extracting method code. On
ROG 3.14.4, two complete original-only 146-case runs, without a candidate
import, reproduced the same 14-versus-0 GC difference seen in Core. Actual
object/lifetime diagnostics tied this to the two temporary seven-object
class cycles. The historical failure therefore remains a v1 HOLD.

Preparation v2 compiles the same fixed wrapper and extracts its one direct
method CodeType without executing either temporary class. The old 16,362-byte
oracle is archived verbatim and the new authority admits exactly two source
splices. Independent disposable-child controls compare every recursive code
attribute, line/position sequence and complete marshal bytes against actual
v1 execution. Original business bodies, fixtures, the two original test
modules, all 146 IDs and the 180+3-second child bound remain unchanged.
Each observation now requires two complete byte-identical original replays
before importing the candidate, and rereads both original files, comparison
records and the preparation receipt at termination. No GC policy, raw field,
exception or traceback is adjusted. Both complete ten-method development
runs passed; the second finished in 99.586 seconds including its owner.

Actual sdist validation then exposed missing original-test and transitive
authoring inputs. Both import failures are retained; 17 existing files were
added to the precise package staging and manifest inventories. The final
6,751,456-byte sdist (SHA256
`6d4438374f7a12ec75b2dac3fe820e30f64503a286a2d484dd0d9a2da087414a`)
contains all 701 declared input paths byte-for-byte, with 261 support files.
The complete original Source3, LocalRelease3 and new Preparation4 methods
passed in 102.652 seconds using only the extracted package. Its sources and
all archived input bytes remained unchanged.

The journal failure is an independent packaging-preparation issue: the old
installed test copies resource groups only through `CONTINUATION_BUILD_FILES`,
whereas the current wheel also requires `executable_capture.hepta` and later
registered groups. A versioned preparation successor and full original21
rerun are required; neither a smaller resource contract nor a skipped test
qualifies it.

The complete current Core inventory, new matching-source cold, affected
native/installed scopes and full regression gate still need to pass on one
final source freeze. Earlier Store Capture, Discovery, Verification and
Slot lifetime/GC observations remain unresolved unless their own complete
current domains establish otherwise. These outcomes are not a native
completion percentage, and old provider removal remains false.

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

- [Published v9 integration and pre-v9 qualification records at `1a4f220`](https://github.com/TrillionniumFoundation/Hepta/blob/1a4f2202a6c7ffbad373329ddcd9451cc59c9401/docs/CURRENT.md).
- [Published R24/R25-era status and preserved lifetime/resource failures at `192be0c`](https://github.com/TrillionniumFoundation/Hepta/blob/192be0c277a6971dc956326372fe4e48a007ae26/docs/CURRENT.md).
- [v75–v77 status at `f33d8da`](https://github.com/TrillionniumFoundation/Hepta/blob/f33d8da316de8fdf27b504371f1a5310997ff548/docs/CURRENT.md).
- [Original suffix failure and repair records at `f33d8da`](https://github.com/TrillionniumFoundation/Hepta/tree/f33d8da316de8fdf27b504371f1a5310997ff548/review-evidence/hia-native-rewrite-20261111/suffix-20838-r2).
- [Kernel implementation and original campaigns at `633feee`](https://github.com/TrillionniumFoundation/Hepta/blob/633feee656f000e2a9b683b366e391b5eefe3ce1/docs/HIA_VERIFIED_KERNELS.md).

These records preserve incomplete Source/Core/cold runs, Capture and Slot
lifetime/traceback differences, resource observations and performance
regressions. Qualification of the unified source requires its own complete
execution and readback.
