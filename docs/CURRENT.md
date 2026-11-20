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

The completed R10 source is [`972ecbb`](https://github.com/TrillionniumFoundation/Hepta/commit/972ecbb9ae7535d7526f655eed87b75c563dec13),
tree `d953b4ef8447fccdb67217dcfb0c7389fcc72f92`, with 2,985 tracked
file byte/mode identities. ROG used CPython 3.14.4 and Clang 20.1.8.
All eight scheduled stages reached terminal records. Six passed; the two
Artifact stages failed. Each result belongs to that exact source and scope.

| Complete R10 scope | Actual outcome | Outer wall time |
| --- | --- | --- |
| Ordinary fresh-source cold producer | PASS under the original 180+3 and 240-second limits | 70.082 seconds |
| Complete Core workflow inventory | PASS, all 786 methods; suite time 534.268 seconds | 535.413 seconds |
| Context native module | PASS, all 15 methods | 5.875 seconds |
| Complete original Context callers | PASS, all 50 methods; no skips or anomalies | 51.852 seconds |
| Cost native module | PASS, all 12 methods | 13.788 seconds |
| Complete original Cost callers | PASS, all 81 methods; no skips or anomalies | 67.133 seconds |
| Complete original Artifact delivery callers | HOLD: all 132 planned methods started and stopped, with 19 NDU prerequisite skips and 2 original budget failures | 252.205 seconds |
| Complete Artifact native module | HOLD: 14 of 15 methods passed; the complete 146-input comparison failed | 11.635 seconds |

The independent DATA reader consumed all eight outer process records,
their raw stdout/stderr, complete ordered method logs, original caller
fixtures and retained caller captures. All 2,985 source bytes and Git
executable modes and each stage's matching cold inputs remained stable.
Its 883,929-byte report has SHA256
`d90727caf333847859de493c6980553b68475729b1fe1dbffd3b064e194184be`.
This establishes outer-process, source and caller DATA integrity; it does
not establish independent complete inner native/raw-cold acceptance.
The original `runTest` observation is included in the 786-method total.
Raw R10 evidence remains under
`/home/qian-qi/hia-unified-v9-caller-evidence-20261120/`.

The earlier [`0ab2a0a`](https://github.com/TrillionniumFoundation/Hepta/commit/0ab2a0aea2585e06ddcf0aa3a6931043b16959f6)
R9 source, tree `a2476742bfce3db07992f46fea3b74e16764d198`, separately
passed ordinary cold, Core767, complete Journal21 and its independent
reader, explicit native-parent cold, original47 twice, selected47,
Handoff8, REF18, FD18 and CT36. Its B3 was 637,172 bytes, SHA256
`f81c42138a259286492e46f221010574d629a4eeea775815bd59ee7d71d66843`.
Both cold producers retained all 38 phase reports and reported the original
5,060 checks, with B1=B2=B3, M1!=M2, M2=M3 and M3!=B3. Those results
remain attached to R9; they do not qualify subsequent source edits.
The ordinary and native cold report hashes were respectively
`5143509d42b6f9c2ceebee7ea52400edc275a4d101c09db46f6cc935b026cca9`
and `eb0a7967639033f97458ac5b44cd8dfd0c0c7b4d3c4a83e3770a41eb14e66d1c`.
Original R9 evidence remains under
`/home/qian-qi/hia-unified-v9-journal-evidence-20261120/`.

### Reviewed corrections and retained original streams

The R10 source includes the installed Artifact worker terminal correction,
complete caller source admission and flat native-helper registry inspection.
The actual installed worker scenario now passes, including the UNKNOWN
lost-PUT-ACK terminal with exit 2, all three required stderr markers and
unresolved custody. The four original workers retain their request/replay
identities and return codes 0/0/2/0. The complete 146-input comparison and
its separate GC difference remain required.

Context50, Cost81 and Artifact132 retain their original fixtures, ordered
methods, forbidden-owner assertions, every capture and original budgets.
Their exact reviewed source successors are bound through whole-file inverse
and forward proofs and actual terminal captures. The original Delivery126
and278 Source control inventories remain unchanged. Flat literal helper
registries are read directly from their AST; every other expression retains
the previous fallback and rejection domain. No GC policy, retained root,
cross-call cache or business deadline was changed.

The composed R10 source/release verification passed all 53 Source methods,
the 11 existing language Native methods selected by the complete module,
and all 23 methods from the actual unpacked sdist. The 6,875,610-byte archive
has SHA256 `9d4cb1fae38f4ad9a354b1ea3bde8b43f0ad5523a23250e1d84b996bf5714d57`.
Independent DATA checked all 2,985 candidate byte/mode identities, 468
declared resources, complete method logs and both original126/278 controls.
Its 19,722-byte report has SHA256
`c88b20711e056b6437c9a56b074f5643d07c4e255e1e45be4812151d78c35475`.

**Complete cold raw-data acceptance is still open.** The R9 and R10 native
observer wrote a JSON receipt to successful `*.stdout.log` files instead
of retaining the returned `HIAOBR02` binary stdout. Retained output buffers
and stderr alone do not prove the full returned source/output/workspace
frame. The strict audit of both R9 cold lanes found 5,200 missing successful
stdout streams and 650 failed or explicitly empty streams in each lane.
Missing historical bytes are not reconstructed or relabelled as captured.

The current successor saves actual stdout and stderr before parsing, including
failure and timeout partial bytes and explicit empties. It retains the
original JSON receipt and failure-log behavior. Lossless zlib sidecars bind
the request, return code, timeout, complete raw/stored lengths and SHA256.
The reader rejects changed or truncated streams, trailing or concatenated
streams, invalid metadata and decompression beyond the original 16 MiB
stream bound. The original 512 MiB archive, 32 MiB manifest, 180-second cold
and 3-second cleanup limits remain in force.

All 14 retention/transport Source methods passed, and all six new retention
methods passed from a real unpacked sdist. Independent DATA read all 2,986
source files before/after, all 1,858 contract source pins, all eight actual
processes, complete ordered Source and release logs, all 1,278 regular tar
members, 474 manifest entries and 298 support files. Its 9,752-byte report
has SHA256 `c7388c5459be1f81edbc9c53289a78bf6ae495e0417d1d1ec53f8aa628b8f447`.
The 8,467,739-byte sdist has SHA256
`8d6982e61d8c4f234cc6038f5d0171a66bd7b80c9df20b090bf28351278915e8`.
The six new Source methods are registered in ordinary Core, increasing its
expected inventory from 786 to 792 without removing an existing method.

The separate full-phase DATA reader passed its nine byte-level controls and
still reports the original R9 missing-stream HOLD. It does not import the
checkout or execute a compiler/native image. The new source still requires
fresh ordinary and native-parent cold, complete original47 twice plus
selected47, Handoff8, REF18, FD18 and CT36, followed by the full retained-raw
reader on the exact new frozen source. Actual wall time and archive size
must meet the unchanged bounds; Source/release results do not close them.

### Preserved semantic and prerequisite failures

The current Artifact132 report is 4,626,089 bytes, SHA256
`c6c1c24823b1d92732ae44bc818b834ffda81e9de3fa09910a3dd8599747dd41`.
All original-direct63 methods passed. The generic37 scope skipped 19 NDU
tests because the actual pinned upstream checkout, matching build workspace
and native executable were unavailable. The Store32 scope failed the
expired-evaluation and frozen-context-deadline methods during their
original `build_pair`, at the second emission under the unchanged 3-second
context budget. All 132 started/stopped IDs and every anomaly remain in
the report. An old environment file pointing at missing executables or
missing Git checkouts does not satisfy those prerequisites.

The current complete Artifact146 comparison differs only at
`$[143].trace[14].collected`: original 0, native 30. Both complete originals
agree, and all other compared fields match. Original observations have
SHA256 `c5e1dc35d9656d41afa19fced6b4ef1d87747a13714c802530e8f38a84caef6a`;
actual observations have SHA256
`2832d0954e5fe474455a7cdfcd495053a1baf66c615842532f1e8c6b8f2fa950`.
Separate current preparation-only diagnostics locate six temporary type
cycles from ctypes, signal and uuid. They establish that diagnostic's
actual object graph, not object identity with the already-finished finite
comparison. No count normalization, forced collection or extra strong root
is accepted as a fix. The preceding native41 failure remains retained on
its original source.

The [`972ecbb` CI run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/44720243874)
passed the complete cold-native-transport job; kernel and NDU workflows
also passed. Its Native job reached the Artifact comparison and failed;
later evidence readers have additional failure records. Source and remaining
Native work were still running when this state was written. GitHub uses
its synthetic PR merge; ROG uses the exact published head. These are not
assumed to be the same tree without independent verification.

Earlier full Slot Native4 and Slot/Capture complete VM comparisons reached
their original deadlines. The earlier full `b2ba900` Slot comparison also
retains semantic HOLD: original248 differed in 2 cases/14 leaves and
derived7574 in 286 cases/1,804 leaves, with unchanged lifetime/event
comparisons. Its other three Native methods passed. Current-source
successors must complete their own full scopes within the existing bounds.

The earlier Discovery56 VM and unselected lanes each had four differences
in `explicit_gc_collected`. Verification185 had four VM and three
unselected differences in that same field. The complete raw archives have
SHA256 `27287cc615c6d2241d1fd50245b48f45dcb02d9dd815a5d0f42dc2ca4efa8f66`
and `b2be14f9bad32ee4a487af1092feacc76ca1910cc126d38c3878d58fd21979e0`.
These are actual comparison failures. Full caller coverage, allocation and
GC behavior, exception/traceback ownership, installed/default execution and
durable adoption still need to close before old providers can be retired.

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

- [Journal/linked source correction and preceding qualification records at `0ab2a0a`](https://github.com/TrillionniumFoundation/Hepta/blob/0ab2a0aea2585e06ddcf0aa3a6931043b16959f6/docs/CURRENT.md).
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
