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

### Completed ROG checks of published source

The published qualification baseline is
[`35882d5`](https://github.com/TrillionniumFoundation/Hepta/commit/35882d52059ca16d0654982edbe48588fe892ac0),
tree `89135ef0778f73a15482ff7235b09990e778a9ec`, with all 2,986 tracked
files and Git executable modes captured. ROG used CPython 3.14.4 and
Clang 20.1.8. Its complete R11 ten-stage run passed:

| Complete R11 scope | Outcome | Outer wall time |
| --- | --- | ---: |
| Ordinary fresh-source cold | PASS within the original bounds | 77.351 seconds |
| Native transport Source controls | PASS | 1.266 seconds |
| Fresh cold with explicit native parent transport | PASS | 102.938 seconds |
| Actual source/native binding | PASS | 0.032 seconds |
| Complete original47 twice, selected47 and Handoff8 regression | PASS | 25.494 seconds |
| Transport terminal readback | PASS | 0.164 seconds |
| Complete REF18 | PASS | 1.316 seconds |
| Complete FD18 | PASS | 1.367 seconds |
| Complete CT36 | PASS | 17.694 seconds |
| Complete Core workflow inventory | PASS, all 792 methods | 560.344 seconds |

These are executions of the published baseline. A later source or package
change requires its own matching-source qualification. R11 raw evidence is
retained under `/home/qian-qi/hia-unified-v9-retained-evidence-20261120/`.
The independent Core DATA reader also checked the complete ordered 792
methods, actual workflow/command, original 1,800-second owner, process cleanup
and all 2,986 source byte/mode identities. Its 834,955-byte result has SHA256
`2ae46a28e5376b749dd040cb380b33fdf40546d6d798bbbdf3c9fe7b3c47559c`.
This does not substitute for every component's independent inner reader.

**Both current R11 cold lanes have complete retained-raw DATA acceptance.**
For each lane the independent reader consumed all 38 phases and 5,850 actual
stdout/stderr pairs, including 5,200 complete binary frames and 650 explicit
empty streams. It decoded and checked 5,521,557,688 bytes of original stdout
per lane, all associated requests, archives, source identities, actual owner
terminals and final rereads. Its ordinary and native results respectively are:

| Complete retained-raw report | Bytes | SHA256 |
| --- | ---: | --- |
| Ordinary R11 | 1,417,045 | `7ca06f341e0c392668e906c4b1e545f6b4cba73b0f01bd9d724b42b353806c8d` |
| Native-parent R11 | 1,533,542 | `280ac4c0a122d1002626f3d30eedd87794988f61a31b3c5a8eeb7a8c3282783b` |

The reader passed nine DATA controls. It establishes complete raw capture and
custody, not independent reexecution of every one of the producer's 5,060
semantic predicates. The original 16 MiB stream, 512 MiB archive, 32 MiB
manifest, 180-second cold and three-second cleanup bounds remain unchanged.
The older R9 missing-stream HOLD remains attached to R9; absent historical
bytes were not reconstructed.

### Current GitHub baseline and original caller failures

The [358 workflow](https://github.com/TrillionniumFoundation/Hepta/actions/runs/44727101814)
did not pass its complete Native or cold jobs. The fresh CI cold process was
stopped at 180.281 seconds under its original 180-second limit: 32 of 38 phases
completed, two had started without a terminal, and four had not started.
Cleanup completed. ROG's successful run does not qualify that CI execution.
All 1,859 declared source hashes match the ROG freeze; 1,857 actual exported
files were independently read and matched. The two workflow files were not
present as actual files in that archive, so this is not a whole Git merge-tree
identity proof. GitHub's synthetic PR merge is not assumed to equal the ROG
checkout without that proof.

Current CI also retains complete Source failures for Slot, Capture,
Discovery, Verification and Bootstrap, together with the Native failures and skipped
later gates. Kernel and NDU workflow results have their own scopes. An earlier
972 cold pass or a later successful independent component cannot erase a
current failed or unexecuted scope.

The original Artifact132 callers remain unqualified. The two Store cases
still exceed their unchanged three-second second-emission budget. A separate
source-scanner candidate passed 22 Source controls, six unpacked-sdist controls
and a fresh ROG cold, and reduced measured complete scanning time; the two
original business-budget cases still failed. It has not qualified the complete
132-method caller set. No hash cache, larger business budget or smaller input
domain is used to turn that result into a pass.

The previously absent NDU prerequisite is now real: the fixed upstream commit
`d3c2d760eca5065fc966820379c35c6e8d56e855`, actual Cargo build and executable
were read and verified on ROG. All nineteen original NDU-dependent methods
passed without skips. This separate 19-method result does not retroactively
qualify the earlier skipped 132-method execution.

The complete Bootstrap CI archive was independently consumed as DATA: all
95 members, 1,688,720,333 logical bytes and the 99,473,402-byte ZIP were checked
and finally reread. The ZIP SHA256 is
`e887cc95eb3498a5295c2a9abe99c65474e404fd84712e061d109139f3aa6a78`.
Its four fresh originals completed: two complete232 and two complete15,830
streams, each pair byte-identical, with actual process terminals and cleanup.
All 91 declared source pins match the published baseline; the archive does
not contain an actual full source export or prove the whole synthetic merge tree.

The candidate Source6 suite completed four methods and started a fifth before
the original 1,800-second owner stopped at 1,800.017 seconds. Its full VM lane
finished 2,478 cases and started 2,479: 2,477 equal and one differing case,
with 134,326 entries in finished observations. The last started case is
`__init__.root-not-directory.outer0.fault.94.ValueError`; the remaining cases
and sixth method are not passed. In `generator_protocol.throw-instance.outer1`,
the two iterator/root deletion events occur before sealing in the candidate
and in the original late-event stream after sealing. The original exception
type, identity, cause/context and three-frame traceback chain are preserved.
This is an observed lifetime difference, not an accepted equivalence.
The outer group has its own terminal, but the separately owned candidate child
has no retained terminal or final source reread. Its cleanup remains unproved.
The independent 261,642-byte DATA report has SHA256
`5dbb837186710d635a1b19a40720ca06dda1b8b49c386177a0891cbe90bd05ac`.

### New explicit v6 carriers and actual package results

The current source adds the [explicit v6 carrier contract](HIA_NATIVE_CARRIERS_V6.md).
One carrier owns the native image and real exported buffers; another owns the
actual cells of Verification's private recursive callback. HIA retains the
business decisions and transitions. Source, binary, compiler receipt, exact
CPython profile, actual loaded types and original live worker scope are bound
before using either carrier. Old v1–v5 routes remain explicit and unchanged.
Unused UUID/FFI dependencies are loaded only on their actual paths; the retained
ID-producing method bodies and real provider replacement behavior are checked.

On desktop CPython 3.14.10, the frozen development source was compiled into
three real extensions with three separate receipts. The original 134 packet
records, mechanical buffer controls, six real-cell controls and 106 actual
admission/refusal controls passed. The complete Artifact146 original replays
and explicit-v6 candidate were byte-identical, with SHA256
`c5e1dc35d9656d41afa19fced6b4ef1d87747a13714c802530e8f38a84caef6a`.
Every original GC observation remains part of that comparison.

The package continuation then passed all 29 selected Source controls and all
13 selected controls from a real unpacked sdist. A real wheel was built and
installed into a clean target. It contained the three separately built
extensions and their source-bound receipts. The complete installed Artifact146
comparison also matched both original replays. No source-tree extension was
substituted for the installed binary. These are explicit development/package
scopes; they do not replace the complete Artifact Native suite, all original
callers, matching-source cold or ordinary default adoption.

The subsequent complete source compatibility candidate passed 82 Source
methods. Its actual unpacked-sdist run completed all 66 declared methods,
with 64 passes and two import errors caused by a missing builder dependency.
That first source-closure package remains HOLD, with wheel and installation
unexecuted. The frozen R2 successor includes the complete builder import
closure and the unchanged normal command entries for 134 packet observations,
six cell controls and all 146 Artifact cases. It completed all seventeen
stages on desktop CPython 3.14.10: Source82 and real unpacked-sdist66 passed,
a new wheel was built and installed, three fresh C extensions were compiled,
all 106 admission controls, mechanical5/packet134 and Cell6 passed, and separate
source and installed complete146 comparisons both passed. All 3,009 source
files stayed unchanged after the two identical metadata generations.
The six component stages retained their original 60-second limits and
three-second cleanup; the existing installed146 retained its 120-second bound.
The 21,640-byte actual terminal report has SHA256
`ab628775de0c03bcaf37b3a124149310984998f7348dfb8ca0743c69d52dc21a`.
An independent DATA reader consumed 11,760 actual retained files, repeated
all five complete file inventories with their modes, and finally reread all
captured bytes. It verified every ordered Source82/sdist66 method, all original
63/126/278 compatibility controls, the complete packet/admission/cell controls,
both full146 streams and the actual installed extension/receipt paths.
The strict successor derives the exact original 25 source paths and two
control-code files from fixed source definitions and original fixtures,
then checks complete maps and both whole registry transformations. The prior
reader and its narrower independent-domain boundary remain retained.
The 163,657-byte independent report has SHA256
`a98fb77fd293bca6ca896ce80fd44128eeaae7127902bfbf7ac837e9d3c30c87`.
This new R2 result has its own source identity. It neither erases R1's import
failure nor qualifies later workflow/source changes or the whole product.

The ordinary Core workflow now declares the six new pure Source selectors
while preserving every old selector's relative order. The Native workflow
separately declares a fresh matching-cold Artifact build, three actual C
extensions, mechanical5/packet134, Cell6, admission6/106 and complete146.
Each original development stage retains its 60-second bound and three-second
owned cleanup. Actual inputs, complete output streams, compiler/binary receipts
and terminal source rereads are retained. These finite controls do not change
the public Native8 or whole-stack acceptance boundary.

Verification has separate results which must not be combined into one pass:

| Exact development scope | Complete outcome |
| --- | --- |
| ROG CPython 3.14.4, direct real-cell carrier, complete original 185 plus 1,344 derived native cases | 1,529/1,529 equal, 126,294 actual HIA entries, zero retained-body calls |
| Same ROG candidate, original twelve lazy-generator controls | 12/12 equal, 5,256 actual entries |
| Same ROG candidate, complete original Source3 | All three passed; full 185 VM and 185 unselected observations equal; 354.180 seconds outer wall time |
| Desktop CPython 3.14.10, fresh HIA build and source-bound explicit v6, complete native domain | All 1,529 executed; 126,294 entries; two exact GC-count differences, therefore HOLD |
| Same desktop source, unchanged Source method03, unselected complete185 | Three GC-count differences, therefore HOLD |

The published 358 CI on CPython 3.14.10 already had four VM and three
unselected GC-count differences. All four fresh original185 streams were
byte-identical; every other candidate observation field matched. The complete
226,875-byte CI archive has SHA256
`e8528a79a967ecd45309bd4950685063b784916f9feaf57c184159ba0ef78ef9`;
all 81 members and all 29 captured source identities were independently read.
This baseline prevents attributing every later GC difference to a new carrier;
it does not waive a later candidate's own exact comparison.

The explicit-v6 desktop differences are `verification.schema.outer0`
(2,216 original versus 1,943 native) and `subject.temporary-store`
(995 versus 1,057). The latter 62-object difference also occurs in the old CI
unselected baseline. A separate diagnostic using only the existing explicit
collections found that its 62-object delta consisted of one additional prior
test `World` and its attached objects. That diagnostic added no collection or
saved garbage and changed no threshold, but its metadata wrappers can affect
allocation timing; its graph is not an identity proof for already-finished
runs. Original failures and raw counts remain unchanged.

CPython's [documented GC behavior](https://docs.python.org/3.14/library/gc.html)
changed again in 3.14.5, restoring generation 1 and `threshold2`. A compiled
3.11–3.14 mechanical ABI guard is not an all-patch semantic qualification.
The local Python 3.12 full-source lifetime failure also remains retained.
Neither runtime pin changes, count normalization nor extra strong roots are
used to manufacture whole-product acceptance.

### Discovery, Slot and the separate runtime repository

The complete current ROG Discovery Source3/Native8 ran all eleven methods.
Eight passed. The full native 11,016-input comparison executed 189,036 entries
with four GC-count differences; the complete 56-input VM and unselected
comparisons each had four GC-count differences. Other compared fields matched.
Its real installed-worker controls passed within that same scope, while the
three complete comparisons remain HOLD. All 2,986 source identities and
matching cold inputs stayed unchanged. The complete 1,778,801-byte DATA report
has SHA256 `adabe4a9f96f584c0964dca767ceca8bace89bee6d24aac890afbe7b1a226864`.

The published Slot Source scope still runs its original v1 preparation. Its
complete248 VM comparison had five semantic/lifetime differences; its original
1,800-second supervisor ended after 2,970 of 7,574 derived observations, with
82 differing completed cases. A separate explicit v5 preparation now uses a
real built and admitted image and real C mechanical owner while executing only
the independent VM controller. The original248/derived7574 domains, four fresh
original children, step/heap/depth limits and 1,800-second total remain fixed.
Its complete248 readback has 247 equal cases and one GC difference
(0 versus 730). That complete lane used 12,072 actual VM entries and 1,426
actual C frame initializations/calls/completions, with zero native-controller
attempts and returns. The full derived lane stopped at the unchanged total
bound after 3,475 of 7,574 finished observations and one started observation:
3,465 equal and ten differing completed cases. Its final report and final
C/native counters are absent; the earlier 248-case counters are not inherited
by that partial lane. The third original method did not start. All four fresh
original streams are complete and pairwise identical.

The original supervisor ended at 1,800.011 seconds. All seven recorded command
groups, the operator and the actual nested children were subsequently observed
absent from `/proc`, without additional termination signals. All 2,986 baseline
source byte/mode identities remained stable within the 2,993-file candidate.
The complete retained DATA remains HOLD. A separate reader custody correction
captures the actual command/result/stdout/stderr bytes before interpretation
and finally rereads them. Its nine Source controls passed; a pure DATA reread
of the actual complete248 leaves the same one GC difference. It correctly
refuses a full-domain directory without its supervisor terminal.
The original v1 failure and frozen v5 execution remain retained.

The separate [hepta-runtime PR140](https://github.com/TrillionniumFoundation/hepta-runtime/pull/140)
now has union commit `94c8b4a9af342e83d11981942ca2463019a7f4d1`, tree
`ec3bdf3e6837d45c7ccb7470db3910876cb95136`, with sole parent
`5b2ee6952acaf00262ca42ad31857012db4618e1`. Its complete selected Git source
has 3,513 files; its execution-source closure has 543. Original reporting
control groups of 64 and 70 passed. The normal successor CI is separate from
PR139's completed 405 checks/81 recipes and private R4's original result.
Neither prior result is inherited by the new head.

The new-head CI independently completed the fresh compiler cold gate, all
eleven native partitions and the native collector. The collector recorded 226
actual native checks and prepared the 81 original recipes. Its complete native
artifact is 754,482,162 bytes, SHA256
`d2d9b871274a7c5441008e5771c43c3603aa3b889c58b920bcb9de10c9d011cf`.
An uploaded artifact and successful producer job do not establish a completed
independent read of every retained byte. The seven
system/services/state/json/config/storage/batch original groups succeeded.
The bytes group failed its original filesystem evidence control at the
unchanged 180-second limit, with exit -9 and complete empty stdout/stderr.
The failure archive completed and remains attached to that actual run;
this is not a successful eight-group original acceptance.

Runtime currently has 126 components, 119 physical containers, 71 runtime
slots and thirteen public routes against the 136-route target. These counts
are different inventories, not interchangeable measures of whole completion.
The private binary-write composition has not become public route fourteen.
Its additional allocation/partial-release fault task was stopped by automatic
approval review; no such product tests were executed and that boundary stays
unqualified. Production activation and whole-runtime replacement remain false.

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

- [Complete pre-v6 current state, R9/R10 failures and stream-retention successor at `35882d5`](https://github.com/TrillionniumFoundation/Hepta/blob/35882d52059ca16d0654982edbe48588fe892ac0/docs/CURRENT.md).

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
