# HIA: current implementation and acceptance

This is the current-state index for `TrillionniumFoundation/Hepta`.
The language is HIA and its source suffix is lowercase `.hepta`.

**Whole-product native replacement and production activation remain
incomplete.** `whole_native_delivery_qualified=false` and
`production_activated=false`. Component acceptance, complete retained
regression and adoption by the installed runtime are separate gates.

## Source identity and naming

The checked [Selfhost-Core contract](HIA_SELFHOST_CORE_SUPPORT.json) identifies
the compiler profile and admitted inputs. The
[current inventory](HIA_NATIVE_REWRITE_INVENTORY.json) is the single counted
inventory of source files, production modules, resources and callers.
Its generation records the actual Git/index state without inventing a
self-referential commit identity. Acceptance receipts identify their actual
frozen commit and tree.

Current assembly and structured Core sources use `.hepta`; paired structured
projections use `.core.hepta`. The assembly header and explicit Core schemas
remain unchanged. Active-source and package gates reject the retired
`.HIA`, `.hia`, `.hiaasm` and `.hia.json` conventions.
The [suffix contract](HIA_SOURCE_SUFFIX.md) and
[original rename map](HIA_SOURCE_SUFFIX_MIGRATION.json) distinguish
byte-preserving renames from later additions and retirements. Frozen protocols
and receipts retain their original names and bytes. The ordinary `hia`
command and existing schema identifiers keep their public names.

The single integration entry is
[draft PR #893](https://github.com/TrillionniumFoundation/Hepta/pull/893),
at `0d2964473d6d5c268cbfe202ebaa532b380b255c` when this follow-up began.
This follow-up advances that same integration branch with the audited changes.
A published branch is source availability; runtime adoption requires the
separate controls below.

At the audit's remote read, `main` remained
`5831f52fada45e076f8f68f198a15c0585e6104f`, with 60 `.hiaasm`, 12 `.hia`
and 11 `.hia.json` files, no `.HIA` and no `.hepta`. The integrated base has
96 `.hepta` sources (71 assembly and 25 structured), and no retired physical
suffixes. Main's state and the integration branch's state must not be conflated.
The audit inventories every retained path, parses all retained Python and
records static caller edges; dynamic caller closure and a semantic audit of
every source line are not established by those counts.

## Implementation boundary

| Area | Implemented capability | Remaining boundary |
| --- | --- | --- |
| Self-compilation | HIA scanner, parser, checker and x86-64 emitter; original/modified-source fixed points | Explicit seed, bounded language/target profile and allocator assumptions |
| Applications and source build | Core checking/patching, workspace operations, native stdio, ELF linking, release installation, assembly source/image self-pack and explicit ordinary selfhost object builds | Default CLI/worker, general structured-project build and complete installed lifecycle |
| Nominal and JSON operations | Selected type/helper/function/constructor/outer owners and raw JSON codecs | Default routing, diagnostics and all foreign-object/state transfers |
| Worker helpers and retained state | Pinned native identity/request/journal/budget/retirement helpers and ordinary snapshot/patch factory views | Hosted transport, SQLite effects, process/resource ownership and complete service migration |
| Slot, version and lease state | HIA ledger kernel and adoption evaluation policy with a hosted store/effect adapter | Default routing, complete receipt/proof admission, SQLite effects and running-worker cutover |
| Release selection | Immutable installation, compare-and-swap selection, previous-release rollback and status | Running-worker identity, active references, restart and old-owner retirement |

The selfhost profile is bounded Linux x86-64. It does not establish
whole-language formal correctness or admission of every general Core program.
The ordinary entry remains `hia = hepta.cli:hia_main`. Its worker serves the
eleven-tool protocol through hosted owners and selected native adapters; the
five-command [native stdio application](HIA_AGENT_STDIO_NATIVE.md) has a separate
protocol.

The explicit
[selfhost build route](HIA_PROGRAM_SELFHOST_BUILD.md) admits an independently
pinned compiler manifest, captures and seals the exact native executable, and
uses HIA's frontend and emitter to produce a bounded primitive Core v8 ELF
object. It rejects unsupported input and never silently falls back to the
Python emitter. The operator pin is an identity decision, not a correctness
proof. Input verification, CLI transport and publication remain hosted; the
ordinary service's general direct backend is unchanged.

The selected [slot ledger](HIA_SLOT_LEDGER_NATIVE.md) now consumes complete
canonical JSON values to decide evaluation completeness, allowed outcomes and
unmet net benefit. Python does not supply precalculated eligibility flags.
Existing field-access order, error identity, SQLite effects and exact request
replay remain part of the contract. These selected decisions do not replace
full receipt, proof, native-artifact or ABI admission.

The final comparison with the separate budget/cleanup candidate
`5386be50a1faddc0d986af3c04cad37a4ac6c102` found one additional publisher
custody check to retain. The selected native publisher now checks exact
descriptor length and complete executable bytes after applying and reading
back the required kernel seals. Missing sealing APIs and construction failures
refuse as `E_PUBLISH_NATIVE_CUSTODY` before a child or publication effect.

Current interfaces are defined by the
[native helper contract](HIA_NATIVE_HELPER_WORKER.md),
[installed-resource bindings](HIA_NATIVE_INSTALLED_SOURCE_BINDINGS.md),
[source-build contract](HIA_NATIVE_SOURCE_BUILD.md) and
[release-selection contract](HIA_RELEASE_SELECTION_NATIVE.md).
The [Agent runtime contract](HIA_AGENT_NATIVE_RUNTIME_CONTRACT.md) preserves
its dated interface design and original pins, rather than reporting a current
deployment.

## Acceptance and preserved failures

The [evidence index](../review-evidence/hia-native-final-20261111/artifact-index.json)
binds reports and lossless original-record archives. Each PASS belongs to its
recorded source, host, inputs and scope. Cold qualification retains its
180-second limit plus 3 seconds for owned cleanup; the complete retained suite
keeps its 5,400-second owner limit. Exact loaded/executed identities and zero
anomalies are required.

The inherited `0d296447` GitHub run
[43114973799](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43114973799)
passed its cold and language gates, but its source and native-application jobs
each failed the same sdist resource assertion. The correction separates the
independent historical gzip oracle from installed production resources while
retaining exact membership and duplicate checks. The sdist keeps the oracle;
the wheel's resource subtree contains only production resources.

A separate local baseline replay of the same `0d296447` source reached the
unchanged 180-second owner limit and reported `QUALIFICATION_TIMEOUT` at
180.398390018 seconds. Its 34 completed phases passed; the complete cold gate
failed, with six of eleven wrapper checks passing. Owned-process cleanup
confirmed no surviving children. This timeout remains a failure independent
of the successful GitHub run. The scanner change only avoids keyword packing
for identifier prefixes that cannot be keywords; it does not change cases,
the two-worker bound, the 180-second limit or the three-second cleanup reserve.

| Frozen source | Complete retained result | Original failure |
| --- | --- | --- |
| `6923b86d9a007aa15b9a5803b35c0f288590dfd2` | **HOLD**: 4,388 loaded/executed; 4,386 passed, two errored | Installed fixtures exhausted the test UID's quota in hardcoded `/dev/shm` directories before reaching their native controls. |
| `c815d8e3637bbcabcee0639b95f87d496f133338` | **HOLD**: 4,388 loaded/executed; 4,387 parent tests passed; two failed subtests in one reference test | Historical compiler-rendering goldens were applied to changed current source. Errors, skips, expected failures and unexpected successes were zero. |

The c815 source passed its matching cold replay (11 checks), all 218 names
compilation-artifact readbacks, both original installed-fixture tests and all
52 source generators. Both installed fixtures also passed within its complete
retained run. The same run's original ten language tests, 1,242 reported checks
and 51 retained language evidence files passed. The enclosing full result
remains HOLD.

The later reference-test correction preserves the historical input, all four
original hashes and the 769,584-byte oracle. Current and mutated current input
are compared byte for byte with the independent original three-pass
transformation. The original test ID and four subtests passed on development
source. That targeted observation does not qualify a later frozen source.

A pure file audit classified all 2,060 original 6923 compile records: 46 names
records had compile/run path collisions; 22 receipt differences were
source-defined `object_inspection` annotations whose raw receipts matched after
removing those report-only fields. The original records and qualification
values remain unchanged. The c815 guard gives all five compilation call sites
a separate namespace, and its 218 actual ZIP-member readbacks cover both phases.
Later successful observations do not restore old overwritten raw bytes.

The [fixed earlier status document](https://github.com/TrillionniumFoundation/Hepta/blob/c815d8e3637bbcabcee0639b95f87d496f133338/docs/CURRENT.md)
retains the detailed prior CI observations, timeouts, interruptions and
source identities. No queued CI run is counted as a pass.

## Repository ownership and cleanup

This index and the generated inventory describe the active tree.
[Development retirements](../review-evidence/hia-native-cleanup-20261111/retired-development-versions.json)
and [historical-report retirements](../review-evidence/hia-native-cleanup-20261111/retired-historical-reports.json)
bind removed paths to exact Git objects, hashes and consumer checks. Old source
and reports remain recoverable through Git history; original failures and
their receipts are preserved.

The additional
[integration-checkpoint retirements](../review-evidence/hia-native-cleanup-20261111/retired-integration-checkpoints.json)
remove eleven superseded staged-delivery narratives, 112,049 bytes, with no
current code, test, package, contract or active-document consumers. Their two
original source-map references are retained unchanged. Current feature
contracts, independent reviews, raw failures, studies and oracles remain.
Common build outputs and Python/tool caches are ignored by the active tree.
The unused 3,555-byte experimental LLVM wrapper emitter was also retired into
the development ledger after confirming no retained caller or source/package
registration. Its historical source-map references remain unchanged.

| Location | Current responsibility |
| --- | --- |
| `hepta/` | Ordinary entry, service, verifier and adapters with actual callers |
| `examples/hia_bootstrap/` | Compiler, library and application build/resource inputs |
| `tools/` and package manifests | Bootstrap, regeneration, qualification and package construction |
| `tests/`, `formal/`, `benchmarks/`, `rust/` | Coverage, independent oracles, supported reference profiles and comparisons |
| `experiments/`, `review-evidence/`, `evidence/` | Consumer-bound frozen inputs, provenance and original observations |

The [retained-directory ownership record](../review-evidence/hia-native-cleanup-20261111/retained-directory-ownership.json)
identifies why the remaining research/evidence directories are required.
They are not installed as product modules. Build outputs and caches are
excluded from source. Hosted modules with current callers remain until a
qualified replacement takes over those callers.

The separate [historical evidence index](HIA_ARCHIVE_PATH_MIGRATIONS.md#current-materialization-limit)
has a materialization gap. Original-Git verification checks all 611 historical
files without restoring obsolete files; current-path verification still
reports 574 missing paths and does not substitute history for a current file.

## Remaining product acceptance

The remaining hosted owners have active consumers; their removal is not
authorized by component test success:

| Boundary | Current owner | Required replacement |
| --- | --- | --- |
| Ordinary CLI and default build | `cli.hia_main`, `hia_program.verify_program`, `hia_program_native` | Preserve all fifteen CLI actions, diagnostics and the complete admitted build profile. The selfhost object route is explicit and bounded. |
| Eleven-tool worker and proofs | `hia_agent_worker`, `HIAAgentService.call`, `_compile`, `_hia_verify` | Preserve request dispatch, proofs, reports and installation-bound backend identities through a native worker. |
| Durable state and replay | `AgentStore`, `_reference_call`, `call_with_native_journal` | Preserve the actual SQLite connection, schema, transactions, exact completed replay and unknown outcomes under the replacement effect owner. |
| Adoption, slots and leases | `_hia_adopt`, `_hia_rollback`, `acquire_slot`, `invoke_lease`, `release_slot` | Complete receipt/context/proof/artifact/ABI admission and actual invocation/effects around the selected HIA ledger. |
| Native execution and process cleanup | `hia_agent_runner.run_native_batch` | Replace the subprocess launched as `sys.executable -m hepta.hia_agent_runner`, including limits, snapshots, termination and report inspection. |
| Resident multiversion runtime | `ScalarMultiversionRuntime`, `GenerationLease`, `hia_native_retirement` | Transfer actual libraries, function references, sealed descriptors and cleanup uncertainty held by optimizer and scalar-state consumers. |
| Release selection and running worker | Native release selector and the separate hosted worker | Connect the selection record to restart, old-request routing, active references, running-image readback and confirmed old-owner retirement. |

`_context`, `_verification`, `_native` and `_build_inputs` bind durable objects
to `installation_manifest`. A changed selection pointer cannot rebind old
contexts, proof receipts or artifacts to new code. Migration must preserve each
old request and generation's original implementation identity until its replay
and live references are finished.

1. Reconcile remaining native owners and ordinary callers, including graph
   payload, helper, slot/version/lease and state authority.
2. Replace the ordinary CLI and worker/service entry while preserving commands,
   diagnostics, rejection behavior and all tool effects.
3. Preserve SQLite stores, in-flight requests, publication references,
   idempotency and unknown outcomes through restart, adoption and rollback.
   Each old request remains bound to its original code identity.
4. Build and install from one frozen source and declared seed; run source,
   actual native, installed-package and complete retained gates on that source.
5. Read back the running worker/backend/catalog/resource identities after
   cutover, exercise recovery, retire replaced hosted owners and validate the
   clean installation.

A selector record or filesystem pointer does not identify an already-running
image. Product activation requires actual installation and process-owner
evidence and remains false.
