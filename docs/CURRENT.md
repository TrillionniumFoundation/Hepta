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

Publication is tracked in
[draft PR #893](https://github.com/TrillionniumFoundation/Hepta/pull/893).
A published branch is source availability; runtime adoption requires the
separate controls below.

## Implementation boundary

| Area | Implemented capability | Remaining boundary |
| --- | --- | --- |
| Self-compilation | HIA scanner, parser, checker and x86-64 emitter; original/modified-source fixed points | Explicit seed, bounded language/target profile and allocator assumptions |
| Applications and source build | Core checking/patching, workspace operations, native stdio, ELF linking, release installation and assembly source/image self-pack | Common ordinary entry, general structured-project build and complete installed lifecycle |
| Nominal and JSON operations | Selected type/helper/function/constructor/outer owners and raw JSON codecs | Default routing, diagnostics and all foreign-object/state transfers |
| Worker helpers and retained state | Pinned native identity/request/journal/budget/retirement helpers and ordinary snapshot/patch factory views | Hosted transport, SQLite effects, process/resource ownership and complete service migration |
| Slot, version and lease state | HIA ledger kernel with a hosted store/effect adapter | Matching-source qualification, ordinary-worker equivalence and durable restart/adoption/cutover |
| Release selection | Immutable installation, compare-and-swap selection, previous-release rollback and status | Running-worker identity, active references, restart and old-owner retirement |

The selfhost profile is bounded Linux x86-64. It does not establish
whole-language formal correctness or admission of every general Core program.
The ordinary entry remains `hia = hepta.cli:hia_main`. Its worker serves the
eleven-tool protocol through hosted owners and selected native adapters; the
five-command [native stdio application](HIA_AGENT_STDIO_NATIVE.md) has a separate
protocol.

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
