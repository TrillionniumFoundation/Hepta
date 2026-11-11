# HIA: current implementation and acceptance

This is the single current-state index for the HIA language and toolchain.
The repository is `TrillionniumFoundation/Hepta`. Dates in this audit are
2026-11-11, America/New_York. The product name is HIA; the source suffix is
lowercase `.hepta`.

**Whole-product native replacement remains incomplete.** The current source
has real HIA self-compilation and native applications, but the ordinary CLI,
Agent service and persistent transaction owners still require hosted code.
`whole_native_delivery_qualified` and `production_activated` remain false.

## Source identity and naming

The continuation starts from published PR #893, commit
`5b4e3fc2d0271ee955000f445cc078aa85abe01c`, tree
`0489ce78455c536a9ba29b4af5a9d8b8a886066a`. The last independently read main
was `5831f52fada45e076f8f68f198a15c0585e6104f`; a candidate is not main adoption.
The exact current compiler/source identity is the checked
[Selfhost-Core contract](HIA_SELFHOST_CORE_SUPPORT.json).

All 95 current language sources use `.hepta`: 70 assembly sources and 25
structured Core sources. There are no active `.HIA`, `.hia`, `.hiaasm` or
`.hia.json` files. Assembly retains its `hia-asm.v1` header, structured Core
retains its explicit schema, and paired JSON projections use `.core.hepta`.
The [87-file migration map](HIA_SOURCE_SUFFIX_MIGRATION.json) records the original
byte-for-byte rename. Four sources in an obsolete experiment snapshot were
subsequently retired with their exact Git objects preserved in the cleanup
ledger. The eight later assembly sources are new inputs, not entries fabricated
into that historical rename map.
Four existing structured examples whose names ended in plain `.json` are also
renamed byte for byte. Their Python and Rust consumers use `.hepta`; the source
gate rejects program/composite JSON documents with a `.json` suffix in current
example, test, formal and benchmark trees. Frozen experiment programs and
receipts retain their original names and bytes.

The [source suffix contract](HIA_SOURCE_SUFFIX.md) explains whole-program
admission, package resources and the exact historical-name projections. Old
patch archives and registered protocols keep their original bytes and hashes.
The `hia` executable and `hepta.hia.*` schema names are unchanged.

## What is implemented

| Area | Current implementation | Remaining product obligation |
| --- | --- | --- |
| Source checking | Typed assembly and structured primitive/composite Core; resource and control-flow checks | Full checker implementation still has a hosted owner outside the qualified selfhost subset |
| Self-compilation | HIA scanner/parser/checker/x86-64 emitter; B1/B2/B3 and modified-source fixed-point gates | Explicit seed toolchain, bounded language/target profile and allocator assumptions remain |
| Standalone applications | Native stdio, Core verification/patching, workspace filters, static ELF linking, release installation | Common ordinary entry and complete installed lifecycle |
| Native source build | Assembly bundle admission, embedded compiler and source/image self-pack in HIA | General structured-project build and initial bootstrap custody remain hosted |
| Nominal Core | Selected type/helper/function/constructor/outer owners; raw JSON codec | Complete default routing, diagnostics and foreign-object/state transfer |
| Agent service | Selected native identity, request, journal and publication kernels | Ordinary worker, eleven-tool service, SQLite effects, recovery and version ownership |
| Worker helper selection | One pinned bundle routes existing helpers and current journal v2 through ordinary callers | Worker transport, service methods and SQLite remain hosted |
| Execution budgets | Native decimal accounting, claim/completion and unknown-outcome fencing use the original SQLite rows through both request journals | SQL durability, process execution and confirmed termination remain hosted |
| Candidate attempt budgets | Native count admission, increment and commit acknowledgement update the original context row | Context/profile authority, wall budget and actual candidate semantics retain their existing owners |
| Resource retirement | Native retained state owns identity observations, one-time release claims and retry decisions | Foreign handles, actual system calls, version transfer and durable recovery remain hosted |
| Release selection | Native immutable installation, compare-and-swap activation, previous-release rollback and status | Actual worker cutover, active references, service restart and old-owner retirement |

The selfhost compiler is a bounded Linux x86-64 profile. It is not a proof of
whole-language formal correctness or support for every general Core input.
The ordinary command remains `hia = hepta.cli:hia_main`; the five-command native
stdio application is a distinct protocol and does not replace all ordinary
commands or the eleven-tool service.

## Changes in this continuation

The `.hepta` migration is retained. This continuation restores build-source
checks from the separately reviewed v67 integration source
`5d5424a31caa33283a562defba9cb6b187deb99c`, adapting only physical source names.
It does not overwrite either parallel candidate's native language semantics.

- All 46 public builder scripts can resolve their own imports when invoked by
  absolute path from an unrelated directory with Python `-I` and no PYTHONPATH.
- SHA builders require the shared strict cold/profile/compiler/full-source gate
  before creating output. The two SHA algorithms and native manifests are unchanged.
- Standalone builders bind captured source bytes to the admitted source map,
  retain consumed image/manifest bytes and recheck them before publication.
- The shared kernel builder rechecks its generated image after complete-source
  readback. A changed image cannot acquire a fresh manifest merely by being
  hashed after substitution.
- Missing-source, changed-packer, changed-manifest and changed-source controls
  are registered in the source CI and frozen support contract.
- The independent [native release selector](HIA_RELEASE_SELECTION_NATIVE.md)
  is integrated from the same reviewed source. Its two HIA programs retain
  their exact bytes, installed-release verifier, limits, refusal policy and
  durable record format. It adds activation, previous-release rollback and
  restart status without changing the ordinary worker or its slot/lease state.
- The ordinary worker accepts one explicitly pinned bundle with 23 actual
  single-image adapters, including the current journal v2, execution budget,
  candidate attempt budget and retirement state.
  It refuses ambient selectors, cross-process/thread reuse and post-effect
  identity drift; recovery observes the original operation before retrying.
- Native execution budgets preserve the original database/WAL namespace,
  Decimal limits, request identities and uncertain cost through restart.
- Native candidate budgets retain `main.contexts.attempts`, the public 4,096
  maximum and original request replay. A lost commit acknowledgement cannot
  refund or repeat the attempt. Failed service/store construction closes the
  actual budget connections while preserving the primary error.
- Retained retirement state is integrated into the original resource and
  multiversion owners. The existing 69-case retained suite executes with the
  old policy functions refused; foreign resources still have their actual
  process owners.
- Native publication verifies actual kernel memfd seals before execution,
  including on Python builds that omit the symbolic Linux constants. Native
  compiler publication also requires exact typed receipts and unchanged input
  and compiler bytes under optimized Python.
- The public workspace compilation bridge also verifies complete kernel seals
  before executing its captured HIA pipeline. Missing symbolic Python constants
  use the Linux UAPI values; incomplete seal readback refuses execution and
  closes the owned descriptor before any output is published.
- Every Core CI unittest group requires a nonempty declared suite, exact
  execution count and zero anomalies. Empty or incomplete success reports,
  skips and expected failures cannot qualify a component. The existing test
  modules, native requirements and resource limits are unchanged.

The combined source has the distinct profile
`selfhost-core-linux-x86_64-v69-native-worker-state-owners`.
Component development records retain their exact source identities. They do
not supply a completed cold qualification for a later integrated source.

The earlier published `ec484121` candidate passed all jobs in
[PR Core run 43037991627](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43037991627).
Its original cold record reports all eleven checks true in 103.804160179 seconds;
all 671 source-manifest entries match the published Git objects. The release
selection and review group passed 25/25 actual controls. The
[original successful evidence](../review-evidence/hia-native-rewrite-20261111/ci-ec484-pr-success/summary.json)
remains distinct from later source observations.
The same source's [push run 43037976912](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43037976912)
timed out at 180.195200988 seconds. Its timeout, partial nested result and
successful owned cleanup remain separate observations. Four actual
release-selection strace fault controls also passed on the matching source
on `rog`; its development B0/B1/B2 fixture is not a cold qualification.
The local ec484 comprehensive run completed 28 stages, then its execution
session disappeared before the ordinary-journal or final receipt was written.
Its complete pinned source still matches the initial snapshot, but that run is
[held as interrupted](../review-evidence/hia-native-rewrite-20261111/ec484-interrupted/interruption-observation.json),
not called a completed retained regression. Its cause is not established.

Original cold limits remain 180 seconds for qualification and 3 seconds for
owned cleanup. A timed-out run remains failed even when another host passes.
Recording compiler/packer stages are custody controls, not native executions.
New code must have its own matching-source cold and native observations.

## Repository cleanup

Two isolated, unused experiments are removed from the active Python package:
`hia_empty_reduction.py` and `hia_result_cache_audit.py`. Repository-wide AST
and textual caller checks found no active production, tool, test or CLI caller.
The empty-reduction document referred to a test module that no longer existed;
that obsolete candidate document is removed as well. This is retirement of
unintegrated experiments, not a claim that they were rewritten in HIA.
Their original source remains in the Git history of the published base.

The active package has 161 Python modules, including the explicit
[native helper bundle adapter](HIA_NATIVE_HELPER_WORKER.md). This count is an inventory,
not a native-completion percentage. Required hosted modules are retained until
replacement and ordinary-operation equivalence are established.

Six superseded progress and deployment reports have been removed from the
active documentation tree. Their exact earlier revisions are linked below.
README points to this single current-state index. The duplicate active-module
report is removed; the complete repository inventory is maintained once.

The [AST and textual caller inventory](HIA_NATIVE_REWRITE_INVENTORY.json) found no further demonstrated unused
production module. `__main__` is the module entry, `hia_agent_exec` is launched
by the native program bridge, and `hia_core_api` is exercised in an isolated
subprocess fixture. They must remain. Repository suffix checks
cover tracked sources and package resources; ordinary file input remains
content-based and can read a valid program supplied under another suffix.

Sixty superseded snapshot directories and seven old qualification, preparation
and source-check scripts are removed from the current tree: 1,022 files,
90,691,056 bytes. The [retirement ledger](../review-evidence/hia-native-cleanup-20261111/retired-development-versions.json)
binds each retired path to its unchanged original Git object at `ec484121` or
`06b1e9b2`. Historical documentation links point to those fixed Git snapshots.
The current entry is `run_hia_qualification_v4.py` with its adjacent
`workflow_process.py`. Current runtime, tests, CI and declared source inputs
have no consumer of the retired physical files. The
[retained-directory ownership record](../review-evidence/hia-native-cleanup-20261111/retained-directory-ownership.json)
identifies the actual callers and input provenance for the 31 retained research
and evidence directories. Required NDU archives, registered research inputs and
model provenance remain in their declared paths.

The remaining directories have distinct current responsibilities:

| Path | Responsibility | Cleanup boundary |
| --- | --- | --- |
| `hepta/` | Ordinary CLI, Agent service, verifier and selected native adapters | Hosted production owners remain required until their ordinary callers have qualified native replacements. |
| `examples/hia_bootstrap/` | Checked `.hepta` compiler, library and standalone application inputs | These are build and installed-resource inputs, including files named as examples; they are not disposable demos. |
| `tools/`, `setup.py`, `pyproject.toml`, `MANIFEST.in` | Bootstrap, source regeneration, qualification and explicit package construction | Build/reference tools are separate from native runtime execution. Removing them requires a replacement build and qualification path. |
| `tests/`, `formal/`, `benchmarks/` | Regression callers, independent checks and registered comparison inputs | Keep the existing coverage and negative controls when replacing an implementation. |
| `experiments/`, `review-evidence/`, `evidence/` | Frozen source observations, original failures and retained fixtures | Some are read by current tests and source contracts. They are not installed as package modules, and wholesale deletion would break retained checks. |
| `rust/` | Explicit reference and research implementations | These are distinct supported profiles; their removal requires an explicit scope change and replacement of their callers. |

`setup.py` packages the `hepta` modules and only the resources declared by the
Agent contract. It does not install the experiment or review-evidence trees as
product modules. Build outputs and Python caches are already excluded by
`.gitignore`; cleanup of another worktree's running qualification output is not
part of source retirement.

The cleanup leaves original failure evidence, registered benchmarks, independent
oracles, licences and fixed compiler fixtures unchanged. The separate
[611-file historical evidence index](HIA_ARCHIVE_PATH_MIGRATIONS.md#current-materialization-limit)
has an existing working-tree materialization gap: the published base and cleanup
worktree both report 574 missing paths. Explicit verification of its
[original Git snapshot](HIA_ARCHIVE_PATH_MIGRATIONS.md#verify-historical-bytes-without-restoring-old-files)
now checks all 611 files and 26,120,286 bytes against the original hashes without
restoring old files. Current-path mode still fails on missing paths and never
falls back to history; the two observations remain distinct.

### Earlier reports

These links preserve earlier observations at immutable commits. Their test
counts, source identities, deployment pins and limitations belong to those
observations, not to the current checkout.

| Earlier report | Preserved revision |
| --- | --- |
| Native closure progress, 2026-11-11 | [Original report at `5b4e3fc2`](https://github.com/TrillionniumFoundation/Hepta/blob/5b4e3fc2d0271ee955000f445cc078aa85abe01c/docs/HIA_NATIVE_CLOSURE_20261111.md) |
| Native rewrite progress, 2026-11-11 | [Original report at `5b4e3fc2`](https://github.com/TrillionniumFoundation/Hepta/blob/5b4e3fc2d0271ee955000f445cc078aa85abe01c/docs/HIA_NATIVE_REWRITE_STATUS_20261111.md) |
| Product closure candidate, 2026-11-07 | [Retained report at `ec484121`](https://github.com/TrillionniumFoundation/Hepta/blob/ec4841212fa97ae98c576b48f8ba1b4815df6122/docs/HIA_PRODUCT_CLOSURE_20261107.md) |
| Product follow-through and original failures, 2026-11-07 | [Retained report at `ec484121`](https://github.com/TrillionniumFoundation/Hepta/blob/ec4841212fa97ae98c576b48f8ba1b4815df6122/docs/HIA_PRODUCT_FOLLOWTHROUGH_20261107.md) |
| Runtime compatibility observation, 2026-11-10 | [Retained audit at `ec484121`](https://github.com/TrillionniumFoundation/Hepta/blob/ec4841212fa97ae98c576b48f8ba1b4815df6122/docs/HIA_RUNTIME_COMPATIBILITY_AUDIT_20261110.md) |
| Core-only cleanup and its fixed-source acceptance, 2026-11-10 | [Retained report at `ec484121`](https://github.com/TrillionniumFoundation/Hepta/blob/ec4841212fa97ae98c576b48f8ba1b4815df6122/docs/HIA_REPOSITORY_CLEANUP_20261110.md) |

## Runtime integration

The ordinary installed command is still `hia = hepta.cli:hia_main`. The
[ordinary worker](../hepta/hia_agent_worker.py) implements the eleven-tool
request/report service through hosted transport, durable store and selected
native adapters. The separate five-command
[native stdio application](HIA_AGENT_STDIO_NATIVE.md) implements another
protocol. Installing its executable does not replace the ordinary worker.

The [Agent runtime contract](HIA_AGENT_NATIVE_RUNTIME_CONTRACT.md) and
[installed-resource contract](HIA_NATIVE_INSTALLED_SOURCE_BINDINGS.md) describe
the current source interfaces. A dated deployment observation or a matching
catalog hash does not identify the code currently executing on a machine.
Runtime migration must therefore establish all of the following on the actual
selected installation:

1. Build and install from one frozen source, then read the actual worker,
   backend, catalog and native-resource identities from that installation.
2. Bind native-helper selection to the administrator-owned runtime profile and
   allowed resources. Ambient environment variables and model arguments do not
   authorize executable replacement.
3. Verify the original request/report protocol and all ordinary tools through
   the real process owner, including diagnostic and rejection behavior.
4. Preserve the existing durable stores, original request identities, unknown
   outcomes, in-flight operations and active version references across restart,
   adoption and rollback. An old operation remains bound to its original code
   identity; changed pins do not authorize replay under a new request key.
5. Read back the running worker identity after cutover and exercise recovery.
   A release-selector record or a filesystem pointer alone does not prove
   which image an existing process is using.

The [release selector](HIA_RELEASE_SELECTION_NATIVE.md) has its own durable
activation and rollback protocol. It does not establish these service migration
conditions. `production_activated` remains false for this candidate.

## Parallel implementation inventory

The v67 integration at `5d5424a3` is not the same source as PR #893 despite its
similar profile label. Its execution-budget and retirement owners are now
integrated with the current request journal. Its separate namespace,
request-journal, individual nominal-operation and value-graph owners still
require deliberate ABI/state/authority reconciliation with the current nominal
pipeline, raw JSON codec and native source-build components.
Deleting either branch's unique implementation is not an integration strategy.
The worker/helper integration reuses the reviewed helper block without
modifying its original worktree. The independent slot/version/lease candidate
still requires state and journal reconciliation.

## Remaining acceptance work

1. Reconcile the remaining parallel native owners into one source identity,
   including graph payload binding, helper interfaces and slot/version/lease state.
2. Replace the ordinary CLI and worker/service entry, including all supported
   commands, error semantics and tool effects.
3. Preserve existing SQLite state, in-flight requests, publication references,
   idempotency and recovery through actual restart, adoption and rollback.
4. Rebuild/install the complete selected product from the declared seed and
   source; establish the supported platform and allocator boundary explicitly.
5. Run source, actual native, installed-package and complete regression gates
   on the same fixed candidate, then exercise the deployed runtime entry.
6. Remove the replaced hosted owners after ordinary callers no longer depend
   on them, and validate the final clean installation again.

None of these remaining obligations is satisfied by renaming a source file,
counting a historical pass or deleting an implementation that is still called.
