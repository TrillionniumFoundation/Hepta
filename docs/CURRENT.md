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

This continuation starts from published PR #893, commit
`ec4841212fa97ae98c576b48f8ba1b4815df6122`, tree
`ba5056defe3bfe2052afa16c5fb71c72374d4d8a`. The last independently read main
was `5831f52fada45e076f8f68f198a15c0585e6104f`; a candidate is not main adoption.
The exact current compiler/source identity is the checked
[Selfhost-Core contract](HIA_SELFHOST_CORE_SUPPORT.json).

All 98 current language sources use `.hepta`: 71 assembly sources and 27
structured Core sources. There are no active `.HIA`, `.hia`, `.hiaasm` or
`.hia.json` files. Assembly retains its `hia-asm.v1` header, structured Core
retains its explicit schema, and paired JSON projections use `.core.hepta`.
The [87-file migration map](HIA_SOURCE_SUFFIX_MIGRATION.json) preserves each
renamed source byte for byte. The seven later assembly sources are new inputs,
not entries fabricated into that historical rename map.
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
| Agent service | Selected native identity, request, journal, publication, execution-budget and candidate-attempt kernels | Ordinary worker, eleven-tool service, SQLite effects, recovery and version ownership |
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

- All 45 public builder scripts can resolve their own imports when invoked by
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

This candidate additionally closes these source and component gaps:

- Four structured `.json` examples now use `.hepta`, with byte-identical source,
  updated Python/Rust consumers and active-source checks that reject recurrence.
- The [execution-budget owner](HIA_EXECUTION_BUDGET_NATIVE.md) is integrated with
  both request journals. The [candidate-attempt owner](HIA_CANDIDATE_BUDGET_NATIVE.md)
  is reached from ordinary `hia_candidate`; HIA owns count admission, increment,
  compare-and-swap, exact readback and commit acknowledgement in the original
  database namespace. Existing context and request identities are preserved.
- Both budget sources are included in sdist/wheel resource declarations. The
  candidate route is exercised from a real isolated installed package with
  authoring imports blocked and hosted attempt policy disabled.
- Compiler-stage publication validates exact integer status/extent, source and
  compiler bytes, format and custody observations explicitly, including under
  Python optimization. Failed or ambiguous receipts cannot publish an image.
- Native publication works when Python omits Linux seal constant names, while
  requiring actual kernel seals and exact sealed-code readback before execution.
  Refused sealing closes the descriptor and starts no child.

These native policy selectors remain explicit operator choices. A runtime
source/image manifest is not a cold-qualification certificate. SQLite effects,
wall-clock policy, the complete CLI/worker, slots, leases and adoption authority
remain hosted or separately selected components; their deletion is not yet
supported by this implementation.

The combined source has the distinct profile
`selfhost-core-linux-x86_64-v69-native-candidate-budget`.
The predecessor's [release-selector development observations](../review-evidence/hia-native-rewrite-20261111/release-selection-v68-development/README.md)
record 21 passing controls and four actual ptrace-environment failures. The
failed fault-injection controls remain required in CI. These development runs
do not supply a completed cold qualification for the integrated source.

Original cold limits remain 180 seconds for qualification and 3 seconds for
owned cleanup. A timed-out run remains failed even when another host passes.
Recording compiler/packer stages are custody controls, not native executions.
New code must have its own matching-source cold and native observations.

## Current preflight observations

The integrated source workflow completed **423/423 tests**, with no failures,
errors or skips in 460.977 seconds. The [raw log and source-contract binding](../review-evidence/hia-native-convergence-20261111/source-tests.json)
belong to this integration. These are source/reference controls, including the
new native budget and strict-publication controls; they do not replace the
matching-source cold, native and complete retained regression gates.

The three Rust consumer targets `chain`, `returned_loans` and
`returned_record_fields` returned exit code 0 on the separate Linux host. The
[original durable job observation](../review-evidence/hia-native-convergence-20261111/rust-source-consumers.json)
records the input archive hash, original request identity and completed,
nontruncated log status. Log-body retrieval timed out, so individual Rust test
counts and stdout input-hash readback are not claimed.

### Later checks on the frozen integration

The following successful runs belong to the exact source commit
`5a39a6d8df1bd17b728a1323bd6f4febeabfad71`, with the unchanged
`selfhost-core-linux-x86_64-v69-native-candidate-budget` profile:

| Check | Observed result | Elapsed time |
| --- | --- | --- |
| Local cold self-bootstrap replay | 11/11 checks passed | 166.340746393 seconds |
| Local native language qualification | 1,242/1,242 checks passed; 10 report assertions also passed | 106.262896981 seconds for qualification |
| Local native execution-budget, candidate-budget and publication controls | 49 tests passed | 218.540 seconds |
| [GitHub push source job](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43044847906/job/130605956890) | 423 tests passed | 327.466 seconds |

The language report assertions inspect that completed native observation; they
are not ten additional native executions. The earlier 460.977-second source
run remains a separate observation. These passes establish the stated checks
on their bound source, without qualifying native-only delivery, the complete
installed product or live worker migration.

## Repository cleanup

Two isolated, unused experiments are removed from the active Python package:
`hia_empty_reduction.py` and `hia_result_cache_audit.py`. Repository-wide AST
and textual caller checks found no active production, tool, test or CLI caller.
The empty-reduction document referred to a test module that no longer existed;
that obsolete candidate document is removed as well. This is retirement of
unintegrated experiments, not a claim that they were rewritten in HIA.
Their original source remains in the Git history of the published base.

The isolated `hia_empty_wrapper_candidate.py` LLVM wrapper experiment is also
removed from `tools/`. It had no current production, tool, test or CLI caller and was
absent from the cold-source contract and installed-resource lists. Its remaining
references were historical source inventories. This deletes an unused experiment;
it does not replace any ordinary emitter with HIA. The original implementation
and its negative observations remain available in Git history and retained evidence.

The active package currently has 158 Python modules, including the new native
budget adapters and retained hosted reference. This count is an inventory,
not a native-completion percentage. Required hosted modules are retained until
replacement and ordinary-operation equivalence are established.

Six superseded progress and deployment reports have been removed from the active
documentation tree. Their exact earlier revisions are linked below. README
links now lead to this current-state index instead of presenting a dated
deployment observation as the current installation. Historical source manifests
still identify the original paths and bytes; they are not rewritten to describe
this cleanup.

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

Three concrete dependencies prevent retiring the remaining hosted implementation:

- Ordinary `hia build` calls `build_program_machine`, and the Agent service's
  `hia_emit` calls `_compile`; both reach the Python `emit_program_machine`
  and `_Emitter` in [the production native backend](../hepta/hia_program_native.py).
  The bounded HIA selfhost compiler does not own these ordinary emission routes.
- Ordinary `hia_evaluate` runs both baseline and candidate through
  `run_reference_batch` before comparing their native observations. The
  [production runner](../hepta/hia_agent_runner.py) calls the hosted Core VM
  through `_vm_observation` in [the Agent service](../hepta/hia_agent_service.py).
  This VM participates in the actual evaluation decision and cannot be removed
  as an unused test oracle.
- [Installation identity](../hepta/hia_agent_contract.py) hashes every actual
  production Python module and the declared resources. Existing contexts,
  artifacts and receipts bind that identity; session and context checks reject
  changed implementations. Removing or replacing those modules requires an
  explicit identity and durable-state migration, preserving existing requests
  and active versions through restart, adoption and rollback.

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
similar profile label. It contains separate namespace, execution-budget,
request-journal, retirement, individual nominal-operation and value-graph
owners. PR #893 contains another journal owner, raw nominal JSON and native
source-build components. Their shared build-custody fixes are integrated here;
the remaining owners still require deliberate ABI/state/authority reconciliation.
Deleting either branch's unique implementation is not an integration strategy.
The separate in-progress worker/helper and slot/version/lease worktrees were
not modified by this continuation.

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
