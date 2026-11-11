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

All 92 retained language sources use `.hepta`: 69 assembly sources and 23
structured Core sources. There are no active `.HIA`, `.hia`, `.hiaasm` or
`.hia.json` files. Assembly retains its `hia-asm.v1` header, structured Core
retains its explicit schema, and paired JSON projections use `.core.hepta`.
The [87-file migration map](HIA_SOURCE_SUFFIX_MIGRATION.json) preserves each
renamed source byte for byte. The five later assembly sources are new inputs,
not entries fabricated into that historical rename map.

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

- All 43 public builder scripts can resolve their own imports when invoked by
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

The combined source has the distinct profile
`selfhost-core-linux-x86_64-v68-native-source-build-release-selection`.
The [development observations](../review-evidence/hia-native-rewrite-20261111/release-selection-v68-development/README.md)
record 21 passing controls and four actual ptrace-environment failures. The
failed fault-injection controls remain required in CI. These development runs
do not supply a completed cold qualification for the integrated source.

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

The active package therefore has 155 Python modules. This count is an inventory,
not a native-completion percentage. Required hosted modules are retained until
replacement and ordinary-operation equivalence are established.

The two long historical status documents now point here and to their immutable
original Git revisions. Current implementation status is maintained once.
Original failure evidence, registered benchmarks, independent oracles, licences
and fixed compiler fixtures remain available to the tests that consume them.

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
