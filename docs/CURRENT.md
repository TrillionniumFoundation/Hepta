# HIA: current implementation and acceptance

This is the current-state index for `TrillionniumFoundation/Hepta`. The language
is HIA and its canonical source suffix is lowercase `.hepta`.

**The suffix migration is on main. Whole-product native replacement remains
incomplete.** `whole_native_delivery_qualified=false`,
`old_stack_can_be_removed=false`, and `production_activated=false`.
The ordinary `hia` executable is still the Python-hosted
`hepta.cli:hia_main` entry. Selected HIA machine-code paths and their successful
qualification do not remove the remaining hosted service, storage and runtime
owners.

## Audited main and source naming

The audited production-source baseline is
[`f33d8da316de8fdf27b504371f1a5310997ff548`](https://github.com/TrillionniumFoundation/Hepta/commit/f33d8da316de8fdf27b504371f1a5310997ff548),
Git tree `378bc0dc613befc7006f1514bd2229357ae0d07c`, observed on
2026-11-13. Its complete recursive Git tree contains:

| Inventory scope | Count |
| --- | ---: |
| Tracked regular-file blobs | 2,580 |
| Total tracked blob bytes | 72,216,393 |
| HIA source files ending in `.hepta` | 178 |
| Files ending in `.HIA`, `.hia`, `.hiaasm` or `.hia.json`, including case variants | 0 |
| Production Python modules directly under `hepta/` | 186 |
| Python files across the complete retained tree | 1,150 |

These are file counts for that exact baseline, not percentages of implemented
behavior. The source gate has its own retained-source scope: its original
report counts 1,142 Python files, 186 package modules and the same 178 HIA
sources. The eight-file difference must not be silently combined with the
whole-tree inventory.

The migration entered main at
[`51bc24b8b03e5adc3da1b2b3490ad5cc7357e8d8`](https://github.com/TrillionniumFoundation/Hepta/commit/51bc24b8b03e5adc3da1b2b3490ad5cc7357e8d8).
The older `5831f52fada45e076f8f68f198a15c0585e6104f` snapshot and old PR base
metadata are not the current main ref. The
[suffix contract](HIA_SOURCE_SUFFIX.md) and
[original migration map](HIA_SOURCE_SUFFIX_MIGRATION.json) retain the exact
rename provenance. Assembly keeps `hia-asm.v1`; structured Core keeps its
explicit schema. Paired structured projections use `.core.hepta`. The `hia`
command, `hepta.hia.*` protocol schemas and historical receipt bytes retain
their recorded identities.

## Verified main qualification

The original [HIA Core-only run 43375258419](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43375258419)
checked out the exact `f33d8da` commit in both jobs. The workflow and its
original job logs are terminal SUCCESS:

| Original gate | Observed result and boundary |
| --- | --- |
| [Source job 131720135787](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43375258419/job/131720135787) | Regeneration and contract checks passed with a clean generated diff; 530 source tests passed in 464.822 seconds. The source report explicitly retains `whole_native_delivery_qualified=false`. |
| [Native job 131720136029](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43375258419/job/131720136029) | Every declared step completed successfully, including the cold gate, original callers, installed component controls and final evidence upload. No later native step was skipped. |
| Current-source cold replay | 11/11 outer checks passed; original B1/B2/B3 SHA-256 values agree, and the modified M2/M3 values agree. The original 180-second qualification and 3-second cleanup limits remain. |
| Language coverage | 1,242/1,242 reported checks and the separate ten report assertions passed. This remains the declared bounded selfhost language profile. |
| Ordinary journal and JSON-wire callers | The original 94 journal callers and 89 JSON-wire callers passed; both reports record all eleven tools. They exercise explicitly selected native owners while retaining the stated foreign effects. |
| [CodeQL run 43375258558](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43375258558) | The C/C++, Actions, Python and Rust jobs all completed successfully. |

Test groups overlap. Component counts, caller counts, language witnesses and
cold checks are not summed into a unique-test total. This is the result of the
original source-bound workflow; it is not a claim that the complete retained
regression suite, an installed default native service or a running-worker
migration executed on every later commit. A documentation-only successor does
not relabel these executions as tests of its entire later tree.

## Current repair candidate

[PR #895](https://github.com/TrillionniumFoundation/Hepta/pull/895) applies the
packer, source-gate, recursive-chain and Store-initialization repairs described
below. Its published `f44c09fcc2c1cec25867c886ff477e83df774561` source passed all
573 Source tests in 895.122 seconds in the original
[push Source job 132014867892](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43463079021/job/132014867892).
The separate [PR Source job](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43463098159/job/132014933545)
also succeeded. This is not a whole-native acceptance.

The same source tree `c9d2e855ebd1eefb45163152786aff2ab0120ca0` had different
cold outcomes in the two original workflows. Push cold completed; the
[PR Native job](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43463098159/job/132014933923)
timed out after 180.212952258 seconds with 36/38 independent phases complete.
The two explicit-traps phases were incomplete. The owner returned -9 and
confirmed complete cleanup within the original three-second cleanup limit.
The original failed artifact `14055954670` and all later skipped stages remain
a failure; the push observation does not replace that result.

The next change reuses the existing HIA linked-ELF observer from published
development commit `a733926a2786a3d4a37304bd2d18ebb2eac57ac9`, with canonical
`.hepta` paths. Its HIA policy controls admission, resource-limit requests,
loader continuation, result construction and output snapshots; its HIA packer
emits the complete relocatable object. Every qualification call execs fresh
sealed bytes and loads the complete sealed target through the real system
dynamic loader. Independent pre-B0 VM/object observations, the original
seed/generation loader, libc startup/finalization, source readback, traps and
original deadlines remain explicit dependencies and controls.

The [reuse and admission evidence](../review-evidence/hia-native-cleanup-20261111/linked-observer-reuse.json)
records exact original blobs, current source hashes and original observations.
All 31 component tests passed, with 59 paired observations and 62 actual
entries through each loader. The additional admission controls first exposed
five malformed receipts reaching object publication, then passed after using
the same complete receipt check as the other packers. These publication tests
use explicit nonexecuting fixtures. The 68-test integration group passed 67
tests and failed its real cold replay at 180.476719175 seconds, with 19/38
phases complete, zero phase exceptions and complete cleanup. That original
test automatically removed its temporary cold directory; the complete test
log and its original diagnostic are retained, not a complete raw cold archive.
Neither component success nor this source change is labelled a cold pass.
The original CI now runs the linked-observer controls against its own admitted
current-source cold compiler and archives their evidence.

## Current native implementation

| Area | Implemented selected path | Remaining boundary |
| --- | --- | --- |
| Compiler | HIA scanner, parser, checker and x86-64 emitter; original and modified-source fixed-point controls | Trusted Python seed/build driver, bootstrap tools and the bounded Linux x86-64 language/target/allocator profile |
| Machine and Core backend | Native instruction bytes, Code state/instructions, plans, Core lowering/emitter, borrowed-byte wrappers and ELF object control through original callers | Builtin-object observation, retained default routing, complete general backend equivalence and foreign-resource custody |
| CLI | Explicit two-image HIA owner for all fifteen ordinary actions, argument/help/errors, sequencing and selfhost-build selection | Ordinary entry, semantic action effects, file policy and successful pretty-JSON presentation remain hosted |
| Native stdio | Six commands: capabilities, verify, compile, render-assembly, assemble and check-assembly | Separate bounded protocol, not the complete fifteen-action CLI or eleven-tool service |
| Core applications | Core/JSON/workspace/patch helpers, nominal type/task/function helpers, ELF linker and source-build applications | Complete ordinary product routing, foreign-object/packet custody and broader diagnostic/support domains |
| Worker and scheduling | Selected request/report/wire images, pinned helper custody and five native in-process scheduling families | Hosted outer handler, object transport, installation/hash IO, process effects and complete service migration |
| State and policy | Native request/journal/identity/budget/slot/retirement decisions with original callers | SQLite transactions, durable IO, proof services, actual leases and foreign resource release |
| Release lifecycle | Immutable installation, CAS selection/rollback/status and coherent selected-release verification | Running-worker restart/handoff, actual image readback, outstanding requests/references and confirmed retirement |

The [selfhost object build](HIA_PROGRAM_SELFHOST_BUILD.md) consumes sealed,
operator-pinned native frontend/compiler bytes without a Python emitter
fallback. Default build and `hia_emit` still retain the direct Python emitter;
`hia_evaluate` retains the Python reference VM. The bounded selfhost profile
does not establish general Core equivalence or whole-language formal
correctness.

The [native stdio entry](HIA_AGENT_STDIO_NATIVE.md) includes direct
`check-assembly`, with its 1 MiB input ceiling and plus-one refusal. Selected
[release verification](HIA_RELEASE_SELECTION_NATIVE.md) holds a shared lock
while checking the installed bytes and exact selection identity; it does not
identify the running worker. The
[worker policy/custody contract](HIA_WORKER_REPORT_NATIVE.md) keeps the hosted
adapter and durable effects explicit. Selected JSON wire owns traversal,
budgets, key admission/collisions, ordering, Unicode escapes and number output;
Python still observes builtin-object facts and transports children, codepoints
and limbs. Arbitrary renderers and foreign option behavior remain outside that
native profile.

The generated [support contract](HIA_SELFHOST_CORE_SUPPORT.json) identifies
the exact admitted inputs. It is not an execution receipt or proof that all
runtime owners have been replaced. Empty-selector refusals, source/image
binding, independent references, resource limits and cleanup obligations remain
part of the existing contracts.

## Remaining product acceptance

| Required closure | Existing owner/effect that still needs a complete replacement |
| --- | --- |
| Ordinary CLI and full build profile | `cli.hia_main`, `verify_program`, `hia_program_native`, their semantic effects and complete diagnostics |
| Eleven-tool worker and proof/backend admission | `hia_agent_worker`, `HIAAgentService.call`, `_compile`, `_hia_verify`, hosted wire/catalog/dispatch and solver/proof obligations |
| Durable effects and replay | `AgentStore` SQLite/WAL, atomic multi-table transactions, request journals, exact replay and unknown outcomes |
| Adoption, rollback, slots and leases | Complete receipt/context/artifact/ABI admission, actual invocation and outstanding generation references |
| Native execution ownership | `hia_agent_runner` process setup, environment/limits, snapshots, termination and complete report checking |
| Resident runtime | `ScalarMultiversionRuntime`, `GenerationLease`, loaded libraries, sealed descriptors and cleanup uncertainty |
| Final cutover | Clean installation/default startup, migration of installation-bound old contexts/requests, restart/handoff, running-image readback and confirmed retirement |

Source generation, matching-current-source cold qualification, installed/native
caller tests, the complete retained suite and actual running-worker adoption
are separate gates. Existing Python modules participate in installation
identity and still have static, dynamic or public consumers. Their deletion
before replacement would remove working behavior and change durable identities.
Each replacement must preserve its real callers/effects and original request
identities across recovery before the former owner is retired.

## Parallel development references

The following are separate development lines, not interchangeable production
snapshots. Their PR descriptions include later detached candidates and evidence
commits; a PR head alone does not identify every referenced experiment.

| Development line | Source-bound continuation |
| --- | --- |
| [PR #888](https://github.com/TrillionniumFoundation/Hepta/pull/888) | CLI/machine/wire and SQLite byte-algorithm work. Its recorded component successes do not qualify the complete SQL transaction/pager/locking service or close its failed original caller budgets. |
| [PR #889](https://github.com/TrillionniumFoundation/Hepta/pull/889) | Union of current main and the separate native-owner development line, including launcher, process/stdio, Store and CLI owners. [R6 candidate cec2f44b](https://github.com/TrillionniumFoundation/Hepta/commit/cec2f44bd4bc0d12298a0282c1eb8ce1d7a7b95f) retains main and development as ordered parents; its [Core run 43430503183](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43430503183) failed in native launcher preparation. |
| [PR #893](https://github.com/TrillionniumFoundation/Hepta/pull/893) | Divergent native component/SQLite integration at `831110b8659a48bf9636997212ca67d5360530f9`. Its [push run 43305434289](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43305434289) passed source/native; its separate [PR run 43305453525](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43305453525) failed at cold and skipped subsequent native stages. Both results remain. |

The #889 [R7/R4 Source run 43451128811](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43451128811)
completed 1,274/1,274 tests with identical planned, started and finished IDs,
zero anomalies, and 1,060.561643572 seconds of test execution. Its generated
candidate tree is `f2bc61c11104136d3f56e3c4aefa00a4dada910b`; the harness commit
`d826ae55a999f0e3f2301c28c9c781eb30fcf374` is a different identity. That run
executed zero native or cold qualification jobs and did not publish a candidate
commit or change a product ref. It does not qualify a native replacement.
The subsequent [R9 Source run 43455699432](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43455699432)
failed: 1,306 planned, started and finished IDs agree; 1,305 passed and one
failed, with no error or skip. Its actual candidate tree is
`a76ebf7e393b9e1472e289235fcac3df326366a3`. The archive-coverage assertion found
that `hia-linux-process-matching-cold` was absent from the main evidence
archive, although a separate upload step included it. That run published no
candidate commit/ref and executed no native or cold qualification. These
active branches and their original artifacts must be reconciled before
combining changes or retiring duplicate implementations.

## Repository ownership and cleanup

The active tree uses canonical `.hepta` paths and ignores build/cache output.
Numbered current source units are parts of their declared multi-image programs;
their filenames alone do not identify obsolete versions. Independent oracles,
fixtures, recovery inputs and original failure evidence also have active
consumers.

The [retained static inventory](HIA_NATIVE_REWRITE_INVENTORY.json) records its
own Git/source context and current indexed-file bytes; its parent HEAD and
explicit changed-path lists are not the later commit identity. The
[completion audit](../review-evidence/hia-completion-20261112/) likewise retains
its historical source identity. Their counts must not replace the baseline
inventory above. The prior
[development retirements](../review-evidence/hia-native-cleanup-20261111/retired-development-versions.json),
[historical report retirements](../review-evidence/hia-native-cleanup-20261111/retired-historical-reports.json)
and [integration checkpoint retirements](../review-evidence/hia-native-cleanup-20261111/retired-integration-checkpoints.json)
record exact removed paths, hashes, Git objects and consumer checks. They do
not establish retirement of the remaining production stack.

The current cleanup also closes concrete admission gaps. The shared unittest
runner, complete-increment gate and execution-observation caller gate require
each declared selector to resolve to distinct tests before execution;
the complete-increment gate checks every raw HEAD blob and executable mode,
including changes hidden by Git index flags. The existing recursive-chain
module now executes 17 resource, cancellation and rejection controls against
the retained `.hepta` fixtures. Its inputs and the original execution-observation
callers, transitive helpers and actual C/Rust reference inputs are bound into
the selfhost contract. These are source-custody and reference controls, not a
whole-runtime native qualification.

All twelve standalone packers using the shared native invocation now reject
nonzero ABI status, noncanonical return length, changed input/image identities
and changed output bytes before publishing an ELF. The
[native packer admission evidence](../review-evidence/hia-native-cleanup-20261111/native-packer-admission.json)
retains the original three real native failures, their fixed rejection controls
and three zero-status controls. Compiler/cold setup for those isolated controls
is explicitly a fixture; those executions do not claim matching-current-source
cold qualification. Two obsolete, unconsumed process tools were retired with
their Git objects and hashes. Current upstream benchmark consumers now verify
their retained HIA fixtures instead of depending on a removed capture tool.

The [Store initialization custody evidence](../review-evidence/hia-native-cleanup-20261111/store-initialization-custody.json)
preserves a separate real SQLite failure: three failed constructions retained
three database descriptors until cyclic garbage collection. The existing
failure handler now covers every initialization operation after the connection
opens. The original database error, bytes and inode remain intact; the failed
connection closes immediately. Normal WAL/FULL initialization, transactional
artifact persistence and reopening have separate real SQLite controls. This
repairs the current hosted owner and does not claim native SQLite replacement.

This index replaces the repeated version-by-version current-status narrative.
The [previous full index at f33d8da](https://github.com/TrillionniumFoundation/Hepta/blob/f33d8da316de8fdf27b504371f1a5310997ff548/docs/CURRENT.md)
preserves its exact wording, source hashes, failed development observations and
earlier pending states. No original evidence file is rewritten by this update.

## Preserved historical results

Cold qualification keeps the original 180+3-second limits and all independent
phases. Complete retained regression keeps its 5,400-second owner limit, exact
planned/started/finished identities and zero failures, errors, skips, expected
failures or unexpected successes. Matching compiler bytes never turn a
timed-out or incomplete run into a pass.

- The original `807bbc4` [run 43127917665](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43127917665)
  passed 471 source tests and failed cold at 180.176448133 seconds with 34/38
  phases complete. Its incomplete names/exports phases, full source bindings
  and owned cleanup remain recorded.
- The v72 source `3d1f2cd70cc65ba1f603fec1ab43cb4e1eeb6fc8` has two retained
  local cold timeouts, 180.674533222 and 180.385562914 seconds, with 26/38 and
  6/38 phases respectively. Its source-only SIGKILL, environment-specific
  `PTRACE_TRACEME` refusal, and [run 43133619396](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43133619396)
  remain historical observations. The old index's queued status is not a
  current statement about that run.
- The original v73/v74 CLI/package failures, v75 wire-caller failure/error,
  later default/reference controls and their separate development passes are
  preserved in the previous full index and associated evidence. They are not
  silently replaced by main's later successful workflow.

The [Chinese completion audit](../review-evidence/hia-completion-20261112/audit.zh-CN.md),
[807bbc4 status snapshot](https://github.com/TrillionniumFoundation/Hepta/blob/807bbc4ce64b80d34b3102c774daf35e454d04be/docs/CURRENT.md)
and [existing evidence index](../review-evidence/hia-native-final-20261111/artifact-index.json)
retain the detailed source/effect boundaries. Historical archive recovery does
not restore missing current paths, qualify a later source tree or remove the
whole-product acceptance obligations above.
