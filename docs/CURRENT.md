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
packer, source-gate, recursive-chain, Store-initialization and linked-observer
repairs described below. Published `d994dd582a410b8f04acfac7ae862e1a2e516867`
passed both original Source jobs. Its
[push Source job](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43468694767/job/132034569634)
ran all 579 tests in 655.480 seconds with no failure, error or skip. The
[separate PR Source job](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43468710527/job/132034624166)
also succeeded. At the 2026-11-13 17:17 UTC observation, both Native jobs had
passed their original cold and language stages and were still running; this
is not a terminal Native result or qualification of this later working tree.

The earlier `f44c09fcc2c1cec25867c886ff477e83df774561` source passed all
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

Published observer commit `c4e83a14e47217a27d8d0f112c484b30315d9f68` subsequently
passed cold in both its [push run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43467604528)
and [PR run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43467621844).
The PR's original 31 linked-observer tests also passed in 8.035 seconds. Both
workflows then refused the stale language coverage inventory: its stored
semantic-support digest had not been regenerated after adding the observer
contract. Source stopped at the unchanged generated-diff assertion; Native
stopped at the unchanged language-inventory assertion and skipped later steps.
The original Native artifact `14059213307`, ZIP SHA-256
`4dbc927aad2b19fce0d1562f4eac22584eb346b0302e6fa76ca8b496850687e7`, retains that
run. The successor regenerates the language inventory and its source-contract
digest using the existing generators. It changes no implementation, selector,
assertion or budget and does not relabel the failed workflow as a pass.

The separate
[complete retained increment audit](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43468065422)
completed against exact observer commit `c4e83a1`, tree
`ec83846584bb0c369f8eea2d27f462fb865b7160`: 127 original selectors,
1,098/1,098 tests, zero failures, errors, skips, expected failures or unexpected
successes. Planned, started and finished ordered test IDs agree, with SHA-256
`b2835e9bbcf6fc64aefb5597bc510a345bb5b7ecb7291acececbe836a65b228d`.
The actual gate took 226.232229037 seconds; its unchanged 5,400-second owner
completed in 227.880117498 seconds with complete cleanup of its started POSIX
process group. All four real NDU prerequisites were built and admitted, and
all 2,588 raw source files remained unchanged. The original artifact
`14060400210` has verified ZIP SHA-256
`f6f32b8ccf07a64817096ea9f039147f7df3ec8aa5e8ec07bd7becea8127fe55`.
This is the entire retained increment gate, not the full discovered test suite
or qualification of any later source. Full discovery at `d994dd5` found 4,731
unique IDs with no loader error or duplicate; discovery alone executes none
of those test bodies.

Published `be36b7cfbe40522ca1b6356e90170aa89aec2bad` moves the loaded-symbol mapping decision in
`native_mapping_identity.verify_loaded_symbols` to the selected HIA program
`native_mapping.hepta`. HIA parses the actual captured mapping bytes and owns
interval ordering, numeric grammar, permissions, device/inode/file extent,
unique-match admission and first-refusal order. It keeps the original 16 MiB
mapping snapshot and 128-symbol domain, including large integers and the
interpreter's actual decimal digit limit. Python still captures kernel facts,
admits function objects, performs final descriptor/seal readback and constructs
result/exception objects. Native selection is explicit and has no fallback;
the default path does not import the native adapter.

The [mapping integration evidence](../review-evidence/hia-native-cleanup-20261111/native-mapping-integration.json)
retains the original development failures and the final component observations.
All 16 component tests passed in 20.916 seconds, and the final 47 source,
packaging, helper and workflow controls passed in 41.785 seconds without skips.
The component uses a fresh local B0/B1 build and is explicitly **not** a
matching-current-source cold result. Real controls include retained-loader FD
reuse, actual sealed DSO execution, a built and isolated installed wheel,
warm installed-source drift/removal refusal, pinned helper ownership and
foreign-thread refusal. The original Python parser, independent Core VM and
native image agree on 24 complete buffer controls; twelve public error cases
preserve exception type, text and cause. The original workflow now additionally
requires a matching-cold component and 14 original runtime/lease callers with
the HIA mapping selector. Both original
[push](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43472814502)
and [PR](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43472828725)
Native jobs subsequently passed the original cold, mapping component and
original mapping caller steps. At the 2026-11-13 17:38 UTC observation, those
jobs and their Source jobs were still running. The separate
[full retained audit](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43473228901)
uses harness `59c6e5912c86f6253b68b7a1579dbeef2fe8c111` and this exact product
commit; its six NDU and fixed verification-tool preparations succeeded, and
the unchanged original v4 `--full` workflow was running. No terminal result or
qualification of this later successor is implied.

The current successor additionally moves `_assess_measurement` into
`publication_measurement.hepta`. HIA owns paired medians and deviations,
ordered refusal reasons, exact cost projections and finite-range rejection,
including multiplication intermediates above 64 bits. Its equivalence domain
is the original frozen measurement envelope and exact-integer `prepare_ns`;
the actual runtime supplies an elapsed integer clock observation. Preparation
integers are transported without narrowing, including negative cancellation
controls. Kernel effects, actual timing, locks/cancellation/CAS, Core proofs,
compilation, loading and resource custody remain their existing owners.

The [publication measurement evidence](../review-evidence/hia-native-cleanup-20261111/publication-measurement-integration.json)
preserves the original development failures, including the compiler's correct
17-edge-parameter refusal before the source was split within the original
16-parameter limit. The final component passed 17/17 tests in 15.355 seconds,
including 595 complete original/native result-or-error comparisons and actual
installed and pinned-helper calls. The 44 related source/workflow/resource
controls passed in 8.246 seconds. A separate final installed-package control
passed in 11.118 seconds after regenerating the packaged support contract.
The original Core-only source check and generation fixed point also passed.
These are development component observations, not a new cold qualification.
The workflow now requires the matching-cold component and all 11 original
publication-profile callers, including observed policy entries both before
preparation and under the actual commit lock. These new CI gates remain
pending. The combined contract binds 978 inputs and registers 26 single-image
helpers. Neither this result nor the earlier mapping result authorizes
deleting resident runtimes or their foreign-resource owners.

## Current native implementation

| Area | Implemented selected path | Remaining boundary |
| --- | --- | --- |
| Compiler | HIA scanner, parser, checker and x86-64 emitter; original and modified-source fixed-point controls | Trusted Python seed/build driver, bootstrap tools and the bounded Linux x86-64 language/target/allocator profile |
| Machine and Core backend | Native instruction bytes, Code state/instructions, plans, Core lowering/emitter, borrowed-byte wrappers and ELF object control through original callers | Builtin-object observation, retained default routing, complete general backend equivalence and foreign-resource custody |
| CLI | Explicit two-image HIA owner for all fifteen ordinary actions, argument/help/errors, sequencing and selfhost-build selection | Ordinary entry, semantic action effects, file policy and successful pretty-JSON presentation remain hosted |
| Native stdio | Six commands: capabilities, verify, compile, render-assembly, assemble and check-assembly | Separate bounded protocol, not the complete fifteen-action CLI or eleven-tool service |
| Core applications | Core/JSON/workspace/patch helpers, nominal type/task/function helpers, ELF linker and source-build applications | Complete ordinary product routing, foreign-object/packet custody and broader diagnostic/support domains |
| Worker and scheduling | Selected request/report/wire images, pinned helper custody and five native in-process scheduling families | Hosted outer handler, object transport, installation/hash IO, process effects and complete service migration |
| Loaded native mappings | Selected HIA parser and exact entry-to-sealed-file mapping policy, registered in the pinned helper scope | Python argument/function objects, kernel snapshot and descriptor/seal readback, dynamic loader and resident resource lifetime |
| Publication measurement | Selected HIA paired-sample, noise, ordered-refusal and exact cost-projection policy in both original publication decisions | Envelope capture, actual clocks, lock/cancellation/CAS, proofs, build/load effects and resource custody |
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
| [PR #889](https://github.com/TrillionniumFoundation/Hepta/pull/889) | Union of current main and the separate native-owner development line, including launcher, process/stdio, Store and CLI owners. Published [R7/R4 candidate abeef212](https://github.com/TrillionniumFoundation/Hepta/commit/abeef212e34023534d91f8f952280e2a8d0cbde6) retains main and development as ordered parents. Its [Core run 43459534648](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43459534648) passed Source but failed the original native namespace caller budgets. Later source candidates are separate identities. |
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

The later #889
[R10/R2 Source run 43463604848](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43463604848)
completed 1,319 tests successfully on Python 3.14.4. Its original result names
the 3,083-file generated tree `1d52f28fa841599b9f1be028098a99e6a7a522b8`,
zero cold qualifications and zero native qualification jobs. The following
[R11 run 43468679071](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43468679071)
failed in generator `cli_parser_context` on the actual `_colorize.Argparse`
object before any product test executed. Source success in R10 does not
qualify R11, the separate native failures or this repair branch.

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

This cleanup removes 17 files and 912,834 bytes: twelve superseded stateful
source copies from attempts 01 through 04, one optimizer rebind source copy,
the unused `audit_hsir_wire.py` and `performance_observation.py` tools, and
two duplicate historical source maps. The retirement index records every
path's mode, byte count, SHA-256 and Git blob at fixed revision
`c4e83a14e47217a27d8d0f112c484b30315d9f68`. Recover original bytes with
`git --no-replace-objects show <revision>:<path>` outside the current checkout,
restore the recorded mode and verify the hash; historical commands require
the complete original revision.

The interrupted run's retired `source-before.json` equals the complete parsed
`source_state` retained in `integration-controls/thin-source-transfer.json`;
the fixed Git blob preserves its exact original JSON serialization. The
release-selection run's retired `source-after.json` is byte-identical to its
retained `source-before.json`. Historical member paths resolve through these
recorded Git recovery entries. All original results, error logs and member
inventories remain byte-identical, alongside the four final
`attempt05/bound-source/` files and all stateful measurements, failed and
superseded results, including the negative full-cost conclusion. References
to historical raw archives do not establish current custody of those absent
archives; the retired files' original bytes remain recoverable from Git.

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
