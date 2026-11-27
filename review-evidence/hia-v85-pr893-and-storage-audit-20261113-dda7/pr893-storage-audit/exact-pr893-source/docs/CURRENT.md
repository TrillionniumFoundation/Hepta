# HIA: current implementation and acceptance

This is the current-state index for `TrillionniumFoundation/Hepta`.
The language is HIA; active language inputs use lowercase `.hepta`.
The integration entry is [draft PR #893](https://github.com/TrillionniumFoundation/Hepta/pull/893).

**Whole-product native replacement is incomplete.**
`whole_native_delivery_qualified=false`,
`old_stack_can_be_removed=false`, and
`production_activated=false`. Component execution, matching-source cold
qualification, complete retained regression and running-worker adoption are
separate gates. Generated contracts describe source inputs; they are not
execution receipts.

## Source naming and retained repository

The [source suffix contract](HIA_SOURCE_SUFFIX.md) requires `.hepta` for
active assembly and structured Core inputs. The
[migration map](HIA_SOURCE_SUFFIX_MIGRATION.json) preserves exact rename
provenance. Current paths, packaged resources, generators, consumers and
production Python owners are enumerated by the
[generated inventory](HIA_NATIVE_REWRITE_INVENTORY.json) and
[support contract](HIA_SELFHOST_CORE_SUPPORT.json).

The observed unchanged main commit
`5831f52fada45e076f8f68f198a15c0585e6104f` contains 60 `.hiaasm`,
12 `.hia` and 11 `.hia.json` files, with no uppercase `.HIA` or
`.hepta` files. The integration branch contains the suffix migration.
Branch availability does not establish main adoption.

The retained tree has one active source per component. Superseded development
and report files have been removed with their consumers checked. Build and
cache output is ignored. Registered independent oracles, byte-exact protocol
fixtures and original failure records remain because current checks consume
them; historical recorded paths do not authorize a second active implementation.

The [stateful retirement ledger](../review-evidence/hia-native-cleanup-20261111/retired-stateful-process-files.json)
records 74 removed experiment payloads, totaling 979,347 bytes, and the one
still-consumed protocol moved unchanged to
`tests/fixtures/hia_stateful_protocol/PROTOCOL.json`. The
[development retirement ledger](../review-evidence/hia-native-cleanup-20261111/retired-development-versions.json),
[report retirement ledger](../review-evidence/hia-native-cleanup-20261111/retired-historical-reports.json)
and [checkpoint retirement ledger](../review-evidence/hia-native-cleanup-20261111/retired-integration-checkpoints.json)
preserve original Git object identities and deletion evidence. These retirements
remove no live production owner. Original records remain available in Git.

## Implemented native owners

| Area | Actual capability | Remaining owner or boundary |
| --- | --- | --- |
| Compiler | HIA scanner, parser, bounded semantic/resource checker and x86-64 emitter; original and modified-source fixed-point controls | Trusted Python seed/build driver, GNU ld bootstrap, bounded language, target and allocator profile |
| Application operations | Core/JSON/workspace/patch helpers, ELF linker and immutable release installer | General build, complete Core/nominal/diagnostic equivalence and ordinary product routing |
| Core diagnostics | Native v4 frames with complete value, body and primitive declaration diagnostics | Composite/nominal boundaries, other reference messages and whole `verify_program` equivalence |
| Native stdio | Six commands: capabilities, verify, compile, render-assembly, assemble and check-assembly | Bounded protocol; ordinary CLI has fifteen actions and worker has eleven tools |
| State and policy | Native request, journal, identity, budget, slot and retirement decisions over retained state | SQLite effects, durable transaction ownership, proofs and complete service migration |
| Artifact reads | Native cursor/page decisions, full-artifact UTF-8 classification and response budgeting | Store admission, same-connection cursor SQL, transport and unselected reference route |
| Complete edit queries | Selected HIA lookup, graph/slice decisions, complete payload and operation/query hashes | Original whole-program admission, unselected construction and matching-source qualification |
| Agent metadata | Selected HIA scalar/byte-export policy and complete signature payload through raw JSON or exact-type transport | Full Core admission, unselected default route and matching-source qualification |
| Release lifecycle | Immutable install, CAS selection/rollback/status and coherent selected-release verification | Worker restart/handoff, exact running image, outstanding requests/references and retirement |

The selfhost profile is Linux x86-64 and bounded. Its fixed point does not prove
general Core equivalence or whole-language formal correctness. The ordinary
entry remains `hia = hepta.cli:hia_main`. Default build and `hia_emit`
still use the Python direct emitter; `hia_evaluate` uses the Python reference
VM. The explicit [selfhost object build](HIA_PROGRAM_SELFHOST_BUILD.md) uses
sealed, operator-pinned native frontend/compiler bytes without an emitter
fallback.

### Queries, metadata and Core diagnostics

The [complete edit-query owner](HIA_AGENT_QUERY_NATIVE.md) is registered through
its public builder, packaged source, exact helper factory, capability declaration,
source bindings and original 15 controls. CLI `edit-query`, dependency
inspection, `prepare_batch` and `apply_edit` reconstruction retain the
original `prepare_edit` admission boundary. A selected HIA owner constructs
the complete query result. Whole-program verification remains an active owner.

The [Agent metadata owner](HIA_AGENT_NATIVE_METADATA.md) is registered with its
original 21 controls. Its canonical production module is
`hepta.hia_agent_native_metadata_native`; installed resource discovery,
builder, service and helpers use that name. Profile 1 accepts standard JSON.
Profile 2 preserves exact built-in types, true lengths, bounded Unicode
codepoints and integer sign/bit length without coercing caller objects.
The selected ordinary `_signatures` entry uses profile 2. Absence retains
`_reference_signatures`; a selected refusal never falls back.

The [Core diagnostic contract](HIA_CORE_ADMISSION_DIAGNOSTICS.md) defines the
private `HIACD001` frame, publication order and complete message bytes.
The v4 owner retains the two exact value-diagnostic families and 39 native
body-message programs, and adds 66 declaration-message programs for primitive
program, function, parameter, block and instruction shapes, names, CFG and
exports. Invalid names retain complete fixed messages; duplicate identifiers
retain all original 1–128 ASCII bytes. Original first-refusal and traversal
order remain part of the contract. Complete opcode UTF-8 and callee return-type
lists remain covered. Body and declaration payloads reuse policy state only
after the refusal is recorded, within the original state capacity; the private
tail remains 576 bytes. Hosted snapshot/JSON transport, composite normalization
and the legacy nominal guard remain. Both Core patch builders obtain the public
schema constant. Other diagnostic equivalence, whole `verify_program`
equivalence and production activation remain unqualified.

All 60 source generators remain mandatory. The query and metadata generation
commands retain their required output/inventory arguments. Their complete
source proofs run in a subsequent mandatory workflow step, so the generator
shell contract can still exercise its original clean, mutation and first-failure
fixtures. The ASCII lexer oracle uses a forward-only quoted-string scan and
retains the original token spans and rejection rules; a long escape-sequence
regression covers incomplete strings.

## Published v77 and helper-contract correction

The published v77 commit is
`494a69067732a282eb7af245fa9c156339a72bb9`, with tree
`f29f0d7f3859213519a356f001208c7b2c206c23`. It contains 105 `.hepta`
sources and 170 production Python modules. Its matching-source local cold run
passed all 11 checks with 767 bound inputs under the unchanged 180-second
qualification and 3-second cleanup limits. The four added component scopes
are explicit JSON wire serialization, selected inspection reports after original
program admission, selected exact-byte Core verification, and the private
SQLite platform component. Ordinary defaults and whole-product claims remain
unchanged.

The [v77 PR workflow](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43274218046)
passed cold qualification and the new component groups. Both its source job
and its later worker-helper native group failed the same original assertion:
the test expected 27 registered helpers while the runtime registry contained
29. Subsequent native steps were skipped. The separate research workflow and
CodeQL check passed; those results do not make the source/native workflow pass.

The source-bound retained run for this v77 commit started and stopped all
4,595 original ordered IDs under the unchanged 5,400-second owner. It recorded
4,594 passing tests, 67,604 passing subtests and the same single helper-count
failure, with zero errors, skips, expected failures or unexpected successes.
The tests took 2,405.245851449 seconds; the original owner took
2,408.03772434 seconds within its 5,400-second limit, without a timeout.
Owned process-group cleanup completed, and the source, cold evidence and all
4,572 bound inputs were preserved. This is a failed full run.
The earlier `4a53f109555fa5567fb1fa98cfe6eeef1f5fefa6` retained result remains
a separate pass of 4,529 tests in 2,375.305 seconds.

This correction aligns the fixed helper assertion and support-contract count
with the actual 29-entry registry, retains the original per-helper source and
schema assertions, and adds exact factory/dependency controls and a direct
contract-to-registry count check. The isolated precursor passed its one
original method and 34 subtests without native mapping. That focused result
does not qualify this corrected source: matching-source cold, CI and complete
retained acceptance remain required. No production owner, fixture or evidence
is removed by this correction.

## Original evidence and source-specific acceptance

The frozen baseline is commit
`ac488f062135c0a93adada084c81544e4719224b`, tree
`dff140a84eb607751ddcab4f689a8df55f5db63f`.
The source-bound local cold run passed all 11 checks. The complete retained
regression executed all 4,464 IDs with zero failures, errors, skips, expected
failures or unexpected successes, in 2,331.235 seconds under the original
5,400-second owner. Those results cover that frozen baseline.

The baseline's [GitHub run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43205669416)
passed its source job but failed native cold qualification at 180.172957576
seconds with 6/11 checks. The original owner reported `QUALIFICATION_TIMEOUT`,
return code -9 and complete cleanup with no remaining children or cleanup
errors. B0, B1–B3 and M1–M3 receipts remain in the original archive. Their
presence does not qualify the unfinished run or its skipped native steps.

The compiler's call-graph admission now skips already resolved rows and stops
at a complete monotone fixed point. Its development check retained all original
limits and completed 41 fresh-child native invocations, identical three-generation
images, original-byte recompilation and the original graph refusal controls.
Three alternating old/new timing pairs each improved; the median paired saving
was 10.597 milliseconds, about 2.58 percent. This small development result does
not establish CI performance or resolve the recorded 180-second timeout.

The registered query/metadata source controls subsequently executed all 484
original IDs successfully under the unchanged 1,800-second development owner.
The selected metadata ordinary-caller run executed 42/42 IDs with 296 observed
parent-process native entries, including `_behavior_equivalence`, `_hia_emit`
and `_native`. The earlier Core v2 diagnostic run executed 21/21 IDs and
35/35 subtests, with 265 native entries and three actual compile calls. The
subsequent Core v3 development run retained those 21 IDs and passed all 29 IDs,
with 332 native entries and four compile calls under the original 1,800-second
owner. The v4 declaration-diagnostic development run retained those 29 IDs and
passed all 39 IDs, with 504 native entries and five compile calls in 28.405
seconds under the same owner limit. These source-specific development results
do not qualify the combined source, establish a Python 3.14 CI result or select
a production default.

Original failures and evidence identities remain in the
[completion audit](../review-evidence/hia-completion-20261112/) and Git history.
The former chronological narrative is available in the
[frozen baseline index](https://github.com/TrillionniumFoundation/Hepta/blob/ac488f062135c0a93adada084c81544e4719224b/docs/CURRENT.md).
A later pass never changes an earlier timeout, interrupted run, missing-input
refusal or failed trace control into a pass.

### Required gates for the integrated source

1. Freeze the complete input set with exact bytes and modes, and regenerate
   the support contract and repository inventory.
2. Run matching-source cold qualification with **180 seconds plus 3 seconds
   for owned cleanup**, two host-oracle workers and every independent phase.
   Fresh seed/generation controls, changed-source controls and verified phase
   archives remain mandatory.
3. Run the original source, native, ordinary-caller, installed-resource and
   complete retained suites. Preserve all original IDs and their relative
   order, append registered new IDs, and report actual planned, started and
   finished identities. The full retained owner remains **5,400 seconds**;
   component owners retain their existing limits.
4. Require zero failures, errors, skips, expected failures and unexpected
   successes. Input/compiler/controller preservation, complete process
   cleanup and full result bytes are part of acceptance. Discovery and source
   generation alone execute no native test bodies.
5. Qualify the installed entry, then observe worker adoption, exact running
   image, outstanding request/reference handling and safe retirement. A
   bounded component or compiler fixed point does not close the whole product.

The [retained qualification runner](../review-evidence/hia-native-rewrite-20261111/run_hia_qualification_v4.py)
and generated contract define the registered groups. The final cold report
must bind the same current source used by strict builders and later native
controls; a development compiler selector cannot substitute for it.

## Remaining product owners

| Required closure | Existing behavior and effects to preserve |
| --- | --- |
| Ordinary CLI and full build | `cli.hia_main`, `verify_program`, `hia_program_native`, every public action and original admission |
| Eleven-tool worker and proof/backend admission | `hia_agent_worker`, `HIAAgentService.call`, `_compile`, `_hia_verify`, real proof/backend results |
| Durable effects and replay | `AgentStore` SQLite/WAL, transactions, journals, exact replay, unknown outcomes and recovery |
| Adoption, rollback, slots and leases | Complete receipt/context/artifact/ABI admission, real calls, epoch changes and generation references |
| Native execution ownership | `hia_agent_runner` child setup, limits, snapshots, termination and report checks |
| Resident runtime | `ScalarMultiversionRuntime`, `GenerationLease`, libraries, sealed descriptors and uncertain cleanup |
| Final cutover | Installation-bound old contexts/requests, restart/handoff, exact running image and confirmed retirement |

Every replacement must own the real caller path and its effects, preserve
original admission and first-error ordering, and survive recovery with the
same request identities. Store/file/SQLite work must retain its actual
transaction and publication boundaries; hosted success flags are not native
execution evidence. Complete Core and diagnostic behavior remain explicit
dependencies until their replacements are equivalent.

Production Python modules still participate in installation identity and have
static, dynamic or public consumers. They remain active until their actual
replacements pass matching-source acceptance and are observed running.
Deleting these owners earlier would remove working behavior and change
durable identities. No whole-stack deletion or production activation is claimed.
