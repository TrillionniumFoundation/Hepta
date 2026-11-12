# HIA: current implementation and acceptance

This is the current-state index for `TrillionniumFoundation/Hepta`. The language
is HIA; every active language input uses lowercase `.hepta`. The single
integration entry remains [draft PR #893](https://github.com/TrillionniumFoundation/Hepta/pull/893).

**Whole-product native replacement is incomplete.**
`whole_native_delivery_qualified=false`, `old_stack_can_be_removed=false`, and
`production_activated=false`. The v73 source contract identifies the actual
inputs; it is not an execution receipt. Current-source cold, installed/native,
complete retained regression, and running-worker adoption are separate gates.

## Naming and repository audit

The incoming integration source is `9a12b6cd13ba103fc7495aa8d5decf8cd5948143`,
Git tree `4e9f169f497e4378d5055c3b509f0f79f1d6e23b`. That snapshot contains 2,373
tracked files, 96 `.hepta` sources (71 assembly and 25 structured Core), and
163 production Python modules. The generated inventory records the subsequent
merged source, including the native read component and source retirements.
Active language inputs use `.hepta`; retired physical suffixes remain forbidden. The unchanged main snapshot `5831f52fada45e076f8f68f198a15c0585e6104f`
has 60 `.hiaasm`, 12 `.hia`, 11 `.hia.json`, no `.HIA`, and no `.hepta`.
Branch availability must not be reported as main adoption.

The [current inventory](HIA_NATIVE_REWRITE_INVENTORY.json) inventories the whole
retained tree, parses retained Python, hashes members, and records static
callers. The [completion audit](../review-evidence/hia-completion-20261112/)
checks current suffixes, resources, dynamic/public consumers and deletions.
These are auditable inventories, not a semantic proof of every source line or
closure over unknown external consumers. The [suffix contract](HIA_SOURCE_SUFFIX.md)
and [original migration map](HIA_SOURCE_SUFFIX_MIGRATION.json) preserve exact
rename provenance. Old receipts and registered frozen protocols keep their
original bytes and recorded names.

## Current native implementation

| Area | Actual capability | Remaining boundary |
| --- | --- | --- |
| Compiler | HIA scanner/parser/checker/x86-64 emitter; original and modified-source fixed-point controls | Trusted Python seed/build driver, GNU ld bootstrap, bounded language/target/allocator profile |
| Application operations | Core/JSON/workspace/patch helpers, ELF linker, immutable release installer | General build, complete Core/nominal/diagnostic support and ordinary product routing |
| Native stdio | Six exact commands: capabilities, verify, compile, render-assembly, assemble, check-assembly | Separate bounded protocol; ordinary CLI has fifteen actions and worker has eleven tools |
| State/policy helpers | Native request/journal/identity/budget/slot/retirement decisions over retained state | Hosted transport, SQLite effects, proofs and complete native service migration |
| Artifact reads | HIA page/cursor decisions, complete-artifact UTF-8 classification and exact response budgeting | Store authority, SQLite effects, hosted transport and the unselected reference route |
| Release lifecycle | Immutable installation, CAS selection/rollback/status, coherent selected-release verification | Worker restart/handoff, exact running-image observation, old requests/references and retirement |

The selfhost profile is Linux x86-64 and bounded; it does not establish general
Core equivalence or whole-language formal correctness. The ordinary entry is
still `hia = hepta.cli:hia_main`. Default build and `hia_emit` retain the
Python direct emitter, while `hia_evaluate` retains the Python reference VM.
The explicit [selfhost object build](HIA_PROGRAM_SELFHOST_BUILD.md) uses sealed,
operator-pinned native frontend/compiler bytes without an emitter fallback.

## Retained native changes

- The selected [ordinary artifact-read owner](HIA_AGENT_READ_NATIVE.md) receives
  the complete captured artifact and original request metadata. HIA determines
  cursor identity, signed INTEGER slicing, full-artifact UTF-8 validity,
  base64/page trimming, repeated response-budget halving and cursor JSON/hash.
  The adapter retains original store admission and parameterized cursor SQL
  on the same connection. The installed worker selects a pinned helper bundle;
  an unselected checkout or wheel retains its documented reference route.
- The [native stdio entry](HIA_AGENT_STDIO_NATIVE.md) accepts `check-assembly`
  directly through its HIA semantic/resource compiler and operator-selected
  output profile. Success returns verification JSON without publishing code.
  The 1 MiB input ceiling and plus-one refusal remain; hosted diagnostics are
  not claimed equivalent.
- [Selected release verification](HIA_RELEASE_SELECTION_NATIVE.md) holds one
  shared lock while HIA checks exact sequence/hash, the actual immutable
  installation, and complete selection bytes/inode/time readback. It performs
  no selection mutation and does not identify a running worker image.
- The compiler clears two complete private per-function tables with checked
  bulk operations, and scans the exact current-function interned identities
  for access/borrow/free conflicts. All live-loan checks, hard capacities,
  independent references and qualification cases remain.
- Execution-budget, retirement, whole-Core admission and local-instruction
  selectors reject an explicitly present empty value before native loading,
  reference entry or new effects. Absence retains their reference default.
  Other selectors keep their individually documented selection contracts.

The generated [support contract](HIA_SELFHOST_CORE_SUPPORT.json) and installed
resources bind these inputs. Development observations belong to their exact
working-tree/source hashes. Only subsequent source-specific runs can qualify
the frozen implementation.

## Acceptance and preserved failures

Cold qualification retains **180 seconds plus 3 seconds for owned cleanup**,
two workers and every independent phase. Complete retained regression keeps
its original 5,400-second owner limit, exact planned/started/finished test
identities, and zero failures/errors/skips/expected failures/unexpected successes.
A timed-out or interrupted run remains failed even when its compiler images
happen to agree.

The read component retains all 18 original source, native and integration
controls, including its installed-wheel worker and actual SQLite cursors.
Acceptance requires executing those controls against matching frozen source;
older development-compiler observations do not replace that gate. Its earlier
eight-control development owner stopped before dispatch because a tracked
historical ZIP was missing: zero project tests executed and the result remains
HOLD. Retiring that historical input in a new Git tree does not change the old
failure or weaken complete-source admission.

The 807bbc4 exact-head push
[43127917665](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43127917665)
passed 471 source tests but its native cold gate failed at **180.176448133
seconds**. Exactly 34/38 phases completed, zero phase exceptions were recorded,
and names/exports original/modified phases were unfinished. Owned cleanup
completed. The original B1/B2/B3 and modified M2/M3 images agreed within their
chains; this does not turn the incomplete run into a pass. All 709 exported
members matched that frozen Git source. Its original logs/artifact identity and
separate local ENOSPC/timeout observations are retained in the completion audit.
The same-tree PR run is a separate observation and cannot replace the failure.

The published v72 implementation is
`3d1f2cd70cc65ba1f603fec1ab43cb4e1eeb6fc8`, exact tree
`dfc42506dddc660316be1fc5bc84ad68e44f7eba`. Its local validation commit
`1661f73565e74c81fa34db874e7887d11ecaaf19` has that same tree; all 40 changed
blobs were independently matched. Frozen source controls passed 25/25 in
26.514 seconds, with zero failures/errors/skips. The full inventory's 2,367
members outside the inventory itself matched their sizes and SHA-256 values.

Both local v72 cold observations failed under the original deadline:

| Observation | Actual result | Complete phases | Owned cleanup |
| --- | --- | --- | --- |
| Initial | QUALIFICATION_TIMEOUT, 180.674533222s | 26/38; zero phase exceptions | ECHILD; no remaining children or errors |
| Independent repeat | QUALIFICATION_TIMEOUT, 180.385562914s | 6/38; zero phase exceptions | ECHILD; no remaining children or errors |

Both wrapper results are 6/11, and both complete 709-member source manifests
match the frozen implementation. The second observation does not replace the
first. Full retained qualification did not start because cold admission failed.
The separate complete source-only workflow, executed with its original heredoc
and Python 3.14.10, was interrupted by SIGKILL after 385.029698662 seconds. It
returned -9 without a unittest summary. Its 227 recorded `ok` lines do not
qualify the full suite; the kill source has not been established.

On 2026-11-12 the published code's
[GitHub source/native run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43133619396)
completed on PR merge `ed77d70f21094a7ce4082d28901bb9419271a320`, whose tree
matches code commit `3d1f2cd70cc65ba1f603fec1ab43cb4e1eeb6fc8`. Its source
job passed **473 tests in 690.194 seconds**. Its native cold gate failed with
**6/11 checks** after **180.173620091 seconds**, under the unchanged 180-second
qualification and 3-second cleanup limits. The actual child returned -9 after
the deadline; the owner confirmed completed cleanup. All subsequent native
test steps were skipped. The [original native artifact](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43133619396/artifacts/13908422179)
retains the failed cold report and its original bytes. This is a v72 observation
and does not qualify the later v73 source.

The [Chinese audit](../review-evidence/hia-completion-20261112/audit.zh-CN.md)
and source-bound outcome record retain their original support/deletion
boundaries and then-observed results. The later evidence-only commit
`9a12b6cd13ba103fc7495aa8d5decf8cd5948143` did not change any of those 708
contracted source inputs or their contract. The new CI observation does not
relabel earlier local failures or the complete later tree as qualified.

The recorded v72 local environment denied `PTRACE_TRACEME`. Its strace fault
controls remain failures; source inspection did not replace execution. New
source-specific strace controls must run on the selected qualification host.
Successful component observations do not relabel those prior failures.

Earlier detailed results, independent oracles, original failures, installed
fixture quota errors, and source-specific results remain in the
[807bbc4 status snapshot](https://github.com/TrillionniumFoundation/Hepta/blob/807bbc4ce64b80d34b3102c774daf35e454d04be/docs/CURRENT.md)
and [existing evidence index](../review-evidence/hia-native-final-20261111/artifact-index.json).
The historical 611-file archive's original-Git verification does not restore
its 574 absent current paths or weaken current-path verification.

## Cleanup and remaining product owners

The active tree retains one generated source per current component. Prior
[development retirements](../review-evidence/hia-native-cleanup-20261111/retired-development-versions.json),
[historical report retirements](../review-evidence/hia-native-cleanup-20261111/retired-historical-reports.json)
and [integration checkpoint retirements](../review-evidence/hia-native-cleanup-20261111/retired-integration-checkpoints.json)
record removed paths, hashes, Git objects and consumer checks. This current index
replaces their chronological status narrative; original records remain in Git.
Build/cache output is ignored. Byte-identical fixtures, original evidence and
independent oracles are retained for their actual consumers.

The [stateful process retirement](../review-evidence/hia-native-cleanup-20261111/retired-stateful-process-files.json)
removes 74 superseded experiment files (979,347 bytes of historical payload).
The one protocol still consumed by the current qualification inventory is
retained byte for byte at `tests/fixtures/hia_stateful_protocol/PROTOCOL.json`.
Its explicit inventory binding preserves the inventory's member count. The
retirement ledger records all 75 original Git objects and the exact consumer
change; this cleanup removes no production module or active HIA source.

The historical NDU scalar campaign ZIP and three original-observation archives
are retired from the current source tree after checking their consumers.
The development-retirement ledger binds their fixed Git locations, object IDs,
sizes and SHA-256 digests. Original indexes, member manifests, failure states
and original/copy paths remain unchanged; their paths describe the recorded
historical observations. The campaign and compiler reports link to their fixed
Git originals. No runtime fixture or test was removed, and strict missing-file
admission is unchanged. The generated contract and inventory describe the new
source tree.

| Required closure | Existing owner/effect to preserve |
| --- | --- |
| Ordinary CLI and full build profile | `cli.hia_main`, `verify_program`, `hia_program_native` |
| Eleven-tool worker and proof/backend admission | `hia_agent_worker`, `HIAAgentService.call`, `_compile`, `_hia_verify` |
| Durable effects and replay | Original `AgentStore` SQLite/WAL, request journals, exact replay and unknown outcomes |
| Adoption, rollback, slots and leases | Complete receipt/context/artifact/ABI admission, actual invocation and generation references |
| Native execution ownership | `hia_agent_runner` child setup, limits, snapshots, termination and report checking |
| Resident runtime | `ScalarMultiversionRuntime`, `GenerationLease`, libraries, sealed descriptors and cleanup uncertainty |
| Final cutover | Installation-bound old contexts/requests, restart/handoff, running image readback and confirmed retirement |

All production Python modules participate in installation identity, and actual
static/dynamic/public consumers remain. Deleting these owners now would remove
working behavior and change durable identities. Each replacement must take its
real callers and effects, survive recovery with original request identities,
pass current-source qualification, and be observed running before the old owner
can be retired. No whole-stack deletion or production activation is claimed.
