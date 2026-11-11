# HIA native continuation: source audit and delivery boundaries

This continuation starts from `TrillionniumFoundation/Hepta` main
`c80eb2ecc5d08421a3d124c879edb33cefff2267`. The HIA language lives in this
repository. `hepta-runtime` is a separate deployed process/MCP owner. No
independent repository named HIA was returned by the organization search.

**The complete HIA-native replacement remains open.** The former high-level
language has already been removed. The remaining hosted production modules
still implement supported operations. They cannot be retired by relabelling a
native kernel or a bounded self-compilation run as whole-product equivalence.
The final retirement target remains one HIA-native product with preserved
language semantics, ordinary callers, installation and recovery.

## Exact baseline audit

The frozen tree has 2,532 blobs, including 1,072 Python files, 147 production
`hepta/*.py` modules, 50 HIA assembly files and 12 HIA JSON programs. These counts
are inventory facts, not a semantic completion percentage. The regenerated
`HIA_NATIVE_REWRITE_INVENTORY.json` records indexed current bytes, parsed Python
imports and static callers; it explicitly does not claim every line has a
semantic proof or that dynamic/external caller closure is established.

The installed CLI has 15 actions and is still a Python entry. The independent
native stdio program has five operations with its own scoped protocol. Its path
cannot replace the ordinary worker executable without implementing that worker's
request/report and durable operation contracts.

Frozen main's [Actions run 42949936235](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42949936235)
passed 252 source tests in 396.046 seconds. Its native cold run timed out after
180.091260887 seconds; only six of eleven wrapper checks passed. Thirty stages
were marked complete in the index, and two further stage reports were written
before termination. Those 32 reports contain 3,718 true checks. Eight index
entries remain incomplete: two with reports and six without reports. None of
these incomplete entries or skipped downstream suites is a pass. All 562 declared cold
source entries were independently matched to the frozen Git objects. The raw
artifact digest is `c1d137bf8f54afaff613e725c152e84ecb19cab20fd03f94531e8392ffef11ec`.

Later main also preserves a separate ROG qualification of exactly that same
`c80eb2e` source: **3,931 retained regression tests** passed without errors,
failures, skips or expected failures, and its cold replay passed. The
[original full readback](../review-evidence/hia-native-rewrite-20261111/v61/c80-qualification/full-readback.json)
records the exact tree, all source identities and each step. This independent
machine run does not erase the GitHub timeout, and neither baseline result
qualifies a later merged source.

A current Runtime discovery read and exact manifest-byte hash check found
different worker/backend identities from the frozen main source. The live
backend profile still reports `self_hosted: false`. This is an observation of
issued discovery bytes, not an independent read of every deployed file or loaded
process. No production worker cutover, state-root migration, configuration-pin
update or default-release activation was performed.

## Implemented native responsibilities

### Current v65 source repair

The current integration includes exact main `5831f52` with complete nominal
constructor and outer-program lowering. At the merged `c4add225` source, all
46 workflow generators reproduced every indexed file byte, and all 18 focused
workflow/source/frame controls passed with identical loaded/executed IDs and no
anomalies. These are source controls, not a native or cold qualification.

The names reference no longer constructs and discards the complete compiler
CFG merely to obtain its AST function-name map. Both the generator and the
reference use the same exact name-index helper. All 154 public assembly calls,
106 positive cases, 40 refusals and original reference bytes remain. The measured
local reference reduction from 7.15068 to 6.01871 seconds is limited evidence;
the full cold deadline remains 180 seconds with two workers and all 38 phases.

The original `6994512` source-generation failure has been repaired by refreshing
the language inventory and support contract in dependency order. Both original
cold runs still stand as explicit timeout failures. Fixed desktop toolchains and
six external fixtures are ready for a new exact-source run; readiness is not a
test pass. Original observations are in
[the source-repair evidence](../experiments/hia_v65_source_repair_20261111/README.md).

### Ordinary worker request payload

[The request kernel](HIA_WORKER_REQUEST_NATIVE.md) implements ordinary JSON
parsing, finite binary64 conversion and shortest printing, canonical byte
production, request schema/field policy, SHA-256 identity, catalog matching and
the tool-name codepoint bound in checked-in HIA. An explicit installed-source
selection connects it to the existing ordinary worker without falling back on
a selected failure.

Independent review found and corrected four real defects in the initial
development candidate: temporary key sorting violated the foreign arena's source
order; reserializing the full envelope imposed a stricter byte ceiling than the
original five-field digest payload; distinct digest diagnostics were conflated;
and `admit(raw, None)` selected plain canonicalization instead of refusing a
missing trusted pin. Original failed observations remain separate from the
fixed v4 tests. The exact 8 MiB counterexample is retained in the regression.

The ordinary service tests exercise completed replay, changed-key conflict,
retained running intent/unknown outcome, malformed requests before store
creation and an actual wheel installation with authoring imports forbidden.
The independent review covers numeric boundaries, Unicode, diagnostic ordering,
private concurrent scratch and native-buffer canaries. These controls establish
the observed responsibility; they do not implement native SQLite or all eleven
tool methods.

### Immutable release publication

[The release installer](HIA_RELEASE_INSTALL_NATIVE.md) implements a complete
bounded multi-file publication operation. HIA checks an operator-pinned package,
safe entry names and modes, complete directory inventory, content and identity;
a fixed Linux syscall adapter holds descriptors, writes/fsyncs files and performs
`renameat2(RENAME_NOREPLACE)`. A HIA packer emits the standalone ELF. No Python,
libc or child executable is required by the installed program at runtime.

Independent actual-host checks found and corrected unnecessary directory-read
authority on ancestors, inherited SGID stage modes, and restrictive ambient
umasks. The operator root is left intact; the installer fixes only its private
process umask and newly created stage mode. Publication preserves existing
releases. A separate read-only `verify` resolves observable bytes after an
interruption or lost receipt. Failed private stages can remain; activation,
administrative staging recovery and reference-aware retirement are still
separate unfinished responsibilities.

### Cold qualification without reducing the gates

Compiler-name fixtures now perform a single combined alpha-renaming operation
with the original input admission and final complete render/parse/semantic
checks. The complete 2,447,154-byte name-reference output remains identical.
Evidence capture hashes the exact bytes written to each ZIP member in one read,
while retaining independent member replay, compressed-byte hashes and final
source/inode/mode/owner checks.

One bounded archive thread seals completed stages while two original oracle
slots continue executing. At most two archive tasks are admitted; a stage remains
pending until sealing succeeds. Every future and sealing failure is observed.
The 180-second qualification deadline, three-second cleanup deadline, all 38
stages, independent reference executions and both compiler fixed points remain.

The isolated cold-repair candidate passed all 11 wrapper checks, all 38 stages
and 5,049 checks in 164.326411014 seconds. Its original compiler generations
agree; its modified second/third generations agree and differ from the original.
All 38 archives, 42,623 member files and 2,396,853,095 uncompressed bytes were
independently replayed. This isolated result does not qualify the later combined
source. Combined-source results belong to the matching contract and retained
evidence for this continuation.

## Combined v61 observations before merging later main

The combined v61 candidate passed a fresh source-only cold replay with
CPython 3.14.10: **11/11 wrapper checks, 38/38 sealed phases and 5,049/5,049
qualification checks**, in 172.841585262 seconds against the unchanged
180-second deadline. The manifest binds 574 declared source files plus the
support contract itself; it does not purport to bind every repository document.
Original B1/B2/B3 bytes agree at
`0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8`.
Modified M2/M3 agree with each other and differ from the original compiler.

The ordinary worker suite and its independent adversarial review then passed
**18/18 tests**, without skips or expected failures, using a new application
build admitted by that exact cold report. A separately retained cold-bound
worker build has image SHA-256
`a206d5e0a54fa67a30655461ff970e1810e38070a86972d7b0f3d631b6b6e1dd`.
The cold-bound release installer has executable SHA-256
`3b089aa5c54fc93bf3b0eb0b11018f2dba0b49142e53be78086b5cf9193196d0`.
These bytes match their independently reviewed development images. The final
release development image passed six source/VM tests and thirteen actual
non-root desktop kernel tests; those executions retain their own development
run identity. The cloud environment refused ptrace fault injection, and that
failure remains recorded separately.

The [evidence index](../review-evidence/hia-native-closure-20261111/evidence-index.json)
distinguishes original reports and logs, exact issued artifact bytes, connector
snapshots and derived summaries. Original absolute paths inside retained
reports are left unchanged. Historical failures are preserved alongside fixes;
development and isolated-repair results are not relabelled as combined runs.

The full pre-merge source runner regenerated all 41 components without changing
bytes and ran 267 tests. Its workflow shell fixture had three failed subcases
because this local Python 3.14 installation lacked a `python` alias beside
`sys.executable`. The original failure is retained. Providing a private alias to
the same interpreter made all four workflow controls pass; no source gate was
relaxed. The subsequent v62 source suite is a separate current-source run.

## Integration of later main

While this continuation was running, main advanced to
`647885c5c3ff067b6477011123335ad5a1aef78e`. Its complete Git commit and tree
identities were verified and merged, preserving the native composite-v4
returned-loan origin decisions, the independent controls and evidence, and the
equivalent structural-traversal changes. That combined profile is
`selfhost-core-linux-x86_64-v62-native-request-release-origins`.
All earlier v61 observations above remain attached to their earlier sources;
they do not qualify this new merged profile.

The first v62 attempt failed after 40.074269915 seconds because the shared
filesystem ran out of free blocks while creating the seed's temporary link
directory. Its wrapper and original `Errno 28` traceback are retained. Completed
historical cold directories were losslessly archived and every regular file's
bytes, mode, UID and GID independently read back before releasing their unpacked
copies. No production source or other worktree was removed.

A fresh v62-r2 run then passed **11/11 wrapper checks, 38/38 phases and
5,049/5,049 checks in 168.469563822 seconds**, with CPython 3.14.10. It binds
576 declared sources plus the contract. A separate standard-library audit
rehashes those 577 entries before and after replay, verifies all six actual
compiler images and phase/process relationships, and reads all 42,661 members
of the 38 ZIP archives through EOF. The independently read payload bytes total
2,396,852,094; manifests add 6,952,530 bytes. Both compiler fixed points remain
valid, and the owned process tree finishes before the unchanged deadline.

The matching v62 application builds reproduce the request and release image
hashes above. The ordinary worker and independent review pass **18/18** tests
under CPython 3.14.10. The complete composite-type and returned-loan-origin
suites pass **28/28** under CPython 3.12.14, including real installed-wheel
normalization. Neither suite has skips or expected failures. Their independent
interpreter identities are retained in `v62/` evidence; GitHub's Python 3.14
workflow remains a separate gate.

The v62 language run also passes **1,242/1,242** checks under both original and
modified compilers, followed by **10/10** assertions over that actual report.
All 41 source generators reproduce their checked-in bytes exactly after the
merge. These checks preserve the existing admitted profile and explicitly do
not establish the unavailable whole-v8 or whole-product claims.

The complete v62 source-control suite passes **283/283 tests** under
CPython 3.14.10, with no failures, errors, skips or expected failures. Its
before/after declared-source hashes remain identical. The unit runner took
394.074 seconds; preparation plus execution took 402.205244260 seconds.

## Integration of native signatures and all five task helpers

Main subsequently advanced to `d6847ac891e0dd07217d179891bb763162211de2`.
Its exact commit, parent and tree were imported and verified before merging.
The combined profile is now
`selfhost-core-linux-x86_64-v63-native-request-release-signatures-helpers`.
Incoming native nominal signatures and task-protocol admission, all five HIA
start/poll/cancel/join/close helper bodies, their source-bound installation,
ordinary error ordering and independent controls remain part of the merged
source. Existing request admission and immutable release installation are
retained in the same source closure.

The new profile requires a fresh cold replay and matching native applications.
Older v62 results remain historical evidence and do not qualify this source.
The external v5 qualification runner includes both new native selectors and
all signature/helper controls, alongside the worker-request and release-install
groups. A combined-selector witness also exercises the native type session and
task-helper generator together while refusing calls to their retained owners.
No hosted production owner is retired by this merge.

The first remote preparation for exact `179a84d` did not reach a test suite:
its public HTTPS clone emitted `fatal: early EOF` and exceeded its 240-second
clone deadline. The remote supervisor reported an incomplete stderr drain and
`effect_unknown`. That observation remains an unknown remote effect and has
no successful-test status. Any later source preparation uses its own pinned
candidate and independent output directory.

## Exact v63 terminal results and continued v64 integration

The published v63 head is `93d66bcc3acb88212c9b153d7852ba22eeab24c8`,
tree `0a67bf07951505a50e9aeb888f1c2c448d1eb816`. Its local source controls
passed 298 tests, and its local cold replay passed all 11 wrapper checks,
38 phases and 5,049 checks in 148.166989520 seconds. Both GitHub Core runs
also passed 298 source controls and 555 native unittest cases, including the
ten language-report assertions. The push cold run took 176.683950431 seconds;
the pull-request run took 112.725333054 seconds on a synthetic merge with the
same exact product tree. The separate exact-head NDU workflow also completed
successfully. These are distinct observations with their original source and
run identities.

The complete retained regression on ROG instead ended **HOLD: 4,031 tests,
two failures, zero errors and 143 skip records**. It exposed a reviewed-QEMU
selection mismatch and two original API diagnostic differences inside the
native preflight dispatch test. Missing explicit compiler, proof and native
fixture selections caused the skips. One class-level skip covers three methods;
the next complete suite must discover its actual current count. The external
guardian observed the leader reaped, no remaining children and kernel ECHILD.
Input source bytes were preserved. The original failure and durable archive
receipts are in [the terminal evidence](../review-evidence/hia-native-closure-20261111/v63/full-retained-terminal-hold/README.md).

An independent local audit had fully read the original v63 cold phase archives
before a cloud interruption. Its reports and hashes survive; the transient
phase ZIPs and original local compiler directory do not. Later interrupted
local audits of the CI artifact produced no successful final audit. Both
original CI ZIPs and the ROG final reports/logs/compiler archive had separately
verified home copies when those receipts were issued. A later live check found
the two home ZIP paths absent, for an undetermined reason. Both original ZIPs
still existed in their original ROG `/var/tmp` directories with matching full
SHA-256 and size; a new create-only home preservation is tracked separately.
The [v63 evidence](../review-evidence/hia-native-closure-20261111/v63/README.md)
keeps these custody limits explicit.

Main `f50b37543d1a379353267ce0ab7111242806b8b4` was subsequently merged,
including complete child-test identity/count checks, the full native preflight
CI module, and private batched-fixture construction without redundant semantic
admission. This continuation additionally gives the shared HIA parser exact
reason IDs for the original API diagnostics. The adapter only maps those IDs to
text. Both the retained and explicitly selected native routes keep the same
original assertions; no native-specific generic-error exception is used to
make the old tests pass. All fifteen affected composed HIA sources were
regenerated.

The published combined v64 profile is
`selfhost-core-linux-x86_64-v64-native-journal-diagnostics-function-lowering`.
[The new request-journal component](HIA_AGENT_JOURNAL_NATIVE.md) owns request
and key identity, tool/key admission, reservation/replay/conflict/unknown
decisions, verification replay routing, phase acknowledgements and terminal
response/cost byte instructions. SQLite operations and durability, the business
methods, foreign objects and existing proof/context authority remain hosted.
Its independent selector has no fallback on selected admission failure.

Independent development review found actual rollback-to-completed defects at
native acknowledgement and SQL-to-acknowledgement interruption boundaries.
The original 36 observations are retained. Replaying them after the bridge
repair preserves original exception types, leaves unconfirmed intent unknown
after close/reopen, and avoids false completed responses or costs. Separate
cached-BLOB observations found UTF-8 error-span and decode-before-size priority
differences. A HIA codec stage now supplies the error span for the foreign
exception constructor; the original five counterexamples agree after the fix.
Further review found two distinct lexical-number projection cases: malformed
escape lookahead after number masking, and an invalid original number whose
masked text passes preflight. HIA now performs the complete projection and
supplies the original syntax reason and Unicode position where necessary.
The original eight cases agree on the r9 source/image. Its complete dedicated
development suite passed 21 tests under Python 3.12.14. A separate exact-956
Python 3.14.4 run had one of twenty tests fail on the interpreter's changed
unhashable dict-key wording; HIA now distinguishes direct and tuple-nested
types and the bridge renders the actual interpreter's text. That original
remote failure is retained and is not relabelled by a different run.

Ten independent dual-path cache-selection controls also agree on r9, including
actual SQLite close/reopen rows and selected-driver admission sequences.
Changing a manifest to name a damaged new image causes fresh admission to
refuse. An already pinned immutable mapping may continue to replay after its
disk file changes, as in the retained path. Cache-internal selector changes
preserve the captured codec and numeric-converter profiles. These are explicit
development observations, not the pending combined cold/full qualification.

Development success is not a combined qualification. The v64 pipeline requires
a new complete matching-source cold replay, source controls, all component
groups, and ordinary caller execution with the retained journal owner forbidden.
That caller gate includes the original Agent tools/proof/lease/machine-choice/
campaign modules, native candidate tests, and native worker/adversarial modules.
Every loaded test ID must execute; empty suites, exclusions in qualified mode,
errors, failures, skips and expected/unexpected outcomes refuse qualification.
The full retained regression and the independent external process guardian are
additional gates. Until those actual results exist, the combined profile is
unqualified.

### Integration of complete nominal function lowering

Main subsequently advanced to
`31d81594997cfb6cce5ab62ea5aaba3bb7757af1`, tree
`dc7b7f1f5fc07c8502a27ba4907fe768ee1f0207`, directly above `f50b375`.
Its exact Git objects were verified and merged. Five explicit HIA kernels now
own complete function block/SSA admission, record/enum/partial/task operations,
terminators, generated helper requests and Core function construction. Public
elaboration closes native sessions on successful and failed exits; private
elaborator behavior and partial-state observation remain available.

The incoming six required test modules and their source controls are preserved
alongside the existing combined type/helper controls. The combined workflow
also requires nonempty, complete execution and zero anomalous outcomes for
this group. Its function kernels use the same new matching-source cold report
as the other components. Incoming development and exact-`f50b375` results retain
their original source identities and do not qualify this combined tree.
At that stage, nominal constructor ordering, outer module/export construction,
final primitive admission and general backends remained distinct migration responsibilities.

### Exact v64 CI terminal and v65 integration

Published `699451201f51fb4bdbd931568e64aa576143e807`, tree
`9be8bd2dbfca0dd5a552a26218f97711425e577d`, failed both Core CI runs
`42981052596` and `42981060503`. The PR checked out synthetic merge
`17835ab6bc13b0814b753f8d6678531879d307ff`, with the same exact tree.
All 44 HIA generators reproduced their sources. The later language-inventory
regeneration exposed a stale semantic-support hash. A two-file regeneration
repair then passed the actual complete source selection: 317/317 loaded and
executed IDs, zero anomalous outcomes, Python 3.12.14, 409.8943568930008 seconds.
That working-tree repair is a source control, not a fresh CI/native result.

Both original cold artifacts record explicit qualification timeouts at the
unchanged 180-second limit, with complete process-tree cleanup and kernel ECHILD.
Thirty-four of thirty-eight phases completed, without phase exceptions;
the original/modified names and exports phases remained incomplete. All six
generation receipts exist and retain the expected original and modified fixed
points. The unfinished nested qualification was correctly refused by the
wrapper. None of those observations changes either terminal result to PASS.
The original job/API observations and repair controls are retained in
[the v64 CI evidence](../experiments/hia_v64_ci_terminal_20261111/README.md).

Main then advanced to `5831f52fada45e076f8f68f198a15c0585e6104f`, tree
`72084752441a61f879dbbcf363a8cade3ef2d6b1`. Its exact Git objects are merged
here. Four additional HIA kernels now own constructor admission/signature
ordering and complete outer function/helper aggregation, late limits, exports
and primitive schema selection. Its installed-resource mapping also correctly
resolves multiple kernels through their actual shared bridges. The incoming
development, installed-runtime and original failed CI evidence retains its
own source identity.

The new combined profile is
`selfhost-core-linux-x86_64-v65-native-journal-complete-nominal-lowering`.
Its workflow preserves the existing journal, worker-request, release-install,
type/helper/function and native-composition controls, and adds the five new
constructor/outer/lifetime modules. All sixteen nominal modules must execute
fully, with no skips or anomalous results, against one exact cold source.
The two new generators join the existing forty-four. This integrated source
still requires its own cold, component, ordinary-caller and full-regression
qualification; preparing tools or external fixtures does not establish it.

## Remaining production owners and retirement gates

| Owner | Current actual responsibility | Required closure before retirement |
| --- | --- | --- |
| `hia_program_composite._Elaborator` | Five explicit native owners now cover types/signatures, helpers, complete functions, constructors and outer aggregation; bounded foreign-object custody and final primitive admission remain hosted | Matching-source complete semantic/refusal/installed controls, native standalone normalization and ordinary default integration |
| General compiler/backend | Canonical machine plans, broader retained Core layouts, object/linking and target support beyond the selfhost profile | Native producers for every retained language and ABI target, with explicit profile boundaries, cross-target execution and source-matched qualification |
| `HIAAgentService` and `AgentStore` | Tool methods, refs/namespaces, SQLite/WAL durability, cost persistence, slots, versions, leases, evaluation, adoption and rollback; an explicit HIA selector now owns ordinary request-journal decisions and canonical write instructions | Full native ordinary worker with same-key conflict, unknown outcomes, crash/restart, original-operation observation and state continuity |
| Worker and foreign bridge | Administrator parsing, Python object materialization, service entry, installation readback and report serialization | Native complete request/report/service protocol with current code/profile pinning |
| Build, authoring and default CLI | Python seed generation/custody, package hooks, source assembly, complete project orchestration and the 15-action installed CLI | Native clean-machine rebuild from an explicit bootstrap trust root, native module/library build and equivalent default installed behavior |
| Release lifecycle | Initial native bundle installation/readback now exists; active-release choice, staging recovery, upgrade/cutover and retirement remain external | Persistent version/ref ownership, no duplicated effects, restart/rollback and real default activation |
| Runtime and proof | Retained runtime/library owners, independent VM/reference roles and scoped proof computation | Native production replacements with preserved proved/unknown/refuted/timeout semantics; keep independent reference controls |
| `hepta-runtime` deployment | Existing Rust MCP/process owner and a separately pinned hosted worker | Full native worker ABI/report parity, real SSH/MCP first use, old-operation continuity and independently observed cutover |

No supported operation was removed to improve a completion count. No skipped
test was converted to a pass. No historical source or result was assigned the
identity of the new combined candidate. Production deletion is still blocked
by the implemented responsibilities in this table, rather than by missing user
authorization.
