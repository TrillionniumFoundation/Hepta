# Native rewrite execution status — 2026-11-11

The working continuation is [PR #889](https://github.com/TrillionniumFoundation/Hepta/pull/889).
The complete HIA-native product and deletion of all former production owners
remain unfinished. The source audit and remaining ownership boundaries are in
[the audit](HIA_NATIVE_SELF_REWRITE_AUDIT_20261111.md). File counts are an
inventory, not a native-completion percentage.

## Current v71 candidate: heap owner integrated; matching qualification pending

This source checkpoint extends `8b9fbcbeb943447bdbd4e534f081f92e5f1ad8b2`
(tree `1766691461d2ba7fef644e2b4e436566016f2226`), which has exactly
33 source changes from the previous `67382498b9d60bfecf3696d8c2cb632d8f20281b`
candidate. Those changes contain the frozen 29-file heap-bound owner, the narrow
static-budget fixture-parent repair, and three registration files. This commit
adds the three actual generated records and this status update. It does not
include the separate source-generation harness in the product source tree.

The isolated source-generation workflow
[43130016232](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43130016232)
actually completed successfully on Python 3.14.4. It checked out the exact
`8b9fbcb` candidate, verified all 3,025 Git-tracked file bytes and modes, and ran
the original generator sequence before language coverage, support, native
inventory, and source controls. All 34 commands exited zero; all 20 source
controls passed without errors, failures, skips, or expected failures. The
generated support contract contains all 821 required source files. The only
generated changes were `HIA_SELFHOST_CORE_SUPPORT.json`,
`HIA_SELFHOST_LANGUAGE_COVERAGE.json`, and `HIA_NATIVE_REWRITE_INVENTORY.json`.
Their exact bytes are retained here. The inventory honestly records the
candidate and intermediate index observed when it was generated; it does not
pretend that the later commit already existed.

The workflow's original report is 5,336,761 bytes, SHA256
`337d4b4fe6e42fe2eec114d9d3320c0209ffe356afd459a1e445587fb2aace27`.
It was independently recovered from checked, numbered log chunks and then
matched to the downloaded artifact. The artifact's source archive independently
reproduces all 3,025 files (108,966,803 raw file bytes), including every Git blob,
mode, size, and SHA256. This establishes source provenance and successful
generation; it is not a cold-bootstrap or complete native qualification.

The original `67382498` full qualification has no recovered authoritative
terminal result. Its last recovered observation contains 30 successful stages
and three failed stages before the final retained-regression step. The failures
were the static-budget fixture-parent error and the namespace and ledger
reference-fixture preparation overruns. The narrow fixture-parent repair in
this candidate does not retroactively change those results. The original
three-second, 1,000-millisecond, and cold-bootstrap limits remain unchanged.
The new candidate still requires its own cold and full qualification.

Parallel development has produced a stricter normalization owner, an observer
that combines HIA continuation policy with ordinary shared-object lifecycle
semantics, and an explicit HIA source-digest owner. Those components remain
separate until their source integration and matching qualification are
completed. Their local development observations do not transfer to this source
checkpoint. A tested Python source-read micro-optimization was slower and was
rejected. No scan was shortened, no digest was cached across public calls, and
no deadline was increased.

**Whole-product closure, public/default activation, live-worker migration, and
deletion of the former implementation remain false.** The independent source
generation pass is a concrete checkpoint; the outstanding ownership and
qualification work below remains active.

## Prior v70 candidate: reconstructed static budget integration, qualification pending

This candidate starts from the published `8ca2197693c98e48d0d16ab3c077efc7cd535653`
tree `d9a0a779301d25ffbfdc1601ed86ce0d76a9236b`. Its 2,994 retained
paths were restored and checked against their exact Git blob identities and
modes. The lost local `92fbc134f522c9cff616419b9555056e7cdd7d51`
commit object, author identity and tree have not been recovered. The current
candidate is **NEW_RECONSTRUCTION_FROM_SAVED_OWNER_FILES**: the 14 complete
source files in the verified `9028d181` archive plus the preserved 17-path
registration recipe. It does not inherit the lost integration's Git identity,
unknown source-gate result or qualification. The original attempt to admit the
incremental bundle failed because prerequisite `f5bb6d4a2014fc43a14737b92bc94e21e5b3be4b`
was absent; that failure and the unchanged bundle remain retained.

The original complete `e03c82d1` qualification has finished with **HOLD**.
All 32 stages actually ran. Total runner time was 6,760.128471506992 seconds.
Full discovery ran 4,583 tests with four failures and one error, and zero skips,
expected failures or unexpected successes. Unittest reported 3,464.998 seconds;
the enclosing full-retained step took 3,468.475736 seconds. The five top-level
failures were an identity-worker empty-JSON error, the namespace caller wrapper,
the ledger caller wrapper, and two scalar-proof identity assertions that
expected `unknown` but observed `proved`. The nested manifest fixture for
the identity-worker case was later repaired in `7d664e7d`; that later
observation does not change the original error.

The original full-run namespace and ledger nested panels each reported one
failure and one error across their 35 and 48 controls. Their original
three-second and 1,000-millisecond deadlines are unchanged. A subsequent complete
read of the original compact evidence identified the two reference-loop
`RequestJournalUnknown` causes: the test callback's
`assertGreater(remaining, 0)` failed with remaining values
`-0.7292891502380371` and `-0.7449177265167236`, with the message
`fixture preparation exhausted the original context budget`. The original
trace runs through ticket `run`/`encode_response(invoke())`, service
`evaluate`, and the test callback. The unknown acknowledgement classification
remains intact; it is not recast as an ordinary `E_BUDGET` result or a pass.
Earlier records that had not yet recovered this cause remain historical evidence.
The complete original compact observation is 36,308 bytes, SHA256
`391f270c3bdca4465455c54c3e4912f41521323aa14b9a9ca028eb38693fe2e5`, retained as
[Git blob b3da5d03](https://api.github.com/repos/TrillionniumFoundation/Hepta/git/blobs/b3da5d034fbbf90ed65216477b8fc9e4ea251c2f).
For context, the original e03 source closure has 751 entries totaling 20,198,062
bytes. Multiplying that static size by 98 preparations gives 1,979,410,076 bytes;
this is a static estimate, not measured runtime I/O.

All three original `8ca` Core CI runs failed:

| Run | Original native-stage result | Later result |
| --- | --- | --- |
| `43070250214` | Cold timeout after 180.185358450 seconds | Source job also failed on stale coverage support identity |
| `43070309546` | Cold passed 11/11 checks in 135.457622031 seconds | Stopped at `validate_inventory`; actual language cases did not run |
| `43070317835` | Cold timeout after 180.210550521 seconds | Source job also failed on stale coverage support identity |

The two timed-out cold runs recorded only six of eleven checks; owned process
cleanup completed. The original 180-second plus three-second cleanup bounds
remain unchanged. The earlier 26-control source panel did not include the
failing inventory gate and therefore did not establish a complete source-CI
pass.

The two original scalar-proof fixtures patched only `totality.__file__`,
while `checker_source_identity` reads `checker_identity.__file__`.
The repaired fixture adds the actual owner's path patch and positive assertions
that its source-lock SHA changes and is restored, retaining the original three
test names and assertions. Its exact source SHA256 is
`03cbde73f488afc7b44dbc0fd25b785a35ffa4acd8cda19feabc72c10558be0e`.
A separate e03 fixture candidate passed 3/3 controls with no failure, error or
skip: unittest 0.135 seconds, runner 0.141893857 seconds. After copying that
fixture to the restored 8ca tree, the original `coverage_manifest` generation
and `validate_inventory` passed. That 176,645-byte coverage file changed only
its semantic support identity and had SHA256
`1da737da6e955e75b5d20bf18230827467b27a3e78e2d0f81bf5ce986d3ac049`.
Those are two-file repair observations. The static candidate must generate its
own coverage and rerun the original three controls; the earlier hash and results
are not imposed on the new source.

The original proof failures, exact fixture candidate, patch, freeze, summary,
raw test log, published-source restoration, static archive restoration and
two-file application record are retained in
[the fixed v70 recovery commit](https://github.com/TrillionniumFoundation/Hepta/tree/cc79242ffb316ce3fbc1f2fd858a99886d2b5bb7/review-evidence/hia-native-rewrite-20261111/v70/recovery).
The original full-run failure index is retained in
[the fixed e03 evidence revision](https://github.com/TrillionniumFoundation/Hepta/blob/378d60da59ada59690768757849d2ac3fa836510/review-evidence/hia-native-rewrite-20261111/v69/recovery/e03-final-failure-index.json).
The reconstruction recipe and unavailable-workspace custody are retained in
[the fixed recovery recipe commit](https://github.com/TrillionniumFoundation/Hepta/tree/70bc0a6c57d9536664c7cba4bc665a3dc8ada854/review-evidence/hia-native-rewrite-20261111/v69/recovery).

Whole-native delivery, default activation, live migration and old-stack deletion
remain **false**. Adding the structural-budget candidate does not close public
live-heap policy, complete public normalization, all general backend profiles,
service and worker behavior, CLI/build/provider paths, or scalar-proof policy.
The `541a` normalization candidate still has its two cause-preservation
boundaries, physical stack behavior and Python 3.14 exception-note behavior open.
The structural owner also retains its explicit heap and final JSON/hash foreign
continuations. Final retirement is authorized, but it requires actual native
replacements and a fresh qualified chain before old owners can be removed.

## Prior v69 checkpoint: execution, static budgets and direct ledger pending

The current profile is
`selfhost-core-linux-x86_64-v69-native-execution-integration-pending`.
The published v68 source `e03c82d1b5b7026ead9a5942336d54273b1a6931`
is preserved in the actual ancestry. The integration now contains the HIA
execution owner for all 50 current Core opcodes and four terminators, its
extent-derived packet/terminal correction `f5bb6d4a`, installed-wheel/worker
binding controls, and direct-ledger lifecycle repair `66681872` with its
evidence-only documentation `12f8fb66`. Merge `705fb3d5` joins that ledger
history; no old owner or database row is removed.

The complete structural-budget owner is now integrated from `9028d181` with
its shared HIA signed limbs, stable graph code and explicitly bounded transport.
HIA selects all policy branches and report fields for call-depth qualification,
static event/tick analysis and bounded-resource coordination. The frozen owner
passed 29 component tests, 157 independent report/error comparisons, 3,515
actual native entries and eight complete independent VM frames; its separate
original public panel passed 39 tests. Those observations use the retained
predecessor compiler. They do not qualify this integration. The original
literal-identity, temporary-set lifetime and retained-traceback failures remain
preserved with their repaired observations. The worker helper registry and
checker now bind 21 single-image helper kinds and 28 semantic owner mappings.

The execution integration at exact source `4e4e60f4` passed 61 component
controls with zero failures, errors or skips. The scope includes 787 execution
differentials, 30,584 scalar mathematical cases, actual installed wheel
resources and a fresh isolated worker. These are explicit predecessor-compiler
development observations, not a cold or whole-source pass. The original
54-test/one-error run is retained separately. The subsequent identity-worker
fixture correction `7d664e7d` fixes a nested cold manifest path; both flat and
nested actual worker layouts, including fresh subprocesses, passed separately.

The selected direct ledger no longer imposes the earlier 192-byte field on
the four direct Python APIs. HIA owns original-object SQL binding order,
short-circuit lease checks, temporary consumption and row release. A real
temporary-result destructor previously changed the release decision; its
original failed observation is retained. Repair `66681872` passed 24 scoped
actual-native controls and nine independent source/VM controls on its own
frozen development export. This includes long names, stateful SQLite adapters,
original exception identity, installed wheels, concurrency and lost-return
custody. The original 48-test caller failures remain failures and require a
fresh complete integration run. These overlapping panels are not summed into
a whole-product test count.

The published v68 GitHub run `43050421476` has a separate retained result:
all 488 source tests passed, but native cold replay exceeded the unchanged
180-second budget, with completed owned cleanup. Its B1/B2/B3 bytes were
equal; the incomplete nested qualification is still a failed run. An
independent exact-e03 replay on `ai395` passed all eleven cold checks in
approximately 123.6 seconds under the same 180/3-second limits. Its original
244-test native-application group has one error from the nested identity
fixture path fixed above. That independent full runner is still being
observed; it has no final whole-source pass in this checkpoint.

The v6 runner retains the v5 groups and adds full execution/installed-worker
coverage plus the structural, bigint, graph and installed static/VM groups,
with all 39 matching-source cold selectors. The original cold,
component, full-discovery and whole-job limits remain unchanged. New source
does not inherit either a preceding component result or a preceding cold pass.

Full input normalization and live-heap analysis remain separate work in
progress. Structural coordination invokes the existing heap APIs at the
original HIA-requested points, and final JSON/hash operations remain explicit
foreign continuations. The entry-payload HIA graph/
report kernel has independent development controls but is not connected to a
public selector here. Hosted service, packaging, external provider and
remaining foreign computation boundaries are not erased by these changes.
Whole-native delivery, a default cutover, live-worker migration and old-owner
deletion all remain unqualified.

## Prior v68 integration checkpoint

The current profile is
`selfhost-core-linux-x86_64-v68-worker-ledger-integration-pending`.
Published v67 commit `3875e6bcd037d9d649e07ae5c4fcf7ce426f8210` is preserved
in the actual ancestry. Worker/helper integration `b9108c53` is joined with
that published source, followed by the reference-custody correction `aec8e044`
and native admission/fixture correction `60e4179b`. Merge `43c63ac2` additionally
joins the explicit slot ledger at `69e97bbc` without deleting an old owner.

The published v67 GitHub run `43034132760` failed both jobs. Its source panel
ran 470 tests with seven failures. Its native job passed cold replay in
161.613083468 seconds, all eleven cold checks, 5,049 nested checks and 1,242
language checks; its final 377-case nominal group had seven failures and three
errors. Later groups were not executed. Complete original logs and the
77,021,493-byte artifact remain retained. See
`HIA_REFERENCE_CUSTODY_COMPATIBILITY_20261111.md` and
`HIA_NATIVE_COMPOSITION_CI_20261111.md` for exact causes and bounded corrections.

The worker bundle retains explicit selection and now includes the actual
request owner; the checker identity covers all 26 integrated semantic native
owners and their immutable mappings. The slot ledger owns generation/epoch,
retained versions and reusable active leases on the original database/WAL.
It remains opt-in: independent actual-image review found that direct APIs can
accept longer slot names and other SQLite-bound values that its current
192-byte native field rejects. A real retained long-slot lease can execute
through the original API but not this candidate. This is an implementation gap,
not a test exemption. Full direct-input replacement must close it first.

The v5 qualification harness adds the ledger, worker-helper and checker groups,
all 37 matching-source cold selectors, and retained slot evidence. It preserves
the original 180/3-second cold limits and unrestricted 5,400-second full test
discovery. Fresh combined-source qualification remains pending. Public runtime
execution and complete input normalization are being implemented in separate
worktrees and are not represented as completed by this source checkpoint.

No default cutover, live-worker migration, all-input equivalence or old-owner
deletion has been established.

## Prior v67 integration checkpoint, before its published CI

The recovered continuation and main `5831f52fada45e076f8f68f198a15c0585e6104f`
are joined by the real merge `93128c470663bf9afe981b9bd4227c62c67b7f6e`.
Both histories and their original evidence are retained. The integrated
profile is `selfhost-core-linux-x86_64-v67-native-unified-nominal-journal`.
The subsequent graph-binding repair is integrated as
`185b7675d0c187686df35e1415e53f4b76449a8c`; generated source identities are
being frozen for a new matching-source qualification.

This candidate includes both explicit nominal-owner families, native
call/primitive and terminator lowering, the individual constructor/function/
module controllers, task-helper cache policy, execution budgets, the durable
request journal and the seven artifact namespace APIs. Conflicting owner
selections refuse instead of changing session ABI. Original function oracles,
foreign object identity, observable refusal prefixes, database tables and
existing rows remain intact.

Development and review observations retain their own exact source scope:

| Observation | Result and limit |
| --- | --- |
| Combined routing and default-reference panel | 94 passed; Python routing/reference evidence, not native composition. |
| Reconstructed admission repair | 42 passed, including the then-current 15 graph controls; the original one-failure run and the earlier mutable-action failure are retained. |
| Namespace candidate `056aacb1` with its explicit development contract union | 29 passed and the nested original 35 passed; earlier missing-package and original three-second deadline failures remain failures. |
| Independent namespace cleanup review | Two actual HIA/SQLite interruption controls passed; this is a narrow transaction-permission review, not a repeated full publisher/request gate. |
| Graph-binding repair `b29ca212` | Eight targeted controls passed with actual native entries and unchanged source/image/compiler inputs. |
| Independent review of that graph-binding repair | Sixteen bounded controls passed, including the three original mutable-receipt cases on actual machine images. |
| Retirement cold-report fixture repair | Two refusal controls passed; actual current-source cold fixture execution remains required. |

These panels overlap and must not be summed into a unique full-product test
count. Two executor resets caused loss of some local raw reports. Exact
recovered source, new reconstructions, newly reproduced failures and missing
historical raw evidence are identified separately. Historical passes do not
qualify reconstructed or subsequently changed source.

The complete remote preparation of `63fa2e7351c6b7e787e3834cbdbfe2307a08d872`
confirmed all 2,956 tracked files, the exact Git tree, no missing files, a
clean worktree and no alternate object store. This is preparation evidence;
the binding repair and generated identities still require transfer before
qualification. The v4 qualification runner preserves the original product
cold budget of 180 seconds plus three seconds for cleanup, ordinary suite
budgets and the unrestricted 5,400-second complete discovery suite. It selects
the new cold report for all 35 current component families and records exact
source and harness identities before and after execution.

No fresh combined cold/full pass, default cutover, live-worker migration or
permission to delete remaining production owners is established by this
status section. Worker/helper interface integration and the slot/version/
lease ledger are separate in-progress v68 work.

## Qualified v65 correction and its separate CI failure

Commit `ac0089d83f5ec1989f6c573b7e12f52ba4989599` is the corrected v65 source.
Its independent `ai395` cold replay passed all eleven checks in 70.863087
seconds, retaining the original 180/3-second limits. Compiler B1/B2/B3 all
have SHA-256
`81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109`.
Its complete retained discovery passed all 4,188 tests in 1,567.277167 seconds,
with zero errors, failures, skips, expected failures or unexpected successes.
Original summary SHA-256:
`731e3a3440e3590ee0c1003bb9ec785ddbb327f8f7b8e84ca546c730fd042c62`;
original result SHA-256:
`05e6a8d8d79a4bfd3bc23f449fd7d7b25f456248851397ac24e54134e295e21c`.

The same source's GitHub run `42989657354` has a separate failed native job:
its cold execution exceeded the original limit at 180.162331 seconds after
34 of 38 phase archives; cleanup completed in 0.083297 seconds with ECHILD.
The source job's 351 tests passed, but later native steps were not executed.
That original failure and its complete downloaded artifact are retained;
the independent pass does not relabel it. Neither result transfers to v67.

## v65 corrected source observations and compiler-path fixture repair

Commit `e80eacab2f85ad9c1217d7464ab9d8a940935090`, tree
`7e7091f5044a0e83fba3f7ed7c347a5663cc4e73`, passed both jobs of GitHub
run `42984401718`. Its source job passed 351 tests in 422.559 seconds.
Its native job passed a fresh 105.989258-second cold replay (all eleven
checks, 5,049 nested checks and 38 phase archives), 1,242 language controls,
and 706 unittest executions across nineteen groups. These groups overlap
source controls and are not a count of unique tests. Artifact `13839103463`
was downloaded and verified: 59,667,124 bytes, SHA-256
`c2174bcc30f9e8fc5de96f9e6607eced26ab978ac13694f32fd4a26d10521b11`.
The same source passed an independent `ai395` cold replay in 71.480926 seconds,
with the original 180-second qualification and three-second cleanup budgets.

The independent complete retained discovery of this source is **HOLD**, not
passed: all 4,188 tests ran in 1,579.995599 seconds, with one error and zero
failures, skips, expected failures or unexpected successes. The sole error
was `ArtifactPublicationKernelTests.test_copied_empty_PATH_link_verify_withdraw_and_kernel_object`:
its literal `/usr/bin/clang-20` executable was absent on that host. The exact
Clang 20.1.8 prerequisite was present and validated in a private prefix. The
error occurred before compiling the independent machine-code object.
Source and prerequisite inputs remained unchanged and owned cleanup completed.
Original summary SHA-256:
`d70f624a0fb6b3306acb8790c71cd48009fa09f85b5d9cd27470bee1716d5e0d`;
original result SHA-256:
`b74e15f82f9de0bfa09d91aba538b77f453fafb7708c5c31fe7738542bb2f8cc`.

The subsequent fixture repair resolves the required `clang-20` executable
from the qualified test environment and uses that exact path for both real
compilation and linking. It still fails if the required compiler is absent;
all object-byte, publication, empty-PATH execution and return-code assertions
remain unchanged. No system-path shim, test exclusion or success relabelling
is introduced. This repair changes the complete source identity and requires
its own fresh cold and full qualification before a pass can be claimed.

## v65 source-bound observations and retained historical fixture correction

Candidate `2ecda852a3eb69d27e25802daab26856a18db033`, tree
`13def5861bea96793809ccd4118eddf5eebfe134`, passed a fresh source-only cold replay
in 150.028493 seconds: all eleven checks, all 5,049 nested checks, original and
modified fixed points, unchanged 180/3-second budgets, and preserved source
bytes. Its compiler B1/B2/B3 digest is
`81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109`.
All 171 selected native nominal/retirement controls passed in 326.380 seconds,
with no skips or expected failures and all tracked source bytes unchanged.

The same candidate's 350-test source panel failed with two subtest records in
one historical fixture test: the new compiler's renamed source has 770,549
bytes, while both frozen v64 assertions require 769,584. The original failure
is retained. This correction keeps the old source/Core digest assertions
unchanged and supplies their exact original compiler source and function
mapping as a compressed test-only fixture. A separate current-source test
compares the composed transformation with all three original public passes
for both the current and modified compiler. These paths share the individual
rename helpers; the unchanged historical SHA controls remain the independent
byte anchor. The corrected 14-test fixture panel passed in 25.634 seconds.
The first v65 preparation attempt was separately refused before any export
because the regenerated language inventory was not yet rebound in the contract.

The fixture correction changes the complete source identity. It therefore
requires a new frozen head and fresh cold/full qualification. The preceding
results remain attached to `2ecda852`; no pass is transferred to the new head.

## Qualified v64 source

The following results belong to commit
`f313af44978c4d21e3e59806c6eb8b388109c29d`, source tree
`b8758007d44cadf204641d825e18b327940fa1fe`, profile
`selfhost-core-linux-x86_64-v64-native-match-selection-build-custody`.
They do not qualify subsequent compiler, nominal-operation or retirement changes.

| Observation | Actual result and scope |
| --- | --- |
| GitHub PR run `42970506711` | Both source and native jobs passed. The tested merge commit `66d5af7e223a98f8776a49addfd1ea5cbc9da181` was separately checked to have exactly the source tree above. |
| PR fresh cold replay | All 11 checks passed in 108.772 seconds; 5,049 nested checks and all 38 phase archives completed. Original B1/B2/B3 equality and the modified-source fixed point passed. |
| PR language controls | 1,242/1,242 checks passed. |
| PR native unittest groups | 608 executions passed across 18 groups, including 25 release-selection cases. Groups overlap some source controls, so this is not a count of unique product tests. |
| Local exact-source source controls | 323/323 passed, with no skips or expected failures and unchanged tracked bytes before/after. |
| Independent `rog` fresh cold | All 11 checks passed in 86.249 seconds, with matching compiler generations. |
| Independent `rog` complete retained discovery | 4,089/4,089 tests passed in 1,697.631 seconds; zero errors, failures, skips, expected failures or unexpected successes. Source and prerequisite inputs were unchanged. The original 5,400-second outer limit was retained and the owned process-group cleanup completed. |

The complete retained discovery includes its ordinary genuine cold-replay test,
which passed original and modified fixed-point reconstruction. The external
runner's `cold_replay_reexecuted: false` means it did not add another standalone
cold gate before unittest discovery; it does not mean that this retained test
was removed, mocked or skipped. Every cold execution retains the original
180-second qualification and separate three-second cleanup limits.

The original full-regression summary SHA-256 is
`ab415c92c648de480f80c9eb563813819a5b837d46a8c551c96f60bb379754d0`;
the original unittest result SHA-256 is
`bd417a477814ab736c12e779e92b7bfbec4df83caa3f7f8badabbd4fee587783`.
These identities describe the original retained observations, not newly
constructed substitute receipts.

GitHub's successful native artifact `13834066003` was downloaded and checked:
59,268,051 bytes, SHA-256
`032433d4493ad36c33f4b5d3cf9cd4aa5fac036c84afdeca85652144b5a36ffd`.
It contains the cold and language reports, compiler images, phase archives
and native release observations. The independent retained-regression archive
contains selected original reports, logs and the three compiler generations;
its inventory records preparation command-alias symlinks without following them.
Generic Cargo build cache is not claimed as retained qualification evidence.

## Failed observations remain failed

The local second cold replay and separate push run `42970496364` each reached
the unchanged 180-second deadline. They remain failed observations with their
original logs and cleanup results. Passing PR and independent-host runs do not
change those outcomes or establish a universal wall-clock bound across hosts.

The original release-selection development candidate accepted surplus empty
arguments to `status`; a later candidate fixed actual-argument-count admission.
The first combined selection test run also found an evidence-directory fixture
collision, which was fixed with separate per-class directories. Original logs
are retained separately from corrected runs.

Cloud syscall fault injection initially failed at the actual ptrace permission
boundary. The same development image subsequently passed the ten-case real
kernel/fault group on `ai395`; current-source CI ran the complete 25-case
selection group. The permission failure was not counted as a passed or skipped
native control. Remote preparation's original shared-memory quota failure and
two later evidence-archive script failures also remain recorded independently
from the successful qualification they preceded or followed.

## Next source profile

The v65 work adds complete enum construction/tag lowering, ordinary record
construction/unpacking/projection, partial-record transitions and field borrow,
all seven ordinary task operations, a retained native retirement policy, and two bounded native compiler traversal
changes. Its source closure, installed resources, cold replay and affected
native tests must be qualified together. Development images and the v64 results
above do not establish that qualification.

Native retirement is an in-process owner of cleanup decisions and state. It
does not replace the AgentStore journal, the multiversion generation/capacity
owner, the deployed runtime, or a release-consumer registry. A quarantined
uncertain resource is not released through a guessed or replayed effect.
The retirement candidate passed 29 development tests, including a nested
unchanged 69-test retirement/publication/multiversion suite with hosted policy
disabled. Independent review passed eleven actual-machine fault and custody
scenarios. A final test-only opcode tracing adjustment passed its two affected
controls in a fresh process. Original replay, attachment and interrupted-open
failures remain preserved. This evidence does not qualify the combined v65
source or establish durable recovery across process death.

The remaining ordinary CLI, Agent service/journal, compiler profiles and
deployment owners keep whole-native delivery and old-stack deletion incomplete.

## Earlier retained status entries

The following original entries are retained as historical observations. The current continuation and source identities are stated above.

# HIA native rewrite: current source, implementation and remaining owners

Further continuation is recorded in the
[self-rewrite audit](HIA_NATIVE_SELF_REWRITE_AUDIT_20261111.md), including native
enum-match CFG generation, release-selection state and the expanded builder
custody review. The observations below retain their original source identities.

The subsequent v62 integration combines the v61 returned-loan origin work with
native worker-request admission, immutable release publication and bounded
cold-evidence scheduling. Its audited baseline,
new source-bound observations and remaining delivery owners are recorded in
[the continuation audit](HIA_NATIVE_CLOSURE_20261111.md). The earlier experiments
and failures below retain their original source identities.

Baseline audited on 2026-11-10 America/New_York:
`c2d937e5eec734af5c1d5d0519afc7e3a91df58a`.
The repository is `TrillionniumFoundation/Hepta`; product development continues
on `main`. The separate archival source-recovery PR #887 is not an adopted
compiler or an alternative product line. This report does not restore the
retired high-level language. Git history and original failed observations remain.

**Whole HIA-native delivery is not yet qualified.** The checked-in HIA compiler,
complete primitive checker, native workspace filters and native applications
are real implementations. The installed `hia` entry, Agent request authority,
build/install ownership and other retained components still contain Python.
Removing those owners now would remove supported behavior, not finish its port.

## Current continuation: v64 complete selected nominal integration

The current source integrates the constructor and outer-program owners on top
of v63 `31d81594997cfb6cce5ab62ea5aaba3bb7757af1`. Five explicitly selected
owners now execute eleven HIA images: types/signatures, task helpers, complete
functions, constructor admission and outer aggregation. Their responsibilities,
dependency requirements, protocol bounds and remaining hosted custody are
specified in [the integration contract](HIA_COMPOSITE_NATIVE_INTEGRATION.md).
Default activation, a native standalone normalizer and whole-stack retirement
remain open. Neither a selected path nor a source contract is a release pass.

Constructor HIA preserves document/function admission, signature and origin
ordering, unused task checks and partial state at the first refusal. Outer HIA
preserves source function order, helper aggregation, late expanded block/function
limits, export eligibility and ASCII sorting, and the v1-to-v6, v2/v3-to-v7 and
v4-to-v8 schema mapping. Opaque function-result handles avoid introducing an
early expanded-output byte limit. The final primitive checker still runs.

Independent review found an actual helper-header mismatch accepted by the first
outer candidate. The corrected HIA owner checks the helper response against its
actual immutable arena before issuing a result. Protocol failure permanently
poisons that outer invocation. The original faulty result is retained in the
recovery branch; it is not counted as a passing test of the corrected source.

The v63 public cleanup remains in place. The new owners additionally release
partial allocations, unpublished type sessions and borrowed function-workspace
references. Actual tests hold exceptions and tracebacks alive while observing
buffer release. Private stateful reference controls remain separately callable.

### Development observations and exact limits of their claims

The complete 15-module nominal group ran 117 tests with zero errors, failures,
skips, expected failures or unexpected successes. It recorded 306,716 actual
parent-process entries into the eleven images, took 681.1583847719994 seconds,
and preserved all source/image pins. Constructor comparisons include 150 complete
state outcomes; outer comparisons include 23 canonical results. The installed
joint control builds a real sdist, builds its wheel, and runs with `-I -S`, empty
PATH and the old semantic owners disabled. Twenty missing/changed new resource,
image and bundle controls refuse. The existing independent function installation
control remains mandatory. Thirty-four focused source/protocol/fixture controls
also pass. These are explicitly bootstrap-development observations for the frozen
stage-3 source, not final-source cold or full-regression qualification.

The full installed-resource class initially ran 17 tests on the available Python
3.12.14 runtime: one failed because that interpreter's `fcntl` lacks
`F_ADD_SEALS`. The existing Python 3.13.5 runtime passed an actual sealed-memfd
probe and then all 17 unchanged tests, including native publication. Build-only
packaging dependencies were reused; the installed children still used `-I -S`,
empty PATH and no PYTHONPATH. No production constants, assertions or tests were
changed to accommodate the first environment. Both original runs are retained.

The three original raw archives contain 1,687 regular files and 144,448,794
uncompressed bytes. Independent readback verified every byte count, SHA-256 and
mode. Source manifests, compiler generations, input/output buffers, logs,
observations, both installed attempts and the final handoff are under
`review-evidence/hia-native-rewrite-20261111/v64`. The published source adds this
audit, README and inventory after the frozen development run; its generated
support contract is therefore refreshed and requires a new exact-source cold
qualification. The original 180-second deadline and two cold workers remain.

### v63 qualification result retained without promotion

GitHub HIA run `42977949269` tested exact v63 commit `31d81594997cfb6cce5ab62ea5aaba3bb7757af1`.
All 292 source tests passed. The cold wrapper passed all 11 checks in
160.646645785 seconds, with 38 fresh phase processes, at most two workers,
5,049 phase checks and complete cleanup. All 591 source/contract payloads match
the Git source. The 1,242 language checks and ten assertions also passed.

The native application group then ran 242 tests with one failure: the installed
resource test incorrectly inferred a distinct Python bridge module from every
HIA basename. The five function kernels actually share one `SOURCES` bridge.
Thirteen later native groups were skipped by the workflow. The complete v63 HIA
workflow is therefore FAIL/HOLD; its cold and language passes do not establish
complete native acceptance. CodeQL run `42977948746` passed independently.

v64 fixes the complete resource mapping, including the four new constructor and
outer sources, without reducing the inventory or adding dummy modules. The
complete original v63 GitHub artifact was retained. Independent streaming
readback checked all 38 nested cold archives (42,623 members) and both language
archives (12,234 members), including their original inputs, bytes and modes.
The small original cold/failure evidence archive and custody are committed under
`review-evidence/hia-native-rewrite-20261111/v63/github-final`.

The independent ROG v63 full run is separately tracked. Its original insufficient
storage preparation remains HOLD; an alternate existing execution volume passed
the unchanged preparation and launched the original full run. Subsequent source
and component logs report `EDQUOT` while writing test files. Those failures are
preserved and require quota-aware environment diagnosis. They are not silently
retried, attributed to language semantics, or counted as full acceptance.

## Audit coverage and evidence

The [machine-readable inventory](HIA_NATIVE_REWRITE_INVENTORY.json) records the
complete indexed-file ledger, current file bytes and SHA-256, every retained
Python module's parsed imports, direct repository callers, public definitions,
native-source literals and explicit native selection variables. The collector
is `tools/audit_hia_native_rewrite.py`; it executes no inspected code. Missing
dynamic or external callers are explicitly unproven. This is complete static
accounting, not a claim that every line received a semantic proof.

The baseline contains 2,388 Git blobs, 1,039 Python files (including tests and
research), 144 production Python modules, 46 HIA assembly files and 12 Core JSON
source files. The patch and raw Agent result adapters add hosted custody modules
while moving transformation and diagnostic construction into HIA. File-count ratios are not a useful measure
of semantic completion; the current exact counts are in the inventory.

Baseline Actions run `42891040706` was independently read, including original
job logs: 216 source tests, 392 native component tests, 1,242 language checks,
10 language assertions and the 11-check cold wrapper passed. Original compiler
generations agreed; the modified compiler reached a distinct fixed point.
Those results qualify that original source, not this changed source. The raw
artifact metadata was read, but its entire archive was not relabelled as a
new independently replayed result.

Development and final qualification evidence is retained under
`review-evidence/hia-native-rewrite-20261111`. Development receipts preserve
their original source identity and failures; the final qualification record
must name the exact common source manifest. A source contract or compiled
image hash is an identity, not a qualification pass.

## Implemented in this continuation

### Immediate visibility of returned capabilities

The native complete Core checker previously created all results of a `call`
before adding them to the live capability inventory. A later result could
therefore miss an earlier conflicting mutable/shared return from the same
call. The independent reference rejected those programs.

Each returned owner or loan is now published to the live capability inventory
immediately; the enclosing instruction does not publish it twice. Actual old
and fixed native images were compared on four conflicting return patterns and
three legitimate patterns. The four old false acceptances now return
`E_HIA_LOAN`; valid shared and independent-owner cases remain admitted.
A fixed-seed differential exercised 30 real fixtures and 12,000 mutations,
with no remaining acceptance or error-category differences in that panel.
The minimal trap-only callee witness establishes a static policy mismatch;
it is not evidence of a demonstrated dynamic memory-corruption exploit.

### Direct HIA assembly in the native application

The native stdio application supports `capabilities`, `verify`, `compile`,
`render-assembly` and `assemble`. Direct assembly preserves the explicit build
profile (`flat`, relocatable ELF or executable ELF), keeps a separate inclusive
1 MiB input ceiling and retains semantic/resource refusal. It does not infer a
different language or output profile from the payload. Original and modified
HIA compiler sources can use the executable self-compilation path.

### Snapshot-bound structural edits in HIA

The [native patch application](HIA_CORE_PATCH_CLI.md) consumes `[BASE, PATCH]`,
extracts and fully verifies the original primitive Core, verifies its canonical
SHA-256 identity, applies the requested edit and fully verifies the candidate.
Only then may candidate JSON reach stdout. The two immutable HIA images run
four stages in one Linux x86-64 executable; no payload parser, serializer,
checker or editing interpreter is delegated to Python at runtime.

It supports function replacement/addition, operation replacement and terminator
replacement; exact target types; 1–64 edits; overlap refusal; v1 interface
preservation and explicit v2 preserve/migrate behavior. Original component-byte
quotas remain independent of canonicalized output length. Primitive v1–v8
Core admission is mandatory for both sides; nominal/composite normalization is
not silently erased. The application does not grant filesystem publication,
request replay, ref issuance or deployment authority.

The existing public patch path can explicitly select these kernels. The
installed source is packaged and participates in actual worker identity;
missing/changed resources or invalid selected manifests refuse without fallback.
The host adapter still materializes its existing Python result object and owns
its surrounding transaction. This preserves the existing ordinary caller while
the complete native Agent is still being built.

### Raw ordinary Agent patch results

The explicitly selected ordinary `hia_candidate` patch branch now passes the
authorized base and patch bytes directly to HIA. It does not construct Python
Core/patch objects, call the hosted verifier/editor or compute signatures and
receipts in Python. HIA returns the canonical candidate and complete existing
diagnostic bytes; full native Core admission still precedes and follows editing.
The existing store receives two opaque payloads and retains ref/context authority.

The independent [patch-result executable](HIA_CORE_PATCH_RESULT_CLI.md) exposes
the same calculation as `hia-patch-result v1|v2`. It writes a bounded `HIAPAR01`
frame only after both admissions. Candidate execution is still false; an editor
running natively does not mean the edited program has been executed. Original
artifact hashes remain distinct from canonical snapshot hashes. Existing v1/v2
receipt fields, interface sorting and default returned-loan equivalence remain.

Independent development controls compared 540 native cases (198 accepted and
342 refused), 11 actual Agent/SQLite cases and 10 HIA-packed CLI controls, with
no remaining difference in their covered behavior. The focused nine-test Agent
suite passed, including a real isolated installed wheel and four real SIGKILL
cut points: committed intent, published candidate, published diagnostics and
committed terminal response. The first three remain unknown after restart;
the last replays the retained response. A completed replay precedes any new
image admission. This verifies compatibility with the existing hosted journal;
it does not replace that journal with a native implementation.

The original local ptrace failures, a corrected `return_loans` test-fixture typo
and an initially incorrect cache-invalidation test remain in the evidence.
Development tests are not substituted for matching-source cold qualification.

### Complete nominal type sessions in HIA

The explicitly selected [nominal type owner](HIA_COMPOSITE_TYPES_NATIVE.md)
now performs the complete declaration and layout responsibility of `_Types`
in HIA for composite v1 through v4. This includes unused declarations,
generic applications and lexical bindings, by-value cycles, record/enum/task
layouts, stored-loan constraints, partial records, exact cache/active state and
the existing work budgets. The ordinary elaborator consumes native descriptors;
it does not rerun the hosted type algorithm on the selected path.

Private nominal keys are exact interned type identities in a held session.
They do not expand a shared zero-width type graph into an exponentially large
display string and never enter public normalized Core bytes. Primitive keys
remain their original strings. The 128-definition/instantiation, depth-32,
64-field, 32-variant, 512-slot and 32,768-step language limits remain explicit.
The arena layout accounts for lexical alias calls that do not increase layout
depth; their frames share a proven bounded region with symbolic nodes.

Development controls include independent Core VM execution before native
compilation, exact layout/error/state/counter differentials, four-version
ordinary normalization with the old type owner disabled, and an actual installed
wheel with build-tool imports forbidden. Original development observations are
retained by source/image identity. The independent boundary review also found
an init-envelope overhead issue at the original 8 MiB input limit; its failed
observation and correction must remain separate from earlier development passes.
The corrected private command envelope permits 8 MiB plus 128 bytes, while
public Core retains its original 8 MiB input, 262,144-node and depth-64 limits.
The complete program-to-command bound is at most five extra bytes, including
malformed inputs that reach the type owner. Five actual native-entry cases at
the public boundary preserve the hosted `E_HIA_FORMAT` result; an extra public
byte still returns `E_HIA_LIMIT` before native entry. The final development
suite passed all 18 tests. Independent raw ABI controls admit the exact private
limit and refuse one extra byte with output/state boundary canaries intact.
This v60 type owner did not replace the operation elaborator, task helper
generation, returned-loan origin lowering, default installer or durable Agent.
The additional v61 origin-resolution boundary is described below.

A further independent fixed-seed panel executes the same r3 native image for
96 seeds and 1,032 initialization/resolution state observations. It compares
record, enum, task, generic and partial combinations, unused invalid declarations,
and state/counters after refusals against the retained reference. No differences
were observed. The original source/image identities and all observations are in
`review-evidence/hia-native-rewrite-20261111/v60/continuation`; this is development
evidence, not a new cold result or proof of equivalence over all inputs.

### Shared native builder source binding

The audit found that the shared JSON/kernel builder accepted a completed cold
report based on compiler hashes without checking the current complete source
manifest. It also accepted JSON `false` as a zero return code through Python's
integer equality. The builder now requires the current profile, exact integer
zero, every cold check, the complete source/contract map and the selected source.
It rechecks source, compiler and report bytes before publishing a manifest.
Custody controls reject stale/missing/extra source identities and changed build
inputs before publication. Their recording compiler stub is explicitly not
native execution evidence; actual native suites retain their separate gates.

The same complete gate now runs in outer application builders before they create
their parent output directory. Eight builders share this admission and recheck
the complete source map before publication; the existing workspace pipeline
keeps its independent full gate and now also requires an exact integer return
code. Nine application paths were checked against ten malformed or stale cold
receipts for both absent and pre-existing output directories: 180 refusal-boundary
observations preserve prior bytes, modes, inode and directory contents. Valid
bindings reach the native-build stage. These controls deliberately stop at that
stage and do not create a synthetic native qualification pass.

### Preserve cold evidence while removing repeated host work

The assembly source boundary uses the same exact forbidden-control-character
set through a compiled regular expression. Input limits, UTF-8/BOM handling and
error order remain unchanged. Name-limit fixtures reuse pure source-string seed
constructors instead of reconstructing unrelated accepted programs merely to
select one string; each actual reference case still executes its own admission,
assembly, interpreter and refusal controls. No qualification result is cached.

The complete old/new name-reference result is byte-identical: 2,447,154 bytes,
106 positive cases, 40 refusals and 52 programs. One local development comparison
measured 24.038 seconds before and 20.145 seconds after; 5,213 source inputs
retain their full outcome/error observations. These timings do not establish
a GitHub cold pass. The unchanged 180-second cold deadline, all 38 phases and
the original/modified compiler generations remain mandatory.

### Qualification observations

The published baseline for this continuation is
`c80eb2ecc5d08421a3d124c879edb33cefff2267`.
Its [Actions run 42949936235](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42949936235)
passed all 252 source tests, source reproduction, contract and inventory checks;
the separate CodeQL run passed all four language jobs. Its native job reached
the unchanged 180-second deadline at 180.091261 seconds. All 562 cold source
entries were matched to the exact Git blobs. Thirty phases completed both
execution and evidence sealing; two further explicit-trap workers returned
PASS but did not finish sealing before the timeout. The remaining six phases
did not start. There is no observed semantic-failure witness in those 32
reports, but this is a failed cold run and every later native CI step was
skipped. The original 41,214,916-byte artifact has SHA-256
`c1d137bf8f54afaff613e725c152e84ecb19cab20fd03f94531e8392ffef11ec`.

A separately prepared ROG run of the exact same clean `c80eb2e` tree completed
all 11 cold checks in 109.429 seconds and all 38 phase seals. The downloaded
67,591-byte cold report has SHA-256
`971cf03b74246da621d2681dfd306c2d798637beee3b3bc8c707a51112df1e2a`;
its entire 562-entry source manifest was independently matched to the same Git
commit. Original B1/B2/B3 hashes agree and the modified compiler reaches its
distinct fixed point. Language and every explicit native component group
passed, including 18 type-session tests, nine ordinary Agent candidate tests
and 16 patch-result CLI tests. Its full retained regression then passed all
3,931 tests in 1,802.846 seconds, with zero errors, failures, skips, expected
failures or unexpected successes. The final status is `FULL_RETAINED_PASS`;
all 2,532 complete-source entries match that Git tree and the before/after
source snapshots and runner identities are unchanged. Its final report has
SHA-256 `1427e146e568c570c687e3e8cc4e6e1ff76f520392c7e6e1b19705c000798d64`.
The previous v59 temporary-directory/socket failures remain original failed
observations; this is a fresh completed run under the corrected preparation.
Neither this host result nor any older passing run turns the GitHub timeout
into a pass or qualifies the changed v61 source.

### v61 source continuation and development controls

The selected HIA type session now also owns the complete source-level
`_Elaborator.loan_origins` decision: annotation arity/absence, original formal
names, nested record paths, exact flattened offsets, owned-origin refusal and
read/mutable permission. Its `HIALOR01` frame preserves type-session counters.
The ordinary v4 path transports issued type identities and consumes native
results without invoking the hosted helper. Final binding to generated Core
entry names remains in the operation elaborator. Public input limits are
unchanged: the private command is at least 103 bytes and eight nodes smaller
than the smallest corresponding reachable public envelope. Native shape/name
diagnostics preserve categories and refusal ordering; their English context
is not claimed to be byte-identical to the hosted helper.

The new HIA source has SHA-256
`8c6fe9a4a3850838038e172c38ea08f16a86d8a03e7c47c250a805888a616cee`.
An independent panel executed its actual development image on 64 different
record/generic DAGs and 1,536 origin scenarios: 320 accepted and 1,216 refused,
with no result, error-category or first-semantic-error differences. All 18,420
observed native entries preserved their input bytes. Every origin command
preserved counters and left later resolution usable. The original incorrect
test expectations for two decimal-ID fatal statuses are retained separately;
the corrected assertions and installed-wheel controls passed. These are
development observations, not matching-source cold qualification.

The host reference's snapshot and independent structure passes remain distinct.
Container-only capture frames and a direct-node verification stack remove
temporary task allocations while preserving traversal/error order, aliases,
cycles and all budgets. A per-call, at-most-1,024-entry string-size arithmetic
table counts each occurrence separately and never caches an admission. Its
length lower-bound gate precedes hashing; an admitted-length malformed string
may still incur a bounded hash before its original surrogate error. Independent
mutation controls and exact boundary/error differentials found no semantic
change. All 105 focused structure/Core controls passed. Complete names, signed
and scalar-cast reference reports remain byte-identical; final single-run
combined wall time was 44.901 versus 44.622 seconds, so a large full-cold saving
is not inferred from faster component CPU measurements.

The JSON reference scanner skips only ordinary spans using exact character
classes. Both preflights and both explicit native selectors remain active.
An independent 281,836-case panel found identical returns and complete exception
type/text, including all escaped and raw BMP units, surrogate pairs, malformed
continuations, mutable-input-free grammar/budget cases and selector boundaries.
Real selfhost attributes still invoked both preflights 5,630 times each. Five
interleaved timing rounds improved aggregate wall time by 6.53%; this is a
local workload observation. Archive buffer and ZIP_STORED experiments did not
show a dependable benefit and were not merged. No deadline, worker count,
phase, witness or evidence-retirement requirement was reduced.

The first combined local development invocation correctly refused a stale
contract produced before the regenerated language inventory; no terminal
qualification pass was observed for that invocation. After regenerating the
contract in dependency order and checking the fixed point, all 71 focused
source/adapter controls passed. Raw observations and source identities are
retained under `review-evidence/hia-native-rewrite-20261111/v61`.

The published v61 commit is
`647885c5c3ff067b6477011123335ad5a1aef78e` (tree
`1c7679357590a9105c666dea95105780b64098fc`). Its
[Actions run 42958081511](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42958081511)
passed all 268 source tests in 507.900 seconds, source reproduction and the
contract/inventory checks. Its separate CodeQL run passed all four jobs.
The native cold run failed at 180.191299 seconds: 32 of 38 phases completed
and sealed, with 3,718 true and zero false checks in those completed reports.
The two CLI phases started but did not return complete reports; the remaining
name/export phases did not start. All 564 cold source entries were independently
matched to that exact Git commit, and the 32 complete nested archive compressed
bytes matched their producer receipts. This timing analysis does not claim a
second replay of every nested member. Cleanup completed, and later native CI
steps were skipped. The original 40,821,695-byte failure artifact has SHA-256
`23afbe7694f1d549f27b5eafa8d23f4c536985492ac289307913803487d72aaa`.

### v62 parameter, protocol and task-helper owners

The selected type-session image now owns the complete ordered parameter
admission and task-protocol checks. Parameter list/shape/name/duplicate checks
and type resolution retain their original order, including partially resolved
types, counters and usable session state after semantic refusals. `HIAPRM01`
returns native-issued nominal identities and complete descriptors. Task checks
consume the complete function-signature registry and compare exact nominal
identities, poll/cancel arity, state/result types and the pending/ready enum
protocol. Structurally identical but distinct nominal types remain distinct.
The private transport introduces no additional public parameter limit. Its
1,024-signature bound is the original public function bound.

The frozen parameter/protocol HIA source has SHA-256
`8fec677e2a7be2292241a4ecf51c0e4c807a63f945928dd3c8eb03a79a42d749`.
Independent development review compared 3,023 semantic scenarios and eight raw
ABI refusals, observing 10,579 actual native entries. Complete graphs/cache
keys, counters, partial state, first errors and post-refusal usability agreed.
Depth 32/33, 512/513 flattened slots, exact registry/type limits, phantom
generics, nominal twins and input mutation boundaries were covered. This is
an independent finite panel, not a proof over every input or a fresh cold pass.

The separately selected [task-helper owner](HIA_TASK_HELPERS_NATIVE.md) now
constructs complete `start`, `poll`, `cancel`, `join` and `close` Core functions
in HIA. It owns generated names, blocks, guards, poll variants, effect sets,
offsets, cancellation, inactive-slot cleanup and padding. The host transports
resolved descriptors and copies the complete result. Exact counter/cache
updates on partial refusal are preserved; no incomplete function is appended.
Its frozen source has SHA-256
`1f0a38ab1235de3ffc35ca3ca01ac327bbea3ceadac99a995d3b550b630790cd`.
An independent 2,774-case panel, including 1,874 actual image entries, found
no complete-result/error-text/state differences. It includes 70 maximum public
layout controls and separately identifies 448 direct-loan controls that are
unreachable through admitted task source.

The two owners were also exercised together on six ordinary task documents:
complete canonical/structured bytes agree, 34 VM execution/resource outcomes
agree, and an actual installed wheel succeeds with the hosted type resolver,
parameter/task checks, source loan-origin helper and task-helper generator
disabled together. Missing/changed installed HIA resources refuse. An actual
ELF comparison used the retained direct x86 backend with HIA-generated helpers:
eight executions observed four allocations, four frees, four allocator refusals
and no live allocations; four illegal transitions aborted. That backend remains
a separate owner. The combined tests do not replace matching-source cold and
full retained qualification.

### Remove repeated fixture construction admissions

The public assembly parser and renderer still perform all of their original
source/syntax checks, complete Core admission, detached object handling and
renderer round-trip verification. Private construction helpers now let the
name/entry fixtures transform fresh syntax documents before their consuming
reference performs its own complete admission. They return unverified bytes or
objects, never `VerifiedProgram` authority. No admission, program execution or
qualification result is cached.

An independent static review matched the parser, renderer, actual reference
consumers and negative corpus to their original ASTs. A 684-case public boundary
panel retained complete return bytes or exception type/code/text/phase/line and
actual verifier invocation counts. A separate complete invocation ledger found
that all 150 retained public assembly witnesses and 137 retained Core gates
match individually, including two direct generator admissions. The removed
474 Core calls belong entirely to pure fixture construction. The 106 VM-positive
controls, 40 bounded-profile refusal controls and four alpha assemblies remain;
of those 40 controls, one is accepted by general Core, 15 stop at assembly syntax
and 24 reach a semantic refusal. General Core admission is not relabelled as a
bounded compiler-profile acceptance.

Four interleaved runs of the unchanged 17-family reference worker harness each
used two workers and returned exactly the same 13,726,901 aggregate bytes, SHA-256
`805cb0d0ea1a32dfb4262b7b2d2f0e4e7460fd8ca89c7a1665e25645db3a0b60`.
Measured old times were 37.765/35.245 seconds and new times 28.897/29.831 seconds.
The median saving was 7.141 seconds (19.56%) for that local reference workload.
All workers were fresh and source/contract checks ran in every round. This is
not a complete cold qualification or a prediction of a specific CI wall time.

Before this construction change, the first local integration invocation selected
the entire contract-test module and consequently also ran its real cold replay.
It passed 29 other controls but timed out at 180.153882 seconds with 35/38 phases
sealed according to the original failure diagnostic. Cleanup completed in
23.193 ms. Its original failure remains separate from the subsequent focused
source group, which uses the same contract test class as CI. A live partial copy
preserves 32 phase archives with 36,342 checked members; the earlier index records
28 completions. These are distinct observation times. The complete final cold
report/index was not retained by that temporary-directory unit test, and the
partial copy is not labelled a complete final artifact or a pass. Neither the
cold deadline nor the full retained suite was changed.

After integration, all 40 HIA source generators and the inventory/contract fixed
point reproduced successfully. The exact combined source then passed 29 focused
source/adapter/installed-resource/workflow controls and all 53 selected native
type/origin/signature/helper tests, with zero errors, failures, skips, expected
failures or unexpected successes. The 570-entry source closure remained unchanged
before and after those tests. These development results do not promote the
pre-fix local timeout or the older GitHub timeout into a pass.

### Exact-source v61/v62 failures and JSON dispatch regression correction

The complete retained qualification of published v61 commit
`647885c5c3ff067b6477011123335ad5a1aef78e` ended in **HOLD**. Its first
21 steps passed, including all 11 cold checks in 95.954178227 seconds, but its
full retained suite reported 3,954 tests, one failure, zero errors, zero skips,
zero expected failures and zero unexpected successes in 1,733.781273 seconds.
The final report SHA-256 is
`902409a9ed1c792f66eb264566b985ad9db6359d325fc49b66706f015e74536e`.
Both complete source snapshots independently match all 2,587 Git blobs and
modes of that commit. The successful earlier steps do not turn that full-suite
failure into a pass or qualify later source.

The failure was in the original-regression subprocess of
`JsonPreflightHiaNativeTests.test_existing_api_dispatch_and_unchanged_original_regressions`.
Two added host-scanner tests expected detailed reference-scanner English after
selecting the unchanged native scanner, whose existing syntax/Unicode ABI
returns the generic diagnostic. The subprocess also still asserted the older
literal `Ran 6 tests`, although the module contains nine tests. The native
adapter, generated HIA scanner and its generator are byte-identical across
c80, v61 and v62; this observation is a test-contract discrepancy, not evidence
of a new production acceptance or rejection difference.

The correction exercises each detailed reference diagnostic explicitly and
separately requires the selected native route's exact existing diagnostic.
Unencodable caller-owned surrogate strings retain their original reference
route. The subprocess reports every current test ID and all six outcome counts;
both parent and child reject an empty suite and require complete execution with
zero errors, failures, skips, expected failures and unexpected successes.
The full native preflight test module is now included in the actual native CI
applications step. The native ABI, public dispatch and scanner algorithms are
unchanged. Development checks and the original failed evidence are kept under
`review-evidence/hia-native-rewrite-20261111/v62-followup`.

Published v62 commit `d6847ac891e0dd07217d179891bb763162211de2` has a separate
GitHub observation: Actions run `42962692808` passed its source job with 278
tests in 254.367 seconds, but the native job's cold replay failed at 180.156933
seconds with 6/11 outer checks and 34/38 phases sealed. Completed phase reports
contain 3,758 true checks and zero false checks; missing names/exports results
are not counted as passes. All 570 cold source entries match that exact commit.
Process cleanup completed in 61.809195 ms, with ECHILD observed and no remaining
children or cleanup errors. The original 46,307,599-byte failure artifact has
SHA-256 `345ea7e8635b6a4603e56eb6fa3f638bc2241e385983652bcb01fb4770929db6`.
The complete artifact, original logs and scoped source/phase analysis are
preserved. This timeout remains a failure; neither the 180-second deadline nor
the two-worker budget was changed.

### Batched signed/cast fixture construction

The signed and scalar-cast batch constructor now uses the same private syntax
parse/spelling helpers as the name-fixture transformation. Its grouping,
rebasing, constant sharing, 12-case maximum and original 2,048-value/8,192-op
limits are unchanged. This utility returns unverified syntax; early refusal of
arbitrary invalid intermediate inputs is not its admission contract. Every
actual final reference still uses the original public assembly/Core/VM gates.

An independent replay of the before/after invocation ledgers compared all
1,420 actual calls in original order: 710 Core checks, 346 VM executions and
364 public assemblies. Inputs, keyword arguments and complete results or
exception identities all match. The complete signed/cast reference is exactly
5,808,503 bytes in both versions with SHA-256
`d58330121ae82ece2364366ffe8c11aac8080164156bf1c846e5b76c2940060e`.
All 52 signed and 58 cast batches, 236 traps and 18 refusals remain. The removed
506 Core calls and 396 public assemblies belonged only to intermediate fixture
construction; no actual VM execution was removed. A new negative control feeds
a syntactically constructible bad helper through the unchanged consuming
reference and observes its original Core SSA rejection. The existing test
methods remain intact; the complete two affected test modules pass 14 tests.

Four interleaved fresh-process panels each ran all 17 reference families with
two workers. Every full 13,726,901-byte panel is byte-identical, SHA-256
`805cb0d0ea1a32dfb4262b7b2d2f0e4e7460fd8ca89c7a1665e25645db3a0b60`.
Observed baseline times were 30.501287 and 27.590464 seconds; candidate times
were 26.281226 and 26.351774 seconds. These development measurements ran in a
shared environment, including overlapping development work. They establish no
specific CI speedup or complete cold qualification. All original ledgers,
reference bytes, worker receipts, source manifests and independent reviews are
retained with the follow-up evidence.

The first published v58 tree was exactly
`243ca1d7d25ba485681488ea330ff81167e0fff1`, committed as
`f174f9b970e227a2c6d3b98ea115cedba7f4e316`. Its Actions run `42933658467`
passed all 11 cold checks; the downloaded archive's SHA-256 and all 548 cold
source-manifest entries were independently matched to that exact commit.
The workflow failed because the language inventory retained the old profile
and support digest. Commit `ecf6886f43e325c411be38fea172bba0d79d7230` regenerates
both the inventory and its source contract. The failed workflow and original
logs are retained, without turning skipped later stages into passes.
Its new run `42934701069` passed both jobs: 222 source tests, 424 native component
test invocations, 1,242 language checks and 10 assertions, plus the 11 cold
checks. That exact v58 qualification does not qualify later v59 source edits.

The v59 commit `95ba911c347f8ef19cead56d04219093705219cf` passed 229 source
tests. Its first native attempt hit the unchanged 180-second deadline after
34 completed phases; all 3,758 checks in those completed phases were true.
Its second attempt passed all 11 cold gates, 38 phases/5,049 nested checks,
1,242 language checks and 10 report assertions. The archive and all 555 declared
cold-source entries were checked against that exact Git commit. The native job
still failed: nine Agent tests stopped in setup because `jsonschema` was absent;
the other 16 tests in that last group passed. Those nine errors are not passes.

Commit `bfea47b6267e4a2b18acb45e114aafcd9f466b1a` pins the missing CI dependency
to `jsonschema==4.26.0` and rebinds the source contract. Its first source job
passed 229 tests; cold again reached 180 seconds after 32 phases/3,718 checks.
All retained completed-phase checks passed, and process cleanup was confirmed.
Its only retry again timed out at 180.139949 seconds. The phase index records
28 completed phases and 2,876 true checks. Two additional scalar-cast reports
were actually written and independently verified, adding 736 true checks,
but remained pending in the index. The retained evidence therefore contains
30 independently checked reports and 3,612 true checks, without a complete
cold pass or any language/application test execution. Cleanup completed in
47.535 milliseconds with the leader reaped, ECHILD observed and no remaining
processes or errors. The source log was reused unchanged, not run a second time.
Repeated elapsed-time increases across identical inputs/images are measurable;
the available records do not establish a specific CPU, I/O or scheduling cause.
Later attempts retain their own source-bound results rather than overwriting
either original failure.

Two local cold attempts reached the unchanged 180-second limit and confirmed
their owned process-tree cleanup. The h execution connector subsequently
returned internal errors even for controller-only and known-state reads; the
uncertain remote source operation was not replayed with a new key. After the
connection recovered, the original environment job was observed successful and
the exact original source request/key was reconciled and observed complete.
A separately identified replay of the frozen `95ba911` Git tree passed source
reproduction, source controls, cold, language and every native component group.
The full retained suite then ran 3,896 tests in 1,742.849 seconds, with four
error records across three methods, no assertion failures, skips, expected
failures or unexpected successes. One public CLI fixture refused a temporary
directory beneath a Git ancestor; three UNIX socket setup records exceeded
the socket path limit. The original final status is HOLD, with full source
identity preserved. A revised external preparation tool requires a fresh short
temporary directory outside Git ancestors, checks a real UNIX socket round
trip and separately checks its disk/inode reserve. The failed complete suite
is not reclassified as passed by this environment correction.

The completed-stage archive now performs one complete ZIP-member replay and
binds that replay to three complete compressed-byte hashes on held descriptors.
Published bytes must retain the same inode, extent, mode and owner, with only
the expected hard-link ctime/link-count transition permitted. Source files
remain until publication and identity checks finish. Twelve archive tests
include actual replacement and in-place-change controls; failed sealing
preserves originals. A local read-only timing panel over 38 earlier completed
archives measured 6.126 seconds for full replay and 0.066 seconds for compressed
SHA-256. This is a bounded removal of duplicate work, not a measured CI speedup,
deadline change or new cold pass.

### Exact-source f50 qualification and retained evidence boundaries

Commit `f50b37543d1a379353267ce0ab7111242806b8b4` completed
[Actions run 42966395957](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42966395957)
with successful source and native jobs. The source job passed 280 tests in
328.079 seconds. Its native job passed 516 component test invocations and the
10 language-report assertions, with all 1,242 language checks true. The four
CodeQL language jobs also passed in the separate run `42966394894`.

The original cold report records 151.755918610 seconds, all 11 outer checks,
all 5,049 nested checks and all 38 sealed phases. The qualification deadline
remains 180 seconds and the phase-worker maximum remains two. Process cleanup
completed in 7.319815 milliseconds, with ECHILD observed, no remaining direct
children and no cleanup errors. All 570 source/contract entries were compared
to the immutable Git contents of that exact commit.

The complete 56,338,188-byte Actions artifact has SHA-256
`a94a13f74c3ac5ee1aee30a6d5ae0f05e2903f77e7a880b5c30710efa6c2ea59`.
An independent streaming audit read every member of all 38 cold phase archives:
42,623 members and 2,396,512,984 uncompressed bytes, checking compressed archive
hashes, member inventories, modes, sizes, SHA-256 and ZIP CRCs. The language
report also references two separate B3/M3 fixture archives, totalling 9,934,221
compressed bytes, which the old upload path omitted. Their reported results
and the ten report assertions passed, but those two original archives were not
independently replayed from this artifact. The next workflow explicitly retains
the language evidence directory. That correction does not retroactively add
bytes to the original artifact.

The same f50 source on ROG independently passed 280 source controls and all 11
cold checks in 95.514395310 seconds. Its complete 570-entry cold source manifest
matches the same Git commit. The complete retained regression then passed all
3,985 tests in 1,708.094883034 seconds, with no errors, failures, skips, expected
failures or unexpected successes. All 22 qualification steps passed. The original
508,277-byte final report has SHA-256
`350642894d8a0e42cf686661a1f42f1ad49c1a25324f99fbea4d37bdc1aa1ff4`.
Its full 2,628-file source map matches the immutable Git tree; original source
snapshots, source reproduction and harness pins remain unchanged. Connector
timeouts were reconciled against the original request and job; no duplicate
qualification was started or substituted for that result.

The separately sealed original top-level evidence archive is 349,432 bytes with
SHA-256 `4a502c4b6d8543c83ad3eb18edcc0dedf55dd20e9e847ac0e99d6a19163e7155`.
All 96 regular members / 7,159,568 raw bytes were independently replayed against
their remote hashes, sizes, modes, owners and timestamps. The original 22 step
receipts and stdout/stderr, all 17 structured suite results and the full retained
unittest conclusion agree. This top-level archive does not contain the separate
ROG cold/language fixture directories; it is not described as a full local replay
of those nested fixtures. These f50 results qualify f50, not the later
complete-function continuation.

### Complete HIA nominal function continuation

The selected [five-kernel function bundle](HIA_COMPOSITE_FUNCTION_NATIVE_DESIGN.md)
now implements the retained complete `_Elaborator.function` responsibility:
two-pass block admission, source value binding, record/enum and partial-record
operations, task helper requests, calls and primitive instructions, jump/branch/
match/return/trap terminators, resource transitions and final binding of returned
loan origins to generated Core entry names. Every typed service resolves through
the already-native type/helper owners. The Python bridge transports issued
identities and object tokens, correlates continuation requests and mirrors
native-issued counters and helper cache updates. It does not call the retained
function algorithm when this bundle is selected.

The five fixed native images stay within the original compiler's per-image
function/block/instruction limits. They preserve the existing public input and
Core-output gates. In particular, a function may temporarily produce more than
8 MiB of Core before a later function fails: the whole-program Core size check
still occurs after all function lowering, preserving the later semantic error's
priority. The adapter checks exact membership of the admitted frozen document;
an arbitrary replacement dictionary passed to its private function API is not
a second public source-admission path. Altered members or malformed transport
poison the session, and subsequent calls refuse.

An environment interruption erased temporary audit directories. The surviving
213-member evidence archive preserved the five HIA sources, four generators,
adapters and actual native images. Fifteen source files were recovered exactly;
seven missing test/configuration/document revisions were explicitly reconstructed
and saved with a new source manifest on a separate recovery branch. Missing
historical raw logs are not claimed to have been recovered. Fresh verification
of that frozen candidate passed all seven protocol controls and all 15 combined
codec, admission, source, installed-wheel and complete-function controls.

A new independent capture ran 83 retained tests and recovered 134 distinct
public nominal documents. With the same native type/helper dependencies, all
134 complete outcomes and states, including 153 function calls and 52 constructor
refusals, exactly match the retained function implementation. Native function
execution occurs with retained function/type/helper semantic methods disabled.
Every ordinary ABI input and complete response was recorded; borrowed type
arenas were identified by their held lease, not misrepresented as full memory
snapshots. Source and image pins remained unchanged.

The additional fully-hosted comparison makes existing type-owner differences
explicit: all 134 public categories, phases and Core outcomes agree; 125 also
retain exact diagnostic text. Nine constructor refusals use the already-declared
native type diagnostic context. Seventeen cases differ in the private presence
of the `native_types` attribute after failed type initialization, including one
of those diagnostic cases. Thus only 109 complete private constructor states
are identical across the fully hosted and selected-native type routes. Those
pre-function differences are not attributed to this new function owner or
hidden by the same-dependency comparison.

Nine explicit historical-lowering controls also match completely. Six actual
public historical imports compare full canonical/structured bytes, import
reports, errors and independent Core VM results/resources: three legitimate
programs are accepted and three newer-opcode attempts are refused. The retained
VM is an independent execution control, not a newly native runtime claim.

A separate new panel covers 1,586 unique public-admitted mutations with 1,674
labels, derived from 36 accepted parents across 45 opcodes and five terminators.
All 1,586 complete same-dependency outcomes and 2,666 function calls agree;
partial failure state, counters, helper ordering/cache and type observations
remain part of the comparison. Lowering accepts 164 cases and rejects 1,422.
Independent Core admission accepts 44 of those 164 and rejects 120; those
distinct admission counts are not collapsed. All 332,872 actual native entries
are preserved, including 203,854 entries into the five new function kernels.
The run took 1,063.940469761 seconds with peak RSS 506,120 KiB and unchanged
source/image pins. Its complete original input, driver, observations and logs
were sealed into a 20,411,212-byte archive, SHA-256
`83a13abceb31b181f8deccc10accdd87ecbddfe3dcfc17fc09c95c84dd0d2a2f`;
all 17 members were read back and checked. This panel is new evidence, not a
reconstruction of the historical lost 1,427-case raw observations.

The v63 integration places all five test modules in the real native CI group
and required-test contract, without skips, and includes all five HIA resources
in both source distributions and installed wheels. The shared fixture either
uses one matching-source cold receipt, all three explicit development manifests,
or an explicitly labelled B0/B1/B2 bootstrap-development build. Ambiguous or
partial provenance refuses. Independent review found and fixed both a source
reread race and a loaded-image versus on-disk pin gap; their original
counterexamples remain separate from the corrected results.

An actual bootstrap-development run passed all 33 function tests in 110.374
seconds (120.177 seconds including bootstrap), with no errors, failures, skips,
expected failures or unexpected successes. The parent process recorded 21,449
real native entries; the isolated installed child has its own verified entry
observations. The actual source-distribution-to-wheel installation ran under
`-I -S`, empty PATH and forbidden build-tool imports, with the retained semantic
owners disabled and resource/image corruption controls active. All 589 source
payload pins, the contract and 81 compiler/build artifacts remained unchanged.
These are development results for their recorded source revision, not the
matching-source cold qualification for the eventual published v63 tree.

Independent public replay then found that retaining a rejected program's
exception also retained approximately 384 MiB of native session buffers. The
public elaboration boundary now explicitly closes its function and type
sessions on both success and failure, including partial construction. Each
native session also releases already allocated buffers if its own initializer
fails before returning it to the elaborator. The 17 private `_Elaborator`
methods and all five HIA kernels remain byte-identical. Private callers retain
their original session and partial-state ownership.

The original public rejection now releases all four buffer objects while the
same exception remains held; an independent six-entry native replay preserves
the exact error category and text. Three new lifecycle tests pass with 1,402
actual native entries, covering two successful and six refused public paths,
private repeated-failure state, and two allocation failures after a real first
buffer allocation. The original 33 function tests also pass again, with 21,449
parent-process native entries and unchanged 590-source/contract and 81-artifact
pins. The final 26 source/contract controls pass on the final recorded bytes.
The initial primitive-name test expectation error and first independent entry
observer's instrumentation error remain preserved as failures of those test
revisions. Neither required a further production change.

The complete lifecycle follow-up archive is 795,448 bytes with SHA-256
`7b60b5ace1babfa539c4287ae8b2a4f4bbc6197a990ef4d97d7016e8be22d9f1`;
all 93 members / 3,197,887 raw bytes were read back. The new lifecycle module is
mandatory in the real CI group, the full external runner and the six-module
required-test contract. These successful development checks still require the
final published source's own cold and complete-workflow acceptance.

Constructor admission/signature collection and final program aggregation/export
selection remained separate hosted owners in the historical v63 integration. A
separate frozen constructor candidate now implements admission and signature
collection in two HIA images. Its 14 development tests and two-case smoke pass;
the author's 150-case panel compares complete state and type-command order.
An independent replay of the separate 134 public documents also matches exactly:
82 accepted, 52 refused, with first error class/category/text, partial state,
source aliases and each real type command preserved. It records 3,535 actual
native entries and unchanged source/image pins. The 1,721,352-byte independent
archive has SHA-256
`d04cdfeb0e28046d0230a344fa40f375c508991b7f9d0ed64ca9a9bcf8e840b5`;
all 53 members were read back. That separate candidate is not yet integrated
into v63 or promoted to a matching-source cold pass. The outer aggregation
candidate has compiled two actual HIA images and passed two initial scalar/task
smoke cases; full outer acceptance is still pending.

The continuation's cold source contract,
unskipped CI execution, source-distribution resources and installed path must
receive their own matching-source qualification. Neither recovered images nor
the earlier f50 pass establish that qualification.

## Remaining implementation owners

| Area | Native implementation present | Work required before retiring the remaining owner |
| --- | --- | --- |
| Assembly/compiler | Direct x86-64 generation, resource checks, original/modified self-compilation, native `assemble` and the retained static x86-64 ELF ET_REL/RELA linker | Full retained language/composite lowering, linking beyond the existing static ELF profile and all claimed targets; retain the compiler's actual limits separately from the larger checker's limits |
| Primitive Core admission | Declarations, 50 opcodes, SSA/CFG, calls/effects, ownership and loans; standalone checker | Nominal/composite normalization, complete object/diagnostic custody and independently justified equivalence for retained semantics |
| Nominal elaboration | Five selected HIA owners cover declarations/layouts, signatures/origins, helpers, complete functions, constructor admission and final aggregation/exports | Native raw-JSON transport and continuation driver, default installed integration and matching-source acceptance; foreign object/materialization bridges remain |
| Workspace/project build | Native module graph, naming/privacy, Core materialization and semantic compiler pipeline | Complete project build, library resolution, installation/upgrade/recovery and file/process ownership without hosted orchestration |
| Agent editing | Native slice/snapshot/data helpers, snapshot-bound patches, complete patch diagnostics and explicit ordinary raw-byte candidate route | Remaining query, batch/impact orchestration, composite/import paths, default installation and ordinary full worker protocol |
| Agent state | Native artifact hashing, no-replace file publication and content byte store | Metadata/ref encoding and issuance, namespace/kind authority, SQLite transactions/WAL, request intents, locks, costs, leases, slots, versions and uncertain-operation recovery |
| Runtime and proof | Native kernels and selected runtime/verification applications | Complete retained runtime/library ownership, independent VM/reference roles, proof computation/certificates, exact unknown/refuted/timeout semantics and other target qualification |
| Authoring and packaging | Checked-in HIA source, native compiler and application packers | Replace remaining Python generation/build/custody entry points, native installer and reproducible clean-machine rebuild without importing the retired stack |
| HeptaRuntime integration | Existing eleven-tool contract and explicit candidate identities | Native worker request/report parity, original operation continuity, immutable installation pins, real SSH/MCP first use and qualified cutover |

The independently deployed Runtime is a separate owner. A new live discovery
and artifact read obtained and independently hashed its complete manifest and
backend profile. Its catalog digest matches `c80eb2e`, but its advertised worker
and backend digests differ from that checkout; the backend profile still says
`self_hosted: false`. This observes issued artifact bytes and advertised source
identities, not an independent deployed-file or loaded-process audit. The earlier
historical X230 observation is not substituted for this current observation.
No live worker, service, state root or release pin was migrated by this source
continuation.

## Retirement and completion criteria

### Composite and compiler prerequisites

`hepta/hia_program.py::verify_program` invokes
`hepta/hia_program_composite.py::elaborate_program` before primitive native
admission. The explicitly selected native type session now owns nominal
declarations, generic binding, finite layout, by-value cycles, stored loans and
partial-declaration obligations; the no-selector path retains `_Types`.
The selected type session also owns parameters and task-protocol admission,
and the separately selected helper image generates the complete task helpers.
The selected complete-function bundle now owns nominal SSA, record/enum
transformations, inactive-slot cleanup, partial tokens and generated entry-name
origin binding. v64 additionally selects HIA constructor sequencing and final
program/export assembly, with the original bodies retained for independent
controls and the no-selector route. Composite v1 lowers to primitive v6, v2/v3
to v7 and v4 to v8; changing those schemas would change the retained language.

The next normalization boundary is an HIA-owned raw-JSON transport and complete
continuation driver, preserving all four composite versions, failure ordering
and the native type session's stateful obligations. Current Python adapters
still own detached foreign-object copying, typed packet construction, callback
forwarding and materialization of HIA-issued results.
The current native JSON compiler frontend accepts v8; its 16 arguments, three
results, 128 functions and 256 blocks per function are smaller than some legal
normalized programs and the complete primitive checker's profile. Type-layout
replacement, full normalization and full compilation therefore need distinct
acceptance gates. A safe but incorrectly lowered program can pass primitive
admission while violating the structured source's meaning.

The retained composite ABI/qualification/bulk/returned-loan/partial tests and
historical `composite-native-72.log` contain actual allocator, refusal, wrong-result
and cross-target controls. They execute normalized code produced through hosted
normalization/emission; their historical results do not make those producers
native or qualify the current complete retained suite.

### Build and installed-runtime prerequisites

`pyproject.toml` still installs the `hia-core` Python distribution with
`hia = hepta.cli:hia_main`. Wheel/sdist source custody packages declared kernel HIA
sources and the publisher's declared assets, but it is not a complete native
self-rebuild kit: the selfhost source, general stdio/result packers, their build
drivers and default installed native executables are not supplied through that
kernel resource mechanism. The worker request/report entry and its subprocess
custody remain hosted. A native installer must own compiler/packer/source pins,
default selection, executable publication and upgrade/recovery before that
delivery path can replace the Python entry.

The current B0 path is hosted assembly, machine emission and linking through
`assemble_program`, `emit_program_machine` and `compile_program_machine` with
`ld`. B1 onward performs real native HIA compilation, while the generation and
qualification drivers still use Python and its native mapping bridge. A native
delivery needs an explicitly retained bootstrap trust root and native build
orchestration; deleting the current seed/build drivers first would remove the
present clean-machine reconstruction path.

The shared `tools/build_hia_json_preflight.py::build` path now binds the
complete current contract and cold source manifest, as the patch/result builders
already do. This closes the observed stale-source admission gap; source binding
still does not establish the behavior of an application merely built afterward.
Actual application execution, installation and recovery remain distinct gates.

The obsolete high-level source language and compatibility entry were already
removed from the active repository. Remaining hosted components retain actual
callers and responsibilities. Their deletion requires a corresponding native
owner with the same retained semantics, ordinary caller integration, matching
source qualification and recovery evidence. Independent reference controls
cannot be deleted merely because the implementation under test is now native.

The durable Agent is a separate remaining vertical slice: exact
metadata/ref/request protocol, write intent before effect, same-key conflict and
unknown-result behavior, interrupted publication/restart, adoption and rollback.
Then bind that owner to a clean native installer and the actual Runtime provider.
Successful payload transformation does not close these transactional obligations.

Only after those paths and the retained compiler/runtime scope pass complete
acceptance can Python/Rust/other legacy production owners be removed. The
inventory grants no deletion authority and does not mark an unimplemented path
as retired or passed. The final repository should have one HIA-native product;
this report records the work still needed to reach that state honestly.
