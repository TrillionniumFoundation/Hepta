# HIA P0–P3 follow-through evidence — 2026-11-07

**P0 production status: `UNKNOWN`.** The authorized cutover was submitted once
as job `1a1b54d0050-fc05-8be3`. After the restart, the existing `h` connection
returned MCP `-32603 Internal error`; no authoritative job terminal or production
result was retrieved. Success, rollback and timeout are all unproved. At
09:24:52 UTC, this chat still exposed 70 general `h` tools and zero HIA tools.
P0 end-to-end acceptance remains open. The [original operation and errors](production-cutover-observations/production-cutover-unreconciled.json)
and [latest connection/catalog observations](production-cutover-observations/post-cutover-connector-observations.json)
preserve this boundary without repeating the mutation.

**Collection status: frozen. This is a recoverable review checkpoint, not a
complete production-deployment archive.** Source, CI and platform qualification
evidence is retained. The successful isolated 39-call HTTP loop has its durable
terminal and complete compact projection locally, but its 9,340,915-byte raw
result (which reports 203 JSON-RPC records), complete HTTP event journal and
response bodies remain on the Mac. The
[availability inventory](http-native-205-c81-loop-r2-partial/AVAILABILITY.json)
distinguishes local files from pending originals. Recovery instructions below
resume observation of existing operations; they do not start a replacement run.

This directory preserves the source-bound results, failures and review repairs
from the HIA follow-through. The implementation is the published Hepta commit
[`205f94ec811018f89fbf68c987c6ab8e826bb15b`](https://github.com/TrillionniumFoundation/Hepta/commit/205f94ec811018f89fbf68c987c6ab8e826bb15b).
Its Git tree is identical to the locally tested commit
`d32ef01f87e489770de487e19e6ca520f304f2a7`:
`d57b1f75e4ca05e5a2fd018906b5e2c32e2fa70e`.
The local run headers retain `d32ef01`; publication did not rerun or relabel them.
[Source identities](source-identities.json) and the
[post-hoc source comparisons](source-manifest-comparison.json) make the mapping explicit.
The exact [local commit payload](source-publication/local-d32ef01.commit.raw)
and [published commit payload](source-publication/published-205f94e.commit.raw)
are also preserved: hashing each as a Git `commit` object reproduces its stated
commit ID, and both payloads name the same tree. This permits checking the
mapping without relying only on the collection's summary.

The 16 observed Hepta source workflows and the final runtime source/platform
gates completed successfully. None of those results substitutes for the
unreconciled production cutover or the missing direct chat-tool exposure.

## Results and their actual scope

| Area | Preserved observation | Evidence |
|---|---|---|
| Final local source gate | 384 tests passed, none skipped, clean worktree, source unchanged; all 1,528 inventoried source files match the frozen local commit | [Report](final-local-d32ef01/tests.json), [log](final-local-d32ef01/tests.log) |
| Published-source CI | All 16 observed workflows succeeded. The unified gate ran the same 384 unique test IDs with the same 1,528-file source inventory; the CI selfhost gate passed 54/54 checks | [Original CI report](final-ci-205f94e/originals/tests.json), [independent verification](final-ci-205f94e/independent-review.json), [all workflows](final-ci-205f94e/ci-all-workflows.json), [original artifact](final-ci-205f94e/hia-unified-205f94e.zip) |
| Final runtime `c81a938` source | Published complete tree `aa10bb33...`; only the cold-load test file differs from `942d470`, with production bytes and the ledger unchanged. The pinned gate projection contains 959 files and all 19 Cargo target source files | [Publication](final-runtime-c81-source/runtime-r6-published.json), [exact patch](final-runtime-c81-source/runtime-mac-compatibility-r6.patch), [input projection](final-runtime-c81-source/runtime-r6-expected-input-projection.json) |
| Final runtime `c81a938` Linux | All seven format/check/clippy/nextest stages passed on unchanged source. All features: 2,354 passed/40 skipped; no defaults: 2,325 passed/28 skipped | [Original platform gate](final-runtime-c81-linux/originals/linux-r6-final-gates.json), [19 original artifacts](final-runtime-c81-linux/runtime-c81-linux-original-artifacts.tar.gz), [retrieval verification](final-runtime-c81-linux/SUMMARY.json) |
| Final runtime `c81a938` Mac | All nine stages passed, including the cold-cache regression and release build. All features: 1,974 passed/29 skipped; no defaults: 1,957 passed/19 skipped. Six real unsupported-operation calls refused with the workspace unchanged | [Original platform gate](final-runtime-c81-mac/originals/mac-r6-final-gates.json), [26 original artifacts](final-runtime-c81-mac/runtime-c81-mac-original-artifacts.tar.gz), [binary identity](final-runtime-c81-mac/originals/mac-r6-release-artifacts.json), [refusal report](final-runtime-c81-mac/originals/mac-r6-final-refusal-tests.json) |
| Final runtime `c81a938` hosted CI | Exact-source push CI completed successfully, including both feature modes, mapping, release and its release smoke/cancellation checks. The full log and two original artifacts are retained. The prospective-merge job was skipped on push and is not a passing merge gate | [Original CI summary](final-runtime-c81-ci/original-packet/SUMMARY.json), [full job log](final-runtime-c81-ci/original-packet/job-128353158255.log), [original run/job observation](final-runtime-c81-ci/root-original-observation.json) |
| Final isolated HTTP lifecycle | The original r2 job succeeded with complete durable output. Its retained projection reports 39 calls across all 11 HIA tools, adoption 0/0→1/1, stale-generation rejection and rollback to generation 0/epoch 2; the same c81 PID/listener/pins were verified before and after. The full raw result/journal/body bundle has not been retrieved | [Partial local packet](http-native-205-c81-loop-r2-partial/SUMMARY.json), [complete compact projection](http-native-205-c81-loop-r2-partial/execution-summary.json), [availability](http-native-205-c81-loop-r2-partial/AVAILABILITY.json), [after-loop probe](mac-preparation-205f94e/final-c81-shadow-after-loop.json) |
| Production cutover | `UNKNOWN`: one original operation was submitted; the connection failed before an authoritative terminal/result could be retrieved. No success, rollback or timeout is inferred, and no replacement mutation was submitted | [Original request/start and errors](production-cutover-observations/production-cutover-unreconciled.json), [independent single observation](production-cutover-observations/p3-status-once-20261107T092105Z.json) |
| Chat-tool exposure after submission | At 09:24:52 UTC the chat catalog still exposed 70 general `h` tools and zero HIA tools; no refresh capability was exposed. This does not determine whether the runtime itself is up | [Original post-submission observations](production-cutover-observations/post-cutover-connector-observations.json) |
| P0 final Linux staged integration | The exact 205 source completed the 113-tool/11-HIA preflight and a 39-application-call, 95-MCP-call native loop including adoption, stale-CAS rejection and rollback. This is staged integration, not production deployment | [Summary](final-p0-linux-205f94e/readable/SUMMARY.json), [final receipt](final-p0-linux-205f94e/readable/qualification/FINAL.json), [complete public archive](final-p0-linux-205f94e/public-evidence.tar.gz), [attempt history](final-p0-linux-205f94e/attempt-history/SUMMARY.json) |
| P0 baseline entrypoint | The baseline runtime entrypoint was observed and its preflight passed. The original receipt explicitly says `production_deployed=false` and does not attest binary build provenance | [Preflight](baseline/p0-live/preflight-592625e.json), [full original archive](baseline/p0-live/baseline-public-evidence.tar.gz) |
| P1 published-source macro campaign | 32/32 native task arms, 8 native NDU evaluations, 32 failed/rejected attempts retained; offline verification checked 440 events and 1,458 objects. Observed NDU saving versus the best comparator was negative: −601,347,392 ns. Verdict remains `HOLD` | [Final verdict](final-published-205f94e/macro-campaign/verdict.json), [offline verification](final-published-205f94e/macro-campaign-offline-verify.json), [complete public objects](final-published-205f94e/macro-campaign-public.tar.gz) |
| P1 original macro campaigns | Both pre-commit runs completed 32/32 native task arms and retained their failed/rejected attempts. Both verdicts remain `HOLD`; economic benefit was not established | [r1 verdict](checkpoints/macro-original-r1/verdict.json), [r2 verdict](checkpoints/macro-original-r2/verdict.json), [original archive](checkpoints/archives/macro-original-r1-r2.tar.gz) |
| P1 provider availability | One local request timed out. Two later requests returned `400 / model_not_found`; usage remains `null`. No actual-provider four-arm campaign or mechanism smoke is claimed | [Initial diagnostics](provider/initial-diagnostics/SUMMARY.json), [compatibility continuation](provider/legacy-compat-diagnostics/SUMMARY.json) |
| P2 published-source fixed-Core self-hosting | The corrected compiler passed 54/54 qualification checks again on the published source. B1/B2/B3 use native HIA parsing, validation and generation; modified-source M2/M3 reach a different fixed point | [Final qualification](final-published-205f94e/selfhost.json), [232 original generation files](final-published-205f94e/selfhost-native-generations.tar.gz), [final log](final-published-205f94e/selfhost.log) |
| P2 admission review | Two original counterexamples were accepted incorrectly. The corrected B3 rejects both before output mutation; additional syntax/resource regressions are retained | [Original and corrected receipts](repairs/p2-independent-audit/), [all requests and outputs](repairs/p2-independent-audit/original-and-fixed.tar.gz) |
| P3 published-source checked machine plans | Five fixed synthetic arms each passed 462 native cases, plus three rejected plans. Build, verification and execution costs are measured; complete Agent search/model economics remain open (`full_search_cost_complete=false`, three unknown cost fields, real-task benefit unproved) | [Final qualification](final-published-205f94e/machine-registers/result.json), [16 original binaries and receipts](final-published-205f94e/machine-registers-native-evidence.tar.gz), [final log](final-published-205f94e/machine-registers.log) |
| P3 snapshot review | A caller-controlled Python hook could mutate an admitted register plan and make `plus7(10)` produce 14. The fix rejects hooks and freezes plain data; the fixed invocation produces 17 | [Retained old-image reobservation](repairs/p3-plan-snapshot/retained-artifact-reobservation.json), [fixed result](repairs/p3-plan-snapshot/fixed-result.json), [43-test log](repairs/p3-plan-snapshot/fixed-tests.log) |
| Historical macOS runtime attempt 5 | The earlier compatibility-patched runtime built both release binaries; six scoped unsupported filesystem operations refused without changing the workspace. This attempt has its own base-plus-patch identity and is not the final c81 runtime | [Build receipt](runtime-mac/compatibility-build-attempt5.json), [refusal tests](runtime-mac/compatibility-refusal-tests.json) |
| Runtime companion original CI | Exact `14dfb09` CI failed its stored REA mapping/source projection gate (step 14, exit 2), after 2,353 all-features tests passed with 40 skipped. Later no-default and release steps were skipped; no artifact was produced | [Original summary](runtime-ci-14dfb09-original-failure/SUMMARY.json), [complete original job log](runtime-ci-14dfb09-original-failure/job-128333906877.log), [captured file inventory](runtime-ci-14dfb09-original-failure/FILES.json) |
| Runtime `14dfb09` Linux build projection | The separately retained 958-file/19-target build projection passed format, check, clippy and nextest for both feature sets: 2,353 passed/40 skipped with all features; 2,324 passed/28 skipped without defaults. This does not override the complete-repository CI failure or qualify later r5 source | [Platform gate](runtime-linux-r4f/linux-r4f-final-gates.json), [all three original Linux runs](runtime-linux-r4f/linux-platform-evidence-r4f.tar.gz), [original inventory](runtime-linux-r4f/linux-platform-evidence-r4f.json) |
| Runtime `14dfb09` original Mac gate | All features: 1,879 passed, 110 failed, 29 skipped. No defaults: 1,862 passed, 110 failed, 19 skipped. Both nextest modes exited 100; the later successful release build did not change the failed gate | [Original terminal gate](runtime-mac-r4f-original-failure/mac-r4f-final-gates.json), [17 original files](runtime-mac-r4f-original-failure/mac-platform-evidence-r4f.tar.gz) |
| Runtime `14dfb09` isolated shadow | After preserving the original accepted operation and a supervisor-PID refusal, the actual child PID 36464's mapping and loopback listener were verified before/after a 113-tool/11-HIA HTTP probe. Production remained unchanged | [Five original probe files](mac-preparation-205f94e/shadow14-originals/shadow14-original-five-files.tar.gz), [retrieval verification](mac-preparation-205f94e/shadow14-originals/SUMMARY.json) |
| Runtime `942d470` Linux | The original two nextest stages failed under an inode-constrained temporary directory. A separate unchanged-source recheck passed 2,354 and 2,325 tests and was composed with the five original successful stages. Both runs remain distinct | [Original and recheck reports/logs](runtime-linux-r5/original-artifacts/SUMMARY.json), [complete original artifact archive](runtime-linux-r5/original-artifacts/runtime-942-linux-original-artifacts.tar.gz) |
| Runtime `942d470` Mac | All features: 1,973 passed, 1 failed, 29 skipped. No defaults: 1,956 passed, 1 failed, 19 skipped. The same cold-load test watch assumption failed in both modes; release succeeded and the gate remained failed | [Original terminal report](runtime-mac-r5-original-failure/originals/mac-r5-final-gates.json), [20 original artifacts](runtime-mac-r5-original-failure/runtime-942-mac-original-artifacts.tar.gz) |
| Runtime `942d470` hosted CI | Cancelled during no-default tests, with no final summary for that stage. All 2,354 all-features tests and the mapping gate passed earlier; release and smoke were skipped, and no artifact was produced | [Original CI summary](runtime-ci-942d470-cancelled/SUMMARY.json), [complete original log](runtime-ci-942d470-cancelled/job-128345734264.log), [source publication](runtime-r5-source/runtime-r5-published.json) |

The finite source gate does not establish a production connector deployment,
real-task NDU strategy gain, whole-language self-hosting, general register
allocation or a formal Core-to-machine refinement proof. The original receipt
claim fields remain authoritative about those limits.

## Resume the original operation and retrieve pending evidence

Recovery starts by restoring the existing `h` connection/session. Do not run
the deployment helper again, submit another cutover, replace the idempotency
key, or rerun the successful HTTP loop. The original cutover key is
`hia-mac-c81-production-cutover-372e7da9-r1` and its original host is `main`.

1. Read the authoritative state of job `1a1b54d0050-fc05-8be3`, then read its
   original stdout/stderr continuously using returned offsets. Preserve the
   terminal's completeness, durability and publication-confirmation fields.
2. Read the already selected public result at
   `/Users/qianqi/work/hia-runtime-9f60-20261107-372e7da9/production-cutover-c81-205-r1/result.json`
   and its adjacent `http-events.jsonl`. If direct Mac access is available,
   reading that exact public `result.json` with `cat` is sufficient to share
   the existing result; no live configuration or token is needed. An absent
   file or another observation error is not itself a completed job result.
3. Reconcile the report's active-release, PID/listener and guarded-rollback
   observations with the original operation. Record success, restoration or a
   concrete failure only when supported by the observed original outcome.
4. Observe the separate owned shadow job `1a1b53eeced-fc05-8ba9`. Its configured
   1,800-second limit is not evidence that it terminated. If it remains active
   and its identity matches the retained shadow launch, clean up only that
   owned shadow job. Do not stop the production controller or infer identity
   from an old PID alone.
5. Retrieve the completed HTTP r2 originals from
   `/Users/qianqi/work/hia-runtime-9f60-20261107-372e7da9/http-native-qualification-205-c81-loop-r2/`
   without rerunning job `1a1b5471643-fc05-8bcc`. Retain `result.json`, the entire
   `http-events.jsonl` and the original `http-body-*.bin` inventory. The
   [availability file](http-native-205-c81-loop-r2-partial/AVAILABILITY.json)
   records exact known sizes, remotely computed digests and the downloaded
   journal byte range. Recompute full-file digests locally after retrieval.

The final release-staging receipt and raw before-loop, after-initialization-
failure and after-loop probe files also remain pending as a complete original
archive. Their exact remote relative paths are listed in
[`source-identities.json`](source-identities.json) under `pending_evidence`.
The local wrappers and compact before/after reports are retained, but they are
not presented as a verbatim archive of every original file and HTTP event.
No final Mac packing job was started after the connection failure.

The final macro archive selects only its three public reports and all 1,458
content-addressed objects, with every object digest and size checked against
the campaign manifest. This retains the source bundle and task snapshots.
Live worker directories and their private state databases are excluded, as
recorded in the [public selection receipt](final-published-205f94e/macro-public-selection.json).
The [runtime contract test log](final-published-205f94e/runtime-preflight.log)
is distinct from deployment and binary-provenance evidence.

The separate CI macro run also reports `HOLD`: its own observed NDU saving is
−1,800,275,253 ns, versus −601,347,392 ns in the local post-publication run.
Their [CI verdict](final-ci-205f94e/originals/macro-campaign/verdict.json) and
[local verdict](final-published-205f94e/macro-campaign/verdict.json) retain each
run's full phase ledger and comparator choice. These deterministic fixture
measurements do not establish qualified real-task strategy benefit.

The Linux P0 `readable/` directory selects the small original reports and source
observer for review. The original `FILES.json` indexes **all 17 files in the
archive**, including the complete large transcripts and `RESULT.json`; those
large files are not redundantly expanded into this branch. Earlier refused
requests and the failed post-checkout assertion are retained in the separately
curated attempt history.

## Source and run chronology

The [baseline](baseline/baseline.json) is Hepta `592625ee...` with runtime
`9f60a305...`. Its [CI report](baseline/ci/tests.json) and
[original downloaded CI artifact](baseline/ci/hia-unified-592625e.zip) are
preserved separately from the final candidate. The intermediate
[`6e7f6a2` gate](checkpoints/integrated-6e7f6a2/tests.json) passed 378 tests;
it predates the later review repairs.

The r1/r2 macro campaigns are **pre-commit checkpoints** based on `592625ee...`.
Their [r1 campaign](checkpoints/macro-original-r1/campaign.json) and
[r2 campaign](checkpoints/macro-original-r2/campaign.json) preserve the source
and worker content inventories. Neither run is assigned the later provider
commit `3da166c` or the final candidate commit. The original P3 direct report
also records a dirty `592625ee...` worktree. A later byte comparison finds all
1,242 inventoried files match `99b1926`; that comparison does not change the
recorded Git HEAD.

The original P3 [machine-plan report](checkpoints/p3-original/result.json) and
[binary archive](checkpoints/archives/p3-original-qualification.tar.gz) are kept
alongside the final published-source run. Their content identities differ and
the old files have not been replaced.

The [original P2 report](checkpoints/selfhost-original/report.json) has 35
passing checks and a 14-file source manifest matching `4b37608`. Its later
review counterexamples are preserved alongside it. The corrected P2 report's
14-file manifest matches `6868b0a`; its expanded 54-check gate covers the
concrete admission defects. The [earlier loader failure](checkpoints/selfhost-initial-loader-failure/B1.receipt.json)
is retained as a failed attempt, separately from both successful chains.
The immediate [admission-fix report](repairs/p2-admission/report.json),
[native generations](repairs/p2-admission/native-generations.tar.gz) and
[11-test regression log](repairs/p2-admission/tests.log) also remain available
separately from the subsequent published-source qualification.

## P2 executable generations and review repair

| Retained compiler | Complete HIA source SHA-256 | B1 = B2 = B3 image SHA-256 |
|---|---|---|
| Original | `781837089b6186575637160a5d8cdd294309cb5ba12578dbc05bbce21263586d` | `b6534b2797de0d7cfc7f0a82ee169adb3d46da8d19771df5fe42c9bf91c7dbfa` |
| Admission-corrected | `3517a59222e15c0bff42c1cbd4e010b383e71eab14cab4e01af87f84578ddc8c` | `6e729244533b66ac901a3d5900f094ac6601412618d85e7bbf3723a4ed5d39e6` |

The compiler source is complete within the bounded profile documented in
[HIA_SELF_HOSTING_CORE.md](../../docs/HIA_SELF_HOSTING_CORE.md). B0 still trusts
the Python assembler, Core verifier, direct emitter, ELF writer and linker.
After B0, the loader only loads/copies/calls the executable image: HIA implements
all successor parsing, checking, encoding and relocations. The OS, hardware,
loader and caller-owned disjoint buffers remain trusted.

The mutation experiment changes the HIA wrapper emitter's stack reservation
from 64 to 80. The corrected M1 hash is
`7402ad848d25b6b755ae00e0de871f9ca62ec881795289f2407b443bcd4b5ff6`;
M2 and M3 share
`5066831a98ce90064bed75b16b3a889faea1334eb25b8e30c5f3176fab8554c8`.
The generations execute compiled sample programs as well as processing their
own complete source. This remains a fixed-subset qualification.

The [read-only edge alias fixture](repairs/p2-independent-audit/readonly-edge-alias.hiaasm)
and [declaration spacing fixture](repairs/p2-independent-audit/declaration-adjacency.hiaasm)
are verbatim original input bytes, with only a readable filename extension.
The old B3 returned 341 and 285 generated bytes respectively; the fixed B3
returns `0xffffffff` in phase 0 and preserves source/output bytes. The fix also
keeps legal repeated read-only call arguments accepted and checks the shared
assembly grammar's required adjacency/separators.

## P3 checked controls and economic boundary

The [final machine-plan report](final-published-205f94e/machine-registers/result.json)
qualifies the bounded checked controls exercised by five fixed synthetic arms:
canonical, explicit register assignments, scalar select lowering, block layout,
and their combination. Each arm passed 462 native correctness cases. The
report retains the three rejected-plan attempts and measured emission,
verification/linking and execution phases; Python/ctypes dispatch remains part
of the timing measurement. The backend does not perform register-allocation
or profitability search for these fixtures.

This closes the demonstrated control and correctness scope. It does not close
the complete Agent economic acceptance condition: `full_search_cost_complete`
is `false`, and `discovery_cost`, `external_agent_model_cost`, and
`failed_agent_search_cost` are all `null`. Missing costs are unknown, not zero.
`real_task_strategy_benefit_proved` is also `false`. Measured synthetic timings
cannot establish a strategy gain on real tasks under a complete search/model
budget; that part of P3 remains open alongside P1's explicit `HOLD` verdict.

## P3 snapshot defect and reproducibility

The [original reproducer](repairs/p3-plan-snapshot/plan_snapshot.py) uses a
`str` subclass with `__deepcopy__` to change an assigned callee-saved register
to `rax` after validation. This affects the direct in-process Python API;
wire JSON cannot carry Python hooks. The original reproducer and retained
vulnerable shared library are in the
[review archive](repairs/p3-plan-snapshot/reproducers-and-vulnerable-image.tar.gz).

The initial console output was not preserved as a standalone file. The later
[reobservation receipt](repairs/p3-plan-snapshot/retained-artifact-reobservation.json)
therefore explicitly records a new execution of the **unchanged retained
artifact**, with no recompilation, still returning 14 for an expected 17.
The [fixed reproducer](repairs/p3-plan-snapshot/plan_snapshot_fixed.py) and fixed
receipt separately establish rejection before hooks and a stable plain-data
snapshot after caller mutation. Earlier ordinary tests are kept in the
[pre-fix focused log](repairs/p3-plan-snapshot/pre-fix-focused-tests.log).

## Provider and runtime failures

The initial provider packet is copied unchanged. The old-CLI continuation is
a separately prepared public packet. Its [redaction record](provider/legacy-compat-diagnostics/STDERR_REDACTIONS.json)
preserves the original stderr digests and sizes while removing embedded upstream
instruction bodies. Public files are explicitly named `stderr.redacted.txt`.
Raw legacy stderr, Codex log/state databases, credentials and live configuration
files are excluded. Missing usage and monetary costs remain `null`.
The [P1 peer review](collection-reviews/p1-provider-scope.json) records a separate
check of these campaign/provider claims against their original receipts, bound
to the README snapshot it actually reviewed.

The historical attempt-5 runtime receipts identify runtime base `9f60a305...` and compatibility patch
SHA-256 `1ac184afdae228c3af0ba0cd0a76f01de2b6084c803c3d77484d48e89856e471`.
That patch digest is not a Git commit and does not turn the runtime into the
Hepta `d32ef01` tree. The earlier sparse/archive/online build attempts and
[unpatched build log](runtime-mac/mac-build-unpatched-online.log) remain in
`runtime-mac/`. Original environment paths in those logs are preserved as part
of their original bytes.

The later runtime companion is separately published as
[`14dfb09aa3263ed35b4f88e8c301f8492d63fea7`](https://github.com/TrillionniumFoundation/hepta-runtime/commit/14dfb09aa3263ed35b4f88e8c301f8492d63fea7),
tree `130ef2bd17fbcd5195d8e8d3655096240d360280`.
Its [publication receipt](runtime-mac/runtime-r4f-published.json) and
[independent r4f static review](runtime-mac/r4f-independent-static-review.json)
remain distinct from the [r3 patch review](runtime-mac/r3-independent-static-review.json).
The earlier [attempt 6](runtime-mac/required-gates-attempt6.json) and
[attempt 7](runtime-mac/required-gates-attempt7.json) are failures and stay failures.

The [supplemental historical observations](runtime-supplemental-observations/SCOPE.json)
also retain the original r3 Mac test failure logs and targeted resource
diagnoses, early nextest installation states, and platform-job terminals. Each
file keeps its own source identity and observed state. The separately retained
65,536-byte Linux r3 log fragment is explicitly partial and matches the prefix
of the [complete original log](runtime-linux-r4f/linux-r3-all-tests.log); it is
not presented as a complete test transcript.

The published `14dfb09` runtime's [original exact-source CI](runtime-ci-14dfb09-original-failure/SUMMARY.json)
also failed. Its original log verifies the source HEAD and records 2,353 passed,
40 skipped all-features tests before the stored REA ledger projection check
returned exit 2 at step 14. Subsequent no-default, release and qualification
steps were skipped; the run produced zero artifacts. Its passed test count does
not qualify the complete runtime gate. The complete captured log, job and run
responses, workflow source and initial failed log-fetch receipts remain in the
separate failure directory; any later correction has its own source identity.

The separate [Linux platform gate](runtime-linux-r4f/linux-r4f-final-gates.json)
passed against the 958-file Cargo build projection
`e53186f8c68db240866f55b77ce63eb320b876b8059e30918000de26e63bfcc0`.
Both feature sets enumerate all 19 Cargo targets. Format/check/clippy passed;
nextest reports 2,353 passed/40 skipped with all features and 2,324 passed/28
skipped without defaults. This runner excludes historical and non-build
documentation, so its result does not replace the failed full-repository CI
ledger gate. The [three-run archive and manifest](runtime-linux-r4f/linux-platform-evidence-r4f.json)
also retain the earlier 955-file r3 and 957-file r4f failures unchanged.

The original [Mac platform gate for `14dfb09`](runtime-mac-r4f-original-failure/mac-r4f-final-gates.json)
completed with `passed=false` and unchanged source. Both nextest feature modes
returned exit 100: all features had 1,879 passed, 110 failed and 29 skipped;
no defaults had 1,862 passed, 110 failed and 19 skipped. Format, check and clippy passed in both feature modes, and
the later release build exited zero. A successful release build does not
override the failed test gate. The receipt retains the exact failed-generation
binary digests and is not assigned to the repaired r5 source. The
[original 17-file archive](runtime-mac-r4f-original-failure/mac-platform-evidence-r4f.tar.gz)
and [member inventory](runtime-mac-r4f-original-failure/mac-platform-evidence-r4f.json)
retain the full logs, metadata, runner and source projection unchanged.

The [14df-only ledger repair](runtime-ci-14dfb09-ledger-repair/SUMMARY.json)
reassembled the existing stored snapshots with the repository generator and
passed its 29 tests and ordinary mapping check. Strict parity still exits 3;
raw reference authenticity remains `NOT_REVERIFIED`, with zero qualified tools.
This pre-r5 candidate is retained as such; it is not the future r5 ledger.

The subsequent [r5 ledger reassembly](runtime-r5-ledger-repair/SUMMARY.json)
binds the 958-file native projection
`34fba720f5488824fbc99e269af6c58531c7768407084b39bb3c829f4629f15e`.
Its ledger SHA-256 is
`d5bb6f5d1be05d67970dc55dccf0a3c0450c6d4f54beef93a2689237ed3be532`.
All 29 ledger tests and the ordinary mapping check passed; strict parity still
exits 3, original reference authenticity is still `NOT_REVERIFIED`, and the
REA ledger still records zero qualified tools. The original report explicitly
predates final published-source assignment and hosted CI; those later bindings
must be read separately.

## Frozen runtime r5 source

The repaired runtime source was published as
[`942d470d155c65ba7235eb19c5bbfd07f1ce2ad0`](https://github.com/TrillionniumFoundation/hepta-runtime/commit/942d470d155c65ba7235eb19c5bbfd07f1ce2ad0),
tree `a19f1dd724bdf80a388ddae17d828b01e5fc42f0`, parent `14dfb09`.
The [publication receipt](runtime-r5-source/runtime-r5-published.json) records
the complete-tree comparison, while the [36-entry changed-file manifest](runtime-r5-source/runtime-mac-r5-source.json)
and [combined patch](runtime-r5-source/runtime-mac-compatibility-r5.patch)
retain the exact source transition from base `9f60a305`.

The [native projection](runtime-r5-source/runtime-r5-formatted-input-projection.json)
contains 958 files; the [final gate projection](runtime-r5-source/runtime-r5-expected-input-projection.json)
contains the same files plus the reassembled REA ledger, totaling 959. The
respective projection digests are `34fba720...` and `f6f2061d...`, explicitly
recorded in full in the publication receipt. The
[Cargo inventory](runtime-r5-source/runtime-r5-expected-targets.json) includes
all 19 target source files. The pinned
[stage runner](runtime-r5-source/runtime-stage-r5-and-gates.py),
[gate runner](runtime-r5-source/runtime-ci-gates-r5.py), and
[format transition](runtime-r5-source/runtime-r5-format-receipt.json)
are retained as inputs. Their presence does not establish that a gate passed.
The subsequent platform and hosted-CI observations retain this exact source
identity. The [Linux original/recheck archive](runtime-linux-r5/original-artifacts/SUMMARY.json)
preserves both initial nextest failures, their available-inode diagnosis, and
the two successful nextest reruns under a different private temporary root.
The resulting matrix composes the original five successful stages with those
two reruns; it is not relabeled as a single uninterrupted successful first run.
The [original Mac gate](runtime-mac-r5-original-failure/originals/mac-r5-final-gates.json)
remained failed, with one cold-load assertion failure in each feature mode,
despite a successful release build. Original log, metadata and source projection
bytes were retrieved from a static-file whitelist after the source directory
had moved on; the retrieval never used the later working source as old evidence.

The [hosted CI](runtime-ci-942d470-cancelled/SUMMARY.json) was cancelled during
no-default tests after the all-features suite and mapping gates passed. It has
no final no-default summary or release qualification. The cancellation timing
is consistent with the unchanged workflow's `cancel-in-progress` policy after
the later same-branch c81 push; the run API does not identify the cancelling
actor or causal reason, so this remains an inference. No cancellation or rerun
was requested by the evidence collector.

An [independent review of the two frozen test fixtures](collection-reviews/runtime-r5-fixture-independent-review.json)
found no material issue: the timeout fixture waits for actual stdout readiness
without consuming its bytes, keeps the one-second capture timeout, and cleans
up its own child on readiness failure. The Unicode fixture keeps both case
variants in the same wildcard comparison using distinct parent directories.
The review binds the exact frozen test files and unchanged production modules;
it does not substitute for the subsequent Rust gate.

A later [cold-load test diagnosis and author repair record](runtime-r6-cold-test-repair/runtime-r6-cold-test-pre-format-review.json)
addresses a Linux content-watch assumption in one test. On Mac, content-watch
absence selects a serial path that still reads and verifies complete original
records; accepting identical rewritten bytes with an updated inode stamp is
valid. The [pre-format test-only patch](runtime-r6-cold-test-repair/runtime-r6-cold-test-pre-format.patch)
keeps the cache-miss assertion when a watch actually exists, checks complete
record and fresh-stamp adoption when it does not, and requires rejection of an
equal-length valid-JSON identity change. This snapshot changes no production
code and does not modify frozen `942d470`; final formatting and execution are
bound to the later c81 candidate below.

## Final runtime c81 source and separate gates

The final runtime publication is
[`c81a938150d2e533843a42af77739cb888812338`](https://github.com/TrillionniumFoundation/hepta-runtime/commit/c81a938150d2e533843a42af77739cb888812338),
tree `aa10bb33f641bc208a3fd11bef5737f6ba026f90`, parent `942d470`.
Its [publication receipt](final-runtime-c81-source/runtime-r6-published.json)
records reconstruction of the complete 10,901-entry source tree. The only
changed path from its parent is the cold-load test file; runtime production
files and the stored ledger are byte-identical to the parent.

The [native build projection](final-runtime-c81-source/runtime-r6-formatted-input-projection.json)
contains 958 files with digest `87557aff...`. The
[full platform projection](final-runtime-c81-source/runtime-r6-expected-input-projection.json)
adds the exact ledger, totaling 959 files with digest `3173737d...`.
The source identities document gives both complete digests. The
[19-target inventory](final-runtime-c81-source/runtime-r6-expected-targets.json),
[native format receipt](final-runtime-c81-source/runtime-r6-native-format-receipt.json),
stage runner and gate runner are retained with the source package.

The [r6 ledger reassembly proof](runtime-r6-ledger-proof/SUMMARY.json) regenerated
the same ledger digest `d5bb6f5d...` from this native projection. Its 29 tests and
ordinary mapping check passed. Strict parity still exits 3, reference
authenticity remains `NOT_REVERIFIED`, and the ledger retains 229 open
requirements and zero qualified tools. Reassembly consistency does not certify
REA parity or reauthenticate historical reference evidence.

The complete [c81 Linux platform gate](final-runtime-c81-linux/originals/linux-r6-final-gates.json)
passed all seven stages with its source projection unchanged: 2,354 tests
passed/40 skipped with all features, and 2,325 passed/28 skipped without
defaults. The [19-file original archive](final-runtime-c81-linux/runtime-c81-linux-original-artifacts.tar.gz)
retains both full nextest logs, format/check/clippy logs, metadata, runners and
source inventories. Every transferred chunk and every original member was
verified against its digest and pinned file version.

The [c81 Mac platform gate](final-runtime-c81-mac/originals/mac-r6-final-gates.json)
also completed successfully, with all nine stages passing and its 959-file
projection unchanged. It passed 1,974 tests/29 skipped with all features and
1,957 tests/19 skipped without defaults, plus its explicit cold-cache regression
and release build. The [release observer](final-runtime-c81-mac/originals/mac-r6-release-artifacts.json)
binds the actual runtime binary to SHA-256 `f5d51838...` and job-controller
binary to `9f9a6f32...`, with matching source inventories before and after.
The [complete platform-job terminals](final-runtime-c81-jobs/platform-terminals.json)
and [release-observer terminal](final-runtime-c81-jobs/mac-release-observer.json)
retain output completeness, durability and publication confirmation.

The separate [six actual refusal cases](final-runtime-c81-mac/originals/mac-r6-final-refusal-tests.json)
passed on that runtime binary with the fixture unchanged. This isolated fixture
intentionally has no HIA worker and reports 102 tools/zero HIA tools; it tests
unsupported-platform refusals and does not represent the production connector
catalog. The [26-file Mac archive](final-runtime-c81-mac/runtime-c81-mac-original-artifacts.tar.gz)
retains all logs, metadata, input inventories and observers, without binary
payloads or private configurations. The exact-source complete-repository
[hosted CI run and jobs](final-runtime-c81-ci/root-original-observation.json)
also completed successfully. The [complete original packet](final-runtime-c81-ci/original-packet/SUMMARY.json)
contains its 1,133,055-byte log and two artifact archives whose digests match
GitHub's artifact metadata. Both feature modes passed, and the mapping,
release build, cancellation/recovery and structural ZIP smoke steps succeeded.
The Linux JavaScript cancellation evidence applies to one owned MCP parent
and its stopped direct worker; the structural ZIP fixture does not claim APK
signature validity or full REA compatibility. Signed artifact-download URLs
are excluded from the public packet with their redaction provenance retained.
Its prospective-merge job was skipped on the push event, so this
result does not claim a passed merge gate. The isolated HTTP summary and the
unreconciled production operation remain separate observations.

## Runtime platform repair diagnoses before the r5 source gate

The [Mac redb lock probe](runtime-r5-repairs/redb-macos-lock-probe/SUMMARY.json)
reproduced a production cache-open defect: the earlier whole-file `flock`
conflicted with redb 4.4.0's OFD range lock even on the same descriptor. The
separate probe then kept a same-descriptor OFD whole-file lock continuously
through database open and a real write/read. Independent child processes were
denied both legacy file-lock and redb acquisition before validation, after
database open and after commit; they succeeded only after the owned descriptors
closed. The [original stdout](runtime-r5-repairs/redb-macos-lock-probe/execution.stdout),
source, selected-library digests and complete durable terminal are retained.
The diagnostic is distinct from a complete build of the repaired runtime.

The [owner-fence test review](runtime-r5-repairs/pre-format-reviews/runtime-r5-owner-fence-review.json)
preserves the exact bodies of seven Linux successor-replay tests while adding
non-Linux checks for the production code's explicit unsupported-platform
refusal. The [timeout-fixture diagnosis](runtime-r5-repairs/privileged-timeout/SUMMARY.json)
preserves the original failure and two actual Mac Python fixture checks; it
changes test readiness while leaving the production capture code unchanged.
The [Unicode glob fixture diagnosis](runtime-r5-repairs/unicode-glob-fixture/SUMMARY.json)
observed the original upper/lowercase Unicode filenames aliasing one inode on
the actual APFS workspace. Separating the fixtures into distinct directories
preserved both names, and ten native ripgrep pattern cases passed. Production
matching code was not changed by that fixture repair.
These snapshots predate final formatting and do not claim a passed r5 Rust gate.

The separately [pinned nextest tool metadata](runtime-tooling/nextest-0.9.137/SUMMARY.json)
retains the original official release response, official checksum, archive
download verification and [16-chunk upload receipts](runtime-tooling/nextest-0.9.137/upload-main-20261107/SUMMARY.json).
The third-party binary body is not duplicated in this collection. These
supply-chain receipts alone do not claim that any runtime test gate passed.

## Mac preparation and deployment-helper review

The [pre-cutover chat catalog observation](mac-preparation-205f94e/chat-catalog-before-cutover.json)
at 07:53:06 UTC exposes 70 `h` tools and zero HIA tools. Available plugin
management actions expose no catalog-refresh operation, and the observed
Hepta/HIA plugin search returned no result. This observation is separate from
the server-side 113-tool/11-HIA catalog; server discovery does not establish
that this chat can call those tools. No permission or plugin installation
change was made by this observation.

The [existing tunnel route observations](mac-preparation-205f94e/tunnel-route-public-observations.json)
retain three read-only jobs, including an initial JSON parse failure because
the active profile is YAML. The final bounded literal projection found
`http://127.0.0.1:8790/mcp` in the active profile and recorded its digest, mode
`0600` and owner UID 501. It did not interpret the complete YAML semantics,
export the raw profile or credentials, or change the running service. This
projection helps bind the local route without claiming a successful cutover.

The [HTTP qualification preparation packet](http-native-205-preparation/SUMMARY.json)
preserves the first adapter draft and its accepted-operation observation
finding, the corrected adapter `ab896592...`, independent review, nine local
tests and nine actual-Mac offline tests, plus validation of 22 tool schemas.
It also retains version/hash metadata for its isolated Python dependencies.
This packet performed no HTTP lifecycle calls, no model-agent campaign and no
production cutover. The planned 39 application calls use a new owned slot;
actual execution needs its own runtime PID/listener binding and receipts.

The [independent v3 adapter review](collection-reviews/http-adapter-v3-p3-review.json)
preserves the subsequent initialization failure and focused parser repair.
The [complete first-attempt packet](http-native-205-c81-initialize-failure/SUMMARY.json)
retains the original request journal, raw response, stderr, registration and
durable failed terminal, with the same server PID verified before and after.
The original 674-byte response begins with an empty SSE priming event before
the JSON-RPC initialize response. Adapter v2 rejected that empty payload; v3,
SHA-256 `e2fd5513...`, ignores blank data payloads while still rejecting malformed
nonblank JSON. Only `response_messages` changed at the top-level AST; original
job reconciliation, request identity, slot rules and retry policy stayed intact.
The failed first-loop journal and control flow show only `initialize`, with
zero recorded domain-tool calls. This is a bounded conclusion about that job,
not an independent packet capture or a successful later lifecycle claim.
The reviewer checked the original body and existing 11-test regression evidence
without issuing HTTP calls or running additional tests. The
[after-failure shadow probe](mac-preparation-205f94e/final-c81-shadow-after-init-failure.json)
again verified the same c81 process, listener, 113-tool/11-HIA catalog and pins;
it does not replace the required complete lifecycle run.

The submitted production-cutover job has no observed authoritative result
in this frozen checkpoint. An independent
[single status observation](production-cutover-observations/p3-status-once-20261107T092105Z.json)
returned MCP `-32603 Internal error` during the restart window. That transport
failure does not determine whether the runtime is reachable or whether the
cutover succeeded. The mutation has not been repeated by the collector; the
original job and any terminal report remain the required source of truth.

The later [r2 local packet](http-native-205-c81-loop-r2-partial/SUMMARY.json)
retains a successful original job terminal and its complete compact execution
projection. It reports 39 HIA application calls across all 11 tools, adoption
from generation/epoch 0/0 to 1/1, rejection with `E_HIA_GENERATION_STALE`, and
rollback to generation 0/epoch 2. Rollback governs future calls and does not
reverse past effects. The same shadow PID 68535, binary and listener were
verified before and after this isolated loop.

The raw 9,340,915-byte result and full 284,512-byte HTTP journal were not
downloaded. Their respective digests `9b9a1021...` and `99e2025d...`, and the
203 JSON-RPC-record count in the result, come from the retained read-only remote extractor;
they have not been independently recomputed from complete local copies. Only
the journal's final 32,768-byte segment is local. The complete 3,262-byte
projection is locally retained and hashed as `f42ee037...`, together with its
source, launch and readback receipts. The raw HTTP-body inventory is also
pending. This is evidence of the scripted isolated lifecycle, with an explicit
archive gap; it does not establish production success, a model-agent campaign
or net strategy benefit.

The [source staging](mac-preparation-205f94e/public-stage-manifest.json),
[resource staging](mac-preparation-205f94e/public-resource-stage-manifest.json)
and [isolated launchd resource probe](mac-preparation-205f94e/public-launchd-resource-probe.json)
do not claim a production cutover. The launchd probe observed its own direct
child's file-descriptor limits and the actual `launchctl print` syntax; an SSH
child's resource limit is not used to attest the controller.

The [v1 helper review](mac-preparation-205f94e/helper-review/mac-controller-deployment-local-review.json)
and [seven local fault tests](mac-preparation-205f94e/helper-review/mac-controller-deployment-tests.log)
are tied to helper SHA-256
`25e2d857d37b0146b3a8f1c20c60fe9e75a427b64889056e3acba8f5323dcc32`.
Its [actual Mac isolated exchange rehearsal](mac-preparation-205f94e/public-atomic-swap-rehearsal.json)
checked file/xattr preservation, symlink inode restoration and detection and
restoration of a concurrent displacement. It left the live controller files
unchanged. The helper preserves displaced entries, detects conflicts and only
rolls back its own replacement inode/value; it does not claim an atomic kernel
content comparison against arbitrary writers that ignore its deployment lock.

The later [v2 review](mac-preparation-205f94e/helper-review-v2/mac-controller-deployment-review-v2.json)
and [12-test log](mac-preparation-205f94e/helper-review-v2/mac-controller-deployment-tests-v2.log)
are tied to helper SHA-256
`043fc6c6045ca3024c898f9878b5fefd743c05de78bcaab577316e5e91340993`.
V2 adds explicit durable-terminal, original-job identity and complete-log gates.
The earlier Mac exchange rehearsal is retained under v1's actual hash; it is
not relabeled as a v2 cutover or a new Mac syscall rehearsal.

The subsequent [v3 review](mac-preparation-205f94e/helper-review-v3/mac-controller-deployment-review-v3.json)
corrects the staged job-controller executable name to the actual Cargo target,
`hepta-runtime-jobctl`. Its helper SHA-256 is
`a9c15b78cf8cee36d93b5e81b73a925de4cfa46e3c33648dd38bad3f5e451726`;
the 12 existing tests passed again, and non-main functions were unchanged.
The v2 bytes are retained separately. This name correction and its release
staging script had not executed a live cutover when this review was recorded.
The subsequent [create-only helper upload receipt](mac-preparation-205f94e/helper-v3-upload.json)
records both v3 scripts staged on the Mac with mode `0600`; it records
`production_modified=false` and preserves the earlier helpers.

The [v4 helper](mac-preparation-205f94e/helper-review-v4/mac-controller-deployment.py),
SHA-256 `6aae1a5e41c02fb6ba1f78dab09b0882a3615edb2dd68b11ed955ecb2b812d29`,
handles an accepted HIA operation by waiting for that original job, reading its
complete durable output, and using the provider's exact-repeat observation
path to authenticate the completed response. It does not allocate a replacement
request identity. The helper checks the old event digest when migrating the
known v3 probe without recorded URL fields, and binds the shadow HTTP endpoint
to the selected PID's executable mapping before and after the probe. The
[18-test log](mac-preparation-205f94e/helper-review-v4/tests.log) and
[independent source review](mac-preparation-205f94e/helper-review-v4/independent-review.json)
do not claim a successful live probe or cutover. Its existing 24 non-main v3
functions/classes were unchanged; the new observation helpers were reviewed
separately. The [earlier draft review](mac-preparation-205f94e/helper-review-v4/draft-independent-review.json)
retains the two recommendations addressed by this version and its different
draft source hash.

The later [isolated shadow receipts](mac-preparation-205f94e/shadow14-originals/SUMMARY.json)
are for runtime `14dfb09` and the Hepta `205f94e` worker. The five exact original
files preserve three attempts: v3 safely failed on an ordinary `accepted`
response; v4 then refused the supervisor PID before any HTTP call; the corrected
child PID 36464 passed the before/after executable-mapping and exact loopback
listener checks, the 113-tool/11-HIA catalog, and installation manifest pins.
Every original report records `production_modified=false` with no publication
changes. These observations do not qualify the failed `14dfb09` test gate,
later runtime source, or the current chat's tool catalog.

The [independent original-operation check](mac-preparation-205f94e/shadow14-original-observation-independent-verification.json)
verifies from the raw HTTP events that the successful attempt first waited for
and read the original job `1a1b5083599-8e70-1`, then used the unchanged
`hia_describe` tool and arguments. Its provider-authenticated completed response
equals the full original worker report's response; the pending and completed
request IDs are correctly treated as different namespaces. The
[archive](mac-preparation-205f94e/shadow14-originals/shadow14-original-five-files.tar.gz)
contains exactly the five specified files, with [original member digests](mac-preparation-205f94e/shadow14-originals/manifest.json),
complete transfer receipts and a durable successful packing-job terminal.

## Integrity and storage format

Original reports, logs and existing checkpoint archives are copied byte for
byte. New archives normalize archive header metadata only; every member's
bytes are retained verbatim, with a neighboring `.members.json` inventory.
The retained CI artifact deliberately includes a 535-byte truncated ZIP
negative fixture. The [format review](collection-reviews/intentional-truncated-zip-audit-review.json)
binds its exact paths and digest and verifies that it equals the fully expanded
companion fixture except for its final byte. The [content auditor](collection-reviews/audit_hia_evidence.py)
records this narrow exception explicitly, scans its raw bytes and expands the
complete equivalent; it does not silently accept arbitrary unreadable archives.
The final collection manifest will list every published file's length,
SHA-256 and canonical Git blob SHA-1. The manifest itself will be the sole
self-exclusion. The [publication preparation helper](source-publication/prepare-evidence-publication.py)
checks every uploaded blob against the local bytes, requires exact agreement
between the upload map and actual file set, reconstructs the complete base
tree, and computes the expected evidence tree without writing a Git index or
creating a local commit. Its result becomes reviewable before a branch update.

The local [failed git push](final-local-d32ef01/source-push.stderr) is preserved.
Publication used the GitHub connector and produced a different commit identity
with the same tree. Evidence remains a separate branch and does not modify any
implementation file in the candidate.
