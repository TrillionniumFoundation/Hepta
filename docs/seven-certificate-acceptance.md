# Seven-certificate acceptance design revision 3

Revision3 design and implementation contract, 2026-11-04. The runner and independent replayer are implemented and have passed independent implementation review. At activation, the complete kernel result remains UNCHECKED until the exact published tree passes the pinned real Lean run and mandatory full replay. Python fake-process tests do not establish that result. Normative companions: hepta-seven-acceptance-v3-schema.md, hepta-seven-v3-serialization-probe.py and its frozen JSON results. Existing source-only and first-four diagnostic interfaces remain unchanged and nonaccepting.

## Scope and unchanged proof requirements

Use a distinct seven acceptance runner/replayer, not a relabeled old six-partition manifest, arbitrary validator callback or diagnostic upgrade. Exactly eleven fresh uninstrumented modules: Baseline, SyntaxData, CertPart01–07, ConnectionsTransportRejections, WrongArm. Linear chain through combined consumer; WrongArm depends only on CertPart04 and its ancestors. All eleven output modules are fresh same-run outputs. The previous54-subject target receipt/olean cannot be reused.

Call existing complete seven validator and original/byte-fact/partition inverse chain on actual declarations. Preserve original66 positive targets, ten kernel proofs of the exact original negations under reversible identifier substitution, and all five complete byte streams. No compiler-error negative test counts. Fresh source-only measurement confirms byte lengths: linear14466,parallel14466,wrong_phi14466,literal_two14466,wrong_condition14585; total72449. All original+candidate declaration bytes are mandatory retained inputs,5593354 bytes total; no shortened/replaced workload. Validate full byte streams independently from retained sources, never just hashes/counts.

Success may set only kernel_core_syntax_connection_checked. All twelve wider obligations unproved, broader bridge/refinement flags false, production/admission/DENY flags unchanged. Last seven runtime and full eleven timing remain unknown.

## Compact storage without weakened validation

Do not retain the211667-byte original manifest separately. Both producer and independent replayer must deterministically reconstruct the complete original preparation/manifest from mandatory actual original source bytes and independently authenticated original inputs, validate it using unchanged oracles, then compare its exact original hash. PLAN binds this hash, all original source files, exact66 targets, complete ten original negation descriptors/current coordinates, and each of five complete reconstructed input lengths/digests/root owners. The source manifests and code identity authenticate reconstruction. Missing original source/input evidence or any inverse discrepancy fails, not a fallback to hashes. The complete manifest remains transient validation data, not an emitted duplicate or hidden artifact.

Keep actual source files, raw complete logs and all actual oleans. Inventory maps need not be repeated in FINISHED or RESULT: compact count/hash fields commit the complete maps reconstructed from the mandatory logs and exact source subject lists. Final frozen-file-map count/hash commits the complete fixed path→hash/length map, reconstructed by replay; no caller-supplied map can authorize paths. Original declarations, input bytes and logs are not removed by this compaction.

Mandatory full replay rehashes actual binary, all780 actual support files, the fixed source identity set and all eleven actual oleans. A summary or stored hashes without these files is not full replay and cannot set any qualification flag.

## Measured bounded serialization

The offline probe serializes every field of complete PLAN/RUN/IDENTITY/success RESULT/display,22 compact stage records, and1162 failure variants. Its finite string/path/count/integer limits and the exact admitted file sets are specified in the schema companion. It uses deliberately maximum-width hash/numeric values and some impossible joint combinations for conservative byte bounds; these synthetic records are not evidence or a claim they are semantically admissible. Actual future implementation paths must match the frozen identity list or require remeasurement/review.

Read exact current numbers from frozen hepta-seven-v3-serialization-results.json. The measured upper reserve is 219144 bytes, below262144; the reserved display is4096 bytes. Full canonical all-three-allowed-axiom output is744461 bytes, leaving 80875 bytes for extra actual output under the unchanged1MiB durable-plus-display ceiling. This establishes serialization capacity under explicit finite schemas, not successful Lean execution or a guarantee actual output remains within budget.

Global raw allowance is exactly1048576 minus measured metadata reserve minus4096. Enforce this across all eleven raw log pairs, additionally507392 per stage. A bounded capture stops immediately on either limit; do not discard earlier logs to make space. All generated metadata must be checked against its declared per-record cap AND precomputed total reserve before writing. Any identity/schema drift invalidates the reserve and requires review; no runtime expansion. PLAN/source manifest<=32768, STARTED/FINISHED/RESULT<=16384, total metadata<=262144. Every existing limit remains an independent constraint. There is no implicit upload/publication or larger display.

Retained container cap137MiB=143654912 bytes, with source8MiB/module128MiB/other1MiB subcaps. Current actual sources + maximum aggregate oleans + full evidence envelope =140859658 bytes. This is strictly a retained validated-file contract, not a claim of active peak disk allocation enforcement. A compiler can create a larger transient file before postprocess rejection. No disk-quota guarantee is made without a separately reviewed enforceable quota/filesystem mechanism. Directory scanning, per-file bounded reads and immediate overflow failure preserve admission correctness; they do not eliminate transient resource exhaustion risk.

## Capture, containment and time

Do not reuse base.capture_result: subprocess.run buffers output and does not establish bounded drain/reap behavior. A separately reviewed streaming collector concurrently reads bounded stdout/stderr, preserves raw bytes, incrementally hashes, rejects invalid UTF-8 and admits only complete exact inventories. Spawn a new session/process group and retain its identity. Keep its leader unreaped until the original-group SIGKILL; observe natural exit without reaping, and perform this cleanup even on natural leader exit because descendants may remain. After signaling, bounded drain/reap is followed by read-only killpg(pgid,0), which must return ESRCH. Never send a nonzero signal after leader reap. Existing group, EPERM, unknown outcome or grace expiry fails closed; residual zombies may cause conservative failure, and numeric pgid reuse can only cause false rejection. The schema companion defines the exact ordering. On60s deadline, overflow or capture error send SIGKILL immediately to the original process group; no TERM grace or additional computation allowance. The existing2s cleanup window is exclusively bounded drain/reap/observation after kill. Missing EOF/reap or nonempty original group fails and prevents later launches.

The guarantee is limited to the original process group. Children can theoretically escape by creating another session/group; this design does not claim they are killed or detected. Pinned trusted Lean is the execution assumption. If acceptance requires proof that no escaped descendants exist, an OS containment facility such as a reviewed cgroup/pid namespace is a separate blocking requirement, not something killpg establishes. Replayer validates the recorded original-group claim and process identity contract; it cannot manufacture stronger historical containment from booleans.

Runner elapsed clock starts before preparation. After costly identity/state checks and STARTED persistence, perform the540s deadline check immediately adjacent to spawn. No extra compiler invocation/probe/retry or prefix reuse.60s per process, immediate kill on expiry,2s cleanup only, outer command600s and job15min unchanged. The outer/job windows include preparation/finalization/other job work; no claim all eleven fit. Missing final evidence or outer termination is failure/incomplete.

## Transactional admission/finalization

PREPARING→VALIDATED→RUN_CREATED→[CHECKING→STARTED→SPAWNED→CAPTURED→VERIFIED→RECEIPT_COMMITTED→ADMITTED] for each stage. Any failure schedules no later stage. Admission only after successful receipt write/fsync/reread and identity/output checks; a mere fresh olean is quarantined until then. Parent links bind same-run source, actual olean and committed successful receipt.

After all eleven, FINAL_VALIDATING rechecks actual binary/support/sources/files/receipts/oleans, exact66+10/five bytes, budgets and launch counts. Build canonical candidate RESULT with narrow flag true but keep public/in-memory authoritative result false. Write exclusive fixed RESULT.pending.json, fsync/reread/check, atomically replace RESULT.json and fsync directory. Independent full replay of the final snapshot must then succeed before exit0 or any success display. On failure, return nonzero and best-effort atomically publish exact failed RESULT via the same pending name; retain at most one fixed FAILURE.json if replacement itself fails. The metadata reserve conservatively includes three terminal-sized records plus one failed stage record even when mutually exclusive.

A crash or filesystem failure can leave a success candidate on disk; it is never independently sufficient. All consumers must run full replay, not inspect flags alone. No absolute atomic guarantee over later-mutating external binary/support is claimed; subsequent use revalidates current actual inputs. Any failure in writing/rechecking/display preparation prevents a success return/display. No unsolicited artifact upload.

## Required next gate

The frozen design/schema/probe/result set and runner implementation have been independently reviewed. Publication and actual pinned Lean execution require final bounded regressions and independent review of the exact implementation plus activation workflow tree. Required control coverage includes: source and inverse mutations; every strict schema boundary; all failure variants; identity/receipt/olean splice races; immediate-kill/EOF/group-leader cleanup adversaries; exact540/60/2/600/job15 constraints; every metadata/raw/display limit; finalization fault injection; unchanged old diagnostic/partition tests. A stronger escaped-descendant or peak-disk requirement must be resolved explicitly before claiming it.
# Revision3 exact schema and sizing contract

Normative alongside v3 design and offline serialization probe. The executable probe contains the full exact key sets and nested record layouts; this text defines admission constraints not imposed by the sizing-only script. The script DOES NOT implement validation/execution and its synthetic files MUST NOT be consumed as proof receipts.

## Universal types and finite bounds

Canonical JSON: sorted keys, comma/colon compact separators, ensure_ascii=true, allow_nan=false, one trailing LF. Reject duplicate keys before construction, missing/unknown keys at every level, noncanonical encoding, bool-as-int, float for any numeric field, null except specifically allowed failure fields, nonfinite values, extra array elements and duplicate inventory names. Strings restricted to ASCII unless exact original theorem/proposition data requires a fixed escaped representation; exact original data bytes are predetermined by validator. All hashes64 lowercase hex, run_id64hex, current Git SHA1 commit/tree exactly40hex. Paths fixed safe relative allowlists; executable/root/sysroot absolute paths each<=128 bytes using only the alphabet ASCII letters A–Z/a–z, digits0–9, slash/, underscore_, hyphen- and period.; require one leading slash, nonempty components, no repeated slash, no trailing slash, and no component equal to a single dot or two dots. Quote, backslash, whitespace, control and every other character are rejected before serialization. This covers ordinary POSIX CI paths and guarantees no JSON escape expansion. Require verified filesystem resolution and exact equality to the canonical lexical form. Their values occur only in PLAN; per-stage exact argv/cwd/environment is derived and verified against PLAN, not repeatedly stored.

IDENTITY exact source path set is the224 current verified diagnostic source-identity paths plus these six proposed files: tools/check_core_seven_certificate.py,tools/core_seven_acceptance_plan.py,tools/core_seven_acceptance_replay.py,tools/core_seven_acceptance_capture.py,tests/test_core_seven_acceptance.py,docs/seven-certificate-acceptance.md. Exactly230 records; each {sha256,bytes}, bytes integer0..2097152. Exact support paths are the780 locked prior support-map paths; bytes integer0..9223372036854775807. Hashes and sizes are independently checked against actual bytes; zero is not permission to omit any file. Any actual new implementation file/path requires explicit identity-set and size review. No arbitrary-map keys or unbounded filenames.

Names/modules/paths/parents/counts/negative data are exactly the validated fixed seven plan. PLAN includes the eleven original source file hashes/lengths, the original manifest hash to regenerate, complete original66 target list, complete original ten negative descriptors with actual current coordinates, exact five input hashes/lengths/root-owner names, the fixed budget object and shared process spec. Per-stage expected names are independently regenerated, committed by subject sequence count/hash, never accepted solely by digest. Full72449 input bytes remain reconstructible and checked from retained actual declaration bytes; hashes do not replace them.

Integers: invocations0..11, index0..10, subject count exact stage value, inventory counts66/10 at final success, raw file bytes0..507392 subject to pair/global limits, module bytes1..33554432 subject to aggregate128MiB, elapsed/wall/remaining durations0..600000000000ns (additional semantic60/540 deadlines still mandatory), cleanup0..2000000000ns, returncode signed32-bit or null only if no exit status exists. No arbitrary error strings/tracebacks. Error codes and phases below are finite enumerations. frozen_files_count must equal actual fixed success set81; frozen_files_sha256 commits canonical sorted map {path:{sha256,bytes}} of22 source files,11 modules,22 logs,22 stage receipts and4 metadata files, excluding RESULT. Source-only seven manifest is20819 bytes without trailing LF in its original protocol; probe counts20820, a conservative one-byte reserve, not authorization to change its hash/encoding.

## Closed record shapes

Every exact field is present in the complete serialized probe output: IDENTITY,PLAN,RUN; for each of11 stages STARTED and FINISHED; RESULT success; RESULT failures and stage-failure FINISHED; display. No placeholders stand for omitted fields. Synthetic f-filled hashes, maximum numeric widths and root strings are sizing values only.

STARTED records bind run/plan hashes, exact stage/source, direct-parent committed receipt/source/olean hashes/sizes, and remaining launch time. Parent paths, argv and log/output names are derived uniquely from PLAN, not omitted authentication information. FINISHED always has schema,protocol,run_id,index,name,started_sha256,status,process,logs,inventory,olean; failure adds error_code, status stage_failed and inventory/olean=null. Success requires exact expected inventory and actual source-bound module. process exact keys: spawned,returncode,timed_out,incomplete,output_truncated,leader_reaped,stdout_eof,stderr_eof,original_group_empty,elapsed_ns,cleanup_ns. Success requires spawned/reaped/EOF/group-empty true, failure/truncation false, returncode0, timing in bounds. Failure does not authorize importing its output.

For a process not launched: spawned=false, returncode=null, elapsed_ns=0, no falsely asserted reaping/EOF/group emptiness; process flags use explicit observed false values. logs may be null only when no capture file was created; otherwise both stdout/stderr records exist, with lengths/hashes of actually retained bounded raw bytes and completeness encoded by process flags. A capture failure's retained bytes are diagnostic only. Missing STARTED before preparation requires no FINISHED; terminal failure fields explicitly bind null run/plan/identity as applicable. Probe's populated failure records overbound nullable variants.

Success RESULT commits run/plan/identity and full file map digest/count, ordered eleven finished-receipt hashes, original66 inventory count/hash, original10 negative inventory count/hash, invocation/wall data and exact flags/obligations/DENY. Replayer reconstructs all inventories/modules/fixed map from raw files. No duplicate top-level complete inventory maps are needed. The exact successful66 names and negative meanings are retained in PLAN and unchanged original source. RESULT flag alone never qualifies.

Failure RESULT exact fields are schema,protocol,run_id,status,run_sha256,plan_sha256,identity_sha256,failed_stage,phase,error_code,invocations,wall_ns,committed_receipt_sha256 plus all proof flags/obligations/authority. status=failed; all proof flags false; committed list is exact successful prefix (<=11), never unrelated hashes. failed_stage=null only for global preparation/finalization errors; otherwise exact current index. Bound-hash fields null only before corresponding artifact commits. A pre-preparation run may have a fresh run_id without any other artifact. Optional does not mean missing: nullable fields remain present.

Failure code → allowed phase(s):
- preparation_invalid → preparation.
- identity_changed → preparation,prelaunch,verifying,receipt_commit,finalization.
- launch_deadline → prelaunch.
- process_timeout,process_failed,output_limit,capture_incomplete,cleanup_failed → capturing.
- inventory_invalid,module_invalid → verifying.
- filesystem_invalid,evidence_limit → preparation,prelaunch,capturing,verifying,receipt_commit,finalization.
- receipt_failed → prelaunch,receipt_commit.
- finalization_failed → finalization.

The probe serializes a1162-record superset spanning all14 codes,6 phases and12 stage choices plus stage-specific failures. Illegal cross-products are rejected by this table and phase/index/state invariants. Measuring a superset provides an upper bound on every admissible failure variant, not permission to accept illegal combinations. It includes worst-width negative returncode and raw counts even when they could not coexist with a particular process state. Actual success records use required safe booleans. Prelaunch failure need not create any compiler FINISHED; a terminal closed failure record suffices.

## Fixed evidence/file admission and reserves

Only PLAN-determined paths are allowed. Global fixed metadata: IDENTITY.json,PLAN.json,RUN.json,seven-manifest.json; stage names produce `.started.json`,`.finished.json`,`.stdout`,`.stderr`; original/{original_stage}.lean and HiaSyntaxResearch/{seven_stage}.lean; latter stage `.olean`. No retained original-manifest.json. Terminal RESULT.json, transient RESULT.pending.json and best-effort FAILURE.json are the only additional paths. Any diagnostic or third-generation source/receipt/olean is rejected. Scans fail on foreign/symlink/hardlink/special files, unsafe ancestor replacements and mutation.

Per-record cap: PLAN/seven manifest32768; each STARTED/FINISHED/RESULT/pending/FAILURE16384; IDENTITY and RUN still bounded by their exact schema and overall limit. Complete metadata reserve is measured by probe: all4 globals + all22 successful stage receipts +1 maximal failure FINISHED +3 maximal terminal records. This deliberately overcounts mutually exclusive states, so transactional failure cannot exceed the reserve. Display is complete bounded canonical summary,<=4096 bytes (a tighter subcap than rev2's65536); no raw logs or full source dumped. Prepare before printing, and fail if it cannot fit. Existing1MiB durable+display envelope remains unchanged.

Full global raw allowance is computed once from the exact frozen reserve and4096 display reserve. Streaming increments raw counters before writes, fails immediately at either global or507392 stage cap, and never truncates into an accepting result. Raw output may have arbitrary permitted whitespace/additional lines up to that allowance;744461 is a standard canonical inventory scenario, not a guaranteed worst actual process log. Metadata comparisons/finalization allow no unbounded accumulation or copies outside this budget.

Offline probe checks each record size and all caps. Exact measured reserve/results are authoritative only for the frozen schemas/path sets. Failure variants and maximum-width field construction are fully serialized in hepta-seven-v3-serialized-records.json; that supplemental sizing corpus is NOT an execution container and is not subject to execution container caps.

## Requirement → tests before implementation

T1 Original/full inverse: mutate all five byte streams, original/candidate declaration body, each negative proposition/mapping, all66 inventory, cuts/ownership/imports; freshly recomputed forged hashes still rejected.
T2 Schema: every field unknown/missing/duplicate/null/wrong-type; bool-as-int, floats/nonfinite, bounds±1, path/count set mutation; success flags/phase table contradictions rejected.
T3 Compact reconstruction: delete original source/log/olean/input evidence, mutate regenerated original manifest, alter inventory digest/count or terminal81-file map; cannot pass from metadata alone.
T4 Failure variants: all allowed code/phase/index combinations and reject all illegal cross-products. Verify prefix receipt lengths, null binding rules, non-launched process fields and no downstream admission.
T5 Capture: immediate SIGKILL at60/overflow/error, no grace computation;2s only drain/reap, EOF/reap/group missing fails; escaped group cannot support a stronger containment claim.
T6 Limits: exact540 deadline after expensive checks, raw stage/global ±1, metadata/record/display±1, source/olean/retained-container caps, outer600/job15 interruption. Separate test/documentation for peak-disk risk, no invented active quota.
T7 Finalization: inject every write/fsync/reread/rename/replay/display failure; no exit0 or success display, no consumer trusting RESULT flag alone, reserve covers failure paths.
T8 Provenance: change actual pinned binary, any support/source/olean, same-run receipt/run ID or external support prefix; reject. Full replay requires actual complete file bytes.
T9 Regression: old partition, byte-fact and seven diagnostic tests unchanged, including EIO; original diagnostic remains nonaccepting. No implicit uploads, budget/time increase, retry or extra compiler calls.

Display has the same closed fields in success/failure: schema,protocol,run_id,status,commit_sha,tree_sha,invocations,positive_targets,exact_negation_proofs,stages,result_sha256,error_code,phase,failed_stage,scope. Success status full_replay_verified has three failure fields null; failure status full_replay_failed has finite code/phase and stage/null. No success counts are claimed for failed execution: numeric counts/stage statuses in failed displays must describe only validated progress; the sizing corpus retains maxima solely to overbound their widths. Pending or missing terminal hash/identity may be null only in an explicit failure display; never a success. Failure displays for all1162 sizing variants are serialized too; their measured maximum stays under4096. Scope is fixed text, not an unbounded user/error string. Display does not certify escaped-descendant containment or peak disk limits.


Original process-group completion protocol (normative): preserve the spawned session/group leader identity and do not reap it before the last possible nonzero group signal. Observe natural leader termination with waitid(..., WEXITED|WNOWAIT|WNOHANG) or an equivalently reviewed non-reaping observation; Popen.poll/wait/communicate before group SIGKILL is forbidden because it can reap. On timeout, output/capture error, or natural leader termination, issue SIGKILL to the original pgid while the leader remains unreaped. Natural exit is not proof that descendants ended: this cleanup signal also handles residual original-group members. A zombie leader may already have no live signal recipient; an ESRCH response is recorded as no currently signalable original group, not standalone cleanup success. Any other signal error fails closed. After this point send no further nonzero signal, particularly none after reaping.

Within the existing2-second cleanup window, drain both pipes to EOF, reap the leader, and require a final read-only killpg(original_pgid,0) probe to return ESRCH before original_group_empty=true. A successful probe (group exists), EPERM, any unknown result, missing EOF/reap or window expiry is failure; bounded read-only probes may await disappearance but cannot extend the window. Residual zombie descendants can keep the group observable until their actual parent reaps them; the runner cannot claim to reap nonchildren, and this may conservatively fail. Once the original leader is reaped its numeric pgid could be reused; because all subsequent probes have signal0, reuse can only cause false rejection, not signaling an unrelated process. No recovery signal after reap is permitted. Retain the exact spawn identity, non-reaping terminal observation, pre-reap signal outcome and final ESRCH observation in the process metadata via the finite fields specified by the serialization probe. Escaped descendants remain outside the guarantee.

The process object additionally has these exact bounded fields: leader_pid and original_pgid integer1..2147483647 or null only if spawn never occurred; leader_start_ticks integer0..18446744073709551615 or null only before an identity could be captured; terminal_observation one of waitid_wnowait/not_observed; pre_reap_group_signal one of sigkill_sent/sigkill_no_signalable_group/not_attempted/failed; leader_reap_observed boolean; post_reap_group_probe one of esrch/group_exists/unknown_or_permission_error/not_observed. Successful stage requires positive captured leader/pgid with pgid=spawn leader pid, authenticated start identity, leader_reap_observed=true, post_reap_group_probe=esrch and pre_reap_group_signal one of the two successful signal outcomes. A real ESRCH before reaping never substitutes for the final post-reap probe. The probe serializes the longest enum spellings and maximum numeric widths for failure bounds; success uses required ESRCH/reap values. For prelaunch failures these fields are explicit null/not_observed/not_attempted/false as applicable. No arbitrary errno message or process description is stored. Timing/order must be checked in the collector and adversarial tests, not inferred solely from a result boolean.

## Implementation notes and invocation

The production entry point is `python -m tools.check_core_seven_certificate
--lean /absolute/pinned/bin/lean --output-directory /fresh/absolute/run`.
The independent consumer is the same command with `--replay` and no `--lean`.
Neither accepts a validator callback, custom identity reader, compiler substitute,
process-limit override or test mode. The kernel workflow invokes this complete acceptance runner once, then replays
the same retained evidence. It does not also invoke the old four-process
diagnostic. Both CLI paths are bounded by the unchanged job limit; the acceptance
command retains its 600-second external limit. No artifact upload is added.

Canonical commitments for regenerated inventories, subject sequences and the
frozen file map use sorted compact JSON with one LF. The original and seven
source manifests retain their original no-LF protocol. Negation inventory
commitments bind each original negative key to its exact certificate name and
actual admitted axiom inventory; the complete original proposition and current
coordinates remain independently checked in PLAN and actual declaration bytes.

`prepare()` invokes the unchanged original builder and `seven.build_sources`.
The latter invokes unchanged `seven.validate_sources`, which invokes the full
original, byte-fact and partition validation chain. It does not duplicate that
same candidate validation immediately after the builder. Reconstruction loads
all actual retained candidates and invokes the unchanged full validator again;
finalization and independent replay each reconstruct the actual retained bytes.
There is no public prepared-object execution entry point.

A spawn whose Popen return crosses the launch cutoff is a spawned, incomplete
capture, not a prelaunch refusal: it receives immediate pre-reap SIGKILL and
cannot admit a module. The closed error is capture_incomplete/capturing.
Blocking host filesystem syscalls cannot be preempted in Python; checks on
return conservatively reject deadline overruns rather than recording success.
No stronger OS process isolation, peak-disk or hostile-host attestation claim is
made. These limitations do not authorize larger time or evidence limits.

Tests use Python-only fake binaries in copied, fully populated installations.
The copied toolchain lock is changed only within temporary test installations.
All230 source and780 support files are present and read by production identity
code. Orchestration-only adversaries reuse a fully validated source fixture with
unittest monkeypatching; full source/inverse and full execution tests remain
separate and production has no bypass switches. Run tests in the documented
bounded groups, each under `timeout 180`; do not extend the limit to hide a slow
test or activate the acceptance workflow.

RESULT.wall_ns is the snapshot wall interval from runner entry to candidate
RESULT construction, not total command runtime: its own subsequent atomic
commit and mandatory independent replay cannot be included without rewriting
the already verified snapshot. The actual monotonic runner clock remains active
through that replay, display preparation and final checks, and must stay within
600 seconds before success return and CLI success display. External measured
whole-command elapsed time is reported separately, never inferred from wall_ns.

Independent replay returns immutable verified result/display bytes prepared
inside the same bounded snapshot and before its final identity/file rereads.
The replay CLI never rereads PLAN or IDENTITY paths after verification.

IDENTITY commit_sha/tree_sha describe the checked-out Git baseline. Source
records bind actual file contents, including local uncommitted implementation
tests; baseline fields alone never assert those contents equal a published tree.
A real CI execution wrapper must require its expected HEAD/tree and a clean
checkout. Publication must independently verify the exact reviewed tree before
making any runtime/proof claim. Temporary copied fake installations deliberately
exercise actual-source identity separately; they do not provide a production
bypass or establish a published kernel qualification.

The locked-binary digest is parsed only from a bounded nofollow reread of the
already authenticated lock file, with its actual length/hash and inode checked
again before parsing. Successful process receipts require elapsed strictly below
60 seconds and cleanup strictly below2 seconds, matching capture rejection at
the exact deadlines. Failure receipts retain the inclusive finite serialization
bounds without allowing admission at those boundaries.

Every external identity pass, including initialization and independent replay,
rejects both `lib/lean/HiaSyntaxResearch` and
`lib/lean/HiaSyntaxResearch.olean` if either lexically exists in the pinned
sysroot, including dangling symlinks. The fixed780-file hash inventory does not
by itself exclude an extra same-module support shadow.

Failure process records also enforce observed-state consistency: no unspawned
flags or cleanup duration, exit status iff reaped, no post-reap observation
before reaping, latest ESRCH iff group-empty, captured identity before terminal
observation, and incomplete status for an expired cleanup window. Every actual
Python collector regression output is fed through that same validator.
The final timeline includes final STARTED elapsed time plus the final process
and cleanup durations, not just their separate lower bounds.
