# Relocated seven-certificate full acceptance

This is a separate implementation of `seven-relocation-acceptance-v1`, with
schema `hepta.hia.seven-relocation-acceptance.v1`. It does not widen, modify or
replace the old acceptance API. The old acceptance, diagnostic, source
validators and capture implementation remain unchanged. Python test results,
source validation, diagnostic timing and an unreplayed RESULT flag are not Lean
kernel acceptance. Implementation review and an independently reviewed atomic
workflow execution/replay switch are separate gates before real execution.

## Source and proof boundary

The source-only relocation moves exactly 491 auxiliary facts,
`HiaCoreSyntaxSlice.parallel_bf0000` through `parallel_bf0490`, from CertPart04 to
the CertPart03 tail after `HiaCoreSyntaxSlice.parallel_pl113_0`. Exactly 100165
raw declaration bytes move and 104 parallel auxiliary facts remain in Part04.
The unchanged relocation validator requires distinct ParallelRelocationSources,
all eleven stages, unchanged metadata/imports/parents, globally unique names,
valid dependencies, exact inventories and the complete actual-byte inverse.
It recovers the old stages from actual relocated declarations, requires exact
old proposal equality and invokes the unchanged old full validators. The old
validator must still reject a relocated candidate directly.

Preparation builds complete original inputs, the transient old seven proposal,
and then the unmarked relocated candidate. Replay loads all actual retained
original sources, reconstructs and validates their original manifest, and loads
all actual retained candidate sources and the actual relocation manifest.
Expected generated stages provide metadata scaffolding only. The actual
candidate goes through the same mandatory inverse. The old seven proposal and
original/old-seven manifests remain transient context, not extra retained files.

All 7685 data definitions, 4215 original transport theorems and 2975 auxiliary
facts are preserved. Full input byte lengths are linear 14466, parallel 14466,
wrong_phi 14466, literal_two 14466 and wrong_condition 14585, totaling 72449.
All 66 original positive targets and ten exact-negation proofs remain required.
No proof body, proposition, input byte, identifier, root owner or import changes.
The relocation manifest has no negative-location ledger: PLAN locations are
freshly parsed from the actual final two candidate modules using the unchanged
unique theorem-line rule. Their names and historical descriptors must match all
ten originals; comparison against the old seven map is an additional check.

The candidate manifest remains source_only=true, acceptance_eligible=false and
kernel_core_syntax_connection_checked=false. Those fields are never upgraded.
Only a complete fresh execution followed by independent full replay qualifies
the separate execution claim. The narrow execution flag is
kernel_core_syntax_connection_checked=true; all other proof flags remain false,
all twelve wider obligations remain unproved and authority remains DENY_ALL.
There is no native/runtime/production/performance/elision permission, merge,
deployment or automatic approval.

## Eleven fresh processes and unchanged lifecycle

The only schedule is Baseline, SyntaxData, CertPart01 through CertPart07,
ConnectionsTransportRejections and WrongArm. Exact inventory counts are
56, 547, 271, 54, 1655, 807, 1297, 1297, 1297, 75 and 1. WrongArm imports Part04
and its ancestors, never the original extractor. Success requires all eleven
successful fresh processes and same-run modules. A failed stage prevents all
later launches; no compiler probes, retries, twelfth process, marker sources or
old receipts/oleans are admitted.

The runner is an explicit isolated copy of the old plan/runner/replayer with
only the reviewed protocol, source preparation/reconstruction, manifest,
identity paths and serialization constants adapted. It imports unchanged
core_seven_acceptance_capture. There are no production validator callbacks,
source-acceptance switches, patched globals or subclass gates.

Each child starts a new session and streams bounded stdout/stderr. Preserve the
original group leader unreaped through the last nonzero group signal: terminal
observation is non-reaping waitid/WNOWAIT. Natural leader exit, timeout, overflow
or capture failure triggers SIGKILL to the original group before leader reap.
A pre-reap ESRCH means no signalable original group, not cleanup success.
The existing two-second cleanup-only window permits bounded drain, leader reap
and final read-only killpg(..., 0) probing. Success requires both EOFs, reap and
final ESRCH. Never send a nonzero group signal after reap. Residual zombies may
conservatively fail; descendants escaping the session/group are not contained.

Process fields and all finite enums are unchanged: spawned, returncode,
timed_out, incomplete, output_truncated, leader_reaped, stdout_eof, stderr_eof,
original_group_empty, elapsed_ns, cleanup_ns, leader_pid, original_pgid,
leader_start_ticks, terminal_observation, pre_reap_group_signal,
leader_reap_observed and post_reap_group_probe. Exact observed-state and timing
consistency remains mandatory. No exit status, reaping, EOF or group emptiness
may be claimed for an unspawned child.

## Fixed identity and complete retained evidence

There are exactly 239 sorted literal source identity paths: the old 230 plus
this document, the new plan/runner/replayer/test, the unchanged relocation
source validator/test/document, and the initialization-frontier workflow. Their
canonical JSON-plus-LF tuple commitment is
cbb40503e9185e8a3f79f6936a60fc0f88e5e3af12cd11d4d6098d241295e8fa.
The fixed 780 support paths and pinned Lean 4.19.0 binary lock are unchanged;
the support tuple commitment is
edcebd3d002159c741e80e9fc3c8c42fc722e54a1a1d7341c91ee31df6ea743f.
No dynamic discovery expands either set. All old files in the source set remain
authenticated even when not directly imported. Every identity pass rejects both
same-module support-shadow locations HiaSyntaxResearch and HiaSyntaxResearch.olean.

The frozen set has exactly 81 files: 22 original/candidate sources, 11 modules,
22 raw logs, 22 STARTED/FINISHED receipts, and IDENTITY.json, PLAN.json, RUN.json,
relocation-manifest.json. The only other permitted names are RESULT.json,
RESULT.pending.json and FAILURE.json. Successful replay requires exactly the
81 frozen files plus RESULT, without pending/failure files. Old seven or any
diagnostic manifests, extra sources, old modules/receipts, unknown paths,
symlinks, hardlinks and special files fail closed. All actual source, binary,
support, module and raw inventory bytes are required; compact display is not
portable evidence. Retained sources total exactly 5593354 bytes.

PLAN and RUN bind original_manifest_sha256, relocation_manifest_sha256 and
previous_seven_manifest_sha256. The old seven_manifest_sha256 field is absent.
PLAN retains complete stage metadata, exact subject-sequence commitments,
parents/imports, all positive/negative descriptors, original-source map, full
five input hash/length/root-owner records, budgets and fixed process spec.
STARTED binds current PLAN/RUN, source and admitted parent receipt/module/source
chains. FINISHED binds STARTED, exact process state, actual raw logs, regenerated
inventory and actual source-bound module. Every receipt carries the new common
schema/protocol and fresh run_id. RESULT retains the original exact structures,
including the complete frozen-map commitment and all 66+10 inventory bindings.

Canonical record JSON uses sorted compact keys, ASCII escaping, no duplicate
keys or nonfinite values, exact types, and one LF. The relocation source manifest
uses its unchanged no-LF encoding: exactly 24492 bytes. Absolute process paths
are bounded at 128 bytes and the original canonical alphabet; there are no
arbitrary filenames, messages, maps or error strings in evidence records.

## Caps and finite serialized envelope

All original maxima remain unchanged:

- Source 2097152 bytes each and 8388608 aggregate.
- Module 33554432 bytes each and 134217728 aggregate.
- Raw stdout plus stderr 507392 bytes per stage.
- Metadata 262144; durable evidence plus display 1048576; display 4096 bytes.
- Retained container 143654912 bytes.
- Process 60 seconds; preparation-inclusive adjacent-to-spawn cutoff 540 seconds.
- Outer command 600 seconds; cleanup-only two seconds; job 15 minutes.

The separately reproduced finite serialization corpus covers all successful
records and a conservative superset of 1162 failure records/displays. It uses
maximal-width hashes, integers and paths, all four globals and all 22 successful
stage records, one maximum failed FINISHED and three maximum terminal records.
The exact metadata reserve is 224589. RAW_GLOBAL is
1048576 - 224589 - 4096 = 819891, below the unchanged collector's older ceiling.
The runner passes only 819891 minus actual cumulative raw bytes to that collector.

Per-record caps are IDENTITY 144713, RUN 630, PLAN and relocation manifest 32768,
and every stage/terminal record 16384. Measured PLAN is 22847. The manifest's
24493-byte serialization reserve is conservative by one byte, not permission
to append an LF. Largest successful STARTED/FINISHED are 829/1336; success RESULT
2556; largest failed FINISHED 1134 and failure RESULT 2274. Success/failure display
maxima are 1308/1335. Canonical complete inventories using all three permitted
axioms consume 744461 raw bytes; combined full reserves leave 75430 bytes.
Arbitrary excess warnings/failure output can still fail closed. Sizing fixtures
are offline arithmetic, not execution receipts or timing feasibility.

Preparation, complete inverse and identity work count against deadlines. The
six-process diagnostic observation does not prove eleven-process feasibility.
Caps are retained-evidence bounds, not active peak-disk quota enforcement. Host
filesystem calls cannot be preempted in Python; deadline checks on return reject
overruns rather than claiming stronger isolation. Pinned processes and host
remain trusted; this is not malicious-host authentication.

## Transactions, replay and failure

Each receipt is exclusively written, fsynced and reread before module admission;
independent stage replay then authenticates its actual source/log/module chain.
Finalization repeats the actual-source inverse, writes/fsyncs/rereads the pending
candidate, atomically renames it and syncs the directory. Independent full replay
and post-replay identity/file/byte checks must complete before exit 0 or success
display. A crash-left candidate RESULT can already contain a true narrow flag;
that flag alone never qualifies. Any pending/failure artifact forces rejection.

Failure shapes, phase/code enums, null rules and successful-prefix accounting
are unchanged. Only finite preparation, identity, deadline, process, output,
capture, cleanup, inventory, module, filesystem, evidence, receipt and
finalization error codes are admitted. Failures never admit modules or authorize
descendants. All 1162 sized combinations overbound the schema; impossible
phase/process/prefix combinations remain invalid.

RESULT.wall_ns measures entry through candidate construction, not the later
atomic commit and full replay. Actual monotonic checks continue through replay,
display preparation and final rereads within 600 seconds. Independent replay
returns immutable verified result/display bytes, not a reason to reread mutable
PLAN/IDENTITY after verification. Git HEAD/tree fields describe checked-out
baseline metadata; actual source records bind file contents. Publication and a
real execution wrapper must separately verify the reviewed exact clean tree.

## Invocation, controls and activation gate

After independent implementation and activation review, the entry point is:

    python -m tools.check_core_seven_relocation --lean /absolute/pinned/bin/lean --output-directory /fresh/absolute/run

Independent replay uses the same entry point with --replay and no --lean. There
is no fallback diagnostic, manual retry or source-only promotion. Activation must
switch workflow execution and replay atomically, preserve old controls and add
the new controls. This implementation itself does not edit workflows or invoke
Lean, and adds no artifact upload.

The new tests adapt all old schema, process, capture/cleanup, identity, snapshot,
filesystem, transaction, replay and source-adversary controls to these separate
modules. All old tests remain unchanged and are rerun. Fake child installations
populate all 239 actual source and 780 support files and change only the copied
toolchain lock to a Python fake executable. They do not establish Lean success.
Scoped unittest fault injection accelerates orchestration adversaries; unmocked
source preparation and retained-byte reconstruction also execute through the
full runner and independent replay. Bounded test shards use timeout 180 seconds,
zero skips, and the pinned Python 3.12.14 / z3 4.15.4 environment. Never increase
limits or patch production validators to hide a test failure.
