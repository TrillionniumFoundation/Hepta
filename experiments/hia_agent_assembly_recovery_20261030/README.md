# Independently registered exploratory Agent replication

This directory prepares one complete, separately registered replication of the
three-arm HIA JSON / HIA assembly / Rust study on a fresh GitHub-hosted
`ubuntu-24.04` VM. **No recovery model completions have been run locally.**
The actual CI launch and outcome are identified by the retained run ID, commit,
registration, raw artifact and final readout; this source directory does not
pretend that preparation controls are model observations.

## Why this is a separate study

The original v4 study remains frozen at **15 of 24 cells attempted**. Qwen
completed all 12 cells with zero successes. Granite attempted three cells and
stopped on `RemoteDisconnected`; nine Granite cells were never attempted. The
original protocol required stopping on that infrastructure failure. The saved
original source, raw cells, unknown usage and negative/incomplete conclusions
are retained under `../hia_agent_assembly_v4_readout_20261030/`.

These four tasks, earlier responses and earlier results have already been seen.
The new cohort is therefore an **exploratory replication**, not unseen-task
evidence. Old and new cells are never pooled, replaced or continued. A different
outcome cannot establish that memory pressure caused the earlier failure:
host, interpreter, compiler identities and preparation are recorded anew.
General Agent productivity, project-scale maintenance and human labor costs
remain unmeasured.

## Fixed experiment and fresh registration

`PROTOCOL.json` binds the original registration, stopped cohort and complete
original source archive. Before tool installation or downloads, the executor
checks the original protocol SHA and all **31 actual evaluator source hashes**.
It builds a separate source snapshot from the original archive; new controls,
protocol metadata and registration are written only into that snapshot. The
serialized/canonical fixture hashes and complete prompt/schema inventory must
equal the original registration before any completion is possible.

The new metadata identifies the replication and resource conditions. The source,
candidate validation, feedback, task order, API decoder and model budget remain
unchanged:

| Item | Fixed setting |
| --- | --- |
| Cohort | Two original model families × four original tasks × three arms = 24 cells |
| Models | Original official fixed-revision Qwen 1.5B and Granite 2B GGUF bytes/SHA-256 |
| Runtime | Original fixed llama.cpp `b11669` binary archive bytes/SHA-256 |
| Model settings | Four inference threads, 8,192-token context, 2,048 maximum output tokens |
| Per-cell budget | At most two submissions; the original hard 180-second entire-generation deadline |
| Runtime environment | `LLAMA_ARG_REPACK=0`, as observed for all nine original owned servers; see `PARENT_RUNTIME_ENVIRONMENT.json` |
| Fresh qualification | 36 reference controls: 24 native builds/executions and 12 expected refusals; nine hostile native controls; 20 original orchestration controls; two tokenizer-only checks |
| Native tools | Signed LLVM 20 packages and Rust 1.95.0; exact installed identities and logs retained |
| Infrastructure failure | Stop the entire new cohort, preserve all partial observations and unattempted cells; no replacement or automatic rerun |

The finite original syntax profiles remain in force. In particular, an otherwise
valid Rust spelling can be outside the registered profile. Such admission
refusals remain recorded refusals; they do not prove semantic incorrectness.
Nothing in this replication repairs model answers or widens correctness gates.

## Resource and launch qualification

Before installation/downloads, before tokenizer-only capacity checks and before
each model family, `resource_gate.py` records actual Linux metadata. Effective
CPU capacity must be at least four; host `MemAvailable` and every visible finite
cgroup memory headroom must each be at least 4 GiB. CPU quota and affinity both
constrain admission. Explicit `memory.max=max` is unlimited at that node; missing
interfaces require a proven hierarchy-root/inactive-controller case. Unknown,
hybrid and cgroup-v1 limits refuse. These are admission observations, not a
guarantee of uninterrupted resource availability or remote attestation.

The workflow is `.github/workflows/hepta-agent-recovery.yml` on
`codex/hia-ndu-verified-optimization-20261027`. A push must contain exactly one
`[HEPTA_AGENT_RECOVERY_20261030_V1]` in **its current head commit message**, or an
explicit dispatch must supply that exact marker. Pull requests cannot launch it.
Workflow attempt must be one. A single workflow concurrency group serializes
push and dispatch; the executor reads and retains current/history Actions API
responses and admits only the earliest eligible launch. Previous failed,
cancelled or queued marker runs consume the study; an earlier dispatch whose
inputs are unavailable also conservatively consumes it. Missing metadata,
incomplete pagination, or reaching the API's 1,000-entry search cap refuses.
Later evidence commits without the marker cannot generate completions.

Only read-only Actions/contents permissions are requested. Checkout does not
persist credentials. The API credential is excluded from child environments;
request authorization headers and general environments are never archived.
Original runtime identity code only reads its registered environment whitelist.

## Ownership, stopping and deadlines

Each wrapper command receives a newly created process group. Linux
`waitid(WNOWAIT)` retains the owner PID until that group has been signalled on
every exit path, including success, and the owner is reaped once. If its identity
anchor has been lost, the wrapper never signals the reusable numeric group ID.
Cleanup errors remain separate from the original timeout/error.

The original llama servers inherit that group. The frozen HIA object compiler
can create its own bounded Clang session; an outer hard interruption cannot
prove that every descendant closed. Existing `engine.close` receipts are
preserved; missing receipts and all-descendant cleanup remain unknown. Group
signalling never fabricates engine shutdown proof. Incomplete observations are
ineligible, and final disposal of the fresh VM is the remaining containment
boundary. No unrelated process is targeted.

The job budget is 300 minutes. The preparation/inference deadline is 270 minutes
from the first bootstrap timestamp, so checkout and Python setup consume it.
Finalization has a fresh 20-minute budget, staging five minutes, with the rest
reserved for artifact upload. This reserve is an operational target: hard job
cancellation, provider failures or exhausted storage can still truncate
retention. Such cases are failures or unavailable evidence, never completed
studies. The outer deadline does not shorten an accepted per-request budget or
authorize additional attempts.

## Raw evidence, costs and the authoritative result

Definitions are copied before qualification, including original/new protocols,
the original registration/source archive, recovery helpers and workflow. Fixed
downloads enforce streaming byte limits, HTTPS, absolute deadlines and exact
SHA-256, without retries. Runtime extraction rejects escaping paths, special
files, duplicate members, excess member counts or expanded bytes before use.
The separate download/tool cache never enters the artifact.

All requests, response bytes, cells, native candidates, source snapshot,
preparation failures, resource readings, registration and model terminal records
are retained. Raw-suite and source archives are created outside their source
directories and completely read back against member/source hashes. Independent
readout and diagnosis perform no model generation, native execution or candidate
repair. If both model terminal records are unavailable, the complete readout is
explicitly unavailable; missing cells are not fabricated.

The uploaded directory is a separate bounded copy of regular evidence files.
Weights, downloaded runtime/tool payloads and symlinks are refused. A failed copy
retains and inventories its actual partial bytes with unverified source-copy
status. `ARTIFACT_STAGING.json` lists the actual staged files, omissions/errors
and costs; its own hash is intentionally excluded. Upload failure and the
provider's retention period remain external limits.

**`RECOVERY_RESULT.json` in the uploaded artifact is the final replication
qualification record.** It combines the independent audit with final inventory
and staging status. `FINALIZE.json` is an earlier audit checkpoint, written
before final inventory/staging; it must not override a later failure. The
underlying readout keeps its original v4 schema/title because its code is
unchanged, and the recovery result explicitly supplies this separate study's
identity and interpretation. `FINALIZATION_UNAVAILABLE.json` indicates that
only fallback receipts survived, not a complete raw artifact.

Costs include bootstrap/setup, installation, fixed downloads and hashes, fresh
controls, source copy, registration, model startup/restarts/shutdown, generation,
validation, readout, archive/readback and staging. Nested intervals must not be
added twice. Partial output usage stays unknown. Provisioning before bootstrap,
action internals, upload until separately observed, human engineering and full
economic cost are unknown. Model-specific outer CPU/maxRSS are measured in a
fresh observer; maxRSS is a completed-process high-water mark, not simultaneous
aggregate peak memory.

## Bounded controls

`test_recovery.py` exercises resource refusal, unreaped-owner cleanup and partial
artifact qualification with pure metadata/mocks and tiny local files. Independent
review directories retain first failures as well as final source-bound controls
for resource/download/tar/process/launch/model-loop/finalization boundaries.
None is counted as an independent model response or a successful coding task.
The original 31 evaluator sources and original study evidence remain unchanged.
