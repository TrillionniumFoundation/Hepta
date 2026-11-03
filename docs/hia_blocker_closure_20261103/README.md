# HIA blocker closure evidence — source-bound research checkpoints

## Current candidate and status

Draft PR [#564](https://github.com/TrillionniumFoundation/Hepta/pull/564) now points to
**`f2b76f5741c83822be2e12cf5a50b50a8d27b96a`**, tree
`0e2e8c982dada17251e9c97c746689ee85f69f37`.
Prospective merge `bc9f537d48e69b84d5f04a1824fd293249aef8d0` into
`18291446e048f760f5519823e865727ef51db11a` has the identical tree and both
expected parents. This evidence branch preserves observations about identified
source commits; its own tree is not the tested implementation.

The current four-file change retains actual ABI native originals before
temporary-directory cleanup. Independent code review and **17 adapter controls**
passed on the identical prepublication tree, with zero failures/errors/skips.
All **17 current actual-host jobs and their artifact reviews** have completed successfully. Root review
rehashed the three direct HIA/LLVM artifacts, including **394** captured-C
manifest members and all functional/resource observations. The seven ABI v3
archives and seven C++ archives passed their separate original-byte
review. Current composition also passed 347 tests and 22 qualifications, and
historical closure passed 175 controls plus all 611 retained-file checks.
Source/application passed its separate 562 safety and 410 regression tests,
449 scalar obligations and 1,826 manifest-member checks. Verified-native is
the remaining running lane.
The current Rust gate is **153/180**, and native NDU has **0/3 scenario wins**;
both remain negative despite successful execution of their measurement lane.

The preceding `23af1df` checkpoint completed all eight workflows and their
artifact reviews. The actual model study remains frozen on that source.
It is not silently re-registered or used as same-source qualification of
`f2b76f5`.

`authority=DENY_ALL`, `safety_certificate=false`,
`production_activation_allowed=false`, `all_blockers_closed=false`.

## ABI original-byte retention repair

The previous ABI matrix report retained native hashes, command observations and
structured build receipts, but its temporary object and executable files were
deleted. A hash receipt is not an independently retrievable original.

The new `hepta.native-host.v3` contract creates a separate, create-only artifact
directory and preserves the actual Rust object, O0 and O2 C executables, the
compiled wrong-echo executable, staged C sources/headers, canonical Rust input,
structured Rust build receipt, and original bounded C-driver stdout/stderr.
The manifest is bound to source commit/tree and compiler/qualifier identities.
Qualification rehashes the complete file inventory and binds each native role
back to the original execution/build report. Missing, altered, truncated,
unexpected, linked or noncanonical members refuse admission. Re-sealing an
archive manifest alone does not replace the role bindings.

Failures remain failures. A failed second optimization profile preserves the
first profile and partial second-profile output. If retention itself fails,
the original execution error and retention error remain distinct. Incomplete
capture cannot qualify. Both the main actual-host workflow and the older
Windows entry point upload their artifact directories under `always()`.

The archive deliberately distinguishes **canonical Rust input and structured
backend receipt** from the Rust compiler's actual temporary `program.rs`,
argv and raw compiler streams, which this patch does not capture. It provides
neither a power-loss transaction nor authentication of an arbitrary third-party
report. Historical v2 reports keep their original meaning and do not inherit
the stricter v3 qualification.

Implementation review is in `abi-retention-implementation-review/`; independent
root review and original control streams are in `abi-retention-root-review/`.
The latter records the prepublication commit and exact tree relationship rather
than claiming a native compiler ran in the local control fixture.

Actual host review is now complete in `abi-cpp-review-f2b76f5/`: **300 retained
ABI files / 16,962,071 bytes**, including **28 native role originals** and
**164 raw C stdout/stderr streams**, were rehashed and cross-bound to original
reports. Windows raw CRLF bytes remain unchanged. All seven original ABI ZIPs
are retained here, totaling **24,249,719 bytes**. Each actual ABI host ran the
17 adapter controls, 16 capture controls and four original type/process controls,
with no individual test skips. The five POSIX hosts additionally ran their
20 ownership/capture controls. This closes the observed original-byte retention
gap for the seven declared profiles.

## Completed source checkpoint: 23af1df

Source **`23af1df3eed65230137aa54ab8b10eac3520abd3`**, tree
`1a6c0c6801e8c4be5117018b8052d289f6546e99`, completed all eight workflows.
Its prospective merge `e32358d1886922f946f2ed5b7b81c93e1077448e` had the same
tree. The complete review index and workflow identities are under
`full-ci-review-23af1df/`.

| Lane | Independently reviewed result | Qualification boundary |
| --- | --- | --- |
| Fixed composition | 347 unique planned/started/finished test identities; 22 qualifications; 23 command receipts; 46 original command streams; 4,850 source-file identities. | Zero test failures/errors/skips. Performance measurements below retain their negative gates. |
| Historical closure | All 611 original files / 26,120,286 bytes; 175 actual controls. | The optional original-NDU closure job was skipped and is not qualified by this lane. |
| Safety boundary | 562 distinct actual test identities; before/after source maps identical. | Explicit whole-language, source/Core/native, global-optimum and absolute-resource claims remain false. |
| Source/application | 410 regressions; 449/449 scalar obligations and 1,826 manifest members rehashed. | The three application profiles are prepared_not_measured with zero samples. |
| Verified-native | 1,777 distinct ordered test identities equal the frozen planned/started/finished digests; no failures/errors/skips/expected failures. | Narrowing has 288 native correctness observations without timing. Returned-loan scope is 11 profiles plus two rejecting controls. |
| Actual native hosts | Seven ABI, seven C++, two captured-C and one standalone AArch64 jobs, all successful. | Detailed scope and the historical ABI original-byte gap are stated below. |

These suites overlap; their test counts are not added into a unique grand total.
The 449 scalar queries cover all typed inputs of their selected emitted bodies,
but do not prove arbitrary loops, heap/resource instructions, foreign code or
machine-code refinement. Three separate ten-Rust-comparison profiles produced
1/10, 9/10 and 8/10 passes; the middle profile's heldout flag is true, while all
three overall performance gates remain false. They do not replace the original
180-comparison gate.

Intermediate economics receipts retain unchanged untracked output/dependency
directories. Their HEAD and tracked source maps are stable; the reports do not
pretend every intermediate workspace is empty. Frozen regression and guarded
opportunity checkpoints are clean. Guarded opportunity qualifies a finite
correctness observation with status `no-economic-opportunity`, not economic
success.

Original composition and closure ZIPs are retained here. The larger source/
application and verified-native ZIPs were downloaded and their digests and
relevant members independently checked in memory; their review records retain
the GitHub artifact identities. This directory does not claim to contain every
original byte of those larger ZIPs.

## Actual native scope

The following scope was fully reviewed independently on both `23af1df` and
`f2b76f5`. The newer campaign additionally verifies the retained ABI originals.

| Route | Verified finite scope | Boundary |
| --- | --- | --- |
| ABI, seven combinations | Linux x86-64/AArch64 GCC and Clang; Windows x86-64 MSVC and Clang; macOS AArch64 Clang. Per host: two optimization profiles, each 181 foreign calls; actual wrong-type and wrong-echo refusals. | Hepta uses the Rust backend. Current v3 retains all 28 native-role originals; historical v2 binaries remain missing. No arbitrary foreign-memory safety claim. |
| Real C++ reuse, seven combinations | nlohmann/json 3.11.3 and 3.12.0. Per host/version: 98 comparison cases, 32 lifecycle cases, 1,024 concurrent calls. Per host: 16 controls with no test skips and 12 evidence/checkout rejections. | Checked bridge and Rust-backend consumer, not translation of the whole C++ library. |
| Captured C → HIA → LLVM | Linux x86-64/AArch64. Per target: 48 functional cases / 144 native calls, 16 resource cases / 32 calls, 12 controls. Twelve translated bodies include eleven upstream bodies. | No Rust codegen or original C link input in the HIA target. Scalar ABI and explicit contracts only. |
| Standalone HIA AArch64 | Direct ELF: 17 scalar returns, one NULL refusal, one bounds exit 134, two wrong-Core controls, four allocations/frees and zero outstanding. Bound: 4,096 bytes and one live allocation. | Exit 134 alone does not attest SIGABRT. No physical MMIO/IRQ/DMA qualification. |

Both C++ checkout inventories contain 8,659 paths, with canonical path-list
SHA-256 `62e8d12878e48bb864679944f90b36aa84d3d8a71da0fe26be4ad4e7c165044b`.
All source identities match before and after, with empty tracked status.
Windows changes eight authored C++ inputs from LF to CRLF; the other 189 equal
their Git bytes. The ordinary live-allocation delta is zero. Registry retention is
two allocations on Linux/macOS and three on Windows.

Each independent C++ review rehashed **514 retained members / 30,480,988 bytes**,
including 14 actual objects and 14 executables and their raw command streams.
It explicitly does not claim to have rehashed the missing v2 ABI matrix bytes.

`HOST_LOGS_23af1df.tar.xz` and `HOST_LOGS_f2b76.tar.xz` retain each campaign's
17 full job logs plus three run/job metadata records. Platform-conditional
workflow steps, including Windows's POSIX-only ownership step, remain separate
from unit-test skips.

## Repairs and preserved checkpoints

| Source | Completed observation | Failure or qualification consequence retained |
| --- | --- | --- |
| `ab1c1a5` | 291 composition tests; 21 qualifications; 17 host jobs under their original checks. | Source-bound larger workflow reviews remain under `final-checkpoint-ab1/`. |
| `5c3741d` | 321 composition tests; 22 qualifications; all eight workflows eventually succeeded; 1,770 verified-native tests. | Later review found dirty checkouts in macOS and both Windows C++ reports. Workflow green did not close strict cleanliness. |
| `d562d6d` | 336 composition tests; seven ABI and five POSIX C++ profiles strict-clean. | Both Windows C++ jobs failed before native execution on a POSIX import. Frozen historical verifier failed on two relocated paths. Original failed ZIP retained. |
| `1629a03` | All eight workflows, 344 composition tests, 22 qualifications, 175 closure controls, 562 safety + 410 source/application tests, 449 scalar obligations and 1,777 verified-native tests. All 17 host profiles reviewed. | The first actual model freeze exposed a double-create defect, before any coding request. |
| `23af1df` | All eight workflows and artifact reviews complete; freeze repair and 347 composition tests. | Actual model cohort remains frozen here. Original Rust/NDU gates are still negative. |
| `f2b76f5` | ABI original-byte retention, 17 independent adapter controls, 347 composition tests, 22 qualifications, 175 closure controls, 562 safety + 410 source/application tests, 449 scalar obligations, and all 17 host jobs/artifact reviews successful. | Verified-native remains in progress. Rust is 153/180 and NDU 0/3 wins. |

The case-only archive repair renamed exactly two uppercase `BASE.json` files
to `BASE_PROGRAM.json`, preserving all four program/receipt bytes and updating
only active producers. The strict C++ qualifier now rejects unchanged dirty
checkout state, missing final identity, changed final tree and casefold
collisions. The frozen historical verifier and manifest remain unchanged.
A pinned relocation-aware verifier checks all 611 original bytes and exactly
two authorized path migrations.

The Windows import fix keeps actual resource measurement fail-closed when
POSIX `resource` is unavailable, while pure generator controls no longer import
it unnecessarily. No mocked generator timing is labeled actual CPU measurement.

`CHECKPOINT_ab1.md`, `CHECKPOINT_5c_EARLY.md` and
`CHECKPOINT_1629_HOSTS.md` preserve earlier narratives, including their then-
pending work. `MANIFEST_CHECKPOINT_6186.json` and
`MANIFEST_CHECKPOINT_c2a4.json` preserve earlier inventories. New reviews are
appended rather than rewriting the original failures.

## Actual Agent preparation and frozen cohort

The first real `1629a03` freeze failed because the inherited registrar had already
created `REGISTRATION.json` before the recovery wrapper attempted a second
create-only write. The partial registration, raw failure and eight owner-file
identities remain retained. **Zero coding requests** occurred in that attempt.
The earlier preparation-ready status does not override the later freeze failure.

The `23af1df` repair enriches the inherited registrar's single publication,
serializes the complete registration before candidate creation, writes/flushes/
fsyncs it, and uses an atomic create-only link for the final name. Existing finals
and failed candidates are preserved; the original writer is restored on every
exit. It is a complete-file publication guarantee, not a whole-directory or
power-loss transaction. Six recovery and twenty original protocol controls
passed, including the actual inherited freeze call path.

The two originally fixed full models were acquired and verified against their
registered bytes and SHA-256. Partial files were never loaded. Failed transfers,
correct-range short EOFs, timeouts and disconnected-header attempts remain in
the diagnostics. The six sequential acquisition stages took **3,386.024812259 s**
in total; overlapping worker times are not summed. This is acquisition wall time,
not a complete development or human cost.

The internal `23af1df` preparation stage took 49.510874578 s inside an outer
61.517165541 s controller invocation; these nested times must not be added.
The original pack records 199 source bindings, 24 preparatory unit tests,
six actual startup/native preflight probes, 26 protocol/recovery controls,
36 native reference records and nine hostile provider-contract controls.
`AGENT_PREPARATION_REVIEW_23af1df.json` binds these values to all fourteen
original member hashes, source identity and review time. The 24-count log is
not a record of 24 distinct startup/native probes. Both models passed their twelve tokenizer
cases without completion generation, with server exit and unchanged model/runtime
identities verified. The final registration SHA-256 is
`19bf8dfd8b6693695b738da2634e3d13bddeb9fa483fb082d74def57892ecb89`.
Root independently reviewed the original fourteen-member pack and issued the
generation review retained in `AGENT_REGISTRATION_REVIEW_23af1df.json`.
The reviewer made zero model task requests.

The unchanged original v4 protocol has SHA-256
`d8ad69246c495783ce5dcaf0db87e14532f8e91931c7b5d7b89a3bb7f12157ce`.
It fixes two small quantized models, four authored arithmetic maintenance tasks,
three representations, at most two submissions, 2,048 output tokens, 180 seconds
per request, 8,192 context, four CPU threads, greedy seed zero and no prompt cache.
Qwen precedes Granite; the original arm rotation is unchanged.

At this checkpoint the original Qwen controller reports **12/12 completed cells
and 24/24 requests**, all cells `public_validation_failed`, with controller-reported
complete usage pending publication of the original-request stage snapshot.
Granite is running. The full cohort is not yet a terminal reviewed result.
No failed cell is rerun, repaired by a human or replaced. Valid orchestration is
not coding success. The final public readout will distinguish each arm/task's
format, compilation, public semantic and hidden result, together with known
costs and original receipt identities.

This authored small-model pilot cannot establish unseen real-project productivity,
frontier-model performance, a fair complete 2×2 study or total human/economic
advantage. Old cloud selector/quota failures remain provider-availability
observations with unknown usage where the provider omitted it.

## Safety proof scope

The borrow increment adds **32 generic Lean theorems** for compatible borrowing,
ancestor preservation, suspended-parent access and guarded finite traces.
The completed `23af1df` lane checked 74 selected instructions, 40 actual production
borrow/access calls, 1,100 kernel dependency entries, 16 rejecting Lean controls
and four actual `E_HIA_LOAN` refusals. Four programs have 86 static instructions;
twelve lie outside this model. Imported and instance dependencies are not 1,100
new generic theorems and overlap earlier proof lanes.

The abstract finite Trace is not restricted to a particular fixed length. The
remaining correspondence gap is continuity and coverage: per-instruction
witnesses independently establish pre-states, but do not yet export a complete
function-wide CFG walk with adjacent state equality, edge renaming, joins and
backedges. Production guards exist; a complete refinement proof connecting
them to the formal model has not been established.

The `Unreferenced` erasure premise is stronger than a local children/root scan
over an arbitrary malformed graph. A reviewed nested-owner countermodel shows
why reachable owners must be proved self-rooted and parentless, with typed
root inheritance. It is not an accepted production program or a demonstrated
checker vulnerability. The read-only review under
`freeze-p0-p1-review-23af1df/` states the exact invariant and next proof obligation.

Heap, source execution, call/return/move/chain, foreign effects, concurrency and
machine-code refinement remain separate obligations. Four identity-bound native
reduction chains and separate scalar proofs do not form an end-to-end theorem.

## Performance and NDU results remain negative where measured

| Preserved measurement | Actual outcome | Remaining qualification |
| --- | --- | --- |
| Original production Rust gate, `5c3741d` | 154/180. | Broad parity/heldout false. |
| Same original denominator, `d562d6d` | 155/180. | Different campaigns are not paired causal improvement estimates. |
| Same original denominator, `1629a03` | 158/180. | Broad parity/heldout false. |
| Same original denominator, `23af1df` | 159/180. | Overall, broad parity and heldout gates remain false. |
| Same original denominator, `f2b76f5` | 153/180. | Overall, broad parity and heldout gates remain false; earlier higher counts are not substituted. |
| Experimental thin wrapper | 232/276; 10/12 complete empty gates; four nonempty median regressions exceed 10%. | Production admission remains disabled. |
| Bounded Python snapshot study | 256 models, eleven paired rounds, 66 samples; validation/exact-control/request medians improve 90.96% / 81.45% / 61.98%. | Zero native calls; this is preparation improvement, not NDU net value. |
| Original native NDU, `5c3741d` | 9/9 calls agree; 0/3 scenario wins; allocated campaign 23.362909522 s native versus 4.960922416 s fixed. | Full lifecycle unknown. |
| Original native NDU, `d562d6d` | 9/9 calls agree; 0/3 wins; 28.365763942 s versus 5.378874631 s. | No positive net advantage. |
| Original native NDU, `1629a03` | 9/9 calls agree; 0/3 wins; 35.002589917 s versus 7.187138209 s. | No positive net advantage. |
| Original native NDU, `23af1df` | 9/9 calls agree; all 36 step choices equal exact control; 0/3 wins; 22.972836375 s versus 5.056386486 s. | Full lifecycle and positive net value remain false/unknown. |
| Original native NDU, `f2b76f5` | 9/9 calls agree; 0/3 wins; 29.386305237 s native versus 6.095080650 s fixed. | Exact DP is 6.096757653 s and lightweight 6.102858588 s; no positive native NDU full-lifecycle value is established. |

The existing controller computes exact Python continuation DP before constructing
the native candidate bank. NDU agreement therefore supplies no solution-quality
gain in that design. Removing one explicit `planner.exact` call would not remove
the DP still performed by `frontier`. Campaign costs allocate observed shared
work, including bridge build; they are not four independent solo campaigns.

The separate 18-native-call costed-model observation agrees with exact-model
values but keeps application speedup and net NDU benefit false. A zero-invocation
gated policy is not evidence that invoking NDU improves economics.

`NDU_NEXT_EXPERIMENT_REVIEW_1629a03.json` and the independent addendum under
`full-ci-review-23af1df/` describe a possible separately registered raw-model
Rust adapter experiment. No such experiment or timing is represented as executed.
It must include a Rust exact-DP-without-NDU control, original rounding/tie/abstain
semantics, cold startup and terminal costs, actual admission after search, and
peak residency. Moving Python work to Rust alone cannot establish NDU-specific
advantage.

## Broad production ledger remains OPEN

The original requirements are retained in `ISSUE_471_SNAPSHOT.json` and the newer
read-only issue snapshot. No checklist item is closed merely by changing its text.

| Gate | Remaining requirement beyond the scoped repairs |
| --- | --- |
| P0 | Complete producer/consumer consistency, continuous integrated refinement and production integration. |
| P1 | Full safety/resource/heap/provenance/outcome/foreign-call correspondence and native stack/RSS/allocation budgets. |
| P2 | All applicable real-host native artifact evidence plus physical MMIO/IRQ/DMA profiles. |
| P3 | Complete multi-file C/C++ migration, upstream upgrades, unsupported inventory and independently measured human maintenance cost. |
| P4 | Original-denominator robust Rust/C/C++ performance, strong heldout workloads, tails, CPU/RSS and energy. |
| P5 | Reproducible positive original native NDU full-lifecycle value with fair candidate information/budgets and independent costs. |
| P6 | Frozen unseen real-project tasks, matched model/tool budgets, human review burden and significant correctness/total-cost advantage. |
| P7 | Durable long-lived recovery, crash/power-loss/restart/rollback, external-effect guarantees, actual deployment and separate release authority. |

A finite implementation or evidence defect can be repaired and independently
verified. That result does not close the entire production ledger or authorize
production activation.
