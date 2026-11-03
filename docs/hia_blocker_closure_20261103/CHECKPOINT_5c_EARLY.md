# HIA blocker closure evidence — integrated research checkpoints

## Newly found portability blocker after the 5c3741d run

Three C++ host artifacts (macOS, Windows Clang and Windows MSVC) record nonempty
tracked worktree state. The Git tree contains two `BASE.json` / `base.json`
case-collision pairs in historical NDU artifact directories. On case-insensitive
filesystems they cannot coexist. Limited native observations are retained, but
these three reports **do not pass a strict clean-worktree qualification**.
The original qualifier checked that the dirty state stayed the same; it did not
require the state to be empty. A lossless path/generator repair and strict
before/after-clean rejection are in progress and will require a new source run.

## 5c3741d source checkpoint

The current source is **`5c3741da1d36e8c1f79ec728ec325b8d973c899e`**, tree
`3492a8efb0ea2818b3260585c6b937935cd505a4`. Prospective merge
`47b71ce239af3dfdc928f4318440a2755e870b8a` into research base `18291446` has the
same tree. This is not production-main qualification or release authorization.

## Final-source results

- **321/321** planned core tests started and finished; zero failures/errors/skips.
- **22/22** composition qualifications passed, with 23 command receipts including
  bridge build. All 46 command stdout/stderr hashes were independently rechecked.
- **17/17** actual-host ABI, captured-C and C++ jobs completed successfully.
- Working-draft status: final source/application and verified-native regression
  jobs are still running; their eventual results must be recorded separately.
- The real startup ACK/EOF fix passed on this same source. All 24 preflight/provider
  regressions and the 23/36/9 recovery-control groups passed; that validation made
  zero coding/availability requests and no downloads.

The original `composition-5c3741d.zip` is 3,256,578 bytes with SHA-256
`026966ec3a8bf448632e20cb25f2a906ef76d0829980273fe9a25ef6b060b634`.
The readout binds the original 4,848-file manifest. `COMPOSITION_REVIEW_5c3741d.json`
and `REFINEMENT_INDEX_5c3741d.json` independently check actual artifact identities.
All older ZIPs remain unchanged. `CHECKPOINT_ab1.md` preserves the original ab1
narrative, and `final-checkpoint-ab1/` records its later complete regression review.

## Borrow-permission increment

The new model adds **32 generic Lean theorems** for compatible mutable borrowing,
ancestor preservation, suspended parent access and guarded finite traces. The
final integrated lane checks **74 selected instructions**, **40 actual production
borrow/access guard calls**, **1,100 theorem dependency entries**, **16 rejecting
Lean controls** and **four actual `E_HIA_LOAN` refusals**. Four source programs have
86 static instructions; 12 remain explicitly outside this model. All 1,100 actual
kernel-output dependency entries match the report and use only the declared Lean
axioms, with no `sorryAx`. Imported foundations overlap with earlier proof lanes;
these counts must not be added as independent generic theorems.

Regression controls include ending only one of two shared children and retaining
a grandchild while omitting its intermediate parent at CFG transfer. The model
does not assume its desired postconditions. It requires stated initial invariants;
its `Unreferenced` erasure premise is stronger than children-only checking on
arbitrary malformed graphs. The observed pre-states satisfy that premise, but
universal reachability and complete checker refinement remain unproved.

This is a proved capability model with finite production witnesses, not a complete
heap, call/return/move/chain, source-language, FFI, concurrent or native-machine-code
proof. Individual instruction witnesses are not an exported whole execution trace.
Four actual reduction Core/LLVM/native chains have been identity-checked; separate
scalar Core proofs are not joined to those chains as an end-to-end theorem.

## Final-source native and performance observations

`HOST_ARTIFACTS_5c3741d.json` binds all 17 original artifacts;
`HOST_LOGS_5c3741d.tar.xz` preserves complete logs and step metadata. The three
direct HIA ZIPs are in `hosts/`. `DIRECT_NATIVE_REVIEW_5c3741d.json` independently
rehashes **394** captured-C manifest members and checks every functional/resource
comparison. The direct HIA and Rust-backend scope distinctions in the historical
table below apply equally to this final run. Platform-conditional workflow skips
remain explicit; they are not skips in the 321-test composition suite.

| Final registered observation | Actual result | Remaining gate |
| --- | --- | --- |
| Rust production-path comparison | **154/180**; 10 failures at n=0, six at n=1 and ten others including nonempty/holdout median or tail failures. | All-Rust, independent holdout and broad parity remain false. |
| Original native NDU | **9/9** workload calls completed and matched exact control; **0/3** scenarios won. | Positive net benefit remains false. |
| Online native NDU episodes | 375,714,745 ns versus exact DP 344,203,010 ns. | Native costs 9.155% more in this run. |

Conservative campaign allocations are 4.960922416 s fixed, 4.961875938 s exact DP,
4.961578821 s lightweight and **23.362909522 s native NDU**, including
18.369521849 s of outer bridge build. These allocate observed shared costs;
they are not four independent solo campaigns. Full lifetime/human/energy costs
remain unknown. The controller computes exact DP before constructing the native
candidate bank; native agreement supplies no extra solution quality here.
Different source/host runs are not paired causal estimates of improvement.

Cloud availability/quota failures and incomplete local model acquisitions remain
separate historical facts. Subsequent asset acquisition or model observations must
retain their own receipts without revising old failures, task protocol or budgets.
Even a completed 24-cell authored arithmetic cohort cannot establish unseen
real-project maintenance productivity or full human/economic advantage.

## Broad production ledger

All eight broad gates in issue #471 remain open: complete consumer consistency
and production integration (P0); full safety/resource refinement (P1); broader
standalone targets and actual device profiles (P2); full-project C/C++ migration
and human cost (P3); robust Rust/heldout optimization performance (P4); positive
full-lifecycle NDU value (P5); real-project Agent productivity (P6); and long-lived
deployment, physical power-loss/external-effect recovery and independent release
authority (P7).

`all_blockers_closed=false`, `authority=DENY_ALL`, `safety_certificate=false`,
`production_activation_allowed=false` remain unchanged.

---

# Historical ab1 checkpoint — retained for comparison

This is a research evidence checkpoint for PR #564. Each observation retains
its actual source commit. These files grant no production authority.

## Verified checkpoint

Source `ab1c1a50b77a0d9f2da14a86b418f60985fbfe28`, tree
`4134b41a604e8ccb86bde62f5d492135590afe99`, passed all 21 composition
qualification entries: 291 regression tests, zero errors/failures/skips;
404 Lean theorem dependency checks and 11 designated rejecting controls.
There are 22 command receipts including the native NDU build. Source/tool
identities were stable. The 404 includes older and concrete-instance theorems;
22 new generic lifecycle theorems were added.

GitHub's prospective merge tree for PR #564 into the stacked research base
matches this source tree. This is not a main-branch release qualification.
The two larger workflows were still running when the initial host review was
recorded; their later completion must be recorded separately.

The original `composition-ab1.zip` and earlier `composition-68c04.zip` were
verified against GitHub artifact digests. Readout JSON files retain their run,
artifact, source and tree identities. Earlier negative results remain intact.

## Implemented repairs

The source now includes logical-line transport bounds, typed frozen performance
registrations, package directory-alias rejection, strict startup ACK handling,
provider quota/cleanup stops that survive malformed output, bounded detached
NDU snapshots, and selected capability lifecycle proofs. The expanded composition
gate executes the new controls and proofs with the original native experiments.

## Actual native scope

All 17 reviewed host jobs passed on ab1. `HOST_ARTIFACTS_ab1.json` records all
artifact metadata; `hosts/` preserves seven inspected ZIPs. Each local ZIP was
independently checked against the original GitHub digest. Full decoded job logs
are retained in `HOST_LOGS_ab1.tar.xz`; conditional skips remain explicit.

| Route | Observed scope |
| --- | --- |
| Captured C to HIA to LLVM | Linux x86-64/AArch64; each has 48 functional cases/144 native calls, 16 resource cases/32 calls, 12 control tests, 12 translated bodies including 11 upstream bodies. No Rust codegen. |
| Standalone HIA AArch64 | Direct ELF execution: 17 scalar returns, one NULL refusal, one bounds exit 134, two wrong-Core controls, four allocations/frees and zero outstanding. Runtime bound: 4096 bytes and one live allocation. |
| Broad ABI, seven combinations | Linux x86-64/AArch64 GCC and Clang; Windows x86-64 MSVC and Clang; macOS AArch64 Clang. Hepta uses its Rust 1.90.0 backend. |
| C++ reuse, seven combinations | Unchanged nlohmann JSON 3.11.3/3.12.0, C++ bridge and Rust-backend Hepta consumer. This is not translation of the entire library. |

The results do not qualify every target ABI, general foreign ownership,
physical MMIO/IRQ/DMA, arbitrary C++ migration or whole-language safety.

## Performance remains a blocker

The production-path reduction gate passed 143/180 comparisons on 68c04 and
152/180 on ab1. Neither establishes broad Rust parity. The separate thin-wrapper
study, retained under `experiments/hia_empty_wrapper_20261103` on the source
branch, passed 232/276 comparisons and 10/12 complete empty-input gates; it also
has four nonempty median regressions above 10%. It remains experimental.

The paired 256-model snapshot study retained all 66 timing samples: median
Python validation, exact-control and request-building times fell 90.96%,
81.45% and 61.98%. That isolated experiment made zero native NDU calls.

The ab1 integrated NDU experiment completed all nine workload calls and matched
the exact model, but won 0/3 scenarios. Its conservative campaign costs were
8.125962415 s fixed, 8.131817693 s exact DP, 8.134412014 s lightweight and
35.792549967 s native NDU. Native includes 27.616697285 s of outer bridge build.
These are declared allocations of observed costs, not four independent solo
campaigns. Full acquisition/human/maintenance costs remain unknown. The current
controller computes exact DP before constructing the native candidate bank;
agreement does not demonstrate additional solution quality. Cross-host and
toolchain timing differences are not paired estimates of snapshot causality.

## Open proof and production obligations

`REFINEMENT_INDEX_ab1.json` verifies the scalar manifest and binds four actual
LLVM/native reduction chains. It keeps different Core artifacts separate.
The selected scalar proof does not prove a native-machine-code endpoint.
The CI archive retains native identities and execution records, but not the
reduction object/library bytes; the separate wrapper archive retains its binaries.

Issue #471 remains open. Outstanding requirements include complete declared
schema/opcode consumer coverage; borrow permissions, calls/returns and
capability-to-heap correspondence; outcome/FFI/resource-budget composition;
broader native targets and physical devices; migration and maintenance cost;
positive Rust/NDU performance; completed real-model productivity studies; and
long-lived deployment, power-loss and external-effect recovery evidence.

Further borrow-permission work is evaluated separately when its actual proofs,
rejecting controls and integrated-source results are available. The status stays
`authority=DENY_ALL`, `safety_certificate=false`,
`production_activation_allowed=false`, `all_blockers_closed=false`.
