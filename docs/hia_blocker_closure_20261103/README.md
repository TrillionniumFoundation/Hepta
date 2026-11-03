# HIA blocker closure evidence — integrated research checkpoints

## Current source and verification status

The current candidate for draft PR #564 is
**`1629a03dc76c5360550da40a6fc6fcbd80425128`**, tree
`06edb86c49637015630ce6097dcfd30921760f74`. GitHub prospective merge
`b26ed7eba940d8cd2c89ab276b0a336a0b07064e` into stacked research base
`18291446e048f760f5519823e865727ef51db11a` has the same tree.
This evidence branch preserves observations about explicitly identified source
commits; its own tree is not represented as the tested implementation.

**All 17 actual-host jobs completed successfully, and all 17 corresponding
finite host artifacts passed independent content review.** The seven ABI and
seven C++ artifacts satisfy strict clean-checkout checks. Both Windows C++
compilers executed the native corpus. Direct HIA→LLVM observations cover the
two Linux captured-C targets and the standalone AArch64 corpus.

At this checkpoint the historical-evidence closure workflow has completed
successfully. Complete composition, source/application and verified-native
workflows are still running. Their final receipts will be appended; previous
source results are not substituted. No new Agent coding generation has started
while the fixed local model assets remain incomplete.

`authority=DENY_ALL`, `safety_certificate=false`,
`production_activation_allowed=false`, `all_blockers_closed=false`.

## Concrete cross-platform repairs now verified

The `5c3741d` tree contained two historical `BASE.json` / `base.json` pairs.
Three C++ reports (macOS and both Windows compilers) recorded nonempty tracked
status. The old qualifier accepted an unchanged dirty status. Those native
observations are preserved but never relabeled as strict-clean qualification.

The `d562d6d` repair renamed only the two uppercase program paths to
`BASE_PROGRAM.json`, preserved all four program/receipt bytes, taught active
producers the new names, rejected casefold collisions, and required an empty
tracked status before and after host qualification. Seven ABI profiles and
five POSIX C++ profiles passed. Both Windows C++ jobs then failed before native
execution because a path-generation regression imported POSIX `resource`.
The historical closure gate independently failed because its frozen verifier
still used the two original paths.

The current `1629a03` source repairs those follow-on defects:

- Real resource measurement imports `resource` when measurement is requested.
  A platform lacking it still refuses before the measured operation starts.
  Pure generator controls run on Windows without pretending to measure CPU.
- `tools/verify_hia_retained_evidence.py` pins the original manifest and the
  exact two-path relocation contract and checks every original size/SHA-256.
  It rejects missing rows, tampered contracts, collisions, noncanonical paths,
  symlinks and nonregular files. All **611 original files / 26,120,286 bytes**
  remain required. The original frozen verifier and manifest are unchanged.
- Four additional C++ controls reject unchanged dirty status, missing final
  checkout identity, changed final tree and casefold collisions. All **12**
  old/new rejection controls pass on all seven C++ hosts.

The local combined regression run passed **23 tests with zero skips**.
`abi-cpp-review-1629a03/` supplies the independent native review. Earlier
failures remain in `abi-cpp-review-5c3741d/`, `abi-cpp-review-d562d6d/` and
`ci-review-d562d6d/`, including the original failed closure ZIP.

## Actual native scope on 1629a03

| Route | Verified scope | Boundary |
| --- | --- | --- |
| Broad ABI, seven combinations | Linux x86-64/AArch64 GCC and Clang; Windows x86-64 MSVC and Clang; macOS AArch64 Clang. Per host: two optimization profiles, each 181 foreign calls; real wrong-type and wrong-echo refusals. | Hepta uses the Rust backend. Selected contracts do not prove arbitrary foreign memory safety. |
| Real C++ library reuse, seven combinations | nlohmann/json 3.11.3 and 3.12.0. Per host/version: 98 comparison cases, 32 lifecycle cases, 1,024 concurrent calls. Per host: 16 unit controls, no test skips; 12 evidence/checkout rejections. | Checked bridge and Rust-backend consumer, not translation of the whole C++ library. |
| Captured C → HIA → LLVM | Linux x86-64/AArch64. Per target: 48 functional cases / 144 native calls, 16 resource cases / 32 calls, 12 controls; 12 translated bodies including 11 upstream bodies. | No Rust codegen or original C link inputs in the HIA target. Scalar ABI and explicit contracts only. |
| Standalone HIA AArch64 | Direct ELF: 17 scalar returns, one NULL refusal, one bounds exit 134, two wrong-Core controls, four allocations/frees and zero outstanding. Runtime bound: 4,096 bytes and one live allocation. | Exit 134 is not an attestation of SIGABRT. No physical MMIO/IRQ/DMA qualification. |

The C++ checkout inventory has **8,659** paths, with canonical path-list SHA-256
`62e8d12878e48bb864679944f90b36aa84d3d8a71da0fe26be4ad4e7c165044b`.
All before/after source identities are equal and tracked status is empty.
Windows materialization changes eight authored C++ inputs only from LF to CRLF;
the other 189 inputs equal their Git blob bytes. C++ ordinary allocations return
to zero. Registry retention is two allocations on Linux/macOS and three on
Windows; both materialization and retention differences remain explicit.

`DIRECT_NATIVE_REVIEW_1629a03.json` rechecks every functional/resource comparison
and **394** captured-C manifest members. The three original direct-native ZIPs
are in `hosts/`. `HOST_LOGS_1629a03.tar.xz` retains all 17 full job logs and their
three run/job metadata records. The ABI/C++ review records original ZIP digests
and 131 key member hashes. Platform-conditional workflow steps are separate
from unit-test skips.

## Preserved source checkpoints

| Source | Composition / regression evidence | Native/qualification finding |
| --- | --- | --- |
| `ab1c1a5` | 291 composition tests; 21 qualifications. Final larger workflow reviews under `final-checkpoint-ab1/`. | 17 host jobs passed their original checks. |
| `5c3741d` | 321 composition tests; 22 qualifications. All eight workflows eventually succeeded. Verified-native completed 1,770 distinct planned tests, zero failures/errors/skips; source/application groups passed 562 + 403 tests. | Later artifact review found three dirty C++ checkouts; workflow green did not close strict cleanliness. |
| `d562d6d` | 336 composition tests; 22 qualifications. Original failed closure and full composition ZIPs retained. | All seven ABI and five C++ profiles strict-clean; both Windows C++ jobs failed before native execution. Historical verifier failed on exactly two relocated paths. |
| `1629a03` | Final larger workflows pending in this checkpoint. | 17/17 host jobs and artifact reviews pass; historical closure workflow succeeds. |

`CHECKPOINT_ab1.md` and `CHECKPOINT_5c_EARLY.md` preserve earlier narratives,
including then-pending workflows. Later completed reviews are separate,
source-bound records. Original ZIP bytes and negative results are unchanged.

## Safety proof scope

The integrated borrow increment adds **32 generic Lean theorems** for compatible
mutable borrowing, ancestor preservation, suspended parent access and guarded
finite traces. On `5c3741d` the lane checked 74 selected instructions, 40 production
borrow/access calls, 1,100 dependency entries, 16 rejecting Lean controls and four
actual `E_HIA_LOAN` refusals. Four programs contain 86 static instructions; 12 are
outside the model. Imported/instance entries are not 1,100 new generic theorems
and overlap earlier proof lanes. The current composition run must establish its
own exact-source result.

The generic model requires stated initial invariants. Its `Unreferenced`
erasure premise is stronger than children-only checking on arbitrary malformed
graphs. Finite observed pre-states satisfy it; universal reachability and complete
checker refinement remain open. Individual witnesses are not an exported whole
execution trace. This is not complete heap, call/return/move/chain, FFI,
concurrent or machine-code refinement. Separate scalar proofs and four
identity-bound native reduction chains do not form an end-to-end theorem.

## Performance and Agent results remain falsifiable

| Preserved measurement | Actual outcome | Still open |
| --- | --- | --- |
| Production Rust gate, `5c3741d` | 154/180; failures include empty, singleton, nonempty and heldout median/tail cases. | Broad Rust parity and heldout gate remain false. |
| Production Rust gate, `d562d6d` | 155/180. | Different campaigns are not a paired causal improvement estimate. |
| Experimental thin wrapper | 232/276; 10/12 complete empty gates; four nonempty median regressions exceed 10%. | Disabled for production admission. |
| Bounded Python snapshot study | 256 models, 11 paired rounds, 66 samples. Validation / exact-control / request medians improved 90.96% / 81.45% / 61.98%. | Zero native calls; preparation improvement is not NDU net value. |
| Native NDU, `5c3741d` | 9/9 calls agree, 0/3 scenarios win. Allocated campaign cost 23.362909522 s native versus 4.960922416 s fixed. | Full lifetime costs unknown; no positive net benefit. |
| Native NDU, `d562d6d` | 9/9 calls agree, 0/3 scenarios win; native 28.365763942 s versus fixed 5.378874631 s. | Different campaigns, not paired estimates. |

The controller computes exact DP before constructing the native candidate bank;
NDU agreement adds no solution-quality gain in that design. Campaign figures
allocate observed shared costs, including bridge build; they are not four
independent solo campaigns. Human, maintenance, energy and lifecycle costs
remain unknown.

Cloud selector/quota failures remain provider-availability outcomes with unknown
usage where omitted by the provider. They are not coding failures or successes.
Local model acquisition is independently bounded and retains failed transfers
and their costs. Only complete original hashes admit weights; partial models
are never loaded. Even a completed 24-cell authored arithmetic cohort cannot
establish unseen real-project productivity or full human/economic advantage.

## Broad production ledger remains OPEN

Current requirements are preserved in `ISSUE_471_SNAPSHOT.json`.

| Gate | Remaining requirement beyond these scoped repairs |
| --- | --- |
| P0 | Complete producer/consumer consistency, independent integrated qualification and production integration. |
| P1 | Full safety/resource/heap/provenance/outcome/foreign-call refinement and native stack/RSS/allocation budgets. |
| P2 | Applicable standalone targets and real physical MMIO/IRQ/DMA qualification. |
| P3 | Complete multi-file C/C++ migration, upgrades, unsupported inventory and measured human maintenance cost. |
| P4 | Original-denominator robust Rust/C/C++ performance, strong heldout workloads, tails, CPU/RSS and energy. |
| P5 | Positive original native NDU full-lifecycle value with fair candidates/budgets and independent costs. |
| P6 | Frozen unseen real-project tasks, matched budgets, human review burden and significant correctness/total-cost advantage. |
| P7 | Long-lived recovery, power-loss/restart/rollback, external-effect guarantees, physical tests and separate release authority. |

A finite host profile closes its concrete implementation defect. It does not
close the whole production ledger or grant production activation.
