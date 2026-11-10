# Seven-track implementation convergence

This source combines the executable and verifier repairs from #551
(`4eacb263b6e73bfee813317089cd0490fd82518f`) with the seven-track implementation
based on `c393b8fe7360e45343f090665d519108656280bf`. The common ancestor is
`1b5e946c9889b1c19ae86235cb14dfb76da10777`. The archived delivery was
`2fedab7db59f56189f2b95eab4fa987a2abb5d2a`, tree
`bf7c271e9fdf03cb72ffe08c209dfa1ff16a213c`.

The implementation merge adds the missing baseline dependencies as well as the
later patch. Applying only that patch would omit the durable queue, its tests,
the existing induction proposer and costed-model qualification. The merge
retains #550's external Rust LTO build directory and #551's source layout,
incremental ownership policy and lowering work/deadline repairs.

## Integrated implementation

| Area | Existing components now in one source |
| --- | --- |
| P0/P1 proof composition | Fresh per-export totality and actual LLVM-body validation; extracted capability rules bound into proof identities |
| P3/P7 foreign lifecycle | Creator-process checks before inherited locks, child-only reference retirement and preserved parent checkpoint |
| P4 native reduction | Inductive guarded checked-add elimination followed by independently checked modular narrowing, original fallback retained |
| P4 strong baseline | Existing Rust O3/fat-LTO baseline plus a separately registered training-only Rust PGO control |
| P5 costs | Reversible residency, eviction/reprepare, future-decision costs and the original native evaluator with independent DP controls |
| P6 readiness | Zero-generation client initialization plus actual HIA/LLVM/Rust native probes, separate from a registered model trial |
| P7 durable pure queue | Revision-conditional admission, historical-prefix lost-ACK recovery, preserved credit and existing crash/replay checks |

Additional repairs reject undersized native timing batches, bind native cost
observations to the actual library/driver/tool bytes, and prevent a dirty
checkout or same-tree HEAD change from qualifying a full regression receipt.
PGO uses the same Rust kernel and only the registered training lengths/seeds.
Its instrumentation, training, merge and profile-use rebuild costs are retained;
holdout timing inputs are excluded from profile preparation. Missing-profile
warnings refuse even when rustc exits zero. The prior v1 protocol is unchanged.

## Evidence contracts

Historical results retain their original source identity. Historical raw logs,
environment locks and detailed result archives are kept separately from this
source publication. No old result qualifies this implementation. The new full
regression plan explicitly includes new tests from both source parents and all
current repair modules, freezes exact test identities, rejects skips and
requires a clean unchanged source commit/tree with evidence outside the checkout.

The native benchmark profiles remain separate experiments with fixed samples,
all original tails and unchanged ratio limits. A completed observation may fail
its performance gate. Native/DP equality is a finite model check, not NDU net
benefit. Successful startup is not model access, a generated completion or a
productivity result. An environment error remains a failed prerequisite and
does not become a skipped or passing test.

Both versions of the JSON library and the durable queue retain their scoped
failure/recovery contracts; external exactly-once effects and physical power
loss are not inferred. The selected Lean add function is mechanically the same
function as the existing register model fixture; its theorem does not cover
the other export's branch/division operations or imply a general cross-model
compiler theorem.

All full P0–P7 gates remain open until their independent acceptance conditions
are met. Physical target/platform coverage, general production type/resource
soundness, independent application performance, complete lifecycle NDU benefit,
unseen real Agent tasks with full costs and production recovery each require
their own evidence.

## Reproduce

Use the recorded tools in a clean committed source tree, with external Cargo
build targets and new absolute output directories:

> Removed source/mixed-campaign reproduction command; its harness is not
> delivered. No historical result is promoted to current qualification.

Final observations must state the actual source commit, tools and each result;
none of the implementation descriptions above substitutes for execution.
