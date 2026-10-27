# Native NDU and a finite compiler continuation loop

This experiment executes the original `codex_hepta_ndu` recursive utility and
candidate evaluation APIs through a separately built Rust executable. It is a
bounded integration experiment. It does not prove global optimality, compiler
soundness, machine-code refinement, or a general performance advantage.

## Final recorded qualification: 2026-10-27

The corrected run is in [`run_20261027_corrected/RESULT.json`](run_20261027_corrected/RESULT.json).
All 30 jobs completed, passed their 30-second admission budget, and returned the
independently checked output. All 60 initial/final workload executions loaded a
sealed memfd whose bytes matched the independently bound native receipt.

| Controller | Actual continuation, 6 jobs | Median job wall | Median with amortized setup |
| --- | --- | ---: | ---: |
| Fixed stop | 6 stop | 367.748 ms | 526.232 ms |
| Fixed fold | 6 fold, prove, build and execute | 702.515 ms | 860.998 ms |
| Calibration-selected fixed | 6 stop | 373.021 ms | 531.504 ms |
| Lightweight arithmetic | 6 stop | 377.844 ms | 536.328 ms |
| Original native NDU | 6 stop | 432.808 ms | 4,754.471 ms |

**NDU did not outperform the strong fixed or lightweight control in this run.**
LLVM already emitted identical native bytes for the original and folded
calibration programs. The model consequently set their execution-rate ratio to
one instead of treating timing noise as a gain. NDU spent a median 78.079 ms on
current-candidate proposal/check/refusal and 3.112 ms on its selection stage.
Stopping further optimization was its selected continuation, and the fixed-fold
control separately exercised the actual later rewrite/build/execution path.

The complete shared setup cost was 950.901 ms. NDU's additional empty-target
bridge build cost was 24.976497457 seconds of wall time and 58.994446 seconds of
child CPU time. The amortized column charges the shared cost once to each
standalone strategy, and the bridge build only to NDU, over six jobs. This
amortization is specific to the registered six-job experiment. It does not
predict a long-lived service's per-request cost. The measured study itself took
14.726713958 seconds, excluding that earlier bridge build.

The original native evaluator is pinned to companion-repository commit
[`2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b`](https://github.com/TrillionniumFoundation/hepta-private-ci/commit/2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b).
Its executable SHA-256 is
`d4f45f88d408d69b269d60fc2073abd669cfda721ddcc89736b2511888944a33`.
The corrected checker identity is
`78694a5f57a303f576dd9b5430498affc9d65e7fa93d639721a940cf66554f12`;
the registered protocol digest is
`d7bf6d487884ca3aac3cdb0381504ed91fe0c33eb0e3577181e687844e455bf5`.

All 16 bridge and compiler-loop tests passed with this exact native identity.
They include a two-second sunk-cost regression that must preserve an affordable
continuation, plus a real child execution after replacing the original artifact
path: the child still loads the sealed verified bytes, and a fresh attempt to
load the replacement is rejected before launch. The incorrect-constant candidate
was rejected with no binary; verification deadline, native process timeout and
source drift probes also failed closed. No statistical-superiority or
global-optimality gate is asserted.

## Archived raw evidence

Complete raw trees are stored in two archives, with their original run-directory
prefixes and every original file byte preserved. Every member was read back from
the completed archive, hashed and compared with the original evidence index
before redundant plain files were removed. Readable result/protocol/source and
build manifests remain alongside the archives.

| Archive | Members | Archive SHA-256 |
| --- | ---: | --- |
| [`run_20261027_corrected.tar.xz`](run_20261027_corrected.tar.xz) | 260 | `de21dc6aed851b8feca46341eb4c10866da76f6d1cb8de7ecfb99990b392c2ef` |
| [`run_20261027.tar.xz`](run_20261027.tar.xz), superseded | 259 | `9e6d87233bea8d1581ff78d5f0cac38d59b9eb59aabd5283e51f3990318b77bc` |

[`EVIDENCE_INDEX_20261027.json`](EVIDENCE_INDEX_20261027.json) preserves both
original full-tree identities. The corrected tree digest is
`c4300cdc6c6c49cb4ef012f9f22f54175c50c2be818d3800031d69309aea1ab1`;
the superseded digest is
`1692b662447eab4887ad249b73b2abd04e0c3e0c3e30502fd199f8c78d983223`.
Each `.members.json` lists the SHA-256 and size of every archived member,
including source snapshots, proof receipts, compiler bindings, raw stdout,
stage ledgers, driver/native binaries and all gate-failure logs.

From this evidence directory, restore into an empty directory with:

```sh
mkdir restored
tar -xJf run_20261027_corrected.tar.xz -C restored
```

The original relative paths then exist below `restored/run_20261027_corrected/`.
Recorded absolute execution paths remain historical evidence of the actual
run; a fresh execution should rebuild using the pinned source and a new output
directory. The retained archive is sufficient to recheck every file's identity.

## Preserved superseded attempt

The first full run remains in [`run_20261027/RESULT.json`](run_20261027/RESULT.json),
with [`SUPERSEDED.json`](run_20261027/SUPERSEDED.json) marking why it is not the
final qualification. Independent review found that working paths included sunk
costs while literal abstention did not, which could cancel an affordable
continuation. It also loaded a mutable artifact pathname after checking its hash.
Those mechanisms were corrected as described above. The optimizer additionally
isolated its Z3 contexts across concurrent callers. All original samples and
source files are retained. The corrected run preserves the workload, controls,
candidate family, budgets and no-exclusion policy. It is a correctness rerun,
not selective removal of an unfavorable performance result; both runs found no
NDU advantage over the strong controls.

The companion repository's required gate attempts are retained in both runs.
`just fmt` succeeded before publication. `just bazel-lock-update` could not run
because Bazel is absent; this standalone bridge is outside the registered Bazel
Cargo inputs. The final `just test --release` compiled its test executable, then
returned exit 4 because this transport CLI contains zero Rust unit tests. It was
not relabeled as a passing test gate. Its behavior is covered by the 16 external
native protocol/loop tests. An earlier debug-gate attempt exhausted the shared
filesystem; that failure record is retained, and only its reproducible target
cache was removed.

## What physically happens

The registered candidate set contains the original Core program, a constant-fold
proposal, and a changed constant that is deliberately not equivalent. The
calibration stage independently checks every candidate. Both valid programs are
compiled into real shared objects and executed by a C driver. The invalid
candidate is rejected by the optimizer's actual SMT check and never built.

Every paired deployment job uses the same source, parameters and budget for five
controllers: always stop, always fold, the fixed choice selected by calibration,
a small arithmetic controller, and native NDU. Deployment source constants differ
from calibration constants, so the study does not discard an already usable
calibration binary to manufacture an optimization cost. Each job starts with an
empty build cache and performs two real workload deliveries.

The first delivery is already observed when the controller chooses whether to
build and execute the fold or stop optimization and execute the current program.
Future cost estimates use calibration and that completed delivery. They never use
the measured outcome of the second delivery. Fixed and lightweight controllers
can avoid optional candidate-proposal work. NDU pays to propose and independently
verify the actual current fold, reject a current invalid candidate, and call the
native evaluator. These additional costs are included in its result.

The native request binds the actual costs of preparation, first delivery,
proposal, proof and refusal through its support digest and the retained ledger.
Its two recursive events describe building/stopping and executing the next
workload. They compare only future incremental utility at the decision point;
charging past costs to working paths but not to the literal zero-valued abstain
path would be an incorrect comparison. Sunk costs remain in the complete reported
net cost regardless of the choice, including abstention. Future event costs are
explicit forecasts until the actions have run. Utility is signed
Q32 milliseconds; resource budgets are Q32 microseconds. The constant completion
reward is not a measured speed improvement. The native `verified` input and
verification digests confer no deployment permission. A chosen candidate must
pass `build_optimized_native`, which performs an independent verification and
binds the source, proof, compiler, target and emitted bytes.

## Fairness and accounting

All controllers have the same initial calibration bank, source, available
candidates, completed-delivery information and 30-second job budget. The fixed
controller is selected before holdout execution. Its selection includes the
additional folding/build cost; the initial build is common to every job.
Controller order rotates across registered groups. No timing sample is excluded.
The workload is deliberately small and is not a broad compiler benchmark.

`episode_wall_ns` measures the whole job, including proposal, proof, native build,
controller call, sealed artifact admission, launch, measurement, checks and record preparation. Detailed
stage timings are retained; unassigned bookkeeping is reported separately. The
driver's internal `elapsed_ns` starts after `dlopen`/`dlsym`. The scored outer
duration includes process startup, library loading, closing and checksum checks.
Correctness is checked by an independent integer checksum oracle. The driver
loads a sealed inherited Linux memfd, whose actual bytes must match the native
receipt, rather than reopening the mutable source path. The recorded artifact
digest therefore identifies the loaded snapshot.

The study reports the actual shared cost once. For a standalone strategy
comparison, each strategy is charged the same complete driver/calibration setup
once and amortizes it over its jobs. NDU additionally pays its recorded native
bridge build and admission costs. The builder records whether the Cargo target
directory was empty. A previously populated dependency source cache is disclosed.
Toolchain installation and initial dependency acquisition are outside this
experiment's cost scope. An absent build-cost record prevents a complete-cost
claim. Descriptive timings are separate from statistical superiority, which this
small experiment does not establish.

## Fail-closed checks and retained evidence

Every controller checks the common deadline before and after each stage. Native
workload processes receive the remaining timeout. An observed overrun prevents
the next stage and makes the job unsuccessful; Python/compiler stage checks are
not a hard-real-time resource guarantee. The negative probes also execute a real
zero-deadline verification, a real native-process timeout and source drift. None
is counted as a successful deployment or a completed workload.

The run archive retains the registered protocol, all source files used for
qualification, their SHA-256 inventory, the native source/build/binary identity,
candidate inputs, verification receipts, compiled artifacts, raw execution
outputs, NDU requests/responses, stage ledgers and failures. The original native
evaluator returns `authority: DENY_ALL` and `safety_certificate: false` throughout.

## Reproduce

Build the bridge from the pinned companion-repository commit with
`tools/build_hia_ndu_bridge.py`. Use a new `--output` directory to measure an empty
Cargo target cache. The command requires explicit Cargo/rustc paths and can use a
previously downloaded Cargo source cache through `--cargo-home --offline`.

With Z3 importable and Clang installed:

```sh
HEPTA_NDU_IDENTITY=/absolute/path/to/identity.json \
  python3 -m unittest discover -s tests -p 'test_hia_ndu*.py' -v
python3 -m tools.qualify_hia_ndu_loop \
  --identity /absolute/path/to/identity.json \
  --clang /absolute/path/to/clang \
  --output experiments/hia_ndu_loop/new-run
```

The output directory must be new. A source change during execution rejects the
qualification and leaves its existing records available for inspection.
