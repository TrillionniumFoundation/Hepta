# Finite NDU compiler graph qualification

## Measured result, 2026-10-28

The registered run completed all 18 episodes, all 72 episode workload executions
and all 27 calibration executions with the independent checksum. Six actual
guarded transitions were regenerated, independently proved, compiled and loaded
by the fixed-candidate controls. The optimal fixed-plan, complete-DP and original
native NDU controls all selected stopping optimization and delivering the
remaining batches with the original program. The measured proof/build cost did
not amortize over this workload. There was **no demonstrated NDU net advantage**.

| Control | Median episode, seconds | Median including allocated setup, seconds |
| --- | ---: | ---: |
| Fixed original | 1.016785 | 5.600837 |
| Fixed small guard | 1.858274 | 6.442326 |
| Fixed wide guard | 11.211101 | 15.795153 |
| Optimal fixed plan | 1.027232 | 5.611284 |
| Complete lightweight DP | 0.967018 | 5.551751 |
| Original native NDU | 1.018801 | 20.026993 |

Common calibration and study overhead was 13.752157195 seconds. The new empty
Cargo target took **43.243376181 seconds** to build the native bridge; this cost
is charged only to NDU and allocated over its three episodes. The measured study
itself took 67.233284148 seconds, or 110.476660329 seconds including that build.
Each strategy receives one common setup charge in the standalone comparison.
The actual study incurred that common setup once.

The guarded code was measurably different machine code, with verified
30-obligation Core proofs for each guard variant. For example, calibration
outer execution at size 4096 was 75.349233 ms for the original and 45.351115 ms
for the wide guard; at size 16384 it was 285.005907 ms versus 241.168773 ms.
The wide candidate's actual proposal/proof/build setup was 8.541949886 seconds.
These observations support the decision to stop for this finite workload; they
do not establish a general speedup or a NDU advantage over the same complete DP.
All samples, rather than selected fast samples, remain available in the archive.

The final local regression ran **32 tests, all passed and none skipped**.
The actual unprotected fast body was rejected, and the verifier deadline,
process deadline, changed source snapshot and wrong artifact digest all failed
closed. The independent native job on published private commit
`4b6391e116949af0c7e59776baead67271856bdb` also passed its five Rust tests and
executable identity/typed-transport checks:
[run 40632653917](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653917).
The broader dependency/workspace gate is reported separately and is not green
merely because this bridge-specific job succeeded.

Readable results are under [`run_20261028`](run_20261028). The complete raw tree
is in [`run_20261028.tar.xz`](run_20261028.tar.xz), including source snapshots,
all SMT queries, all machine-code artifacts, all requests/responses/samples,
native executable/build identity, test logs and the complete remote bridge log.
The archive contains 218 files, compressed from 7,539,507 to 805,388 bytes. Its
SHA-256 is `0b9d0824e59b8f07db67078996c8eebee02bcacb19b96c701f4a8fc89f736a1b`.
Every member was re-read and checked against its individual SHA-256 both before
and after publication; only then were redundant scratch copies removed.
[`run_20261028.members.json`](run_20261028.members.json) defines the raw tree
digest and every member; [`run_20261028.archive.json`](run_20261028.archive.json)
records the original path and restoration command. The archive preserves all
original relative paths below `run_20261028/`.

## Registered method

This experiment tests an actual compiler loop with the original Rust NDU
recursion and feasibility/Pareto evaluator. `PROTOCOL_20261028.json` registers
the workloads, six controls and cost accounting before holdout measurements.
The earlier constant-fold experiment under `../hia_ndu_loop` remains unchanged.

## Executable candidates and transitions

The input is the resource-owning Hepta source in
`../hia_optimizer_eval/kernels.hepta`. The measured export is
`full_lifecycle(size_t, uint32_t) -> uint64_t`. Each call allocates a byte buffer,
fills it, reduces it with checked arithmetic and releases it. The independent
checksum is computed without executing Hepta or LLVM.

The graph has the original program, a guarded reduction with a small size
limit, a guarded reduction covering the registered sizes, and the unprotected
fast body. The last is actually submitted to the equivalence checker and must
be rejected: an unguarded removed overflow check cannot receive universal
authority. Its measured rejection cost and counterexample remain in the bank.
Guarded variants retain the complete original slow path. Their safety evidence
comes from the independent guarded checker, not from the NDU result.

Each finite path contains real transition/build and execution events for each
remaining batch. `hold` delivers the current batch and then permits replanning;
`stop` closes optimization while delivering all remaining batches; a transition
regenerates the proposal, verifies the source identity, independently reproves
and compiles it, and checks the final Core and native receipt. The runner loads
only receipt-matched bytes sealed in an inherited Linux memfd. The path cap is
explicit, and exceeding it rejects the whole planning request rather than
silently labeling a partial search complete.

## Controls and information

The three fixed-candidate arms show the actual cost of retaining the original,
always installing the small guard, or always installing the wide guard. The
strong fixed-plan control searches every legal complete path using the same
calibration bank and the common initial workload, then commits that schedule.
The lightweight control solves the same complete finite graph with additive
dynamic programming and replans after actual observations. Fixed and light
controls avoid unnecessary native event serialization. Cross-checks compare
the DP's decisions against exhaustive path enumeration. The NDU control passes
the paths to the original native
recursive-utility and feasibility/Pareto functions. An unresolved native
frontier is an explicit refusal, not a concealed candidate-name tie-break.

All strategies receive the same registered input schedule, candidate bank,
proof results and budget. No strategy can read a future holdout execution time.
The cost model uses per-size calibration medians, updated only by completed
measurements for that same executable state. Unknown future gains are not
replaced with an oracle. The supplied estimates remain estimates: NDU cannot
turn a miscalibrated cost model into a proof of globally optimal performance.

## Costs, failures and interpretation

Every arm enforces the same deadline before and after each stage; native work
also receives the remaining process timeout. Observed deadline overrun cannot
be admitted as completion. Historical proposal, proof, rejection, build,
measurement and control costs remain in the full ledger. Candidate comparison
uses future incremental value, so literal zero-valued abstention is not given
an artificial advantage by charging already incurred costs only to work paths.
Utility uses signed Q32 milliseconds; the resource budget uses Q32 microseconds.

Episode wall costs include proposal, independent proof, compilation, planning,
artifact sealing, process startup, dynamic loading, execution and each arm's
evidence encoding/write. The aggregate report records the outer observed cost;
the earlier per-episode report records admission cost before its own write.
Reports also
charge the shared calibration once to each standalone strategy comparison,
and charge the recorded native bridge build/admission only to NDU. The actual
study incurs shared setup once. Toolchain installation and preexisting source
cache acquisition are outside the declared measurement scope. A missing or
nonempty-target native build record prevents a complete-build-cost claim.

Actual negative controls cover verifier deadline exhaustion, source snapshot
drift, receipt/artifact mismatch and native process timeout. None is converted
to successful execution. The report retains every episode, including refusals,
wrong outputs, deadline failures and controller failures. Core optimization
speedup and additional NDU controller benefit are separate questions. The
experiment makes no whole-language proof, backend refinement, statistical
superiority or unrestricted global-optimality claim.

## Reproduction

Build the native bridge using `tools/build_hia_ndu_bridge.py` at an exact private
repository commit. Its optional `--target-dir` places reproducible Cargo cache
elsewhere; the admitted executable is copied into the output directory and both
copies' digests are recorded. Run the graph with the qualified Python/Z3/Clang
environment and the resulting identity manifest:

```sh
PYTHONPATH=<pinned-z3>:. /usr/bin/python3 tools/qualify_hia_ndu_graph.py \
  --identity <native-build>/identity.json --clang <qualified-clang> \
  --output <new-run-directory>
```

`tests/test_hia_ndu_graph.py` contains bounded graph tests, actual original-NDU
tests and a small end-to-end proof/build/execution graph. The native tests
require `HEPTA_NDU_IDENTITY`; full compiler tests additionally require the pinned
Z3 and `HEPTA_CLANG`. Missing prerequisites are reported as skips and are not
represented as successful native qualification.

`CI_TRIAGE_20261028.json` records the previous private blocking run's actual
failed jobs and diagnostic excerpts. The dedicated bridge CI supplements those
gates. It does not replace the full workspace/platform/dependency jobs or claim
that unrelated failures have been fixed.
