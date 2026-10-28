# HIA system closure evidence — 2026-10-28

This directory records finite implementation, execution and review evidence for the P0–P7 acceptance table used in the current work. The Chinese report is the primary narrative: [REPORT.zh-CN.md](REPORT.zh-CN.md). The actionable acceptance ledger is [blockers.json](blockers.json).


## Source identities and result boundaries

| Record | Source | Status represented here |
| --- | --- | --- |
| Historical complete collector, native-loan v1 and checked-reduction experiments | `b92141483ca5084691f436d28d4cd0dcbefe4717` | 35 gates completed, 34 passed; standalone performance inconclusive. Two registered reduction attempts retained no-change. |
| Corrected implementation | `de49fe3e0254b7b71dbcb5b2907a3f3145999393` | The source-bound full35 and native-loan v2 final results appear below. |
| Development and independent review | Exact source/patch hashes in each record | Reproduced cleanup defects and repairs; not a substitute for current-source execution. |

The corrected unit gate has completed 274 isolated module processes and 2,706 unique test IDs, with two workers and no retries. Failures, errors, skips, expected failures and unexpected successes are all zero. The completed ID inventory is `a991735e1ca47e77805735b5b63687cb2c5d6081c7059f209d8e6ac184901738`. The corrected Cargo gate has also completed 56 tests across 10 binary summaries, with zero failures, ignored tests or filtered tests. The complete collector and separate native-loan v2 results follow; the unit and Cargo counts are not additional system qualification claims.

- Current full35: 35/35 项执行完毕，34/35 项通过；未合格项：standalone_performance；`scoped_gates_not_all_qualified`
- Current source/tool/commit binding: 源码 `de49fe3e0254b7b71dbcb5b2907a3f3145999393`；运行前后源码及所选工具身份均未变化；完整检查点、报告和日志见当前源码审计。
- Current standalone-performance result: `measurement_inconclusive`；保留 63 个样本；固定 MAD 门槛失败 8 项，性能比值门槛失败 0 项；没有删样本或改变接受标准。
- Current native-loan v2 result: `passed`；尝试 7，确认启动 7，确认回收 7，完成观察 7，有入口证据 6；入口结果不可用 1，总入口调用数 `null`；最终 drained=true，释放 3 个映像。

The corrected run does **not** repeat the two preregistered NDU measurements. Their source remains `b921414`; neither a new cleanup commit nor a later test pass changes that identity.

## Evidence map

The listed audit JSON files are copied into `audits/` and also retained with the complete raw records in [raw-evidence-parts.json](raw-evidence-parts.json). [raw-evidence-manifest.json](raw-evidence-manifest.json) is the per-member inventory generated from the actual package. The archive is a standard solid-compressed tar.xz; existing historical ZIP packages remain unchanged.

| Relative audit file | What it establishes |
| --- | --- |
| [audits/collector-source.json](audits/collector-source.json) | Frozen collector source, independent expected-ID inventory and source/dependency admission boundaries |
| [audits/collector-unit-execution.json](audits/collector-unit-execution.json) | Historical 273 modules / 2,697 unique IDs; exact Rust/Python and overlapping native denominators |
| [audits/collector-frozen-execution-final.json](audits/collector-frozen-execution-final.json) | Historical completion of all 35 gates, 34 passes, retained performance uncertainty and source-bound outputs |
| [audits/collector-candidate-cross-reference.json](audits/collector-candidate-cross-reference.json) | Immutable cross-reference between collector and candidate execution audits |
| [audits/candidate-source.json](audits/candidate-source.json) | Checked-reduction matcher, Lean boundary and candidate/evidence identity review |
| [audits/candidate-execution.json](audits/candidate-execution.json) | 30/31 and 31/31 actual pairs; retained binary hashes; fixed policy arithmetic; paid and CLI costs |
| [audits/native-source.json](audits/native-source.json) | Historical native lifecycle/counting findings; original source provenance |
| [audits/native-cleanup-review-v1.json](audits/native-cleanup-review-v1.json) | Independent discovery of finalizer-masking and blocking-reap-lock interactions |
| [audits/native-cleanup-review-v2.json](audits/native-cleanup-review-v2.json) | Closure of those findings on the exact eight-file patch; retained failing-before/passing-after controls |
| [audits/real-workload-feasibility.json](audits/real-workload-feasibility.json) | Pinned upstream modules, exact rule mismatches and the limits of existing workloads |
| [audits/p7-assets.json](audits/p7-assets.json) | Dated model/runtime/storage observations, platform/long-load/Agent scope and remaining work |

Raw package input map (the manifest records the final member paths; do not rewrite the retained producer records to change their original absolute execution paths):

| Retained source directory in the working evidence set | Required package content |
| --- | --- |
| `validation-system-frozen/` | Historical runner source/tool snapshots, 35-gate reports/logs/checkpoints, native-loan v1 images, both NDU attempts including failed attempt 1 artifacts |
| `validation-system-corrected/` | Current-source plan, all final reports/logs/checkpoints, source/tool before-and-after records and native-loan v2 observations |
| `validation-system-audits/` | All original audit JSON, prior findings, v2 closures and immutable cross-references |
| `validation-candidate-next/` | Checked-reduction development outputs, finite case counts, proof/fixture failures and corrected controls |
| `validation-native-cleanup-fix/` and `validation-loan-next/cleanup-fix-development/` | Original and v2 patches/plans, initial 40 focused tests, three failing review controls, corrected 3 and final 43 logs with unchanged source hashes |

Do not count overlaps as extra coverage: Rust/Python observations total 1,830; 95 selected bulk/chain native controls overlap them. The 1,454 checked-reduction before/after pairs are 2,908 executions, not 1,454 unique test methods. The 43 focused cleanup methods include the 9 added methods and the 3 reproduced/repaired interactions. The historical selected 77 Rust-parity and 53 agent-query Python methods are reruns from the 2,697-ID complete inventory.

## Inspecting the raw package

From this evidence directory, extract into a new destination outside the checkout:

```sh
mkdir -p /tmp/hepta-system-closure-20261028

python3 reassemble_raw_evidence.py --output /tmp/hepta-system-closure-20261028/raw-evidence.tar.xz

tar -xJf /tmp/hepta-system-closure-20261028/raw-evidence.tar.xz -C /tmp/hepta-system-closure-20261028
```

The package contains ordinary relative member paths/modes; every member was reopened and checked against its manifest before publication. The archive itself and manifest do not establish toolchain or platform attestation. Tests, compilers and timing protocols are not rerun merely by extracting or reviewing the package.

Normative scope: [HIA Core](../../docs/HIA_PROGRAM.md), [integration contract](../../docs/HIA_SEVEN_STAGE.md), [qualification collector](../../docs/HIA_UNIFIED_QUALIFICATION_V3.md), [independent Rust chain execution](../../docs/HIA_RUST_CHAIN_VM_20261027.md), [checked reduction](../../docs/HIA_CHECKED_UNSIGNED_REDUCTION.md), [NDU pipeline](../../docs/HIA_NDU_CANDIDATE_PIPELINE.md), [native version lifecycle](../../docs/HIA_NATIVE_VERSION_DISPATCH_20261027.md).

## Current audits and tool provenance

See the [current unit audit](audits/collector-corrected-unit-execution.json), [current complete execution audit](audits/collector-corrected-frozen-execution-final.json), and [machine-readable results](results.json).

Core qualification and Rust performance baselines use actual Rust/Cargo 1.90.0. The unchanged NDU bridge was built earlier with Rust/Cargo 1.99.1. Its binary SHA-256 is `ada753864ff3bcf03f56fbbc6cc0884259fdf513565bbf6499e19f1c6e93d3e8`; its upstream pin is `f8c9419df6ddeb36ff8b522a50219981fb8d9345`. The archive retains `dependencies/ndu-build-provenance.json`, without private NDU source or its implementation binary.


## Rechecking records and reproducing execution

Record inspection does not execute native artifacts. Check the archive SHA-256 in `raw-evidence-manifest.json`, then compare every extracted ordinary file with its listed member path, size and SHA-256. `source-run-index.json` binds each outer report to its source commit. Original absolute paths inside retained records describe the original run and have not been rewritten.

For a new execution, use separate clean checkouts of the exact `b92141483ca5084691f436d28d4cd0dcbefe4717` baseline or `de49fe3e0254b7b71dbcb5b2907a3f3145999393` corrected source. The corresponding archive paths `baseline/command-plan.json` and `corrected/command-plan.json` retain complete argv; `summary.json` retains selected environment settings, `tool-versions.json` records actual versions, and `tools-before.json` binds their hashes. Use fresh output directories and port the host-specific executable/cache paths explicitly. Do not overwrite these recorded runs or silently substitute a different source/tool identity.

The corrected plan invokes `tools/qualify_hia_unified.py` and `tools/qualify_hia_native_loans.py`. It requires the declared Linux execution facilities and recorded compiler/QEMU/Lean dependencies. The `reproduction/` wrapper scripts preserve how this workspace was run; their original absolute paths and expected source identities must be reviewed before adapting them to another host. They are not a self-contained environment installer.

The historical baseline plan separately invokes the registered two-attempt reduction protocol. Reproducing its real NDU evaluation requires authorized access to the pinned bridge and matching build inputs; the private implementation is not distributed in this evidence package. A new measurement is a new source/tool/host-bound experiment, keeps the fixed budgets and acceptance thresholds, and preserves timeout, regression and no-change outcomes. The original two attempts remain immutable historical evidence.

## Bounded transport after interrupted publication

The original 25,521,872-byte archive is stored in Git as 33 ordered binary parts, each at most 786,432 bytes. Use `reassemble_raw_evidence.py` and `raw-evidence-parts.json` to reconstruct it. The reassembler checks each part and the final archive SHA-256, and refuses to overwrite an existing output. The reconstructed SHA-256 remains `6b2d39d9d1cdc3263859527310285f83b27cf83009fb4b7f42a538f569b0bc61`; all 7,490 original members and their records remain unchanged. The transport recovery receipt explains the interrupted large-blob publication.
