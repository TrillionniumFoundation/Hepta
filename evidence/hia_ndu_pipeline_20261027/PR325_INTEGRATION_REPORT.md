# PR #325 与本轮 HIA/NDU 实现：固定提交整合审查

审查日期：2026-10-27。结论：**不能直接无冲突叠加；可以在保留两套工作和证据的前提下整合，但需要显式解决三个文件的四处文本冲突，以及 CLI、solver、NDU 协议、证明作用域和运行时生命周期的接口差异。** 当前将本轮发布到新的独立分支 `codex/hia-ndu-bounded-pipeline-20261027` 是合理的保全方式。不要覆盖 PR #325 的分支，也不要把该 PR 的 201 项测试结果归给本轮。

## 1. 比较身份与方法

| 身份 | 固定值 |
| --- | --- |
| 仓库 | `TrillionniumFoundation/Hepta` |
| 共同 base | `3db07aa877ab1a5fc00560d7037e6efbc884fc1f` |
| PR #325 head | `bdb0b39c99b7980b98cb3f9e07ba406cc20f0940` |
| PR #325 远程分支 | `codex/hia-ndu-verified-optimization-20261027` |
| 本轮冻结实现 | `c4309712d8f4d21563a26c174391bd66195a9e34` |
| 不属于此次比较对象的 API 镜像 | `e1473a42…` |

GitHub 只读 PR 元数据与 commit compare 确认，#325 当前为 draft/open，base 与 merge-base 均是上述 `3db07aa…`，共五个提交、177 个变更路径。本轮从共同 base 到 `c430971…` 有 48 个变更路径。

本次通过固定 commit 的 GitHub 文件接口读取源码，核对关键下载快照的 Git blob SHA；从本地 Git 对象读取 base 和冻结版本。对重叠文件运行独立 scratch 快照中的 `git merge-file --diff3 -p`，未在工作仓库执行 merge、checkout、commit、reset、push 或远程 ref 写入。没有执行另一分支的程序或测试。审查结束时本地 HEAD 仍为 `c430971…`，tracked/untracked 工作树状态输出为空。

来源：[PR #325](https://github.com/TrillionniumFoundation/Hepta/pull/325)、[固定比较](https://github.com/TrillionniumFoundation/Hepta/compare/3db07aa877ab1a5fc00560d7037e6efbc884fc1f...bdb0b39c99b7980b98cb3f9e07ba406cc20f0940)。机器可读快照为同目录 `github-pr.json`、`github-compare.json`、`path-and-merge-summary.json`。

## 2. 精确路径重叠与文本冲突

| 路径 | 本轮变化 | PR #325 变化 | 三方预检 |
| --- | --- | --- | --- |
| `hepta/cli.py` | 新增 verify-translation 与 NDU optimize | 新增 routes、verify-optimization、常量折叠 optimize、build-optimized，并统一旧输入路由 | **2 个冲突块**：action 注册和执行分派 |
| `pyproject.toml` | `verification = ["z3-solver==4.15.4.0"]` | `optimization = ["z3-solver==4.13.4.0"]` | **1 个冲突块**，且有实际依赖冲突 |
| `tools/build_hia_ndu_bridge.py` | 新增独立工作区构建器 | 新增私库内置 bridge 构建器 | **add/add，1 个冲突块** |

三者均不是 clean textual merge。预检输出保留在 `merge-preview/`，没有写回工作树。这里是逐文件三方文本预检，未创建或测试合并后的树；不能把“其余路径不重叠”解释成整个集成版本已兼容。

本轮有 45 个独有变更路径；#325 有 174 个独有变更路径，其中 142 个位于 `experiments/`，属于实验脚本、输出、制品和历史证据。两边变更路径的并集是 222 个。完整路径集合在 `path-and-merge-summary.json`。

### 同名命令有不同含义

本轮 `hia optimize` 要求 `--function --bridge --bridge-build-receipt --observations --objective`，通过 `propose_candidates` 生成有限候选，经独立行为证明及原生 NDU 排序，返回 `hepta.hia.ndu-optimization.v1` 决策。

#325 的 `hia optimize` 接受可选 `--policy --output`，执行一次 `fold_constants`，再做全模块的优化验证，返回 `hepta.hia.optimization-proposal.v1`；它不是同一个 NDU 决策命令。简单合并 action 列表或参数集合不能保留两者原义。

整合时应给两种操作明确名字或明确互斥模式，例如让常量折叠使用独立 `fold-constants` 入口，保留两个验证命令的显式 scope；是否保留兼容 alias 应在整合 PR 中决定。不能静默根据缺少参数切换含义。

来源：[PR CLI 注册](https://github.com/TrillionniumFoundation/Hepta/blob/bdb0b39c99b7980b98cb3f9e07ba406cc20f0940/hepta/cli.py#L48-L96)、[PR CLI 执行](https://github.com/TrillionniumFoundation/Hepta/blob/bdb0b39c99b7980b98cb3f9e07ba406cc20f0940/hepta/cli.py#L321-L349)；本轮 `hepta/cli.py:50–77,339–373`。

## 3. 架构对应：同一 Core，互补的证明范围

两边均以既有 `hepta.hia_program.verify_program` 和 immutable canonical Core 为基础，都没有改写这个共同 admission 核心。新增模块名字不同，不表示能力完全互不相关。

| 层次 | PR #325 | 本轮 c430971 | 整合判断 |
| --- | --- | --- | --- |
| 输入路由 | `hia_routes.py`，明确历史 IR/source 适配并最终重验 | 沿用既有显式导入入口；另有有限 Rust 迁移资格工具 | 路由元数据与适配层可保留，必须准确标明有限入口 |
| 等价性 | `hia_optimization.verify_optimization` | `hia_translation_validation.validate_translation` | 不能互换 receipt；范围互补 |
| 候选生成 | `fold_constants`，全模块常量折叠 | `hia_finite_actions.propose_candidates`，选定函数的有限代数/CFG 变换 | 可以适配 program，不可沿用对方成功标记 |
| NDU | `hia_ndu.NduBridge`，递归效用加候选评估 | `hia_ndu_optimizer.rank_candidates`，证明绑定的稳健成本排序 | 协议、身份、单位及 cost ledger 需明确转换 |
| 原生构建 | `build_optimized_native` 把 fresh 全模块证明绑定到构建制品 | runtime 内逐导出 fresh 证明再构建；另有有限 x86 指令/ELF 字节检查 | 需保留不同证明和 backend 资格范围 |
| 运行时 | `hia_adaptive.AdaptiveRuntime`，显式全局静止切换 | `hia_multiversion` + `hia_background_optimizer`，逐代租约与条件后台发布 | 不可只改类名替换 |
| 资源与迁移扩展 | C++ lexical scope、条件构造/move、早退与反向清理 | Rust owned CFG/byte-memory shadow 扩展与有限 Rust 迁移资格 | 路径不冲突，属于不同增量 |
| 研究证据 | 五臂 NDU loop、C++ 四路径、强性能/Agent pilot、201 项选定模块集成记录 | 有限指令搜索、等价性、native bridge、成本 gate、租约/后台、Rust CFG 等资格与全回归 collector | 证据必须分别保存，合并后重跑 |

### 证明契约不能靠状态重命名统一

#325 的 `verify_optimization(base, candidate, policy=None)` 返回 `hepta.hia.optimization-verification.v1`，状态为 `verified/rejected/unknown/timeout`。它要求整个模块的 CFG、接口和资源/调用骨架不变，然后按 block 和 effect barrier 证明标量观测及首个规定陷阱相同。这个 profile 能检查循环/资源程序内的局部纯标量改写，但不是任意循环、资源重排或 CFG 变化的证明。

本轮 `validate_translation(before, after, *, function=None, timeout_ms=2000)` 返回 `hepta.hia.translation-validation.v1`，状态为 `proved/disproved/unknown`，作用域为 `selected_public_scalar_function`。它比较选定公开标量函数的完整无环行为，允许两个无环 CFG 不同；资源、调用或循环返回 unknown。行为反例须经 canonical interpreter 重放。runtime 对全部导出逐个重新证明。

因此远程 `rejected` 不一定等于本轮 `disproved`，远程 `verified` 也不能直接塞入本轮要求的 proof 字段。建议保留两个显式 profile，以共同 envelope 表达 checker ID、scope、目标、Core/input hashes、solver identity 和 outcome；消费者仍实际调用对应 checker。

还存在候选范围差异：远程 fold 会遍历全模块，本轮 `rank_candidates` 要求除选定函数外所有函数保持原样。适配时应只把选定函数的变换纳入该接口，或者新增明确的全模块证明/排序 profile，不能放松原有检查来容纳输入。

来源：[PR 证明骨架](https://github.com/TrillionniumFoundation/Hepta/blob/bdb0b39c99b7980b98cb3f9e07ba406cc20f0940/hepta/hia_optimization.py#L98-L131)、[PR 证明与构建](https://github.com/TrillionniumFoundation/Hepta/blob/bdb0b39c99b7980b98cb3f9e07ba406cc20f0940/hepta/hia_optimization.py#L220-L445)；本轮 `hepta/hia_translation_validation.py:312–431`、`hepta/hia_ndu_optimizer.py:165–181,242–258`。详细 API 对照见 `peer/API_COMPARISON.md`。

## 4. Solver pin 是实际运行阻点

#325 的 pyproject extra 固定 `z3-solver==4.13.4.0`，且 checker 在运行时检查 `z3.get_version_string()=="4.13.4"`，否则返回 unknown；它绑定 Z3 动态库和 Python bindings 身份。本轮 extra 固定 `z3-solver==4.15.4.0`，但本轮 checker 没有相同的运行时硬拒绝条件，而是报告实际版本并绑定验证器身份。

直接安装本轮依赖再调用 #325 checker 会触发版本不匹配。两个 extras 同时安装也不能满足两套精确 pins。反向采用 4.13.4 可能被本轮 API 接受，但已改变本轮资格使用的 solver，不能沿用既有测试结果。

可选收敛路径是统一版本并重新资格验证，或把两种 checker 放入明确隔离的 Python 进程/环境。不能仅删除版本门槛便宣称兼容。timeout 的意义也不同：#325 按整个请求的剩余 deadline 分配每个 obligation 时间；本轮 `timeout_ms` 是 solver timeout，端到端实际成本另由 rank/runtime/coordinator 计量。

来源：[PR solver 身份与 pin](https://github.com/TrillionniumFoundation/Hepta/blob/bdb0b39c99b7980b98cb3f9e07ba406cc20f0940/hepta/hia_optimization.py#L23-L96)、[版本拒绝](https://github.com/TrillionniumFoundation/Hepta/blob/bdb0b39c99b7980b98cb3f9e07ba406cc20f0940/hepta/hia_optimization.py#L261-L280)；两份 `pyproject.toml` 已保留在 `remote/`、`local/`。

## 5. NDU：共有算法基本一致，桥协议不可互换

| 契约 | PR #325 | 本轮 |
| --- | --- | --- |
| 私库 pin | `2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b` | `d3c2d760eca5065fc966820379c35c6e8d56e855` |
| bridge 源码 | 私库 `tools/hia-ndu-bridge/src/main.rs` | Hepta `rust/hia-ndu-bridge/src/main.rs` |
| 构建入口 | `--ndu-source --expected-source --cargo --rustc --output` | `--upstream --output [--cargo]` |
| 构建行为 | 在指定私库 bridge 上构建 release；lock 缺失时可生成 | 从固定 Git object 提取生产输入到新隔离目录；要求已提交 lock；构建 debug adapter |
| 构建记录 | `identity.json`；`hepta.hia.ndu.build.v1` | `build-receipt.json`；`hepta.hia.ndu-build.v1` |
| request schema | `hepta.hia.ndu.request.v1` | `hepta.hia.ndu-request.v1` |
| 核心输入 | events、discount/terminal utility、risk/resource/uncertainty、verified 与摘要 | cost/resource/uncertainty、hard_violation、support 摘要 |
| 原生调用 | `evaluate_recursive_utility` 后 `evaluate_candidates_with_policy` | `evaluate_candidates_with_policy` |
| 建议输出 | `advisory_candidate_id`；`authority=DENY_ALL` | `advisory_recommendation`；`authority=ADVISORY_ONLY` |
| 上层控制 | `tools/qualify_hia_ndu_loop.py` 里实际执行 proposal/proof/build/measure/continue/stop 的有限实验 | production Python rank 接口 + 单 worker 后台 coordinator；实际 qualifier 单独验证 |

两边都把原生 NDU 输出当作建议。远程低层 `NduBridge.evaluate` 的 `verified` 输入不是证明授权；本轮 rank 必须继续自行重验，不可从 transport 的 flag 或 digest 推导合法性。

对已保留的 native source inventories 作逐路径摘要比较：本轮记录 120 个原始文件，#325 记录 89 个；共有 89 个中 **88 个字节摘要相同**。唯一共有差异是 `codex-rs/hepta-ndu/src/lib.rs`，固定源码 diff 显示本轮额外声明/导出了 `generation_rollout` 模块。共有 evaluator/recursive-utility 源文件不是两套改写算法。记录范围不同，本轮还覆盖包含 fixture 在内的所有原始输入；不能仅比较聚合摘要就得出算法全部不同。

整合可保留“候选成本排序”和“递归事件效用”两个版本化协议，或在同一个新桥内显式实现两种 mode。选定一个新私库 pin 后必须重建并重验。当前本轮验证器还检查 builder 文件自身 SHA，因此改名/合并这个脚本也会使原有 build receipt 失效，需要同步调用者、CI、builder 身份规则和新 receipt，不能只添加参数 alias。

来源：[PR builder](https://github.com/TrillionniumFoundation/Hepta/blob/bdb0b39c99b7980b98cb3f9e07ba406cc20f0940/tools/build_hia_ndu_bridge.py#L35-L103)、[PR transport](https://github.com/TrillionniumFoundation/Hepta/blob/bdb0b39c99b7980b98cb3f9e07ba406cc20f0940/hepta/hia_ndu.py#L78-L146)、[私库递归效用与候选评估调用](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b/tools/hia-ndu-bridge/src/main.rs#L166-L267)；本轮 `tools/build_hia_ndu_bridge.py:29–137`、`hepta/hia_ndu_optimizer.py:99–162`。摘要比对在 `ndu-source-inventory-comparison.json`。

## 6. 运行时生命周期与成本不应混用

#325 `AdaptiveRuntime` 接受一个单块、1–8 个 u64 参数、单 u64 返回、无效果的函数。`prepare` 返回 token；`select(mode="explicit")` 会重新证明当前函数到候选的等价性，有任何 active call 就拒绝切换。`select(mode="auto")` 明确保留当前版本；shadow measurement 不是盈利自动发布的凭据。images 保留到 close，close 遇到在途调用/准备工作会拒绝。

本轮 `ScalarMultiversionRuntime` 接受有限的多个 bool/整数标量导出和无环 CFG，维护 per-generation leases。新调用可以进入新一代，旧代直到已有租约释放才回收；保留初始 baseline 供 rollback。`publish_if_current` 检查 generation 与 epoch、实际 preparation budget 及取消 token，后台 coordinator 再把当前源、目标、测量 profile、净收益和真实控制成本绑定起来。其 host observations 与 expected_calls 仍是可信主机输入，并非独立性能证明。

可以通过共同 facade 暴露两种不同能力，但 token、generation、state descriptor、receipt 不能互换。若采用远程内部 shadow measurement 给本轮排序提供数据，须重新绑定 canonical/input hashes、目标、计量 profile 和当前 epoch，并明确测量成本与未来工作量；不能把已经完成的 shadow calls 再记成未来收益。两者都没有一般 live owner/loan/state layout 迁移。

来源：[PR runtime profile](https://github.com/TrillionniumFoundation/Hepta/blob/bdb0b39c99b7980b98cb3f9e07ba406cc20f0940/hepta/hia_adaptive.py#L26-L105)、[PR select/close](https://github.com/TrillionniumFoundation/Hepta/blob/bdb0b39c99b7980b98cb3f9e07ba406cc20f0940/hepta/hia_adaptive.py#L313-L381)；本轮 `hepta/hia_multiversion.py`、`hepta/hia_background_optimizer.py`，完整签名见 `peer/API_COMPARISON.md`。

## 7. 文本不冲突但需要重新验证的共享依赖

1. **直接 LLVM allocator 声明。** #325 在共同 `hia_program_llvm.py` 给 calloc/malloc 返回值增加 `noalias`，保留 opaque/nullable 和 no-builtins。本轮没有修改该文件，因此 Git 会直接接受；但本轮 runtime、差分资格和 native artifacts 都依赖其输出。需要重跑实际 allocation/refusal/cleanup 和相关 native 检查，旧二进制及旧 source identity 不自动适用于合并树。
2. **JSON wire 边界。** #325 在 `hia_program_tools.py` 拒绝 lone surrogate 和转换后的 dict key collision，本轮没有同路径改动。它影响共同 admission 的 bounded serialization；值得保留并运行新增边界测试及本轮有关输入冻结/身份绑定的测试。
3. **C++ 词法作用域。** #325 修改 `cpp_composed_migrate.py`，新增 scope_ids/scope_depth、最多 16 层作用域、局部 owner 逆序清理、条件构造/move 和早退处理。本轮的 Rust owned CFG 扩展在不同文件，可独立整合；仍需对应 C++ 和 resource/LLVM 路径执行验证。
4. **CI 构建入口。** #325 新增 `hepta-verified-optimization.yml`，使用旧 builder 的 `--ndu-source`、`HEPTA_NDU_IDENTITY` 和 4.13.4 extra；本轮已有 `hepta-qualification.yml` 使用 `--upstream`、`HEPTA_NDU_BUILD/BRIDGE/UPSTREAM` 和 4.15.4。文件不冲突不等于两条流水线能共享同一个 builder。
5. **已有测试的观察时间。** #325 将 `tests/test_hia_native_side_effects.py` 的 child 观察期限由 3 秒改为已有的 10 秒上限，仍断言确切信号/标记，timeout 仍拒绝。该独有变更应独立审阅；本轮未在此次只读审查采纳或重跑它。

上述固定 diff 已保留在 `remote-changes/` 或可由 `base/` 与 `remote/` 重建。另一个分支的 `.gitattributes` 仅对一份已保存 diff 关闭 whitespace 检查，没有自定义源文件 merge driver。

## 8. 建议的整合顺序与证据边界

1. **先保留两个分支和各自固定 SHA。** 本轮采用新的 bounded-pipeline 分支，PR #325 的 refs 和实验目录原样保留。
2. **建立单独整合分支。** 在 reviewable PR 中解决三个冲突文件；显式决定 CLI 命名、solver pin/进程隔离及两种 NDU bridge 的入口。当前没有必要为发布本轮而先完成这个整合。
3. **先合并独立、明确的基础改进。** 例如 wire 拒绝修复、路由、C++ lexical scope、Rust owned CFG；每一项保留自己限定的 profile。LLVM noalias 变更单列，执行实际 allocator 回归。
4. **增加 profile adapter，不转录授权。** 可以适配 candidate program 的数据形状；证明、预算、ABI、target 和所有导出覆盖必须由实际消费者重新检查。serialized receipt 的成功标记不能作为 admission。
5. **重建桥与 native artifacts。** 采用清楚的 source pins、锁文件、builder/adapter hashes 和 schema；两套历史 build receipts 均只属于原先构建。
6. **对最终整合树重新 discovery 和执行。** 不能把本轮测试数与 PR #325 的 201 相加，因为后者是选定模块的集成集，存在共同基线测试。需要新的合并树 SHA、完整用例集合、skip 分母、真实工具链与独立输出目录。
7. **保留失败与阴性结论。** PR #325 自己明确 NDU 净收益、Rust 性能非劣、Agent 正确维修优势、盈利自动适应未获确认。整合源码不会改变这些研究结论，也不构成全局最优、任意 C++ 迁移或整个语言安全性的证明。

此次读取了 PR 中保留的 `run_20261027_ci_fix/result.json`：记录 201 tests、0 failures、0 errors、passed=true；这是另一实现的历史记录，未在此次复跑，也不是本轮 `c430971…` 的执行结果。本轮冻结收集器的结果由主线程单独报告。本报告本身只证明来源身份、路径重叠、文本预检和已读取接口的静态差异。

来源：[PR 保存的集成结果](https://github.com/TrillionniumFoundation/Hepta/blob/bdb0b39c99b7980b98cb3f9e07ba406cc20f0940/experiments/hia_verified_integration/run_20261027_ci_fix/result.json)、[PR 实施与未通过目标](https://github.com/TrillionniumFoundation/Hepta/blob/bdb0b39c99b7980b98cb3f9e07ba406cc20f0940/docs/HIA_NDU_IMPLEMENTATION_20261027.md)。

## 附件导航

- `path-and-merge-summary.json`：完整两侧路径集、交集与每文件冲突数。
- `merge-preview/`：三份只读三方文本结果，保留冲突标记。
- `remote/`、`base/`、`local/`：关键文件的固定快照；`remote-ndu/` 为固定私库源码快照。
- `fetched-source-manifest.json`、`fetched-source-manifest-extra.json`、`fetched-ndu-manifest.json`：GitHub URL 与原始 blob SHA。
- `ndu-source-inventory-comparison.json`：两套原生生产源记录的逐路径比较。
- `peer/API_COMPARISON.md`：完整证明、solver、运行时 API 与生命周期对照。
