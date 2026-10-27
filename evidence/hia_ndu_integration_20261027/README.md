# HIA / NDU 可执行集成与保留证据 — 2026-10-27

本轮交付了真实 NDU 编译候选链路、资源解释执行扩展、迁移正确性修复及解释器版本切换。**两轮固定预算 NDU 实验均选择 `no_change`；严格 Rust 性能对照为 `measurement_inconclusive`。P4 尚未取得可验收的净收益，P0–P7 没有整体完成。**

交付在 [Draft PR #326](https://github.com/TrillionniumFoundation/Hepta/pull/326)，叠加于 [PR #323](https://github.com/TrillionniumFoundation/Hepta/pull/323)。测试与性能运行绑定的代码提交是 [`34c5526ff87ec1208a88f8c86c806fde39505737`](https://github.com/TrillionniumFoundation/Hepta/commit/34c5526ff87ec1208a88f8c86c806fde39505737)。运行完成后的提交增加本证据目录，并澄清一份 NDU 文档的三处表述；可执行实现及测试保持该冻结版本，最终提交的完整 Git tree 与测试时不同。没有合并 PR，也没有把远端 CI 当成本地结果的替代品。

机器可读入口：[integration-summary.json](integration-summary.json)。原始日志、命令、逐模块发现清单、历史失败和保留产物位于 [raw-evidence.zip](raw-evidence.zip)；[evidence-manifest.json](evidence-manifest.json) 与 [SHA256SUMS](SHA256SUMS) 记录文件身份。

## 本轮实现与阶段验收

| 阶段 | 已交付的可审查增量 | 验收状态及剩余义务 |
| --- | --- | --- |
| P0：收敛语义 | 沿用共享 Core 版本注册与重验入口；JSON 预检拒绝孤立 surrogate、序列化后的键名碰撞，并计算包含键与标点的累计编码预算 | 有限入口修复已验证；所有新增前后端和兼容适配器仍须服从同一语义与旧正确性约束 |
| P1：资源模型 | 保留既有 owner/loan/composite 规则；补充跨调用所有权转移、形式借用身份与只读别名的执行对照 | 未完成一般 typed place、布局、初始化、逃逸借用、异常析构、完整取消和并发模型 |
| P2：编译链 | Rust 共享 VM 增加 CFG、循环、受界调用与 byte-owner 执行；保留完整资源账本对照及独立原生分配器控制 | 有限 profile 有执行证据；未证明全编译器 refinement、任意资源或平台安全 |
| P3：NDU 候选 | 计划、精确候选复现、重验、产物/证据身份、原生测量、实际上游 NDU 与 `abstain` 连通；两轮均完成真实选择 | 一个注册变换的闭环已执行；更广变换空间仍需逐项证据；无自动激活、全局最优或通用等价证明 |
| P4：实际收益 | 两轮预声明 31 对测量及一轮未放宽门槛的 63 样本 Rust 对照；保留所有样本、失败与成本 | **未验收**：未建立重复净收益；实际工业热函数、完整开发/模型/维护成本仍缺证据 |
| P5：扩大迁移 | 修复 C/C++ 编译捕获的选项、源文件写法与 cwd 语义；五个真实反例修复，2,086 次原生结果执行 | 有限迁移范围通过；任意工程、自动资源契约、广泛对象模型、桥接比例与人工维护成本未验收 |
| P6：动态优化 | 解释器真实调用的版本固定、显式激活 CAS、在途引用排空、退役与回退 | **仅解释器范围**；原生热替换、活动外部借用、回调、任务与外部状态切换未验收 |
| P7：系统资格 | 冻结源码回归与明确失败复验；工具、代码和原始记录绑定 | 未执行完整 35 门资格计划；多物理平台、复杂资源长期负载和独立 Agent 成本实验未完成 |

实现范围详见 [NDU 候选链路](../../docs/HIA_NDU_CANDIDATE_PIPELINE.md)、[Rust byte-owner VM](../../docs/HIA_RUST_BYTE_OWNER_VM_20261027.md) 和 [解释器版本切换](../../docs/HIA_LOCAL_VERSION_DISPATCH_20261027.md)。

## 回归结果：区分一次运行与补充通过记录

| 执行 | 原始结果 | 解释 |
| --- | --- | --- |
| 冻结提交的 Rust 测试 | 52 项通过，0 skip | 实际 shadow 测试使用 Rust/Cargo 1.99.1；源语言后端与性能参考另使用锁定 Rust 1.90.0 |
| 单进程 Python 全发现 | 发现 2,576 项；1,800.0687 秒超时 | 没有完整 unittest 结果计数，不能推算部分通过数 |
| 四 worker、逐模块新进程 | 263 个模块完成，260 个通过；实际执行 2,571 项，2 failure、1 setup error、0 skip | 2,576 个唯一发现 ID 与原始清单完全一致；setup error 阻塞 5 项执行；耗时 686.807 秒 |
| 三个受影响模块完整串行复验 | 17 项通过，0 failure/error/skip；29.395 秒 | 安装哈希锁定的 Rust 1.90 Thumb 标准库，保留原测试与时间门槛；主机编译器、native 标准库和源码未变 |

通过记录覆盖 **2,559 个原先通过模块中的 ID + 17 个完整复验 ID = 2,576 个唯一测试 ID**。分模块执行与复验共 2,588 次测试执行观察，含 12 次重复；这不能表述成“单次 2,576 项全绿”。原始单进程超时及分模块失败报告均保持原样。

两个失败模块缺少 `thumbv7em-none-eabi` 目标组件。另一项原生隔离测试在 0.35 秒预算内先超时，未观察到期待的 SIGSYS；完整模块在同一门槛下串行复验通过，但这不证明并发负载就是原失败的唯一原因。

查看 [单进程摘要](tests/monolithic-summary.json)、[分模块摘要](tests/partitioned-summary.json)、[串行复验摘要](tests/serial-rechecks-summary.json) 与 [进程退出记录](tests/recheck-process-completion.json)。

局部 P2 开发记录另保留 59 项 Python 测试、124 + 105 = **229 次 Rust/Python 完整资源账本对照**。它们属于记录中的提交前 worktree；32 个记录源文件哈希与冻结版本一致，但没有改写历史运行身份，也不额外加到全量测试分母中。Rust 动态 `--owned-run` 支持有限 CFG/call byte-owner profile，**不执行 `buffer.swap`、bulk、chain 或 composite 输入**。静态 `--owned-shadow` 的能力不能代替动态执行证据。

## NDU：真实闭环完成，两轮均保留基线

实际调用 `hepta-private-ci` 提交 `f8c9419df6ddeb36ff8b522a50219981fb8d9345` 的 `evaluate_candidates_with_policy`。构建和运行身份见 [构建 provenance](provenance/ndu-build-provenance.json)。

两轮事先固定相同预算：20 个计时输入、31 对样本、每个后端每样本 200,000 次调用，每轮共 **12,400,000 次计时调用**，另有 40 次逐输入原生正确性调用。每轮 50 次语义观察比较返回值、trap 与完整资源账本，全部匹配。这是同一个 Python VM 对两个 Core 的执行对照；该链路没有在 Rust VM 中动态执行 swap 候选。计时路径的正常结果检查也不替代独立原生 trap/分配失败资格。

| 读数 | 第 1 轮 | 第 2 轮 |
| --- | ---: | ---: |
| 基线中位数，ns/调用 | 24.364850 | 24.421400 |
| 候选中位数，ns/调用 | 27.332045 | 23.312350 |
| 基线 / 候选相对 MAD | 17.446% / 17.604% | 11.440% / 9.921% |
| 配对节省中位数，ns/调用；负数为退化 | -3.150995 | +1.693250 |
| `qualify()` 内实际已付墙钟成本 | 1.266365 秒 | 1.172339 秒 |
| 完整 CLI 进程墙钟成本 | 1.420805 秒 | 1.327943 秒 |
| 实际 NDU 建议 / 主机决定 | `abstain` / `no_change` | `abstain` / `no_change` |

两轮的基线与候选原生库都具有相同 SHA-256：`527992d971d479b12a0a8ef033745527f36764df081bc78ba4ac3d0ee94421d1`，大小均为 15,432 字节。**这次不同 Core 没有产生不同的原生库；表中的时间波动不能作为机器码优化收益。**

两轮噪声均超过预设 5% 门槛，配对节省未超过噪声余量；按声明的 1 亿次调用 horizon，预计节省也不能覆盖搜索成本与预留的 2 秒决策预算。实际上游响应为 `InfeasibleExplicitAbstain`，候选被硬约束拒绝，`authority=DENY_ALL`，没有激活代码。第 1 轮的退化和第 2 轮看似有利的读数都保留，未删样本、挑选最好一轮或重复直到通过。

`qualify()` 成本不含 CLI 初始读入、预验证、Python 启动及最终报告序列化，因此同时列出完整进程成本。两者均不等于安装工具链、构建 evaluator、人工研发、模型、能耗及长期维护总成本。horizon 是工作负载假设，MAD 过滤也不是统计置信证明。

原始读数：[第 1 轮](performance/ndu-pair-1.json)、[第 2 轮](performance/ndu-pair-2.json)、[预声明计划](performance/plan.json)、[运行与完整进程成本](performance/execution-summary.json)。

## Rust 对照：正确性有限通过，性能结论不成立

未修改既有 `hepta.hia.program.perf.v3` 门槛：3 个内核 × 3 个后端 × 7 个配对组，共 **63 个样本**；参考为 Rust 1.90.0 的同源 checked Rust 与独立手写 safe Vec/slice Rust。完整命令运行 239.605 秒，退出码 1，状态为 **`measurement_inconclusive`**。

9 个“内核 × 后端”组的相对 MAD 均超过 5%，范围 7.109%–23.772%。描述性几何平均配对时间比为 LLVM/同源 Rust **0.914861**、LLVM/手写 Rust **0.913645**；测量质量门槛未通过，这两个数字不能换算成已证明的提速或净收益。

独立于性能判断，588 次有限原生结果观察全部匹配。未计时的 LLVM 分配器正控制观察到 7 次分配、7 次释放、0 个存活分配及 1 次拒绝；删除释放的负控制观察到 7 次分配、0 次释放、7 个存活分配及 1 次拒绝，并被拒绝。这不构成 Rust 与 HIA 所有分配器行为的一般等价证明。完整数据和产物身份见 [Rust 对照报告](performance/rust-comparison.json)。

## 迁移：原语言参考揭示并修复五个错误

| 反例 | 原实现 | 修复前解释器 / 原生 | 修复后解释器 / 原生 |
| --- | ---: | ---: | ---: |
| `-O2` 预处理分支 | 8 | 9 / 9 | 8 / 8 |
| `-pedantic-errors` 内建分支 | 9 | 8 / 8 | 9 / 9 |
| 相对 `__FILE__` / include | 9 | 8 / 8 | 9 / 9 |
| 符号链接源路径 / quoted include | 9 | 8 / 8 | 9 / 9 |
| C++ 模板源文件身份 | 41 | 157 / 157 | 41 / 41 |

修复保留影响语义的选项及顺序、词法源文件参数和原 cwd；绝对规范化路径仅用于身份识别。修复前两个 Hepta 执行路径彼此一致却共同偏离原语言，说明只比较解释器与后端不足以证明迁移正确性。查看 [修复前](migration/capture-before.json)、[修复后](migration/capture-after.json) 与 [10 条原语言命令核对](migration/reference-command-audit.json)。

C 矩阵 816、C++ 矩阵 816、C++ 模板项目 454，共 **2,086 次原生结果执行**，包含原实现与 HIA 两侧；对应案例/配置比较 1,043 次，不能称 2,086 个独立迁移模块。三个 corpus 都是仓库中的受控项目 fixture，不是外部生产模块。输入分母为 10 条编译命令、144 条 active 声明记录及 29 条跨配置具体函数转换记录；声明和函数记录会随配置重复，不代表同样数量的独立模块。目标未链接原 C++ 函数体，也不能据此声称真实工程 100% 转换或一般 C++ bridge 已获资格。完整分母见 [迁移范围计数](migration/scope-counts.json)。历史 44 项回归中的 3 次 Rust pin 失败、随后 3 项精确复验通过及测量仪器的初始失败记录均保留在原始证据包中。

## 可信基础与复现边界

Core 验证器、运行时、LLVM/Clang、Rust 工具链、链接器/加载器、分配器、操作系统、硬件与主机进程完整性仍属于声明的可信基础。主机独立重算候选 support digest，并核对候选身份、objective、generation、覆盖范围和 `DENY_ALL`；对 evaluator/policy/profile 的三个摘要仅检查非零小写 SHA-256 格式，真实性依赖固定 Rust evaluator，不是独立重新计算全部 NDU 结果。

原始 `source_was_committed=false` 保留：完整输入快照含 1,113 个与冻结提交匹配的 Git 普通文件，以及一份忽略的构建 provenance。参见 [补充源绑定](provenance/source-binding.json)。运行后的单文档澄清明确了上述可信边界、同一 Python VM 的双程序对照以及 CLI 成本范围，没有重新给历史记录贴上新 tree 的身份。

所有最终测量在测试进程结束后串行执行，固定到一个允许的逻辑 CPU；没有独占该 CPU，也未宣称运行于不可用的物理主机。原始记录足以审查这次有限实验及失败原因，不能替代一般语言安全、所有负载性能、任意 C/C++ 低成本迁移、原生动态更新或完整 P7 系统资格。
