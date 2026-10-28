# Hepta 智能汇编：系统闭合进展与验收边界


## 结论与源码边界

Hepta 已形成可独立准入和执行的、带类型与资源约束的 HIA Core，并接通独立 Rust 执行、原生下降、有限候选生成、实际 NDU 评估和原生版本生命周期。此次补上了 v7 chain 的独立执行、checked 无符号归约候选、完整测试清单核对，以及子进程清理失败后的隔离和恢复。

**完整目标仍未关闭。** 历史冻结运行完成全部 35 个门槛，34 个通过，性能门槛因测量噪声未取得资格。两次预注册归约实验都保留 `no_change`。目前没有真实应用热函数的可重复净收益，也没有任意 C/C++ 低成本迁移、独立 Agent 开发成本优势、全语言安全或全局最优的证据。

| 证据层 | 源码身份 | 可以支持的结论 |
| --- | --- | --- |
| 历史完整运行与归约实验 | `b92141483ca5084691f436d28d4cd0dcbefe4717` | 本文列出的历史测试、35 门槛、原生借用 v1 和两次 NDU 实验 |
| 修正后的当前源码 | `de49fe3e0254b7b71dbcb5b2907a3f3145999393` | 清理与计数修复；本次当前源码的执行资格由其自身最终回执决定 |
| 开发及审阅证据 | 每份回执记录的文件散列 | 复现具体缺陷、检验修复和审查实现；不替代完整冻结运行 |

当前源码的完整单元门槛已完成：**274 个模块、2,706 个唯一测试 ID**，两个 worker、零重试，失败、错误、跳过、预期失败和 unexpected success 均为零。Rust Cargo 门槛也已完成，**56 项测试、10 个测试 binary 汇总**，失败、ignored 和 filtered out 均为零。完整资格链及独立原生借用 v2 的最终结果如下；单元与 Cargo 通过数不另加为系统级验收结论。

| 当前源码项目 | 最终回执 |
| --- | --- |
| 全 35 门槛及未取得资格的门槛 | 35/35 项执行完毕，34/35 项通过；未合格项：standalone_performance；`scoped_gates_not_all_qualified` |
| 完整单元与 Cargo | 已完成：274 / 274 模块、2,706 / 2,706 唯一 Python ID；Rust 56 项，所有失败/遗漏类别为零 |
| 源码与工具前后身份、当前 commit、最终记录完整性 | 源码 `de49fe3e0254b7b71dbcb5b2907a3f3145999393`；运行前后源码及所选工具身份均未变化；完整检查点、报告和日志见当前源码审计。 |
| 当前源码 standalone performance 的资格、噪声与退化结果 | `measurement_inconclusive`；保留 63 个样本；固定 MAD 门槛失败 8 项，性能比值门槛失败 0 项；没有删样本或改变接受标准。 |
| 当前源码原生借用 v2 的尝试、子进程启动/回收、完成、入口证据和排空 | `passed`；尝试 7，确认启动 7，确认回收 7，完成观察 7，有入口证据 6；入口结果不可用 1，总入口调用数 `null`；最终 drained=true，释放 3 个映像。 |

修正版只重新执行当前源码的完整资格链和独立原生借用资格器；**不会重复这两次预注册 NDU 计时，也不会把它们改记为 `de49` 的测量。** 即使当前 35 门槛全部通过，本文后续所列扩大语义、真实工作负载、外部状态、长期运行和开发成本义务仍分别成立。[历史运行审计](audits/collector-frozen-execution-final.json) 与 [候选执行审计](audits/candidate-execution.json) 保存了对应边界。

## 1. 已落地的有限实现

### P0：唯一准入与可核对的完整测试清单

独立 HIA 路径以 `hepta.hia_program.verify_core` 为准入入口，`hepta.core.verify_core` 和 `verify_program` 暴露同一能力。primitive v1–v7 与 composite v1/v2 使用不同命名空间；composite v1 规范化到 primitive v6，composite v2 到 primitive v7，再对完整输出重验。`CANONICAL_CORE_SCHEMA` 的 v6 与 `LATEST_CORE_SCHEMA` 的 v7 有明确职责，不能无条件升级后丢掉身份。历史歧义 nominal-v2 必须经过显式适配器，不能靠字段猜测语义。[规范](../../docs/HIA_PROGRAM.md)

兼容入口保留原有检查，再翻译实际操作并重验。历史 Rust/C/source LLVM 和保留外部实现的桥接路径继续使用其声明的合约；它们的测试不能赋予 standalone HIA 尚未编码的功能。空 owner 析构不引入多余 `free(NULL)` 的旧修复继续保留。[集成约定](../../docs/HIA_SEVEN_STAGE.md)

完整单元门槛采用每模块独立进程。独立发现的 expected IDs 必须逐一 start/finish，模块或 ID 遗漏、重复、跳过、预期失败、日志与回执不一致不能变成通过。源码快照只排除两个明确的生成 Cargo target 根；NDU 上游导出和 build provenance 单独作为依赖输入记录，不冒充 Hepta 已提交源码。只读审阅核查了这些边界，审阅次数不计作测试次数。[收集器源码审阅](audits/collector-source.json)

### P1、P2：同一 primitive Core 的独立 Rust 资源执行

Rust 的 `--owned-run` 采用 `cfg-call-byte-owner-chain-v4`，在已有字节 owner/loan、CFG、内部资源调用和六类 bulk 操作之上，执行六个 v7 chain 操作及 chain move/drop。默认标量模式仍拒绝资源程序；公开输入和返回只接受标量，内部 owner/loan 句柄不能由 JSON 参数伪造。Rust 先独立检查完整 primitive 文档，执行指令时不调用 Python 或 LLVM。[Rust chain 执行规范](../../docs/HIA_RUST_CHAIN_VM_20261027.md)

chain 节点存储和 payload 共用语言 heap、allocation-attempt 和失败注入序列；节点存储计入 24 字节。析构用显式迭代，并在逐节点销毁前计步；预算中断后留下的节点和字节仍留在语言账本。宿主容器最终释放不冒充语言 `owner.drop`。执行边界为一百万步、包含根调用在内的 32 帧及 16 MiB 语言 heap；这些数字不等于进程 RSS 上限。

历史冻结运行记录 **1,830 次 Rust/Python 完整账本对照**：基础 owner 124、CFG 106、bulk 1,231、chain 369。比较同一 Core 的状态、停止码、结果、精确步数和完整资源字段。另有 **95 次所选 bulk/chain 原生控制 = 60 + 35**；这些输入与前述语料重合，不应相加为 1,925 个互不相同案例，也不包含另外的 CFG 原生控制。raw nominal/composite 仍由 Python 展开为 primitive 后交给 Rust；该对照不证明展开器。[执行分母审计](audits/collector-unit-execution.json)

### P3：第三个注册候选与独立算术证明

`checked-unsigned-reduction.v1` 把严格匹配的、从零开始的无符号 checked 重复加法替换为 checked 乘法。匹配要求固定 unsigned 类型、唯一前置块和回边、单位增量、不变 count/value、原样传递其余参数；循环中不能夹带读写、调用、分配、析构、借用转换或其他 trap。出口和其他操作顺序保留，完整 Core 再次验证。公共规则保留 primitive v1–v7 身份；NDU 适配器仍限定 primitive v1–v6。[规则说明](../../docs/HIA_CHECKED_UNSIGNED_REDUCTION.md)

有限控制包含 **1,454 对优化前后 Core 观察，即 2,908 次执行**，分解为整数边界 1,394、外层 trap 次序 6、分配/借用/拒绝 32、活动 formal loan 4、最终 index 5、count 同时作为 addend 6、版本与 v7 共存 7。输入可重合，不能把这一分母等同于唯一测试方法。另有 16 次真实 native u32 观察（8 输入 × 两个库，10 次返回、6 次 SIGABRT）。不同原生产物只是代码变化证据。

Lean 独立定义自然数上的 checked 重复加法和 checked 乘法，证明 optional 结果相同、overflow 一致和 index 增量界。把初值零改为一、去掉乘法 overflow guard 的两个变异被拒绝。该证明没有连接 Python matcher、CFG、资源验证器、LLVM 或 ABI；Lean kernel 与记录的 `propext`、`Quot.sound` 仍在可信基础中。指令预算、宿主中断/调度与宿主分配失败不在此可选优化的等价性承诺内。[Lean 文件](../../formal/HiaCheckedReduction.lean)；[源码审阅](audits/candidate-source.json)

目前三个注册规则为 byte-swap、full-view-fill-loop 和 checked reduction。计划、Core、实际产物、语义验证、测量和评估内容均绑定身份；NDU 是 advisory，`DENY_ALL` 不授予安装权限。有限规则和有限候选集的选择不建立任意程序的全局最优性。[候选链](../../docs/HIA_NDU_CANDIDATE_PIPELINE.md)

### P6：清理失败也保留所有权

历史原生源码审阅发现两个缺口：回收确认失败后仍可能释放 dispatch 引用；失败报告用 attempt 数冒充实际子进程数。修正版增加实际 `Popen` 的 cleanup owner、逐调用 ID、quarantine、有限重试和幂等释放。回退及关闭不能提前释放尚未确认回收的版本引用；恢复不会重跑入口，也不会把先前失败改成成功。进程组只在首次清理时尝试 signal，后续重试不向可能被复用的 PGID 再发 signal。

独立作者复核又发现两个交互边界：父端关闭异常可覆盖 pending-reap 异常；长持有的回收锁可阻塞零期限重试及经快照间接阻塞调度锁。新增三个真实子进程控制先在旧草稿复现 **2 个错误、1 个失败**，修复后 **3/3** 通过。最终使用短持有的元数据锁与有期限的回收串行锁，并在最外层根据实际 cleanup 状态决定隔离；次级关闭错误作为有限诊断保留。

此次共增加 **9 个回归方法：新 cleanup 模块 8 个，加 producer 计数负例 1 个**。完整专项 **43/43、零跳过**；三个修复控制和九个新增方法都包含在该 43 项中，后续完整单元运行也包含它们，不能重复相加。全部八个文件与打包补丁、专项运行前后散列一致。[v1 审阅及发现](audits/native-cleanup-review-v1.json)；[v2 独立审阅](audits/native-cleanup-review-v2.json)

v2 回执区分 admission/attempt、观察到的子进程启动、确认回收、完成观察及实际入口证据。Popen 成功只证明创建了子进程；没有借用握手或正常返回的 pre-loan SIGABRT 不能独立证明入口调用或 trap 原因。底层观察器调用者必须保留 pending exception 的 cleanup owner；dispatcher 的排空保证要求宿主持有 dispatcher 到排空完成。它不提供崩溃持久化恢复或硬实时内核完成保证。[原生版本生命周期](../../docs/HIA_NATIVE_VERSION_DISPATCH_20261027.md)

## 2. 历史 `b921` 的完整运行

历史运行已经结束：**35 个门槛全部完成，34 个通过，`standalone_performance` 未取得资格**；源码和所选工具记录前后未变化。完整单元为 **273 模块、2,697 个唯一 ID，失败、错误、跳过、预期失败和 unexpected success 均为零**。Cargo 为 56 项测试；另外选出的 Rust parity 77 方法和 agent-query 53 方法属于上述完整发现集的重新执行，不新增唯一 ID。完整证据与重算范围见 [最终执行审计](audits/collector-frozen-execution-final.json)。

该运行覆盖声明范围内的语义、资源、源码适配、原生/ABI、C/C++ 配置与桥接、平台和形式化门槛。Linux x86-64 GCC/Clang 是实际宿主执行；AArch64、RV64GC 为 QEMU 执行；Cortex-M4 板级控制是历史 Rust/no_std BSP 的 QEMU 路径。不能把这些合并写成所有平台上的原生 HIA 或物理设备资格。

standalone performance 保留全部样本、16 个产物和退化方向。5 个测量单元的相对 MAD 超过固定上限，结果为 `measurement_inconclusive`，不是速度优势结论。独立审计重新计算了统计值和固定顺序，没有重新运行大量 checksum 调用，也没有挑选有利样本。

另一个、位于 35 门槛之外的历史 native-loan v1 资格器完成七个固定子进程控制：四次正常返回、两次 trap 和一次预期 timeout，保留三个诊断 image。它观察一个 local byte loan 及端点字节，不观察完整账本或全部内存；其正常路径成功不能覆盖后来发现的回收失败漏洞。`de49` 的 v2 结果使用前面的独立最终回执。

## 3. 两次预注册归约实验：保留失败与 no-change

协议在 `b921` 固定为两次尝试；每次 18 输入、31 对样本，每个 backend/sample 重复完整语料 50,000 次，即每侧样本 900,000 次调用，计划每次 **55,800,000 次 timed 调用**，另有 36 次 untimed 正确性调用。没有删除样本、放宽 5% MAD / 2% 收益门槛或重试直到通过。[固定协议与入口](../../experiments/hia_checked_reduction_20261027/README.md)

| 项目 | 第一次 | 第二次 |
| --- | ---: | ---: |
| 结果 | failed_closed_no_change | completed_no_change |
| 完整配对样本 | 30 / 31 | 31 / 31 |
| 完整计时样本记录 | 60 | 62 |
| 可确认的完整样本内 timed 调用 | 54,000,000 | 55,800,000 |
| untimed 正确性记录 | 36，全相符 | 36，全相符 |
| 实际 NDU evaluator | 未运行 | 已运行，abstain / DENY_ALL |
| 内部已支付墙钟秒 | 33.002678969 | 20.884716247 |
| 完整 CLI 墙钟秒 | 34.530551280 | 21.304591250 |

第一次触发原生驱动固定 30 秒限额；未报告样本中的额外调用数未知。两次只能确认完整样本内共 **109,800,000 次 timed 调用**，不能把计划总数 111,600,000 当成完成数。第一次的 36 条正确性记录相符，但 measurement 的成功标志仍为 false，本报告不升级该失败。

第二次用全部 31 对样本重算得到基线 MAD **6.1063%**、候选 **12.3740%**，均高于 5%。对应拒绝理由为 `baseline_timing_noise` 与 `candidate_timing_noise`。100,000,000 次调用 horizon 下的成本投影是工作负载假设，不能绕过噪声门槛。实际 evaluator 返回 `InfeasibleExplicitAbstain`；宿主未激活代码。

两次的基线、候选和驱动均保留。基线和候选各 15,360 字节，SHA-256 分别为 `0abb0f63a8ab24cfe0791bc845249d2cae10d97ac1b09224628a5546e835ae1e` 和 `adcfb63c5f0774dc086facf8a0020f5d1826e9d2cd6b2b221574ca4fb2e4bece`；两侧使用相同 Clang 和后端参数。八个保留文件（含 driver.c）已与测量前记录核对，第一次缺少成功后保留清单的事实也保留。二进制不同不等于可重复加速。[候选执行审计](audits/candidate-execution.json)

两次内部已支付时间合计 **53.887395216 秒**，CLI 合计 **55.835142530 秒**，整个协议过程 **65.648198148 秒**。这些计时边界相互包含，不能相加。工程实现、模型/工具安装、人工审查、长期维护及生产切换成本不由这些数字代表。

## 4. 真实模块与迁移范围

本轮额外核对了现有、固定来源的真实模块，未找到可直接匹配三个现有注册规则的上游热函数。该排查完成了输入可行性确认，没有关闭工业 P4。[完整排查](audits/real-workload-feasibility.json)

| 来源 | 固定身份及当前能力 | 与当前优化规则的距离 |
| --- | --- | --- |
| AndersKaloer/Ring-Buffer | `8de8fff55a0baee4fef2a1c6a82d258a27c3c0ba`；完整模块、调用者资源契约、状态对照和构建配置证据 | queue/dequeue 数组循环有数据读写、辅助调用、head/tail 更新和早停；批量复制需要新变换及完整状态/别名论证 |
| fragglet/c-algorithms | `23d453792ed89a28ed7d2c8d4311a4d9f7822edd`；保留的 compare-int / hash-int 模块 | 无相应循环、byte-view swap 或 full fill |
| nlohmann/json | 3.11.3 / 3.12.0，完整头文件内容散列固定；真实 C++ 桥接/升级边界 | 现有 sum 是 authored adapter 的有符号、数据相关求和；桥接保留 C++ 实现 |
| Hepta `OwnedBytes::fill` | 仓库自编 owner 迁移样例 | 源码接近 full fill，但当前 Core 下降的长度位置和逐次 loan 事件不匹配现有严格规则；不是工业来源 |

现有 Ring-Buffer mode 1 基准在 1024 字节环形缓冲区上重复 64 字节入队/出队，是可复现的库操作负载；它没有生产轨迹或应用热度证据。不能删掉持久状态、别名约束、未写入输出和 backing bytes 来强迫优化规则通过，也不能把普通 C unsigned 回绕运算改标为 checked 运算。

C 迁移、standalone HIA 和 C++ 保留实现的桥接必须分别报告。输入有处置、限定配置通过，与自动恢复任意资源合约、全项目转换比例和低人工成本是不同问题。真实模块路径使用的人工契约及 foreign 实现仍是合约/可信边界的一部分。[C 迁移](../../docs/C_MIGRATION.md)；[C++ 项目 HIA](../../docs/CPP_PROJECT_HIA.md)；[C++ 上游升级](../../docs/CPP_UPSTREAM_UPGRADE.md)

## 5. 阶段验收与剩余义务

下表区分限定 profile 的已有证据与原始完整目标。机器可读逐项记录见 [blockers.json](blockers.json)。阶段号不沿用早期记录中不同的编号含义。

| 阶段 | 已有证据 | 当前验收结论与后续义务 |
| --- | --- | --- |
| **P0 收敛语义** | 唯一 registry/入口、显式适配、版本保留、独立完整 ID 收集 | 当前 `de49` 的语义/兼容/旧修复门槛、完整 ID 与源码身份已核对；该有限 profile 的当前回执义务已关闭 |
| **P1 资源模型** | 有限 byte owner/loan、field/nominal 组合、chain、失败与取消控制 | 为扩大的 typed place、通用递归结构/树、逃逸 stored borrow、异常/取消/并发定义统一操作语义，并实现检查、执行、下降及正负控制 |
| **P2 编译链** | 同一 primitive Core 的 Python/Rust/native 对照、有限 Lean 性质、明确 TCB | 当前源码已有路径的实跑和对照已完成；扩大 profile 时对应增加独立实现与原生账本/陷阱/副作用对照；广泛安全或精化主张需额外证明，不能由单个算术定理代替 |
| **P3 NDU 候选** | 三个注册规则、真实候选身份/编译/证据/评估/no-change | 扩大候选时固定目标、输入域、候选空间与预算，验证每个变换并保留不可行结果；有限候选选择不升级为任意程序全局最优 |
| **P4 实际收益** | 同预算预注册实验、失败和 no-change、实际产物及付费成本 | 一个有来源的真实热函数及代表负载；固定噪声/收益门槛，取得可重复净收益并计入生成、验证、编译、测量和适用的切换成本；保留退化 |
| **P5 扩大迁移** | C 构建捕获、固定上游模块、有限 owner/template 转换和 C++ bridge | 对实际项目全部 TU/配置/声明给出处置；核对转换/桥接/拒绝分母，验证契约来源；记录人工编写、修复、审查及一次真实上游升级维护成本 |
| **P6 动态优化** | 后台编译、sealed image、generation、逐调用 pin、隔离/恢复、回退 | 当前 v2 实跑已通过；持久回调、活动外部借用、任务和共享状态的迁移合约与失败恢复；实际并发切换/取消/回退证据和生产开销 |
| **P7 系统资格** | 有限 35 门槛、QEMU 平台、已有 Agent/应用实验入口 | 实际目标宿主/设备执行、完整锁定 Agent 实验及长期并发负载；性能、资源、安全、迁移、开发成本各自达标，不用某一维通过代替其余维度 |

### P7 的可执行入口与具体缺口

已有 atomic-maintenance study 定义两个模型家族、四任务、四接口，共 32 个 task request、4 个 preflight 和 32 个 native control。`p7-assets` 审计时，两个锁定权重路径均不存在，PATH 未发现 `llama-server`；锁定权重共 7,377,193,632 字节，当时可用空间为 729,915,392 字节。这是带时点的资产观察，不是完整宿主搜索或永久资源结论。需要原锁定内容、可用固定 runtime 和足够资源后，按原计划运行并保留失败/未完成单元。即使该有限 study 完成，也不等同于独立工业维护任务或总人工成本优势。[P7 资产审计](audits/p7-assets.json)；[实验计划](../../experiments/hia_atomic_maintenance_20261027/README.md)

现有 application gate 的 3 trials、96 个顺序 ABI 请求和 16 次 warmup 是有限负载。长期资格还需要预设持续时间、并发与失败/切换安排，观察吞吐、尾延迟、allocator/RSS、泄漏、排空和恢复。其他原生 OS/ABI、物理 MMIO/IRQ/DMA/GPU 也需要相应后端、runtime/BSP、设备资源合约与实际执行；不只是补一个外部设备就能关闭的软件工作。

这些源码审阅不计作独立 Agent 生产率实验。审查者身份在 JSON 中保留：归约等部分源码审查由实现作者完成，清理 v2 有不同作者的独立审阅；它们各自支持具体实现审查，不支持模型开发成本结论。

## 6. 证据与复核方式

[README.md](README.md) 给出文件地图、源码边界和证据复核步骤；[原始证据包重组清单](raw-evidence-parts.json) 与 [成员清单](raw-evidence-manifest.json) 用于保留完整命令、stdout/stderr、失败记录、源码/工具身份和实际产物。归档全部成员已重新打开，并与成员清单核对路径、普通文件类型、大小和散列。历史 ZIP 与早期失败记录保持原样。

本文的有限结论分别依赖 Core 准入、独立执行、变换合约、实际工具链和宿主。Python verifier/展开器、LLVM/Clang、linker/loader、libc/allocator、操作系统及所列 Lean 基础仍属于各自的可信基础；源文件或回执内容 hash 不等于独立平台认证。所有不足保留在阶段账本中，完整 P0–P7、工业收益与全语言安全标志仍为 false。

## 当前源码审计与工具来源

当前单元及完整执行证据分别见 [单元审计](audits/collector-corrected-unit-execution.json)、[完整执行审计](audits/collector-corrected-frozen-execution-final.json) 和 [机器可读汇总](results.json)。

Core 资格与 Rust 性能对照使用实际 Rust/Cargo 1.90.0。固定 NDU 桥接程序的构建记录为 Rust/Cargo 1.99.1，其二进制 SHA-256 为 `ada753864ff3bcf03f56fbbc6cc0884259fdf513565bbf6499e19f1c6e93d3e8`，上游 pin 为 `f8c9419df6ddeb36ff8b522a50219981fb8d9345`。它没有在本次资格运行中重建；归档 `dependencies/ndu-build-provenance.json` 保存原构建回执，没有包含私有 NDU 源码或实现二进制。

## 证据包发布恢复

大对象发布中断后，同一份归档改为 33 个有序二进制分片，每片最多 786,432 字节。按 [README](README.md) 的命令重组；脚本逐片核对，再验证完整归档散列，并拒绝覆盖已有输出。重组后仍为 25,521,872 字节，SHA-256 为 `6b2d39d9d1cdc3263859527310285f83b27cf83009fb4b7f42a538f569b0bc61`。全部 7,490 个原始成员内容不变，源码身份、失败记录和验收结果没有因发布恢复而改变。
