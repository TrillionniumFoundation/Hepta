# HIA 七项推进：源码交付与严格验收读出

日期：2026-11-01。实现提交 `5e719795683b03da16fe9860b87b4694387aeca9`；受检与生成前注册提交 **`a9be5fb5ac2231e731e750237f64818a6d0d623f`**，tree `4be944cb2a2a4cda678dc1ff1d5a77307148696c`。基线为 `c393b8fe7360e45343f090665d519108656280bf`。本轮实现与注册修改 32 个文件，新增 2,503 行、删除 156 行；文档归档提交另记，不混入实验源码身份。

本轮交付了可运行的源码增量、固定组合、独立读出和原始证据。严格验收按下表判断。实验进程成功结束、正确性通过、限定性质得到证明和优势成立分别计量。

## 1. 七项验收总表

| 优先级与目标 | 本轮实际落地 | 严格验收状态 |
| --- | --- | --- |
| P0 统一源码组合 | 固定 HIA 头、四个原始 NDU bridge、验证器、编译器和协议；同一源码执行正常、拒绝、恢复及目标资格 | 限定组合通过：完整1,429项回归、原生及目标正常/拒绝/恢复验证；源码、工具与协议身份保留 |
| P0 可证明的核心 | totality 的工具/实现身份与全程 deadline；全部公开 scalar export 的 totality + actual LLVM 组合资格 | 限定数学模型的普遍定理和具体程序全输入性质成立；整个生产 Core 的类型/所有权 soundness 未闭合 |
| P0 性能差距 | 三项 checked-add 归纳义务与 modular narrowing 组合为 `verified-reduction-narrowed-release-v1` | 观察有效；25/30比较通过，Rust9/10；五项p99失败，严格性能门槛未通过 |
| P0 NDU 净收益 | invoke/skip、未来决策、stop、可逆驻留、重准备与 holding 成本进入模型；执行同信息 DP/native 对照 | 未证明净收益；本轮实际策略阶段 invoke=0，对强固定策略的三个服务成本比较均失败 |
| P1 C/C++ 迁移 | 实际 GSL RAII/factory 升级、两版 JSON foreign 生命周期与分配故障恢复；修复 fork owner/lock 问题 | 所列行为、生命周期和有限 ABI 通过；人工成本与普遍迁移效率未得到证明 |
| P1 Agent 开发优势 | 两模型 × 两语言 × 两项 API 维护任务，生成前冻结、作者控制、独立审查和完整分母 | 8 个单元均在客户端初始化阶段失败；没有观察到生成，优势与每成功任务完整成本不可判定 |
| P1 并发与硬件 | durable revision 条件准入；AArch64/RV64 HIA 目标执行；Cortex-M4 Rust 后端 MMIO/IRQ | 主机与三个模拟目标的限定证据通过；通用并发内存模型、外部借用、设备能力和物理硬件仍未闭合 |

## 2. 固定组合与完整回归

[RELEASE_LOCK.json](../../final-evidence/RELEASE_LOCK.json) 记录实际字节身份、原始构建回执和环境修复。该组合包含四个固定 NDU 协议 bridge，而非一个混用移动分支的 NDU 指针：

| 组件 | 固定版本或提交 |
| --- | --- |
| HIA / Hepta | `a9be5fb5ac2231e731e750237f64818a6d0d623f` |
| NDU ranking | `d3c2d760eca5065fc966820379c35c6e8d56e855` |
| NDU recursive | `2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b` |
| NDU stream | `c4a1bbed3a39beba43a6abf1a18b6f75c5725c21` |
| NDU finite | `4b6391e116949af0c7e59776baead67271856bdb` |
| 主机 C/C++ 编译器 | Clang / LLD / LLVM 20.1.8；GSL 与 JSON 的 native 构建另使用 GCC/G++ 14.2.0，按各回执绑定 |
| Rust 编译器 | Rust 1.90.0 用于主机 Core/release 等资格；finite bridge 与 Agent v2 作者控制/冻结 evaluator 使用 Rust 1.95.0 |
| 验证工具 | Z3 Python package 4.15.4.0 及绑定的实际 native library；Lean 4.19.0 |
| 目标模拟器 | QEMU 8.2.2+ds-0ubuntu1.18；user-mode 原仓库锁与本轮 system-ARM 依赖锁分别记录 |

四个 NDU 二进制均按原始 Rust 源码构建并核对构建身份；没有授予 NDU 安全裁决权限或启用生产 activation。

[最终完整回归](../../final-evidence/regression-final/result.json) **1,429/1,429 通过**：0 failures、0 errors、0 skipped、0 expected failures、0 unexpected successes；耗时 **1108.843807486 秒**。144 个模块/选择器的计划、启动、完成身份完全一致，digest 为 `74d3994305cceaebc3b6948a84907314e180424bbddda83d73ef6d5d1cfdc42f`；运行期间源码与工作区均未变化。

首轮 [完整红色结果](../../final-evidence/regression/result.json) 保持 25 FAIL +22 ERROR、passed=false。逐项审计归为 **43 项缺失 libLLVM.so.20.1、1 项由两个直接错误引发的外层累积断言、3 项临时 AF_UNIX bind 被沙箱拒绝**。补齐匹配库的 RUNPATH 目录链接，随后在允许本地 Unix socket 的执行环境中重跑同一完整计划；没有改源码、删测试或放宽门槛。两个 socket 方法及其3个原失败案例均实际通过。最终 stderr 的152字节来自两个预期拒绝的 schema-audit CLI 控制，详见 [回归独立读出](../../final-evidence/REGRESSION_FINAL_READOUT.json)。

此外，[Rust Core 日志](../../final-evidence/rust-core.log) 记录 **121 项测试通过，0 失败、0 忽略**。独立资格及回归覆盖存在重叠，本文不把不同分母相加成“独立测试总数”。

## 3. 证明核心：量词、组合与信任边界

新增 `qualify_hia_sequential_core.py` 对指定 Core 的**每个公开 scalar export**重新执行全输入 normal-return 与实际生成 LLVM 的 value/abort/poison 验证，绑定同一 Core、checker 实现、Z3 binding/native library 和 LLVM 内容。它拒绝把导入的旧 receipt 当作证明权威。primitive totality 同时补齐 whole-proof deadline，覆盖预检、编码、求解、反例回放与最终身份核对；迟到结果、异常与身份漂移保持 unknown。

[形式化独立读出](../../final-evidence/FORMAL_READOUT.json) 的准确分母：

| 证明组 | 定理记录 / 负例 | 普遍量词的实际范围 |
| --- | --- | --- |
| Abstract Core | 11 / 2 | 所定义抽象资源状态/转换、预算准入，以及由 u64 literal、wrapping add/mul 构成的任意有限表达式到抽象栈指令的 lowering |
| Memory / Typed Core | 19 / 5 | 13 个 provenance/view 定理；6 个封闭 u64/bool/add/equality/conditional 类型表达式定理 |
| Register Safety | 14 / 3 | 任意有限、合法的 literal/wrapping-add/sub u32 寄存器机器程序；另有具体 source/candidate 全输入实例 |
| Selected Program | 2 / 2 | 一个导入 Lean 的具体加法程序，对全部 2^64 个 u32 输入对成立 |

合计 **46 条报告定理记录、45 个唯一限定名称**，`HiaSelectedCore.run_append` 在两份报告中出现。四次正向 kernel 检查与 12 个负例均符合预期；正向没有 `sorryAx`。Lean 可执行文件、777 个 `.olean`、3 个共享运行库及 28 个源码/工具源文件均复核身份。

[Sequential 资格](../../final-evidence/sequential-core/qualification.json) 对 Core `d0bd183fa2908b0a099e92975286b554cb10311bf989df21f530906cdc57be0c` 的 `add_with_dead_literal` 与 `calculate` 各完成两项 UNSAT 义务，合计 **4 项**。每个入口均量化全部 **2^64** 个类型合法输入对；限定的是无环程序、CFG、操作数及调用展开规模。`calculate` 的私有 division helper 在入口 guard 下可达；没有要求脱离 guard 后的私有 helper 也 total。

Register source 与上述 add 函数对象完全相同；其 candidate 与 Selected 函数除名字外一致。因此可以在明确保留 Python exporter、canonical verifier、SMT encoder、LLVM subset parser 与 Z3 信任假设下连接这个具体函数的证据。**尚未形成由证明器检查的跨模型总定理。** `calculate` 的分支/除法不属于该 Lean register 机器。删除 dead literal 的定理保持结果，但会改变 evaluator tick，未证明 budget-stop 或 cancellation 等价。

Abstract Core/Memory 定理也没有自动证明生产 checker soundness、allocator freshness、外部指针、资源 lowering、C ABI 或 LLVM→机器码 refinement。有限 native differential 执行仍按有限观察计量。

## 4. Checked reduction 与强 release 基线

新增快路径组合已有归纳证明与独立 narrowing 证明，覆盖 fill index、reduction index 和 reduction sum 的 checked-add；`include_induction` 显式启用后，构建链绑定 original → guarded → narrowed → native object。在 guard 范围外保留原始 checked 路径。实现未降低旧 profile 的验收门槛；真实四后端、分配拒绝、错误中间产物和 guard 外回退进入回归。

[执行前计划](../../final-evidence/release-parity-run-plan.json) 固定 3 个训练长度与 7 个独立长度，训练/独立种子分开。四个后端合计 **120 个性能请求、2,520 个计时批次、161,280 次计时 kernel 调用**，另有 192 个正常/拒绝核验请求。统计量的单位是 **64 次调用组成的批次总耗时 ns**；每个 backend/length 汇合 63 个批次观察。nearest-rank 的 median/p95/p99 分别为排序后的第32/60/63点，故 p99 是最大批次耗时；它不是逐调用尾延迟。

Rust 采用 opt-level=3、fat LTO、单 codegen unit、panic=abort 和 release overflow 策略；Clang 与 Rust 的 LLVM 均为 20.1.8。C/C++ 使用 O3 与 thin LTO；HIA 从生产 LLVM emitter 进入 O3 native object。编译选项并非完全相同，具体差异保留在计划与报告。门槛固定为 HIA/baseline **median ≤ 1.10、p95 ≤ 1.20、p99 ≤ 1.20**，要求所有长度及 C/C++/Rust 比较同时满足。

[最终正式观察](../../final-evidence/release-parity-verified-reduction-narrowed-v1/RESULT.json) 有效，源码、工具和产物身份未变。全部比较通过 **25/30**：训练 **5/9**、独立长度 **20/21**；C **8/10**、C++ **8/10**、Rust **9/10**。**performance_gate_passed=false、holdout_gate_passed=false**。

从28个原始 driver JSONL 另写算术/转录实现的 [独立复算](../../final-evidence/RELEASE_PARITY_INDEPENDENT_READOUT.json) 完成3,407项核对，无差异。复算者参与过该 profile 实现，因此这里只声明计算与转录实现独立，不声明组织独立复现。

HIA 在这10个长度的 median 和 p95 均低于 Rust，完整比值为：

| 集合 | 长度 | HIA/Rust median | HIA/Rust p95 | HIA/Rust p99 | 三项同时通过 |
| --- | ---: | ---: | ---: | ---: | --- |
| 训练 | 64 | 0.853837 | 0.753022 | 0.765471 | 是 |
| 训练 | 4,096 | 0.840270 | 0.723422 | 0.231581 | 是 |
| 训练 | 65,536 | 0.832661 | 0.370222 | 1.035237 | 是 |
| 独立长度 | 2 | 0.914013 | 0.902077 | 0.009703 | 是 |
| 独立长度 | 63 | 0.838170 | 0.830878 | 0.823278 | 是 |
| 独立长度 | 257 | 0.867347 | 0.884213 | 0.885161 | 是 |
| 独立长度 | 1,025 | 0.800989 | 0.810896 | 1.003711 | 是 |
| 独立长度 | 8,193 | 0.807523 | 0.923973 | 1.077650 | 是 |
| 独立长度 | 32,769 | 0.876397 | 0.906284 | 0.984386 | 是 |
| 独立长度 | 65,535 | 0.884194 | 0.942438 | 1.233885 | 否 |

30项比较的 median 与 p95 均满足既定门槛，5个失败全部来自 p99：

| 集合 | 长度 | 基线 | 失败的 p99 比值 |
| --- | ---: | --- | ---: |
| 训练 | 4,096 | c | 2.019481 |
| 训练 | 4,096 | cpp | 1.320103 |
| 训练 | 65,536 | c | 3.097069 |
| 训练 | 65,536 | cpp | 4.236191 |
| 独立长度 | 65,535 | rust | 1.233885 |

唯一 Rust 失败发生在独立长度65,535：HIA的批次p99为 **1,190,541 ns**，Rust为 **964,872 ns**，比值 **1.233884909** 超过1.20。所有异常大样本保留；例如长度2的极小p99比值包含Rust端95,023 ns的最大批次观察，不能把它推断成稳定的百倍尾延迟优势。没有删除样本、放宽门槛或择优重跑。

本次在其他本地重任务全部退出后运行，但宿主独占性与稳定频率未建立。完整 campaign wall **19.382294714 秒**，其中 build **18.509132873 秒**；嵌套 build-command 时间不重复相加。工具获取、人工、能耗和完整生命周期成本仍未知。

这是同一 owned-buffer kernel 的预先分离长度/种子；没有由此证明独立生产应用、其他资源模式、并发负载或任意合法程序达到 Rust 基线。

## 5. NDU：模型正确性与净收益分别验收

v3 模型新增可逆 resident set、eviction 与重准备费用；每批 holding、未来决策、stop 费用都进入目标。v1/v2 保持兼容。范围固定为 **2 个候选、4 个驻留状态、12 条边、horizon≤4**。release-before-prepare 是模型约定，尚未实现通用 native loader unload；观察到的实际支出、generation 与重放拒绝由 ledger 核验。

[模型/native 对照](../../final-evidence/ndu-costed/RESULT.json) 的 **18 次原始 Rust NDU 调用**均通过，最优值和完整 winner 集合与独立 exact DP 一致。同信息有限确定性目标下，exact DP 本来就是最优值；值相等验证正确性。要证明 NDU 更有价值，还须证明完整决策和执行成本的改善。

[原生应用读出](../../final-evidence/NDU_READOUT.json) 保留如下结果：

| 项目 | 结果 |
| --- | --- |
| 正常、分配拒绝与 allocator 观察 | 192 条通过 |
| 策略 × episode 执行 | 12/12 正常完成 |
| 服务比较门槛 | 4/9 通过，整体收益 gate 为 false |
| 策略阶段实际 NDU invoke | **0** |
| 训练期 native 校准 | 3 次，单列计费与归因 |
| NDU / 固定策略服务成本比 | **1.740、1.957、2.127**，三项均失败 |
| 共享准备/验证/训练/校准/失败证明成本 | **19.580841247 秒** |
| 其中 controller 校准实际成本 | **34.093256 毫秒**，已在共享费用范围内，不能再次相加 |

服务比较使用 `service_total = actual_total − independent_audit_ns`；全部 arm 均实际执行独立审计，其费用保留并单列。以下为已采集的 episode 墙钟分解，单位毫秒；共享准备费用单列于上表，未按任意规则摊入某个 arm。

| episode | arm | actual_total | independent audit | service_total |
| --- | --- | ---: | ---: | ---: |
| 0 | fixed | 9.121912 | 1.503734 | 7.618178 |
| 0 | exact_dp | 10.974031 | 0.950552 | 10.023479 |
| 0 | greedy | 15.631683 | 1.794271 | 13.837412 |
| 0 | native_ndu | 14.907783 | 1.652397 | 13.255386 |
| 1 | fixed | 7.822136 | 1.797256 | 6.024880 |
| 1 | exact_dp | 13.483138 | 1.854862 | 11.628276 |
| 1 | greedy | 14.034819 | 1.779007 | 12.255812 |
| 1 | native_ndu | 13.599904 | 1.811537 | 11.788367 |
| 2 | fixed | 6.799616 | 1.352625 | 5.446991 |
| 2 | exact_dp | 14.116743 | 1.852509 | 12.264234 |
| 2 | greedy | 13.577130 | 1.911017 | 11.666113 |
| 2 | native_ndu | 13.576580 | 1.991597 | 11.584983 |

工具安装、源码获取、过去复用的 NDU 构建、人工实现/审核、能耗、allocator 元数据/碎片和归档成本未完全计入。服务比值排除了独立审计及共享准备，不构成完整生命周期成本。本次应用试验与回归共享宿主，未声称独占主机。**模型正确性、跳过高成本决策和几项局部比较均不足以证明 NDU 净收益；完整生命周期优势保持未成立。**

## 6. 真实 C/C++ 行为、生命周期与升级

[GSL 3.1.0→4.0.0](../../final-evidence/gsl-upgrade/report.json) 验证 **416 组输入 × 6 个原始/迁移实现配对**，得到 **4,992 条正向观察和 14,976 次 native scalar 调用**。两版 const factory 的 4,992 次调用已包含在总数中。3.1 非 const 左值 factory 的拒绝与 4.0 成功行为得到保留；迁移实现没有链接原始 C++ 对象。

错误返回宽度和 signedness 在不兼容调用前被拒绝；duplicate/lost owner 被拒绝。资源合法但结果错误的 mutant 被独立 oracle 检出 **325/416** 行；实际 callback 源码乘数 31→37 的变更也通过独立执行。这提供 RAII/factory 升级和限定 ABI 的实质证据。

[nlohmann/json 3.11.3 / 3.12.0](../../final-evidence/cpp-json-checkpoint/qualification.json) 运行 **146 个 worker**，包含 **112 次正常提交、28 次被捕获的 foreign exception 和 6 次真实 noexcept SIGABRT**。两版共 34 个实际分配故障点，全部保持父 checkpoint；34 次显式新请求重建及随后继续执行成功。消耗过的故障请求再次执行均被拒绝，未启动额外 invocation。112 次正常提交包括校准、已提交前缀、重建、后续执行及 6 个 ordinary case，不能把它当成 112 个独立普通用例。

本轮修复将 creator PID 检查放到 RLock 之前，防止 fork 子进程继承其他线程的锁后阻塞；子进程 close 仅关闭自己的继承引用。状态有界复制后重新核验长度，closed/poisoned 上下文被拒绝。

JSON 保留原库，资格对象是 scoped foreign 调用和父状态重建；失败 invocation 仍失败，外部副作用回滚与原进程内 noexcept 恢复没有建立。ABI 范围为已执行的本机 Linux x86_64 / SysV AMD64 LP64 scalar C 调用；跨目标 ABI 另按目标用例限定。GSL/JSON 资格墙钟分别约 4.505/23.136 秒，只是执行成本。人工工时和完整迁移成本未知，故尚不能通过“人工成本可核算/开发效率优势”的总验收。

## 7. Agent：完整保留生成前失败

maintenance-v2 固定两个作者编写的 API 维护任务、`gpt-6.1-sol` / `gpt-6-luna` 两个请求选择器、HIA/Rust 两种语言，共 **8 个单元**。v1 协议保持不变。作者控制与独立审阅绑定 180 个文件、注册提交、prompt/catalog 和工具身份；审阅者没有模型请求。

[正式结果](../../final-evidence/agent-maintenance-v2/RESULT.json) 与 [独立基础设施读出](../../final-evidence/AGENT_INFRASTRUCTURE_READOUT.json) 显示 8/8 在客户端初始化时退出：

> Error: failed to initialize in-process app-server client: Read-only file system (os error 30)

stdout 全空，**观察到的生成次数为 0**；没有进入公开/隐藏任务评估。已报告 token 小计为 0，但 usage 不完整，完整成本保持未知；每成功任务成本不可得。不能据此判断 HIA/Rust 或两模型的能力差异。原始失败保留，不重跑这些冻结 cell 来替换结果。

即使客户端可运行，两项作者任务也不足以代表真实第三方库升级或总体生产率；Rust Vec observer 的 API witness 也不构成机器写入证明。后续须先恢复可用执行环境，再建立新的注册、控制和独立审查，保留本轮失败及相关成本，扩充真实维护任务和完整成本分母。

## 8. 并发入口、恢复与目标执行

`DurablePureQueue.execute(..., expected_committed_steps=...)` 在同一 mutex 内检查持久化 revision、准入、执行并提交。新 stale 请求在磁盘、预算和 native 副作用前被拒绝；重复请求按其原始历史前缀核验，使已发生后续提交时仍能恢复丢失 ACK。revision 来自已提交步数，不增加第二个持久化计数器。未传 revision 的旧接口继续提供串行语义。

[最终回归日志](../../final-evidence/regression-final/tests.log) 中，原 durable queue **17/17** 与新增 revision **6/6**，合计 **23/23**；JSON checkpoint **19/19** 与 fork **4/4**，合计 **23/23**，均无跳过。真实并发 producer、重复提交、stale request、后续提交后的ACK恢复及既有故障恢复测试都在这次冻结组合上执行。限定 pure queue 不提供外借 native pointer 或设备操作接口；这组证据尚未定义通用并发语言内存模型或外部 exactly-once 副作用。

[目标独立读出](../../final-evidence/HARDWARE_READOUT.json) 与 [实际执行](../../final-evidence/HARDWARE_EXECUTION.json) 记录三种模拟目标各执行一次；总计 **20 次镜像执行：7 正向、13 预期负向**，全部符合固定断言。

| 目标 | 实际执行路径 | 结果与恢复范围 |
| --- | --- | --- |
| AArch64 Linux user-mode | standalone HIA Core→生产 LLVM→目标对象，独立 C caller | 17 个正常 ABI 用例；4 alloc / 4 free / 0 outstanding / 1 real NULL refusal；两项错误 Core 控制与 bounds exit134 按预期观察 |
| RV64GC LP64D | 生产 HIA→LLVM 的 scalar、双 owner bulk、recursive chain 对象 | 3 正向镜像，233 次 C→HIA 调用，7 负控制；包括分配拒绝后 payload/tail 恢复 |
| Cortex-M4 / mps2-an386 | Hepta 源码→生产 Rust no_std UART/timer 函数，加受信 BSP | 4 编译镜像、6 cold boots；3 正向各 5 IRQ / checksum55；错误 IRQ 计算、禁用 IRQ、遗漏 data copy 按43/42/41退出 |

RV64 `chain_recover(17)` 在第 36 次分配拒绝后读回 payload=73、drain 旧 chain 并释放保留的 owner：35 alloc / 35 free / 0 outstanding，返回 1,000,209；正常路径 36 alloc / 36 free，返回 209。这里验证分配拒绝后的 owned-data 恢复，未承诺 trap 或进程崩溃后恢复。

Cortex-M4 的 reset/vector、FLASH→RAM `.data`、`.bss`、raw 地址、VTOR/NVIC、barrier、SeqCst ISR/main 通信与终止均由受信 BSP 提供。其 watchdog 为 SysTick IRQ 计数到 20 后的软件超时检查，未使用独立 WDT 外设，也未执行故障复位或负控制后的自动重建。raw MMIO 仍带 `unsafe/io/write` 外部义务；没有验证 MPU 拒绝、通用设备 capability、DMA、GPU 或物理板卡。

三项实际资格约 1.758、5.814、1.133 秒，编排总墙钟约 9.878 秒，与广回归共享宿主。125 个原有 Rust 文件及 41 个编译器/宿主库保持原字节；仅新增3个 thumb target rlib。System QEMU 的47个动态库与包获取证据保留。这里的执行成本不代表物理目标性能。

## 9. 仍需闭合的实质问题与远端状态

下一步证明工作应连接生产 verifier/type/ownership 的规则与形式模型，并分别处理循环、预算/取消语义、资源 lowering 和后端 refinement。性能工作须依据保留的预注册结果定位差距，并使用新的独立负载验证。NDU 须在收益能够覆盖决策/准备/驻留费用的实际工作负载上，与同信息固定、DP 和轻量控制比较完整成本。Agent 与迁移优势需要可执行的真实维护任务、人工/共享准备成本及每成功任务分母。并发与硬件需要明确的语言内存模型、外部借用和设备权限协议，以及对应物理目标证据。

代码和文档形成可审查的本地提交。向 `TrillionniumFoundation/Hepta` 上传本轮源码被自动审批拒绝，原因是未确认本轮源码可向该目标仓库外发。本轮没有创建远端提交、分支或 PR。拟发布的隔离分支和 Draft PR 内容随交付包提供；远端写入需明确授权。
