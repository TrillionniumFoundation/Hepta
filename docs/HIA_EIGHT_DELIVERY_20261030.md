# HIA 八项交付：统一实现、实际资格与未闭合条件

本报告对应 [Draft PR #399](https://github.com/TrillionniumFoundation/Hepta/pull/399)。
这是一份实施和证据报告，不是“八项全部完成”的发布声明。

## 精确源码与范围

本轮将 #394 的已审阅增量收敛到 #395，并修复两个新复现的准入缺口。
实现提交包含 42 个文件、4,654 行增加和 225 行删除；其中相当部分是已有候选代码的集成，不能视为本轮全部新发明。

- 本地冻结资格提交：`60dfedc626b7ce3feaaa87ac16d711fe0cc8e9d3`。
- 远端源码提交：`37d3a317b77aeac8f42b8a727f0f123b4a46e49f`。
- 两者精确 Git tree：`6add0d477bf92c3980110b50a6b1675306175c99`。
- 两者 parent：`2cc9fb3b92a7306d2f5aae316c99e8364be700f9`，即本轮使用的 #395。

两个 commit 的身份不同。GitHub connector 发布时生成了自己的 commit metadata，所有资格结果仍保留真实的本地冻结提交，未改写成远端 SHA。
`SOURCE_PUBLICATION.json` 记录这一映射，`qualified-source.bundle` 保留可导入的原始资格提交及其 prerequisite。
后续证据提交只增加文档和观察资料，不改变已测生产实现。

## 八项验收逐项判断

| 项目 | 本轮已交付 | 尚未满足的完整条件 |
| --- | --- | --- |
| 1. Core、registry、生产准入 | Python `verify_program` 保持唯一生产权威；旧格式显式适配；Rust v3/v4 显式 opt-in；补齐精确调用快照和有限跨引擎语义核对 | 有限核对不是全语言等价定理；Rust shadow 不拥有生产准入权；公共 registry 尚未完整枚举 primitive 指令，实际 Agent 暴露名称发现缺口 |
| 2. 资源、失败、取消 | 明确正常、错误值、预算停止、协作取消、trap、crash 六类行为，保留递归和并发边界；实际清理与不确定清理拒绝经过验证 | 任意异步取消、外部库析构恢复、持久状态崩溃恢复和一般共享内存模型未闭合 |
| 3. 分段验证链 | 分别记录源捕获/有限差分、Core 资源检查、有限 SMT 等价、有限 LLVM lowering 和真实 native 观察；unknown/timeout 不准入 | 无端到端 source→Core→机器码 refinement theorem；可信计算基仍包括编码器、求解器、编译器和宿主 |
| 4. C/C++ 迁移和升级 | 真实锁定 C 函数体的 4TU 迁移、人工维护补丁、真实 nlohmann release 升级与故障注入 | 不是整个上游构建系统重现；C++ 库仍通过桥接复用；完整开发/维护人时未测，故障有未恢复位置 |
| 5. 有净收益的候选 | 真实候选准备、验证、执行、切换/释放和完整冻结 trace 已运行，负机会完整保留 | 本轮净收益门未通过；冻结两内核不是新未见真实工作负载；全生命周期成本不完整 |
| 6. NDU 独立增量 | 固定、贪心、DP、原生 NDU 四臂完整复现；真实输入/输出逐条与独立 DP 和穷举核对 | NDU 没有胜出；有限模型一致性不证明全程序或逐指令全局最优 |
| 7. 真实 Agent 开发 | 新模型实际资格 3/3，完整运行四臂 16 个主单元，14/16 通过；23 次实际请求及全部失败保留，完成独立原始记录复核 | HIA 两臂各 3/4，Rust 两臂各 4/4；固定小任务不代表未见真实项目生产力，模型后端/缓存未独立控制，完整人时未测 |
| 8. 目标设备和运行时 | 实际 Linux x86_64 宿主 ABI、原生映像、并发准入、故障/清理与有限 owned-state 控制 | 没有指定物理板卡、MMIO/DMA/中断、设备故障恢复、整进程 RSS 或 WCET 资格 |

不能从本轮结果推出 Rust 性能已被超越、任意 C/C++ 可低成本自动安全重写、全语言绝对安全或全局最优。

## 实现中的实际修复

### 一次校验对应同一次调用

旧 Python runtime 校验调用方 list 后又读取该 list 执行。在真实并发夹具中，已检查的 `u8=7` 能在校验后被替换为 `300`，并逃逸为返回值；分配长度和预算结果也能被替换。
现在入口只获取一次 immutable tuple，验证和执行使用相同快照。原始非法值仍被拒绝，合法值、arity、分配失败注入和停止账本均有回归控制。

### 已验证字节保持到执行结束

旧 Rust shadow 临时路径和原生 NDU ranking 路径存在验证之后再次按路径执行的窗口。
本轮用 sealed `memfd` 保持已经验过的字节，以显式继承的 descriptor 执行，运行中限制输出，超时后处理整个 owned process group，并确认 reap。
封印不可用、封印/回读不符、未确认 release 均拒绝；没有 mutable-path fallback。
这仍信任 ELF loader、依赖库和宿主，不是任意外部代码的 sandbox 或硬件 attestation。

### 证明工作共用剩余预算

旧 ranking 会为每个候选和最终复核重新发放完整 solver timeout。
现在求解器许可同时受剩余总预算、剩余可能净收益和单次上限约束；不足 1ms 不启动。
原生排序耗尽余额后也不能再启动最终证明，实际超支保持 incumbent。
这是启动与准入策略，不是对 host overhead 或 solver 的硬实时证明。

### C 语法扩展与严格预处理拒绝

集成有限结构化 `do/while/for`、最近一层循环的 `break/continue`、声明和提前返回；definite assignment 分别处理正常、break、continue 等退出路径。
`goto/switch`、不受支持的求值次序、变更后置条件及超过展开预算仍被拒绝。
严格 scalar importer 同时拒绝 hash digraph/trigraph、注释前缀指令和行拼接，并依据真实 Clang AST 的 expansion provenance 拒绝 `__LINE__` 等 builtin macro。
保留 #395 的目录 FD 发布和有界 capture，没有为集成旧分支而退回更弱的路径检查。

## 分段验证究竟覆盖什么

| 阶段 | 当前证据 | 不能推导的结论 |
| --- | --- | --- |
| 原始 C/C++→迁移源码/Core | 原始源、flags、cwd、contract 与工具身份；有限 native/VM 差分与拒绝控制 | 任意 C/C++ UB 推断、全输入前端 refinement |
| Core 准入 | 真实 Core 重验、类型、ownership、loan、effects、CFG/call contracts | 元数据或模型建议可以替代验证器 |
| Core→优化 Core | 声明的无环标量、资源 barrier 或有限循环 profile 中 SMT 证明返回值/首个 trap；不足范围、unknown、timeout 拒绝 | 任意循环、并发、资源不变式或全程序等价自动得到证明 |
| Core→有限 LLVM 模型 | 单独声明的选定 lowering/poison/值与 abort 条件 | 任意 LLVM pass、机器码和微架构的完整 refinement |
| Native / Rust shadow | 实际工具、精确工件/请求绑定、有限输入输出和停止账本比较 | Rust shadow 变成生产权威、执行一次等于安全定理 |

边界协议保持 8 项未证明的普遍性声明全部为 `false`。这次明确增加 budget/crash 的描述，未把 OS 回收进程资源写成 guest 析构、恢复或可安全 replay。

### 六种退出结果的组合规则

| 结果 | 调用方可以依赖的行为 | 仍不能假定的行为 |
| --- | --- | --- |
| 正常返回 | 按签名转移 owner；其他本地 owner 消耗，loan 结束或依声明合法返回 | 自动得到源到机器码的精化证明 |
| 错误作为值返回 | 使用正常返回的资源规则；此前资源须按已检查路径消耗或合法转移，失败分配产生的逻辑空 owner 也须消耗或合法转移 | 任意异常展开，或替遗漏的清理自动补救 |
| 预算停止 | 与语义 trap 分开，保留停止时的 VM 资源账本 | 当成分配返回错误；把 interpreter 预算当 native 硬限额 |
| 协作取消 | 在支持的任务/队列边界执行已检查状态转换及已初始化字段清理 | 任意指令位置异步打断后安全展开 |
| 语义 trap | VM 保留停止账本；native 路径 abort | guest 析构完成、可恢复、所有资源已正常释放 |
| 崩溃或强制终止 | 拒绝不完整 native 观察，宿主保留清理责任，直到终止和 reap 被确认 | guest 正常展开、持久状态一致、可以无条件重试或安全 replay |

这些区别必须跨模块保留。调用方不能把 budget stop 转成普通错误值，把“请求取消”当成“取消和清理完成”，也不能把进程已回收当成业务操作无副作用。

## 正式资格及首次失败

最终 canonical safety contract：**277/277 passed，0 failure/error/skip**，耗时 201.572448420 秒，source 前后稳定。
首轮为 273 pass、4 skip，因此仍记录 `failed`；缺的是实际 pinned NDU identity 环境。
恢复精确 `4b6391e…` / Rust 1.95 finite 构建后，先真实运行原 4 项，再完整重跑 277 项，没有改源码、selector 或门槛。
Rust Core 使用 Rust 1.90，finite bridge 使用独立 Rust 1.95；两个来源没有混用。

另外，实际宿主控制 **43/43** 通过、零跳过。它与 canonical matrix 有交集，不能将两者相加充当独立测试总数。
开发阶段的 93 个 Rust crate 测试、71 个 Python Core/Rust 组合方法、39 个 ranking 方法、38 个迁移方法等单独保留，不冒充冻结源码上的第二份全量资格。
未在本轮声称运行了整个项目所有数千项测试；远端 CI 结果也没有被预先标为通过。

## C 迁移和真实 C++ release 升级

### 4TU C

固定输入域包含 24 个输入及 4 个分配设置（正常执行，以及第 1/2/3 次分配拒绝），共 96 个组合。
正式执行为 **384 次 native 调用、192 次 Core VM 调用**；实际资格耗时 40.838200187 秒。
两个版本各 4TU、12 个翻译实现体。原版是 11 个上游原样函数体加本地 `checksum_byte`；维护版是 10 个上游原样体、人工修改的 `ring_buffer_queue_arr` 和同一本地 `checksum_byte`。集成 client 另行计数。
迁移生成函数体的手工编辑数为 0。

保留的是已捕获编译数据库的 flags、cwd 和源操作数。该数据库本身是资格实验编写的配置，不能称为完整上游项目构建系统。
`ring_buffer_queue_arr` 的变更是人工维护 patch，不是上游 release 升级。
完整人工工作时间仍是 unknown；编译运行秒数不能换算成开发成本。

### nlohmann/json 3.11.3→3.12.0

真实替换锁定的上游 release，两版本各 **98 case**。
adapter、contract、Hepta caller 在这次升级中均零修改；C 导出清单一致，按协议归一化版本目录后的 `bridge.cpp`，以及 `bridge.h`、`bridge.hepta`、`contract.json` 的身份一致。这里不声称两个版本的全部生成物逐字节相同。错误签名与错误实现负对照均被拒绝/检出。
初始集成仍需要 adapter 33 行、contract 104 行、Hepta 8 行，其设计、审查和维护人时未测。

执行路线是 C caller→经 Rust backend 编译的 Hepta consumer→生成 C++ bridge→原 C++ adapter/库。
因此，这是桥接复用与一次真实升级的证据，不能称为 nlohmann 已翻译成 HIA。

**每版 17 个真实分配故障位置中，14 个恢复，15/16/17 三个位置因外部 `noexcept` 下 `std::bad_alloc` 触发 SIGABRT。**
`all_allocation_failure_paths_recovered=false` 必须保留。
脚本的整体 `status=passed` 表示完成它定义的兼容性/故障观察协议，不表示所有故障已恢复。

## 优化与 NDU：实际结果为负

| 策略 | 本轮 warm 归属总成本（秒） |
| --- | ---: |
| fixed | 27.809215321 |
| feedback-greedy | 28.429366716 |
| DP | 28.318381481 |
| native NDU | 28.877934407 |

16 个 policy episode 和 6 个 opportunity control 全部运行完成。
340 个实际输出包括 36 calibration、256 policy、48 opportunity，checksum 均正确，owned release 均完成。
NDU warm 比 fixed/greedy/DP 分别多 3.843%/1.578%/1.976%；这只是有限观察，不是统计显著性结论。
加入原历史 empty-target、已有 dependency-cache 的 21.387330636 秒 NDU build，归属成本为 50.265265043 秒；它不是本轮新 cold build。

独立脚本从实际校准及各臂过去观察重构真实 stdin model，再用 bottom-up DP 和全组合枚举核对：**32/32 决策相同、modeled regret=0**。
各臂 eligible 信息、准备配额与一个编译额度相同，无 NDU decision cache；实际运行反馈来自各臂自己的过去执行，不能称每步反馈数值完全相同。
本轮 policy 阶段全部选 base，候选 build 都为 0；没有出现两个有盈利候选竞争一个额度的情况。
校准和机会控制实际构建了代码不同的 guarded/narrowed 版本，但四项完整 trace 机会差值全为负。

首轮 sandbox 的 `/proc` 进程身份不可观测导致 NDU 四组全部拒绝，0 个 policy request；70.621403980 秒全部保留。
真实身份预检通过后，在可观测环境以相同协议重新运行全部四臂，没有混用校准或择优取样。
两轮加预检共 161.603867712 秒；这些是全部尝试费用，不是某一臂的性能分数。
工具获取、审查/分析、人时及部分外层启动/归档成本仍未全部纳入。因此未见负载净收益和全生命周期收益资格仍为 false。

## Agent 证据

### 新模型的前瞻登记与真实四臂实验

本轮使用实际可用的 Codex CLI 运行时，显式请求 `gpt-6.1-sol`。先前 header 确认了 alias 和 provider，但没有每次请求的底层权重或服务路由 attestation；服务端 sampling、cache 与继承配置不能视为已控制变量。

协议、runner、19 项本地 controls、19 个实际人工 reference 和 19 个 dummy 拒绝控制，以及两份 generation 前审查，先发布到 commit `5e4ad121e5721e6d82fe071b6a1e3f805cbe2674`。远端提交记录时间为 06:39:15 UTC，本地运行登记为 06:40:01.813030 UTC，之后才发生首个 benchmark task 请求。
资格任务全部结束后才启动主实验。模型、提示、任务、冻结源码和预算均未按结果调整，没有重跑取优。

新资格为 **3/3**。主实验完整执行 **16/16** 个单元，结果为 **14/16 通过**：

| 固定任务 | HIA 完整代码 | HIA 节点编辑 | Rust 完整代码 | Rust 节点编辑 |
| --- | --- | --- | --- | --- |
| `saturating_score` | 失败，3 次尝试 | 失败，3 次尝试 | 通过，1 次 | 通过，1 次 |
| `wide_span_upgrade` | 通过，1 次 | 通过，1 次 | 通过，1 次 | 通过，1 次 |
| `owned_byte_return` | 通过，1 次 | 通过，1 次 | 通过，1 次 | 通过，1 次 |
| `owner_pair_replace` | 通过，1 次 | 通过，1 次 | 通过，1 次 | 通过，1 次 |
| 合计 | 3/4 | 3/4 | 4/4 | 4/4 |

三个资格单元与 14 个成功主单元均实际通过 public/native/resource 和最后的 hidden 检查；两个失败单元仅经历公开修复，未进入 native/hidden。
独立审计重新计算了 23 份实际 CLI 事件和响应、34 组 public/hidden native stdout 共 462 行观察；另一个审阅者核查 23 个 transport 和 23 个 evaluation worker 的生命周期与流哈希。审计没有再次调用模型或重跑 native。

### Agent 接口暴露出的具体缺口

HIA full 三次分别提出 `int.gt`、`int.lt`、`int.cmp.lt`；HIA node 分别提出 `int.gt`、`int.lt`、`cmp.lt`。六次均被真实 verifier 以 `E_HIA_OPCODE` 拒绝。
Core 实际支持的名称为 `compare.eq/ne/lt/le/gt/ge`。两个 HIA 初始 prompt、捕获 query 及全部修复请求均未提供这些合法名称，只说 comparisons return bool。

项目已有 schema registry、`hia routes`、inspect/edit-query 和公开 ISA 文档。registry/routes 目前没有完整的 primitive 比较指令枚举；query 主要描述现有源中的指令，本次源本身又没有比较指令示例。这个冻结 pilot 禁止工具调用，模型无法交互查阅文档。
因此，名称发现和接口披露不足是具体混杂因素；这不证明仅换指令名字就一定通过，也不能把一个任务的结果解释为语言本质差异。本轮没有事后加入合法名称再重测同一任务。

### 实际请求、费用边界和保留异常

| 主实验臂 | 请求数 | 报告 input / output / reasoning | 保守预算计数 | 实际 CLI 用时（秒） | evaluation worker 用时（秒） |
| --- | ---: | --- | ---: | ---: | ---: |
| HIA full | 6 | 99,782 / 5,064 / 378 | 105,224 | 96.536585646 | 1.730231985 |
| HIA node | 6 | 104,070 / 2,402 / 958 | 107,430 | 113.266068601 | 1.994061354 |
| Rust full | 4 | 62,008 / 516 / 62 | 62,586 | 33.807767570 | 1.509881702 |
| Rust node | 4 | 67,466 / 284 / 24 | 67,774 | 26.596148691 | 1.533459860 |

资格加主实验合计 **23 次真实 generation、23 次确认 CLI 启动**，任务请求未知 usage 数为 0。报告 input 为 385,335，output 为 8,540，reasoning 为 1,456，cached input 为 224,000；cached 部分不重复加到 input。
冻结预算采用 input + output + reasoning，合计 395,331；由于无法独立确认 output 与 reasoning 是否重叠，**这只是保守预算计数，不是精确 token 总量**。
整个实验 wall 为 327.131960289 秒，以上用时是操作记录，不能当作控制了服务端状态的语言性能比较。

每次 token 限额为请求返回后的拒绝门，不是 provider 的硬中断限额。先前 header 的 reasoning effort 为 none，而实际任务有非零 reasoning 报告，两项观察均保留。
另有两次 READY 准备请求，一份完整 usage 为 14,583 input + 5 output，另一份精确拆分未知。因此完整服务生命周期、人工工时和货币成本仍未测齐。

原始 QUALIFICATION 票是主实验开始前的 live snapshot，顶层 `requests=0` 尚未由 finally 汇总；票内三个实际请求行完整，真实费用按这些行、raw events 和最终 RESULT 计算，不能引用该零值表示无成本。
23 份记录确认当时工作目录为空并已移除；独立后验观察发现其中 9 个同名路径目前又以空目录存在，原因未由本次审计解释。因此没有声称所有路径永久不存在，也没有据此推断模型获取了答案。

本次是已知有限任务上的真实模型开发、修复及跨模块升级试验，**未建立 HIA 对 Rust 的优势**，也不是未见真实仓库的生产力研究。181 个源码、3 个 pilot 文件和 4 个工具文件在运行后重新哈希，均与冻结身份相同。原始运行保留 607 个文件、46,179,320 字节。

### 历史负结果继续保留

历史 V9（Qwen2.5-Coder 7B）保留其原 source `865a462…`：9 次完整请求，21,857 input + 3,479 output = 25,336 tokens，资格 0/3。
后来发现的 V10（Qwen3 4B）绑定独立 source `11d6f78…`：9 次完整请求，19,369 input + 1,473 output = 20,842 tokens，资格仍为 0/3。
V10 main CLI 实际被调用但在创建输出目录/engine 之前被资格门拒绝，主实验 0 cells、0 requests。
两者的人工 reference capacity 都不能算模型成功，也没有 HIA-vs-Rust 主实验成绩。
本次对历史资料的复核不等于重新执行模型，也不为本轮源码提供旧资格继承。

## 设备与发布边界

本轮实际 native 运行发生在可用 Linux x86_64 开发宿主，覆盖 ELF/C ABI、映像身份、concurrent native-child admission、超时 SIGKILL/reap、清理不确定时的所有权保留、有限 owned-state 切换/取消/rollback 等控制。
这不等于指定物理芯片、板卡或驱动已经通过 qualification。
全进程 RSS、allocator metadata、foreign memory、硬中断、MMIO、DMA、异构一致性及崩溃后持久状态恢复仍需要各自实机证据。

可发布结论是：统一实现已交付、声明范围内的安全回归和真实迁移/宿主控制已运行、优化及模型实验按真实结果保留。
仍缺的正向结果不会由文档、审查、历史通过或测试数量替代。

## 下一轮应闭合的具体门槛

1. 从同一 Core 指令定义导出完整 primitive catalog，包含拼写、版本、操作数/结果类型、effects、trap 和资源转移；将旧格式适配入口绑定到同一 catalog，增加 drift 拒绝。当前发现的问题应通过这个公共接口解决，不能只给单个 benchmark 填一个正确名字。
2. 对上述接口另行前瞻登记新的模型任务和披露对照；保留本次 14/16，不用同题补跑改写成绩。真实仓库工作还需纳入工具检索、跨模块维护、所有失败尝试与实际人工审查时间。
3. 为外部 `noexcept` 分配崩溃设计明确边界：可错误返回的路径、必须进程隔离的路径、宿主恢复和不可 replay 的副作用分别记录。在这些条件未被证明或测试之前，不开放对应安全承诺。
4. 净收益实验需要新的、事先冻结的未见应用负载，并实际出现候选可以回本及多个候选竞争准备额度的情形；计入获取、准备、证明、切换、清理和所有失败尝试，再检验 NDU 对同信息/缓存/预算基线的独立贡献。
5. 目标设备需给出实际板卡/芯片、OS/ABI、工具链和恢复协议。宿主单元测试不能替代该设备上的资源峰值、并发、MMIO/DMA/中断、故障和恢复证据。

本轮仅完成现有声明范围的实现和实测；上述门槛保持未闭合，release qualification 为 false。

## 证据入口与重放

见 `evidence/hia_eight_delivery_20261030/RESULTS.json`、`SOURCE_PUBLICATION.json`、`ARCHIVE_MANIFEST.json`、`FRONTIER_ARCHIVE_MANIFEST.json` 和两个原始证据压缩包。
原始报告保留真实绝对路径；manifest 提供归档路径、每文件 SHA-256 和来源映射。
`raw-core-evidence.tar.xz` 保留实现/资格、迁移、NDU、历史 Agent 与当时已有的审查材料；`raw-frontier-evidence.tar.xz` 保留新 pilot、生成前被修正的 controls/runner、全部实际请求/验证、独立后验审计和迟到的只读归档补充资料。最终摘要不覆盖原始失败报告。

恢复原资格提交时，先取得 prerequisite，再导入 bundle：

```sh
git fetch origin 2cc9fb3b92a7306d2f5aae316c99e8364be700f9
git fetch /path/to/qualified-source.bundle HEAD:refs/heads/reproduce-hia-60df
git switch reproduce-hia-60df
```

按保留的工具身份配置实际 Clang、Rust、Z3、各 pinned NDU profile 后，可重放：

```sh
python3 tools/qualify_hia_safety_contract.py --output /new/path/safety.json
python3 tools/qualify_hia_c_loop_migration.py --output /new/path/c-migration --source-sha 60dfedc626b7ce3feaaa87ac16d711fe0cc8e9d3 --clang /actual/clang
python3 tools/qualify_cpp_upgrade.py --workdir /new/path/cpp-work --output /new/path/cpp.json --cxx /actual/g++ --rustc /actual/rustc
```

完整原命令及环境允许项保留在各 launch/registration/manifest；缺依赖、source drift、unknown 或 skip 都不会自动取得准入。
