# HIA 八路线推进：实现与冻结证据（2026-10-30）

本轮已把新的 Rust API 对照、不可变执行镜像、C/C++ 循环跳转迁移、共享证明预算和有限仿射搜索整合到同一份 Core 上，并针对发布后的准确提交重新执行核验。八项最终完成条件仍未全部满足；下面逐项记录实现、观察、负结果和剩余门槛。

## 1. 准确来源与证据身份

- 基线：PR #389，`865a4626910efbc882cad47a7816e9aa276a9600`。
- 本轮实现：[`ab6d34613d1e2e90bbfc5081e0cd17354f1b8711`](https://github.com/TrillionniumFoundation/Hepta/commit/ab6d34613d1e2e90bbfc5081e0cd17354f1b8711)。
- 实现树：`a288101efd886ad55a1d1904f34b6d399164a793`。
- 集成 PR：[#394](https://github.com/TrillionniumFoundation/Hepta/pull/394)，基于 #389 分支的 draft PR。
- [机器可读结果](../evidence/hia_eight_track_20261030/RESULTS.json)、[归档说明](../evidence/hia_eight_track_20261030/README.md)和[原始证据清单](../evidence/hia_eight_track_20261030/RAW_MANIFEST.json)。

最终运行先检出公开实现提交，再冻结来源和工具；没有用先前分支的通过记录替代这次集成核验。后续证据提交仅添加文档和证据，原始回执仍绑定上面的实现 SHA。历史独立审阅保留自己的 `4867ebac68d80fbd7580ef16e0ba0ac882789ce9` 身份，不计入本次实现提交的测试分母。

## 2. 八项工作的实际状态

| 工作 | 本轮已落地 | 观察结果 | 尚未达到的完成条件 |
| --- | --- | --- | --- |
| 1. Core、registry、Rust 收敛 | 增加独立 v4 调用封装；保留原有协议和 Core ISA；扩展 canonical safety selectors | 155 个正向 API 观察、37 个原生拒绝、8 个旧 primitive 版本；24 个新增循环输入的 C/LLVM/Python/Rust 四路径一致 | Rust 生产准入切换、完整前后端 refinement 仍开放 |
| 2. 资源、失败、取消、lowering | 修复 Rust 执行镜像替换窗口；保留停止时的资源前缀；实际证明使用共享剩余预算 | 密封镜像、进程生命周期、输出上限、超时及不确定清理均有回归；NDU 预算测试包括实际 Z3 | 通用异常清理、异步取消、崩溃后的语言资源恢复、进程 RSS 和完整 native refinement 未证明 |
| 3. C/C++ 纵向迁移 | `for/while/do` 的最近循环 `break/continue`；按出口区分确定初始化；真实 C 项目构建重放和维护补丁 | 96 个输入/分配拒绝组合全部完成，384 次 native + 192 次 VM；没有 Rust codegen fallback | 大型 C++ 库及任意 RAII/异常/回调尚不覆盖；完整人时和长期维护成本未测 |
| 4. 净收益候选 | 修复搜索证明费用和最终新证明的共同预算；执行带完整阶段费用的候选比较 | 两个模块的 guarded 和 guarded-narrowed 候选均未产生本轮净收益 | 未见真实工作负载上的正净收益仍未建立 |
| 5. NDU 独立价值 | 原始 native NDU 与 fixed、feedback-greedy、精确 DP 四臂执行 | 16/16 回合准入；32 次同模型 DP 审计全同；warm 和含构建净收益门槛均未通过 | 本轮未证明 NDU 独立选择质量、搜索效率或统计优势 |
| 6. AI agent 开发优势 | 在冻结 V9 任务上实际执行参考控制并核对工具来源 | 19/19 参考控制通过；模型请求、tokenizer 调用和 agent 成功任务均为 0 | 仍需要通过资格的模型进行同预算开发、修复和跨模块维护比较 |
| 7. 原生与硬件资格 | 实际执行 AArch64、RV64 的有限 returned-loan profile | QEMU 下 256 次正向 native 调用，另有 trap/mutation 负控制 | 实机 ABI、设备语义、运行资源和恢复能力未获本轮资格 |
| 8. 可证明最优子问题 | 仿射函数域扩展；保持 146 个候选文法和旧搜索协议；先冻结全部选择 | 10 个目标、1460 个已判定 SMT 查询、10 个文法内字节最小值 | 不推导整个程序最优、任意 x86 最优、运行时间最优或后端 refinement |

## 3. Core 与 Rust：扩大准入域，保留语义边界

新增 `crosscheck_rust_execution_v4` 复用原有独立 Rust checker、显式帧 Machine 和 ByteMemory。它接受精确的内建 `list`/`tuple` 有序参数，并通过规范十六进制编码保留超过 `u64::MAX` 的正整数 `allocation_fail_at`。完整 policy 仍受 1024 字节限制；标量参数仍受 8192 项、128 KiB 边界限制。它没有把任意大整数偷偷截断、饱和或转成“无分配失败”。旧 v1/v2/v3 协议和八个 primitive 版本的拒绝规则保持不变。

最终 v4 collector 的 8 个测试方法全部通过，保留 155 个正向观察、37 个原生拒绝、完整双执行报告和请求绑定。Rust crate 另外执行了 93 个测试，零失败、零忽略。独立的新增循环对照在同一份 Core 上比较原始 C native、直接 LLVM native、Python VM 和 Rust v4，24/24 输入一致；8 个函数分别覆盖零值、普通输入和 `UINT32_MAX` 边界。

Canonical safety contract 从 25 个能力扩展到 27 个，selector 从 158 个扩展到 196 个，保留此前能力和 selector。生产准入仍由 `hepta.hia_program.verify_program` 决定。registry、TCB 和八项未证明声明没有因测试通过而升级；外部回执不能授予执行权限。

合并后的本地选定回归为 159 个测试，零失败、零错误、零跳过。这些测试与单独的 collector/crate 测试有重叠，不相加为“独立成功任务总数”。远端完整集成 qualification 及 canonical safety matrix 的状态单独记录在证据目录的 CI 快照中。

具体契约见 [Rust v4](HIA_RUST_BOUND_API_V4.md)、[canonical safety contract](HIA_SAFETY_CONTRACT.json)。

## 4. 资源契约与执行镜像修复

独立审阅复现了真实的替换窗口：runner 校验并复制可执行文件之后，`Popen` 再次按临时路径打开；拥有同一文件系统权限的过程能够替换这一路径。修复后，实际执行使用密封的 Linux `memfd`，检查完整 seal mask、长度和字节回读，持有描述符直到既有进程组清理和 leader reap 完成。缺少能力、seal 不完整或字节不一致都会拒绝，没有可变临时文件执行 fallback。不确定的最终 `close` 也不能形成成功回执，并且不会重试可能已被重用的数值描述符。

此机制约束的是被执行镜像的字节身份。loader、动态库、内核和受信父进程仍在 TCB 内。来源绑定、密封镜像、语言资源证明和整个进程隔离是不同的保证。

| 执行结果 | 当前明确行为 | 证明或观察所覆盖的阶段 |
| --- | --- | --- |
| 正常返回 | 局部 owner/loan 被消费，或经检查过的签名转移；返回借用保留参数来源 | 已准入 Core 的静态检查和声明的有限执行 profile |
| 错误作为值 | 使用正常返回的所有权规则；分配失败产生的逻辑空 owner 也须消费 | 显式失败分支和已执行分配拒绝控制 |
| tick/heap/depth 预算停止 | 保留实际停止前缀及资源账本，不把宿主容器析构算作语言级释放 | VM 报告与声明的逻辑资源预算；不是进程 RSS/WCET |
| 协作取消 | composite task/owned-state queue 的显式状态转移 | 已声明协作任务 profile；不是任意线程的异步取消 |
| trap、进程信号或崩溃 | VM 报告停止状态；native trap 使用 abort；host runner 按其进程所有权契约清理 | 不承诺源语言析构、异常展开或崩溃恢复完成 |
| lowering 后执行 | native 值、分配器事件和目标执行分别记录 | 源码到 Core、Core 到 native 的完整 refinement 仍未证明 |

NDU 优化器现在对候选证明和最终新证明使用同一实际费用累计。每次证明受剩余总预算及仍可能获得的净收益限制；毫秒超时向下取整，低于 1 ms 时不启动证明。原生排序已经耗尽预算时保留 incumbent；证明实际超支也不会授权替换。12 个新增测试包括实际 Z3 正确、错误、unknown 结果和可控时钟的预算边界。求解器超时控制不等于硬实时终止证明。

具体执行边界见 [镜像 custody](HIA_RUST_EXECUTABLE_CUSTODY.md)、[进程所有权](HIA_RUST_SHADOW_PROCESS_OWNERSHIP.md)、[v3 预算](HIA_RUST_BOUND_BUDGET_V3.md)与 [returned chains](HIA_RUST_RETURNED_CHAINS_V8.md)。

## 5. 真实迁移及成本保留

循环迁移使用已有分支和状态变量，不新增 Core 指令。`for continue` 执行一次 increment；`break` 跳过 increment 和下一次条件；`do continue` 到达条件，`do break` 跳过条件；嵌套跳转只作用于最近循环。确定初始化把 normal、break、continue 出口分别合流，保留零次迭代路径，并在循环局部声明处清除上一迭代的初始化状态。合成语句展开受 64 层边界约束，原始捕获 AST 完整保留。

通用 scalar profile 仍拒绝有副作用的循环条件；既有 record-view profile 保留其已支持的有序谓词。`goto`、任意 `switch`、一般 C++ 控制/异常/RAII 和路径依赖的 loop-local owner cleanup 不因这次扩展自动获准。

最终项目资格使用冻结 Ring-Buffer/musl 组成的有限应用。原始版本与一个**本轮编写的维护补丁**分别捕获和构建：维护补丁改写一个函数体，并有两处仅注释的 attribution 修改，不能当作上游发布的新版本。四个 translation unit 的原编译数据库保留 `-O3`、宏、`-funsigned-char`、include 和相对 source operand；编译器解析到记录的真实 Clang，重放时仅调整 `-o` 目的地。observer 使用可执行文件，避免为共享库添加 `-fPIC` 改变原编译宏环境。

24 个输入与 0/1/2/3 分配拒绝模式的笛卡尔积全部保留，共 96 例。四个 native 版本和两个 VM 版本产生 384 次 native 调用、192 次 VM 调用；记录分配尝试、成功、释放、live owner 和 loan 平衡。29 项身份记录核对通过，11 个临时构建文件被清理。完整项目、许可、pin、补丁、命令、AST、Hepta、Core、LLVM 和账本进入归档。

| 实际阶段 | 本轮机器 wall time |
| --- | ---: |
| 原始版本 capture | 10.797 s |
| 维护版本 capture | 10.670 s |
| 原始版本 build | 0.755 s |
| 维护版本 build | 0.701 s |
| 完整有限对照 | 17.543 s |
| 临时构建清理 | 0.000881 s |
| 整个 qualification | 40.649 s |

这些是本机资格运行费用，包含检查、工具启动和观察工作；它们不支持应用运行更快、低人时重写或低维护成本的结论。`human_effort_measured=false`。

历史独立循环审阅另保留 12 个程序、480 个函数输入对、6 条路径共 2880 次执行，以及初始化负控制、owner/分配失败和 record-view 控制。该审阅有自己的来源提交。其原始 native 参考使用共享库编译，而 capture 使用原语义输入；对固定、无宏分支的程序可作有限差分观察，不能冒充完整编译配置一致的真实项目资格。最终四 TU 项目重放使用上述更严格的构建契约。

该历史审阅的 80 次 failure-index 执行仅在 VM 注入：70 次实际分配拒绝，10 次零长度控制没有分配尝试。它们不是 80 次 native 故障注入。最终 96 例项目资格另行检查了四路 native allocator 计数和两路 VM 账本。

## 6. 净收益与 NDU：完整保留未通过的结果

最终 NDU 运行使用已冻结协议，四个 Latin-rotated 组，每组四臂、每回合八个 epoch、两个模块和一份 compile credit。比较 fixed、feedback-greedy、exact DP、原始 native NDU stream；共同准备、校准信息、artifact reuse 规则和预算一致。各臂之后使用自己的已观察反馈；32 次逐决策审计再把 NDU 当时实际可见的同一模型交给 exact DP。

| 策略 | 四组 standalone warm 总费用 | 计入 NDU 空 target 构建 |
| --- | ---: | ---: |
| fixed | 26.848905503 s | 26.848905503 s |
| feedback-greedy | 26.635777327 s | 26.635777327 s |
| exact DP | 27.952875873 s | 27.952875873 s |
| native NDU stream | 26.665582954 s | 48.052913590 s |

16/16 策略回合和 6/6 事后候选机会控制均准入。32 次 NDU 选择均为 base/base，与同模型 exact DP 完全一致、建模 regret 为零。warm NDU 比最强已观察控制 feedback-greedy 慢 29.806 ms；额外空 target 构建为 21.387330636 s。两个净收益 gate 均为 false。NDU 相对本轮 DP 的较低 wall time不足以证明独立增量：逐决策模型中没有更好的选择，最强控制仍更快，且本轮没有统计优势资格。

实际 DP 臂在 group 1 花了一份 credit 构建 `packet_xor guarded-narrowed`，于 epoch 1–5 使用，epoch 6–7 返回 base。32 次“同模型完全一致”只指把 NDU 当时的模型交给精确算法复核，不能改写成四臂每次实际选择都相同。

事后机会控制中，`byte_sum` 的 guarded、guarded-narrowed 分别比 base 多耗 0.643 s、0.782 s；`packet_xor` 分别多耗 1.155 s、1.126 s。它们使“候选本身是否提供机会”可检查。不能把 prepared artifact reuse 的共同收益归给 NDU。

构建成本是**空 target、已有依赖缓存**，不代表冷机器、工具链下载和所有准备的全冷启动。host 不独占。此运行重放已有冻结工作负载，未增加“未见真实工作负载”资格，也不推翻此前负面观察。

上述 standalone 费用按冻结协议计入共同 setup 和各臂内部准备、证明、构建、交付及清理；工具链/依赖获取、外层 Python 启动与 import、事后机会控制及分析、最终聚合编码/归档和人力开发费用未计入这些数值。完整原始账本和独立审计保留这些排除项；这些数值不能称为项目全部生命周期成本。

初次执行的 sandbox 中，子进程 PID 与 `/proc` 命名空间不对应，4 个 NDU 回合全部在 executable identity 检查处拒绝，零实际交付观察。其短耗时不进入有效比较。保持安全检查后，在能核对真实子进程身份的获准环境中从空 target 完整重跑四臂；两次原始记录都被保留，没有为改善速度选择性重试。

## 7. AI agent 与硬件：资格边界可检查

冻结 V9 的 19 个 authored reference controls 在真实 `/usr/bin/python3` 3.12.3 上全部通过。首次使用的另一 Python build 不提供 `fcntl.F_ADD_SEALS`，19 个控制均属 infrastructure failure；原始失败记录保留。第二次使用实际安装的兼容 runtime，没有 shim、改任务、改评分或模型答案替换。

本轮没有可调用的合格模型执行环境。因此 `model_requests=0`、`tokenizer_invocations=0`、`agent_successes=0`、`capacity_qualified=false`、`model_qualified=false`。参考控制证明任务和 evaluator 能在声明环境工作，不产生 AI coding 正确率、修复成本或维护优势的数据。此前模型资格的失败也没有被覆盖。

跨目标 qualification 实际编译并在 QEMU 执行 AArch64/RV64 的 v8 returned-loan profile：每目标 128 次正向 native 调用，共 256 次；14 个 native 进程包含 2 个正向驱动和 12 个 trap/mutation 负控制。另有 5 个静态拒绝和 VM 对照。实际值、分配器观察、trap 行为与 VM loan 账本分别记录；native lowering 擦除 loan 检查对象，不把 VM loan 计数当作 native 仪器结果。

跨目标原始报告没有 HEAD 字段。独立审计将其 299 个 source digests 与本轮 `ab6d346` 的完整冻结 inventory 逐项核对，全部一致；它与实现提交的来源绑定由这项核对派生。

`physical_hardware_executed=false`。本轮没有覆盖真实 MMIO、DMA、interrupt、共享内存原子模型、general allocator、foreign callback lifetime 或设备恢复。

## 8. 有限最优性：目标与边界都进入证据

新增 API 接受 `f(x)=(a*x+b) mod 2^64`，其中 `a∈{-1,0,1,2,3,4}`、`b∈[-16,16]`。既有 146 个 recipe 文法、encoder、candidate ID 和旧 `x+offset` 搜索协议保持不变。完整枚举所有候选，全部证明结果必须可判定且等价候选集合非空，才给出文法内最小值；unknown 或空集拒绝，选中候选进入 native 构建前再做一次新证明。

最终冻结 10 个目标：`a=-1,0,2,3,4` 分别配 `b=-12,+12`。所有选择在第一次 native build/timing 之前冻结。

- 1460 个实际 SMT 查询：10 个 proved、1450 个 disproved、0 个 unknown；每个否定项保留反例。
- 10 个文法内 minimum 均为 9 个函数体字节，包含 `ret`；另有 10 个新选择证明。
- 20 个 native build、160 个边界输出全部匹配；140/140 timing 样本保留，未删除慢样本。
- 实际 LLVM `-O3` 比较允许使用文法之外的指令：1 个目标候选更小，7 个同样大，2 个 LLVM 更小。`a=0` 的两个 LLVM 结果分别为 8、6 字节，直接说明有限文法的 9 字节 minimum不能扩大成任意 x86 minimum。
- 运行时间有快有慢；未建立运行时间优势、整个程序最优或真实后端 refinement。

成本模型是 Linux x86-64 SysV 的 `u64 -> u64` 函数体字节数。可观察输出为返回值；算术 flags 不是函数结果；ABI、ISA 模型和受信 SMT encoder 的范围写在完整协议中。详情见 [有限仿射搜索](HIA_BOUNDED_AFFINE_SEARCH.md)。

## 9. 原始失败、复现及下一道门槛

归档同时包含三类修正前记录：Python runtime 不支持 sealing 常量、最初四路径 harness 误读 Rust 报告字段，以及 NDU `/proc` 身份检查拒绝。四路径 harness 仅修复外部脚本的 `result`/`values` 读取；Hepta 实现没有为复跑变化。失败记录不计入成功分母，也不删除。

归档保留所有可解码 UTF-8 的原始输出及 SHA-256 清单。native 可执行文件、共享库、object 等二进制不打包；排除清单保留原路径、长度和 hash。回执中的原绝对路径是执行时身份，不保证在下载归档后的机器上仍可打开。复现需要重新构建实际 native 产物，不能把 retained receipt 当作重新执行。

执行命令、工具 pin 和外部 replay 脚本在证据目录说明中列明。完整 CI 的结果以绑定准确 SHA 的 Actions run 为准；证据提交本身不重新命名实现提交的结果。

下一步应按用户顺序继续提高这些门槛：生产 Rust 的明确 profile 准入；停止/取消/崩溃与 lowering 各阶段可组合的证明；真实 C++ 上游版本变更及完整人时；冻结未见真实 workload 的正净收益；同信息、同缓存、同预算的 NDU 独立增量；通过资格的模型实验；真实目标设备执行；更大但边界明确的可判定候选图。当前证据没有授权跳过其中任何一项。
