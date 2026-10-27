# HIA 下一步交付验收审计

## 审计结论与版本

**现有实现已经形成可独立执行、共享资源检查权威的 HIA 核心，并完成了有限范围的组合资源、C/C++ 迁移和跨目标执行资格；不能据此宣布用户六项要求或全部 blocker 已闭合。** 第 1、2 项在声明的 profile 内具备实现和执行证据；第 3、4 项存在明确的未支持功能；第 5 项修订后的性能重测与实体设备验收尚未计入；第 6 项真实模型试验已完成，但没有证明一般开发收益。

本审计固定实现提交 `83cbd102ce3f94d95e51a94e446f2a0ff639816c`，对应 [统一 run1 报告](../hia_next_20261026_run1/qualification.json)。该报告记录 **1,780 个测试、0 跳过、0 失败、0 错误，11/11 个限定范围 gate 通过**，同时明确 `full_six_deliverables_complete: false`。运行前后源文件快照一致。编译器树 SHA-256 为 `56d86bb0fef6fa2c8f0ced9e501f62450c96759fe5c9a98c2e5de78ad807b2c3`；完整源快照 SHA-256 为 `f788c9018541d0236ded555ee8c41421fee2900aa0c628017934559736fe0238`。

审计时 HEAD 已推进到 `6899d4761c3a42437ac02b7b5c6c8f8aa153dd79`。相对上述固定提交，仅性能脚本、其测试及相应文档变化；**本审计不把 v1 的已测结果自动归给 v2 性能协议**。所读源码的提交字节哈希、当前字节哈希、证据文件哈希均见 [claims.json](claims.json)。本次只读实现、文档和保留证据，复核文件哈希，没有重新运行模型、解释器、原生程序或重型测试。审核人参与过模板迁移及组合资源 qualifier 的实现，因此这是团队内部的独立验收视角，不是第三方认证。

## 六项要求逐项判断

| 用户要求 | 已有具体闭合 | 仍不能据此声称的内容 |
| --- | --- | --- |
| 1. 统一两条实现线 | 旧 executable Core 的实际操作、旧 SSA 的实际 PHI/边转换为同一个 primitive core；v2 再进入同一 verifier；规范明确后端和资源范围 | 历史兼容命令并未全部移除；不存在整个编译器的语义保持证明 |
| 2. 独立 HIA 入口 | JSON 程序无需原高层源码即可检查、解释、直接 LLVM 编译；控制流、资源、身份绑定的反例有拒绝证据 | 不等于任意机器汇编、裸指针或所有硬件目标；安全规则通过也不等于符合用户业务意图 |
| 3. 可组合资源核心 | 有界泛型 product/enum、函数内存储借用、错误路径、显式 poll 和取消协议已组合执行 | 逃逸借用、递归堆 ADT、后台调度、通道、抢占和一般并发仍未支持；部分协议状态错误在运行时拒绝 |
| 4. C/C++ 迁移 | 真实 compile_commands、宏/头文件、具体模板实例、重载与多资源案例进入独立 HIA；捕获范围内声明有处置 | 任意历史库、STL/class templates、通用 RAII、复杂 C++ ABI 与低总迁移成本未完成 |
| 5. 性能与硬件 | v1 三个内核、两个 Rust 对照的 63 个样本达到既定阈值；x86-64 原生、AArch64 QEMU 有实际执行 | v2 固定构建布局重测待证；模拟器不等于实体板、设备协议和时序；无 Rust 全面性能优势结论 |
| 6. agent 收益 | 真实本地模型、冻结输入、2×2 四任务试验、实际原生控制和完整计数已经运行 | 成功率/错误率的可推广改善、维护成本和总体开发成本改善均未证明 |

## 共同安全权威与 canonical exports

[core.py](../../hepta/core.py) 的 `verify_core` 直接指向 primitive verifier。`from_executable_core` 认证并解码实际 executable operations 后降低到该 core；`from_scalar_core` 读取真实 SSA/PHI 和控制流，做向后活跃性传播后再检查结果。转换不是把几份报告放进一个容器，也没有以缺失值默认补零。历史源语言检查与兼容后端仍保留自己的范围，这些范围不会扩大独立 HIA 的许可集合。

[hia_program.py](../../hepta/hia_program.py) 对 v2 调用结构 elaborator，然后对其完整 v1 输出再执行同一 primitive verifier。公开构造 `VerifiedProgram` 并不会获得信任；执行和发射入口重新检查其字节。携带结构来源的对象还要重新展开来源并与 canonical core 字节严格匹配，输入哈希与 core 哈希分别记录。SHA-256 提供身份绑定，不提供正确性证明。

公共接口已经写进 canonical v1 的 `exports`。v2 标准化总会发出该字段，解释器和 [LLVM 后端](../../hepta/hia_program_llvm.py) 都读取它；资源描述符不能进入公共 scalar C ABI。无 `exports` 的历史 v1 仍按原有 scalar 签名规则推断入口，这是兼容语义。[组合执行报告](../hia_next_20261026_run1/composite/qualification.json) 的结构输入与脱离原输入重载的 canonical 程序，共用 core 哈希 `0c0b858d29798fc7ab025d5a802d3b0105b868685fede7643abc34269b538cf6`，均仅导出 `choose`、`stored`、`task_case`，分别构建并执行了 18 个结果。

这里的共同权威是可执行资源规则与入口边界，不是任意程序等价性的判定器。独立修改一个已经降低的 v1 程序，会产生一个新的 primitive 程序；检查通过不能自动恢复被擦除的高层 nominal 意图，更不能证明仍与原 C/C++ 一致。现有整个编译器也没有形式化 refinement 证明。

## 组合资源：静态检查、运行时检查与外部条件

[结构 elaborator](../../hepta/hia_program_composite.py) 处理有界的名义 records/enums 和类型实例。打包、拆包和分支携带实际 owner/loan 身份；相同底层布局不允许忽略 nominal 类型。函数内部的存储借用可同时携带 owner、可变父借用和只读子借用，随后降低为相同的 primitive 资源规则。提前释放 owner、先结束父借用、子借用存活时写父借用以及非穷尽 owner enum 都有静态拒绝案例。

任务通过线性 token 持有状态；即使状态全是 scalar，也不能复制或遗失任务。`poll` 消耗旧状态并给出 pending 状态或 ready 结果，`cancel` 的实现必须消费状态资源。显式 `start/poll/cancel/join/close` 支持合作式执行。**任务的全部阶段并非静态 typestate**：重复 start、尚未完成就 join、运行中 close、完成后再 poll 的具体反例是编译后实际 abort。成功之后取消不会销毁成功结果，仍需 join；取消之后重复取消不再次运行清理。

[组合资格](../hia_next_20261026_run1/composite/qualification.json) 保留了 36 次原生结果、16 次实际分配与 16 次 free、12 次实际 NULL 拒绝、4 次协议 abort 和 8 个静态反例。两个正例变体各自结束时均为 0 live allocation、0 invalid free。删除所有 free 的独立编译反例仍给出相同 18 个业务结果，但观测到 8 次分配、0 次释放、8 个存活分配；因此结果正确没有被替代成资源正确。

现有存储借用不能从函数逃逸，enum payload 和任务状态/结果不能携带 loan；递归堆 ADT 不在此 profile。任务没有线程执行器、后台调度、抢占、通道或 I/O 唤醒。算术溢出、边界、分配失败和部分任务协议以运行时检查处理；native abort 和解释器预算耗尽后不承诺清理。原生安全还依赖 verifier/elaborator/LLVM emitter 正确、Clang/链接器/loader、ABI、allocator 契约和硬件。有限测试不能把这些可信前提升级为“绝对安全”。

## C/C++：声明、行为、ABI、链接和成本分别判断

[现有迁移报告](../hia_next_20261026_run1/migration/qualification.json) 记录 56 个 C 多 owner 案例、20 个 scalar C++ 案例、475 个 owned C++ 案例，共 1,102 次原生结果观测及 212 次受控故障观测。其中 owned C++ 路径仍识别完整的标准化 ownership protocol，不能推广成任意析构函数或自定义 RAII 的结构翻译。

[具体模板迁移](../hia_next_20261026_run1/cpp-templates/qualification.json) 则实际捕获两个 C++20 translation unit、本地头文件和 `PROJECT_BIAS=19`，读取 Clang 已实例化的函数体，支持有限类型/整数模板参数、重载、prototype 和跨 unit 调用。**70 个 active project declaration rows 都有处置，4 个具体模板实例执行了 227 个解释器案例与 454 次原生结果观测。** 70 是含容器、参数、prototype、重复头文件等条目的清单行数，不是 70 个独立库 API。范围是列入 compile_commands 的这次配置；遗漏的其他宏配置、平台或项目不能靠这份清单获得覆盖。无具体执行去向的模板、不支持的声明和对未捕获实现的调用都拒绝。

这条迁移路径的五个结论需要分开：

- **行为**：在所列的 defined C++ 输入上，原实现、解释器和目标程序结果相符。无符号数显式 wrap；有符号数在 HIA 中检查溢出。单独的 HIA overflow 反例原生 abort，未把该 UB 输入运行在 C++ oracle 上。没有声称所有输入语义等价。
- **安全**：迁移后的 core 独立资源检查；源程序 capture 或 Clang 的存在不是安全凭证。
- **ABI**：保留 extern-C scalar 名称，实际调用了 signed/unsigned 32/64 位及 bool 接口。C++ 内部符号改名。没有保留 class layout、vtable、异常、任意 aggregate 或一般 C++ mangled ABI。
- **链接来源**：原 C++ 对象只进入 oracle library；HIA target 使用直接生成的对象。精确链接参数有验证，目标没有复用原 C++ 函数实现。这与其他历史包装/桥接路径应分别陈述。
- **成本**：本次翻译耗时约 1.714 秒，原文件 2,538 字节，生成 Hepta 3,695 字节、HIA 14,852 字节。没有人工评审、移植工程、长期维护或总体经济成本测量，因此不能声称大规模迁移成本极低。

支持与拒绝边界见 [CPP_PROJECT_HIA.md](../../docs/CPP_PROJECT_HIA.md)。历史库生态、class/STL templates、指针/引用接口、异常、自定义析构和复杂 ABI 仍是实质性开放项。

## 性能与硬件：已有观测不跨版本外推

[run1 性能报告](../hia_next_20261026_run1/performance.json) 使用三个内核、7 组成对测量、三个实现，共 63 个样本，另有 588 次 correctness native calls。样本不剪裁、不择优重试。两个 Rust 对照分别是同源生成 Rust 与手写 safe Vec/slice Rust，保留 checked arithmetic 和 panic/abort 口径。

| 内核 | HIA / 同源 Rust 中位配对时间比 | HIA / 手写 Rust 中位配对时间比 |
| --- | ---: | ---: |
| constructor_error | 0.8554 | 0.8639 |
| full_lifecycle | 0.5649 | 0.9940 |
| two_stage | 1.0269 | 0.5628 |
| 几何均值 | 0.7917 | 0.7848 |

这是 v1 已记录的通过结果，不是 Rust 全面性能结论。HIA 保留 allocator effects，Rust 对照遵循其标准 allocator 优化规则；未比较 Rust allocator traces，资源观测位于独立的 untimed HIA 对象。机器为共享 host，固定 logical CPU 不能等同独占硬件。

后续发现 retention 目录参与构建路径，可能影响 Rust 嵌入路径和机器码布局。`6899d47` 将所有构建固定在等长临时路径，测量后再复制精确 artifact 并核对哈希。[v2 静态回归](../hia_perf_fixed_layout_20261026/README.md) 与 [之前的静态诊断](../hia_perf_layout_probe_20261026/probe.json) 均为 **0 个 timing sample**。它们证明所检查的构建布局性质，不能代替新协议的计时资格；本审计将 **v2 timing 标记为 pending**。

[原 AArch64 gate](../hia_next_20261026_run1/aarch64.json) 与 [组合补充](../hia_next_aarch64_composition_20261026/qualification.json) 使用实际 QEMU 执行；补充包含结构/normalized 各 18 个返回案例、12 次实际 NULL、缺 free 和错结果反例及 4 次协议退出。该补充绑定确切的 4,096 字节、一次仅一个 live owner 的 reviewed arena 与 calloc adapter。其结果不覆盖一般 allocator、实体板、真实设备时序、DMA/MMIO 或 GPU。历史 Cortex-M4 gate 也不能作为 standalone 32 位 HIA 或设备协议的验收替身。

## Agent 收益：完成实验，但收益标准未达成

[实际 Qwen 试验](../hia_next_agent_qwen_20261026_run1/report.json) 记录 29 次 started/received/validated generation，未决请求为 0；其中 2 次 preflight、27 次比较任务尝试。输入源码与工具绑定在实验前后不变；[16 个正负控制](../hia_next_agent_qwen_20261026_run1/controls.json) 均实际执行 native candidate。推理来自 owned llama.cpp child，经 private Unix socket 与 Linux SO_PEERCRED PID/UID 校验；模型文件哈希有绑定。这是本地进程与文件身份，不是硬件 attestation。

| 试验臂 | 成功任务 | 尝试次数 | 被拒绝候选 | 接受但结果错误 |
| --- | ---: | ---: | ---: | ---: |
| HIA full JSON | 1 / 4 | 7 | 2 | 4 |
| HIA semantic patch | 2 / 4 | 6 | 0 | 4 |
| Rust full function | 2 / 4 | 6 | 2 | 2 |
| Rust semantic expression | 0 / 4 | 8 | 8 | 0 |

这些是一个量化小模型、四个已披露单点修复任务的描述性结果。patch 臂的差异不能独立归因于语言，也不能推广为总体成功率、错误率或维护收益。完整生成臂也未显示 HIA 优势。报告正确保留 `effect_established`、`general_coding_advantage_established`、`maintenance_cost_measured`、`total_development_cost_measured` 为 false。第 6 项仍开放，不能用实验已运行替代收益已证成。

## 证据完整性与仍需完成的验收

本审计重新读取并核对了 composite 清单的 **74 个文件**、C++ templates 清单的 **30 个文件**，以及统一报告各 gate 的 stdout/stderr/子报告哈希；均与保留 receipt 一致。源码哈希与冻结 run1 源快照相符。哈希只能核对所保留文件，不能代替原始执行真实性或全输入证明；本审计未重新执行这些程序。

后续验收仍需真实新增证据：一般资源组合特性、历史 C/C++ 生态与复杂 ABI、总迁移成本、v2 稳定性能重测、实体硬件/设备协议，以及 agent 的可推广成功率/错误率/维护与总成本改善。把这些问题列为开放项是对现有结果边界的准确描述；本报告没有将用户原要求缩减后宣布全部完成。
