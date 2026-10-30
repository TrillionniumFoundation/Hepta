# HIA P0–P7：双候选收敛与后续执行

本轮由用户要求的 P0–P7 完成条件驱动。它延续现有 Core、registry、前端、
Rust checker/Machine、LLVM 后端及 NDU 原生桥，没有建立第二套 HIA ISA。
实现完成、有限回归通过、真实实验完成和阶段最终闭合分别记录。

## 来源与收敛

合并基线是以下两个实际候选：

| 候选 | 精确 HEAD | 保留的实现 |
| --- | --- | --- |
| PR #394 | `95a67fb487da981e1941ec0d44c7f4305a22e6d6` | Rust v4 与密封执行镜像、返回借用与资源链、结构化循环跳转、共享证明预算、146 文法搜索 |
| PR #395 | `2cc9fb3b92a7306d2f5aae316c99e8364be700f9` | v8 payload/borrowed extent、实际 native/source 复核、有限原生执行上下文、CRC 协议及后测试循环证据 |

双亲合并提交为 `53717f78e5d3dd91e7d41776c326665fa702222c`，分支为
`work/hia-p0-p7-integrated-20261030`。后续功能和证据提交分别保留自己的来源。
旧 #394/#395 的运行记录仍然只证明各自原来的实现；不会因为出现在合并树中
而自动成为本轮结果。

合并处理了六个文本冲突，以及一个自动合并没有标出的语义问题：
`CTranslator.stmt` 中出现两个 `DoStmt` 分支。保留较新的出口敏感确定初始化
分析和唯一的结构化循环 lowerer，删除不可达的旧实现。原 round8 测试给每个
拒绝例子都追加了 label，无法区分“结构化循环不支持”和“label 不支持”；
现在分别验证已支持的声明、嵌套循环、break/continue/return、单语句循环体，
以及仍然拒绝的 goto、label、switch 和未获资格的副作用表达式。

Canonical safety matrix 保留两边能力及回归，并对范围有变化的 post-test
条目重新审查和固定 hash。工作流使用明确的分支名单选择 integrated profile，
同名前缀或后缀分支仍进入原 full profile。

## 同一 Core 的入口与适配关系

| 入口 | 实际语义/适配 | 准入与限制 |
| --- | --- | --- |
| primitive HIA v1–v8 | 版本化闭合 SSA、整数、byte owner/loan、bulk memory、chain、参数借用返回 | 默认 Python Core verifier 重新核验实际字节；版本名称不是安全回执 |
| composite v1–v4 | 受检 nominal products/enums/tasks/partial records；分别降至 primitive v6、v7、v7、v8 | 保留输入与规范 Core 双身份；不直接赋予公共 C ABI |
| 有限 Hepta source | 已有 source checker/lowering → 同一 canonical Core | 不把 source checker 成功视为完整 source→Core refinement 定理 |
| 捕获 C 项目 | 实际 Clang AST、构建参数、依赖及 foreign contracts → 已有 source/Core 路径 | 本轮新增完整 if 条件中的有限 postfix 顺序求值；未支持的控制和指针语义明确拒绝 |
| 捕获 C++ 项目 | 已有 concrete leaf/composed/unique-owner 项目与配置矩阵路径 | 只覆盖已实现的有限类、所有权、调用与 ABI 约束，不是任意 C++ 迁移器 |
| 独立 Rust shadow/预算分析 | 原始 primitive Core → Rust owned verifier、Machine 和独立 DAG 预算 | 与默认生产选路区分；Python/Rust 差分不能自行授权 native |
| 独立 Rust byte-DAG 执行 | 原始 primitive v1–v8 字节 → Rust 全模块验证、逐函数静态限额、同快照 v4 Machine | `raw-byte-dag-v1` 模式由 Rust 独立准入；拒绝 cycles/chains/source/nominal，不产生 Python VerifiedProgram 或 native 授权 |
| direct LLVM | 重新验证的 Core → 已有 LLVM emitter → 实际 compiler/linker/产物复核 | backend、目标 ABI、host 环境及执行证据各自限定范围 |
| NDU 建议 | 原始 pinned Rust bridges、有限候选/路径规划 | 建议不授予 Core 准入、资源证明或生产发布权 |

Rust、TypeScript、Python、Go 和任意汇编源码还没有通用 Hepta frontend。
继承这些语言的设计优势与宣称已经实现这些语言的自动翻译是不同的工程结果。
机器可读兼容信息继续来自 `hepta.hia_schema.schema_registry` 和
`hepta.hia_routes.route_inventory`；历史 nominal v2 的歧义仍只能走显式适配器。

## 本轮增量与阶段门槛

| 阶段 | 本轮增量 | 最终完成条件中仍须单独验证的部分 |
| --- | --- | --- |
| P0 | 双亲合并、单一 post-test 路径、完整 safety matrix 与 integrated coverage | 最终冻结源码上的完整 qualification，不能替代为开发日志或旧 CI |
| P1 | Rust 独立 byte-DAG 静态上界：每函数 ticks、allocator interactions、root-inclusive depth | 活跃 heap/RSS、循环/递归/chain 上界、异常恢复、完整 source→Core→native refinement |
| P2 | 实现 `execute_rust_byte_dag`，无需 Python 语义准入；私有 Rust 快照绑定全模块检查、静态政策和实际执行 | 有限模式仍须最终整体验证；默认/source/nominal/native 完整范围的权威切换尚未完成 |
| P3 | 原始 musl 1.2.5 `strncmp` 保持源字节，通过捕获、Core、LLVM、VM 和 allocation-refusal 纵向验证；对真实 1.2.6 再次迁移并执行 | 后续 release 的函数体相同，不能证明语义变更维护；任意 C/C++、大型 C++ 版本变更、完整人力成本和长期维护优势未完成 |
| P4 | 有界 oracle reference 复用；完整执行/查找/证据/冷准备成本比较 | 多样真实热点上，计入必要成本后的正收益 |
| P5 | 保留强 static controls、相同输入与 reference 条件，以及 NDU 四类 pinned native identity | 本轮 CRC 五臂没有 NDU；不能把上下文合并或共享缓存收益归给 NDU |
| P6 | 复用结果与 trace nonce/实际执行分离，身份漂移、trap、poison、关闭和两种存储上限的负控制 | 通用活跃调用、foreign callback、持久状态迁移、回收和恢复范围仍须扩大 |
| P7 | 保留此前真实模型失败及门槛，检查新的可执行模型资格路径 | 必须由真实模型通过冻结资格和开发/维护对照，完整计费；参考答案、开发者脚本和本次助手写代码均不冒充该结果 |

## 资源语义

独立静态预算先检查完整 module，包括未调用 helper；再拒绝 byte-only inventory
以外的类型/指令、CFG/call cycles 和超出 `u64` 的有限展开成本。每项指标取各
分支独立保守最大值，不声称这些最大值同时发生。Bulk 操作的一次 VM tick
不等于常数 CPU 时间，allocator interaction 也不等于堆字节或 RSS。

正常返回、错误作为值、trap、预算停止、协作取消、递归和并发的原边界继续适用。
停止时保留实际资源前缀，不把宿主析构、进程退出或清理尝试写成语言级释放定理。
依赖外部 binary pin 的工具仍须信任其真实来源；攻击者自选一个 hash 并不能把
任意 executable 变成可信 checker。

详见 `HIA_RUST_STATIC_BUDGET.md`、`HIA_RUST_BYTE_DAG_ADMISSION.md`、
`HIA_C_POSTFIX_CONDITIONS.md` 和
`HIA_FINITE_ORACLE_REFERENCE_REUSE.md`。

## 原始 C 库和后续发行版

musl 1.2.5 与 1.2.6 的官方归档分别核验并重新捕获；两版 `strncmp.c` 都是
同一份 220-byte 原始函数体，`COPYRIGHT` 确有变化。每版实际执行 1,158 个
输入/分配失败组合，包含 2,316 次 C/Hepta native 执行和 1,158 次 VM 执行。
原始 C 代码、迁移结果、资源账本、编译/进程状态、源码快照和首次工具链失败
保存在 `evidence/hia_musl_strncmp_20261030/`，可离线重算归档清单和观测比较。

这些运行各自绑定原实现提交 `46534e04ec874bd5681b9f38914e210c2ef813be` 和
维护工具提交 `f82d016e08431bf9c16d12a613bfab6151103d8a`。后续合并不改标这些
证据的来源。此例采用明确的 LP64、`-funsigned-char` 和受限 owned-storage
适配；不能泛化为默认 signed-char ABI 或任意裸指针兼容。报告分别列出已测
自动化耗时、开发记录和未测人力，未知成本没有填成零。

## CRC 实验的来源与负结果

旧 120 秒 protocol v1 不变。独立 protocol v2 完成了 60 observations 和
240 native contexts，但所取历史 corpus 的前 4096 bytes 全零，两个 phase
重复；其原始输入、结果、成本和缺陷都保留。

在识别该缺陷后，另行冻结 protocol v3。SHAKE256 的 domain/phase/seed
分隔产生两个不同 phase 和 32 个互异、非全零 chunk；arms、预算、样本数、
停止条件与完整冷成本门不变。该修正有适应性，不能称为独立统计确认。

两次均保留全部 60 observations、240 contexts 和 245,760 native step calls。
V3 的 64 次 oracle miss、960 次 hit 和 70,188 canonical-byte peak 是
reference 复用观察，不是 cache-disabled 对照的端到端收益。冷经济门为 false，
NDU 独立增量为 false。共享开发机计时没有独占性能资格。

完整记录位于 `evidence/hia_finite_reference_20261030/`。V2 实际执行源码是
`2cd000135b5a252cf3b0f31d1c2b04649cd5a12e`，V3 为
`31574dc5387af54d0dd8e2336b9f69e3113c96ba`。后续合入的源码具有同一功能，
仍不把这些提交上的计时改标为最终 integration HEAD 的计时。

## 最终验收纪律

完整 integration runner 继续要求实际 Clang 20+、Rust、Z3 4.15.4、Linux seals、
Lean/QEMU 和四个分别 pinned 的 NDU profile；实际工具、外部输入和源码在
前后复核。全部 Python discovery 运行一次，critical module coverage 是该次
运行的子集，不增加测试分母。Canonical safety matrix 另列，不能将两者的
重叠方法相加为独立成功案例。

本轮默认 Python runtime 缺少 sealing 常量、Clang 19 不满足 native gate、
本地提取的 libclang 需要显式动态库路径等环境失败记录也保留；没有为通过
而降版本门、shim 安全常量、忽略失败或计入 skip。最终可执行资格只能由
冻结源码的 actual qualification 记录给出。
