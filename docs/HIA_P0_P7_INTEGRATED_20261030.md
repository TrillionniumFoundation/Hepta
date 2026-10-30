# HIA P0–P7：双候选收敛与后续执行

本轮由用户要求的 P0–P7 完成条件驱动。它延续现有 Core、registry、前端、
Rust checker/Machine、LLVM 后端及 NDU 原生桥，没有建立第二套 HIA ISA。
实现完成、有限回归通过、真实实验完成和阶段最终闭合分别记录。

## 本轮实际验收结果

实际执行的统一实现提交是
`50c4067399989e7194028576c38c0e783b78cf06`，Git tree 为
`464e1643e804d9f6dc4b1536416012317ea7b680`。后续文档与证据归档提交不改标
这些结果的执行来源，也不被称为另一个已经测试过的实现提交。

| 验收 | 实际结果 | 范围 |
| --- | --- | --- |
| run04 完整 Python discovery | 4,183 methods；0 failures、0 errors、0 skips；unittest 2,120.665 秒 | 一次完整运行；外层 full-regression gate 为 2,121.940367842 秒 |
| 独立 Rust crate | 109 tests；0 failures、0 skipped | 同一冻结提交上的独立 Rust 测试门 |
| 集成资格 | 全部 8 gates passed；source/external inputs unchanged | 6,570 个受跟踪仓库文件（含 docs/evidence/fixtures）和 440 项已记录外部输入前后相同 |
| critical coverage | 72 groups、179 unique modules、1,763 unique selectors 全覆盖 | 完整 discovery 的子集，不增加分母 |
| canonical safety matrix | 364/364 selectors、39/39 capabilities passed；unittest 412.379 秒 | 独立运行；与完整 discovery 重叠，不相加 |
| 补充依赖观察 | Boost/GDB 16,076 项、QEMU 396 项前后相同 | 实际依赖文件与已观察 loader 闭包，不是完整环境证明 |

Canonical contract SHA-256 为
`591573c769ad36061b00ac91b3ab780daa448074909d559c78f23eac32776cb5`。
矩阵 canonical report 及其 unittest log 完整。其额外外层 diagnostic stream
被工具输出预算截断，留存为 `OUTER_CAPTURE_PARTIAL.json`；没有借用另一轮输出
补齐，也不声称该附加流完整。矩阵的已记录 440 项外部输入在结束后与 run04
再次比较相同。

先前运行均原样保留：run01 在 `ba267bf` 上因模型运行时 pin 与失败计费问题
主动中止；run02 在 `50c4067` 上遇到缺少 Boost header 的实际错误后中止，
同时发现 GDB 缺失会使相关检查跳过；run03 在同一提交上
完整执行了 4,178 个方法，但 board class 初始化因 QEMU 10.0.13 不满足固定
8.2.2 要求而失败，留下 5 个方法未执行。修复使用真实官方 QEMU 8.2.2 和实际
依赖；没有改版本门、shim 安全常量、将 skip 计为成功或重标旧结果。

本次资格只关闭所声明的有限实现合同回归。完整语言 soundness、source→Core→
native refinement、一般并发安全、Rust 性能优势和全局最优声明仍为 false。

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
| 独立 Rust byte-DAG 执行 | 原始 primitive v1–v8 字节 → Rust 全模块验证、逐函数静态限额、同快照 v4 Machine | `raw-byte-dag-v1` 模式由 Rust 独立准入；外部入口限 exported scalar function 的精确标量参数/返回值；拒绝 cycles/chains/source/nominal，不产生 Python VerifiedProgram 或 native 授权 |
| direct LLVM | 重新验证的 Core → 已有 LLVM emitter → 实际 compiler/linker/产物复核 | backend、目标 ABI、host 环境及执行证据各自限定范围 |
| NDU 建议 | 原始 pinned Rust bridges、有限候选/路径规划 | 建议不授予 Core 准入、资源证明或生产发布权 |

Rust、TypeScript、Python、Go 和任意汇编源码还没有通用 Hepta frontend。
继承这些语言的设计优势与宣称已经实现这些语言的自动翻译是不同的工程结果。
机器可读兼容信息继续来自 `hepta.hia_schema.schema_registry` 和
`hepta.hia_routes.route_inventory`；历史 nominal v2 的歧义仍只能走显式适配器。

## 本轮增量与阶段门槛

| 阶段 | 本轮增量 | 最终完成条件中仍须单独验证的部分 |
| --- | --- | --- |
| P0 | 双亲合并、单一 post-test 路径、同一 50c4067 上完整 qualification 与 canonical matrix 均通过 | 已完成本机声明范围内的候选收敛；远端发布/CI不从本地结果推定 |
| P1 | Rust 独立 byte-DAG 静态上界：每函数 ticks、allocator interactions、root-inclusive depth | 活跃 heap/RSS、循环/递归/chain 上界、异常恢复、完整 source→Core→native refinement |
| P2 | 实现并在统一源码回归中验证 `execute_rust_byte_dag`，无需 Python 语义准入；私有 Rust 快照绑定全模块检查、静态政策和实际执行 | 只在 `raw-byte-dag-v1` 模式切换 Rust 权威；默认/source/nominal/native 完整范围的权威切换仍未完成 |
| P3 | 在同一 `50c4067` 上重新执行 musl 1.2.5→1.2.6 的有限 C 直接翻译，以及 nlohmann/json 3.11.3→3.12.0 的现有 C ABI 桥接升级；保留所有分配失败结果 | musl 函数体未变；JSON 仍链接 C++ 原库，每版有 3 个 foreign noexcept 终止；通用重写、语义变更维护、完整人力成本和长期维护优势未完成 |
| P4 | 有界 oracle reference 复用；按冻结协议核算执行、查找、证据和冷准备成本 | 多样真实热点上，计入必要成本后的正收益 |
| P5 | 保留强 static controls、相同输入与 reference 条件，以及 NDU 四类 pinned native identity | 本轮 CRC 五臂没有 NDU；不能把上下文合并或共享缓存收益归给 NDU |
| P6 | 复用结果与 trace nonce/实际执行分离，身份漂移、trap、poison、关闭和两种存储上限的负控制 | 通用活跃调用、foreign callback、持久状态迁移、回收和恢复范围仍须扩大 |
| P7 | 实际容量 19/19 与 CLI token-ID 95/95 通过；三项真实模型资格 0/3，九次生成完整计费；实际 main CLI 在 engine 启动前拒绝，主试验 0 cells | 当前量化模型与冻结工具协议组合未通过准入；没有 HIA/Rust 主对照结果，也没有 AI 开发优势证据 |

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

musl 1.2.5 与 1.2.6 的官方归档分别核验并重新捕获；两版完整 `strncmp.c`
源文件均为 220 字节且逐字节相同，包含头文件引用等文本；`COPYRIGHT` 确有变化。每版实际执行 1,158 个
输入/分配失败组合，包含 2,316 次 C/Hepta native 执行和 1,158 次 VM 执行。
原始 C 代码、迁移结果、资源账本、编译/进程状态、源码快照和首次工具链失败
保存在 `evidence/hia_musl_strncmp_20261030/`，可离线重算归档清单和观测比较。

这些运行各自绑定原实现提交 `46534e04ec874bd5681b9f38914e210c2ef813be` 和
维护工具提交 `f82d016e08431bf9c16d12a613bfab6151103d8a`。后续合并不改标这些
证据的来源。此例采用明确的 LP64、`-funsigned-char` 和受限 owned-storage
适配；不能泛化为默认 signed-char ABI 或任意裸指针兼容。报告分别列出已测
自动化耗时、开发记录和未测人力，未知成本没有填成零。

### 同一集成提交上的实际重跑

两版 musl 已在 `50c4067` 上重新捕获、构建并完整执行：每版都是 386 个输入 ×
三种分配拒绝设置，共 1,158 cells、2,316 次原生观察及 1,158 次 VM 观察。
两版 Core SHA 同为 `831ce9c34374520b4d4b912638a4ef85809e3775794793807787480cc6bd2699`。
HIA 目标没有链接原 C 实现，也没有 Rust codegen fallback。实际最终 native
live allocations、VM live owners/bytes/local loans 均为零；这些是该有限域的
实际观察，不替代全部输入的翻译证明。它们仍是既有矩阵的合并回归，
`same_matrix=true`、`new_holdout=false`。

另行执行了现有真实 nlohmann/json 3.11.3→3.12.0 升级工具。每版 98 个普通
输入通过，五个 C export、生成接口、原始 adapter/contract/Hepta caller 在该
次升级中保持一致。这条路径继续链接 C++ 库与 adapter，native Hepta caller 使用现有 Rust backend；
它没有重写 JSON 库，也没有证明 foreign memory safety。
每版实际校准 17 个分配失败点：14 个捕获异常并恢复，3 个被工具归类为 `foreign_noexcept_termination`：进程收到 SIGABRT，
原始 stderr 报告 `std::bad_alloc`；这些记录没有定位到库内部的具体析构路径。六次 SIGABRT 的完整原始 streams、退出码与
成本均保留；`all_allocation_failure_paths_recovered=false`。

三个外层执行分别为 32.201699015、32.943381907、28.600450890 秒，总计
93.745531812 秒。内部编译/执行计时是这些区间的组成，不重复相加；历史获取
成本没有再次计入。当前升级的零 adapter/contract/caller 改动不代表初次集成
免费，完整开发和人工成本继续保持 `null/unknown`。419 成员归档保留 182 个
源码绑定、三阶段真实产物与六个旧证据文件原字节；离线验证只重算字节与有限
观察一致性，没有执行归档代码或产生新的原生执行分母。

## AI 开发对照的独立资格

`experiments/hia_agent_toolstudy_v11_20261030/` 保留本轮唯一新模型的来源、
实际下载 hash、模板差异及冻结协议。它继承原任务、提示、预算和编辑接口，
不继承 V9/V10 的容量或模型资格；协议仅在本地先冻结，未声称公开预注册。
实际输入是 Unsloth 量化权重，并未证明与官方原权重/全部模板等价。

实际执行均绑定同一 clean `50c4067`。容量检查完成 19/19 原生/参考控制和
95/95 独立 CLI token-ID 比较；该阶段没有生成答案，参考答案不计作 agent 成功。
随后模型沿用 1,536 output tokens、8,192 context、每格最多三次提交、4 CPU
threads、seed 0 和 greedy sampling 的冻结预算，完成了全部三项资格任务：

| Rust node 资格任务 | 实际提交数 | 终态 | 正确 |
| --- | ---: | --- | --- |
| `json_scalar_reasoning` | 3 | `observable_wrong` | false |
| `two_file_signature_repair` | 3 | `response_rejected` | false |
| `owner_flow_repair` | 3 | `response_rejected` | false |

首题第一次提交被编译检查拒绝，后两次产生错误的可观察结果。其余两题的六次
提交均留下 `E_STRUCTURED_EDIT: changes exceed the selected node fields`：编辑
超出了所选节点允许修改的字段。这些具体失败说明当前模型与冻结编辑协议的
组合未通过资格；三个 CELL 均没有进入 hidden evaluation。

结果为 `valid_observation=true`、`status=all_cells_attempted`，但
`calibration_eligible=false`。九个请求都有完整返回用量：21,843 input tokens +
3,497 output tokens = 25,340 total tokens；未知用量请求为零，人为修复答案为零。
源码、工具和模型在执行前后相同，模型进程完成关闭。三项任务都属于该模型/协议
组合的独立资格，不构成 HIA 与 Rust 的主对照。

随后实际调用 `main` CLI，得到 `E_TOOLSTUDY_NO_QUALIFIED_MODEL`，进程退出码 1。
拒绝发生在 engine 构造之前，main 输出目录没有创建；主试验完成 cells 为 0，
不能报告成 16 格主试验失败或相对开发效率结果。本次冻结运行中没有更换模型、修改提示/任务、
扩大预算、人工修复答案或重新选择失败样本。

| 已记录操作 | 实际 wall time | 计量关系 |
| --- | ---: | --- |
| capacity 外层进程 | 79.384721413 秒 | 内层 79.253140256 秒已包含，不重复累计 |
| calibration 外层进程 | 697.485887898 秒 | 内层 697.344993804 秒及三个 cell 耗时已包含 |
| main 实际拒绝 | 2.874049887 秒 | 包含拒绝前身份/资格检查，没有生成 |
| 同一 GGUF 的恢复下载与校验 | 50.896889846 秒 | 1 次下载，未重试；与原首次获取 41.630981373 秒分别保留 |

模型是第三方 `unsloth/Qwen3.5-4B-GGUF` 的 Q4_K_M，实测大小 2,740,937,888 bytes，
SHA-256 为 `00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4`。
恢复只在完整 size/hash 匹配后发布模型路径。为恢复该模型，先在既有回归、矩阵与
P3 完成后移除了已记录的本轮临时构建/部分测试工具，保留观察和获取身份；该清理
耗时 0.588722641 秒。再次执行完整资格需要恢复那些测试依赖，不能把已归档的
环境观察解释为这些临时工具目前仍全数安装。上述时间不是完整工程或人工成本。

首次完整回归在 `ba267bf824a0f978f86b2003c8e4f0e9f70935ce` 上主动中止。
原因是并行只读审查发现 V11 尚未强制 runtime 归档成员 pin，以及 finalizer
异常可能遗漏成本记录；该次部分运行不计为合格。修复在任何模型加载或生成
之前完成：40 个运行时成员的字节和链接拓扑均受检，identity/close/file 失败
仍保留已知成本并使资格失败，未知用量不填零。任务、提示、模型和预算保持
原协议条件，修后的完整源码另行冻结并重新执行全部验收。

## CRC 实验的来源与负结果

旧 120 秒 protocol v1 不变。独立 protocol v2 完成了 60 observations 和
240 native contexts，但所取历史 corpus 的前 4096 bytes 全零，两个 phase
重复；其原始输入、结果、成本和缺陷都保留。

在识别该缺陷后，另行冻结 protocol v3。SHAKE256 的 domain/phase/seed
分隔产生两个不同 phase 和 32 个互异、非全零 chunk；arms、预算、样本数、
停止条件与完整冷成本门不变。该修正有适应性，不能称为独立统计确认。

复用只针对可信确定性 oracle 的不可变期望结果，需显式设置 `reuse_oracle=True`，
默认关闭；缓存限于单个 bank，不持久化、不在 owner 间共享。256 条目和 1 MiB
canonical 输入/结果 bytes 双上限保持独立，后者不包含 Python 容器开销，也不代表
活跃 heap 或 RSS。该路径额外假定 oracle 在 bank 生命周期内对同一输入具有确定性；
Python 纯度和这一确定性本身没有被证明。实际 native 调用、trace nonce、
证明、准入和执行回执不会由缓存替代。

两次均保留全部 60 observations、240 contexts 和 245,760 native step calls。
V3 的 64 次 oracle miss、960 次 hit 和 70,188 canonical-byte peak 是
reference 复用观察，不是 cache-disabled 对照的端到端收益。冷经济门为 false。五个臂均没有运行 NDU，
因此本轮未测量或建立 NDU 的独立增量；`NDU_incremental_value_established=false`
不表示已测得 NDU 增量为零。共享开发机计时没有独占性能资格。

完整记录位于 `evidence/hia_finite_reference_20261030/`。V2 实际执行源码是
`2cd000135b5a252cf3b0f31d1c2b04649cd5a12e`，V3 为
`31574dc5387af54d0dd8e2336b9f69e3113c96ba`。后续合入的源码具有同一功能，
仍不把这些提交上的计时改标为最终 integration HEAD 的计时。

V3 记录的 cold setup（含 release）为 8.101166973 秒，whole-study 为
12.093415514 秒。报告明确排除工具安装、外层解释器启动/imports/参数解析，以及
最后的分析、report JSON 编码与写入。因此这些是冻结协议的成本范围，不能称为
从零部署、全部研发或完整操作系统生命周期成本。六组 dispatch 对 strongest
static envelope 的比较在扣冷成本前也均为负值；观察到的 batching 差值不能
算成 specialization、cache 或 NDU 的独立收益。


## 最终验收纪律

完整 integration runner 继续要求实际 Clang 20+、Rust、Z3 4.15.4、Linux seals、
Lean/QEMU 和四个分别 pinned 的 NDU profile；实际工具、外部输入和源码在
前后复核。每次完整 qualification 的 full-regression 门运行一次全量 Python
discovery；critical module coverage 是对应运行的子集，不增加测试分母。Canonical safety matrix 另列，不能将两者的
重叠方法相加为独立成功案例。

本轮默认 Python runtime 缺少 sealing 常量、Clang 19 不满足 native gate、
本地提取的 libclang 需要显式动态库路径等环境失败记录也保留；没有为通过
而降版本门、shim 安全常量、忽略失败或计入 skip。最终可执行资格只能由
冻结源码的 actual qualification 记录给出。CRC 早期 Clang 19 开发尝试的
29 个普通方法通过及两个 native 方法报错只有已披露摘要，原始日志未保留；
该次尝试未计入 native 成功分母。

## 交付与离线复核

最终源码分支在执行过的 `50c4067` 之后仅追加文档及证据。编译器/runtime 实现、测试、工作流、
实验协议和生产运行器不随归档变更；最终 Git HEAD 与实际执行的实现 SHA 分别记录。
旧证据仍保留自己的提交、失败结局和计量范围。

| 证据 | 仓库内入口 | 作用 |
| --- | --- | --- |
| 本轮结构化检查点 | [RESULT.json](../evidence/hia_p0_p7_integrated_20261030/RESULT.json) | P0–P7 分阶段状态、实现身份、声明与未完成项 |
| P0 完整回归与矩阵 | [P0 README](../evidence/hia_p0_integrated_20261030/README.md) | 四轮历史与本轮终态、工具身份、原始输出、归档清单与有界只读 verifier |
| P3 同提交真实库重跑 | [P3 SUMMARY](../evidence/hia_p3_integrated_20261030/SUMMARY.json) | 有限 C 直接翻译、保留 C++ 库的升级、原始进程与未恢复失败 |
| P7 本次真实模型运行 | [P7 README](../evidence/hia_agent_v11_integrated_20261030/README.md) | 容量、三题资格失败、实际 main 拒绝、原始模型输出与完整已知用量 |
| 根审阅记录 | [root-review](../evidence/hia_p0_p7_integrated_20261030/root-review/) | 独立离线读回与报告范围审阅，不添加 native 或模型执行分母 |

离线 verifier 只检查归档成员、身份及已记录观察的一致性，不提取或执行归档内的
程序，也不替代完整 native/模型重跑。GGUF 权重及整套工具链没有随源码交付；
其实际获取来源、字节身份、运行参数和边界保留在对应记录中。

本轮 GitHub push 尚未完成：自动审批此前拒绝外部推送。分支
`work/hia-p0-p7-integrated-20261030` 的 push 会自动触发已配置的 integrated CI，
因此交付后需要确认这一具体远端写入及自动触发的运行；本地通过不能替代远端结果。
