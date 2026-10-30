# HIA 第二轮推进：资源清理、C++ 检查点、CRC 候选与真实模型

本轮继续执行 P0–P7 的严格条件。新增实现已收敛到同一个提交：
`953fa62dee5aa563551d57b1374ab95b6d548b45`，Git tree 为
`aa0683509a02ca97e4e0c1dd723e4047f50d81b3`，包含 6,907 个受跟踪文件。
远端实现分支为 `work/hia-p0-p7-integrated-20261030`。文档和证据交付使用
独立的后续提交，不将交付提交冒充已经执行过的新实现。

本轮实际关闭了有限停止清理、C++ 父状态恢复、候选超出 lowering 限额、
native 计时缺失、失败前缀费用遗漏及模型 decoder 字段顺序等具体问题。
**P4 的必要成本净收益仍未通过，P5 的 NDU 独立增量没有建立；完整语言
安全、全范围权威切换和一般 C++ 自动安全重写也没有被有限实验替代。**
不能把 P0–P7 写成全部闭合。

## 1. 同一实现的验收

[最终实现的完整 GitHub CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41081527613)
已经 completed/success，job 为 `124151631902`。官方 artifact ID 为
`12993630367`，ZIP 1,364,149 字节，SHA-256 为
`c958985f54b2ace092af6c2ed38f95b06bd73414b6365a23bc4931c88794faa0`。下载内容与官方摘要一致，独立 reader 已逐条核对
测试方法终态、Rust 结果块、矩阵、source/tool inventories 与四个 NDU 身份。

| 验收项 | 当前提交的实际结果 | 范围 |
| --- | --- | --- |
| Integrated gates | 8/8 passed | 工具和 Linux seals、四个原生 NDU 身份、Rust crate、完整回归和 critical coverage |
| Python discovery | 4,346 个不同方法；0 failures/errors/skips | 外层进程 2082.230651266 秒 |
| Rust crate | 121 个测试、21 个完整结果块；0 failures/ignored/filtered | 实际固定编译器与 locked/offline 依赖 |
| Canonical safety matrix | 527/527 selectors、50/50 capabilities | 实际矩阵 614.747947479 秒；属于 full discovery 子集 |
| Critical coverage | 82 groups、194 unique modules、1,926 unique methods | full discovery 的精确子集，不加分母 |
| 输入身份 | 6,907 个源码文件、440 项外部输入前后一致 | 源 tree/blob/mode 与记录的实际工具身份 |

Workflow 的替代 profile 及其对应上传步骤存在条件性 skip；上述零 skips
指实际测试结果。CI 不重跑完整经济研究或真实模型生成，也不改变它们的
负结果。四个 NDU 身份 probe 不等于新的算法增量实验。

中央 canonical contract 为
`3ff0362f995c8341ab75fa32c19cc6bb9fc5d1bc1bbe932ab00d45409ef62faa`。
原有 45 项 capability、447 个 selectors 全部保留；新 contract 登记 50 项
capability 和 527 个 selectors。八项未经证明的普遍声明保持 false。
这是有限准入范围的声明与回归目录，不能由数量推出整个语言的 soundness。
完整回归、focused 资格与矩阵存在重叠，不将它们相加为独立成功案例。

中间提交 `3533b95c53d23de2d22c91fcc05cb601b8448eb3` 曾完成 P1/P2、
P3/P6 正式执行，但静态审查随后发现原 `xor_fold` 没有提供经济实验需要的
native 计时。该提交没有执行经济研究或模型生成，也没有发布为新的实现
分支或请求其 CI。补齐计时后，在 `953fa62` 上重新执行 P1/P2 与 P3/P6 正确性资格，并首次
执行本轮完整 CRC 经济研究与 V13 模型阶段。
3533 的记录与成本保留为历史，不能取得当前实现的资格。

## 2. P0–P7 状态

| 阶段 | 本轮新增且已实际验证的范围 | 严格阶段仍缺少什么 |
| --- | --- | --- |
| P0 | 继承 #394/#395 的共同实现基础，将本轮能力、routes、registry、contract 和回归放入同一实现；精确保留 Git 对象身份发布 | 本轮声明的候选收敛、精确源码验收与实现发布条件已闭合 |
| P1 | 有限 Rust profile 在预算停止或 trap 后按依赖顺序显式清理逻辑 loans/owners；保留原停止状态与清理前账本 | 完整 source→Core→native refinement；一般循环、递归、并发与任意失败路径；宿主 RSS、栈、CPU、OOM 与终止保证 |
| P2 | opt-in Rust 独立 verifier、有限堆准入、清理准入与 Machine 执行共享私有 admitted snapshot；不能保守界定所需资源预算或不支持的范围拒绝 | 默认/source/nominal/native 的完整独立验证和差分覆盖，以及明确的全范围权威切换 |
| P3 | 固定 nlohmann/json 两版本、固定 ABI/config 的父检查点保留与新请求重建；原真实 C 迁移记录保持各自身份 | 一般 C/C++ 低成本重写、一般硬件 ABI、长期上游维护与完整人工成本 |
| P4 | 新 GF(2) 线性候选通过现有证明与 native 门；真实计时接口和完整八臂成本研究完成 | 必要准备/交付成本计入后仍有正收益的合格热点；本轮冷门槛为 false |
| P5 | 强固定六候选与已知多项式静态 dispatch 的完整成本对比完成；旧 feedback/DP/NDU 只保留历史身份 | 同信息、预算、缓存条件下超过强固定、反馈贪心与轻量规划；本轮没有新的 NDU 资格 |
| P6 | 有界 C++ 父状态协议在异常、已识别 foreign abort 后保持已提交状态，并要求新请求；不确定清理会 poison owner | 一般活跃调用、任意 callback、状态迁移、回收及外部副作用恢复 |
| P7 | decoder 的实际 HTTP 字节和返回 GBNF 均可核对；新增公开类别约束与诊断，完整保留真实模型试验 | 真实模型校准仍 0/3；main 实际准入拒绝；独立开发和维护优势未证明 |

## 3. P1/P2：有限停止路径的显式逻辑清理

新增 `raw-byte-dag-finite-heap-cleanup-v1` opt-in profile。它继续使用独立
Rust 全模块 verifier、DAG 检查、私有 admitted snapshot 与原 Machine，
并在执行前独立核对有限 live-payload 和清理动作界。令 A 为该入口的结构性
allocator interaction 上界、T 为结构性 VM tick 上界、P 为整个准入模块中
最大的 borrowed-parameter 数，保守预留界为 `B = A + T * (1 + P)`。
请求上限最高 32,768 项；算术溢出或 B 超预算就拒绝。Typed journal 在
Machine 创建和语言入口执行前以 `try_reserve_exact(B)` 取得容量，不能
在执行后补造准入。清理动作和普通执行 ticks 分开记账。

发生支持范围内的 budget stop 或 trap 时，Machine 审计实际完整资源
inventory，按 child loan → parent loan → owners 的顺序执行显式释放；call-formal
witnesses 按其父子关系参与清理，并单独核算。
错误 inventory、无法完成的内部释放或未知范围不会得到清理成功回执。
原始 stop/error、ticks、peak 与清理前账本保持不变；清理 journal 和后置
账本分别记录。正常返回本来就必须清洁，不由该机制修复不合格返回。
外部资源入口、chain、callback 不因这个 profile 获得准入。

同提交正式执行得到 20 项 Python 测试、121 项 Rust 测试全部通过，
没有 failure/error/skip/filtered。314 个直接 Rust 进程包含 271 次 rc0、
43 次预期 rc1；其中 260 条完整观察为 183 returned、48 budget stop、
29 trap。58 条停止时有非零 payload，18 条停止含 formal witnesses，
全部观察的清理后逻辑账本归零。37 条显式 refusal 是直接进程的子集，
另有 2 个隔离 Python 子进程；这些分母不能相加。

本轮重用原 253-case 矩阵并增加 7 条观察，不称独立 holdout。复用 Cargo
缓存后重新执行实际进程；4,625,464 字节的 executable SHA-256 为
`39fb7af2de0178997ffbe5b13c0e54302c0453accdf6ea3e421fc9b4427e4af7`，
没有声称 clean rebuild。外层耗时 55.408975566 秒；Python stage
49.170802457 秒、Rust stage 2.329417820 秒属于其中的嵌套成本。

这里证明/观察的对象是声明范围内的逻辑资源，不包括 JSON 报告分配、
宿主 OOM、panic、进程死亡或 OS 释放。它没有授予 native 执行权威，也没有
把有限差分当成整个语言的 soundness 或 source/native refinement。

## 4. P3/P6：C++ 父状态重建

在冻结提交 `953fa62dee5aa563551d57b1374ab95b6d548b45`（tree `aa0683509a02ca97e4e0c1dd723e4047f50d81b3`）上，正式 collector 实际执行了 **146 次 worker 调用**。nlohmann/json 3.11.3 和 3.12.0 各执行 73 次：2 次校准、17 个实际分配故障点各 4 次调用，以及 3 个普通输入案例。每个故障点的 4 次调用依次是提交前缀状态、注入故障、用新独立请求重建、继续下一次状态转换；拒绝旧请求重放不会启动额外 worker。因此 146 = 4 次校准 + 136 次故障链调用 + 6 次普通案例，不能再把下面的重建观测加到 146 上。

两个版本各有 14 个故障点返回 caught-exception 状态，另外 3 个故障点在 `noexcept` 析构路径发生 `SIGABRT`，位置均为 15、16、17。合计 **28 次 caught exception + 6 次 foreign SIGABRT = 34 次故障调用**。这六次 foreign 终止仍是失败调用，没有被改记为已恢复的 C++ 生命周期。

实际新增的是父状态的有限保证：34 次故障调用全部保持前一个已提交的父 checkpoint；随后 34 个新请求分别完成重建，再以 34 次后续调用继续状态转换。保持、重建和继续是同一批 34 个故障点上的三个阶段观测，不是三组独立 holdout。父状态是有界整数数组，并非任意 C++ 对象的快照。实现复用现有 scoped C ABI、Hepta caller 和 bounded process owner，在 fresh child 内执行原库，不传递 foreign 指针或句柄，不自动重试失败请求。只有正常子进程退出、完整且绑定请求的标量结果、普通资源账本等检查全部通过后，才提交新父状态；cleanup 不确定或协议不一致会 poison owner。

该路径仅覆盖 Linux x86-64 上两版固定库和固定 adapter/config，父状态为 1–64 个绝对值不超过一百万的整数，每个 owner 最多签发 128 个请求。它没有把 C++ 库重写为内存安全语言，没有证明一般 C/C++ 低成本自动迁移、任意 foreign 状态迁移、外部副作用回滚、完整环境隔离或所有 escaped descendants 的结束。旧有 signed-UB、overflow 与一般 C++ 安全/迁移边界也没有被本轮结果消除。**Universal migration 和通用 foreign 恢复仍未成立。**

正式运行前后，6907 个受跟踪仓库文件、354 个 profile source 文件、13 个所观察的工具/loader/runtime 文件及 PLAN、launcher 身份保持一致。实际 collector 报告 SHA-256 为 `30b04094713b33b9f51dd474574fcd637c3273eb554eb4be934672d393abe099`。Collector 23.800755358 秒、stage 23.922731220 秒、launcher 27.613573332 秒与外层调用 27.663971308 秒相互嵌套，不能相加；运行与另一项正确性验证并行，因此不用于性能比较。完整人工开发、审查、集成成本和完整 agent token/财务成本仍为 unknown，不能由这些测试耗时推算为零或完整开发账单。

此前 `3533b95c…` 的独立正式运行、原始记录和已核验归档全部保留，没有改标为 953 的资格。953 的原始 Git 对象 audit、1,580 成员完整归档回读和独立交叉回读现已完成，均返回 0；归档保留 1,130 个原始 Git 对象、完整 354 文件 profile source 闭包和 6,907 文件仓库清单，但并未打包全部仓库 blob。最终目录另附完整 prior-3533 子包及当时 reader 首次失败和修复后成功的原记录。实际离线可搬迁验证把两个包复制到 /tmp，拒绝对子进程的一切 /workspace 文件读取后，953 与 3533 两个独立 reader 仍均返回 0。上述回读不运行归档程序、不重新执行 worker，也不授予新 HEAD 执行资格；历史与本轮分母保持分开。

## 5. P4/P5：新候选通过正确性门，实际净收益未通过

复用已有 CRC byte kernel 和强固定基线，新增 IEEE、Castagnoli 与 dual
三类 GF(2) 线性展开候选。候选生成器不具有语义或安全准入权；独立有限
u32/first-trap 验证、LLVM lowering 和实际 native 检查仍是必要门。
旧三个候选的内容不变。第一次 dual 展开有 148 个 operations，被原 128-op
后端上限拒绝；修复共享 fast body 后为 4 blocks、105 operations，没有
扩大后端准入限额。首次失败与已执行的 native 前缀完整保留。

本轮还补上两个实际实验缺口。其一，native 交付已完成前缀的调用次数与
计时先登记，再进行可能失败的证据写入；未知或未结束费用不能记零。其二，旧 `xor_fold` 没有计时，
因此新增显式 `allow_timed_xor_fold=True`、wire mode 3，而旧 wire modes
0/1/2 的含义保持不变。实际 `CLOCK_MONOTONIC` 覆盖同一个 fold 循环，
包括 input load、间接调用、rolling checksum 和循环开销；它不是纯 LLVM
body 时间。缺失、非整数、非正或倒退的时钟被拒绝，trap 保留已完成前缀。
没有靠增加重复次数、扩大工作预算或取消 proof gate 取得结果。

在最终冻结提交上的唯一完整八臂研究完成 96/96 observations、276 个
native contexts、1,536 次交付请求、393,216 次登记 kernel calls。
原始 C 参考 48 项和 native preparation differential 384 项另列，不加到
交付调用数。本轮 NDU 决定次数为 0。准备差分的留存依据是 aggregate receipts 与产物
身份，离线 reader 没有宣称具备逐案例原生 transcript 或重新执行这些调用。
各臂使用同一冻结输入、候选池、工作
预算和缓存规则；来源、工具、协议保持一致，释放完成，外层 300 秒上限
内完成。

| 实际观察 | 结果与范围 |
| --- | --- |
| 新候选 full-host 比较 | 18/18 均未取得正收益，全部负例保留 |
| dispatch 对六个强固定候选 | 6/6 均未取得正收益；未加共同准备成本已经慢 1.129–6.172 ms |
| `linear_ieee` 在 IEEE 数据 | 训练/验证的计时 fold loop 分别节省约 1.803/1.705 ns 每调用 |
| `linear_dual` 在 mixed 数据 | 训练/验证的计时 fold loop 分别节省约 2.521/2.534 ns 每调用 |
| 必要成本冷门槛 | false |
| NDU 独立增量 | 未建立，没有用本轮局部循环改善晋级 P5 |

也保留 dual 在 IEEE validation 变慢、单一 Castagnoli 的保守 envelope
未通过等反例。两个重复样本不是统计置信区间，冻结合成数据不是独立真实
生产热点，`performance_timing_qualified=false`。

子进程完整外层成本为 29.117586164 秒；交付 host 时间合计 4.203922984 秒，
其余共享非交付费用 24.913663180 秒。额外三份候选映像准备 component 为
10.865144990 秒，已包含在相关费用中，不能再次相加。按 mixed 观察假定
局部节省始终保持，仅这个 component 就约需 42.9–43.1 亿次调用摊平；
按全部共同费用约需 98.3–98.8 亿次。**这些是条件算术，没有测得未来盈利，
没有证明存在相应生产负载，也没有消除已经观察到的 host 端负收益。**

当前 owner 的硬限为 4,096 个 trace、每 trace 最多 65,536 个值，单 owner
容量上界是 268,435,456 次调用；取消的 trace 也消耗登记数。上述十亿量级
已超出同一已实现 owner 的寿命。这里只做容量与条件成本算术，没有执行
这个上限的工作，也没有把纳秒样本差当成可持续的性能定理。

旧 `44e34b7` 上的 stb/NDU 研究保持原身份：固定、反馈、轻量 DP、原生 NDU
同信息比较仍是负结果，32 次 NDU 决定与同模型 DP 完全相同。那不是本轮
重新运行的数据，也不能证明 NDU 超越轻量规划。NDU 继续只能提交待验证的
候选/调度建议，不能授予资源、安全或执行权限。

## 6. P7：真实模型结果与接口改善分开记账

V13 由完整公开 query 构建 decoder：所有 editable IDs 保留，Rust type
与 expression 分类，type 只使用已公开的 scalar/`Vec<u8>` 语法。实际 HTTP
body 保留 insertion order，随后独立检查 native GBNF 的 edit-object rule
确实先选择 node 再生成 changes；原 canonical 内容摘要仍单独计算。
模型输出原样保留，decoder 不提供参考答案节点或替换值，不改变编译、资源
或行为准入权限。新的公开诊断说明选中节点的类别与原位置；各臂都收到
同一类通用的完整规格复核提示。

提示与 decoder 的变化在 V13 协议中明确披露。任务、预算、temperature、
seed、8192 context、1536 output reserve、每格最多三次提交以及 3/3 校准门槛
保持冻结。实际模型仍是固定 Qwen3.5-4B Q4_K_M；GGUF 2,740,937,888 字节，
SHA-256 `00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4`。

容量阶段 19/19 controls 通过，独立 CLI tokenizer 的 95/95 次 token IDs
完全匹配；模型答案请求为零。这些参考控制不是模型开发成功。随后实际
执行全部三个资格任务，每任务三次提交：

| 资格任务 | 实际三次提交 | 正确 |
| --- | --- | --- |
| `json_scalar_reasoning` | 1 次节点祖先/后代重叠拒绝、1 次类型编译拒绝、1 次行为错误 | false |
| `two_file_signature_repair` | 3 次节点祖先/后代重叠拒绝 | false |
| `owner_flow_repair` | 3 次节点祖先/后代重叠拒绝 | false |

**结果仍为 0/3。** 九次实际返回均满足当前公开 JSON/category schema，且
九次原生 decoder/GBNF 的顺序检查通过；这没有赋予编辑事务结构、类型或
行为正确性。输入 21,577 tokens、输出 1,659 tokens，总计 23,236；未知
usage 为零、人工答案修补为零、hidden evaluation 为零。原始模型输出未
经 host 改写。三个资格任务都用于校准基础 Rust 节点开发能力；16 格
HIA/Rust 主对照没有运行，不能从这里推断两种语言谁胜谁负。七次重叠拒绝仍保持原 source revision，不能自动择一或删除
其中编辑来伪造模型成功。

随后实际调用 main CLI，rc1 返回 `E_TOOLSTUDY_NO_QUALIFIED_MODEL`，
拒绝发生在引擎构造之前；主目录未创建、主试验格数和生成请求均为零。
容量、校准、main 拒绝的外层耗时分别为 95.149394835、538.952711871、
5.579925408 秒，内层成本已包含，不再相加。源码、模型与工具身份前后
一致，引擎关闭/退出完整。P7 的成熟语言工作流对比尚未获得启动资格。

这是基于 V12 失败的同任务接口跟进，不能称为新独立 holdout 或公开预注册
研究。V11/V12 的所有失败与用量仍保留；未知人工开发、审查和完整财务
成本不记为零。没有正确开发/维护任务对照就不能声称 AI 开发效率超过 Rust、
TypeScript 或 Python 工作流。

## 7. 可复核交付与继续开放的严格条件

| 证据 | 仓库入口 |
| --- | --- |
| 同提交官方 CI、完整方法/矩阵与独立读回 | [hia_next2_ci_20261030](../evidence/hia_next2_ci_20261030/README.md) |
| Rust 清理：953 正式包与独立 3533/development 历史包 | [hia_next2_resource_20261030](../evidence/hia_next2_resource_20261030/README.md) |
| C++ 检查点、原始 Git 对象、两版故障与历史 reader 失败 | [hia_next2_cpp_checkpoint_20261030](../evidence/hia_next2_cpp_checkpoint_20261030/ARCHIVE_README.md) |
| CRC 全部样本、负对照、成本、四版源码和 reader 失败 | [hia_next2_crc_linear_20261030](../evidence/hia_next2_crc_linear_20261030/README.md) |
| V13 模型输出、实际 wire/GBNF、SSE 用量和 main 拒绝 | [hia_next2_agent_v13_20261030](../evidence/hia_next2_agent_v13_20261030/README.md) |
| 总账、报告审查、集成测试和源码发布回执 | [hia_next2_integrated_20261030](../evidence/hia_next2_integrated_20261030/README.md) |

离线读回逐成员检查摘要、实际输入/输出、源和工具绑定、状态与费用分母；
不解包执行程序，不增加 native/model 成功案例，不签发语言准入回执，也不
充作历史执行的密码学证明。原始失败、修复前版本与未知费用均保留。

本轮已把上述具体实现问题转化为代码、回归和同源实际观察。仍开放的条件
需要新的正面证据：完整的跨层语义/资源证明、覆盖全部声明范围的独立 Rust
权威、真实大规模 C/C++ 迁移和维护账目、必要成本后的优化收益、NDU 在强
基线之上的独立收益，以及合格真实模型上的独立开发/维护比较。普遍的
“每条指令全局最优”“任意 C++ 零成本安全转换”“绝对资源安全”不是本轮
有限数据所能签发的结论。
