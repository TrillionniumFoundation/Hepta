# HIA 下一步：同一实现验收、实际负结果与剩余条件

本轮继续执行用户给定的 P0–P7 严格完成条件。现有 Core、registry、前端、
Rust checker/Machine、LLVM 后端和原生 NDU 桥继续复用。本轮没有另建一套
ISA，也没有把旧结果改标为新版本。

**实际执行的统一实现提交是 `44e34b7a9ecd6bf1b3ad6093d21bba10d2a18304`，
Git tree 为 `835555fb35dbdcf867724ef7a0bb1a6616270217`。**
后续交付提交只保存文档与证据；它与实际执行的实现身份分开。

本轮完成了资源准入、真实 C 语义变更迁移、执行上下文、Agent 编辑接口和
实验成本汇总的具体修复。完整工程回归通过。**P4/P5 的净收益条件和 P7 的
模型资格没有通过，P0–P7 不能标为全部闭合。** 完整语言证明、一般 C++
安全重写、全范围 Rust 权威切换与一般动态恢复也没有被有限回归替代。

## 1. 同一实现提交的实际验收

[最新实现的完整 GitHub CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41061115481)
已经 completed/success，job 为 `124080797698`。CI 从精确的上述提交建立干净
工作树，执行完整回归及 canonical safety matrix。官方 artifact ID 为
`12982148935`，下载 ZIP 为 1,318,884 字节，SHA-256 为
`fd29bbd98ac293e51e1c2acc234d5ef0157333c634b6f390e2e95a6a356c8c6e`。

| 验收项 | 实际结果 | 解释 |
| --- | --- | --- |
| 八项 integrated gates | 8/8 passed | 工具与 Linux seals、四个独立 NDU 身份、Rust crate、完整回归、覆盖核对 |
| 全量 Python discovery | 4,266 方法；0 failures、0 errors、0 skips | 一次完整运行；外层回归命令 1,665.732013695 秒 |
| 独立 Rust crate | 116 测试；21 个结果块；0 failures、0 skipped | 20 个 Running harness 与 1 个 Doc-tests；包含零测试块，使用实际编译器与离线锁定依赖 |
| Canonical safety matrix | 447/447 selectors、45/45 capabilities | 原 364 个 selectors 全保留；本次矩阵 391.799899017 秒 |
| Critical coverage | 77 groups、187 unique modules、1,846 unique selectors | 完整 Python 运行的子集，不另加分母 |
| 输入身份 | 6,685 个受跟踪文件、440 项外部输入前后一致 | raw Git tree/blob/mode 与实际工具输入核验 |

Canonical contract SHA-256 为
`bd58291c3bc3470840a6b22b9f712fe1766629e3cbae8bd83291da16c911f018`。
矩阵与 full discovery 存在重叠，不能相加为独立成功案例。CI 没有重新运行
完整经济研究或模型生成；这些活动的同提交独立记录分别列在下文。

历史发布提交 `73922c1` 的 CI `41056856811`、中间实现 `f7cc872` 的 CI
`41059399079` 也分别通过，原始 API 回执和 ZIP 保留各自的 HEAD。
`f7cc872` 的 CI 通过并没有修正该版本随后实际发现的经济研究汇总错误；
其经济研究继续保留 `qualified=false`。

## 2. 本轮修复与严格阶段状态

| 阶段 | 本轮已实现并实际验证 | 仍未满足的完整条件 |
| --- | --- | --- |
| P0 候选收敛 | #394/#395 的既有双亲合并继续作为祖先；全部新能力进入同一 `44e34b7`，registry/路由/权威范围明确；该提交远端完整验收通过 | 本轮声明范围内的候选收敛与发布阻塞已闭合 |
| P1 资源证明链 | 独立 Rust 有限入口 live-payload 分析覆盖调用、移动 owner、借用根、返回 loan、分配失败与停止前缀；未知范围拒绝 | source→Core→native 的完整 refinement、一般循环/递归/并发、RSS/CPU 与通用失败清理证明 |
| P2 Rust 权威 | `raw-byte-dag-finite-heap-v1` 在独立 Rust 私有快照上完成检查、预算准入与实际 Machine 执行，无 Python 语义准入依赖 | 默认、source、nominal、native 全范围权威没有切换；有限差分不是全语言 soundness |
| P3 真实迁移 | 完整 `stb_divide` 0.93→0.94 的真实函数体变更，经现有 Clang capture→source→Core→direct LLVM 重新迁移；源与 VM/native 回读严格绑定 | 一般 C/C++ 低成本重写、一般硬件 ABI、长期维护成本与完整人工成本；历史 C++ foreign 终止仍存在 |
| P4 有价值候选 | 原始 scalar-call closure 与候选独立 SMT 比较，保留首次 trap 次序/代码；真实组件形成四个有验证的 native 候选 | 本轮计入准备与交付成本后的候选净收益为 false |
| P5 NDU 增量 | 原生 NDU 与强固定、反馈贪心、轻量精确规划获得匹配的信息、候选、预算、缓存；32 次真实 NDU 决定完成 | 本轮 NDU 增量门为 false；32/32 与同模型精确规划相同，未证明独立算法收益 |
| P6 动态执行 | 关闭 oracle 重入造成的状态/配额漏洞，增加有限独立输入 map-repeat；46 项实际 context 回归通过 | 一般活跃调用、任意 foreign callback、持久状态迁移、回收和恢复仍未获得完整资格 |
| P7 AI 开发 | 公共节点字段驱动的 V12 decoder、公开诊断及构造失败清理；容量与真实模型试验完整执行 | 三项模型资格 0/3，主对照未启动；AI 开发及长期维护优势未证明 |

### 独立 Rust 有限入口堆准入

新 profile 接受 primitive v7/v8 的一个精确标量入口。它在既有 Rust 全模块
owned verifier、DAG 检查与私有 admitted snapshot 上加入有界抽象 live-payload
分析，然后由原 v4 Machine 执行同一快照。caller 保留的 owner、传入借用根、
移动给 callee 的 owner 与返回 loan 的来源都进入界限计算；失败分配的逻辑
空 owner 不被当作必然成功分配。无法为分配长度建立支持范围内的有限界、
payload 界求和溢出或分析工作耗尽时拒绝；部分确定会 trap 的常量运算也
拒绝，其他无法建模的标量事实保留为 `Unknown`，不作为成功路径证明。
固定 work limits 未因测试改变。

同提交 focused 执行完成 51 个方法；原始记录含 296 次直接 Rust 进程：
261 次 rc0、35 次 rc1。253 份 bound＋Machine＋Python 完整差分观察是该进程
集合的子集，包括 183 returned、48 budget_exceeded、22 trapped。显式
`raw_refusals` 列表的 28 项也属于上述进程，另外 7 个非零控制没有删除。
还有一个隔离 Python 子进程，阻断 Python 语义模块导入后验证独立路径。

53 份停止观察保留非零 live payload。这里验证的是保守峰值和停止账本，
没有把停止时的宿主释放或进程退出改写成语言级清理定理。逻辑 payload
上界也不等于进程 RSS、原生栈或 CPU 上界。

本次复用 Cargo target，实际 locked/offline 命令和全部进程重新执行；
4,527,792 字节的 Rust executable 与原缓存同字节，SHA-256 为
`eca5c05c474471506dd375f17a4bb8e79bce8d5f7239934885d02e3a32dc685e`。
这不是 clean rebuild。外层 59.249860604 秒包含 Rust 与 focused 阶段，
嵌套耗时不相加，也没有把未知人工/agent 开发审查成本计为零。

### 真实发生函数体变化的 C 迁移

固定 Linux x86-64/LP64、32 位 C `int` 和 `C_INTEGER_DIVISION_TRUNCATES`
配置下，完整组件有 6 个 active functions、12 个 declarations。两版实际
Clang AST 中 `stb_div_floor`、`stb_mod_eucl` 发生变更，重新生成的 Core/native
身份不同。HIA 目标通过 direct LLVM 生成，没有链接原 C 函数来冒充重写。

共同定义域的 119 组输入产生 2,856 份原生函数观察与 1,428 份 VM 观察。
另有 successor-only 48 份 native/24 份 VM、8 份 witness VM、24 份
invalid-target native/24 份 VM，以及两个实际 stale/wrong-target 负控制。
旧版本的 4 次 UBSan UB 失败和 4 次 HIA overflow 终止单列保留，不能纳入
跨版本等价的成功分母。

本轮还修复了两类证据接纳漏洞：核对 Core 输入文档摘要、函数与外层 typed
实参，并核对 VM 内外层状态、值或 trap、资源账本和成本；VM 内层没有独立
实参字段，不能把其 Core 输入摘要称为实参哈希。另直接绑定 Git commit/tree/blob 和 owner
执行位，拒绝被 assume-unchanged、skip-worktree、软链接或 filemode 设置
隐藏的源码漂移。四项新的 pure 回读回归进入 canonical matrix。

历史 nlohmann/json 3.11.3→3.12.0 仍是保留 C++ 库的 C ABI 桥接路径。
每版 17 个分配故障点中恢复 14、发生 3 次 foreign noexcept 终止，合计
6 次 SIGABRT。该结果没有被本轮 C 子组件成功覆盖，也没有补造完整人力成本。

### 执行上下文

oracle 回调曾能在同一 bank 的 trace 准备中重入 close/prepare 等变更，造成
关闭后的使用或累计输入超过配额。现在变更入口在修改任何状态前检查准备中
状态，并在异常路径清除 guard；诊断读取仍可用。显式 map-repeat 对每个
独立输入执行实际 native 调用，保留原有执行、超时、内存、输入、映像和
one-shot trace 边界。内容摘要不等于一次性权限 token；离线记录不能独立
证明未序列化内存 token 的新鲜性。

四个 context 模块及实际 map-repeat 生命周期方法共 46 个方法全部通过，
没有 skip。P3/P6 合并外层耗时 58.838356302 秒；它们与 P1/P2 并行完成
正确性校验，不具有专用性能主机资格。

## 3. P4/P5：实验完整，净收益门未通过

真实 `stb_mod_eucl` 捕获产生 baseline、除数 8 guard、除数 10 guard 与双
guard 四个候选。独立 scalar-call 编码验证原始 caller/callee closure，
没有用被验证的 inliner 生成基准语义。该有限 profile 限制函数、block、
operation 与展开数量，未知/递归/resource effects 不会被扩大准入。

四种策略获得同一候选 bank、输入与校准信息；固定策略可选完整 bank 并
预先提交按除数调度表。每种策略遵循相同 reference-cache 规则，真实执行
不由 cache 替代。单独建立 baseline-only bank，分别核算共同准备、候选
搜索/证明/编译、交付、控制器、清理和身份复核成本。

修复后唯一完整研究含 20 个 episodes、184 次交付，即 3,087,007,744 次登记
内核调用；准备差分另有 320 次 native calls。四个 NDU 会话、32 次实际
请求均完成，关闭/退出与 bank/cache 释放记录完整。外层为 33.750088274 秒。

| 每种独立策略的成本归属 | 秒 |
| --- | ---: |
| 单独 baseline-only | 7.544361814 |
| 强固定调度 | 22.231319908 |
| 反馈贪心 | 22.344815734 |
| 轻量精确 DP | 22.301498219 |
| 原生 NDU | 22.428837229 |
| NDU 加原始 build 历史分摊 | 50.977749895 |

这些数值分别把必要共同成本归属给独立策略，不能相加作为整个研究耗时。
原 NDU build 的 28.548912666 秒仅作历史分摊，没有声称重新冷构建。
候选冷净收益、NDU 运行净增量、含 build 增量三个门全部为 false。
32 次 NDU 选择与同模型精确规划完全相同，modeled regret 为零；没有由此
推导 NDU 的独立算法优势，也没有统计或生产流量泛化结论。
`performance_timing_qualified=false`：这些是共享开发主机上的实际观察，
没有专用性能主机资格，不能将小幅计时差解释成统计性能排序。

第一轮 `f7cc872` 已完成同样全部交付，但最后分析遇到真实 `KeyError`：
计时器先把分析自己的未完成行加入 live ledger，分析随后读取该行的
`wall_ns`。该次 `qualified=false`、145,660 ns 分析失败成本和全部原始
记录保留。修复在分析前取得已关闭成本快照，拒绝缺失/未知/负值/重叠/
缺必需阶段的账目；七项取自真实失败数据的回归纳入矩阵，随后在 `44e34b7`
重新执行完整研究。旧数据的离线 sidecar 没有重新赋予旧运行资格。

证据读回还保留两次离线核验器错误：本地 image slot 与 bank index 的
混淆，以及把可重复内容摘要当作 nonce。修正后逐 3,242 个成员、两轮
全部交付、原生 NDU 帧、独立数学 checksum 与成本核验通过。它不执行归档
程序，不替代编译链证明或历史真实性的密码学证明。

## 4. P7：接口约束改善，模型资格仍为 0/3

V12 decoder 由捕获的公开 query 构建，包含全部 editable IDs 及其允许字段，
排除 readonly 节点，不选择参考答案节点或替换值。Rust 和 HIA 使用同一
公开目录构建规则。语法 decoder 不赋予类型、所有权、资源或行为准入权限。
旧 V11 运行器及其失败结果保留。

实际模型仍是已固定的 Qwen3.5-4B Q4_K_M，GGUF 为 2,740,937,888 字节，
SHA-256 `00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4`。
模型、运行时、初始提示、任务、seed、8192 context、1536 output reserve、
每格三次提交上限均没有为这轮结果调整。

容量阶段 19/19 通过、独立 CLI tokenizer 95/95 token IDs 相同，生成答案
请求为零。随后完成全部三项真实资格：

| 资格任务 | 实际三次提交 | 正确 |
| --- | --- | --- |
| json_scalar_reasoning | 1 compile_rejected、2 observable_wrong | false |
| two_file_signature_repair | 3 response_rejected：完整函数进入 type fragment，违反已公开类型规则 | false |
| owner_flow_repair | 3 response_rejected：expression fragment 中出现额外 statements/trailing tokens | false |

9 次实际输出均通过对应公开 JSON schema 的独立校验；这与全部任务未完成
同时成立。每次提交 accepted、hidden_evaluated、source_published 均为 false。
输入 21,025 tokens、输出 2,279 tokens，总计 23,304；unknown usage 为零，
人工修补答案为零。没有正确任务，因此不能计算有意义的 tokens-per-correct
优势，也没有 HIA/Rust 主对照结果。

随后实际执行 main CLI，返回 `E_TOOLSTUDY_NO_QUALIFIED_MODEL`、rc1，拒绝
发生在模型引擎构造前，main 目录没有创建，主试验完成格数为零。
容量、资格和实际拒绝的外层耗时分别为 98.915811914、610.943766376、
5.167062658 秒，内部计时已包含，不重复相加。源码 raw Git 身份、工具、
模型与运行时 pin 在前后保持一致，进程关闭记录完整。

这是在保留 V11 失败后进行的同任务接口跟进，不能叫独立新任务 holdout，
也不能推广为成熟语言开发或长期维护的效率比较。

## 5. 证据入口与复核纪律

本轮保留原始失败、修复源码、实际程序输入/输出、工具与源身份、实测费用、
未知费用及独立回读。新的证据归档分别覆盖 CI、P1/P2、P3/P6、P4/P5 与
P7；每个包提供摘要、清单、归档与有界只读核验器。源实现身份统一为
`44e34b7`，历史记录继续注明原实现或审计版本。

解码与回读只检查字节和已记录观察的一致性，不执行归档程序，不新增 native
或模型成功分母，不签发程序准入回执。未证明的完整语言 soundness、source/
native refinement、全局最优、一般并发内存安全、进程资源上界和 Rust 性能
超越声明仍为 false。完整人工开发、长期维护及研究成本继续记录 unknown。

| 证据包 | 仓库入口 |
| --- | --- |
| 同提交远端 CI、两个历史 CI | `evidence/hia_next_ci_20261030/` |
| Rust 有限入口堆及独立差分 | `evidence/hia_next_resource_20261030/` |
| 真实 changed-body C 迁移与 context | `evidence/hia_next_migration_context_20261030/` |
| 实际四策略研究、失败和成本 | `evidence/hia_next_stb_ndu_20261030/` |
| V12 真实模型、完整用量与 main 拒绝 | `evidence/hia_next_agent_v12_20261030/` |
| 总结果、发布身份与交付校验 | `evidence/hia_next_integrated_20261030/` |

源代码与测试的复核应 checkout 精确实现提交，再按已保存的 workflow/PLAN
安装固定依赖并执行。交付文档与证据追加提交不被称为一个重新运行过的实现。
