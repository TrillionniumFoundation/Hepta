# Hepta Round 6：完整模块、资源准入与受约束改进的证据报告

## 结论与身份

本轮把现有能力接成了可执行、可核对的工程链，并完成实际原生模块、NDU、策略演化和真实模型开发观察。证据支持“链路已经接通”；尚不支持“七条工作线的全部成功标准已经达到”。强 Rust 基线在本次中位延迟上领先 HIA，原始 NDU 没有带来独立决策收益，策略演化没有产生计入完整成本后的多代收益，AI 观察也没有建立总开发成本优势。

- 实现评审：[Draft PR #752](https://github.com/TrillionniumFoundation/Hepta/pull/752)。保持 draft，未合并、未激活生产权限。
- 所有最终本地正式实验的源码提交：`c3989242881dbe6e4fba330d4979b5c94b7fc5a9`。
- 源码树：`cae8dd7f2404b92cdf602e65d94f99f3d992a8e1`；与发布到远端的树完全一致后才开始测量。
- 实现相对本轮基线：40 个文件，4,354 行增加、116 行删除；源身份固定为 313 个输入路径，其中 188 个 compiler Python 输入，原有输入均保留。
- 权限始终为 `DENY_ALL`。哈希、保存的 JSON、成功测试或研究选择都不授予生产执行权限。

可直接核对的摘要是 [round6-results.json](round6-results.json)，完整观察的路径与字节哈希列于 [FILE_MANIFEST.json](FILE_MANIFEST.json)。本报告的数字来自保留的真实运行，不把参考答案控制、模拟 transport 或旧提交的成功当作最终模型结果。

| 工作方向 | 已交付 | 当前达到的边界 |
| --- | --- | --- |
| 统一语言与指令语义 | schema/opcode/route/verifier 的生产者与消费者关系、同一资源准入入口 | 接入路径收口；共享契约不等于 VM 与 LLVM 的一般形式等价证明 |
| 最小安全配置 | 有限整数、byte owner/loan/call、正常返回资源义务、结构预算及拒绝门 | 实际 checker、VM、native build 接通；泛型 checker/model/resource refinement 尚缺 |
| 真实模块迁移 | 完整六函数 stb_divide，0.93→0.94 的真实 changed-body 重捕获与重翻译 | 构建、有限行为、异常路径和原始负例通过；人工维护时间未知 |
| 原生性能 | 八方案 resident harness，C/C++ LTO，Rust LTO/native/PGO | 原生运行和对照完成；没有一致速度或尾延迟优势，RSS 指标有启动历史限制 |
| NDU 独立价值 | 五控制器固定生命周期预算、独立 exact oracle、原始 native NDU 配对消融 | 两组各 72 对候选排名相同；未证明独立净收益 |
| AI 开发价值 | 16 个人工任务组合与 8 个真实历史修复组合，真实新会话一次提交 | 24/24 正确；小样本、费用与人审未知，不能证明总体生产率优势 |
| 受约束 RSI | 三代参数提案、独立 selection、终测保留集、全搜索成本账本 | 合成仅第 1 代采用，模块成本回放 0 代采用；未证明多代净能力提升 |

## 1. 单一准入权威与最小资源配置

schema 目录定义 wire grammar 与版本特征；opcode 目录集中签名、effects、guards 和声明规则。Hepta source、Agent assembly、primitive/composite Core、经过身份核对的 legacy 输入及受支持的 C/C++ capture 都在进入执行路径前汇入 `verify_program`。HSIR、HMIR、resource IR 或历史 envelope 不能独立授予 standalone 执行资格。VM 和 native build 再次验证实际 Core bytes，不把 dataclass、hash 或旧 receipt 当成准入凭证。

| 位置 | 生产实现 | 意义 |
| --- | --- | --- |
| schema 与 opcode | [hia_schema.py](https://github.com/TrillionniumFoundation/Hepta/blob/c3989242881dbe6e4fba330d4979b5c94b7fc5a9/hepta/hia_schema.py)、[hia_opcodes.py](https://github.com/TrillionniumFoundation/Hepta/blob/c3989242881dbe6e4fba330d4979b5c94b7fc5a9/hepta/hia_opcodes.py) | 统一版本、指令及规则目录 |
| 生产者与准入 | [hia_routes.py](https://github.com/TrillionniumFoundation/Hepta/blob/c3989242881dbe6e4fba330d4979b5c94b7fc5a9/hepta/hia_routes.py)、[hia_program.py](https://github.com/TrillionniumFoundation/Hepta/blob/c3989242881dbe6e4fba330d4979b5c94b7fc5a9/hepta/hia_program.py) | 各输入 route 转为 canonical Core 后统一检查 |
| 资源策略 | [hia_static_budget.py](https://github.com/TrillionniumFoundation/Hepta/blob/c3989242881dbe6e4fba330d4979b5c94b7fc5a9/hepta/hia_static_budget.py) `qualify_bounded_resources` | 重新检查完整策略和每个明确 export 的结构预算 |
| VM 消费 | [hia_program_runtime.py](https://github.com/TrillionniumFoundation/Hepta/blob/c3989242881dbe6e4fba330d4979b5c94b7fc5a9/hepta/hia_program_runtime.py) | 正常返回、trap、budget stop 分开记录 |
| 原生消费 | [hia_program_llvm.py](https://github.com/TrillionniumFoundation/Hepta/blob/c3989242881dbe6e4fba330d4979b5c94b7fc5a9/hepta/hia_program_llvm.py) | 资源不合格时在 LLVM/产物发布前拒绝 |

新增配置接受已审查的无环 scalar/byte 资源子集，覆盖 v1–v6 与受限 byte-only v8；nominal/v7、未审查的资源形状、循环/递归调用图、未知 extent 和不完整或类型不精确的策略被拒绝。整数策略字段不把 Python `bool` 当作整数。保存的资源回执不替代新鲜准入。完整接受与拒绝范围见 [HIA_BOUNDED_BYTE_PROFILE.md](https://github.com/TrillionniumFoundation/Hepta/blob/c3989242881dbe6e4fba330d4979b5c94b7fc5a9/docs/HIA_BOUNDED_BYTE_PROFILE.md) 和 [最终静态审计](semantic-evidence/final-claim-audit.json)。

最终本地 Core 回归 **679/679，0 failure、0 error、0 skip**，外层墙钟 125.761 秒，前后 source identity 相同。16 项新增资源配置测试包含在其中；早期 90 项专项回归与其重叠，不能相加。v8 夹具另外保留五种实际分配成功/拒绝下的 VM/native 对照，声明上限为 6 次 allocator interaction、26 VM ticks、3 个同步帧、8 字节 requested live payload。

这些是实现中的保守分析、拒绝和有限执行证据。requested payload 不是进程 RSS；VM ticks 不是 CPU 纳秒；正常返回资源平衡不等于保证永不 trap、永不宿主 OOM 或原生栈字节数受限。

## 2. 完整真实模块与有语义变化的上游升级

模块是 `stb_divide` 在 `C_INTEGER_DIVISION_TRUNCATES` 配置下的全部六个活动函数。0.93 固定于 `dcb1116f1351bc8edad059d9ca432e8f322ba922`，0.94 固定于 `003501f6d7a8668ce8b6d875e34dd97ad0d5d5b5`，对应实际修复 `c38ec91d229cbe56167f8af865c05b3d92db705f`。变更影响 `stb_div_floor` 与 `stb_mod_eucl`。本轮从真实捕获重新翻译活动函数体，人工改写迁移函数体次数为 0；HIA 目标没有链接原 C 实现，也没有把 Rust codegen 当成 HIA 原生执行。

历史升级保留 119 个共同输入、2,856 次共同原生函数观察、1,428 次共同 VM 观察，以及 successor-only 的 48 次原生、24 次 VM 观察。旧版本四个 UBSan 失败与四个 HIA overflow 进程、无效输入路径、陈旧/错误目标负例均保留；旧 C 的未定义行为没有重分类成成功。

正式服务使用统一 `i64(i32,i32)` 结果 ABI。六个服务入口在进入算法前，将除零返回为 `2147483648`，将 `INT_MIN/-1` 返回为 `2147483649`；正常值在 i32 范围内。这是六个 `service_*` 包装入口的合同。完整 Core 仍有 **18 个显式 exports**，包括迁移函数和辅助函数，不能把六个服务入口的错误值合同扩大成全部 18 个入口都 total。

资源准入覆盖全部 18 个 exports：**0 allocator interactions、70 VM ticks、3 frames、0 live heap bytes**。实际把 ticks 降至 69 后收到 `E_HIA_BUDGET_EXCEEDED`，没有发布产物。模块是标量模块，不能据此宣称一般缓冲区或分配失败路径已由该真实模块覆盖。

正式服务的 257 个输入对（包括 100 个边界对）产生 **1,542 次 VM** 和 **12,336 次八方案原生函数观察**，全部一致。独立回读核对原始流、完整 inventory、upstream 变更、PGO 输入、实际构建和源码前后身份；见 [模块独立审阅](migration-evidence/service-final-independent-review.json)。仍有 source→Core 的全输入数学等价、外部 ABI/loader、编译器和操作系统义务；人工维护及审查时间为未知。

## 3. 原生性能：强基线已执行，优势没有被预设

宿主为 AMD EPYC 9V74、Linux x86-64，共享且不独占。每个子进程固定在初始允许的第一个 CPU。工具包括 Clang 20.1.8、GCC/G++ 13.3 和 Rust 1.95.0；具体二进制哈希、完整命令和版本流均保留。

C/C++ 使用 O3、LTO、`-ftrapv`、`-fno-semantic-interposition`，分别保留 generic/native 两个方案。Rust 使用 opt-level=3、fat LTO、单 codegen unit、panic=abort、overflow-checks=on；保留 generic、native、native+PGO。PGO 只使用预先固定的 129 个训练输入对，与 257 个测量输入对无交集，使用匹配的 llvm-profdata；instrumentation、训练、merge 和最终重编译成本均记录。HIA 保留既有 generic x86-64 O3 LLVM 路线。因此这些是明确配置下的比较，不能说所有语言拥有相同后端或完全相同优化选项。

每个方案 4 组，每组 41 个样本；每个样本包含 128×257×6＝**197,376 次函数调用**。固定轮换/反转顺序，全部 164 个批次样本保留。下面的 p95/p99 是批次延迟，不是单请求 p99。本次是小型标量 resident harness，未达到真实长期生产负载的验证范围。

| 方案 | 批次中位数 ms | 批次 p95 ms | 批次 p99 ms |
| --- | ---: | ---: | ---: |
| HIA | 0.769311 | 1.538220 | 2.546633 |
| C generic | 0.833518 | 1.018857 | 2.122973 |
| C++ generic | 0.832777 | 1.070435 | 1.550870 |
| Rust generic | 0.752835 | 0.940468 | 1.077365 |
| C native | 0.899627 | 1.237216 | 2.849579 |
| C++ native | 0.898005 | 1.160230 | 2.063413 |
| Rust native | 0.719335 | 1.252870 | 1.931834 |
| Rust native + PGO | 0.677382 | 0.949372 | 4.476974 |

本次 HIA 中位数比 C generic 低约 7.7%，但比 Rust generic/native/native+PGO 分别高约 2.2%/6.9%/13.6%；HIA p95 高于全部七个对照。PGO 的 p99 本次很高，也保留在表中，没有删掉尾部样本。共享宿主、有限组数和不同编译实现不支持普遍性能优越性结论。

| 方案 | 单次实际构建 ms | ELF 文件 bytes | load+首次请求中位数 µs（4 个进程） |
| --- | ---: | ---: | ---: |
| HIA | 452.349 | 16,120 | 40.346 |
| C generic | 116.353 | 16,032 | 44.357 |
| C++ generic | 135.384 | 15,920 | 202.745 |
| Rust generic | 324.632 | 8,008 | 38.182 |
| C native | 130.973 | 16,032 | 40.676 |
| C++ native | 122.885 | 15,920 | 248.195 |
| Rust native | 146.388 | 8,032 | 36.730 |
| Rust native + PGO | 269.727 | 8,112 | 38.438 |

PGO preparation 总计 457.455 ms，已经包含最终 PGO 构建，不能再把表内该构建重复加一次。正式服务完整资格/测量/回读外层命令为 200.644 秒，内部记录 200.451 秒；这包含上游升级、逐次 VM 验证和测量，不是一次原生请求耗时。

**内存结论受限。** 32 个计时进程均报告 `ru_maxrss=67,032 KiB`。driver 读取整个进程的高水位，Python launcher 的 fork/exec 路线可能把 exec 前的高水位带入统计；这个相同值不能证明模块内存持平或 HIA 更省。ELF 文件大小也不是 resident memory。独立审阅保留每个方案的 `.text` 哈希和共享函数片段；八个完整 `.text` 并非完全重复，部分 C/C++ 函数字节一致，全部候选仍保留。

## 4. NDU 与受约束策略演化

五个控制器是 fixed-direct、greedy、beam、ordinary learned-value 和 evolved-policy。每个控制器有相同 **2,000,000 次生命周期 search transition 上限**，每任务上限 4,096；所有失败和落选训练候选、三代 incumbent/candidate selection、终测搜索逐 action 扣账。它是相同 allowance，不是假装实际耗时或实际消耗相同。exact 和另外的 bottom-up oracle 是单独计费的诊断基准。

合成队列固定 24 个训练任务、每代 8 个新 selection 任务、24 个未用于选择的 final 任务。模型驱动队列将 HIA 与全部七个对照分别配对，group0 用于训练，group1 的三个固定窗口用于 selection，groups2/3 用于 final。后者仍使用同一语义语料的不同计时样本，不是独立未见语义任务，也不是新执行的应用策略 dispatch。

| 控制器 | 合成最终模型成本 | 合成 oracle regret | 合成生命周期 transitions | 模块回放最终预计成本 ms | 模块生命周期 transitions |
| --- | ---: | ---: | ---: | ---: | ---: |
| fixed-direct | 28,071 | 14,063 | 96 | 76.695954 | 96 |
| greedy | 14,134 | 126 | 672 | 73.218974 | 192 |
| beam | 14,080 | 72 | 1176 | 73.048387 | 336 |
| learned-value | 14,026 | 18 | 19992 | 73.048387 | 5712 |
| evolved-policy | 14,026 | 18 | 19992 | 73.048387 | 5040 |
| exact | 14,008 | 0 | oracle 另计 | 73.048387 | oracle 另计 |

合成成本字段名为 `ns`，是该有限模型的声明单位，不能当作宿主实测纳秒，不能直接与控制器墙钟相减。模块回放成本来自已保留的原生计时，但仍依赖模型：retirement cost=0 是假设，image bytes 是资源记账代理，七组两候选模型不是同时联合优化八方案。

三代演化中，合成只第 1 代通过严格 selection：4112→4065，后两代持平而拒绝；终测 evolved 与普通 learned 同为 14026，只比 beam 的14080低54。模块队列三代均未通过严格改进门；beam、ordinary learned、evolved 与 exact 同为73.048387 ms。该模块配对模型只有两个合法 mask，width=2 已是 exact，没有可供学习改善的剩余决策差距。

原始 source-pinned native NDU 确实被执行。每队列 24 个终测模型×3 组候选＝72 对，共144个 native请求；两队列总计144对、288个 native请求，hello/close另计。每对 `supplied` 与 `supplied_ndu` 得到完全相同的候选，native 搜索 states/transitions 都为0，未在 NDU 路径前偷偷使用 exact 搜索；两种模式的候选排名和首动作全部一致。进程正常关闭、严格 returncode=0，原始 frames 与结果逐条绑定。

NDU 额外 evaluation 的中位数为合成 **39.0785 µs**、模块 **39.495 µs**；roundtrip 和 service 的负差值样本也保留。候选决策质量没有改善，不能把模型中相对 fixed-direct 的收益归因于原始 NDU。见 [NDU 独立审阅](review-evidence/ndu-final-independent-review.json)。

普通学习训练墙钟为合成185.362 ms、模块108.975 ms；演化训练与selection为202.409/124.117 ms。最终 native bridge 构建15.800秒只计一次，两队列共用同一经过字节身份核对的 binary/receipt。研究选择不激活生产版本。当前没有“多代真实能力持续提高且覆盖训练、搜索、证明、维护成本”的证据。

## 5. 真实模型开发观察

所有24个单元均为真实新模型会话，`fork_turns=none`，无模型覆盖参数；每个单元只收到已注册公开 prompt 和初始文件，只有一次提交，65,536-byte上限、240秒 host-observed delivery上限。固定轮换顺序；公开验证通过后才执行一次终次隐藏验证，隐藏反馈不送回生成模型。原始response、materialized代码、实际编译与sealed native执行、公开/隐藏结果均保留。36+8项参考/负例控制是准备验证，不记作模型开发成功。

| 队列 | 方案 | 正确 / 计划 | 平均交付等待 s | 平均实际验证 s |
| --- | --- | ---: | ---: | ---: |
| 人工设计，4 个任务 | HIA / 完整源码 | 4/4 | 62.538 | 1.095 |
| 人工设计，4 个任务 | Rust / 完整源码 | 4/4 | 55.484 | 1.255 |
| 人工设计，4 个任务 | HIA / 结构化修改 | 4/4 | 63.407 | 1.237 |
| 人工设计，4 个任务 | Rust / 结构化修改 | 4/4 | 50.583 | 1.078 |
| 真实历史修复，2 个任务 | HIA / 完整源码 | 2/2 | 87.619 | 2.081 |
| 真实历史修复，2 个任务 | Rust / 完整源码 | 2/2 | 67.521 | 0.926 |
| 真实历史修复，2 个任务 | HIA / 结构化修改 | 2/2 | 104.205 | 1.652 |
| 真实历史修复，2 个任务 | Rust / 结构化修改 | 2/2 | 111.975 | 1.013 |

第一队列是四个既有两文件任务；第二队列是同一项目的两个真实历史算术修复。第一组16项、第二组8项都保留原分母和全部终态，总成功数为 **24/24**。独立只读审计核对了96次公开、7,492次隐藏用例观察和48条原生执行记录；这些是观察次数，不是独立任务数。44个控制包含16个预期正确、28个预期失败控制。

host-observed delivery合计1,670.686秒，实际validation合计30.004秒，两个cohort内部preparation合计12.961秒。delivery包含派发、模型工作和协调者接收开销，不是纯模型推理时间。后验文件mtime诊断发现一项响应写出到开始评分相隔130.333秒；该值未替换原指标，且时钟没有独立认证。**因此不能按上表秒数排列语言、模型或编辑接口的速度。** 原始计分口径、同一case分母和协调开销全部保留。

Upstream四个HIA cell的公开/隐藏执行共保留8个 `same_core_vm_agreement=true`，但原始报告只保留agreement Boolean，没有逐例原始VM输出向量。独立审计确认其Core哈希绑定，不把这项记录扩写成重新执行或形式证明；详见 [AI独立审阅](review-evidence/ai-final-independent-review.json)。

文件访问约束是指令边界，未构成强制 filesystem sandbox；provider routing/weights、训练数据接触情况没有独立认证。token、金钱、人类审查时间和长期维护成本均为null，不能当成0。CLI/provider探测中保留的阻断没有被算作成功开发；实际观察使用可用的fresh delegated-model通道，协议与旧CLI研究分开。成功率相同不能证明HIA、Rust或某种编辑接口更有生产率。

## 6. 形式检查、实际 lowering 与尚未闭合的证明链

最终源码的GitHub kernel资格成功，固定Lean 4.19.0 binary hash为 `92c3d35b5bfaa5e0fea413a775d504cf46cd95e1345df61c2274f76779e7e023`。11个阶段、66个正向目标、10个精确否定证明通过；远端独立full replay同样成功。完整ZIP的GitHub digest、81个frozen文件、313个canonical Git source条目、11个receipt父链与原始流、olean身份均完成独立字节核对。协议墙钟为 271.443 秒；source-controls另为50/50、0skip/failure/error。

见 [精确head的kernel作业](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42179969010/job/127767054882) 与 [完整产物独立审阅](review-evidence/ci-c3989242-kernel-independent-review.json)。这只关闭 **Narrow Core syntax connection**；12项更宽的初始化桥义务仍全部unproved，生产权限仍为DENY_ALL。远端完整语义replay和本地下载后的字节核对是两种不同操作，报告没有把后者冒充重新运行Lean。

另外，对正式服务中已经测量的同一Core与同一LLVM执行了六个固定服务入口的现有标量检查，未裁剪18个exports或改变任何函数体。每项totality固定10秒、lowering固定5秒；保留的lowering查询以新context/solver再次求解，整个replay阶段固定5秒并检查solver身份。源代码、Core、LLVM和native build receipt的绑定均保留。

| 服务入口 | totality | actual LLVM lowering | 新solver查询回放 | 两项及回放均合格 | 原始原因 |
| --- | --- | --- | --- | --- | --- |
| `service_stb_div_trunc` | proved | verified | unsat | true | nonreturning_call_closure_unsatisfiable;  |
| `service_stb_div_floor` | unknown | verified | unsat | false | call_closure_program_budget_exceeded;  |
| `service_stb_div_eucl` | proved | verified | unsat | true | nonreturning_call_closure_unsatisfiable;  |
| `service_stb_mod_trunc` | proved | verified | unsat | true | nonreturning_call_closure_unsatisfiable;  |
| `service_stb_mod_floor` | proved | verified | unsat | true | nonreturning_call_closure_unsatisfiable;  |
| `service_stb_mod_eucl` | proved | verified | unsat | true | nonreturning_call_closure_unsatisfiable;  |

该诊断的 `all_six_selected_pairs_proved` 为 **false**，`all_18_export_totality_proved` 始终为false。脚本退出0仅说明六项观察完成且输入没变。`service_stb_div_floor` 的调用闭包有34个block，超过现有totality profile的32个block上限；保留真实拒绝，不放宽budget或删改Core来获得通过。新solver重放同一个查询不是另一个独立编码器或另一种求解器。

即使个别行通过，也只说明该固定artifact的选定call closure与实际优化前LLVM内部函数体在所有声明类型输入上的相应性质。canonical checker、两个编码器、LLVM parser和Z3仍受信；C→Core数学等价、资源分析soundness、checker→Lean、native优化/codegen、C ABI与OS/硬件没有因此被证明。Alive2同样有明确的过程间变换范围限制，不能用局部LLVM验证替代这些义务；参见[Alive2官方说明](https://github.com/AliveToolkit/alive2)。

## 7. 失败、成本与保留义务

本轮独立审阅实际发现并修复了进程身份在PID/procfs namespace不一致时失效、构造出来的JSON冒充完整模块证据、native build cost manifest漂移、native session非零退出仍被接受、隐藏验证后source drift留下陈旧correct标志等问题。原始复现和修复后控制均保留。Linux memfd常量名称缺失时仍要求真实seal syscall和完整readback；没有把名字fallback当成可执行文件不可变性的替代。

两个早期本地Lean资格失败保留各自旧head与原终态：第一次是捕获器namespace身份问题，第二次是官方Lean运行时在该容器中无法定位自身。随后使用精确最终head在GitHub正常宿主完成原预算的资格和独立回放，没有修改pinned Lean、增加证明预算或把旧成功重新标注为新head。早期失败Core回归、依赖环境补齐、编译/PGO开发失败、provider阻断和旧cohort准备成本同样保留。

[formal-cost-ledger.json](formal-cost-ledger.json)记录实际已测成本及嵌套关系。STB的upgrade/VM/build/PGO/readback都包含在其完整wall中；PGO最终build包含在PGO preparation中；NDU native bridge build在两队列间共用一次；CI作业可能并发。没有把这些嵌套或并发wall直接相加制造总成本。历史工程、人审、token、费用与长期维护仍未知，因此没有完整总账或总成本优势结论。

截至 **2026-11-06 08:06:14 UTC**，更宽CI为12个workflows中11成功、1排队；完整107个jobs中54成功、52排队、1条件性跳过、0失败。verified-native已于08:06:04 UTC成功完成；剩余排队来自research矩阵，CI整体仍为PENDING。完整状态及链接见 [ci-final.json](ci-final.json)。条件性跳过的原始native NDU workflow只在手工dispatch选择时执行；本轮本地正式原始NDU配对已另有实际证据。未结束的远端作业不算作通过，也不阻止本报告如实保存已完成的实验。

## 8. 复核与下一道实质门槛

完整原始包及分片哈希/重组步骤见 [EVIDENCE_ARCHIVE.json](EVIDENCE_ARCHIVE.json)；[FILE_MANIFEST.json](FILE_MANIFEST.json)列出每个原始文件的路径、长度与SHA256。原始receipt中的绝对路径保持原样，便于核查实际运行位置；解压包本身不授予新环境执行资格。公开证据保留原始NDU的pin、source/binary身份、build回执和native frames，不分发私有原始crate源码或其派生可执行文件；重现这部分需要已有的授权source访问。provider状态/日志数据库没有读取或导出。

当前可交付的是：同一源码下，完整真实标量模块的升级、资源准入、原生执行、强基线对照、控制器实验与真实模型开发观察已经相连，拒绝、失败与无收益结果都有明确落点。

下一道实质门槛是关闭实际checker/资源分析到模型及backend的连接；建立能区分模块内存的测量；在更有决策空间的真实联合候选/长期负载上证明原始NDU超过强普通控制器；扩大未见维护任务并实际测得token、金钱和人审成本。现有证据不足以把这些门槛宣布为已完成，也不足以授权生产采用或自动自我修改。
