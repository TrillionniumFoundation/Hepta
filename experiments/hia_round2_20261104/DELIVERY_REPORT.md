# Hepta / HIA 第二轮交付报告

**状态：P0-1 的固定目标行为组合已关闭；其余六项均未关闭。** 同一冻结5ee/d47a组合实际完成36条命令、34项门槛和516项核心检查，源码与工具保持不变。该组合强AOT联合门槛为337/372，NDU应用场景净胜0/3；独立原生动态NDU实验仍为0/24。桌面v10/v11/v12完整shared证明各自outer124，后续独立replay0不追溯升格；同树CI成功作为另一个环境的独立事实并列保留。唯一正式 Agent 队列已完成 **16/16 cells、26 次尝试**，四臂均 **0/4 正确**；实际 outer 为 **4405.504830151 秒**。全部 10 个模型会话已回收，完整原件独立审计通过；本次结果没有建立 Agent 收益。观察通道读取超时保留为交付记录，不算模型失败。

完整数据证据固定到提交 `5eeee67c64052c520b43d7e44dc0ba52bdfec010`（tree `3484b3e87dc3dd82387b57c24fc55067b81c79c3`），已实际发布到 `evidence/hia-seven-delivery-round2-20261104` 并独立核验ref。数据提交共 **492 条文件路径**：先前216条原件身份全部不变，新增 **270条数据路径、84,727,942字节** 和6份发布审计元数据。四组新包的全部字节及最终路径映射已核验，旧NDU、AOT、development和三个CI head原件继续保留。[固定数据目录][evidence] · [最终入口说明](README.md)。报告逐项引用这个不可变数据提交；报告/README另作元数据提交，不改写被测源码或原始运行。

implementation [PR #682](https://github.com/TrillionniumFoundation/Hepta/pull/682) 已创建且保持draft。当前公开候选 `3102c2bb6cd819c27aef36cc927c23b39b279204` 与原始runtime `5ee6d8fec0e5c72d87a36dbed60789de211abf1b` 同树 `d47a711461dc66d4606bdc9659203889e205d6c7`。该源码通过本报告列出的有限行为组合验收；**没有达到七项全部关闭，也没有获得生产 Safe Core 的完整证明**。

本报告的机器可读对应文件为 [closure-matrix.json](closure-matrix.json)。其中 `null` 表示未测量、未记录或观测边界内无法确定，不能解释成零成本、零失败或成功。全部正式测量、归档恢复、逐件字节回读、统一数据总树核验和ref发布均已完成；科研条件仍开放、输出 token 未知和整轮成本未观测的字段继续明确保留。

## 七项关闭条件

| 原编号与条件 | 已完成证据 | 尚未达到的条件 | 当前结论 |
|---|---|---|---|
| **P0-1 统一实现组合** | 同一5ee/d47a组合 **36/36命令、34/34门槛、516/516核心检查**；0失败/超时/skip，源码与工具不变 | 本行有限目标的build/run/refuse/cancel/recover均有实测；其余六项仍独立判断 | **限定范围Closed** |
| **P0-2 完成顺序 Safe Core 证明链** | v10/v11/v12均11个Lean阶段通过；CI窄链有完整成功；所有原失败保留 | 三次桌面outer124；后续独立replay0不升级原验收；12项生产refinement仍开放 | **Open** |
| **P0-3 强 AOT 性能基线** | 独立候选 `d482f36`：联合性能门槛 **348/372**；最终组合 **337/372**、中位数 **372/372**、内存 **5680/5680** | 最终 **35项tail-only**；cold-call **34/48**，14项失败 | **未达全门槛** |
| **P0-4 NDU 净收益** | 原生动态缓存实验 **432/432 episodes** 完成；六臂、同信息强对照及独立 exact-DP 审计齐全 | 独立原生策略净胜 **0/24**、invoke子集 **0/12**；本次HIA应用另为 **0/3**，raw session NDU比DP贵约4.01% | **未达净收益门槛** |
| **P1-1 真实 C/C++ 迁移** | 真实GSL三版本8个配对，另有1个人工callback变体配对，合计22,464次正例scalar calls；swap两个变体各 **2616** 案例 | GSL仅限定构造/析构及factory实例；swap维护变体仍是人工fixture；通用迁移、完整库实现和低人力成本未证明 | **限定实现有进展，广义条件开放** |
| **P1-2 Agent 收益** | 唯一正式 **16/16 cells、26 attempts**；原件独立审计通过，10 个模型会话全部回收 | 四臂均 **0/4 正确**；8 次输出 token 未知，总输出与 cost/correct 为 null；单项目小样本不支持稳定生产率优势 | **未建立收益** |
| **P2 硬件与并发** | 开发期和最终clean组合分别完成有限host-RAM调度；3102另有17个实际硬件/ABI/C++/captured-C CI job日志 | 未穷举交错，未证明语言内存模型、DMA/MMIO或进程/OS崩溃恢复 | **限定调度有证据，广义条件开放** |

最终组合数字明确绑定5ee/d47a；独立d482 AOT、f48原生NDU和开发期回执仍保留各自身份，不拼成同一cohort。[AOT][aot-observation] · [NDU][ndu-report] · [开发证据][development] · [v9 失败][proof-v9]

## P0-1：统一实现组合与源码身份

本行关闭条件严格限定为用户要求的：**同一实际组合完成 build/run/refuse/cancel/recover**。proof/CI 可支持该组合的受控源码、工具与执行证据；正式 Agent 队列属于独立的 P1-2，PR 创建和发布属于交付工作，不额外加入 P0-1 的关闭条件。

唯一行为组合job `1a1aa2a527b-fc05-3e84`已终态exit0。磁盘审计和root独立回读核实：**36条命令按原顺序全部严格exit0且无timeout，34个qualification flags全true**；72份stdout/stderr共121,423字节逐份尺寸/SHA匹配。CORE的**516个planned/started/finished ID顺序精确相等**，failures/errors/skips均0；源码clean，source和tool identities不变。

outer为**1995.815171483秒**，其中child进程**1995.556773176秒**、runner内层**1995.406977717秒**；三者嵌套，不能相加。所有互不重叠命令wall之和1743.365454444秒是内层的子集，其余可观测编排开销252.041523273秒。当前materialized源码绑定5117条，与完整Git tree的8946个tracked路径是不同清单；后者不是完整历史恢复通过的证据。

原始RESULT SHA256为`c92fe59f1d50e84114560d7229e0db69ca19285582ef206a7d4171a7905a76d2`，outer回执为`6ff3a63c0bb1d379f36eb8b5ba4a63e1e9e08525b36db3d7e98b211799bff939`，独立磁盘审计为`697ec0ecdb4c68fe7ef03a36ce1cc365aece0e65bfea201cdf810f320a85b26d`。原件位于`composition-v4-r1/`及同级outer/audit，已由[composition公开包][composition-package]完整保留。

这36命令不调用或读取shared十一阶段研究证明链；此前等待该链通过只是外部排程条件，核对依赖后单独运行行为组合。原build/run/refuse/cancel/recover条件与36/34门槛没有降低。P0-1通过不改变shared桌面outer124、DENY_ALL或其余条件。最后的`ndu_model_planner`实际运行既有`qualify_hia_ndu_budget_erasure.py`，**不是重新执行f48的432个原生动态episodes**。

源码和发布身份必须分开记录：App 创建同一 Git tree 的提交，可以使源码可审查，但不能将新 commit 冒称为原始被测 commit，更不自动获得旧运行的资格。

| 身份/用途 | 原始 commit | Git tree | App 同树投影或状态 |
|---|---|---|---|
| 原生 NDU 动态任务 | `f48ae07eb86db1cc41acabfe22449634b897df31` | `ec6537ff93f67b0af0907616909ddad172bb3e64` | 原始身份保存在 NDU 包；本稿未建立独立同树投影 |
| AOT 候选一 | `db98ea63604a4a6a41b3a9fb94692b30203a5c12` | `29f304c33559481566dc98e28a6f15326f15e00c` | 独立候选，318/372；原始失败与后续只读复核保留 |
| AOT 候选二 | `d482f36cfa5f77558bd664749a37973a28083a6c` | `69ac2654a653146c40a408636008305e8b660773` | 独立候选，348/372；AOT 证据提交不是此源码的同树投影 |
| 中间源码 staging | `d33d559469cb620387c7e2b4bed57e1661a9fa51` | `0d5a773f44d6eafab7baf57b7ed5be4603743daf` | `766947d6942ff7229fa882095ffe06ae9478bf76`；118 件 staging 文件完整回读，不是最终验收 |
| 已失败的 v9 组合候选 | `2d964d27b068b3eb0b19e72ea4132eefd12d4360` | `6ac384198d9438df91888178e06e4a5ef44ed40f` | `0d75c60d477444e469723aed7787f96fc8501da0`；tree 相同，证明结果仍是失败 |
| 最小 CI 子提交 | `7f4a37c90741aa16ed09374e774ce2e7504339cd` | `43e4ccbabbb379c0750105e413288503642fffcd` | 父为 `2d964…`；只有工作流静态检查，无新 Lean/native 验收 |
| v10 候选 | `b47ce924c5941b42448e9da0b07a2bcedaf75d1f` | `69cd887f7a2a56de62c6b074bea9fca717d01355` | `47c9935d4d1406f6697810d23d45cb3b45c3b950`；桌面超时，旧CI有75项job失败 |
| v11 候选 | `0c8a91003aee2732308bb654d0e1f941ae561728` | `3870c31f7779a6c1bbcde21159c3c559e92b5501` | `e06aacb66c849b202378268630249be2e7a153fa`；11条CI成功，桌面仍超时 |
| 当前 v12 候选 | `5ee6d8fec0e5c72d87a36dbed60789de211abf1b` | `d47a711461dc66d4606bdc9659203889e205d6c7` | `3102c2bb6cd819c27aef36cc927c23b39b279204`；4文件145,284B完整投影回读，桌面outer124 |
| 本次行为组合通过的实现 | `5ee6d8fec0e5c72d87a36dbed60789de211abf1b` | `d47a711461dc66d4606bdc9659203889e205d6c7` | `3102c2bb6cd819c27aef36cc927c23b39b279204`；36/34/516有限行为验收通过，shared研究链桌面失败仍保留 |

原始测量及中间投影信息分别见 [AOT 原始身份][aot-observation]、[NDU 身份][ndu-report]、[staging 完整回读][staging]、[v9 同树投影与失败][proof-v9]。CI 子提交只将两处资格/replay 入口接到 `tools.check_core_seven_shared`，补齐当前 258 项源码身份闭包的触发覆盖；exact-head、Lean 锁及既有 600 秒/15 分钟预算未更改。接线本身不构成运行证据；后来的真实head47、e06和3102结果须分别引用，不能反向赋给此早期接线提交。

开发期证据也保留自身边界。C++ swap 回执记录 **26 项源码绑定与编译器 SHA256**，这些绑定在运行前后相同，但该回执没有给出完整测量 Git commit/tree，故相应字段为 `null`，dirty 状态为“未记录”。host race 则明确记录 HEAD `f3b8cd1e38ffc979966ccb458adb1f86c4c4130a`，且新增 race 源码当时尚未跟踪；其 **source_dirty=true**，前后状态相同。两者都不能被追溯包装为最终 clean 源码已通过。现在新增的5ee最终组合结论来自其独立原件，不追溯覆盖上述开发期dirty/unknown身份。[开发归档及原件索引][development]

## P0-2：顺序证明链、失败和生产边界

所有完整尝试保留各自源码与终态，不能拼接通过的阶段或以独立replay改写原运行：

| 尝试 | 原完整运行终态 | 已观察时间与后续行为 |
|---|---|---|
| v7，`3f0ef24…` | Part02超过不变的60秒进程预算，失败 | inner **322.677038663秒** / outer **323.303891681秒**；tree `f5680d76…` |
| v8，`0ab0c441…` | 前9阶段通过，原消费者证明elaboration/归约失败，错误恢复出现`sorryAx`，随后进程超时 | inner **550.018232070秒** / outer **550.409338160秒** |
| v9，`2d964…` | 前10阶段通过，WrongArm第11阶段原证明实现elaboration/归约失败（process_failed） | inner **495.656681267秒** / outer **496.094883981秒**；不是总预算超时 |
| v10，`b47ce924…` | 11个Lean阶段通过，内置replay未在外层600秒内结束，**exit124** | inner **558.870179933秒** / outer **600.079463180秒**；之后独立replay **exit0 /73.055962129秒** |
| v11，`0c8a910…` | 11个Lean阶段通过，同样**outer124** | inner **553.393567603秒** / outer **600.047503236秒**；之后独立replay **exit0 /55.874570337秒** |
| v12，`5ee6d8fe…` | 11个Lean阶段通过，同样**outer124**，source仍clean | inner **550.561070862秒** / outer **600.049994673秒**；之后独立replay **exit0 /61.189014082秒** |

v10/v11/v12的后续独立replay都是单独观察，不能追溯升格原失败。v11与v12对应公开候选的CI kernel qualifier/replay又分别实际成功，说明该CI环境完成了有限研究链；它同样不能覆盖桌面失败，更不能把环境间差异归为已识别的单一原因。[v10原观察][proof-v10] · [v11原观察][proof-v11] · [e06实际CI][ci-e06] · [3102 shared实际CI][ci-3102-shared]

v12 原内层RESULT SHA256为 `7bd76924b97877929b3264c91b7c0d7cb5c33b9a465327c7662f4dcbc9d28341`，原外层回执SHA256为 `496981fa6a5bc1b2d0c8259bcfb325f3035f35839bc825d29f64a7ea2e3b868f`。root已直接读终态；精确公开observer已独立读取并保存，原始输出、outer和独立replay目录已按各自身份进入[proof归档][proof-package]。[v12原观察][proof-v12]outer600、launch540、child60秒与job15分钟预算未改变，也没有以重试同head挑最好结果。

v9的失败是原`by decide +kernel`证明实现的elaboration/归约错误（process_failed），不能据此推断Lean内核漏洞或原命题存在反例；最后进程**4.007495654秒**已含在当次inner/outer之内；当时尚未执行最后两次重建。[v9完整观察][proof-v9]

保留较早v10诊断的原边界：43/43 源码控制在 **CPU4** 上通过，outer **294.748858726 秒**，记录的 tests 内层约 294.239 秒，source snapshot 未改变；prepare **67.758620305 秒**以及一次实际 23 文件 reconstruct **61.603523611 秒**的诊断在非独占 **CPU5** 上通过。两组工作并行，均未调用 Lean，**不构成正式整链通过**，也不能把各自 wall 相加作为这段工作的日历耗时。正式流程的 finalization 和内置 evidence replay 各重建一次；另行 `--replay` 还会再重建一次，但不重新运行 fresh Lean。每一段都应按真实边界计费，不能由一次诊断成功推断全流程在预算内。后来v10正式运行的失败与独立replay已分别列入上表，不能把这组早期诊断重新称为整链成功。

即使后续有限顺序语法/运输链通过，也不自动证明生产 verifier、Python exporter、源程序到 Core、优化或 LLVM 后端的完整精化。当前原始结果中的 **12 项生产义务全部未证明**：`environment_phi`、`dynamic_owner`、`allocation_extent`、`finite_integer`、`direct_body_seed`、`store_write_frame`、`value_schedule`、`normal_completion`、`empty_extent`、`trace_edge_cut`、`post_completion_frame`、`observational_boundary`。对应权限继续是 **DENY_ALL**；不授权 production/native admission、初始化省略、配额等价或性能资格。[义务与权限原件][proof-v9]

## P0-3：AOT 性能、尾部和资源成本

### 当前冻结组合的实际结果

当前5ee/d47a唯一完整六臂cohort有3348次timing requests、70,308条timed batch observations和1,898,316次timed kernel calls，未重跑、未排除样本。对两个强Rust基线的联合门槛为**337/372**：median **372/372**、p95 **361/372**、p99 **337/372**。35个不同失败全部tail-only，准确分解为**24个p99-only、11个p95和p99同时失败、0个p95-only**；不能把两类重叠失败相加为46项。

各组为历史回归**78/84**、历史holdout **88/96**、先前wrapper长度**89/96**、预设prospective长度**82/96**。内存门槛仍为**5680/5680**，build/proof **4/4**、median load **4/4**、estimated automated **1116/1116**；cold first-call只有**34/48**，14个失败为**n=0的12项、n=31的2项**。全部失败行保留在最终AOT派生摘要与原始报告中。它仍未满足完整运行时及自动化成本门槛。

AOT命令outer **89.845068227秒**，其中报告内层**89.348143761秒**；resource assessor是另一命令，outer **1.618909429秒**，内层分析**1.256038156秒**。这些都嵌套于组合总outer，不能再加入1995.815171483秒。当前摘要SHA256为`0ea35522c35f05cff698094bfe90e9c5be77ca8cfbd2810ad0940badbb72068e`，原始AOT与资源文件SHA见该摘要的inputs。

### 独立候选与保留的比较

独立候选二的优化是在x86_64上同时检查逻辑长度和owner实际buffer范围、每轮处理16字节的SSE2 byte-sum前缀，以及独立stride-1 scalar tail。源码/LLVM IR的尾部逐字节推进并保留load check；保留的Clang20机器码先peel 0–7字节余数，再每轮展开8次单字节load、index+=8。8字节是后端展开步长，不是Hepta语言循环语义或固定最终余数。其固定六臂队列对两种强 Rust baseline 的联合 median/p95/p99 门槛为 **348/372**。单项分别为 median **372/372**、p95 **370/372**、p99 **350/372**；24 个不同失败项全部是 tail-only，其中 2 个 p95、22 个 p99，不能把中位数全过写成性能全过。[完整失败项][aot-observation]

372 的分母是四组预设长度集合合计 31 个组内长度点 × 两个 workload × 三种 batch call 数 × 两个强 Rust baseline。各组为历史回归 **78/84**、历史 holdout **87/96**、先前 wrapper 长度 **89/96**、预设 prospective 长度 **94/96**。这些是离散样本，不是对所有长度或所有程序的证明。[各组结果][aot-observation]

尾延迟口径也需保持准确：每个固定 `(workload, group, n, calls, backend)` 的三个 seed 各有 21 条 measured **batch 总时间**，合并成 63 条样本后计算 median/p95/p99，gate 使用批次总时间的比值。它不是逐次 kernel invocation 的独立尾延迟，也没有在 gate 前先除以 calls。只有另外的摊销成本估计会使用 warm batch median / calls。

| 候选二资源/成本项 | 结果 | 限定解释 |
|---|---:|---|
| 内存门槛合计 | **5680/5680** | 五类分配/栈观测各 1116 项，加 library file 4 项、loader mapped 48 项、backing resident 48 项 |
| cold first call | **38/48** | 10 个失败全部发生在 `n=0`，仍须保留 |
| build and proof | **4/4** | 该协议中的自动化成本门槛 |
| median load | **4/4** | 有限 loader 观测 |
| estimated automated | **1116/1116** | 协议定义的费用估计，不是完整生命周期总成本 |

正确性控制记录 36 个 native tests、2304 个 guarded-page cases、6 个 abort children，以及 15 个 resource-protocol tests。它们是有限执行和拒绝证据，不是机器码 refinement theorem。[资源、正确性与成本结果][aot-observation]

旧组合 `3707…` 的 293/372、候选一的 318/372和候选二的 348/372是不同源码的完整独立 cohort。候选一 native 队列有效结束，但外层 assessor 出错；该失败和之后的只读修复/重放都保留，没有重测 native 来替换记录。共享主机下这些变化不能单独识别因果效应或建立统计置信。**最终组合已单独记录337/372和cold34/48，没有复制348/372或挑选最好的一次。** [历史及比较边界][aot-observation] · [各次实际费用][aot-costs]

## P0-4：NDU 的实际净收益与 exact-DP 差距

### 当前组合：实际HIA应用、raw服务与准备开销

当前5ee组合把实际编译的HIA kernel与C/C++/Rust比较镜像接入完整成本任务，保留固定训练选择、轻控制和同信息exact DP。三个场景各三次重复、四臂共**36个policy episodes**。native臂有9个episodes、36个决策step，其中**6个episodes实际调用，共9次native请求**；其余3个tiny episodes始终不启动native。step层面为9次invoke、27次skip。这里的“9”是请求数，不是9个实际invoke episodes。

| 场景 | strong fixed中位服务毫秒 | light | exact DP | native NDU | NDU/最佳控制 |
|---|---:|---:|---:|---:|---:|
| tiny | 36.139953 | 39.839723 | 40.100235 | 36.259921 | 1.0033195395 |
| amortized | 140.997177 | 149.420595 | 154.047832 | 163.731969 | 1.1612428879 |
| invalidate-recover | 118.674307 | 117.489550 | 129.482598 | 138.011824 | 1.1746731858 |

实际净胜仍为**0/3**。九次真正评价的完整有限模型witness均与同信息exact最小值相等，模型gap为0；未invoke的step没有被填成零gap。其native搜索子区间合**16.608255毫秒**、请求往返合**19.273287毫秒**，均已包含在决策wall内。九个episode的完整在线决策wall为native **101.396029毫秒**、exact DP **21.297151毫秒**；后者是整个控制器决策边界，不冒充已隔离的pure solver时间。零模型gap只约束所供有限预测，不证明机器指令或实际未来执行全局最优。

native策略实际准备9次、复用12个step、旧epoch退役3次、恢复重新准备3次。退役由caller在规划前完成，因此模型action里的`invalidated`为空，不能据此说没有实际失效；三份`epoch invalidation`回执都记录退役后loader mapped bytes为0。四个后端的load/retire/reload有限探针通过；另外的NDU拒绝/恢复是同进程先拒绝`verified=false`模型请求、后接受有效请求，不等同进程崩溃恢复或独立安全证明。

原bridge构建outer **39.585104485秒**，完整HIA成本资格命令outer **15.959036573秒**，两个不重叠命令实际合**55.544141058秒**。每个策略各承一整份公共准备和runner余量的保守单独部署分配为：fixed **12.957897545秒**、light **12.980340156秒**、DP **13.003283105秒**、native **52.638884840秒**。这些是替代方案的费用分配，彼此重叠，**不能把四行相加当成实际总耗时**；工具取得、人力与全生命周期成本仍未知。

raw-model服务四臂为24 cases×31 rounds×4，共**2976/2976成功请求**、744完整quartets，0失败/error/未尝试；每臂744请求，决策与witness一致，未观察到附加NDU决策质量。持久session DP服务**5.614753936秒**，session NDU **5.839730656秒**，比值**1.0400688476**；one-shot分别12.059316135与12.175730318秒。持久会话确实省启动费用，但NDU仍比同信息DP贵约4.01%。完整build+freeze+service三个命令实际合**70.533553192秒**；各臂另列的保守solo分配仍是替代分配，不能相加。这个lane没有应用执行，不能借其启动收益声称HIA应用加速。

准备优化另列：lazy witness在256模型、64次真实native请求上保持完整witness/frontier/请求与响应一致，request构造中位ratio **0.7679147109**；既有budget-erasure检查128模型、**0次native调用**，request ratio **0.2284908767**、exact-control ratio **0.1704847901**。两者都没有测应用净收益。完整派生账本`NDU_COMPOSITION_READOUT.json` SHA256为`76d19deacb6e8dcedd3e79742ab97647448d6c5d81c684a8fb92e06325e89d51`，公开目标为`composition/NDU_COMPOSITION_READOUT.json`；原始请求/见证/失败与外层流由组合包保留。

### 独立f48原生动态任务：432个episodes

新增实验运行真实 Rust 编译的矩阵转置缓存：准备、容量限制、驻留、复用、版本失效、淘汰和计算均有实际执行。**它尚未通过 HIA 已验证桥编译这些内核，因此只能评价这个原生控制器任务，不能作为 HIA 语言提速证据。** 历史HIA任务和本次组合HIA任务各自的0/3结果也不被这个独立原生实验覆盖。[完整中文报告][ndu-report]

六臂共享密封镜像、训练观察和有限未来请求信息，没有未来实测时延；各控制器自身观测费用进入各自模型。共有 **432/432 episodes、10,368 次工作负载执行请求、47,520 次内部 kernel 调用**，正式运行 0 失败、0 取消、0 超时。每次请求返回的最终向量按注册矩阵族逐元素核对；不是把所有内部重复结果都独立检查了一次。[分母与原始观察][ndu-analysis]

| 控制臂 | episode | 实际在线服务总秒 |
|---|---:|---:|
| Direct | 72 | 11.883347779 |
| 训练选定 strong fixed | 72 | 10.319435990 |
| Light | 72 | 9.181876569 |
| Exact DP | 72 | 9.119953214 |
| 同镜像 Beam，无 NDU 评价 | 72 | 11.211403695 |
| Beam + 原始 NDU | 72 | 10.991079677 |

服务 wall 已包括进程启动、数据与模型准备、真实决策、传输/证书重放、准备/淘汰/执行、版本更新、清理和退出；内部 solver、kernel、replay 时间不能再加一次。NDU 对全部强对照的 cohort 中位数净胜为 **0/24**；其中实际调用 NDU 的 12 组也为 **0/12**。NDU 与同镜像 beam 比较为 **8/24 更快、16/24 更慢**；小尺寸两臂都可能直接 skip，所以总体 1.9652% 的服务差不能归因为 NDU 的附加评分价值。NDU 总服务比 exact DP **慢 20.5168%**，比 strong fixed **慢 6.5085%**。[全 24 组与计费][ndu-report]

真实事件包括 **618 次 NDU 调用、2490 次全部 planner 请求、4422 次 gate skip、579 次准备、7377 次复用、84 次失效、159 次策略淘汰**。缓存资源在每个 episode 结束时回收。Beam 和 Beam+NDU 各有 **15/618** 次没有一致的第一动作，保留 incumbent；这些不算作零 gap 或成功最优。[事件原件][ndu-analysis]

exact gap 是“提出的完整路径预测成本 − 同一有限模型的精确最小值”，不是实际运行 regret，更不是任意汇编代码的全局最优证明。离线原生 exact DP 与独立 Python bottom-up 枚举相互核对，离线成本单列、不反馈给线上；hot path 的 `search_complete` 仍是固定实现声明。Exact DP 的 624 个提案均为零模型 gap；Beam+NDU 的 603 个一致动作提案中 378 个零 gap、225 个正 gap，最大预测差距 21.088 毫秒，另有 15 个无一致动作。其原生搜索约 0.194732100 秒虽然低于 DP 的 0.662522137 秒，但完整 planner 调用约 3.701168706 秒，高于 DP 的 2.181228104 秒，逐字段 witness 构造、传输与重放不能省略计费。[精确审计及成本][ndu-report]

结论是：任务中确实存在动态缓存调度机会，但本次 NDU 尚未证明完整成本净收益。后续紧凑证书或更大任务只能作为新候选；不得把尚未实现/测量的预期收益写进本轮结果。

## P1-1：C/C++ 迁移的实际范围

当前clean5ee组合重新执行unique_ptr swap的original与人工`api_maintenance`两个变体，各**2616 cases**。独立C++ reference与HIA输出逐字段相等；每个变体2200次allocation、2200次free、1361次allocator拒绝、live=0。两个变体的missing-drop均在artifact生成前拒绝，wrong-order突变虽通过资源检查但被生命周期oracle检出。最终qualification报告内层wall为**76.116542429秒**，峰值RSS **190480 KiB**；开发期78.966585149秒仍单独保留。最终原件SHA为`9caf420fe90689a82be367d3860117f5e0b01d87731b0066aaebd1ba3d6b9823`。Clang原始大AST流由原builder记录完整流digest/count和标准库census，`raw_ast_retained=false`，归档不能声称保留了那些未写盘的原流。

新增 `cpp20-direct-unique-byte-array-reusable-swap-v3` profile 对 `std::unique_ptr<unsigned char[]>` 的 member swap、self-swap 和空/活 owner 交换建立显式所有权映射。原 C++ 组件与翻译后的独立 HIA/Core/LLVM 组件分别由独立编译的 C caller 调用；HIA target 不链接原始 C++ object。两个人工项目/API 变体各 **2616** 个案例，总计 5232 个有限案例；oracle 检查返回值、分配/拒绝次数、分配身份、释放顺序及零活资源。[开发归档中的 `cpp-swap-r1/native/qualification.json`][development]

负控制也有实际区分力：故意错误但仍满足资源检查的 cleanup 顺序，被生命周期 oracle 检出；移除必要 drop 会在发布对象前拒绝。边界覆盖容量和 allocator 拒绝、异常/早退、空 slot、重复交换与 self-swap。回执明确 `source_equivalence_formally_proved=false`、`whole_cpp_abi_preserved=false`、`standard_library_implementation_migrated=false`、`real_upstream_library_upgrade_tested=false`。[同一原始回执与范围说明][development]

每个最终变体的声明清单有**10条source declaration、0条unconverted项**，另列**5条compiler implicit declaration**；标准库census各**46,152条声明**且reference expansion相同。它只覆盖实际列出的translation unit与配置。标准库body实际翻译数仍为**0**：`new/delete/operator[]/release/reset/swap`由明确的受信操作合同承接，不能把完整声明分类清单称为完整标准库实现迁移。

这个 profile 仍是顺序 LP64、默认 deleter、显式长度/容量守卫的有限片段。自定义 deleter、逃逸/保留原始指针、自由函数 `std::swap`、一般 move assignment/控制流合流、C++ class ABI、并发及进程崩溃恢复不在新增准入范围。Clang active declaration census 与标准库 probe 绑定是对受信实现的约束，不是标准库实现本身的证明。

### 真实GSL版本升级：与人工swap维护变体分开

同一5ee组合的`gsl-upgrade`命令带`--include-current-upstream`，实际检查了[microsoft/GSL](https://github.com/microsoft/GSL)的三个固定版本；不能套用另一组CI每job两个版本的分母，也不把v5.0.1称为未经核验的“当前最新”。

| 固定版本 | 实际上游commit | 翻译的上游方法体 | factory实例 |
|---|---|---:|---:|
| v3.1.0 | `0f6dbc9e2915ef5c16830f3fa3565738de2a9230` | 3 | 2 |
| v4.0.0 | `a3534567187d2edc428efd3f13466ff75fe5805c` | 3 | 3 |
| v5.0.1 | `fbd20b8e8c52cba04dbc869cc9068a7800a5665d` | 4 | 3 |

实际范围是`gsl::final_action<GslCallback>`的选定构造、move构造和析构，加特定`finally`实例。每个版本另翻译一个人工closed callback body；C++测试client和显式status的HIA集成client是人工编写、未翻译的部分。v3.1.0没有本profile的nonconst-lvalue factory，v4.0.0/v5.0.1实际覆盖该路径；三版本const-lvalue分别配对检查，其中每版164个不同seed/tag组合。

报告合计分母为**9个original/migrated正例配对、每对416 cases、7488条双方观察行、每行3次scalar调用，共22,464次正例native scalar calls**。固定qualifier源码进一步分解：三个上游版本本身有8对（2+3+3），共19,968次scalar calls；另1对是GSL4.0.0中人工callback multiplier由31改37的源变体，共2496次调用，原报告放在`negative_controls.changed_actual_callback`下，双方仍与调整后的独立oracle匹配。这个变体不是第四个真实上游版本；9对不能全写成未经修改的版本配对。const-factory的3对、7488次调用已包含在总数内，不能再加。另有wrong-but-linear负控416观察行、1248次调用；不兼容签名控制实际调用数为0，不能写成已安全执行。

该GSL路径实际使用**legacy Hepta source / 独立Core检查 / C backend**，生成C后由gcc编译并与独立C harness链接；它与本轮unique_ptr swap的HIA/Core/LLVM profile是两条不同准入路径。不能把GSL的历史C后端成绩归给HIA/LLVM。分母/后端的只读核对保留为`composition/GSL_DENOMINATOR_SCOPE.json`。

实际ABI是Linux x86_64 SysV LP64的`u64(u64,u64,u32,u32)`scalar入口，不是C++ class-layout或跨目标ABI证明。原报告wall为13.53283574199304秒（原字段浮点精度）；组合命令outer13.898626784秒，二者嵌套。generated component1192B、人工integration client1604B，human time仍null。报告明确whole GSL/general C++/general exceptions/arbitrary callback lifetimes/migration speedup/full semantic equivalence均false。原报告SHA256为`22d0566a780035f0b15a6898aaa70547a7888565f948e3d58509f614e5bad38e`，直接审阅摘要为`composition/GSL_FACTS.json`（SHA256 `dcb31505de216e57c4570f0b0cfb1c6fc2dc6f4c67ca67d300b99452ba702c2d`）；该摘要已作为同一数据提交中的独立metadata发布，不改原始归档。

最终组合的`upstream-native-ports/CONTROLS.json`顶层ok=true，共12个控制记录，实际历史任务为`stb_floor_overflow`和`stb_euclidean_int_min`。每任务旧/新upstream C各提供433组输入：旧版分别在4/3个输出后被UBSan检测并exit1，新版各433输出、exit0；预期缺陷控制通过不表示旧程序正确。原件SHA为`da0a87036d1818a6fe181e3ed42eeb7cb04355bf77b5cea403de5b0693c8d327`。

真实上游 `stb_divide` 的两个历史修复用于本轮 Agent 维护任务及原生参考控制，但它们来自同一 header/同一历史改动。新版 floor 函数的完整内联在既定 10 秒 all-input validator 预算内仍为 unknown；未将该未知 rewrite 当成已授权执行结果，而是固定使用另写的数学 HIA reference。原先函数与新版 remainder 的有限位向量验证也不证明 C-to-Core refinement。新增 C++ swap 维护 fixture 不能冒称另一个真实上游升级项目。

现有SQLite相关profile不构成整库迁移、完整生命周期覆盖或低人工成本证明；本轮新增迁移证据主要是GSL版本升级与unique-owner扩展，SQLite的广义关闭条件仍开放。这不表示既有SQLite控制没有执行，也不把现有profile描述为本轮新增的SQLite升级成果。

C++ 开发期完整 qualification wall 为 **78.966585149 秒**；记录峰值 RSS 为 **184256 KiB**，未做应用性能比较；human engineering cost 为 `null`。这些数据不足以证明一般 C/C++ 代码可以低成本、自动、全安全迁移。[开发成本索引][development-costs]

## P1-2：Agent 正式队列、结果与公平性边界

唯一预注册队列实际完成 **16/16 cells、26 次尝试**，四臂均 **0/4 正确**。主 job `1a1aa6c69d2-fc05-42e1` 正常 exit0 表示 runner 完整记录并清理了全部试验，不表示模型解决了任务。源码固定为5ee/d47a，CPU16–19；原 study RESULT 为170,759字节，SHA256 `31d24b0bc7f289e32239acffa4299f0bdb12718cd9256620a93afcf42bbad7c4`。[原始结果](agent/STUDY_RESULT.json)

设计为两个固定模型 × 两个相关维护任务 × 四种语言/编辑接口，每臂4 cells。所有臂使用相同任务信息、公共示例、模型、**32768 context、7168 output ceiling、240秒请求上限、最多两次尝试**及 terminal hidden oracle。隐藏结果不进入重试反馈。初始8192 context /4096 output方案的真实tokenizer拒绝、0 generation，以及扩容后的容量验收，保留为独立准备记录；它们不是模型作答。[开发准备证据][development]

| 臂 | cells / attempts | 正确 | 公测/验证失败终态 | timeout终态 | 已知input tokens | 已知output tokens下界 | 假设该臂单独部署的完整outer分摊（秒） |
|---|---:|---:|---:|---:|---:|---:|---:|
| HIA full-file | 4 / 7 | 0/4 | 2 | 2 | 24,611 | 1,511 | 1374.527414345 |
| Rust full-file | 4 / 7 | 0/4 | 3 | 1 | 6,149 | 1,289 | 1120.897059008 |
| HIA exact-patch | 4 / 6 | 0/4 | 1 | 3 | 19,340 | 1,346 | 1475.498437758 |
| Rust exact-patch | 4 / 6 | 0/4 | 2 | 2 | 5,862 | 850 | 1123.264574019 |

这四个费用是**替代部署方案**，各复用同一common成本，不能相加当作实际总开销。真实外层成本只有 **4405.504830151秒**；16格不重叠cell wall之和 **4175.943945158秒**，差额 **229.560884993秒**为此次边界内的共同准备、模型生命周期和编排成本。prepare outer **44.772683903秒**与run outer **4359.615415837秒**是其中不重叠的子区间，两者之和4404.388099740秒，剩余observer开销1.116730411秒；它们已经包含在总outer中。每臂的单位正确解成本都未定义，明确记为 **null**。[完整成本及逐格投影](agent/OUTER_COSTS_AND_FAILURES.json)

26个生成请求中，18个收到完整响应、8个超时；不能把26个请求称为26次完成生成。全部输入token可观测，合计 **55,962**；已知输出合计 **4,996**，但8次尝试缺少完整输出用量，因此总输出以及四臂各自的total_output_tokens均为 **null**。4,996只是已知下界，不能把超时输出补为0。历史模型下载、人力和能耗没有完整观测，仍为null。

16格终态为8个`public_validation_failed`与8个`budget_timeout`。进一步按26份原始attempt回执描述，分为8次预算超时、7次编辑拒绝（6次`E_FACTORIAL_FILE_INVENTORY`、1次`E_FACTORIAL_EXACT_EDIT`）、2次HIA typed-instruction/terminator语法拒绝、3次Rust编译拒绝、6次真正执行的公测`observable_wrong`。其中5次Rust执行returncode101，1次HIA执行returncode−6，未完成全部6个公共输入。这里是原回执分类，不推断模型能力或失败的外部原因。超时CELL不恒等于只有一次尝试，完整分母必须保留。

只有 **6次候选实际公测**，没有候选获得公共验收，因此 **0次候选hidden执行**。另外的 **8份人工reference controls** 包括4个历史缺陷公测拒绝及4个修复参考的427项hidden输入结果，它们验证评估路径，绝不计为模型正确解。独立审计将记录的expected与整数数学oracle逐项比较（floor=`a//b`，Euclidean=`a%abs(b)`，保持原i32域和除零、MIN/−1排除），检查原stdout/actual、封印与artifact身份；没有重跑模型、VM、native程序、编译器或evaluator。[独立原件审计](agent/INDEPENDENT_AUDIT.json)

10个owned模型会话全部实际reaped。8个returncode0；Granite的session5与7记录了`kill_requested=true`、returncode−9，随后成功wait/reap，cleanup errors为空。不能写成“没有kill”，也不能据−9推断OOM。模型和runtime前后身份不变，独立observer同样exit0、完整输出580,929字节。曾发生的MCP读取超时属于观察/交付通道，不添加到模型失败分母。[外层终态](agent/OUTER_RESULT.json)

独立原件审计检查了完整16格schedule、26次attempt、HTTP原body到response/usage的对应、全部候选文件、首次实际公测正确后即进入terminal hidden的规则、model/session/cleanup归属及前后原件字节；结果`audit_passed=true`、issues0。独立审核费用属于测量结束后的分析，不反向加入原实验outer。

预注册顺序为固定轮转`start=(model_index+task_index)%4`，四个(model,task)偏移为 **0、1、1、2**；没有随机化，四位置也未完全平衡。两任务来自同一项目、同一header的相关历史修复，模型训练暴露未知。当前观察没有建立HIA相对Rust的Agent收益，也不能用这个小样本断言所有模型或所有任务的普遍表现。

### 正式Agent原件的完整交付

唯一归档job `1a1aace57e2-fc05-478a` 实际exit0，完整保留 **356份原件、69个目录、42,688,341字节**，包含16个CELL、26个attempt、原HTTP/response/usage、候选和native产物、参考控制、10个session及完整outer/observer记录。XZ归档 **1,312,752字节**，SHA256 `39384cf88ddeb13eec5a334b133a80fa0ba24f512f79475c2dbc4070bca9f9ae`，分两片；实际搬移后的fresh Python恢复逐路径/字节/权限/目录集合通过，356个恢复文件使用独立普通inode，原件末尾再hash且集合和元数据未变。

直接可读原结果、审计和费用，加原20个交付文件及5个最终receipt/Runtime/stdout/manifest补件，共 **25件、2,087,407字节**，已在detached提交 `892ef3dc6eb3bb85fd3a1833bba58d1d4e4d0618` 完成App逐件全字节回读；随后由统一数据提交 `5eeee67c64052c520b43d7e44dc0ba52bdfec010` 纳入已更新的证据分支，全部25件原字节与最终路径映射保持一致。实际归档script总wall **15.137811032秒**，另有轻量base64导出阶段0.101427848秒（其manifest写入前边界）；均在原实验终态之后，不追加进4405.504830151秒。早期`FINAL_DELIVERY_RESULT/COST`只到final metadata之前，完整script末端见`ARCHIVE_TERMINAL_RESULT.json`，不混用边界。

恢复命令为 `python3 /path/to/agent/RESTORE.py --source /path/to/agent --target /new/absent/output`。原时间记录保留，不声称目标历史mtime/ctime还原。模型权重、工具链和credentials没有拷入；`OMISSIONS.json`保留已观测外部model/runtime文件身份，未编造未记录的传递sysroot清单，也不声称解压后就能hermetic重跑模型。

## P2：host-RAM 并发恢复与硬件范围

开发期已执行一个实际 Linux x86_64 host-RAM 调度：两个 native reader 通过 C11 atomics 会合；timeout 后数据区域在 reader 仍活跃时进入 quarantine，此时 recovery、unmap 和 unload 均拒绝。所有 owned worker 实际 join 后，两个 recovery contender 竞争，**一个提交、一个拒绝**。旧 epoch 的 host caller 被延迟到新 generation 恢复且完成新 HIA fill 后才返回，其旧结果不能提交，也不能撤销/清零新 generation。最终 worker 已 join，保留的 library/region 注册表为空。[开发归档中的 `native-race-development-01/RESULT.json`][development]

HIA 验证后的 scalar exports、实际 C ABI、memfd、页权限、owner/lease gate 和 worker join 均位于执行路径。调度 hook 只延迟外层 caller，没有伪造 native completion 或替换 recovery receipt。该次完整生命周期 wall 为 **2.987499543 秒**。[开发成本][development-costs]

当前clean5ee最终组合另行重复这个有限调度并通过：两个实际native reader进入，两个recoverer中一个commit、一个denial，延迟旧caller结果被拒，所有native worker实际join，保留library/region注册表为空。原件`host-region-race/RESULT.json` SHA256为`9588390f82a4bcab55468c4824394de19b844c1bc452f4e618f7767f57e0a6bd`。这仍只是各自一个受控调度，依赖同步、不保留/逃逸指针的FFI合同，不穷举交错，不证明语言内存模型，不提供新MMIO/DMA/IOMMU支持，也不是进程/OS crash recovery。开发时source dirty的事实和本次clean组合证据分别保留。

### 当前同树CI的实际平台执行

3102/d47a的17份完整job日志已独立逐字节核查；下表使用真实运行器与工具输出、实际命令及成功步骤，未从矩阵声明推定执行。合计为7个ABI job、7个C++ job、2个captured-C job及1个独立AArch64 HIA job。

| 实际OS / 架构 | 已执行编译器lane | 可由已读取日志确认的范围 |
|---|---|---|
| Ubuntu24.04.5 LTS / x86_64 | gcc、clang | ABI/stb组件及GSL限定迁移；另有captured-C的LLVM/C命令步骤成功 |
| Ubuntu24.04.5 LTS / aarch64 | gcc、clang；独立HIA用clang20/ld.lld20 | 同上；独立HIA还实际观察17个返回、1个bounds abort、1个null refusal、2个wrong-Core控制、4alloc/4free/0outstanding |
| macOS15.8.2 24H232 / aarch64 | clang | ABI/stb组件和GSL限定迁移 |
| Windows Server2025 10.0.26100 Datacenter / x86_64 | clang、msvc | ABI/stb组件和GSL限定迁移 |

7个普通ABI job各自直接报告fixed-array通过1、VLA拒绝1；7个C++ job各自报告**2 upstream versions**通过与16个contract tests OK，日志没有列全部native调用，因此不套用桌面GSL三版本的分母。2个captured-C job的详细输出重定向至未下载的artifact；已知的是实际命令和step成功，case/refusal精确数仍null。日志中Rust1.90是既有source参考/互操作角色，不改写AOT/NDU/Agent的Rust1.95身份。此表不建立epoch recovery、全交错、DMA/MMIO或通用ABI证明；host-region recovery仍仅由上一节独立实测支持。[17份原始日志与独立范围表][ci-3102-hardware]

## 成本账本：已观察边界与未知项

费用采用原始计时区间；不能把父子时间、不同策略的替代分配或并行 lane 的 wall 再次相加。

| 账本边界 | 已观察秒 | 不得重复相加的内容 |
|---|---:|---|
| 正式Agent归档script总wall | **15.137811032** | 终态后交付，不含先前upload/transport/API；不加入原模型实验outer |
| 正式Agent实际outer | **4405.504830151** | 包含prepare、run、全部26次尝试及清理；四臂替代分配不相加 |
| 正式Agent prepare outer / run outer | **44.772683903 / 4359.615415837** | 两者不重叠且均嵌套在上项；另含observer编排1.116730411秒 |
| 最终组合 outer / child / inner | **1995.815171483 / 1995.556773176 / 1995.406977717** | 三个嵌套时钟；36条命令、AOT/NDU/迁移等均在其中 |
| 最终组合 AOT命令 / resource assessor命令 | **89.845068227 / 1.618909429** | 两个不重叠命令均已包含在组合outer中 |
| 最终HIA NDU bridge-build + full-cost命令 | **55.544141058** | 每个策略的solo完整分配不能相加；所有内部阶段已包含 |
| 最终raw NDU build + freeze + service命令 | **70.533553192** | 四臂的solo替代分配不是实际总和；启动/关闭按服务协议计入 |
| 最终C++ swap qualification报告内层 | **76.116542429** | 在组合cpp命令与总outer内；开发期费用另列 |
| NDU 八个保留串行命令 | **173.448619231** | 已含构建 outer、准备和正式 campaign；不是全生命周期 |
| NDU 正式 campaign outer | **105.143264754** | 已包含下面在线服务与离线审计 |
| NDU 六臂在线服务之和 | **62.707096924** | solver、replay、kernel 等均为其子项 |
| NDU 离线 exact gap 审计 | **18.050397052** | 原生 solve、独立 Python check 和传输均在该区间内 |
| AOT 两个独立 campaign outer 之和 | **230.414917059** | 分别 115.197005314 与 115.217911745；各自 native、工具 inventory、assessor 已包含 |
| C++ swap 开发 qualification | **78.966585149** | 源捕获、build 与执行子项已包含 |
| host-race 开发生命周期 | **2.987499543** | 构建和调度执行子项已包含 |
| upstream capture r3 / r4 / r5 内层 | **22.764209452 / 3.471629261 / 25.148039068** | r3/r4 失败保留；r1/r2 无 CAPTURE 回执，成本为 null |
| upstream r5 driver / supervisor 端点 | **34.697529590 / 34.800** | 同一任务的重叠时钟；后者只有 1 毫秒端点分辨率，不能再加到 driver |
| v9 证明 inner / outer | **495.656681267 / 496.094883981** | WrongArm 进程及前序阶段均已包含；此 run 没有最终重建/replay |

NDU 若把全部已观察非服务费用 **110.741522307 秒**分配给每个候选，再加各臂 72 个 episode，是“每个候选单独部署”的保守情景，六行分配彼此重叠，不是六次独立实测。所有臂共享一个链接 NDU 的镜像；独立 NDU-free 构建成本没有隔离计量。摊销只是明确假设下的推算，不能替换服务实测。[NDU 完整账本][ndu-analysis]

开发证据的完整总 elapsed、整轮生命周期总成本、人力、能源、硬件购置/折旧、历史工具与模型取得费用、完整发布耗时均未全部观测，保留 `null`。AOT 的两个已测 cohort、NDU 的串行命令账本、开发成本和证明诊断属于不同边界；即使数值都已知，也不能直接相加宣称整轮真实日历耗时或投资回报。[AOT 费用][aot-costs] · [开发成本规则][development-costs]

## 证明、逐程序验证与有限实测的层次

| 证据层次 | 当前实际覆盖 | 不能由此推出 |
|---|---|---|
| 通用/参数化定理 | Lean对显式形式模型中、按各自前提量化的引理/定理作内核核验。shared的11阶段另核验模型、语法/证书运输及consumer检查/拒绝的具体连接；11是流程阶段数，不是通用定理数量 | 任意生产程序或实现的类型、ownership和资源安全；实际Core桥、all-edge transfer、body-prefix及Python exporter refinement仍未证明；12项生产义务仍open、DENY_ALL |
| 逐程序、全输入域的验证 | 仅对明确提交的有限位向量程序与其声明域给出裁决；现有scalar公开桥限两个exports，具体历史函数和新版mod各保留自己的结果。新版floor完整内联在10秒预算内为unknown | 任意C/C++翻译正确、所有权/后端精化或未获验证rewrite可执行；unknown不能视为通过 |
| 有限输入、有限调度的测试/测量 | 516 Core controls、已声明AOT/NDU样本、GSL/swap/native ports、一个host-RAM恢复调度、16-cell Agent与实际CI矩阵 | 所有输入/交错/硬件的绝对安全、所有程序性能优势、完整ABI兼容或稳定Agent生产率优势 |

归档恢复属于交付验证：实际选用的proof v1恢复完整路径、字节、权限和成员集，原mtime/ctime记录保留并用于原件前后不变检查；它没有恢复目标文件系统的历史mtime。未执行的v2内容寻址静态备选不贡献任何已实测恢复性质。

流程接受结果另列：当前同树CI完成受控11阶段资格与replay；桌面11阶段成功，但完整outer124仍是验收失败。超时不表示定理被反例推翻，CI成功也不覆盖桌面的失败。

## 可信计算基与不外推的边界

| 边界 | 仍受信或尚未关闭的部分 |
|---|---|
| 证明 | 固定 Lean kernel/checker 与 support library；Python 生成、捕获、身份验证和 replay 工具；有限模型 theorem 不等于生产 verifier refinement |
| 编译 | HIA parser/verifier/exporter、源到 Core 的桥、优化识别和 LLVM lowering；生产精化义务未全部证明 |
| 原生执行 | Clang/LLVM、Rust 后端、native loader、allocator、C/C++ 标准库实现及目标 ABI/CPU 的既定行为 |
| FFI 与 host 资源 | 同步、无指针保留/逃逸合同；Linux 内核页权限、memfd、锁、线程与 join 观察；未知 completion 通过 quarantine 保留资源 |
| NDU | 有限成本模型、预测误差与实际未来事件；独立 replay/DP 审计约束候选与算术，不能把模型最优升级为硬件或机器码全局最优 |
| 经验结果 | 共享主机、有限长度/矩阵族、相关任务和有限调度；不能从有限测试推出绝对安全、所有输入性能或普遍生产率 |

因此当前材料支持“可执行、可拒绝、可追溯的有限研究实现及部分性能改善”，尚不支持“全面超过 Rust、保留任意 C/C++ ABI、自动安全重写所有库、每条机器指令全局最优”的承诺。

## 已取得的候选 CI 与硬件执行观察

| 公开候选 | 实际终态/当前快照 | 下载与范围 |
|---|---|---|
| `47c9935d…` | 11 runs中10成功、1失败；102 jobs为26成功、75失败、1可选skip | 101执行日志完整；24 artifacts仅1份controls实际下载；原kernel没有upload步骤 |
| `e06aacb…` | **11/11 runs成功；101实际job成功、1可选job未执行** | 101完整日志7,169,846B；25 artifact清单、2份shared完整下载；46 controls、207+705实际verbose IDs全核验 |
| 当前`3102c2b…` | **11/11 runs成功；101实际job成功、1可选job未执行** | 101完整日志7,164,392B；25 artifact清单、2份shared完整下载；**49 controls/0skip**、207+705实际verbose IDs全核验、11阶段kernel两次full_replay_verified一致 |

旧75个失败来自真实缺失的31/39个workflow声明测试模块，导致ordinary清单和所有74个isolated清单失败。修复从历史`0ab0c441…`精确恢复45个缺失文件，保留9个已有不同文件，未降低207/705或任何分片门槛。独立本地clean `bb295ac…`实际执行207 ordinary与16 sources，其余73组当时未本地执行；后来e06和当前3102分别在实际CI完成全部75个job，两份历史完整ID集合哈希均一致。不能把后来的CI成功追溯改写旧失败。[旧CI完整读数][ci-head47]

e06与当前3102各自的17个实际硬件job均独立审阅；当前3102日志共856,758B，包括1个standalone Linux AArch64、7个ABI、7个上游C++、2个captured-C。日志直接支持的Linux AArch64结果是17 return、1 bounds abort、1 null、2 wrong-Core、4 alloc/4 free/0 outstanding；7 ABI分别有native/stb通过及fixed-array通过、VLA拒绝；7 C++分别报告2个上游version通过和16项contract OK。captured-C详细stdout重定向到未下载artifact，具体分母保持null。原生参考/互操作角色采用Rust1.90，不能改称AOT/NDU科学对照所用的Rust1.95。该表没有证明host-region恢复竞争、DMA或所有交错；两个head的实际日志和哈希分开保留。[当前实际ABI job组][ci-3102-hardware] · [当前实际C++ job组][ci-3102-cpp]

当前3102的mandatory native NDU job从05:06:50至05:44:42 UTC实际成功，API秒级envelope为2272秒；其regression步骤1658秒已包含在父job中。six-outcome另报告410 tests /288.876秒并为OK。shared kernel内层RESULT为294.573688317秒，完整qualifier步骤的API envelope为335秒，独立replay步骤40秒；内层与父步骤不能重复相加。这些CI成本不代替本轮动态NDU432episodes的完整成本账本。

可选native NDU的原条件为`workflow_dispatch && inputs.run_native_ndu`，pull_request事件下实际0个step；它与另一个已经实际执行的mandatory native NDU job分开。CI成功不证明本轮NDU0/24净收益已改变，也不把最终组合的NDU0/3、AOT337/372升级为净收益或全门槛通过；正式16-cell模型队列已独立完成且四臂0/4，不由CI状态替代。

打包时明确排除含临时签名URL的原始download response，保留原ZIP、过滤metadata、尺寸与SHA。已下载的shared原件可按字节恢复，但语义replay仍需要精确源码与pinned Lean/support；不声称只解压即可独立证明整门语言。所有CI job秒级时间、嵌套step/test时间与桌面inner/outer时间均按各自边界保留，不重复相加。

## 交付范围与原始证据索引

所有正式测量都已终态，原始失败、未执行阶段和独立后续检查分别保留。以下是固定数据提交中的实际交付范围；公开文件数指可逐件读取的包文件，归档内原件数另列，两个分母不能相加比较。完整文件清单、字节数、SHA256、Git blob SHA 与路径映射见数据提交的 `DATA_FILE_INVENTORY.json` 及各包原始 manifest。

| 公开目录 | 公开包文件数 | 实际保留范围与边界 |
|---|---:|---|
| `ndu/` | 66 | 独立 f48 原生动态任务的注册、六臂全部 432 episodes、完整账本、24 个队列及失败；不是最终 5ee 组合的新队列 |
| `aot/` | 12 | 两个独立候选的全部原始样本、318/372 与 348/372 结果及失败；不替代最终组合 337/372 |
| `development/` | 19 | 选择范围内的开发、捕获、工具准备和源码 staging 原件；原来缺失的成本继续为 null，dirty/unknown 身份不升级 |
| `ci-head47/` | 11 | 旧候选 11 runs、102 jobs 的完整状态和 101 份日志，保留 75 个失败；24 份 artifact 清单中只下载并审计 1 份 payload |
| `ci-head-e06/` | 46 | 400 份原件、54,640,224 字节；11 workflows 及其日志、2 份实际下载的 shared artifact 与硬件日志审阅 |
| `ci-head-3102/` | 53 | 398 份原件、53,331,742 字节；完整恢复与 fresh Python 第二次恢复通过，101 份实际 job 日志、49 个 source controls 与完整 kernel artifact 保留 |
| `proof/` | 102 | 81 个明确选择的证据根、1076 份原件、197 个目录、180,913,620 字节；保留 v7–v12 全部正式失败、独立 replay、相关诊断、固定成本对照及 CI 依赖恢复记录 |
| `composition/` | 49 | 原包 47 件及两份 GSL 摘要；原归档保留 1785 份文件、249,883,473 字节，1492 份构建/上游中间物另列尺寸、哈希与省略原因；36 命令与全部原始日志、AOT/NDU 成本和失败均保留 |
| `source-history/` | 94 | 原源码身份、小增量 bundle、900 秒公开历史获取失败、有界独立本地恢复和所有 8946 tracked 路径的核验记录；395,845,206 字节本地 pack 不公开 |
| `agent/` | 25 | 356 份原件、69 个目录、42,688,341 字节；16 CELL、26 attempt、原 HTTP/usage、参考控制、10 个 session、outer/observer、独立审计与精确成本均保留 |

新增 proof、composition、source-history、Agent 数据合计 **270 条公开路径、84,727,942 字节**，与先前已发布的数据保持分开计数。上述四组原字节及其 Git blob 身份均完整读回，最终路径映射也已通过统一数据提交核验。发布审计、报告与入口说明是另行的元数据，不能称为新实验。

### 证明历史和恢复范围

`proof/INVENTORY.json` 固定了实际 81 个证据根与每份原件；原 SHA256 为 `c31c4d1446e5d382ff93f239af5de515dbd617168d43a150f442c91a77d62008`。它包括 v7/v8 原候选与控制、v9 实际 theorem 实现失败、v10/v11/v12 的原 outer124、各自另次独立 replay0，以及 consumer、WrongArm、依赖闭包和成本诊断。旧 `proof-integrated-controls-v9-r1/` 的缺文档失败和恢复出的 source snapshot、v12 controls 的失败首轮和成功次轮都保留；不存在只留下最好结果的替换。[证明清单][proof-inventory] · [证明包说明][proof-package]

consumer 早期诊断使用过 d33d 派生的未提交候选及 v8 父模块，仍以各自源码 SHA、输入副本和 parent receipt 归属，不能统一写为最终 5ee 或旧 2d964。CI 依赖修复中的 45 个历史文件、全部原始 test IDs、207+16 本地实际检查及只读 peer 记录同样保留；后续完整 CI 执行属于各自的公开 head。

实际选用的是原 v1 归档：恢复完整路径、文件字节、权限和成员集，原 mtime/ctime 保留在清单并用于源前后不变检查；恢复目标未声称重建历史 mtime。可选内容寻址 v2 仅写过静态脚本与计划，未执行、未替换原包，也不贡献任何已测恢复性质。完整独立重验仍需要原先声明的外部工具和依赖；证据字节可恢复，不等于离线工具链环境已全部随包提供。

旧计划中的目录名称不是自动的包含声明。最终保留范围由各包实际 inventory 决定；例如 `ci-shared-wiring-v1/` 和 `composition-v4-preparation-r1/` 不在 proof 包这 81 个根内，不能据早期计划把它们算入 proof 原件数量。其相关源码改动、身份和最终实际执行分别由源码交付及 CI/组合原件说明。历史规划名单继续保存在机器可读文件的历史部分，避免将规划改写成已观察事实。

### 组合、Agent 和 CI 的保留边界

组合归档为 37 片，共 **28,898,872 字节**，SHA256 `7d57ad41c7168eb0352b9196471f9e43de048a917bb4c4b6afd1260cb571cbb3`。恢复与末尾原件复核通过；包括最终 337/372 AOT、cold 34/48、HIA NDU 0/3、raw 服务及生命周期原件。未随包重复发布的上游 checkout、Cargo/构建中间物与外部工具范围有明确清单；它不是可在没有声明外部依赖的环境中独立重跑的完整工具镜像。[组合包][composition-package] · [NDU 实际读数][composition-ndu]

Agent 两片 XZ 和直接可读的研究结果、独立审计、outer 成本、恢复记录均完整保留，25 件公开文件全部完整回读。压缩、恢复、传输和发布发生在模型会话全部回收之后，没有发出额外生成请求，也没有重跑 VM、native oracle 或资格检查。[Agent 原结果][agent-result] · [独立审计][agent-audit] · [完整 outer 成本][agent-costs]

当前 3102 CI 归档为 15 片 XZ、11,157,096 字节，SHA256 `2d8c9c26c3bf3ec41281b6e5d5df55b323e770774154acd8d166bec74f02915d`。53 个包文件共 12,386,716 字节，连同当时入口 README 替换的 54 项 delta、12,393,048 字节，曾在完整回读后发布到历史提交 `7bac2b2c134dff523801a78b42dfa9e3dd23f8e8`，原件在最终数据提交保持不变。两份含签名下载 URL 的工具 response 明确排除；25 份 artifact 清单仅 2 份 payload 下载核验，另外 23 份只有 metadata。e06 的两份及 head47 的一份签名下载 response 也不公开；实际下载 ZIP、提取原件和过滤后的审计均保留。

### 源码与历史恢复的实际界限

源码交付的原完整 public-history fetch 实际 timeout：命令 **900.004810061 秒**、父边界 **906.592669382 秒**，returncode −9，原失败未重跑或删除。随后另一次**有界、独立 object store 的 offline restore 实际通过**：8361 个对象、全部 8946 个 tracked 路径和 595,478,368 字节，原 commit 在导入前不存在，逐 tree/blob hash 匹配。真实 shallow 边界是 `931c96fcc7fb698226b809862c233a345dcca4ec`，完整 public ancestry 仍不存在。[源码交付说明][source-package]

本地 395,845,206 字节 pack（SHA256 `7b73f368160b6f68061e1f6cd6904b9d3ee00e9a0c54a7f73784eb92843c2452`）不公开；94 路径、8,726,587 字节的公开选择保留恢复回执、原始身份及小增量 bundle，并已完整回读。该 **3,634,207 字节 bundle**（SHA256 `0e0b8628a22f23836b2ba0002e475cec83a6e1b53b088896d8e3fd1ff2ca6367`）仍要求外部 `f2b76f5741c83822be2e12cf5a50b50a8d27b96a` 对象闭包，**公开包不是自包含的完整 Git 历史恢复包**。

真实 pack+restore 交付为 **31.090646886 秒**，共用 source/composition base64 staging 为 4.066226605 秒，后续小选择 staging 为 0.373395659 秒；这些是交付费用，不构成新实验，也不再叠入原组合性能。整轮日历 wall、人力和完整发布成本仍为 null；没有用并行或嵌套账本拼造一个总数。

[evidence]: https://github.com/TrillionniumFoundation/Hepta/tree/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104
[aot-observation]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/aot/OBSERVATION.json
[aot-costs]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/aot/COSTS.json
[ndu-report]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/ndu/NDU_DYNAMIC_REPORT_ZH.md
[ndu-analysis]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/ndu/ANALYSIS.json
[development]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/development/README.md
[development-costs]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/development/OBSERVED_PREPARATION_COSTS.json
[staging]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/development/SOURCE_STAGING_READBACK.json
[proof-v9]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/PROOF_V9_OBSERVATION.json
[proof-v10]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/PROOF_V10_OBSERVATION.json
[proof-v11]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/PROOF_V11_OBSERVATION.json
[ci-head47]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/ci-head47/CI_READOUT.json
[ci-e06]: https://github.com/TrillionniumFoundation/Hepta/actions/runs/41967339558
[ci-3102-shared]: https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915880
[ci-e06-hardware]: https://github.com/TrillionniumFoundation/Hepta/actions/runs/41967339518
[ci-e06-cpp]: https://github.com/TrillionniumFoundation/Hepta/actions/runs/41967339623
[proof-v12]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/PROOF_V12_OBSERVATION.json
[ci-e06-readout]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/ci-head-e06/CI_READOUT.json
[ci-3102-hardware-workflow]: https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915915
[ci-3102-cpp]: https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915863
[ci-3102-hardware]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/ci-head-3102/hardware-review/README_ZH.md
[proof-inventory]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/proof/INVENTORY.json
[proof-package]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/proof/README.zh.md
[composition-package]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/composition/README.md
[composition-ndu]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/composition/NDU_COMPOSITION_READOUT.json
[agent-result]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/agent/STUDY_RESULT.json
[agent-audit]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/agent/INDEPENDENT_AUDIT.json
[agent-costs]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/agent/OUTER_COSTS_AND_FAILURES.json
[source-package]: https://github.com/TrillionniumFoundation/Hepta/blob/5eeee67c64052c520b43d7e44dc0ba52bdfec010/experiments/hia_round2_20261104/source-history/README.md
