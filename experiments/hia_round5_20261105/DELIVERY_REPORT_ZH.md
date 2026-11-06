# HIA 第五轮统一交付报告

日期：2026-11-06（UTC）。对应源码草稿：[PR #737](https://github.com/TrillionniumFoundation/Hepta/pull/737)。

**本轮完成了新的统一候选、原预算下的完整证明与组合验收，以及额外的真实迁移和两机执行证据；七项研究目标尚未全部达标。** 同一冻结组合完成 36/36 条命令、34/34 项执行与证据判定、613/613 个 CORE 测试。强 AOT 仍有 32 个尾部联合门槛和 10 个冷调用门槛失败，NDU 净收益仍为 0/3，Agent 开发收益没有得到证明。执行协议通过与性能、生产安全或开发收益成立分别报告。

## 1. 对照用户完成标准

| 优先级与工作 | 本轮实际交付 | 按原完成标准的判断 |
| --- | --- | --- |
| P0：保持统一实现组合 | Safe Core、AOT、NDU、验证器、工具链及产物全部重新绑定；完整 proof、独立 replay、36 条 composition 命令均在同一源树完成；有限 profile 的构建、执行、拒绝、取消、恢复均有记录 | **本轮注册组合完成**；每次后续源码变化仍须重新绑定与验收，不授予更广的生产保证 |
| P0：顺序 Safe Core 实际证明连接 | 修复真实 LLVM return 类型检查漏洞；重跑固定程序验证与一般模型证明；新增 GSL checker→Core→LLVM 实际连接；保留类型、owner、错误、退出和可信边界的区别 | **推进，未整体闭合**；十二项更广 refinement obligations 仍未证明 |
| P0：强 AOT | 新增带逻辑/物理双边界的 8 字节 SSE2 尾段；维持原工作负载、baseline、采样和门槛 | **未达标**：joint 340/372、cold 38/48；不豁免原失败 |
| P1：真实 C/C++ 迁移 | 补上 GSL 5.0.1 三组 HIA LLVM 原生对照、错误实现和 owner 拒绝控制；核对原构建与 ABI 范围 | **部分完成**；整组件迁移、一般异常/真实资源生命周期及人力维护成本尚无完整对照 |
| P1：NDU 独立价值 | 更紧的 preparation 下界；统一候选重新构建 bridge，完整保留同候选同信息控制和成本账本 | **未达标**：三个场景全部未胜出；当前 exact-DP 前置结构不提供模型内更优解 |
| P1：Agent 开发收益 | 审计真实历史模型请求、超时、token、外层成本和任务范围，纠正分母；明确新任务协议的结构缺口 | **未达标**：历史 29 次请求、0/16 正确交付；本轮未新增模型实验，接口升级/跨模块任务尚未接入 |
| P2：平台与并发保证 | 同一包、同两份共享库在 Xeon 与 X230 Linux 真机执行六个阶段；逐产物复核已完成 Windows/macOS CI | **有限 profile 扩展**；没有设备、一般内存模型或全部平台整体资格 |

主要数值与全部失败 cell 见 [SUMMARY.json](SUMMARY.json)、[独立摘要](SUMMARY.zh.md)；完整独立复算脚本、逐项 audit 和末次 CI 快照见 [independent-analysis.tar.xz](independent-analysis.tar.xz)。

## 2. 身份、源码和同一组合

| 身份 | 值 |
| --- | --- |
| 实测冻结 commit | `0a06ef4f0894681af92b0caefba0704c1278d2cc` |
| GitHub App 发布 commit | `67da0ab0a51203f6f640c4459bc15bef442885b8` |
| 两者完全相同的 Git tree | `a5239982f9fd8f08ab3a6e791147fc989e8d9df6` |
| 上一个实测 S3 commit | `996e2626d9aa89bc0e2b1017ebb858c6666604e7` |
| 主执行 durable job | `1a1ae149dcf-fc05-5d36` |
| 独立复算 durable job | `1a1ae3f635c-fc05-5e6d` |

实测 commit 与发布 commit 的元数据不同，报告始终分别标记。完整源树一致已经核验；八个原始 commit 对象及其对象哈希保存在 [COMMITS.json](COMMITS.json) 与 `raw-commits/` 中，可核对原始身份。先前 native GitHub push 返回 `commit_refs_rules` 错误，随后通过正常连接的 App 发布同一树，没有强制覆盖已有引用。

源码身份检查现在清理继承的 `GIT_*` 覆盖，禁用 replace objects，取得稳定 head/tree 对，从该 commit 的规范对象读取源文件，逐字节核对工作树，并在输出观测前再次核对身份。组合验收绑定完整 materialized checkout；较窄的 proof source union 明确包含 **267 个路径和 780 个 support 输入**。两个新测试模块已加入 CORE 与 proof union，前一版所有 union 路径保留，commitment 为 `d27b4d1edaa27950489d7b54fa6b8242b493883d0927933fa303e5b1203c9c55`。

本轮没有通过不同候选的局部最好成绩拼接“成功组合”。源码、工具身份在整个正式序列中不变，`identity_errors=[]`。主执行与独立审计均权威记录 `succeeded / exit 0`，输出完整、持久化且终态发布已确认，见 [TERMINAL_STATUS.json](TERMINAL_STATUS.json)。

### 执行与成本

| 阶段 | 结果 | 外层 wall |
| --- | --- | ---: |
| 最终集成 preflight | 74/74，源码前后干净 | 25.034289766 秒 |
| 全部 11 阶段 fresh proof | exit 0，原 600 秒预算 | 595.116502644 秒 |
| 独立 replay | exit 0，原 600 秒预算 | 43.595967989 秒 |
| 全部 composition | 36/36 命令，34/34 判定 | 2005.257633654 秒 |
| 冻结正式序列合计 | identity 不变，exit 0 | **2670.960663875 秒，约 44 分 31 秒** |

序列总 wall 已包含三个子阶段，不能相加两遍。Preflight、此前开发、补充实验和归档不在该总数中。历史获取、人力、能耗和长期维护成本未完整观测，不能记作零。独立 replay 不等于重新运行 Lean kernel。正式性能 cohort 没有为了获得更好结果追加重跑。

613 个 CORE planned、started、finished ID 完全一致，0 failure/error/skip；S3 的 590 个 ID 全保留，新增 23 个。34 个资格标志说明执行与证据协议完成，不代表 34 项商业或研究主张成立。完整源、工具、注册信息、命令收据、原始观测与资格结果见 [composition.tar.xz](composition.tar.xz)；proof 原始记录另见 [proof.tar.xz](proof.tar.xz)。

## 3. Safe Core：修复真实 checker 漏洞并限定证明层级

### 真实连接的修复

原 checker 在 Core 全部 trap、没有正常返回路径时，可能没有检查 LLVM 中不可达 block 的 return 类型，因而允许选定 `i64` 函数含 `ret i8` 或 `ret i1`。这属于 checker 接纳条件漏洞，不是已观测 emitter 生成该错误 IR 的证据。修复在符号路径执行前，对选定函数的**每一个 block return terminator**核对函数签名。

旧实现的 RED 控制有 4 个方法、5 次失败；修复后的专项 43/43 通过，并进入本次统一 CORE。Clang 对相应 malformed IR 的拒绝也保留。初始化、owner/loan、错误和退出依然依赖各自明确的模型、检查器和运行时假设；这次修复没有被扩大为完整语言 soundness。

### 三种证据不能混为一项

| 层级 | 本轮可以据此说什么 | 仍需信任或限制 |
| --- | --- | --- |
| 一般模型定理 | 形式化模型中、明确前提下的结论通过对应 kernel 检查 | 模型与实际 Python checker/lowering/native runtime 的连接没有全部成为一般定理 |
| 固定程序验证 | 对固定 Core/LLVM 程序及规定语义，检查相应全输入约束或证明对象 | 依赖具体编码、checker、Python/Z3、工具身份及已声明假设，不等于所有未来程序 |
| 有限测试和真机观测 | 记录的样例、输入、ABI、取消恢复路径和故障控制实际执行成功或被拒绝 | 不推出全部输入、全部硬件、任意并发调度或完整 C++ 语义 |

十二项更广 obligations 仍未证明：`environment_phi`、`dynamic_owner`、`allocation_extent`、`finite_integer`、`direct_body_seed`、`store_write_frame`、`value_schedule`、`normal_completion`、`empty_extent`、`trace_edge_cut`、`post_completion_frame`、`observational_boundary`。编译器、链接器、加载器、libc 和硬件等仍处于相应可信边界。权限保持 **DENY_ALL**，`safety_certificate=false`。

### 退出与取消的实际漏洞

外层监督器曾出现 leader 正常退出而同组后代仍运行的 false success；仅给 GNU timeout 加 kill-after 也不能处理所有这类情况。最终修复在 Linux profile 使用 `waitid(WEXITED|WNOWAIT|WNOHANG)`，在清理原 session/process group 前保持直接 leader 身份不被 reap。普通文件日志和 capture 采用同一退出判定；正常 leader 退出但仍有活的同组成员返回 **125**，原 deadline 超时返回 **124**。

真实普通文件输出的旧实现首先得到 `0 != 125`；修复通过 12/12 真实进程与身份控制，包括 signal 发生在 leader reap 前。最初不充分的修复、观测失败及 source-inventory 的 71/72 preflight 均保留在 [raw-static-evidence.tar.xz](raw-static-evidence.tar.xz)。保证限于原组、默认 SIGCHLD 和独占 child ownership 等条件；不覆盖 detach、外部 reaper、任意内核阻塞，也不把 Z/X 的“已不执行”说成“所有后代均已 reap”。内层其他启动器不能自动继承这项证明。

## 4. 强 AOT：全部原门槛保留，尾部与冷调用未关闭

变更为 16 字节循环后增加最多一次 **8 字节 SSE2 尾段**，同时检查逻辑长度和实际 owned extent，使用实际 8 字节读、清零上半部后 `psadbw`，保留 scalar remainder、checked fallback 和 owner 清理。专项包括 2,304 个 guard/unaligned-page 情形、2,568 个逻辑前缀与物理 extent 组合、400 个算术对照、9 个预期 SIGABRT 和 8/16 字节 SMT lemma。它没有更改零长度 entry；零长度入口机器码仍是 `48 85 ff 75 03 31 c0 c3`。

正式 cohort 保留 2 个工作负载、原 6 个 arm、全部长度/seed/批量及阈值，共 **3,348 个请求、70,308 个批次、1,898,316 次调用**。相对两种 Rust baseline 的 median ≤1.10、p95 ≤1.20、p99 ≤1.20 门槛保持不变。

| 指标 | 当前通过/总数 | 原标准判断 |
| --- | ---: | --- |
| median | 372/372 | 本轮全部通过 |
| p95 | 371/372 | 1 个失败 |
| p99 | 340/372 | 32 个失败 |
| median/p95/p99 同时通过 | **340/372** | **未关闭** |
| 冷首次调用 | **38/48** | **10 个失败，全部 n=0** |
| 内存门槛 | 5680/5680 | 有限观测通过 |
| 全部 resource/cost gates | 6842/6852 | 10 个失败为 cold gate，与上面的 32 个运行时失败分别计数 |

32 个 joint 失败中，31 个仅 p99 失败，1 个 p95/p99 同时失败。双失败为 linear / prospective / n=101 / calls=64 / rust_release：median ratio 0.640730、p95 2.226113、p99 8.325879。最大 p99 ratio 是 affine / prospective / n=331 / calls=1 / rust_byte_release 的 **47.254753**。10 个 cold 失败为 linear 5 个、affine 5 个，全部 n=0。

这里是批量延迟：每个 cell 合并三个 seed 的 63 个样本，经验 p99 等于最大样本。全部样本和失败保留，不用“噪声”豁免失败，也不将该样本分位数当作总体尾分布定理。

上一个实测 S3 是 joint 315/372、cold 36/48。相同 cell 的迁移为：289 个 pass→pass、**26 个 pass→fail**、**51 个 fail→pass**、6 个 fail→fail。净增 25 个通过 cell 不能写成 25% 加速，且存在明确退步。两次共享主机观察也不是受控的因果 A/B。不同历史候选的 337/372 或 352/372 不能替换 S3 或本轮结果。

### 共享主机活动的限制

本协议明确 `exclusive_host=false`。AOT 外层从 2026-11-06 00:01:45.965237249 UTC 开始，按外层单调时长推算结束于 00:03:09.434233453。proof/GSL 打包在此前完成；P2 打包和后来的公开归档在此后完成。但一个只读 Windows ZIP review 的终态时间 **00:02:56.328 UTC** 落在该外层区间，其原始收据缺少 start/CPU duration，因此不能确定是否覆盖 timed sample 或量化影响；还有其他只读远端访问，活动清单不完整。不得据此宣称主机独占、完全空闲或没有竞争。详见 [SHARED_HOST_ACTIVITY.json](SHARED_HOST_ACTIVITY.json)。

## 5. NDU：下界更紧，独立价值仍为负结果

新的 optimistic bound 按有效 artifact segment 累计可恢复执行收益，扣除一次 preparation/proof，处理初始 residency、invalidation 和容量过大的单个 artifact，并与旧下界取 max。它有明确有限模型论证、39 个专项测试和 256 个独立穷举模型的验证，不是物理 deadline 或一般最优性证明。专项独立评审见 [ndu-independent-review.md](ndu-independent-review.md)。

最终冻结组合另行完成 **36 个真实 episode、9 次实际 native invocation**。三个场景的 native median 都输给最佳控制，净赢场景仍 **0/3**：

| 场景 | fixed ms | lightweight ms | exact DP ms | native NDU ms | native / 最佳控制 |
| --- | ---: | ---: | ---: | ---: | ---: |
| tiny | 37.740465 | 43.726289 | 38.746358 | 39.043825 | 1.034535× |
| amortized | 140.300471 | 139.742754 | 147.038824 | 153.246003 | 1.096629× |
| invalidate-recover | 121.181635 | 108.780444 | 113.964074 | 133.801081 | 1.230010× |

本轮 fresh bridge inner build 37.015251921 秒、outer build 37.236646032 秒。注册规则下四个**替代 solo-policy 成本归因**为 fixed 11.283078238 秒、lightweight 11.299919508 秒、exact DP 11.309013613 秒、native NDU **48.631855777 秒**。它们共享成本，是互斥的归因口径，不是四次独立执行，不能相加。

两个实际外层命令合计 **51.333880935 秒**，已经包含在正式 sequence 中。每个场景独立的完整构建成本没有被观测，维持 null；不会把同一 bridge 重复计三次。本轮成本与先前 `66d796e...` 专项分开，后者重用的旧 bridge 不冒充本轮 fresh build。

当前 native path 先算 exact-DP frontier，再用 NDU 求同一标量目标；该 profile 没有模型内解质量优势可供 NDU 获取。要证明独立价值，仍须在真实机会和全部观测成本下胜过强固定、轻量控制和 exact DP，本轮结果没有做到。更紧下界的旧专项中 108 个 gate 有 36 个 bound 变紧，但 **0 个动作改变**，不构成实测收益。

## 6. 真实迁移：GSL 5 的 LLVM 连接已补上，范围仍有限

新增补充实验使用同一 `0a06ef4` 源码，对 GSL **5.0.1 / `fbd20b8e8c52cba04dbc869cc9068a7800a5665d`** 进行 fresh capture、source checker、实际 source→Core 验证与 HIA LLVM object 构建，保留原 GCC 13 C caller/link 和 G++ 13 C++ reference。源码预检查会产生 C 文本，但没有编译使用它；最终链接的是 Clang 20.1.2 编译的 LLVM object，`c_codegen_used=false`、`rust_codegen_used=false`、`fallback_used=false`。

三组为主生命周期 client、non-const factory、const factory。每组两侧各 416 个 case，共 **2,496 条 observation row / 7,488 次 scalar call**，全部匹配原 oracle。两个 factory 组忽略 mode，各只有 **164** 个不同的 `(seed, tag)`，不能写成 416 个独立参数；主生命周期 client 仍使用 mode。wrong-but-linear 实现也实际编译为 LLVM 并执行，在 416 个 case 中有 **325 个不匹配**被抓到；duplicate owner 和 lost owner 分别在 checker 处被 `E_USE_AFTER_MOVE`、`E_LINEAR_UNCONSUMED` 拒绝。

补充实验计时为 **9.690739659 秒**，边界为 driver 开始至最后源/工具核验，不包含前期人力、准备和最终报告序列化。原始构建参数、LLVM/Core、完整输出、注册文件及 artifact manifest 见 [gsl-hia-connection.tar.xz](gsl-hia-connection.tar.xz)，主要结果见 [GSL_HIA_RESULT.json](GSL_HIA_RESULT.json)。

迁移范围是选定上游 `gsl::final_action<GslCallback>` 的构造、移动构造、析构和 `finally` 实例，以及闭合的 authored callback。显式 status client 是作者编写的集成代码，不是自动从完整 C++ client 迁移；它使用零长度 owner token，产物没有 unresolved runtime imports。不能由此推出真实 allocator、文件描述符、取消、任意异常、一般 C++ exception ABI 或整个 GSL 已迁移。历史主 GSL 升级 qualifier 实际使用 C backend，保留 3.1.0、4.0.0、5.0.1 三版本矩阵；最新升级段是 4.0.0 / `a3534567187d2edc428efd3f13466ff75fe5805c` → 5.0.1 / `fbd20b8e8c52cba04dbc869cc9068a7800a5665d`。其真实变化包括按值构造改为 `const F&`/`F&&` 两个构造、成员 `f_/invoke_` 改为 `f/invoke`、`finally` 返回型改为 `auto` 与 `std::decay_t<F>`。本次补充只为 5.0.1 after 端新增 fresh HIA LLVM 连接，没有重做 4.0.0 的 LLVM 对照，两份证据分别保留。

其他范围也已纠正：unique_ptr reset/reuse/swap 有真实 ABI/行为/生命周期控制，但 API 版本是作者构造的变体；SQLite 3.46.0→3.53.2 选定的 841 字节函数片段没有变化，不能用它代表真实 changed-function 升级，且只覆盖所注册的宏配置。自动化 wall 不是人力维护优势。完整迁移审计保留在静态证据包。

## 7. Agent：纠正分母与成本，没有生产率胜出证据

本轮没有启动新的模型 cohort。历史 v10 在 `b47ce924...` 上实际为 **16 个 cell、29 次生成请求 = 26 次完成 + 3 次超时，正确交付 0/16**；四个 arm 均为 0/4。3 个 Granite/HIA 第一轮请求到 240 秒 deadline 后按原协议终止，没有补算为已完成回答。五个 owned model session 的成功 reap/身份清理有记录。

两个固定模型为 Qwen2.5-Coder-1.5B-Instruct Q4_K_M 与 Granite-3.3-2B-Instruct Q4_K_M，固定 llama b11669 runtime、CPU 16–19、4 线程、无 GPU、32768 context、7168 output ceiling、240 秒 deadline、最多两次尝试、greedy seed 0。相同公开信息仍有表示长度差异，例如 Qwen floor 的 HIA full-source prompt 5398 token，Rust 755 token，此成本不能隐藏。

已知 input 合计 **63,255 token**、已返回 output **6,729 token**；3 次 timeout 的 output 数量未知，保留 null。原外层真实 wall 为 **2564.181270859 秒**，已包含 preparation、完整 cohort 和外层 overhead；不能再叠加 inner 计时，也不能把旧 PR 的不同统计混入这一 cohort。没有正确任务，因此 cost-per-correct 为 null。

两个真实 upstream 任务来自同一个 stb signed-arithmetic fix，函数签名未变，属于相关的算术维护任务。floor 的 accepted reference 是另行编写的 widened quotient/remainder 程序，完整 captured after-version 在原 solver budget 下仍 unknown，不能声称完整 C→Core rewrite 已证明。

S3 的 public feedback 只重放 **26 个已保存回答，0 个新模型请求、0 个新 native candidate 执行**；统一组合中的 10 个 reference/refusal 控制用于基础设施验收，不是 Agent 开发收益实验。现 evaluator 强制单文件、单个 `target(i32,i32)->i32`，排除 imports、额外函数、resources、loops、FFI；因此需要新的任务与 evaluator 才能实际测接口升级和跨模块。完整请求分母、逐次成本与范围见 [agent-audit.md](agent-audit.md) 和 [agent-audit.json](agent-audit.json)。

## 8. 平台与并发：同产物两机通过，CI 按实际后端报告

### 两台实际 Linux x86_64 主机

同一 `0a06ef4` 199 文件包、同一两份 `.so` 在 Xeon E5-2673 v3 / Linux 7.0.0-38 和 X230 Core i5-3230M / Linux 6.8.0-142 上执行。每台 base、预期 protected-write SIGSEGV 及 recovery race 三阶段均达到预期，合计六阶段通过。实际两 reader、竞争恢复一次 commit/一次 refusal、迟到旧调用不能污染新 epoch、worker join 和 owner/library registry 清空均有记录。

这是一次 desktop preparation campaign、两次 qualifier 调用、五条实际 compile/link 命令、两份共享库；X230 **零编译、零安装**，测试的是相同 artifact 的执行。不是新的 ISA/ABI，不等于 X230 编译器资格，也没有把全套 36 命令搬到第二台机器。runner 在隔离导入下核验 manifest/head/tree，并在执行前后核查所有已加载的 hepta/tools 模块及 namespace 来源均在包内，包前后身份一致；标准库和系统运行库仍属于外部运行环境，`fully_hermetic_runtime_custody=false`。详见 [CROSS_HOST_RESULT.json](CROSS_HOST_RESULT.json)、[P2_PUBLICATION_RESULT.json](P2_PUBLICATION_RESULT.json) 和 [p2-two-host.tar.xz](p2-two-host.tar.xz)。

它提供具体恢复/并发控制的证据，不推出一般并发内存模型、DMA/MMIO、设备或任意 OS crash 后恢复。

### exact published head 的 CI

2026-11-06 00:31:31 UTC 记录的非原子 API 汇总快照为 **12 个 workflow aggregate queued；106 个 job/check 中 6 个实际 success、100 个 queued**。四个 Windows x86_64（Clang/MSVC 的 C++ 与 ABI/STB）和两个 macOS AArch64 Clang 任务完成。不能把 queued 标记成通过；Windows 两项 POSIX step skipped、macOS 两项 Visual Studio setup skipped 分别记录。

Windows 四个 ZIP 的 digest 与 API 一致；421 个保留文件、100 份原始小 stdout/stderr 全部核对。独立整数 oracle 核对 **85,812 条 TSV row** 匹配，审计本身没有新增 native/CI/model 执行。实际 C++ consumer、ABI object 与 STB native target 是 **Rust backend**；STB HIA 的 native requested/executed 为 false，每个 STB 配置（generic / truncating）有 58 个 input、348 个 interpreter function observation。ABI 每个优化 profile 181 次 foreign call，产物为实际 PE32+，范围限于已执行的 C ABI。

Windows C++ ordinary lifecycle delta 为零，但存在 3 个 process-lifetime registry allocation，不能称全部内存已释放。每个 C++ profile 的 8 个示例文件与 Linux hash 不同，16/16 差异均精确为 LF→CRLF；已与规范 Git blob 对照，不能说各平台物化字节完全相同。其余 196 个 C++ source input/profile 和 477 个 ABI/STB implementation record/profile 字节匹配。ABI 原始 Rust compiler argv/完整 raw streams/临时 Rust input 没有全部留存，结构化 receipt、规范 Rust 输入和 object hash 保留，缺口明确披露。详见 [Windows 审计](WINDOWS_ARTIFACT_AUDIT.md) 和 [windows-gha-evidence-review.tar.xz](windows-gha-evidence-review.tar.xz)。

macOS 两个原始 ZIP 也已独立核验：实际 profile 为 **Apple Clang 17 + Hepta Rust 1.90 backend / aarch64-apple-darwin**。245 个 ZIP 普通文件建立完整身份清单，212 个声明 retained 文件、19 个 ARM64 Mach-O、54 份单独保留的输出流和 40 个 C++ 嵌入字节流记录均完成核对；C++ 的 204 份 source input 与 STB 的 477 份 implementation input 对应字节匹配冻结 Linux checkout。这个子集检查不等于独立重建整个 CI Git tree。

macOS STB 使用同一 21,453 个唯一输入的两个配置，共 42,906 条 TSV row，与独立整数 oracle 逐行匹配；报告原生函数观察为 514,872 次，包含协议的重复 original/target 调用。24 个 target-only trap 进程均为预期 -6，错码目标返回 2。HIA 仍只有 **696 次 interpreted observation**，两配置都明确 `native_requested=false/native_executed=false`。C ABI 的 -O0/-O2 各有 181 次 foreign call；原 qualifier 缺少完整 Rust compiler argv/raw streams 和临时输入原字节的边界仍保留。两个 job 的原日志有 73 个现有 unittest 全部 Ran/OK，无内部 unittest skip；本次只读审计没有重跑它们。

Windows/macOS 的 C++ 集成还实际对照 nlohmann/json 3.11.3 与 3.12.0，每版本 98 个 direct/Hepta case，保留原生库和生成 bridge，并没有把整个库重写成 HIA。macOS 每版本 ordinary live delta 为零，**另保留 2 个 registry allocation**，与 Windows 的 3 个记录分别报告。有限生命周期、并发、取消和错误控制不等于一般 foreign-memory 安全、全部配置兼容或维护优势。macOS 公开小包完成 71/71 成员恢复核验，完整 CI ZIP、大 TSV 和二进制留在原始远端证据中，其清单及哈希公开；见 [macOS 审计](MACOS_ARTIFACT_AUDIT.zh.md)、[完整审计 JSON](MACOS_ARTIFACT_AUDIT.json) 和 [macos-gha-evidence-review.tar.xz](macos-gha-evidence-review.tar.xz)。

## 9. 历史测试范围与公开恢复

“S3 的 CORE ID 全保留”不能扩大成“所有历史研究分支的所有测试原样保留”。旧 `5ee6d8...` 不是 S3 祖先；其 shared-source 文件有 43 个 test method，S3/当前是 40 个，共同 40 个 AST 不变。三个旧方法未保留，另有 10 个 structured-source 控制实际运行；新旧不是逐项等价替换。旧 Raw 动态 subclass 读取语义存在未保留的静态反例，TextSubclass 和全部五类 certificate 对手写旧 oracle 的控制也缺乏直接替代。这个反例属于 helper 的外部 Python object domain，不是 Lean theorem 或规范 Core 执行失败。详见 [历史测试范围审计](HISTORICAL_TEST_SCOPE_AUDIT.md) 及独立分析包。

发布证据与执行源码分别保存在不同分支。归档均有 manifest、SHA256、Git blob SHA1 和全新目录的逐文件恢复检查；保留失败、unknown、拒绝与缺失成本。公开包不包含模型、工具链、私有 NDU 上游复制源码或私有编译产物；对应身份、构建命令、cost 与结果 receipt 在可公开范围保留。实际保留/排除列表和完整恢复计数见 [EVIDENCE_INDEX.json](EVIDENCE_INDEX.json)。

公开的 `composition.tar.xz` 为 **8,535,652 bytes**，由原 20,116,196-byte 包做无损重压得到。两者解压后的完整 tar 都是 205,373,440 bytes，SHA256 `6ea7dd9b923997541b5a97d3244e82d53c83585a56f0a47ba87fffd75c490900`；1,778 个原文件与 4 个 sidecar 的成员和字节完全一致。原包及 revision 3 receipt 保持原样，公开文件应按 [COMPOSITION_COMPACT_PUBLICATION_RECEIPT.json](COMPOSITION_COMPACT_PUBLICATION_RECEIPT.json) 的新压缩包身份核验；原恢复结果见 [COMPOSITION_ORIGINAL_PUBLICATION_RECEIPT.json](COMPOSITION_ORIGINAL_PUBLICATION_RECEIPT.json)。重压耗时不计入产品性能或冻结正式序列。

后续关闭标准保持原样：把剩余 checker/lowering 语义逐项接入证明；在新冻结候选上按原条件处理尾部与 n=0 冷调用；引入发生真实接口/资源变化的迁移与独立任务；让 NDU 在真实动态机会和全部观测成本下获胜；扩展已资格化 profile 的实际硬件与内存模型证据。本轮保持草稿和 DENY_ALL，不把这些未完成项写成已实现保证。
