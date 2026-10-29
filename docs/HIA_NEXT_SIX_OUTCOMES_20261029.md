# HIA 六项成果：下一轮执行与证据边界

本轮沿用现有独立 HIA Core、schema registry、验证接口、Rust shadow Machine 与
Clang/LLVM 路线，继续修复工程阻塞并执行实际实验。**目前不能判定所有 blocker 已闭合。**
完整语言安全、一般 C/C++ 自动迁移、NDU 实际净收益、Agent 效率优势和强性能资源优势
各自需要证据；任何一项阴性结果都没有被更换分母、删除样本或改标版本来关闭。

代码及可重建文本证据发布在 [Draft PR #360](https://github.com/TrillionniumFoundation/Hepta/pull/360)。
原始实验继续属于原始提交。公开 API 创建的提交可能与本地提交有不同元数据，
只有明确核对 Git tree 后才记录同树关系，不把本地测量重新命名为公开 HEAD 的测量。
机器可读状态见 [BLOCKERS_20261029.json](../experiments/hia_next_closure/BLOCKERS_20261029.json)。

## 1. 统一 Core 与版本归属

本轮保留此前对返回借用、schema 版本、资源移动、空 owner、失败清理和旧 generation
lease 的语义选择。新 allocator payload 分析没有扩域旧的 heap-budget/native admission；
prepared image 复用接续现有私有证明边界；HIA Agent 编辑也必须经过现有 Core verifier
和实际 native admission。Rust 对照则经过其独立的有限源码/资源检查、rustc 和 native
观察。没有增加可由外部 receipt 开启的执行权。

| 工作 | 原始冻结来源 | 证据入口 |
| --- | --- | --- |
| 初次实际 C 组件迁移、449项 lowering 检查 | `ccd423bc9ee22888fec5d23f993978f2c0f51b57` | `hia_legacy_queue/results_20261028`、`hia_next_safety/results_20261028` |
| 独立 Rust 对实际迁移 Core 的核对 | `a1e14e2364eab8c6697187157f30d70291c1309c` | `hia_legacy_queue/rust_shadow_20261029` |
| IR PGO 强基线应用实验 | `6191eca3e896473707306fb8fb98d9b7b6f187bb` | `hia_legacy_queue/irpgo_results_20261029` |
| sealed artifact / 内部证明复用实现 | `3c547848a4e9e488b42de631bb29ba039c489093` | `hia_next_safety/artifact_review_20261029` |
| NDU prepared reuse 正式实验 | `b53d61cd3cdb522ccd718f3fdc7cd62d1d5964a2` | `hia_ndu_prepared_reuse/results_20261029` |
| Agent v5 正式资格验证 | `9c9cfaccb4eff5fa5d62e3c9f33efdaf50b3c70e` | `hia_agent_factorial_v5_20261028/evidence` |
| Agent v6 正式资格验证 | `f695384324d2de784f727d349bd67891f7f45bd3` | `hia_agent_factorial_v6_20261028/evidence` |
| 实际 Core 静态 payload 分析 | `d246aecf3cd1b96e818bd4e53ffe0408fb1fbd93` | `hia_next_payload_bound` |
| 真实节点事务最终工程控制 | `677a15928c1dd3b236c7bee8cf4b3e6041177f6c` | `hia_next_safety/structured_review_20261029` |
| V8真实节点容量与模型资格 | `33c46cdef12c60faf0c1dbef02ea20caa3ad7d56` | `hia_agent_toolstudy_v8_20261029/evidence` |
| V9通用节点契约、容量与完整阴性资格 | `ef9fbafabe9db52a5e59220f1738d5842ac164cc` | `hia_agent_toolstudy_v9_20261029/evidence` |
| V10单一新模型容量与完整阴性资格 | `11d6f78c6c01f66978af7fcf4d40eea7dae5d5f0` | `hia_agent_toolstudy_v10_20261029/evidence` |

以上路径均位于 `experiments/`。源文件、协议、输入、工具、原始响应和构建身份分别绑定。
同树发布记录与实际 CI 观察分别保存在本轮 publication / CI ledger；历史结果不直接
验收后来的组合。新增实现和审查必须在完整集成来源上经过相应检查。

已发布的 `97aa97110be8fd307503dce3baca9499f8bb0da4`（与本地 `c576e94` 同树）
通过了两套独立记录的集成CI：source/application为37项安全契约、213项回归、
449/449 lowering obligations、实际payload和IR PGO准备、35+3项既有参考控制及9项
真实节点事务；verified-native为756次测试执行、0跳过及36项native NDU observations。
旧综合测试清单重复列入了`tests.test_hia_returned_loans`，该模块的31项测试运行了两次；
756不能作为756个独立测试的分母。`79d7bb4`删除重复项，并使重复模块成为显式错误，
同时接入13项V8研究工具回归、12项参考入口回归及19项实际native参考检查。
与其同树的公开来源`fc4a63e8a5064c6f054a67ea2fe8dd56cbcb37a4`已通过自身两套CI：
source/application为37安全契约、238回归、449/449 obligations，以及全部19原生参考；
verified-native为750次测试执行、0跳过和36项native NDU observations。
之后的公开来源`7511d99b80511b33082a76d71109adf4ecdb1395`与本地`ee99df4`同树，
自身source/application有37安全契约、249个不同回归ID、449/449 obligations，
V8、V9分别运行19项实际原生参考；verified-native有761个不同测试ID及36项native
NDU observations，均无跳过。两个套件与安全契约有重叠，三者并集是792个不同ID，
不是独立统计样本。完整GitHub原始artifact已下载，ZIP摘要与GitHub元数据一致，
两轮原始artifact均已独立复核；参考控制的模型请求、tokenizer和Agent成功数均为0。
新增V10协议、来源与CI selector需在新的统一来源上再次验证，不继承7511结果。
重叠测试不相加；旧绿色也不覆盖新组合。模型资格仍按其原始冻结来源独立记录。

## 2. 可检查的安全与资源规格

### 已完成的有限验证

- 449/449 个选定标量 lowering obligations 通过，unknown 和 refuted 均为0。
  每个 obligation 对该实际 Core/LLVM 形状的全部良类型输入检查值与 abort 行为。
  5个故意改变指令、guard 或 LLVM flags 的负控被反驳或拒绝。
- 对实际有符号/无符号游标函数另设66位数学规格，检查
  `0 <= offset + index < extent`，覆盖全部192位输入组合，不施加样本推导的前提。
- 独立 Rust Machine 实际读取迁移 Core：16个函数、162个基本块，96/96次执行的
  返回值、资源字段和 steps 与保留的 Python VM 记录一致。这是差分证据，不是健全性定理。
- 对同一 Core 的静态 payload 分析给出每次 fresh scalar entry 的如下上界：

| 量 | 上界 |
| --- | ---: |
| allocation opcode 执行次数 | 3 |
| 非零 HIA allocation request 次数 | 3 |
| 累计 requested byte-owner payload | 32 bytes |
| 逻辑同时 live byte-owner payload | 32 bytes |

实际 Core SHA-256 为
`1044e28ea68a18d6a0681cff9cd5f835e26e91c9a669dab01256b9592f64ca51`。
该分析遍历完整调用 DAG 与 CFG SCC：循环及循环中的传递调用必须无分配，
非循环分配必须使用同块先前的 literal `usize` 常量。三个点的尺寸为16、8、8。
分支累加保守计费，owner 返回/移动不重复计费；失败、trap 和预算停止的有限前缀
也不超过上界。19/19正负回归通过，独立审查使用另外的可达性与 call-site 计费计算
复核了结果；集成来源 `0d0164f` 上又实际重新执行并得到相同 analysis digest。

### 仍然需要分别证明的范围

32 bytes 指逻辑 byte-owner payload，不包括 allocator header、VM metadata、RSS、
线程或机器栈。它不证明终止、异步取消后的清理、并发资源上界、递归存储或 native 精化。
静态分析以 canonical verifier、闭合操作语义和分析器实现为 TCB，是经过审查的结构归纳
论证，不是 proof assistant 对语言及实现的完整定理。

449项检查也不覆盖全部程序、内存操作、循环、资源清理、并发、LLVM 优化和最终机器码。
将实现写成 Rust 可减少实现层面的某类内存错误，但不会自动提供源语言到 Core 或
Core 到 native 的语义精化证明。上述边界没有通过本轮结果被省略。

## 3. 真实多文件 C 迁移纵向案例

迁移对象是有实际用途的 Ring-Buffer 和 musl 比较实现，完整保留上游原文件与版本。
迁移了11个上游函数体、3个原始 TU；另计一个手写 CRC 辅助 TU 和 Hepta 集成客户端。
流水线包括实际构建捕获、记录/视图转换、所有权验证、独立 VM、native 差分、分配失败
注入、scalar C ABI 调用以及新增第五 TU 的维护任务。

初次正式实验得到768次正确 native 对照、96条资源拒绝/释放记录、12项维护用例和
112个性能样本，0剔除。随后 IR PGO 实验扩展到11臂，得到1056次正确 native 对照、
96条资源行（24个输入 × 4种 refusal 配置）、12项维护用例和154个性能样本
（2算法 × 11臂 × 7组）。二者是不同注册实验，分母分别保留。

外部入口是受检查的 scalar C ABI；原来的 pointer/record ABI 没有原样迁移，通用文件
I/O host 仍然保留。这个案例不能说明任意 C++ 模板、异常、虚继承、外部回调和历史库
均能低成本翻译。机器执行成本有原始计时；人工开发、审查、维护总工时未做可信记账。

## 4. NDU：工程复用闭合，经济指标保持阴性

`PreparedArtifactSession` 在现有内部证明边界中建立 sealed image，按有限 lease、entry、
byte 和 attempt 预算复用。每次运行仍检查 Core、policy、工具/实现身份、proof ancestry、
sealed bytes 与 fd。未知 close 结果继续占预算且不按数字 fd 重试。

独立审查修复了部分发布事务、driver fd 元数据失败的所有权丢失，以及编译器身份检查
无界/阻塞读取的问题；24/24真实 native 生命周期回归通过。证明复用对 fixed、DP、NDU
完全共享，不能把该运行时工程收益归因于 NDU。

正式实验包含24个 policy episodes：618个 workload outputs，加54个校准、8个机制和
100个后置机会控制 outputs，总计780个正确 native batches。每批调用131071次。
全部 source/tool/driver 与 release 检查通过。NDU构建6个候选，148/148个决策与其
当前输入模型上的完整有限 DP 一致；这只说明模型内最优。

| 策略 | 含各策略一次公共准备的注册 warm 成本 |
| --- | ---: |
| 强 fixed | 208.131606 s |
| 完整有限 DP | 212.495324 s |
| NDU | 237.767684 s |

公共准备92.294971066 s在每个独立策略账本中各计一次。后置机会控制59.476823747 s
不计入策略选择成本表，但计入实际全 study 的533.293238534 s（截至最终编码之前）。
外层启动、工具链安装、归档及人工工作不在该注册测量范围内；这些成本不能被称为已测量。

两个后置实际候选机会分别比 baseline 多花0.902403 s和2.870096 s。因此两个真实盈利机会
竞争预算的 gate 和 NDU warm 净收益 gate 都为 false。旧32.133198039 s controller build
只作为历史空 target 参考，没有改称本次冷启动。两个 group 的 rotate/reverse 也没有
实现全部顺序位置平衡，报告保留此限制，不建立统计优势或将所有 wall-time 差异归因于算法。

## 5. Agent：先建立能辨别效率的实验

v5 正式资格验证中的1.5B和7B模型都只通过1/3任务；共15请求、15594 tokens、
1350.885819202 s。计入更早的部分运行和旧来源诊断后，全部v5请求为28次、27609 tokens、
1612.593904963 s；不能只报告成功完成的末次成本。这仍不是工具开发与模型取得的总工时。

v6 接入实际 rustc 对 bare primitive parameter `.into()` 的类型检查，并提供已公开用例
的结构化错误反馈。冻结来源上，7B仍只通过1/3任务：8/8完整响应，7151 input tokens、
1458 output tokens，合计8609 tokens；796.357656461 s，unknown usage为0、人工修复为0。
签名和 owner 任务仍失败，所以主实验没有启动，也没有把参考答案控制算作模型成功。

此前 query 条件仍返回完整函数替换，不能称为真正的节点编辑。本轮新增的真实节点事务
路线已在 `677a159` 冻结并经独立审查；它使用现有 HIA batch/patch API，以及有限 Rust
表达式/类型节点和实际 source spans。需要签名/容器重建的操作必须显式披露、绑定政策，
不能把隐藏的完整函数重写算作纯节点原语。

审查实际修复了并发旧 revision 覆盖、`else if`/AST 深度越界、失败构建先执行，以及
候选 digest 异常后仍提交四处缺陷。最终51/51静态控制包括21项新接口与30项既有
profile/transport 控制；9/9真实工程控制包括5个接受与4个预期拒绝事务。7项有 public
native 观察，5个接受案例另做 terminal hidden 观察；均不计为模型成功。
HIA基底必须是已验证Core，Rust仅支持有限ASCII语法，四文件维护也不是长期生产维护。

### V8：真实工具容量通过，模型资格仍未通过

`33c46cd`冻结了4任务×4臂的真实full/node研究，以及独立的3项资格门。
固定Qwen2.5-Coder 7B Q4_K_M、8192上下文、每次1536输出、最多3次提交；
所有完整请求用实际模板和tokenizer再次检查容量。推理主程序、模型及伴随库身份
跨capacity、qualification、main绑定，先前资格不能继承。

正式生成前，19/19人写参考控制通过真实编译、public、资源及terminal hidden；
此阶段generation为0。最长初始请求2758 tokens，最长正确参考1059 tokens，
实际修复控制输入加完整输出预留最多5001；登记allocation envelope加输出预留
最多7238/8192。最后一个数字不是任意BPE串的数学上界，仍依赖每次实际容量检查。
参考答案未加入模型请求，参考控制也不计为模型成功。

| V8资格任务 | 提交次数 | 正确任务 | input tokens | output tokens | 实际结果 |
| --- | ---: | ---: | ---: | ---: | --- |
| 标量修复 | 2 | 1 | 3574 | 188 | 首次真实rustc拒绝`u64 + u32`；第二次通过public、hidden和资源检查 |
| 多文件API升级 | 3 | 0 | 7505 | 2370 | 三次完整回答逐字相同；将完整函数填入类型节点，均在编译前拒绝 |
| 所有权修复 | 3 | 0 | 7935 | 840 | 三次完整回答逐字相同；将语句填入表达式片段，均在编译前拒绝 |
| 合计 | 8 | 1/3 | 19014 | 3398 | fresh资格为false |

8/8响应完整，合计22412 tokens，unknown usage、代码截断、诊断裁剪及人工修复均为0。
生成包装调用wall time合计2015.920246400 s（不是纯模型计算时间），
注册实验wall time为2059.597590950 s；
模型、工具和来源未变化，owned server已退出。两项失败任务没有执行hidden。
实际调用main入口得到`E_TOOLSTUDY_NO_QUALIFIED_MODEL`，发生在输出目录和engine
创建前：main为0/16 cells、0模型请求；该拒绝检查另花5.690141661 s。
capacity/reference阶段另记录64.003405956 s，三个已记录阶段合计2129.291138567 s；
这仍不包括工具开发、模型取得、归档或人力成本。
**没有HIA模型对照结果，不能从本轮推断HIA或Rust的开发效率优势。**

V5全部保留尝试、V6和V8合计44请求、58630 known tokens、4468.549152374 s
注册实验wall time。这个合计不包括V4残留未知成本、人力、模型取得/训练、参考控制和
工具开发，也不是完整项目成本。

独立后续审查还发现通用batch契约没有充分说明“ID唯一”和“Rust同文件spans不可
重叠”。这影响工具说明的公平性，应前瞻补齐；但V8实际失败先发生于已披露的
type/expression片段规则，尚未进入overlap检查。不能据此重判失败、自动修复模型
答案或声称补充两句话必然成功。最小修订另行登记，旧V8协议、原始响应、资格和成本
保持不变；新来源仍须重新审查容量和fresh资格。

### V9和V10：前瞻登记与完整结果

V9仅补充两条通用节点契约，8项完整程序提示与全部参考答案未改。
冻结`ef9fbaf`的19/19真实capacity/reference控制通过，0生成，76.953562987 s；
最大initial为2804 tokens，最大参考1059，实测repair加输出reserve最高5044，
登记分配包络7284/8192；所有真实请求仍逐次tokenize并保留完整输出reserve。
独立审查`34cafc7`允许其fresh资格；完整结果已结束且由`757bbf3`独立复核：

| V9资格任务 | 提交次数 | 正确任务 | input tokens | output tokens | 实际拒绝 |
| --- | ---: | ---: | ---: | ---: | --- |
| 标量语义 | 3 | 0 | 6091 | 272 | 三个不同回答均被实际rustc以E0277/E0308拒绝 |
| 多文件API升级 | 3 | 0 | 8017 | 2931 | 三次完整回答相同；完整函数不符合类型节点规则 |
| owner资源修复 | 3 | 0 | 7695 | 276 | 三次完整回答相同；选择了query中不存在的节点 |
| 合计 | 9 | 0/3 | 21803 | 3479 | 未取得fresh资格 |

9/9完整EOS响应，共25282 tokens，unknown usage/人工答案修复/代码截断/诊断裁剪为0。
没有public或hidden native执行。资格wall 2261.307883468 s，owned engine已退出，
source/model/tools身份未变化。实际main入口在engine/输出目录创建前拒绝，0请求、
0 cells，单独耗时12.242381912 s；容量、资格、拒绝三个独立阶段合计2350.503828367 s。
generation wrapper与HTTP/SSE是嵌套时钟，不能再加到该合计。
独立审查还核对172个source snapshots与原提交Git blob、全部9条SSE和usage。
V5/V6/V8/V9保留模型运行合计53请求、83912 tokens、6729.857035842 s；原先排除的
V4残留未知成本、参考控制、获取、人工与工具开发成本仍不在该分母内。

单一新候选V10冻结于`11d6f78`：Qwen3-4B-Instruct-2507的固定Q4_K_M文件，
大小2497281120 bytes、SHA-256 `3605803b982cb64aead44f6c1b2ae36e3acdb41d8e46c8a94c6533bc4c67e597`。
其题目与提示直接复用V9，仅固定模型和官方模板/tokenizer适配。
54项静态/mock控制及185个来源绑定已由`250e982`独立复核，预审只允许0-generation
capacity；该次预审时模型尚未下载/运行，qualification/main保持HOLD。完整19项真实参考、95项
CLI/server原始token-ID对照及实际完整模板必须先通过独立审查，才可启动fresh资格。
仍须3/3资格才能执行四任务×四臂的main；若失败，保存全部成本并停止，不追加候选
或按失败样本继续调题目提示。官方模型性能宣传不作为本实验的能力证据。

V10实际容量随后完成，并由`d265b61`独立审查：19/19真实参考、95/95 CLI原始
token-ID对照、76/76完整模板对照通过，0生成。185个来源与Git/current/snapshot匹配；
19个ELF、8个object和8个Core，以及54个public、472个hidden案例观察逐项核对。
capacity为68.212309461 s，其中CLI38.050519589 s已包含在内；模型取得另计
57.295566572 s。一次启动前transport断连发生在创建进程之前，精确调度wall未知，
单独保留后只重试原命令，未将未知成本填为0。容量记录SHA-256：
`28a6461f287b473b3c7e0683fb638c1504d913440940741a229e57b35fab79d6`。

GGUF嵌入模板全文与固定官方模板全文不同，含额外reasoning分支；本实验76次注册
plain-role渲染及后续9次实际生成前渲染均逐字符合官方plain分支。冻结guard每次
生成前检查完整渲染；该差异没有触发本轮拒绝，不能用于重判负结果。

| V10资格任务 | 提交次数 | 正确任务 | input tokens | output tokens | 实际拒绝 |
| --- | ---: | ---: | ---: | ---: | --- |
| 标量语义 | 3 | 0 | 5045 | 173 | 将新provider调用填入原调用的参数节点，形成额外调用 |
| 多文件API升级 | 3 | 0 | 6218 | 327 | 三次相同回答把完整函数放入类型节点 |
| owner资源修复 | 3 | 0 | 8106 | 973 | 表达式节点含额外语句，trailing tokens |
| 合计 | 9 | 0/3 | 19369 | 1473 | fresh资格为false |

9/9完整EOS响应，共20842 tokens，qualification wall 1199.440217767 s。
全部在编译器调用前被拒绝，public native/hidden执行均0；unknown usage、代码截断、
诊断裁剪、公共案例移除、人工或host答案修复均0。source/model/tools身份未变，
owned模型进程退出。实际main入口再次在输出目录/engine构造前拒绝，0 cells/0请求，
单独耗时3.138174268 s。capacity、qualification、main拒绝合计1270.790701496 s，
不含模型下载、人工、调度等待、归档和工具开发。

`cbb83f0`独立核对九次完整模板和repair历史并明确DENY main，`be1980f`独立核对
全部SSE/token/成本、185个Git blobs、query摘要和实际拒绝链。资格RESULT的SHA-256为
`9d528ebfdfa5e6f0e748f625a6364cbbe8786ffd54f55ab8bb3f335d50905b94`。
V5/V6/V8/V9/V10全部保留模型运行合计62请求、104754 tokens、7929.297253609 s
登记模型study wall；参考控制、取得、人工等原排除项不变。单候选停止规则已经执行，
没有追加模型或调题目提示。没有HIA主实验模型结果，仍不能比较语言开发效率，
也不能把有限节点接口失败泛化为该模型不具备一般编程能力。

## 6. 公平应用性能与资源

选定候选预先登记为 HIA IRPGO。对照包括 HIA default/LTO/IRPGO，C和C++的LTO、
frontend PGO与IR PGO，以及 Rust LTO/PGO。训练、held-out输入、算法和布局约束均保留。
实际正的 ENTRY block counters、编译输入/Core字节绑定、O3/LTO资源观察器和成本范围
均经过独立审查；开发阶段的失败和旧O2观察保留原归属。

| 算法 | 方案 | 吞吐 MiB/s | 整进程median ms | 批次P95 μs | 批次P99 μs | RSS KiB |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| CRC | HIA IRPGO | 51.659757 | 38.715538 | 155.316 | 300.052 | 1696 |
| CRC | 最强对照C LTO | 47.714906 | 41.916362 | 152.416 | 272.406 | 1636 |
| IEEE | HIA IRPGO | 47.795260 | 41.845892 | 163.037 | 308.714 | 1732 |
| IEEE | 最强对照C IRPGO | 51.851267 | 38.572544 | 123.845 | 235.596 | 1616 |

这里的 median 是整个 workload process 的 wall time；P99 是汇集的、每批最多4096 bytes
的处理时长，不能解释为生产服务请求P99。RSS列是7次 child `wait4` 峰值的中位数，
单位为KiB；后述RSS比值由对应中位数相除。这不是全程序静态峰值或跨所有运行的
最大值。原始各次峰值均保留。
CRC的HIA/对照时间、P99和RSS比值分别为0.923638、1.101488、1.036675；
IEEE分别为1.084862、1.310353、1.071782。吞吐由同一实际处理字节数和进程wall time计算。

CRC median 有较低观测值，但两种算法没有同时通过 latency/RSS 复合门槛，
`performance_and_rss_gate=false`。报告不会事后换成较弱的参考来把结果改成阳性。
初始化0.049134493 s，run83.032088636 s，合计83.081223129 s；HIA IRPGO准备
1.003022127 s，Rust PGO准备7.188470515 s。该timer不含外层Python启动/import、工具链
安装、归档与人工工作。旧实验遗漏 constructor 的 cost scope
单独明确保留，未补造未测量的时长。

另保留实际切换和失败回退观察：成功切换一次，`switch_ns=89995`；拒绝一次切换后
继续有效baseline，`switch_ns=52927`，最终checksum保持正确。两条观察的监控计时
分别为2987 ns、3316 ns。这是本地具体路径的单次计时，不是生产切换延迟分布，
也没有测出进程崩溃后的服务恢复时间或长期监控成本。

全部本地测量发生在共享开发主机，结果不提供普遍或统计性能优势，也不说明真实生产服务
的长期P95/P99、设备协议或所有硬件 ABI 已得到验证。硬件/资源优势与安全边界分别验收。

## 验收结论

本轮可以交付实际实现、版本清楚的原始记录、可重建的完整文本证据、反例与有限规格。
闭合的是这些明确 profile 中已经修复并验收的工程缺口。完整语言精化、普适迁移成本、
全局实际最优和三项优势主张继续保持未建立，不能用增加测试数量替代所缺的证明或实验。
