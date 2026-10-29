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

以上路径均位于 `experiments/`。源文件、协议、输入、工具、原始响应和构建身份分别绑定。
同树发布记录与实际 CI 观察分别保存在本轮 publication / CI ledger；历史结果不直接
验收后来的组合。新增实现和审查仍需在完整集成来源上经过相应检查。

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

新模型资格和四臂主实验仍需独立注册与实际 tokenizer 容量审计，不能继承 v6 资格或
把工程参考控制当成 Agent 成功。初始及修复提示、完整正确参考答案必须在所有条件中
容纳于相同的预定上下文/生成预算，参考答案不能进入模型请求。

## 6. 公平应用性能与资源

选定候选预先登记为 HIA IRPGO。对照包括 HIA default/LTO/IRPGO，C和C++的LTO、
frontend PGO与IR PGO，以及 Rust LTO/PGO。训练、held-out输入、算法和布局约束均保留。
实际正的 ENTRY block counters、编译输入/Core字节绑定、O3/LTO资源观察器和成本范围
均经过独立审查；开发阶段的失败和旧O2观察保留原归属。

| 算法 | HIA IRPGO median | 最强对照 median | HIA/对照时间 | P99比值 | RSS比值 |
| --- | ---: | ---: | ---: | ---: | ---: |
| CRC | 38.715538 ms | C LTO 41.916362 ms | 0.923638 | 1.101488 | 1.036675 |
| IEEE | 41.845892 ms | C IRPGO 38.572544 ms | 1.084862 | 1.310353 | 1.071782 |

这里的 median 是整个 workload process 的 wall time；P99 是汇集的、每批最多4096 bytes
的处理时长，不能解释为生产服务请求P99。RSS列是7次 child `wait4` 峰值的中位数之比，
不是全程序静态峰值或跨所有运行的最大值。原始各次峰值均保留。

CRC median 有较低观测值，但两种算法没有同时通过 latency/RSS 复合门槛，
`performance_and_rss_gate=false`。报告不会事后换成较弱的参考来把结果改成阳性。
初始化0.049134493 s，run83.032088636 s，合计83.081223129 s；HIA IRPGO准备
1.003022127 s，Rust PGO准备7.188470515 s。该timer不含外层Python启动/import、工具链
安装、归档与人工工作。旧实验遗漏 constructor 的 cost scope
单独明确保留，未补造未测量的时长。

全部本地测量发生在共享开发主机，结果不提供普遍或统计性能优势，也不说明真实生产服务
的长期P95/P99、设备协议或所有硬件 ABI 已得到验证。硬件/资源优势与安全边界分别验收。

## 验收结论

本轮可以交付实际实现、版本清楚的原始记录、可重建的完整文本证据、反例与有限规格。
闭合的是这些明确 profile 中已经修复并验收的工程缺口。完整语言精化、普适迁移成本、
全局实际最优和三项优势主张继续保持未建立，不能用增加测试数量替代所缺的证明或实验。
