# NDU 四关续作：全合法历史、完整策略与纯信念归因

## 结论与处置

本轮已完成实现、冻结、原始 native 全量执行和独立复核；正式结果为 **54 个初始环境、10,224 个登记状态、122,688 个状态—控制器单元全部完成**。完整 native 调用为 **84,960 次**，108 个原生进程全部正常关闭。源代码、原生输入和预登记清单在执行前后保持一致。

科学结论是：**这组冻结任务需要信息利用和规划，但没有显示动态数值偏好的额外收益，也没有显示 NDU 超过普通 MPC 的独占收益。** 在全部合法自然状态上，动态 NDU、固定偏好 NDU、普通 MPC、同目标普通控制器和 exact oracle 选择相同动作，并得到相同的外部完整策略价值。普通 MPC 的内部候选值不同，不能把其内部值也说成与 NDU 相同。

本轮关闭的是有限模型内的诊断、覆盖、归因和证据链缺陷。对于“自然动态偏好带来收益”“NDU 独占净收益”“可进入生产”的主张，本轮处置为 **当前候选 NO_GO，保持 Draft / DENY_ALL**。负结果可以完成对当前候选的判断，不能被改写成优越性证明。真实部署净收益、未知模型学习和未完成的跨平台 CI 仍有明确边界。

## 1. 交付和源码边界

- [续作 Draft PR #761](https://github.com/TrillionniumFoundation/Hepta/pull/761)，基于 [原四关 PR #758](https://github.com/TrillionniumFoundation/Hepta/pull/758)。
- 新源码 commit：`a07c5ecae52436234af370779cc440686dbe4139`；tree：`273e7c458713ede9593c03267245a5bf756fc4f7`。
- 三个源码提交分别增加独立全图／完整策略评价器、冻结 campaign／因果对照、CI 路径覆盖／方法说明。
- [冻结协议](https://github.com/TrillionniumFoundation/Hepta/blob/a07c5ecae52436234af370779cc440686dbe4139/benchmarks/hia_ndu_feedback_state_coverage/POLICY_PROTOCOL.json)、[执行器](https://github.com/TrillionniumFoundation/Hepta/blob/a07c5ecae52436234af370779cc440686dbe4139/tools/qualify_hia_ndu_policy_audit.py)、[评价器](https://github.com/TrillionniumFoundation/Hepta/blob/a07c5ecae52436234af370779cc440686dbe4139/experiments/hia_ndu_feedback_20261106/policy_audit.py)与[方法文档](https://github.com/TrillionniumFoundation/Hepta/blob/a07c5ecae52436234af370779cc440686dbe4139/docs/HIA_NDU_POLICY_AUDIT.md)可分别审查。
- 原 feedback model 字节未修改，SHA256 为 `56b335e5a7fc205e4ad955faf3eece2a63d43c097f71d5fb4af6d84ee1081b79`。仍使用已准入的原始 source-bound NDU 二进制，其 SHA256 为 `60a2118570078536e9298dbfb6b908988aead25d741e072a0b630d0315b97875`；原始 upstream commit 为 `8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d`。

旧证据已单独固化在 [e51de7a4 的证据入口](https://github.com/TrillionniumFoundation/Hepta/blob/e51de7a422988e69ddecaceba595e62b7d051507/reports/hia-ndu-four-gates-20261106/README.md)。它的唯一 parent 是 `78c0b951`，包含原始四组队列、历史失败、原始 CI、独立复核和逐文件恢复校验。原 feedback 队列仍绑定 `b1746d3e`，其余旧正式队列绑定 `78c0b951`；没有把旧结果回填成新源码结果。

本报告的逐项数字见同目录 `policy-descriptive-summary.json`，完整原始数据和重放方法见 [README.md](README.md)。该 summary 是描述性聚合，独立数值审计另有原始脚本与报告，不以聚合代替验证。

## 2. 本次实际修复的三项实验缺陷

### 2.1 从单一 owner 轨迹扩展到全部合法动作历史

旧自然支持覆盖的是 54 个 profile 的全部外生 request/signal tapes，但缓存、预算与期限由一个指定 owner policy 推进。其他控制器可能采取不同动作，到达旧清单之外的状态。

新图对同样 54 个初始 profile 枚举每个合法动作前缀；保留、切换、卸载／直接执行及显式 abstention 都进入图。每个动作分别保留下一观测的精确有理概率。不同动作之间没有先验概率，不能把所有动作分支相加当成一个随机试验。

结构预检只检查图大小，没有根据策略效果或计时调参。冻结后完整图为 10,224 个 profile-state、18,624 条 action/observation edges；每个 profile 最多 376 个状态、624 条边。状态按完整观测去重，跨 profile 仍分别计数。**这些是覆盖分母，不是 10,224 个独立统计样本。**

### 2.2 从首动作条件 regret 改为同时评价完整策略

旧条件 regret 为：

`V*(s) − Q*(s, 当前控制器动作)`。

它允许第一步之后由 oracle 接管，不能判断测试控制器一直运行到结束会怎样。新评价器在每个后续节点继续采用同一控制器，独立计算真实环境法则下的递归外部价值、预期交付数和资源成本。

评价统一使用动态外部目标、原 discount、逐节点 downside 风险函数、精确概率及 Q32 ties-to-even 舍入。第一次观测前，各 root 的条件价值按真实概率求均值并舍入一次，不另加一层风险变换。错误预测控制器的内部 forecast 不改变用于评判它的真实转移律。

首动作 regret 和完整策略 regret 均保留。本轮确实发现大量首动作 regret 为零而完整策略 regret 为正的状态，说明补这一层评价会改变实质结论，而非只增加一个重复指标。

### 2.3 将联合消融拆成真正的 2×2 对照

旧 `no-adaptation` 同时重置 posterior 和冻结 numerical preference，因此历史 `state_information_value` 标签必须解释为联合消融。本轮保留旧记录和 schema，新增只重置信念的 `prior-belief-only`：

| 控制器使用的信念 | 动态数值偏好 | 固定数值偏好 |
| --- | --- | --- |
| 当前公开 posterior | dynamic NDU | fixed-preference NDU |
| 初始 prior | prior-belief-only | 原 no-adaptation |

纯信念干预保持物理状态与数值偏好规则不变。四个策略均在同一个真实环境和外部动态目标下评价。报告分别保留两个条件下的信念效应、两个条件下的偏好效应与 interaction，避免将联合差值全部归给信念或偏好。

## 3. 正式全量分母与控制器

| 环境族 | 初始 profile 数 | 全合法自然状态数 | 状态—控制器单元 |
| --- | ---: | ---: | ---: |
| adaptive | 18 | 4,568 | 54,816 |
| fixed | 18 | 1,088 | 13,056 |
| misleading | 18 | 4,568 | 54,816 |
| 合计 | 54 | 10,224 | 122,688 |

12 个登记控制器为 fixed-direct、fixed-cache-0、fixed-cache-1、state-greedy、ordinary-MPC、same-objective、fixed-preference-NDU、dynamic-NDU、wrong-forecast、prior-belief-only、no-adaptation、exact-oracle。最强 fixed 是登记的三个“常量优先动作＋既定可行性回退”候选中的最优：根据完整 policy 的 ex-ante 外部价值，每个 profile 只选择一次，不能按观察到的 root 偷换固定策略。三个候选的规划、评价和选择成本全部保留。这不是对所有任意开环时间表或更广义固定策略类的全局最优主张。

所有 122,688 个单元完成；failed、not-run 均为零。每个 native arm 完成 10,224 次状态决策、42,480 次实际原生价值调用、54 个正常进程会话。动态和固定偏好各自都在搜索时调用原始 NDU，不以“native”标签或事后评分替代调用。

单次决策扩展上限保持 20,000，全 arm 上限保持 20,000,000。动态 NDU 实际扩展 169,920 次；没有为了通过而改变额度。正式全量外层墙时为 **101.028519050 秒**，包括图重建、规划、日志、完整策略评价和 native 生命周期。它是审计成本，不是物理端到端收益终点。

## 4. 结果：信念有效，动态偏好额外效应为零

### 4.1 同一自然状态上的数值变化与行为变化

动态 NDU 对比同 posterior 的固定偏好 NDU：

| 指标 | adaptive | fixed | misleading | 合计 |
| --- | ---: | ---: | ---: | ---: |
| 数值偏好发生变化 | 2,716 | 636 | 2,716 | 6,068 |
| 递归候选价值发生变化 | 2,860 | 724 | 2,860 | 6,444 |
| 动作发生变化 | 0 | 0 | 0 | 0 |
| 完整策略外部价值发生变化 | 0 | 0 | 0 | 0 |

此处零行为效应已经覆盖全部合法动作历史，而不只是旧 owner 轨迹。原有 supplied-boundary 反转和物理执行已经证明数值通道可以跨过决策边界；因此这组自然任务中的零效应不能直接归因为接线未接入。更准确的结论是：这些冻结自然状态没有形成偏好导致的动作边界穿越。

动态 NDU、same-objective 与 independent exact oracle 在所有 10,224 个状态上候选值、动作和外部完整策略值一致。ordinary-MPC 与 fixed-preference-NDU 的内部候选值可以不同，但它们的动作和外部完整策略值同样全等。普通控制器已经复制了此任务中观察到的全部收益。

### 4.2 首动作与完整策略的差异

| 控制器 | 首动作正 regret 的状态 | 完整策略正 regret 的状态 | 首动作零、完整策略正 regret |
| --- | ---: | ---: | ---: |
| state-greedy | 260 | 338 | 78 |
| wrong-forecast | 328 | 412 | 84 |
| prior-belief-only | 188 | 244 | 56 |
| no-adaptation | 188 | 244 | 56 |
| ordinary-MPC | 0 | 0 | 0 |
| fixed-preference-NDU | 0 | 0 | 0 |

以上行彼此重叠，不能相加当独立成功次数。一个清晰的根状态例子是 natural-profile-00 的 `7078f637d82663be9493c210506a73191670fe44922f8352558b54339df04a62`：step 0、request 0、signal 0、resident -1、budget/deadline 12/24、posterior 36/37。动态 NDU 与 pure-prior 此刻均选 cache-0，因此当前动作条件 regret 为 0；若继续使用各自策略，oracle 完整值为 `188311347298` Q32，pure-prior 为 `175205739230` Q32，差距 `13105608068` Q32，约 3.051387 个模型效用单位。下一步 request 1 / signal 0 分支出现时，两者分别保留 cache-0 与换为 cache-1。该反例来自原冻结自然环境，未为展示效果额外改造。

在 2×2 的完整策略差分中，保留 posterior 的纯信念收益在 adaptive／misleading 各 122 个状态上为正，fixed 为零；两个偏好条件下完全相同。动态偏好效应在两个信念条件下均为零，interaction 在 10,224 个状态上也均为零。按初始 profile 的 ex-ante 完整策略看，纯信念收益在 adaptive 18/18、misleading 18/18 为正，fixed 0/18。

这是对本模型中可用信念信息的机制判断，不是对现实训练预测器误差率的估计。misleading 的信号正确率低于一半但已知，正确控制器可以反向利用；它没有证明控制器会在未知漂移下自动识别坏反馈。

四格的归因针对同一外部模型下的策略价值。各格的 backend 不同，不能用这一 2×2 直接将物理时间差归因为信念或偏好本身。

### 4.3 最强固定策略与初始完整策略价值

下表为 exact oracle 减各策略的外部完整策略价值，单位为模型效用。每个环境族的 18 个 profile 等权描述性平均；不表示真实部署分布，也不是统计显著性检验。

| 比较策略 | adaptive 平均 regret | fixed 平均 regret | misleading 平均 regret |
| --- | ---: | ---: | ---: |
| 每个 profile 的最强 fixed | 12.118713 | 0.028778 | 12.118713 |
| state-greedy | 5.415810 | 10.390879 | 5.415810 |
| prior-belief-only | 5.187442 | 0 | 5.187442 |
| no-adaptation | 5.187442 | 0 | 5.187442 |
| wrong-forecast | 7.187793 | 0 | 7.187793 |
| ordinary-MPC | 0 | 0 | 0 |
| same-objective | 0 | 0 | 0 |
| fixed-preference-NDU | 0 | 0 | 0 |
| dynamic-NDU | 0 | 0 | 0 |

最强 fixed 在 **5/54** 个初始 profile 上已经足够，在另外 **49/54** 个上存在严格正 regret。5 个平手都来自 fixed 环境族；这个族其余 13 个 profile 仍可从状态规划受益。其 request-0 概率为 0.99，不是每个请求都确定相同，所以不能只看环境名称就宣称固定策略处处足够。

“所有决策单元完成”也不代表“所有服务请求均交付”。受预算／期限约束，连 exact oracle 在 **36/54** 个 profile 上的期望交付数也小于 horizon 3。完整记录保留这一点，不能将审核执行完成率作为业务成功率。

## 5. 四关如何定位问题

| 关口 | 本轮可关闭的诊断 | 不能由此推出的主张 |
| --- | --- | --- |
| 观测→偏好／信念→候选价值→动作 | 原 supplied 网格的 24 个严格反转、实际缓存 witness；本轮全图逐候选与原生调用绑定。数值接线和选中动作消费可核验。 | 自然动态偏好收益。本轮自然全图该效应仍为零。 |
| 真实反馈与动作耦合 | 实际动作改变缓存、资源与后续可行空间；只使用当前观测及预测分布；全图评价为离线审计输入，不送给在线决策。 | 未知需求核学习、未知信号漂移、真实硬期限下的长期收益。 |
| 公平普通控制器 | 三个固定候选的 ex-ante 最优、贪心、普通 MPC、同目标控制器、固定偏好 NDU、动态 NDU和 oracle 完整比较；纯信念 2×2。 | NDU 独占优势。普通 MPC 在本轮全状态／全策略上已经复现结果。 |
| 模型、求解与成本 | 有限已知模型上的原生候选值和解与 exact 一致；错误 forecast 的完整策略损失可分离；计时与退出成本有记录。 | 学习模型误差率、参数梯度正确性、通用 FBSDE 解法或生产净收益。 |

`U` 和 `Z` 仍没有被当作参数梯度。本轮没有参数训练循环，因此没有用有限 Bellman 一致性为一个未实施的求导或梯度估计器背书。现有结果也没有理由把零额外收益直接归咎于梯度、模型可辨识性或近似求解偏差。

## 6. 成本与停止计算：保留原始负结果

本次完整图审计的动态 NDU 规划墙时（含原生进程／日志／关闭）为 20.480627400 秒，同目标普通控制器为 5.451501308 秒，ordinary-MPC 为 5.415711735 秒。它们没有得到不同的外部策略价值。这些开销含实现与仪器成本，且不是随机化物理速度试验；它们不能用来声称通用速度差异，但也不能从成本账中删除。

旧 compute-price 正式队列保留以下实测总量，均为每 arm 24 episodes：

| arm／成本 | 总墙时 |
| --- | ---: |
| always-native dynamic NDU | 1,787.790080 ms |
| priced dynamic NDU | 244.518089 ms |
| state-greedy | 241.400921 ms |
| 共享训练 | 885.064963 ms |

priced dynamic 在 72/72 次决策上跳过 native，真实 NDU 价值调用为零，动作与 greedy 全同。相对 always-native，它节省 1,543.271991 ms；相对 greedy，它多花 3.117168 ms。即便把全部共享训练计入 priced，仍比 always-native 少 658.207028 ms，但比 greedy 多 888.182131 ms。这个队列说明停止额外计算有价值，不证明 NDU 独占收益，也不提供“priced 比 greedy 更快”的证据。

旧构建历史的总尝试成本为 52,448.706284 ms，其中失败尝试 15,523.963966 ms，保留在旧证据中。本轮复用原已准入二进制，未把这段历史清零。工程人力、能源和金钱等未观测全生命周期成本仍未知。

现有 compute-price bound 在效用里扣除预测计算费，但其未来 budget/deadline 状态没有同步扣除未来计算耗时，因此它是预测准入模型，**不构成硬实时可行性证明**。部署准入不能越过这个边界。

## 7. 自动化、测试与证据保护

新增独立回归包含：13 项 graph／完整策略算式检查、12 项 campaign／注册／中断检查、1 项 CI 路径覆盖检查。固定策略的“按 root 换策略”错误、零 native 调用冒充 native、注册清单和分母被篡改、native 失败和进程关闭、预算耗尽、KeyboardInterrupt、postflight 源码变化均有拒绝或保留证据的回归。注入替身明确标为 scalar test control，不用于正式 native 资格。

参考套件为 175/175，原生套件为 16/16，重复 7 项，所以是 **184 个唯一测试**，失败、错误、跳过均为零。远端 [CI run 42205882393 / job 127852267161](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42205882393/job/127852267161) 在新源码上通过：独立取得原始 upstream、构建两个 adapter、执行 wrong-head 和 synthetic-merge 拒绝检查、原生反转与退化、实际 workload，以及执行后源码不变检查。

远端 CI 的原始 ZIP digest 与服务端一致；37 个成员、36 项输出哈希校验通过。source-before 与 source-after 一致，9,105 个源文件逐一对照固定 Git commit 字节一致；CI 的 430 次 native value exchange 与 5 次 workload exchange 均保留，实际 workload 2/2 请求完成。CI 冒烟调用与正式图审计的 84,960 次调用是两个独立分母，不重复合并宣传。

原 PR 的 macOS host/C++ host 作业曾在 runner 尚未分配、无执行步骤时取消；已各发起一次重试。尚未取得成功执行证据的跨主机作业保持未通过状态。新 PR 的 NDU 专项 CI 成功不代表整个仓库 Actions 全绿；最新状态和原始服务响应另附于证据中。

独立数学审计不导入生产 planner、model、graph 或 evaluator，重新编码 Fraction 概率、Bayes 更新、各控制器规划及完整策略递归。最终 1,129,252 项审计断言通过，覆盖全部图、决策、attempt journal 和 native Bellman 请求。这是审计断言数，不是额外的百万个单元测试或独立样本。首轮审计器将 9,105 文件的外层 snapshot 与 230 文件的内层 source identity 当成相同 schema，产生两条审核器假阴性；原脚本、原报告和日志全部保留，修订版按 HEAD、clean、子集哈希和前后全量一致性比较后通过。首轮、修正预终轮、加入独立摘要审计绑定并使用新输出路径的最终轮，共三次审核尝试均有脚本／报告／日志哈希清单。正式 campaign 本身只运行一次，源码、注册和结果均未为此更改。

另一个独立审计从原始 Rust 摘要规范重新实现整数／字节序列化，逐一验证 84,960 个 evaluation digest、339,840 个 recursive evidence digest、170,028 个原始帧及 20,448 个 native 状态决策的调用范围和最终消费。此项验证本地原始记录的完整性，不声称硬件远程认证或新增物理收益。

## 8. Blocker 处置原则

接线、全合法状态覆盖、完整策略评价、信念／偏好混合归因、最强固定策略公平性、原生身份、失败分母、源码绑定和 CI 触发路径均已得到具体实现和验证。

自然动态偏好与 NDU 独占优势，在这套预登记有限模型内按负结果结案；没有为获得正结果改写模型或删除原队列。新的机制假设若要再检验，应建立新的冻结实验，不能改变本轮结论。

生产净收益、计算耗时进入真实资源／期限转移、未知模型学习与参数求导不在本轮已验证范围；没有将其标成 PASS。外部 runner 尚未执行的 CI 也不能标成 PASS。当前候选继续保持 Draft、禁止生产激活，完整处置机读表见 `blocker-disposition.json`。
