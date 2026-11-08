# HIA NDU：独立源码审查与历史证据重分析

日期：2026-11-08  
研究性质：历史不可变数据的独立重分析，加上固定源码的选择器审查。  
被审查 HIA 源：eb3f25f57dc5f7b49d1ca56b1570e232f5a932dc。  
原始公开证据版本：3ead0f535c271b07766c5d7c5d15ca69f0f3e8df。  
固定 native NDU 上游：d3c2d760eca5065fc966820379c35c6e8d56e855。

## 1. 可公开的研究结论

**P2 尚未达到“相同任务与预算下，相比强对照取得稳定、可计价的实际总收益”。这不是只有样本不足：当前配置的单目标选择器没有增加决策信息；在两个较便宜的非 incumbent 候选并列时，它的 Python 包装层还会退回较贵的 incumbent。**

在共同的、已通过质量和资源门槛的有限候选池内，strong ordinary 枚举并最小化与 native NDU 完全相同的保守预测成本。固定的 Rust evaluator 使用单一 Minimize 维度、零 Pareto 容差、无 scalarization。唯一最小值时，两者选同一个候选；incumbent 本身是并列最小值时，两者保留 incumbent；两个更便宜的非 incumbent 候选并列时，Rust 返回未给出推荐，Python 把它解释为保留 incumbent。因此不能声称两者在所有输入上完全相同。准确的结论是：**在该受限配置与相同可行池上，ordinary 的供给预测目标值不劣于该 native 包装层，且存在严格更优的选择。** [S1–S6]

这是一条源码和整数目标上的结论。它不证明 Python 的执行耗时一定更低，也不证明某个未来真实任务的总收益，不否定其他 NDU 多目标、递归或学习配置。所有时间预算、native 成功返回、数值域和候选资格都必须按下面的范围限定。没有新运行 native NDU，没有新 provider 调用，没有重新执行旧 campaign，也没有为取得正收益启动新合成 campaign。

现有历史数据独立重算后仍然是：32 个注册 task-arm，22 个正确完成，420 个计费事件，42 个失败或拒绝事件，4 个 arm 均未完整交付；complete_controls 为空，qualified NDU saving 为 null。原始两轮 native 对照的收益符号翻转，合计 −19,947,098 ns；没有稳定增益证据。金额、费率、账单及完整的人力/服务成本缺失，经济收益不能补为 0 或套用今天的费率。 [E1–E7]

## 2. 同一供给成本下，选择器到底做什么

### 2.1 当前实际配置

宏状态控制器 ordinary_plan_selection 对完整、已知的原始账本计算剩余 wall/token 预算，并枚举全部显式计划。计划的保守成本为：

    R(i) = remaining_cost_ns(i) + uncertainty_ns(i)

它按 (R(i), 是否非 incumbent, 稳定 ID) 选最小值，incumbent 在同成本时优先。未知原始成本会阻断决策。advise_macro 把同一个 R(i) 转成 Q32 送入 native；uncertainty 字段没有在 native Pareto dominance 中再次变成一个独立惩罚。控制器自身耗时和失败尝试仍计入账本，native 前后还可能发生预算门槛变化。本文的相同选择关系限定在相同已判定可行池、相同冻结剩余预算和成功返回的 evaluator 上；不把这些运行时路径抹去。 [S1, S3, S6]

较新的 checked_pool_selection 最多接受三个候选，先要求 quality_complete 且 R(i) 不超过剩余 wall。第一个真实质量合格 proposal 是 incumbent，native 接口将它命名为 abstain。原始未改善的 task baseline 不属于这个可交付候选池。ordinary 和 native 接收相同的成本行。后者的 uncertainty_q32 为 0，因为不确定性已经计入 R(i)。 [S2]

实际桥接配置为一个 owner、一个 total-ms/Minimize utility 维度、一个 search-ms 资源上限、无 risk 维度、零绝对 Pareto 容差，并向 evaluator 传入 scalarization=None。RequireEqual 聚合在这里不提供新的候选质量或未来成本信息。源码没有在这一路径执行递归效用或学到的宏观动态。 [S1, S3]

Q32 转换使用 round-to-nearest-ties-even(n × 2^32 / 1,000,000)。在非负、可表示的整数纳秒域内，增加 1 ns 会增加约 4294.967296 个 raw 单位，转换严格保序；下述并列不是浮点舍入制造的。溢出或越过输入域的情况由输入检查处理，不属于本结论。 [S6]

### 2.2 Rust 分支与 Python fallback

单目标、零容差下，Rust dominance 的严格改善条件就是成本严格更小。Pareto frontier 因而正好包含所有最小成本候选。evaluator 的实际分支是：

1. 唯一可行项只有 abstain：显式保留 abstain。
2. frontier 长度为 1：推荐该唯一最小候选。
3. frontier 长度大于 1 且没有 scalarization：ParetoSetRequiresSlowPath，advisory_recommendation=None。

Python checked_pool_selection 将 None 或 abstain 映射回 incumbent。宏控制器 advise_macro 也将缺失推荐映射为 abstain。这使“没有唯一推荐”可能退回一个已经被其他候选严格支配的 incumbent。 [S1–S5]

### 2.3 三组可复核数值

三组均有质量合格的 a、b、c，incumbent 为 a，不确定性为 0，剩余 wall 为 1,000 ms。表中数字是调用者供给的预测目标；不是真实任务耗时，也不是新 native 测量。

| 情况 | a / b / c 的供给成本（ms） | 实际 Python ordinary 输出 | 从固定 Rust 分支推出的 frontier / 推荐 | Python native 包装层推导选择 | ordinary / native 的供给目标（ms） |
| --- | --- | --- | --- | --- | --- |
| 唯一最小值 | 100 / 50 / 60 | b | {b} / b | b | 50 / 50 |
| incumbent 参与并列最小 | 50 / 50 / 60 | a | {a,b} / None | a | 50 / 50 |
| 两个更便宜非 incumbent 并列 | 100 / 50 / 50 | b | {b,c} / None | a | 50 / 100 |

第三组给出严格反例：native 包装层选择的供给目标比 ordinary 多 50 ms，是该目标值的两倍。这不能写成“实际收益下降 50 ms”，因为没有测量 native 调用和后续真实任务。

本次实际执行的是从固定生产源 AST 提取的 checked_pool_selection 的 ordinary 分支及其真实 Q32 转换函数；没有重新实现 ordinary 来获得表中结果。输入为隔离的算术例子，artifact/support 摘要仅为必需字段的合成标识，不代表已生产真实任务产物。_native_rank 替身只会抛出禁止调用的异常，从未调用。Rust 结果是源码推导，未执行。三次 ordinary 调用 wall 为 74,372 / 31,918 / 24,417 ns，CPU 为 72,777 / 31,927 / 24,467 ns；单次微测量仅记录这次分析发生了什么，不能当作性能基准。完整输入输出和函数源码摘要在 findings.json。 [A1]

## 3. 旧单候选 fixture 为何必然 abstain

当前源码保留的旧 campaign 构造为：

    stop_remaining_ns = baseline_ns
    candidate_remaining_ns = search_forecast + baseline_ns + 2,000,000
    candidate_uncertainty_ns = 10,000,000

其中 search_forecast 是已观测的基线导入、验证和 emission 耗时之和，非负。因此：

    candidate_robust_cost - incumbent_cost
      = search_forecast + 12,000,000 > 0

在完整、预算可用的状态里，strong ordinary 必然保留 incumbent；native 单目标最小化也没有选择该更贵候选的理由。若预算已经不足，则候选还会被排除。这个结论由 fixture 构造决定，不能作为 NDU 发现了普通方法不知道的更好策略的证据。 [S7]

保留的两轮 native 历史 excerpt 共列出 16 次决策，全部只有一个显式候选、全部原始 NDU=abstain，历史 ordinary replay 也全部=abstain。此次分析核对 excerpt 的状态/结果摘要、计数及费用算术，没有取得这些原始完整状态并再次做 16 次独立状态 replay。因此“16/16 对齐”是对保留旧重放结果的准确引用，不是此次新生成的 native 或状态重放证据。 [E6]

另一个必须区分的事实是：旧 provider-enabled campaign 的 ordinary arm 使用同一模型返回的 ordinary_choice，而不是此次被审查的全枚举 ordinary_plan_selection；每个 arm 分别调用 provider 并取得自己的 proposal。相同任务、模型标识和预算不等于相同的实际候选池。因此旧 provider arm 间的耗时差不能直接归因于两个当前数学选择器的差别。 [S7]

## 4. 原始 provider campaign 的独立重算

原始 comparison 注册 8 个 source-authored synthetic wrapping-u8 任务 × 4 arms。每个 task-arm 的 wall allowance 为 180,000,000,000 ns，token allowance 为 32,768。注册、任务 ID、输入和资格摘要、agent、预算、phase 声明、event/receipt 唯一性均经独立脚本核对；保留全部 task-arm，没有删除失败来制造完成子集。任务库存中的真实用户任务数量为 0。 [E1, A1]

| arm | provider 完成 | 正确 native task-arm | 原始计费 wall（ns） | 原始预算 token 计费 | 事件数 | 失败/拒绝事件 wall（ns） |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| fixed | 7/8 | 2/8 | 130,466,301,676 | 80,941 | 116 | 18,663,966,714 |
| greedy | 7/8 | 7/8 | 134,985,846,220 | 81,530 | 102 | 12,733,351,477 |
| ordinary | 6/8 | 6/8 | 151,383,646,332 | 83,543 | 100 | 44,387,390,176 |
| ndu | 7/8 | 7/8 | 113,450,243,024 | 81,292 | 102 | 12,962,540,189 |

总计 420 个账本事件、42 个 failed/rejected。32 个是各 cell 保留的负例搜索拒绝，10 个是任务失败；保留事实文件将这 10 个分成 5 个 model-final JSON 语法失败和 5 个 candidate Core admission 失败。失败耗时已经包含在各 arm wall 内，不能再次加总。事件中的 wall/token 字段没有未知值，不表示账单、能力隔离或经济成本已知。 [E1–E3, A1]

32 个 provider 进程有 terminal 五项 token counters 和 cleanup 的说法来自原始 retained facts；原始 verifier 报告核验 1,441 个对象。此次没有重新认证全部原始 provider/native 对象、完整进程流或服务方收据，所以这些事实保持其原本出处和保证级别。哈希一致性证明的是读取到的字节身份，不能升级为独立 provider provenance。原始 campaign supervisor 退出 2，原始 verify 退出 0，automatic retries 为 0；验证收据完整不等于收益验收通过。 [E3, E4]

独立计算的合格比较结果：

- fixed 缺 6 个任务，greedy 缺 1 个，ordinary 缺 2 个，ndu 缺 1 个。
- 失败任务也缺下游使用证据；NDU 失败任务没有 native value evaluation。
- complete_controls=[]，best_complete_control=null，qualified ndu_saving_ns=null。
- raw fixed−NDU 为 +17,016,058,652 ns，但 fixed 只交付 2/8，不能当作“完成相同工作节省”。
- raw ordinary−NDU 为 +37,933,403,308 ns，但完成数、实际候选和 provider 延迟不同，不能据此证明当前 NDU 优于强 ordinary。

这些结果由新脚本从原始 comparison 重新计算，再与旧 reassessment 交叉核对；没有调用项目原有 assessor，也没有改写旧 verdict。 [E1, E5, A1]

## 5. 成本边界：已知、嵌套和缺失

| 项目 | 原始已知数值或状态 | 使用方式 |
| --- | --- | --- |
| task ledger 总 wall | 530,286,037,252 ns | 四个 arm 相加，含失败 |
| 外层 campaign wall | 531,558,629,396 ns | 含外层流程，不与 ledger 再相加 |
| 独立原始 verify wall | 287,456,723 ns | campaign 后的单独校验 |
| model phase wall | 493,868,197,094 ns | 嵌套在 task/campaign 内 |
| provider subprocess wall | 493,583,641,701 ns | 嵌套，不重复计费 |
| 先前 READY 诊断 | 外层 9,656,068,540 ns；进程 9,201,968,397 ns；input 7,523、output 5 tokens | 独立历史边界，未隐去 |
| 先前 native NDU build | 19,799,468,424 ns；其中 cargo 19,696,509,844 ns | 历史取得成本，本 campaign 未重建 |
| 五项原始 token counters | input 306,442；output 16,149；cached input 112,896；cache write 0；reasoning 4,715 | 原计数全保留 |
| 原始预算 token 计费 | input+output+reasoning = 327,306 | 保守预算记账，不等同账单口径 |
| input+output | 322,591 | 与上项区分，不把 cached input 再加一次 |
| money / tariff / invoice | null / null / null | 保持缺失，不推定金额或正收益 |
| 完整人力、服务取得和端到端经济成本 | 未取得 | 不能声称 total economic benefit |

历史 build 的 target cache 初态为 absent，但依赖 cache/取得成本并未独立测量；原收据也不宣称整机 cold start。reasoning tokens 与 output 是否重叠没有独立计费说明。本次没有用当前价格修补旧账。完整原始成本对象及父/子进程 CPU 字段保留在 findings.json。 [E2, E4]

本次新增的是纯 Python 分析：内部 wall 51,600,406 ns，CPU 49,183,029 ns；范围从 run() 入口到输入二次校验完成，排除 Python 启动/import、源码拉取、报告落盘和审阅。该数值不加回旧 campaign。分析脚本 provider 调用为 0、native 执行为 0；本轮 ChatGPT/连接器和人工审阅总费用没有单独账单，因此也不能把这次整个研究的经济成本写为 0。 [A1]

## 6. 波动、较新验证与预注册的边界

历史 native-only 两轮均有 32 个正确 task-arm，各 8 次 NDU evaluation；以下为保留报告的原始 wall 算术： [E6]

| 轮次 | 最低控制 arm wall（ns） | NDU wall（ns） | control−NDU（ns） |
| --- | ---: | ---: | ---: |
| r1 | 6,965,414,782 | 7,077,247,310 | −111,832,528 |
| r2 | 7,065,319,196 | 6,973,433,766 | +91,885,430 |

两轮合计 −19,947,098 ns，均值 −9,973,549 ns。符号翻转，两个运行不足以估计可靠总体分布或稳定性；不能挑正的一轮报告收益。两轮 manifest SHA 分别为 6f0cd9daa050eb70d1784341d40afb6af510953ce06058ca4a907631834716e1 和 9535357d9a49adba89fc0da8f10b8c40e36cb0a4f574201988bffb33b8ed86ac。

较新的 local campaign 第一次因为缺 jsonschema 导致全部 32 次 discovery 失败；保留 96 个事件、718 个对象。修正环境后第二次 32 个 native task-arm 正确，保留 440 个事件、1,457 个对象，并验证 8 条 ordinary advice。但两轮均没有 provider 调用、没有 native NDU evaluation，因此这组成功只能支持机制和 ordinary receipt 验证，不能支持 NDU 性能收益。首次失败仍保留在原 archive，未当作不存在。 [E7]

当前 multistep protocol 注册 2 个 calibration 任务、4 个 heldout 任务、4 arms，共 24 cells，每 cell 最多三个 proposal；所有 arm 具有相同提案和反馈机会。质量门槛要求真实 selected artifact 通过全部 256 个 u8 结果且严格小于 baseline。协议状态仍为 implementation_and_preregistration_requires_source_freeze_before_provider_run，且 provenance 明确为 private synthetic maintenance。没有把这份协议当作已执行的新研究或真实用户仓库任务。每个 arm 看的是自己的错误与测量，“相同机会”也不等于每个 cell 已得到完全相同的候选池。 [S8]

## 7. 未通过验收的具体原因

1. **当前 selector 没有额外决策信息。** 它收到的候选质量、保守成本和预算与枚举对照一致。改正 tie fallback 可消除供给目标上的劣化，但只会使其接近相同 argmin，仍不能单独创造增量价值。
2. **旧单候选 fixture 不能识别决策优势。** 候选成本按构造总大于停止成本，16 次保留决策全是 abstain；新增同类重复不会证明更强决策能力。
3. **provider 历史比较没有一个完整交付控制。** 四个 arm 失败率不同，旧 ordinary 又是模型建议而非当前强枚举；原始差值不能作为合格收益。
4. **稳定性能未建立。** 两个 native-only 运行收益符号相反，且只是当前受限 fixture；新 multistep 研究尚未执行。
5. **真实任务与完整费用不足。** 此批证据没有真实用户任务 cohort，没有 provider 账单、计费重叠解释、完整取得和人力成本，无法建立“全部成本后”的经济收益。

因此当前可交付的是一个可复核的负面/有限结论，而不是性能达标声明：current_scalar_profile_additional_decision_information=false；universally_identical_choices=false；stable_measured_gain_established=false；qualified_provider_saving_ns=null；economic_benefit_established=false。 [A1]

## 8. 复核身份、文件与重现

独立分析脚本仅使用 Python 标准库，不导入/执行 provider 或 native。原始输入按 Git blob SHA1 和 SHA256 双重绑定，20 个代码/证据输入均与公开拉取的 blob 一致；其中七个 HIA selector/protocol/bridge 文件还逐个与最终 eb3f25f 源目录内容 SHA256 核对一致。输入在分析前后完全不变。

- findings.json：83,094 bytes，SHA256 5536dd29fe53dfbd9871c49d3e49e999c63a598113cc6236625e75c93b3b2ebf。
- reassess.py：19,196 bytes，SHA256 8a892aecc490233a9a919d70f05f93516f0b171121a6622305adc1a53c199a62。
- 原始 comparison：132,252 bytes，SHA256 76a6ac07a3e7c56969ce9ea1ac4abba5874592327e19e4c1b05e2449d686d468；Git blob 3d3e9515d2f27fa182b70fc977bb9e0be72f514f。
- 原始 registration SHA256：52e18af06354621bcb8d403338098524f53c30b75182e8f98c1d6ee66fe05a77。
- pinned evaluator.rs SHA256：910644ee9c4e90e6859dc746c8a441424909fff68e55a070b7827724a0c3df81。
- pinned scoring.rs SHA256：84b3d8c6ba7daefd67b6676ffebe5234a125c5bdbc38def9e38a7d175202d9a7。
- 执行 UTC：2026-11-08T10:14:08.038141+00:00。
- Python：3.12.14，Clang 22.1.3；Linux x86_64 glibc2.39；真实可执行文件 /opt/codex/runtimes/codex-primary-runtime/dependencies/python/bin/python3.12。

完整输入及 retrieval-manifest.json/current-source-identity.json 在 inputs/，所有 URL、文件字节数和摘要在 findings.json。为重现，应在这个只读输入集旁运行 python3 reassess.py --output 一个尚不存在的新文件名；脚本拒绝覆盖已有报告。时间字段会变化，其余语义和原输入身份可比较。这个过程只是新的只读重分析，不会重放旧任务。

### 固定一手来源

[S1] [HIA macro policy：ordinary_plan_selection 与 advise_macro](https://github.com/TrillionniumFoundation/Hepta/blob/eb3f25f57dc5f7b49d1ca56b1570e232f5a932dc/hepta/hia_agent_macro_policy.py#L200-L354)  
[S2] [checked_pool_selection：可行池、argmin 与 None fallback](https://github.com/TrillionniumFoundation/Hepta/blob/eb3f25f57dc5f7b49d1ca56b1570e232f5a932dc/tools/qualify_hia_macro_multistep.py#L125-L186)  
[S3] [实际 Rust bridge profile 与 scalarization=None](https://github.com/TrillionniumFoundation/Hepta/blob/eb3f25f57dc5f7b49d1ca56b1570e232f5a932dc/rust/hia-ndu-bridge/src/main.rs#L73-L136)  
[S4] [固定 upstream evaluator 的 recommendation 分支](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/d3c2d760eca5065fc966820379c35c6e8d56e855/codex-rs/hepta-ndu/src/evaluator.rs#L144-L169)  
[S5] [固定 upstream Pareto frontier/dominance 实现](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/d3c2d760eca5065fc966820379c35c6e8d56e855/codex-rs/hepta-ndu/src/scoring.rs#L16-L75)  
[S6] [实际 Q32 转换](https://github.com/TrillionniumFoundation/Hepta/blob/eb3f25f57dc5f7b49d1ca56b1570e232f5a932dc/hepta/hia_ndu_optimizer.py#L62-L73)  
[S7] [旧 campaign 的预测构造与 provider ordinary 分支](https://github.com/TrillionniumFoundation/Hepta/blob/eb3f25f57dc5f7b49d1ca56b1570e232f5a932dc/tools/qualify_hia_macro_campaign.py#L346-L399)  
[S8] [未执行 multistep 预注册协议](https://github.com/TrillionniumFoundation/Hepta/blob/eb3f25f57dc5f7b49d1ca56b1570e232f5a932dc/benchmarks/hia_macro_multistep/PROTOCOL.json)

[E1] [原始 comparison（完整 task/ledger）](https://github.com/TrillionniumFoundation/Hepta/blob/3ead0f535c271b07766c5d7c5d15ca69f0f3e8df/review-evidence/hia-ndu-completed-control-20261107/original-comparison.json)  
[E2] [原始费用与范围](https://github.com/TrillionniumFoundation/Hepta/blob/3ead0f535c271b07766c5d7c5d15ca69f0f3e8df/review-evidence/hia-ndu-completed-control-20261107/original-cost-and-scope.json)  
[E3] [保留 provider facts excerpt](https://github.com/TrillionniumFoundation/Hepta/blob/3ead0f535c271b07766c5d7c5d15ca69f0f3e8df/review-evidence/hia-ndu-completed-control-20261107/retained-provider-facts.json)  
[E4] [原始 supervisor campaign/verify 记录](https://github.com/TrillionniumFoundation/Hepta/blob/3ead0f535c271b07766c5d7c5d15ca69f0f3e8df/review-evidence/hia-ndu-completed-control-20261107/original-execution-result.json)  
[E5] [原始 qualified comparison 重分析](https://github.com/TrillionniumFoundation/Hepta/blob/3ead0f535c271b07766c5d7c5d15ca69f0f3e8df/review-evidence/hia-ndu-completed-control-20261107/retained-provider-reassessment.json)  
[E6] [两轮保留 native/ordinary replay excerpt](https://github.com/TrillionniumFoundation/Hepta/blob/3ead0f535c271b07766c5d7c5d15ca69f0f3e8df/review-evidence/hia-ndu-strong-control-20261107/retained-native-replay.json)  
[E7] [较新 local campaign 的失败与成功均保留](https://github.com/TrillionniumFoundation/Hepta/blob/3ead0f535c271b07766c5d7c5d15ca69f0f3e8df/review-evidence/hia-ndu-strong-control-20261107/local-campaign-summary.json)

[A1] 本次新独立分析：同目录 findings.json 与 reassess.py；身份和复核方式见本节。它们不替换或修改任何 [E1–E7] 原始证据。

