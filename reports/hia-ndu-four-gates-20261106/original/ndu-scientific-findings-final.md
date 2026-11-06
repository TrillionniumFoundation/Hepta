# NDU 正式有限状态覆盖：科学归因与实际动作核验

**结论：本轮已证明数值偏好通道能改变合法服务动作，且选中动作确实被真实缓存执行；在冻结有限模型的 5,736 个登记状态上，原始 native 动态 NDU 与同目标普通控制器、独立 exact oracle 完全一致。自然支持中的偏好动作收益和 NDU 独占净收益仍未得到证明。**

只读依据：[正式覆盖 RESULT](sandbox:/workspace/scratch/3f3fcd2808a5/state-coverage-final-v1/RESULT.json)；[物理执行 RESULT](sandbox:/workspace/scratch/3f3fcd2808a5/physical-witness-final-v1/RESULT.json)。source commit：`78c0b951adc08b02be60d64b386620c5ac9faf99`。完整来源 SHA256、逐候选整数值和六个物理 cell 的证据保存在 [配套 JSON](sandbox:/workspace/scratch/3f3fcd2808a5/ndu-scientific-findings-final.json)。未修改源代码、协议或正式结果，未追加实验。

## 1. supplied 24 与 natural 0 回答的是不同问题

| 证据范围 | 状态数 | 根偏好数值变化 | 递归候选值变化 | 偏好动作反转 / 外部条件收益 |
|---|---:|---:|---:|---:|
| natural-support 全集 | 2,716 | 1,608 | 1,818 | 0 |
| supplied-boundary 全网格 | 1,950 | 1,170 | 1,170 | 24 |

24 个严格反转全部来自 supplied-boundary：adaptive 12、misleading 12、fixed 0。每个反转都满足动态／固定偏好动作不同、候选可行性相同、两者均交付当前请求，而且固定偏好所选动作在统一动态外部目标下具有严格正 regret。该完整网格独立组合后验与预算，跨过保留旧缓存／切换新缓存的价值边界。它证明偏好参数被数值计算和选择真正消费；不是仅更改 preference digest。

自然覆盖从原始 prior 和完整公开 request/signal 历史推出后验，按登记参考 owner 的缓存转移产生剩余资源。它覆盖 54 个初始 profile × 每个 64 条观察 tape，不是任意策略的全部可达状态。这个轨迹约束下，偏好和递归值经常变化，却没有跨过动作边界。故不能把 natural 0 归因为数值通道未接入，也不能把 supplied 24 宣称为自然分布上的收益。两例 supplied 见证仅属于 supplied-boundary，未获得自然可达性资格。

## 2. 自然状态显示了信息、预测与规划价值，但不是 NDU 独占收益

| natural-support 指标 | adaptive | fixed | misleading | 合计 |
|---|---:|---:|---:|---:|
| 登记自然状态 | 1,144 | 428 | 1,144 | 2,716 |
| wrong-forecast 的正条件 regret | 82 | 0 | 82 | 164 |
| 相对 state-greedy 的正条件 regret | 46 | 46 | 46 | 138 |
| no-adaptation 的正条件 regret | 42 | 0 | 42 | 84 |
| 完整 fixed policy 与 oracle 等值 | 739 | 282 | 739 | 1,760 |

这里的条件 regret 为 `V*(s) − Q*(s, comparator_action)`：比较当前选择，此后接 oracle continuation。164/138/84 不是整段比较策略的 episode 收益，不是实测延迟改进，也不是独立样本；同一状态可同时满足多个条件，三列不能相加当独立成功数。

wrong-forecast 是人为反转当前 posterior 的明确模型错误干预；misleading 环境的 0.2 信号可靠性对正确控制器已知，可以反向利用。结果表明错误信念会损害动作选择，不给出真实训练预测器的误差率。no-adaptation 同时重置 prior 和固定偏好，因此 84 应标为联合消融损失。由于自然状态中的 same-belief fixed-preference 动作全部与 dynamic 相同，这组额外控制支持“固定偏好条件下，保留 posterior 比重置 prior 更有价值”；它不证明动态偏好本身获益。

fixed sufficient 的 1,760 不是“当前碰巧选择同一个动作”，而是登记 fixed-action-zero 策略（含既定可行性 fallback）在整个剩余 horizon 上的递归价值等于 oracle。它支持这些状态无需额外适应；不能宣称 fixed 环境所有状态都如此（该环境实际为 282/428），也不能由此证明实现已经停止计算或计算成本为零。

## 3. 两组实际执行的 numeric-preference triples

两组均为 horizon 2、当前 request 1、旧 resident 0、deadline 24、load 4／hot 1／direct 6／retire 0；初始资源 profile 为 24/24。预算为声明模型单位，不能当纳秒。每组实际重建相同 resident，分别重新决策并运行 dynamic NDU、fixed-preference NDU 和 same-objective。

| 环境与 cell | supplied posterior / 剩余预算 | dynamic 与 same-objective | fixed-preference | 固定偏好动作的统一外部 regret |
|---|---|---|---|---:|
| adaptive 040/041/042 | 43/64；11 | cache-1；外部值 `127863339966` | cache-0；外部值 `125827468494` | `2035871472` Q32 = 0.474013265 单位 |
| misleading 030/031/032 | 33/64；9 | cache-1；外部值 `18489671680` | cache-0；外部值 `17728372736` | `761298944` Q32 = 0.177253723 单位 |

表中值是 raw Q32，除以 `2^32` 才得到模型效用单位。固定偏好自己的内部值不能直接与动态偏好的内部值相减：它使用不同数值偏好。统一 regret 使用同一 exact 动态外部价值表。

- **adaptive**：state `2079233e402a17af4065dca07226a1982cec5530220360e64c98284677400b07`；动态 price/risk 为 `4652881237` / `1163220309`，固定偏好为 `4294967296` / `1073741824`；discount 均为 `4026531840`。固定偏好自己的 cache-0 / cache-1 值为 `129864669593` / `129730451866`，因此它确实选择 cache-0。证据：[cell 040 dynamic-ndu](sandbox:/workspace/scratch/3f3fcd2808a5/physical-witness-final-v1/cells/040/RESULT.json), [cell 041 fixed-preference-ndu](sandbox:/workspace/scratch/3f3fcd2808a5/physical-witness-final-v1/cells/041/RESULT.json), [cell 042 same-objective](sandbox:/workspace/scratch/3f3fcd2808a5/physical-witness-final-v1/cells/042/RESULT.json)。
- **misleading**：state `028951dd71bb6f76e703c08875a50cf3fb53e35e1e26c43b0ffbd79464c8dff9`；动态 price/risk 为 `5368709120` / `1342177280`，固定偏好为 `4294967296` / `1073741824`；discount 均为 `4026531840`。固定偏好自己的 cache-0 / cache-1 值为 `28126321050` / `27488786842`，因此它确实选择 cache-0。证据：[cell 030 dynamic-ndu](sandbox:/workspace/scratch/3f3fcd2808a5/physical-witness-final-v1/cells/030/RESULT.json), [cell 031 fixed-preference-ndu](sandbox:/workspace/scratch/3f3fcd2808a5/physical-witness-final-v1/cells/031/RESULT.json), [cell 032 same-objective](sandbox:/workspace/scratch/3f3fcd2808a5/physical-witness-final-v1/cells/032/RESULT.json)。

两组动态 NDU／同目标控制器均真实执行 `retire(0) → prepare(1) → run(id=1, packed)`，缓存由 `[0]` 变为 `[1]`；固定偏好均真实执行 `run(id=1, direct)`，保留 `[0]`。六次运行均检查全部 128 个输出、checksum 同为 `10608614108073300261`，无错误且 close returncode 0。它们是“动作已被消费”的正证据，而不是只有建议或离线评分。整个物理 witness 队列为 43/43 执行通过，0 abstention。

## 4. 已闭合与仍未成立的主张

已闭合的范围是：登记有限模型里的数值接线、候选选择、实际派发，以及动态 native 求解与独立 exact oracle 的局部一致性。5,736/5,736 状态通过，167,976 次原始 native 调用保留，0 failed、0 not-run。同目标普通控制器得到完全相同的候选值和动作，这是正确性对照成功，也表明这些收益可以由普通有限控制复现。

仍未成立的是：自然分布下动态偏好带来的动作／任务收益、NDU 超过同目标控制器的独占优势、物理端到端净收益、生产外推，以及任何参数梯度或 FBSDE 层面的理论结论。物理 witnesses 只验证当前动作消费；它们没有把抽象 24 单位预算伪装为真实纳秒，也没有证明其 supplied 历史在真实环境中自然到达。

边界网格的设计是在已披露的 reference-only 开发探索之后登记；全部网格结果保留，物理样本按 lexicographic 规则在测时前选出。这是透明的机制资格，不应包装为未看过效应的盲测收益估计。原 v1 的 216 个偏好反事实数值／动作全零、36 个 wrong/reset episode 全等结果应原样保留，不能被后续 supplied witnesses 回填或重标为成功。

更精确的结案表述是：**接线和有限模型求解的诊断阻塞已关闭；自然偏好收益与独占净收益属于当前结果未支持的科学主张，不能用工程通过状态替代。**
