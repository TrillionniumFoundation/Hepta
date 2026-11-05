# P2 轮 3：离散再生与有效性通道的完整负结果

日期：2026-11-05。

**四个固定配置的正式评价已补完，但全部质量面板失败。P2 仍 OPEN，没有 HCSN 优势或生产准入结论。** 原 180 秒试验确实预算失败；追加补完使用另行公开登记的协议，原失败记录和部分权重未被覆盖。

四个模型在正式九个面板上的全部 **39,552 次模型查询均回答 UNKNOWN**。其中 **23,404 次要求已知值的查询全部被拒答**。每模型 9,888 次查询、5,851 个已知答案、4,037 个 UNKNOWN；每模型 864 个序列没有任何一个全对。四个模型均为 **0/9 面板通过**，合计 **0/36 模型／面板通过**。

## 1. 做了什么，为什么做

上一轮关联记忆在三个学会主要任务的 fit 上出现多次 RESET 后 UNKNOWN 被答成旧已知值；另一个 HCSN seed 整体训练失败。这一轮只选择一个共享结构候选，测试能否严格擦掉失效状态并继续保存所需信息：

- 原始 token 与 elapsed time 仍是唯一观测输入；没有真 reset 标签、真 write mask、键值表或真实隐藏状态。
- 普通门控和 HCSN 共用同一模型、初始化、数据、更新数和全部验收门槛。模型 forward 不按语义 token ID 分支。
- write/reset 都改为神经控制器产生的硬事件，阈值 0.5，反向使用 sigmoid 的直通替代梯度。
- 增加 16 维 validity 记忆，用同一 learned address 和 write event 更新；读出将四个已知值概率与 UNKNOWN 概率分解。
- reset 在计算旧状态内积前先清除 matrix、validity 和旧上下文，并取消同一步的写入。后续当前 token 作为新的 previous 保留。

新模型有 **2,276 个可训练参数和 176 个持久浮点状态**；上一轮模型为 2,301 参数、160 状态。新候选同时涉及离散事件、有效性通道、分解读出、初始 write bias 和预先登记的课程；不能把跨轮变化单独归因于自由边界。HCSN 在这里仍只是简化停止 Call/Put 通道，不是完整 HX 或已求解最优 QVI。

## 2. 注册、数值修复和执行谱系

| 阶段 | 记录 | 实际状态 |
|---|---|---|
| 未执行初稿 | 原协议 SHA `2ee6b6ef862aba719cbaf2d4283c6cbf48d29647d587d13db6ce45d7fc5380d0` | 独立数值审阅失败，0 fit、0 heldout；源码和协议快照保留 |
| 数值修正版原试验 | Git `b9571fb1de3c420ceaea27152f59898e36795dfe`；协议 SHA `a02bc9f2601af393eb83adaf5b7845768778b25b0c35e7d4f40f40ff179d846c` | 注册后训练；180 秒软上限触发，exit 2 |
| 固定配置追加补完 | Git `fa8eb7413d72762f51e61144c36912047dfce240`；协议 SHA `a41c7aa2763a494fc11abbc52a47355c81fc4cba8322109a56326e4ccbf26d1f` | 原证据和 3 个最终权重锁定；只重放 HCSN719；随后正式评分，exit 0 |

两个执行器均先用 `git show` 核对公开注册的协议字节，再核源码 SHA。原始证据、原模型和两个冻结执行器在运行中均未改变。

初稿的数值反例不是训练失败：有限 FP32 大状态可以先溢出，再出现 `0*Inf`；FP16 的 `1e-8` 归一化常数会下溢。修正版把清除移到内积之前，明确只接受 FP32/FP64，对非有限事件、输出或状态 fail closed；13 项模型行为测试通过。修复改变了 STE 的具体替代梯度，该顺序在任何 fit 前重新冻结，未伪称与初稿梯度相同。

另保留了浮点硬阈值的 Put＋线性反例。对逐点特意选取的 bias，4,097 个构造点中 1,095 个事件不同；这是构造性数值边界，**不是训练模型错误率**。本次两个最终 HCSN checkpoint 的 18 个实际映射面板事件恰好完全一致，最大 log-probability 差为 0，也不能推广为全 FP32 输入的事件等价。

## 3. 原预算失败与透明补完

原试验依次完成 Ordinary613、HCSN613、Ordinary719 的各 300 步；HCSN719 在第 173 步达到训练软上限。完整损失、梯度范数和四份权重均保留。原执行器没有保存 optimizer 状态，所以不能假装从旧权重直接续接 Adam。

追加协议只允许一个固定 fit：HCSN719 从同一 seed、同一初始化、同一 optimizer、完全相同的数据序列重新执行 300 步。**前 173 个 loss 和 173 个 preclip gradient norm 逐值相同；第 173 步所有模型 tensor 的 dtype、shape 和 C-order bytes 完全相同；训练 stream SHA 和 13,700 个查询标签计数一致。** signed zero 差异也会被检查拒绝。任何前缀不一致都会终止补完并跳过 heldout。

另外三份 300 步权重按 SHA 原样复用。新增 fit 保存最终 optimizer 状态。补完后四个配置每个都到 300 步，但实际发生了 **5 次训练尝试、1,373 次 optimizer 更新**；多出来的 173 步重放全部计入成本。

| 执行 | 真实训练尝试 | optimizer 更新 | 训练查询标签计数 | 训练 CPU 秒 | 主 campaign CPU 秒 |
|---|---:|---:|---:|---:|---:|
| 原 180 秒协议 | 4 | 1,073 | 92,900 | 180.109696 | 181.443368 |
| 追加固定配置补完 | 1 | 300 | 26,400 | 48.845148 | 58.745328 |
| 合计 | 5 | 1,373 | 119,300 | 228.954844 | 240.188696 |

这里的 CPU 数字是两个主 campaign 记录的进程 CPU；独立审阅、测试、纯数组汇总的成本不混入这些训练计数。180 秒和追加 80 秒都是训练软停，不是包含所有初始化、保存和评价的总 CPU 硬限。原 180 秒预算仍为 **FAIL**；不能用补完后的完整四配置把它改写成通过。

completion 协议继承的 `development.fit_count_before_registration=0` 指原 `b957...` 注册前；completion 注册前已经执行过 4 次真实尝试。顶层元数据明确记录原 4 次、追加 1 次、总 5 次。

正式九个 heldout 在原预算分支中完全未构造。它们只在补完四配置且 173 步复核通过后才构造和评分，没有换 seed、换面板、调参数、选最佳 checkpoint 或降低门槛。

## 4. 固定四配置的正式结果

门槛始终为每个面板、每个 seed、每个模式 **query accuracy ≥95% 且 sequence exact ≥90%**。以下表格是每个模型的结果；四模型的这些整数计数相同，为便于阅读只显示一次。

| 面板 | 每模型查询 | 正确查询 | 查询准确率 | 全对序列 / 96 | 质量通过 |
|---|---:|---:|---:|---:|---|
| MQAR 常规 | 384 | 0 | 0.0000% | 0/96 | 否 |
| MQAR 长干扰 | 384 | 0 | 0.0000% | 0/96 | 否 |
| 覆盖写入 | 384 | 0 | 0.0000% | 0/96 | 否 |
| 状态跟踪 | 1,152 | 0 | 0.0000% | 0/96 | 否 |
| IGNORE 假写入 | 384 | 0 | 0.0000% | 0/96 | 否 |
| 四轮可见 RESET | 2,304 | 775 | 33.6372% | 0/96 | 否 |
| RESET 后不重绑定 | 3,456 | 3,072 | 88.8889% | 0/96 | 否 |
| 不规则时间 | 720 | 94 | 13.0556% | 0/96 | 否 |
| 短时间间隔 | 720 | 96 | 13.3333% | 0/96 | 否 |

所有正确查询都来自真实标签为 UNKNOWN 的位置。每个模型的 5,851 个已知值查询全部拒答；每个模型 864 个序列全部失败。四模型共享同一套 heldout 流，不能把跨模型重复查询或同序列内的多个查询当成独立样本，未据此计算虚假的置信区间或显著性。

零 UNKNOWN 误接受和 reset 窗口全覆盖在本轮都成立，却不足以说明有效记忆。固定质量门槛正确阻止了“所有输入一律拒答”的假阳性。

## 5. 从实际轨迹确定失败机制

从保存的原始 query positions、events 和 binding logits 重新计数，四模型各自均为：

| 原始轨迹指标 | 每个模型 |
|---|---:|
| 查询位置发生 hard reset | 9,888 / 9,888 |
| reset 优先规则之后的实际 query write | 0 |
| query binding logit 最小值／最大值 | −6 / −6 |
| 已知目标拒答 | 5,851 / 5,851 |
| UNKNOWN 误接受 | 0 / 4,037 |

因此这里可以把全拒答直接联系到实现的擦除公式：每次读取前触发 reset，使 memory 和 validity 为零；binding logit 固定为 −6，因而

\[
P(\mathrm{UNKNOWN})=\sigma(6)\approx0.9975273768.
\]

这不是仅凭低准确率猜测原因。每个正式查询的事件和有效性读数都保存在原始数组，并由独立回放核对。

四个开发集 counterfactual erasure witness 也通过：保持当前 token 上下文一致，扰动旧 memory/validity，触发模型自己的 reset 后状态差和输出差均为 0。它验证了“检测到事件就能擦除”的条件性质；无法单独验证“该不该擦除”。当前控制器把所有查询都当作清除时点，丢掉了需要回答的已知信息。

## 6. 为什么当前替代梯度会形成即时纠错死区

独立数学审阅针对冻结模型完成 36 个确定性微型 autograd 例子，0 fit、0 optimizer 更新、无 checkpoint、无 dataset 或 heldout 访问。记硬 reset 为 \(r\)，\(s=1-r\)，旧状态为 \(M,v\)，旧 token 为 \(p\)。当前实现同时计算

\[
M_0=sM,\quad v_0=sv,\quad k=\operatorname{normalize}(A(sp)),\quad a=sw.
\]

当 \(r=1\) 时，\(M^+=v^+=k=0\)。读出依赖 \(M^+k\)，有效性依赖 \((v^+)^Tk\)：两者都是两个零因子的乘积。因此当前 query loss 对 write/reset 事件以及 embedding/address/value/controller 的一阶 STE 梯度恰好为零。sigmoid 的导数可以严格为正，仍然无法跨过这个零乘积。readout 可以继续学习类别先验。

**这个结论有条件，不能扩大为全局不可学习。** 如果后续某个 query 不 reset，它仍能沿持久状态把梯度传回此前的 reset；独立的双步例子确实观察到非零纠错梯度。现有 optimizer 动量或其他 batch 也可能改变参数。36 个微例覆盖当前全 reset 死区、非 reset 对照，以及随后非 reset query 的链式梯度，保留了所有数值。

实际四模型的所有监督 query 都 reset，和这个即时纠错死区一致；它为下一次重设计提供了明确机制约束。本轮没有据此修改模型或重调参数。任何保留读地址梯度的改动，都仍须重新证明有限数值输入下的清除安全性，再另行注册。

## 7. legacy stale 指标的口径修正

冻结的 `metrics_from_logits` 把 `previous_label >= 0` 且不等于目标的情况作为 stale opportunity，其中 **UNKNOWN=4 也被算作 previous label**。例如 MQAR 常规面板全答 UNKNOWN 时，原指标仍会报 `stale_answers_emitted=384`，因为最初的 previous label 是 UNKNOWN。

原始指标未改写。另从原始数组生成解释性统计后，每模型得到：

- legacy stale predictions：3,576；全部是 previous label 为 UNKNOWN 时的拒答。
- 旧已知值机会：5,753；实际输出旧已知值：**0**。
- 已知目标拒答：5,851；已知目标正确：**0**。

因此本轮不能把 legacy 的 3,576 称作“旧已知记忆泄漏”，也不能把旧已知值输出为 0 称作有效记忆修复。这里的主失败是主动擦除后的全拒答。

## 8. 独立复验和完整性

另一审阅 agent 使用独立解释器与指标重算，核对注册 Git 字节和全部冻结源码；原预算分支的训练 stream、1,073 条 loss/gradient 轨迹、四份权重和未执行 heldout 的事实也已单独核对。

完整补完结果经过 **36 个主模型面板回放、18 个映射面板验证、4 个 erasure witness 复验**。逐查询预测、概率、事件和 binding logits 精确复现；整数质量计数、原始 legacy stale 与旧已知值分拆一致。独立审阅没有新增 fit 或新的质量试验。这是内部可复演审计，不是外部第三方科学签名。

13 项模型行为测试和 4 项 completion 完整性 guards 通过。completion guard 的一次普通磁盘测试曾因 ENOSPC 出现两个临时文件错误；原错误作为 IO incident 保留，随后在 `/dev/shm` 临时目录运行的四项 guards 全部通过。释放可重建缓存后，任务目录写读哈希探针通过，最终证据已写回并核对。没有把 IO 错误隐去或记成模型训练失败。

## 9. 证据入口与结论边界

- [原注册协议](2026-11-05-round3-p2-reset-validity-protocol.json)、[原预算失败结果](2026-11-05-round3-p2-reset-validity-results.json)。
- [追加注册协议](2026-11-05-round3-p2-reset-validity-completion-protocol.json)、[完整四配置结果](2026-11-05-round3-p2-reset-validity-completion-results.json)、同名 `-artifacts` 目录中的权重、optimizer 和逐查询数组。
- [原始数组指标解释](2026-11-05-round3-p2-reset-validity-metric-clarification.json)、[开发集事件诊断](2026-11-05-round3-p2-reset-validity-development-diagnostic.json)。
- [独立完整审计](2026-11-05-round3-p2-reset-validity-independent-review/completion-independent-audit.json)、[独立完整审阅说明](2026-11-05-round3-p2-reset-validity-independent-review/P2_COMPLETION_INDEPENDENT_REVIEW.md)。
- [独立梯度推导](2026-11-05-round3-p2-reset-validity-gradient-review/REVIEW.md)、同目录 36 微例完整 evidence、源码和执行 receipt。另附[便携复现说明](2026-11-05-round3-p2-reset-validity-gradient-portable/PORTABLE_REVIEW.md)：同一组 36 微例重演逐值一致，新增 0 fit／0 heldout；复用输出目录会在导入 torch 前拒绝，原证据哈希不变。原执行源码与便携源码分别保留，未把重复验证计成新的 36 个独立案例。
- [未执行初稿审阅失败记录](2026-11-05-round3-p2-reset-validity-rejected-draft.json)、[磁盘 IO 失败与恢复记录](2026-11-05-round3-p2-reset-validity-io-incident.json)。

本轮新增了可复验的条件性擦除合同、数值边界反例和一个具体的 STE 梯度死区证据，完成了固定四配置的正式负结果评价。它没有实现需要的信息保持与失效信息更新的共同目标，没有 HCSN 机制优势，没有 Selective Copy 完整覆盖，没有真实多模态、端到端规模或固定质量效率结论。**P2 保持 OPEN。**

## 10. 最小复现命令

在包含上述注册 commits、完整证据且冻结源码未改的 checkout 根目录运行；`python` 使用记录的 Python/PyTorch/NumPy 环境。所有 `/tmp/...-new` 输出必须尚不存在。补完命令会真实再训练一个固定模型；审计命令只验证归档结果。

```sh
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1
python -m unittest research.hcsn.test_p2_reset_validity research.hcsn.test_p2_reset_validity_completion -v

python -m research.hcsn.p2_reset_validity_completion \
  --protocol research/hcsn/gates/2026-11-05-round3-p2-reset-validity-completion-protocol.json \
  --registration-repo . \
  --registration-commit fa8eb7413d72762f51e61144c36912047dfce240 \
  --output /tmp/p2-reset-completion-new.json

python research/hcsn/gates/2026-11-05-round3-p2-reset-validity-independent-review/audit_reset_validity_results.py \
  --root . --registration-repo . \
  --evidence research/hcsn/gates/2026-11-05-round3-p2-reset-validity-completion-results.json \
  --output /tmp/p2-reset-audit-new.json
```

梯度诊断的 `--root`／`--output-dir` 命令和 create-only 行为见[便携复现说明](2026-11-05-round3-p2-reset-validity-gradient-portable/PORTABLE_REVIEW.md)。
