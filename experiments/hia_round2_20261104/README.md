# Hepta / HIA 第二轮证据

状态：持续实现与独立验收中；本目录不声明七项研究关闭条件全部达成。

## 已测量并封存的结果

| 范围 | 实际观察 | 入口 |
| --- | --- | --- |
| 强 Rust AOT 对照 | 两个独立候选分别 318/372、348/372；第二个候选全部中位数门槛通过，但有 24 项批次尾延迟和 10 项冷调用门槛失败 | [AOT 观测](aot/OBSERVATION.json) |
| 原生动态缓存 NDU | 432/432 episodes；含 skip 的完整队列 0/24 组净胜全部强对照，实际 invoke 子集 0/12；不是 HIA 编译应用提速证据 | [中文报告](ndu/NDU_DYNAMIC_REPORT_ZH.md) |
| C++、恢复、Agent 准备 | 328 份开发原件，包括失败、拒绝、实际生命周期控制及零模型生成的容量准备；未知人力和历史成本保留 null | [开发证据](development/README.md) |
| 旧 head47 的完整 CI | 11 runs / 102 jobs：26 success、75 failure、1 optional skipped；101 个执行作业完整日志，75 失败均发生于测试清单检查 | [旧 CI 报告](ci-head47/README.md) |
| e06 候选的完整 CI | 11 workflows 全部成功；102 jobs 中 101 实际 success、1 optional skipped；207 + 705 = 912 个前沿测试逐项实际通过；shared 46 controls 和完整 kernel artifact 已独立核验 | [中文 CI 报告](ci-head-e06/README_ZH.md)、[硬件实际日志](ci-head-e06/hardware-review/README_ZH.md) |

前三包共 97 件发布文件；旧 CI 包另有 11 件，e06 CI 包另有 46 件。各包提供原件和分片哈希、恢复脚本与实际全量恢复验证，发布内容经过完整字节回读。e06 包保存 400 份原件，25 个列出 artifacts 中只下载并核验 shared 的 2 个，其余仅保留元数据。旧 CI 包保存 293 份原件，仅下载过一个 source-controls ZIP；原 kernel 作业没有提供完整 proof artifact。签名下载凭据明确排除。

## 各次证明结果分别保留

| 候选 | 实际结果 | 原始观察 |
| --- | --- | --- |
| v9 / `2d964d27` | 前 10 阶段通过，最后 WrongArm theorem 实际失败；不是总预算超时 | [v9](PROOF_V9_OBSERVATION.json) |
| v10 / `b47ce924` | 11 个 fresh Lean 阶段通过，完整命令在内置回放中超时：outer 600.079463180 秒 / exit124；后来独立 replay 73.055962129 秒 / exit0 | [v10](PROOF_V10_OBSERVATION.json) |
| v11 / `0c8a9100` | 11 个 fresh Lean 阶段通过，完整命令仍超时：outer 600.047503236 秒 / exit124；后来独立 replay 55.874570337 秒 / exit0 | [v11](PROOF_V11_OBSERVATION.json) |
| v12 / `5ee6d8fe` | 11 个 fresh Lean 阶段通过，inner 550.561070862 秒，但完整命令仍超时：outer 600.049994673 秒 / exit124；后来独立 replay 61.189014082 秒 / exit0 | [v12](PROOF_V12_OBSERVATION.json) |

内层 RESULT、后来的独立 replay 和另一个环境中的 CI 成功均不能追溯改变原始完整命令的失败。原来的 600 秒整体、540 秒 launch、60 秒进程预算保持不变。所有 12 项更广生产精化义务仍未证明，权限保持 DENY_ALL。

[v10 绝对 epoch 元数据精度纠正](PROOF_V10_EPOCH_PRECISION_CORRECTION.json) 精确列出三项序列化误差。原始 observer 记录和已发布历史文件都保留；耗时间隔、退出码、证据哈希和结论未改变。新观察使用十进制字符串保存超出 JavaScript 精确整数范围的绝对纳秒。

## 当前源码与未完成工作

[Draft PR #682](https://github.com/TrillionniumFoundation/Hepta/pull/682) 当前候选为运行提交 `5ee6d8fec0e5c72d87a36dbed60789de211abf1b`，公开同树投影 `3102c2bb6cd819c27aef36cc927c23b39b279204`，共同 Git tree `d47a711461dc66d4606bdc9659203889e205d6c7`。本次 4 项源码变化已经逐字节回读，见 [源码身份](SOURCE_PUBLICATION_V12.json)。投影提交不冒称直接测量的原始提交。

此前恢复的 45 个历史 CI 依赖文件保留原 207 / 705 测试清单及 74 个隔离组。v12 保留原 46 个源码控制并扩展到 49 个：首轮因新增控制的 Unicode 快照序列化出错，实际 48 pass / 1 error；只修正测试快照后全部 49 项通过。失败源码字节和原记录保留。一次固定 old→new 准备/重建对照为 133.057458747→109.174032726 秒，完整 23 个源码文件、11 个 Lean 模块及清单字节一致；这不是正式整体验收或统计性能结论。

3102 的 shared 与 frontier 工作流已报告成功，49-control 和完整 kernel artifact 正在独立收集；剩余工作流尚待终态。e06 的完整 CI 成功是独立历史观察，不能替代 3102 的最终 CI。

当前 36-command / 34-flag 组合尚未执行。源码明确将该行为组合与 shared 11-stage 研究链分开：下一步在冻结候选上独立观察 build/run/refuse/cancel/recover，并保留研究链整体验收未通过；这不是放宽任何原验证门槛或声明研究证明成功。正式 16-cell Agent 队列仍为零模型生成。

最终组合必须得到自己的 AOT 分数；不能复制独立候选的 348/372，也不能挑选不同版本的通过项拼成成功。父子费用区间、并行任务及替代部署分摊不能重复相加。此前发布的实验目录及失败记录继续保留；本轮没有合并 main 或以前的 PR。
