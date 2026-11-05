# Hepta / HIA 第二轮证据

状态：持续实现与独立验收中；本目录不声明七项研究关闭条件全部达成。

## 已测量并封存的结果

| 范围 | 实际观察 | 入口 |
| --- | --- | --- |
| 强 Rust AOT 对照 | 两个独立候选分别 318/372、348/372；第二个候选全部中位数门槛通过，但有 24 项尾延迟和 10 项冷调用门槛失败 | [AOT 观测](aot/OBSERVATION.json) |
| 原生动态缓存 NDU | 432/432 episodes；含 skip 的完整队列 0/24 组净胜全部强对照，实际 invoke 子集 0/12；不是 HIA 编译应用提速证据 | [中文报告](ndu/NDU_DYNAMIC_REPORT_ZH.md) |
| C++、恢复、Agent 准备 | 328 份开发原件，包括失败、拒绝、实际生命周期控制及零模型生成的容量准备；未知人力和历史成本保留 null | [开发证据](development/README.md) |
| 旧 head47 的完整 CI | 11 runs / 102 jobs：26 success、75 failure、1 optional skipped；101 个执行作业完整日志，75 失败均发生于测试清单检查 | [CI 可读报告](ci-head47/README.md)、[完整清单](ci-head47/CI_READOUT.json) |

前三包共 97 件发布文件；旧 CI 包另有 11 件。各包提供原件和分片哈希、恢复脚本与实际全量恢复验证，发布内容经过完整字节回读。旧 CI 包保存 293 份原件，归档仅含 24 个列出 artifacts 中实际下载的一个 source-controls ZIP；原 kernel 作业没有提供完整 proof artifact。签名下载凭据明确排除。

## 各次证明结果分别保留

| 候选 | 实际结果 | 原始观察 |
| --- | --- | --- |
| v9 / `2d964d27` | 前 10 阶段通过，最后 WrongArm theorem 实际失败；不是总预算超时 | [v9](PROOF_V9_OBSERVATION.json) |
| v10 / `b47ce924` | 11 个 fresh Lean 阶段通过，完整命令在内置回放中超时：outer 600.079463180 秒 / exit124；后来独立 replay 73.055962129 秒 / exit0 | [v10](PROOF_V10_OBSERVATION.json) |
| v11 / `0c8a9100` | 11 个 fresh Lean 阶段通过，完整命令仍在内置回放中超时：outer 600.047503236 秒 / exit124；后来独立 replay 55.874570337 秒 / exit0 | [v11](PROOF_V11_OBSERVATION.json) |

内层 RESULT、后来的独立 replay 和另一个环境中的 CI 成功均不能追溯改变原始完整命令的失败。原来的 600 秒整体、540 秒 launch、60 秒进程预算保持不变。所有 12 项更广生产精化义务仍未证明，权限保持 DENY_ALL。

[v10 绝对 epoch 元数据精度纠正](PROOF_V10_EPOCH_PRECISION_CORRECTION.json) 精确列出三项序列化误差。原始 observer 记录和已发布历史文件都保留；耗时间隔、退出码、证据哈希和结论未改变。新观察使用十进制字符串保存超出 JavaScript 精确整数范围的绝对纳秒。

## 当前源码与未完成工作

[Draft PR #682](https://github.com/TrillionniumFoundation/Hepta/pull/682) 的当前候选为运行提交 `0c8a91003aee2732308bb654d0e1f941ae561728`，公开同树投影 `e06aacb66c849b202378268630249be2e7a153fa`，共同 Git tree `3870c31f7779a6c1bbcde21159c3c559e92b5501`。52 项本轮文件变化已经逐字节回读，见 [源码身份](SOURCE_PUBLICATION_V11.json)。投影提交不冒称直接测量的原始提交。

该候选恢复 45 个历史 CI 依赖文件，保留原 207 / 705 测试清单及 74 个隔离组，并把全部原 43 个源码控制扩展为 46 个。一次固定 old→new 准备/重建对照为 137.284187024→117.147739773 秒，完整 23 个源码文件、11 个 Lean 模块及清单字节一致；这不是正式整体验收或统计性能结论。

截至此快照，新 head 的初始化 CI 75 个作业以及 shared 两个作业已经报告成功；新的 46-control artifact 已独立核验，新 kernel 完整 artifact 已提供并正在核验。剩余工作流及下一算法修复仍在推进。完整桌面证明未达预算，因此最终 36-command / 34-flag 同源组合和 16-cell 正式 Agent 队列尚未启动。

最终组合必须得到自己的 AOT 分数；不能复制独立候选的 348/372，也不能挑选不同版本的通过项拼成成功。父子费用区间、并行任务及替代部署分摊不能重复相加。此前发布的实验目录及失败记录继续保留；本轮没有合并 main 或以前的 PR。
