# Hepta / HIA 第二轮证据

状态：已完成测量先行封存；最终同源证明、组合验收与 Agent 队列仍在推进。本提交不声明七项研究关闭条件全部达成。

## 已完成并完整回读的证据

| 范围 | 已观察结果 | 入口 |
| --- | --- | --- |
| 强 Rust AOT 对照 | 两个新源码候选分别 318/372、348/372；第二个候选全部中位数门槛通过，但仍有 24 项尾延迟和 10 项冷调用成本失败 | [AOT 观测](aot/OBSERVATION.json) |
| 原生动态缓存 NDU | 432/432 episodes 完成；允许 skip 的策略为 0/24 组同时超过全部对照，实际调用子集为 0/12；不是 HIA 编译应用的性能证据 | [中文 NDU 报告](ndu/NDU_DYNAMIC_REPORT_ZH.md) |
| 迁移、恢复及 Agent 准备 | 328 份原始文件完整封存，包含拒绝、失败准备、原生控制与零模型生成的容量检查；未知成本保留为 null | [开发证据](development/README.md)、[成本说明](development/COST_INDEX.md) |

三包共 97 件发布文件，均通过完整字节回读；各包附带分片顺序、原件哈希、恢复脚本和实际全量恢复验证。开发成本的父子区间不能重复相加；各替代策略的独立费用分配也不能相加成一次实测总额。

## 已保留的证明失败

源码候选 `2d964d27b068b3eb0b19e72ea4132eefd12d4360` 的新鲜 11 阶段证明在前 10 阶段通过后，于最后 WrongArm 阶段拒绝；不是完整成功。详见 [该次原始结果索引](PROOF_V9_OBSERVATION.json)。后续修复必须重新以确切源码提交验收。所有更广的生产精化义务仍按各原始记录保持未证明。

该候选的发布投影为 [`0d75c60d477444e469723aed7787f96fc8501da0`](https://github.com/TrillionniumFoundation/Hepta/tree/0d75c60d477444e469723aed7787f96fc8501da0)，二者 Git tree 均为 `6ac384198d9438df91888178e06e4a5ef44ed40f`。投影是相同源码树的发布身份，不冒称被直接测量的原始 commit。

## 冻结候选 v10 与当前集成状态

[Draft PR #682](https://github.com/TrillionniumFoundation/Hepta/pull/682) 发布了 runtime `b47ce924c5941b42448e9da0b07a2bcedaf75d1f` 的同树投影 `47c9935d4d1406f6697810d23d45cb3b45c3b950`，共同 tree 为 `69cd887f7a2a56de62c6b074bea9fca717d01355`；完整回读记录见 [SOURCE_PUBLICATION_V10.json](SOURCE_PUBLICATION_V10.json)。

该候选的新鲜 11 个 Lean 阶段均通过，但完整命令在最后证据重放期间触及原 600 秒外限，退出码为 124。内层 RESULT 在 558.870179933 秒写出不等于完整接受。随后独立证据重放以 73.055962129 秒、退出码 0 完成，它不能追溯改变原始验收失败；详见 [PROOF_V10_OBSERVATION.json](PROOF_V10_OBSERVATION.json)。

初始化研究 CI 在执行测试前拒绝了缺失的历史测试依赖；固定清单引用的 39 个测试模块中有 31 个未纳入这份候选。正在恢复原始文件与依赖，保持原清单计数和证明预算。最终同源组合及正式 Agent 队列尚未开始；PR 保持草稿。

本目录的证据只增加到新的 round2 命名空间。以前的实验目录和原始失败记录继续保留。最终交付索引将另行关联完整源码 bundle、各自测量身份、同源验收、真实 CI 和正式 Agent 队列。
