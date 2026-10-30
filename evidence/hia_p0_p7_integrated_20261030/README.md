# P0–P7 integrated checkpoint, 2026-10-30

本目录汇总本轮实际执行结果。实现来源始终是
`50c4067399989e7194028576c38c0e783b78cf06`，tree 为
`464e1643e804d9f6dc4b1536416012317ea7b680`。后续仅加入文档和证据，
不把旧结果或该实现上的结果改标为归档提交的重新执行结果。

- [完整报告](../../docs/HIA_P0_P7_INTEGRATED_20261030.md)
- [机器可读阶段状态](RESULT.json)
- [原始交付文件逐字节复制清单](TRANSFER_MANIFEST.json)
- [P0 qualification 与 canonical matrix](../hia_p0_integrated_20261030/README.md)
- [P3 真实 C/C++ 两条迁移路径](../hia_p3_integrated_20261030/README.md)
- [P7 实际模型资格失败与 main 拒绝](../hia_agent_v11_integrated_20261030/README.md)

P0 在本机声明范围通过。P2 的 Rust 独立准入仅限 `raw-byte-dag-v1`。
P3 的有限直接 C 翻译和保留 C++ 库桥接升级均实际完成；全范围资源恢复、
通用重写和完整人工成本未取得。CRC 没有正的冷经济候选，也没有 NDU arm。
P7 容量控制通过，但模型三项资格为 0/3，主试验实际拒绝，执行 cells 为零。
所有 P0–P7 严格门槛并未全部关闭。

## 复核范围

P0、P3、P7 原始交付包保持原字节。根审阅记录在 `root-review/`，其中：

- `p0.json` / `p3.json` / `p7.json` 保存根独立离线读回的命令、返回码、计时与 SHA。
- `p7-result.json` 保存完整逐成员读回及原始 SSE 用量重算结果。
- `p7-independent-readonly-review.json` 记录独立的任务、usage、源码/工具与 main 控制流复核。
- `report-review-before-p7.json` 是先前草稿审阅记录；其草稿 hash 不代表后续扩充的最终文档。

这些检查只验证已保留记录的完整性与一致性，不执行归档程序或模型，
不增加 native、测试或模型生成分母，也不构成完整主机执行认证。
各包 README 提供各自有界离线 verifier 的实际用法。

## 发布状态

本检查点仍是本地交付。此前 GitHub push 被自动审批拒绝。
对 `work/hia-p0-p7-integrated-20261030` 的推送会触发 integrated CI；
远端结果必须来自该次真实运行。当前没有把本地资格当作远端 CI 成功。
