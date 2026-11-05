# 证据索引

| 目的 | 直接可读文件 | 原始依据 |
|---|---|---|
| 全部 CI 终态和范围 | [CI_READOUT.json](CI_READOUT.json)、[中文说明](README_ZH.md) | 恢复后的 `snapshots/TERMINAL_METADATA.json` 与全部历史快照 |
| 101 个实际 job 日志身份 | [JOB_LOG_INVENTORY.json](JOB_LOG_INVENTORY.json) | 恢复后的 `jobs/*.log` 与原 App responses |
| 207+705 完整实际测试 ID | [FRONTIER_ACTUAL_AUDIT.json](FRONTIER_ACTUAL_AUDIT.json) | 75 份实际完整 job logs，原历史集合哈希保留 |
| 49 项 source-controls | [预期固定清单](EXPECTED_SOURCE_CONTROLS.json)、[artifact 审计](artifacts/13389633139-AUDIT.json) | 恢复后的原 ZIP、RESULT、stdout、stderr；预期49个ID已在payload下载前固定 |
| 11 阶段 kernel 原件 | [artifact 审计](artifacts/13390875937-AUDIT.json)、[独立回执绑定审计](KERNEL_RECEIPT_BINDING_AUDIT.json) | 恢复后的 82 原件、完整 ZIP 与实际 qualifier/replay job log |
| 实际硬件/ABI 执行边界 | [硬件表](hardware-review/README_ZH.md)、[逐行 JSON](hardware-review/REVIEW.json)、[17 logs 清单](HARDWARE_LOG_MANIFEST.json) | 17 个完成 job 的实际完整日志；未读 artifact 的计数保持 null |
| 同树桌面失败与后续 replay | [PROOF_V12_OBSERVATION.json](cross-evidence/PROOF_V12_OBSERVATION.json) | 原公开 observer 记录，原 outer124 不被后来 replay0 或 CI 成功升级 |
| 源投影与取消配置 | [SOURCE_PUBLICATION_V12.json](cross-evidence/SOURCE_PUBLICATION_V12.json)、[CONCURRENCY_AUDIT.json](CONCURRENCY_AUDIT.json) | 精确原始/source public commit、同 tree 与 11 个冻结 workflow |
| 独立 peer 审阅 | [SCOPE_PEER_REVIEW.json](SCOPE_PEER_REVIEW.json) | 精确 CI_READOUT / 原中文说明的哈希、分母和嵌套成本核验 |
| 签名 URL 排除 | [PUBLIC_SCOPE.json](PUBLIC_SCOPE.json)、[限定模式筛查](PUBLIC_DOWNLOAD_URL_SCREEN.json) | 2 份 excluded raw responses 的身份仍保留；筛查不声称普遍无秘密证明 |
| 原始文件与完整恢复 | [MANIFEST.json](MANIFEST.json)、[COLLECTION_INVENTORY.json](COLLECTION_INVENTORY.json)、[RESTORE_VERIFICATION.json](RESTORE_VERIFICATION.json)、[ORIGINAL_INPUTS_RECHECK.json](ORIGINAL_INPUTS_RECHECK.json) | 398 个原件、15 分片、全归档和恢复后逐文件哈希 |

25 份 artifact 只有清单完整；实际下载并保留的只有 shared 的 2 份，其余 23 份不是已读取的 payload。直接公开副本的字节身份在 [READABLE_INDEX.json](READABLE_INDEX.json) 中，完整原始路径恢复到新目标目录后使用。恢复命令与约束见 [README.md](README.md)。
