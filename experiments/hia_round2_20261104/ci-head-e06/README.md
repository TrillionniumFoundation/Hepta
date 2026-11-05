# e06 候选的完整 GitHub CI 证据包

此包冻结公开候选 `e06aacb66c849b202378268630249be2e7a153fa`、tree `3870c31f7779a6c1bbcde21159c3c559e92b5501` 的实际 CI：11 条工作流成功，101 个 job 实际成功、1 个可选 job 未执行。**同树桌面 v11 的 600 秒整链超时仍然是失败，不被 CI 或后续独立 replay 覆盖。最终组合和 Agent 队列仍 pending，12 项生产 refinement 保持 open / DENY_ALL。**

完整中文说明见 [README_ZH.md](README_ZH.md)，机器可读结果见 [CI_READOUT.json](CI_READOUT.json)，按证据类型查阅见 [EVIDENCE_INDEX.md](EVIDENCE_INDEX.md)，实际硬件执行表见 [hardware-review/README_ZH.md](hardware-review/README_ZH.md)。这些直接公开的原件副本均与归档内相同文件逐字节一致。

## 恢复完整原始证据

400 个原件共 54,640,224 字节，包含 101 份完整 job 日志、全部快照、两个实际下载的 shared artifact、解压文件与审计。XZ 归档共 11,180,688 字节，分为 15 片。两个含签名 URL 的原始下载响应明确排除，保留其大小、SHA256 和排除原因；没有从公开原件中删掉失败或未知结果。

下载本目录的 `MANIFEST.json`、`RESTORE.py` 和全部 15 个 `evidence.tar.xz.part-*` 文件到同一目录，运行：

```sh
python3 RESTORE.py --target restored-e06
```

目标目录必须不存在。restorer 按清单校验每个分片、完整归档、每个成员及每个恢复文件。`RESTORE_VERIFICATION.json` 记录本次 400 文件完整恢复通过；`ORIGINAL_INPUTS_RECHECK.json` 记录恢复后原件字节、mode、mtime 及排除原件再次核对无变化。原报告中的 `jobs/`、`snapshots/` 等完整路径可在 `restored-e06/` 下找到。

这里验证的是完整字节恢复。要重新进行语义 replay，仍需要精确源码 checkout 与 pinned Lean/tool support；此包没有运行新 Lean、模型或测试，也不承诺仅解压即可独立证明全部语言安全。

打包与恢复成本单列于 `DELIVERY_COST.json`，公开索引整理成本单列于 `PUBLICATION_PREPARATION_COST.json`。它们不加入已完成 CI 或性能实验的运行时间；网络发布、人工审阅及未观测成本没有被推为 0。
