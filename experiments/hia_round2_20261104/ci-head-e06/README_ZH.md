# e06 候选源码的实际 GitHub CI 观察

该 head 的 11 条已触发工作流全部成功结束，102 个 job 中 101 个实际执行成功，1 个可选 job 按原条件跳过。本目录保留所有 101 个已执行 job 的完整返回日志、完整 job/step 元数据，以及 shared kernel 与 source-controls 两份原始 artifact。**同树桌面 v11 整链仍在 600 秒外层预算下以 exit 124 失败；CI 成功不覆盖这一失败，也不是最终组合或 Agent 队列的完成凭证。**

## 精确源码与执行身份

| 身份 | 值 |
|---|---|
| 公开候选 commit | `e06aacb66c849b202378268630249be2e7a153fa` |
| 原始 runtime commit | `0c8a91003aee2732308bb654d0e1f941ae561728` |
| 两者相同 tree | `3870c31f7779a6c1bbcde21159c3c559e92b5501` |
| 草稿集成 PR | [#682](https://github.com/TrillionniumFoundation/Hepta/pull/682) |
| CI 最终读侧快照 | `2026-11-05 04:56:30 UTC`，11 个 run 均为 attempt 1 |

完整结果在 [CI_READOUT.json](CI_READOUT.json)。原始分页与状态演进在 `snapshots/`，最终统一元数据为 `snapshots/0007-TERMINAL_METADATA.json`。run 查询第一页返回 11/11，第二页为空；各 run 的 jobs/artifacts 页返回数均等于 API 的 total_count。前期尚在执行的快照没有覆盖。

## 本次实际完成的检查

初始化控制工作流 [41967339570](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41967339570) 的 75 个 job 全部实际通过：ordinary 207 项，74 个 isolated group 合计 705 项。日志中每个预期 ID 都对应一条实际 `... ok`，无缺失、重复、失败、错误或跳过。两集合与恢复前历史源码 `0ab0c441d9d115f9288f18707a117506369b93ff` 的完整 ID 集合哈希相同，原计数与分片门槛没有降低。[FRONTIER_ACTUAL_AUDIT.json](FRONTIER_ACTUAL_AUDIT.json) 保留完整 ID 与逐 job 证据。每个 job 日志都打印了实际 head；只有 ordinary job 打印完整 tree，其他 job 的 tree 由独立 Git commit 映射绑定。

这说明补回的 45 个历史缺失文件闭合了该 head 的 CI 运行依赖。旧 head `47c9935d…` 的 75 个真实失败仍保留在独立旧 CI 包中；本次成功没有追溯改写它们。

shared 工作流 [41967339558](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41967339558) 的 kernel 与 source-controls 均实际成功。kernel 原始日志中的 qualifier 和独立 replay 两次 `full_replay_verified` 摘要一致：11 次 Lean invocation、66 个 positive target、10 个 exact-negation certificate。其原始 RESULT SHA256 为 `f234ed103e8078e0640066a4812101433b6fafcd3068a47d485d016544705e57`。新源码的算法候选称为 v11，冻结的协议标识仍是 `seven-shared-acceptance-v10`。

kernel artifact `13388502118` 的 ZIP 为 6,561,862 字节，SHA256 `2290b18b9b0fe3e21add1ba2cf5230af1c1d57fa61d7a4555794b650854a5952`。82 个文件共 26,456,119 字节，均已安全解压并完整回读。独立字节审计还逐条核对了 11 个阶段的源码、olean、stdout/stderr、start/finish 回执与父模块哈希绑定，以及实际子进程退出、完整流和清理字段。见 [KERNEL_RECEIPT_BINDING_AUDIT.json](KERNEL_RECEIPT_BINDING_AUDIT.json)。审阅方没有重新运行 Lean、源码重建或语义 replay；两次 replay 成功来自原 CI 完整日志。

source-controls artifact `13387789348` 的 46 项全部实际通过，原 43 个 ID 完整保留，新增 3 项，0 failure/error/skip/loader error。排序后的 collected IDs 与 expected 清单相等；collected、started、finished 三份执行序列相同。expected 清单本身是排序顺序，不要求与原执行顺序相同。源 commit/tree 与 clean 状态前后相同。原始 `RESULT.json`、stdout、stderr、ZIP 与逐文件审计均保留。

mandatory native NDU 工作流 [41967339534](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41967339534) 实际成功，job `127047279187` 从 04:23:30 至 04:55:15。其原生集成与 regression 步骤从 04:25:58 至 04:49:01，属于已执行工作，不能与另一个未执行的 optional native NDU job 混同。详细 regression 输出重定向到未下载的 artifact，本目录不补造其完整测试数量，也不从 job 成功推断 NDU 净收益。

optional job `127050398208` 的冻结条件是 `${{ github.event_name == 'workflow_dispatch' && inputs.run_native_ndu }}`。本次事件为 pull_request，实际 0 个 step，结论是未执行，而不是测试通过。采集方没有 dispatch 或重跑任何工作流。

six-outcome 工作流 [41967339511](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41967339511) 实际成功，原日志打印 410 个 regression tests / 358.491 秒。这是测试子过程时间；其中原生 reference/hostile controls 不等于尚未执行的正式 16-cell 模型队列。

17 个硬件与 ABI job 的具体执行、拒绝和未证明范围在 [硬件日志审阅表](hardware-review/README_ZH.md)。它区分 1 个 standalone Linux AArch64、7 个 ABI、7 个真实上游 C++、2 个 captured-C job；依据实际日志和 step 结果，不以 matrix 标签充当执行证据。captured-C 重定向输出中的分母与完整 receipt 未读取，保持 null。此表不证明 host-region 恢复竞争、DMA 或所有并发交错。

## CI 成功与桌面失败分别保留

同树桌面原运行的外层 exit 为 124，耗时 `600.047503236 s`。其 11 个 Lean 阶段通过，内层 RESULT 在 `553.393567603 s` 写为 passed，但内置 evidence replay 未在外层 600 秒内完成。因此原整链验收仍失败。

其后的独立 replay 以 exit 0 完成，耗时 `55.874570337 s`；这是单独观察，不能追溯升格原运行。CI 的独立环境成功也不能证明这两个环境之间存在已确定的单一性能原因。原始、精确公开记录在 `cross-evidence/PROOF_V11_OBSERVATION.json`，绝对 Unix 纳秒保持原 decimal strings。

shared 的 15 分钟 job、600 秒 qualifier、600 秒独立 replay、540 秒新进程启动预算和每个子过程 60 秒预算全部保持不变。540 秒是 launch budget，不是整个 job 预算。kernel RESULT 的 `289.254367918 s` 是写入该内层结果之前的时间，不能当作包括后来内置 replay 的完整 qualifier 墙钟。

CI job API 时间仅有秒级分辨率；step 和 unittest 时间嵌套在父 job 中，多 job 可能并行，不能把这些数再次相加当作端到端耗时。桌面内层耗时也嵌套在失败的外层 600 秒内。采集、人类审阅和完整研发总成本未被完整测量，保持 null，不写成 0。

## 证据完整性与公开范围

完整日志为 101 份、7,169,846 字节，均与 App 返回的 decoded content 逐字节相同；这是返回解码文本的完整性，未声称保留 GitHub 服务内部的压缩传输字节。见 [JOB_LOG_INVENTORY.json](JOB_LOG_INVENTORY.json)。

25 个 artifact 的完整清单共 138,872,276 ZIP 字节；实际仅下载并核验 shared 的 2 份，其余 23 份只保留元数据。不能把清单中存在的 artifact 写成已下载或独立验证。shared kernel 的新 upload 步骤使这次原始阶段文件可下载；旧 head 缺 kernel artifact 的历史事实不变。

两个 `*.download.tool.json` 原始响应含临时签名下载 URL，保留在采集目录，但明确从公开 payload 排除。其大小、SHA256 和原因在 [PUBLIC_SCOPE.json](PUBLIC_SCOPE.json) 中；公开使用过滤后的 download metadata、原 ZIP 与哈希，不发布签名 URL。未修改原日志或 artifact 字节。

本目录提供原始证据与字节绑定审计。自行进行语义 replay 还需要精确源码 checkout 与 pinned Lean/tool support；artifact 中记录了 258 项源文件及 780 项 tool-support 的身份，但没有打包全部外部依赖，因此不承诺仅解压 ZIP 即可独立 replay。

共享证明仍只涵盖窄 Core syntax connection，权限保持 **DENY_ALL**，12 个生产 refinement 义务全部 open。最终同源组合、最终组合 AOT 与正式 Agent 队列仍 pending。本 CI 观察不宣布七条关闭条件全部完成。
