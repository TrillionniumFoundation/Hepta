# 3102 候选源码的实际 GitHub CI 观察

该 head 的 **11/11 条已触发工作流成功结束**；102 个 job 中 101 个实际执行成功，1 个可选 job 按原条件跳过。本目录保留所有 101 个已执行 job 的完整返回日志、完整 job/step 元数据，以及 shared kernel 与 source-controls 两份原始 artifact。**同树桌面 v12 整链仍在 600 秒外层预算下以 exit 124 失败；CI 成功不覆盖这一失败，也不是行为组合、强 AOT 或正式 Agent 队列的完成凭证。**

## 精确源码与执行身份

| 身份 | 值 |
|---|---|
| 公开候选 commit | `3102c2bb6cd819c27aef36cc927c23b39b279204` |
| 原始 runtime commit | `5ee6d8fec0e5c72d87a36dbed60789de211abf1b` |
| 两者相同 tree | `d47a711461dc66d4606bdc9659203889e205d6c7` |
| 草稿集成 PR | [#682](https://github.com/TrillionniumFoundation/Hepta/pull/682) |
| CI 终态采集截点 | `2026-11-05 05:46:31 UTC`，11 个 run 均为 attempt 1 |

完整结果在 [CI_READOUT.json](CI_READOUT.json)。原始分页与状态演进保存在 `snapshots/`，统一终态元数据为 `snapshots/TERMINAL_METADATA.json`。run 查询第一页返回 11/11，第二页为空；各 run 的 jobs/artifacts 返回数均等于 API 的 total_count。前期仍在执行的快照保留，未覆盖。

## 实际完成的控制与证明链

初始化控制工作流 [41971915905](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915905) 的 75 个 job 全部实际通过：ordinary 207 项、74 个 isolated group 合计 705 项，共 912 项。已逐项核对实际 verbose `... ok` 与完整预期 ID 清单，无缺失、重复、失败、错误或跳过。两集合分别与历史源码 `0ab0c441d9d115f9288f18707a117506369b93ff` 的完整 ID 集合哈希相同，原计数、分片和预算未降低。[FRONTIER_ACTUAL_AUDIT.json](FRONTIER_ACTUAL_AUDIT.json) 保留每个 ID 和 job 的对应证据。75 份日志都打印实际 head；只有 ordinary job 打印 tree，其余 tree 通过独立 Git commit API 映射绑定。

此前 head `47c9935d…` 因缺少 31 个 workflow 声明的测试模块，实际发生 75 个 job 失败。后续精确恢复 45 个历史缺失文件，保留 9 个已存在且不同的文件，没有覆盖当前实现。旧失败及 e06 的独立 CI 成功保留在各自证据包中，本次成功不追溯改写它们。

shared 工作流 [41971915880](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915880) 的 kernel 与 source-controls 均实际成功。kernel 原始完整日志中，qualifier 与独立 replay 的两次 `full_replay_verified` 摘要一致：11 次 Lean invocation、66 个 positive target、10 个 exact-negation certificate。RESULT SHA256 为 `4bfefb9b8f827c9b2c3c693789d887606010efc0ccf20a5ee42c3da2eb072ceb`。算法候选称 v12，冻结的协议标识仍为 `seven-shared-acceptance-v10`。

kernel artifact `13390875937` 的 ZIP 为 6,561,849 字节，SHA256 `1ff1bf0e18edf8c6a8d743ebae5939a1d61eea637a96692e4906df679f1fddff`。82 个文件、共 26,456,122 字节均安全解压并完整回读。独立字节审计逐项核对 11 个阶段的源码、olean、stdout/stderr、start/finish 和父模块哈希绑定，以及实际子进程退出、完整流和清理字段。[KERNEL_RECEIPT_BINDING_AUDIT.json](KERNEL_RECEIPT_BINDING_AUDIT.json) 记录该审计的范围。采集方没有重新运行 Lean、源码重建或语义 replay；两次实际 replay 成功来自原 CI 日志。

source-controls artifact `13389633139` 的 **49 项全部实际通过**，原 46 个 ID 完整保留、新增 3 项，0 failure/error/skip/loader error。预期清单已在下载 artifact payload 前由冻结 workflow 静态提取并登记。排序后的 collected IDs 与 expected 清单相等；collected、started、finished 三份执行序列相同。expected 本身按 ID 排序，不要求与原执行顺序相同。源码 commit/tree 与 clean 状态前后相同。内部 elapsed 为 `159.125206367 s`，这是测试子过程时间，不是完整 workflow 成本。

## 原生回归与可选未执行项

mandatory native NDU 工作流 [41971915895](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915895) 的 job `127061903108` 实际成功，从 `2026-11-05T05:06:50Z` 至 `2026-11-05T05:44:42Z`，API 秒级 envelope 为 2272 秒。原生集成与 regression 步骤的 API envelope 为 1658 秒。详细输出重定向到清单中列出但未下载的 artifact，本目录不补造其完整测试数量；job 成功也不证明 round2 的 432-episode 动态任务已取得净收益。

另一个 optional job `127065564208` 的冻结条件为 `${{ github.event_name == 'workflow_dispatch' && inputs.run_native_ndu }}`。本次事件为 pull_request，实际 0 个 step，结论是未执行；它与上述真正运行的 mandatory native NDU 分开计数。采集方没有 dispatch 或重跑任何工作流。

six-outcome 工作流 [41971915894](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915894) 实际成功。原日志打印 `Ran 410 tests in 288.876s` 后为 `OK`。这些原生 reference/hostile controls 不等于尚待执行的正式 16-cell 模型队列。

17 个硬件与 ABI job 的逐日志审阅在 [硬件执行表](hardware-review/README_ZH.md)，原始 JSON 带具体行号和哈希。它覆盖 1 个 standalone Linux AArch64、7 个 ABI、7 个真实上游 C++、2 个 captured-C job，共 856,758 字节原始日志。OS/架构、编译与执行事实来自实际日志及 step 结果，matrix 标签仅作索引。captured-C 细项输出被重定向到未读 artifact，case 数和完整 receipt 保持 null。Rust 1.90 是这些旧参考/互操作 lane 的角色，不改写为 AOT/NDU/Agent 科学实验的 Rust 1.95。该表不证明 host-region 恢复竞争、DMA、MMIO 或所有并发交错。

## CI 成功与桌面失败分别保留

同树桌面 v12 的原 outer exit 为 **124**，耗时 `600.049994673 s`。11 个 Lean 阶段通过，内层 RESULT 在 `550.561070862 s` 写为 passed，但内置 evidence replay 未在 600 秒外层预算内结束。因此原完整验收仍失败。

之后独立 replay 以 exit 0 完成，耗时 `61.189014082 s`；它是单独观察，不追溯升格原运行。CI 独立环境成功也不识别两个环境之间的单一因果因素。精确公开 observer 原件在 `cross-evidence/PROOF_V12_OBSERVATION.json`，绝对 Unix 纳秒保留原 decimal strings。

15 分钟 job、600 秒 qualifier、600 秒独立 replay、540 秒新进程启动预算及每个子过程 60 秒预算均不变。540 秒是 launch budget。kernel RESULT 的 `294.573688317 s` 只覆盖内层 RESULT 写入之前的工作，不包括后来内置 replay；不得当作完整 qualifier 墙钟。

CI 的 API 时间分辨率为秒。step 与 unittest 时长嵌套在父 job 中，多 job 可以并行，不把它们再次相加成端到端耗时。桌面内层也已包含在失败 outer 中，后续 replay 独立列账。采集、人类审阅以及完整研发总成本未完整测量，保持 null，不解释成 0。

## 证据完整性与公开范围

全部 101 份日志共 **7,164,392 字节**，与 GitHub App 返回的 decoded content 逐字节相同。这验证的是返回解码文本，没有声称保留 GitHub 服务内部的压缩传输字节。逐项尺寸和 SHA256 在 [JOB_LOG_INVENTORY.json](JOB_LOG_INVENTORY.json)。

artifact 清单共有 25 份、138,864,136 ZIP 字节。实际仅下载并回读 shared 的 2 份；其余 23 份只保存元数据，不写成已下载或已独立验证。新 kernel upload 步骤保留了这次阶段证据；旧 head 缺少 kernel artifact 的历史事实不变。

两份 `*.download.tool.json` 原始响应含临时签名下载 URL，保留在本地原始采集目录，明确从公开 payload 排除。其尺寸、SHA256 和排除原因在 [PUBLIC_SCOPE.json](PUBLIC_SCOPE.json) 中。公开集合使用过滤后的 metadata、原 ZIP 与哈希；没有修改原日志或 artifact 字节。

语义 replay 仍需要精确源码 checkout 和 pinned Lean/tool support。kernel artifact 记录了 258 项源码与 780 项 tool-support 身份，但未包含全部外部依赖，所以不承诺仅解压 artifact 即可独立 replay。这里的独立审阅只检查原始字节和回执绑定，不声称重新证明了所有语义。

共享证明范围仍是窄 Core syntax connection，权限保持 **DENY_ALL**，12 个生产 refinement 义务全部 open。行为组合是另一个独立条件，已由 root 启动且其终态不在本 CI 观察中；其中强 AOT 与正式 Agent 队列也必须分别引用自己的实际结果。本目录不宣布七项条件全部关闭。
