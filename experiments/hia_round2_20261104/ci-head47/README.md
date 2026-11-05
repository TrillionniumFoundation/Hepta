# head47 历史 CI 证据

本目录固定记录 Hepta 公开提交 **47c9935d4d1406f6697810d23d45cb3b45c3b950** 的 CI。它与原始 runtime 提交 **b47ce924c5941b42448e9da0b07a2bcedaf75d1f** 具有相同 Git tree：**69cd887f7a2a56de62c6b074bea9fca717d01355**。这是保留失败的历史候选观察，**总体 CI 未通过**。

## 完整性与终态

- 11 个 workflow runs：10 个成功，1 个失败，0 个仍在运行。
- 102 个 jobs：26 个成功，75 个失败，1 个跳过。早期只有 101 个 jobs 的快照原样保留；后出现的可选作业使最终分母变为 102。
- 101 个实际执行 jobs 的完整 decoded logs 均已保留，共 **6,803,834 字节**。每份日志逐字节等于保存的 GitHub App 工具 content；各原始工具回执、日志 SHA256 和失败分类在 [JOB_LOG_INVENTORY.json](JOB_LOG_INVENTORY.json)。
- run 列表的第一页实际返回 11／total_count 11，第二页返回 0；每个 run 的 jobs 与 artifacts 请求均返回其全部 total_count，最大 jobs 页为 75／100。
- 24 个 artifacts 已取得完整清单。**实际只下载、校验了 source-controls artifact 13385123248；另外 23 个仅有清单与 GitHub digest**。不能把清单当成已恢复的原始结果。

机器可读总表为 [CI_READOUT.json](CI_READOUT.json)，终态原始元数据为 [snapshots/0004-TERMINAL_METADATA.json](snapshots/0004-TERMINAL_METADATA.json)。此包不触发或重跑任何工作流。

## 75 个失败作业与后续本地修复

[初始化前沿 run 41961216397](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41961216397) 的完整日志显示：普通组 1 个作业止于 `AssertionError: test inventory changed`，74 个 isolated 作业全部止于 `AssertionError: isolated test inventory changed: sources`。失败发生在建立清单时，不能报告为这些测试已经执行后失败。

独立固定源码审计发现，该 head 缺少 workflow 声明的 39 个测试模块中的 31 个。所有 isolated 作业都会先加载同一个 sources 清单，因此共同遇到同一个缺依赖问题。后续从完整历史提交 `0ab0c441d9d115f9288f18707a117506369b93ff` 精确恢复 45 个缺失文件；9 个既有但不同的实现保持原字节。恢复提交只另加六行真实 loader.errors 报告／拒绝，所有旧计数、分片、ID 和 180 秒限制均保留。

本地最终修复提交 `bb295ac7404efadf91c641a55b37b33d2d22a2bd`（tree `103794d798aecf8568d4ccd14f02524057b51b29`）上：

- 普通 207 个与 isolated 705 个完整 ID，以及全部 74 个分组分配，与历史清单逐项相同；没有 loader.errors 或 _FailedTest。
- 实际执行普通 207 项及 sources 16 项，223 项均通过，无失败、错误或跳过；每项都有开始／结束记录，提交保持 clean。
- 两个子命令分别为 109.536181761 秒和 157.852429773 秒，均低于原 180 秒上限。总 driver 为 267.416112565 秒，已经包含这两个子命令，不能重复相加。
- **其余 73 个 isolated 分组未在本地执行。**下一精确提交的真实 CI 仍是完整执行门槛，不能用 collection 或这两组结果代替。
- 修复另增加一个 `if: always()` 的 kernel artifact 上传步骤，仅指向 `${{ runner.temp }}/core-syntax-proof/`，名称绑定 head／run／attempt。它不会改变旧 head47 已缺失的 kernel artifact。

本地修复摘要在 [cross-evidence/CI_REPAIR_LOCAL_OBSERVATION.json](cross-evidence/CI_REPAIR_LOCAL_OBSERVATION.json)。该摘要指向单独保留的 runtime 原始证据；**本 CI 包不包含本地修复的完整原始测试目录**。其 Python open 观测缺少 dir_fd，部分相对临时文件名不能被当成已证明的缺失仓库文件；这个局限与“其余 73 组”命名更正都明确保留。

## shared proof 与 source-controls

[shared run 41961216283](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41961216283) 的 kernel 与 source-controls 两个作业都实际成功。kernel 完整日志保留两次相同的 `full_replay_verified` 摘要，分别来自完整 qualifier 与后续独立 evidence replay；均绑定上述 head/tree，RESULT SHA256 为 `ae661bd98768c750372f3e903967bc4e06d7a5facab4215914f1fc45cfe4bb03`，包含 11 个通过阶段、66 个 positive targets、10 个 exact-negation proofs。

冻结协议仍保持 600 秒 outer、540,000,000,000 ns 的 launch budget、60,000,000,000 ns 的单进程 budget、2,000,000,000 ns 的 cleanup budget，以及 15 分钟 job 上限。启动预算不应被误写为整个观察的总耗时。所核对的精确 head 源码和预算相等控制已保存在 source/。

**该 head 的 kernel job 没有 artifact 上传步骤。**完整 job log 与摘要已保留，但 CI 没有可下载的完整 proof 目录，因此此包不能提供该 CI kernel 原始目录的独立 replay 保证。source-controls 唯一 ZIP 则已下载、GitHub digest 比对、解压校验，包含原始 RESULT.json、stdout、stderr；ZIP SHA256 为 `cab66cc26b291ce376798eb863bbd34d4b2a6735830766e36a3fdf7730e032e5`。

43 项 source controls 满足 `sorted(collected_ids) == expected_ids`，且执行顺序满足 `collected_ids == started_ids == finished_ids`；四个列表的原始顺序并不全部相同。失败／错误／跳过均为 0。内部观察为 210.023122996 秒，不能再与包含它的 CI job 时间相加。这些 controls 没有新 Lean 调用，也不授予 production admission。

全部 shared 结果仅覆盖窄 Core syntax connection；12 个更广泛 production refinement 仍未证明，授权保持 **DENY_ALL**。

## 同 tree 的 desktop 失败仍然保留

同 tree 的原始 desktop v10 完整 qualifier 观察为 **outer exit 124，600.079463180 秒**。11 个新 Lean 阶段通过，内部 RESULT 在 558.870179933 秒写入 passed，但完整 qualifier 的内置 evidence replay 尚未完成。后来单独 replay 为 exit 0、73.055962129 秒。后者和 GitHub CI 的成功都不能追溯把原完整超时改为通过。

这些是不同环境中的独立观察；本报告没有推断单一环境因素就是耗时差异的原因。公开原始观察和 same-tree 身份元数据在 cross-evidence/ 中。

## 实际原生 NDU 与可选跳过作业

[verified-native run 41961216118](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41961216118) 实际完成，job 127027766554 成功。API 给出的开始／结束为 03:22:48Z 至 03:57:59Z；native regression step 实际为 03:25:33Z 至 03:50:57Z。它执行了真实回归，而非一直排队。API 时间为秒分辨率，step 时间嵌套在 job envelope 内。

另一个 job 127029829597 来自 closure workflow，名称为 “Optional original native NDU qualification”。冻结条件精确为 `${{ github.event_name == 'workflow_dispatch' && inputs.run_native_ndu }}`，而本次事件为 pull_request，因此它实际 skipped、steps 为空。它**没有执行，也不是测试通过**；不能与上述独立必需原生作业混同。

作业成功仅表示该 workflow 声明的门槛通过，不能推导 NDU 净收益、所有代码超越 Rust，或任意 C/C++ 迁移能力。最终硬件／ABI 执行表应从下一提交的真实 jobs、日志和 receipts 提取；matrix 声明本身不算执行证据，也不授权 DMA 或所有并发交错结论。

## 公开归档范围

原始签名下载响应 `artifacts/13385123248.download.tool.json` 保留在原 scratch 目录，**从公开包排除**。公开版本仅保留 artifact ZIP、原始三个成员、hash、审核及过滤后的下载元数据。具体排除项与原文件 hash 见 [PUBLIC_SCOPE.json](PUBLIC_SCOPE.json)。

本目录的实际日志与回执没有被采集者改写。独立审阅时的解析假设失败也作为报告准备记录保留，与 CI 失败、qualification 失败分开。最终同源 composition、最终组合 AOT、16-cell Agent 正式队列与新 head CI 均保持 pending，不由本历史包宣告关闭。

## 恢复已保留的归档成员

下载本目录文件后，在该目录运行：

```sh
python3 RESTORE.py --target restored-head47
```

目标目录须尚不存在。该命令校验每个分片、整体归档、每个成员和恢复后的文件；本包已对293个原件完成实际恢复验证。它只恢复 MANIFEST.json 所列的字节；旧 kernel 未上传的证明目录及另外23个仅列清单的 artifacts 不在可恢复范围内。

## 原v10绝对时间戳更正

上级 [PROOF_V10_EPOCH_PRECISION_CORRECTION.json](../PROOF_V10_EPOCH_PRECISION_CORRECTION.json) 保留原根元数据中三个绝对Unix纳秒字段经JS Number舍入的更正，正确绝对值使用decimal strings。所有耗时间隔、退出码、SHA与结论不变，原始observer与raw stdout保持精确。旧文件与本归档保持原字节；本包未重新压缩。
