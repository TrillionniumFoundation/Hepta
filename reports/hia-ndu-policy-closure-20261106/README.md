# NDU 完整策略审计：原始证据与处置

本目录保存 2026-11-06 完成的 NDU 完整策略实验、独立审核和 source-bound CI 证据。
**当前候选处置为 NO_GO_FOR_EXCLUSIVE_GAIN_OR_PRODUCTION，`all_blockers_closed=false`；
保持 Draft、DENY_ALL，未授权生产启用。**

54 个冻结 profiles 的全合法历史和完整策略审计已完成；有限模型内的覆盖、求值、选择、
归因及证据链能够接受独立核验。研究结论和开放事项见
[最终结果报告](ndu-policy-closure-report.md)、[逐项 blocker 处置](blocker-disposition.json)
及[方法审查](METHOD_REVIEW.md)。本次自然状态没有显示动态数值偏好的额外行为收益，
普通 MPC 复制了观察到的全部任务价值；真实部署、独占净收益和完整跨平台 CI 的边界仍保留。

## 固定源码和历史边界

| 对象 | 固定身份 |
| --- | --- |
| 本轮执行源码 | `a07c5ecae52436234af370779cc440686dbe4139` |
| 本轮源码 tree | `273e7c458713ede9593c03267245a5bf756fc4f7` |
| 源码 PR | [Draft PR #761](https://github.com/TrillionniumFoundation/Hepta/pull/761) |
| 本证据分支 | `codex/ndu-policy-records-20261106`，唯一 parent 为上述执行源码 commit |
| 历史四关源码 | `78c0b951adc08b02be60d64b386620c5ac9faf99`，PR #758 |
| 历史四关证据 | [`e51de7a422988e69ddecaceba595e62b7d051507`](https://github.com/TrillionniumFoundation/Hepta/blob/e51de7a422988e69ddecaceba595e62b7d051507/reports/hia-ndu-four-gates-20261106/README.md) |

本证据提交只添加本目录，不修改源码。历史归档的原始结果、失败构建、审核和 CI 状态
继续由历史证据 commit 保存。它的约 86 MB 原始归档未在本目录重复上传；新旧实验保持
各自的源码绑定。原始完整源码仓库、模型权重和可执行文件不打入本次 raw archive。
原始构建收据和命令元数据保留在相应旧归档以及本次 hosted CI ZIP 中。

## 可直接阅读的报告

| 文件 | 作用 |
| --- | --- |
| [ndu-policy-closure-report.md](ndu-policy-closure-report.md) | 最终结果、解释、源界限与未闭合事项 |
| [blocker-disposition.json](blocker-disposition.json) | 机器可读处置；明确 `all_blockers_closed=false` |
| [policy-descriptive-summary.json](policy-descriptive-summary.json) / [聚合脚本](summarize_policy_campaign.py) | root 的描述性聚合，**不作为独立核验** |
| [independent-policy-review-v2.json](independent-policy-review-v2.json) / [独立审核脚本](independent_policy_audit.py) | 终轮 1,129,252 项独立检查及其原始实现 |
| [independent-policy-review-attempts.json](independent-policy-review-attempts.json) | 三轮审核的原脚本、报告、日志、字节数与哈希索引 |
| [NATIVE_FRAME_AUDIT.json](NATIVE_FRAME_AUDIT.json) / [原帧审核脚本](verify_native_frames.py) | 独立序列化、digest、调用区间和 source/input 身份核验 |
| [METHOD_REVIEW.md](METHOD_REVIEW.md) | 四关结案口径、2×2 因果干预、固定策略类和外推边界 |
| [new-ci-audit/AUDIT.json](new-ci-audit/AUDIT.json) / [CI 审核脚本](new-ci-audit/audit_ci.py) | 新源码 hosted feedback CI 的原始 artifact、日志、来源和全输出哈希核验 |
| [release-ci-snapshot.json](release-ci-snapshot.json) | 发布前全库 workflow 快照，保留排队和运行中状态 |
| [closure-ci-snapshot.json](closure-ci-snapshot.json) | 较早的全库 CI 快照，保持原样 |
| [combined-local-qualification.json](combined-local-qualification.json) | 本地 reference/native 资格测试分母与源码边界 |

独立审核首轮出现审核脚本的两项 schema 比较假阴性，原报告、脚本和日志完整保留，
后两轮修正审核后通过。它们没有改写正式 campaign，也没有被表述为生产实现的
RED-to-GREEN 修复。`independent-policy-review-attempts.json` 列出的全部三轮文件和
`additional_preserved_first_attempt_artifacts` 均以原文件名保存在本目录。

## 完整原始数据

| 归档指标 | 数值 |
| --- | ---: |
| 原始文件数 | 1,606 |
| 原始文件总字节 | 422,841,617 |
| `policy-raw.tar.xz` 字节 | 36,671,560 |
| 分片数 | 70 |
| 单片最大字节 | 524,288 |

完整 archive 的 SHA-256：

```text
b7041512487e9bfa94ec6d36b9d4523225a7556f5bbaf433034ac32efbf10e60
```

[policy-raw-manifest.json](policy-raw-manifest.json) 保留所有成员的原始路径、字节数和 SHA-256；
[policy-raw-parts.json](policy-raw-parts.json) 固定分片顺序及每片 SHA-256、Git blob SHA。
原始文件字节保持不变，仅 tar 容器的时间、权限及所有者元数据规范化。

恢复后的 archive 成员包括：

- `policy-final-v1/` 全目录，包括 54 个 profile 的图、状态结果、原生帧、attempts、成本账本、SUMMARY、REGISTRATION 与 RESULT；
- `policy-registration-final-v1.json.gz`、正式执行 stdout 和 stderr；两份 registration gzip 原字节分别保留，解压内容一致；
- `final-reference/`、`final-reference.log`、`native-final/`，包括 source-before/after 和原生测试、smoke、控制用例原记录；
- `combined-local-qualification.json`、`source-object-import-receipt.json`、`published-source-commits.json`、`progress-preflight.json`；
- `new-ci-audit/` 全部 7 个原文件，包括 2,914,149 字节的原 GitHub artifact ZIP、原 job log、原 API 观测与独立审核脚本及结果。

小型审核文件同时在目录中提供可直接阅读的副本；复制身份见
[READABLE_EVIDENCE_COPY.json](READABLE_EVIDENCE_COPY.json)。
[ARCHIVE_AUDIT.json](ARCHIVE_AUDIT.json) 记录归档前后原字节一致、逐成员核验和选择范围。
[FILE_MANIFEST.json](FILE_MANIFEST.json) 绑定发布目录内除其自身以外的每个文件。

## 从分片恢复并逐字节验证

在本 README 所在目录运行以下命令，选择一个尚不存在的输出目录：

```bash
python RESTORE.py --output /tmp/ndu-policy-evidence-restored
```

[RESTORE.py](RESTORE.py) 仅使用 Python 标准库。它按登记顺序读取 70 个分片，核验每片
字节数、SHA-256 和 Git blob SHA，核验完整 archive，再对全部 1,606 成员逐一核验字节数
与 SHA-256 后写出；拒绝已有输出目录、不安全路径、链接或未登记成员。

完整压缩归档写到 `archives/policy-raw.tar.xz`，原文件恢复到 `policy-raw/`，例如：

```text
policy-raw/policy-final-v1/RESULT.json
policy-raw/policy-final-v1/natural-profile-00/STATE_RESULTS.json.gz
policy-raw/native-final/source-after.json
policy-raw/new-ci-audit/pr761-ndu-feedback-a07c5ec.zip
```

已用该脚本从分片实际恢复全部文件，结果见
[RESTORE_VERIFICATION.json](RESTORE_VERIFICATION.json)。此验证没有重跑实验、原生二进制
或计时，也没有修改任何原始失败、排队或完成记录。

**字节恢复和科学审核／原生重执行有不同前提。** 审核脚本保留原执行时的绝对路径及输入
绑定。重新执行完整科学审核需要上述固定源码 checkout、相应原始构建输入／source-bound
receipt、历史文件以及明确的路径映射。原生重执行还需要登记的构建和运行环境。本目录
提供可移植的逐字节恢复与核验，没有宣称无条件一键复现原生部署。

## Hosted CI 的范围

新源码的 [feedback run 42205882393](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42205882393)
和 [job 127852267161](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42205882393/job/127852267161)
实际完成全部 14 个步骤。原 artifact ZIP 的 SHA-256 为
`22d2a19015f5fea82e62480c956c26d2a5cf437b5fadef509e16640d8739eda7`。
独立审核验证了 GitHub digest、37 个 ZIP 成员、36 个登记输出哈希及 9,105 个源码文件与固定
Git commit 的逐字节一致性。175 个 reference 与 16 个 native 测试交叠 7 个，合计 184 个唯一
测试，失败、错误和跳过均为零。

此 CI 结果对应有限资格测试和 2 个物理 smoke 请求；完整 54-profile policy campaign 的
本地原始 native 记录及独立审核另行保存。最新全库快照仍含运行中／排队工作，README
与结果报告均没有宣称全库所有 CI 通过，也没有将旧 attempt 的复用成功状态当作新执行。

分片写入时所有 GitHub 返回的 Git blob SHA 均与本地字节计算值精确一致，见
[原始 blob 写入收据](metadata/raw-blob-upload-checkpoint.json)。目录与 ref 的发布后核验
由单独的 publication receipt 记录；二进制 blob 的对象 SHA/树元数据核验与本地完整恢复
保持各自的验证范围。
