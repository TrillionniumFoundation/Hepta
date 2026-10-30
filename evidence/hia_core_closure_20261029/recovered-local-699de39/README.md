# 当前 699de39 本地原始证据恢复

本目录把工作区维护清理前已上传的四个 Git blob 挂到公开 evidence 分支。四片已重新实际下载，逐片 bytes、SHA-256、Git blob 以及顺序拼接的整体 SHA-256 全部吻合。它们是第二份原归档的原始字节。

- 源码：`699de39a8e92e0f083df316ecc5333fb3ecf8571`。
- 整包：16,084,731 bytes，SHA-256 `5f460c4e1e2165b1752d4cc6c5143ef86d483459e7697043573a715ee66da0a2`。
- 恢复观察：2026-10-29 20:56:34 America/New_York（原始机器记录为 2026-10-30 00:56:34 UTC）。
- 有序分片与完整身份：[anchor-manifest.json](anchor-manifest.json)；实际请求及哈希记录：[recovery-summary.json](recovery-summary.json)。

第二份归档包含两轮完整本地执行的原始记录、第二轮独立审计和更正后的 status v2。它没有包含首轮独立审计的 16 个文件，虽然其中一份旧 README 的范围文字说包含两轮审计；首轮审计完整原件已保存在 [独立公开的首轮包](../first-attempt-699de39/README.md)。该范围差异明确保留，不把第二包改称后续第三包。

第三包的 SHA-256 `9bcc40d851b7b6bc16ad7b11a9f6d27e2ed27afbf322463bc89d203159d53de2` 在上传中断后没有找到四个原 blob；当前没有恢复其原字节。新的检查不能重建旧的审计记录或冒用第三包身份。

按 manifest 顺序无损拼接四片即可恢复 gzip 原件；核验完整 SHA-256 后检查归档内容。归档保留其产生时的旧 CI 快照，不把快照改写为之后的状态。官方 run 40862645318 后来已完成 success，其实际原报告另行审核与保存。

这是原字节恢复记录，没有执行新的语言/native 测试。Python 生产权威、`no_change` 和 P0–P7 严格 OPEN 义务保持；文件可取回不构成全语言或全项目关闭证明。
