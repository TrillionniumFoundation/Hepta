# 699de39 官方 full release：完成且原始内容核验通过

**官方 workflow 和四类实际报告均已通过。** 本次核验绑定公开源码
[`699de39a8e92e0f083df316ecc5333fb3ecf8571`](https://github.com/TrillionniumFoundation/Hepta/commit/699de39a8e92e0f083df316ecc5333fb3ecf8571)，
tree `592b6114f659fb18b13ad3fa5ed5e213ecdb92b5`，
[官方 run 40862645318](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40862645318)。
工作流于 **2026-10-29 08:49:40 America/New_York（12:49:40 UTC）** 更新为 completed/success。
本次下载、读取和审计没有运行新的编译、native artifact 或测试。

| 实际报告 | 当前源码上的结果 |
| --- | --- |
| Release candidate | **50/50 gates**；完整 Python 发现 3,628，原 verbose 日志逐方法全部 `ok` |
| Standalone HIA | **37/37 gates**；原 `unittest -q` 日志为 3,628 / `OK`，无逐方法 ID 日志；Rust 88 tests / 17 harnesses |
| HIA/NDU pipeline | **9/9 gates**；focused 201 methods 全部 `ok`，Rust 88 / 17；科学增量与全阶段关闭仍为 false |
| Integrated | **8/8 gates**；原 verbose 3,628 方法全部 `ok`，Rust 88 / 17；47 groups / 119 modules 完整覆盖 |

Candidate 与 integrated 的 3,628 个实际方法 ID 集合完全一致；NDU 的 201 与 safety 的 95 均为子集。
三处 Rust 运行各为 88 tests / 17 harnesses，原 harness 记录的 failed、ignored、measured、filtered 全为零。
这些重复运行、子集、覆盖组和审计检查不相加为新的语言测试分母，也不代表独立 Agent 任务。
Python 的原终态和逐方法记录没有 failure、error、skip、expected failure 或 unexpected success。

## 原始字节与可恢复性

官方 artifact **12898133203** 已完整取得：

- 原 ZIP：**344,601,243 bytes**。
- 官方 SHA-256：`0bd04d40b4a88be8f244d93d6adfb6460680ddc0b1c03e4524c9a02c6bbb613e`，与实际下载完全一致。
- **7,619 个成员 / 1,126,190,514 展开字节**，逐成员读至 EOF 并通过 CRC，完整 inventory 保留路径、长度、SHA-256、Git blob、ZIP 内模式与压缩长度。
- **83 个顺序原始分片**保留完整 ZIP 字节，前三类数据或历史失败均没有被删除；每片身份及偏移见 [raw-parts.json](raw-parts.json)。

`metadata-archive-receipt.json` 与 `metadata-retention.json` 绑定较小的审计资料归档。该归档保留当前四份顶层报告、207 次已验证引用所对应的原报告/日志、327 个方便核验的原 ZIP 成员副本、四个实际 NDU binary/build receipts、完整原 inventory、原 Git 源码绑定、逐方法状态、审计程序与其执行记录。完整官方 ZIP 的历史成员和未单独复制成员仍在原始分片中。

通过 GitHub API 取得的完整 job 日志以解码后的 UTF-8 字节留存；未将临时签名下载地址纳入公开材料。
原 ZIP 成员经过十类有限凭据模式扫描，无命中。扫描对成员字节执行，不递归解释内部压缩格式，不构成普遍无凭据证明。

## 来源范围与真实限制

四套 producer 的源码库存范围不同，均按其实际规则复核，未混称为相同分母：

| 报告 | 其实际源码库存 | 独立复核 |
| --- | ---: | --- |
| Candidate | 2,111 files | 完整声明路径集与 raw Git 699 匹配，前后相同 |
| Standalone | 2,111 files | 完整声明路径集与 raw Git 699 匹配，前后相同 |
| NDU | 758 files | 完整声明路径集与 raw Git 699 匹配，前后相同 |
| Integrated | 全部 4,385 tracked files | 与完整 raw Git tree 匹配，前后相同，原报告工作树为空 |

Integrated 记录 **440 条外部输入**前后相同。其中 **8 条**有实际 ZIP 成员可重新核验字节，**1 条**对应公开源码，其他 **431 条**保留原记录身份。原 workflow 没有上传所有外部 compiler/toolchain 或上游源码本体，本次没有重新取得它们，不把原身份记录升级为独立重建。

四个 NDU profile 的不同原 commit、实际上传 binary 和 receipt 均匹配；原 `DENY_ALL` / 未激活生产边界保留。源码原 Git 绑定、完整 before/after 与每项限制见 `audit.json`，简要状态见 [summary.json](summary.json)。

原 ZIP 中明确选定的当前路径为 **5,136 成员**；另外 **2,483 历史或其他上传成员**保持原字节和原语义。没有将它们改标为当前源码执行结果。前两次离线审计开发尝试分别暴露了 planned-gates 的 list/int 和独立日志引用的 dict/string 解析假设，原程序与失败输出保存在 `auditor-development/`；这些属于审计器开发记录，不是 CI 或语言测试失败。

**严格 P0–P7 仍为 OPEN。** 当前有限 qualification 不建立全语言健全性、Rust 生产权威、完整一般内存/生命周期/ABI、代表性 RSS/物理设备或完整 backend refinement。此官方执行有自己的时间、主机与原始记录，不是已被工作区维护移除的旧本地运行的重建。
