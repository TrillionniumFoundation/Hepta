# Hepta 七线交付证据

这是 PR #644 的配套证据分支；源码及其固定组合与证据提交分别记录。完整交付报告仍在生成，尚不宣告七项目标全部关闭。

- 实现 PR：https://github.com/TrillionniumFoundation/Hepta/pull/644
- 独立证明研究 PR：https://github.com/TrillionniumFoundation/Hepta/pull/648；最新完整接受运行在 Part03 超时，未被接受。
- 当前确切源码的原生 CI 证据：`../hia_seven_native_ci_final_20261104/`。17 个原始 ZIP 均校验了大小与 SHA256；1,983 个文本和源码成员完整保留，150 个二进制成员保留原始大小和哈希索引。
- 旧版失败 CI 的完整回归日志：`../hia_ci_failure_review_20261104/`。1,777 项测试中的旧源到 Core 回执兼容错误保留原样，后续修复不会改写这次失败结果。

`PROVENANCE.json` 给出原始测量提交、发布投影提交及确切 Git 树的映射。发布投影的提交号不作为本机测量提交号使用。后续提交将加入完整组合、原始历史 bundle、性能与 NDU 成本、Agent 试验和终态报告。
