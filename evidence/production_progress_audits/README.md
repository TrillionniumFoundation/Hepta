# 本轮历史资格、调试失败和环境前置条件

本目录保留最终统一冻结之前的实际运行记录。它们来自不同的编译器／工具
快照；不能把旧报告的成功当作修改后的资格。最终整轮入口是
`../production_progress_final/`。每个原始文件的路径、长度和 SHA-256
都记录在 `manifest.json`。

- `integration-unit-attempt1.log`：初次整合后的 896 项测试通过、零跳过。
- `order-integration.log`：赋值顺序和后续 Copy 字段修复合入后，103 项针对性
  编译器／IR／原生后端／调试构建回归通过、零跳过。最终完整测试另行计数。
- `debugger-attempt1..5.json`：早期资格样例效果声明、不可独立设断点的函数
  epilogue、C 后端集成状态和 C 多行扩展行号漂移问题，以及最后两后端
  实际 GDB 成功。早期失败没有被删除或改写为成功。
- `native-host.json`、`memory-proofs.json`、`concurrent-attempt1.json` 及图：
  相应工具首次实际执行；后续证据验证器／求值顺序修复后仍须重新资格。
- `execution-prerequisites.json`：2026-10-25 实际进程环境复查，只检查明确
  要求的凭据是否存在，不记录值；API 域名解析失败，无 TLS／HTTP／模型
  请求。可见 GPU 和串口板卡路径列表为空，未操作设备。

源码求值顺序与报告验证器的独立 before/after 反例另见
`../audits/resource_evaluation_order/`、`../audits/concurrent_ir/` 和
`../audits/native_evidence_tools/`。非法所有权候选没有作为原生 C 执行；
不存在可宣称的 ASan 崩溃测试结果。

应用基准的早期报告另以 `.json.gz` 保留原始 JSON 的无损压缩。索引的
`sha256`／`bytes` 对应解压后的原字节，`stored_sha256`／`stored_bytes`
对应实际压缩文件。使用 `gzip -dc 文件.json.gz` 可查看全部原始样本。
这些性能报告来自开发分支，不能替代最终集成源码上的重复资格。

此目录没有真实 AI 模型试验、物理板卡或 GPU 资格。
