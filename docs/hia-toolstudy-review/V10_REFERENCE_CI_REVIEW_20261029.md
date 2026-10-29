# V10 reference-only CI 接线独立静审

审查对象为统一提交 `0a775624da16be08fee95c493fe74da1d76817e4`（tree `91aac5c4247b15ee2b3b469cb24bb9804c86e580`）相对 `6d3ead8816a3b671dac70fb24b8c9d73c7cd8b59` 的六个接线文件。**未发现阻止该接线的实质问题。** 同一提交中的进度 ledger、中文报告及随后远端 CI 结果不在本次审查范围。

wrapper 的精确代码差异只有有限 selector 增加 literal `v10` 分支，以及 CLI choices 增加 `v10`。默认值仍为 `v8`。独立 AST 比较确认 `source_bindings`、`clean_source`、`registered_cells`、`tool_identities`、`boundary`、`native_observation_passed`、`evaluate_reference`、`run` 和 `digest` 全部不变。

选定 support 模块仍作为显式参数传给来源、注册项、session、snapshot 和各次身份边界，没有模块全局 rebinding。返回记录绑定 selected version、其 protocol schema 和实际 protocol digest。三个 profile 继续使用原 reference builder 与 validation/evaluator，并保留原 public compiled/native/resource/VM 门及 terminal hidden 门。

V10 support 在该入口仅读取本地协议及来源元数据；该入口不调用 `check_model`、不构造 engine、不执行 capacity/generation，也没有模型或 tokenizer 参数。引入模型/template 元数据绑定不能被写成模型装载、容量合格或 Agent 成功。CLI 输出目录为三个不同的 `agent-tool-native-references`、`agent-tool-native-references-v9`、`agent-tool-native-references-v10`，均在 checkout 外。

三个原有 mock 控制组按 V10/V9/V8 顺序覆盖选定协议、禁止回退 V8 的 source binding，以及 selected session 配合原 validator。producer development log 显示 16/16、0.265 s、OK；本次仅核对日志并保留 hash，没有重跑。不能把这份 development log 描述成新的远端 native 或来源冻结后的独立执行结果。

两份 workflow 与统一 inventory 只增加 V10 路径触发、其 13 项静态/mock 控制模块、来源目录和第三组 19-reference CLI。全部冻结 V10 文件与 `11d6f78c6c01f66978af7fcf4d40eea7dae5d5f0` 逐字相同。当前统一树自身的远端 native 结果必须等待实际运行记录；旧提交的 green 不能继承给它。

本次 reviewer 执行量为 production-module imports、tests、native、model、tokenizer 均 0。六文件完整 patch、冻结文件 hashes、producer development log 与独立 receipt 保存在 `experiments/hia_next_safety/toolstudy_v10_review_20261029/ci_selector/`；patch SHA256 为 `760236b46b0009b03ee2179022d41b69e60e9ca9dd519ba6dbe095522e120746`。

V10 容量阶段的 conditional ALLOW 与 qualification/main HOLD 仍按先前 `250e9820ee82fce5c6468c17b67b7f535aac0bb3` 记录；这次 CI 接线审查没有扩大该决定。
