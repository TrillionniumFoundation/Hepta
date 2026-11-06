# 历史研究测试范围审计

## 结论

`tests/test_core_seven_shared_sources.py` 没有变空。对比提交 `5ee6d8fec0e5c72d87a36dbed60789de211abf1b` 有 43 个 test 方法；S3 `996e2626d9aa89bc0e2b1017ebb858c6666604e7` 与当前冻结 `0a06ef4f0894681af92b0caefba0704c1278d2cc` 都有 40 个，该文件字节完全相同。共同的 40 个 test 方法 AST 全部未变。

5ee6 **不是 S3 的祖先**，两者 merge-base 为 `f2b76f5741c83822be2e12cf5a50b50a8d27b96a`。这是两个优化分支之间的差异。S3 改用整段 possessive tokenizer 与局部 Raw DAG 解码缓存，撤回了 5ee6 的 strict flat-decimal 路径；同时新增另一文件中的 10 个差分、缓存和对抗控制。因此不宜写成“在 S3 线性提交中清空或删除整个测试模块”，也不能声称“全部历史测试原样保持”。

| 项目 | 5ee6 | S3 / 当前冻结 |
| --- | ---: | ---: |
| shared source 文件字节 | 52,430 | 42,151 |
| shared source test 方法 | 43 | 40 |
| structured source cost test 方法 | 文件不存在 | 10 |

新 10 个控制的文件 SHA256 为 `ed11be42fc5cfc51c514a4e14f4bb918508371c09b200f0b6c5d449f0ab6050f`，S3 与当前相同；它被 CORE_TESTS、proof source inventory 及专门 GHA 研究任务显式登记。历史 S3 的实际 CORE 逐 test ID 关联见 JSON 报告。增加的测试数不能自动抵消不同语义域的覆盖缺口。

## 三项不再原样保留的控制

1. `test_actual_data_fast_paths_keep_full_verifier_outputs`：原来对全部五个实际 structured certificates 使用独立旧 parser/Raw 转换逐项对照，并检查 flat-decimal 命中次数。当前的小型更改树测试及 DAG 对照是相关覆盖，不能写成同一个全实际输入 differential。
2. `test_raw_string_domain_and_subclass_reads_match_original`：当前保留基本 Raw 字节域和部分 int subclass 拒绝检查，但没有原来的动态 Raw subclass 属性读取、恶意 metaclass 回调和容器 subclass 完整控制。
3. `test_strict_subgrammar_and_legacy_fallback_match_original`：旧 flat-decimal 分支已撤回。新测试扩大有限字符串、别名及长空白拒绝检查，但没有原样保留 TextSubclass hook 控制。测试名中的 complete 不构成全 Python 对象域定理。

## 可具体指出的静态语义差异

删除的 ChangingRaw 控制包含连续三次 `.value` 返回 `[65]`、`[34]`、`[67]` 的情况。独立旧谓词在第二次读取见到禁用的引号字节 34 后拒绝，不进行第三次读取。当前 `_raw_value` 在第二次读取仅检查整数类型，随后 `bytes(raw.value)` 进行第三次读取，得到合法的 `[67]`，据源码推演会返回 `C`。

**这是静态代码推演，本审计没有执行测试。** 它说明历史 Python subclass / 动态读取语义不能被宣称完整保留。实际 verifier 从源文本内部构造精确的私有 `_Raw` 对象，本审计没有据此推断序列化候选可利用、Lean kernel 验收失败或任意原生代码不安全。

## 交付边界

当前冻结源码保持不变。本轮只能明确主张 S3 注册 CORE test ID 的保留及其真实执行状态，另列上述跨分支覆盖差异。如果后续要声称全历史 helper 语义等价，应先明确并约束允许的对象域，或恢复旧 subclass/read 行为及对应控制，并补回全部实际证书的独立旧算法对照。任何修复都需要重新冻结统一组合并完成相应验证。
