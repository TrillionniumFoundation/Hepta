# 已完成 CI 的只读归档

- Run：41017484010，attempt 1，completed / success。
- Source：`1c13caeb08993fcbb2c4d64e6b10f22f3356c18f`。
- 原 artifact：12960198980，ZIP 62118935 字节；下载 SHA256 与 GitHub API digest 完全一致。
- 保留内容：3696 个原始成员，220280134 字节；最终 tar.xz 为 7583496 字节。
- 校验：安全相对路径、无重复路径、仅普通文件/目录；写入前和重新打开磁盘归档后，各逐项复核全部 3696 成员的原始长度与 SHA256。
- 未保存 ZIP 或展开树；签名下载地址未写入文件。tar 的 uid/gid/mtime 归零，原 ZIP 元数据保存在 manifest。这里保留原始成员字节，不声称保留原 ZIP 容器的逐字节可重建性。

## 读取到的 CI 结果

| 结果 | 原始 artifact 记录 |
|---|---|
| 注册安全检查 | 277/277，35 个登记能力，source_stable=true |
| 回归测试 | 354 tests，0 failures，0 errors，0 skipped |
| 标量 lowering 证明 | 449/449 verified，unknown=0，refuted=0 |
| Factorial controls | 35/35，model_requests=0 |
| Structured node controls | 9/9，model_requests=0 |
| v6 profile controls | 3/3，model_requests=0 |
| v8 native references | 19/19，model_requests=0，model_qualified=false |
| v9 native references | 19/19，model_requests=0，model_qualified=false |

标量证明只覆盖登记的有限 lowering 形状及其选定内部实现的类型化输入域，不是完整语言或任意后端正确性证明。参考控制属于人工答案/工程接口验证，不能计作实际 Agent 成功、模型容量或资格通过。本次归档没有运行模型、native 程序、基准或新的 CI，也不覆盖单独登记在源码 60df 上的实际模型实验。

## 摘要

- 原 ZIP SHA256：`5e47b8df8b25e55b967b77c565bfbb087c989697ba15cd57155a9aea70edc015`。
- tar.xz SHA256：`535ab70d835bc493f1c97cf5e1213f96905475ad52e38b14c8d0351c7ccdca9c`。
- 完整成员 manifest SHA256：`d93a9c7bb24b6121561a49876cef6c2249a3ae0143095a650e3fe69e6a84d324`。
- 机器可读范围、源记录、成员摘要与局限见 `ARCHIVE_SUMMARY.json` 和 `artifact-12960198980.manifest.json`。
