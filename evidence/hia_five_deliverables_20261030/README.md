# 五项交付的证据入口

实现代码锚点：`053d07045a06335011050277d3c563cf3ddefe70`。
完整解释见 [综合报告](../../docs/HIA_FIVE_DELIVERABLES_20261030.md)，
机器可读验收见 [ACCEPTANCE.json](ACCEPTANCE.json)。

本目录保留实际运行结果和失败尝试。实现检查通过不代表所有研究目标已成立：
第三方生产组件代表性、低成本迁移、NDU 相对同目标轻量控制的完整成本优势、
Agent 开发优势都没有通过本轮验收。安全结论仅限各自声明的 Core/profile，
不包含整个编译器、LLVM、操作系统或硬件的正确性定理。

## 证据与计量单位

| 入口 | 实际记录 |
| --- | --- |
| [integration/attempt03](integration/attempt03/) | 175 项测试，零失败、零错误、零 skip；冻结源及运行器 |
| [component](component/) | 两个配置、2,370 个输入；原 C++ 和独立 HIA 实现分别执行；完整 allocator 观察、负控和强 LTO 基线 |
| [call-expansion](call-expansion/) | 892 个语义输入、1,784 次 native 观察、38 个 VM 分配失败注入；实际产物和证明回执 |
| [语义合同](../semantics_contract_20261030/) | 独立冻结源上的 70 项合同回归 |
| [NDU 八臂](../../artifacts/hia-ndu-eight-arm-20261030/) | 原生执行与完整分项成本；精确 Q32 DP 和固定策略对照 |
| [NDU 数值边界](../../artifacts/hia-ndu-numeric-boundaries-20261030/) | 11 项自动门禁、12 次原生调用，包含两项预期请求拒绝 |
| [双模型复现](../../experiments/hia_five_deliverables_20261030/agent_replication/) | 24 cells、47 次请求、77,880 tokens；所有成功、失败和原始产物 |

这些计量不能相加成一个总测试数。`component/raw.tar.xz` 包含原始
`qualification.json` 和全部 79 个原始文件；`call-expansion/raw.tar.xz`
包含全部 47 个原始文件。各 `ARCHIVE.json` 列出逐文件 SHA-256、大小和
压缩归档身份；`ARCHIVE_VERIFICATION.json` 记录逐成员核验。

最终集成的组件外部门禁由 attempt02 的完整组件 qualifier 执行。
attempt03 的 `QUALIFICATION_SOURCE_REBIND.json` 逐字节确认生产、工具和组件
源码完全相同，没有把旧观察冒充新的执行。attempt01、attempt02 的错误日志和
源快照原样保留：分别暴露父进程 `dlopen` 文件描述符路径缓存问题和不支持 `u64`
的观察 helper；最后使用独立、有资源上限的 64 位 child。

## 校验已保存证据

在仓库根目录运行：

```sh
python evidence/hia_five_deliverables_20261030/VERIFY.py
```

该命令校验 `EVIDENCE_FILES.json` 中所有证据的大小和 SHA-256，不执行归档内二进制，
也不会把历史性能重新解释成当前主机性能。manifest 自身不自包含；其身份由包含它的
Git commit 固定。归档的成员校验报告与压缩容器哈希共同保留。

七臂、八臂 NDU 证据中的 `drift-probe.json` 是实际输入漂移负控，末尾空白是
刻意制造的不同原始字节。它们会触发 `git diff --check` 的空白提示，不能为通过
样式检查而清洗历史证据；程序、测试、workflow 与文档的空白检查另行通过。

## 重放最终集成与组件资格

需要 Linux x86-64、Python 和 `z3-solver==4.13.4.0`、Clang/Clang++ 20、LLD、
GCC/C++ 标准库，以及按原构建身份提供的 native NDU。NDU 源 pin 为
`hepta-private-ci@c4a1bbed3a39beba43a6abf1a18b6f75c5725c21`。
运行环境需要允许本任务创建本地 Unix socket 并读取自有子进程 `/proc` 身份；
不应删除这些检查来适配受限执行器。CI 中的原生构建步骤见
[原 NDU workflow](../../.github/workflows/hepta-verified-optimization.yml)及
[CI 说明](../../docs/INTELLIGENT_ASSEMBLY_CI.md)。

在**新的**运行目录内创建 `source/`，把 `integration/attempt03/source.tar.xz` 的内容
解压到这个 `source/`。把同目录的 `SOURCE_MANIFEST.json` 和 `RUN_TESTS.py` 复制到
新运行目录的顶层。不要在原证据目录
上运行或覆盖历史 `RESULT.json`。配置实际工具路径：

```sh
export CLANG=/absolute/path/to/clang
export CLANGXX=/absolute/path/to/clang++
export HEPTA_CLANG="$CLANG"
export HEPTA_NDU_IDENTITY=/absolute/path/to/original-native-identity.json
export HEPTA_NDU_STREAM_IDENTITY="$HEPTA_NDU_IDENTITY"
python /new/run/RUN_TESTS.py
```

运行器会新建 `tests/`，拒绝已有目录，重新检查冻结源码并要求零 skip。
随后在解压所得 `source/` 中，独立运行外部门禁；所有输出目录也必须是新目录：

```sh
python tools/qualify_cpp_callback_project.py \
  --workdir /new/run/callback --clang "$CLANG" --clangxx "$CLANGXX" \
  --iterations 200000 --repeats 5
python tools/qualify_hia_call_expansion.py \
  --output /new/run/call-expansion --clang "$CLANG" \
  --component-core /new/run/callback/three_weight/standalone.core.json
```

捕获 Core 的具体路径由实际 callback qualifier 的输出清单确定；不能用旧的或不同
配置的 Core 代替却保留原资格声明。NDU 各证据目录有自己的 `REPRODUCE.py` 和冻结
来源；Agent 复制按其 [README](../../experiments/hia_five_deliverables_20261030/agent_replication/README.md)
重新登记，不能修补历史模型答案或只重跑失败单元。

`CODE_ANCHOR_CI.json` 只记录上述实现代码提交的已完成远端 CI。后续证据提交的
实际状态见 [PR #400 checks](https://github.com/TrillionniumFoundation/Hepta/pull/400/checks)，
不能从代码锚点的成功推断另一提交的 workflow 已执行。
