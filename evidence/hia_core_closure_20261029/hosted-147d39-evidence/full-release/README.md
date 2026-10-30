# 147d39c 官方完整发布：原始内容独立审计

**精确公开提交 `147d39c4a9d3ded00fb5d22439493bc006a8b76d` 的官方完整发布已成功完成，原始工件内容审计通过。** 本包审计的是 run `40989068148` 的实际输出，不能将结果沿用为之后 PR／集成提交的资格，也没有宣称 P0–P7 全量关闭。

最终机器可读结论为 `summary.json`；详细 8,521 项只读验证记录、源码范围、原始报告引用与限制见 `audit.json`。这些是审计检查数，不是新增测试次数。审计者没有修改源码、重新执行原生程序／测试或进行 GitHub 写入。

## 官方工作流与原始字节

| 项目 | 实际记录 |
| --- | --- |
| Source commit | `147d39c4a9d3ded00fb5d22439493bc006a8b76d` |
| Source tree | `2050ec5e447ae5191ac2e685ba463292b2d2d3fe` |
| Workflow run | `40989068148`，completed / success |
| Job | `123846823216`，所有步骤 success |
| Job 开始／完成 | `2026-10-30T01:59:50Z` / `2026-10-30T03:46:45Z` |
| Run 最后更新 | `2026-10-30T03:46:46Z` |
| Official artifact | `12952846418` |
| Original ZIP bytes | **370,966,739** |
| Official ZIP SHA256 | `515b2166e3b47c0b51b46421f67531eb053ac21266a8202cba8ba0ba8dc95c6c` |
| Whole ZIP Git blob identity | `06b6f777afa7fca5f5eb9faf21c7d6083289ec66` |

实际 API 响应保存在 `metadata/observation05/`，完整 job 日志保存在 `job-123846823216.log`。日志是 GitHub connector 返回的完整解码文本，其原内容、UTF-8 字节大小和 SHA256 分别保存于 response／receipt；不冒称取得了未经解码的原始 HTTP 日志字节。

原 ZIP 的官方 size／SHA256 均匹配。**7,724 个成员、1,251,096,836 解码 bytes** 全部流式读取至 EOF 并通过 ZIP CRC；成员 path、mode、bytes、SHA256、Git blob 和 CRC 见 `zip-inventory.json`。其中 **5,241 个成员**属于本工作流选择的 current output 路径，**2,483 个成员**属于历史或其他上传输出。这里的 current 仅指本次 `147d39c` 工作流，不能解释为仓库之后任何版本的执行结果。

十种有限凭证模式扫描未发现匹配，具体模式及范围见 `zip-credential-scan.json`。这不是一般的凭证不存在证明，也没有递归解码嵌套归档。下载用的临时签名 URL 保存在本证据目录之外，没有收入发布文件。

## 实际门与测试分母

| 实际范围 | 门数 | Python 原始记录 | Rust 原始记录 |
| --- | ---: | --- | --- |
| candidate release | **50 / 50** | 完整回归 **3,659**，verbose IDs 可核验 | 不用此列冒充另一份 Rust corpus |
| standalone HIA | **37 / 37** | 完整回归 **3,659**，nonverbose terminal summary | **96 tests / 19 harnesses** |
| NDU pipeline | **9 / 9** | focused regression **201** | **96 tests / 19 harnesses** |
| integrated qualification | **8 / 8** | 完整回归 **3,659**，verbose IDs 可核验 | **96 tests / 19 harnesses** |

全部声明门通过。candidate 与 integrated 的 3,659 个 verbose method ID 集合完全相同；每个实际 method status 都是 `ok`，没有 failure、error、skip、expected failure 或 unexpected success。standalone 只保留 nonverbose 完整计数，没有把它改写为第三份独立 method ID 清单。NDU 201 是完整集合的子集，不与完整回归相加。

三处 Rust 结果都从原始 Cargo 输出解析，实际 method 名称多重集合、tests 和 harnesses 一致；failed／ignored／measured／filtered_out 均为 0。重复运行的同一语料不相加为更大语言覆盖面。

### 安全合同与关键模块覆盖

实际通过的完整 method 集合包含当前源码声明的 **126 个 safety selectors，分属 17 项 capabilities**。integrated 原始覆盖报告包含 **49 个 critical coverage groups、122 个唯一模块**，没有 missing modules；每个模块的实际方法列表均与完整 verbose 记录相符，也与当前源码 AST 中的声明相符。

126／17 是 selector／capability 分母；49／122 是 group／module 分母。它们不是 release gates，也不是额外执行的 126 或 122 个独立新测试。详细 method statuses 与 gate statuses 分别保存在 `method-statuses.json` 和 `gate-statuses.json`。

## 源码前后绑定

| 范围 | 声明源文件数 | 审计结果 | 范围限制 |
| --- | ---: | --- | --- |
| candidate | **2,124** | before=after，所有哈希匹配公开 Git bytes | release 所声明路径，排除 artifacts 等目录 |
| standalone | **2,124** | before=after，所有哈希匹配公开 Git bytes | 同一 release 路径规则 |
| NDU | **767** | before=after，所有哈希匹配公开 Git bytes | 声明的 implementation/tests/tools/Rust/workflow 等路径 |
| integrated | **4,398** | before=after，完整 tracked tree 匹配，tree 正确、status clean | 完整 tracked source tree |

`source-git-binding.json` 独立读取公开 commit 的 Git blobs，记录每个 tracked 文件的 path、mode、bytes、SHA256 和 Git blob。审计没有导入 producer 代码来代替字节核对，也没有用可变工作树或旧 699 的清单冒充当前源码。

候选、standalone、NDU 的规划器文件相对早期已审计版本确实字节相同，原始比较见 `gate-plan-source-comparison.json`；这只用于建立预期门集。当前通过结论仍来自本次实际报告和日志，不是从旧执行推断。当前安全合同和 critical coverage 的声明直接来自精确 `147d39c` 的 JSON／AST。

## 实际工具与平台记录

integrated 的实际工具门保留 14 份 version command、returncode、stdout/stderr、path 和 executable SHA256，并绑定到 external before／after 清单。完整记录见 `actual-tools.json`，主要版本包括：

| 工具 | 实际原始命令输出 |
| --- | --- |
| Python | 3.11.17 |
| 主 rustc / cargo | 1.90.0 |
| clang / clang++ / llvm-readobj | LLVM **20.1.8** |
| 主 rust-lld | LLD 20.1.8 |
| GCC / G++ | Ubuntu 13.3.0 |
| Lean | 4.19.0 |
| QEMU aarch64 / riscv64 / system-arm / x86_64 | 8.2.2 |
| Z3 | 4.15.4 |

这次 hosted LLVM 20.1.8 不能改标成本地恢复的 LLVM 20.1.2。Rust 也保留实际 hosted 路径／hash，不用其他机器的同版本文件身份替换。各独立 NDU build receipt 的具体工具链仍按其原记录解释。

本次实际环境记录为 Linux、x86_64、kernel `7.0.0-1017-azure`、Python 3.11.17。Linux memfd seal 门实际 required_bits=15、actual_bits=15，写入按预期被内核拒绝；该结果限于这个实际平台能力。

### 外部身份的保存范围

integrated **实际原始报告**有 **440 项 external identities**，其 before／after 完全一致。本次数量来自 hosted 原文，没有套用本地旧清单：

- **8 项**能在原 ZIP 中找到实际 bytes，已逐项核验哈希。
- **1 项**可对照精确公开 Git source bytes，已核验。
- **431 项**只有原任务记录的身份，原始安装文件／源码体未上传到该 ZIP，本审计没有重新下载或运行它们。

四个固定 NDU binary 与 build receipt 的实际字节和哈希已经绑定；它们的固定 upstream source commit 保留在报告中。对应 upstream source bodies 没有由本审计重新获取，不能将 receipt 中的 commit 记录扩大为 source body 重新验真。

## 正常通过与尚未关闭的科学条件

四份主报告的原始 status 分别为：

- candidate：`passed`
- standalone：`all_scoped_gates_passed`
- NDU：`bounded_mechanisms_passed_scientific_gates_open`
- integrated：`bounded_integrated_contracts_passed`

NDU 和 integrated 均明确否认 whole-language soundness、完整阶段关闭、scientific incremental advantage 和 global optimality。ranking receipt 未开启 production activation；另外三类固定 evaluator 的 authority 为 `DENY_ALL`、safety certificate 为 false。测试通过不改变这些原始边界。

standalone 的有限 host performance 门实际通过，原始报告有 63 个 interference observations、0 个排除样本，未调整 acceptance thresholds。环境仍是 shared host、非独占 CPU；physical_device_qualified、whole_language_performance_qualified、backend_refinement_proved、universal_rust_superiority_proved 均为 false。原始资源观察和限制保存在 `scope-observations.json`。本审计不将逻辑资源账本当作 RSS，也不从门通过推断优化政策切换。

integrated 声明本轮 full regression 包含 native timing controls，但 standalone performance campaigns 没有在 integrated 范围内再次重放；独立 standalone 门的实际报告仍有自己的身份。历史工件没有被复用为当前 integrated execution。

所以，本包支持精确 `147d39c` 的有限完整工作流资格和原始内容完整性，**不支持 Python→Rust 生产权威切换、全语言健全性／后端 refinement 或 P0–P7 全量关闭**，也不能资格化之后的集成源码。

## 原始 ZIP 的持久保存与恢复

`raw-parts.json` 将唯一原始 ZIP 按顺序分为 **89 段**：前 88 段各 4,194,304 bytes，最后一段 1,867,987 bytes，从 offset 369,098,752 开始。每段都有 offset、bytes、SHA256 和 Git blob。逐段读取产生这些身份时，原 ZIP 未变；全部有序范围恰好覆盖官方 ZIP，整体 SHA256 再次匹配。

本地没有复制所有 part 文件。发布端可直接读取 `source_archive` 的对应 byte range，将这些相同字节发布为 `raw-artifacts/12952846418.zip.part0001` 至 `.part0089`。实际远端上传／读回由主线负责，本审计没有把待发布状态写成已完成。

下载公开 parts 后，可使用：

```sh
python3 restore_official_zip.py --part-directory . --output restored-official-147d39.zip
```

helper 验证每段和整体 bytes／SHA256／Git blob，拒绝覆盖已有输出，不执行 ZIP 中代码。由于本地没有全部物化 part 文件，本审计没有宣称执行过从远端下载 parts 的完整恢复；原始连续字节校验与远端恢复验收是分别记录的步骤。

元数据归档保存主报告、全部被引用的保留记录、当前源码清单、完整解码 job log、所有 method statuses、工具与范围总结、下载／审计／分段脚本和过程日志。它不重复存储原 ZIP；必须与 89 个原始 parts 一起保存。`metadata-retention.json` 和 `metadata-archive-receipt.json` 记录元数据包的输入身份与逐成员读回结果。

`PENDING.json`、早期 metadata observations 和 `preparation.json` 是此前 02:27 等时刻的真实历史记录，已由 observation05、`summary.json` 和本报告更新最终状态，未被删除或改写。先前冻结的独立 peer 包与 14-host 包保持原样。
