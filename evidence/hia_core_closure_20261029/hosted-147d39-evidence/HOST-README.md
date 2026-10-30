# 公开提交 147d39c：实际宿主 CI 工件审计

**14 个原始宿主 ZIP 已完整保存并完成审计。** 7 个 C++ 上游复用任务和 7 个 C ABI／标量 C 组件任务均在公开提交 `147d39c4a9d3ded00fb5d22439493bc006a8b76d` 上完成，Git tree 为 `2050ec5e447ae5191ac2e685ba463292b2d2d3fe`。结论是这些有限报告与保留的原始数据一致；Windows checkout 文本表示、工具字节保存范围和 ABI 临时二进制缺失均明确列出。本审计没有重新执行原生程序，也未修改源码。

最终结论见 `host-audit-summary.json`，每个工件的逐项审计见 `host-report-audits/`。原始 ZIP 不包含在元数据归档中，必须与 `raw-artifacts/` 的 14 个原始文件一起保存。

## CI 与原始工件身份

| 独立范围 | GitHub run | 实际结果 |
| --- | --- | --- |
| C++ upstream host | `40989068162` | completed / success；7 jobs、7 original ZIPs |
| Native host ABI | `40989068224` | completed / success；7 jobs、7 original ZIPs |
| Full release | `40989068148` | 本宿主包封存时仍 in_progress，0 artifacts；本包未审计完整发布结果 |

`metadata/observation01/` 保存最初实际 API 返回；`metadata/observation02/` 保存随后完整发布任务仍在进行的观察。已完成的 14 个 job 的完整解码日志、API job/工件清单和实际报告已交叉绑定，见 `host-job-artifact-bindings.json`。日志是 GitHub connector 返回的完整解码文本，保留其 UTF-8 编码、BOM／换行表示及 SHA256，不冒称取得了未解码的 HTTP 原始日志字节。

14 个 ZIP 合计 **27,051,499 bytes**，官方 digest 和官方 size 全部匹配。ZIP 内 **1,370 个成员、152,792,171 解压 bytes** 全部读取至末尾，通过 ZIP CRC；逐成员 SHA256、Git blob、压缩大小及原始 mode 元数据见 `inventories/`。提取后的每个成员再次读回并核对字节身份。下载用临时签名 URL 存在证据目录之外，未收入本包；ZIP 成员中也没有这些签名 URL。

## 实际宿主／编译器矩阵

| 托管镜像 | 架构 | C／C++ family | C++ 范围 | ABI／C 组件范围 |
| --- | --- | --- | --- | --- |
| ubuntu-24.04 | x86_64 | gcc | 通过 | 通过 |
| ubuntu-24.04 | x86_64 | clang | 通过 | 通过 |
| ubuntu-24.04-arm | aarch64 | gcc | 通过 | 通过 |
| ubuntu-24.04-arm | aarch64 | clang | 通过 | 通过 |
| macos-15 | aarch64 | clang | 通过 | 通过 |
| windows-2025 | x86_64 | clang | 通过 | 通过 |
| windows-2025 | x86_64 | msvc | 通过 | 通过 |

每个 job 的实际 host、宏探测的 compiler family、target、版本、binary hash 与 artifact 名称都保留在原始报告和独立绑定中。这些是托管虚拟机原生进程结果，不是物理板、MMIO／DMA／IRQ、GPU 或一般线程安全资格。审计没有用本机工具身份替代 hosted 工具身份；宿主 compiler/rustc 的原始安装文件没有随包保留，因此它们的 executable hashes 属于原始报告／命令绑定，不能冒称审计者重新读取了这些宿主工具文件。

## C++ 上游复用：实际观察

每个宿主都分别执行固定的 nlohmann/json **3.11.3 与 3.12.0**。每个版本的原始 stdout 包含 **98 个 direct／Hepta 对照案例**，两端 status/value 一致；各案例 live_delta 为 0。每个版本另有 32 个生命周期案例、32 次 borrowed input 覆写、32 次 stale read、32 次 duplicate destroy、64 次拒绝 mutation、4 个 pointer guard、1 个 malformed constructor 和 1,024 次有限 concurrent calls。

取消协议的原始观察为 requested=7、committed=3、value=107、replayed=0。这是调用之间的有限协议，不能视为 foreign call 内部的异步取消资格。`ordinary_live_delta=0` 同时伴随 `registry_ordinary_allocations_retained=2`，报告没有宣称全进程所有分配均已释放。

实际 linked executable bytes 均在原始 ZIP 中。审计核对 SHA256、大小以及 ELF64／Mach-O64／PE32+ 的架构字段；生成 bridge 文件和 process stdout/stderr 的文件字节、内嵌 base64 与报告哈希一致。故意错误的二进制实际退出 2，并报告 direct／Hepta mismatch；不兼容 C++ 返回签名在真正 C++ 编译时触发预期 static assertion。固定上游 header/license 的哈希与公开 Git 对象一致。

每个 C++ job 另有 **9 个 adapter tests，OK，无跳过或预期失败**。这是独立测试方法计数，未与运行案例或 native calls 相加。

此范围复用未改写的上游 C++ 库，不声明该库已经被翻译为 Hepta，也不证明 foreign UB／内存安全、一般 borrow retention、任意升级兼容性、完整分配失败恢复或总人工迁移成本。

## C ABI 与标量 C 组件：实际观察

### 有限 ABI 矩阵

每个宿主报告包含 12 scalar types、36 aggregate shapes、12 pointer shapes，另有 register-spill 参数。两个优化档均执行成功，每档实际 stdout 报告 **181 foreign calls**，layout_checked=true。三种 C 类型反例（函数参数、数组 extent、嵌套 pointer const）均被实际 C 编译器拒绝；wrong C echo 二进制按预期非零退出。该路径是 **frontend → Rust object**，不等同于 v8 直接 LLVM 的公共 aggregate ABI。

**ABI 原始二进制保存限制：** `native-host.json` 声明的临时 matrix object、两个正例 executable 与 wrong-code executable 共 4 个 hashes，在每个 ABI 原始 ZIP 中实际均为 **0/4**。这些对象位于原 job 临时目录；原始 workflow 上传的是其命令、stdout/stderr、布局结果和哈希。审计因此只能核对保留的原始观察及其绑定，没有独立读取这 4 个 ABI 临时二进制的 bytes。这个限制不能用另外保留的 C++ 或 stb 二进制替代。

### 冻结 stb_divide 组件

每个宿主对 `generic` 与 `truncating` 两个声明配置分别执行 6 个公开标量函数，完整未修改 header 为 14,507 bytes／433 lines。原始输入语料每宿主 **21,453 个唯一输入**，共有 **42,906 个 input/configuration pairs**。

审计逐行读取实际保留的输入 JSONL 与两个执行 TSV，使用独立整数公式重新计算 truncating、floor、Euclidean quotient/remainder，并核对 TSV 中 expected、original C 与 generated target 三组结果。每宿主报告的 **514,872 native function observations** 与实际行数一致；这项计数包含 original/target 两端每行各 6 个调用。另有 696 次有限 interpreter function observations、24 个只调用 target 的 trap processes；不安全输入没有发给 original C。

原始 caller／generated target 和 wrong-code target 的 bytes 均保留且与 hashes 一致；wrong code 实际被功能 oracle 拒绝，三个额外声明反例拒绝整个迁移 bundle。Rust allocator probe 在每组六函数输入前后保持不变；组件本身是无借用的标量算术，不覆盖 owning upstream 资源。每个 hosted 报告都明确 `hia.native_requested=false`、`native_executed=false`，不能将这 7 个宿主结果标成 HIA 直接 LLVM 原生结果。

`manual_review_hours` 与 `agent_tokens` 为 null；自动耗时不能充当完整人工迁移成本。禁用的 STB self-test、floor simulation、另一整数除法配置、C++ extern-C wrapper 仅保留完整源 bytes，没有被计为已翻译的 active declarations。

每个 ABI job 另有 clang capture **16 tests**、native host adapter **11 tests**、original-type process **4 tests**，全部 OK，无跳过或预期失败。

## 源码与 Windows 表示区别

公开 source tree 的 4,398 个 Git 条目已读取建立索引；审计仅对 hosted 报告实际声明的 source sets 逐项绑定，不编造每个宿主完整工作树字节清单。全部 Hepta Python compiler aggregate SHA256 为 `8d5ab3fd739ba5622277ddcfc40837dc56e89f2df15ef35494c0c30f9b6ab547`，根据公开 Git 对象按原始文件名／NUL／源 bytes／NUL 算法重算一致。

C++ 报告各自绑定 157 个选定源文件。5 个 Linux／macOS jobs 的 157 个哈希都等于 raw Git bytes；2 个 Windows jobs 各有 **150 个 raw Git matches，加 7 个明确的 LF→CRLF 表示绑定**。后者是 `examples/cpp/upgrade/` 的 adapter.hpp、consumer.hepta、contract.json、harness.cpp，以及 `examples/cpp/upstream_host/` 的 README.md、consumer.hepta、harness.cpp。它们报告的 SHA256 精确等于公开 LF bytes 转换为 CRLF 后的 SHA256，不能称为 raw Git bytes 相同。

公开 `.gitattributes` 将 Python 固定为 LF，并将上游 fixtures 标为 `-text`，没有为这 7 个 example text paths 固定 eol。原始 Windows job 日志仍明确 checkout 精确公开 commit，报告 tracked status clean 和 inputs_unchanged。每个 CRLF 绑定分别保留 Git SHA256、reported SHA256、对应表示的大小和证据范围；原始 hosted example 文件 bytes 不在 ZIP 中时，只声明这个显式 hash/表示对应。

stb 报告各自保存 before／after 源码身份，二者完全一致，包含精确 commit/tree、276 个 implementation hashes 和 6 个 fixture hashes；这些都匹配公开 Git bytes。它们的 status_scope 排除了生成 artifacts，不能扩大为整个目录没有生成文件。

最初严格审计脚本把所有 Windows example bytes 一律要求等于 LF Git blob，导致两个 C++ 审计项失败；原脚本、全部结果、stdout/stderr 和分类保留于 `auditor-development/attempt01-strict-git-bytes/`。后续审计明确记录两种字节表示，未修改源码或重跑原生任务。

## 原始类型 preflight 的平台限制

各宿主 fixed array 被接受，VLA entry 被拒绝；该 preflight 的 native_program_executions=0、rust_compiler_invocations=0，仅检查原始类型读取。

| 平台 | 原始 address-space 记录 | 原始 file-size 记录 |
| --- | --- | --- |
| Linux | absolute 2 GiB，enforced_and_read_back | 32,000,000 bytes，enforced_and_read_back |
| macOS | initial virtual size + 2 GiB growth，enforced_and_read_back | 32,000,000 bytes，enforced_and_read_back |
| Windows | `not_enforced_here` | `not_enforced_here` |

全部报告均明确 `whole_process_rss_bounded=false`。这些 preflight 限制不授予一般 sandbox、进程所有权或物理内存上界资格。

## 保存与适用边界

`host-metadata-retention.json` 列出元数据包成员及 path/mode/bytes/SHA256/Git blob，`host-metadata-archive-receipt.json` 记录逐成员读回与 gzip CRC。`host-publication-metadata.json` 同时列出 **14 个独立 original ZIP** 和元数据归档的发布身份。原始工件、解码 job logs、审计脚本、初次审计差异及最终结论都可据此恢复。

本包未核验完整发布的安全合同选择器／capabilities，以及 critical coverage groups／modules；这些计数和验收必须以完整发布任务的实际报告为准。没有将旧提交 699 的工件或本地 505 的组件资格改标为本次 hosted 147 结果。P0–P7 的全量关闭结论仍为 false。

## 文档勘误 v2

本版本仅修正 v1 最后一段对未来完整发布计数的类别标签。126／17 若获实际报告确认，应指 safety selectors／capabilities；49／122 若获实际报告确认，应指 critical coverage groups／modules。它们不是 candidate gates 或 workload gates，也不是本宿主包已核验的计数。原始 ZIP、实际宿主审计及其计数不变，v1 元数据归档完整保留；本文件与勘误 receipt 为当前文档。
