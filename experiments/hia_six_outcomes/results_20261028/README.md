# 统一源提交的四组正式证据（2026-10-28）

本目录保存已经完成的 filecheck、C++ 跨翻译单元所有权迁移、安全契约回归和分支整合报告。打包期间只读原始结果，没有重新执行编译、模型、性能或资源实验，也没有重新选择性能胜者。

统一源提交是 96bc1b4598a8469b0d44b09e7e97d4705cac2cc5，源树是 e5bde8f551d07aa7c264e4e49eb4918b6abd2bce。原始报告的路径、字节数和 SHA-256 在各组 INDEX.json 中；SOURCE_BINDING.json 记录与干净独立 checkout 的字节核对。Agent 校准仍属于 68cbd79ac61224a08be1f3ec2f3026ef0881745e，不能算成在本次源提交上重新验证的结果。

## 阅读入口

- [SUMMARY.json](SUMMARY.json)：从原报告提取的计数、原性能汇总、验收状态、资源缺陷及声明边界。
- [INDEX.json](INDEX.json)：各数据集、原始文件身份和小文件索引。
- [SOURCE_BINDING.json](SOURCE_BINDING.json)：filecheck 的 149 项、C++ 的 7 项以及安全报告的 858 项源文件核对；C++ 编译器集合哈希单独核对。
- [FORMAT.md](FORMAT.md)：JSONL 分片的格式、重组和校验规则。
- [inspect_evidence.py](inspect_evidence.py)：只读验证分片、索引及规范化 JSON 哈希，不调用编译器或运行实验。

## 实际观测与边界

| 正式报告 | 保留的实际结果 | 不扩大解释的边界 |
| --- | --- | --- |
| filecheck | 完整 112 样本，7 组 × 2 算法 × 8 arm；96 个差分输入 × 8 路，共 768 次 native 调用；48 个资源差分行；4 个维护输入；243 条命令记录 | 功能检查通过，原 performance_advantage_gate=false；没有删样本、重排结论或重算最快基线 |
| C++ unique owner | three_weight、five_weight 各 437 个输入；原 C++ 和独立 HIA 两条执行路径都与 oracle 相同；每配置 401 次分配、401 次释放、196 次拒绝、结束 live=0；两个缺少 drop 的反例被拒绝且未发布产物 | 每配置迁移 2 个项目函数，跨 TU owner transfer=1；标准库实现迁移为 0；仅声明的 unique_ptr 数组/默认删除器契约，不是普遍 C++ 支持 |
| 安全契约 | 37/37 passed，0 skipped、0 failures、0 errors；15 个能力条目；执行前后 858 项源绑定一致 | 有限边界回归，未证明全语言健全性、源码到 Core / Core 到机器码精化、一般并发安全或进程内存上界 |
| 整合清单 | 3 个 donor、7 个更早分支、5 项历史实验身份；unintegrated_selected_paths 为空 | 保留全部 explicit_unintegrated_scope；路径盘点和 Git 祖先关系本身不证明语义组合、安全性或性能 |

### filecheck 的资源测量缺陷

原 112 个样本的 peak_rss_kib 全为 35072 KiB，无法区分各 arm，原数值完整保留。这不能解释为各实现具有相同实际峰值内存，也不能作为 HIA 的资源优势证明。独立小 C supervisor 的后续控制观测支持启动历史 high-water floor 污染的解释，但没有精确重建旧进程的内核路径。

补充证据位于 [RSS 诊断](../../hia_filecheck/rss_diagnostic_20261028/README.md)，目标仍是原 96bc 二进制；协议提交 c4efc29610fab58f495e38e22c7cb10b0d63c876，结果提交 b96cae073f0b1c955d7600eb6e923b4a0b269cc3。本目录 SUMMARY.json 同时绑定原 qualification.json 和该补充证据文件哈希。补充资源观察不替换原 112 样本，其 incidental timing 不用于性能排名。

原性能汇总在 [filecheck/summary-001.jsonl](filecheck/summary-001.jsonl) 和 SUMMARY.json 原样保留。协议的 P95/P99 是每个至多 4096 字节 batch 的延迟，包括读、打包和组件计算；不是面向用户的请求延迟或跨平台承诺。测试是新的小型 C 组件与共同 C 宿主构成的文件校验 CLI，并非大型历史应用完成迁移。

### C/C++ 迁移量、成本与假设

filecheck 初始迁移 2 个 C 实现体、2 个翻译单元、33 行 / 1138 字节实现、1 个 owner allocation site；维护任务增加第三个 API 翻译单元，重新捕获后是 3 个实现体。完整生命周期差分、ABI/build receipts、维护观测与声明假设都保留在 filecheck 分片中。共同宿主的文件 I/O 和打包仍由 C 承担。

C++ 的两个配置各保留 149 条项目声明记录、全部 437 个输入、生成的 Hepta 源码、16 个 lowering 函数记录、对象符号检查、链接命令、native 执行 stdout 和字节哈希。合计是 874 个配置内输入、1748 个 case-route 检查；实际 native 执行是每配置每路径一个批量进程，不是 1748 个进程。精确日志观察摘要为 three_weight 79fca1db8d2f0865、five_weight dd7575852bb30d54。

C++ 原报告没有直接 Git HEAD 字段。本次绑定依据是 7 项明确源文件哈希、与 96bc 完全一致的 hepta/*.py 编译器集合哈希，以及已捕获的项目输入和 Clang 身份；不补造当时未记录的版本信息。原报告中的运行耗时、RSS 是实验工具过程成本，人工工时为 null，不能推导总迁移劳动成本或 Agent 生产率。

两个配置各有 92058 条 standard_library_declarations，属于未迁移的标准库依赖。只在本 Git 文本包省去这两个大数组；每个省略点的 JSON pointer、条数、规范化字节数及 SHA-256 在 cpp_unique/INDEX.json 中，完整数组保存在完整原始 qualification.json。其余报告 JSON 值完整保留。原工具对 Clang AST 采用流式普查，已明确 raw_ast_retained=false；小型 AST 捕获收据保留，但后来归档也无法补回从未保存的 AST 字节。

### 保留方式

filecheck、safety、integration 三份报告可以从 JSONL 分片无损重组成相同 JSON 值；C++ 可以重组成仅删除上述两个数组后的投影。样本序号、原数组次序、每个数值和原声明均保留。规范化不保留原始空白；原文件的 raw SHA-256 单独绑定原字节。全部文本文件小于或等于 48000 字节。

filecheck 的 differential.jsonl 和 maintenance-cases.jsonl、C++ 的两份 cases.json 均另外完整保留。processes.jsonl 的完整原始输出、生成的对象 / 动态库 / executable、其他生成文件由完整原始目录归档保存；本包不重复二进制或巨大的 AST。filecheck 的全部 243 条 qualification 命令记录仍在包内，外部 ledger 身份仍保留。

本包不包含新的 NDU 或 Agent 运行。NDU、RSS 和 Agent 证据应按各自的协议、来源提交和结果解释，不能以本目录的 96bc 标记覆盖其历史归属。
