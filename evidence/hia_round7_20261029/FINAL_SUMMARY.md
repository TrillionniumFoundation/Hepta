# Hepta HIA 第七轮交付：资源组合、真实迁移与优化收益门槛

## 交付结论

源码已经发布至 [Draft PR #388](https://github.com/TrillionniumFoundation/Hepta/pull/388)，
固定提交为 [`e57f440c32b54ffc8da795370fc288652f3c3319`](https://github.com/TrillionniumFoundation/Hepta/tree/e57f440c32b54ffc8da795370fc288652f3c3319)，
tree 为 `c5f098feb0cd1d9e465a364088b49f2568ceea31`。本轮修复版本的 **6 个工作流、18 个任务全部首次运行成功**。
PR 基于 round6 开发分支，仍为 Draft，未合并 main、未部署。

这轮完成了可审查的编译器增量、同一源码上的执行验收和完整证据整理。
六项长期目标尚未全部关闭：新的 guarded 优化在完整计费后没有净收益，
旧 NDU 比较没有建立增量价值，后台重优化与一般状态迁移也未取得正收益。

## 六项工作的实际状态

| 顺序 | 本轮落地与验收 | 当前边界 |
| --- | --- | --- |
| 1 | 同一源码运行真实前端、规范 Core、验证器、解释器、Rust 差分和原生路径；完整集成验收通过。 | 声明子集通过；未证明整个语言的保持性、进展性或最终机器码精化。 |
| 2 | 有限 v8 分析同时处理 owner 转移、返回借用和调用者根资源；独立 Rust 与原生分配观测通过。 | 精确调用参数、无环图和字节资源子集；未知长度、一般递归、并发及异步展开仍不在证明范围。 |
| 3 | 资源合法性、所有输入上的 Core 行为/首个 trap、选定 LLVM 语义分别设门槛；未知或被反驳的候选拒绝接纳。 | 最终机器码身份与有限差分已检查；未获得最终机器码精化证明。 |
| 4 | 保留旧五策略同预算比较；新候选产生真实不同的机器码，并按预注册协议完成经济性筛选。 | 旧 NDU 无增量价值证据；新候选净收益为负，不进入新的 guarded-bank NDU 比较。 |
| 5 | captured C 的严格 do-while 子集及 RingBuffer/musl 应用通过；C ABI 与 C++ 库复用各通过 7 个真实主机配置。 | 未实现任意 C/C++ 自动安全翻译、外部指针契约推断或通用 C++ 升级兼容。 |
| 6 | 有界子进程、多版本已有状态路径、取消与释放记录通过；保留实际净成本。 | adaptive 与 owned-state 净收益均负；一般后台自动激活及堆状态迁移未关闭。 |

## 同版本验证

完整 integrated 执行 **3,947 个唯一 Python 方法**，另有 **84 个实际 Rust 测试**。
规范矩阵是 **28 项能力、171 个唯一 selector**；verified 回归 **825 个方法**；
six-outcome 回归 **354 个方法**；标量 lowering **449 项已验证、0 项 unknown**。
本地两组互不重叠的 Python 方法为 **170 + 24 = 194**，均无失败、错误或跳过。
不同 CI 群组有重叠，selector、证明义务、原生调用和资源观测不能加成一个“总测试数”。

| 工作流 | 运行记录 | 任务数 | 结论 |
| --- | --- | ---: | --- |
| integrated | [40987874131](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40987874131) | 1 | 首次运行成功 |
| verified | [40987878470](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40987878470) | 1 | 首次运行成功 |
| six-outcome | [40987878447](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40987878447) | 1 | 首次运行成功 |
| C-ABI-hosts | [40987874075](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40987874075) | 7 | 首次运行成功 |
| C++-hosts | [40987874060](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40987874060) | 7 | 首次运行成功 |
| migration | [40987874028](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40987874028) | 1 | 首次运行成功 |

资源证据中，有限 v8 有 103 条 Rust ledger、4 条 v2 边界记录、2 个非法程序拒绝和
5 条原生分配观测；组合资源有 239 条 Rust ledger、11 条拒绝记录、60 条原生观测。
这些是上述测试内的观测，不能作为额外测试方法重复计数。
有限 v8 给出声明字节资源的 payload 上界；它不是进程 RSS 或任意原生堆占用的上限证明。

## 实际失败及修复

首轮提交 `e6b10e9b74c6585f9dba18a78a31cf8f36c071c5` 的 six-outcome
[运行 40984938152](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40984938152)
在 legacy IR-PGO 训练时产生真实 SIGILL，其余 17 个任务成功。
失败主机的 Clang 原生目标配置禁用了 AVX-512，而未经绑定的 HIA 插桩 DSO 中出现了
AVX-512 指令。原运行没有保留精确故障程序计数器，因此不能把静态指令检查写成已捕获的故障地址。

修复把 LTO、IR-PGO 插桩、profile-use 和独立资源观测对象的四条路径接回同一目标策略绑定，
逐次核对实际编译器、完整正负 CPU 特性、raw/bound IR、profile 文件及允许的参数。
独立 QEMU masked-CPU 控制保留原 raw IR 的 SIGILL 与修复路径成功记录；
没有声称重建原 CI 的同一物理主机。
最终 IR-PGO 准备验收完成 361 个子进程、1,056 次差分调用、96 个资源案例的 288 次原生观测，
训练计数器真实非空。其状态明确为 **prepared_not_measured，正式性能样本 0**。
首轮失败、开发诊断、修复后的同版本结果各自保留身份。

## 新优化候选的真实经济性

[预注册协议](https://github.com/TrillionniumFoundation/Hepta/blob/18be73e4bb42063d3f78c506cd2ec6c37226b47d/experiments/hia_guarded_opportunity/protocol_v1.json)
固定两个 90% 热分母工作负载、三种候选、7 个训练种子与 7 个独立验证种子，
每次研究保留 84 个有序样本，未修剪或重试。
baseline、guard8、guard10 的实际导出函数大小分别为 **19、39、54 字节**。
每个候选都先通过 Core 及选定 LLVM 证明，再编译并做原生差分。

收益按完整 fresh-child 外层墙钟计算，计入装载、guard 和清理，以及测得的整个研究成本。
1 亿次调用/模块、500 个未来 batch 是研究假设，并非真实应用需求。
观察到的最小/最大包络不是统计置信区间；60 秒预算在各有界操作之间检查，并非全局硬实时抢占。
一次只能选一个 specialization，不等于只编译一个候选：三个候选实际全部构建。

| 修复版观测 | 计费研究成本 | hot8 训练 / 验证净收益 | hot10 训练 / 验证净收益 |
| --- | ---: | ---: | ---: |
| 本地 | 11.941468703 秒 | −12.105060703 / −12.237340703 秒 | −12.412024703 / −12.131623703 秒 |
| CI | 12.840035892 秒 | −12.999244892 / −12.927356892 秒 | −12.946548892 / −12.999411892 秒 |

计费排除工具安装、最外层 Python 启动/导入/参数解析及最终报告整理、序列化和写入。
两次结果均为 `qualified=true`、`no-economic-opportunity`，新的 NDU 比较资格为 false。
原 e6 提交的两次负结果也完整保留，未混合或挑选最优样本。

旧 constant-fold bank 的 **30 个 episode = 5 种策略 × 6 组配对**；
NDU 自身 **6/6 选择 stop**，并非所有策略的 30 次都停止。
固定选择、简单搜索、NDU 的独立策略总成本分别为
**2.387637494、2.384051334、29.482030839 秒**，
NDU 其中包含 **26.627448330 秒**原生 bridge 构建及 **0.001777439 秒**接纳成本。
这是构建在内的本次协议成本，不能解释为每次决策延迟；该 bank 的 identity/fold 原生代码相同，
也不能用来证明新 guarded bank 的控制策略价值。

现有 adaptive 路径 131 对观测的净收益为 **−0.290610458 秒**；
owned-state 路径为 **−0.549779618 秒**。后者最终 ledger 为 17 次分配、17 次释放、
2 次拒绝、0 live，取消未重放已完成工作；这些资源正确性记录不能改写负的经济性结论。

## C/C++ 迁移与 ABI 的实际覆盖

新的 Linux x86-64 LP64 C 应用捕获并翻译 **12 个函数体**：
11 个未修改的上游 RingBuffer/musl 函数体，加 1 个显式编写的维护 checksum 函数体；
另有 1 个 HIA 客户端。目标没有链接原 C 实现。
48 个功能案例在 GCC 原版、Clang 原版和 HIA native 间产生 144 次原生调用；
16 个资源案例在原 C 与 HIA native 间产生 32 次调用，并另核对解释器和独立 CRC oracle。
这是声明子集的结构化 AST 翻译和实际差分，不是整个 C 源码语义的全输入等价证明。

既有 C ABI/C++ 库复用分别覆盖 Ubuntu x86-64 clang/gcc、Ubuntu arm64 clang/gcc、
macOS arm64 clang、Windows x86-64 clang/msvc，共 7 个配置、2 种架构、3 类操作系统。
C host component 迁移实际使用 **Rust native**；新 HIA LLVM 应用尚未在这 7 个配置全部执行。
nlohmann/json 的两个版本为 3.11.3 与 3.12.0，每版本每配置有 98 个案例、
32 个生命周期案例和 1,024 次并发调用。
普通调用的 live delta 为 0；进程级 registry 在 Linux/macOS 保留 2 次分配，Windows 保留 3 次。
Windows 两条 C++ 路径的 7 个例子文件采用 CRLF，已逐字节核对相应 Git 内容表示；
不宣称各主机所有源输入原始字节完全相同。

## 证据如何使用

最终归档同时保留 e6 首轮和 e57 修复版的原始公开 CI ZIP、逐文件摘要、完整任务日志、
本地观测、失败/拒绝记录、协议和工具链来源。两轮 verified 工作流仅保留各 306 个
经审查的公开成员；原始 ZIP 和私有 bridge 字节不进入公开包。

归档入口为发布包根目录中的 `ARCHIVE.json`、`RAW-INDEX.json`、`INPUT_SELECTION.json` 和 `RESTORE.py`。
在发布包根目录执行 `python3 RESTORE.py --verify-only` 可校验分卷、完整 XZ、TAR、所有原始记录及公开 ZIP 的每个成员；
执行 `python3 RESTORE.py --output /tmp/hepta-round7-evidence --expand-ci` 可恢复到新的目录。
恢复程序不执行归档内的编译器、测试、原生程序或任何脚本。
归档完整性通过与编译器语义、性能或安全证明是不同的结论。

机器可读的 `final-summary.json` 给出本报告依据的原始文件路径、字节数及 SHA-256。
全部六项研究目标、全局最优、普遍优于 Rust、整个语言/外部库绝对安全和 AI 编码生产率提升，
本轮均未宣布已证明。
