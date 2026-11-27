## 当前结论：整套全 HIA 原生交付尚未闭合

继续执行用户要求的完整链路：全量审计、迁移所有生产职责、同源冷自举与完整原门禁、默认及安装/连续性验证，最后移除旧生产整套并重新验证。**whole-native=false；默认未切换，旧生产整套未删除。**

本 PR 仍为 draft，产品 HEAD 仍是 `4b19af89a766593f7d5f1cc2db256e81aba7afcb`。新工作在独立候选中推进；以下组件结果不表示本 PR HEAD 已包含所有新改动，也不表示整套已经通过。

最新[完整审计提交 06f4856](https://github.com/TrillionniumFoundation/Hepta/commit/06f4856e6adee5af8597941201382ab0eddabd13)追加 184 个证据对象，保留此前 25 个审计子树。入口是[续审说明及完整证据目录](https://github.com/TrillionniumFoundation/Hepta/tree/06f4856e6adee5af8597941201382ab0eddabd13/review-evidence/hia-native-rewrite-v80-global-joint-closure-20261112-dda7)。本次更新前的 PR 正文已逐字保存于该目录的 `global/PR889-BEFORE-UPDATE.md`；历史失败、当时的环境不可用情况及其后恢复不被覆盖。

## 已发布的联合源码与实际门禁

独立联合源码提交 [64f67ae](https://github.com/TrillionniumFoundation/Hepta/commit/64f67ae897c3cb49d45a1e1a4622db974812e3fe)，树 `b7cf3502931d5fae8f58444b0af04cc642414a4a`，共 3,255 文件，相对本 PR HEAD 有 132 个改动、零删除。所有源码 blob 和完整树已读回核验。

| 实际运行 | 结果与边界 |
| --- | --- |
| [Proof joint R1 / 43271704649](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43271704649) | 89 个生成器、171 个选择器、860 个测试完整执行，2 FAIL：Context/Emission 的显式 held-owner 集合尚未登记 Proof。原 764 个 ID 与新增 96 个按序保留，原 1,800 秒限制未改。 |
| [Proof joint R2 / 43276054646](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43276054646) | 修订后 860/860 PASS，1,128.716 秒，无 failure/error/skip/xfail/xpass。生成上述 3,255 文件联合源码。外层 601、内层 593 个归档成员 CRC 均通过；592 个清单成员逐字节、SHA、Git blob、模式核验。 |
| [64f67 原自动 Core 工作流 / 43282165461](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43282165461) | source 作业 `131406013787` 已成功执行原 860 项并保留完整日志；最近观察 native 作业仍在第 27 个 durable 组。后续未完成，不能从中间步骤推断冷构建/全组终态。 |

完整 R1 原失败及 24 段作业日志、R2 原完整日志与源包、归档核验和实际源码发布记录均在新审计的 `joint/` 目录中。成功资格只属于其实际源码。

## GLOBAL／分组导入／异常寿命修复

真实 HIA Core/Byte 映像及名字查找端口的原 104 个配对观察中，有 88 个不一致。具体修复包括：公开 helper 替换/删除/设为非函数时仍按原全局绑定决定；只在当前绑定等于定义时的原入口时选择 HIA helper；缺失名字保留 NameError 的 `name` 与原异常上下文；Byte 使用一次原分组 IMPORT_NAME 和逐项真实 IMPORT_FROM，保留 fromlist、原命名空间与导入次序。

后续寿命观察又发现：被保留的 ImportError 会使导入端口的 `module` 形参延长模块寿命。原 Byte 组有 6/8 个差异、Build 组有 4/6 个差异；端口修复后，原 104 项、Byte 8 项和 Build 6 项均一致。Build 的生成器同步修正，原负例完整保留。

新增 8 个永久方法（3 Source、5 Native），相关原 91 个测试方法正文逐字保留。本机 Python 3.12.14 实际 8/8 PASS、24,880 次实际原生返回，源码执行前后相同；这不代替原组件/原调用组或 Python 3.14。

冻结修复包相对 64f67 有 20 个完整改动、3,257 文件、树 `0a3fba637afe252f9bdf192b7a24df67b08efcbe`。完整本地 142 文件证据已通过 17 个 Git 片段无损保存并全文读回，见新审计 `global/`。该包随后发现新测试辅助文件遗漏在总 SOURCE_FILES 中，三个生产构建器会正常拒绝；只读检查及原遗漏保留，新的联合修订补齐登记而不改变拒绝断言。

下一轮独立源生成 [harness 提交 523edd8](https://github.com/TrillionniumFoundation/Hepta/commit/523edd82b9856f0e2703969d13d7276cf550ff0c) 已发布于 `codex/hia-global-import-source-v80-r1-20261112-dda7`，固定 actual64f67 加 20 个修复和 4 个机械登记路径。[实际运行 43294252598](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43294252598)已启动，当前 in_progress，目标为 89 个生成器、171 个选择器、863 个源码测试；原 860 个有序 ID 保留。5 个新增 Native 方法另行执行，并继续进入原冷构建/完整原组。harness 发布或运行中状态不等于新源码已经通过生成或测试。

## Evaluation／Adoption／Lease：组件通过，原预算仍失败

定义时 helper 身份、store 在 service 之前导入、循环寿命和导入异常保留模块的问题已在独立 Evaluation 修订中修复并保留原负例。

[R5 实际 Python 3.14 运行 43286586760](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43286586760)终态为 **failure**：

- 47 个 Source/Adapter、12 个 Native、原 48 个 Agent 方法通过；Agent 组 2,789,605 次实际原生进入，旧 owner 调用为零。
- 原 namespace 35 项：32 PASS、3 FAIL；原 ledger 48 项：45 PASS、3 FAIL。两组原 ID 完整按序执行，零 error/skip。
- 每组两项在准备阶段第二次 emit 前遇到 codegen E_HIA_BUDGET；另一个原 native_timeout 要求小于 5 秒，实际分别为 6.378441793 与 6.298987390 秒。R3 曾通过的 timeout 结果不能转移到 R5。

完整原 R3、R4/R5 本地负例与源码、R5 原内层 ZIP 11 片、外层全部成员元数据及日志已挂载到新审计 `evaluation-p1/`。优化继续针对实际完整 fresh 源码读取和原生流程开销，不放宽预算、不缩小源码域、不以跨公开调用缓存跳过校验。原 Path 微优化和 HIA SHA 内联并未解决预算，历史结果保持原判。

## 公共入口：Core 与汇编应用分开验证

原 13 入口开发修订已有实际 Python 3.14 差分和本机原调用组结果，但其汇编应用依赖 `hia_program_tools`，不能据此扩大 Core 的纯依赖边界。新的实现拆成 Core `_reject`/`verify_program` 与汇编应用两个 HIA 所有者，原 Core import 断言保留。

两个新像均已在原 20 秒编译限制内生成。首轮沿用 Plan 的最小函数数断言拒绝 Core 两函数表，相关组在首个测试前停止，记为 0 测试；原失败保留。纯传输最小表改为非空后，各具体 owner 仍核精确函数数及完整表哈希。

新本机五组分别实际通过：Core-only Program/Composite 46、Core-only assembly 18、assembly-only 18、both 64、default 64。它们有重复调用组，不合计为互不重叠的新增测试。原策略 poison 调用为零，源、像和 manifest 守恒。另 9 项首次准入、早期语法错误优先、首次漂移、captured None、held owner 及 scope 恢复控制也已通过。其余 lazy、传输/ACK/寿命和 FIFO 控制继续推进；这些结果尚不是新双像的 Python 3.14、冷构建或安装资格。

## 完整闭合与旧整套移除的顺序

完整保留 harness 当前准备包为 254 文件，原 121 文件输入逐字保留；367 个静态检查、56 个真实 loader 清单和 10 个编排控制通过。导出器原超长行失败及缩短分块后无损恢复成功均保留。它尚不代表实际 full qualification；将固定在当前修复最终生成的准确源码上运行。

原冷构建 180+3 秒、编译子进程 20 秒、普通组 1,800 秒及原完整组限制均保持。还需继续闭合公共 JSON/归一化、source/install/checker 身份、worker/dispatch、进程/发布、编辑及其他后端、会话/自适应执行、安装后的默认和恢复路径；CPython 对象/异常/加载等仍存在的机制与其他生产提供者不能隐去。

只有同一最终原生候选完成冷自举、完整原组件和调用组、默认/安装/连续性/恢复门禁后，才清除旧生产实现，并做干净安装和完整复验。当前不会把组件通过、可恢复证据或已发布 harness 写成整套重写完成。

历史原 Proof 64 项的源码及全部原记录已经恢复、验证并实际持久化，见[恢复审计 cb1eec1](https://github.com/TrillionniumFoundation/Hepta/commit/cb1eec11f7fb4221deda2fc29604cd299aad6321)。当时缺 Z3 的原 40 项尝试停在导入预检、业务执行数为零；恢复记录不授予新 Proof/联合源码冷资格。
