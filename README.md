# HIA 原生重写实际执行检查点 — v152

冻结时间：2026-11-15 02:53:33 UTC。父检查点：`0318838e4ee4fce0fce3fcca07f965e67e61e16c`。

**整套 HIA 原生化仍未闭合，旧生产实现删除数为 0。** 本轮新增并实际生成了 HIA CLI 组合选择器、Store 提交头与十表目录根代码，同时完成多组当前源码的独立核验。执行环境随后失联；两个已经启动的验证尚未取得终态。不能将它们算作通过、失败或已停止。

## 当前开发和验证状态

| 范围 | 实际进展与保留的限制 | 证据 |
|---|---|---|
| 当前 op8 Core | 独立读回通过：5 owners、65 方法、6 次构建，35,939 次实际 Native 调用、215,634 个完整缓冲区；涵盖真实 wheel 构建安装。203,467 次完整新鲜读取。先前 reader R1/R2 失败保留 | [独立结果](v152-current-results/core-r3-terminal-RESULT.json) |
| 当前 op8 Patch | 独立读回通过：20 owners、58 方法、8 次构建、19,502 Native、12 VM；144 个调用日志无孤立项。395,728 次读取、48,893 个物理缓冲区。此批当前源码原件不在旧 Patch archive 中 | [独立结果](v152-current-results/patch-terminal-r1-RESULT.json) |
| Inspect | 完整证据读回覆盖原 Source18、Native17、VM12，共 47 个原方法 ID；13,586 次 Native 调用与 81,516 个 Native 缓冲区核对通过。原 R2 父控制器因五字段缓冲区行格式失败，R5 父进程退出 -9、原因未知；二者原失败保留，合并证据不冒充一次原始成功运行。R6 未执行 | [完整读回](v152-native-development/inspect-complete-terminal-result.json)、[R2 原结果](v152-inspect-results/inspect-native-vm-r2-RESULT.json)、[R5 原退出](v152-current-results/inspect-vm4-r5-OUTER-FAIL.json) |
| R11 HIA 谓词边界 | 1,806 对输入、3,612 次实际 VM、6,000 个完整缓冲区跨度通过；独立读回通过 | [独立结果](v152-current-results/r11-predicate-independent-r1-RESULT.json) |
| R11 原八组 | 已实际执行至 163 次 Native、六个 VM；五个 VM 通过，cross-target-loans 仍在原上限后的第 10,000,001 步失败，后四组未启动。独立 reader 验证的是这次真实失败，燃料闭合仍未成立 | [原结果](v152-current-results/r11-original-eight-RESULT.json)、[独立核验](v152-native-development/r11-original-eight-terminal-result.json) |
| R12 HIA 顺序读取优化 | 109 函数、1,458 块、6,308 操作；实际生成/check/compile/pack 与独立 prefix 读回通过。HIA 397,548 B、image 545,202 B、ELF 1,040,384 B，原 1 MiB 容量内余 8,192 B。2,268 对顺序/短缓冲区/别名/深度/缓存边界验证已启动，**终态 UNKNOWN** | [源码作者](v152-r12-eqbytes-author/MOUNT-RECIPE.json)、[生成结果](v152-current-results/r12-prefix-RESULT.json)、[prefix 独立结果](v152-native-development/r12-prefix-terminal-result.json)、[中断记录](v152-checkpoint/ENVIRONMENT-INTERRUPTION.json) |
| 普通 CLI 组合选择 | 新增 HIA 选择器，显式组合六个报告镜像、Inspect、Patch 与选择器；保留真实签发记录和 op35 导入见证。两次完整生成与原 check、24 项当前 host 绑定及独立读回通过。18 owners、85 方法、9 次构建的资格验证已完成输入准备并启动，**终态 UNKNOWN**。默认入口未切换，Python 端口/签发器仍存在 | [HIA 代码](v152-native-development/cli_owner_selection.hepta)、[生成独立读回](v152-native-development/ordinary-generation-terminal-result.json)、[完整作者包](v152-ordinary-qualification-author/MOUNT-RECIPE.json) |
| Store HIA 提交头与目录根 | 两个组件共六个原生成/check owner 通过，独立读回通过。提交头 HIA 100,795 B；十表目录根 HIA 64,912 B。Native/VM 的 248 个 case ID、1,139 对调用是**已作者的预期数量，产品尚未启动**。真实 FD/fsync/rename、非空行图、多表事务、并发与重启恢复及 SQLite 替换均未闭合 | [提交头](v152-native-development/store_commit_head_v1.hepta)、[目录根](v152-native-development/store_catalog_root_v1.hepta)、[生成独立结果](v152-native-development/store-generation-terminal-result.json)、[验证作者包](v152-store-codecs-controls-author/MOUNT-RECIPE.json) |
| Namespace / 编译器 / cold / 安装 | 原 Namespace 35 项中的 32 PASS、3 FAIL 保留；两个燃料失败和原 5 秒限制超时未消除。历史冻结 u32 的 5,052 项 / 38 阶段成功不等于当前源码 cold 通过。普通编译器、匹配当前源码的完整冷启动与原生安装门槛仍待完成 | [完整状态及历史](STATE.json) |
| 默认生产链 | 当前代码路由仍依赖 Python CLI、Worker、Service、SQLite Store；runtime 默认仍是 22 个 Rust 工具。HIA 策略 owner 和局部原生调用不能代替这些完整职责。没有合并、默认切换或部署 | [路由审计](v152-default-production-audit/REPORT.md)、[源码身份](v152-default-production-audit/SOURCE-PINS.json)、[默认引用](v152-checkpoint/PRECOMMIT-MAIN-GET.json) |

本轮仍使用 Python 生成器和宿主胶水代码。新增 HIA 文件及局部 Native 结果不能证明源码生成、编译、运行、安装和开发工具链已全部改由 HIA 自身承担；这些也是整套重写的未闭合项。

## 环境中断与原会话恢复

执行器报告 `exec-server transport disconnected; failed to resume exec-server session: recovery timed out after 45s`。目前只取得如下最后观察：

| 已启动任务 | 会话 | 最后实际观察 | 当前结论 |
|---|---:|---|---|
| R12 ordered-read boundary R2 | 54384 | 已运行；最后一次轮询输出为空，未取得退出码 | 终态未知 |
| Ordinary CLI owner-bundle qualification R2 | 67922 | 已运行；初次启动返回会话，输出为空 | 终态未知 |

普通 CLI 的准备进程 34202 已实际 exit 0、ECHILD、进程组消失，耗时 12.485 秒；这只证明准备完成。随后启动的产品 67922 不继承准备 PASS。已保存其冻结描述符身份，但完整 BINDING / BOUND-PLAN 原始字节尚未远端封存。

R12 R1 的输出路径未达到原空间门槛，因此没有启动。R2 明确改用已审查的 `/home/agent` 输出父目录，原 3 GiB 门槛、512 MiB 证据估算、所有测试输入与预算保持；21 项纯描述符控制不替代实际目录准入。普通 CLI R2 同样只显式改变输出路径与绑定，110 个控制函数/类全文保持。没有自动换目录重试，也没有删除证据腾空间。

恢复时应先读取两个原会话及其完整原始输出，检查中断中的 reader 文件实际落盘情况，再决定后续动作。不得直接重跑产品、补造缺失 RESULT、从传输故障推断 OOM 或测试失败，或把已不存在的目录按旧身份重建。详见[中断与恢复顺序](v152-checkpoint/ENVIRONMENT-INTERRUPTION.json)。后续只读重连两条原会话时，执行器均返回“没有可用执行环境”；[原始重连回执](v152-checkpoint/ORIGINAL-SESSION-RECONNECT.json)已保存。

## 已保存内容及范围

- R11 原八组完整原件已远端保存：2,221 个逻辑文件、1,122,135,347 B，压缩 archive 13,437,001 B、1,296 个成员。作者独立从真实 Git GET 全量解码核对字节、模式、七项 stat 与路径集合；Root 另外逐一全文 GET 全部 59 个 payload。该包包含 Root seal 与小型 terminal 报告，不包含独立 reader 其他大型输出。[完整原件 recipe](v152-r11-actual-complete-custody/MOUNT-RECIPE.json)
- 普通 CLI 的 R1/R2 验证和 generation reader 完整作者包覆盖 82 文件、1,904,030 B；Store R1/R2 完整作者包覆盖 30 文件、438,241 B。Root 已逐一全文 GET 这两包所有 payload。[Root 读回记录](v152-checkpoint/NEW-AUTHOR-ROOT-FULL-GET.json)
- 环境断连后救回并实际 POST / 全文 GET 的 Root 原始缓存为 **105 文件、1,296,640 B**。原始 UTF-8 文本和 19 位纳秒数字字面量保持。这是明确子集，**不是当前 Root 目录的完整封存**；未以推算的 stat 代替原现场。[恢复清单](v152-root-cached/RECOVERY-MANIFEST.json)
- R12 优化源码作者包已保存；R12 ordered-boundary 与 prefix reader 的全部作者源码未能从断连缓存恢复。其缓存回执已单独保存，不能据此宣称原作者包完整远端保管。[R12 中断恢复包](v152-r12-environment-recovery/MOUNT-RECIPE.json)
- 旧 Patch R4 本地完整封存成功，archive 249,783,577 B；R1 的 -9 与 R3 达到原 256 MiB archive 限制的失败保留。R4 仅更改压缩级别与显式路径，32 个 helper 全文保持。远端大 archive 运输只完成作者，尚未实际运输，且此包不包含当前 Core/Patch 原件。[R4 报告](v152-current-results/patch-custody-r4-REPORT.json)、[运输作者](v152-patch-custody-transport-author/MOUNT-RECIPE.json)
- 当前 Core / Patch / Inspect 及新生成链的大体积原始输出远端封存仍有缺口。发布 RESULT 不代表全部原始日志、帧、账本和输入已远端保存。所有已观察的原失败继续保留。

另一次独立 Git 事实审查确认上述 R11 / R12 核心数字，并逐个完整读回 Root 恢复子集的 105 文件；不改变失败或 UNKNOWN 状态。[独立事实审查](v152-independent-audits/R11-R12-FACT-CHECK.json)

Store 的六份原控制源码在断连后完成独立静态审查：完整重建 head 118 IDs / 1,009 pairs、catalog 130 IDs / 130 pairs，并核对逐 pair 15 份完整 payload 和失败停止逻辑。审查范围内未发现确定性接线阻断，但实际运行、时间/空间准入与真实持久性未获资格。[Store 静态审查](v152-store-controls-static-review/REPORT.json)

普通 CLI 的源码窄审也已完成，未在所读 producer 边界发现确定性接线阻断。新增 121,747 B 终态 reader 草稿保留 57 个原函数/类全文，显式适配真实 child/error、三键构建封套、五键缓冲区、完整有序日志与有限 VM8。它仍为 **未绑定、未冻结、未执行** 的草稿，未做 Python AST 检查，入口恒拒绝，实际 ordinary outer 适配等待恢复原件；没有补造终态或 fresh stats。[审查与草稿包](v152-ordinary-terminal-draft/MOUNT-RECIPE.json)

## 继续闭合的工作

先恢复原执行环境并收取 54384、67922，再完成独立读回。随后执行尚未启动的 Store Native/VM 控制，落实真实文件效应、非空表行、多表原子事务及崩溃/并发恢复；继续降低真实 HIA 编译器路径成本，完成 Namespace、Inspect/R6、普通编译器、当前源码 cold 和原生安装门槛。最后完成默认 CLI / Worker / Service / runtime 的完整 HIA 职责替换及兼容验证，届时才具备清理旧生产实现的依据。

全部原测试 ID、方法、断言、预算、完整新鲜读取与失败历史保持。当前 `whole_native=false`、`production_legacy_retired=false`；本轮生产旧实现删除 0，原始证据删除 0。

默认 Hepta main 为 `f33d8da316de8fdf27b504371f1a5310997ff548`，runtime 默认 `hepta-runtime-base` 为 `ba574f2a6a1b74e85191c58d7bec011720736bb9`。PR #889 保持 draft，原 PR head 为 `4b19af89a766593f7d5f1cc2db256e81aba7afcb`；本进展检查点不冒充已合并的 PR head。详见[完整状态](STATE.json)、[本轮更新](v152-checkpoint/V152-UPDATE.json)、[组件清单](v152-checkpoint/COMPONENTS.json)。

---

## 完整保留的 v151 历史记录

# HIA 原生重写实际执行检查点 — v151

冻结时间：2026-11-14 23:51:30 UTC。父检查点：`f3cf855ca83f7fa3223cbdfb42be1511b15d4c4c`。

**整套 HIA 原生化仍未闭合，旧生产实现删除数为 0。** 当前代码与实际验证有进展，但默认 CLI、Worker、Service、SQLite Store 和 22 个 Rust runtime 工具仍待完整替换。

| 范围 | 实际结果与边界 | 证据 |
|---|---|---|
| R10 原八组 | 独立核验确认原 163 Native、6 VM，其中跨目标借用仍在 10,000,001 步失败。Counted 在原预算复现完整失败缓冲区；处理停在 phase=1、函数索引13/38、输入游标6,183/19,089，后四组未启动 | [独立结果](v151-r10-terminal-actual/RESULT.json)、[诊断](v151-r10-counted-actual/RESULT.json) |
| R11 HIA 改动 | 仅两个 ASCII 谓词块改变，另外 105 个函数不变；全 u64 语义，无新增字段范围假设。107 函数、1,456 块、6,270 操作 | [源码作者](v151-r11-ascii-author/MOUNT-RECIPE.json)、[执行作者](v151-r11-execution-author/MOUNT-RECIPE.json) |
| R11 生成与打包 | 生成/check/compile/pack 通过；HIA 396,167 B，Native image 543,961 B，ELF 1,036,288 B，保留原 1 MiB 上限。独立重新读取原 6,777 文件、全部 214 原件和 12 个逻辑缓冲区通过。真实 HIA 边界与完整八组尚未执行，燃料闭合未成立 | [生成结果](v151-current-results/r11-prefix-result.json)、[独立核验](v151-current-results/r11-prefix-terminal-result.json) |
| 旧源码 Patch R3 | 独立复核通过：20 owners、58 方法、8 次编译、19,502 Native、12 VM；完整读取 395,397 次。大体积证据封存尝试退出 -9，原因未证实，原失败及部分输出保留 | [独立结果](v151-patch-terminal-r3-actual/RESULT.json)、[封存失败](v151-patch-custody-r1-failure/FAILURE-OBSERVATION.json) |
| 当前 op8 Core | 原源码报告12、原生报告2、CLI43、外部8，共65方法与6次构建通过，包含真实 wheel 构建安装。独立 reader R1 拒绝原测试的符号链接，R2 因嵌套计数器作用域失败；最窄 R3 仅作者完成 | [产品结果](v151-op8-core-actual/RESULT.json)、[R1失败](v151-current-results/op8-core-terminal-r1-result.json)、[R2失败](v151-current-results/op8-core-terminal-r2-result.json)、[后继作者](v151-op8-terminal-readers-author/MOUNT-RECIPE.json) |
| 当前 op8 Patch | 原20 owners、58方法、8次构建、12 VM全部通过；当前独立终态尚未执行，不借用旧源码 Native 计数 | [结果](v151-current-results/op8-patch20-result.json)、[作者](v151-op8-patch20-author/MOUNT-RECIPE.json) |
| Inspect R1/R2 | Source18通过。Native阶段编译和十项测试通过后，父控制器因完整 INDEX 为28,066,785 B、12,376调用而触发原16MiB读取限制；后8 owners和VM未启动。R2独立新scope以流式全量索引/前驱核验修复，未修改原capture限制和测试，尚未执行 | [Source18](v151-current-results/op8-inspect-source18-result.json)、[Native失败](v151-current-results/op8-inspect-native-r1-result.json)、[R2作者](v151-op8-inspect-r2-author/MOUNT-RECIPE.json) |
| R6 | 原18阶段、76方法、7构建作者完成；须绑定当前实际Source/Native/VM前驱。旧R5 witness10失败保留，尚无R6实际PASS | [作者](v151-op8-r6-author/MOUNT-RECIPE.json) |

Core R2 失败前已调用两次 readlink；记录计数为0不代表没有读取链接目标文本。链接载荷没有被跟随。R11 独立 reader 的工具返回显示被截断，原返回原样保留；完整 RESULT 另行完整读取并发布，未用重建内容替换原工具返回。

已完整远端保存的作者、R10 prefix/helper/admission 和历史证据按各 recipe 定义恢复；当前产品的全部大体积原始输出远端封存仍有待办，不能由 RESULT 已发布推断完成。所有原测试ID、断言、预算、完整新鲜读取和失败历史继续保留。

接下来执行 Core R3、当前 Patch 独立复核、R11真实边界与原八组、Inspect R2与R6；同时完成真实HIA持久事务Store、Namespace、ordinary compiler、匹配当前源码的cold链及默认安装入口。完整生产链与恢复/兼容门槛通过前，不删除旧生产实现。

默认 Hepta main 为 `f33d8da316de8fdf27b504371f1a5310997ff548`，runtime 默认为 `ba574f2a6a1b74e85191c58d7bec011720736bb9`；本检查点没有合并、默认切换或部署。详见[完整状态](STATE.json)和[本轮更新](v151-checkpoint/V151-UPDATE.json)。

---

## 完整保留的 v150 历史记录

# HIA 原生重写实际执行检查点 — v150

冻结时间：2026-11-14 22:12:50 UTC。父检查点：`7a40b9f8cdef74aaad86482e48ff95570aefb972`。

**整套 HIA 原生化仍未闭合，旧生产实现删除数为0。** 本轮实际推进了HIA字节读写优化、Patch终态隔离修正和op8原生报告入口。R10原语义测试仍有燃料失败；Patch产品测试通过，独立终态核验未闭合；op8完成生成及独立核验，后续资格验收未执行。

| 范围 | 实际结果 | 证据 |
|---|---|---|
| R9完整证据 | 2,213原件、1,122,457,162 B完整远端保存；独立读回163 Native、6 VM。Counted在原10M预算下复现相同失败缓冲区 | [原件](v150-r9-controls-complete-actual/MOUNT-RECIPE.json)、[独立终态](v150-r9-terminal-readback-complete/MOUNT-RECIPE.json)、[Counted](v150-r9-counted-complete-actual/MOUNT-RECIPE.json) |
| R10 HIA优化 | 仅五个私有函数改变，另102函数及全部ABI保持。107函数、1,456块、6,299操作。原生成/check/compile/pack通过；ELF 1,036,288 B，在原1MiB内余12,288 B | [作者](v150-r10-byte-io-author/MOUNT-RECIPE.json)、[生成HIA](v150-r10-prefix-direct/GENERATED-R10.hepta)、[实际结果](v150-r10-prefix-direct/RESULT.json) |
| R10字节边界 | 553对、1,106次实际VM全部通过；独立核对2,212份前后缓冲区及完整操作/异常/资源/步数，重新读取原6,777文件 | [作者](v150-r10-helper-author/MOUNT-RECIPE.json)、[独立结果](v150-current-results/R10-HELPER-INDEPENDENT-RESULT.json) |
| R10原八组 | 948原角色+14候选角色、67控制入场核对通过。累计163 Native、6 VM，五个VM返回；cross-target仍在10,000,001步失败。后四组未启动，独立终态及全量远端原件继续中 | [实际结果](v150-current-results/R10-EIGHT-GROUP-RESULT.json)、[六VM观察](v150-checkpoint/R10-CONTROLS-ACTUAL-OBSERVATION-R1.json) |
| Patch修正 | 原生成两次及check通过；20个owner、55原方法+3新增方法、8次开发编译实际通过，原Native11本轮通过 | [完整生成](v150-patch-generation-complete/MOUNT-RECIPE.json)、[资格结果](v150-patch-terminal-qualification/RESULT.json) |
| Patch独立读回 | R1退出137，仅有STAGES；R2流式发布后仍退出137，输出目录为空。原因未证实；继续有界账本R3，不借产品PASS宣称核验完成 | [R2及两次失败](v150-patch-terminal-r2-author-failures/MOUNT-RECIPE.json) |
| op8生成 | 三个host路径改动及8项外部测试已作者。Inspect/Patch各两次原生成及check共6个owner通过；HIA/ports字节不变。独立核对40,794次读取、1,466,953,120 B；140原件34,477,797 B完整保存 | [候选](v150-cli-as-dict-author/MOUNT-RECIPE.json)、[完整生成](v150-op8-generation-complete/MOUNT-RECIPE.json) |

R10五个已返回VM场景的新步数为3,774,295、2,779,096、7,285,022、188,901、254,951；跨目标借用仍未在原预算内完成。下一步用实际Counted诊断继续优化HIA，不提高燃料、不删测试、不省略完整缓冲区。

op8原CLI43需要真实wheel构建/安装，须明确隔离并固定依赖，不能借旧环境PASS。原Inspect/R5 witness10失败保持，R6作为明确后继独立验收。Namespace、ordinary compiler、匹配当前源码的cold链、默认入口及持久存储仍待完成。

默认Hepta main仍为 `f33d8da316de8fdf27b504371f1a5310997ff548`；runtime默认 `hepta-runtime-base` 仍为 `ba574f2a6a1b74e85191c58d7bec011720736bb9`。默认CLI/Worker/Service/Store仍含Python/SQLite，runtime默认22个Rust工具。没有合并、默认切换或部署。见[引用核验](v150-checkpoint/CURRENT-DEFAULT-REFS-v150.json)、[完整状态](STATE.json)、[本轮更新](v150-checkpoint/V150-UPDATE.json)。

真实HIA持久事务owner、默认服务/运行时/安装链以及全部原验收完成之前，保留旧整套。所有原失败、测试方法、断言、预算和完整读取要求保持。

---

## 完整保留的 v149 历史记录

# HIA 原生重写实际执行检查点 — v149

冻结时间：2026-11-14 20:02:34 UTC。父检查点：`d3983c203a08708e171634cfc42f2c8443c72093`。

**整套 HIA 原生化仍未闭合；默认运行链和旧生产实现保留。** 本轮完成 R9 的真实生成、复查与原生尺寸打包，并实际执行原有语义验证；跨目标借用用例仍触发原步数限制。op13 已越过原参考夹具问题，推进至 Native11，暴露出真正的终态隔离登记缺口。修复代码已静态审查，但未把作者结果当作产品通过。

| 范围 | 本轮实际状态 | 可核验依据 |
|---|---|---|
| R8 R4 完整闭合证据 | 原 VM fuel FAIL 保持；2,216 原件、1,130,193,525 B 已完整远端重组，独立终态逐帧读回通过 | [完整原件](v149-r8-r4-complete-actual/RECIPE.json)、[独立终态包](v149-r8-r4-independent-terminal/RECIPE.json) |
| R8 Counted 诊断 | 同一原输入在原 10M 上限下再次得到相同完整失败缓冲区；仅诊断，不构成通过。静态计数证明 317 个移除位点中 28 个在旧前缀至少省 570,519 步 | [诊断包](v149-r8-cross-counted-complete/RECIPE.json)、[静态成本](v149-cost/MOUNT-RECIPE.json) |
| R9 生成与尺寸 | 原生成、check、compile、pack 通过；HIA 398,741 B，镜像 545,428 B，ELF 1,040,384 B。相较 R8 u32 镜像减少 4,438 B。两生成 owner、一次编译、一次 pack，无语义执行冒充 | [实际完整包](v149-r9-prefix-complete-actual/MOUNT-RECIPE.json)、[HIA 源](v149-r9-prefix-complete-actual/file_render_checker_word64.hepta) |
| R9 语义四组 | public 拒绝、Native162、edge VM 通过；合计 163 Native、6 VM，5 PASS / 1 FAIL。cross-target 在 10,000,001 步停止，phase 由旧 0 推进至 1。kernel130、observer-build、pipeline7、tail2 未启动 | [实际观察](v149-late-observations/R9-ACTUAL-TERMINAL-OBSERVATION.json)、[六用例原报告](v149-late-observations/R9-ACTUAL-SIX-VM-REPORT.json) |
| R9 证据边界 | 入场重新完整读取原 6,777 文件、948,620,735 B；948 原角色完全保持，新增14真实候选角色。冻结时全部 raw 已本地封存，远端运输与独立终态读回继续中，尚不宣称语义资格完成 | [作者包](v149-r9-controls-author/MOUNT-RECIPE.json)、[完整 Root 元数据](v149-root-metadata-complete/MOUNT-RECIPE.json) |
| op13 R1/R2 | 原设备 guard 失败与原夹具 Native05 FAIL 全部保留；11,714 原件、135,672,211 B 远端完整重组及失败证据验证通过 | [完整原件包](v149-op13-r1-r2-complete-actual/RECIPE.json) |
| op13 R3 | 使用原 HIA import 命令初始化夹具后，Source8、8 次编译、Native01–10 通过；Native11 的 lost-return 隔离登记断言失败，Native12 / VM12 未启动 | [R3 完整原件](v149-op13-r3-complete-actual/MOUNT-RECIPE.json) |
| op13 R3 证据 | 40,990 原件、236,321,241 B 全部远端重组；8,986 实际 Native 帧、22,411 物理缓冲区独立读回。原 FAIL、未知退休状态与编译 workspace 观察缺口保留 | [Root 全叶 GET](v149-checkpoint/OP13-R3-COMPLETE-CUSTODY-ROOT-FULL-GET.json) |
| Patch 终态修正 | 仅在 Patch 自有 lazy generator 退出和 owner.finish 退出两处，把不确定帧登记进原隔离容器；共享引擎、七个代理、旧测试不变。新增三项独立测试；尚未生成或执行 | [静态作者包](v149-patch-quarantine-author/MOUNT-RECIPE.json) |

R9 五个已返回用例的步数均下降。正式用例的旧实际报告数是 **4,426,100**，新值 **4,028,084**，减少 **398,016**；此前对话摘要中的 2,564,426 并非这份 R4 原报告的值。更正作为新记录追加，原报告不改。cross-target 两轮均因步数上限失败，不能将阶段推进解读为完整语义成功。

所有旧测试 ID、方法、断言、原预算与 fuel、全量 fresh reads、目录和祖先守卫保持。Root 两次产品启动前的外层元数据错误也完整保留：一次把 1800 秒传入只接收最多180秒的 owner API，另一次把描述性 fail_stop 字段当作布尔值；均在产品子进程创建前停止，另版只修外层绑定，未重跑产品或放宽门槛。详见 [当前完整状态](STATE.json) 和 [v149 更新记录](v149-checkpoint/V149-UPDATE.json)。

默认 Hepta main 仍为 `f33d8da316de8fdf27b504371f1a5310997ff548`，runtime 默认 `hepta-runtime-base` 仍为 `ba574f2a6a1b74e85191c58d7bec011720736bb9`。默认 CLI / Worker / Service / Store 尚含 Python / SQLite，runtime 默认22个 Rust 工具；其他 PR 的125个 handlers 是独立范围。部署状态未知；没有切换 main/default，也没有删除旧生产实现。[引用核验](v149-checkpoint/CURRENT-DEFAULT-REFS-v149.json)

接下来完成 R9 独立终态读回并降低真实 phase1 成本，运行 Patch 修正的原生成与全部原验证、新增隔离测试，继续剩余 aggregate、Inspect/R6、Namespace、ordinary current-cold、默认入口、runtime、存储与安装链。只有这些实际门槛全部通过，才具备清理旧整套的依据。

PR #889 原 v148 的 **63,256 字节完整正文**已单独归档，后续精简 PR 摘要不会覆盖历史：[PR 正文历史](pr-history/PR-889-v148-body.md)。

---

## 完整保留的 v148 历史记录

# HIA 原生重写实际执行检查点 — v148

冻结时间：2026-11-14 18:29:32 UTC。父检查点：`b5f4c9e899395a7a66634d04d61966ca6d1984b1`。

**整套 HIA 原生化尚未闭合，旧生产实现保留。** 本轮已执行恢复后的真实产品检查，新增 345 个已逐一完整 Git GET 验证的证据叶。以下为当前实际结果；后附 v147 全文逐字节保留，仅作为历史记录。

| 范围 | 实际结果与边界 |
|---|---|
| R8 输入准备 | 808 份独立输入、136 份原始 oracle 恢复均通过。R4 执行前重新完整读取 6,777 文件、948,620,735 B，原始字节、模式、七字段 stat、路径集合和全部防护保留。 |
| R8 R3 | 首个 public-refusal 的实际零调用证据正确；封装把零写成 None，使原精确数量断言失败。完整失败保留；R4 只修为调用原始 validator，不改断言。 |
| R8 R4 | public-refusal、Native162、edge-VM 通过；共 163 次 Native、6 项 VM，其中 5 通过，cross-target-loans 在第 10,000,001 步触发原 10,000,000 步限制。四个后续组未启动。122.196 秒结束，各 owner 清理完成，无超时。 |
| op13 R1 | 新 3,210 文件源码绑定及独立读回通过；产品启动前 /dev 祖先设备号变化触发原保护，零产品 owner。失败原件保留。 |
| op13 R2 | 新 /tmp 路径绑定、12,146 次独立完整读取通过；Source8、8 次编译、Native01–04 通过。Native05 在原参考夹具初始化时缺少 consume_mask，尚未进入新 adapter；Native06–12、VM12 未启动。 |
| 证据范围 | 上述实际主报告已保存。冻结时，R4 与 op13 的全部原始帧远程归档及独立终态读回仍待完成；观察摘要不替代完整原始证据。 |
| R6 与 Namespace | R6 是显式另版合约修正，原 R5 FAIL 保留，尚未执行。Namespace 固定八字节循环候选只完成作者与逆投影；原 35 项仍为 32 PASS / 3 FAIL。 |
| 清理 | 只清除经完整校验且可重取的 344,034,257 B 冗余下载 ZIP；生产旧实现删除数为零。 |

原测试方法、ID、断言、预算、fuel、完整 fresh reads 和目录/祖先守卫均保留。没有自动重跑、抬高预算、缓存摘要代替读取或删减覆盖。详见 [STATE.json](STATE.json)、[R4 实际观察](v148-late-observations/R4-OBSERVED-TERMINAL.json)、[op13 实际观察](v148-late-observations/OP13-R2-OBSERVED-TERMINAL.json)。

Hepta 默认 main 仍为 `f33d8da316de8fdf27b504371f1a5310997ff548`。相邻 runtime 默认分支为 `hepta-runtime-base`，头为 `ba574f2a6a1b74e85191c58d7bec011720736bb9`；默认 22 个 Rust 工具与另一个固定 PR 的 125 个 Rust handlers 是不同审计范围。默认 CLI / Worker / Service / Store 仍由 Python / SQLite 承担部分职责，部署状态未知。

下一步先封存全部实际原件并完成独立终态读回，再分别修复 op13 原参考夹具与 R8 的真实 HIA 成本；继续执行原大小/pack、完整语义与 aggregate 链、R6、Namespace、普通 current-cold 链和默认入口、存储、runtime、安装替换。只有全套资格闭合后才清除生产旧实现。

---

## 完整保留的 v147 历史记录

# HIA 原生重写当前恢复检查点 — v147

冻结时间：2026-11-14 16:50:45 UTC。前一完整检查点：`bdc9db0a4ba04cc29dd590c098e572da7ef37471`。

**整套 HIA 原生化尚未闭合，旧生产实现保留。** 本轮完成原源码和固定输入在新路径的实际恢复、独立逐完整字节核验，以及一次固定开发解释器的标准库探针。原R8语义组仍未执行，CLI op13仍在作者与审查，准备结果没有提升为产品资格。

| 范围 | 当前实际结果 | 完整证据 |
|---|---|---|
| R8冻结源码 | 3,180文件、98,471,253 B；原SHA/Git/模式、新七字段stat、精确路径集合和Git树全部一致 | [Root读回](v147-root-static-readbacks/SOURCE-RESULT.json)、[恢复包](v147-r8-source-static-recovery/RECIPE.json) |
| 原固定输入 | 948次引用逐次完整读取717,016,014 B；944独立路径710,690,611 B，原角色、顺序、阶段及身份逐项相等 | [Root读回](v147-root-static-readbacks/INPUTS-RESULT.json)、[恢复包](v147-r8-inputs-static-recovery/RECIPE.json) |
| 远端完整保管 | 输入13叶、源码19叶及2个recipe全文GET；实际重组576份元数据19,160,281 B并逐字比较当前原件 | [独立重组读回](v147-root-static-readbacks/REMOTE-CUSTODY-RESULT.json) |
| 固定开发解释器 | 1次CPython3.14.4标准库探针退出0、stderr空、ECHILD及进程组清理通过；2,496文件前后保持 | [完整结果](v147-runtime-readiness/runtime-readiness-r1/RESULT.json) |

原源码树为`4c62be4ed66ff107fa6f88c6131313a354868bd9`。两个输入模式差异明确保留：编译器被捕获副本0400转原要求0644，作者OWNER副本0644转原要求0600。Root输入reader前两次对声明Git字段和嵌套模式来源的错误、完整作者与回执均保留；最终按原声明字段核验948行，为全部行测量新Git身份，没有降低约束。[Root完整作者和读回包](v147-root-static-readbacks/MOUNT-RECIPE.json)保存17个逻辑文件3,362,845 B。

R8正在作者新连贯目录视图：808个非oracle输入独立复制到新的共享内存目录；136个原oracle仍须由原restore owner在180秒执行、3秒清理限制内实际恢复。原3GiB空闲门槛、Native162、VM6及130/7/6/2 aggregate的正文、顺序和预算保留；本冻结时binder、copy及上述产品组均为0。静态恢复不替代原restore阶段。

开发探针明确发现z3和pytest尚未恢复，旧venv没有继承，项目导入依赖仍在审查。源码公开恢复包排除4份私有签名下载响应/HTTP头，168份完整源码GET响应正文仅留本地。原CLI R5 witness-10仍为FAIL，未应用的契约提案、未到达后缀及历史原件缺口全部保持。

本冻结时再次核对默认Hepta main=`f33d8da316de8fdf27b504371f1a5310997ff548`、runtime默认`hepta-runtime-base`=`ba574f2a6a1b74e85191c58d7bec011720736bb9`；实际部署runtime版本仍未知。没有修改原测试、提高燃料或预算、缓存摘要、裁剪源码或删除旧生产实现。

---

## 保留的v146完整记录

# HIA 原生重写恢复检查点 — v146

冻结时间：2026-11-14 16:12:04 UTC。前一完整检查点：`eb0e9670b8065707187204f21f1e8ae8919a3a15`。

**整套 HIA 原生化尚未闭合，旧生产实现保留。** 本轮继续完成了 PatchResult 的实际 Native 编译、原 Native12 和原 VM12；CLI R5 推进到第十个见证用例并暴露真实契约冲突。随后执行环境原工作区与临时目录消失，尚未远端封存的部分运行原件无法继续读取。因此本检查点分别记录实际观察、完整保管材料和确实缺失的证据，不将有限门通过提升为当前环境或默认整套资格。

## 最新实际结果与证据边界

| 范围 | 已实际观察 | 本检查点可证明的边界 |
|---|---|---|
| PatchResult build R2 | 1 次原编译通过，HIA 103,357 B → 镜像 123,468 B；六个实际缓冲区完整核对 | 43 个运行原件及作者/Root材料共81个逻辑文件完整远端保管；[完整包](v146-patch-build-r2-complete/TREE-RECIPE.json) |
| PatchResult Native12 | 12 方法、24事件、10子测试通过；9,844次实际调用，其中9,176次Patch、668次Inspect；原180+3 owner和ECHILD成立 | 新归档仅30/207片完整远端保管。前缀实际解压未得到任何完整TAR成员，恢复原件数为0；[缺口记录](v146-patch-native12-partial/INTERRUPTION.json) |
| PatchResult VM12 | 12方法、24事件通过；12组返回值及72 VM跨度对72 Native跨度逐字相等；原10M步骤/8MiB/depth128保持 | 新VM原件及有限链终态未完整远端封存。保留的执行工具回执与作者文本支持历史观察，不代替原始运行包 |
| CLI op10 R5 | 前13阶段通过；第14阶段witness-10为1 FAIL/0 ERROR；后4组未启动 | 原测试期望1次refusal，真实原流程产生2次；未删除第二次验证，也未改原断言。作者与实际前检完整，失败运行原件不完整 |
| R8 R2 | 147个作者文件和原语义/aggregate控制完整保存，环境中断后重新逐字读回 | 原Native162、VM6、130/7/6/2仍为0次；未重放旧restore或product计划 |
| CLI op13 | 两个源码草稿从完整工具文本恢复，另有明确标记的中断后support草稿 | 仅AST检查；缺少旧独立字节pin，未执行产品，也未完成默认调用接线 |

所有原测试ID、正文、断言、时间/CPU/内存/容量/VM预算保持。没有通过删除用例、缩减源码扫描、摘要缓存、自动产品重试或提高预算获得通过。默认main仍为本轮核对的`f33d8da316de8fdf27b504371f1a5310997ff548`，没有因这些有限结果获得整套资格。

## 环境中断与已保存材料

Root在2026-11-14 15:22:06 UTC使用显式`/tmp`工作目录确认原工作区、Root临时目录、Native归档目录及共享内存生成目录均不存在。中断原因未知；没有重建旧路径并声称恢复旧device/inode/ctime。GitHub对象和会话保留文本仍可读取。

此前v145的1,420个叶片已重新全文递归GET核对。本检查点新增204个叶片，包含54份Root恢复记录以及CLI R5、Patch编译、R8作者、op13草稿和Native部分归档材料；所有新增载荷均由Root全文GET并核对字节身份。具体分类和边界见：

- [环境中断事实](v146-recovery/ENVIRONMENT-DISCONTINUITY.json)
- [中断前实际执行观察](v146-recovery/SESSION-OBSERVATIONS.json)
- [保留文本与工具回执清单](v146-recovery/RETAINED-PAYLOAD-MANIFEST.json)
- [Native部分前缀实际恢复结果](v146-native-prefix-recovery/RECOVERY-RESULT.json)
- [R8作者包中断后读回](v146-r8-reset-readback/RESET-READBACK.json)
- [op13草稿恢复边界](v146-op13-recovered-drafts/RECOVERY-REPORT.json)

Native归档完整压缩体原为27,009,263 B；已保存的前30片合计3,932,160 B，仅能解压出部分首个INDEX成员。该INDEX正文原需38,902,040 B，实际前缀仅含24,289,263 B，尚缺14,612,777 B；gzip未到EOF，也不能检查终态CRC。缺少的177片没有从哈希凭空补出。更早Inspect归档仍为44/179片，也不声称完整恢复。

## CLI R5 的真实未闭合点

R5保留R4的完整code-object比较，仅修正固定CPython3.14操作数code object的位置元数据。原60字节代码及15项非位置字段保持，完整原64,615行有序前驱保持。实际产品执行69.814360769秒后在原witness-10停止：Source18、7次编译和witness-01..09已通过，witness-11、witness-12、retained3及原CLI43没有启动。

原`inspect_program`首先调用`verify_program(document)`，随后访问`normalization_report`；该属性再次调用当时的`verify_program(self)`。原busy回调因此观察两次拒绝，而用例末尾要求一次。三条busy状态断言在两次回调内均通过，最后计数断言失败。删除原第二次验证会改变可观察行为，修改原断言也不能算保留原资格。中断后又从完整作者包恢复12个精确源码文件进行独立源级审查，确认该失败段直接调用owner并绕过CLI适配层；保留两次正常provider调用和每次回调的三条状态断言，就必然追加两个marker，无法仅修wrapper同时满足singleton断言。[完整源码证明](v146-r5-contract-review/ANALYSIS.md)和[未应用的版本化契约提案](v146-r5-contract-review/PROPOSED-CONTRACT-SUCCESSOR.diff)已保留。原R5仍为FAIL，提案没有应用或执行。该用例的lost-claim后缀尚未到达，不能声称通过。

完整[作者包](v146-cli-r5-authoring/TREE-RECIPE.json)、[前检作者](v146-cli-r5-preflight-author/TREE-RECIPE.json)与[实际前检](v146-cli-r5-preflight-actual/TREE-RECIPE.json)可恢复；尚未保存的15,188个实际失败原件不由这些材料代替。

## 固定运行时已静态恢复

原Actions artifact 14062024126的39,213,243 B ZIP已通过真实下载恢复。原解释器、动态库及标准库共2,496文件、108,197,034 B均在全新路径恢复。Root独立重新读取ZIP全部12成员、内部gzip完整终态与2,496个TAR成员，逐完整字节比较当前2,496文件，并核对原模式及此次新七字段stat。原解释器17,752 B、libpython32,366,232 B的固定SHA均完全相符。

- [独立完整静态读回](v146-runtime-static-root/ROOT-READBACK.json)
- [原始manifest、新身份与恢复报告完整包](v146-runtime-static-recovery/RECIPE.json)

该恢复没有执行解释器、binder、产品或CI；旧venv、6,487个原导出排除路径及旧动态映射身份没有继承，动态运行时资格仍为false。此项恢复填补的是开发工具字节，不代表产品已经摆脱Python或整套HIA资格完成。

## 源码与输入的恢复路径已找齐

[R8恢复可行性报告](v146-recovery-feasibility/REPORT.json)逐项映射了3,180个实际源码文件及948个固定输入引用（944个独立路径）。源码共98,471,253 B；独立输入共710,690,611 B。原编译器被捕获副本的0400模式与所需固定输入0644模式不同，后续恢复必须明确记录模式设置和新身份，不能声称旧文件未变。

该报告冻结时尚未找回compact的70片传输入口。其后已经从保留的旧完整读回记录定位到[原78叶recipe及70片INDEX](v146-compact-transport-locator/RECIPE.json)，Root已全文GET两份清单并核对每片映射。旧R5 Native162通过、VM6为5通过/1原10M燃料失败，以及两项历史缺失原件全部保持。源码和所需输入正在新路径恢复，尚未借此执行任何产品或继承原资格。

## 整套替换与清理门仍未闭合

Hepta的普通CLI、Worker、Service和Store链仍有Python与SQLite所有权。hepta-runtime的默认分支`hepta-runtime-base`固定在`ba574f2a6a1b74e85191c58d7bec011720736bb9`，有22个处理器且没有被审计PR121的11条HIA链；固定PR121 `008036843625e12c21b6dc533be5cf3115cda579`有125个处理器，其HIA路径仍经过Rust分派/持久任务和Python Worker/Service/SQLite。两个native-local处理器没有替换默认Rust分派；实际部署版本未知。两种范围不可混为一谈。原R20 NativeNamespace仍为32 PASS／3 FAIL，私有R8原语义与aggregate门未执行，当前源码的cold生产者、严格读取器、选择器和负例尚未整体通过。原普通测试入口及安装/默认激活也须独立闭合。

下一步完成原源码和固定输入的恢复，独立验证新环境中的固定运行时，并记录新的路径及身份；然后继续解决CLI契约、op13接线、R8和namespace的真实功能门。任何恢复均不继承已失效的旧stat证明，任何有限门都不授权旧生产整套删除。

## 保留的 v145 历史快照

以下原文完整保留，反映当时冻结状态；与上文冲突的待办状态以v146明确范围为准。

---

# HIA 原生重写进度 — v145

冻结时间：2026-11-14 14:20:45 UTC。前一提交：0ff42a9d7fd1f3876deb804c9c3288c64d754d88。完整谱系、原测试与历史失败保留在 [STATE.json](STATE.json)。

**整套 HIA 原生资格仍未闭合，旧生产实现继续保留。** 本轮已经完成 PatchResult 的两次真实生成、一次一致性检查和原 Source11；u32 编译与 HIA 打包跨过 R8 的实际容量障碍。CLI 原控制序列推进到第五个见证用例，暴露并保留了新的真实失败。以下每项结果均限于所列源码和执行域。

| 范围 | 本轮真实结果 | 仍需完成 |
|---|---|---|
| PatchResult 原策略 | 两次生成与一次 check 通过；24 函数、247 块、1,876 操作；3,202 文件和 13 宿主绑定由 Root 全量核对 | 单次 Native 编译、原 Native12、原 VM12及默认生产调用接线 |
| PatchResult Source11 | 11 方法、22 起止事件、15 子测试通过；原 Source10 正文与 ID 保留，新增 slice 常量检查 | Source 通过不授 Native、VM或当前源码 cold 资格 |
| u32 → R8 → 私有打包 | 1 次实际编译和 1 次 HIA 打包通过；R8 549,866 B，ELF 1,044,480 B | 原 Native162、VM6、aggregate 130/7/6/2 与公开配置及 cold 的独立验证 |
| CLI op10 R4 | Source18、7 次编译及 witness-01..04 通过；witness-05 失败；后九组未启动 | 修复操作数 code object 的位置表后，保留原 18 组／76 方法调用重验 |
| CLI op10 R5 源码 | 位置表最小修复已作者；固定 3.14 元数据诊断通过，Root 完整读回 6 个 Git 叶 | 独立物化与原产品控制尚未执行 |
| u32 原入口布局20 | 既有有限20检查结果不变；完整远端保管补齐，28叶与recipe由Root全文GET | 未执行原 ordinary unittest，未获得 matching-current-source cold |
| namespace / 默认整套 | 原固定 R20 NativeNamespace 仍为32 PASS／3 FAIL；默认生产链仍有外部语言所有权 | 保留 fresh 全量读取、原守卫与预算，继续真实原生替换 |

## 本轮实现与独立核验

### PatchResult：完整策略生成与 Source11

R3 生成前审查发现的 exact slice 常量缺口，已由 R4 的递归 start/stop/step 比较补齐；未知常量仍拒绝。两段原策略 apply_program_patch 与 _check_patch_interface 全文保留。R4.2 另只修正生成器的唯一输出目录字面量。所有旧作者版本与阻断原件均保留。

真实生成 session 45405 返回0，耗时28.813967791秒。三个原180+3 owner均完成并取得ECHILD；两套输出与三份安装文件逐字相等。Root独立核对原3,188文件、完整3,202文件后继、原3,199准备文件不变、新inode独立无硬链接、所有源文件模式与七字段stat、控制和固定解释器。HIA源码为103,357 B。

Source11 session 28469 返回0，耗时8.829049490秒。原10方法和新增slice控制按原序执行，错误、失败、跳过、expected failure与unexpected success均为空。原测试内部的生成复现仍在同一个180+3 owner内执行。Root核对11方法、22事件、15子测试、89实际执行控制、65作者权威、完整当前3,202文件及进程回执。

- [14个实际原生策略相关源码文件](v145-patch-result-native-source/)
- [生成终态独立证明](v145-root-review/patch-generation-r4-2-root-terminal.json)
- [Source11终态独立证明](v145-root-review/patch-source11-root-terminal.json)
- [生成完整保管清单](v145-actual-custody/patch-r4-generation-manifest.json)
- [Source11完整保管清单](v145-actual-custody/patch-source11-actual-manifest.json)

接下来的单次编译门已作者，必须消费本次实际Source11记录；冻结时尚未执行。原Native12与VM12也尚未执行。既有selected_prepare_patch、Agent mode2和生产默认入口的资格不会由Source结果自动改变。

### R8：实际镜像与打包容量通过

实际session 93012返回0，外层耗时6.860173643秒。固定u32 B3镜像对原R8完整源码进行一次真实编译，得到549,866 B镜像，比旧562,746 B缩小12,880 B。严格ELF组件上限557,376 B、原1 MiB总容量及frame上限均保持。

实际三组件frame为1,040,064 B；原HIA packer输出ELF 1,044,480 B，余量4,096 B。ELF保持0644，没有执行、安装或公开配置提升。原controller 59,889 B与representation 430,261 B保持。Root完整核对12个逻辑缓冲区、六个物理canary跨度、两个真实request/report/全量hex、输出尾部、源不变、ELF布局及对齐填充、四份完整源码快照和当前3,180文件。

两个调用共享一个原180+3 owner，各自20秒／10CPU／1MiB限制保持，ECHILD成立。原SyntaxWarning完整保留。完整77原件共37,837,128 B已无损保管并全文Git读回。

- [R8实际大小与打包独立证明](v145-root-review/u32-r8-size-pack-root-terminal.json)
- [全部原件清单](v145-actual-custody/u32-r8-actual-size-pack-manifest.json)
- [完整可逆保管包](v145-actual-custody/u32-r8-actual-size-pack-capsule.json)

原Native162／VM6和aggregate 130 kernel／7 pipeline VM／6 fullframe／2 last-byte控制待执行。下一阶段使用明确的私有R8参考域，公开R5配置的原source pin及R8拒绝行为继续保留；不将该私有参考等同于原公开profile通过。ordinary源码选择与matching-current-source cold均未闭合。

### CLI：真实 R4 失败与 R5 最小修复

R4仅在records模块补入12字节import copy，恢复固定CPython3.14下被捕获函数与被动模板的原完整code-object比较。没有放宽比较器。3,191文件独立字节复制完成，所有原文件、模式和七字段stat保留。原61,550前驱行完整保留，追加R3真实失败的133行，形成61,683行实际前驱。

session 37139返回1，耗时50.494759353秒。前八阶段通过，包括原Source10、Source8、七次编译和四个新见证方法。witness-05的test_every_import_failure进入正文后，真实ImportFailure经过一个co_linetable为空的60字节私有端口code object，固定traceback查询位置时抛StopIteration；unittest和观察器后续格式化也失败。第九owner返回1并完成清理，其余八owner返回0；全部保留原180+3和ECHILD。后九组，包括retained3和CLI43，没有启动。

Root完整核对2,930原件／22,039,778 B以及600次已观察的真实机器调用及其完整六缓冲区。前四见证的28个journal已最终化；失败组七个journal没有INDEX，已存在的四次调用前后帧仍完整保留。设置阶段早于journal的准入调用不计入600。ECHILD不证明所有语言帧退休；原七次编译未观察完整workspace。

R5源码仅修复操作数位置元数据，保持60 B指令、15项非位置字段、导入顺序、异常传播和原测试。原导入片段19个真实位置与11个合成无位置条目覆盖全部30个code unit；固定3.14元数据诊断另检查完整原模块53个code object／13,389个位置。诊断没有执行项目code object或端口。R5尚无产品通过结果；未来独立运行必须保留原61,683行，再追加R4 proof、inventory与2,930原件，总计64,615行。

- [R4真实失败独立证明](v145-root-review/inspect-cli-r4-product-failure-root-terminal.json)
- [R4完整保管清单](v145-actual-custody/inspect-cli-r4-actual-failure-manifest.json)
- [R5源码及诊断完整recipe](v145-cli-r5-source-authoring/TREE-RECIPE.json)

## 整套闭合与清理门

当前default main实际读到f33d8da316de8fdf27b504371f1a5310997ff548；本轮没有把有限组件结果继承为该默认提交的全量资格。固定R20历史Source1421及NativeNamespace结果保留各自谱系。

默认runtime审计中的PR121共125个工具处理器，仍有Rust分发、Rust持久化所有权、Python Worker／Service和sqlite3链。现有局部HIA owner和native-local两个入口已记录，完整默认dispatch替换未完成。CLI opaque issuer registry、外部provider及连接层也仍需处理。

继续顺序是：PatchResult单编译与Native12/VM12；CLI R5原全序列；R8原语义与aggregate；namespace原失败；默认CLI／Worker／Service／Store与runtime全部处理器、安装入口、matching-current-cold producer／strict reader／selector／negative controls。删除旧生产实现须在这些实际路径闭合后进行。已有旧失败、原预算、原断言与所有权隔离不因后继通过而移除。

本轮新增103个Git叶，保留前一提交的1,317叶；仅当前README和STATE替换为新快照。旧Native大档续传停在44/179个完整ACK／GET边界，未冒充完整远端保管。

---

## v144 原快照（完整保留，以下状态属于上一冻结时点）

# HIA 原生重写进度 — v144

冻结时间：2026-11-14 13:39:26 UTC。前一提交：`5ecafbb86dc79514a73efdf6fddaae5f3b9ac708`。完整字段、谱系与历史失败见 [STATE.json](STATE.json)。

**整套 HIA 原生资格尚未闭合，旧生产实现未删除。** 本次取得新的有限组件结果，也保留了真实阻断。原测试、ID、断言、燃料、期限和失败原件均继续保留。

| 范围 | 本次实际状态 | 资格边界 |
|---|---|---|
| Inspect drive R3 | 两次生成、一次check、Source18、Native17、VM12全部通过；Root完整核对证据与当前三棵源码树 | VM只重放明确选定的12帧；四次丢失返回的未知所有权隔离保留 |
| u32入口布局 | 原20检查通过：24编译、32invoke、8个原1M燃料VM参考、8链接、4ELF；Root全量原件核对通过 | 显式源码投影，未执行原ordinary unittest方法；ELF内部workspace未观察，未获得当前源码cold资格 |
| CLI op10 R3 | Source18与7次编译通过；第一个新控制在setUp定义准入处ERROR，立即停止 | 5个owner完成原180+3和ECHILD；后13阶段、retained3、CLI43未启动，新op10正向资格未取得 |
| namespace单次fresh诊断 | 独一CI调用一次原current_sources，1551文件全部fresh读取；Root原ZIP与事件核对通过 | 原NativeNamespace 35项仍为32 PASS／3 FAIL；270.75ms包含观察开销，不能当优化收益 |
| PatchResult策略 | 11个新增源码已作者；Root发现exact slice常量未覆盖，在生成前阻断 | HIA、ports、data均未生成，新Source／Native／VM未运行；最小后继尚待完整审查 |
| u32 R8大小与打包 | 19个作者对象由Root完整远端读回，具体执行计划冻结 | 零新编译、零打包；须满足严格ELF大小上限后才可进行一次HIA打包 |

## Inspect drive 的实际闭合范围

R3只在真实pending已发出且尚未执行时调用原service，再交回原drive完成真实ACK。原service、step、finish和ContinuationFrame不变。同帧重入仍拒绝，独立帧可以进入；额外Python辅助调用帧的可观察性边界保留。

当前独立3188文件树为 `b7a3881a4d9f6d5a725d6e8d560fa492f6b26d96`。唯一Native／VM运行session5079以0退出，外层730.344秒，其中原catalog构造在各180秒owner之外。Root核对61495条完整证据、13586次实际机器调用、34081个唯一完整缓冲区、12个真实Native／VM六缓冲区比较、22组源码保护记录及当前三树的全字节、模式、七项stat和路径集合。完整结果见 [Native与VM终态](inspect-drive-r3-root/ROOT-DRIVE-R3-NATIVE-VM-TERMINAL.json)。

没有宣称全部13586次调用都经VM，也没有宣称未知所有权全部退役。此前把第09目录出现描述为“VM已经运行”的中途说法已纠正。原catalog重复哈希的成本未通过缓存、裁剪、重试或加预算规避。原R2的11 PASS／1 ERROR及未知退役原件保留。Source18完整原件已封入Git；Native／VM的179份压缩分片本机已完整复原校验，远端运输尚未全部闭合。

## CLI op10 的实际失败与修复方向

旧绑定计划为26,454,315字节，超过原执行器16MiB输入上限。R3把全部61,550条前驱记录按原顺序分成四份不超过8MiB的索引，主计划降为25,729字节。Root逐条核对原件，逆向恢复旧计划全部字节；原10项控制保留，实际R3 executor、support、tests三个执行路径均绑定。没有删前驱、加上限或改变18阶段、76次方法调用、7次编译和预算。76是调用次数，包含重复保留项，不能当76个不同ID。

实际session45546只运行一次，38.688秒后退出1。Source10、Source8、六映像构建、Inspect构建四阶段通过。第五阶段 `test_actual_record_and_hia_op10` 在setUp调用 `issue_preselected_inspect_record` 时拒绝真实 `function_signature`，报 `ValueError: selected function is not the frozen policy definition`。没有进入该测试体，没有自动重跑。见 [失败核对](inspect-cli-op10-r3-root/FAILURE-TERMINAL.json)；131份实际attempt／outer原件，加7份Root记录，均可由 [完整失败原件](v144-custody/op10-r3-actual-failure-CAPSULE.json) 复原。

执行后的独立compile-only诊断发现，Python3.14编译上下文造成原signature的248字节code与模板244字节code及异常表不同：原模块有 `import copy`，被动模板没有。源码或AST相等不足以证明code对象相等。R4最小候选仅补齐这次模块setup import，继续严格比较全部原字段；额外import hook、异常、引用及traceback影响明确记录。候选尚未物化新3191文件树，尚未进行新产品执行。

三个CLI适配器由完整外层源码树绑定；旧六映像manifest本身未包含三路径，support contract也未再生。原CLI43嵌套子进程不能被描述为已选择新私有op10。当前结果仍为开发范围。

## u32与namespace的边界

u32入口检查使用实际R19加五个u32文件的3180文件树 `4c62be4ed66ff107fa6f88c6131313a354868bd9`。Root核对830份原件、173,880,184字节、77个调用索引项、154事件及32次完整六缓冲区观察。8个原VM参考在首次Native调用之前完成；原四次0644到0700的ELF chmod来自原函数，捕获时模式与执行时模式明确区分。冻结runner的SyntaxWarning保留。该投影不能替代ordinary、R8语义、aggregate或最终current-cold。

R8计划保留原20秒、10 CPU秒、1MiB跨度。三映像frame允许R8最大558,378字节，而4096对齐后的ELF只允许557,376字节。相对旧562,746字节需减少5,370字节；历史6,600字节保守估计保留。若真实编译产物不满足两项边界，必须拒绝打包。原R5生产读取器source pin不放宽，生成ELF只保存0644且不执行。

namespace唯一CI为run43595690951／job132449559860，固定R20源码3177文件。Root核对原ZIP27成员、四次完整源码快照、22,820事件／11,410成对区间、1551个实际fresh读取和1823次保护。原current_sources一次测得270,752,930ns；保护、读取和LINE区间有嵌套重叠，不能相加，也不能推断未观察版本的期限余量。没有摘要缓存或闭包裁剪，原E_HIA_BUDGET未修复。公开保管保留产品ZIP全部27成员、130份普通原件及两份明确标注的非秘密响应投影；带临时凭据的两份原始响应仅保留本机。

## 新策略与生产调用链

PatchResult owner准备降低完整 `apply_program_patch` 与 `_check_patch_interface` 原体，保持两次验证、prepare顺序、接口比较、回执字段顺序和业务receipt中的 `native_executed: false`。既有selected_prepare_patch及Agent mode2字节引擎不变。四值解包端口只处理原UNPACK的有限形状。

Root在固定3.14.4下只compile完整模块，没有执行项目模块或策略体，就发现原 `changed[:8]` 的co_consts含exact slice，作者比较器未覆盖而必然拒绝。旧R1／R2／R3源码、控制与失败前检保留在 [Patch作者原件](v144-custody/patch-author-r1-r2-r3-CAPSULE.json)。slice后继递归比较start、stop、step，保留未知类型拒绝和全部code字段；原10个Source方法全文保留，另加一个窄控制，尚未执行。生成器最终缺失／漂移检查已补齐；R4新目录与旧硬编码名称不一致也在执行前发现，R4.2精确单字面量修正已作者，仍待Root核验。

生产调用链审计区分真实范围：hepta-runtime固定默认头有22个Rust工具handler；125个handler属于固定PR121头，不能写成默认主线数量。两个native-local示例尚未替换公开Rust调度。HIA工具链仍跨Rust调度、durable owner、Python Worker、Service及sqlite3；这些层已有可选HIA owner，但默认入口、资源闭包和进程／存储链尚未整套闭合。见 [生产调用链](production-next-boundary/CALL-CHAINS.md)。

本次实际读取主线头为 `f33d8da316de8fdf27b504371f1a5310997ff548`。固定谱系测试不自动转移为该主线或后继源码的全量资格。继续修复并实际验证CLI、PatchResult、R8和namespace，再完成当前源码cold、安装链和全部默认生产入口；这些条件闭合后才执行旧生产整套退役。
