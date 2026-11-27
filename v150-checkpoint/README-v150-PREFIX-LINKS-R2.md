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

