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

