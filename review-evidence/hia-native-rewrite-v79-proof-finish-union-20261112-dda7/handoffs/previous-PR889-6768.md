## 当前结论：整套全 HIA 原生交付尚未闭合

此 PR 保持 **draft**。产品 HEAD 仍为 `4b19af89a766593f7d5f1cc2db256e81aba7afcb`，产品树仍为 `1bc7c90996e1910ad66ba771b0bfee1d5bfa655c`。后继源码在独立开发分支和可恢复源码包中推进，尚未合成为默认启用且完整资格通过的产品。

**没有合并 main、没有切换默认入口、没有删除旧生产栈。** 用户已授权完成重写并在技术闭合后清理旧栈；剩余阻塞来自实际实现与资格，毋需重复索要许可。

完整当前材料：

- [全量剩余差距审计：576 条源码路径、20 个业务族](https://github.com/TrillionniumFoundation/Hepta/blob/1e47764e0d5d0577330029ea4029a6a83dcac2b1/review-evidence/hia-native-rewrite-v78-source-owner-custody-20261112-dda7/FULL-REMAINING-AUDIT.md)
- [逐路径源码身份、职责与闭合条件](https://github.com/TrillionniumFoundation/Hepta/blob/1e47764e0d5d0577330029ea4029a6a83dcac2b1/review-evidence/hia-native-rewrite-v78-source-owner-custody-20261112-dda7/FULL-REMAINING-AUDIT.json)
- [本次完整原件与源码包目录](https://github.com/TrillionniumFoundation/Hepta/tree/1e47764e0d5d0577330029ea4029a6a83dcac2b1/review-evidence/hia-native-rewrite-v78-source-owner-custody-20261112-dda7)
- [完整传输与文件摘要索引](https://github.com/TrillionniumFoundation/Hepta/blob/1e47764e0d5d0577330029ea4029a6a83dcac2b1/review-evidence/hia-native-rewrite-v78-source-owner-custody-20261112-dda7/INDEX.json)
- [准确的恢复状态与仍未闭合项](https://github.com/TrillionniumFoundation/Hepta/blob/1e47764e0d5d0577330029ea4029a6a83dcac2b1/review-evidence/hia-native-rewrite-v78-source-owner-custody-20261112-dda7/RECOVERY-STATE.json)
- [此前完整 PR 正文，逐字保存](https://github.com/TrillionniumFoundation/Hepta/blob/1e47764e0d5d0577330029ea4029a6a83dcac2b1/review-evidence/hia-native-rewrite-v78-source-owner-custody-20261112-dda7/handoffs/previous_pr889_58420.md)

审计分支新增提交为 `1e47764e0d5d0577330029ea4029a6a83dcac2b1`，父提交为 `e7ecd135b5f97204292de2b61e6875ffadba1c58`。所有先前审计子树保持相同，产品分支没有因此移动。

## 已实际完成的验证及范围

| 范围 | 实际结果 | 边界 |
| --- | --- | --- |
| 联合源码 R2 | [run 43240090419](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43240090419)：实际 Python 3.14，82 个生成器、原 157 个选择器产生的 764 项完整有序检查全部通过；原 `git diff --cached --check` 返回 0 | 3181 个冻结文件，真实 CI Git 树 `43e17b3cc225af8a8ddab795696a4ebad799cef7`；只授予该源码树的源门禁资格 |
| Core / Plan R4 | [run 43244880819](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43244880819)：60、124、44 三组全部通过 | 整个原运行仍为 **FAIL_OR_INCOMPLETE**：旧基线 120 项阶段参数错误，未执行其业务用例。补充 [run 43248933245](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43248933245) 只观察旧 R3 的 64 相等、56 差异，不能改写前一运行 |
| Emitter R4 | [run 43231246218](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43231246218)：实际 3.14 原 116 项通过，旧六方法零进入 | 六个完整方法的后继资格，不覆盖所有外部 provider 或新联合源码 |
| Byte 与 whole-emit 接线 | [run 43231223573](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43231223573)：25 + 29；[run 43236730014](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43236730014)：新增 4 + 原 29 全部通过 | 捕获 owner/absence、原 exports 域和实际绑定；单个 selector 不自动选择所有下游 owner |
| Service Emission R6 | [run 43220160251](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43220160251)：52 + 12 + 16 + 16 + 48 通过 | 完整服务发射策略与其冻结身份，仍需并入最终联合树 |
| Service Verification R6 | [run 43250927176](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43250927176)：实际 3.14 的 12 固定机制 + 2 默认 replay 回归 + 原 43 组件 + 原 48 调用者通过 | 修复真实默认 replay 的 carrier 变量错误；原七策略零进入；仍依赖独立 proof engines |
| NativeBuild | [run 43253621060](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43253621060)：实际 3.14 的 25 组件 + 原 114 调用者通过；原报告全部有序 ID、零异常、旧 writer 零进入 | 原 9 个根模式实际执行，完整 3203 源文件在运行前后不变。完整日志和 32 份原文本已无损恢复；22,483,410 B 原二进制 ZIP 的独立 CRC 核验另列未完成 |
| CallArena | 冻结候选本机 26 项通过，原 22 项方法 AST 完整保留 | 四文件开发结果；没有据此宣布原六个 deadline 失败或原 377 项性能风险已闭合 |
| Proof 固定 foreign 机制 | [run 43252053853](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43252053853)：实际 3.14 的 17 项通过 | **零 HIA / 零 Proof 策略入口**，不可把它当成完整 Proof 重写资格 |

表内各组不相加为“整套通过”。每组绑定各自真实 source/image/manifest、原测试分母、时限和运行记录。

## 本轮修复与正在形成的联合候选

已修复并保留对应原始失败：CPython 3.14 固定调用及常量布局的真实差异、默认 replay 的局部变量错误、原生调用临时对象寿命、全局名称删除/替换语义、Source/Core 与 coordinator 机制的身份清单边界，以及多余末尾换行导致的原 Git 源检查失败。

当前又有明确的共享结束处理问题：Core 与 Plan 的显式 held frame 在调用者已处理异常的作用域内成功返回后，旧 `sys.exc_info()` 判断会阻止退休。普通直接 `run` 路径在原小反例中未证明泄漏。Byte 存在同形源码，Emitter / Verification 分别继承这些路径。后继使用成功完成标志、异常重置和原有 `finally.close`，不额外持有返回对象，不释放失败或 unknown frame，不重放已发行操作。Byte 的旧版行为需要实际前控；新源需要独立完整资格。

联合作者正在合并 Core、Emission、CLI、Emitter、Byte、Verification、NativeBuild、CallArena 和上述 shared-finish 修复。共享 backend/service/checker/helper/资源声明按精确基底合并；生成的合同和 inventory 要在真实 Git checkout 重新产生。原 82 个生成器、157 个选择器和 764 项有序身份保留，新增组另列分母；当前扩展数量尚待真实 3.14 执行确认。

## Proof 新候选与执行环境的准确状态

共享执行环境在 2026-11-12 变为 unavailable，exec-server 恢复失败。

断连前的新 Proof 整合候选完成本机 64 项组件检查；原 40 项调用者门禁在缺少已固定 Z3 依赖的启动阶段退出，业务主体尚未执行。该候选的完整 3202 文件、生成器/HIA 输出和原新测试组尚未持久恢复。两个累计包的摘要虽已计算，但没有 Git create ACK，不能把它们当成已发布源码。

现已恢复并逐字核对五份原件：native、control、selection、固定 foreign 源码，以及原 4b Proof oracle。前三个机制源中的 native/selection 和 foreign 还与先前独立审计保存的完整源文本交叉匹配。新恢复候选继续使用原八个策略 AST；新作者的生成器、接线和测试明确是新修订，**不继承失联的 64 项通过结果**，需重新完成实际 3.14、原 22 Proof + 18 SafeCore 完整 40 项调用者、原编译与运行时限。

本机 NativeBuild 原 114 项任务最后状态为 **UNKNOWN**；另一份远端成功运行不替代该本机终态。通过 GitHub 的独立开发、源码恢复与真实 CI 继续进行；没有重放无法确认的本机任务。

## 全量审计确认的剩余职责

当前 exact4b 的 3153 条 Git 文件身份已逐项对齐；197 个生产 Python 模块、378 个 tools 模块及 setup.py，共 576 路径，映射为 20 个业务族。代码行或路径数量不作为语义完成百分比。

1. **Agent 评估、成本账本和采用准入**：包括 `_hia_evaluate`、`_cost_ledger`、构建准入、采用证据与 lease 调用。已原生的 CAS/namespace 不等于外层决策迁移完成。
2. **完整公共规范化与前端**：保留原对象、别名、循环、富比较、错误、编码器及递归域；不能拿 bootstrap 的有限 profile 缩小公共域。
3. **源码、安装、helper 与 checker 准入**：完整 fresh source/image/manifest 身份、ordered maps、首错顺序、captured/held 身份和五类资源，仍有外层策略。
4. **Worker、service dispatch 与 provider**：完整 wire/vocabulary、启动、分派、journal/unknown 状态，以及进程监督、ELF/符号/映射/工具身份与出版顺序。
5. **独立 proof engines、proposal、其他 target、持久状态机及 NDU**：不能由协调器或 x64 后端的资格替代。
6. **最终运行时与部署**：固定 CPython 对象/调用/异常桥仍是生产依赖，不能宣称 Python 运行时已经消失。当前 whole-HIA / default / live-migration / legacy-removal 均未闭合。

完整模块映射、逐项源码锚点和执行优先级见上方全量审计。

## 原始阻塞与最终晋级条件

原 [run 43197399906](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43197399906) 的 namespace/ledger 六次 deadline 失败仍未闭合，包括 baseline capture timeout、candidate context expiry，以及 native timeout 超过原 5 秒。后置两项诊断通过走的是 native child 未启动的预算拒绝路径，不能替代原失败。原 nominal 377 项确实通过但耗 2258.701 秒；未来 v10 的原 1800 组限存在风险，**v10 从未执行**。

最终需要同一精确联合源码依次完成：全部生成与源检查；当前源码完整 cold bootstrap 和 fixed points；该 cold 编译器生成全部 owner；完整组件与原调用者；原 27 组和无过滤 retained full discovery；worker / wheel / installed / live continuity；默认 HIA 组合；最后删除旧生产栈并从干净安装复验。

原编译 20 秒、cold 180 秒 + 3 秒清理、各原 1800 组限、原 public deadlines 与 full 5400 秒限制均不放宽。没有缩小原域、过滤原测试、吞掉异常、扩大 deadline 或跨调用缓存源码身份来换取通过。

## 原件保管

新审计目录挂载 **316 份完整归档分片**，包含首次失败和继任成功的两份联合源码 CI 完整 ZIP。分片包装/Git blob、原始区间和重组完整归档摘要均经过核对。Core/Byte/Verification/NativeBuild 的完整与选定原件范围在索引中分别声明，不把小报告包冒称完整大 ZIP。

原首次读回缺失、后来独立核对、旧小包日志多一个换行及其修正、Git 大树发布超时与 422 原响应均保留。此前审计和原始失败不覆盖、不删除；最终旧生产栈移除也不能删除独立 oracle、测试和审计证据。
