# Hepta HIA P0–P7 实际执行与生产 Blocker 主报告

**时间**：2026-10-31（美东时间）  
**项目**：`TrillionniumFoundation/Hepta`；相关 NDU、Final-use、运行时依据：`TrillionniumFoundation/hepta-private-ci`  
**总判断**：本轮提交了三个新研究 PR（#464、#465、#466），获得三个分别绑定准确源码的专项成功结果，其中主集成 131/131、下游原生迁移 172/172、验收器自测 7/7；两套真实 7 宿主矩阵 7/7 + 7/7。**未完成 P0–P7 全部生产资格；禁止将 Draft 分支或通过局部实验的结果视作主线发布。**

## 一、本轮真正提交的源码

| 项目 | PR / 分支 | 精确 SHA | 源码交付 | 已验证的范围 |
|---|---|---|---|---|
| P0/P1/P5 集成 | [#464](https://github.com/TrillionniumFoundation/Hepta/pull/464) `work/hia-crosslane-p0-p1-p5-20261031-gpt6` | `d6247cb5e4787ed86d52787858c38029afcddf61` | 整合 #458/#459 P0 有界输入，#434 P1 退出/资源，#455–#460 P5 成本证据，新增严格源码绑定验收器 | [CI 41183411815](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41183411815)：105 Core/Z3 + 13 Linux ELF 回放 + 13 独立 Rust1.95，**131/131，0 skip** |
| P0/P2/P3 真实机器与迁移验证 | [#465](https://github.com/TrillionniumFoundation/Hepta/pull/465) `work/hia-p0-p3-native-legacy-matrix-20261031-gpt6` | `5b100d33c7e57e3b4dffd18c32b01db1bbcd1110` | 旧 HSIR、CFG/SSA、文本汇编、LLVM20、真实 C/C++ 项目回归；启用已有 x86-64/ARM64/Windows/macOS 宿主工作流 | [CI 41183792893](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41183792893)：104 legacy + 42 LLVM/ABI + 26 migration，**172/172，0 skip**；[C ABI 7/7](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41183792875)；[C++ 7/7](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41183792909) |
| 测试门禁严格化 | [#466](https://github.com/TrillionniumFoundation/Hepta/pull/466) `work/hia-proof-test-gate-hardening-20261031-gpt6` | `db4608200ce600ebbecf0eb9c31e9c99e5c094b7` | 测试数量/身份/期望失败/跳过/HEAD/Tree/工作区漂移全部 fail-closed；新增对抗自测 | [CI 41184121926](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41184121926)：**7/7，0 skip** |

**重要**：#465 的 172 项及 7+7 宿主结果属于精确 SHA `5b100...`，不能自动移植为 #466 的完整原生复验。#466 的 7 项仅证明它自己的严格验收器性质。#464、#465、#466 均为 Draft，未合并 `main`。

## 二、P0–P7 主状态表

| 阶段 | 已有受限证据 | 仍缺必须关闭的 Blocker | 生产关闭 |
|---|---|---|---|
| **P0** | HIA v8/50 指令目录、统一集成测试；有界可变输入与 UTF-8 修复；旧 HSIR 明确拒绝错误适配 | 全部受支持源代码/Legacy IR 到 Core 到 LLVM/Rust 全路径的精化保证、最终 main 合并 SHA 的独立复验；仍缺完整语言级健全性证明 | **OPEN** |
| **P1** | 真实 Owner、Borrow、资源/失败/取消检查、Z3 抽象 ledger 和 Rust shadow 回归 | 普遍 pointer provenance、生命周期、任意异常/异步取消、外部资源和机器码精化边界；完整独立证明 | **OPEN** |
| **P2** | Clang20 x86-64 真实 native HIA、AArch64 有限对象；Linux/AArch64/Windows/macOS C ABI 七宿主矩阵通过 | Windows 原生 HIA LLVM 执行全配置、真机外设 MMIO/DMA/IRQ、目标机端到端内存/延迟实测、全部 ABI profile | **OPEN** |
| **P3** | 实际 GSL 分支/回调、有限 C 迁移与 7 宿主 C++ 库资格 | 完整第三方 C/C++ 项目全量迁移/上游升级、复杂模板/异常 ABI、人工迁移时间及维护成本 | **OPEN** |
| **P4** | 具备 SSA、有限优化、原生执行及强基准实验 | 全程序受约束优化精化证据，在预注册未见应用工作负载相对于强 Rust/C/C++ 基线的可重复净性能/资源优势 | **OPEN** |
| **P5** | 原生 Rust NDU advisor、Pareto/硬约束、真实成本/配对回放器、完整成本守卫、负对照 | 在样本外真实任务中对同信息 Fixed/DP 的稳定**完整生命周期净收益**、独立可信观察和所有构建/搜索/证明/切换/人工成本计价。既往实测失败不可覆盖 | **OPEN** |
| **P6** | Agent 协议、目录发现、有限真实实验、无反馈泄漏拒绝和成本回执 | 未见真实项目同模型同工具同预算的可重现优势、可靠 provider 可用性和完整 token/人工/部署成本 | **OPEN** |
| **P7** | hepta-private-ci 具有单次 Final-use、Generation Fence、部分持久 journal、控制 owner 与 rollback 基元 | 最终 Agent/编译发布产品执行 owner 单线接入、跨节点签名与同步、故障/断电恢复、负载资源实测、外部副作用未知结果结算、物理设备实测及持续运行 | **OPEN** |

## 三、保留的失败及科学非结论

1. 首轮 #464 集成因全新 Runner 缺锁定 serde、Z3 未安装/两项形式化测试 skip 而失败；随后模块导入路径错误也导致原始失败。修复后在 `d624...` 的 Z3、Rust 离线真实测试才完全通过。
2. 首轮 #465 因把真实 Clang20 Agent 测试误放 Clang18 lane，及 Hepta 源码 `rustc 1.90.0` 与独立 HIA shadow `rustc 1.95.0` 混淆而失败。修复工具链归属后 `5b100...` 的全部 172 项和 14 宿主作业通过。没有删除失败测试或放宽零 skip。
3. 历史 Hepta/hepta-private-ci 原生 NDU 全成本实验：Fixed 约 **348.75 秒**、轻量 DP **352.59 秒**、Native NDU **398.46 秒**。该范围内 NDU 比 Fixed 多约 **14.25%**，**不满足 P5 净收益门禁**。不可用局部中位延迟缩短替换完整成本。
4. `hepta-private-ci` 主线文档 `docs/readiness/LANE_B_NATIVE_HOST.md` 显式保留外部 provider 恢复、Fleet lease durable/物理观测、Final-use 外部效应调用方分离等未实现部分。`codex-rs/hepta-contracts/FINAL_USE.md` 亦把跨进程状态和外部 anti-rollback 作为独立信任假设。不能宣称 P7 结束。
5. 大型整体 HIA CI 工作流除本报告列出的专项成功外，如果在本轮观察时尚未完成，必须保留 unknown/in-progress，不能按成功处理。

## 四、下一组无法伪造的关闭门禁（严格依赖）

**A. 单一集成 SHA**：把 #464/#465/#466 的有用增量按共同祖先和语义合约审查后合并到统一候选，不以 PR diff 不冲突替代真实 Core 语义等价；全部专项测试在最后提交执行。

**B. 有限语义精化扩展**：新增 Clang/LLVM/Rust 原始 machine witness + 资源/退出负例，以状态转移/trace 关系追踪至源合同，强制真实重组和拒绝未知。

**C. 真实第三方工程迁移**：选取许可证允许的固定开源项目，完整生成编译数据库并在上游升级后重做测试；量化不可迁移函数、unsafe/FFI 假设和人工耗时，禁止填 0。

**D. 预注册四臂 NDU 成本研究**：对相同候选库、相同随机源和任务身份运行 baseline/fixed/DP/native NDU，记录一次性与每轮成本、RSS/p99、失败/失效数据和样本外收益。没有统计和经济正效益就保持拒绝。

**E. 实际 Agent + P7 产品**：同模型同预算未见任务，输出、错误与工时完整结算；由真实 Final-use/CAS/Generation Fence/Ledger 的单 owner 安全发布，断电/重组/回滚和硬件负载实测资格独立关闭。

> 所有提交只形成受限、可复核的技术增量。**截至本报告生成，P0–P7 全部长期生产 blocker 未被宣称关闭。**