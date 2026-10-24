# Hepta blocker ledger — 0.2

用户目标保持不变：面向 AI agent coding，保留甚至超越 Rust 的性能与资源管理优势，并具有 C ABI / 硬件适配能力。仓库为 [TrillionniumFoundation/Hepta](https://github.com/TrillionniumFoundation/Hepta)。

**0.2 已实现下表列出的可执行增量；完整生产语言目标仍未全部闭合。** “实现”“通过当前资格”“完成普遍证明”是不同判断。验收报告的 `whole_project_blockers_closed` 保持 false。

## 已实现的增量及验收条件

这些项目在本版本有实际代码、正反例和可重放入口。是否通过最终统一快照，以 `artifacts/release-validation.json` 引用的报告为准；已归档的本轮报告位于 `evidence/next_stage/`。

| ID | 已实现范围 | 验收入口 / 证据 |
| --- | --- | --- |
| M01 | 独立语法、闭合 AST、类型/效果检查，版本 0.2.0 | SPEC.md、完整单元与集成测试 |
| M02 | Rust 原生路径最终借用检查、工具链身份和非空产物检查 | 原生正例、拒绝用例；frontend-only 不冒充完成 |
| M03 | Buffer/Task/TaskGroup 正常路径线性消费、传递效果与零分配等条款 | 分支、循环、match、提前返回、泄漏/重复消费负例 |
| M04 | 多文件 import、别名、公开性、依赖图；本地库、清单及内容锁 | test_modules.py、带 --locked 的跨包可执行样例 |
| M05 | 枚举、穷尽 match、Result、Copy 范围的用户泛型 | test_language.py、results.hepta、泛型布局循环与未调用函数检查 |
| M06 | 有界 channel、背压、任务组、协作取消和显式 worker 错误传播 | validate_groups.py 四场景 × 三轮；并发身份/顺序检查 |
| M07 | 组生命周期累计任务/输入字节准入与队列槽预算 | 真实拒绝、队列峰值、等待、取消唤醒、join 后 active=0 |
| M08 | C ABI、头文件生成、普通 C 头文件导入及探针 | ABI 差分矩阵；双后端链接；元数据/目标/源码身份拒绝用例 |
| M09 | 独立 AST→C11/GCC 编译路径 | 不调用 rustc；保守借用检查、checked 运算、边界与不支持特性拒绝 |
| M10 | no_std 多目标对象，以及 AArch64 QEMU 实际执行 | ABI/原生报告；cross-execution.json 含故意错误实现的失败对照 |
| M11 | Lean 检查的抽象资源/预算不变量、小型表达式降级定理 | 11 定理、标准公理依赖检查、两项破坏 guard 的负向证明检查 |
| M12 | 图快照绑定的 Agent 函数体修改协议 | 项目/接口身份、路径重绑定、跨图锁、v1/v2 共享锁和竞态回归 |
| M13 | 六个核心的独立 Rust 性能对照，四算法另含 C 后端 | 正确性 oracle、全部计时样本、逐函数机器码比较与回退记录 |
| M14 | 冻结配对 Agent 评测器与可信夹具资格 | 四任务 × 两语言；统一预算、收据校验、native 隐藏评分、重放 |
| M15 | 资源载荷 ADT、`Result<Owned, Error>`、fallible Buffer、递归 drop、单源返回借用和字段借用 | test_owned_types.py、test_borrowed_returns.py；真实分配器拒绝、提前返回、取消/失败及 owned 库执行 |
| M16 | 与前端分离的显式资源/loan CFG 验证器 | test_resource_ir.py、独立 JSON CLI、validate_resources.py；两个真实源项目、七个图变异拒绝对照 |
| M17 | 编译数据库捕获、跨 TU C 模块迁移、结构/循环/调用、缓冲区与受限分配释放配对、完整声明分母 | qualify_c_migration.py、qualify_c_algorithms.py；冻结且未修改的第三方 compare-int/hash-int 模块 |
| M18 | C++ 直接调用、调用期借用、动态 handle 和 C++ 侧模板实例化，异常/析构/线程/重入/分配器契约 | validate_cpp.py；实际 std::vector/std::string、双向调用、异常与生命周期负例、六项分开计时 |
| M19 | 不可变项目版本、语义节点编辑、跨文件接口迁移、单引用一致发布与恢复、源级 Rust 诊断映射 | test_workspace.py、test_source_map.py；真实进程中断、写者竞态、stale 身份、发布后 I/O 状态 |
| M20 | 五种跨文件任务 × Rust/Hepta × 普通/语义工具四臂评测器 | experiments.crossfile_eval；全部计划分母、未知人工成本保留 null、receipt 跨样本唯一、失败已知费用前缀保留 |

M07 不等于全进程内存/CPU 上限。M10 的 QEMU 运行不等于真机或独立外部 C 编译器的跨平台 ABI 资格。M11/M16 没有证明真实编译器与抽象模型的精化关系；M16 尚不覆盖并发 IR。M12/M19 不证明补丁功能等价。M13 不证明普遍快于 Rust。M17 只迁移明确接受的 C 子集，M18 不重写外部 C++ 实现。M14/M20 的实际 AI 模型运行数仍为 **0**。

## 完整目标中的剩余 blocker

| ID | 状态与已完成部分 | 仍需关闭的条件 |
| --- | --- | --- |
| P01 | PARTIAL — 资源载荷 ADT、Result、单源返回借用、字段借用、有限 Copy 函数泛型与本地库已实现 | 通用生命周期/trait 设计、存储引用和部分字段移动、较大多包项目的一致语义与标准库 |
| P02 | PARTIAL / OPEN_RESEARCH — 11 个抽象核心定理、独立资源/loan CFG 检查已实现 | 指针 provenance / 别名 / 生命周期形式化、核心类型健全性、真实 AST 与资源 IR/双后端降级精化、并发资源 IR、unsafe/FFI 条件 |
| P03 | PARTIAL — 组内三类数值预算与取消/失败协议可执行 | 分配器/线程栈/worker 新分配/FFI 统一计费、嵌套任务树、全局预算、可证明的故障与恢复边界 |
| P04 | PARTIAL — channel、背压、任务组、协作取消已实现 | 异步 I/O、select/调度器、超时与结构化任务树、真实网络服务负载、长期运行与故障注入 |
| P05 | PARTIAL — 完整活动声明盘点的 C 模块迁移、受限分配模式与三档 C++ 接口已有原生资格 | 任意 C/C++ 的自动安全重写；inline/函数式宏、packed、bitfields、varargs、复杂预处理；异步/保留回调与跨线程外部生命周期证明 |
| P06 | PARTIAL / ENVIRONMENT_REQUIRED — 多目标对象与 AArch64 QEMU 通过 | Windows/AArch64 等真实宿主、各自 C 编译器/链接器双向执行、持续平台矩阵 |
| P07 | OPEN / HARDWARE_REQUIRED — no_std 对象路径存在 | 板卡启动入口、链接脚本、MMIO/DMA/IRQ、设备协议、真实板卡资格 |
| P08 | OPEN / HARDWARE_REQUIRED — GPU 尚未实现 | 地址空间、kernel 与同步语义、GPU 后端、驱动互操作、真实设备性能与正确性 |
| P09 | PARTIAL / OPEN_RESEARCH — 六核心对照及原始样本可重放 | 代表性应用/服务/内存/尾延迟基准、公平调优、多机器重复；C 后端已观测回退需逐项优化 |
| P10 | FRAMEWORK_READY / ENVIRONMENT_REQUIRED — 五个跨文件任务、同等工具范围的 2×2 框架及 native oracle 资格可执行 | 可用隔离环境、实际 provider 适配器和明确模型版本、多个模型/seed 的完整计量；独立未公开任务、更大项目、完整生产 v4 协议的额外对照 |
| P11 | PARTIAL — 独立 C11/GCC 子集后端、生成 Rust 诊断到源节点的精确映射已可运行 | 完整语言覆盖、后端一致性、优化回归门槛、DWARF/调试器验证；独立机器码后端尚未实现 |
| P12 | PARTIAL — 本地内容锁、版本化工具协议、公开仓库 | 注册表/版本求解、兼容性与迁移工具、发布签名和持续平台维护、生产标准库/文档体系 |

P10 当前 namespace sandbox 探测失败，生产 provider 模式在启动适配器前拒绝。可信 fixture 使用显式的进程分离路径，`ai_comparison_eligible=false`；不能当成真实模型成绩。具体环境失败原因保留在资格报告中。

## 本轮集成审查修复

- 保留原有工具链身份、非空产物、显式失效路径不回退，以及 unsafe 调用边界等回归门槛。
- 泛型参数/枚举 payload 中出现运行时类型时，生成器正确发现其运行时需求。
- 泛型与 ADT 不再意外进入尚不支持它们的 C 后端；最小 isize 常量与 64-bit 模型明确处理。
- 跨模块生成名在源程序中保留，阻止通过 inspect 暴露的内部名字访问私有符号。
- 项目身份包含实际解析的 import 边；同一组已加载文件之间的 symlink 重绑定也会使事务过期。
- 模块验证、dry-run、提交前复核均绑定同一依赖图；源文件路径绑定与内容一起复核。
- 重叠项目和旧 v1 协议共享按序取得的源文件锁；部分取得失败会释放已取得的锁。
- C 导入带公开结构、配对元数据、源码/主机身份及可见原始头文件哈希检查；未经验证的跨目标复用拒绝。
- workspace 拒绝版本目录重定向；初始和后续发布遇到 I/O 错误时保留已发布/未知状态并要求恢复，不把可能完成的提交报告成未应用。
- 资源 IR 拒绝同一 loan 同时占用 mut/read 参数；覆盖 Copy 枚举后使旧 variant fact 失效；未知操作、伪造类型身份和未经证明的 claim 升级均拒绝。
- Rust 跨文件候选编译为独立 rlib，不能通过模块祖先访问可信 driver 的分配/释放计数器；原始伪造反例现为编译拒绝。
- provider receipt 按 `(provider, request_id)` 在整个计划矩阵中去重；无效后续 tool frame 不抹掉此前已验证的模型费用前缀。
- C 导入分离 tag/typedef 名字空间并保留 const 层级；实际 native probe 先验证 typedef，再验证函数存在及原型兼容，拒绝被预定义/include guard 隐藏的虚假 ABI。
- HSIR 沿 nominal/generic/array 类型保留 raw-pointer 外部义务；该修复保证审计清单完整，不冒充外部代码安全证明。具体反例与修复见 `C_IMPORT_SAFETY_INTEGRATION.md`。

准确的测试数、当前编译器身份、性能样本和运行结果，以最终验收报告及其绑定的证据为准。任何未执行、未知或环境阻塞项目均保持其真实状态。
