# HIA 全仓清点、原生重写与清理审计

## 结论

准确仓库为 `TrillionniumFoundation/Hepta`。源码已经具有真实的 HIA 自编译器、x86-64 直接机器码生成、ELF 构造与若干原生应用；整套产品尚未完成 HIA 原生替换。当前不能删除全部 Python owner，也没有完成生产激活。

本轮公开实现为 `3d1f2cd70cc65ba1f603fec1ab43cb4e1eeb6fc8`，与本地冻结提交 `1661f73565e74c81fa34db874e7887d11ecaaf19` 的完整 Git tree `dfc42506dddc660316be1fc5bc84ad68e44f7eba` 相同；40 个改动 blob 已逐项核对。两者是不同 commit 身份，不互相冒名。

`whole_native_delivery_qualified=false`、`old_stack_can_be_removed=false`、`production_activated=false`。

## 审计覆盖与限制

- 基线 `807bbc4` 的 2,360 个 tracked files 已逐项验证 Git blob 身份；所有 retained Python 均作 AST 清点，记录静态 import、公开定义、资源与 selector 消费边。
- 当前冻结树有 2,368 个 tracked files，inventory 自身之外 2,367 项大小/SHA-256 全部一致；96 个 HIA 源文件、1,057 个 Python 文件，其中生产 Python 模块 163 个。
- 深入检查普通 CLI、服务路由、直接后端、自举与支持域、资源打包、SQLite/WAL、request replay、预算、slot/lease、retirement 与 release selection。
- 核查了静态图未能发现的实际消费者，例如子进程源码中的 `hepta.hia_core_api`。不能把“没有 AST import”当成没有用途。
- 这不是每一行程序的语义证明，也没有建立所有未知外部消费者的闭包。有限实验、库存数量、固定点与形式模型均保留其范围。

## 文件后缀

| 快照 | 实际 HIA 文件后缀 |
| --- | --- |
| main `5831f52f` | 60 个 `.hiaasm`、12 个 `.hia`、11 个 `.hia.json`；没有 `.HIA` 或 `.hepta` |
| 当前整合实现 | 96 个小写 `.hepta`：71 assembly、25 structured Core；没有旧物理后缀 |

所以原项目并非统一使用大写 `.HIA`。活跃源可以统一为 `.hepta`，整合分支已完成这项迁移；main 尚未采用。

迁移同步了内容识别、旧后缀拒绝、生成器、资源路径、安装 manifest、Python/Rust 消费者、示例、CI 和身份绑定。配对的结构化投影使用 `.core.hepta`；schema、`hia-asm.v1` 和 `hia` 命令名称保持其原合同。不可变历史收据、注册协议及归档内的原始路径保留原名与原字节，数据 JSON 也不会仅因含有 HIA 字样而改后缀。

## 实际开发状态

| 关键路径 | 已实现 | 尚未闭合 |
| --- | --- | --- |
| 编译器与自举 | HIA scanner/parser/checker/emitter，原始及修改源码固定点控制 | B0 与构建驱动仍有 Python/GNU ld 信任边界；目标和语言 profile 有限 |
| 普通 CLI | 15 个 action、显式 selfhost object build | `hia = hepta.cli:hia_main` 仍是 Python；完整 CLI 未被原生入口接管 |
| 原生 stdio | 六命令，新增直接 `check-assembly` | 独立的有界协议；不等于十五 action CLI 或十一工具服务 |
| 普通编译/评测 | Python 直接 x86-64/ELF emitter；显式 HIA selfhost 路径 | 默认 build 与 Agent `_compile` 仍有 Python emitter；`hia_evaluate` 仍用 Python reference VM |
| Core/nominal 与 proof | 多个原生 admission/shape/JSON/helper owner；有限形式模型 | 完整支持域、诊断、证明准入与机器语义对应未统一闭合 |
| Agent worker | 十一工具、source/installation 身份与原生 helper 接口 | `hia_agent_worker`/`HIAAgentService` 装配和完整服务行为仍 hosted |
| 持久状态 | 真实 SQLite/WAL、原生 journal/budget policy、exact replay 与 unknown 保留 | 实际数据库效果、连接/事务与完整恢复仍需迁移，不能另造独立 store 冒充原 store |
| slot/version/lease | 原生 slot ledger、部分 adoption policy 与 retirement 状态 | 完整 receipt/context/artifact/ABI 准入、驻留引用与 generation lease 尚有 Python owner |
| 执行与清理 | 真实受限子进程、快照、报告及终止检查 | `sys.executable -m hepta.hia_agent_runner` 仍是产品执行路径 |
| release | 原生 immutable install、CAS/rollback/status，新增锁内完整 verify | selector 未接通真实 worker restart/handoff、运行中 image readback 和旧 owner 退休 |

不能通过把默认 backend 改名、把 Python 包装成原生进程、只保留 `.hepta` 文件，或先删旧模块来完成上述替换。仍有效的请求、context、proof、artifact 与 lease 必须继续绑定其原始实现身份。

## 本轮实质改动

1. **原生汇编检查。** HIA 精确分派命令，调用实际语义/资源编译器，再检查 operator 选定的 flat/ELF/exec profile，只返回验证 JSON。保留 1 MiB 与加一边界、effects/borrow/owner 拒绝和 I/O 行为；不宣称与 hosted 诊断完全等价。
2. **原生发布一致性校验。** `hia-select verify ROOT EXPECTED_SEQUENCE CURRENT_SHA256` 在同一共享锁内检查真实已安装包，并复核完整 selection bytes/inode/time/lock/root。实际读中修改合法记录、以新 inode 换入相同字节均拒绝。它不是运行中 worker 身份证明。
3. **编译器成本优化。** 两处私有表清理改为受检查 bulk fill；access/borrow/free 仅扫描当前函数已 intern 的 SSA 身份。全部活跃借用检查与 2,048 SSA 容量保留。600 次原生对照比较完整输出及公开 header；没有主张私有 scratch 的写入轨迹或全部字节相同。
4. **显式空选择拒绝。** execution budget、retirement、whole-Core admission 和 instruction policy 四个普通 owner 在 manifest 变量存在但为空时拒绝；变量缺失才使用 reference。普通调用回归禁止进入旧检查器或创建新持久化效果。其他 selector 没有被悄悄统一改约定。

## 验证边界

冻结实现的 25 项源控制全部通过，零 failure/error/skip。编译器 300 个不同程序、zero/A5 两种 workspace，共 600 项真实原生前后比较一致；同源自编译固定点一致；scanner/name 源测试 15/15 通过。

稳定源码的 stdio 开发 run 为 15 项、13 PASS/2 FAIL；release 开发验证有 24 次 PASS、5 项 strace 控制 FAIL。这些 strace 失败来自 sandbox 的 `PTRACE_TRACEME: EPERM`，仍作为失败保留；开发编译器不能冒充 matching cold 资格。

同一冻结源码两次本地 cold 均失败：

| 运行 | 实际结果 | 完成阶段 | 清理 |
| --- | --- | --- | --- |
| 首次 | QUALIFICATION_TIMEOUT，180.674533222s | 26/38，0 phase exception；wrapper 6/11 | ECHILD，无剩余子进程或清理错误 |
| 独立复跑 | QUALIFICATION_TIMEOUT，180.385562914s | 6/38，0 phase exception；wrapper 6/11 | ECHILD，无剩余子进程或清理错误 |

两次 708 个 source members 加契约文件均与冻结实现一致。复跑没有替代首失败；相同编译器 image 或局部相等不能把超时变成通过。没有采集真实 CPU 时间，不能把不同运行的 wall 差异武断归因编译器、CPU 或调度。

原 cold 180s、cleanup 3s、two-worker 和 retained 5,400s 门槛均未放宽。完整 retained 验收因 cold 前置未过而未启动。公开代码 head 的 GitHub run `43133619396` 的 source/native jobs 仍排队；排队不能计作 PASS。随后按原 workflow heredoc、实际 Python 3.14.10 执行的完整源控制在 385.029698662 秒被 SIGKILL（returncode -9）中断，没有 unittest 最终 summary，未形成整套结果；不能以日志中的 227 个 ok 行宣称整套通过。终止来源未核实，没有取得 kernel kill 记录或运行前资源基线，不能武断认定 OOM。

## 清理结论

本轮对 38 个非空重复组逐组记录了用途，未找到额外可安全删除的完整生产模块。版本化 fixture、独立 oracle、原始失败和实际动态入口继续保留；163 个生产模块还进入 installation identity，删除会改变耐久对象身份。

当前状态索引已精简，原逐阶段叙述保留在固定 Git 历史；本任务可重建的大输出在逐成员归档回读后清理，释放约 1.3GB 临时空间。这不能被称为已删除整个旧产品栈。

最终删除条件仍是：完整原生替代接管普通调用与实际效果、原安装/请求/lease 身份迁移和恢复通过、同一冻结源通过规定验收、真实运行 worker 的 code/resource/backend 身份可读回、旧 owner 的引用和清理结果已确认。现有证据尚未满足这些条件。
