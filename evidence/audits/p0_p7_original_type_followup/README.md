# Hepta P0–P7：原始参数类型、独立 v1–v7 执行与冻结回归

本轮完成三个具体增量：拒绝会丢失函数入口副作用的 C VLA 参数迁移；把独立 Rust 资源执行器从 primitive v1 扩展到既有 v1–v7；固定 Cargo 版本、依赖准备和源码外构建目录，并显式声明完整回归预算。原始失败、负控和中止运行均保留。下面每一组结果绑定实际执行的源码身份，没有把祖先或组件结果追认到后续提交。

- Review stack：[Draft #330](https://github.com/TrillionniumFoundation/Hepta/pull/330) → [#332](https://github.com/TrillionniumFoundation/Hepta/pull/332) → [#334](https://github.com/TrillionniumFoundation/Hepta/pull/334)。均未合并。
- 当前公开实现提交：`e6379178a3e9a682f88c344aaa86b3d74932ffd7`。
- 当前实现 tree：`66d0950ce0d41c0b705509b14ac97313052ec3ef`，与本地集成 `de40b4a` 的树逐对象一致。
- 父实现提交：`ff88d4cd378435c745ce339107f38622a5cc91a6`；其 tree 为 `3e7fe6cc7a9319f478aaee5af54b63733587a813`，实际执行源码快照为 `ccf57ebe2105a8ca2563834414a0106b32167847eaf87bccc5573e0b507c190f`。
- 各组件及最终完整回归的源码快照以各自报告为准。
- 本目录只补充后续修复及其新执行证据；原始 108762ba 归档是另一份独立交付，没有拆分或复制到本目录。

## 1. 可复现的语义错误及修复

```c
unsigned int probe(unsigned int n, const unsigned int data[++n]) {
    return n;
}
```

使用 `n = 7` 和八个已初始化元素，所选 Clang 的原始程序实际返回 **8**。修复前的 `91225c02` 接受迁移，生成的 Hepta/Rust 原生库实际返回 **7**。这是定义良好输入上的独立原生差分反例。

修复后重复使用相同 source、build database、contracts 以及原始原生库，四个文件的哈希均不变。原始程序仍返回 **8**；迁移器以 **`E_C_VLA_PARAMETER`** 拒绝，并且没有发布产物。两个运行的源码身份分别保留在 [修复前报告](vla-6e16922e/before/report.json) 和 [修复后报告](vla-6e16922e/after/report.json) 中。

新增检查使用捕获的同一 Clang、前端参数顺序、原词法 source operand 和 cwd 生成 serialized AST，再由同一安装内独立哈希的 libclang 实际加载。每个声明均按文件、offset、函数名、完整函数类型、参数数量及顺序匹配。变量类型拒绝为 `E_C_VLA_PARAMETER`；缺失、重复、命令不一致、读取失败和未建模类型拒绝为 `E_C_ORIGINAL_TYPE`。

检查位于共享 C collector，覆盖 record-view 签名适配路径。普通 pointer、固定数组、不完整数组语法仍经过既有 slice 契约。新的 `hepta.c-original-parameter-types.v1` 收据单独版本化，既有 build-capture schema 不变。编译与读取有独立的进程、输出、AST 大小及 POSIX 资源边界。

当前实现通过拒绝解决入口副作用丢失；通用 VLA 执行语义仍未实现。匹配 libclang 是显式依赖，缺失时拒绝。初始实际执行范围是 Linux x86-64、Clang/libclang 20.1.8；完整设计、信任边界和资源预算见 [原始参数类型说明](../../../docs/C_ORIGINAL_PARAMETER_TYPES.md)。

## 2. 预算配置修复

旧 `108762ba` 的完整 2,424 项单测实际用时 **2,298.44 秒**，而发布入口原先固定给单测 **600 秒**。本轮增加 `release_check.py --unit-timeout-seconds`，范围为 1–3600 秒，原默认值 600 秒保留；无效值在创建输出或启动子进程之前拒绝。报告记录所选单测预算和每个门禁的预算。

工作流为两个完整单测入口显式指定 3,600 秒，并把包括安装和两套验收的 outer job 时限从 60 分钟改为 180 分钟。独立检查确认 **46 个 release 门禁保留**，其余 45 个命令与时限不变，验收阈值与零 skip 规则不变。[25 项预算相关测试](budget-0f272a44/budget-default-01/report.json) 实际通过。该 fixture 的其他门禁故意不合格，没有被计算为完整发布通过。

这没有证明整个 GitHub Actions job 可在 180 分钟内完成。本 stacked 分支及其 base 仍不在既有自动 workflow filters 内；本轮没有远端 CI 通过记录。

## 3. 独立保留的执行身份

各行属于不同源码和不同测试集合，不能相加成一轮测试总数。

| 执行 | 结果 | 实际源码身份 |
| --- | --- | --- |
| #330 的 ABI、编辑呈现、CLI 及 C/C++ 回归 | 37 + 10 = **47 个不同方法通过**，零失败、错误和跳过 | `91225c023b3d61bd8b87bfbd16ac5990c3fb0a62` |
| 原始类型修复的六个 C 模块 | **82 通过**，零失败、错误和跳过；465.138 秒 | 本地冻结 `6e16922e9f5c19b332c2d520dc5651eed5c3aa13` |
| 预算修复回归 | **25 通过**，零失败、错误和跳过；1.366 秒 | 本地冻结 `0f272a4424f87997e96cbfa5f69dc7d818280370` |
| 独立 VLA 及声明审查 | 25 个原始 C 调用，16 次公共迁移调用；3 准入、13 拒绝 | 本地冻结 `6e16922e` |
| 独立进程机制检查 | 正常退出和超时两条路径均清理同组后代，保留资源限制 | 本地冻结 `6e16922e` |

实际编译的正确 `ms_abi` 原始 caller 返回 9；旧 `108762ba` 接受两条迁移入口并发布 ordinary-C ABI 输出，`91225c02` 均以 `E_C_ATTRIBUTE` 拒绝。错误 ABI 的生成程序没有被执行为参考对照。[新执行汇总](followup-91225c02/summary.json) 保留了这一区别。

旧 47 项汇总中，Python unittest 的显示格式导致方法后缀在标签内重复。原始 stderr、报告和计数保持不变；[独立 ID 澄清](followup-91225c02/identity-clarification.json) 从原始日志恢复了 **47 个 canonical ID、47 个唯一方法**。这不是新增测试。

[独立 VLA 审查](independent-vla-review/summary.json) 的 3 个准入正控只验证前端准入。观察到入口增量的 11 个探索输入均被拒绝，其中两个 `typeof(NULL-array)` 探索输入排除在定义良好等价分母之外；保守分母为 **9 个**。两条进程 fixture 证明清理机制，不能计为 Clang 语义验证。

源码和工具的前后身份均保留在各自报告内。`ff88d4cd` 的完整 tree 与本地合并 `76c928ac` 一致，但早先各组件测试仍属于上述实际 SHA。

## 4. 两个公开实现的执行身份

### 4.1 `ff88d4cd`：完整单测中止，两个原生门禁通过

[实际终态](integration-ff88d4cd/execution-completion.json) 明确记录：原始 runner 已退出，返回码 1。单测阶段在发现启动环境缺少 `CARGO_TARGET_DIR` 后被显式停止，持续 1,340.184 秒、返回码 -9，状态为 `interrupted_predeclared_environment_error`。日志只有 **628 个唯一方法的开始记录**，没有 unittest 完成 footer，`tests_run/skipped/failures/errors` 均为 null，**不得写成 628 项通过**。

中止通过已核对身份的 pidfd 操作，只作用于本次 runner 的 unit 子树；动作、请求、结果与进程身份全部保留。没有改变运行中的环境，没有放宽官方源码快照排除规则，也没有把该次执行续写成成功。

同一个 runner 随后实际完成两个预先声明的原生门禁：

| 门禁 | 实际结果 | 明确范围 |
| --- | --- | --- |
| `qualify_hia_migration.py` | **通过**，11.089 秒；1,102 次 native result execution、212 次 fault execution | C multi-owner 56 案例、C++ 值类 20 案例、C++ owner 475 案例；原始源码与生成目标的实际行为和资源观察 |
| `qualify_c_resource_matrix.py` | **通过**，70.573 秒；plain/masked 两个实际配置 | 每配置的跨模块子组有 1,536 状态转移、3,072 次 transfer 调用、3,072 次后续 query、12 次 init；boundary controls 另有 5 个 refusal；目标未链接原始 C object |

同一资源矩阵的独立 upstream 子组，每个配置另记录 2,048 状态转移与 8,200 次 original/translated 配对操作观察（16,400 次实际 native 调用）。这些子组按各自原始分母列示，没有相加成一个总测试数。

第二行属于 **safe Hepta/Rust** 实现，报告中的 `native_hia_implementations` 为 **0**，不是 standalone HIA LLVM 原生实现。两个门禁的 [原始 HIA 报告](integration-ff88d4cd/hia-migration/artifacts/qualification.json) 和 [原始 C resource matrix 报告](integration-ff88d4cd/c-resource-matrix/artifacts/qualification.json) 原样复制，没有改变计数或声明。

本次整体和每个阶段的源码、Git 与工具前后身份都不变。原始 manifest 388 个文件逐哈希复核通过；这属于完整性核对，不是新增程序执行。

### 4.2 `e6379178`：修复后的最终完整回归

**本次正式回归通过。** 原始 [summary](final-e6379178/summary.json) 记录正式回归通过，[完成复核](final-e6379178/execution-completion.json) 记录外层 runner 实际退出码 0；正式执行提交为 `e6379178a3e9a682f88c344aaa86b3d74932ffd7`，不是后续的证据提交。

| 阶段 | 实际结果 | 时间与边界 |
| --- | --- | --- |
| Cargo metadata preflight | 通过；实际 target 位于源码外 | 0.018 秒，单独 60 秒预算 |
| Cargo locked/offline build preflight | 通过；锁定依赖可实际离线构建 | 12.066 秒，单独 240 秒预算 |
| 完整 Python unittest discovery | **2,458 passed；0 skipped / failures / errors** | unittest footer 1,702.563 秒；外层 1,707.917 秒；预算 3,600 秒 |
| 全 crate Cargo test | **54 passed；0 failed / ignored / filtered out** | 外层 2.093 秒；预算 240 秒 |

完整单测的 **2,458 个 canonical ID 全部唯一**，与终态 footer 一致，没有从未完成的开始记录推算通过数。两个 preflight 没有混入正式测试计数。实际受控环境显式包含 `CARGO_HOME`、源码外 `CARGO_TARGET_DIR`、`CARGO_NET_OFFLINE=true`、固定 Rust/Cargo/Rustdoc 与 `PYTHONDONTWRITEBYTECODE=1`，unit 子进程的实际环境也另行核对。

运行前后 Git HEAD/tree 均相同、工作树均清洁，官方源码清单 **1,050 个文件**，前后快照均为：

```text
ce1f52a3f003cda6565de178942e4720e2386f8055c5aed54982fd9feaa6bc2c
```

每个阶段和整体记录的工具身份都一致。完整 [unit 报告](final-e6379178/unit-discovery/report.json)、[原始 stderr](final-e6379178/unit-discovery/stderr.log)、[Cargo 报告](final-e6379178/cargo-test/report.json) 与其双流均保留。summary SHA256 为 `46aeefd9f8a55f041c59eb3f18fe4a697cf0e06f4aa75fa076130f104e157c6d`。

[独立完成复核](final-e6379178/execution-completion.json) 重新解析原始 footer 与全部方法 ID，核对原始 manifest 的 26 个文件无差异，并保存验证结束时的 VM 字节及哈希。VM 的保留收据在本目录；该二进制与工具链接未复制进这份选定审查材料。完成复核 SHA256 为 `192ca4d071fb9da9d576ec051c9d6a06f23461907c76038ee0af62664f0b3937`。

这些是本地批准的原生执行环境中的实际结果，未借用远端 CI 状态，也没有重复声称全部 19 项统一门禁已在新提交通过。历史性能和模型实验的未通过结论保持各自原始身份。

在正式执行前，`76c928ac` 的一次默认沙箱 preflight 因 Lean `failed to locate application` 退出，尚未启动 unittest。相同只读版本命令在批准的原生执行环境中成功。该 [preflight failure](preflight-76c928ac/preflight-failure.json) 及原始双流保留；正式运行使用新 attempt 身份。

上一次 `ff88d4cd` 的计划选择完整 unittest discovery 和两个受共享 C collector 改动影响的迁移门禁。新一次 `e6379178` 的计划选择完整 unittest discovery 与全 crate Cargo test，另有独立的 Cargo metadata/build preflight。它们不是完整 19 门重新验收；性能和模型实验没有在这一实现上重新运行。

## 5. P2：独立 Rust v1–v7 资源执行

冻结组件 `dfdf944f9868fd30f3ac4bbb43a675343de7442a` 补齐已存在的 primitive v2 fill/copy、v3 move_within、v4 swap、v5 copy_range、v6 fill_range 和 v7 chain 操作；包括跨块、消耗型调用、内部返回与析构。它没有更改 Core 语义、生产准入或 LLVM 优化假设，也没有让 Rust 执行器调用 Python 或生成的 native 程序。

chain root 与 node 用独立索引表管理，逻辑借用根与实际 payload storage 分开。header 的 24 字节申请参与同一分配失败序列，成功/失败 push、空 owner、pop 和逐节点 drop 都保留现有事件顺序。执行预算在部分析构中断时，不报告尚未执行的清理。报告显式升级为 `hepta.hia.rust-owned-execution.v2`；旧 v1 报告的含义不变，v1–v6 账本字段不变，v7 新增六个 chain 计数。公开函数入口仍只允许标量参数与返回，未知版本和未支持构造继续拒绝。

| 组件执行 | 实际结果 |
| --- | --- |
| 全 crate Cargo test | **54 passed**，0 failed/ignored；29.526 秒 |
| 既有 Python owned VM 回归 | **10 passed**，0 skip/failure/error；1.537 秒 |
| 另一审查者独立编写的新增 Python 扩展 | **15 passed**，0 skip/failure/error；22.769 秒 |

三组属于相同冻结组件源码快照 `205472509a2d04ab0c1abf1769630faa2d38995d84546592cdefded352d1fc96`。54/10 的 [组件报告](p2-components-dfdf944f/components-cache-dfdf944f/report.json) 与 15 的 [独立报告](p2-independent-dfdf944f/report.json) 原样保留。

新增 15 个方法记录 **352 次 Rust/Python 差分**：276 次正常返回、47 次陷阱（40 bounds、4 allocation、3 user）、29 次预算停止（24 steps、5 heap）。对照完整返回/陷阱、steps、资源账本与 Core digest。另有 **28 次准入负例**。

**95 次真实 native 程序执行**包括 85 个正例、8 次实际 SIGABRT 越界对照及 2 次漏释放负控。负控分别实际删除 header/payload free，即使标量返回正确仍检测到 72 字节 header 或 3 字节 payload 泄漏。4 次编译/链接和 3 份 LLVM 对象构建收据单列，没有混为程序执行次数。预算中止只在 Python/Rust VM 间比较；native abort 没有被声称为正常清理。

[全部 case 记录的派生 JSONL](p2-independent-dfdf944f/all-case-records.jsonl) 和 [Core 记录](p2-independent-dfdf944f/all-core-records.jsonl) 保留记录内容及每个原始文件的大小、SHA256。它们明确标为派生聚合，未冒充原始 byte stream。原始 546 文件清单和独立重算审计一并保留。352 次调用包含 336 个不同请求，**不是 352 个独立真实应用**。

第一次组件尝试因缺少离线 `CARGO_HOME` 在编译前返回 101；[失败报告](p2-components-dfdf944f/components-dfdf944f/report.json) 保留。新尝试显式指定已核实的 cache 后通过，源码、预算与 offline 规则未改。

上述结果支持闭合“现有 primitive v1–v7 缺少独立 Rust 动态执行”这个有限软件缺口。它不构成任意递归 ADT、完整 source/Core/LLVM refinement、全平台或并发内存模型的证明。精确定义见 [执行说明](../../../docs/HIA_RUST_RESOURCE_EXECUTION_V2.md)。

## 6. Cargo 安装与执行环境

`toolchain-lock.json` 新增官方 Cargo 1.90.0 锁定包，bootstrap 默认选择它并沿用 payload 安装完整性检查。workflow 使用源码外的 `runner.temp` 存放 `CARGO_HOME` 与 `CARGO_TARGET_DIR`，明确选择同一安装目录的 `RUSTC`，为后续步骤追加工具 PATH，并在离线回归前执行锁定的 `cargo fetch --locked`。

[10 项实际回归](cargo-environment-de40b4a/report.json) 在本地冻结 `de40b4a` 上通过：2 项环境/缺包检查与 8 项已有安装完整性回归，unittest 1.097 秒，外层 1.704 秒，源码与工具身份不变。临时零依赖 crate 实际编译并执行，target 目录实际位于源码外；测试没有声称完成真实远端 CI 的冷 cache 网络预热。部分旧测试的 Cargo 准备命令仍不是 offline 模式，本轮也没有把整套 qualification 声称为强制断网流程。

[官方发布包核对](cargo-official-artifact/report.json) 实际下载了 10,679,724 字节归档，SHA256 为 `9853db03d68578a30972e2755c89c66aec035fec641cf8f3a7117c81eec2578d`，与官方校验文本及锁表一致。未执行 installer；只读归档中的 Cargo payload 与所选已安装 Cargo 逐字节相等，二进制 SHA256 为 `51de284e8bb0d03dcee595a0fb1cb3a952fe9e7e4b953a8b1467b7f71725b561`。归档本身没有复制到本目录。

## 7. 集成后的有限只读复核

[Cargo 审查](reviews/cargo-readonly-review.json) 未确认当前 workflow 路径的阻断性故障；它明确指出零外部依赖的临时 probe 不会检测冷 cache 预热步骤或 Cargo PATH 追加被删除。因此该 10 项结果只用于其实际验证范围，完整远端 CI 仍未执行。

[借用与范围指令复核](reviews/p1-p2-readonly-review.json) 在 `e6379178` 上，复用已构建的独立 VM 增加 8 个小型 v6 差分案例（5 正常返回、3 bounds trap）及 3 个借用安全负例。全部按返回/错误码、steps、完整资源账本比较；11 次 VM 调用没有编译，也没有新增 native LLVM 执行。第一次临时审计 harness 在正确的 Rust 拒绝上错误解析空 stdout，失败原始记录保留，之后只完成剩余两个负例。此项不并入之前的 15 个 unittest 方法或 352 次差分分母。

[交付证据独立审查](reviews/delivery-evidence-review.json) 对 108 份原样复制收据（6,000,397 字节）、482 份派生 case 与 42 份 Core 逐一对照原始文件，并重算 P2 关键分母；没有发现内容或计数不一致。唯一分母措辞问题已通过 [独立修正记录](reviews/delivery-evidence-resolution.json) 解决。这些属于审计检查，不是新的程序执行。

## 8. 旧终态已恢复，原结论不改标

旧 `108762ba` 的实际终态已恢复并完成只读完整性核对：**19 门全部执行、18 门通过**；完整单测 **2,424 项通过、零 skip/failure/error**。唯一未通过门禁是 `standalone_performance`，状态仍为 `measurement_inconclusive`。428 项恢复审计检查属于哈希、绑定和独立算术重算，不是 428 个新的原生测试。

旧 CPU 协议的 63 个样本全保留，9/9 组相对 MAD 超过固定 5%。`two_stage` 的 HIA/手写 Rust 描述性配对时间比为约 **1.09951**，保留这一退化观察；测量质量不足，不能建立稳定优势或稳定退化。旧模型实验也没有达到预设收益标准。这些结果属于原始提交，不能改称当前实现的实验。

本目录不重发旧的原始证据包或模型请求/响应。恢复状态的公开说明见 [#322](https://github.com/TrillionniumFoundation/Hepta/pull/322)。

## 9. P0–P7 的实际未闭合条件

[结构化当前状态](current-status.json) 使用用户指定的 P0–P7 对应关系，属于审查状态清单，不是第二份语义 registry 或准入证书。

| 阶段 | 当前边界及剩余条件 |
| --- | --- |
| P0 单一语义 | registry、显式旧版适配和公共准入已统一；本轮冻结回归结果单独列出。未发现另一个已证实的 P0 语义分叉；已有通过仍只覆盖当前声明的 profile。 |
| P1 资源与内存 | 已有跨块/调用 Owner、Loan、bulk、局部记录借用、v7 buffer chain 及合作取消；一般 typed place/布局/部分初始化、逃逸借用、任意递归堆 ADT，以及同一 standalone Core 下的并发/原子/通道统一语义仍待实现。 |
| P2 Core 到原生 | 独立 Rust `--owned-run` 已扩展并验证现有 primitive v1–v7 的资源执行。全部前端/规范化/Core/LLVM 构造的精化关系仍待证明；有限差分、静态 shadow 和选定 Lean 定理不能替代全编译器语义保持证明。 |
| P3 C 迁移 | 已闭合本轮 VLA 误接受，并保留显式 slice 契约；原 GCC 驱动完整语义、任意 AST/构建配置/指针语义、代表性工程的低成本迁移仍未认证。当前拒绝 VM/VLA 参数。 |
| P4 C++ | 具体模板、受限 owner 协议和多对象 foreign bridge 有证据；一般对象/模板/STL、实现迁移及异常 ABI 仍待扩展。foreign noexcept 终止不等于分配失败恢复。 |
| P5 性能 | CPU 测量质量门禁未通过，Rust 全面性能优势未建立；代表性应用、布局/向量路径和真实 GPU 执行仍缺。 |
| P6 Agent | 语义编辑以全模块重验证兜底；健全增量验证和完整诊断仍待补齐。已有真实模型实验未证明相同任务/预算下的收益，需代表性独立维护任务。 |
| P7 硬件与生产 | 已有 Linux CPU/QEMU 范围；standalone 当前排除 MMIO、atomics、32 位字模型。真板 MMIO/IRQ/DMA、真实持续负载、边界与故障恢复尚无资格结果。 |

[本轮只读硬件可见性记录](hardware-visibility.json) 中，没有可见 GPU render/NVIDIA/KFD 节点或 USB/ACM 板卡串口节点，也没有 nvidia-smi/rocminfo。它只描述当前执行 namespace，不推断不可访问宿主机的设备，更不构成真实 GPU/板卡实验。

原始类型读取每个含指针 TU 前后重验整个 capture，存在静态可见的 O(N²) TU 重验规模成本。本轮没有计时研究，不把它写成已经测量的性能退化。

**完整 P0–P7 验收仍未完成。** 历史兼容字段 `full_seven_deliverables_complete` 和整体 `whole_project_blockers_closed` 继续为 false。各阶段的公开边界见 [HIA_SEVEN_STAGE.md](../../../docs/HIA_SEVEN_STAGE.md)。

## 10. 证据读取与复核

[首批复制清单](copied-receipts.json) 和 [后续复制清单](subsequent-copied-receipts.json) 与 [独立审查复制清单](review-copied-receipts.json)、[组件源码复制清单](source-copied-receipts.json) 与 [最终执行复制清单](final-copied-receipts.json) 记录逐文件原路径、大小和 SHA-256；复制前后源文件及目标内容逐字节核对。原路径用于来源身份，不是可移植链接。各原始 manifest 可能引用本目录没有复制的原生二进制或其他文件；本目录没有声称包含这些遗漏内容。

### 恢复实际接受组件测试的源码

[verified-component-sources.bundle](sources/verified-component-sources.bundle) 保留五个实际本地提交对象：`0f272a44`、`6e16922e`、`dfdf944f`、`e1cfb040` 与 `de40b4a`。它只有 **27,417 字节**，以已公开的 `ff88d4cd` 及其祖先作为前置对象，内容限于后续源码和 Git 元数据，未打包原始实验归档或模型请求/响应。

[bundle 收据](sources/bundle-receipt.json) 绑定各分支、对象清单和 SHA256；[独立解包收据](sources/bundle-replay.json) 确认五个组件 commit 都实际位于新解出的 pack 内，并通过 Git 对象校验。该解包不是新增项目测试。

在已获取本 PR 及其 base 的仓库内，可以恢复这些精确提交：

```sh
git bundle verify evidence/audits/p0_p7_original_type_followup/sources/verified-component-sources.bundle
git fetch evidence/audits/p0_p7_original_type_followup/sources/verified-component-sources.bundle 'refs/heads/work/*:refs/heads/review/hepta-components/*'
```

[发布收据](sources/publication.json) 另外证明 `e6379178` 的完整 tree 与已审查本地 `de40b4a` 一致，12 个变更 blob 逐一核对。对象一致不是测试执行，也不是远端 CI 通过。

本目录新增说明、派生聚合与原始执行记录分开保存。最终证据发布只增加审查记录及历史审查说明的指向，不改变执行源码；完整回归的正式执行身份始终是实际运行的 `e6379178`，不会改成后续 evidence commit。
