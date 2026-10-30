# Hepta HIA — round 7 原始证据与独立恢复

> **修复源码的 6/6 workflows、18/18 jobs 均在首个 attempt 成功。** 最终 integrated 完成 401 modules、3,947 个唯一 Python 方法、8 个集成 gates、171 个 canonical selectors 与 84 个实际 Rust tests；各计数的范围和重叠关系见第 5 节。初始 e6 的真实 SIGILL 失败和两版负收益证据继续按原身份保留。

本轮完成了有限 HIA 资源语义、独立 Rust 差分、C post-test 循环迁移、原生优化机会实验以及 Legacy IR-PGO 目标策略修复的实际执行与证据收集。修复源上的本地正确性检查、六条已完成 CI、原始负结果和历史失败分别保留。两个最终 guarded 实验均得出 `no-economic-opportunity`，旧 NDU 对照也没有建立增量净收益；本包不声明全局最优、不声明性能优于 Rust，也不声明六项长期目标全部关闭。具体范围和仍为 `false` 的声明见各原始报告及下文。

## 1. 发布身份与归档

| 项目 | 值 |
| --- | --- |
| 源码仓库 | `TrillionniumFoundation/Hepta` |
| 最终资格源码 commit | `e57f440c32b54ffc8da795370fc288652f3c3319` |
| 最终资格源码 tree | `c5f098feb0cd1d9e465a364088b49f2568ceea31` |
| 源码分支 / PR（尚为草案） | `codex/hia-round7-opportunity-20261029` / [#388](https://github.com/TrillionniumFoundation/Hepta/pull/388) |
| 初始资格源码 commit | `e6b10e9b74c6585f9dba18a78a31cf8f36c071c5` |
| 初始资格源码 tree | `18d5689f68baa2b1e0c496b1ee097adffe43ae39` |
| 最终 CI 汇总记录时间 | `2026-10-30T02:30:34.371429+00:00`；[汇总依据][final-summary] `/authored_at_utc` |
| Integrated 最终结论及审查入口 | `success`；[内容审计][integrated-audit] SHA-256 `0b89c90dffc40d88ca5129c095b27b75c5342430d409f5a26b83633eeecccd9c` |
| 冻结输入 selection SHA-256 | `4feab6e6941d5fd62766de64eeb0c6e7ed12377c30a5456ac8a6d560f3d26482` |
| 原始选入文件总数 / 字节数 | **3,064 files / 376,682,379 B** |
| 原始公共 CI ZIP 总数 / 字节数 | **32 ZIP / 126,961,509 B**；共 **8,636 members** |
| 完整 XZ 字节数 / SHA-256 | **119,323,516 B** / `cdddee389756a2825166000889b5b78a57d3cd2257d07f147f58ca47ade69fac` |
| 6 MiB 分片数 / 最后一片字节数 | **19 parts / 6,077,308 B** |
| 独立恢复验收 | `all_passed: true`；[INDEPENDENT-RESTORE.json][independent-restore]，22,223 B，SHA-256 `5f5e3693ead27c689f5346c4c8c848c73edffd9cf7fe916492c9db5d4977dabf` |
| 独立逐字节对照 | `all_passed: true`；[INDEPENDENT-COMPARE.json][independent-compare]，6,844,234 B，SHA-256 `1635abc7adab1ca14d4424f58f6f7b69d88c142e3f4fe216cec048fd6d1e588d` |
| 归档清单身份 | `ARCHIVE.json`：4,607 B，SHA-256 `0fb0ebf8ab344b71fdd6932665c7fe9077eb9e202b5ade83aae3a11bd99c4b4b` |
| 证据发布 commit / tree | 由包含本目录的 Git 提交与 tree 确定；见 [PR #388 中的发布链接](https://github.com/TrillionniumFoundation/Hepta/pull/388) |
| 远端逐字节回读 | 以 [PR #388 的发布记录](https://github.com/TrillionniumFoundation/Hepta/pull/388)所列实际回读收据为准；本文不预先声明后续远端操作完成 |

最终资格源码身份来自[修复源码发布收据][source-repair]的 `/commit`、`/expected_tree` 和 `/remote_commit`。这组身份约束本轮最终资格执行；它不把历史失败、开发阶段输出或审查记录改写为同一版本的执行结果。`INPUT_SELECTION.json` 的 `/evidence_inputs` 为每一组输入单独记录来源、源码身份、状态和说明；`RAW-INDEX.json` 为实际选入的每个文件及每个公共 ZIP 成员记录大小与 SHA-256。

**路径约定：** 本文的 `evidence/...`、`guarded-development/...`、`resource-review/...` 均为原始归档中的相对路径，恢复后按相同路径读取。下文链接供恢复后查阅；未展开时，可先在 `RAW-INDEX.json` 中定位对应路径。JSON 字段引用使用 `/field/subfield` 形式，避免只凭摘要判断结果。

## 2. 先验证，再按需恢复

把 `RESTORE.py`、`PACKAGER.py`、`ARCHIVE.json`、`RAW-INDEX.json`、`INPUT_SELECTION.json` 与全部 `parts/` 分片保持在发布布局中。需要 Python 3.10+ 和支持 POSIX no-follow 目录操作的主机。恢复器只使用 Python 标准库，不执行归档内的程序、编译器、测试或求解器。

仅检查完整性，不创建恢复后的证据树：

```bash
python3 RESTORE.py --verify-only
```

恢复到一个**尚不存在**的目录，其父目录必须已经存在：

```bash
python3 RESTORE.py --output /tmp/hepta-round7-evidence
```

同时展开已索引的原始公共 CI ZIP：

```bash
python3 RESTORE.py --output /tmp/hepta-round7-evidence-expanded --expand-ci
```

`--verify-only` 和两种恢复方式都会检查元数据及工具身份、冻结 selection 的完整映射、分片顺序和逐片哈希、连接后的完整 XZ 哈希、单一 XZ 流与解压长度、TAR 文件及对齐填充、尾部填充，以及全部已索引 ZIP 的每一个成员。`--expand-ci` 只增加文件写出；ZIP 验证不依赖这个开关。展开位置为 `expanded-ci/artifact-<id>/`。

恢复器拒绝非规范相对路径、逃逸、符号链接、特殊文件、重复或别名路径、未索引成员以及多余尾部载荷；所有恢复出的普通文件使用 `0644`，新输出目录使用 `0700`。它不覆盖已有目录，失败时可能保留一个新建的部分输出目录。`all_passed` 仅表示本次归档完整性检查通过，不改变任何原始报告的失败、负收益或研究范围。最终发布 commit 与远端回读收据提供独立核对入口；自包含的哈希本身不证明发布来源的真实性。

独立恢复于 `2026-10-30T02:35:26.646554+00:00` 完成。两条 reader 命令分别是 `--verify-only` 和 `--output ... --expand-ci`，均返回 0、stderr 为 0 B，完整 stdout/stderr 嵌入[恢复收据][independent-restore]。随后独立实现未导入 reader/packager 模块，直接把 **3,064 个 raw files / 376,682,379 B** 与原始允许目录文件逐字节比较，再把 **32 个 ZIP 的全部 8,636 个文件成员 / 567,609,658 B** 与原始 ZIP 重新解压的成员逐字节比较，全部一致。

恢复树共 **11,700 个普通文件、1,243 个隐式目录**；ZIP 显式目录成员为 0。路径/类别集合精确相同，所有普通文件为 `0644`，无符号链接、特殊文件或硬链接，比较前后元数据稳定。[完整对照收据][independent-compare]保留逐文件和逐成员账目，而不是仅保留汇总。以上是归档工具验收，不是重新执行项目测试或原生性能实验；恢复时没有运行归档内项目代码。

## 3. 两个源码版本与原始失败完整保留

| 来源组 | 源码与状态 | 证据入口 |
| --- | --- | --- |
| 初始 round 7 正式执行 | `e6b10e9…` / `18d5689…`；six-outcome run `40984938152` 在真实 IR-PGO 训练子进程上失败，signal 4；其后五个功能阶段未执行 | [初始 six 审计][six-initial]，`/IR_PGO`、`/failed_steps`、`/not_executed_functional_steps` |
| 初始版本其他结果 | 当时合计 17/18 jobs 成功；这个数字包含一个真实失败。初始 verified、integrated、host 结果各自保留，不能代替修复源重验 | [初始执行 checkpoint][checkpoint]、`evidence/ci-core/*-initial/`、`evidence/ci-public-hosts/` |
| 修复开发与路径审查 | 针对 Legacy/IR-PGO override 的目标策略缺口完成实现和独立审查；开发输出保留当时源码状态 | [IR-PGO 路径审查][irpgo-review]、[修复开发 handoff][repair-development] |
| 修复源正式执行 | `e57f440…` / `c5f098f…`；本地以及六条 CI workflow 按新源码重新执行，六条均已收集并审查成功，合计 18/18 jobs | `evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/` |
| 早期证据 checkpoint | 证据 commit `34faf93efdf1b8fba7f304b1c5da037aa11fd30a` 保存初始版本本地负结果；这是证据身份，不是最终源码身份 | [checkpoint 发布与回读收据][checkpoint-publication] |

初始发布收据记录本地提交 `13f19af3b61f8d1bbb1bf1668d17f92052d41c89` 与发布后的 `e6b10e9…` 对应同一 tree；修复发布收据记录本地 `15ba326979f2791b14d8f5053003f63028d9f12a` 与发布后的 `e57f440…` 对应同一 tree。正式资格结果以各报告记录的实际 commit/tree 为准，不能只因 tree 相同便修改原报告身份。历史目录 `evidence/final-source/` 保留的是初始 e6 阶段的原字节；目录名中的 `final-source` 不表示它属于后来的 e57。[初始源码收据][source-initial]、[修复源码收据][source-repair]及[verified 执行来源声明][verified-lineage]保留这一关系。

这次缺口在研究编译路径中：原始 HIA IR 没有绑定实际 C 前端完整的 CPU 正、负特性。修复覆盖 LTO、IR instrumentation、profile-use 和 resource object 四条 override 路径，对 Core、原始/绑定 IR、编译器、profile 文件和 flags 的前后身份进行检查。真实 probe 只去掉明确的 link-only 参数；对象编译保留 CPU、优化、LTO 和 profile-use 策略。旧训练失败没有通过自动重试、降低优化级别或删除负例掩盖。新的 guarded 机会协议保持原样，没有给它追加 `-march=native`。[路径审查][irpgo-review]及[e57 实际目标与训练审计][irpgo-final]提供源码与执行证据。

原始同一 CI job 的实际 Clang 前端 capture 记录了 `znver4` 与禁用 AVX-512 的目标策略，保留的插桩 DSO 含有超出该策略的 EVEX 指令；这支持目标特性传播缺口的因果判断。[初始失败诊断][irpgo-failure]同时明确：编译器选择的策略不等于失败子进程的完整硬件 CPUID/XCR0 测量，也没有捕获精确故障 PC。独立 masked-CPU 回归控制实际重现 raw IR 的 SIGILL，并验证绑定后的四条路径；这支持修复机制，但不冒称获得了原始主机缺失的诊断数据。原始 SIGILL 收据、无重试控制、完整日志中的 JSON 行与修复后的正常训练分别保留。[修复控制日志审计][repair-controls]：`/actual_execution_controls`、`/host_reconstruction_or_original_fault_PC_claim`。

## 4. 修复源 CI：六条工作流全部完成

下表仅对应 e57。**6/6 workflows、18/18 jobs 均在 run attempt 1 成功**；结论来自各自最终 API、完整任务日志和内容审计。最终 integrated API 的 `updated_at` 为 `2026-10-30T02:25:36Z`，其后完成了原始产物收集和逐项审查。此表不把初始 e6 的失败改记为成功。

| Workflow | Run | Jobs | 当前有证据的结论 |
| --- | --- | ---: | --- |
| Actual host ABI qualification | `40987874075` | 7 | success，首个 attempt；[host handoff][hosts] |
| Real upstream C++ host qualification | `40987874060` | 7 | success，首个 attempt；[host handoff][hosts] |
| HSIR and C migration checks | `40987874028` | 1 | success，167 unique methods、0 skip；[host handoff][hosts] `/migration` |
| Verified optimization | `40987878470` | 1 | success；[verified handoff][verified-handoff] |
| Six-outcome source and application gates | `40987878447` | 1 | success；[six handoff][six-handoff] |
| Integrated qualification | `40987874131`，job `123843024179` | 1 | success，首个 attempt；[integrated handoff][integrated-handoff]、[内容审计][integrated-audit] |

Workflow 名称中的 “six-outcome” 不是六项研究目标全部关闭的结论。工作流通过、有限实验执行完成、经济机会成立和一般语言安全证明是不同命题。

## 5. 正确性计数与证据范围

| 队列 | e57 上的真实结果 | 核对入口 |
| --- | --- | --- |
| Full integrated regression | 401 modules，**3,947 个唯一方法**，0 failure/error/skip；8/8 gates 通过 | [integrated 审计][integrated-audit] `/full_regression`、`/gates`；[完整方法清单][integrated-methods] |
| 本地 focused Python | 13 modules，**170 个唯一方法**，0 failure/error/skip | [focused handoff][focused] `/python`、`/method_counts_by_module`；[完整结果][focused-result] `/python/executions` |
| 本地独立 C migration Python | 3 modules，**24 个唯一方法**，0 failure/error/skip | [migration 结果][migration-result] `/unittest/executed_ids` |
| 本地两队列去重 | 两个 ID 集交集为 0，合计 **194 个不重复 Python 方法** | 上面两个原始方法 ID 清单；[checkpoint][checkpoint] `/repair_local_results` |
| 独立 Rust shadow crate | `cargo test --locked --offline`：**84 个实际 tests**，0 failed/skipped/filtered-out | [focused handoff][focused] `/rust/outcome`；15 条 Running 记录与一个空 Doc-tests 段不能称为 16 个已执行二进制 |
| Verified regression | 83 个选定 modules，**825 个唯一方法**，0 failure/error/skip | [verified 审计][verified-audit] `/regression`；[范围变化][regression-scope] |
| Six regression | **354 个唯一方法**，0 failure/error/skip | [six 审计][six-audit] `/regression`；[完整 test ID 审计][six-methods] |
| Canonical safety contract | 28 capabilities，**171/171 selectors**，0 skip | [six 审计][six-audit] `/canonical`；原始 `selected-reports/safety.json` |
| Selected scalar lowering | **449/449 verified**，0 refuted/unknown；另有 4 个 refuted 和 1 个 rejected-profile 负控制 | [scalar 原始输入与义务审计][scalar-audit] |

Integrated 与初始 e6 的 3,944 个方法相比，保留全部原方法，新增以下 3 个；没有删除方法。比较依据是[初始方法清单][integrated-initial-methods]与[修复源方法清单][integrated-methods]中的完整 `/methods/*/id` 集合。401 modules 的范围没有增加；这 3 个方法与 canonical 新增 selectors 对应，但 verified 的选定队列只纳入其中后两个。不能把 full integrated、canonical 与 verified 的增量相加。

| 新增 integrated 方法 | 实际覆盖 |
| --- | --- |
| `test_hia_filecheck_target_profile.FilecheckTargetProfileTests.test_legacy_irpgo_overrides_preserve_masked_cpu_features` | 真实 masked-CPU 下，原 raw IR 失败控制及四条修复构建路径 |
| `test_hia_legacy_irpgo.SameCoreBuildInputTests.test_changed_bound_ir_profile_and_compiler_refuse_before_build` | bound IR、profile 和编译器输入漂移在构建前稳定拒绝 |
| `test_hia_legacy_irpgo.SupervisedChildFailureTests.test_actual_sigill_retains_failed_child_receipt_without_retry` | 实际 SIGILL 子进程失败收据与不自动重试 |

Integrated 的 8 项 gate 分别是实际工具/Linux seals、ranking/recursive/finite/stream 四个 bridge identity probes、Rust resource crate、full regression，以及 merge/profile coverage。四个 bridge probes 是合成 advisory 协议检查：ranking 为 `ADVISORY_ONLY`，其余为 `DENY_ALL`，不能据此获得代码接纳权或推断 NDU 性能增益。63 个 coverage groups 覆盖 1,515 个唯一方法，均是 full regression 的子集，不是额外测试。[integrated 审计][integrated-audit] `/gates`、`/coverage`、`/NDU_identity_probe_scope`。

上述数字不是一个可相加的“总覆盖率”。不同 CI 队列与本地队列有重叠，求解义务、方法、native calls 和资源账本快照也采用不同计数单位。Verified 的 825 是冻结的选定队列，不是全仓库 unittest discovery；与 e6 的 823 比较，增加两个方法、没有删除方法。Canonical 的 171 则是原 168 加三个 repair selectors，不能把这两种增长混为同一清单。[范围变化][regression-scope]和[方法审计][six-methods]给出 ID 层依据。

本地 focused 与 migration 执行都保存源码前后快照和工具身份；focused 的 6,421 个 tracked source paths 前后相同。最终 integrated 也独立核对 6,421 个 tracked Git paths 的原始 blob 字节、执行前后身份和外部报告输入；具体见 [integrated 源码审查][integrated-source]及[内容审计][integrated-audit] `/source`。独立资源核心的有限 v8、组合资源、返回借用、分配失败、显式取消以及逐步停止账本检查只支持声明的子集。预算停止、进程信号与宿主中断不自动等价于源码析构或一般异常展开；通用共享内存、原子操作和任意线程安全未因此获得证明。[focused handoff][focused]以及原始 safety contract 的 `/boundaries` 记录这些边界。

## 6. Legacy IR-PGO 修复后的真实执行

e57 six 公共原始 ZIP `12947987813` 为 **62,005,028 B**，SHA-256 为 `d5723d60938b5c9da6ee8c93ba6526030ca5a0824965b155a10f862c5ff2a152`。3,684 个成员的路径、CRC、大小和 SHA-256 已逐一核对；相关报告中的 1,001 个公开源码路径已与 e57 的 Git blob 原字节绑定，313 项归档内路径/哈希引用已检查。[six handoff][six-handoff]、[源码字节审计][six-source]和[ZIP 索引][six-zip]保留可复核身份。

| 应用准备 | Native differential | 资源观察 | 维护案例 | 状态 |
| --- | --- | --- | ---: | --- |
| Filecheck | 96 cases × 8 routes＝768 calls | 48 cases × 2 routes＝96 calls | 4 | `prepared_not_measured` |
| Legacy queue | 96 × 8＝768 calls | 96 × 2＝192 calls | 12 | `prepared_not_measured` |
| Legacy IR-PGO | 96 × 11＝1,056 calls | 96 × 3＝288 calls | 12 | `prepared_not_measured` |

IR-PGO 的 361 条实际命令均返回 0。四条受影响构建路径均消费绑定后的 IR，实际前端记录 `znver5` 的 119 个 signed features（62 正、57 负），22 个内部/导出定义的属性重建逐字一致。HIA/C/C++ 的 entry block-counter 数分别为 44/18/28，原始计数列表、非空 raw profiles、merged profiles 和训练子进程均保留；block counters 不解释成函数入口调用次数。资源 observer 使用同一 LLVM/profile 的独立二进制，报告没有声称在性能 DSO 本体内注入了失败。[目标与训练审计][irpgo-final]。

原先在 e6 失败后跳过的五个 Agent 阶段本次均真实运行，计数依次为 **35/35、3/3、9/9、19/19、19/19**。其中包括预期的错误输出、编译拒绝、旧 profile 拒绝和 stale revision 拒绝；失败事务保持原 revision。它们是 native reference/hostile controls，**模型请求为 0**，不构成 Agent 生产力测量，也不是 NDU 经济实验。[Agent 控制审计][agent-controls]。

三项应用准备报告的正式性能样本均为 **0**。PGO 训练、准备耗时和有限差分通过不能写成性能通过；`default_backend_receipt`、native refinement 和普遍性能优势声明仍为 `false`。[six 审计][six-audit] `/applications`、`/IR_PGO`、`/limits`。

## 7. 最终 guarded 机会实验：两次真实负结果

最终 e57 在本地和 verified CI 各完成一次预先固定协议的实验。两次均保留完整 **84 样本**，`qualified: true` 表示规定的实验及正确性检查完成；经济结论同时明确为 `status: "no-economic-opportunity"`、`opportunity_gate_passed: false`。

| 执行位置 | 协议内完整 study cost | hot8 training / validation 净节省 | hot10 training / validation 净节省 |
| --- | ---: | ---: | ---: |
| e57 本地 | **11.941468703 s** | −12.105060703 / −12.237340703 s | −12.412024703 / −12.131623703 s |
| e57 verified CI | **12.840035892 s** | −12.999244892 / −12.927356892 s | −12.946548892 / −12.999411892 s |

数据分别来自[本地 guarded 原始结果][guarded-local]与[CI guarded 原始结果][guarded-ci]的 `/charged_search_wall_ns` 和 `/economics/module_opportunities/*/phases/*/net_savings_ns`。两次使用同一个协议 SHA-256：`1b4d1818d7fa9aff079bf7b27220d9f4df2bc0668a52b827e8a0adbd1b8cebbf`。早期 e6 的本地/CI 样本仍保留原身份，不与这里的样本合并，不从多次结果中按性能挑选赢家。

协议计算 `((x // denominator) + (x % denominator)) mod 2**32`，分母为零先 trap。公共候选银行包含 baseline、denominator-8 guard、denominator-10 guard；hot8/hot10 各有 90% 的合成 hot denominator，training 与 validation 使用分别固定的七个种子。每 batch 200,000 次迭代；3 candidates × 2 modules × 2 phases × 7 trials＝84 样本。每模块预定 100,000,000 次未来调用，即 500 batches。这是合成研究需求，不是实际 C/C++ 应用流量或生产需求。[两份原始结果][guarded-local] `/protocol`。

保守节省按**完整新子进程 batch 的外层 wall time**计算：同一模块/阶段的最小 baseline batch 减最大 candidate batch，再乘 500，扣除完整 study cost。内部 kernel 计时和 break-even 只作诊断；这个 min/max envelope 不是统计置信区间。机会门要求至少两个 module-specific、原生代码不同的 specialization 在 training 和独立 validation 中扣完全部记录成本后均为正，才允许另行比较 NDU 与完整枚举。两次均不满足，`ndu_comparison_authorized_by_this_evidence` 和 `NDU_gain_established` 均为 `false`。[本地][guarded-local]、[CI][guarded-ci] `/economics`。

这里的 study cost 包括协议范围内候选生成、baseline 及候选的证明、选定 LLVM 检查、编译、pinning、Python oracle、native 差分、training/validation、preflight 和最终源码检查；每个外层样本包含子进程启动、load、guard 与 cleanup。它**不包含**外部工具安装、最外层 Python 启动/import/参数处理，以及最终 cost 字段装配、报告修饰、JSON 序列化与写入。最大 60 秒是有界操作之间检查的验收预算，编译和证明各有有限 timeout，不是对所有操作的 60 秒硬实时抢占保证。最多选择一个 specialization 的限制也不代表只构建了一个候选；本次整个银行实际生成并计费。精确边界见 `/protocol/cost_boundary`、`/cost_exclusions`、`/limits`。

Core 全输入等价与选定 LLVM 检查均有独立证据，finite native differential 通过；这些证据不升级成最终机器码 refinement、并发/资源通用证明或性能收益。[CI 审计][verified-audit] `/guarded_opportunity` 与两份原始 `/claims`。

## 8. 旧 NDU 对照与版本切换的真实成本

Verified 中的旧 NDU bank 使用另外一份 constant-fold 协议，**30 episodes＝5 arms × 6 matched cohorts**，所有 episodes 完成并保留同样的每 episode 30 秒 deadline。NDU 自己的 **6/6 次选择 `stop`**；`fixed-fold` 的六次选择 `constant-fold`。因此不能写成“30 次全部 stop”，也不能把这个旧 bank 当作新 guarded bank 的 NDU 对照。[NDU 预算与成本审计][ndu-cost] `/episode_rows`、`/episodes`、`/new_guarded_bank_comparison`。

| 旧协议策略 | 每个 standalone 策略的总成本 |
| --- | ---: |
| fixed-stop | 2.389267367 s |
| fixed-fold | 3.902819133 s |
| fixed-selected | 2.387637494 s |
| light | 2.384051334 s |
| NDU | **29.482030839 s** |

这组比较包含共享 setup 对每个 standalone 策略一次计费，以及仅向 NDU 计费的实际 native build **26.627448330 s** 和 native admission **0.001777439 s**。原始实验实际共享成本只发生一次，不能把反事实 standalone 比较误算为它重复发生五次。NDU build 的 target cache 为空，但已有 dependency source cache，不能声称整机完全冷启动。成本排除工具安装、预先存在的依赖源码缓存获取、build manifest 最终写入与 build 进程启动；各项与 ledger 的和已经对保留数据重新计算。旧 bank 的 identity 和 constant-fold 原生字节相同，没有由此建立 NDU 的统计优势或增量收益。[verified 审计][verified-audit] `/old_ndu_cohort`；[成本审计][ndu-cost] `/standalone_costs_recomputed`、`/cost_exclusions_as_declared`。

版本切换和 owned-state 检查也保留了实际负收益：adaptive `net_before_switch_ns` 为 **−290,610,458 ns**；owned queue 的部署净值为 **−549,779,618 ns**，部署成本为 **549,786,084 ns**，含反事实审计的实验总成本为 **549,806,777 ns**。自动盈利选择没有启用。已观察到活动调用阻止切换、过期证据拒绝、显式切换保持同一 owner/allocation、取消队列不重放已提交步骤；最终 native ledger 为 allocations/frees **17/17**、live **0**、refusals **2**，pending resources **0**。这些是有限状态与声明生命周期的证据，不是任意 heap 迁移、崩溃恢复或外部副作用 exactly-once 的证明。[生命周期与净值审计][lifecycle]。

## 9. C/C++ 迁移与七组实际 host profiles

### 9.1 直接源码迁移

本地和 verified CI 分别执行 e57 的 C post-test 应用验收：48 functional cases、144 native functional calls，16 resource cases、32 native resource calls。结构化 AST 迁移覆盖 12 个函数体，其中 11 个 upstream、1 个 authored migrated helper，另有 authored HIA client；HIA 目标没有链接原始 C implementation objects，Rust backend 不是这条独立 HIA 执行路径的依赖。原始捕获输入、Core、LLVM、资源记录与 source before/after 都有保留。[本地 C 结果][c-local]与[verified 审计][verified-audit] `/c_posttest`。

Verified 另保留 C++ scoped 1,121 cases，以及 composed 两个变体各 437 cases。Scoped 原始 native ledger 是 allocations/frees 3,180/3,180、live 0、refusals 398，并有 destruction-order 和 leak 负控制；composed 每变体为 401/401、live 0、refusals 196。独立目标不链接原始 C++ objects；保留的是声明范围的 scalar C ABI，不是任意 C++ class layout、mangled ABI 或全部 RAII 的自动支持。[verified 审计][verified-audit] `/cpp_scoped`、`/cpp_composed`。

### 9.2 实际 host ABI 与未修改 upstream C++ 库复用

两个 native host lanes 各在以下七组配置真实执行；这是 **3 个操作系统家族、2 种架构、7 个 OS/compiler/architecture profiles**，不是七种架构。[host handoff][hosts] `/profiles`、`/architecture_count`、`/operating_system_families`。

| 操作系统 profile | 架构 | 编译器 |
| --- | --- | --- |
| macos-15 | aarch64 | clang |
| ubuntu-24.04 | x86_64 | clang |
| ubuntu-24.04 | x86_64 | gcc |
| ubuntu-24.04-arm | aarch64 | clang |
| ubuntu-24.04-arm | aarch64 | gcc |
| windows-2025 | x86_64 | clang |
| windows-2025 | x86_64 | msvc |

每个 C ABI profile 执行两个优化配置，每次 181 foreign calls，另保留类型拒绝与 wrong-native-code 拒绝。每个 C stb profile 有 21,453 distinct inputs、42,906 input/variant pairs、514,872 native function observations、696 interpreter function observations 与 24 个目标 trap 进程。**这个 host 应用 lane 的 native route 是 Rust，`HIA_LLVM_host_execution` 为 false；不能把七组 host 结果算成 HIA LLVM 后端七平台执行通过。** 独立 HIA LLVM 的迁移执行证据在前述明确的对应报告中。[host handoff][hosts] `/C_ABI_per_profile`、`/C_stb_per_profile`。

C++ host lane 复用未改写的 upstream 库版本 `3.11.3`、`3.12.0`，每版本每 profile 98 cases、1,024 concurrent calls、32 lifecycle cases，另有错误 native code 和不兼容 signature 拒绝。ordinary live delta 为 0 的基准点是在 registry warmup 之后；Linux/macOS 仍保留 2 个、Windows 保留 3 个进程生命周期 registry allocations，原报告没有把它们隐藏成“全进程零分配”。这些观察不证明外部库内存安全、任意借用保留、所有 foreign allocation failure 恢复、异步取消或普遍升级兼容性。[host handoff][hosts] `/CXX_per_profile`、`/qualification_boundaries`；[逐 profile 原始结果索引][host-index]。

Windows 两个 C++ profiles 对七个 example 文件记录了 CRLF 字节，共 14 个对应观察。审查确认它们与相关 Git blobs 的这组具体 CRLF 表示一致；这不是各 host 原始字节完全相同，也不是一般换行正规化等价证明。[host handoff][hosts] `/source_byte_identity`。

## 10. 这份证据能支持什么，哪些目标仍开放

| 工作项 | 本轮可支持的判断 | 尚不能关闭的部分 |
| --- | --- | --- |
| 统一语义入口与候选实现 | 精确源码上的 canonical admission、有限资源语义及实际编译路径得到一致性检查；未证明候选不由 metadata 自动授权 | 整门语言 preservation/progress、source→Core→最终机器码的通用 refinement |
| 资源核心与 Rust 差分 | 声明子集内组合资源、返回借用、失败/取消及停止账本有实际对照和稳定拒绝 | 任意并发、MMIO、通用异常展开、所有宿主中断的清理定理 |
| 优化前后行为 | 选定 Core 全输入与 scalar LLVM 义务有证据；native 差分和资源观测分开保留 | 一般机器码等价、所有优化/所有输入的资源安全 theorem |
| 有限动作 NDU 优化器 | 旧 bank 的 matched-budget 与 build-inclusive 成本透明；新 bank 机会门正确保留负结果 | 新 guarded bank 上的公平 NDU 增量收益、普遍优于固定策略和简单搜索 |
| C/C++ 迁移与 ABI | 有限真实函数体迁移、独立目标执行、七组实际 host 配置和未改写库复用 | 任意 C/C++ 低成本无损翻译、原始指针契约自动推断、外部库绝对安全 |
| 多版本与更低层搜索 | 有限状态切换、资源释放、无重放控制有实际输出；负净值完整保留 | 正的生产净收益、一般 heap/state 迁移、全局最优指令规划 |

这里没有“超过 Rust 性能与资源管理”的测量结论，也没有“绝对安全”的全语言证明。保留有限等价证据、拒绝控制和负实验，是让进一步实现能够被审查的基础，不应被改写成更强的营销结论。原始 safety `/claims`、guarded `/claims`、[six 审计][six-audit] `/limits` 和 [verified 审计][verified-audit] 中的边界共同约束本包摘要。

## 11. 公共输入、隐私隔离与完整性

最终选入范围由冻结的 `INPUT_SELECTION.json` 枚举，组件限定为 `evidence`、`guarded-development`、`resource-review`；每个文件有独立大小、SHA-256 和 provenance group。工具不扫描 toolchain 安装树或其他历史包，不根据文件夹现状静默补项。源码绑定及工具版本/安装获取记录见各 cohort 的原始 receipts 与[工具链来源记录][toolchains]。

公开 host、integrated、six 的原始公共 ZIP 按明确 allowlist 纳入，并在 `RAW-INDEX.json` 逐成员登记。**Verified 原始 ZIP 含私有 bridge 字节，整包禁止进入公共发布；只纳入经过审查、逐项列明的公共原始成员。** 当前 e57 verified 选入 306 个成员、12,707,315 B，排除 357 个成员，其中有 4 个私有 bridge binaries。正式数值与 include/exclude 身份见 [verified handoff][verified-handoff] 的 `/public_original_members`、`/excluded_members`、`/original_zip_publication_allowed`，以及该目录的 `PUBLIC_EXTRACTION_ALLOWLIST.json`。初始版本同样按它自己的清单保留，不能复用修复源统计。

签名传输 URL、私有 NDU 源码与 bridge binary bytes 留在公共输入之外。公开的 NDU identity/build metadata 中可以保留来源路径、大小和哈希；保留身份元数据不意味着保留了私有文件内容。six 公共 ZIP 已验证未包含与这些已记录私有 source/binary 哈希相同的成员。路径、成员类别和敏感模式检查有明确范围，不能被称为任意秘密不存在的数学证明。[six 内容审查][six-content]。

API JSON 记录 connector 返回的完整语义值，经 JSON 序列化保留字段；它们不冒称原始 HTTP wire bytes。Job logs 是 connector 返回完整字符串的 UTF-8 表示；各目录记录是否存在 BOM/CRLF。原始公共 ZIP、选出的 ZIP members 和逐行提取的控制 JSON 按各自收据记录原字节，不能将上述不同表示混称为一种“原始字节”。[six 日志表示][six-log-representation]、[host handoff][hosts] `/qualification_boundaries`、[verified handoff][verified-handoff] `/boundaries`。

发布包根目录的 `VERIFY_ONLY.json` 与 `ASSEMBLY-VERIFICATION.json` 记录组装阶段的归档检查和源码/工具稳定性；独立恢复及逐字节对照收据另见第 1 节。归档工具验收不会重新运行任何已保存的项目程序，也不增加正确性或性能测试方法数，不改变任何失败或负结果。发布 commit/tree 取包含本目录的 Git 身份，远端逐字节回读以 PR #388 中的实际发布记录为准。

[source-initial]: evidence/publication/source-receipt.json
[source-repair]: evidence/publication/repair-source-receipt.json
[checkpoint]: evidence/publication/active-checkpoint.json
[checkpoint-publication]: evidence/publication/guarded-checkpoint.json
[six-initial]: evidence/ci-core/six-initial/RESULTS_AUDIT.json
[irpgo-review]: evidence/reviews/irpgo-path-review.json
[repair-development]: evidence/repair-development/resource-suite-HANDOFF.json
[focused]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/focused/HANDOFF.json
[focused-result]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/focused/RESULT.json
[migration-result]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/migration-tests/RESULT.json
[c-local]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/c-posttest/RESULT.json
[guarded-local]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/guarded-opportunity/RESULT.json
[guarded-ci]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/verified/selected-public/guarded-opportunity/RESULT.json
[hosts]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-public-hosts/HANDOFF.json
[host-index]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-public-hosts/RESULTS_INDEX.json
[verified-handoff]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/verified/HANDOFF.json
[verified-audit]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/verified/RESULTS_AUDIT.json
[verified-lineage]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/verified/QUALIFICATION_LINEAGE.json
[regression-scope]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/verified/REGRESSION_SCOPE_CHANGE.json
[ndu-cost]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/verified/NDU_BUDGET_AND_COST_AUDIT.json
[lifecycle]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/verified/LIFECYCLE_AND_NET_AUDIT.json
[six-handoff]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/six/HANDOFF.json
[six-audit]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/six/RESULTS_AUDIT.json
[six-methods]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/six/REGRESSION_METHODS.json
[scalar-audit]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/six/SCALAR_OBLIGATIONS_AUDIT.json
[irpgo-final]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/six/IRPGO_TARGET_AND_TRAINING_AUDIT.json
[repair-controls]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/six/REPAIR_CONTROL_LOG_AUDIT.json
[agent-controls]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/six/AGENT_CONTROL_AUDIT.json
[six-source]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/six/SOURCE_BYTE_REVIEW.json
[six-zip]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/six/ZIP_INDEX.json
[six-content]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/six/PUBLIC_CONTENT_REVIEW.json
[six-log-representation]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/six/LOG_REPRESENTATION.json
[toolchains]: evidence/toolchain-provenance/RESULT.json
[final-summary]: evidence/publication/final-summary.json
[integrated-handoff]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/integrated/HANDOFF.json
[integrated-audit]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/integrated/RESULTS_AUDIT.json
[integrated-methods]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/integrated/REGRESSION_METHODS.json
[integrated-initial-methods]: evidence/ci-core/integrated-initial/REGRESSION_METHODS.json
[integrated-source]: evidence/by-source/e57f440c32b54ffc8da795370fc288652f3c3319/ci-core/integrated/SOURCE_BYTE_REVIEW.json
[independent-restore]: INDEPENDENT-RESTORE.json
[independent-compare]: INDEPENDENT-COMPARE.json
[irpgo-failure]: evidence/reviews/irpgo-failure-analysis.json
