# HIA / NDU 资格证据台账

生成：2026-10-27T17:38:16.578034+00:00。仅审计现有记录、重算分母并核对文件哈希；未执行新测试、未修改仓库。

## 源码及总状态

| 运行 | 精确提交 | 已有 gate 记录 | 汇总状态 |
|---|---|---:|---|
| run1 | `c8c11a4c51a16d262663d5f8181a96cac98a04d8` | 10/10 | ok=False; mechanism_qualified=True; source_unchanged=True |
| run2 | `c4309712d8f4d21563a26c174391bd66195a9e34` | 10/10 | ok=True; mechanism_qualified=True; source_unchanged=True |

## Gate 分母

| Gate | run1 | run2 |
|---|---|---|
| focused_regression | 193 tests; F=0, E=0, skip=0 | 198 tests; F=0, E=0, skip=0 |
| rust_resource_crate | 54 tests; F=0, E=0, skip=0 | 54 tests; F=0, E=0, skip=0 |
| translation_controls | 通过 | 通过 |
| rust_owned_cfg | 通过 | 通过 |
| real_migration | 通过 | 通过 |
| equal_budget_ndu | 通过 | 通过 |
| native_generations | 通过 | 通过 |
| background_reoptimization | 通过 | 通过 |
| finite_x86_search | 通过 | 通过 |
| full_regression | 2633 tests; F=42, E=21, skip=12 | 2640 tests; F=0, E=0, skip=0 |

run1 的 42 FAIL + 21 ERROR 是 **63 条 unittest 失败/错误记录**，涉及 **38 个测试方法及 1 个类初始化**。它们不是63个独立缺陷，也不能据此把2633减63当作通过方法数。

其中61条来自一个 Python 未导出 fcntl seal 常量名称的兼容性问题，覆盖37个测试方法；另有缺少 `qemu-system-arm` 的类初始化错误，以及缺少 `thumbv7em-none-eabi` core 的一个失败。

聚焦回归、完整回归、Rust crate 和工具内部测试有重叠，不能合并为一个不重复测试总数。

## 有限语义与迁移证据

- Rust crate：54个测试通过，10个 result 汇总组，其中8组非空；没有忽略或过滤测试。
- Rust CFG：179对 Python/Rust 观测、18个不同程序；比较返回值、trap、步数/堆/调用深度停止和资源台账。工具另执行10个回归测试。
- 迁移：C多所有者56个、C++标量类20个、C++字节所有者475个输入案例，每个分别运行原始实现和HIA，因此为 **551×2=1102次 native 结果执行**。212次分配故障执行已包含在1102内。
- 迁移解释器比较为 **188对** Python/Rust：56+20+112。C++字节所有者仅选size≤17的112例，不能声称475例均经Rust执行。
- 翻译验证控制：wrapping cancellation被证明；安全但错误的改写和删除checked trap被否证；循环返回unknown；伪造proved receipt被拒绝。
- 这些结果不等于任意C/C++可自动安全迁移、Rust版验证器取得生产准入权、全语言安全或native backend refinement证明。

## NDU：实际等预算负对照

### run1

6个候选均获得实际SMT证明；49个训练样本+35个holdout样本，合计 **16,800,000次计时native调用**，另有1,680,000次预热。基线及6个候选的完整共享库SHA-256均为 `6d10b9f4492450288598d7d030e3231e2eaa9876a19504fa36e2babc8fe01238`，重新读盘核对一致。

共享搜索成本1,719,308,407ns；固定配方、随机、穷举观察和原生NDU均选择abstain。

| 选择器 | 实际选择 | 策略调用开销ns | 搜索+策略ns |
|---|---|---:|---:|
| exhaustive_observed | abstain | 5,858 | 1,719,314,265 |
| fixed_recipe | abstain | 431 | 1,719,308,838 |
| ndu | abstain | 34,239,349 | 1,753,547,756 |
| seeded_random | abstain | 30,526 | 1,719,338,933 |

NDU内部实际adapter成本另记为34,165,029ns，内部准入总search成本1,753,473,436ns；上表使用完整外层调用计时，二者不应混写。

### run2

6个候选均获得实际SMT证明；49个训练样本+35个holdout样本，合计 **16,800,000次计时native调用**，另有1,680,000次预热。基线及6个候选的完整共享库SHA-256均为 `6d10b9f4492450288598d7d030e3231e2eaa9876a19504fa36e2babc8fe01238`，重新读盘核对一致。

共享搜索成本1,764,569,193ns；固定配方、随机、穷举观察和原生NDU均选择abstain。

| 选择器 | 实际选择 | 策略调用开销ns | 搜索+策略ns |
|---|---|---:|---:|
| exhaustive_observed | abstain | 5,348 | 1,764,574,541 |
| fixed_recipe | abstain | 351 | 1,764,569,544 |
| ndu | abstain | 40,118,337 | 1,804,687,530 |
| seeded_random | abstain | 18,397 | 1,764,587,590 |

NDU内部实际adapter成本另记为40,024,876ns，内部准入总search成本1,804,594,069ns；上表使用完整外层调用计时，二者不应混写。

这是一张共同观测表的paired replay，不能视为在线或顺序学习对照；经验不确定性包络不是置信区间。所有策略均没有建立运行时收益或NDU独有增益。资源cap是准入门槛，非抢占式OS配额。

## 后台优化及多版本生命周期

- run1：实际NDU调用3次。测量共14,592次native调用，其中14,336次计时、256次预热；计时包含Python lease校验和native调用开销。
- run1：实际测量的expected_calls=1 horizon选择`abstain`；显式synthetic-cost lifecycle控制实际发布新代；随后行为错误候选被否证并abstain。真实发布证明生命周期接通，不能作为实测加速证据。
- run2：实际NDU调用3次。测量共14,592次native调用，其中14,336次计时、256次预热；计时包含Python lease校验和native调用开销。
- run2：实际测量的expected_calls=1 horizon选择`abstain`；显式synthetic-cost lifecycle控制实际发布新代；随后行为错误候选被否证并abstain。真实发布证明生命周期接通，不能作为实测加速证据。

独立多版本控制保留3代的生命周期证据：18次native准入探测、14次额外调用观测、2个逐导出翻译证明；观察旧lease继续运行、回滚和内核拒绝写sealed代码。这不是任意在线指令修改或资源状态迁移。

## 有限x86指令搜索

- run1：完整146个配方，实际Z3判定139个不等价、7个等价；全部7个等价候选与LLVM基线均汇编/检查/执行。
- run1：56个等量样本、11,200,000次计时调用、64次边界调用；另有1,120,000次预热。搜索及所有构建成本2,159,882,941ns。
- run1：最短函数体5字节，`488d470cc3`，与LLVM `-O3`的5字节函数体完全相同；7组计时包络全部重叠。
- run2：完整146个配方，实际Z3判定139个不等价、7个等价；全部7个等价候选与LLVM基线均汇编/检查/执行。
- run2：56个等量样本、11,200,000次计时调用、64次边界调用；另有1,120,000次预热。搜索及所有构建成本1,995,369,630ns。
- run2：最短函数体5字节，`488d470cc3`，与LLVM `-O3`的5字节函数体完全相同；7组计时包络全部重叠。

这个byte minimum仅针对完整声明的146配方文法及可信ISA模型/编码器，不能推导最低运行时间、全程序最优或普遍超过LLVM/Rust。该离线穷举结果也不能归功于NDU的学习能力。

## 另行完成的既有C ABI host CI

这组证据属于原有Hepta有限C ABI matrix，不把新的Linux HIA multiversion、NDU后台优化或x86指令搜索扩展成跨平台支持。

| Host | C编译器 | 两个实际优化级 | 实际foreign_calls | 负例 |
|---|---|---|---:|---|
| Linux x86_64 | gcc | -O0, -O2 | 362 | 1运行负例+3类型负例均拒绝 |
| Windows x86_64 | msvc | /Od, /O2 | 362 | 1运行负例+3类型负例均拒绝 |
| Linux aarch64 | clang | -O0, -O2 | 362 | 1运行负例+3类型负例均拒绝 |
| Linux x86_64 | clang | -O0, -O2 | 362 | 1运行负例+3类型负例均拒绝 |
| Darwin aarch64 | clang | -O0, -O2 | 362 | 1运行负例+3类型负例均拒绝 |
| Windows x86_64 | clang | -O0, -O2 | 362 | 1运行负例+3类型负例均拒绝 |
| Linux aarch64 | gcc | -O0, -O2 | 362 | 1运行负例+3类型负例均拒绝 |

共7个job、14次正向native执行，每次181 foreign_calls，合计2534次调用；28项预期负例拒绝。ZIP digest与metadata逐一匹配，报告与ZIP内成员逐字节一致。

保留的GitHub workflow-run/jobs/artifacts API记录逐一绑定sourcehead `e1473a42f6b9a50a42f8cca8fadff47e709cf4d4`、run40551242969及ZIP digest。Git commit API记录与独立读取的本地Git tree均为 `f0625fe5579fcfd0c712cd37da88455c1ae39fa0`，证实e147与c430源码树完全一致。仍严格将本地资格验证归于c430、host CI归于e147；native-host.v2报告本身没有Git commit字段。

有限profile包含12种scalar、36种ordinary-record形状、12种pointer形状、嵌套数组及整数/浮点register-spill调用。packed records、bitfields、varargs、外部对象生命周期安全不在此matrix内；不声称物理板卡、MMIO/DMA/IRQ或GPU验证。

每个上传ZIP只有native-host.json、native-host-setup.log、native-host-adapter-tests.log三成员。它们是完整下载并校验的CI上传制品，但不能称为七个平台native对象或可执行字节的归档。

## 文件和核验范围

机器可读账本保存每个gate证据路径及重新计算的SHA-256，并逐个重新哈希NDU与x86保留的native产物。它是对现有证据的独立计数/完整性审阅，未重新执行这些工作负载。

- run1汇总：`/workspace/scratch/bf7d454bbc83/hia-final-qualification/qualification.json`
- run2汇总：`/workspace/scratch/bf7d454bbc83/hia-final-qualification-run2/qualification.json`（文件完成前，状态保持pending）。
- 机器可读账本：`/workspace/scratch/bf7d454bbc83/hia-evidence-audit/evidence-ledger.json`

正式结论必须保留：`six_stages_closed=false`、`whole_language_soundness_proved=false`、`global_optimality_established=false`、`scientific_incremental_advantage_established=false`。完整运行通过只关闭当前声明的有限机制gate。
