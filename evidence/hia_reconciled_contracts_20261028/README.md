# HIA 同源契约、资源差分与可验证优化：整合验收

本交付把此前两条 HIA 实现线合入同一源码，并修复了完整回归实际发现的 sealing／文件描述符所有权问题。**声明子集的实现与同源验收已经完成；用户提出的六阶段总体目标仍未全部关闭。** 正式 NDU 经济实验保持原负结果，不将功能测试、有限搜索或重复 CI 换算为性能优势。

## 1. 精确版本与阅读入口

| 项目 | 身份或入口 |
| --- | --- |
| 被验收源码 | `efb210e994c151c1161acfe8d50d5d48716d2755` |
| Git tree | `560cbea19f5cdebdd1659c0408183594e43ed4da` |
| 直接父提交 | `739e84a402a800d51abefc6007118c887db7d91a` |
| 上一整合提交的两个父来源 | `5fead4df11e6157626773ea74c42a59b342f91a6`、`d5a0bf0e42611309cbc6461b1a414b9f8ece254f` |
| 代码评审 | [Draft PR #329](https://github.com/TrillionniumFoundation/Hepta/pull/329) |
| 总体机器可读结论 | [acceptance.json](acceptance.json) |
| 本地完整资格 | [qualification.json](qualification.json) |
| 独立逐项审计 | [final-audit.json](final-audit.json) |
| 组件命令／扩展 profiles | [component-invocation.json](component-invocation.json)、[profile-invocation.json](profile-invocation.json) |
| 七个真实主机 | [host-audit.json](host-audit.json) |
| 实际发布身份与资源关闭复核 | [resource-and-publication-audit.json](resource-and-publication-audit.json) |
| CI 只读审计 | [verified-ci-audit.json](verified-ci-audit.json)、[full-ci-audit.json](full-ci-audit.json) |
| 原始 NDU 负结果与独立复核 | [ndu-result.json](ndu-result.json)、[ndu-independent-audit.json](ndu-independent-audit.json) |
| 归档清单、分片与复核程序 | [raw-evidence-manifest.json](raw-evidence-manifest.json)、[SHA256SUMS](SHA256SUMS)、[verify-evidence.py](verify-evidence.py) |

该证据提交只增加本目录下的数据与复核材料，不改变所验收源码。PR 保持 Draft，没有合并 main。此前 [5fe 完整检查点](https://github.com/TrillionniumFoundation/Hepta/blob/cecbf0c5ba884f13ab5a11b4fd704caf7dc7839e/evidence/hia_v8_native_economics_20261028/README.md) 保留独立身份；其 2,887 项 Python 回归不重标为本版结果。

## 2. 六个阶段的实际关闭范围

| 顺序 | 本次已经落地并有执行证据的部分 | 总目标仍欠缺的证据 |
| --- | --- | --- |
| 1：语义入口收敛 | Canonical Core v8、真实 source lowering、验证器、解释器和 Linux x86-64 LLVM 后端；guarded、ranking、captured C++ profile 入口明确分离；整合版本实际执行 | 全语言的前端／Core／LLVM refinement 定理；更多原生目标的同一资源契约 |
| 2：资源核心与 Rust 差分 | 返回借用 origin、调用者父借用冻结、组合资源的声明子集、失败和预算停止；独立 Rust verifier／VM 拒绝非法输入；C++ scoped/composed 与 owned-state 分别执行 | 任意返回 owner 与 loan 组合、借用记录的一般存储与返回、通用异步取消／异常展开、跨版本活跃栈与 loan 迁移 |
| 3：优化前后行为 | 资源合法性与功能等价分别设门；有限标量子集 fresh Z3 证明、totality、反例复现；unknown／超时不发布；guard 与 fallback 真实执行 | 任意资源程序的全语义等价和生产编译器精化证明 |
| 4：有限动作 NDU | Ranking、recursive、finite 三套原生实现与身份隔离；有限 continuation graph、同预算强对照、实际成本计入 | 正式 48-episode 实验为 0 发布，未证明 NDU 增量价值；不能关闭性能增益条件 |
| 5：C/C++ 与 ABI | 未修改上游函数体的完整 `stb_divide.h` 两配置、七实际主机 Rust 目标；本地另有 HIA LLVM；自建多翻译单元 C++ 资源项目及不同后端 | 大型第三方 C++ 库与任意语言特性的自动迁移、跨全部平台的 C++ 实测、低迁移成本的实测比较 |
| 6：多版本与更低层搜索 | Native 映射身份、固定 owner 的标量版本切换、真实有限队列取消、至多一次卸载与关闭、pending 容量；有限 x86 机器码搜索 | 持续净收益、任意状态兼容与活跃帧迁移；选定 x86 机器码与 LLVM 相同，不构成超越 LLVM 的证据 |

这里的“通过”总是绑定明确 profile、源码、输入域与平台。它不等于全语言绝对安全、普遍超越 Rust 或全局最优。

## 3. 同源完整执行结果

本地一次完整 Python discovery 实际运行 **2980 项，0 failures、0 errors、0 skips**；独立 Rust resource crate **60 项通过**。七个必要 gate 全部通过，包括实际工具与 kernel seals、三种 NDU 身份、Rust、完整 Python 回归及整合 profile 覆盖。

执行前后 **4005 个源码文件与 341 个外部输入身份**保持不变。独立主审状态为 **PASS_WITH_OBSERVATIONS**，逐项检查 **2580 项**，没有 failed checks。审计检查数是对原始材料的核对次数，不是新增测试数。

| 独立执行 | 实际结果 | 原始来源 |
| --- | --- | --- |
| 本地完整回归 | 2980 Python + 60 Rust；七 gate | `same-source/full/` |
| 本地组件 | 10 个命令满足预期，其中默认不支持的 CLI 路径以 exit 2 正确拒绝 | `same-source/components/` |
| 四个扩展 profile | Guarded CLI、captured C++、owned-state、adaptive 各自通过 | `same-source/profiles/` |
| 七实际主机 | 7/7，通过结果与下载字节独立核对 | [run 40655694204](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40655694204) |
| Verified CI | 304 个方法，33 个模块，0 failure/error/skip | [run 40655694241](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40655694241) |
| Full CI release | 50 门；2980 项完整 Python | [run 40655694195](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40655694195) |
| Full CI standalone | 35 门；另一次 2980 项完整 Python | 同一工作流内独立调用 |
| Full CI bounded NDU | 9 门；200 项 focused | 同一工作流内独立调用 |

这些执行存在重复覆盖，分母没有相加。Push 与 PR 事件的重复工作流也没有相加。完整 CI、verified CI、正式 48-episode NDU 经济实验是不同的执行范围。

### 实际发现并修复的失败

父版本 `739e84a` 的本地完整回归是 **2,979 项、1 error、0 failure、0 skip**。错误来自 `upgrade_pilot.execute()` 直接读取当前 Python 没有导出的 `fcntl.F_SEAL_WRITE`。内核真实 sealing gate 当时已经通过；远端 Python 3.11 的成功不能抹掉这个本地兼容错误。

修复让实验执行器复用 `_pin_native_artifact`，要求真实 kernel seal mask、原始文件身份和字节读回。缺少 Python 常量名字时使用 Linux UAPI 数值，仍向内核实际查询并拒绝未封存产物。审查同时发现旧 helper 使用 `sys.exc_info()` 判断是否失败：调用者正在处理另一个异常时，它会误关成功交出的 fd。现在仅在完成所有校验后显式转移所有权，失败路径才由 helper 关闭。

定向验证在一个活跃 `except` 块内删除六个 Python seal 常量名，实际编译并运行 Rust，核对 seal mask 为 15，且继续拒绝返回值看似正确但没有调用 provider 的候选。负例注入未满足的 kernel seal 观察，证明 native child 根本没有启动。**20 项定向验证通过**，随后才冻结本版并执行上面的新一轮完整资格。原失败、开发修复与最终源码证据分别保留。

## 4. 语义与资源：真实前端到原生后端

Core v8 显式保存 `return_origins`。当前函数可返回至多一个 `readbuf`／`mutbuf` 借用并组合标量；被返回借用必须具有允许的来源。跨 CFG 的来源不能悄悄变化，调用者的父借用在返回的子借用结束前保持冻结。本地 owner、错误参数来源、未结束的子借用、错误顺序 drop/move，以及不可达但非法的 helper 都有拒绝覆盖。

实际 CLI 链路使用源文件 `examples/hia_returned_loans/returned_views.hepta`，显式选择 v8：

```bash
python -m hepta hia lower examples/hia_returned_loans/returned_views.hepta \
  --core-schema hepta.hia.program.v8 -o returned-v8.json
python -m hepta hia verify returned-v8.json
python -m hepta hia run returned-v8.json --function probe --arguments '[1,42,true]'
python -m hepta hia build returned-v8.json --clang "$HIA_CLANG" -o returned-v8.so
```

验收另对最后产物进行 sealed native 调用：2 种非空 buffer 大小 × 256 个 byte 值 × 2 个分支，共 **1,024 次**，逐次断言 `value XOR 90`。记录保留执行程序、退出状态和完成计数；没有宣称逐行输出保留了这 1,024 次结果。

返回借用专项包含 **278 个 Python／独立 Rust ledger 观察**：83 正常返回、13 trap、182 budget stop；43 个非法模块在独立 Rust 两种准入路径中实际拒绝，共 86 次。还有 **17,920 次原生成功调用、15 个原生失败策略观察、两个错误结果／漏释放负控制**。

Trap 和预算停止会如实报告仍存活的 owner、loan、bytes 等，不将未执行的展开清理伪造为零。因此，这些记录支持声明失败策略的一致性，不能推导任意异步取消已经安全展开。返回 owned 与 borrowed 混合结果、一般 borrowed record 存储等不支持范围继续稳定拒绝。V8 原生返回借用当前限定 Linux x86-64；AArch64、RV64 的相关新原生入口不会冒充已支持。

## 5. 优化必须同时满足资源、行为与发布条件

资源 verifier 证明的是声明规则内资源使用是否合法。功能保持需要独立依据：有限标量 profile 使用 fresh Z3 公式证明候选与基线结果相同；启用 totality 时还要求声明输入域没有不可接受的 trap。SAT 给出可在解释器复现的反例；unknown、solver 不可用或超时均拒绝。

Guarded 路径通过独立 `optimize-guarded`／`verify-guarded`／`build-guarded` 入口工作，原 ranking `optimize` 契约保留。新 CLI 验收保留三份 fresh proof receipt，每份 30 个 obligation，实际 native 执行 **36 个输入**：24 个属于 fast 输入域、12 个属于 fallback 输入域。标签表示输入域分类，不等于硬件分支追踪；timeout 负控制没有发布提案。

从证明到执行还必须核对具体产物。多版本、owned-state 和 adaptive 的动态加载路径使用已封存的字节快照；首次 probe 前核对导出地址落在同一 fd 的 device/inode 对应的私有可执行映射中。这项映射门的范围不扩张为所有 C/C++ 原生比较或任意 CLI 产物。通过编译不等于可接纳，结果看起来正确也不能跳过对应 profile 的 provider、资源、身份或成本约束。

上述 fresh proof、native 差分和原始字节是不同证据。它们没有被称为 LLVM／Clang／OS 的完整形式化正确性证明。最终安全结论依赖声明语义、验证器、受信任工具链与运行时边界。

## 6. NDU 的作用与正式负结果

整合后明确保留三种不同身份：

| Profile | 上游 pin | 工具链／用途 |
| --- | --- | --- |
| Ranking | `d3c2d760eca5065fc966820379c35c6e8d56e855` | 原独立 ranking bridge |
| Recursive | `2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b` | Rust 1.90；实际递归 NDU API |
| Finite graph | `4b6391e116949af0c7e59776baead67271856bdb` | Rust 1.95；有限 continuation graph |

Builder 核对 clean Git、每个输入 blob、工具字节与输出二进制。新 recursive／finite 构建各保留 11 条实际命令、22 条原始 stdout/stderr，并单独保留真正执行的 bridge ELF。两种协议不靠静默 fallback 混用。完整资格核对 consumer 的实际 binary 路径与外部身份清单一致。

有限 graph 的功能验证运行了真实原生 NDU，并使用具有相同信息的 exact DP 强对照。它证明机制可以接入，不证明 NDU 比简单搜索更有价值。若动作集合与 continuation graph 已经很小，exact DP 本身可能就是足够强且更便宜的方案。

正式经济实验保持冻结源码 **`8b0fd11dde9f13ac784b3579ec9930ae4832784d`**，协议 SHA256：

```text
bdf110209ea714c807948c5dc572636994166ac2bc52eab877bcc5bbdd3d5bc2
```

3 个 workload profile × 2 次重复 × 8 个策略，共 **48 episodes**。每个策略仅摊销自己的 6 个 episodes。每个 episode 的 holdout 为 64M 次实际 native 调用，搜索预算、测量 quorum、证明超时与最大候选测量数事先冻结。

| 策略 | warm 全成本（秒） | cold 全成本（秒） | 候选测量批次 | 发布 |
| --- | ---: | ---: | ---: | ---: |
| 直接基线 | 2.715459131 | 2.715459131 | 0 | 0 |
| 固定 d=3 | 3.865049981 | 3.865049981 | 12 | 0 |
| 固定 d=10 | 3.809161994 | 3.809161994 | 12 | 0 |
| 固定 d=16 | 3.752031558 | 3.752031558 | 12 | 0 |
| 校准选择固定候选 | 4.877475437 | 4.877475437 | 12 | 0 |
| 简单穷举 | 5.663383267 | 5.663383267 | 36 | 0 |
| 强算术递归对照 | 3.631058206 | 3.631058206 | 0 | 0 |
| 原生 NDU | 3.637279312 | 24.873339562 | 0 | 0 |

**48 个 episode 全部完成，0 个候选发布，holdout 全部使用基线。** NDU 的 warm 全成本为 **3.637279312 s**，直接基线为 **2.715459131 s**；相对基线的净收益是 **−0.921820181 s**。将实际 cold 构建计入后，NDU 成本为 **24.873339562 s**，净收益 **−22.157880431 s**。

NDU 和强算术对照各有 6 次 stop；固定策略和穷举的 84 个候选测量批次均未通过 ROI。整个实验保留 276 个测量批次、3,129,000,000 次 timed recurrence 调用与 18,087,936 次重复 oracle 检查。后者是同一 65,536 个输入对在 276 批次中的重复检查，不是 1,800 多万个独立输入。

实验不预支未来收益，不用热代码片段的加速掩盖构建、证明、搜索、校准和切换成本。新源码的 CI bounded search、verified 30-episode loop 与这份 48-episode 原始实验分开；没有挑新的 seed 或重跑来替换负结果。

## 7. C/C++ 迁移与实际 ABI

### 完整真实 C 组件

保留官方 `stb_divide.h` v0.94 全部 **14,507 bytes、433 行、6 个公开函数**，函数体零改动。适配入口仅 58 bytes、两行 include；两种配置分别有 12 个有效声明，包含函数定义与原型解析。定义输入域明确排除除零以及原始 C 的 `INT_MIN / -1`，这些未定义行为从不送入原 C 参考程序。

本地 21,453 个不同输入 × 2 配置 × GCC/Clang × Rust/HIA LLVM 两目标，共 8 条路线，**171,624 组原始／目标配对执行，2,059,488 个函数观察**。另外保留 514,872 个原始 UBSan 函数观察、696 个解释器函数观察和 48 个只在目标执行的 trap 进程。Rust 路线实际观察 allocator counters；HIA LLVM 的对应计数是 `null`，不能解释为测得零分配。

七个真实主机为 Linux x86-64 GCC/Clang、Linux AArch64 GCC/Clang、macOS AArch64 Clang、Windows x86-64 Clang/MSVC。每个主机的跨平台目标是生成的 Rust，各有 42,906 组配对输入、514,872 个函数观察、24 个目标 trap、实际 wrong-code 拒绝以及三个整包迁移拒绝控制。它们不证明 HIA LLVM 在七个平台都执行过。

Windows 显式绑定实际安装的 Visual Studio linker 路径与哈希。该镜像的 MSVC 14.51 help probe 确实返回 1100，只对这个观察到的身份协议做窄接受；真正编译仍必须退出 0。十个 Windows EXE/DLL 已下载并重新核对字节。其他主机的原生文件及所有 TSV 行未全部重新下载，范围如实写在 host audit。

### C++ 组合资源与复用边界

新的 captured 多翻译单元 C++ 项目是**自建 fixture**。两配置分别 437 个输入，原始 C++ 与独立 HIA/direct LLVM 路线共 1,748 个结果观察。每配置 219 个声明记录，139 个有效、80 个编译器隐式记录；原始两处 free 定义保持在迁移资源契约审查内。分配拒绝、构造中途失败、move 前后提前返回、borrowed read、逆序析构与漏 `owner.drop` 负例均有证据。

另一个 scoped C++ fixture 在 verified CI 中使用原始 C++、生成 Rust、生成 C11/GCC、direct LLVM 四条路线，对 1,121 个输入分别核对 ledger；它仍是自建 fixture，不是大型生产 C++ 库。ABI 兼容使库调用成为可能，但原 C/C++ 内部未定义行为、指针与生命周期约束不会因换一个调用语法自动获得内存安全证明。

这些工作支持声明子集的自动翻译与原生互操作，尚未证明任意 C++ 模板、异常、RTTI、多态布局或复杂共享所有权可低成本全自动迁移。没有测量人工时间、token 成本或相对另一迁移工具的成本优势。

## 8. 多版本、取消与资源生命周期

主 multiversion 与 background 两条执行共保留 **3 + 2 次 native retirement、7 个 identity pins 的关闭后证据**，pending 为零。发生无法判定的关闭结果时，记录进入 pending 并继续占用容量，不重试可能已关闭的数字 fd，也不会再次调用已卸载代码。活动 capability 先撤销，实际关闭的每一步保留至多一次尝试。

Owned-state 使用固定的外层 native u64 array owner 与纯标量 HIA ABI，支持声明的 1–65,536 cell 范围。实际验收完成 16 步状态转换；一个请求 1,000,000,000 步的队列实际取消于 **1167086 步已提交前缀**，不重放已完成步。关闭后 native ledger 为 **17 allocations、17 frees、live 0、2 refusals**。三个 native capabilities 均释放且 pending 0；driver 的 14 个导出映射已核对。

Adaptive 的四个 worker 各完成 65,536 次调用。验收共记录 **262,407 次应用 native 调用**，278 次 shadow 调用单列；两个 native capabilities 关闭、pending 0。显式切换和并发调用通过，不推导自动优化已经带来净收益。

有两处必须随结论保留的证据范围观察：

1. 额外后台测量实例保留映射与关闭前 pin，报告没有单独的关闭后快照。它不进入上述 5 次 retirement／7 个 pins 的关闭证据分母。
2. Owned-state／adaptive 的四个 scalar image 保留真实字节、proof 与 source-bound loader gate，但报告没有序列化每个 scalar image 的 mapping。只有 owned driver 的 14-export mapping 单独保留；不能宣称所有 image 的映射收据齐全。

正式旧 NDU 实验还有独立的路径观察：48 次 close 当时路径不存在，96 个 pins 已关闭；随后五个路径以不同 inode 再出现，原因未确定。一次有限、非性能 strace 诊断未复现。证据没有把某一时刻的路径不存在写成永久不存在。

## 9. 如何复核与解释归档

本目录附有分片 XZ tar，合计 **5602 个原始成员**；每个成员重新读回核对 SHA256、大小和 mode 后才分片。分片与可读 JSON 的哈希列于 `SHA256SUMS`。可在空目录下载本目录内容后运行：

```bash
python verify-evidence.py --directory .
```

实际命令、stdout/stderr、源码清单、外部身份、native 产物、proof receipts、失败尝试、只读审计脚本、打包脚本与配置均在原始归档中。路径元数据保留原始执行身份；不要求在另一机器创建同名目录或相信一个 JSON 的自报结果。真实 Git blob、下载成员和 raw native bytes 为进一步复核提供依据。

旧 48-episode NDU 的 473 个必需 payload 加两份固定元数据完整保留；原 676 项文件哈希索引保留，455 项可再生 Cargo cache 排除。旧 builder 当时没有保留成功 Cargo 的原始输出流，这个缺口没有用后来重建日志补造。新的三个 profile 构建证据不重标为旧实验来源。

远端 CI 使用经校验的 HTTP Range 与 ZIP member CRC/SHA 收取必要成员。报告中的整个 ZIP digest 来源于 GitHub API，未宣称对未下载的完整 ZIP 独立计算了 SHA256。有限敏感字符串扫描无匹配不等于任意秘密不存在的形式证明；临时签名下载配置不进入证据。

完整工具链安装包和可再生构建缓存不归档。实际执行的关键 bridge、返回借用 Rust VM、候选 native 与原始源码身份按清单保留。Git 支持的历史源码仍可从公开提交精确重建；清理旧 clean worktree 与两个独立 Cargo cache 的核对记录也保留。

## 10. 结果的工程含义

NDU 对 HIA 有帮助的方式，是在明确动作空间内提出、排序和调整候选。候选必须通过资源、行为、具体产物、状态兼容和成本门，才有发布资格。当前实现已经能把这些边界变成实际拒绝与原始证据。

“更智能”不赋予任意程序全局最优或绝对安全的证明能力。有限动作的最优解也只是给定动作、目标函数与预算下的最优；跨硬件、运行分布和未来负载的最优需要不同证据。当前交付最有价值的结论包括明确的负结果：NDU 尚未证明增量收益，任意 C++ 低成本迁移和通用活跃资源迁移尚未关闭。这些结论与已通过的实现范围同时保留，作为下一阶段工作的真实起点。
