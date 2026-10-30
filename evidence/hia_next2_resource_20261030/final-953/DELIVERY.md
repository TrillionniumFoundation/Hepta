# P1/P2 交付摘要：有限 Rust 调用的显式停止清理

## 结论与当前状态

最终实现提交为 `953fa62dee5aa563551d57b1374ab95b6d548b45`，tree 为 `aa0683509a02ca97e4e0c1dd723e4047f50d81b3`。本轮闭合了一个具体有限缺口：此前已准入的私有 byte-DAG 调用在陷阱或预算停止时只保留资源账本，现在可显式选择一个执行前预留额度、在同一 Machine 内完成逻辑释放的清理阶段。**P1 完整资源证明链和 P2 全范围 Rust 权威仍未全部闭合。**

当前已完成该最终提交上的实际正确性重跑、纯字节目录读回、完整归档及独立 archive 读回。最终包的 43 个成员、17,526,658 字节全部核验通过。3533 的记录保留为历史执行与额外成本，不给 953 授予资格。

## 实现与已闭合的有限问题

资源实现提交为 `39ae13638170fad2fe3234f8e7ca989997ef69c4`，已经进入最终集成提交。新增 `raw-byte-dag-finite-heap-cleanup-v1`，复用既有全模块 Rust owned verifier、有限 DAG 与 live-payload 分析、私有 admitted snapshot 和原 v4 Machine，没有另建 Core。

公开入口及结果仍限于标量；owner 全部属于该私有调用。对 primitive v7/v8 的受限模块，先由静态结构得到 `B = A + T × (1 + P)`：A 是 allocator-interaction 上界，T 是 VM-tick 上界，P 是全模块最大 borrowed-formal 数。journal 在语言执行前预留，B 超过调用方额度或固定 32,768 上限时先拒绝。有限 heap 准入并不自动赋予 cleanup 准入。

停止后先保留原始状态、错误、步数和资源账本，再审查完整实际 owner/loan 库存。清理按 child loan、parent loan、owner 的依赖次序发生；call-formal witness 单独核算，不冒充源代码的 loan.end。失败可选分配得到的空 owner 仍被消费，但不虚增实际 free。正常返回必须原本已经干净，清理阶段不修复泄漏的正常返回。清理失败、库存矛盾或额度不足不能被报告为完成。

这一过程在仍存活的同一 ByteMemory 上实际执行，不以宿主进程退出替代语言逻辑清理。旧 profile 和默认/source/nominal/native 权威保持原状。Python 只核对受绑定的 wire、账本和 journal；Rust 准入与 Machine 不依赖 Python 语义模块。

## 最终提交上的实际验证

| 项目 | 实际结果 | 分母与范围 |
| --- | ---: | --- |
| Python cleanup class | 20/20 | 0 failure/error/skip |
| Rust crate | 121/121；21 个 footer | 0 failure/ignored/filtered/measured |
| 完整差分与清理观察 | 260 | 183 returned、48 budget_exceeded、29 trapped |
| 停止时非零 live payload | 58 | 全部在同一 Machine 的清理后账本归零 |
| 停止时含 call-formal witness | 18 | 单独核对 witness 与本地 loan 计数 |
| 直接 Rust 进程 | 314 | 271 rc0、43 预期 rc1；失败控制完整保留 |
| 显式 refusal 记录 | 37 | 属于上述 314 进程，不能再次相加 |
| 隔离 Python 子进程 | 2 | 验证无 Python 语义导入时的实际接纳与拒绝；其嵌套 Rust 调用不充入 314 |

260 条观察沿用原 253 条矩阵并增加 7 条观察，属于同一 authored corpus 的继续验证，不是新 holdout。53 条历史非零 payload 停止属于被继续覆盖的旧矩阵；本次的 58 条是最终提交上实际重新执行所得。不能将两个提交的相同案例相加成更多独立案例。

6,907 个 tracked 文件在运行前、两个阶段后、最终共四次 raw-source 记录一致；工具、PLAN 和 launcher 前后也一致。现有 Cargo target 被复用，locked/offline 构建和实际进程重新执行；**这不是 clean rebuild，也不是性能试验**。

## 精确身份

| 对象 | SHA-256 / 身份 |
| --- | --- |
| 最终 implementation | `953fa62dee5aa563551d57b1374ab95b6d548b45` |
| Canonical contract | `3ff0362f995c8341ab75fa32c19cc6bb9fc5d1bc1bbe932ab00d45409ef62faa` |
| 新 PLAN | `3436749b6b6c94f54afa2195de9df0b3d508702c2d68c8dcaab17f25d531f091` |
| 新执行 RECEIPT | `40e56ead84bdf44795952967ede6a683a385e29c1428b6396a48ddef3fb5ed28` |
| 新 actual corpus，8,560,411 B | `955db11d94adf41f59effcbe9d2ec8be7af6f711100ceede7df3b4e78962bba9` |
| 实际执行 binary，4,625,464 B | `39fb7af2de0178997ffbe5b13c0e54302c0453accdf6ea3e421fc9b4427e4af7` |
| 历史 3533 archive，4,294,484 B | `cd6ad1181899e7be44d478557cb6101248d6995d4b9034cc5d4833553c481f59` |
| 历史 3533 manifest | `29a6a4808cef3fb36756a66df55e98c7d0a4722b74082753a1a7f2a87a4d42ce` |

原始最终记录位于 [run/RECEIPT.json](sandbox:/workspace/scratch/f0c12f106c89/p1-p2-scoped-cleanup-final-launches-20261030/run/RECEIPT.json)、[actual.json](sandbox:/workspace/scratch/f0c12f106c89/p1-p2-scoped-cleanup-final-launches-20261030/run/focused/raw/actual.json) 和 [SUMMARY.json](sandbox:/workspace/scratch/f0c12f106c89/p1-p2-scoped-cleanup-final-launches-20261030/SUMMARY.json)。这份摘要先在模型窗口内依据小型元数据准备；模型窗口释放后，又实际读回完整 corpus 和压缩归档。

## 实际成本与重叠

| 区间 | 秒 | 如何使用 |
| --- | ---: | --- |
| 953 外层进程区间 | 55.408975566 | 包含 launcher 进程寿命及外层记录/身份读取；最终外层 receipt 写入和 tool/shell 开销在外 |
| 953 launcher 内区间 | 55.308506738 | 嵌套于外层，包括 pre/postflight、stages 与文件 inventory |
| 953 Python stage | 49.170802457 | 嵌套于 launcher；不能再加到外层 |
| 953 Rust stage | 2.329417820 | 嵌套于 launcher；不能再加到外层 |
| 953 prepare | 0.179594554 | 是外层运行前的单独区间，不含测试执行 |
| 历史 3533 外层 | 55.307373912 | 是另一轮真实执行，完整保留；不替代本轮执行 |
| 六次独立开发命令的已测区间合计 | 154.078073477 | 包含重复测试范围；不是更多独立测试，也不是全开发总成本 |

完整人工、Agent 编写与审查成本仍为 `unknown/null`，没有按零计。3533 的归档、读回及其 FIFO 修复/负例成本分别保留在历史包和外层记录中；953 后续离线工作已实际完成：目录读回 0.473891212 秒、归档构造 0.577577569 秒、归档读回 0.541413471 秒；它们位于同一个 1.596571343 秒的离线外层区间，不能再与该区间相加。独立同行 archive 读回另耗 0.729988084 秒，内部 0.675090862 秒同样嵌套。三步均为首次实际执行 rc0/0stderr；编排脚本之前的纯准备修订已保留，没有假造执行失败。

## 尚未闭合的严格条件

| 阶段 | 本轮有限条件已闭合 | 仍未闭合 |
| --- | --- | --- |
| P1 资源证明链 | 对获准的私有 byte-DAG，执行前预留并在语言停止后显式清理实际逻辑库存，保留原 prefix 与精确 journal；反例与拒绝路径进入回归 | source→Core→native 的完整 refinement；一般循环、递归、owned chain、并发、异步取消、任意 foreign 资源和析构/回调；RSS/CPU/栈与宿主失败保证 |
| P2 Rust 权威 | 新 profile 的实际准入与执行沿独立 Rust checker/Machine，Python 语义模块被阻断时仍可接纳/拒绝 | 默认、source、nominal、native 的全范围权威切换；完整语言 checker/Machine soundness 与编译链证明 |

32,768 是附加逻辑准入上限，不是宿主时间、内存或所有有限程序都获准的保证。journal 预留不涵盖之后的 JSON/report 构造、宿主 allocator panic/OOM、进程死亡、OS 回收或被中断调用方的继续执行。有限差分及 wire 回读不认证恶意 producer，也不构成通用恢复定理。没有新增超越 Rust 性能、零成本清理或一般 C/C++ 安全迁移主张。

## 已完成的离线证据与持久交付

最终 `evidence.tar.xz` 为 **2,095,396 B**，SHA-256 为 `c1a84262caf2babcf7625982e59cb2e3fda46f37a820123048cbe164a351a949`；`MANIFEST.json` 的 SHA-256 为 `85c3d67347f3b4f755f73798e5fd5b244bca2af546dd1d3194af5af6a84a51e1`。全部 43 个成员、17,526,658 B 经同次 bounded/no-follow/nonblocking 读取、XZ 内存上限、tar/逐成员哈希及观察一致性校验通过。verifier 不提取归档、不执行 Core、native、模型或归档里的代码。

完整交付包括两个并列目录：`final-953/` 保存本目录全部文件；`history-3533/` 保存原 3533 evidence 目录全部文件。历史包 107 个成员、44,434,580 B 已包含本轮完整 scoped-cleanup development、六次开发命令原始输出、精确旧/新 Rust executable、3533 的 raw/launches 及其独立读回记录，因此不再复制完整工作目录。两个 archive、manifest 和分母各自保持，历史记录不升级为最终源码资格。更早的 `6f97deb...` 开发失败证据仍沿已发布 Git 提交引用，不虚构为本轮执行。

最终包可迁移后独立执行：

```sh
python -B verify_archive.py evidence.tar.xz MANIFEST.json 85c3d67347f3b4f755f73798e5fd5b244bca2af546dd1d3194af5af6a84a51e1
```

使用已审查的档外 verifier；不要执行归档成员。该命令的同源证据读回已经实际成功，同事又独立执行并确认成功。`independent-peer/` 保留同行的精确脚本、原始 stdout/stderr 和实际成本。`POST_MODEL_EXECUTIONS.json` 与三个 stage 目录保留本次离线动作；旧准备摘要另存，不覆盖执行证据。所有原始执行目录仍保留。
