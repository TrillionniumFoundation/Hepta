# P3 / P6 本轮整合审阅草稿

本轮在同一冻结提交 `44e34b7a9ecd6bf1b3ad6093d21bba10d2a18304`、树 `835555fb35dbdcf867724ef7a0bb1a6616270217` 上完成了两项实际验证：stb 的真实函数体变更经既有迁移器重新捕获和翻译，以及有限候选 context 的完整 focused 生命周期回归。P3 资格及严格回读通过；P6 实际执行 46 个测试方法，0 failures、0 errors、0 skips。

这是已经注册的样本和回归集合在新整合源码上的运行。完整源码清单包含 6,685 个受跟踪仓库文件，涵盖代码、文档、fixture 和历史 evidence；该数字不是生产源码文件数。源码原始 Git blob / mode、所记录的工具、启动计划和 launcher 身份均在执行前后保持一致。

## P3：真实 changed-body 上游维护

使用完整、固定来源的 `stb_divide.h` 0.93 与 0.94。两版实际活跃函数体差异为 `stb_div_floor` 和 `stb_mod_eucl`；每个版本的 6 个函数均重新走既有 C 项目捕获、Hepta source、Core 和直接 LLVM 路径，迁移后的函数体没有人工修改。HIA 原生产物不链接原始 C 实现，原始 C 仅在独立对照及 UBSan 进程中执行。

验证范围固定在本次 Linux x86-64 / LP64 环境、32 位 C `int`，以及 `-std=c11 -O2 -DC_INTEGER_DIVISION_TRUNCATES` 配置。共同定义域保守排除了原始旧代码的已知未定义行为。它覆盖 119 组固定输入，不能从这一分母推导任意输入、其他 ABI 或其他宏配置的迁移正确性。

| 观察类别 | 本轮实际分母或结果 |
|---|---:|
| 共同定义域输入对 | 119 |
| 每个版本迁移函数 | 6 |
| 共同域原生函数观察 | 2,856 |
| 共同域 VM 观察 | 1,428 |
| 旧版原始 C UBSan 失败进程 | 4，完整保留 |
| 旧版 HIA 溢出终止进程 | 4，完整保留 |
| successor-only 原生函数观察 | 48 |
| successor-only VM 观察 | 24 |
| witness VM 观察 | 8 |
| HIA invalid-target 原生进程 | 24 |
| HIA invalid-target VM 观察 | 24 |
| 真实 stale/wrong-target 负控制 | 2，按预期拒绝 |

旧版的 4 个 UB 失败和 4 个 HIA overflow 终止都没有被计入跨版本等价成功。successor-only 输入是单列的新版本观察。负控制实际运行过旧目标产物和功能错误的目标产物，分别观察到预期终止和不匹配。

保留数据回读现在将所有 common / witness / invalid VM 记录与相应版本 Core SHA、函数、精确类型的外层参数、内外返回或 trap 状态、结果及非负耗时绑定。当前 VM wire 本身没有独立的参数字段，因此这里没有额外宣称不存在的内层参数签名。源码资格另绑定原始 Git 树、完整声明闭包、文件字节、regular-file 属性和 owner execute 位；隐藏工作区变化不能只凭 `git status` 为空获得提交资格。

该结果提供了真实上游函数体变化后的有限维护证据。仍未证明全输入源语义与机器码 refinement，没有测量 native allocator counters，也没有授予一般 C/C++ 自动重写或维护资格。

## P6：有限 context 生命周期与 oracle 重入修复

修复针对真实的 callback 重入问题：oracle 在生成 reference 时通过同线程可重入锁调用 `prepare_trace`、`run`、`cancel` 或 `close`，可能破坏外层 trace 的配额、nonce 或关闭状态。当前实现先拒绝这些重入状态修改，保持诊断读取可用，并在异常退出时恢复 preparation 状态。

本轮完整 focused 范围包括 context 22 个方法、oracle reference reuse 9 个方法、重入 5 个方法、map-repeat 9 个方法，以及 1 个实际原生 map-repeat 生命周期方法，共 46 个。最终 footer 为：

```text
Ran 46 tests in 21.623s

OK
```

46 是测试方法数，其中同时包含单元控制和实际原生观察；它不是原生调用次数。测试覆盖引用缓存与原生执行的分离、真实生产字节配额、单次 nonce 消费、显式 map-repeat profile、实际重复调用计数、首个 trap、拒绝回放，以及保留 cleanup debt 的失败路径。

## 仍未关闭的 C++ 边界

此前提交 `50c4067399989e7194028576c38c0e783b78cf06` 的 nlohmann/json 3.11.3 → 3.12.0 维护证据仍然有效地记录着：每个版本 17 个实际校准分配故障点中，14 个恢复，3 个触发 foreign `noexcept` 终止；合计 **6 次 SIGABRT 未恢复**。本轮未提供关闭该边界的新证据。

这条 C++ 路径保留外部库并经过生成桥接，不能解释为已经把库实现重写为 Hepta。P3 的标量 C 子组件成功以及 P6 的有限 context 修复，都不能推广为一般 C++ 内存安全、异常恢复、ABI 兼容或大库自动重写完成。

历史 C++ 摘要保留在：

`/workspace/scratch/f0c12f106c89/p3-integrated-50c4067-evidence/SUMMARY.json`

SHA-256：`66f0a1eb737e89e45b2df8b97c1c79efefb5cfa80ffdcfd2655389dd7b5166e0`。

## 成本及证据口径

P3 collector 实际耗时 31.952196561 秒，外层 P3 阶段 32.222954833 秒；P6 阶段 21.735303912 秒；总外层 58.838356302 秒，包含前后身份检查、两阶段、回读及保存。这些数字存在嵌套关系，不能相加。本轮是与另一个 correctness 回归并行的验证窗口，没有性能优势或专用主机统计资格。

完整人工开发、审查和维护成本为 **unknown**，不能记为零，也不能据这次命令耗时声称总体低成本。历史工具获取与开发失败不被伪装成本轮独立命令内的工作。

本轮原始日志完整保留，outer stderr 为零字节，outer capture 没有截断。独立回读逐项检查了 163 个保留文件、10,555,679 字节；P3 内部资格清单有 152 个成员。归档计划另保留原重入复现、P3 开发过程、旧 `ffe4a127` 资格及 readback 修复记录。当前阶段仅生成轻量清单和摘要，尚未压缩、复制 payload 或声称归档验证完成。

| 核心记录 | SHA-256 |
|---|---|
| 当前 P3 `qualification.json` | `e23a911fa50e748b6ee2cf60bcc1d4488061507b79160f44739e438f406d2475` |
| 当前外层 `RECEIPT.json` | `12eca7ede8b4232eef2493b93703d94b7d589e409e63242b2bdc21319c228b92` |
| 独立 `INDEPENDENT_REVIEW.json` | `b4e639c83aa746967d332a289681f05c086fb9a91dc359e802a39fc69ce36ced` |
| 原 `ffe4a127` 资格，字节未变 | `1739deaae7229d6494732a495dac38e195ccef0fbd7586f08b725ebcd51a6f4c` |

当前记录共同位于 `/workspace/scratch/f0c12f106c89/p3-p6-integrated-launches-20261030`；本草稿及轻量清单位于 `/workspace/scratch/f0c12f106c89/p3-p6-integrated-44e34b7-evidence`。环境和工具身份检查仅覆盖所记录的输入，未形成完整操作系统、动态 loader 或全部外部环境的证明。
