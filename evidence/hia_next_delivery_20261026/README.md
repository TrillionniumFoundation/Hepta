# Hepta HIA 下一步实现与验收记录

本次交付包括实际编译器改动、独立 HIA v2 资源核心、真实 C++ 模板项目迁移、完整原生与模拟器执行、性能测量修复，以及一次保留全部失败的真实模型试验。

**最终统一资格：10/11 个限定范围门禁通过；1787 项测试，0 跳过、0 失败、0 错误；整个执行期间源码未变。完整六项原始验收仍未全部完成。**

这里的“通过”对应公开、有限的输入与目标范围，不代表整个语言已经证明绝对安全、任意 C++ 已可自动迁移、实体设备已通过验收，或 agent 综合开发成本已经优于 Rust。

## 1. 源码身份与可审查提交

- 最终发布源码：[ce8d2689e72ad4da19e835f21424e77d43154623](https://github.com/TrillionniumFoundation/Hepta/commit/ce8d2689e72ad4da19e835f21424e77d43154623)。
- 本地完整验收提交：`ae0c0f8b467b401e22efdb18ffbb15ab32da0eb9`。
- 两者 Git tree 均为 `b83bcfbecaf380ba6369ce01128389175e59f7f8`，已经远端读回核对。
- 源码快照：`7cd189285e0df22d99989dce1404b7d9c73acfd6a86befe086e3aaa0c205ad75`。
- 编译器树：`56d86bb0fef6fa2c8f0ced9e501f62450c96759fe5c9a98c2e5de78ad807b2c3`。
- [PR #179](https://github.com/TrillionniumFoundation/Hepta/pull/179) 保持 draft；没有以本地执行记录冒充 GitHub Actions 通过。

首轮源码为本地 `83cbd102ce3f94d95e51a94e446f2a0ff639816c` / 远端 `6958abc20a66a597674414700554fdcf9f801845`，tree `bc0459c6a369b7df3b7ce331fe356d4dc4c2b33f`。第二轮为本地 `6899d4761c3a42437ac02b7b5c6c8f8aa153dd79` / 远端 `13cd297b9c7d3d34a7c7bb1af0e7c9794f7521bb`。首轮与最终轮之间只修改性能 harness/共享评估函数、对应测试和规范段落。Core、两套后端和真实模型试验的 90 个绑定文件逐字节未变。

[完整增量补丁](source-from-previous.patch) 可从上轮发布 `f3e8e1d33b502b393d63e0fcaf49d477d9e13fda` 重建最终源码树；[构建路径修复](retention-layout-fix.patch) 从首轮源码重建第二轮树，[采样顺序修复](counterbalance-fix.patch) 从第二轮重建最终树。每条路径都用独立 Git index 实际验证，见 [source-patches.json](source-patches.json)。

## 2. 六项验收状态

| 项目 | 本次实际闭合内容 | 仍未闭合的范围 |
| --- | --- | --- |
| 统一实现线 | v2、规范化 v1、既有源入口和兼容转换共同进入独立 `verify_core`；解释器与 LLVM 消费相同重新验证的 Core | 历史前端所有构造的语义等价、全编译器 refinement 定理 |
| 独立 HIA | 无高层源码即可检查、解释、直接生成原生产物；规范化后保存 exports；篡改、CFG、资源负例有执行记录 | 全输入形式化 soundness 与对恶意同用户进程的隔离证明 |
| 可组合资源 | 名义 record/enum、有限泛型、局部存储借用、错误结果、真实 poll/cancel 实现、线性任务 token；跨构造正反例 | 逃逸借用、递归堆 ADT、带借用的 enum/task、后台线程、channel、抢占取消及 abort 后清理 |
| C/C++ 迁移 | 实际 compile_commands 输入、多 owner 实现、类型/整数模板实例、重载、namespace、跨单元调用；声明处置与链接来源记录 | 任意 STL/class template/RAII/指针或复杂 class ABI、异常展开；迁移人工成本与历史库全覆盖 |
| 性能与硬件 | 最终性能状态 `measurement_inconclusive`；x86-64 原生及独立 AArch64 QEMU；另外保留历史 Cortex-M4 QEMU | 实体板卡、DMA/GPU/设备时序；跨硬件与跨工作负载的 Rust 全面性能结论 |
| agent 收益 | 真实模型完成 29 次生成、27 次任务尝试；所有候选、失败、token 与原生评价保留并独立复算 | 独立任务族、多模型、维护成本、总体开发成本；本次结果没有建立相对 Rust 的综合改善 |

详见 [独立验收审阅](ACCEPTANCE_AUDIT.md)、[机器可读审阅](acceptance-audit.json) 和 [summary.json](summary.json)。独立审阅检查同一批证据，不是新的独立抽样试验。

## 3. 本次实现和实际负例

`hepta.hia.program.v2` 是可独立提交的结构化、带类型与资源约束的智能汇编输入。它把泛型 record/enum 和合作式任务确定性展开为 v1 的 SSA、调用和线性资源操作，然后重新执行原始 Core 检查。`VerifiedProgram` 对象和摘要本身不授予权限；有原始 v2 字节时，消费端重新展开并核对整个规范 Core。`hia normalize` 输出包含公开 exports 的独立程序，重新加载后的解释器和 LLVM 遵守相同边界。

任务具有 pending、running、succeeded、cancelled 状态，poll 和 cancel 都要求存在可检查的函数实现。每个任务带真实零长 owner token，即使 state/result 只含标量，规范化后也不能复制或遗失任务义务。静态规则检查类型、线性消费与借用来源；重复 start、过早 join 等阶段错误使用运行时 guard。取消已完成任务会保留其结果供显式 join。这里没有后台调度，也没有承诺 abort 后执行析构。

组合程序分别从结构化输入和无源码的规范化输入编译，取得 **36 次原生结果观察、16 次成功分配、16 次释放、12 次真实 NULL 拒绝、零存活分配**。另有 8 个静态资源拒绝输入、伪造 origin/Core 控制和 4 次真实 SIGABRT。故意删除全部 free 的 LLVM 负例仍产生全部 18 个正确返回值，但独立地址观察器发现 8 次分配、0 次释放、8 个存活对象并以 91 退出；不会只凭返回值宣布资源正确。

C++ 模板项目包含 2 个真实翻译单元、4 个具体模板实例和 70 行活动声明处置，执行 227 个解释器案例、454 次原生结果观察。旧的 C、多资源 C++ 和标量 class 迁移继续通过 1,102 次原生结果观察及 212 次真实 NULL 拒绝。目标链接中不存在原 C/C++ 实现；原实现仅作为定义域内行为 oracle。超出支持范围的声明会拒绝，不能把捕获 receipt 当作实现。C++ 原实现的未定义域不会被当成可移植语义 oracle。

独立 AArch64 组合补充执行 36 个返回值案例、12 次真实 NULL 拒绝、1 个错误 Core、1 个漏 free 和 4 个非法协议负例。它使用明确限定的 4096 字节单活跃分配运行时，强制失败所需的 harness 预留分配单独计数。它是模拟器证据；本轮实体硬件执行次数为 0。

## 4. 性能结果及测量修复

最终协议为 `hepta.hia.program.perf.v3`，状态 **`measurement_inconclusive`**。本轮性能门禁未通过；以下时间比仅为原始描述，不能作为稳定速度估计。未达到 MAD 上限的组为：constructor_error/llvm = 5.0547%；two_stage/handwritten_rust = 5.2854%。实际保留 63/63 个样本、588 次有限正确性调用。九组 backend/kernel 的最大 relative MAD 为 **5.285%**。以下为配对时间比，HIA 时间除以对应 Rust 时间；小于 1 表示该有限测量中 HIA 用时较少。

| 内核 | HIA / 同源生成 Rust | HIA / 独立手写安全 Rust |
| --- | ---: | ---: |
| `constructor_error` | 0.8302 | 0.8372 |
| `full_lifecycle` | 1.0036 | 1.0104 |
| `two_stage` | 0.5471 | 0.5616 |

验收规则保持原值：7 组配对，MAD ≤ 5%，每个内核时间比 ≤ 1.20，几何平均 ≤ 1.10；所有样本保留，没有剔除、自动重试或择优轮次。两套 Rust 都保留 overflow-checks、panic=abort 等既定安全选项。Clang 20.1.2 和 Rust 1.90 内置 LLVM 20.1.8 的版本差异有完整身份记录；本机是共享主机，CPU affinity 不等于独占硬件。

第二轮 v2 的所有时间比门槛通过，但 `constructor_error` 的 generated Rust/handwritten Rust relative MAD 分别为 6.175%/7.131%，超过 5%，所以其 10/11 门禁和 `measurement_inconclusive` 状态永久保留。对应 process CPU 时间本身也有 6.031%/6.991% 的 MAD；不能把差异简单归因于计时器分辨率或普通 off-CPU 等待。HIA、手写 Rust 和测量 driver 与首轮逐字节相同；CPU 频率、宿主机调度或其他物理原因未被识别。

对第二轮的独立方法审阅找到一个确定的顺序缺口：按“当前旋转后的位置”再次旋转后端，会让手写 Rust 在全部七组 constructor 中固定居中。V3 改用每个内核的原始稳定索引，保持奇数组反转；现在每个内核出现全部六种后端排列，每个后端位于每个位置的次数均为 2 或 3。完整 v3 顺序在运行前冻结，测量和评估共同要求它；旧 v1/v2 顺序作为 v3 记录提交会拒绝。调用次数、warmup、时长门槛、安全选项、MAD/耗时比阈值和全部样本策略不变。只执行一次冻结后的完整 v3 资格；无论最终状态如何，都不能据此断言顺序缺口造成了 v2 的波动。

本次后端修复从分配成功时已成立的长度不变量导出可优化表示，使 LLVM 能删除冗余检查；每次 byte load/store 的检查仍由后端生成，checked overflow 也保留。没有通过任意 `assume`、unchecked 操作或识别基准源码删除安全分支。

首轮 11/11 门禁已经通过，但静态检查发现：将文件直接构建在较长证据目录下，会改变生成 Rust 内嵌路径和循环对齐。首轮对 generated Rust 的 0.565 full_lifecycle 比值因此不能宣传成普遍接近两倍的编译器优势。修复后所有构建使用固定长度 `/tmp` 路径；测量结束才复制二进制，核对测前身份、原文件和副本，并保留路径映射。两个相差 353 字符的保留目录下，实际 Rust 输入路径均为 62 字符；每套基准的 119 个被选函数保持完全相同机器码和地址。整个 ELF/`.text` 的恒定性未作保证，早先三个无关 std 字符串引用字节的差异也原样保留。

[最终性能报告](performance.json)、[首轮性能报告](run1-performance.json)、[第二轮性能报告](run2-performance.json) 和三个完整归档共同保留；本次最终判断使用修正后的协议，不把不同构建/采样策略的数据混合计算。

最终独立 agent 产物复核确认：run2/run3 的 HIA、手写 Rust 和 driver 二进制逐字节相同；生成 Rust 的 119 个测量及 allocation 命名函数具有相同代码与地址，整个 `.text` 的三个其他字节差异完整保留。63 个最终样本及 protocol hash 与预注册顺序相符；全部保留路径和测量身份再次核对。该复核没有重新执行任何工作负载，见 [FINAL_ARTIFACT_REVIEW.md](FINAL_ARTIFACT_REVIEW.md) 和 [final-artifact-review.json](final-artifact-review.json)。

## 5. 真实 agent 试验：综合收益未成立

锁定 Qwen2.5-Coder-1.5B-Instruct Q8_0 GGUF 和 llama.cpp b11669，固定温度 0、seed 0；两次资格探针通过后执行四任务 × 四 arm。16 个正确/错误 native controls 必须实际执行。29 次模型生成中有 27 次任务尝试；全部完整计费记录保留，11 次二次尝试没有恢复成功。

| 编辑方式 | 成功任务 | 尝试数 | 接受但逻辑错误 | 拒绝 | 输入+输出 token | 推理+评价秒 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| HIA 完整 JSON | 1/4 | 7 | 4 | 2 | 6,570 | 178.874 |
| HIA 语义补丁 | 2/4 | 6 | 4 | 0 | 4,406 | 86.364 |
| Rust 完整函数 | 2/4 | 6 | 2 | 2 | 1,285 | 22.432 |
| Rust 语义表达式 | 0/4 | 8 | 0 | 8 | 2,515 | 36.711 |

HIA patch 与 Rust full 都完成 2/4，HIA patch 总 token 为后者 **3.43 倍**，观测推理+评价耗时为 **3.85 倍**。成功任务也不同。因此没有建立成功率与成本的联合改善。Rust semantic 的 8 次拒绝都是返回完整函数而非所要求 JSON；事后提取函数重新加分会改变冻结协议，本记录仍严格计为失败。

在 HIA 内部，patch 相对 full 的累计总 token 少 32.94%，但这个数字包含少一次失败重试；两边只比较第一轮各 4 次请求时，总 token 仅少 9.94%。这两组数字都记录，不能把重试差异全部归因于表示长度。HIA 的若干类型正确候选保留了原业务错误，说明安全准入不能代替需求正确性检查。

这些四个公开单点修复没有覆盖新资源核心、多文件维护或真实迁移工程；一次模型和任务集不能建立通用 agent 优势。人类维护、审阅、工具链开发和总体工程成本未测。下一项研究需要在新冻结任务集上，为两种语言同时控制结构化输出协议和最小反例反馈，再进行独立比较。当前负结果保留，不以新的试验覆盖它。

完整分析见 [AGENT_AUDIT.md](AGENT_AUDIT.md)；[agent-audit.json](agent-audit.json) 的 12 项一致性检查全部通过，含 90 个源码绑定、实际模型/runtime 身份、token ID 数量以及 native artifacts。

## 6. 使用和重现

```sh
python -m hepta hia verify examples/hia_program/cooperative_task.hia
python -m hepta hia run examples/hia_program/cooperative_task.hia --function task_case --arguments '[2]'
python -m hepta hia normalize examples/hia_program/cooperative_task.hia --output /tmp/task-core.hia
python -m hepta hia build /tmp/task-core.hia --clang clang --output /tmp/task-core.so
python -m hepta hia import-cpp-project /absolute/path/to/compile_commands.json --clangxx clang++ --output /tmp/project.hia --report /tmp/project-capture.json
```

完整统一执行命令、固定工具链和源码库存见 [qualification.json](qualification.json) 与归档中的 plan。HIA v2 的规范见 [docs/HIA_PROGRAM.md](../../docs/HIA_PROGRAM.md)，C++ 有限项目配置见 [docs/CPP_PROJECT_HIA.md](../../docs/CPP_PROJECT_HIA.md)。

下列归档全部进行了完整解压读取、逐文件大小/模式/SHA-256 核对。归档内 `MANIFEST.json` 包含完整库存；`verify_bundle.py --verify FILE.tar.xz` 复查而不执行其中的二进制。历史 receipt 中的绝对路径保持原样；解压、重定位或验证摘要不等于在新机器上重新执行资格。独立审阅内的原始相对链接沿用工作目录结构；在仓库根目录展开相应归档后可访问这些完整原始文件，未展开的 GitHub 文件视图不包含归档成员。

| 归档 | 原始文件数 | 原始文件总字节 | 归档 SHA-256 |
| --- | ---: | ---: | --- |
| [unified-run1.tar.xz](unified-run1.tar.xz) | 429 | 13,225,885 | `3527918596e737d3053578995e9bc8657df56d104d4400dc0a838b399170ee3a` |
| [unified-run2.tar.xz](unified-run2.tar.xz) | 429 | 13,227,932 | `569f14031a9320ac6e90379230aa00d0a4a06f6190a7643ed96996c29759cba6` |
| [unified-run3.tar.xz](unified-run3.tar.xz) | 429 | 13,227,933 | `e4a1833876bb15a5ee33b29ba4205d56ccd93e66683544483e0e29cffc5aae02` |
| [agent-qwen-run1.tar.xz](agent-qwen-run1.tar.xz) | 278 | 47,972,408 | `b3fad9cc6ea8e2615936393493f9f2731b872ac25daaff2ff26d31a9cc34fdbd` |
| [target-and-layout-evidence.tar.xz](target-and-layout-evidence.tar.xz) | 160 | 33,957,651 | `39a39225a8641f26832829ad803000cec6ea74489671e978156ff6b67941d92b` |
| [blocker-diagnosis.tar.xz](blocker-diagnosis.tar.xz) | 31 | 360,514 | `f3654ddf6f06447ae1efc0acd2959effbe077d56b4a3e0241651e42d9f04ee4f` |

最终结论保留 `all_requested_blockers_closed=false`、`full_six_deliverables_complete=false`。实体设备条件尚缺；通用资源/复杂 C++ 范围和 agent 总体收益也仍有实际研发与验证工作，不能通过更改报告状态闭合。
