# Hepta HIA P0–P7：已发布实现与执行中断后的状态记录

> **后续恢复结果已确认：** 原 `108762ba` 的 19 个门禁全部实际执行，18 个通过；完整单测 2,424 项通过、零 skip/failure/error。唯一未通过项仍是 `standalone_performance`，状态为 `measurement_inconclusive`。本文下方保留失联时的历史检查点；其中“尚未恢复”等时态不再代表当前状态。后续修复、原始身份和新执行结果见 [当前审查记录](../p0_p7_original_type_followup/README.md)。恢复检查未把旧结果改标为新提交的执行。

**实现已发布；完整 P0–P7 验收仍未完成。本文件记录环境失联前已经读取的结果，不能替代尚未取回的原始终态报告。**

- 实现提交：[108762ba](https://github.com/TrillionniumFoundation/Hepta/commit/108762baaefedde931f4160dbeadb6442fbb824b)。
- Draft PR：[#322](https://github.com/TrillionniumFoundation/Hepta/pull/322)，基线为 `209fa298127adf41b24d128d0291dcb4a0649c73`。
- 实现 tree：`c5f5995586877b8b5c52ec2188377e3f7ebe2f56`。
- 启动时源码快照：`46dede19aacd1efd42fa99bffa38825cc1177f8243d4728f71a6bd2e2027066d`。
- 结构化记录：[checkpoint.json](checkpoint.json)。

## 最后已直接观察到的结果

完整 19 项检查于 2026-10-27 13:54:22 UTC 在冻结的 108 源码上启动。单测外层预算为 3,600 秒，其余各项为 1,800 秒；完整 discovery、内部限制、零跳过要求和性能阈值均保留。

| 已读取的检查 | 实际观察 |
| --- | --- |
| 完整单测 | **2,424 项通过，零跳过、零失败、零错误**；unittest footer 为 2,293.959 秒，外层 gate 为 2,298.442513065 秒 |
| standalone native | passed；29.776267 秒 |
| standalone resources | passed；24.189718 秒 |
| composite resources | passed；7.968323 秒 |
| composite bulk targets | 最后只读到 running；当前状态未知 |
| 完整 19 项终态、最终源码一致性、新性能结果 | 当前无法读取，尚未确认 |

这里是“已观察到前四项通过、第五项开始”，不是一个完整的 4／19 失败结论，也不是 19／19 通过。执行环境访问故障不能说明资格进程已经失败、停止或完成。

2026-10-27 17:38 UTC 后，运行环境返回 exec-server 握手超时及“无可用执行环境”。尝试保存已经完成的关键原始报告也因“no primary turn environment is available”失败。GitHub 重新读取确认实现仍在远端。运行后的本地源码快照、完整报告和新 CPU 样本尚不能重新读取。

**完整原始证据 ZIP 尚未生成、校验或保存。** 已准备的 summary、rootmap、packager 不构成归档完成证据。此 checkpoint 是故障前真实读取记录的转录摘要；未伪造原始日志或为未读取的结果补值。

## 实际落地的改动

### P0：公共语义入口

`python -m hepta hia schema` 直接输出已有 registry。规范区分 primitive v1–v7、composite v1→primitive v6、composite v2→primitive v7；canonical 与 latest 不混用，歧义旧格式要求显式适配器，未知版本拒绝。版本标签本身不充当验证结果。

### P1／P2：资源行为与独立执行

新增 Rust `--owned-run`，先验证整个模块，再在 primitive v1 范围执行 owner、loan、reborrow、CFG、内部调用及内部 Owner 返回。公开入口只接受标量参数与结果；借用返回不支持。Python Core 仍为生产准入权威。

修复两个只读形参接收同一调用方 view 时的作用域身份问题。对一个形参的重借用不再错误阻塞另一个形参，原有权限和父借用规则保持严格；最小反例返回 82、20 步、资源归零。

块内循环 owner 的堆上界分析扩展到 fallible allocation；未支持的跨块／跨调用／borrow 范围继续拒绝。9+4 字节同时存活样例得到 13 字节 payload 上界。删除 LLVM free 的变异实现仍返回正确值，但独立分配器观察到 26 字节未释放并拒绝。该结论不等于通用内存、RSS 或整个语言的资源证明。

独立 HIA 直接接受 typed SSA 程序并经 LLVM 生成原生代码；较高层 Hepta 的 Rust 参考后端有另一套支持范围。本轮没有新增 TypeScript、Python、Go 的完整前端。

### P3／P4：保留真正被编译的源程序

保留优化／PIC 选项的原始顺序，以及影响预处理分支的 C99 `-pedantic-errors`。进一步保留源文件操作数的词法写法和编译 cwd；解析后的绝对路径只用于文件身份，不能替换原始编译参数。

已发布的 [source operand 审计](../c_project_source_operand/README.md) 保存以下五个定义良好输入的实际三方反例：

| 反例 | 修复前：原始／解释器／HIA 原生 | 修复后 |
| --- | --- | --- |
| C 相对文件名 `__has_include(__FILE__)` | 9／8／8 | 9／9／9 |
| C++ 同类文件名 | 9／8／8 | 9／9／9 |
| C 符号链接源文件和相对头文件 | 9／8／8 | 9／9／9 |
| C++ 同类符号链接 | 9／8／8 | 9／9／9 |
| C++ 模板中的文件名长度常量 | 35／169／169 | 35／35／35 |

首次较广回归为 27 项中 24 项通过、3 项失败；它暴露了 helper 日志目录与实际 cwd 不同的问题。修复后三项工具重放 3／3 通过。中间失败与五个最终反例分别保留，没有合成为虚构的一次 27／27。

当前捕获绑定所选 Clang，数据库里的 gcc／g++ 名称不等于原始 GCC／G++ 驱动语义认证。一般指针 provenance、完整 C++ 对象／异常模型和任意工程自动安全转换仍未证明。

### P6：语义上下文与真实实验

语义编辑查询递归补齐已展示 terminator 所需的 SSA 定义，保留 callee 签名、256-op 上限、原子编辑及全模块重验；重复 key 诊断保留受控原因。

真实 v1 实验发现提示未公开 parser 强制的候选集；该运行中断并保留。前瞻性 v2 对四组提示公开相同语言下的同一 typed 候选集，排序不依赖 gold；任务、评分、预算及 parser 接受范围不变。

## 已完成的真实模型实验：没有达到收益标准

本实验实际运行于 **EB 提交 `eb722984c488a721bd6c69d2bd9a69d7c600def1`**。32 个 task cells 加 4 个格式预检，共 36 个请求、36 个响应，32／32 原生控制通过。独立审计在故障前已确认账目一致。

| 模型 | 组 | 正确／任务 | 任务 token |
| --- | --- | ---: | ---: |
| Qwen2.5-Coder 7B Q4_K_M | HIA 完整上下文 | 0／4 | 3,620 |
| Qwen2.5-Coder 7B Q4_K_M | HIA 查询 | 1／4 | 2,063 |
| Qwen2.5-Coder 7B Q4_K_M | Rust 完整上下文 | 0／4 | 1,852 |
| Qwen2.5-Coder 7B Q4_K_M | Rust 查询 | 1／4 | 1,687 |
| Granite 3.3 2B Q8_0 | HIA 完整上下文 | 0／4 | 3,945 |
| Granite 3.3 2B Q8_0 | HIA 查询 | 0／4 | 2,434 |
| Granite 3.3 2B Q8_0 | Rust 完整上下文 | 0／4 | 2,153 |
| Granite 3.3 2B Q8_0 | Rust 查询 | 0／4 | 1,902 |

两个模型的 primary 和 secondary 均为 false。任务 token 不含预检；Qwen 预检 178、含预检总量 9,400，Granite 预检 232、含预检总量 10,666。不同 tokenizer 的 token 不直接代表相同经济成本。

Granite 的六次响应拒绝是 SITE×2、FIELD×3、FIELDS×1，属于编辑位置或字段契约错误，没有候选取值越界，也不是模型安全拒答。四个组合任务在各组重复使用，非 32 个独立任务或独立 holdout；Rust fixture 有有限的三文件组合。该单次候选修复实验未评估有代表性的多文件仓库维护、多轮调试和总开发成本。

EB 到 108 的 HIA Python 文件、Rust tree、模型工具及锁未变；整个 hepta tree 因三个 C/C++ 迁移模块改变而不同。模型结果保留 EB 执行身份。

## 历史失败与范围

- 32ef 的完整 19 项运行：19 项执行、15 项通过；旧单测超时、两个 QEMU 工具身份拒绝和 CPU 测量质量不足保持原记录。后续真实 static QEMU 的 2／2 补充单列。
- 32ef CPU：588 次正确性调用和独立未计时资源观察通过；63 个样本全保留，8／9 组相对 MAD 超过固定 5%，判定为 `measurement_inconclusive`。two_stage 对手写 Rust 的原始时间比 1.040114 是保留的退化；不能用其他有利比值宣称性能超越。
- EB 完整 Python suite：2,411 项、1 error、零 skips／failures。错误在测试把裸 Python 字符串传入 JSON 源文本入口，生产拒绝正确；修复保留 300 个随机值并补足入口契约。
- EB 协议回归 15／15、Rust 测试 49／49、独立 v1 Rust／Python 探针 785／785。它们没有被改标为 108 的执行。
- 发布前 d1c 的 57 项聚焦测试全通过，其完整 tree 和源码快照与 108 相同；实际执行 SHA 仍为 d1c。

## 对照 P0–P7 的剩余验收条件

| 阶段 | 已有进展及未闭合条件 |
| --- | --- |
| P0 | 当前 profile 的 registry／规范／兼容入口补强；全局最终资格仍待取回报告 |
| P1 | 局部堆界、v1 owner／loan 执行及反例修复；通用 typed place、布局、初始化、provenance、并发和取消路径未闭合 |
| P2 | 独立执行与原生差分基础；后续资源 ISA 的独立执行及全 LLVM 语义保持未证明 |
| P3 | 已修复真实构建输入丢失；任意 C 工程、原驱动完整重放与通用指针契约未认证 |
| P4 | 所选对象、模板及 foreign 生命周期有有限证据；任意 C++ 实现迁移和异常 ABI 未认证 |
| P5 | 旧 CPU 计时未资格化，新尝试终态不可读；没有 GPU 执行 |
| P6 | 编辑协议修复已验；真实模型没有达到预设收益标准，健全增量验证与代表性工程收益仍待建立 |
| P7 | 已有 QEMU 范围证据；没有实体板卡 MMIO／IRQ／DMA、长期真实负载和恢复资格 |

## 恢复原始证据的顺序

先恢复原始工作目录，读取 final qualification、launch closing receipt 和源码／工具后置快照；确认写入进程结束，再运行已准备的 summary、rootmap 和 packager。文件位置和已观察到的 SHA 列于 checkpoint.json。

如果原始数据无法恢复，应明确记录不可恢复；重新执行必须使用新的 attempt 身份。源码提交、同 tree 验证、旧模型实验、新 19 项运行和后续证据发布分别保留，不能互相替代。
