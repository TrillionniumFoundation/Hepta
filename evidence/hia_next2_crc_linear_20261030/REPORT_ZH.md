# P4/P5：CRC 线性候选的真实结果与下一步判断

## 结论

本轮闭合了“只有旧候选、没有真正不同的计算结构”和“折叠事件没有可用循环计时”两个实际实现缺口。新的 GF(2) 候选经过现有安全门后真实执行，部分输入的原生折叠循环变快；但 **18 组新候选的完整 host 对照、6 个 dispatch 对最强固定池的完整 host 对比全部为负，完整冷成本门为 false**。因此不能把本轮说成 P4 已取得净收益，更不能说 P5/NDU 已取得增量价值。[F1][F2]

本轮唯一正式源码是 `953fa62dee5aa563551d57b1374ab95b6d548b45`，tree `aa0683509a02ca97e4e0c1dd723e4047f50d81b3`。协议为 `d7fa8f5e580803d4a27b56d66f53b3fb04443527329f01c3a80cb54eb571e99d`；外层 launcher 为 `5737afdf1745afb4962442cb594ed6163710d4dbb49e241b52265e162862914b`。执行期间源码、工具身份前后一致，资源释放完整，无运行错误、重试、删样或异常值排除。[F1][F3]

## 已闭合的实现 blocker

| 问题 | 本轮实际改变 | 证明和验证的范围 |
| --- | --- | --- |
| 旧多项式守卫仍以原串行八步计算为主 | 新增 `linear_ieee`、`linear_castagnoli`、`linear_dual`：用八个固定多项式 basis contribution 和平衡 XOR 组合一个字节步；非目标多项式走完整原 fallback | 原 captured Core 到 baseline 的有界桥、baseline 到候选的全 u32/first-trap TV、实际 emitted LLVM 检查和 native differential；不是一般 C 源语义或机器码精化证明 |
| 初版 dual 148 operations 超过已有 selected-LLVM 128-op 门 | 两个 guard 向一个共享 fast block 传入 basis，使 dual 降至 105 operations / 4 blocks | 128-op 门不变，6 个候选完整入池；旧 `2f7052c` 的真实失败及先前 320 个已完成 native differential 保留 |
| 原 mode 1 `xor_fold` 结果没有 `kernel_ns` | 显式新 profile `hepta.hia.finite-u32-timed-xor-fold-context.v1` / mode 3；八臂与参考缓存 priming 均用新 mode | 旧 mode 0/1 wire 与 result 保持；map-repeat mode 2 保持；两个 opt-in 互斥。真实计时、byte256拒绝、trap 前缀、异常 timer 拒绝通过 |
| 原生记录写入失败可能丢掉已经获得的 prefix 计数和成本 | 先登记实际 prefix、已加载项与未知计量，再尝试持久化；写失败保留有界原始观测并置失败 | 已有故障测试覆盖；不以 0 或 outer wall 冒充未知循环时间 |
| 只检查内层 deadline 可能遗漏最终收尾 | 内层保存/关闭/身份检查计费，外层完整启动至退出重新计算 300 秒门；失败内层不能被纯成本函数升格 | 实际外层 29.117586164 秒，执行资格通过；经济收益独立为 false |

上述 timer 修复源 `1873755` 的 90 项 focused tests 全过且 0 skip；同源 fresh 六候选正确性资格完成 48 个原 C controls、384 个准备 native differential、18 个 mode 3 请求 / 162 calls。随后正式试验在整合 `953fa62dee5aa563551d57b1374ab95b6d548b45` 上重新完成自己的必要准备，未把开发资格当作免付成本的执行权限。[D1][Q1][F1]

旧 `3533b95c` 只冻结了原计划；读取真实旧 7e 事件时发现计时接口缺陷，正式经济执行尚未开始。其旧协议 `19b46a…` 和旧 launcher/PLAN 原字节仍保留；新的测量契约单独修订，候选、输入、调用数、寿命和 300 秒预算均未改变。已有 2f 真失败和此前开发测试失败不是被新结果覆盖。[D2][P1]

## 真实分母与计时边界

正式试验：2 phases × 2 repeats × 3 workloads × 8 arms = **96 个完整观测**；**276 contexts、1,536 requests、393,216 byte-update calls**。另有 **48 原 C reference controls、384 准备阶段 native differential cases**。后两项不是额外性能样本，也不是 AI 模型成功数。实际 NDU decisions = **0**。[F1]

每个完整观测交付 4,096 bytes，分为 16 个 256-byte 请求，request seed 保持 `0xffffffff`。数据来自旧 v3 已冻结的两个 SHAKE256 synthetic streams，32 个块互异且非零；本轮不是生产 trace。fresh-child 每请求一个 child，其余臂每 16 请求一个 child。所有候选均真实加载并执行，参考缓存只复用纯 oracle 结果，不复用 native 结果、资格或 nonce。[P1][F1]

`kernel_ns` 是 **native fold loop，包括输入加载、间接调用、滚动校验和与循环开销**。它嵌套于 native outer；native outer 又嵌套于 full arm host。不能把下面各列相加；也不能把 `kernel_ns` 称为纯 LLVM body、单条汇编指令或整个文件应用的速度。[S1][F1]

| Arm（每项 12 observations / 49,152 calls） | Full arm host 合计 ms | Native outer 合计 ms | Fold loop 合计 ms | Trace preparation 合计 ms |
| --- | ---: | ---: | ---: | ---: |
| `fresh_child_baseline` | 2703.550571 | 2470.556973 | 0.674421 | 161.234313 |
| `coalesced_baseline` | 266.826623 | 162.302823 | 0.465092 | 28.474935 |
| `coalesced_ieee_only` | 204.279362 | 161.354854 | 0.591931 | 28.711013 |
| `coalesced_castagnoli_only` | 201.611589 | 159.208223 | 0.620997 | 28.736866 |
| `coalesced_linear_ieee_only` | 202.038949 | 160.244102 | 0.491887 | 27.314337 |
| `coalesced_linear_castagnoli_only` | 206.835792 | 162.129020 | 0.411979 | 30.106795 |
| `coalesced_linear_dual` | 206.451391 | 161.332981 | 0.296141 | 30.273938 |
| `coalesced_poly_dispatch` | 212.328707 | 164.333043 | 0.361386 | 33.531600 |

这些小请求的大部分时间位于折叠循环外。以 `coalesced_linear_dual` 为例，12 次共 49,152 byte calls 的 loop 合计仅 0.296141ms，而完整 host 为 206.451391ms，loop 只占约 0.143%。这只能定位量级差异，不能把未单独测量的余额归因给某一个 Python 函数、文件系统或系统调用。源码显示每个 trace 包含身份/封印重检、输入与 nonce 绑定、子进程/动态加载、输出核验和记录保存；不能在没有新验证的情况下删除这些必要工作。[F1][S1]

## 完整成本

| 项目 | 实际时间 |
| --- | ---: |
| Inner study | 28.909388694s |
| 完整 child outer（主比较计费区间） | 29.117586164s |
| 各 full arm host 之和 | 4.203922984s |
| 完整共同非交付成本 = outer − arm sum | 24.913663180s |
| 三项新增 image 准备分量 | 10.865144990s |
| 包含外部 launcher 自身的观测时间 | 29.259407336s |

内外层和 image 准备均有嵌套，不能重复相加。共同费用包含本轮实际 capture、证明、构建、参考准备、身份检查、清理、分析和证据写入；每个冷比较都扣全额共同费用，没有假设原 baseline 准备免费抵扣。外部 launcher 自身较 child outer 多出的时间、开发资格、历史工具获取、后续归档审计各自保留，不被伪装为本轮内层样本。完整人工成本和全部历史获取成本仍未知；因此“完整冷成本”严格指冻结协议定义的本轮执行成本边界，不表示整个项目历史成本已知。[F1][F2][F3][D1]

## 全部 18 组候选对照

每组以 **三个旧 fixed 候选的最小值** 为旧基线，再减去新候选两次观测的最大值。正号表示新候选在该项较快，负号表示较慢。这个 min/max 包络是预定描述性规则，不是统计置信区间；保留所有波动，没有排除异常值。完整 cold 差再扣 24.913663180s。[P1][F2]

| Phase / workload | 新候选 | Fold loop 差 ns/byte-call | Full host 差 ms | Cold 差 s |
| --- | --- | ---: | ---: | ---: |
| 训练 / IEEE | `linear_ieee` | +1.802979 | -1.102229 | -24.914765409 |
| 训练 / IEEE | `linear_castagnoli` | -2.276123 | -1.560201 | -24.915223381 |
| 训练 / IEEE | `linear_dual` | +1.369141 | -1.824941 | -24.915488121 |
| 训练 / Castagnoli | `linear_ieee` | -2.294678 | -0.397790 | -24.914060970 |
| 训练 / Castagnoli | `linear_castagnoli` | -1.120605 | -0.716151 | -24.914379331 |
| 训练 / Castagnoli | `linear_dual` | +1.522461 | -1.146601 | -24.914809781 |
| 训练 / 交替混合 | `linear_ieee` | +0.760498 | -1.595369 | -24.915258549 |
| 训练 / 交替混合 | `linear_castagnoli` | +0.792480 | -2.818826 | -24.916482006 |
| 训练 / 交替混合 | `linear_dual` | +2.520752 | -2.149676 | -24.915812856 |
| 验证 / IEEE | `linear_ieee` | +1.704834 | -1.029220 | -24.914692400 |
| 验证 / IEEE | `linear_castagnoli` | -8.749023 | -0.726742 | -24.914389922 |
| 验证 / IEEE | `linear_dual` | -4.594482 | -0.923641 | -24.914586821 |
| 验证 / Castagnoli | `linear_ieee` | -2.299805 | -0.637142 | -24.914300322 |
| 验证 / Castagnoli | `linear_castagnoli` | -1.698730 | -0.646916 | -24.914310096 |
| 验证 / Castagnoli | `linear_dual` | +1.538574 | -0.768340 | -24.914431520 |
| 验证 / 交替混合 | `linear_ieee` | -32.289551 | -1.530073 | -24.915193253 |
| 验证 / 交替混合 | `linear_castagnoli` | +0.010254 | -2.522520 | -24.916185700 |
| 验证 / 交替混合 | `linear_dual` | +2.533936 | -2.176274 | -24.915839454 |

因此，局部正差有明确适用域：`linear_ieee` 在 IEEE 两 phase 分别 +1.802979 / +1.704834 ns/byte-call；`linear_dual` 在混合输入分别 +2.520752 / +2.533936 ns/byte-call。但 dual 的 IEEE validation 为负，Castagnoli single 的纯 Castagnoli 保守包络也为负，不能选最低的那一次来宣称全部场景获益。全部 18 项 full host 差仍为负。[F2]

## 全部 6 个 dispatch 对照

这里的固定池包含 **全部六个候选**，包括新 dual，不是只和 baseline 比。差值 = 六个 fixed 与两 repeats 的最小 full host − dispatch 两 repeats 的最大 full host。所有六项在共同准备费之前就已为负。[P1][F2]

| Phase / workload | Dispatch full host 差 ms | Dispatch cold 差 s |
| --- | ---: | ---: |
| 训练 / IEEE | -6.172459 | -24.919835639 |
| 训练 / Castagnoli | -2.025654 | -24.915688834 |
| 训练 / 交替混合 | -1.887880 | -24.915551060 |
| 验证 / IEEE | -1.677077 | -24.915340257 |
| 验证 / Castagnoli | -1.129105 | -24.914792285 |
| 验证 / 交替混合 | -1.989033 | -24.915652213 |

所以本轮 `complete_cost_cold_gate_passed=false`；`qualified=true` 仅表示协议执行、正确性、成本完整性和预算合格，不是正经济收益。[F1][F2]

## 摊销假设为什么没有成立

冻结分析仅在 loop 差为正时计算 `ceil(cost_ns × 4096 / saving_per_4096_bytes_ns)`。例如 mixed dual 的三项新增 image 准备分量对应约 **4.29–4.31×10^9 byte calls**，扣全额共同准备成本对应约 **9.83–9.88×10^9 byte calls**。这不是实测 break-even，也不是确认把相同子进程边界重复足够多次就会赚钱。[F2]

原因具体有四个：第一，分母只取局部 loop 节省，当前 full host 差本身为负；持续复制当前请求结构并不能消掉每次发生的 host 差。第二，现 owner 最多 4,096 个登记 trace、每 trace 最多 65,536 个值，严格上界约 268,435,456 calls，而且 cancelled trace 也消耗登记数；上述十亿量级已经超出同一个已实现 owner 寿命。这里仅做容量算术，不声称该上界工作已执行。第三，生产需求、真实文件分布、I/O、故障率与长时间持有代价尚未测量。第四，两个 fixed repeats 中出现真实波动，不能把纳秒差当作可外推的常数。[S1][F1][F2]

上述关系只是当前 owner 硬限与已观察局部纳秒差的条件算术，不是性能定理，也没有执行容量极限试验。完整 host 差已经为负，不能用这个 loop 比值替代它。

因此下一步不应扩展本轮寿命、增加重复数、筛输入或删除安全检查来追求正数。当前结果应保持终态；另一个任务如有价值，应独立定义实际应用边界与费用，而不是把同一负结果重标成摊销成功。

## P5 / NDU 为什么不能晋级

本任务的多项式在请求前完全可见，两个 single 与 dual 都已公开给 fixed 控制；它没有真实未决的规划问题。当前 0 个 NDU decisions 是“未执行”，不是 NDU 成功或失败样本。此前真实 NDU 的 32/32 决策与同模型 exact DP 相同，也不能据此声称超过同一有限模型的精确最优。新的候选计算结构是 P4 的工作，不能算在 NDU 控制器账上。[P1][F1][H1]

只有出现真实应用中的可测资源耦合与选择，例如多热点竞争有限编译/代码缓存预算、准备成本与实际需求持续时间不同，才值得重新建立策略比较。该问题必须来源于真实执行路径；强 fixed、反馈贪心、轻量规划、exact-DP 以及真实 NDU 应获取相同候选、信息、缓存规则和预算，并计入规划、证明、发布、守卫与失败成本。不能通过隐藏 dual、假设额外 switching penalty 或把 DP 人为削弱来制造控制器价值。任何新的有限预算优势也仍不等于全局最优或生产部署资格。

## 下一项可验证、值得实施的工作（纯静态建议，未执行）

**优先把已证明的纯字节候选接入现有 Filecheck 整文件路径，验证端到端收益能否出现；暂不再为此任务增加 NDU 控制层。** 现仓库已有真实文件 `fread`、4,096-byte host buffer、最多 8-byte packed chunk ABI、C/C++/safe-Rust LTO/PGO references，以及包含读取、packing、load/close 的完整 application 测量。因此无需另造一个弱基线微基准或为了摊销扩大本轮工作量。[S2][S3]

最小实现边界应当如下：

1. 扩展已有 `source_wrapper` 的候选接入，使其能把有 guard 的多 block pure CRC 候选合法嵌入 captured `c_checksum_byte(u32,u8,u32)->u32`，保持 ABI。现 helper 限定一 block baseline；这是一个明确源码缺口。必须对原 captured 八步 loop 与候选完整 guard/fallback 作新的独立 bounded translation，保留 first-trap 和所有 u32 多项式输入；不能只复用原 baseline 的 proof，也不能用生成器替换证明源。[S4]
2. 只替换已验证的纯 `checksum_byte` body。`checksum_chunk` 的 count=0、count>8、`calloc` 失败返回、逐 byte 的顺序、`free` 和 scalar 状态边界必须保留，并检查其他函数未变。尤其不能以栈缓冲或删除分配当作“免费优化”：原程序明确观察 allocation failure，直接删掉会改变契约。对整个新 Core fresh admission，并重新做资源/失败与 native differential。[S2]
3. 复用现有整文件应用和强 C/C++/Rust reference 比较路径，冻结独立新协议。原 Filecheck protocol 已有 65,537-byte training、524,325-byte held-out 及末尾 partial chunk；可把它作为工作量依据，而不是按预期收益不断放大文件。原八 arm 的历史实验不修改。若新增 portable C 线性候选，应把相同算法知识公开给它；不要把算法更换的收益直接命名为语言优越性。[S3]
4. 明确分开 fresh prepare+完整文件 cold 与同一已验证构建的实际文件服务成本；计入实际 source/proof/build、身份、I/O、packing、完整应用进程、监测、清理、失败，以及额外参考编译/PGO成本。固定所有样本后一次执行，无正值也保留。只要当前强 fixed/标准编译器已解决，不增加策略层。

这项工作值得做，是因为当前 loop 有局部信号，且已有整文件路径可减少 tiny trace 的重复子进程边界；它仍然可能得到负结果。当前统计不能证明分配、I/O 或 ABI packing 哪项会成为下一瓶颈。若独立 whole-file gate 仍负，应停止宣称 CRC 收益，转向有明确真实瓶颈与可证明候选的另一应用，而不是继续为负例增加控制器。以上均为静态工程判断，未产生新性能样本、未修改任何冻结源或参数。[F1][S2][S3]

## 证据索引与边界

以下 `raw/...` 是待封装归档内的逻辑路径；原始外置目录仍保持不变。此报告只读取小 JSON 与源码；完整有界归档读回将等模型窗口结束后执行，届时另存真实验证 receipt，不能以本报告替代它。

- [F1] `raw/formal/run/RESULT.json`，SHA256 `fd2ce8e0adbefe160c01ba2fbb79492cf98bbd6b4905f6ab2c9e76bb0e69bbd4`。
- [F2] `raw/formal/OUTER_ECONOMICS.json`，SHA256 `7735a856e4c76de25d34da0350db5adb614d9d116e6554f8e661d352d57957a8`。
- [F3] `raw/formal/EXECUTION.json`，SHA256 `2b16f4d10831ba4f5bdc7aa83e1378cd21328279c80da9ff44ae1183f1d44dc1`。
- [D1] `raw/development/11-timed-fold-final-tests.{json,stdout,stderr}` 与 `12-timed-native-qualification.{json,plan.json,stdout,stderr}`；开发测试并非正式性能样本。
- [D2] `raw/development/PRE_EXECUTION_CONTRACT_REPAIR_1873755.json`、原 `FINAL_PLAN_3533b95c.json` 及两份 launcher。
- [Q1] `raw/qualification-timed-1873755/RESULT.json`，SHA256 `c1c9d095fe5dc1ab61c5946c30c2ab6222f6d6e93d41834e2c887ec6d7cde1e9`。
- [P1] [冻结 CRC 协议](https://github.com/TrillionniumFoundation/Hepta/blob/953fa62dee5aa563551d57b1374ab95b6d548b45/experiments/hia_crc_linear_20261030/PROTOCOL.json) 与 [完整比较实现](https://github.com/TrillionniumFoundation/Hepta/blob/953fa62dee5aa563551d57b1374ab95b6d548b45/tools/qualify_hia_crc_linear_economics.py)。
- [S1] [有界 context、身份和寿命实现](https://github.com/TrillionniumFoundation/Hepta/blob/953fa62dee5aa563551d57b1374ab95b6d548b45/hepta/hia_finite_context.py)。
- [S2] [实际 app driver](https://github.com/TrillionniumFoundation/Hepta/blob/953fa62dee5aa563551d57b1374ab95b6d548b45/examples/hia_filecheck/app_driver.c)、[资源 chunk](https://github.com/TrillionniumFoundation/Hepta/blob/953fa62dee5aa563551d57b1374ab95b6d548b45/examples/hia_filecheck/chunk.c) 与 [范围说明](https://github.com/TrillionniumFoundation/Hepta/blob/953fa62dee5aa563551d57b1374ab95b6d548b45/examples/hia_filecheck/README.md)。
- [S3] [既有整文件 protocol](https://github.com/TrillionniumFoundation/Hepta/blob/953fa62dee5aa563551d57b1374ab95b6d548b45/experiments/hia_filecheck/PROTOCOL_20261028.json) 与 [整文件 qualifier](https://github.com/TrillionniumFoundation/Hepta/blob/953fa62dee5aa563551d57b1374ab95b6d548b45/tools/qualify_hia_filecheck.py)。
- [S4] [原 captured-body bridge 的单 block 限制](https://github.com/TrillionniumFoundation/Hepta/blob/953fa62dee5aa563551d57b1374ab95b6d548b45/hepta/hia_crc_kernel.py)。
- [H1] 前轮 `44e34b7` stb 原始 RESULT 与原独立归档保持历史身份；不把其 NDU 决策移入本轮 0 decisions 分母。
