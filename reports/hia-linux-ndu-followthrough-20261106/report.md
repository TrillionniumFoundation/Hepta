# HIA Linux 组件实测与 NDU 整体判断

日期：2026-11-06。实际测试源码：`96d01c50ef1920e5b39c52f62b43ef8746d2c621`；Git tree：`c19d9f42caa7e78c192adf442252c9d220515046`。本报告及原始证据作为后继提交发布；测试身份始终指向上述源码提交。

## 结论

**目前没有证据证明 NDU 在完整 Linux 系统上具有优势。本轮也没有完成 Linux 内核的完整 HIA 重写。** 已实际完成的工作是：修复实验进程清理与显式计算资源扣账，保留原 v1 模型的字节身份，在 Linux 主机上执行 220 项精确源码回归，并运行冻结的四组 HIA／Linux 原生叶子函数对照。

这次原生实验得到明确的局部负结果：在所测主机、输入和调用方式下，保留 Linux 寄存器约定的 HIA 包装版本，相对原始 Linux 软件汇编的配对耗时中位数为 **1.438130 倍，即增加 43.813%**，24 个配对块全部更慢。HIA 裸 C ABI 函数耗时较短，但不满足原 Linux 软件计数函数的特殊寄存器保留契约，不能把这个诊断臂的数字当作合格内核替换的加速。

仓库既有完整有限模型审计同样没有发现 NDU 独占的决策质量收益：动态 NDU、固定偏好 NDU、same-objective 普通规划器和 ordinary MPC 在全部登记状态上的动作及外部完整策略价值相同。两项实验的工作负载、源码和成本边界不同，不能把它们的时间相加或相除当成端到端 Linux 性能。

## 1. 本轮实际实现的改动

### 1.1 进程组退出与原始日志

原 CommandRunner 的超时处理可能在进程组 leader 退出后停止等待，而忽略仍存活、忽略 SIGTERM 并继续写日志的后代。现在以拥有的 Linux process group 为边界观察活进程，执行有界 TERM／KILL 清理，记录是否排空。

即使 leader 返回 0，只要退出时组内仍有活进程，命令也不能成为成功证据。取消会先写终态回执，再重抛原异常。该判据继续传递到 check=False 的 QEMU preflight、guest serial replay、stock evidence 和本次 pilot 消费者，避免下游只看退出码重新把失败升级成 PASS。

新增测试实际 fork 子进程，包含忽略 TERM 的后代、提前退出的 leader、取消及不应被杀死的独立 sentinel。边界是拥有的 process group；没有声称可以约束主动逃出 session/group 的进程，也没有把旧回执补写成曾观察到完整排空。

源码：[runner](https://github.com/TrillionniumFoundation/Hepta/blob/96d01c50ef1920e5b39c52f62b43ef8746d2c621/tools/qualify_hia_linux_baseline.py)、[真实进程测试](https://github.com/TrillionniumFoundation/Hepta/blob/96d01c50ef1920e5b39c52f62b43ef8746d2c621/tests/test_hia_linux_baseline.py)。

### 1.2 显式启用的计算资源扣账

新增 ComputeDebitProfile，把 scenario 身份、校准身份和按剩余 horizon 登记的预测计算纳秒绑定到独立 profile。新入口 compute_plan.plan 在当前与未来决策中，都把预测的计算时间与 workload 时间从 budget／deadline 递推中扣除，并使目标摘要包含新 profile。

真正派发 workload 前，dispatch_after_compute 读取已发生的控制器耗时，校验状态、profile 和剩余资源；资源已经耗尽或不足以容纳登记 workload 时拒绝新服务。最终环境转换只扣一次实际整步耗时，不能再次叠加预测值或计算 subtotal。callback 失败保留 UNKNOWN 与耗时，不自动重发；已经发生的 workload 超时不能被改写成取消或回滚。

这些是有限模型和实际单步计费的正确性修复。预测不等于最坏情况界限；时钟采样到 callback 真正进入之间仍存在调度间隙；没有 native 抢占、硬实时或全系统资源保证。新 profile 尚未完成独立 compute-aware 全策略 oracle、训练校准和实测 native 性能 campaign。不同控制器还须事前满足共同的 native 数值范围，拒绝项不能从分母删除。

源码与协议：[compute_plan.py](https://github.com/TrillionniumFoundation/Hepta/blob/96d01c50ef1920e5b39c52f62b43ef8746d2c621/experiments/hia_ndu_feedback_20261106/compute_plan.py)、[compute_debit.py](https://github.com/TrillionniumFoundation/Hepta/blob/96d01c50ef1920e5b39c52f62b43ef8746d2c621/experiments/hia_ndu_feedback_20261106/compute_debit.py)、[协议](https://github.com/TrillionniumFoundation/Hepta/blob/96d01c50ef1920e5b39c52f62b43ef8746d2c621/benchmarks/hia_ndu_feedback/COMPUTE_DEBIT_PROTOCOL.json)。

### 1.3 保留原模型，而不是修改历史实验身份

第一份组合源码 `02e421c562ab48a96fb45ff19ff2891186d259c1` 上，83 项 Linux 和 96 项 NDU 回归通过；随后扩展的 40 项回归中有 9 项 ERROR。原因是旧 coverage 协议锁定原 model.py 的精确字节；默认语义兼容仍不足以通过该门禁。policy-audit CLI 另有独立的相同模型哈希检查。

修复将 model.py 恢复为原 Git blob `82fbd412342ec8053fca7c35c8b64e37568d5316`，SHA-256：

`56b335e5a7fc205e4ad955faf3eece2a63d43c097f71d5fb4af6d84ee1081b79`

新递推单独放在 compute_plan.py。旧 model.plan 不导入新规划器、不接受新 profile；旧 coverage／POLICY／WITNESS／COMPUTE_PRICE 协议及历史结果保持原样。新的局部 adapter 绑定 compute objective，再复用原 backend response 检查，没有全局 monkeypatch。新增回归直接调用真实的旧 coverage.load_protocol，检查模型字节与新旧入口边界。

两次结果均保留。第一次的局部绿色结果不被用来资格化后来拒绝的组合；修复后的结果来自新提交上的完整重跑。

## 2. 精确提交回归结果

| 组 | 计划 | 执行 | 失败／错误／跳过 |
|---|---:|---:|---|
| Linux baseline、translation、component、system、contract、native pilot parser | 83 | 83 | 0／0／0 |
| NDU compute debit 及原 feedback、campaign、economical、compute price、CI path | 97 | 97 | 0／0／0 |
| 默认模型 coverage、policy audit、policy campaign 扩展 | 40 | 40 | 0／0／0 |
| 合计 | **220** | **220** | **0／0／0** |

每组保留计划、开始和结束的 test ID、源码前后 commit/tree、clean 状态及原始 stdout/stderr。测试与 pilot 的源码前后均为 `96d01c50ef1920e5b39c52f62b43ef8746d2c621`，checkout 保持 clean。

这些是源码契约、实际 native 叶子对象及有限模型回归。它们不等于 220 项 Linux guest 测试，也没有触发全内核构建。

原始回执：[Linux](../../evidence/hia_linux_ndu_followthrough_20261106/results/qualification-r2/linux-regressions.json)、[NDU](../../evidence/hia_linux_ndu_followthrough_20261106/results/qualification-r2/ndu-regressions.json)、[policy 扩展](../../evidence/hia_linux_ndu_followthrough_20261106/results/pilot-launch-r2/ndu-policy-regressions.json)。

## 3. 四组原生实验

### 固定输入、构建与测量条件

- Linux 源：6.18.60，stable commit `f45ed76d6791cf72ff1265ee93511175bbbc2f18` 的 arch/x86/lib/hweight.S。输入 SHA-256：`12cc569b2a6022f9cad115c34139dad681f783be7c0f6c411297f428db08633d`。
- 工具：Clang／LLVM 20.1.8；Z3 包 4.15.4.0，solver 自报 4.15.4。官方包索引及下载包校验记录保留；这不额外声称已验证 APT 签名链。
- 主机：Intel Xeon E5-2673 v3 @ 2.40GHz，Linux 7.0.0-38-generic，glibc 2.39；绑定允许 CPU 47，SMT sibling 为 23。主机共享，schedutil，未锁频、未独占 CPU。
- 每个 trial 有 135,168 个输入，重复 64 次，即 8,650,752 次计时调用。24 个 block 遍历四组的全部排列，每组每个顺序位置出现 6 次；这是固定平衡顺序，不是随机化物理试验。
- 共 96 个计划单元，全部执行并通过；总计 **830,472,192 次计时调用**。全部结果均纳入描述，没有按速度删掉样本或为了获得更快结果重跑。
- 同一个 C driver、运行时函数指针、输入、循环与 sink，无 LTO；墙时使用 CLOCK_MONOTONIC_RAW，另记 process CPU clock。
- profile.config 是本次对象实验的显式 fixture，不是实际解析完成的 Linux .config。host return-thunk 是共同用户态 stub，不能代表内核缓解机制成本。

协议与实现：[NATIVE_PILOT.json](https://github.com/TrillionniumFoundation/Hepta/blob/96d01c50ef1920e5b39c52f62b43ef8746d2c621/benchmarks/hia_linux_kernel/NATIVE_PILOT.json)、[runner](https://github.com/TrillionniumFoundation/Hepta/blob/96d01c50ef1920e5b39c52f62b43ef8746d2c621/tools/qualify_hia_linux_native_pilot.py)、[C driver](https://github.com/TrillionniumFoundation/Hepta/blob/96d01c50ef1920e5b39c52f62b43ef8746d2c621/examples/hia_linux_kernel/native_pilot.c)。

### 结果

单位为每次调用的纳秒；这些数值包含所登记循环和调用方式的成本。

| 实验组 | 完成 | 墙时中位数 ns/call | CPU 时间中位数 ns/call | 相对 stock 的块内配对比值中位数 |
|---|---:|---:|---:|---:|
| Linux 原始软件汇编 | 24/24 | 3.912429 | 3.912034 | 1.000000 |
| HIA + 寄存器保留包装 | 24/24 | 5.629434 | 5.628722 | **1.438130** |
| HIA 裸 C ABI，诊断臂 | 24/24 | 3.479907 | 3.479469 | 0.888511 |
| 硬件 POPCNT，函数调用控制 | 24/24 | 3.057340 | 3.056923 | 0.780532 |

HIA 包装／stock 的 24 个配对比值范围为 **1.398118–1.742967**，24/24 更慢。裸 HIA 的配对耗时约短 11.149%，但两者寄存器保留契约不同，这不是公平内核替换的性能收益。硬件臂包含函数调用，不能当作正常 Linux 内联 POPCNT 热路径的性能。

本轮计时区间墙时加总为 3.350545303 秒。pilot 自身外层墙时为 17.078269253 秒，包含该次 proof、构建、子进程启动、正确性检查、原始日志与 trials；调用它的外层进程回执为 17.565563311 秒。它们是嵌套成本边界，不能相加。工具链环境部署发生在此前，这不是整个研究过程或生产服务的端到端成本。

原始数据：[RESULT.json](../../evidence/hia_linux_ndu_followthrough_20261106/results/native-pilot-r2/RESULT.json)；[全部单元的描述统计](../../evidence/hia_linux_ndu_followthrough_20261106/export-r2/DESCRIPTIVE_SUMMARY.json)。

### 正确性和负控

每个 trial 在计时前比较全部支持的函数与独立 bit-count oracle，并做 64 次 ABI 探针。96 个 trial 合计 **51,904,512 次正确性比较、6,144 次 ABI 探针**，均无错误。输入 digest 与累加输出也由 Python 独立校验。

同一实际 driver 链接一个返回常量 0 的错误 HIA 对象，得到 **270,334 个差异并以退出码 1 拒绝**，没有进入性能计时。这是预期负控，不是被删除的失败测量。

linked disassembly 验证 bridge 实际调用 HIA body、硬件控制实际包含 POPCNT、两个软件 body 不含 POPCNT。HIA 纯 u32 Core 算术与独立 32 位逐位和的 SMT 不等价式为 unsat，覆盖该算术模型的全部 2^32 输入；原回执明确 `backend_or_source_refinement_proved=false`。这不能扩大为 LLVM、机器码、整个 ABI 或 Linux 内核的形式化正确性证明。

实际 HIA 对象为 59 字节；对象回执中的 `kernel_objtool_gate=NOT_RUN`，本 pilot 没有替代真实 Kbuild／objtool 验收。

本 pilot 的 `ndu_calls=0`，所有 kernel_built、kernel_booted、whole_kernel_rewritten、global_comparison_completed、ndu_gain_established 标志均为 false。

## 4. NDU 的既有完整有限模型审计

以下结果来自仓库已经完成的固定历史审计，本轮读取并核对，没有伪称重新执行其 84,960 次 native 调用：[原始完整报告](https://github.com/TrillionniumFoundation/Hepta/blob/040669b6a5b84586108b9ced600396fb89b4f794/reports/hia-ndu-policy-closure-20261106/ndu-policy-closure-report.md)。

| 项目 | 已登记并完成的范围 |
|---|---|
| 初始 profile | 54 |
| profile-state | 10,224 |
| action／observation edges | 18,624 |
| 状态—控制器单元 | 122,688 |
| 实际 native 价值调用 | 84,960 |
| 正常关闭的 native 会话 | 108 |

10,224 是覆盖分母，不是独立统计样本数。动态与固定偏好之间，6,068 个状态的数值偏好发生变化、6,444 个状态的递归候选价值发生变化，但**动作差异和外部完整策略价值差异均为零**。动态 NDU、same-objective 和独立 exact oracle 的候选值也一致；ordinary MPC／fixed-preference NDU 的内部候选值可以不同，动作及外部完整策略价值仍一致。

| 控制器 | 该完整图审计的规划墙时 |
|---|---:|
| ordinary MPC | 5.415711735 s |
| same-objective 普通规划器 | 5.451501308 s |
| dynamic NDU | 20.480627400 s |

动态 NDU 在这次审计中的开销约为 same-objective 的 3.76 倍、ordinary MPC 的 3.78 倍，而没有不同的外部策略价值。这些时间包含实现、原生进程、日志及退出成本，且不是随机化物理速度试验；可以保留在成本账中，不能概括成 NDU 在所有任务上慢多少倍。

逻辑判断是：在相同信息、合法动作、转移和完整搜索下，强普通基线已经复制所观察到的收益。要证明 NDU 的独占优势，需要在共同总预算下提供更好的求解效率、计算分配或真实外部服务结果。本轮新增扣账修复为这种比较补上必要语义，并未产生一个正面的 NDU 性能结果。

## 5. 全 Linux 比较仍然缺少什么

当前用于 Linux 的 HIA kernel object 后端只接纳 total u32 straight-line leaf；memory、allocation、普通 calls、loops 和外部 effects 均不在该已接受 profile 内。当前接入替换的是 __sw_hweight32 的算术 body，其余 Linux 实现及 __sw_hweight64 保留。因此不能形成覆盖整个 Linux 的 HIA 映像。见[后端](https://github.com/TrillionniumFoundation/Hepta/blob/96d01c50ef1920e5b39c52f62b43ef8746d2c621/hepta/hia_linux_kernel.py)和[完整内核协议](https://github.com/TrillionniumFoundation/Hepta/blob/96d01c50ef1920e5b39c52f62b43ef8746d2c621/benchmarks/hia_linux_kernel/PROTOCOL.json)。

| 全内核所需能力或证据 | 本轮状态 |
|---|---|
| GNU C／inline asm／布局／链接段／全配置源清单的完整转换 | 未完成；不能用一个叶子函数代表 |
| 内存、alias、生命周期、per-CPU、分配上下文 | 未资格化 |
| atomics、MMIO、IRQ、SMP、锁、RCU 与 Linux 内存模型 | 未资格化 |
| stock／HIA 真实内核映像及匹配 guest 执行 | 本轮没有构建或启动 |
| 同一真实 workload 的吞吐、p95/p99、错误、CPU、峰值 RSS／能耗 | 未完成全系统比较 |
| 新 compute profile 的独立全策略 oracle 与实测 native campaign | 未执行 |

Linux 的 KUnit／kselftest、动态检查器与 LKMM 解决不同层面的正确性问题，不能由纯算术 proof 或用户态微基准代替。官方资料：[testing overview](https://docs.kernel.org/dev-tools/testing-overview.html)、[LKMM](https://docs.kernel.org/dev-tools/lkmm/index.html)、[LLVM kernel build](https://docs.kernel.org/kbuild/llvm.html)。

仓库已登记的八臂为 linux-stock、hia-static、hia-best-fixed、hia-state-greedy、hia-ordinary-mpc、hia-same-objective、hia-fixed-preference-ndu、hia-dynamic-ndu。它们的完整内核比较仍为 NOT_RUN。本轮四臂对象结果不能填入这些全内核单元。

后续完整比较必须先取得同一冻结配置下的真实覆盖、构建和 guest 资格，再在相同观测、动作权限、工作负载及总预算下比较。Linux 自带自适应能力必须保留；best-fixed 必须从独立开发／训练数据选定；训练、校准、保留测试要分开；错误、超时、native 拒绝和 UNKNOWN 都保留在分母中。计算、IPC、日志、切换和初始化／退出费用必须进入相应成本边界。

在真实 CPU、内存和 I/O 共享预算的任务上，NDU 是否改善 deadline 内完成量、goodput 或尾延迟，仍是待实测的问题。局部函数加速、参数变化或偏好变化本身都不能回答它。

## 6. 证据保存、失败与边界

- 修复后的 220 项回归与 96 项计时均在精确提交上实际执行；没有复用旧测试的绿色结论作为本轮结果。
- 前一组合的 9 项 ERROR、其余已执行项及未启动 timing 的状态完整保留。
- 早期开发执行环境中断导致部分原始本地日志无法取得。恢复分支把那些观察明确标成 transcript summary；本报告的正式结果全部采用之后远程精确提交重跑的原始回执。
- 对已有 #764 全构建工作的有界主机／路径检查未找到可接管的原始运行回执；这不等于全盘证明不存在。本轮没有把该 PR 的 in-progress 描述或通过的源级 CI 改写成全构建成功。
- 封存时重新计算并核对 **248 个文件绑定**，包括实际对象、可执行文件、工具、输入及命令 stdout/stderr；源码仍 clean。
- 原始归档包含 **491 个文件**，176,480 bytes，Git blob 与远端计算一致。归档 SHA-256：

`f8830e1beecbe10220217b8a3681d7185ca055a8e207d437f2b2749a0914b1d5`

[原始归档](../../evidence/hia_linux_ndu_followthrough_20261106/export-r2/raw-evidence.tar.gz)包含原始命令日志、对象、driver、SMT、所有尝试与 SEAL.json。独立[归档元数据](../../evidence/hia_linux_ndu_followthrough_20261106/export-r2/ARCHIVE.json)、[调度脚本](../../evidence/hia_linux_ndu_followthrough_20261106/launchers)和[运行时终态回执](../../evidence/hia_linux_ndu_followthrough_20261106/runtime-statuses.json)一并保留。未安装、替换或激活主机内核；production activation 保持 false，实验授权边界保持 DENY_ALL。
