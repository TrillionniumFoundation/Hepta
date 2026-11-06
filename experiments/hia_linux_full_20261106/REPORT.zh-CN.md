# Linux 整内核 HIA 转换与 NDU 实测报告

## 结论

**冻结配置的完整 Linux 内核已经完成 HIA 转换、重构、构建和启动验证；本轮比较没有建立 NDU 的净性能优势。**

实际覆盖 Linux 6.18.60 的同一份 `x86_64_defconfig + boot overlay + olddefconfig` 配置，包含 **2,958 个目标 C 编译单元、71 个目标汇编单元、3,029 份 HIA 程序和全部 9 个配置模块**。目标 C 旁路回退为 0。随后从保留的 HIA 完整重放，目标 C 前端和目标汇编预处理调用均为 0，重新生成了可启动内核。

12 次校准启动和 160 次预定正式启动全部正确完成，正式数据没有重跑、替换或剔除。动态 NDU、独立同目标 Rust 控制器、普通 MPC 和 greedy 的 **20 次镜像选择全部相同**。动态 NDU 相对 stock 的四阶段 guest 执行时间变化为 **−1.73%**，描述性 95% 区间 **[−18.80%, +19.55%]**；计入完整规划后的交付成本变化为 **+18.16% [ +9.16%, +29.57% ]**。

与同目标 Rust 控制器直接配对时，动态 NDU 的交付成本变化为 **+1.26% [−5.35%, +9.84%]**，没有建立交付性能优势；进程内部 native service 时间则增加 **43.03% [37.81%, 48.61%]**。这些结论只适用于本报告明确记录的整镜像、短任务、冷启动实验。

主要证据：[最终评估](evidence/comparison/EVALUATION.json)、[160 次原始观测](evidence/comparison/HELDOUT_OBSERVATIONS.json)、[独立数值复核](evidence/review/REVIEW.md)、[执行终态](evidence/comparison/RUNTIME_ATTESTATION.json)。

## 1. 实际完成的全量范围

| 项目 | 实际值 |
|---|---|
| Linux 版本 | 6.18.60 |
| 上游提交 | `f45ed76d6791cf72ff1265ee93511175bbbc2f18` |
| 配置 SHA256 | `46aed354c1a2a059b3abffa9bc03524541c5336565d350102f2d450b39551c6c` |
| LLVM | 20.1.8 |
| 目标 C / 汇编单元 | 2,958 / 71 |
| 唯一 HIA 程序 / 活跃源路径 | 3,029 / 3,027 |
| 记录的 compiler invocations | 3,235，含另行分类的宿主工具、探测及预处理 |
| 构建目录中的 `.o` / 配置模块 | 3,089 / 9 |
| 保存的 Kbuild command files | 4,688 |
| 目标 C 回退 | 0 |
| 原始编译配置、O3、Os | 各自独立完整导入、构建与启动成功 |
| HIA 全量 replay | 3,029 个目标单元成功，目标前端调用为 0 |

分母来自完整 compiler ledger 和 Kbuild `.cmd` 闭包；其中包含 compile database 未列出的 4 个生成汇编的 C 调用，也包含 boot、compressed、vDSO 和实际 16/32 位目标单元。HOSTCC 等宿主构建工具有独立记录。

这里的 HIA 转换采用显式的 `hepta.hia.system.v1` 系统方言：C 前端生成模块后，将类型、指令、全局对象、原子操作、属性和调试信息转换为结构化 HIA；解码器仅根据 HIA 重新构造 LLVM 模块，再由 LLVM 后端生成机器码。汇编以显式 token/机器能力表示保留。完整 canonical IR 往返比较只忽略首行 ModuleID，不通过删减指令、调试信息或比对范围获得通过。

这条路径保留 LLVM 语义和后端依赖。replay 的目标代码生成独立于 C 前端；Kbuild、HOSTCC、源依赖及来源核验仍保留 Linux 源树。系统方言承认 Linux 所需的不安全内存和机器操作；本结果没有把 Linux 转变成 safe Core 的内存安全证明。

本次“全量”指上述冻结配置的全部目标构建。Linux 仓库其他架构、其他 Kconfig 组合和未启用的源码不在本次转换覆盖分母内。

证据：[HIA original](evidence/hia-original/RESULT.json)、[O3](evidence/hia-o3/RESULT.json)、[Os](evidence/hia-os/RESULT.json)、[完整 replay](evidence/hia-replay/RESULT.json)。

## 2. 完整构建、镜像和正确性

| 构建 | Kbuild 实际耗时，秒 | bzImage 字节数 | 相对 stock 大小 | 完整构建及启动 |
|---|---:|---:|---:|---|
| Stock | 609.618 | 14,525,440 | 0 | PASS |
| HIA original | 1,334.280 | 14,525,440 | 0 | PASS |
| HIA O3 | 1,438.126 | 15,000,576 | +3.271% | PASS |
| HIA Os | 1,443.077 | 14,001,152 | −3.609% | PASS |
| HIA replay | 683.161 | 14,525,440 | 0 | PASS |

O3、Os、replay 的构建并行发生，上表是各个真实任务的耗时，**不构成隔离条件下的编译速度排名**。HIA import 包含转换、重构和严格往返检查。replay 复用已保存的 HIA；本实验没有另设等价 LLVM IR 缓存基线，因此不将 replay 的时间解释为 HIA 独有优势。

HIA original 与 stock 的 `vmlinux`、`bzImage`、`System.map`、两份配置及全部 9 个 `.ko`，共 **14/14 对最终文件逐字节一致**。replay 的 `vmlinux` 和 `bzImage` 也与 stock 一致。共同 bzImage SHA256：

```text
b904dc56222b7fba9cc261af536c7eb39540264a25e42cbc2204e2cc07ed1ec8
```

因此 stock 和 HIA original 的计时差异不能归因于不同的内核机器代码。模块文件一致性核验没有被当作全部模块的加载或运行测试。

每次完整 HIA 构建通过了 14 项原始启动检查。Stock、original、O3、Os 又分别通过独立 KVM all 资格运行，每份 28/28 样本校验正确。比较源码集成后的 93 项自动测试通过。独立数值复核重新聚合了 160 次启动的 800 个正式测量值，复算 32 组已发表 cycle/utility 统计，256 个精确数值字段全部一致。

证据：[完整产物对等核验](evidence/readiness/HIA_ORIGINAL_ARTIFACT_EQUIVALENCE.json)、[四镜像 KVM 资格](evidence/readiness/KVM_IMAGE_QUALIFICATIONS.json)、[集成测试日志](evidence/readiness/INTEGRATION_TESTS.stderr)、[独立复核结果](evidence/review/REVIEW.json)。

## 3. 比较方法和成本口径

测试采用 Intel Xeon E5-2673 v3 宿主、QEMU 8.2.2/KVM、2 vCPU 和 1 GiB guest 内存。QEMU 绑定宿主 CPU 0、1；guest 工作负载绑定 CPU 0。频率未锁定，宿主核心非独占。没有将测试内核安装为宿主正在运行的内核。

四阶段为系统调用/进程/pipe、匿名内存、tmpfs 文件、Unix socket/loopback TCP。每阶段 1,024 轮；每次启动内有 2 次 warmup 和 5 次正式重复。一次启动的统计量是这 5 次正式测量的中位数。

首先执行 12 次独立 all 校准启动，每镜像 3 次；随后执行 **5 blocks × 4 phases × 8 arms = 160 次独立冷启动**。资格运行不进入校准。每个 phase cell 在首个执行前固定八臂选择和运行参数，按预先固定的随机顺序执行；各臂使用相同 workload seed 和迭代数。模型只读校准数据及已经完成的共同历史。

NDU 是宿主端的完整镜像选择器：在 original、O3、Os 三份已构建镜像之间选择，然后启动一个新 guest。实际调用了固定版本生产 Rust NDU 的偏好更新、递归效用和候选评估入口。独立对照使用同一 Rust 工具链、独立实现同目标整数计算，不读取 NDU 的返回值决定动作。

四阶段 horizon 的全部 81 条路径及 abstain 都进入评估。预测执行时间总预算取同一模型的 original 四阶段路径；20/20 个 cell 都实际排除了超预算候选。公共目标由执行延迟与镜像字节数组成，权重在测前固定。镜像大小不等于运行时 RAM；预测预算不等于真实 deadline 保证。original 对应的原生 `O2` 槽保留 Kbuild 原有逐单元混合 flags，并非强制全内核统一 `-O2`。

本报告的 **net delivery = 实际 QEMU wall + standalone planning wall**。后者包含共享模型/候选构建、请求准备、native 冷进程、输入输出处理和持久记录；独立 Python 数值审计另列。准备费用单独计算。主表先给“已经提供共同历史反馈”的条件，再另列承担全部共享反馈采集的情况。

区间采用预先固定的 5 个完整 block 配对重采样，穷举 5^5 = 3,125 个 resamples。boot 内重复和 20 个 phase cells 均没有被当作独立 block。区间是描述性的，未对多重比较作校正；跨阶段控制器还共享过去历史。

协议与执行源码在任何校准之前冻结于 `0f1d1b53b177b902453ca12c132a9cd45a6948ca`。[协议](COMPARISON_PROTOCOL.json)及[比较驱动](../../tools/qualify_hia_kernel_comparison.py)记录了完整规则。

## 4. 八种方案的整周期结果

以下每行都是五个 block 的“四阶段之和”的均值。guest 时间合计四个工作负载，不含启动；net delivery 包含四次冷启动和规划。负的相对变化代表耗时减少。

| 方案 | Guest 合计，ms | Guest 相对 stock，95% 区间 | Net delivery，s | Net 相对 stock，95% 区间 |
|---|---:|---|---:|---|
| Stock | 62.897 | 基线 | 5.249 | 基线 |
| HIA static/original | 65.167 | +3.61% [−13.91%, +23.29%] | 5.283 | +0.65% [−0.91%, +2.95%] |
| Best fixed（校准后固定 Os） | 63.768 | +1.39% [−18.27%, +20.87%] | 5.281 | +0.62% [−2.85%, +4.91%] |
| Greedy | 56.917 | −9.51% [−20.24%, −0.92%] | 5.354 | +2.00% [−0.70%, +4.76%] |
| Ordinary MPC | 57.431 | −8.69% [−18.85%, +0.48%] | 5.408 | +3.03% [+0.50%, +5.44%] |
| Independent same-objective Rust | 60.329 | −4.08% [−14.97%, +3.37%] | 6.125 | +16.69% [+9.19%, +25.82%] |
| Fixed NDU | 63.734 | +1.33% [−14.05%, +19.04%] | 6.302 | +20.06% [+11.38%, +27.61%] |
| Dynamic NDU | 61.809 | −1.73% [−18.80%, +19.55%] | 6.202 | +18.16% [+9.16%, +29.57%] |

**镜像选择相同性是解释这张表的必要条件。** Greedy、ordinary MPC、independent same-objective、dynamic NDU 在每一个 cell 都选择相同镜像：14 original、4 Os、2 O3；没有 abstain。Fixed NDU 仅一个 cell 不同。Best fixed 始终选择 Os。

所以不能把 greedy 的 guest 区间或 MPC 的公共效用区间单独摘出来，宣称其选型策略优胜：四者实际执行了相同镜像序列和 workload inputs，分别启动的 guest 仍受到重复执行波动、宿主状态和控制器运行的影响。所有观测均保留。

Dynamic NDU 的各阶段 guest ns/op 相对 stock：

| 阶段 | Stock ns/op | Dynamic NDU ns/op | 变化及描述性 95% 区间 |
|---|---:|---:|---|
| Syscall/process/pipe | 8,954.934 | 9,223.323 | +3.00% [−9.80%, +16.91%] |
| Anonymous memory | 5,302.314 | 4,618.667 | −12.89% [−31.34%, +7.08%] |
| Tmpfs files | 19,025.579 | 19,594.964 | +2.99% [−0.18%, +6.55%] |
| Unix/loopback TCP | 14,069.869 | 13,461.585 | −4.32% [−34.15%, +35.67%] |

这里的 op 是该阶段 guest 定义的一轮组合工作，不是单一 syscall 的通用延迟指标。

## 5. NDU 与同目标原生 Rust 的直接比较

两者有独立的实际 native 进程和独立的偏好状态。直接配对复算使用同样五个完整 block；这些区间不是将两个“相对 stock”的区间相减。

| 指标 | Dynamic NDU 相对 independent Rust，95% 区间 |
|---|---|
| Guest 四阶段时间 | +2.45% [−6.68%, +18.86%] |
| QEMU 四次运行 wall | +1.94% [−0.54%, +5.76%] |
| Net delivery | +1.26% [−5.35%, +9.84%] |
| 公共效用 | +1.18% [−8.01%, +8.57%] |
| Native service | +43.03% [+37.81%, +48.61%] |
| Native 冷进程 I/O wall | +31.40% [+26.16%, +36.75%] |
| 完整 standalone planner wall | −2.86% [−28.89%, +35.59%] |

每次决策的实际开销：

| 指标 | Independent Rust | Dynamic NDU |
|---|---:|---:|
| Native service 均值 | 8.850 ms | 12.658 ms |
| Native 冷进程 wall 均值 | 13.546 ms | 17.799 ms |
| 含持久日志的 wrapper，均值 / 中位数 | 190.023 / 47.851 ms | 180.069 / 55.041 ms |
| 完整 planner，均值 / 中位数 | 216.617 / 75.881 ms | 210.414 / 81.163 ms |

完整封装耗时有长尾；均值方向与中位数方向不同。没有删除这些样本，也不把完整封装均值略低当作 NDU 算法优势。`native service` 是原生程序报告的输出前服务时间；它与进程启动、持久日志和外层完整 planner 是不同口径。

原始 NDU state lineage、每次 request/response、全部候选评估和独立算术核验都已保留。这证明本实验实际接入并运行了 NDU；它没有证明 NDU 在本轮选择上优于同目标独立实现。

## 6. 准备成本、反馈与摊销

记录的 stock 准备成本为 748.236 s；HIA static 为 1,505.009 s；独立同目标 Rust 搜索方案为 7,128.682 s；dynamic NDU 为 7,207.253 s。

搜索方案共同准备成本包含 7,066.397 s 的实际多镜像构建时间窗，其中活跃区间并集为 3,836.421 s、间隔为 3,229.976 s。它包含当时的并行和等待情况，不能当作隔离的编译速度或未来部署必需耗时。报告同时保留各任务 Kbuild wall 和 child CPU。

| 条件，四阶段周期 | Stock | Dynamic NDU |
|---|---:|---:|
| 已提供共同历史反馈，仅本臂交付 | 5.249 s | 6.202 s |
| 本臂承担本实验全部共享反馈采集 | 5.249 s | 43.313 s |
| 记录的准备成本按 1,000 周期摊销，已提供反馈 | 5.997 s/周期 | 13.409 s/周期 |

第二行是把本次比较实际采集的共同反馈全部收费的情景，不是声称任何实际部署都必须重复八臂实验。第一行则明确以共同反馈已经提供为条件。

本轮所有备选臂的 net-delivery 点估计均未节省每周期成本，因此注册的摊销模型没有得到相对 stock 的正收益 break-even。这个判断基于记录的任务和成本条件，不是对任意长任务或未来控制器实现的保证。

## 7. 证据与复现

| 内容 | 固定身份 |
|---|---|
| 完整 HIA 编译工具源码 | `a3c3ab3a386253afb7d2856eaf055c52634d9791` |
| 比较执行源码 | `0f1d1b53b177b902453ca12c132a9cd45a6948ca` |
| 生产 NDU 内核输入提交 | `8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d` |
| EVALUATION SHA256 | `27fb22c9cc12b6852efd2515730401c1094c1e90b174e756fde04a103d95b582` |
| HELDOUT_OBSERVATIONS SHA256 | `542948cfcecc8d3328b9d47c2b1bc355d8ac046e5a319a2b0d579c9d2b262481` |
| 唯一正式 campaign durable job | `1a1b222835d-fc05-7c8b`，succeeded / exit 0 / output complete and durable |
| 预定 driver 调用 | 183/183 完成，含校准、注册、20 个 plan、160 个 execute 和 evaluate |

独立复算只需 Python 标准库，不会重新启动内核：

```sh
python3 experiments/hia_linux_full_20261106/evidence/review/review.py \
  --evaluation experiments/hia_linux_full_20261106/evidence/comparison/EVALUATION.json \
  --observations experiments/hia_linux_full_20261106/evidence/comparison/HELDOUT_OBSERVATIONS.json \
  --output /tmp/hia-independent-review-new
```

完整重建使用 [HIA 系统方言工具](../../docs/HIA_SYSTEM.md)、[整内核驱动](../../tools/qualify_hia_linux_full.py)、[基线驱动](../../tools/qualify_hia_linux_baseline.py) 和 [比较说明](../../docs/HIA_KERNEL_COMPARISON.md)。保留的 [spec](evidence/campaign-input/spec.json) 与 [单次 supervisor](evidence/campaign-input/supervise.py) 记录了此次所有实际路径、输入身份及运行顺序。复跑应创建新的输出目录和 campaign identity；已有正式结果不续写、不覆盖。

### 完整 HIA 程序、内核镜像与构建记录

完整实验目录已在配置主机 `desktop` 上封存为：

```text
/data/hepta-hia-linux-full-preserved-20261106-bedaafad8a2f-r1/snapshot-r1/FULL_ROOT.tar.zst
```

归档 **3,138,900,504 bytes（2.923 GiB）**，SHA256：

```text
330579de275dc6f0e094284be9e44920100154ec5e6d721aa225e689f3291335
```

独立流式解压重新核验了全部 **381,736** 个成员和 **10,031,497,950 bytes** 常规文件内容，目录、权限、uid/gid、mtime 和 symlink 同时核验；封存前后原树路径及 metadata 未变。原始目录没有移动或被硬链接替代。

三套实际 HIA store 各保留 **3,029 份程序、3,029 个索引、3,026 份依赖 sidecar**；压缩 HIA 程序文件合计 **632,728,094 bytes**。归档还包含完整 stock/original/O3/Os/replay 构建树、所有模块和镜像、Linux 源归档及展开源码、前述失败尝试、编译记录和全部正式原始日志。

已安装的 LLVM、Rust/Cargo registry 与 QEMU/系统依赖由明确路径和身份清单记录。这个包保存完整实验目录；恢复时仍需清单所列外部依赖，不将它称为无需外部依赖的离线系统镜像。

见 [总清单](evidence/archive/PRESERVATION_MANIFEST.json)、[归档执行结果](evidence/archive/RESULT.json)、[独立文件身份复核](evidence/archive/ARCHIVE_ROOT_OBSERVATION.json) 和 [恢复说明](evidence/archive/RESTORE.md)。

### 完整比较原始证据的单独包

另有只包含校准、正式 campaign、supervisor、input 四个目录的内容去重包：

```text
/data/hepta-hia-linux-full-comparison-export-20261106-bedaafad8a2f-r1/CAMPAIGN_EVIDENCE.cas.tar.gz
```

该包 **21,935,265 bytes**，SHA256 `c00d028b0632e29e8edc0018b362ca2d8155f161d69b60138fb288aaea5a4e6b`。它保留 2,959 个常规文件及 3,459 个路径条目，通过实际内容相等去重为 2,367 个 payload，原始文件总量 142,557,417 bytes，遗漏文件为 0。所有 payload 已解压核对。见 [导出封存记录](evidence/archive/COMPARISON_EXPORT_FINALIZED.json)。

仓库中同时提供未改写的原始 JSON、[压缩数据](evidence/export/)、[精确统计摘要](evidence/export/SUMMARY.json) 和独立复算程序，可以先复查数值，再按需要访问主机上的完整源与镜像归档。

## 8. 结论的适用范围

本实验验证的是上述配置的完整内核转换与完整镜像策略。四类工作负载覆盖了实际系统调用、内存、tmpfs 与本机 socket/TCP 路径；没有测量持久块设备、真实外部网络、多核吞吐、长期稳定性、全套 LTP/KUnit 或所有驱动。

NDU 决策发生在宿主端的冷启动边界，没有进入运行中内核的调度器，也没有测量 livepatch、热切换或状态迁移。每次 guest 的业务工作较短，启动和控制成本在交付时间中占比较大。

因此可以确认：**全配置目标代码的 HIA 转换和重放已经实际完成；原配置机器码保持一致；本轮 NDU 的选择没有超过独立普通控制器，新增控制路径也没有换来可确认的净性能收益。** 本结果不支持宣称 NDU 对 Linux 具有全局性能优势。
