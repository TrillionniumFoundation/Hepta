# 冻结组合 0a06ef4：独立结果核对

本次冻结组合完成原预算下的 proof、独立 replay 与全部 composition；强 AOT 的尾部及冷调用标准、NDU 净收益标准仍未关闭。此文只汇总保留证据，不产生新测量。

## 身份与执行

- 实测提交：`0a06ef4f0894681af92b0caefba0704c1278d2cc`。
- 实测 tree：`a5239982f9fd8f08ab3a6e791147fc989e8d9df6`。
- 主 job：`1a1ae149dcf-fc05-5d36`；独立审计 job：`1a1ae3f635c-fc05-5e6d`。两者权威状态均 succeeded、exit 0、输出完整且持久化、terminal publication confirmed。
- 36/36 命令，34/34 资格标志；CORE 613 个 planned / started / finished ID 完全一致，0 failure / error / skip。S3 的 590 个 CORE ID 全部保留，净增 23 个。
- source/tools unchanged，identity_errors 为空；独立核对 0 错误。保持 DENY_ALL，十二项较广生产 refinement obligations 仍未证明。

| 阶段 | 外层 wall（秒） |
| --- | ---: |
| proof | 595.116502644 |
| independent replay | 43.595967989 |
| composition | 2005.257633654 |
| 整序列 | 2670.960663875 |

proof 与 replay 原预算均为 600 秒。整序列包括子阶段，不可再与子阶段相加。

## AOT：中位数通过，尾部与 n=0 冷调用未关闭

保留全部 3348 个请求、70308 个批次、1898316 次调用；两个工作负载、原六个 arm、原长度/seed/调用批量与阈值未变。median ≤1.10、p95 ≤1.20、p99 ≤1.20，比较同一 cell 的两种 Rust baseline。

| gate | 通过 / 总数 |
| --- | ---: |
| median | 372/372 |
| p95 | 371/372 |
| p99 | 340/372 |
| 三项同时通过 | 340/372 |
| 冷首次调用 | 38/48 |
| 内存门槛 | 5680/5680 |
| 全部资源与成本门槛 | 6842/6852 |

32 个 joint 失败中：p99-only 31、p95+p99 1、p95-only 0。10 个 cold 失败全部 n=0，linear 5、affine 5。唯一双失败是 linear / prospective / n=101 / calls=64 / rust_release；median ratio 0.640730，p95 2.226113，p99 8.325879。最大 p99 ratio 47.254753 位于 affine / prospective / n=331 / calls=1 / rust_byte_release。

这里的 p95/p99 是批量延迟。每个 cell 合并三个 seed 的 63 个样本，经验 p99 为最大样本；所有值保留，不以“噪声”豁免失败，也不声称总体尾分布已被证明。

| 资源或成本类别 | 通过 / 总数 |
| --- | ---: |
| cost.build_and_proof | 4/4 |
| cost.cold_first_call | 38/48 |
| cost.estimated_automated | 1116/1116 |
| cost.median_load | 4/4 |
| memory.library_file | 4/4 |
| memory.loader_backing_resident_bytes | 48/48 |
| memory.loader_mapped_bytes | 48/48 |
| memory.peak_requested | 1116/1116 |
| memory.peak_usable | 1116/1116 |
| memory.requested_total | 1116/1116 |
| memory.stack_max_distance | 1116/1116 |
| memory.usable_total | 1116/1116 |

S3→当前的相同 cell 对照为：pass→pass 289、pass→fail 26、fail→pass 51、fail→fail 6。315/372→340/372 是通过 cell 数变化，**不是加速百分比**。完整转换 cell 清单及全部 32+10 个失败 cell 见 SUMMARY.json；共享非独占主机下的两次完整注册观察不构成受控因果速度估计。allocator stack distance 仍不是整个函数的 stack 上界。

## NDU：本次冻结组合仍为 0/3

36 个真实 episode，每个 scenario×policy 三次重复；9 次实际 native invocation 完成。下表单位为毫秒，数值来自本轮服务 wall 中位数。

| scenario | fixed | lightweight | exact DP | native NDU | native / 最佳 control |
| --- | ---: | ---: | ---: | ---: | ---: |
| tiny | 37.740465 | 43.726289 | 38.746358 | 39.043825 | 1.034535× |
| amortized | 140.300471 | 139.742754 | 147.038824 | 153.246003 | 1.096629× |
| invalidate-recover | 121.181635 | 108.780444 | 113.964074 | 133.801081 | 1.230010× |

本轮 fresh bridge inner wall 为 37.015251921 秒，outer wall 为 37.236646032 秒；空 target cache，未宣称机器完全冷。共享 build/training/proof/calibration 为 9.965018836 秒，另有 0.431643231 秒共同 runner remainder。bridge outer-minus-inner 的 0.221394111 秒只给 native 额外计一次。

| policy | 注册规则下的完整 outer solo-campaign 归因（秒） |
| --- | ---: |
| exact_dp | 11.309013613 |
| fixed | 11.283078238 |
| lightweight | 11.299919508 |
| native_ndu | 48.631855777 |

这些是同一次多 policy 实验的替代归因，**不是四次独立 solo 实跑，不能相加**。两个实际外层命令（fresh bridge build 与 NDU qualification）合计 51.333880935 秒，已经包含在本次 composition / sequence wall 中。每 scenario 的三次服务 wall 总和另列在 SUMMARY.json；原协议没有独立的每 scenario 构建/共享成本分摊，因此每 scenario 单独全生命周期成本记为未观测，不能重复分摊同一 bridge 三次。此处没有使用 66d 专项的 build 或 service 成本。历史获取、人力、能耗、长期维护和驻留仍非完整生命周期已知成本。

## GHA 与历史测试边界

exact GitHub head `67da0ab0a51203f6f640c4459bc15bef442885b8` 的末次 API 快照仍有 12 个 queued workflow。106 个 jobs 中 6 个实际 completed/success（Windows 4、macOS AArch64 2），100 个 queued；不能把 queued 算通过。两个 Windows ABI jobs 的 POSIX non-reaping step skipped；两个 macOS jobs 的 Visual Studio 环境 step skipped。逐 job、逐 step 状态保留；完整 profile 的产物验收另见对应 artifact 审计，step success 本身不是该验收。

S3 CORE 的保留不等于全部历史研究测试原样保留。5ee6 是另一实现分支；其 shared-source 文件有 43 个 test，S3/当前为 40 个，共同 40 个 AST 不变；另有 10 个新 structured-source 控制。旧 Raw 动态 subclass 读取语义存在未保留的静态反例。范围与来源详见 HISTORICAL_TEST_SCOPE_AUDIT.json，当前冻结源未被本审计修改。

主要证据：FINAL_AUDIT.json（SHA256 `de6f81fb7fc74b9f17da4bf12db8e3eed561de78cfe1def9a81d5372377b270f`）、TERMINAL_STATUS.json、GITHUB_FINAL_SNAPSHOT.json。父 wall、子 wall 与替代成本模型按层列示，不能混加。
