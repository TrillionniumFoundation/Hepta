# 真实 HIA 结果缓存：有限 pilot（2026-11-05）

## 本轮交付与结论

已把实际 HIA 编译内核接入动态复用实验：源码先经 `lower_source`、独立 Core 验证、LLVM 发射和 Clang 20 编译；执行器核对并封存 ELF 字节，然后调用其 `calculate`。direct 和 prepare 两条路径都执行 HIA 内部的缓冲区分配、初始化、读取、checked reduction 与释放；缓存只保存该计算的精确结果。没有以 Rust 工作负载替代 HIA。Rust 原始 NDU 仅负责建议。

此次冻结 pilot 完成 **84/84 episodes、1,008 次请求**，包含 **14 次在线原始 NDU 调用**。所有输出通过独立算术校验；**P1 尚未关闭**。累计服务耗时 NDU 193.795 ms，强固定 100.830 ms，本地轻量 95.537 ms，NDU 没有超过所有对照。该结论来自本轮同一源码组合，不使用上一轮 Rust matvec 的结果补齐。小样本、共享主机条件下，不给出显著性或广泛性能结论。

## 冻结身份

| 项目 | 本轮值 |
| --- | --- |
| 执行源码 commit | `b89e881a51eed933e93ee79bdace91bb5433848f` |
| 执行 source tree | `3e8f311e4198aebb2fb54a01980b38eb1295f685` |
| HIA Core SHA-256 | `8503ab457a753f390940dc971e41a4cc42acf71f91eb45b2c9556c72ff8b081c` |
| LLVM SHA-256 | `8c25d2fc62e87d3beb10f21075ca5d363c29e02ff22b816e3bddd6f997ed0cd7` |
| ELF SHA-256 | `3c1bd1f6a16e2f82ec368cd12566253ce1045e7a2127c7f250d62eb873482449` |
| 原始 NDU upstream | `8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d` |
| 原生桥 SHA-256 | `2abca59106c8bacfa5d79f5243996a85d66e0d4b12af430f7c11970643179cce` |
| HIA 工具链 | Ubuntu Clang 20.1.2，直接 LLVM，-O3 -fPIC -shared |
| 原生桥工具链 | Rust 1.95.0，原始已绑定构建回执 |
| 目标 / CPU | x86_64-unknown-linux-gnu / affinity [14] |
| 主机 load average | 约 11.47 / 11.62 / 12.74；共享主机 |

完整 Python 编译器/验证器、原生桥适配器、协议与驱动逐文件散列在 registration 中，运行前后核对一致。编译回执仍保留 `backend_refinement_proved:false`、`whole_language_soundness_proved:false`；实际执行观察与这些一般证明主张分开。

## 执行器与对等条件

每条64字节缓存记录绑定 ELF hash、n、seed、data epoch、generation 和 value。配额为两个记录。失效清除旧 epoch，代次提升清除驻留记录，退役置零，episode 关闭清空 payload arena。非当前 epoch、缺失记录、代码键或值损坏、越配额、关闭后调用均拒绝。HIA 对超过1,048,576的原生入参独立拒绝；高位错误返回不会与注册域内有效和混淆。

七个策略使用相同执行器、同一四对象候选语法、同样的至多八步未来请求信息和冻结训练估计。固定策略从独立训练轨迹的全部11个合法集合中选定 mask=3。local_light 按已公布 epoch 内收益减准备成本排序，不启动原生规划进程。其余对照为原生 light、exact DP、beam 和 beam+原始 NDU。配对控制用完全相同 model 检验 beam/NDU 候选 plans 与首动作一致。NDU 不签发执行或安全授权，`DENY_ALL` 不变。

训练 n=65,521；留出 n=262,157、1,048,559；stable、phase_shift、invalidate 三种预注册队列；每种两次重复、每次12请求。留出运行没有重新拟合成本或更改协议，没有选择性重试。

## 观察结果

| 策略 | 服务合计 ms | 真正 HIA 调用数（工作负载） | prepare | reuse | invalidation | 在线原生规划 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| direct | 130.239 | 144 | 0 | 0 | 0 | 0 |
| fixed | 100.830 | 72 | 36 | 108 | 12 | 0 |
| local_light | 95.537 | 60 | 38 | 122 | 8 | 0 |
| native light | 156.639 | 103 | 17 | 58 | 3 | 21 |
| exact DP | 163.736 | 101 | 17 | 60 | 3 | 23 |
| beam | 190.574 | 121 | 8 | 31 | 1 | 14 |
| beam + NDU | 193.795 | 121 | 8 | 31 | 1 | 14 |

每个策略12 episodes、144请求均完成。只有三个大 n cohort 真正调用 NDU，分别3、9、2次；三个小 n cohort 全跳过。不能把零调用 cohort 的时序波动归因于 NDU。

NDU 工作负载中少做了23次原生 HIA 计算，但模型构造约41.745 ms、决策与验证约73.720 ms，准备约6.546 ms、执行与输出 oracle 约46.338 ms；其余约25.065 ms 属于原始记录、状态检查和驱动。local_light 决策约5.228 ms，真实 HIA 调用降至60次。因此本轮没有观察到复杂决策费用被额外复用收益覆盖。上述分项是 episode 内不重叠的顶层计时，原生内部计时与外层计时不叠加。

## 成本与验证

新 HIA 构建286.665 ms，封存加载0.407 ms，内核校准2.367 ms；完整本次 campaign 墙钟2.115 s，其中含共享设置、实际控制与离线审计，外层解释器启动和最终报告序列化不在此计时内。原生桥使用上一轮身份绑定的同一原始编译产物；其历史构建92.447 s没有伪装为免费。本轮独立部署比较中，native planner各自承担这笔完整已知构建成本，加上各自校准、启动、关闭；非 planner各自承担完整 HIA 构建/加载/基础校准。这个反事实分摊不能跨策略相加。

| 策略 | 已知独立部署分摊 s |
| --- | ---: |
| direct | 0.419678 |
| fixed | 0.390795 |
| local_light | 0.384976 |
| native light | 92.911521 |
| exact DP | 92.916834 |
| beam | 92.950923 |
| beam + NDU | 92.953920 |

资格控制和离线审计记在 campaign 账中，不分摊为服务运行时成本。工具链获取、人工和能源成本未知，不能称为完整生命周期成本已经闭合。固定 payload128字节不包含 Python 元数据、ELF 映射和 HIA 临时缓冲区；进程高水位 RSS 39,912 KiB只属于整个 Python进程，不能归给单个策略。封存描述符与 ELF 保持驻留至进程退出，不宣称卸载或持久借用缓冲区 ABI。

验证包括：10个状态机单元测试；18个实际 HIA 正控制；8个原生/缓存拒绝控制；错误 ELF hash 额外拒绝。单元测试的算术替身只验证状态机，与真实 native 控制明确区分。72个实际在线模型全部通过离线独立有限状态审计；23个 exact-DP 最小值全部一致。beam和NDU候选与独立最小值的模型 gap约1.299–5.245 ms，说明给定有限候选构造仍会遗漏更低模型成本计划。这是给定预测模型的审计，不能转成真实时延的最优性证明。

## 复现与统一组合后续

运行命令与协议详见上级 README；本轮桌面路径：

```sh
taskset -c 14 /data/hepta-hia-round2-20261104/toolchains/venv/bin/python \
  tools/qualify_hia_result_cache.py \
  --output /absolute/new-output-directory \
  --clang /data/hepta-hia-round2-20261104/toolchains/clang20/usr/lib/llvm-20/bin/clang \
  --planner /data/hepta-hia-round3-20261105/evidence/ndu-build-r1/target/release/hia-ndu-bridge \
  --planner-manifest /data/hepta-hia-round3-20261105/evidence/ndu-build-r1/build-receipt.json
```

动态库运行需要与本次回执一致的 Clang工具链库搜索路径。source、协议、构建、执行、拒绝和审计证据属于b89e881这一组合；并入新的统一源码后，应在该新 source tree重新执行。当前证据不关闭 P0统一组合，也不关闭 P1动态净收益。下一步有依据的工程工作是削减完整控制路径与见证序列化成本，并研究为什么beam漏掉低成本计划；此结果不支持扩大训练或推广性胜出宣称。

## 证据索引

同目录 `summary.json`、`analysis.json`、`registration.json` 与 `RAW_MANIFEST.json` 可直接阅读。`raw-evidence.tar.gz` 完整保留本轮 result.json、raw.jsonl、四个规划器原始JSONL、冻结训练与协议绑定、Core/LLVM、构建捕获及实际ELF；压缩仅减少空间，不重算数据。原始外部工作目录仍保留每个episode记录和全部失败（本轮没有失败）。

统计与执行身份见 [summary.json](summary.json)、[analysis.json](analysis.json) 和 [registration.json](registration.json)；完整逐事件数据可用 [RAW_MANIFEST.json](RAW_MANIFEST.json) 校对。
