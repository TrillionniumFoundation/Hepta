# HIA / NDU 第二轮实施与七项验收

本轮继续交付可执行代码、真实原生验证和对照实验。验收区分实现已运行、有限资格通过和全面优势：性能改善不能被改写为已超越 Rust，资源检查不能被改写为整个编译器的形式证明，NDU 规划也不授予部署权限。

Hepta 仓库起点为 `bdb0b39c99b7980b98cb3f9e07ba406cc20f0940`。首轮 116 个 `hepta/*.py` 的冻结清单见 [core-freeze.json](../experiments/hia_verified_integration/next_20261028/core-freeze.json)；实际加载身份修复后另行冻结 117 个文件，保留旧身份。原生 NDU 实验源码固定为 `4b6391e116949af0c7e59776baead67271856bdb`；后续仅修改测试夹具的交付版本是 `dc984bb3b3cb21259f838a31f67a7c2983ea9510`，不能用它重标旧性能数据。两个仓库当前均为公开仓库。实测绑定实际源码、工具及产物 SHA；发布前再次核对，不凭最新 commit 名字重标历史数据。

## 1. 同一执行核心与明确入口

`hia routes` 列出实际来源与后端，`admit_route` 执行导入，最后进入同一个 `verify_program`。Hepta 源码、独立 HIA、历史 executable/scalar Core 和显式版本升级都必须通过实际操作验证；旧 Rust/C 后端不会被静默选作 HIA 的替代路径。

本轮将捕获的 C++ 项目和配置矩阵接入统一入口，新增 composed project/matrix 路线。必须验证全部配置，才能发布指定配置；未选配置的非法 Core 也会拒绝整个导入。

```sh
python -m hepta hia routes
python -m hepta hia import-cpp-composed-matrix \
  examples/cpp/composed_project_migration/matrix.json \
  --variant three_weight --clangxx clang++-20 \
  --output selected.core.json --report capture.json
```

Rust、TypeScript、Python、Go 和一般汇编的源语言前端仍未实现，路由明确拒绝。借鉴某种语言的设计并不意味着已具备其源代码兼容能力。

## 2. 带 guard 和归纳证明的真实优化

上一轮定位到 checked byte reduction 阻碍循环展开。本轮实现提案、独立验证和 native build 三个接口，并提供 `optimize-guarded`、`verify-guarded`、`build-guarded` 命令。

候选携带实际 fast Core、源身份、运行时 guard、逐块不变量和精确变换清单。独立验证器证明初始不变量、每条控制边的不变量保持，以及每个被移除检查在实际位置不可能溢出。只允许清单中的 unsigned checked-add 改为 wrap；资源操作、调用、接口及其他行为保持不变。两个实测内核共 30 条证明义务。

证明使用 `sum <= 255*i`。当 guard 保证 `n <= floor(U64_MAX/255)`，循环条件为 `i < n` 时，下一次求和不能溢出。guard 外执行完整原版 checked CFG；原本不安全的无 guard 候选仍被拒绝。

所有义务必须得到 UNSAT。反例、unknown、timeout、预算耗尽、不支持结构和身份漂移都不能发布。输入先冻结，组合 Core 再验证，证据绑定 solver、checker、compiler、target 与实际二进制。执行加载核验后的 sealed image，外部 receipt 本身没有权限。

详见 [guarded 优化合同](HIA_GUARDED_OPTIMIZATION.md)。SMT 编码、solver、Core 检查器、LLVM、加载器、OS 和硬件仍属于信任边界；没有宣称任意程序或整个工具链的绝对安全。

## 3. 完整有限 NDU 编译闭环，净优势未过

桥接调用 NDU 仓库原有递归效用与候选评估算法，返回 `authority: DENY_ALL`。本轮最多支持 8 个状态、32 条变换边、4 个后续批次、127 条完整路径及弃选。超出完整枚举预算会拒绝，不能截断后声称全局最优。

动作涵盖实际拒绝候选、测量、独立证明与重编译、后续执行，以及停止优化但继续交付原版工作。强固定控制承诺完整校准最优序列；轻量控制对同一图做完整有限时域动态规划，不支付它不需要的 NDU 事件序列化成本。各臂具有相同信息和期限，沉没成本始终保留。

最终 18 个 episode 全部完成，72 次 sealed 工作负载执行全部正确。固定候选臂进行了 6 次实际 guarded 变换。NDU、强固定计划及完整动态规划均选择停止，因为注册负载不足以摊销证明和编译。

| 策略 | episode 总成本中位数（秒） | 含 setup 摊销中位数（秒） |
| --- | ---: | ---: |
| 原版固定 | 1.016785 | 5.600837 |
| 固定小 guard | 1.858274 | 6.442326 |
| 固定大 guard | 11.211101 | 15.795153 |
| 校准最优完整固定计划 | 1.027232 | 5.611284 |
| 完整有限动态规划 | 0.967018 | 5.551751 |
| 原生 NDU | 1.018801 | 20.026993 |

NDU 的空 target 构建耗时 43.243376181 秒，全部计入其自身 setup；依赖缓存已有，不称为无缓存整机冷启动。两项 NDU 净优势判定均为 false，也未建立统计优势。整个 study 耗时约 67.233 秒，含原生构建约 110.477 秒。

这建立了真实闭环和正确的停止行为，没有证明 NDU 优于同信息的强控制，更没有证明任意代码全局最优。

## 4. 多配置、跨编译单元 C++ 实现迁移

新增项目在 `entry.cpp` 构造包含两个 byte owner 的复合对象，将完整 owner 按值移入 `consume.cpp`，覆盖再次移动、借用、提前返回、构造失败和逆序析构。两个宏配置都捕获完整源文件、活动声明、类定义与函数实际定义。

原 C++ 参考程序分别编译并链接三个 C++ 对象；迁移目标仅包含生成的独立 HIA 与观察 harness，不链接原 C++ 实现。支持范围内的实现迁移与外部桥接分开记账。

每配置记录 139 个活动声明出现位置，计入隐式声明为 219 个，均有处理去向。每配置 437 个用例比较返回值、分配身份/大小、析构顺序及失败清理，观察到 401 次分配、401 次释放、196 次实际拒绝及 live=0。参考 wrapper 的跨 TU 精确 C ABI typedef 修正单独留痕，旧结果不删除。

一般引用别名、共享所有权、自定义 allocator、继承/虚调用、模板容器，以及原 C++ 对象布局/异常 ABI 没有因此获得支持。有限 native 差分也不构成一般 C++ 源等价的形式证明。详见 [跨单元迁移说明](CPP_COMPOSED_PROJECT_MIGRATION.md)。

## 5. 强性能基线：改善明确，总门槛未过

固定七个臂：原 HIA、受证 guarded HIA、Rust O3/fat LTO、C/C++ O3/LTO、实际训练并重建的 C/C++ PGO/LTO。训练与未见输入分离；两个内核、七组配对，共 98 个样本全部保留。1,260 个有限正确性观察通过，源码、工具和产物身份稳定。质量门槛通过，联合非劣门槛失败。

下表为候选耗时除以对照耗时，越小越快。点估计为配对几何平均，95% 上界与 batch p95 单独记录。

| 内核 / 对照 | 耗时比 | 95% 上界 | batch p95 比 | 本比较通过 |
| --- | ---: | ---: | ---: | --- |
| full_lifecycle / 原 HIA | 0.6020 | 0.7123 | 0.6962 | 是 |
| packet_xor / 原 HIA | 0.7088 | 0.9333 | 0.5342 | 是 |
| full_lifecycle / Rust | 1.2040 | 1.4486 | 1.4381 | 否 |
| packet_xor / Rust | 0.9795 | 1.0907 | 1.0307 | 否 |

五个强基线共十项比较，仅 `packet_xor / C PGO` 通过。所有 RSS 门槛通过，但进程 RSS 包含各自 harness/运行库，不能外推为普遍语言内存优势。主机为真实共享 x86-64 环境；团队内部串行计时，不声称独占整台物理机。

首次 proof 约 3.900 秒。完整提案、多次验证、emit 和 build 合计约 12.919 秒，原版 build 约 0.347 秒。依据实测混合输入的平均每调用节省，额外成本的点估计回本量约为 461.5 万次或 329.2 万次调用，不是保证阈值。

反汇编确认 fast reduction 去除了逐字节 carry/abort 分支并被展开，fallback 保留检查。剩余 full 填充中 Rust 每轮 32 bytes，HIA fast 每轮 16 bytes。后续可研究带独立证书的模运算窄化，不能直接删检查或按本次未见样本改门槛。

全部对照、失败原因、样本、成本和反汇编见 [性能结果](../experiments/hia_optimizer_eval/next_20261028/benchmark-results.md)。上一轮负结果保持原样。

加载器修复后另做[只读重绑定审计](../experiments/hia_optimizer_eval/benchmark_rebinding_20261028/README.md)：260 个原始归档成员全部核对；123 项历史源码绑定中 121 项未变，变化仅涉及两处运行时 loader，加上一份新身份检查模块。实际生成 Core/LLVM 的 25 个已导入项目模块未变，当前两份 Core 与完整 LLVM 字节和历史 receipt 一致。七个原生后端产物、六份 PGO profile、98 个样本与全部原成本均保持原样。本审计未重编译、重新求解或重新计时，也不授予新部署资格。完整动态库/sysroot 工具链依赖闭包当时未记录，仍为 unknown，不能据 executable hash 推断已经覆盖。

## 6. 实际 Agent 维护与升级

预登记官方 Qwen2.5-Coder 7B Instruct Q4_K_M 和 IBM Granite 3.3 2B Instruct Q4_K_M，固定 model revision、SHA、运行时、线程数、greedy/seed、预算与所有 prompts。

每家系主实验为四个维护任务 × HIA/Rust × query/full，共 16 格，单次 512-token 预算；每任务有 77 个未见输入。另加两个真实 provider/consumer API 升级，共四个语言任务格，最多两次 1,536-token 提交，只反馈编译和公开用例，隐藏答案不能回灌。

升级包括整数接口扩展与调用者位布局调整，以及新增 capacity 参数、返回有效性/结束位置和调用者错误处理。单侧修改由真实 checker/compiler 拒绝，正确参考实现仅用于控制，不能计为模型成功。

原先 Rust 升级 evaluator 漏检公共入口返回签名，理论上可能接受数值正确但接口错误的更宽返回类型；HIA 已拒绝该变更。独立审查还发现表达式形式调用、隐式分配以及“调用者答案正确、实际 provider 未执行”的真实反例。所有修正在零模型请求时完成，保留旧登记，并核验新旧全部 prompts 与 fixtures 完全相同。

最终检查同时要求实际原生 entry 输出正确、provider 被恰好调用一次且参数正确，以及 provider 自身满足接口合同。Rust 在可信 wrapper 内计数；HIA 的调用计数来自同一 Core hash 的实际 VM 调用轨迹，原生 entry 仍单独验证，不把 VM 计数称为原生计数。有限源配置不是通用 OS sandbox；没有声称 seccomp、文件系统或网络隔离。

主实验、升级、格式 probes、失败提交、tokens、推理/验证和自动修复成本分别计。人工时间未实测，保持 null；升级成功不追加到主实验分母。

首次实际启动因 8 GiB cgroup 下权重重排产生额外副本，发生两次 OOM，尚未得到任何 completion，不能计为模型的任务失败或零成本实验。在零正式答案时记录运行环境修订：同一锁定运行时设置 `LLAMA_ARG_REPACK=0`，其余模型、上下文、线程、seed、token 和时间预算保持原登记；每个实际服务进程核对该环境。原启动日志、成员级归档、修订理由与后续模型存储置换成本全部保留。

原登记 driver 的外层异常处理会在单个请求超时后中止其余任务。Qwen 升级的第一格以及 Granite 主实验的第四格实际触发了该缺陷。原协议的中止记录和未达门槛结论不改；独立审计的续行程序只执行尚未尝试的固定后缀，不重试原超时格、不增加预算、不把隐藏测试反馈给模型。续行是登记后的故障恢复观察，不能改称原协议一次完成。

最终 **32 个主实验格和 8 个升级格全部实际尝试**。原实验与独立续行合并观察后，主实验通过 **5/32**，升级通过 **0/8**；两家系原科学门槛均未通过。

| 模型 | 接口 | 主实验成功 | 真实尝试 | timeout | 已知输入 token | 已知输出 token | 完整总 token |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Qwen | HIA 语义编辑 query | 2/4 | 4 | 0 | 1,446 | 227 | 1,673 |
| Qwen | HIA full context | 0/4 | 4 | 0 | 3,004 | 261 | 3,265 |
| Qwen | Rust 语义编辑 query | 1/4 | 4 | 0 | 1,109 | 179 | 1,288 |
| Qwen | Rust full context | 2/4 | 4 | 0 | 1,270 | 116 | 1,386 |
| Granite | HIA 语义编辑 query | 0/4 | 4 | 0 | 1,725 | 555 | 2,280 |
| Granite | HIA full context | 0/4 | 4 | 1 | 3,238 | 1,536 | unknown |
| Granite | Rust 语义编辑 query | 0/4 | 4 | 0 | 1,285 | 440 | 1,725 |
| Granite | Rust full context | 0/4 | 4 | 0 | 1,519 | 248 | 1,767 |

Qwen 的 HIA query 存在真实通过隐藏原生输入的答案，但没有达到四题全对及 token 非劣门槛。Granite 的 15 个完整主任务响应均被响应合同/JSON/允许编辑检查拒绝，另一个请求超时，没有进入原生候选验证。升级的 12 个完整响应都把文件名放在 JSON 顶层，违反唯一顶层 `files` 的原合同；另两个 HIA 升级请求超时。升级候选因此没有进入原生构建或隐藏验证，不能将字段拒绝解释为其程序正文已被证明语义错误。

全部 46 个计分提交分为：30 个准入/JSON/允许编辑拒绝，8 个实际原生语义错误或陷阱，5 个通过，3 个预算超时。另有四个不计分的格式 probes。没有事后给模型答案补包装、代写修复或把参考控制当模型成功。详细诊断见 [响应合同分析](../experiments/hia_optimizer_eval/next_20261028/AGENT_RESPONSE_DIAGNOSIS.md)。

| 家系 | 原主阶段 | 原升级阶段 | 原两阶段外层进程 | 主任务续行外层 | 升级续行外层 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Qwen | 542.211 秒 | 202.381 秒 | 766.019 秒 | 不适用 | 416.352 秒 |
| Granite | 339.722 秒 | 574.507 秒 | 921.595 秒 | 459.815 秒 | 不适用 |

阶段时间包含在父进程区间，不能与父区间重复相加。总计 **50 次真实请求、47 个完整响应**；已知输入 25,387 tokens、已验证输出 6,803 tokens。三次超时的输出 usage 不完整，整体 output/total tokens 保持 `null`，不采用服务端部分 generation 计数补齐。工程准备、首次 OOM、下载、存储置换、归档与人工成本分别留痕；其中人工/工具开发时间未计量，不能称为全经济成本已知。

Qwen 原主阶段完成、原升级阶段 incomplete；Granite 原主阶段 incomplete、原升级阶段完成。原模型级协议均仍 incomplete，补充覆盖只表示未尝试任务已经补齐。本轮仅涉及两个固定量化模型、四个有限维护任务与两个双文件升级，不能外推到大型工程或所有 Agent。完整任务足迹、失败尝试、验证/修复次数、token 与成本见 [最终模型结果](../experiments/hia_optimizer_eval/next_20261028/AGENT_FINAL_RESULTS.md) 和其配套 JSON。

## 7. 持久原生 owner 上的自动选择

`OwnedAdaptiveRuntime` 管理实际 calloc/free 的独占 u64 数组，受证 HIA 版本仅提供无外部效果、总定义的标量状态转换。安全点切换保留同一分配与内容；活借用、活动调用、过期 token 或不兼容状态拒绝切换/销毁，不开放任意 foreign-buffer ABI。

队列先冻结再计算身份；原生逐项提交进度。完成、取消、部分失败的队列都是终态，不能重放。校准仅作用于独立克隆 owner，不重复应用工作。策略使用实际提交长度、交替配对校准的最小观察节省和实测成本，在提交记账后重新判断收益；损失时恢复已验证原版供后续工作使用，保留完成状态。

最终资格保持 400,000,000 次转换参数，并补齐外层计量：从本 fixture 的确定性程序/候选构造开始，覆盖运行时构造、全部编译/验证/校准、提交、执行返回与最终 close。仅扣除完整 post-decision 独立 clone audit API 的墙钟；它另计入实验总成本。进程启动和本实验未执行的 LLM/NDU 搜索不在该范围内。

| 最终完整外层观察 | 秒 |
| --- | ---: |
| 完整部署墙钟（扣除独立 audit） | 4.019186453 |
| 独立原版 clone 原生执行 | 3.307593459 |
| 完整部署净收益 | **−0.711592994** |

此次自动成本检查保留原版，收益门槛未通过。控制器拒绝切换仍已经支付候选准备和测量成本，不能把这些成本归零。全部正确性/身份/owner 控制通过，24 次分配和释放配平，最终 live=0。

此前 attempt03 曾在内部计量区间观察到 +0.354192625 秒净收益，作为历史数据保留。attempt04 补齐外层计量后观察到 −0.805389844 秒净收益；增加的外层尾部成本实测为 711,733 ns，两次实际校准与选择也不同，不能错误声称单靠这 0.712 ms 就把旧正收益变成负收益。最终 attempt05 仅因生产加载身份漏洞修复，以完全相同的 400,000,000 次转换参数重新取得资格，净收益仍为负，原因是实际准备和切换成本耗尽预测收益。全部历史轮次保留，未更换参数以追求正数。

该范围不覆盖一般堆图/活动栈帧迁移、外部 I/O 或崩溃恢复后的 exactly-once。详见 [持久 owner 协议与计量边界](HIA_OWNED_STATE_RUNTIME.md)。

## 集成、CI 与完整验收

NDU [bridge CI 40632653917](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653917) 通过实际 Rust tests、transport/identity 和 clean-worktree。前次 workflow 的 job-level runner context 错误与最小修复独立保留。专门 CI 不替代更广的 blocking/Bazel/platform 门禁。

首轮统一回归实际运行 259 项测试，发现 3 个 failure 和 6 个 error，原始失败日志保持不变。其中两个旧 C++ 路径要求固定 Rust 1.90，不能被新实验的 Rust 1.95 直接代替；CI 现分别绑定两版工具链。另外七项暴露了真实动态加载器缓存问题：关闭 fd 而保留旧 `dlopen` 引用后，复用 `/proc/self/fd/N` 可能返回旧机器码，即使新 fd 的 SHA 正确。生产 loader 现在在调用前核对每个实际函数地址所在的 `r-xp` 映射、dev/inode、文件范围以及完整 seals；缺少证据或身份不符立即拒绝。单个 HIA 入口与 stateful driver 的全部 14 个 export 都受此门禁保护，真实同名 export/fd 复用负控已拒绝。没有通过弱化验证或仅修测试掩盖该问题。

最终本地统一回归实际运行 **264 项，0 failure、0 error、0 skip，源码前后完全一致**，耗时 179.555448339 秒。最终 CLI 的提案、验证、构建流程完成 36 次真实 fast/fallback 原生执行，检查实际 loaded mapping；timeout 提案未发布。首轮失败没有覆盖或移除。

实现发布为 `03d463599484ca18c5ff8eebbb4c0fd149cd2d56`，发布 Git tree `383b3c7c8a6b68a3857a87c9acbd86af3ca32c24` 与本地已验证版本精确相同。[公开 CI 40636856854](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40636856854) 独立运行相同源码，**15 个步骤全部成功**，包括实际无 skip 回归、CLI、NDU、迁移/运行时资格及证据上传。后续证据提交单独记录，不将本地 commit 元数据和远端 commit SHA 混为一谈。

第二个公开证据提交为 `d5a0bf0e42611309cbc6461b1a414b9f8ece254f`，tree 为 `2395f4d8628c2c9ce8a649f129200a71afff083b`；[CI 40639809081](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40639809081) 同样 15 步全部成功。模型原始归档超过仓库连接器单次请求限制，采用有序二进制分片；每片绑定长度、SHA-256 与 Git blob，拼接后必须等于原始 archive SHA。原始内容、成员清单与失败记录没有删减或重压缩。

NDU 仓库旧完整 blocking run `40632653912` 最终失败，37 个 job 中 16 成功、7 失败、10 取消、4 跳过。其中 Ubuntu Clippy 明确拒绝了此前把 fixture `unwrap()` 改为 `expect()` 的处理；修复提交 `dc984bb3...` 改为对 `Result` 显式断言，不添加 lint allowance，不改算法、依赖或锁文件。新 [bridge run 40640810614](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40640810614) 与 architecture 都成功。

新 [blocking run 40640810612](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40640810612) 的完整终态仍为 failure：37 个 job 中 16 成功、5 失败、12 取消、4 跳过。Ubuntu Clippy 的官方 annotation 明确为超过一小时上限后取消，不算远端 lint 通过。Windows shard 1/4 和 3/4 的完整日志已取得，包含 canonical path、UnsafeStateDirectory、Capacity、socket AlreadyExists 和恢复断言等实际失败；没有将它们称为已修复或与本工作无关。cargo-deny 日志仍返回 Transport closed，具体根因保持 unknown，不能把 runner-image notice 当作失败原因。完整四个 workflow、44 个 job、失败诊断与无损日志见 [终态 CI 证据](../experiments/hia_private_ci/final_dc984bb3_20261028T094818Z/README.md)。

模型完成后，在独立精确 `dc984bb3...` 源码上运行仓库原 `just test -p codex-hepta-fleet --locked`：**两个 binaries 的 41 项测试全部通过，零跳过**，包含实际 authority fixture 测试。原 `just clippy -p codex-hepta-fleet --locked` 首次 exit 0，无 lint warning/error；不调用 `--fix`，没有更改源码、锁文件、nextest 或 Clippy 配置。完整[本地 crate 资格](../experiments/hia_ndu_ci/fixture_scoped_validation_20261028/README.md)保留 nextest 版本对原配置键和 metadata 的 warnings，不代替远端 Bazel Clippy。两个独立续行工具另外通过 7 项故障路径控制，已加入最终公开 CI；这些 mock 控制不计为模型成功。

旧 NDU 数据另做无重计时的重绑定审计：218 个 archive members、27 份 proof/artifact receipts、99 个既有成功 sample 都核对身份；当前代码重新生成的三份 Core/LLVM 等于旧 receipt，新 mapping gate 也接受归档的确切库字节。新 runtime 身份与旧身份明确区分，旧记录不授予新部署资格。详见 [重绑定审计](../experiments/hia_ndu_graph/loaded_mapping_rebinding_20261028/README.md)。

每项优势必须使用自己的证据。单测通过不能改写性能、NDU 净收益或 Agent 成本的负结果；“全局最优”“全面超越 Rust”“任意 C/C++ 低成本安全迁移”均不能由这些有限实验推出。
