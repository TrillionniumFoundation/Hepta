# HIA / NDU：七项实施增量与验收结果

本文保留该次实现和实验的历史结果。整合树中两套原生 NDU 桥的当前构建入口、
独立环境变量及收据协议见 [双桥契约](HIA_NDU_BRIDGES.md)；历史实验原始记录未改写，
下文的 201 项测试及性能样本不自动归属于整合树。

本轮交付了可执行实现、真实原生资格、对照实验和失败证据。**七项总验收尚未全部通过**：NDU 净收益、Rust 性能非劣、Agent 正确维护优势以及盈利的自动适应，都不能由本轮结果确认。

实现基于集成源码 `3db07aa877ab1a5fc00560d7037e6efbc884fc1f`，保留 PR #324 的 JSON wire 边界修复。原生 NDU 使用独立提交
`2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b`：
<https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4118>。
原 NDU 算法与应用工作区未被改写。

## 验收矩阵

| 项目 | 已实际完成 | 本轮验收状态 |
| --- | --- | --- |
| 1. 统一执行核心 | 机器可读 route registry、实际 adapter dispatch、历史来源验证、同一 HIA Core 的值/资源/错误/效果执行；不支持路径拒绝 | 有限 profile 已通过；七种通用源语言前端并未全部实现 |
| 2. 优化验证接口 | 独立 SMT 翻译验证、前提/义务/资源/target 合同、unknown/timeout 拒绝、最终 native bytes 绑定 | 支持的标量段改写已通过；任意 CFG/内存变换及全编译器形式证明仍未完成 |
| 3. 真实 NDU 编译闭环 | 原始 Rust NDU API、真实提案/拒绝/证明/编译/测量/后续执行/停止，五个同预算控制臂 | 30/30 episode 正确完成；净收益优势未通过 |
| 4. C/C++ 实际迁移 | 新增嵌套词法作用域与条件 owner 生命周期、提前返回/构造失败清理，四条 native 差分路径 | 新增完整 C++ fixture 的 64 个活动声明全有去向；一般多配置跨模块 C/C++ 迁移仍未完成 |
| 5. 强性能基线 | Rust/C/C++ O3+LTO、真实 C/C++ PGO、训练与测试输入分离、尾部/峰值 RSS/全部构建成本 | 84 个样本完整；全部 10 组非劣比较失败 |
| 6. Agent 开发优势 | 同一实际模型、固定预算/工具/任务的 HIA/Rust × query/full 四臂，77 个 prompt 外测试输入/任务 | 16 个任务格均完成，但 0/16 正确修复；无生产率优势证据 |
| 7. 运行时自适应 | 两种实际不同 native 指令实现、sealed memfd、状态匹配、active lease、安全点显式切换和拒绝 | 空状态显式切换已通过；盈利的自动策略、活 owner/loan/state 迁移未实现 |

## 统一核心与优化权限

新增 `hepta/hia_routes.py`，并将相关 CLI 导入连接到实际统一 dispatcher：

```sh
hepta hia routes
hepta hia verify-optimization baseline.json --candidate candidate.json
hepta hia fold-constants baseline.json --output folded.json
hepta hia build-optimized baseline.json --candidate folded.json \
  --clang clang-20 --output candidate.so
```

优化器只承认实际 Core。它保持完整 CFG、接口、资源操作与调用序列，在每个 effect barrier 前独立证明标量输入及首个 trap 相等。只要出现反例、未知结果、超时、身份漂移或不支持的变换，就不能发布该候选。

独立 review 发现并修复了三个具体问题：效果输出与参数的 SMT 名称碰撞；生产者在证明后修改候选字典的竞态；并行 Agent 共用 Z3 默认 Context 导致的真实 SIGSEGV。最终实现先冻结输入、隔离符号命名空间，并为每次验证使用独立 Context。原四线程二十次崩溃反例修复后全部返回 `verified`。

所有 Core、proof、solver、编译器、target 和产物身份都进入证据。发布后的磁盘路径仍可能被同权限进程修改；实际运行时因此使用已核验并封存的 memfd，不重新加载可变路径。SMT 编码、solver、LLVM、loader 和硬件仍属于明确的信任边界。

详细合同见 [HIA_VERIFIED_OPTIMIZATION.md](HIA_VERIFIED_OPTIMIZATION.md)。

## NDU 真实闭环：有效停止，没有测得优势

原生桥接调用未改动的 `evaluate_recursive_utility` 和
`evaluate_candidates_with_policy`。它始终返回 `authority: DENY_ALL`；候选能否执行由编译器独立判断。

五个臂分别是固定停止、固定常量折叠、由校准选择的固定策略、轻量控制和 NDU。校准输入与部署程序分开；决定仅使用已发生的测量与共享校准，不能读取未来测试结果。不同策略可以省去不需要的提案/拒绝工作。全部策略使用同一 episode deadline，超时后不继续后续动作。

最终 30 个 episode 的实际结果：

| 策略 | 单任务总墙钟中位数 | 含统一 setup 及自身原生构建成本的摊销中位数 |
| --- | ---: | ---: |
| 固定停止 | 367.748 ms | 526.232 ms |
| 固定折叠 | 702.515 ms | 860.998 ms |
| 校准选出的固定策略 | 373.021 ms | 531.504 ms |
| 轻量控制 | 377.844 ms | 536.328 ms |
| NDU | 432.808 ms | 4,754.471 ms |

公共 setup 为 950.901 ms；NDU 的新 target 原生构建为 24,976.497 ms，完整计入其成本。依赖下载缓存已有，不能称整机冷启动。NDU 控制本身中位数 3.112 ms，额外提案/证明/拒绝工作中位数 78.079 ms。

NDU、轻量控制和选出的固定策略均 6/6 选择停止优化并继续交付 baseline。固定折叠臂 6/6 真正执行了改写、独立证明、编译和后续工作。LLVM 已将这组 base/fold 编译成相同机器码，所以没有用计时噪声伪造折叠收益。

review 另修复了弃选路径漏计沉没成本的问题：最终所有候选一致比较从当前决策点开始的未来增量，已发生成本完整保留于总账并绑定 support identity。2 秒沉没成本的真实原生回归确认不会凭空偏向弃选。60 次首轮/后续执行均从 sealed memfd 加载，实际加载 SHA 与独立 native receipt 一致。

这些数据证明有限闭环实际运行，不能证明 NDU 已优于固定策略或实现全局最优。证据与协议见 [NDU 实验目录](../experiments/hia_ndu_loop/README.md)。

## C++ 作用域资源迁移

新增迁移覆盖词法块和条件分支中的构造、移动、逆序析构，正常退出保留外层 owner，提前返回先计算结果再清理，构造失败清理已完成的外围对象。分支汇合时外层 owner 状态不兼容会拒绝。

冻结后的真实资格包含 1,121 个用例，分别执行原 C++、Hepta→Rust、Hepta→C、直接 LLVM，共 4,484 次正向调用。每条路径观察到 3,180 次分配与释放、398 次实际分配拒绝，以及每次返回时 live=0；大小、身份和销毁次序均一致。漏释放与错误销毁次序两个实际错误二进制均被捕获。

64 个活动声明均有明确 disposition；三个转换目标不链接原 C++ 实现。行为差分、静态资源检查、ABI 范围、形式证明与性能仍分开记录。详细范围见 [C++ 迁移说明](CPP_SCOPED_OWNERSHIP_MIGRATION.md) 和 [完整证据](../experiments/cpp_scoped_eval/evidence/README.md)。

## 性能与 Agent 结果

两个 byte-buffer 内核包含实际分配、填充、变换、求和及释放。六个后端共 864 个有限原生正确性观察通过，84 个预先登记的计时样本全部保留。相对调优 Rust，HIA 几何平均耗时比是 1.7469 与 1.3670；对应 batch p95 比为 1.8095 与 1.3734。HIA 进程峰值 RSS 为 744/804 KiB，Rust 为 948/1,012 KiB；这不是可外推到所有程序的语言内存优势。

所有 Rust/C/C++、LTO/PGO 对照的联合非劣门槛均失败。受测主机共享且曾短暂与另一个 NDU 构建重叠，没有删除样本或选择更好的一轮；该限制单独保留。

反汇编定位了主要差距：HIA 的逐次 checked reduction 阻碍循环展开。删除检查的诊断变体确实更快，但改变任意输入语义，**未获优化权限**。可继续研究带条件的 reduction 快路径及 `sum <= 255*i` 归纳义务，保留 checked 慢路径。仅为分配器添加既有 freshness 的 `noalias` 合同没有改变这两个最终二进制，不能被宣称产生加速。

Agent 实验使用实际 Qwen2.5-Coder 0.5B、同一量化模型和固定预算：四个任务 × 四个臂，全部 16 个 task cells 返回，32 个原生正/负控制通过；四臂均 0/4 正确修复。所有失败、tokens、推理及 native 验证时间均保留。HIA 格式可被接受也不等于修改正确。人工修复、真实依赖升级及长期维护成本并未测量，不能当作零成本。

完整数值与原始证据见 [性能与 Agent 报告](../experiments/hia_optimizer_eval/results.md)。后续独立 Context 修复没有改动这些计时内核或模型请求；最终源码重新生成的 Core、LLVM、15,536 字节 native artifact 以及 16 个完整 task requests 均逐字节相同。这个 [重绑定](../experiments/hia_optimizer_eval/rebind.json) 没有新增性能样本或模型请求，也没有改写历史测量。

## 运行时版本选择

最终资格使用实际不同的机器实现：`x+y` 与等价的
`(x^y)+2*(x&y)`，包含 131 对 native 输入及四线程各 65,536 次调用，共 262,144 次。运行中拒绝切换/卸载、seal 写入返回 `EPERM`、加载前篡改拒绝、加载后路径替换不重绑定、伪造 receipt 与过期证据拒绝等控制均通过。

本轮只有无持久状态、无活 owner/loan、无外部效果的显式安全点选择。默认自动请求保留原版，`automatic_profitable_selection_supported=false`。测量成本中同时支付 baseline 与 candidate 的 shadow 调用，因此不能把其差值伪装为已经回本的自动策略。未来要有独立的工作负载承诺、置信下界及真实摊销期限；一般堆图、栈帧与活资源迁移仍需要单独实现和证明。

详细设计见 [运行时说明](HIA_ADAPTIVE_RUNTIME.md) 和 [完整资格](../experiments/hia_runtime_eval/evidence/README.md)。

## 集成验证、CI 与证据边界

`tools/qualify_hia_verified_increment.py` 对最终冻结的实现运行 22 个测试模块：**201 项通过，0 failure、0 error、0 skip**，源码身份前后一致。日志与源码清单在 [集成验证目录](../experiments/hia_verified_integration/run_20261027/result.json)。

发布后的首轮 [GitHub CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40545121868) 出现一项失败：ELF constructor 测试在观察到预期 `SIGSYS` 前先触发了 3 秒子进程期限。完整失败 artifact 已保留于 [CI 初次记录](../experiments/hia_verified_integration/ci_20261027_initial/summary.json)。修复只将该测试辅助函数的观测预算提高到已有接口支持的 10 秒；精确 `SIGSYS`、文件不得生成、超时仍拒绝以及不重试的断言保持不变，编译器和隔离实现未改动。四项真实原生测试及延迟 constructor 对照见 [修复证据](../experiments/hia_verified_integration/ci_timeout_fix/README.md)。对照区分了超时和实际 syscall 拒绝，没有把人为延迟冒充为 CI 宿主的唯一根因。随后完整本地复验记录在 [修复后的集成目录](../experiments/hia_verified_integration/run_20261027_ci_fix/result.json)，远端状态以 [PR #325](https://github.com/TrillionniumFoundation/Hepta/pull/325) 的对应提交为准。

最终 compiler identity：

```text
fd17300a237eb722dc86cda00416f126dfc4a582da54123a84ed9ef66a04b3fd
```

新 CI workflow 固定 NDU 源码提交和 Rust/Z3/LLVM profile，运行实际原生测试、闭环、迁移和 runtime 资格，禁止将 skipped tests 计为通过。它没有把性能或 Agent 优势改写成 unit-test success。

原始数据、源码 snapshot、实际二进制、SMT queries、构建/执行命令和失败 attempt 以逐成员 SHA 校验的无损压缩包保留。磁盘耗尽、缺失 PGO runtime、Agent 源码漂移、已被修复版本替代的结果均保留。私库默认 nextest 发现零 Rust unit tests，Bazel 工具不可用的默认门禁没有被称为通过；实际功能由公共仓库中的原生 CLI 集成覆盖。

**工程下一关是扩展可证明且真正有机器码收益的变换集合，并在更强的模型与真实迁移维护任务上产生正确完成结果。当前数据不支持“已经超越 Rust”“NDU 已实现全局最优”或“七项全部完成”。**
