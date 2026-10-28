# HIA 守卫特化与 NDU：冻结版本 01310b2 的实际结果

本轮完成了有限守卫特化、提前拒绝无经济价值的证明工作，以及真实原生 NDU 对照。
**没有证明 NDU 相对固定策略或简单搜索具有增量价值，也没有出现可接纳的原生净收益。**
36 个执行 episode 全部完成，全部保留基线，不能把这批结果描述为成功的后台发布或版本切换。

## 版本与范围

代码版本是 `01310b2e6c1676e73cd0f338fcf0b8bf072d3fe4`，基于冻结基线
`817713b163b6812a6516179951412b4a6c93ae2b`。运行前 tracked worktree 干净，运行后所有
绑定的源码摘要未变。本目录是独立 evidence 分支上的原始副本；后续合并不改变这次实验的
source commit。`PROVENANCE.json` 记录原始路径和完整报告摘要，`MANIFEST.json` 绑定本目录文件。

实际运行从 2026-10-28 00:16:12 UTC 开始，campaign 自报耗时 42.553 秒。
目标是本机 Linux x86-64；实际工具链、源文件、Core、证明、LLVM IR、ELF、驱动、输入、
调用命令和分阶段耗时均在 `native/RESULT.json`、`native/PROTOCOL.json` 和原始调用记录中。
本机二进制仍保留在 `PROVENANCE.json` 指向的原始 artifact 目录，仓库中保留源码、收据和反汇编。

工作负载是自写研究函数：对 u32 做 8 轮 wrapping add，再与运行时 mask 做 xor。
守卫分别检查 mask 为 0 或 `0xffffffff`，命中后使用常量专用路径，其他输入走完整通用路径。
两种候选都经过 fresh canonical 验证及独立全输入 Z3 UNSAT 证明。
三个 `calculate` 函数的实际机器码不同；命中路径分别简化为最终的加 76 或减 8。
这不是生产项目，也不是第三方 benchmark，指令条数减少没有被当作性能收益。

## 原生观察与完整成本

协议在任何本次构建和计时之前冻结。训练共有 45 个 batch，每个实际调用 500,000 次，
无失败或删样。两个固定 seed 区分训练和 holdout 输入。三个 profile 各有 64 个输入，
hot profile 中 62 个命中对应守卫，mixed 使用混合 mask。

下表为原始训练 batch 中位数折算到每次调用的时间；这些是训练观察，不是发布后收益：

| Profile | 基线 ns/call | mask=0 特化 ns/call | mask=all-ones 特化 ns/call |
| --- | ---: | ---: | ---: |
| hot_zero | 2.614028 | 3.176654 | 2.756062 |
| hot_ones | 2.616412 | 2.642770 | 3.048240 |
| mixed | 2.521350 | 2.934008 | 2.732846 |

两种候选在其对应 hot profile 上反而更慢。没有为了改变结论调整 profile、调用次数、
不确定性规则、编译参数或候选集合，也没有执行“直到胜出”为止的重跑。
测量差异的微架构原因未被单独确定，不能从这组数据推导一般性的特化优劣。

每个策略运行 3 个 profile × 2 次重复，共 6 个 episode；六个策略合计 36 个。
每个 holdout episode 真实执行 250,000,000 次调用，即共 90 亿次计时调用。
每次都校验独立整数规格和 checksum，原生库、驱动、输入文件均以 sealed memfd 绑定实际消费字节。
所有 holdout 实际执行的是同一个基线 Core，没有候选版本被发布。

共享候选生成、证明、编译和训练成本为 **816.280115 ms**。候选的两次初始行为证明分别耗时
75.747945 ms 和 81.608119 ms。原始 ranking NDU 使用单独 fresh target 冷构建，实际耗时
**10.875083207 s**；严格只摊到 **6 个 NDU episode**，即每个加 1.812513868 s。
冷构建使用已有依赖缓存，未复用原生可执行文件。之前安装的工具链和缓存创建成本按协议披露为排除项。

同信息对照中，每个独立 episode 都保守地全额承担共享表成本。这是独立部署场景的成本分配，
不表示共享工作在实际 campaign 中重复执行了 36 次。下表为各组 episode 中位成本：

| 策略 | 完成 / episode | 发布 | 含共享成本的 warm 全成本 s | 再计 NDU 冷构建摊销 s |
| --- | ---: | ---: | ---: | ---: |
| fixed_stop | 6 / 6 | 0 | 1.677540 | 1.677540 |
| fixed_zero | 6 / 6 | 0 | 1.700684 | 1.700684 |
| fixed_ones | 6 / 6 | 0 | 1.662918 | 1.662918 |
| fixed_selected | 6 / 6 | 0 | 1.649751 | 1.649751 |
| light | 6 / 6 | 0 | 1.675004 | 1.675004 |
| ndu | 6 / 6 | 0 | 1.650057 | 3.462571 |

这些 warm 微差来自都执行同一基线程序的不同 episode，不能归因于优化或 NDU。
预先声明的主指标是 NDU 冷摊销全成本对每个控制组的六组配对差值中位数，
无增量阈值为 `max(1 ms, control median 的 1%)`，且每个 profile 的中位收益须为正。
NDU 对 light 的配对成本增加 **1.807760729 s**，对所有固定控制也增加约 1.79–1.82 s，
全部没有通过主指标。报告中的一般性、统计性和全局最优声明仍为 false。

直接部署基线另设账本：fixed_stop 实际 episode wall 的中位数是 **0.861260299 s**，
不把无需进行的候选搜索、证明和训练表强加给它。NDU 对这个直接基线的配对 warm 成本增加
**0.805626971 s**，冷构建摊销后增加 **2.618140839 s**。其余优化策略的独立部署账本
同样保留完整共享成本，未靠同信息对照人为制造部署收益。

## 减少无价值证明工作：单独的控制器回放

`pruning/` 是另一份预先冻结次数和交替顺序的 focused replay，不是上述原生性能实验的重跑。
它读取完全相同的 baseline、两个候选、冻结 observations、目标和真实原生 bridge，
只替换旧/新 ranker 模块。两边使用同一个当前 canonical verifier 和当前 behavior validator，
因此隔离的是 preproof pruning 改动，不是旧版本整个工具链与新版本整个工具链的比较。

| 实现 | 原生 NDU 实际调用 | fresh 行为证明尝试 | 保留基线 | 观察调用 wall 中位数 |
| --- | ---: | ---: | ---: | ---: |
| 817 中的旧 ranker，配当前 validator | 9 | 18 | 9 / 9 | 162.199254 ms |
| 01310b2 ranker，配同一 validator | 9 | 0 | 9 / 9 | 12.128132 ms |

九组配对 wall 减少的中位数是 149.772015 ms。主机并发负载没有隔离，因此该墙钟数字仅作
描述性控制器开销记录，不用于宣称可归因系统性能优越、原生程序加速或 NDU 策略增量价值。
能够直接确认的是：同样保留基线、同样运行原始 NDU，省去了 18 次没有经济价值的证明尝试。
所有 pruned candidate 保持 `proof: null`、`equivalence_proved: false`，并以 hard violation
交给 advisory NDU；没有将跳过证明等同于安全证明。

## 验证、失败保留与尚未关闭的条件

聚焦实现验证共 **98 个测试通过**，覆盖守卫特化、旧/新符号编码比较、translation validation、
NDU、有限动作、多版本和后台生命周期。独立审查者另运行 **8 个指定测试**，并对 **3,072 组**
含 false reachability、合流、先陷阱后分支的输入交叉比较新编码、canonical VM 和独立整数规格，
结果一致；强制 unknown 后，旧 proved 收据仍不能复用。这些证据见 `validation/`。

`development/` 完整保留最初 33-test run 的 1 failure / 7 errors、修复后的 34-test run、
5 秒 unknown 的 u64 division 及多轮算术尝试，以及未采用的 bounded tactic 和编码原型日志。
初始错误包括测试观察 helper 未捕获规定陷阱，修复没有改变被测语言的陷阱语义。
内存中修改过 encoder 的原型 receipt 可能仍带磁盘文件的摘要；它们明确只是开发记录，
不能作为 committed-source 证明或执行接纳凭据。当前正式 campaign 只用 fresh、独立重算的证明。

本轮未关闭：NDU 对强固定控制和简单搜索的增量价值、特化后的实际净收益、生产 workload、
native backend refinement、任意资源/heap/loan/stack 的状态迁移、更低层任意指令搜索和全局最优。
本次 campaign 为零发布，所以版本切换、取消和租约安全的正向证据来自另列的真实 native 测试，
不能从 36 次 abstain 中推导。ranking 和 recursive NDU 的两个 pin/协议继续分开，递归桥在本次
实验中未调用，PR326 的第三种协议没有覆盖现有桥。
