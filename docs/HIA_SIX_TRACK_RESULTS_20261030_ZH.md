# Hepta 六条线实现与验收报告

本轮已经提交可执行实现、真实原生运行、负控制和原始证据。六条线都有工程推进，但用户提出的六项完整验收尚未全部关闭。尤其是：NDU 两次注册执行均未建立候选竞争或净收益；Agent 试验被提供方额度拒绝；物理设备、MMIO、DMA 与硬件中断尚未资格化。

## 1. 源码、实验与证据身份

| 对象 | 精确身份 | 用途 |
| --- | --- | --- |
| 本轮基线 | `192d2cbba7e49bde3b03af73685ecf96f6fb1b05` | PR #405 的集成基线，不能称为已经合并的 main |
| 第一轮源码 | `03c8205271dc5e8f9c5cad806e46056bffe2bc02` | 六线实现、原始协议与首次正式运行 |
| 当前冻结源码 | `91ac6008fc5d67acb8354383f7006d9d899f54f3` | 补齐 scalar receipt 依赖身份；登记实际 CLI 启动提示 |
| 代码评审 | [PR #412](https://github.com/TrillionniumFoundation/Hepta/pull/412) | 保持 draft，尚未合并 |
| 第一轮原生执行 | [Actions 41059492139](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41059492139) | 绑定 `03c8205…` |
| 当前源码原生执行 | [Actions 41063003872](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41063003872) | 绑定 `91ac600…` |

后续保存报告的 evidence commit 不是执行这些二进制的源码。两个提交的结果分别保留，不能用较晚的文档身份重新标记较早的测试。完整 CI 状态以 `evidence/hia_six_track_final_20261030/CI_STATUS.json` 为准；机器可读的六项验收记录是同目录的 `ACCEPTANCE.json`。

## 2. 逐项交付与尚未关闭的验收

| 优先级 | 本次实际交付 | 已取得的有限实证 | 尚未关闭 |
| --- | --- | --- | --- |
| 1. 统一语义与可信核心 | 生产 CFG / owner / loan / 返回资源平衡共用内核；解释器预算次序；LLVM 边绑定；缓存与证明身份依赖 | 两个架构各 14 项资格测试、30 个真实原生场景；56 个旧版与新版 VM 独立进程对照 | 全语言机械化语义与 soundness、完整 backend refinement、原生与 VM 预算等价 |
| 2. 可验证优化 | guarded proof 到真实发布产物的身份与事务修复；scalar receipt 的九文件语义依赖指纹 | x86 13 项 binding 测试，含 2 项真实 native；两架构各 7 项 receipt 测试，含实际 SMT 重放 | 本次没有新增通用循环、复合资源、开放跨模块或降低峰值内存的优化算法 |
| 3. 真实 C++ 维护迁移 | 两个历史 INIReader 版本；三个决策片段的 Hepta 实现；callback lease 适配；18 个成员的处理清单 | 原始与迁移组件独立编译运行；逐位 Boolean 结果、生命周期、故障、回调与真实上游行为变化 | 整个组件或一般 C++ 自动翻译、低人工成本及任意未来升级成本 |
| 4. NDU 增量价值 | 共享候选启用成本的 DP、独立枚举 oracle、五臂真实原生对照及完整已测成本 | 两次各十个 episode 完成，原生数值/选择与精确模型一致 | 两次均无实际非 baseline 选择、无竞争、无净收益；没有 learned predictor |
| 5. Agent 开发效率 | 函数上下文、全模块 patch 重验、新维护任务与真实 CLI runner | 作者控制与协议回归通过；真实进程、登记身份和提供方拒绝均留证 | 无完整模型答复或完整 usage；没有真实 A/B 效率结论，也没有完成真实项目文本/结构与工具因子的研究 |
| 6. 目标接口资格 | x86_64 / AArch64 的实际 Hepta 对象链接；pthread、eventfd、取消、故障与恢复 | 每宿主 21 个有序场景、244 次完成的 callback；FD、线程与已跟踪资源平衡 | 专用设备可用性未知；物理 MMIO / DMA / IRQ、驱动、任意共享内存并发尚未资格化 |

### 2.1 共用内核具体改变了什么

保留 50 条指令及已有 primitive 版本。`hia_semantic_kernel.py` 集中了有序 CFG 后继、并行边参数快照、线性 capability 重命名、借用冲突/挂起/祖先关系和正常返回资源平衡。生产检查器调用这些规则，VM 与直接 LLVM emitter 共用 CFG 与并行绑定规则。缓存与主要优化证明的依赖身份包含新内核；独立 scalar translation receipt 的遗漏随后在 `91ac600…` 补齐。

失败的语义没有混在一起：failure-as-value 和协作取消是需要显式清理的正常控制流；trap 保留停止时账本，不声称自动析构；VM quota stop 是单独的执行器结果。VM 的 tick、调用深度、live payload 配额不自动等于原生 RSS、栈、时间或 allocator metadata 限制。

每宿主的 30 个 native 场景由 24 个 pipeline 场景和 6 个 owner-loop 场景组成。实际 Core 经 Clang 编译，再链接独立的 C 分配器观察器；独立子进程比较 ABI 返回值、分配尝试、存活 payload 和峰值 payload。30 个场景包含在一个 native 测试方法内，不能与 14 项测试简单相加。

这仍是共用可执行规则及有限一致性证据。其余指令执行、composite elaboration 与 LLVM lowering 还不是从单一机械化语义自动生成。Python、VM、编译器、链接器、allocator、操作系统、硬件及保留的外部包装器属于明确可信边界。

### 2.2 优化准入与机器产物绑定

本次修复的实际问题包括：另一个合法 Core 的编译产物不能借用原 proposal 的证明；错误 IR、目标、接口、长度或摘要被拒绝；缺失工具链收据不能在发布后才抛错；发布中断与发布后的身份漂移会撤回本次创建的链接，同时保留其他写入者替换的路径。

两个 native 测试实际使用 Z3 和 Clang：一个执行 guarded owned-buffer loop 的 fast 与 fallback 路径，另一个真实编译错误 Core 并验证拒绝发布。其余十一项是明确标注的边界故障注入，不能当作十一项独立 native 证明。

新增 scalar receipt 修复对九个实际语义源码依赖计算身份。旧 receipt 在外部规则或 VM 身份改变后不能继续具有同一 checker 身份。已有 actual Core 重验与 SMT 重跑仍然执行；伪造一致身份也不能隐藏实际返回值反例。原来的单文件摘要在八个外部依赖变化控制中均被新回归识别为不足。

这些身份、重放与事务保证不是机器码 refinement 定理。已有窄范围循环归纳、leaf-call expansion、复合资源 elaboration 和有限预算合同仍按各自 profile 工作。保序资源优化中的 Core 峰值差为零，不能据此宣称本次实现了峰值下降。预算合同明确区分 candidate 重新资格与 source/candidate 都满足相同 quota；精确 quota 停止位置没有被宣称保持。

## 3. 真实 C++ 组件迁移结果

固定上游 `benhoyt/inih` 的两个提交 `de720a6f4066587618edfba3960ea9ed4132c665` 与 `2d5ec7b59abbb8e1797e48060965001aaac6996a`。执行路线是源码钉住的决策提取 → 真正的 Hepta parser/checker → 独立 C11/GCC 输出 → 真实 INIReader C++ 组件。它不是一般 Clang C++ importer，也不是把 Rust 转译结果换一个名称。

`GetBoolean`、`ParseErrorMessage`、`ValueHandler` 的三个决策片段已迁移，两个构造路径接入 lease 适配，18 个成员均有处理去向。C parser、STL map/string、类布局、部分大小写/格式处理及 callback registry 仍在外部边界。

每个宿主、每个版本的关键结果包括：

- 10,780 个 Boolean 结果按完整有序位流与原始实现比较。
- 64 个完整对象生命周期，最终 C 分配与 C++ new/delete 账本平衡。
- 11 个 callback 控制和 36 个状态/事件转换；伪造、过期、跨线程、重入及容量条件分别检查。
- 实际回放上游读取目录失败行为从旧版 `0` 到新版 `-3` 的变化；两条实现路径各自保持所对应版本的行为。
- 在 `INI_USE_STACK=0` 的堆缓冲配置下，注入 `std::bad_alloc` 复现原始 C 缓冲区剩余一个分配；适配路径先完成 C 清理再重新抛出，剩余为零。这是明确的异常资源修复，并非声称异常资源轨迹与旧实现完全等价。
- 错误 Boolean Hepta 实现确实被编译、链接并运行，独立原始组件对照拒绝其输出；负控制没有用编译失败替代。

最新资格运行每宿主均为 48 条实际命令，x86 为 15.288790267 秒，AArch64 为 16.097856699 秒。它们是自动验证时间。人工合同编写、审阅、迁移与升级维护工时仍未知，不能用这些秒数宣称“低成本重写 C++ 已经成立”。

## 4. NDU：两次均为阴性结果

两次执行均使用原始 native NDU 源 `4b6391e116949af0c7e59776baead67271856bdb`，两组、五个 arm、每个 episode 十二个 region。两次源码身份不同，但实验协议、种子、长度和调用次数相同；第二次属于已知负载重复，不能算新的未见负载。

下表为各 arm 两个 episode，加一次本 arm 应负担的已测共同准备和 controller；NDU 列额外计入原始空 target 构建：

| Arm | `03c8205…` | `91ac600…` |
| --- | ---: | ---: |
| Fixed base | 11.525890119 s | 11.286693796 s |
| Fixed best plan | 11.530288001 s | 11.308013916 s |
| Lightweight greedy/single | 11.561936611 s | 11.309730020 s |
| Exact Q32 DP | 11.584965177 s | 11.322619686 s |
| Original native NDU | 39.715816139 s | 39.279519449 s |

原始 NDU 构建分别占 28.015371201 秒、27.817915555 秒。在 NDU 已构建的范围内，其总量分别为 11.700444938 秒、11.461603894 秒，仍比精确 DP 多 115.479761 毫秒、138.984208 毫秒。这里只能报告已测范围的描述性差异；依赖/工具链取得、缓存历史、人工、持久存储和最终汇总写入等未知项保留为 null，不得当作零成本。

两次都出现 `competition.established=false`，实际非 baseline 制品列表为空。独立审计分别核验了费用加总、每事件 Q32、资源约束、每轮 120 个执行观测和 24 个原生 NDU 响应。全部选择 base 有简单下界解释：在每个实际决策状态，最低非 base 激活费用已经高于完成剩余 baseline 的全部费用。不是搜索漏选了已证明更优的候选。

实验设计也没有进入预期竞争区：guard-small 的上限是 256，正式负载最小长度为 257，其 fast guard 在十二个 region 中零次适用。不能在看到阴性结果后增加重复次数，再把改变后的负载称为原实验成功。

**搜索贡献**：共享启用成本的精确 DP 与独立小枚举 oracle、原始 NDU 数值/选择一致；本轮选择又被简单下界决定，不能证实更复杂搜索的实际选择优势。native NDU 接收外层精确搜索产生的路径，不能在同一有限目标上超越其精确输入解。

**预测贡献**：本 profile 没有训练出的 predictor。动态 arm 共享相同校准信息，只按各自观测做受限比例更新。没有非 base 执行或切换，不能声称证明预测、探索或泛化收益。

目前结果支持保持候选建议与确定性证明准入分离。若继续研究 NDU，下一实验必须先固定外部真实 workload trace 和部署复用周期，再分别消融预测、候选生成/证明费用与搜索贡献；本次阴性结果仍应保留。

## 5. Agent：已运行真实入口，效率验收仍阻断

上下文工具保留完整被编辑函数、直接调用接口、调用位置、函数清单、返回 loan 的 formal origin 和需要的 opcode 子集。最终 patch 始终针对原始完整模块重验，focused context 不是隐藏函数可以忽略的安全许可。

| Attempt | 登记源码 | 真实 CLI 启动尝试 | 完整答复 | 结果 |
| --- | --- | ---: | ---: | --- |
| 01 | `03c8205…` | 4 | 0 | 严格事件门拒绝未登记的启动配置提示；usage 未知 |
| 02 | `91ac600…` | 0 | 0 | 本地 Git 注册检查失败，未启动 provider；已保留失败 |
| 03 | `91ac600…` | 4 | 0 | 启动门通过，provider 明确返回 usage limit；usage 未知 |

Attempt 01 的原始输出含 `turn.started`，不能由 parser 提前停止推出提供方零推理或零成本。新注册只登记实际四条 pre-turn 提示的精确文本和 2/1/1 最大次数，未知、超量、回合后的提示及工具事件继续拒绝。任务、模型、表示、评分与预算没有改变。Attempt 02 的 Git 对象物化问题修复后，全部 171 条登记路径与发布提交再次逐字节匹配，再启动 Attempt 03。

Attempt 03 的额度拒绝是环境阻断，不能计为模型解题正确率。没有任何完整 token 记录，也没有人工修复模型答案或历史答案替代。公开证据只省略账户特定的重置时间与充值链接；原始摘要、公开副本摘要、全部失败与 redaction 记录均保留。

初始 context 字节减少是已有测量，不能换算为 token、时间或审阅效率优势。当前两个人工构造维护任务、两种 JSON 上下文视图，也尚未完成用户要求的真实项目文本/结构表示与工具因子研究。模型可用额度、真实项目任务、人工盲审与失败成本仍是后续独立验收条件。

## 6. 宿主系统接口与真实设备的边界

最新两宿主均实际编译 Hepta callback 对象并链接 C pthread/eventfd harness，`reference_implementation_linked=false`。每宿主 21 个有序场景包含正常、十个故障/取消及十个恢复场景，共完成 244 个 callback；正常批次观察到三个 worker 参与及三个 job 生命周期重叠。

原始 eventfd 探针实际观察 empty read / saturated write 的 `EAGAIN` 与非法写入的 `EINVAL`。分配拒绝、启动错误、部分 I/O 故障等注入场景与真实内核错误分别标注。最终账本检查 FD 前后相同、opened=closed、created=joined、已跟踪 live owners/bytes 为零，恢复场景在同一进程继续执行。

线程调度和 OS 接口由明确的 C/pthread 宿主承担，Hepta callback 使用私有缓冲区。上述结果不证明任意共享内存 HIA 并发，也不是抢占取消、物理设备、MMIO、DMA、硬件 IRQ 或内核驱动资格。当前接口无法核验专用设备 inventory，设备可用性应记为 unknown，不能据此声称组织没有设备。

## 7. 发布与下一验收条件

代码评审继续保持 draft。以下字段仍为 false：六项完整验收、全语言 soundness、backend refinement、全量真实 C++ 组件迁移、低人工迁移成本、NDU 完整生命周期净收益、Agent 普遍开发效率、物理 MMIO/DMA/IRQ 资格及 release qualification。

下一步的验收对象应是可判定的具体结果：扩大并机械化语义范围；增加真正新的资源/循环/调用变换及危险负例；进一步迁移真实组件并记录实际人工成本；以真实部署 trace 建立 NDU 候选竞争；在可用 provider 和真实项目上取得完整模型/审阅记录；对已明确的设备、ABI、MMIO/DMA/IRQ 与恢复合同进行实际资格测试。实现、有限通过、阴性结果和环境阻断分别保留，不用绿色 CI 替代这些结论。
