# HIA 全量重写当前开发状态审计：acffa9262

状态观察截至 **2026-11-12 01:19 UTC**。本报告固定于产品提交 [acffa9262f31d073f8f0a6f0201eae201039f619](https://github.com/TrillionniumFoundation/Hepta/commit/acffa9262f31d073f8f0a6f0201eae201039f619)，完整树为 `22a095436c94efc87b1a89aca912c8caab2eed80`。独立工作与证据提交不自动计入该产品版本。当前结论是 **整体 HIA 原生替换尚未闭合，旧整套尚不能删除**。

本轮将完整 Git 树清点、生产模块入口审计、已实际执行的组件结果、当前失败及待运行开发分开记录。4023 个 Git 叶的模式、对象身份和大小已全部取得，完整树对象身份已独立重算。随附 current-tree-inventory.json 保存完整清单。清点不代表对全部 408 MB 内容逐字语义审计，也不代表运行资格。

## 1. 当前完整源码树

| 范围 | 文件 | Python | Rust | HIA assembly | HIA JSON source |
| --- | ---: | ---: | ---: | ---: | ---: |
| (root) | 8 | 1 | 0 | 0 | 0 |
| .github | 4 | 0 | 0 | 0 | 0 |
| benchmarks | 92 | 11 | 0 | 4 | 0 |
| docs | 313 | 0 | 0 | 0 | 0 |
| evidence | 1 | 0 | 0 | 0 | 0 |
| examples | 150 | 1 | 2 | 102 | 11 |
| experiments | 1727 | 317 | 0 | 12 | 1 |
| formal | 15 | 1 | 0 | 0 | 0 |
| hepta | 169 | 168 | 0 | 0 | 0 |
| review-evidence | 541 | 36 | 0 | 0 | 0 |
| rust | 54 | 0 | 39 | 0 | 0 |
| tests | 587 | 467 | 0 | 1 | 0 |
| tools | 362 | 341 | 7 | 0 | 0 |
| 全库 | 4023 | 1343 | 48 | 119 | 12 |

所有 Git 叶合计 408149624 字节。生产包 hepta 的 169 个文件含 168 个 Python 源文件；这 168 个实际源文件合计 2634860 字节。后者已由独立审计代理逐文件读回并核对大小与 Git blob，不能与 hepta 目录的 2637881 字节总量混用。现有 44 个 `_native.py` 名称只是适配器命名，既不是 44 个完整模块替换证明，也不能用来计算“原生完成百分比”。

原 [HIA_NATIVE_REWRITE_INVENTORY.json](https://github.com/TrillionniumFoundation/Hepta/blob/acffa9262f31d073f8f0a6f0201eae201039f619/docs/HIA_NATIVE_REWRITE_INVENTORY.json) 是历史清单，标明 head 75e06b91e7a90222dee3607ac935064b535c06a2、3063 文件和 156 个生产 Python 模块。它明确否认整体交付、动态调用闭合和旧栈删除资格。本轮逐 SHA 对照生产模块得到：145 个未变、11 个改动、12 个新增、0 个删除。145 个字节未变也不能视为 145 个已迁移模块。历史清单的范围是当时 Git index paths/current worktree bytes；本轮按记录的文件 SHA 比较，没有把它记载的旧 HEAD 视为所有历史文件的逐字来源。历史清单保留原身份，随附新清单不回写过去结果。

[完整168模块的当前所有权矩阵](https://github.com/TrillionniumFoundation/Hepta/tree/1d6d2c0ea9c410cbaedddab27490a4716ab216e1/experiments/hia_current_owner_audit_20261112/acffa-r1) 给出13类、23项详细当前入口审计，以及其余145项的字节/声明/selector核查范围。Root已实际读回全部四份审计原件，并把168项的mode/size/Git blob与完整产品树逐一关联、按原清单SHA独立重算145/11/12/0。

## 2. 业务所有权与替换缺口

当前 [完整支持契约](https://github.com/TrillionniumFoundation/Hepta/blob/acffa9262f31d073f8f0a6f0201eae201039f619/docs/HIA_SELFHOST_CORE_SUPPORT.json) 对 native_owners、hosted_owners、显式 selector 和 whole_native_delivery_qualified 作了分项声明。以下按实际入口和契约整理；声明与运行证据分别使用。

| 领域 | 已有 HIA 实现或实际进展 | 当前仍需闭合 |
| --- | --- | --- |
| HIA 自举编译器 | 固定 Core 子集的 HIA assembly 编译器、原生代际构建、ELF 输出及多类资源规则已有源码与历史结果 | 一般 Core 检查器和完整语言不等于该有界子集；最终源绑定的冷启动及全套资格仍未完成 |
| 机器编码、状态、指令 | 字节编码、Code 状态六模式与指令控制分别存在显式 HIA owner；当前两次 CI 到这几项完成 | 三个 selector 相互独立；只选编码器不会迁移状态与操作数策略；对象、链接、安装和默认入口仍需完整迁移 |
| Core 函数降低 | 22 个 _Function 方法及五个辅助方法已有 HIA 控制；独立开发三组共 113 个测试、28 模式实际通过 | 三组分开运行不等于原 180 秒完整资格；acffa 的 _Emitter 与公开外围仍是 Python |
| Core 发射器后继 | 新 v2 计划覆盖 22 个 _Function、6 个 _Emitter 与5个辅助方法，共33原 AST 体、36模式、39个预期 HIA 单元 | 新 source-authoring run43131161021 当前排队；39是预期分母，尚不能写成已生成或通过；外来对象与公开入口仍需验证 |
| 机器 ELF | HIA 已拥有符号、重定位、布局和对象字节构建等策略；组件门已先于 caller 门完成 | 当前两个原始 CI 在51调用门 HOLD；真实内层错误尚待原件解码；foreign TimSort 比较轨迹仍未闭合 |
| JSON、数字、哈希 | 多个 HIA 解析、wire、binary64、SHA owner 和源绑定适配器已存在 | 普通 wire 仍有明确 foreign graph、option、renderer 与资源边界，不能覆盖 Python JSON 的任意调用域 |
| CLI | HIA 负责15动作的参数/呈现/阶段控制，部分独立工具可原生执行 | effect 仍调用 read_bounded、verify_program、编辑、patch、发布和 output_json 等 Python 业务；默认 CLI、普通成功 JSON、安装资源未整体迁移 |
| 新 JSON 格式化 | HIA 布局源码已写成，拥有结构遍历、转义保留、测量/写出和缓冲区拒绝；修订版31开发 IR 案例通过 | 公开入口 u64→u32 ABI 修正后，真实原生验证控制已冻结但未运行；原 CLI 调用与完整值域均未被替代 |
| Agent 日志与存储 | 请求摘要、重放/UNKNOWN策略、引用/profile authority、分页与部分原生文件发布已有 HIA 策略 | SQLite/WAL、schema/transaction/锁/持久性、context、budget、proof、evaluate/adopt/rollback/lease 等业务仍未全部迁移 |
| Worker | HIA 负责部分请求/模式/错误/报告控制和单次效应确认 | 普通服务、SQL、机械外来对象、安装、IO 和部署的完整所有权仍待闭合 |
| 安装、构建与测试 | 已有显式源/镜像绑定、部分真实安装回归与原测试修复 | Python 构建/生成工具341个、Python测试467个仍存在；干净机器 native-only 引导、默认启动及完整回归尚未闭合 |
| 证明与资源分析 | 13个生产模块涉及Core/机器/LLVM模型、Z3义务、scope和资源分析 | Python仍拥有语义与证明控制；原生生成器通过不能替代这些独立依据 |
| 变换与优化 | 16个生产模块承担候选、搜索、识别、guard与独立校验 | 即使输出是HIA程序，变换决策和验证编排仍未全部HIA化 |
| 运行时与生命周期 | 25个生产模块承担VM、缓存、代际/lease/队列、自适应选择与代价/清理 | 原生payload执行不等于调度、所有权、预算和失败清理已迁移 |
| 其他目标与对象检查 | 6个模块包含LLVM/AArch64与ELF/COFF/Mach-O检查 | 现有支持范围保留；不得仅完成x86路径便删除其他目标 |
| NDU 与 Rust 接口 | 15个NDU模块及3个Rust reference/byte-DAG接口仍有原实现 | 需迁移Rust算法和进程会话协议，不能把native binary等同HIA源码 |
| Rust 与外部运行时 | 当前 Hepta 树含48个 Rust 文件；另有先前 hepta-runtime 源码审计 | 外部已部署执行体的实际身份与迁移未核定；不能凭主仓库源码重写删除外部运行时 |

### 公开调用边界的具体含义

当前 acffa 的 `_Emitter.__init__`、`ordered_blocks`、`wrapper`、`render` 与 `_emit_program_machine_with_encoding` 仍属原 Python 控制。后继发射器 v2 的源码和结果不能倒填为 acffa 已有能力。相同原则用于 file-read、JSON pretty 和 TimSort 等独立工作。

CLI 的 `output_json` 仍调用 `json.dumps(ensure_ascii=False, indent=2, sort_keys=True)`；`publish_json_view` 使用不同的 ensure_ascii/allow_nan 条件并带文件系统语义。新 HIA pretty 仅消费已经被上游接纳的 compact JSON，保持键顺序和词法文本。它没有获得任意 Python JSON 值域、无限输出、非有限数值或 foreign subclass 的等价性证明，因此不直接改默认入口。

AgentStore 六模式 authority 和分页策略不包含整个数据库所有权。仅凭 HIA 决定 SQL 文本和参数，不能声明 SQLite 事务、WAL 耐久性或 service 业务已由 HIA 替代。当前整个 AgentStore 以及所有 business action 的旧实现保持必要。

## 3. 当前真实运行与失败

产品提交仍是 acffa9262；草稿 [PR #888](https://github.com/TrillionniumFoundation/Hepta/pull/888) 没有合并或默认激活。

| 原始运行 | 已确认现象 | 状态解释 |
| --- | --- | --- |
| [43117621509](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43117621509)，push | source job 130849576940 通过401项；native job130849577269在第38步原51 ELF callers门退出1 | 原始失败保留；不能用此前组件通过覆盖 |
| [43117632066](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43117632066)，pull_request | source job130849612900通过401项；native job130849613150同门HOLD/退出1 | PR checkout 9796578 与 acffa 为同一22a源码树；失败同样保留 |
| [43119431198](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43119431198)，独立后续push | source job130855795285成功，native130855794913同阶段失败 | 独立第三次观察，不擅自扩入固定两份历史产物恢复请求 |
| [43128015294](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43128015294)，只读历史产物恢复 | 原两份约600MB产物已在独立900/3所有权内读取；成功产出35,868,688B小包 | 仅证据恢复成功，原产品失败不重分类 |
| [43132079819](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43132079819)，原件帧读取 | 唯一create/attempt1已确认，当前queued | 读取既有小包的固定23目标，不重跑原CI；完整原报告尚未到达 |
| [43131161021](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43131161021)，发射器source authoring | 唯一create/attempt1已确认，当前queued | 只生成与公开Core检查新39单元，不执行原生编译/VM/callers/cold |

恢复产物 ID13905131691 的 ZIP SHA256 为 `0bdd2c0eb471e21cee980e00c397f5fa2e2e681dcdc16cadec2174798bf2412d`。原 FINAL SHA256 为 `a0c87bc6fee4dec1bf8acf995aab6634e56b8f8afa5cdd19638d3329ff0a0fef`。这些身份已由官方 artifact metadata 和完整原 job log 核对；它们还不是内层51调用错误的读取证明。下一步以固定帧的整文件大小、SHA、偏移和 END 完整性确认原字节后定位代码。

Core 三组 12+51+50 的历史开发实际结果保留为113个测试、3799403步。三次独立 phase wall 合计235.768049677秒、owner合计252.133646551秒，因此不能描述成一次180秒的完整资格。只读汇总本身自然结束也不能重跑或加速历史测试。

TimSort r3 的原 h 启动与一次同键对账均未返回 job id；有限元数据检查没有提供完整时间覆盖。状态继续是 **UNKNOWN_NO_JOB_ID**。不以新键重发，不根据某一时刻 FileNotFound 断言旧操作从未启动。

## 4. 尚未改变的硬门

最终原生交付必须在最终实际源码身份上满足原冷启动180秒、2 worker、全部38 phase；完整 retained discovery 5400秒及外围10800秒；原调用3/5秒预算；逐项实际 loaded/executed test ID、零失败/错误/跳过/预期失败/意外成功。开发子测试、分组通过和静态声明均不能替代它们。

编译器上限继续为源1MiB、16384行、8192操作、全局1536块/每函数256块、每函数2048个唯一SSA名称、128函数、16参数/边参数。新源码通过拆组件和减少重复解决规模，不能抬高这些门以获得通过。UNKNOWN mutation acknowledgement 不得换键重试。

旧整套的删除前提是每个生产、公开API、构建安装、运行时、持久性及测试所有者都有完整HIA替代，旧业务实现被禁止时原精确分母仍成功，并完成最终整套源绑定资格与实际默认入口核验。当前这些前提没有成立，所以没有执行旧栈删除，也没有把任何 FAIL/HOLD/UNKNOWN 写成 PASS。

## 5. 本轮继续工作的顺序

先从已保全的原件恢复51调用门真实错误，并完成对应源修复；并行完成新Core发射器39源与新JSON布局的实际开发运行。随后将剩余公开入口/foreign行为/安装资源补齐，形成统一产品候选并运行原精确门。AgentStore完整业务/耐久性、CLI十五动作、工具链及外部运行时继续各自按实际输入输出与失败语义推进。只有最终闭合后才进行旧实现退出与清理。

这是一份当前状态和缺口审计，不是完成交付声明。后续结果应追加自己的源码、运行和原件身份；本报告固定的失败和待执行状态不被追认改写。
