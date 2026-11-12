# HIA 全量原生重写审计（2026-11-12，FOLLOW37）

## 当前结论

**整套仍为 OPEN。普通补丁协调器已有完整独立 CI 通过；Function、wrapper 和命名空间若干域已有明确进展。完整 Emitter、Worker、普通 Store/SQL、安装与全部公开入口仍未闭合。当前生产入口仍依赖 Python，本提交不激活新生产入口、不删除旧实现。**

本轮基于父提交 23c0d3a3e8ea11d2c6fa1286623b2cfeba1d359f，完整树 d46b8640f48e8c8d41cdcdf55a59a112c0c078b2。独立完整基线始终固定为 0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5，树 6ef9e1713065436a3b1886fe9edcf0a4a1120773，共2,798文件。最终新增/恢复文件身份见本提交 ci-followup-r37/publication-manifest.json。

本地计算环境在本轮工作中容量耗尽，随后正式 unavailable。失联前未取得终态的任务保持 UNKNOWN，不重放或推断成功。已落入 Git 的源码/证据继续用于独立 CI；尚未完成封包的本地记录不被描述为完整可恢复证据。

## 全量盘点与恢复出的真实缺口

对完整父树的只读审计实际读了5,025文件、558,946,765字节：1,917个Python文件中1,914个可解析，153个生产Python模块均可解析；另有60个.hiaasm和12个.hia。全部原始Git blob、模式、SHA256在读取前后相等。3个历史语法错误被逐项报告并保留，不通过删除历史失败来获得通过。

完整9,445,685字节本地静态清单的SHA256为 e0df484a5318eec4aaf73bfc082aca13dc352a9ad7bafb06df4dc7c252b2926d；该大清单尚未取得持久化回读点时环境离线，不能据此声称文件目前可恢复。新CI审计会重新生成完整清单和全部生产模块投影。静态解析不等于逐函数语义审计或完整HIA替代。

随后对照完整基线，发现非review-evidence树有48个缺失文件和51个被修改文件。本提交精确恢复48个缺失文件和50个被修改文件，保留恢复分支已有的进程dumpability修复。恢复内容包括：

- Worker请求、Agent日志、composite outer三个已经存在的原生适配模块，以及相应HIA源、构建器、安装资源和测试。
- 动态链接ELF观测器、调用图固定点提前收敛优化。
- JSON前置诊断、构造/外层生命周期和完整原始测试工作流。

恢复后生产包为156个Python模块。这是恢复覆盖范围，不是减少原生工作量或宣称完成比例。未归因于任何具体删除者。

47项原始源生成器在独立副本执行完成；生成合同检查通过，另13项所选恢复源控制通过。这些是本地观察。保留的allocator child文件SHA256为 c40e809af7d213daacb2bf066b5177784aa09c9b5c1b528ee76353b1e5c4fb9e；再生合同Git为 e6da630f6244f3c227ba2541f8a5e8e68b1c239d，129,034字节，SHA256为 d684f22bcfe86be1d359aef9c30307d316fd1136a14d2795d0f203070682b139。环境离线后从基线合同精确重建，身份与先前实际再生文件相等。

pyproject.toml仍使用setuptools、Python >=3.11，hia入口仍为hepta.cli:hia_main。当前交付不能被称为全量HIA原生整套。

## 原始4,157项完整回归仍为 FAIL/HOLD

原始结果是 **4,157项、187 errors、1 failure、18 skips**。原始压缩包Git为 2aae1a9fc536d476cf02f32d40b7c3a34335cf34，666,816字节，SHA256为 5595532d3fc1d8e8b5021236b30217b85ec53a1452d4b23a98b378996e67cee5。124个原始归档成员已完整回读。

| 原始异常分组 | 数量 |
| --- | ---: |
| 旧调试桥绝对路径不存在 | 1 error |
| 有界普通文件读取失败 | 19 errors |
| 无法以no-follow打开原生工件 | 2 errors |
| raw-model release/hia-ndu-bridge不存在 | 155 errors |
| raw-model target不存在 | 10 errors |
| 预期native evaluator failed，实际文件读取失败 | 1 failure |
| 缺实际native NDU bridge路径 | 14 skips |
| 缺实际Z3与固定native NDU build | 4 skips |

全部187个错误与1个失败的原始异常链包含ENOENT。造成依赖消失的行为主体仍为UNKNOWN。原结果不因新组件或读回器通过而改变。

原完整执行器是20,328字节、28步骤的版本，Git为9bf24a8b81f26b86ee250c48066f0ce3232b9b35。本提交将其原字节复制到ci-full-retained-r1/run_original_retained.py，并保留原相邻workflow_process.py。完整discover仍要求加载数等于执行数，errors/failures/skips/expected failures/unexpected successes全部为零。完整回归5400秒和冷启动180秒内部门均未修改。

新增独立CI重新构建六组NDU桥，保留固定源码、原Cargo锁与真实原生身份；配置Rust 1.90.0/1.95.0、固定Lean/QEMU、Clang20、Boost1.83及原Python包版本。原prepare观察器必须实际READY才能启动原完整执行器。构建前后完整源码不变、实际工具/二进制hash与全部stdout/stderr均保留。新准备/流式封包脚本是在环境离线后从已审草稿重建的明确新版本，必须接受新的AST和实际CI，不能继承旧草稿的运行结果。

即使该完整保留回归通过，也只是完整功能基线通过；全HIA入口及旧实现不可调用时的完整验收仍是另一项必需条件。

## 已确认的真实执行结果及范围

| 范围 | 实际结果 | 仍开放的边界 |
| --- | --- | --- |
| Function35完整降级组合 | 原39组、718例、129私有控制、43,156次native入口；580条成功Code链与4条预期Code错误 | 完整Emitter、公共入口和安装不能继承此结果 |
| 普通patch固定ELF协调器 | FOLLOW36 job131016969400 SUCCESS；原9组293例，293实际native进程，5次新B3和1次原生packer | Python对象输入API、公开CLI、整套patch激活仍未验收 |
| scalar/borrowed wrapper | 原FOLLOW36首组因trap fixture缺code失败，0语义入口；最小fixture修复后本地26组502例/79私有控制/55,083入口通过 | 本地复用原4个B3镜像；新CI须4次重编；182,656原件的本地封包未完成，完整新raw不冒称已持久化 |
| URI/创建模式 | FOLLOW36正式222语义、389协议、8直接边界；1,255 VM =1,255 native，37个C策略调用，2次B3+1次C编译 | 受控provider，实际OS策略syscall为0；不是完整unixOpen或Store |
| 六角色物理链r6修复 | 本地新6角色+1packer B3、33packer、84组三方对照通过；原test10+test12的322次VM/native全缓冲区相等 | 原18项物理门仍待新CI；本地SQLite3.53.1与原CI3.45.1分别记录 |
| Store35 | 原9次B3；5组269例、10,268入口完成；两个90CPU大值组失败 | 失败发生时storevalues/scan/emit没有实际入口，不能将pending文件解释为卡住native |
| initializer/Store组合36 | 原11次B3；effects/catalog/growth共16案、14,298入口完成；semantic前5案完成，第6案未终态 | 原90CPU FAIL保留；新缓存尝试的8案exit0伴随95.352369 CPU秒，预算未解，不能计90CPU PASS |
| 可复用DB描述符 | 新精确C与HIA语料、原32个方法体和8个新组已提交 | 本地40组VM部分运行后环境离线，终态UNKNOWN；新CI须原40+40、900秒聚合门 |

Function独立读回校验了完整ZIP、144,598内层成员、所有39个入口账本、CAS页和计数；没有把逐页核验夸大为再次重建每一个逻辑完整工作区。完整原始日志/摘要及作用域分别保存。

普通patch的失败原因已由新九组实际重跑闭合：收据完成结果在64..95字节写元数据，旧协调器错误要求该区域全部为零。修复严格绑定实际prepare版本/策略/编辑数，约束变化数≤2048；NEED路径仍校零。未改收据内核、执行器、原oracle、原用例或限制。九组数量分别为semantic113、errors58、interfaces48、input67、identity3以及四个各1例的大边界组。完整原工件2,608成员、143,620,345字节已在离线前逐成员核验。

物理r5原FAIL已完整读回：10项完成PASS，test10 error，test12在SQLite WAL链上未完成并出现SIGBUS。第一个确定缺陷是机械载体错误把action按跨call递增比较；HIA会在新call重置action。新载体绑定(call,action)，保留重放门。第二个是测试父进程用Path.read_bytes打开并关闭相同inode，释放其POSIX锁；改为新的只读子进程观察。独立锁witness和真实test12证明父DMS锁保持，前后32,768字节相等；没有修改六角色HIA策略以绕过旧失败。该修复完整本地644文件、174,132,446原字节已封入3,199,908字节Git归档。

Store35两个大值原组完成前沿分别为293/294次入口，属于sequence、registry和merge；两个pending均是最后已完成调用。原fixture把约8MiB字符串复用于7个profile，形成约58.7MB图；原实际profile为字典。后续须分别保留原对抗案例和验证真实profile数据，不能用新正常案例覆盖原FAIL。

robust_open原90CPU失败保留：完整前沿为117个语义例、2,139对VM/native相等；后续协议控制未完成，不能宣称完整gzip或整个域通过。

源码复核已纠正全局 inode/FSTAT 的范围判断：现有六角色 outer 已有全局 dev/ino 索引，j_pre_stat 保存真实 FSTAT 的 request/result，再在注册阶段回送同一结果；注册链没有重复发出该 FSTAT。新增 completed-receipt adoption 是待验证的接口方案，不是已确认双调用缺陷的修复。完整 unixOpen 的描述符复用、创建/只读回退与真实 FS7 仍需接入；verifyDbFile 的后续独立 stat 不在上述单次注册 FSTAT 声明内。精确源码绑定与撤回记录见 namespace-ci/db-global-reuse-r1/single-fstat-scope-correction.json。

## 冷启动与只读审计

FOLLOW34原冷启动完整读回为11/11、38/38阶段，164.068272474秒；FOLLOW35为6/11、34/38阶段，180.164994456秒超时。FOLLOW36 Core source成功、native失败。所有原始成功和失败分别保存。

恢复源码后的新本地冷启动仍失败：6/11、26/38完成，180.414209434秒，返回-9。本地生成的B3镜像为669,556字节，原始镜像、请求和收据均包含在归档中；这不代替整次冷启动通过。完整本地冷启动及13项源控制原件已逐字节封存：2,689归档成员、2,612普通文件、266,536,395原字节；归档22,409,344字节、SHA256为19c0f613dd43da62d1918a5e3cb7d46fe88c5e8b9e8130f8b488e3a6e0f63d6e，以43个有序Git片段保存。归档内容与观测到的失败保持原样。

独立字节校验分支的原 Core 工作流也运行了相同恢复源码：提交 0d6ca7d450128032c7e7dc67a14b370647c47e41、run43178823310 的 source job131049505021 正式SUCCESS，47项再生成、合同检查、git diff均通过，331项源控制在489.709秒完成。native job131049504192 的冷启动步骤已返回success，后续完整native job仍在运行；在完整原件到达前，不推断其最终结论或阶段耗时。原本地冷启动FAIL保持不变。这是校验分支的实际结果，后续主恢复提交仍接受自己的精确CI。

FOLLOW36全树审计读回器在读取Git pack时受原1GiB地址空间限制而失败，未进入AST扫描。新修复只为各Git命令设置16MiB映射窗口和64MiB映射总量，不改资源门、不修改全局Git配置。此前本地含相同修复的版本完成静态与原始失败档案读回；当前精确CI版仍须新的实际运行。

## 最终闭合和清理门

B3保持10CPU秒/20wall秒/256MiB，源/输出/工作区各1MiB。Bootstrap保持128functions、1536blocks、8192operations、每函数256blocks、每block16参数、SSA<2048；不存在额外128operations/block门。公共1024函数与Bootstrap容量分别验收。普通配对原90CPU/180wall/1GiB、物理原900秒聚合门不变。

完整公开入口、编译/执行/存储/Worker、工具链、安装、更新与恢复都必须有实际HIA承接。随后需要在旧业务实现不可调用的环境中执行完整功能、冷启动、故障、平台和安装验收，并绑定可重建的HIA源、镜像、安装包与精确提交。Python作者、现有安装器、机械汇编和当前产品入口仍是待替换依赖。

**FOLLOW37只恢复覆盖、提交修复、保存原件并启动后续验收；激活0个新生产入口，删除0个仓库文件。**
