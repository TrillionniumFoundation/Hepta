# R19 生产执行链与旧实现删除前提：只读审查

## 结论与范围

固定输入是 `v116-union-r19/source`，3175 个文件，登记树 `ab0514765fc819b921557b9d857a9a13a1a4f48b`。本次只读实际启动代码、关键调用体和相关原文；没有导入产品、执行生成器、编译、VM、原生程序或测试，没有修改源树或 refs。随附 `EVIDENCE.json` 对引用文件逐一核对原 `SOURCE-MANIFEST.json` 的完整 bytes、mode、SHA256 和 Git blob，并保存关键源码原文；没有声称重新独立核遍全部 3175 文件。

**这套候选已有真正由 HIA 执行策略、以及可以由内核直接执行的独立程序；普通安装入口和完整 Worker 服务仍有实际 Python 与外部运行时依赖，旧套目前不能删除。** 三种事实需要分别登记：HIA 已接管哪些策略；Python/C/内核端口实际还执行什么；原完整公开域与当前新 profile 的差异及资格是否闭合。

R19 中的 `docs/HIA_NATIVE_REWRITE_INVENTORY.json` 仍是 3120 项的生成 seed，记录的 Git head 是旧 `f33d8da…`。它自己明确 `whole_native_delivery_qualified=false`、`old_stack_can_be_removed=false`、`live_worker_migrated=false`、未建立动态调用闭包。其 266 个 package modules 和 534 个 hosted tools 是静态分类，不能解释为 800 项未完成业务，更不能以当前 3175 文件作分母计算重写百分比。R19 的 1411 Source 和后继 Native 门禁需要实际终态；本报告不以 authoring 元数据或既有组件通过替代它们。

## 逐条实际执行链

| 执行入口与实际调用 | 已有 HIA 实现 | 仍实际执行的非 HIA 职责 | 删除旧实现前的具体缺口 |
|---|---|---|---|
| 安装的 `hia`：`pyproject.toml` 的 console script → `hepta.cli:hia_main` | 显式选择 CLI manifest 时已有 HIA argument/control/format、发现 JSON、routing、parser context，以及七项 verified report 策略 | 解释器启动、环境及流对象观察、Python 值与异常对象、fixed foreign ports；未选择时仍执行原 argparse 与 Python CLI 主体 | 当前 wheel 明确 `requires-python >=3.11`，默认入口尚未换成独立 HIA executable；必须覆盖完整 argv/environment/encoding/TTY/exception/stdio/退出语义后才能替换 |
| 选择后的 CLI：`CliSession._effect` 的固定端口 | HIA 控制全部十五个 action 的顺序和握手；op9 的七项 report 策略已有独立 owner | op3 `read_bounded`，op10 `inspect_program`，op13 patch，op14 impact，op15 起 edit/batch，文件发布，以及各 callable 的真实 Python 效应 | 选择 HIA control 不代表所有 provider 已迁移。必须逐端口关闭真实策略与效果差异；不能把当前多个 native components 混称完整 CLI |
| 已有独立 CLI/process/file/roundtrip ELF | Linux stdio 固定0/1、process argv/env/fd2、只读 file 能力、capabilities/catalog 进程候选、render+semantic+独立 canonical roundtrip 都有真实 HIA 路径 | 作者、严格构建/监督器、独立 VM/参考 oracle 仍为 Python；具体物理 profile 有自己的固定权限 | 这些独立入口尚未替代所有十五 action 或原 Python API。IO9、TTY/locale、原 E_DRIVER 文案/异常、完整输入域和当前冷链不能由发现/渲染成功推得 |
| 公共 `verify_program` / assembly / Core front | 原 front continuation、Core structure/decoder/canonical/wire/sha 等可显式选择 HIA；各 Linux profile 是单独 verified authority | 默认 Python 验证主体、对象桥、动态 provider/全局绑定、Python 格式化/异常；原全域包括 composite 与版本特征 | 默认 `profile=None` 与显式 Linux profile 权限不能混用。独立 semantic resident 的受限 assembly 输入与完整 public verifier 不是同一接口；保所有旧拒绝、版本和错误先后 |
| 公共 `execute_program` → selected owner 或 `_Machine` | 选择的 program execution/evaluation HIA owners，以及独立 ELF 真实运行 | 默认 `_Machine` 是 Python typed VM；数据对象/owner/loan/heap、解释器事件与外部 effect ports 仍有实际宿主执行 | 对用户可调用 VM 的完整语义、资源/fuel/异常/动态提供者需逐项迁移。用于独立校验的原 VM 可保为 oracle，不能把它的保留混算成部署业务 |
| `emit_program_machine` / `compile_program_machine` / `build_program_machine` | Core lowering/emitter、Code、Plan、Byte、ELF/MachineObject、NativeBuild 顶层策略已有多组 HIA owner；bundle/control 两族保持独立 | Python public scope、admission/custody、fixed foreign CALL/import/context-manager/异常端口；默认原实现仍保留；链接/子进程按选择运行 | 不能写成“后端仍全部 Python”，也不能写成“选了 HIA 就无 Python”。需完成所有使用中的 provider、原完整域与默认路由/安装资格；不混用同名不同 ABI |
| `python -m hepta.hia_agent_worker` → helper scope → report/request → `HIAAgentService.call` | Worker report/request/helper、Service context/requests/evaluation/artifacts/verification/emission、budget/slot/journal、Store lifecycle 等已有 HIA 策略 | CPython 启动/stdio、实际 Service 对象与 catalogue/installation identity、固定 provider，以及请求状态/数据对象和最终输出 | Worker 是单请求 envelope，源码明确不是 MCP。尚未证明完整安装后 worker 可由独立 HIA executable 替代；`hia-native` 的六个 bounded commands 不是 durable Service worker |
| Service → `AgentStore` → SQLite / artifact files | StoreLifecycle 和若干 namespace/journal/budget 策略已有 HIA owner，原公开方法和事务顺序保留 | `sqlite3.connect/execute`、真实同一 Connection 的未提交页与事务、WAL/同步、锁、COMMIT/ROLLBACK；Python 对象与 OS 文件效应 | 冻结的 SQL snapshot 原型没有接 public execute，也没有解决同 Connection 未提交状态，未并入 R19；不能把 snapshot 读核标为 SQLite 引擎替代 |
| MCP startup / preflight → 外部 `hepta-runtime` binary `mcp --runtime-config …` | 本仓有 HIA 工具 catalogue、worker 协议、部分 standalone native worker 资产 | 外部 Rust adapter 担任 MCP negotiation、caller auth、durable job identity、cancel/terminal checking；本仓 Python preflight/客户端负责配置及探测 | 必须显式 exact runtime checkout/revision 与 binary SHA。仓内旧设计 PR/fixture revision 不是当前部署或 binary-build provenance；没有从 R19 可推出的唯一外部运行 head |
| `_installed_json_image` / native helpers / continuation transport | 映射中的机器像执行 HIA；明确的 held owner、bundle custody、source/image、PID/thread、default-None、fail-closed 等契约已有实现 | Python manifest 解码/源读取、mmap/ctypes、对象注册、真实属性/运算/异常/引用寿命及 CALL effect dispatcher；不是空壳字节搬运 | 原源码身份和 runtime provider 能力本身仍由这些对象维持。删除 `.py` 会改变执行与权限，不可仅将 hash 清单改成 native image hashes 就称等价 |
| 自宿主 compiler runtime | `selfhost.hepta` 真实 scanner/type/resource/CFG/call/effect/code-generation 与固定点，B1+不再靠 Python 编译 HIA 源 | `generate_hia_selfhost.py` 是 Python AST→HIA 作者；B0/bootstrap、current-source/cold replay、receipt/进程 owner 和构建发布仍由 Python 协调 | “编译器机器像由 HIA 自编译”已经实现；“编辑/构建/发布/资格全工具链无需 Python”尚未实现。两者不能互相否定或代替 |
| standalone source-build / candidate-build / agent-stdio builders | 原 source-build/55 candidate dispatcher/Agent stdio admission、compile、pack 等已有 HIA policy/packer；运行时可无 Python child | Python production builder 与 matching-cold receipt 准入/发布；部分旧运行时 transport 仍使用明确 `.S` syscall adapters | source-build 原64 MiB/128-member、1 MiB 单 source/image、resident-image 调用和映射域必须保留；新1 MiB stdio/process 原型尚不能完整替代它。`.S` 是明确 CPU/OS 边界，不能改后缀伪装 HIA |
| release install / selection / launch / retirement | 安装、选择、SHA、sealed-memfd launch、bounded retirement state 等真实 HIA policy 已存在；launch 执行被准入并持有的同一像 | 包作者、安装 wheel、cold qualification、当前 loader effect 对象与 syscall/文件发布端口；运行中库/引用的实际生命周期仍有宿主角色 | 选择/字节 hash 不是整套 HIA 资格。安全删除旧套还需要 active generations/leases、跨进程 release ownership、恢复/回滚、no-unknown-effects 的整体证据，不能据单次 cleanup 就删整个栈 |
| Python wheel / sdist installation | 默认210资源＋显式三个 optional profiles 的8资产已严格分离；HIA entry资源不伪造 runtime bridge | setuptools build hook、AST 静态资源组、Python包复制、显式 profile FD读取/安装验证 | 当前交付格式就是 CPython package；可以同时保独立 HIA tools，但删除旧 package 前必须给出真实 native 安装/启动/资源定位替代，并迁移 source/identity/cold 协议 |
| Qualification / tests / audit / inventories | 原HIA image和一些native runners是真实被测对象；已有独立Oracle、Source/Native/cold严格登记 | unittest、Python VM、fault/ptrace observer、process owner、原件保存、Git/元数据脚本 | 这些是检验/作者职责，不是每一次产品业务执行。原测试和失败证据应保留；若“旧整套删除”含开发工具，也须单独替代/归档检验环境，不能通过删测试制造闭合 |
| 显式附加 Rust / solver profiles | NDU 当前仍有真实 original Rust algorithms，Core shadow 是独立检查器 | Rust NDU APIs/adapters、可选 Python proof/optimization/solver providers | 不是默认 `hia` 的必需依赖，也不是 HIA 实现。若最终产品仍保留这些附加功能，必须逐 profile 迁移或明确排除；本轮没有重新资格它们 |

上述矩阵的源码依据分别在 `pyproject.toml`、`hepta/cli.py`、`hia_cli_native.py`、`hia_program{,_runtime,_native,_selfhost}.py`、`hia_agent_{worker,service,store,contract}.py`、`hia_native_helpers.py`、`hia_json_preflight_native.py`、`hia_front_{runtime,continuation}.py`、`tools/hia_candidate_preflight.py`、`tools/qualify_hia_selfhost.py`、相应 builder 与 docs；逐项 hash 和关键原文见附件。

## 必须保留的两种依赖

执行依赖与身份依赖不相同。`checker_source_identity` 对生成的完整 custody closure 加 mechanism/consumer sources 每次重新读取；`installation_manifest` 对实际安装的所有 hepta Python 源、默认十二组资源和 backend/helper 身份进行绑定。即使某个文件只剩参考分支，当前合同也可能仍把它的字节作为准入输入。直接删除文件、缩小 source inventory 或把未闭合 provider 改叫“机械端口”，都会改变当前证据与许可边界。

也不能反向把所有 source pin 都当业务执行。`generate_hia_*`、资格 runner、unittest/oracle、审计归档脚本通常是构建/检验时运行；普通独立 ELF 的运行时并不因此执行它们。只有沿具体入口出现的 provider 才列入该入口的实际宿主链。本报告没有声称穷举了任意 Python monkeypatch、插件或外部部署造成的动态调用图。

## 下一个可独立推进的最小边界：inspect 报告策略

### 为什么选这一块

R19 `hepta/hia_program_tools.py:inspect_program` 仍是原 Python 函数：动态导入 verifier，调用 `verify_program`，取 `as_dict`，组装 schema/sha/module/normalization/functions/blocks/ops/term 和固定 claims。`function_signature` 深拷贝四个签名字段，并在 v8 路线包含 return_loans 默认。实际消费者不止 CLI：`CliSession._effect(10,…)` 调它；ServiceRequests 的 `_hia_inspect(view='summary')` 也通过固定 import/foreign port 调它。

这些调用已经真实接通；没有找到 `selected_inspect`、inspect manifest 或独立 inspector owner。Surface 确认其已封的 op9/report owner 没有占 inspect。它与 Native 的 R8 词法缓存、Roundtrip resident、Surface 的 Native 门禁/qualifier 后继互不重叠。

### 拟实现接口与权限

1. 在独立新目录建立显式 inspector HIA continuation，复用已存在的 frame/claim/ACK/异常交付/retirement 机械协议，HIA owning `inspect_program` 和该调用内部 signature 构造的完整顺序。保持未选择默认行为；不修改 R19。
2. 输入仍是原 `document` 对象；返回仍是原 live dict/list/object graph。verifier、as_dict、deepcopy、普通对象/容器/属性/调用能力是显式 provider，不把独立 binary semantic resident 冒称全公开 verifier。
3. 固定可审的原定义/命名空间与 provider anchor；修改过的 callable/descriptor/global 不能误入原定义的 HIA 路径。若保留 foreign compatibility，明确是原 Python 动态域仍在执行，不能据此宣称整个接口无宿主。
4. `function_signature` 另被 patch 接口调用，本组件不得靠整文件覆盖改变 patch 的默认策略。可让 inspect 的 exact original-definition 路径进入同一 HIA 签名子例程，动态替代函数仍按原调用观察；不能悄悄内联并跳过可见替换。
5. 不增加 fd、路径、写入或发布权限。CLI inspect 原 parser 不接受 `--output`；不得借 normalize 的 publication 协议给 inspect 新增写能力。

### 需要逐项保全的语义

- verifier 动态导入和调用先于 `as_dict`；原失败不创建后续报告；对已经 verified 的输入也遵从原 verifier 的实际行为。
- dict 展开/插入顺序与 schema 判断一致；`input_sha256` 的 `getattr` 默认表达式仍会先求值 `verified.sha256`，不能优化掉可观察的额外属性访问。
- `normalization_report` 缺失/存在、v8 return_loans 缺失时的 `[None] * len(returns)`、显式 return_loans 的深拷贝、非 v8 不添加该字段均保留。
- function signature 字段深拷贝；blocks 的 params、term 和 operation 展开产生的浅引用关系按原代码保留，不将全部统一深拷贝。
- 每个 operation 的 `{"index": index, **operation}` 合并语义及 key 顺序保留；不擅自做不同的 sanitize。
- verifier/as_dict/global function_signature/deepcopy 的异常类型、对象、原因链、首次错误顺序和已发生效果不重放。normal return、lost ACK、外部 BaseException、重入和 held traceback 分别检验。
- 原完整 verifier 接受域不偷偷缩成 v6-v8 native-file-render 的有限域；验证器自己仍是独立 owner/foreign boundary。

### 原验收入口和新增控制

保留下列原方法完整字节和 IDs，不能借只跑几个新示例替代原入口：

- `tests.test_hia_program_tools.HIAProgramToolsTests.test_cli_verify_run_inspect_and_patch_need_no_rust_or_high_level_source`：原 `tools.hia_core_reference` 的 verify/inspect/run/patch，原20秒子进程界限。
- `tests.test_hia_agent_entry.AgentEntryTests.test_assembly_roundtrip_uses_only_core`：实际安装式公开 hia 路径 verify/import/check/inspect。
- `tests.test_hia_cli_native.CliNativeTests.test_all_fifteen_real_actions_and_publication_branches`：现有 HIA CLI op10 在完整十五动作/发布分支矩阵里，不能删其他动作或改其原预期。

新增 exact-ID 控制应覆盖 verifier/as_dict 的真实调用次序、sha 默认求值、deepcopy 与 shallow alias、v8 loan defaults、mutation/descriptor/global 替换、原异常优先级、claim/ACK 消费一次、full frame 原生/独立VM对照，以及显式 selector 的缺源/空值/错误 identity/installed wheel/matching-current-source cold。现有七 report owner 与所有原43 CLI 方法保持完整，不把新 inspector 通过迁给它们，反之亦然。

此切口完成时可陈述“inspect 报告策略由 HIA 控制，现有 public callers 实际进入该 owner”。仍不可陈述“完整 CLI/Worker 无 Python”或“旧整套可删”。后续真正 standalone inspect 还需要将已验证 program/report 数据表示接到物理入口，补齐原 JSON/错误/encoding 域；它是另一条明确的组合工作。

## 删除旧套的可审核条件

| 删除对象 | 现在为什么仍需保留 | 可删除前必须有的实际替代与证据 |
|---|---|---|
| 默认 Python CLI 与其 provider | 默认 console entry 就执行它；选 CLI 仍调用多个 provider | 原全部公开动作/参数/环境/流/文件顺序/错误输出和退出码的独立 native entry，实际打包/默认切换后完整原控制 |
| Worker/Service/SQLite 栈 | 实际 durable request、same-connection transaction 与状态生命周期仍在其中 | 原 MCP/worker 协议、事务/取消/崩溃/observe-original/identity 的全链替代；真实外部部署和冷构建绑定 |
| Core/VM/backend 参考实现 | 默认路径与动态 compatibility 会进入；独立 oracles 还用于检验 | 区分 production dispatch 与 oracle。先消除生产调用并保独立等价证据，再决定参考实现是随开发包保留还是归档 |
| Python loader/continuation foreign layer | 源/映像准入、对象协议、异常、引用寿命、owner 能力真实执行 | 明确新的 runtime object/effect ABI 与完整 owner/exception/retirement 资格；仅序列化 hash 不等于可执行 capability |
| Python 作者/构建/发布工具 | 当前新增源码、cold/receipt、wheel/发布都通过这些工具 | 真正 HIA author/compiler/build-manifest/package/publish 链，包括固定源到实际像的来源证明；B3 fixed point 单独不够 |
| 旧 `.S` adapters | 若当前 native entry 仍链接它，仍是运行期 CPU/OS 实现 | 用明确 HIA primitive/packer ABI替代并保原64MiB/1MiB/权限/错误/lifecycle域；不能改文件后缀或嵌整段opaque code |
| 原测试/资格/审计原件 | 当前结果可复核与防退化所需，不是未重写业务数量 | 保存不可变原tests/failures/receipts/完整buffers；若迁测试工具，保持独立oracle和严格ID/预算，无skip/伪PASS |

本次不授权任何旧树删除或默认切换，不把 R19 的准备状态、已有 Source 通过或独立组件开发通过扩大为整套 Native 完成。
