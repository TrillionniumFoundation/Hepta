# 固定生产链与下一组 HIA 策略替换

## 结论

下一组应只迁移 `hepta.hia_program_tools.apply_program_patch` 与 `_check_patch_interface` 的完整策略：原导入、两次公开验证、已存在的 patch 准备调用、接口比较、receipt 构造与返回顺序。保留已有 `selected_prepare_patch` 和 `apply_candidate_patch` 的 HIA 实现及真实默认分支，不再实现一份 edit/JSON/byte-patch 引擎。

这组直接覆盖 CLI op13，并成为 impact、单点 edit、batch edit 的共同内部调用。Service 的原 patch 分支也调用该公开函数；显式 `HEPTA_HIA_CORE_PATCH_MANIFEST` 分支已经走 HIA candidate/diagnostics 字节管道，必须原样保留。策略替换完成仍不表示 SQLite、外部进程所有者、整个 Worker 或完整 CLI 已不依赖 Python。

本报告只有源代码、Git 对象与原测试清单的静态读回。没有产品导入、生成、编译、VM、测试、CI 或 ref 操作。Inspect R3 的后来实际结果另由其原件定义，不能转移成本报告或拟议 patch 组件的资格。

## 准确谱系：125 不属于固定 default

| 固定来源 | 实际 tree / 文件 | 本次观察 |
|---|---|---|
| Hepta R20 产品 `26fd6c4c1a71dc970ae11b00c8a9ff74c5c8508d` | tree `84df4b42f1e20fd7d0c7229e658cf3b458984ffb`；actual manifest 3177 项 | 所选 29 个完整文件逐 bytes、mode、SHA256、Git blob 与实际 manifest 相等，并前后 stat 相等；没有声称重新执行全部资格 |
| hepta-runtime PR121 固定 `008036843625e12c21b6dc533be5cf3115cda579` | root `460e5be584ae0c732c0e6eec1b6cb31512e875bd`；server blob `90fe15fd6a998e9b165739bc27e6f3854022221d` | server 实际 125 个 `#[tool] async fn`，名字及顺序与该头 migration.json 的 125 条完全相等 |
| hepta-runtime 固定 default `ba574f2a6a1b74e85191c58d7bec011720736bb9` | root `fe987c3d37e721e558be5a72890e52d52bf8d5ea`；server blob `485b57d99286a93142b17c7c92fbfe2c897751e0` | server 实际 22 个 `#[tool] async fn`；不是 125，且该 server 没有 HIA 11 个工具 |
| Root 先前只读审计 `d368a87fe52f33461b3f418ebe8e7dd8dee63bd7` | 完整原 blob 实际 GET 并核 Git identity | 保留其固定观察域，补正“125 属于何头”的使用范围；未刷新任何分支头 |

固定 PR121 的 125 条声明分类为：HIA Agent 11、filesystem/control 28、durable requests 10、hosts/processes 24、reverse engineering 34、weights 9、documents 9。它们的 migration 字段均为 `not_ported` / `native_owner: null`。这是固定 inventory 与实际入口名的对应，不是本次对每个 handler 的完整动态语义证明。默认 22 个实际名字以及 PR121 125 个名字已全部保存在 `EVIDENCE.json`。

没有读取或推断部署中的 binary SHA、发布切换或最新分支头。若以后读取新头，必须另列新来源，不能修改这里的固定事实。

## 跨仓真实生产调用链

### MCP 到 Worker

PR121 `src/main.rs::run` 在 `Commands::Mcp` 下读取 `RuntimeConfig`、初始化 runtime，并启动原 Rust STDIO/HTTP server。`src/mcp/server.rs` 的 11 个 `hia_*` handler 进入 `OctofsServer::dispatch_hia`。它先消费 session/workdir 和 owner binding，再验证 input；随后调用 `hia_provider::execute`，最后经 `hia_contract::wire` 返回。

`src/mcp/hia_provider.rs::prepare_request` 读取管理员 `hia_worker` profile，核安装 worker/backend/catalog digest、host/root/资源条件，保留捕获路径规范化。构造的实际命令是 profile 的 `python_executable` 加 `-B -E -s -m hepta.hia_agent_worker`，state/artifact roots、三安装 digest、可选 native-helper manifest/digest 和 `--request-json-stdin`。请求身份与原参数相关，mutation key 不因更换 payload/profile 自动变成另一个执行。

`execute` 先 `crate::native::observe_request`；不存在原绑定才进入 `execute_or_observe_with_entry`。`src/native.rs` 实际只是原 Rust jobs owner 的 facade：对应 `jobs::observe_request`、`jobs::start_job_with_entry`，不是 HIA process owner。完成时必须绑定原 job/request/output 和 Worker report。终态未知、输出不完整或 identity 不符只返回原操作的 pending/unknown；不能重放效果。

R20 `hepta/hia_agent_worker.py::main` 仍由 CPython 和 argparse 启动，首先进入 `native_helpers_scope`。未给 bundle 时该 scope 明确 `yield None`，不自动选择 HIA；已有 ambient selector 也会拒绝。显式 bundle 才安全读回并设置其已固定 selections，终态恢复全部 selector 命名空间。`_run` 选择 WorkerReport owner，否则走 `_reference_run`；请求验证后实际构造 `HIAAgentService`，调用 `service.call`，在 finally `service.close`，再执行安装 identity 的完整后检和 report 发布。

因此 HIA 字样的 MCP 工具不等于 handler 全由 HIA 实现；同样，已有 HIA WorkerReport/Request/Service 等策略不能被描述为仍全部 Python。当前公开默认路径和每个明确选择的策略域必须分开。

### Service 到 Store

`HIAAgentService.__init__` 会捕获多个可选 context/emission/verification/evaluation/requests/artifacts/proof owners，建立 catalog 与 installation identity，再创建 `AgentStore`。`call` 根据实际 journal 选择执行 HIA journal 或原 `_call_reference`。原分支会在真实 transaction 中检查/写 request intent，完整 validate/fresh installation 后才分派 `_hia_*`，最后写 costs 与精确 response；adopt/rollback 效果与 response commit 保持同一 transaction。

`_hia_inspect` 的 summary 仍通过捕获的 `inspect_program` provider；此次在途/刚完成的 Inspect owner 以及作者 op10 adapter 是独立后继，R20 公共字节未改。Requests owner 控制其外层方法，但其固定 CALL port 仍真实调用 provider；不能因为外层已 HIA 就跳过这个内部策略。

`AgentStore` 有 HIA lifecycle、namespace、journal、budget、slot 等选择点，但原初始化仍实际 `sqlite3.connect(..., isolation_level=None, timeout=10, check_same_thread=False)`、`PRAGMA journal_mode=WAL`、`PRAGMA synchronous=FULL`，并持有同一 connection。transaction 原顺序是 RLock → `BEGIN IMMEDIATE` → body → `ROLLBACK` 或 `COMMIT`。已选 HIA namespace/journal 通过原 connection effect ports 执行同一 SQL；它们不构成新的 SQLite 引擎。此前未接公共 execute 的 snapshot 原型也不在当前生产链，不能读取外部 snapshot 来代替 connection 内未提交页。

### CLI 到 patch

`pyproject.toml` 的 `hia` console script 仍是 `hepta.cli:hia_main`。未选择 `HEPTA_HIA_CLI_MANIFEST` 走 `_reference_hia_main`；明确选取后由 HIA parser/control/formatter/discovery/report 组合管理流程，但 `CliSession._effect` 仍真实调用诸 provider。op35 的原两次 from-import 捕获 `apply_program_patch`；op13 在原位置取该 callable，先求 `value(a)`，再求 `argument(b,1)`，随后调用并解包两返回值。

op14 的 `analyze_patch_impact`、op16 的 `apply_edit`、op18 的 `apply_batch` 又从各自模块原绑定调用公开 patch。它们有自己的先前验证、上下文重建、预算和后置 receipt 扩展，不能用新 patch owner 合并或删掉这些步骤。发布 op19/20/21 在后续独立发生，不在拟议 owner 中加入文件权限。

## 相邻 native-local 实际闭合到哪里

在固定 PR121 server，`host_list` 仍调用 Rust `runtime::inspect::host_list` → `cached_host_list` → `render_host_list`；它读取原 immutable configured hosts 的完整公开投影。`binary_read` 仍调用 `runtime::binary::read`，经 host/operator/path/longest-root policy，再走可选 observation pool 或 `rpc` → `run_python_json`。原 descriptor helper 对每个请求有自己的路径重新打开语义。

独立 `native/local_service.hepta` 确实有 HIA `host_list` 和 `binary_read`，但其已声明域是管理员启动时固定的 native-local Linux readonly root。它并未替换 server 上述两条 dispatch；其 lifetime-held root 与原每请求 pathname reopen 明确不同。完整 SSH/configured hosts、HTTP、PTTY、durable request/process ownership、document/weight/REA handlers 都不能从该两动作成功推出完成。Migration 中所有 14 个 native components 自己也标 `legacy_call_sites_replaced: false`。

## 最小下一组：公开 patch 策略 owner

### 所有权界限

新独立 owner 的两个原策略入口为 `apply_program_patch(document, request)` 和 `_check_patch_interface(original, verified, interface_policy)`。完整原体位于 `hepta/hia_program_tools.py`；冻结 blob `f2f0d5aebc1edb924bc584046c837b8493a12609`。可复用 Inspect continuation 的 generator/control/foreign-port 机械架构，但不能借它的 image、host pins、Native/VM 结果或 token 签发范围。

`_prepare_program_patch` 是保留的真实依赖：未选择时走现有 Python 完整行为，显式选择时走现有 HIA patch/admission。原 Agent `apply_candidate_patch` 已让 HIA 生成 opaque candidate 和 diagnostics，且两次原生完整准入；该分支不接入新公开 receipt owner。`function_signature` 也已有独立 Inspect HIA entry，可用其真实 `invoke_bound_signature` 复用，只有实际原定义/已准入域才进入它；动态 provider 仍调用一次。若最终选择不包含该已有 owner，则 signature 是明确 foreign dependency，不把它写成新 HIA 成果。

### 必须原样保留的步骤

1. 函数内部原 verifier from-import 仅发生一次，得到的实际 provider 用于两次调用。原 document 验证结束后才调用现有 prepare；prepare 完成后才验证 candidate；第二次验证前不得比较接口或建立 receipt。
2. `_check_patch_interface` 的两次 `as_dict`、functions 顺序、两次 comprehension、动态 signature callable 解析、`include_return_loans=True`、set union、排序、dict.get 比较均保留。changed 且 policy 非 migrate 时，只列前8名字并按原消息 `_reject`。
3. receipt key 插入顺序、实际 `original.sha256` 的重复访问、`getattr(original, 'input_sha256', original.sha256)` 的先求值默认参数均保留；不做“相同属性只读一次”的改写。
4. v1/v2 receipt 区别、`verified_unpublished`、whole rechecked、behavior/native/external callers 的原非声明全部保留。HIA owner 自身执行也不能把原业务 receipt 的 `native_executed: False` 改成 True。
5. 任一 verifier/prepare/signature/attribute/provider 异常原位传播；不重试、不重新读取 request、不产生半个可发布 candidate。保留实际 aliases、返回 verified 对象身份和可变 receipt，供 edit/batch 原 caller 后续扩展。

### 接线分两步，不混同准入

第一步只做独立真实 HIA owner 和原入口差分：两原函数完整模板/逆投影，原 ports 捕获和 physical busy/claim/ACK/retirement 协议，真正 image 与完整 F/O/W。调用者显式准备它，不改默认公共函数。

第二步才做 `invoke_bound_patch(provider, document, request)` 的私有 CLI adapter：消费 op35 原 IMPORT_NAME/IMPORT_FROM 的 operand witness 和预先独立成立的 patch 定义记录；记录不能从本次 operand 自签，不能拿 inspect token 充 patch authority。op13 必须保持 provider lookup → document → request 的原求值顺序；状态变化/未知 callable 原 foreign once，进入真实 HIA 后异常绝不 fallback 重试。原 op10/report/discovery/parser 六映像闭包仍分别绑定。

Service 的后续接线只能在 Requests 已捕获 callable 的实际 CALL 点加入显式新 profile，或在公开显式 adapter 入口选择；不可全局替换模块函数、重复 import/getattr、把已 bound foreign CALL 当身份凭证。只有该特定后继完成原 Service caller 控制，才能说 Service 的公开 patch 分支也进入新 owner。

## 验收与尚未执行门

`PATCH-POLICY-PLAN.json` 保存原策略全文/pins、原测试全部 IDs、原 CLI43 清单与拟议控制，不执行任何一项。至少保持原 HIAProgramTools8、HIAPatchImpact9、EditQuery12、HIAEditBatch14、CorePatch16、AgentCandidate9、ServiceRequests16 的全部方法字节；这些是 AST 发现方法数，不是这轮已运行或最终注册分母。原 CLI43 两源及 IDs 不能剪裁。

新的控制必须有真正 HIA 正路径；仅 wrapper/fallback 不算通过。覆盖 import/provider 次序与替换、v1/v2 和 returned loans、interface排序及首8、错误/alias/ref-lifetime、selected prepare 有/无、Agent native 分支不变、同 frame/service reentry、lost ACK/unknown/close、完整 Native/VM 三 buffer 与 canary。原预算和权限不增：编译20秒/1MiB，VM每次10M，受原180+3 owner；生成数量/ops/image尺寸需实际产生后再报告。

所有新源、generated ports、资产和安装 profile 必须独立登记；禁止静默扩大旧 worker210/ENTRY19/NATIVE92 或把外层3191开发闭包当6像独立安装/current-cold。完整 cold、原始公开 caller、真实轮包与缺失/漂移负控均是未来未执行门。

## 证据与读回限制

`EVIDENCE.json` 含29个选定R20原文件全文、13个固定远端原blob全文、10个完整Git tree对象的重算、两commit实际GET、全部测试方法清单与源前后stat。没有穷举任意 monkeypatch/plugin 造成的动态调用图。第一版捕获脚本猜错 discovery 文件名，真实只读失败在输出前，原script/trace保留；R2仅改为实际 `hia_cli_discovery_routing_native.py` 后完成。另一次只读猜错 retained fixture 的父目录，随后通过 rg 找到 `tests/fixtures`，原错误登记在计划 authoring history 中。无产品失败被重标。
