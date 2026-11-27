# 全 HIA 闭合剩余差距：当前只读审计

日期：2026-11-12。范围：GitHub 元数据、固定源码和已经持久保存的源码/原始报告 capsules。此轮没有本机执行、编译、测试、CI 重跑、产品或审计 ref 修改。

## 结论

目标仍未完成。CoreR4、Emitter、Byte、VerificationR6 和 NativeBuild 已使直接 x64 后端及若干 Agent 协调职责有了完整 HIA owner，但当前产品仍是 4b19af89a766593f7d5f1cc2db256e81aba7afcb / tree 1bc7c90996e1910ad66ba771b0bfee1d5bfa655c；这些后继组件尚不是同一份默认启用、matching-source cold 和完整门禁全部通过的产品。公共规范化、Agent 评估/采用、独立证明引擎、源码/安装准入、进程与对象检查、其他平台、适应性/NDU/队列，以及最终运行时与部署闭合仍有具体责任。

不能把固定 CPython bridge 算成已经消除了 Python 运行时。也不能因为 Python reference body 仍保留，就重复迁移已经完整被 HIA 接管的 primitive verifier、VM、static/heap、nominal 或 Code/ELF/Plan owner。以下清单同时记录这两条边界。

## 1. 精确依据和本轮能证明什么

- 当前 PR889/head 与 main 已通过 GitHub API 读取：产品4b19af89…，main5831f52fada45e076f8f68f198a15c0585e6104f，PR仍open/draft。PR正文是状态记录，不拿其中历史pending句子替代最新原报告。
- 重新读取 exact4b 完整 recursive Git tree：3153 blobs。此前完整源码审计的3153条 path/blob/mode/size逐项与该树相同；576模块记录的Git blob也全部相同。
- 既有完整审计的12个保存块重新读取、验证wrapper/raw SHA与Git blob，重组2,115,385 B gzip；gzip CRC、tar checksum和PAX解释、23个manifest列出的成员全部bytes/mode/SHA通过，另一个成员是归档内manifest。第一次只读tar解析器未实现PAX而明确拒绝，该解析观察被保留；没有改原归档。
- 本轮另逐字读取19份关键源码/合同/文档并对照exact4b bytes/SHA。其余模块的完整结构与分类继承固定前次审计，不冒称这轮重新逐行语义证明。
- 197个生产Python模块、378个tools模块、setup.py共576路径，全部映射到20业务族/工具类别。路径或代码行数不是语义完成百分比，也不证明动态/外部caller可达性已完全穷尽。

当前native inventory列3151文件是有意排除自身和状态文档；实际Git树3153。其git_head=5f7记录的是生成时真实基底，不应伪改成4b来声称新checkout。support的source_identity有963条，cold再加support本身为964条。这几种分母用途不同。

依据：[完整前次审计](https://github.com/TrillionniumFoundation/Hepta/blob/e7ecd135b5f97204292de2b61e6875ffadba1c58/review-evidence/hia-native-rewrite-v78-component-custody-20261112-dda7/remaining-owners/REPORT.md)；[当前support](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/docs/HIA_SELFHOST_CORE_SUPPORT.json)；[当前inventory](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/docs/HIA_NATIVE_REWRITE_INVENTORY.json)。本交付AUDIT.json保留全576路径/Git身份、20族完整映射和所有新旧scope。

## 2. 已有后继：从“仍未迁移”清单中准确扣除

| Owner | 已有实际职责/证据 | 仍不能据此声称的范围 |
| --- | --- | --- |
| Core/Plan R4 | _Function/helper及通用CALL/BoolOp修订；actual3.14新60、124、44三组全PASS。主run因原baseline脚本argv错误整体FAIL；独立补采原R3得到64/120相等、56差异，不能改写原run。 | 默认激活、全输入等价和新联合资格；显式held frame在outer handled exception内finish仍有真实退休反例。 |
| Emitter R4 | 原六方法全部HIA，actual3.14 15+51+50=116。 | 外部对象/进程/出版policy；继承Core.finish的同形源码风险；不能继承到共享后继字节。 |
| Byte final | normalize_exports、emit_wrapper及load/helper闭包，whole-emit捕获owner/absence与proof绑定；独立3.14新增4+原29通过。 | 单独选择不自动选择所有下游owner；其finish有同形源风险，本轮没有执行Byte反例。 |
| Verification R6 | 七个完整service方法加一个lazy frame。actual3.14 12固定机制+2source+43component+原48通过；原7policy零进入。 | proof_contract与独立proof engines、provider policy；其image继承Plan.finish。 |
| NativeBuild | 九完整top-level协调函数和辅助控制。权威run43253621060 success，原114报告实际读取：114/114，129.691 s，source/bundle稳定、旧writer零。 | 本机session99993仍UNKNOWN；对象/ELF/进程/出版及verify等依赖仍独立。选择Build不等于所有子owner原生。 |
| EmissionR6 / Context / CLI39 | 已有HIA service emission/context和CLI动作控制与实际生命周期后继。 | 整个service/worker/installed入口、所有callee和CPython runtime仍未整体迁移。 |
| CallArena4文件 | 实际26/26；原22方法AST完整；两生产窄改保留64/32MiB域；真实旧helper失败保留。 | 不是原六budget失败或原377组的已证性能修复，没有资格转移。 |
| ProofContract当前WIP | 新八roots+八lazy设计存在；恢复包确实有五个完整原件。Build和该恢复native已采用完成flag退休。 | 完整3202源码/generator/tests尚未持久恢复；原40启动前停止；64为失联前观察不可继承。actual3.14 fixed foreign17只有0 HIA / 0 proof-policy，不是完整Proof native通过。 |

固定源码锚点：[CoreR4](https://api.github.com/repos/TrillionniumFoundation/Hepta/git/blobs/440f47786b68dc4b162ee205712aa8eaa0449494)、[EmitterR4](https://api.github.com/repos/TrillionniumFoundation/Hepta/git/blobs/f8f0b3b7d4ceb1ddef035a38fbc1e0454911710f)、[Byte](https://api.github.com/repos/TrillionniumFoundation/Hepta/git/blobs/be62f31a392a9224acfb35ab91012a36cfdcd0df)、[Verification最终handoff](https://api.github.com/repos/TrillionniumFoundation/Hepta/git/blobs/a77c00b6b41209853753b0b627ff8a73e2fe4122)、[Build](https://api.github.com/repos/TrillionniumFoundation/Hepta/git/blobs/c947e457ef02851a16ff04970d047b7a650db44b)、[Proof五原件](https://api.github.com/repos/TrillionniumFoundation/Hepta/git/blobs/ab5097a1bbd93a0bc74266b99b750ebde5d78558)、[CallArena](https://api.github.com/repos/TrillionniumFoundation/Hepta/git/blobs/7649859b7a54984450ede058d73f64565314335d)。

## 3. 当前最短、可执行的后继顺序

### P0：先完成一次真实联合，另修已复现共享finish

把上述已冻结组件的源码、实际HIA资产、selector/cold-builder、普通/held/captured checker、完整五资源组、SOURCE_FILES/MANIFEST以及原caller注册做语义并集。对每个owner固定完整source/image/manifest与已捕获absence；不可用单个selector注册代替全依赖选择。所有生成都针对真实Git checkout，inventory记录真实HEAD/index/worktree，不能造.git或冒future commit。

当前CoreR4的两个finish和Byte.finish仍以sys.exc_info()[0] is None判断是否成功。它会看到调用者已处理的异常。原显式prepare→finish且继续持有frame的实际Core/Plan反例已保存：成功返回7却不退休；普通owner.run本案未证明public leak。Emitter继承Core.finish；Verification继承Plan.finish，是源级可达风险，不是这轮新增机器失败。后继只把这三处改为completed flag，except BaseException复位，finally按flag.close；不额外持有return value，不释放失败/unknown frame，不重放。Byte原版必须先实际复现后才能称失败。全部旧结果保留，新3.14/原组对新字节独立验收。

### P1：Agent评估、cost ledger、采用准入与lease调用

这是Verification/Emission/Build之后最连续、同时接近现有deadline问题的真实policy范围。精确入口：HIAAgentService._hia_evaluate、_cost_ledger、_native、_build_inputs/_build_receipt、_hia_adopt_native的证据准入、invoke_lease。现有_context/budget、Namespace/Request/Slot与execution budget不得重复实现。

_hia_evaluate仍在Python决定baseline/candidate ABI和proof/readback、两轮reference结果、first trap/resource比较、剩余原deadline、normal/trap分组、native claim/run、完整性与improvement结论，以及measurements→ledger→receipt出版顺序。_hia_adopt_native仍先以Python审context/evaluation/proof/build/ABI及net-benefit门，再进入已HIA的slot CAS。把CAS迁过不等于采用policy整体迁过。

最小新owner应让HIA持有这些分支和迭代，固定端口只进行一次原store/runner/object/clock操作；保留绝对创建时间与剩余预算，不更新deadline起点。需原48、namespace35/ledger48原门禁、未知效果/partial publication/实际SQLite、真实完整原始预算case。不能用两项后置诊断PASS替代那六次失败。源锚点：[service](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/hepta/hia_agent_service.py)、[runner](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/hepta/hia_agent_runner.py)。

### P1并行硬阻塞：完整公共normalization和front end

当前verify_program在selected_core_structure之前仍执行_decode和namespace/nominal路由。_decode会处理VerifiedProgram、原dict/list富类型成员比较、字符串/byte界、detached snapshot、_structure、最终json.dumps及内部decode。当前已读生产路径没有把selected_program_normalization接进此入口。

必须保持原公开Python对象域，包括metaclass富比较、alias/cycle、late encoder扩大最终图、int digit policy时点、错误/cause/notes、临时析构和真实递归/活动C栈。不能拿8MiB原始wire、固定深度或bootstrap编译器16参数/3结果上限缩小这个域。完整primitive Core admission、VM和nominal所有已存在的HIA策略继续复用。另需组装文本parse/render、版本namespace/adapters的完整入口。源锚点：[hia_program](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/hepta/hia_program.py)、[normalization声明](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/docs/HIA_SELFHOST_CORE_SUPPORT.json)。

### P1/P2：源码、安装、helper和checker准入

NativeHelpersBinding的schema/路径/重复项/大小/依赖构造顺序，checker_source_identity/checker_native_selection的source/selector/captured/held有效性，installation_manifest和publisher的source/receipt准入，仍是可观察生产policy。已有native_file_digests完成一次鲜读map，已有SHA/publisher kernel完成各自工作；它们没有自动迁移这些外层规则。

将完整ordered map和错误次序、source/image/manifest实际mapping身份、安装双副本和bundle构造policy迁入HIA；保留每次public调用完整鲜读，不加跨call digest/mtime缓存。当前963-source SHA4 ABBA仅约3.346%且不是原3s业务资格。先明确实际hot owner，再改变真实实现；不可把混合2.9s诊断区间全算为hash。源锚点：[helpers](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/hepta/hia_native_helpers.py)、[checker](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/hepta/hia_checker_identity.py)、[contract](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/tools/hia_selfhost_contract.py)。

### P2：Worker完整wire与普通service dispatch

catalog/check_vocabulary/validate/installation_manifest仍在Python。WorkerRequest HIA只接收其声明的原始请求域，worker.main/_run还决定管理员pin、mode、startup、service_entered、终态source变化、E_HIA_REQUEST_UNKNOWN和correlated report。service.call/_call_native_journal/_error及describe/artifact/read/inspect/candidate仍有外层业务。十五CLI动作有native控制，也仍经Python入口、未移植callee和安装策略。

迁移整个closed schema/vocabulary及启动/分派/报告状态机，复用真实journal/namespace，而不嵌套执行旧service body。资格覆盖全部原11工具、same-key conflict/replay、原未知结果、before/after身份、wheel无authoring导入和真正默认入口。源锚点：[contract](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/hepta/hia_agent_contract.py)、[worker](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/hepta/hia_agent_worker.py)。

### P2：进程监督与对象/符号/映射/出版provider

NativeBuild选择compile/link的协调policy，仍调用clang_capture.run_bounded、runner、inspect_object_symbols、inspect_owned_shared_elf、native_mapping_identity、native_tool_identity以及publication。读取一个fd/一次wait/syscall是机制；决定何时launch/timeout/kill/reap、如何分类trap/fault/invalid/unknown、是否接受完整ELF/导入/符号/工具/映射、何时出版是policy。

按依赖拆完整provider，继续真实ELF/linker/loader、完整sealed.so、constructor/finalizer、shared trap写回、pipe/信号/资源、进程树清理和未知保管；不要提取.text来绕过loader，也不要把linked observer资格推广到所有public runner。源锚点：[capture](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/hepta/clang_capture.py)、[ELF inspector](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/hepta/elf_shared_abi.py)、[publication](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/hepta/artifact_publication_native.py)。

### P2/P3：独立证明engine与proposal policy

VerificationR6和ProofContract解决协调/receipt含义之后，_behavior_equivalence/_independent_native_refinement、translation validation、scalar totality/lowering/call validation、SafeCore的Core模型/x86模型/ELF绑定、solver调度和replay仍是独立policy。Z3、LLVM和其他外部solver/编译器身份仍须明确。原proven/refuted/unknown/timeout/unsupported与反例域不能被统一成bool。

初始化/归纳、unroll/call expansion、guarded/reduction/narrowing、specialization、swap/byte/CRC/finite action/x86 search等proposal仍需完整HIA策略。建议先可信验证链再不可信proposal；不能把产物生成器当独立checker。原reference/oracle作为测试证据保留。源锚点：[proof_contract](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/hepta/hia_proof_contract.py)、[SafeCore](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/hepta/hia_safe_core.py)、[scalar totality](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/hepta/hia_scalar_totality.py)。

### P3：编辑/查询/增量、其他target与持久状态机

- 编辑和路由：hia_routes/core_api/schema/core_upgrade、hia_program_tools、edit_batch/query/patch_impact/incremental。复用已有patch/workspace kernel，但完整同时编辑/接口/loan/identity/no-replace规则仍须HIA持有。
- 其他target：LLVM、AArch64/ELF、Linux kernel及entry-layout。原支持路由不能因Linux x64完成就悄悄删除；需要实际target/profile/ABI替代与原caller。
- 自适应：adaptive、multiversion、artifact_session、background_optimizer、prepared/result_cache/scalar_state，及stateful/finite_context/durable_queue/continuation/queue_commit/host_region。retirement小owner不等于这些整个state machine。
- NDU/advisory：hia_ndu*、planning/economic/search/cost/holdout/invocation_bank/macro与Rust byte-DAG替代路线。Rust执行不是HIA；建议先迁receipt/session/cache/成本/控制policy，再迁真正算法/runtime。原经济净收益没有证据不能从语言迁移推得。

完整文件映射在AUDIT.json；[LLVM](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/hepta/hia_program_llvm.py)、[AArch64](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/hepta/hia_program_aarch64.py)、[NDU](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/hepta/hia_ndu.py)、[queues](https://github.com/TrillionniumFoundation/Hepta/blob/4b19af89a766593f7d5f1cc2db256e81aba7afcb/hepta/hia_durable_queue.py)是固定源锚点。

## 4. “固定foreign bridge”与“仍有Python策略”的明确边界

| 类别 | 本次判定 | 最终要求 |
| --- | --- | --- |
| HIA发行一次GETATTR/CALL/ITEM/IMPORT/DICT_MERGE、context-manager或exception primitive | 业务分支可已经HIA拥有；桥不能重跑业务body或runtime AST。 | 保持原真实对象/错误/退休顺序；若最终声称无需Python，还需真实运行时表示/ABI替代。 |
| mmap/ctypes字节视图、装箱、固定CPython raised-exception调用 | 机械/表示职责，不按文件名算业务owner。 | 外部引用寿命、失败/中断和版本边界独立验；不能算Python runtime已经消失。 |
| source/manifest/helper/checker/receipt准入 | 真实policy，即使文件名以_native结尾。 | HIA完整decision，真实观察与映射身份，不暗借host validator。 |
| 一次SQLite/OS/loader执行 | 可为固定mechanism；事务/预算/未知结果的决定另算policy。 | 每次native preclaim/ACK，unknown不重放，完整原操作/持久状态连续性。 |
| 独立oracle、qualification和历史归档工具 | 可保留为生产执行闭包之外的审计/测试材料。 | 不把生产仍调用它们的事实删掉；也不为“只有HIA”的字面文件计数删独立证明。 |

当前selfhost编译器受128函数、16参数、3结果和1MiB等原profile界约束，这属于bootstrap组件合同；通用Core/VM/nominal的原公开无界声明不能跟着缩域。显式native数据VM/continuation是已采用的保域办法。support明确whole_HIA_language_self_hosted=false，不可拿子集fixed-point改成全语言完成。

## 5. 当前原始阻塞与完整晋级条件

原4b正常Core run43197399906的六次失败仍未修复：namespace/ledger各有baseline capture timeout、candidate context expiry和native-timeout超过原5秒（5.515/5.553）三项。后来的两项方法PASS都在native child未启动的budget-refusal路径，不是对原运行的修复。原nominal377确实PASS但耗2258.701s；这是未来v10原1800组限的风险，v10从未执行，不存在可报告的v10实际FAIL。CallArena26的新结果只绑定自己的4-file3.12开发源。

最终需要以下同一条真实链：

1. 所有仍支持的public policy与其transitive依赖都有HIA替代，并保持原域、原错误/partial state/alias/lifetime及未知结果语义；现有组件不重复移植。
2. exact真实Git联合源码完成全生成、source/coverage/contract/nativeinventory校验与原所有source IDs。normal流程已补的65个generation-only原controls必须保留。
3. 当前源码重新cold：原B0/B1/B2/B3、M1/M2/M3顺序、两个fixed points、所有families/phases/checks和独立参考完整；180秒+3秒清理、外层240不变。
4. 从该实际cold编译器生成每个owner，全部source/image/manifest/checker/captured/held及五资源组绑定到同一checkout与installed package。
5. 所有完整component、原caller、worker/wheel/isolation、shared/normal/temp/thread/error路径在原20秒编译、1800组限和原public deadline内通过；3.12通过不代替3.14。
6. 原27组与无过滤retained full discovery在原5400 full限内实际完成；任何failure/error/skip/unknown均原样记录，不能延长、拆组、删除或换source结果通过。
7. 原六deadline问题与nominal性能风险必须在真实新源原gates上闭合；每次public完整freshness保留。
8. 真正默认CLI/worker/package选择完成HIA组成，没有旧policy fallback或业务源码解释；原live-operation/restart/recovery/rollback、数据库/slot/lease与安装身份连续性分别观察。
9. 最后凭完整生产可达性与原default/installed/live验收删除旧production栈，保留独立oracle、原失败、测试、源身份和历史证据。用户已授权最终删除，缺的是技术闭合，不是再次索要权限。

所谓policy已经由HIA驱动与“最终只剩全HIA”是两种不同状态。当前固定CPython对象/异常/调用ABI仍是生产依赖；必须真实消除或在明确兼容边界交付，而不能把未替代部分从总目标中静默排除。

## 6. 保存与下一步

全576路径与20族、最新8项后继scope、11项可执行优先级、原始阻塞、资格条件和本轮读取来源都在AUDIT.json。所有current_cold / whole_native / default_activated / live_migrated / legacy_deleted仍false。本轮不运行测试，不修改产品或audit refs。

下一项已经得到根任务授权：在独立新revision修复Core.finish、Plan.finish、Byte.finish三处；以原Core/Plan真实反例和新增Byte前控为依据，再跑保持原限额与原测试的纯Git actual3.14后继。此前所有freeze与结果原样保留。
