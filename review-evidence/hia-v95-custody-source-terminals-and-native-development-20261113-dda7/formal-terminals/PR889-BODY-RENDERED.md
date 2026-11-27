## Current verified state — 2026-11-13 17:15 UTC

**whole_native=false.** Default/main and this draft PR head remain unchanged. Legacy production implementation has not been deleted.

- **R10-R2 formal Source PASS:** [run 43463604848](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43463604848), Python 3.14.4, all **1,319/1,319 actual methods**, 0 failures/errors/skips, **1014.938465389 s**. All 121 generators ran twice and 1,505 syntax checks passed. Generated 3,083-file source tree `1d52f28fa841599b9f1be028098a99e6a7a522b8`; 637 exact delta paths. Original RESULT `8a88dd5a1054221ef93f81aa3ccb6a8b2c6d50e2`, full job log `bd6d0f0196c6e6fd1b824118e018a258605b7ca6`, and evidence manifest `95caad6583bf9617342e093d7f02842c427f41c4` are preserved. The 336,112,054-byte original ZIP was downloaded and SHA-256 matched; independent full inner-byte/mode/source restoration is running.
- **R11 formal generation FAIL before any Source test:** [run 43468679071](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43468679071), harness `2a91857219e0c676420f02251e1a772f0e0c7362`. Syntax 1,518 PASS, but generator `cli_parser_context` rejected the actual Python 3.14.4 `_colorize.Argparse` object. **0 product tests executed; no formal 1,329-method pass.** Original RESULT `50a08f9830010079fa9ae7a29bf73fe3eb0f6185`, complete log `a592c083fcb2c59ad1c8088c5fb5148456517ec1`, manifest `cf11f4c1b6d75aba0869b7a74e651d19b665b138`, and publication receipt `1e1a34b826e812df32170694dbc7ffc52854a53e` all full-GET verified. Original ZIP 117,390,821 bytes/SHA-256 verified. Earlier local Python 3.12 generation 123×2 and 254 affected tests PASS/196.363007451 s remain separately scoped.
- **Native still blocked:** actual R7-R4 product `abeef212e34023534d91f8f952280e2a8d0cbde6` Source 1,274 PASS, but original namespace inner 35 has 3 budget failures. Fresh-source checks and original 3 s/5 s assertions remain unchanged. Narrow guard controls are not a business qualification.
- R12 read-only file profile integration remains frozen/source-only; it inherits the R11 parser failure until a separately preserved successor repairs real 3.14 graph handling. No claim that the 13 old file CLI actions are connected.
- R6 archive custody remains **331/434** verified parts. Part 331 POST UNKNOWN followed by fixed-object GET 404 is preserved; no completed remote restoration claim.

---

<details><summary>Earlier chronological reports (preserved; superseded by current state above)</summary>

## 最新实测：Source 通过，Native 预算失败已隔离，1319 项后继正式运行

- 产品候选 `abeef212e34023534d91f8f952280e2a8d0cbde6` 的 [run 43459534648](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43459534648) 已终态：**Source 1274/1274 PASS，804.168s；Native FAIL**。匹配当前源码冷启动、发布启动器、候选构建55镜像、Store原控制及原Agent48调用步骤成功；原 namespace 调用步骤失败，后续门禁未执行。外层原1测试完整运行402.119s；嵌套原35测试399.947s、3失败：两个原3000ms/1000ms预算场景在首次baseline emit前耗尽总预算，原<5s终止测试实测5.721897753s。未改任何原断言/预算；完整98,307,377B Native ZIP、Source/Wire ZIP及日志均核身份保留，逐成员原权限恢复正在独立复核。日志全文已ACK/GET：`d304602ea70e0bcc541c215f1265e5b17448e22b`、`7cd5bf57c7ac02807c1855f3403a0e80d5470f7b`。
- **R10-R2 正式 Source 已开始**：[run 43463604848](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43463604848)，harness commit `7bc59aabc80e36838e604cd0ec8a2dd83b65140e`、tree `59ed21f7a4d6377225c1ee9d6e79a09fcc51b735`；76叶/8目录/27变化均逐项GET与树哈希核，原R9失败全文与本轮原前置错误均保留。计划 `035d0681a26bb6398d1def298ee9f990b7b4d7ff`。自己的本机121×2生成/1505 AST通过；**232/232回归PASS，214.742832679s**，源码前后不变，原归档失败方法实际执行并通过。实际加载1319方法，原1306保持有序投影；正式解释器会重跑全部，未继承本机资格。发布收据 `956be2c9feeea5c4c8617bdbc2ca9d789e8b9288`。
- R11解析器累计后继仅完成静态整合：3100文件、123生成器、229选择器/预计1329方法，完整plan/26路径前后像已保存；**0生成/0测试**。HIA只读文件profile另有21真实ELF场景与原输出/errno/长度对照通过，但其新FD生命周期政策、缓冲差异和未完成的13个CLI文件动作仍明确保留边界。
- 大型R6原证据Git封存当前仅**331/434**片完整；331号POST的UNKNOWN后固定GET404仍未重试，332以后未开始，完整本机原件保持。所有错误响应/暂停/运输记录已保存；不宣称Git已可恢复全套。

**whole_native=false；默认main/本PR head不变；旧生产整套未删除。以下历史状态按其当时证据保留。**

---

## 当前续作状态：精确 Source 候选已发布，原完整 Native 正在运行

- **R7-R4 正式 Source 通过**：[run 43451128811](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43451128811)，原 Python 3.14.4，实际 **1274/1274 PASS**，0 failure/error/skip，1060.561643572 秒；116 个生成器各两遍、1484 个 Python AST。独立完整读回恢复了 3055 个源码、5470 个证据文件和 1257 个目录，全部字节、Git/SHA、完整事件与原 530/973 ID 投影一致；文件/目录权限恢复，包括 installed/bin/hia 的 0755。完整复核收据 blob `2086526a251f2d553de2368e40c82f769908b4c0`。
- **该精确产品候选已发布**：commit `abeef212e34023534d91f8f952280e2a8d0cbde6`，tree `f2bc61c11104136d3f56e3c4aefa00a4dada910b`，ordered parents 为固定 main `f33d8da316de8fdf27b504371f1a5310997ff548` 与 development `a733926a2786a3d4a37304bd2d18ebb2eac57ac9`。独立分支 `codex/hia-combined-native-v92-r7-r4-f2bc61c-20261113-dda7`；[完整产品 CI 43459534648](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43459534648) 的 Source 与 **原118步 Native 正在运行**。26 段树创建全部 ACK/GET，3055叶和255个目录树重新计算；最后一次树GET的404原件保留，随后只读GET恢复，未重复POST。发布收据 `8331cb2b2703c12d0dbbba30f0f7c8803e4117c2`，完整API原件压缩封包 `a909e3faf5b9e5fb6d893964d2e0feb3c8fb2385`。
- **R9 正式结果为失败，不能继承通过**：[run 43455699432](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43455699432)，118×2生成/1499 AST通过；实际1306完整执行，**1305 PASS / 1 FAIL / 0 ERROR / 0 SKIP**，832.256319047秒。唯一失败是原 `CoreWorkflowContractTests.test_native_archives_cover_every_explicit_fixture_and_caller_destination`：新process证据虽有独立归档，却缺于原主归档路径清单。303366008字节完整Actions ZIP已下载并核SHA，原失败/result/log/全部安装包保留，独立恢复正在进行。R9无产品commit/ref、无Native资格。
- **R10-R2 后继准备/本机生成进行中**：原生CLI组件与精确资源注册合并后3083个源码、121生成器、228选择器、预计1319方法；61个固定源码封包、430作者文件、166条显式前像覆盖。仅对R9实际缺口在原主Native归档中追加process路径；原测试全文、120步顺序、所有执行命令/条件/预算保持，R9及未运行的R10原版本保留。原生CLI实际开发域仍只有capabilities/catalog两类业务动作，其余13个文件动作在副作用前拒绝；223内核对照、6个完整VM开发结果不构成314/TTY/locale/当前cold/whole资格。新的文件能力和解析器累计组件继续独立推进。

**whole_native=false；默认main与本PR head均未改；旧生产整套未清理。** 以下为完整历史记录，历史中的 pending 状态只描述当时，并非覆盖上面当前结果。

---

## 当前整合状态（2026-11-13 15:46 UTC）：R9 本地200项通过，完整1306项正式门禁已启动

R9 独立 harness commit [2df61cbfe17db622a7a0bdc65a09c73ff51de487](https://github.com/TrillionniumFoundation/Hepta/commit/2df61cbfe17db622a7a0bdc65a09c73ff51de487)，tree `665a9f9ad93477aad52d01022e32fd5ae679da84`，已逐项回读全部52个文件、全部子目录、commit与ref。新 [Source run 43455699432](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43455699432) **正在执行，尚无正式PASS结论**。R7-R4 [run 43451128811](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43451128811) 也仍在执行；两份固定候选不混用资格结果。

R9 精确加入 Linux process 的当前源冷构建器和永久验证：17项Source守卫＋1项真实portable，完整Source预计 **1306**，原1288个ID保持同序前缀；完整Native保留此前118步骤逐字不动，新增130方法的严格冷资格及独立always证据上传，共120步骤。Source文件3074，声明冷输入1298，118生成器，227 selectors，十二资源族仍为197资产/ENTRY8/NATIVE90，Core54/mechanism51。新冷资格必须读取实际当前树冷报告，不能使用开发pin或历史pass。

发布前该候选实际 **118×2完整生成、1499语法检查、固定200/200本地回归PASS**；200项耗时154.961004240秒，全部start/stop同序，无错误/失败/skip/expected failure/unexpected success，tree `15bb040191d359bfc17dc8d79b5bfc6ef7d1f91f` 前后不变。两项真实sdist/wheel/安装测试均执行并保留目录。39项未改的Core/assembly参考方法在正式Source之外单列。完整本地报告 `428642e3b7188f75441d01f2a78191596ec3bbb2`、生成报告 `bf8ce87696ef508e33e3653bb84975d32bd07ea2` 已挂入harness；这些是本地Python3.12结果，不冒充正式3.14.4或Native/cold。

R14只在R13中扩展精确Source证据入口，加入process portable第三键，要求两份原RESOURCE-READBACK，并保留原runner/期限及其余所有driver字节。24项harness守卫控制PASS，产品Source/Native/cold执行均为0。此前R7-R3实际失败已完整恢复：3175外层文件、2740内层文件、3055源码与2548事件逐字/CRC/哈希核对；v1归档mode归一化限制明确保留，恢复核对报告为 `b3f8892fd397714ad76173c155d8e563c7180856`。

原生独立CLI已冻结开发源码，223个普通UTF-8非TTY内核案例及6个独立完整VM案例通过；有效文件类命令当前仍明确拒绝，IO9为新process政策，不能称CPython关闭fd/缓冲异常、TTY、locale或3.14完整兼容。后继真实文件IO与13个文件动作正在实现，尚未纳入R9。

**whole_native=false；主分支再次核对仍是f33d8da316de8fdf27b504371f1a5310997ff548；PR head/draft、默认与旧生产实现保持。** R6原件归档当前144/434分片完整回读，剩余继续，不能称完整远端备份。

### 以下保留此前进度、失败与限定范围

---

## 当前整合状态（2026-11-13 15:18 UTC）：R7 正式 Source 1273/1274，已修构建依赖并启动完整重跑

R7 R3 正式 [Source run 43443042808](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43443042808) 已终态 FAIL：CPython 3.14.4 上 **1,274 项全部执行，1,273 PASS / 1 FAIL / 0 ERROR / 0 SKIP**，耗时 **1,371.250084404 秒**，未放宽原 1,800 秒预算；116 个生成器两轮及 1,484 项语法检查通过。唯一失败是 portable 原测试的真实 sdist 子进程缺少 `setuptools`；其 wheel/installed 分支尚未到达，不能称正式通过。完整 136,636,893 B ZIP 已下载、SHA-256 和全部 3,175 外层成员 CRC 核对通过；原 1,047,374 B job log、完整失败 RESULT `5c7e0f2bbc2d91c92bfa9657a55e63077d8831ee`、manifest `0a27a5a3cf508cec7671d8210916174673d71fdd` 均保留。失败候选没有发布产品 commit/ref。

R7 R4 只为产品 Source 添加独立的 `setuptools==78.1.1 wheel==0.46.3` 安装步骤，沿用原 Native 已有精确版本；原 jsonschema 步骤、所有测试字节/1,274 ID、224 selectors、116 generators、完整 Native 工作流均保持。38 文件独立 harness 的全部 blob、目录树、commit/ref 已实际 ACK＋全文回读；commit [d826ae55a999f0e3f2301c28c9c781eb30fcf374](https://github.com/TrillionniumFoundation/Hepta/commit/d826ae55a999f0e3f2301c28c9c781eb30fcf374)，tree `6736febcafdbffdf92bb136c90e1977498e6e10f`，plan `16d2aea275f41e59d07757e7066398d3b30bf336`。新 [完整 Source run 43451128811](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43451128811) **正在执行，尚无 PASS 结论**。

R13 harness 只改归档函数，保留实际文件/目录权限与根目录 mode，拒绝链接/特殊文件并检查读取期间变化。9 项实际 harness 控制通过，包含复现旧归档把可执行文件 mode 归一化的缺口、完整字节/mode 恢复及 6 项拒绝；控制显式替代 Git transport，产品 Source/Native/cold 执行数为 0。原 R12 Source gate、runner 与全部期限不变；历史 v1 归档的 mode 限制不会倒填为已保存。

独立 R8-R2 进程公开入口整合的本地结果：118×2 生成、1,491 AST PASS，3,064 文件 tree `5f460d7ed5bf9f035b3d9a972f5e86813db7caa4`。原 R8 的 146 PASS/2 ERROR 完整失败保留；只向封闭 entry_paths 清单补两个明确路径后，54 项原安装/stdio/preflight 测试实际全部通过，9.799052657 秒，无异常且源前后相同。此为 Python 3.12 本地范围，未混入 R7 正式候选，也不是 Native/cold 资格。

审计完整 head 仍为 `b93eaced7f9381d643f474204d26205891e5f7e7`；R6 大型正式原件归档另有明确部分检查点（120/434 分片），不能称全部 Git 可恢复。原始 ZIP 和完整本机档案保持。**whole_native=false；默认未切换；旧生产整套未删除。** 后续原生 CLI、真实 parser context 与进程冷资格继续独立推进。

### 以下为保留的历史进度与原始失败记录

---

## 最新整合状态（2026-11-13 14:22 UTC）：R6 产品 Source 通过，R7 保留失败并修复，尚无整套原生闭合

R6 产品 [Core 工作流 43430503183](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43430503183) 已全部结束：Source job `131902501822` 实际 **1,224/1,224 PASS，1,019.321 秒**；Native job `131902502212` 在启动器准备阶段 **FAIL，原 26 项启动器控制执行数为 0**。三处实际生产者/消费者协议名称已在 R7 修复，原测试、当前源冷启动、回执与期限校验保持。下方“Source 仍在执行”是保留的历史记录。

R7 R1 的真实本地结果为 **276 完成 / 274 PASS / 1 FAIL / 1 ERROR**，原始失败未改写。R2 两轮完整生成（116×2、1,484 项语法检查）完成，完整发现 **1,274 个 Source ID**；其 47 项定向检查实际 **46 PASS / 1 ERROR**，源 tree `6d46ed3820451de75e8770330846ca9c8f4a6bc8` 未变。两个 R1 问题已通过；新增错误来自验证器仍绑定 portable 测试文件旧 SHA256。真实 sdist、wheel、安装文件及全部 195 资源逐项核对原件已经保留。

R3 仅把该冻结 SHA256 绑定到审阅后的完整测试文件，所有验证器函数/类 AST、原 69 个有序 ID、五个完整文件字节守卫及 1,274 个 Source ID 保持。独立八项控制确认旧守卫拒绝、修复后精确接受、五个文件任意单字节变更均拒绝。目前正在执行 R3 的 116×2 完整生成；**R7 R1/R2 未发布正式运行，R3 正式 Source 尚未启动**。

R12 harness 只改变 Source 证据保存入口，精确限定两个新的/既有的证据路径；原 Source runner、530/973 原始 ID 投影、1,800 秒预算和清理保持。18 项 harness 路径/环境/失败传播控制已通过，使用显式观察替身，**执行产品 Source/Native/cold 数均为 0**，不会冒充完整资格结果。

审计分支已完成 [b93eaced7f9381d643f474204d26205891e5f7e7](https://github.com/TrillionniumFoundation/Hepta/commit/b93eaced7f9381d643f474204d26205891e5f7e7)：新增 174 与 315 文件两个完整节点，Root 独立核对全部 27 条成功单父提交链、315 项路径/mode/blob、原 50 个目录和全部 19 个非审计根项。后续 R6 正式结果原件正在单独归档，不混入此前历史结果。

**whole_native=false；默认入口未切换，旧生产整套未删除。** 新进程入口、CLI 异常路径与资源生命周期的后继开发仍在独立验证中，尚未纳入本轮正式候选。

---

## 最新 Native 结果：R6 启动器准备失败，已保留完整原件，正在修复协议名称

候选 `cec2f44bd4bc0d12298a0282c1eb8ce1d7a7b95f` 的完整 [Core 工作流 43430503183](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43430503183) 中，Native job `131902502212` 已结束为 **FAIL**。原始冷启动重放、2 项调用图原生测试、语言覆盖 **1,242/1,242** 及 10 项实际报告断言均通过；随后新增启动器资格步骤在准备阶段失败，**groups=[]，原 26 项启动器控制未执行**，其后的 Native 步骤没有资格结果。产品工作流 Source job 仍在执行；前述独立正式 Source 1,224 PASS 事实不变。

实际 `PREPARE.json` 堆栈显示：消费者以 `core-frontend` 查找回执，实际 producer 产出 `core-json-frontend.receipt.json`。后续对应 manifest/build schema 也正按实际 producer 逐项核对。修复仅统一生产者协议标识，不放宽回执、完整输出、当前源冷启动或原期限校验。

Root 已下载并全 CRC/bytes 校验原件：Native ZIP **75,586,609 B**，SHA-256 `0ea4008a213a0a215e2844d12208525794684a2f5af17a89a39a9aa77d5d9f69`，完整 **2,500** 文件；wire ZIP **66,086 B**，SHA-256 `16268d031159ca2b97d5977957a27b5b8aa27f50039829168ddb73df7752c768`，其唯一文件是冷报告，没有 wire 测试通过之意。完整 Native job log **62,452 B**，Git blob 计算值 `3f4a9da63d5b9edaad73ff21a03d620aeca4fdae`（此时仅原始下载/本地校验，不冒称 Git 挂载）。

下一份 R7 源语义合并已包含 Linux stdio 冷实现与 CLI discovery JSON 实现：3,055 文件、116 个生成器、224 selectors，预计 1,272 Source 方法；实际发现/执行尚待完成。原 116 个 Native 步骤的命令、环境、顺序和预算保持，另加两个严格 matching-cold 组件步骤。**whole_native=false，默认入口未切换，旧生产整套未删除。**

---

## 当前进度：R6 正式 1,224 项全通过，完整 Native 工作流已启动

R6 正式运行 [43422327653](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43422327653) 在 **CPython 3.14.4 完成 1,224/1,224 PASS，0 FAIL、0 ERROR、0 SKIP**，Source 组耗时 1,521.086862444 秒，保留原 1,800 秒限制。113 个生成器各运行两轮，1,466 个 Python 文件语法检查通过；530 个 main 和 973 个 development 原始方法投影、2,448 条有序 start/stop 事件完整。

Root 已独立下载并校验完整工件：134,207,267 B ZIP，SHA-256 `3105b20b4e4cc68badbac217380218e5be7eb01a1ea2f8508c819eaad2ab6fc0`；4,441 个外层文件全部 CRC、4,016 个归档成员、83 个分块与完整恢复源逐项一致。原件 manifest 为 `2f3bf86f9ea05117cdb8b5dc227a0b7508ae94b9`。正式源 tree **`78155bac080168d2946116ede1607e48b221ec1b`** 的 3,024 个文件已全部从 Git 递归读回，与实际测试源完全一致。

候选提交 [**`cec2f44bd4bc0d12298a0282c1eb8ce1d7a7b95f`**](https://github.com/TrillionniumFoundation/Hepta/commit/cec2f44bd4bc0d12298a0282c1eb8ce1d7a7b95f) 保留固定 `f33d8da…` 和 `a733926a…` 两个有序父提交，分支为 `codex/hia-combined-native-v88-r6-78155ba-20261113-dda7`。原有完整工作流 [**43430503183**](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43430503183) 已启动，Native workflow 声明的 **116 个步骤**保留；Native 结果仍待实际完成，不继承 Source 或独立开发范围的通过。

单次创建 576 路径的 Git 树曾返回超时。Root 保留该响应，随后按每次 24 路径建立了 24 个只读物化阶段，每阶段均实际 ACK/GET，最后重算并完整读回相同 `78155bac…`；没有改变候选源或放宽检查。

R5 [43415454682](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43415454682) 的原 10 个失败仍完整保留。新 Linux stdio strict-cold/portable（29 路径）和 CLI JSON owner（14 路径）已各自完成有限 Source/开发范围与可还原交付，正在准备下一联合候选；两者的 matching-current-source cold 正例尚未在最终联合源执行。

**whole-native=false；默认未切换，旧生产整套未删除。** 本草稿 PR 的原 head 保持不变。以下为先前各时间点的原始记录，不回写当时结果。

---

## 当前进度：R5 完整 Source 已保留真实失败，R6 正在全量重验

R5 正式运行 [43415454682](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43415454682) 已在 CPython 3.14.4 完成 **1,224/1,224** 项：**1,214 PASS、10 FAIL、0 ERROR、0 SKIP**。113 个生成器各执行两轮，1,466 个 Python 文件语法检查通过；Source 失败后未发布产品 tree、commit 或分支。完整 109,945,006 B artifact 已独立校验 ZIP SHA/全部 CRC、2,209 个归档原件、69 个 Git 分块身份及 2,448 条有序执行事件；恢复的正式源 tree 为 `d7e35e1e0b2907a5375bdbdb75c8547e3fa8cd42`，证据 manifest 为 `0ccfbc33a2b946831eb32855008497e848f2815a`。这是原件完整性检查通过，Source 结果仍为 FAIL。

R6 已固定为 **11 个登记修复文件**：10 个测试文件只更新精确集合或计数；checker 补齐 Store lifecycle foreign/native 两项真实外部依赖。原有方法、其余断言、1,224 项 ID、220 个选择器、113 个生成器及所有预算均保留。独立检查确认 49 个机制的实际依赖边；没有通过删除失败控制获得通过。新 harness [`a6026cdb141c79f657b1b097e97f4de34e634974`](https://github.com/TrillionniumFoundation/Hepta/commit/a6026cdb141c79f657b1b097e97f4de34e634974) 的 [完整运行 43422327653](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43422327653) 正在执行，结果尚未产生。

最新完整审计 checkpoint 为 [`236ed3e93cf166d37bebda41ce041123892c00bf`](https://github.com/TrillionniumFoundation/Hepta/tree/236ed3e93cf166d37bebda41ce041123892c00bf/review-evidence/hia-v87-native-development-and-d79-originals-20261113-dda7)：新增目录 541 项，保留此前 48 个审计目录及 19 个非审计根节点，13 个顺序提交已逐一全文 GET，均标记 skip CI。该节点含 d79 原始 Native 失败全部逻辑原件、Store R3、ENTRY、candidate-cold、Linux stdio/ELF 开发范围；不冒充尚未挂入的 R5/R6 新证据。

并行的新公共 Linux stdio 开发包已完成 57 项 Source、5 个实际 HIA 构建与 12 项直接 ELF 执行；HIA capabilities/catalog JSON 内核完成 61 项 Native 和 6 项 VM 对照，保留原 10M fuel 上限。两者正在补严格当前源 cold/portable 接线，尚未加入联合生产候选；SQL snapshot 读内核也仍是独立开发范围。

**whole-native=false；默认未切换，旧生产整套未删除。** 草稿 PR 的原 head 保持不变；以下各节是先前时间点的原始记录。

---

## 2026-11-13 11:15 UTC：完整 Source 两次通过，R5 联合候选正在正式验证

**全量 HIA 原生替代尚未闭合：`whole_native=false`。默认入口未切换，旧生产整套尚未删除，本 PR 保持 draft。** 当前产品源码与审计按精确版本分别保存，旧失败没有被后续结果覆盖。

固定开发输入仍为 main `f33d8da316de8fdf27b504371f1a5310997ff548` 与 development `a733926a2786a3d4a37304bd2d18ebb2eac57ac9`，保留两个实际最佳合并基点，不追逐新的 HEAD。

### 已实际执行的完整结果

| 精确范围 | 实际结果 |
| --- | --- |
| [Source R3 正式运行 43396616508](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43396616508)，harness `68a30237`，Python 3.14.4 | **1172/1172 PASS**，213 selectors，loaded/started/stopped/run 完全一致；原 main530 与 development973 方法投影全部保留；零错误、失败、跳过、预期失败、意外成功、重复或缺失。109 owner 生成器各执行两遍，1441 个 Python 文件通过语法检查。 |
| 精确联合产品 [d79eb096](https://github.com/TrillionniumFoundation/Hepta/commit/d79eb096ddcce6c317b2c316a4773ce76a37bab9) | tree `279c5459c9cc7746d5e347d90285eebfe21986d2`，2989 文件；全部路径、模式、blob 与 CI 候选相等。双父按固定 main、development 顺序保留；仅创建隔离产品分支。 |
| d79 原始 [Core 运行 43402528459](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43402528459) 的 Source job | **1172/1172 再次 PASS**，实际 Python 3.14.4。 |
| 同一 d79 Core 的 Native job | **FAIL**。机器计划完整 12 方法中 11 PASS、1 ERROR；`test_backend_custody_binds_selected_native_owner` 修改已加载 image metadata 后，真实 freshness guard 正确抛出 `checker native mapping differs from its loaded identity`。后续未执行的步骤仍记 SKIP，不能视为整套原生通过。 |
| 对上述测试的 R2 修复 | 保留真实损坏映射拒绝，另行检查 backend identity dependency；没有放松 production guard、伪造映射或冷回执。本地原完整 12 方法 PASS；原失败和首次不完整修复均保留。该结果不转移为 R5 资格。 |

Source R3 原始 Actions ZIP 120,474,423 B 已完整读取，3939 个外层成员及 3554 个内部原件逐字节、权限、SHA-256/Git 身份校验；38,854,610 B gzip 与原 75 个逻辑 chunk 相等。d79 原始 Native/JSON-wire ZIP、全部失败日志及嵌套证据另行保全。最后一个 Source 二进制 chunk 的 Git ref 传输问题已通过显式 UTF-8 base64 包装解决，原逻辑字节、manifest 和 gzip 不变；74个raw chunk加1个包装块已按实际形式完整挂载并重组校验。

最新完整审计检查点为 [e51be72e](https://github.com/TrillionniumFoundation/Hepta/commit/e51be72ef1de213e49610ba0c98ee1ece8bdcb6c)：新增目录195项全部path/mode/blob及root/review/leaf树独立全文读回并重算；47个历史审计目录与19个其它根项逐Git身份保留，临时挂载进度文件已移除。终态root `d2c5533048b2f770bda7b1f1debe610466e3a7b8`。此前失败提交与传输回应保留，不改写历史。

### R5：新的共同源码，资格重新开始

正式 harness [29b1145e](https://github.com/TrillionniumFoundation/Hepta/commit/29b1145e37db05d5efa62d75c4d1dd5916f1f8b4) 已启动 [完整 Source 运行 43415454682](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43415454682)。**本节记录时运行中，尚无 Source 或 Native PASS。**

R5 合入启动器及严格匹配当前源码的 cold qualifier、独立 ENTRY 构建资源组、固定 55 项候选构建器、Store 公开 Service→Store→request→close 的实例 held-owner 路由，以及机器计划测试修复。源码整合是 3024 文件、35 新增、111 修改/新增路径；44 个固定输入包、366 个作者路径、112 项明确顺序覆盖、31 个逐字保留 resolution 与185个再生成 seed。原55项开发路径迁移保持；五个此前逐字保留的测试文件改为明确整合，原 body 的保留与该单一修复分别记录，没有继续称其逐字未改。

共同注册为113 owner 生成器、220 Source selectors、SOURCE_FILES1245、12个资源组中的NATIVE89/ENTRY4/总192。Native工作流116步，原全部步骤及预算保留，新增三组件的严格cold与Store原agent/namespace/ledger调用组；新增计数须由实际加载和执行确认。

R11仅为原Source监督器提供一个源码目录外的新鲜VM证据路径。原 `run_source_gate.py`、冻结的530/973 ID文件、1800秒组限时及原cleanup保持逐字或逻辑未改。所有生成器两遍、派生checker/language/support/inventory和完整Source均须在本版本重做。

独立 Linux stdio 原型已由内核直接执行 HIA packer 生成的 ELF，并完成真实二进制复制及边界控制；它不依赖运行时 Python/ctypes payload，但仍是开发原型。公共 Core profile、完整15动作CLI、64 MiB源码构建入口、驻留镜像调用及live worker 尚未由其全量替换。SQLite和固定CPython机制依赖仍存在，不能据组件通过删除旧整套。

PR产品 head 仍为 `4b19af89a766593f7d5f1cc2db256e81aba7afcb`；当前精确联合产品和新harness通过上面的独立提交链接审阅。

---

### 以下保留此前历史快照，当前状态以上节为准

## 2026-11-13：完整 Source R2 已执行，仍未达到全原生闭合

审计续存提交：[13fca5014f678c8ab175e40e25103be0456d75d6](https://github.com/TrillionniumFoundation/Hepta/commit/13fca5014f678c8ab175e40e25103be0456d75d6)。[完整索引与说明](https://github.com/TrillionniumFoundation/Hepta/tree/13fca5014f678c8ab175e40e25103be0456d75d6/review-evidence/hia-v85-source-repairs-and-local-pass-20261113-dda7)包含 239 项新增证据文件，并保留原有 41 个审计目录及全部 19 项非审计根条目。

固定开发输入仍是 main `f33d8da316de8fdf27b504371f1a5310997ff548` 与 development `a733926a2786a3d4a37304bd2d18ebb2eac57ac9`。已形成 33 个明确源码包、286 个作者路径、15 项有前像的覆盖；没有追逐新 HEAD，也没有把本地结果转移成原运行时资格。

| 实际执行范围 | 结果及边界 |
| --- | --- |
| 六项窄修复后的本地完整再生成 | 109 owner 各两遍、checker/support/inventory、55 项开发路径迁移及最终逐文件 byte/mode 守恒通过，239 条真实命令均 rc=0；此循环未执行 Source 测试体 |
| 不改原方法的本地 Source 控制 | 原 checker/front/inventory/import-template 31/31，加原 nominal workflow 方法独立 1/1 通过；仍只是 Python 3.12 的本地观察 |
| 正式 Python 3.14.4 [run 43385529411](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43385529411) / job 131752971013 | 109 owner 两遍与 raw-worktree 校验通过；完整 212-selector Source 实际执行 1,167 方法，全部有有序 start/stop，900.210555442 秒 |
| 正式 Source 结果 | **FAIL**：74 个方法有失败或错误，展开为 140 项 assertion-failure 与 48 项 error 记录（含子测试，不能当作 188 个方法）；无缺失、重复或跳过，原 main 530 和 development 973 方法投影均完整保留 |
| CI 候选树上传 | Source 完成后 Git tree POST 返回 403 `Resource not accessible by integration`；另行记录该能力拒绝，不掩盖 Source FAIL；未创建产品 commit/ref |
| 原整套 Native | 当前候选尚未执行，不能承接任何旧分支资格；正式 Source 全过后才会在精确隔离候选上原样启动 110-step Native 工作流 |

完整失败证据已从 Actions artifact 14020160804 读回并独立核验：112,854,263 字节 ZIP 的 3,730 项 CRC 全部通过；36,373,784 字节内部 gzip 的 70 个 Git chunk 与 3,370 个原始成员逐项 bytes/SHA-256/Git 身份一致，所有内部成员还与 ZIP 原始副本逐字相等。证据 manifest 是 `e9b80273d5b2edf16459246502af8222d65b9e65`；完整 job log、源码终态、失败栈、执行事件及 403 原响应全部保留。

正式树 `bae7ef557428fe426b4f436fb549f4806e578e4f` 与本地再生成树仅有三项已明确解释的差异：不同 CPython 的 AST dump 空字段格式、绑定这些 checker 字节的 support 文档，以及记录真实 HEAD/index 的 inventory。没有宣称跨运行时逐字相同。

正在按实际反例继续修复固定原文件准入、资源夹具、明确的后端 family 接口和不完整 HIA 片段。独立 HIA 原生启动入口也在隔离开发中。**`whole_native=false`；默认入口未切换，旧生产实现尚未删除，PR 保持 draft，head 仍为 `4b19af89a766593f7d5f1cc2db256e81aba7afcb`。**

---

### 以下保留此前各次观察，属于历史快照；当前结论以上表为准

## 2026-11-13 实际整树运行：合并和语法通过，checker 首个反例已定位

本轮原始结果已完整增量封存到 [49b181a](https://github.com/TrillionniumFoundation/Hepta/commit/49b181a58f3f9463ed34af1c2379b4050e811807)。新增 73 项，含全部 49 个失败归档分块；原 40 个审计目录和 19 个非审计根项保持相同 Git 身份。**whole_native=false；本 PR 仍为 draft，产品 head 仍为 `4b19af89a766593f7d5f1cc2db256e81aba7afcb`。**

固定输入为 main `f33d8da316de8fdf27b504371f1a5310997ff548` 与 development `a733926a2786a3d4a37304bd2d18ebb2eac57ac9`，保留两个真实最佳合并基点。实际 harness 为 `97b869129993f450f17bc632ab6da21c9a504a75`，运行 [43379129114](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43379129114)，job 131732539209。

- 真实整合已解决全部 **122 个冲突**，明确应用 **285 个作者文件、36 个精确保留文件、185 个再生成 seed**。
- **1,439 个 Python 文件**在 Python 3.14.4 下实际 AST/compile 全部通过。
- 首个 checker 预生成命令实际退出 1：`ValueError: unreviewed dynamic import mechanism: hia_proof_contract.py:_safe_core_method_reference`。本次尚未执行后续 109 个 owner 生成器和完整 Source 测试体，不能把语法通过写成 Source/Native 通过。
- 失败终态完整登记 **3,039 个非 .git 文件**，其中 235 份新增/改变 bytes 全部保存。原样文件明确依赖四个固定 Git commits，归档没有被误称为自包含。
- 原 Actions ZIP 的 78,366,629 bytes / SHA256 已实际下载核验，全部 **1,433 个外层成员 CRC/SHA、1,178 个内层成员、49 个有序 gzip 分块**均逐字吻合；完整 job log、2893-byte 原 stderr 和命令记录已经 Git 保存。
- 失败对应固定的外部 z3 provider 导入机制。局部修复保留未知导入拒绝，并在实际 3.12 AST 机制正反控中验证；**完整 inventory 同命令仍待恢复树后执行**，局部结果没有升级为整树通过。
- f33d 增量只纳入实际三路径变化。旧增量包的测试 preimage 过时，实际执行使用纠正版：除步骤顺序方法外保留 Surface 最终测试全文和 BytePolicy 登记。
- 完整 Native workflow 静态复核仍为 **110 steps**，Source 登记 **212 selectors / 110 distinct generators**；原测试范围、预算和拒绝条件保持。失败后另有一个未执行的 61-byte 上传路径补丁，保存 Rust 输入原 SHA 清单，以及直接输出失败命令诊断的 harness 草稿。

下一步在完整恢复的失败源码树上执行 checker 原命令并修真实反例，随后继续全部 owner 再生成、确定性检查、完整 Source 和 Native/cold 门禁。当前未切默认、未修改产品 refs、未删除旧生产宿主实现；此前任何通过都没有转移为本组合的资格。

---

以下保留上一检查点及历史原文，状态以本节为准。

## 2026-11-13 当前整合进展：静态门禁通过，实际再生成待执行

本轮源码与实际日志已增量封存到 [147ec49](https://github.com/TrillionniumFoundation/Hepta/commit/147ec49abaabb3b544cbce08b8a33f2dacae81a6)。新增 88 项，原 39 个审计目录与 19 个非审计根项保持相同 Git 身份。本 PR 仍是 draft，产品 head 仍为 `4b19af89a766593f7d5f1cc2db256e81aba7afcb`；whole_native=false，尚未切默认或删除旧宿主实现。

- 固定 22 个源包组成 251 个文件，其中 234 个 Python。两轮实际修订后的静态 CI 分别为 [43374050904](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43374050904) 与 [43374863047](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43374863047)，Python 3.11.18 / 3.14.4 均 PASS。后一轮同时验证后端保留体与原 main 控件的完整 AST。
- 原有 7 组回归中的 68 个方法保留，加入开发分支 8 个方法，共 76 个声明方法；此数字来自 AST，产品测试执行仍为 0。八个 NativeBuild 保留体、原 Function/Emitter 方法、严格冷观察者及源读取协议完成对应 AST 校验。
- [43373857456](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43373857456) 的原失败完整保留：我在检查器中误写了 53 个主线支持字段，实际原件为 52。修复只改检查器计数；251 个产品文件字节未改。不能把修复计数描述为删减产品门禁。
- 后续 Native R4 与 19 路冲突源扩展至 273 文件，随后 checker 六源已经交付。它们尚未执行，不继承前述 251 文件的结果。checker 将从真实 AST 生成全物理闭包，并与原 54 个语义 Core 角色分别校验，不硬写初扫 112 作为最终分母。
- 最新主线 `016f00bb` 已独立读取实际 [43367645642](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43367645642)：Source 530/636.605s PASS，冷 11/11、语言 1242/1242；随后 130 项原运行时 caller qualifier 整体 FAIL，后续 53 步 SKIP。原工件逐 1831 成员核实确实缺该 qualifier 的目录与详细 report/tests.log，无法恢复具体失败 ID 或栈；不猜测原因。新工作流将显式保存它们。

下一步执行固定 016f+a733 的真实双 merge-base 合并、显式冲突覆盖、全量源语法、所有 owner 的真实 HIA 再生成与复现，以及完整 Source 方法投影/执行。随后再进入同源 cold、完整 Native/caller 和最终交付资格；旧主线或旧开发分支的成功不转移给合并源码。

---

## Latest verified integration checkpoint — 2026-11-13

**The complete HIA-native replacement remains unfinished. This PR remains draft, at unchanged product head `4b19af89a766593f7d5f1cc2db256e81aba7afcb`.** The current main ref was read again and is `51bc24b8b03e5adc3da1b2b3490ad5cc7357e8d8`. No default activation or legacy production deletion has occurred.

[Audit commit 07230419](https://github.com/TrillionniumFoundation/Hepta/commit/07230419344b50f188d2940573a2e6d6b2a0d8d8) preserves all 35 prior audit directories and 19 non-audit root entries, and adds 498 evidence entries in four directories. All four leaf trees and the final 39-directory review tree were read back and independently recomputed.

### Original normal Core outcomes, now with complete retained inner evidence

| Exact source | Source job | Cold replay | Subsequent original native job |
| --- | --- | --- | --- |
| main `51bc24b8` | 528 passed | 6/11; qualification timeout, return code −9, wrapper 180.201199634 seconds; cleanup completed | Failed; later gates skipped |
| candidate `a733926a` | 973 passed | 11/11 and 5,052 internal checks passed; owned child exited before the unchanged 180-second deadline at 179.842562192 seconds; cleanup completed | Language 1,242/1,242 passed, then 108 outer tests had two outer failures containing six nested failures; 39 later business steps skipped |

The a733 cold wrapper's 180.404546584-second wall observation includes post-child verification and is separate from the owned child's actual deadline observation. Neither original 180-second qualification nor three-second cleanup limit was changed. These results remain attached to their own sources.

The original collector's receipt-size failure and its narrow transport repair are both preserved. The final 366-entry recipe retains the main 89-chunk pool and a733 237-chunk pool, all original nested ZIP bytes, and the complete 53,663,592-byte a733 qualification JSON. The main pool and full a733 qualification received separate independent reassembly. The actual collector fully read back every a733 pool chunk; a second complete independent read of all 237 chunks is **not** claimed. The original outer ZIP byte streams remain in the recorded Actions artifacts; computed binary Git hashes are not misrepresented as uploaded raw binary objects. Custody completion is not product qualification.

### Actual merge history and source integration

Actual `git merge-base --all` returned **two** best bases: `5831f52f` and `93d66bcc`. Earlier comparisons against 93d66 remain explicit reference-ancestor comparisons, not a unique best base or actual conflict count. The first rehearsal refused the single-base assumption before merging; the second stopped on a missing promisor-object transport error. Their original failures remain.

The third [fixed rehearsal](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43364315272), after bounded prefetch of the four fixed input trees, ran the unchanged Git merge and produced 122 conflict paths, 291 unmerged index stages and 2,839 stage-zero paths, including 418 changes from main. Its exact unresolved AUTO_MERGE tree is `9bf5677a4cbb45ec192f09e90df49d4ad39330c9` (2,961 files). This is a textual construction result, with semantic qualification explicitly false.

Implementation is resolving the real protocol differences: main bundle/continuation owners remain on their existing selectors, while a733 single-image control families receive explicit distinct selectors. Main's canonical `.hepta` policy, all eleven installed-resource groups, original scheduling custody, a733 lifetime fixes, and both complete control sets are being retained. A compiled-HIA snapshot witness reproduced the conflicting registration; the typed mapping restored the public buffer path with the retained reference poisoned. Its narrow new regression method observed the original error and corrected pass; its complete original setup/class and combined cold gate are still pending.

The independent PR893/storage branch audit is also retained, including its same-tree successful push and failed PR cold run. Its native SQLite work and the unexecuted varint follow-up are not relabelled as main or a733 qualification.

### Execution environment and exact interruption boundary

The environment recovered at 03:29 UTC. All 84 historical Core transport wrappers were fully read back, their 43,711,416-byte archive was actually reconstructed, and the capsule was rooted at [c3f1df5e](https://github.com/TrillionniumFoundation/Hepta/commit/c3f1df5efe011bffe330143b2bb4782000469bbf). A new strict plan removed only 96 verified recoverable derived copies, totalling 181,813,692 logical bytes. The protected original, unique outer ZIPs and production source remain.

The full main source was then materialized and independently verified: 2,579 files, 72,234,761 bytes, exact tree `578a72d9bd6dadf0375bed33e3d1aa5341c8f452`. The environment became unavailable again during preparation of the isolated unresolved-merge workspace. Its script-write acknowledgement and materialization state are unknown; no successful execution receipt was observed. That local action will be reconciled before any retry. Source authoring and immutable Git evidence work continue separately, with all new drafts marked unexecuted until actual validation.

## Retained earlier checkpoint — 2026-11-13 03:36:58 UTC

The earlier checkpoint below is retained verbatim. The latest observations above supersede its pending-run, single-base and local-environment assumptions; they do not reclassify its historical results.

## Current state and why this remains draft

The complete HIA self-rewrite is not qualified. The exact a733926a development source passes the unchanged 973-test Source suite in both its normal Core workflow and the independent four-profile workflow. Its default profile passes; its Artifact and Evaluation business profiles still fail. Contract Service separately passes 46 component controls, but its original 55-caller driver reaches the original 1800-second limit with 50 reported ok, four FAIL and one unfinished. No complete native replacement or production retirement is claimed.

Production PR head is still `4b19af89a766593f7d5f1cc2db256e81aba7afcb`, and this PR remains draft. A fresh Git ref read discovered that live `main` has independently advanced to [51bc24b8](https://github.com/TrillionniumFoundation/Hepta/commit/51bc24b8b03e5adc3da1b2b3490ad5cc7357e8d8), tree `578a72d9bd6dadf0375bed33e3d1aa5341c8f452`. The PR metadata snapshot still reports base `5831f52f`; it is not the live main ref. The newly integrated .hepta source and its evidence are under a separate read-only audit. Results from main, a733, older sources and independently authored prototypes are not transferred between trees. This workstream has not moved main or the product PR head.

## Current live-main audit boundary

The complete, non-truncated Git trees were independently compared. Current main 51bc has 2579 files, including 178 `.hepta` files (20,903,544 bytes), 1149 Python files (15,422,360 bytes), 48 Rust files and 10 assembly files; it has no `.hiaasm` or `.hia` files. File extensions do not prove runtime or toolchain independence. Its tree is exactly the tree of `bbc5551e97d9d7d995416e553531cff656e21f7a`. Main and a733 have 1597 identical paths, 419 paths with different contents/modes, 563 main-only paths and 1308 a733-only paths; this is not a linear successor that can inherit the other's results.

[Current main original workflow 43347872271](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43347872271) is terminal FAILURE. Its Source job passes 528 tests in 649.699 s. Its cold step reports 6/11 checks passing, empty original/modified generation lists and exit1; the following language and native business stages are skipped. The original detailed cold report is being retrieved. The commit message's earlier local 11/5049, 57-stage and 4657-test statements are being traced to original records and are not substituted for this observed workflow result.

Independent SQLite development must also remain visible. Source831110 in [PR893](https://github.com/TrillionniumFoundation/Hepta/pull/893) has ten SQLite platform paths absent from main. Its [push run43305434289](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43305434289) passes 501 distinct Source IDs, cold11/11, and the original SQLite13 methods after matching-cold production build. The [PR synthetic-merge run43305453525](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43305453525) has the same complete tree88ad888b but fails cold6/11. Both original outcomes remain valid records; neither substitutes for main/a733. Later varint7ab75e is explicitly authored/unexecuted in its original handoffs. These storage paths and the main/a733 semantic overlap require deliberate integration; a fixed-input textual three-way rehearsal is being prepared, with no product qualification inferred from an automatic merge.

## Latest a733 actual results and execution boundary

[Four-profile original run 43349097808](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43349097808) is terminal, using exact source `a733926a2786a3d4a37304bd2d18ebb2eac57ac9` / tree `1c5ba7e1217f46f2b95512640d08f19e2cc8b1fd` / 3324 files and harness `129123c03d950a2eb0690881dfccf7512e77be34`. Original drivers, observers, 973 ordered IDs, 97 generators, 181 selectors, compile20 and group1800 limits remain unchanged.

| Original profile | Verified result |
| --- | --- |
| Actual Python 3.11 default | PASS: original 8 and 64 callers, selected unsupported owners have zero native entries/effects/cached failed entries. |
| Actual Python 3.14.4 Source | PASS: 973/973 in 712.939293851 s, identical ordered loaded/executed IDs, no errors, failures, skips, expected failures or unexpected successes. |
| Actual Python 3.14.4 Artifact | Source45, compatibility27, native12 and Agent48 PASS. Namespace35: 33 PASS / 2 FAIL; ledger48: 46 PASS / 2 FAIL. Both original native-timeout cases pass. Four preparation failures remain under the original 3000/1000 ms context limits. |
| Actual Python 3.14.4 Evaluation | Source73, native14, all96 combinations and Agent48 PASS. Namespace35: 32 PASS / 3 FAIL; ledger48: 45 PASS / 3 FAIL. Four preparations fail at the first emit; original timeout observations 8.857413465 and 8.711724823 s exceed the unchanged 5 s assertion. |

Artifact failure positions differ from the earlier 4925 run: namespace expired and ledger reference-loop fail at the second emit, with `E_CAPTURE_TIMEOUT/admission`; namespace reference-loop and ledger expired reach encoding and fail with `E_HIA_BUDGET/context`. Complete original stacks are retained. Namespace and ledger original-wrapper elapsed times are 246.149387347 and 404.310881908 s; these are not durations of individual failed methods.

[Normal Core run 43347253395](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43347253395), exact a733, is now terminal FAILURE. Its original Source job passes 973 tests in 515.050 s. Original native stdout records cold 11/11 PASS with equal B1/B2/B3 images, language 1242/1242 PASS, and 19 preceding component groups passing. The 1049 executions in those separate component summaries are not a unique-method total. Step27 runs 108 outer tests in 1571.207 s and reports two outer failures, containing six original nested failures: namespace35 and ledger48 each fail three methods. Four preparations fail at the FIRST emit; original timeout observations 5.602196662 and 5.583486049 s exceed the unchanged less-than-5 s assertion. The remaining 39 business steps are skipped. Full original logs and all six stacks are [rooted in the current audit](https://github.com/TrillionniumFoundation/Hepta/tree/3dabe28a94f032c0b9472fce3aa1d961f5e82273/review-evidence/hia-current-main-and-branch-audit-20261113-dda7/a733-normal-core-terminal-v84). Detailed cold artifact qualification counts and internal elapsed time are still being verified; stdout/step duration is not substituted for that report.

The 4925-only original phase diagnostic confirms that 47 fresh scans cross 47 distinct public AgentStore invocations and all 46 adjacent intervals include real publication execution. Expired/loop preparation exhausts the original 3 s deadline before the first remaining-budget check. Coalescing these scans across public effect boundaries is not justified. This instrumented observation does not qualify a733 or main.

The local execution environment was unavailable from approximately 02:35 UTC until restoration at 03:29 UTC on 2026-11-13. Local read-only reconciliation then confirmed that all 96 planned derived-copy reclamation targets remain present with exact original bytes/modes; the retained recovery archive is intact, and no reclaim script or completion receipt exists. The interrupted deletion is not counted as completed and will not be blindly replayed. [Boundary checkpoint 76866ab6](https://github.com/TrillionniumFoundation/Hepta/tree/76866ab614d0f439ee214367e3c92fd204d0de5c/review-evidence/hia-native-rewrite-v84-environment-boundary-20261113-dda7) preserves the unavailable-period state. The restored local runtime supports continuing implementation; frozen remote evidence collection and a separate textual integration rehearsal retain their original inputs.

The independent [evidence-only collector 43354625082](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43354625082) completed CRC/SHA/Git/source checks for all five frozen artifacts. Its complete [144-file custody packet](https://github.com/TrillionniumFoundation/Hepta/tree/3dabe28a94f032c0b9472fce3aa1d961f5e82273/review-evidence/hia-v84-completed-ci-originals-20261113-dda7) is now rooted: all 129 original objects were fetched again, all 99 wrappers independently reassembled, and all five original inner ZIPs matched their complete 50,039,157 bytes. Original outer ZIP identities and retention remain separate; the offline restore helper is authored but unexecuted. This job ran no product/compiler/tests and changed no original result. A separate fixed-input [normal-Core custody run 43358604029](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43358604029), source f59d24eb, is verifying the terminal main and a733 original cold artifacts independently.

The new mem-packing compiler experiment is NOT ADOPTED: retained development fixed points agree but the six-scenario fixed-CPU feasibility results are small and mixed. It has no full 340-pair or 11412-VM proof. The empty-CALL-retirement prototype is AUTHORED_NOT_EXECUTED; the unchanged original qualifier's complete entry observer disables its current guard, so it is not a demonstrated deadline fix. The last interrupted derived-copy cleanup has no observed execution terminal receipt and is not claimed complete. Production legacy deletion remains zero.

## Reviewable source and additive audit

- [Latest joint audit 3dabe28a](https://github.com/TrillionniumFoundation/Hepta/commit/3dabe28a94f032c0b9472fce3aa1d961f5e82273) adds 211 exact evidence files in the completed-originals and live-main/branch audit directories. All 32 previous audit subtrees and all 19 non-audit root entries are preserved, with full tree/commit/ref readbacks. Current audit inventory is 34 directories.
- [v84 source and terminal audit a09f49d3](https://github.com/TrillionniumFoundation/Hepta/commit/a09f49d3e8001adf739482d260f60cfb5256524f) preserves the complete new source publication, root emitter originals, exact 4925 normal-Core failures, Contract Service local/default/native originals, scope controls and VM observations; all 29 prior audit directories remain intact.
- [Reversible inactive-copy recovery b7666f00](https://github.com/TrillionniumFoundation/Hepta/commit/b7666f004f2ba459a37a1da335b9ec951a4f8522) records exact reconstruction of 9394 old base files and retention of 299 unique deltas. This concerns inactive scratch copies, not production or unique original CI ZIP deletion.
- [Boundary audit 76866ab6](https://github.com/TrillionniumFoundation/Hepta/commit/76866ab614d0f439ee214367e3c92fd204d0de5c) adds the execution-boundary checkpoint while retaining all 31 previous audit directories. The review-tree create returned 422; its independently computed immutable tree was fetched and all 32 entries matched before the root and commit were created. The failed response is retained and not reclassified as an ACK.

- [Latest default-scope source a733926a](https://github.com/TrillionniumFoundation/Hepta/commit/a733926a2786a3d4a37304bd2d18ebb2eac57ac9), tree `1c5ba7e1217f46f2b95512640d08f19e2cc8b1fd`: exactly 3324 files, sole parent 4925e72d, exactly three changed paths: two assembly/Core scope-selection modules and regenerated support hashes. All paths, modes, sizes, Git identities and changed bytes were read back. All HIA programs, generators, original tests and workflow limits are unchanged. [Normal Core run 43347253395](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43347253395) was automatically triggered by this one new branch publication and is terminal FAILURE at the durable-budget step27; cold stdout is PASS, with detailed artifacts separately under verification. The change skips only an already-bound nested default assembly scope and original no-op Core borrow, retaining first admission, lazy Core resolution, dynamic-provider fallback and final ContextVar restoration. Local original capture 9/admission 4, 46/18/18/64/64 callers, registration eight and 14 paired semantic observations pass; these local results are not transferred into an actual cold pass.
- [Latest receipt/Evaluation source 4925e72d](https://github.com/TrillionniumFoundation/Hepta/commit/4925e72d9f51f4dc3e8f4d1d2a7b24cce2f5772b), tree `bc276bc832a7d6f04a21d63f55645859b75a01ee`: complete 3324-file source, sole parent 936aee28. All nine changed paths and all complete source identities are verified; no deletions. The changes include three HIA checksum loops, exact integration inventory repair, support metadata and four missing Artifact evidence upload paths. [Actual four-profile run 43341104136](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43341104136) uses harness `eb39aaaeeb8cb55d478e7c7045ccf67d4a4ca22a`; every Python driver/fixture byte, 973 ordered IDs, 97 generators, 181 selectors, compile20 and group1800 limits remain unchanged.
- [Earlier v83 additive audit dfa0cd2a](https://github.com/TrillionniumFoundation/Hepta/commit/dfa0cd2a116d787d868b814056c9b36e35c3f7d8), [v83 inventory and full evidence](https://github.com/TrillionniumFoundation/Hepta/tree/dfa0cd2a116d787d868b814056c9b36e35c3f7d8/review-evidence/hia-native-rewrite-v83-receipts-and-cold-20261113-dda7): 246 new entries, all 28 prior audit directories and all non-audit root entries retained. Complete R4 terminal/normal-Core originals, Contract R7 actual failures, Evaluation phase/local/default originals, source/harness receipts, receipt-loop comparisons and the single cold-reference ABBA diagnostic are rooted. The exact review tree was recovered by read-only lookup after an API 422 response; the original error is retained and that create was not repeated.
- [Prior Artifact/Evaluation source 936aee28](https://github.com/TrillionniumFoundation/Hepta/commit/936aee286e30ee271b8d09235aba57d6ba76cd9e), tree `bb0dd941caa3ae4d5ac970983cd687404cbf65b8`: complete 3324-file source, sole parent 1cd416ab. All 37 changed paths, including 18 new paths, have full byte readbacks; every intermediate tree and final source tree is verified. Actual CI is terminal; detailed results are below.
- [Published Artifact R4 source 1cd416ab](https://github.com/TrillionniumFoundation/Hepta/commit/1cd416ab028a4c59ac76bf4b8e2c4018fb552d9d), tree `eca3dd8ba5067d77fb56454ee354bd0eddb9cfe9`: all 3306 paths, bytes, Git identities and modes read back. Its sole parent is the [3291-file Requests/front union 3e474790](https://github.com/TrillionniumFoundation/Hepta/commit/3e4747901fdc59adc2572d0b56ee0281eab232e7). There are 33 changed paths, 15 new paths and zero deletions relative to that parent.
- [Earlier additive audit 74528cb1](https://github.com/TrillionniumFoundation/Hepta/commit/74528cb113fecc59e58857fae72e82b87c640863), [scope, inventory and evidence](https://github.com/TrillionniumFoundation/Hepta/tree/74528cb113fecc59e58857fae72e82b87c640863/review-evidence/hia-native-rewrite-v82-terminal-and-joint-20261112-dda7): 533 newly mounted entries, all 27 prior audits retained, all non-audit root entries unchanged. Every mounted object has an actual create ACK and complete readback. The audit is a frozen observation; later run conclusions below do not rewrite that earlier snapshot.
- [Earlier repaired source 65ceb711](https://github.com/TrillionniumFoundation/Hepta/commit/65ceb711e47548f85ecf6b2ec2ae90f11dd50743), tree `49a48cef565b78d0a353822026ec525789768840`, remains an exact 3257-file predecessor with its own source and cold results.

The Requests owner moves eight discovery/artifact/request methods into ten HIA modes, including the original context-manager region and lazy generator. The Artifact owner moves six original methods into seven HIA modes, including metadata generation. Selected caller controls poison the old bodies and definition-time aliases. Exact name deletion, early release/destructor ordering, original error context, captured absence and held owner identity remain explicit controls. Published R4 Core/front registration is 54/27/81; the latest Evaluation union is exactly 54/29/83. Fixed Python object/import/call/exception mechanisms are still explicit dependencies.

The R4 source repair keeps the frozen original source hash and compares complete original/candidate ASTs under the same running interpreter. It also repairs the stale front count assertion. The prior actual R3 AST-display and count failures remain preserved. No business deadline or old test is relaxed.

## Actual terminal results

Counts describe the named original groups; overlapping groups are not added as unique coverage.

| Exact source/run | Actual result |
| --- | --- |
| [Receipt/Evaluation source 4925e72d, run 43341104136](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43341104136) | Actual 3.14.4 source: 97 generators, three contract commands and 973/973 original tests PASS, no errors/skips/expected substitutions, ordered loaded/executed IDs exact; 732.744160749 s (733.190622828 s original 1800-second supervisor). Artifact: 45 source/27 compatibility/12 native/Agent48 PASS; namespace33/35 and ledger46/48, four original second-emit codegen deadline failures before entering the second emitter. Both Artifact native-timeout methods PASS. Evaluation: 73 source/14 native/96 real combinations/Agent48 PASS; namespace32/35 and ledger45/48. Four preparation failures occur at the first baseline emit this time, plus original native-timeout 8.758590115/8.764052947 s against unchanged under-five-second assertions. Actual3.11 original eight and default64 PASS; strict unsupported selections have zero entries/effects/cache. All four original ZIPs and exact source/harness bytes are independently verified. |
| [Normal Core on 4925e72d, run 43340452551](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43340452551) | Source 973 PASS in 1015.041 s. Native cold FAIL: `QUALIFICATION_TIMEOUT`, 180.216654570 s, return code -9, complete cleanup under original 180+3. 36 phase-process receipts exit zero, with 35 complete phase archives; names-modified finished but its 2354 raw members remain directly in the outer ZIP. The two export requests lack terminal process/report/archive outcomes. All 4965 outer members, 39058 members in 35 phase ZIPs and 443 members of the separate historical source ZIP were read and CRC/hash checked. The cold export has 1138 files, each matching the exact 3324-file source; it is not a complete3324 export. Partial B1/B2/B3 images match the retained compiler, but no final cold report exists. |
| [Independent Contract Service run 43342561448](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43342561448) | Actual3.14 component46/46 PASS (56.262379 s inner,56.797560 s supervisor), two generators and support check PASS. The original55 caller driver is terminated at 1800.011098 s: partial logs have 50 ok, four FAIL and last BufferLifecycle workload-byte/duplicate-export case unfinished. No complete unittest summary or failure tracebacks were emitted, so no55 terminal result or inferred stacks are claimed. Original source3323/base/harness bytes remain unchanged and process cleanup completes. Actual3.11 all65 original/public outcomes match, including20 existing or negative exceptions, with zero native mappings. This independent candidate is not in a733926a or4925e72d. |
| [Artifact R4 development 43328942162](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43328942162), actual CPython 3.14.4, exact 3306-file source | 95 generators and all 930 source tests pass, with loaded IDs equal to executed IDs and no skips, errors or expected-failure substitutions; source driver 1023.672675642 s under original 1800. Artifact 45 source, 27 compatibility and 12 native controls pass. Original Agent 48 pass with 516979 real machine returns and all seven modes positive. Namespace 32/35 and ledger 45/48: each has two original first-baseline-emit budget failures and one original native-timeout failure, at 6.778104439 / 6.885046790 s against unchanged under-five-second assertions. |
| Same R4, actual CPython 3.11.18 | Original Artifact eight pass. Unsupported selection has zero real entries/effects and zero cached failed admissions, with accurate exception-delivery refusal. The separate older default-64 group is not attributed to this eight-test profile. |
| [Normal Core on published 1cd416 source 43330392476](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43330392476) | Source job passes all 930 tests in 1037.751 s. Native job fails at original cold qualification: authoritative `QUALIFICATION_TIMEOUT`, 180.224381637 s, return code -9, unchanged 180+3 s limits. Cleanup is complete in 0.087250349 s, leader reaped, no remaining children. The final report has no nested qualification report or recorded generation hashes. Partial B1/B2/B3 images do exist in the original ZIP, each 669494 bytes with identical SHA256 81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109; 34 phase process receipts exit zero. These partial artifacts do not complete cold qualification. |
| [Prior Artifact R3 43322044447](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43322044447) | Original default eight pass. Actual source 927/930; failures are two interpreter AST-rendering comparisons and one stale front count. Native 27/12 and original Agent 48 pass. Namespace 32/35 and ledger 45/48; native-timeout 6.863295219 / 6.849092581 s. Complete failed originals are retained separately from R4. |
| [Requests/front union 43321319848](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43321319848) | Actual 3.14: 93 generators and all 901 source tests pass; original Core/assembly 46/18/18/64/64 groups and capture, transport, admission and GLOBAL controls pass. Requests 40/27/11 and original Agent 48 pass. Namespace and ledger each retain three budget failures, with timeout 5.095967536 / 5.074769762 s. Actual 3.11 original Artifact eight and frozen default 64 pass. |
| [Requests R2 43312842625](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43312842625) | Actual 3.14: 40 source, 27 compatibility, 11 native and original Agent 48 pass; namespace 32/35 and ledger 45/48, timeout 6.767591374 / 6.835295419 s. Actual 3.11 strict default/refusal controls pass, while original eight still error in the old eager Core emitter import. The later front union resolves that default path; the original failures remain intact. |
| [Evaluation R8 43320178466](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43320178466) | Actual 3.14: 57 source, 24 binding, 14 native and original Agent 48 pass. Namespace 32/35 and ledger 45/48; four second-emit budget failures plus native-timeout 6.292185610 / 6.422813105 s. Zero old Evaluation bodies are called in the poisoned selected process. Fewer machine returns than R6 are an operation-count observation, not a cross-runner speed claim. |
| [Contract R7 43329384741](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43329384741) | Actual 3.11 default observations match the original, including existing exceptions; no native admission occurs. Actual 3.14 component controls are 27 pass / 2 fail / 2 error, exposing generator/constant-origin portability. Original 55 callers are 50 pass / 3 fail / 2 error, with both first-use errors at the constant-origin key and original timeout 26.9527 s. All 55 ran under the unchanged 1800 s driver limit. These are independent R7 results, not a qualified Service integration. |
| [Published 65ce normal Core 43306363597](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43306363597) | Source 863 pass. Cold completes 11/11 phases and 5052/5052 cases in 97.558018818 s with identical retained B1/B2/B3 compiler images. Native still ends in four original preparation failures across two wrappers; both native-timeout assertions pass in this particular run. This older cold pass is not transferred to later source. |
| [Complete retained full run 43308827101](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43308827101) | Terminal failure. Prerequisites and source 863 pass; original cold times out at 180.207334888 s with return code -9 and complete child cleanup. 32 of 38 phases complete; six remaining CLI/name/export phases are pending, not failed or passed. All 121 original inputs, 255 harness files, 27 original groups and limits remain intact. Full requested=true, full executed=false. |

## Current integration and repair work

[Joint Artifact/Evaluation run 43332961445](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43332961445) is terminal on exact published source 936aee28: 3324 files, tree `bb0dd941caa3ae4d5ac970983cd687404cbf65b8`, harness `dd5357a85e4f8812d1d16ad50c5d771da9d2d68a`. All four original ZIPs and complete source bytes/modes have been verified.

| Joint profile | Actual result |
| --- | --- |
| Source, CPython 3.14.4 | All 97 generators and three contract commands pass. All original 973 IDs execute: 971 pass / 2 fail, no errors, skips or expected failures; 1041.128699842 s under original 1800. Both failures identify missing Evaluation entries in the explicit joint builder/mechanism inventory. The old 930 IDs remain in order. |
| Evaluation, CPython 3.14.4 | 73 source, 14 native, all 96 real combination controls and original Agent 48 pass. Namespace 32/35 and ledger 45/48: four second-emit codegen budget failures plus native-timeout 5.854679140 / 5.926875891 s against unchanged under-five-second assertions. |
| Artifact, CPython 3.14.4 | 43/45 source, with the same two inventory failures; 27 compatibility, 12 native and original Agent 48 pass. Namespace 33/35 and ledger 46/48: four second-emit preparation failures, three capture/admission timeout cases and one codegen budget case. Both original native-timeout methods pass in this specific profile. |
| Default, CPython 3.11.18 | Original eight and frozen default 64 pass. Both owner refusal controls pass before real entry/effects. Complete 39-member raw archive is verified and preserved. |

Published successor 4925e72d repairs the six explicit inventory literals while retaining all six original test methods, assertion calls and all 973 ordered IDs. Its original 45 source controls, all original 21 checksum-owner Source controls, and four metadata/check commands pass locally. The failed original CI source and reports remain unchanged. In actual run 43341104136, all four profiles are terminal. Source 973/973 and default eight/64 pass; the exact Artifact and Evaluation budget failures are recorded in the terminal table above. Artifact failures reach the second emit with the three-second frozen context already expired, before real second-emitter entry. Evaluation has first-emit admission/codegen failures, often before any Evaluation machine entry, and two separate under-five-second timeout failures. The ordinary reports do not record separate first-emitter durations; that missing timing remains unknown, and phase timings from older source are not transferred to this source.

Local integration controls compare 96 actual native combinations of the three overlapping Artifact/Evaluation methods, selections, connection/output variants and install failures. Artifact retains priority when selected; Evaluation runs those overlaps only when Artifact is absent. Poisoned old bodies and aliases have zero calls. Exact captured absence and invalid-owner refusal are preserved. These local controls are not actual-CI or current-cold qualification.

Contract's next independent Service integration preserves original admission/effect/close ordering and captures the exact contract owner, including explicit absence. It reuses the captured-owner hook without adding a duplicate held-owner override. The actual R7 constant-pool portability failures are fixed in that independent candidate, leaving the failed R7 source and evidence unchanged. Its close-continuation controls first exposed three real mismatches; the repair preserves parent-authorized internal calls after close, single-use exact-owner permits, escaped lexical lifetimes and unpublished-function refusal. The complete local 46 component controls and 42 Source controls pass. Actual independent [Service run 43342561448](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43342561448) is terminal: Python 3.11 original/public outcomes match in all 65 cases, including 20 existing or negative exceptions, and real captured-absence Service controls pass with zero native mappings. This is not a claim of 65 successful business operations. Actual 3.14 component46 passes, while the original55 driver hits its unchanged1800 limit with the precise partial boundary recorded above. The original four FAIL names and incomplete final case remain preserved; no missing traceback is inferred. This candidate is not part of either 4925e72d or a733926a.

The published narrow HIA-only change moves invariant extent reads out of three checksum byte loops in Artifact namespace, request journal and slot ledger. Six original/candidate images compile with the same retained development compiler under the unchanged 20 s child limit. Actual local controls cover 82 diagnostic scenarios and 778 paired calls (1556 real machine entries), with complete input/output/workspace/canary equality, independent VM observations, corrupted state, repeated claims and maximum 8 MiB payloads. Same-process, fixed-CPU alternating measurements cover 18 scenarios. At 1 MiB, read-only receipt time changes from 110.98 to 19.95 ms for namespace, 121.74 to 22.92 ms for request journal, and 121.44 to 24.53 ms for ledger. These are component kernel measurements, not an original-business-budget or current-cold pass. Two initial zero-length diagnostic expectation errors and an interrupted large textual trace remain preserved; the complete successful trace uses bounded streaming binary records. Checksum arithmetic, receipt bytes and all original business budgets remain unchanged.

The cold-path audit additionally executes one unchanged-worker A-B-B-A comparison on this host's Python 3.12.14. All eight complete reference payloads and all input byte/mode guards match. Actual child CPU averages increase from 8.3813355 to 10.0194025 seconds for signed and 7.3658995 to 9.035346 seconds for casts between actual 65ce export and the new source. These two observations per source/family establish an added CPU cost here, not a function-level attribution or a replacement cold pass. A separate HIA selfhost `emit` expansion preserves all 125 functions and 1459 blocks at 8152 instructions under the unchanged 8192 limit; retained-seed B1/B2/B3 and modified M2/M3 development fixed points agree. That separate candidate completed340 paired native observations (680 actual entries), including every short-output prefix, full input/output/workspace/canaries, bounds traps and capacity/refusal cases. An independent original-Core-VM experiment compares11412 pairs and rejects a deliberately wrong output/cursor store-order mutant. The fixed CPU experiment is neutral or mixed: bytesum CPU1.034x, instruction8192 1.007x, original selfhost1.009x, candidate selfhost0.999x, namespace0.986x and128-function chain0.999x (old/new medians). Because it consumes48 additional instructions without a consistent material gain, this compiler expansion is explicitly not adopted. Both initial development-driver authoring failures and all neutral/regressive measurements remain preserved. No fresh-B0 or current-cold pass is claimed for it.

## Evidence custody and remaining replacement scope

The new audit roots complete original inner archives, raw logs/reports and recovery recipes for root development, Requests/front, Evaluation R8 and Contract development/default results. The two root archives preserve 897 and 152 logical originals respectively; every archive fragment has been acknowledged, fetched in full and reassembled byte-for-byte. Complete Source R2 outer ZIP is also rooted. Other unique outer ZIPs remain local and in Actions where explicitly documented; whole-outer-ZIP Git custody is not claimed for them.

Recoverable inactive scratch copies and derived transport encodings may be reclaimed only after exact byte/mode reconstruction and custody verification. Unique originals and all production files remain preserved. Scratch maintenance is not old-production removal.

The latest exact published 3324-file inventory includes 1454 Python files: 228 under hepta, 438 tools and 558 tests, plus other paths. It includes 118 HIA assembly files and 12 HIA JSON files. These are syntactic file counts, not semantic completion percentages. Python/runtime providers, Agent wire/catalog/dispatch, tooling/setup/checkers, process/ELF/publication, proof/compiler/optimization and live state/recovery dependencies still require explicit replacement and whole-system validation. HIA-generated control flow with fixed Python object/call mechanisms is not a claim that the Python runtime has been removed.

Closure requires the full owner union, original durable budgets, the original complete suite, matching-current-source cold generation and clean installed/default behavior. Only after actual complete substitution and verification can the old production stack be removed.

Status observed 2026-11-13 01:48:15 UTC. `whole_native=false`.


</details>
