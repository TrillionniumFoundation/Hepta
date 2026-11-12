## 最新核验状态（2026-11-12 15:36 UTC）

**全量 HIA 原生重写仍未闭合，PR 继续保持草稿，旧整套未删除。**

- v89 纯源码 `e4fc00a775dab323758d77a2ef4918fd35585cdc`，树 `d9e8407c70e44a3ea0152b8b4c5eb2ed3833d790`；同树 CI 提交 `784f088fcc5ad81c65de541d54e26d380c86293c`。4076 文件，7 项差异（6 修改、1 新增、0 删除）；61 个生成器保持字节幂等。
- 本地固定 118 项源码控制全部 PASS（107.233 秒，180/3 秒边界）；原有 19 项独立控制全部 PASS（1.858 秒，20/3 秒边界），均保留自然退出、ECHILD 和完整原始记录。
- [标准 CI #43247845814](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43247845814) 已唯一触发。源码任务 **469/469 PASS，360.452 秒**；原生任务仍运行，已进入 Core 函数/SSA/CFG 验证。原有 39 项发布验证、Core 116/UNPACK 等后续结果仍待实际完成。
- v88 的 38 PASS + 1 FAIL、发布归档 HOLD 和缺失原始文件事实继续保留；v89 修复证据工具受共享 `os.fsync` 注入影响及预启动失败摘要字段未初始化的问题，未移除产品故障注入。
- 数值比较有限原生验证已通过：185 个案例、131397 次入口、131200 个窗口。根审阅已独立完整核对 86 个 Git 文件、229 个原始文件和 252282240 字节追踪；这仍是 Python 3.12 开发验证，尚未替代原有 Core 39/18/116、冷启动和安装验证。
- CLI 的四组件源码验证请求已冻结，原有 17 项调用与 46 项追踪尚未执行；数值比较完整接入及 HIA 任意精度整数 ADD/SUB/NEG/INVERT 正在实现。172 个 Python 包模块、19 类托管 Core 操作、41 项 CLI 托管效果及对象运行时等依赖仍须逐项消除。全量 retained 5400/外层 10800 秒验证尚未执行。

以下为按原字节保留的先前状态记录；以各记录自己的时间和验证范围为准。

---

## 当前核验状态（2026-11-12 15:15 UTC）：v88 标准 CI 失败已完整保存；v89 发布记录器修复源码验证进行中

**全量 HIA 原生改写尚未闭合。** 主分支与本 PR head 不变，未合并、未切换默认实现、未删除旧整套。当前仍有172个 Python package modules，19类 hosted Core owners及41项CLI hosted effects；完整5400秒/外层10800秒资格运行尚未执行。

### v88 本次真实标准 CI

- 精确纯源码 `1fd7a1366a2f1fe3f8a6207e400464beb3686a58`，同树 CI head `4202fee300d54344712d727135bef9202b92f8c7`，tree `c7aa2396bb242efb89cd4135557d51e1d2ccfda1`。
- [run43235471904 attempt1](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43235471904) 在14:29:22Z终态 **FAILURE**。source **453/453 PASS，429.735s**；cold原180/3内 **124.952968914s PASS**，38 phases/2 workers/11 checks，B1=B2=B3=`9de8606c...`。
- 发布原39项全部实际执行，**38 PASS + 1 FAIL，53.279s**。未改动的store测试对共享 `os.fsync` 的poison误伤证据记录器；未完成初始化的 `_Call.request` 又令finalizer抛错。archive随后HOLD，Core116/UNPACK及后续19–42步骤均SKIPPED，不能提升为PASS。
- 官方ZIP **68,163,049B / SHA256 `1675be2fd780038b80017f876e63f09272f46e4a7b5eb1a3f2a7541c560bdfb5`**，全部1983外层成员、38内层ZIP/42937成员、840源码对应关系完整读回，133813个custody检查零错误。publication只留START/ARCHIVE；缺失RUN/REPORT、逐调用与fixture原件，**未补造**。上传特殊条目警告保留。
- 全部可得原件与独立审计见 [789c4044](https://github.com/TrillionniumFoundation/Hepta/tree/789c4044270277c3f98a9be39f5ec35785fafba2/experiments/hia_native_source_merge_20261112/combined-v88-standard-ci-failure-r1)。大目录树的两次超时仍记录UNKNOWN；停止该平铺请求后，用已核相同内容的目录树对象构建，最终同一预期tree441e与完整5555叶、168全文读回确认。没有ref写入。

### 新修复与原生进展

- 发布记录器修复纯源 [d79c3142](https://github.com/TrillionniumFoundation/Hepta/commit/d79c3142090636c301cb5307793ebe00c84a5ca7)，证据 [0586d455](https://github.com/TrillionniumFoundation/Hepta/tree/0586d45511b7d2a0b9be598a598332b0a7918b36/experiments/hia_publication_observer_isolation_20261112/actual-r1)：证据自身fsync与原product poison隔离；失败preflight安全记录；仅明确未启动的失败调用可保存其实际残留。原39 bodies/IDs/poison/时限保持。**新16项source/IO控制PASS**；真实标记为SOURCE_CONTROL_ONLY的失败child仍HOLD，6原文件5262B可完整归档。并非原39重新通过。
- v89已合入上述三文件及源码清单/CI入口，拟保原61 generators、**原102+新16=118 source controls**、另行原19、standard source469。准备r1因调用未加-B产生缓存目录被原admission拒绝，**未启动owner或执行测试**；r1保留，新r2输入相同、仅正确使用-I -S -B。r2冻结时为 **PREPARED_NOT_EXECUTED**；现已按同一原180/3请求启动唯一一次118项源码验证，结果尚未返回。
- 数值比较首次finite native：证据 [8abaaa8c](https://github.com/TrillionniumFoundation/Hepta/tree/8abaaa8c0dd381b8ab4422d13eee7b4f033f1aea/experiments/hia_core_compare_20261112/native-development-plan-r3/actual-finite-native-r1)，**8/8 PASS**，185cases/131397 entries/131200 windows，完整252282240B trace `f71b1aec2673bc973e27e92cacb0c2f1be3b3dc3945952d39e62412544db2558`在同一原180/3内全读回；worker6.058057806s，owner6.127729109s自然退出并ECHILD。仍仅CPython3.12.14开发验证，**Core39/18/116、matching cold、wheel、默认与全系统均未闭合**。接线审计 [6a4bfff7](https://github.com/TrillionniumFoundation/Hepta/tree/6a4bfff71a4e83aa1336f9fa51d57e180f18b2de/experiments/hia_core_compare_20261112/v88-merge-handoff-r1) 已找出resource/generator/source-fixture/双companion安装参数缺口，正在实际修复。
- full-retained capsule [b2888a0e](https://github.com/TrillionniumFoundation/Hepta/commit/b2888a0ee47e29f17e080e7c37de429da8ea2ab7) 包含139项proxy入口source controls PASS，当前 **ready=false**，必须等待新修复源码自己的标准CI成功。CLI graph HIA工作继续；旧UNKNOWN操作不重放。

以下为上一版完整正文，原样保留历史状态；以本节的带时间实际结果为当前状态。


---

## Current development status — 2026-11-12 14:16 UTC

**v88 source controls passed; exact-source standard CI is queued, not qualified. The complete HIA rewrite remains open.**

- Pure source: `1fd7a1366a2f1fe3f8a6207e400464beb3686a58`; CI child: `4202fee300d54344712d727135bef9202b92f8c7`; identical tree `c7aa2396bb242efb89cd4135557d51e1d2ccfda1`. Root independently verified all **4,075 source leaves / 410,601,068 bytes**, all seven changed raw files, six modifications, one new test file, and zero deletions.
- Actual v88 source gate: **102 expected = loaded = executed**, all five anomaly lists and loader errors empty, complete 61 generators byte-idempotent, derived declarations stable, worker **111.141073424 s** under original **180/3** ownership. Final source remained unchanged.
- The separate historical custody controls were executed unchanged: **19 expected = loaded = executed**, zero five anomalies and loader errors, **1.835967965 s** under original **20/3** ownership and original **8 s** probes. Natural exit and ECHILD cleanup were observed. Their deliberately synthetic HOLD/UNKNOWN records remain unchanged; historical descendant inventory is not claimed complete. These 19 are not part of the prior standard 437-test source population.
- Actual source102 plus original19 preexecution originals: `643c2a0db10a9a8985a1258b7d5e1e57cc9130fb`. Complete original19 actual custody: `06d99ae1032754d3ce7a533f5e938d1b1043beb6`, including **331 typed objects / 208 regular files / four external roots** named by the original records. All canonical raw evidence parts were read back.
- Standard workflow: [run 43235471904](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43235471904), **attempt 1, push, queued**, created **2026-11-12T14:16:26Z** on `codex/hia-combined-native-v88-20261112-e26e`. The branch was created once after observed absence and zero prior same-head runs; the exact ref was read back. Pretrigger record: `b6572678747ecab6829635cf19e0549ecad0d342`. Expected standard source population is **453**, not an observed result.
- This change streams and verifies complete cold evidence for publication custody. The original product 64 MiB boundary, original 39 publication methods, and their original 30/60/10/5-second callers remain unchanged. v87's original failure and its unexecuted 39 methods remain preserved in `5ee89b4870030c38cb388813506ce8391d4bfe16`.
- Numeric comparison finite native r2 made **one actual launch attempt and stopped before operation-root/owner/compiler/native creation**: the pinned, byte-identical system interpreter has UID 65534 while the generic reader admitted only UID 0 or the caller. Canonical original prelaunch HOLD: `a7a01387318e166f4bf20f8d2beaaf871f897aec`. No native, Core39, original18/116, installed, or matching-cold success is claimed. A narrow interpreter-role admission revision is being prepared separately.
- Complete CLI JSON graph rewrite has a static isolated checkpoint `3e2a218abdb2bdff48d5f16620589e3a37e8d9ae`; it remains incomplete, with actual items-list sorting and versioned exception/reference restoration still open.
- **Full retained 5400/outer10800 has not been dispatched. All 19 hosted Core families and 172 Python package modules remain; the CPython object/runtime, CLI effect ownership and other retained owners are not closed. No default activation, merge, old-stack deletion, or whole-native claim has occurred.** PR #888 remains draft at `acffa9262f31d073f8f0a6f0201eae201039f619`; main/base remains `5831f52fada45e076f8f68f198a15c0585e6104f`.

### Earlier status and original evidence (preserved verbatim)

---

## 2026-11-12 — v87 standard CI FAILURE retained; v88 custody-ingress source request prepared

**Whole-native rewrite remains OPEN. No merge, default activation or legacy deletion.** The latest completed standard run is [43220208164](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43220208164), attempt 1, on exact CI head `b7c2f79e04965e53a1c198703f20b1ff22df4765` / tree `dc29b16468d5ae1e558f317c7ab360b31ac2a002` (pure source `677cca3eb7a781726578aa51172012df34e7d627`).

- **Source:** all 61 generators and contract/idempotence checks passed; 437 tests passed in 429.435 seconds.
- **Native before failure:** cold replay passed in 106.312480565 seconds under original 180/3 limits, with 38 phases and two oracle workers. B1/B2/B3 were byte-identical at `9de8606c153e50f2e742a18d4eb9f3b7c210b404f005346e95b550648d8f2892` (670,467 B). Language 1242 checks, bounded-read finite 55 + 8 + 7, applications 245, and the intervening original native steps passed.
- **Actual failure:** publication step 17 stopped in the new evidence reader before loading or executing any of the original 39 methods. Its 16 MiB evidence limit rejected the ordinary 53,350,905 B cold qualification JSON. The original REPORT is HOLD; RUN has no calls, tests or fixtures. This is not a v87 64 MiB product call observation. Evidence archive step 18 passed; native steps 19–42 were skipped.
- **Complete failed-run originals:** [canonical evidence commit 5ee89b4](https://github.com/TrillionniumFoundation/Hepta/commit/5ee89b4870030c38cb388813506ce8391d4bfe16), tree `87d56268a86522b3b98e9d1830cc12f86fe68495`, preserves the official 68,308,445 B ZIP, both complete job logs, provider metadata and read-only audit. All 1,983 outer members, 42,899 cold-phase original files, 839 source/contract files and the 16 publication originals were fully checked: 134,672 checks, zero discrepancies. The provider's special-entry upload warning remains; no claim covers every original runner filesystem object. Original byte-archive restoration and every new Git blob were verified. Transport disconnect/timeout records and exact immutable-object recovery are retained; no mutable reference operation was repeated.
- **Concrete repair:** candidate [3f21b2c](https://github.com/TrillionniumFoundation/Hepta/commit/3f21b2c6b09835dcf05ed8c6334292d80d9d0893) changes two custody tools and adds 16 I/O controls. It streams complete outer/nested/B3 originals, checks file identity before/after, actual hashes/lengths, unique JSON keys and generation/source/profile bindings. Its explicit 256 MiB aggregate applies only to three evidence originals; original 39 methods and product limits are unchanged. The isolated 16 controls and the actual 54,121,426 B three-file chain passed; full originals are in [664695a](https://github.com/TrillionniumFoundation/Hepta/commit/664695a1e898dfa1a5f1c0707bc76c91dab68cdd).
- **v88 integration is not yet a PASS:** root prepared a 4,075-file source candidate with the new test declaration/profile. The separate source-only request has 102 methods (original 86 + new 16), original 61 generators, only two mutable derived documents, and original 180/3 owner; request SHA256 `33294ce75ea95246738e61b3e208450e398d6afb954087a7e8b7ea628d7316a7`. The historical 19 custody/launch controls are separate, under their original 20-second outer and 8-second probe limits; they were not part of the prior 437-test standard source suite. Neither those v88 requests nor a new v88 standard CI result is claimed here.
- **Remaining work:** matching-source original Core116, new UNPACK116/18 and installed gates remain unqualified by this failed run. Full retained 5400/10800 has not run; its concrete capsule remains blocked pending repaired matching-source CI and final review. All 19 hosted object primitive families, CPython representation/allocation, 172 package Python modules and other runtime/build owners remain open. The isolated exact numeric comparison candidate has source/Core-VM evidence only; its actual native request is still being reviewed.

Previous progress, failure, HOLD and UNKNOWN records are retained verbatim below.

---

## 2026-11-12 12:43 UTC — v87 组合源码通过，标准原生 CI 运行中

**全套 HIA 原生重写仍未闭合，旧栈删除条件仍不成立。** 新组合源码已发布于独立分支；本 PR head 与 main 暂未移动，默认运行路径未切换。

### 当前可审查结果

- 纯源码 [677cca3](https://github.com/TrillionniumFoundation/Hepta/commit/677cca3eb7a781726578aa51172012df34e7d627)，tree `dc29b16468d5ae1e558f317c7ab360b31ac2a002`：整合 bounded-read、UNPACK、SHA 字读写改写、发布原件保留、启动身份修补、UNPACK type cache 与有界进度记录。完整 **4,074 文件 / 410,577,229 字节**逐项核对；45 个文件变更，其中23新增、0删除；172个Python包模块、838个声明源文件、92个native资源/107个安装资源。
- 新组合源码实际 **61项完整生成检查字节幂等，86项源级控制 expected=loaded=executed，五类异常及loader错误为零**。四次派生与原三命令再派生保持一致，worker **103.608346812秒**，原180/3自然退出、reaped/ECHILD。[完整165原件与结果](https://github.com/TrillionniumFoundation/Hepta/tree/34b8ef5a4ccd87bdb01ea6da67c3938de05ded14/experiments/hia_native_source_merge_20261112/combined-v87-source-actual-r2)保留。此结果不等于native、安装或full-retained通过。
- 首轮源检查发现遗漏的SHA传递依赖 `agent_journal.hiaasm`，原 **HOLD** [完整保留](https://github.com/TrillionniumFoundation/Hepta/tree/78efc5522f375f6b1e8cc4ea33601dc127dd732f/experiments/hia_native_source_merge_20261112/combined-v87-source-r1-hold-r2-preexec)。三份派生HIA都仅改相同的两个SHA字读写函数，其余函数原文一致；补齐源码后才建立新请求，未改预算或重标首轮。
- 同树CI child `b7c2f79e04965e53a1c198703f20b1ff22df4765`，独立分支 `codex/hia-combined-native-v87-20261112-e26e`，已单次触发 [标准CI 43220208164](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43220208164)，push / attempt1，12:41:25 UTC创建；12:43观察为 **IN_PROGRESS**。source job131189502400正在全量生成检查；native job131189502067已完成固定Python3.14.4、四包和Clang20供给，正在原180秒冷启动。后续步骤尚待实际完成。[触发前完整冻结记录](https://github.com/TrillionniumFoundation/Hepta/commit/338229f1a96183f3a7b2548b11da6526cadedf95)。

### 已保留的独立结果与未闭合项

- v86独立原生开发验证 [00cc4ce](https://github.com/TrillionniumFoundation/Hepta/commit/00cc4ce217e0b2459530dcf0c2224030b856fcdf)：原12个SHA方法体与2个发布开发方法通过。实际64MiB store-put **24.530895772秒**、store-get **20.147274360秒**，超额hash/put均rc17，通用64MiB+1发布 **24.102972027秒**；调用时限仍为原60/30秒。该轮使用固定开发输入，未执行原发布39全套、匹配新冷启动或完整CI；不继承为v87资格，也不把旧v82超时称为flaky。85个regular原件479,273,670字节已全量归档和读回。
- v79官方614,221,066字节ZIP及完整恢复脚本已[全部持久保留于47f089a](https://github.com/TrillionniumFoundation/Hepta/commit/47f089ad427825bc43d522a7252b600822faa1fe)。原v79标准CI PASS、v82 FAIL、UNPACK旧116超时FAIL/HOLD及全部UNKNOWN状态分别保留。
- 当前标准CI新增门必须读取同一当前冷启动的B3/Core39/UNPACK实际原件，要求**完整116不拆组、完整18、独立两门合取**；原30门保持，新增2门不可省略。进度记录只用于定位执行过渡，不能把“开始”或局部完成当PASS。
- **19类Core宿主分派与CPython对象/事务桥仍存在，CLI、SQL、Z3及Rust/构建依赖尚未整套闭合。** 下一处真实算法迁移正在独立实现精确bool/int/float比较，当前不计为已交付。
- **完整retained 5400秒 / 外层10800秒尚未运行。** 已在准备固定源码与实际Lean/QEMU/LLVM/Rust离线55crate/六NDU夹具供给和原972d预检；需标准CI实际通过和具体冻结胶囊审查后执行。未伪造READY、未移除依赖门、未扩展原限制。

以下历史审计与 PASS / FAIL / HOLD / UNKNOWN 原文保留；其“当前”指对应记录时间：

---

## 2026-11-12 11:30 UTC — UNPACK 实际超时，完整失败原件已持久保留

整套仍未闭合；本 PR head 与 main 均未移动，没有启用默认原生路径或删除旧实现。

- [UNPACK 独立开发 run 43207324933](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43207324933) / job 131145694244，create / attempt1 / B `7207a911aa9c7f6f218f70d145b3c87ec5d54e91`：实际 **FAILURE**。新 B0/B1/B2 + Core39/UNPACK 共42次编译准备自然完成；18组件（4shim + 6finite + 2source/6native）expected=loaded=executed、五类异常为零，worker3.261423593s。两阶段分别在原180/3内自然结束。
- 默认完整116调用方阶段触发原180s超时，SIGKILL/-9，cleanup46,817,514ns、reaped/ECHILD、remaining=[]；原 `FINAL.json` 为 **HOLD**。完整116报告缺失，已有安装报告与局部日志不能代替整轮通过。不得拆组、延长时限或把这轮重新标为 PASS。
- [完整原件 canonical 6af63ed](https://github.com/TrillionniumFoundation/Hepta/tree/6af63ed0bb226ff5c19cffb612f10aa5875cdf37/experiments/hia_native_source_merge_20261112/core-unpack-v83-r1/native-originals-r1)：原ZIP159,656,529B / SHA256 `7b963b2db27ca29a62ad8090d20b78589c3e27945bd067d2cf3e8f9c590d29a6`，1550成员159,115,835B逐文件完整CRC/SHA读取；原ZIP、全日志及审计共31原件171,173,469B无损归档，全部39新Git叶已读回。5964只读核验、1252内部原件引用吻合，只证明原件留存和明确标注的阶段检查，不授予产品资格。
- [匹配当前冷启动的 UNPACK 门槛草稿 2f61dc1](https://github.com/TrillionniumFoundation/Hepta/tree/2f61dc1002086dbebaf5d65ce1f924c430df4610/experiments/hia_core_unpack_20261112/matching-cold-gates-draft-r1)：保留原30必需门槛并增加2项；要求当前同一B3、Core39、UNPACK、完整18+116及安装原件，两独立180/3。14项源码控制通过；尚未在组合源码执行 cold/native/full-retained。

以下历史审计与 PASS / FAIL / HOLD / UNKNOWN 原样保留：

---

## 2026-11-12 11:08 UTC — 全量审计与候选更新

**整套原生重写仍未闭合，旧栈删除条件不成立。** PR head仍为 `acffa926`，main仍为 `5831f52f`，各独立候选尚未整合。

[全量审计、模块清单及剩余所有者](https://github.com/TrillionniumFoundation/Hepta/blob/72a74337e49cec315f1d3a94c48d49414160b944/experiments/hia_native_source_merge_20261112/full-project-audit-r1/AUDIT-NOTES.md)：当前PR为4023文件/168个Python包模块；v84为4051/170；UNPACK候选为4063/172。170模块逐blob/AST审读51270行、687条包内导入；19类Core宿主分派仍存在，数量不是迁移完成率。

| 独立候选 | 实际新增结果 | 仍待验证 |
| --- | --- | --- |
| v84 `752495d` | 原54源码方法PASS，精确rename原参考、60生成器及派生幂等修复 | 新完整CI |
| v83 `006accd` | 3幂等+56方法PASS；61生成器、3.14.4固定，Core39原字节保持 | 18组件+完整116原生；A418062f8/B7207a911已冻结供审 |
| v85 `3b1fe7d` | 14现场保留控制PASS；原/tmp、39方法、64MiB及30/60/10/5秒时限保持 | 带保留机制的原39；原发布步骤没有外部180秒门 |
| v86 `83106d7` | 4420完整u64作者轨迹+原16源检查PASS；非get/put HIA函数全等 | native/性能/原64MiB；容量和时限未改 |

两代实际B3进行了唯一6编译+2打包开发诊断，三份机器码和最终147954字节ELF逐字相等；73原件11.26MB已封存于[`2f76bf1`](https://github.com/TrillionniumFoundation/Hepta/commit/2f76bf1ba7827734bd469d062cd0802a4e001f31)。未运行app、未恢复原CI已删程序，原60秒FAIL不归为flaky。

v79完整原件169226项、v82完整原件169280项核对PASS；严格配对6144分母中2989对完整请求相同且输入/输出/status零差异，3155对不同请求另留。v80原安装FAIL/HOLD保留，修正只读arity后262项核对通过；v82 bounded独立2044项核对通过。均不改原CI状态。

下一步接入完整18及116 matching-cold/full-harness门，再整合候选运行同源标准CI。**完整retained5400s/外层10800s尚未执行；原30门、全部FAIL/HOLD/UNKNOWN、CPython事务shim及其他宿主依赖边界保留。**

---

## 当前审计状态 — 2026-11-12 09:52 UTC

**仍为开发中的草稿；整套 HIA 原生重写未闭合，旧实现尚未删除，默认运行路径与本 PR head 尚未切换。** 以下是本次续作的当前状态；后文全部旧记录保留为历史事实，不能用旧 PASS 覆盖新 FAIL/HOLD。

- **v79 标准 CI 两项均通过**：[run 43182678063](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43182678063)。source 406 项通过，native 标准流程包括原完整 Core 116 项与 ELF 原调用者门禁通过。纯源码 [e7debb7](https://github.com/TrillionniumFoundation/Hepta/commit/e7debb7492da1b597cf02f018ee3c64fd157405d)，实际 CI head 9739fb8 与其 tree 相同。原始 source/native 日志已逐字保存。614,221,066 字节官方 ZIP 正由唯一已审查的两片传输任务 [43194656565](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43194656565) 保全；尚不把传输中的原件宣称为完成物理审计。
- **合并候选 v82 仍 FAIL**：纯源码 [35ff537](https://github.com/TrillionniumFoundation/Hepta/commit/35ff5374bc2f913e5139c49e1cea0acaf37ffc3c)，实际 [run 43191120147](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43191120147)，同 tree 的 CI head afea182。source 412 项中产生 4 个失败记录：完整编译器重命名样本两项旧精确值，以及两处仍固定为 59 生成器的清单。正在保留原方法 ID、旧 59 项有序前缀和完整 payload 断言，使用独立历史 reference 实算新精确值；没有放宽编译器容量或删除测试。
- v82 native 的冷启动、新 bounded-read 匹配冷构建门禁及先前步骤通过；后面的制品发布/内核竞态 39 项中有 1 项 ERROR：64 MiB inclusive quota 的真实 store-put 超过原 60 秒调用时限。该时限保留，后续门禁被跳过；完整日志与官方失败制品均保留，不能记作全 CI PASS。原 source/native 日志分别 SHA256 b835d3e52f621f848c23720eb69a4d084149e7313e65591d40730d3f3339af9d、b8793cdfd0d93ab1f577c11d3b31bd41ccd5eb1df82d6cfa80f60d3a089f5ef0，见 [封存提交 f403c16](https://github.com/TrillionniumFoundation/Hepta/commit/f403c16d4dd9ad4948c1cef19e8d5c7d377a3c33)。
- **bounded-read v80 实际运行仍为 FAIL/HOLD**：[run 43191718592](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43191718592)。新鲜编译、原 55+8/7 CLI 与安装执行步骤自然完成；独立最终 reader 错把三个 buffer span 当作三个扁平 ABI 参数，而实际为六个参数。9 个安装方法与实际 native 记录已完整保存，官方 ZIP 17,443,242 字节及所有成员封存于 [f76e1e1](https://github.com/TrillionniumFoundation/Hepta/commit/f76e1e1fcbe118519aa70f8ff13f6ab8b9419aad)。只对这同一份封存结果修正 readonly 核验；不重跑产品，也不重标原 workflow/FINAL。
- **Core UNPACK**：HIA 控制流与最小 CPython C-API 事务桥已完成有限原型和接入源码。当前 35ff 上的合并覆盖与 15 项 compile/AST 检查通过；新的 8 项普通组合、10 项有限控制和完整 116 项还未执行，不能沿用旧输入的结果。CPython/对象模型依赖仍存在。
- **整体边界仍未闭合**：当前包有 170 个 Python 模块；Core 原 ABI 仍有 19 类 hosted primitive，CPython、OS/SQL/Z3、Rust/构建工具等依赖仍待消除。完整 retained 5400 秒 / outer 10800 秒套件尚未运行。冷启动保持 180 秒、2 workers、38 phases、cleanup 3 秒；所有应有 ID、完整载荷、五类异常零值要求保持不变。当前证据不支持删除旧整套或声称“全 HIA 原生交付”。

### 以下为此前检查点与历史原文（保留）

## Purpose

Continue the complete HIA migration with source-bound native owners, ordinary caller coverage, installed resources, and strict process ownership. The requested final cutover still requires complete matching-source qualification and closure of the remaining hosted owners.

## Current audit and development state — 2026-11-12 (UTC)

**Full HIA ownership, full retained validation, and removal of the old stack remain OPEN.** The PR head remains `acffa9262f31d073f8f0a6f0201eae201039f619`; the newer candidates and original evidence below are isolated commits/branches, not a merged or activated release.

### Latest combined source and actual CI failure

Pure candidate [d0e110e](https://github.com/TrillionniumFoundation/Hepta/commit/d0e110e19f9433baaf202a0f605671c7205b4cff), tree `6381daf9beb11d873d4608c26facc0b9e5bc747f`, has 4,034 leaves. Its seven changes repair retained `.py.txt` document references, preserve separate naming compile/invoke originals, add independent controls, and regenerate source identities. All 47 selected source controls passed with exact expected/loaded/executed IDs, five anomaly counts zero, natural exit, and ECHILD (60.189 s under the original 180 + 3 s owner).

The single source-identical CI child [8ecb4a0](https://github.com/TrillionniumFoundation/Hepta/commit/8ecb4a0a3bcb27381fa2c7b7af962876e5836edd) produced [run 43178231433](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43178231433), push/attempt 1, **FAILURE**:

- Cold replay **PASS**, 91.985578220 s under the unchanged 180 s limit, with natural exit, ECHILD, and all 11 wrapper checks true. Language coverage also passed. The official 67,366,366-byte ZIP was downloaded and all 1,736 outer members were fully CRC/SHA checked; complete independent joins inside all phase ZIPs remain pending.
- Source regeneration, the 59 generators, contract checks, coverage generation, and clean regeneration diff passed. The source suite ran **406 tests / 586.486 s**, with one failure.
- The next native application suite ran **245 tests / 183.466 s**, with two failures. Both jobs expose the same stale independent installation-test expectation: `CORE_LOWERING_RESOURCE_FILES` still enumerates `range(31)`, while the actual ABI, source package, and release manifest correctly contain numbered units 000–037 plus the pool (39 HIA sources, with one additional ABI resource). The installed-child comparison is the second native failure.
- All later native workflow steps were skipped. This run does not prove the complete combined native stack. The test expectation repair and actual installed-package rerun remain outstanding.

The complete original job logs, acknowledged single trigger, provider terminal records, and scoped failure assessment are preserved in [66fe9a4](https://github.com/TrillionniumFoundation/Hepta/tree/66fe9a4501dec49a4e9c5cc43664c7f7dc6a36d8/experiments/hia_native_source_merge_20261112/combined-ci-fixes-r3/actual-run43178231433). The prior combined [run 43172943629](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43172943629) remains a genuine FAIL: document-reference rejection and a 180.194632726 s cold timeout with only 34/38 indexed phases complete. The new cold PASS does not erase that result or establish the cause of its timing difference.

### Independently completed component development runs

| Scope | Actual result | Boundary still open |
| --- | --- | --- |
| Core lowering r3, [run 43175231100](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43175231100) | 39 HIA units; all **116 = 15 + 51 + 50** original methods; five anomaly counts zero; 96.675546620 s test report; 2,288 independent readback checks; full 157,231,746-byte official ZIP retained losslessly | 19 hosted primitive kinds remain. Candidate `946f3fd` and actual derived tree differ only in the two generated support/coverage JSON documents. This is scoped development qualification, without default activation or a whole-stack claim. |
| Bounded read r2, [run 43175489773](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43175489773) | Exact **55 finite cases + 8 original methods**, seven original CLI children at their unchanged 20 s limits, 34.200557801 s outer natural owner; 260 independent physical/native joins; complete official ZIP and typed custody retained | CPython object/context/OS transport, full foreign-input equivalence, cyclic-GC scheduling, installed integration, and current combined cold qualification remain open. |
| JSON pretty, [run 43156502540](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43156502540) | 43 native + 9 installed original methods; 122 native completions; exact populations and five anomaly counts zero | Whole-graph serialization, Unicode flags and mutable hooks remain hosted; this isolated result does not prove the combined 103-resource installation. |

Core full originals and audit: [842be83](https://github.com/TrillionniumFoundation/Hepta/tree/842be83dc63de511d4a4fcb461ddf546e4689d91/experiments/hia_core_emitter_20261111/native-development-r3/actual-run43175231100). Bounded full originals and audit: [a270261](https://github.com/TrillionniumFoundation/Hepta/tree/a27026122c62c55994c5f836914cccf25fec3836/experiments/hia_bounded_read_owner_20261112/actions-native-development-r2/actual-run-43175489773). The bounded evidence commit and every blob are readable by SHA; its branch-ref update acknowledgement remains UNKNOWN and has not been resent. Root additionally compared the exact frozen Core 116 IDs and all five bounded populations against the actual audits, and read both full audit files back byte-for-byte from their canonical Git blobs.

### Full project inventory and retained historical gaps

The corrected full package AST inventory has **169 Python modules, 2,647,109 bytes, 50,763 lines, 254 classes, and 2,233 function definitions**. Every definition was independently matched to `ast.walk`; zero parse errors. [The complete r2 inventory](https://github.com/TrillionniumFoundation/Hepta/tree/ac2eba6ea24e7532a95d75edd3c3b8c52ea2ea1f/experiments/hia_native_source_merge_20261112/current-source-inventory-r2) preserves the prior r1 miss of 29 definitions in 13 modules. Counts are an inventory, not a native-completion percentage. CPython/object/OS, SQL, Z3, Rust and development tooling remain dependencies.

The historical successful `9704596` run now has a complete [physical readback](https://github.com/TrillionniumFoundation/Hepta/tree/55564b67e2de0cc4a8bd5c2bba641b8ed0e3ee9c/experiments/hia_970_ci_original_custody_20261112/independent-full-physical-readback-r3): 19,100 outer members, all 38 phase ZIPs and 42,623 inner files, with **162,338 checks** and no remaining reader errors. However **46 original compile companion records were genuinely overwritten** by later names invocations. Produced images remain verified; lost original records were not recovered. Historical functional PASS remains, and complete per-invocation custody remains HOLD. The current naming-label repair must be independently checked against the new actual artifact.

The [cold-cost comparison](https://github.com/TrillionniumFoundation/Hepta/tree/7c48cac08cd31b62f26854b6ca881c853e33d9c7/experiments/hia_970_ci_original_custody_20261112/cold-cost-comparison-r1) verifies 4,897 paired native invocations over 35 shared phases, with equal inputs/images/outputs/results and the same qualifier/observer implementation. The records do not establish CPU scheduling or resource contention as the cause of the slower failed run. A separate minimal HIA compiler scan-bound optimization is under review; all admission limits remain unchanged.

### Remaining closure work

1. Repair the stale independent installed-resource expectation; rerun the complete original source/native CI and finish full physical custody joins for the new cold run.
2. Integrate the audited bounded-read HIA component into the current pure-source candidate with complete resources and original finite/original-CLI validation, without widening its proven semantic scope.
3. Continue replacing the 19 Core hosted primitive kinds and the remaining package/tooling/OS owners with actual HIA implementations.
4. Execute the unchanged **5400 s retained qualification / 10800 s outer owner** on the eventual exact combined candidate. This has **not** run.
5. Only after complete semantic, installation, bootstrap, retained-evidence, and native-owner closure, remove the superseded stack. No old owner, historical FAIL/HOLD/UNKNOWN, default branch, or activation setting has been removed or rewritten.

The local executor is temporarily unavailable after the latest readbacks; Git-only audit and source preparation continue. Historical UNKNOWN mutation acknowledgements remain readonly-reconcile-only.

## Earlier verified development state — 2026-11-12 05:07 UTC

Full HIA ownership and final cutover remain **OPEN**. The PR head remains `acffa9262f31d073f8f0a6f0201eae201039f619`; the isolated product candidates and evidence below have not been merged or activated. No old owner is qualified for deletion.

| Area | Actual result | Remaining boundary |
| --- | --- | --- |
| Seven-module compiler caller source closure | [Original CI 43140734709](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43140734709) succeeded; all 401 original source IDs and all native job steps passed | Independent original cold JSON and complete five gate/owner chains are still being recovered |
| Native JSON pretty formatting and installation | [Fresh installed run 43156502540](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43156502540) succeeded: 43 original native cases plus 9 installed cases, all exact IDs and all five anomaly counts zero, 122 native completions | This verifies the pretty owner and its installed Python adapter/resources; full graph serialization and whole-project HIA replacement remain open |
| Core emitter generated source custody | [Small diagnostic 43157292390](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43157292390) succeeded; 25 originals recovered and independently joined to exact bytes | The 39 HIA assembly bodies plus ABI body are still to be retrieved in fixed bounded partitions, then compiled and tested |
| Bounded file-read owner | [Lifetime-aware HIARDB03 source revision](https://github.com/TrillionniumFoundation/Hepta/commit/856551e9b233c1c2ccc81dcbcd3c7867c2c3b5fb) saved with explicit operand moves, local roots, and unwind/release order | Unexecuted development source; native callback/finalizer/error-path differential traces are required |

### Fresh pretty installation result

The pure [product candidate a74a0306](https://github.com/TrillionniumFoundation/Hepta/commit/a74a030680bb73da9a4599567962d01a9d6bcac0), tree `2d47e3af79e558d2651d5f43f0759a02a404b6a5`, has 4,027 leaves: four additions and six modifications relative to 970, no deletions, and the other 4,017 leaves unchanged. Its resource declaration preserves the original 80 native resources and adds pretty as the 81st; the 96-entry publication manifest preserves every original resource. The generated support and language-coverage locks were corrected together and then reproduced byte-for-byte by the actual Python generators in this run.

Frozen controls A `72cc84c7451440e131d1f848288d26e057bf00c3` and its single-workflow child B `3e5366b2613bb487337bdc48b4337e1799dde797` performed actual sdist creation, wheel construction, installation into a fresh target, and native execution against that installed target with an empty PATH. The 43 original cases and 9 additional installation cases all passed. Installation cases include invalid manifests, warm source mutation/removal with restoration, absent installed data roots, duplicate JSON keys, and reentry. The normal and callback paths produced 108 native completions; the installed cases added 14.

The owned 43-case subprocess took 0.938624598 seconds and the installed-case subprocess took 0.564553660 seconds, each within its original five-second limit. The authoring worker took 25.184684661 seconds; the outer start-to-exit lifecycle took 25.550755220 seconds within the unchanged 180/3 owner. Every recorded owner closed naturally with ECHILD, without timeout, kill, remaining children, or cleanup error. The internal 43-case loop time of 0.512376470 seconds is not the full subprocess duration.

The run freshly produced equal B1/B2 compiler images, then a 34,203-byte pretty native image with SHA-256 `a98b066da08dd29757fe4ef801704c66be69f0aed350290e8672aca6e9a59555`. It also verified an 8,593,534-byte output, preserving the absence of an 8 MiB output cap. Root retained and independently decoded the complete 1,892,372-byte job log into 50 raw originals / 185 frames / 1,326,845 raw bytes, and passed 74 cross-record and source-tree checks. [Canonical originals and root observation](https://github.com/TrillionniumFoundation/Hepta/tree/a62661e60c3f0accdf019f51cdbebcecc28fd810/experiments/hia_json_pretty_20261112/installed-development-r1/root-actual-43156502540) preserve those exact bytes. [Independent peer proof](https://github.com/TrillionniumFoundation/Hepta/commit/2549efc9730f6d2d970ed178270567552a6bb6c4) independently decoded and checked the same run.

The complete 51,341,636-byte uploaded artifact has provider SHA-256 `f410a26f5b1c61e993612ec832ba819030d0e4785c8f6576f76ae1724807efc7`. Root directly received the framed originals and complete log; it did not independently materialize that artifact binary. Package archives and installed members were read by the frozen worker and independent finalizer, with their original reports joined against the exact product tree.

### Original failures and bounded custody recovery

The Core generated-asset reader [43152508792](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43152508792) remains **FAILURE**. Its owned artifact read closed naturally, but the provider marked the later framing step failed. Its retained 7,381,515-byte artifact was read once by the new small diagnostic, which checked the complete ZIP CRC/SHA inventory and all 54 historical pins. Root independently recovered 25 raw diagnostic originals / 59 frames / 386,671 bytes and confirmed 39 assembly hashes. The recovered old RESULT declares complete framing, but this does not change the failed provider run or establish its failure cause, which remains **UNKNOWN**. The new stream contains no assembly or ABI bodies. [Exact originals](https://github.com/TrillionniumFoundation/Hepta/tree/0b5fffce79ea2cb10ea32edbbc520625e91e380c/experiments/hia_core_emitter_20261112/failed-reader-diagnostics-r1/actual-r1) and [root trigger plus 28 independent checks](https://github.com/TrillionniumFoundation/Hepta/tree/5a16aa32bf15f8e0e01a3fe8641811276da0f382/experiments/hia_core_emitter_20261112/failed-reader-diagnostics-r1/root-independent-43157292390) preserve this scope. The next reader is being prepared as 20 fixed source partitions, two concurrent jobs, with each stream capped at 512 KiB raw / 1 MiB framed output.

The original 970 evidence reader [43150215535](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43150215535) remains **CUSTODY_HOLD / FRAMING_HOLD**. Its separate 22 MB recovery [43152509740](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43152509740) was officially **CANCELLED**, with no uploaded artifact and no recovered terminal job-log bytes; cancellation cause remains **UNKNOWN**. A smaller fixed 13-original-plus-5-current-control diagnostic is being prepared against the retained 22,390,611-byte artifact. It checks the outer ZIP and original captured-file ledger but does not open the inner selected archive, download the 599 MB artifact again, or rerun the product CI.

The remaining whole-project requirements are unchanged: matching-source complete cold qualification in 180 seconds with two workers and all 38 phases; original caller limits; retained regression in 5,400 seconds under its 10,800-second outer owner; complete exact test-ID populations with zero anomalies; and closure of the remaining hosted owners before old implementation removal. The historical FAIL/HOLD/UNKNOWN results below remain historical facts.

## Repaired source closure and historical original CI

Current head is [acffa9262f31d073f8f0a6f0201eae201039f619](https://github.com/TrillionniumFoundation/Hepta/commit/acffa9262f31d073f8f0a6f0201eae201039f619), tree `22a095436c94efc87b1a89aca912c8caab2eed80`, with 4,023 source leaves. The PR checkout is the real merge commit `9796578f490cb9ed2720fd6b0fb6d1a42cc25987`, with the identical source tree.

Both recovered acffa HIA CI runs failed at **Original 51 ELF callers with retained writer forbidden**. The exact original reports now identify the failure: the strict cold-source membership assertion rejected three missing test modules. Both inner caller reports actually loaded and executed the complete same 51 IDs with zero anomalies and no retained-writer calls, under naturally closed 180/3 owners. The enclosing gates remain `HOLD` and those historical CI runs remain `FAIL`; the inner reports do not qualify the incomplete source closure.

A same-class audit found four additional omitted original caller modules. The isolated [complete seven-module repair](https://github.com/TrillionniumFoundation/Hepta/commit/9704596acc4470bd0042838586602e26bac7b3d1), tree `c3ca94c57f9bd75f22f2c694e32bca2dfc6b329b`, changes only the declaration, an existing source-control test and the generated support contract. It preserves all 4,023 leaves, the other 4,020 files, every original caller ID, the failing membership assertion and all limits. [Original CI 43140734709](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43140734709) is now **SUCCESS**. The source job passed all 401 exact original IDs in 423.801 seconds, after the original 59-generator/contract regeneration and clean-diff steps. Its complete ordered 401-ID population matches the historical original log. The native job completed all steps through the original ELF caller gate. Root and Native independently retained both complete logs and the exact 599,427,251-byte artifact seal. Independent recovery of the original cold JSON and five complete compiler gate/owner chains is still open; the PR head remains acffa while that evidence is resolved.

The two historical acffa source jobs passed all 401 tests each. Their native jobs passed through the complete state, instruction, Core lowering, and ELF component/boundary gates before the final ELF caller gate failed. Those failed runs remain unchanged. Complete retained regression has not been dispatched for the final migration candidate.

## Changes in this candidate

- Integrate the native Store authority, artifact/page, machine state, instruction, ELF, and 32-image Core lowering owners with ordinary caller paths and source-bound installed resource admission.
- Preserve the complete 30-gate qualification surface and the actual process-owner receipts, including their raw hashes, natural termination, bounded cleanup, and source/image identity checks.
- Repair four integration source controls: the exact 33 Core resources, the complete bootstrap/source contract union, the full workflow command sequence, and the original 55 commands plus four new gates. The original test method populations and failure behavior remain intact.
- Regenerate the support contract from the complete source. The regenerated language inventory is byte-identical to the preceding candidate.

## Actual validation

| Observation | Actual result | Scope |
| --- | --- | --- |
| [Source authoring 43116276591](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43116276591) | PASS | 59 generators, 53 parsed Python files, 68 zero-return commands; 11 accounting + 18 compiler-gate + 24 original integration methods. Original 180-second owner closed naturally in 90.260128181 seconds. |
| [Push 43117621509](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43117621509) source | PASS | 401 tests, 584.453 seconds. Complete original log independently read. |
| [PR 43117632066](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43117632066) source | PASS | 401 tests, 429.017 seconds. Complete original log independently read. |
| Both recovered acffa native jobs | **FAIL** | Step 38 `HOLD`: the global cold-source map omits three of the four exact caller modules. Both original inner 51-test reports and natural owners were recovered and verified; this does not upgrade the failed gates. Steps 34–37 recorded PASS. |
| Separate Core development observations | PASS in three separate runs | Exact 12 + 51 + 50 IDs and zero anomalies; 28 modes and 3,799,403 actual native steps. The three owners' times are not a single 180-second qualification. |
| [Exact-source supplier 43119431463](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43119431463) | PASS | Unchanged exporter preserved the real commit/tree/object closure, reconstructed it, and reproduced an independent clone. Source supply only; no product qualification. |
| [Repaired source CI 43140734709](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43140734709) | **SUCCESS** | Source: exact 401 original IDs / 423.801 seconds; complete ordered list matches the prior original. Native: all original steps succeeded. Cold and compiler gate originals remain pending independent recovery. |
| [JSON layout bulk r4 43145616377](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43145616377) | PASS, component development | Fresh source build, 37 exact cases / 61 actual native calls / five anomaly counts zero; child 0.531802866 seconds under unchanged 5 seconds; natural 180/3 owner. |
| [JSON byte bridge 43149458039](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43149458039) | PASS, component development | Fresh source build, all 43 exact cases / 108 actual native calls / five anomaly counts zero; child 0.823272526 seconds under unchanged 5 seconds. Original 37 guarded cases retained; six new bridge controls include one explicitly host-only type case. |
| Complete retained regression | NOT RUN | Requires newly bound final source, completed native owners and full original prerequisites. |

The push cold summary recorded 11/11 checks and language coverage recorded 1,242/1,242 checks. The original artifact receipts, phase inventories, and new native gate details still require independent recovery; job summaries do not replace those originals.

All original constraints remain: cold 180 seconds, two workers, all 38 phases; original 3/5-second callers; unchanged compiler capacities; complete retained discovery at 5,400 seconds under the 10,800-second guardian. No skips, reduced denominators, or development-group totals can substitute for a complete gate.

## Current full-tree audit — 2026-11-12

The [complete current-tree status audit](https://github.com/TrillionniumFoundation/Hepta/tree/83fb689d41893d368dcb69817d10b05995210915/experiments/hia_current_development_status_20261112/acffa-r1) pins all **4,023 leaves / 408,149,624 bytes** to the exact product tree. The independent [168-module production owner matrix](https://github.com/TrillionniumFoundation/Hepta/tree/1d6d2c0ea9c410cbaedddab27490a4716ab216e1/experiments/hia_current_owner_audit_20261112/acffa-r1) records **145 unchanged / 11 changed / 12 added / 0 removed** against the historical recorded file hashes. All 168 current production Python files were read and blob/size checked. The 23 changed/new entries received current control review; the other 145 received identity and entry/selector census, not a new line-by-line semantic proof.

The audit covers thirteen production families, including proof/resource analysis, alternate backends, optimization, lifecycle and NDU/Rust interfaces. Explicit native selectors still retain unselected Python owners; native payload execution does not qualify the whole runtime, database, build/install or test stack.

The two historical failed artifacts were recovered by [run 43128015294](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43128015294) into a sealed 35,868,688-byte artifact. That is successful custody only. The separate [fixed original-report framing run 43132079819](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43132079819) was queued at this checkpoint; no original product run is replayed or reclassified. A third same-tree [push run 43119431198](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43119431198) separately has source success and native caller-gate failure.

Emitter v2 [source authoring run 43131161021](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43131161021) was queued at the original 01:19 UTC audit checkpoint. A separate HIA JSON layout candidate at that checkpoint had 31 development IR cases passed and a corrected public u32 entry; its public Core/native validation control was frozen but unexecuted. Neither candidate is part of this PR's product head or a replacement for original callers/cold qualification.

## Subsequent development observations — 2026-11-12 02:04:32 UTC

These isolated development results do not change product head `acffa9262f31d073f8f0a6f0201eae201039f619` or the original failed ELF gate.

- **Actual Core Emitter source authoring passed:** [run 43131161021](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43131161021) generated all 39 HIA source units, with 39/39 public Core parse/render/verify round trips inside the unchanged source, line, operation, block, SSA-name and argument limits. The complete 33 original AST bodies and 36 modes were bound. Worker time was 36.092089259 seconds; its original 180/3 owner observed natural exit at 36.398639482 seconds and closed ECHILD. The [independent original 14-file and complete log readback](https://github.com/TrillionniumFoundation/Hepta/tree/771835ef1230a47bb61e7438ae4eddb65a67a92a/experiments/hia_core_emitter_20261111/actions-source-authoring-r2-root-actual) retains the raw source-only report. No native compiler, Core VM, product tests or cold qualification ran in that operation.
- **Actual source asset recovery is queued:** [run 43138417048](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43138417048), exact workflow `0753cae7150e2c8d01b0d5cbec41264e831b5d3e`, reads the sealed 12,049,642-byte artifact once. The [reviewed fixed inventory](https://github.com/TrillionniumFoundation/Hepta/tree/4e3db512d852d3becbc0b97985c0cc26dd6a40bf/experiments/hia_core_emitter_20261111/generated-assets-reader-root-review-r1) binds all 103 original members and selects 54 original files / 7,251,108 bytes for exact log-frame readback. This is read-only custody, not a new generation or a qualification run.
- **JSON pretty r2 native validation is queued:** [run 43134139906](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43134139906) retains the exact original 31-case request and limits. It is not replaced or restarted by subsequent source work.
- **JSON pretty r4 development passes:** the [actual HIA bulk-copy revision and observations](https://github.com/TrillionniumFoundation/Hepta/tree/8357db004130819a82f44451e8b6e552aa93f100/experiments/hia_json_pretty_20261112/bulk-source-r4) preserve valid-input short-output error offsets. The predecessor's concrete offset regression is retained. All 33 V8 IR cases, 477 small-capacity comparisons and eight explicitly sampled maximum-depth capacity comparisons passed with guarded buffers; these are development interpreter results, not native timing or original CLI compatibility. The 21,222-byte r4 assembly has eight functions and stays within the existing compiler caps. Every nonzero status still invalidates output and length.

The next Core native development candidate must preserve all **15 component + 51 machine + 50 Core = 116** exact test IDs in one unchanged 180/3 owner. Separate source preparation is not cold qualification and may update only the two declared generated contract files, with complete resulting source identities retained. Existing FAIL, HOLD and UNKNOWN results remain unchanged.

## Original failure diagnosis and minimal repair

The [root's exact original-byte readback](https://github.com/TrillionniumFoundation/Hepta/tree/4294dba64d00f142f6504445e46f5d64f868ec1d/experiments/hia_machine_elf_recovery_20261112/original-gates-root-readback-r1) retains the complete 1,810,149-byte log and all 28 original files / 69 frames / 1,312,028 raw bytes. Each frame and complete file hash was checked. Both tracebacks stop at the unchanged `tools/hia_compiler_owner_gates.py` source-membership condition with `ValueError: ELF original caller source bytes differ`.

The three actually omitted ELF inputs were `tests/test_hia_machine_plan.py`, `tests/test_hia_machine_x64.py` and `tests/test_hia_safe_core_artifact.py`. Their original report hashes match the exact repository bytes. The related original machine/Core module census additionally found `tests/test_hia_agent_native_machine_choices.py`, `tests/test_hia_machine_registers.py`, `tests/test_hia_program_native_review.py` and `tests/test_hia_machine_lowering_edges.py` missing from the same declaration. The repair covers all seven and adds a provider/module-to-declaration/contract/actual-byte regression inside an existing method, preserving all 18 original source-control method IDs.

The [independent root review](https://github.com/TrillionniumFoundation/Hepta/tree/6db22d881a270db40b66ca028fe588df318a05a4/experiments/hia_machine_elf_recovery_20261112/source-closure-fix-root-review-r1), [repair derivation](https://github.com/TrillionniumFoundation/Hepta/tree/49259b01cbaeff1ea15f10c8c8f73985700c5f5b/experiments/hia_machine_elf_recovery_20261112/caller-source-closure-repair-r1) and [post-failure read-only audit](https://github.com/TrillionniumFoundation/Hepta/tree/401c7c23e143a72139297bf5445f6d45f26aa7db/experiments/hia_ci_original_artifacts_actions_20261112/post-line821-readonly-audit-r1) distinguish the actual three-path failure from the four further static omissions. Post-failure physical build/image reads that were not recovered remain explicitly unverified; no historical gate is accepted counterfactually.

## Latest independent evidence — 2026-11-12

The [root original-byte checkpoint](https://github.com/TrillionniumFoundation/Hepta/commit/d97de00d2245c6fbbd3c80c2f4d7077ca57ba5ac) retains the complete r4 and byte-bridge logs, all 34 original framed files, independent observations and unique trigger receipts. Native's [independent byte-bridge checkpoint](https://github.com/TrillionniumFoundation/Hepta/tree/24ade62def18f82015df262ef30232d0c571f8aa/experiments/hia_machine_elf_recovery_20261112/pretty-byte-bridge-native-actual-43149458039) retains 91 acceptance checks and all original bytes separately.

- **Original 31-case JSON layout run also passed:** run 43134139906 completed its original fixed 31 cases with five anomaly counts zero; its full child completed in 0.289360063 seconds under the unchanged 5-second limit. The later r4 run retains the earlier populations and fixes the observed short-output offset regression.
- **The new byte bridge executed actual HIA measure/emit:** it successfully emitted 8,593,534 bytes from a 131,199-byte compact input without adding an 8 MiB output cap. Actual refusal paths discarded failed extents before allocation. Two concurrent calls used distinct live 161-byte workspaces. The fresh B1/B2 compiler images matched, and all compiler/source caps remained unchanged.
- **JSON component scope remains explicit:** these runs qualify admitted compact UTF-8 byte layout and its new transport. They do not execute the original CLI's broader graph/text semantics or qualify installed bridge resources. The [original CLI boundary audit](https://github.com/TrillionniumFoundation/Hepta/tree/baf058018ec7a5815386807fa1d14547e67ed86d/experiments/hia_cli_json_boundary_20261112/static-audit-r1) preserves Unicode/surrogate, NaN, type-hook, output-size and publication-order differences that still require implementation.
- **The repaired CI original-artifact custody run is HOLD:** the unique [read-only run 43150215535](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43150215535), workflow `896cb5ceaf8a34c9263b26e8131886285042cea6`, retained a 22,390,611-byte failure artifact `13913382201` with SHA-256 `58424f2690a09f10e2f06557985648aa89d0dab1c37be89833b0f2653344976d`. No complete original frame stream was recovered. Its original worker/finalizer failure details require reading that retained small artifact; the failed custody is not promoted. The first separate small-artifact recovery was cancelled, as recorded in the latest section above. A smaller diagnostic is being prepared; it preserves the original HOLD and does not replay the product CI or download the original 599 MB artifact again.
- **Core Emitter v2 native qualification remains open:** actual source authoring produced all 39 HIA units. The unique source-asset reader 43138417048 is still awaiting its original execution/result; no new trigger replaces it. The next candidate preserves all 15 component + 51 machine + 50 Core IDs in a single original 180/3 owner. Constructor-binding and retained-directory IO corrections are static controls until that execution occurs.
- **Full retained 5,400-second / outer 10,800-second qualification, final cold 180-second two-worker 38-phase closure, installed/default paths and old-owner removal remain open.** The successful development populations are not counted as those gates.

## Remaining work before cutover

1. Recover and independently audit the original cold/gate results from the now-successful seven-module source-closure repair CI, then bind that exact candidate before updating this PR's product head.
2. Complete matching-source cold, all 30 gates, full retained discovery, installed-package, recovery, and default-path observations for the final candidate.
3. Finish the Emitter control expansion, complete foreign ELF sorting behavior, remaining Agent business/persistence/process owners, CLI/build/install paths, and the separate runtime implementation.
4. Remove the supported old implementation only after those replacements and the final cutover are qualified.

Emitter v2 now has the actual 39-unit source-only authoring result recorded below. Native compilation, the complete updated 116-test caller population, and cold qualification remain unexecuted; no v1 native result is inherited. TimSort r2's original receipt-wiring HOLD is preserved. The corrected r3 source-authoring operation has an unknown original start acknowledgement and no job ID, including after one same-key reconciliation and bounded metadata reads: **UNKNOWN_NO_JOB_ID**. It is not retried with a new key and no source generation or native result is inferred.

## Durable evidence and retained failures

- [Current two native CI failures, original logs, external artifact seals, and previous complete PR narrative](https://github.com/TrillionniumFoundation/Hepta/tree/d52a9b005dfa91d9d2500cf5b3b4f0fdd0243e6d/experiments/hia_native_stack_integration_20261111/acffa-native-ci-failure-r1).
- [Both complete 401-test source logs and exact-source supplier evidence](https://github.com/TrillionniumFoundation/Hepta/commit/358bac4bdbdd681bf4dc5b80675745fafc6a2172).
- [Independent source authoring acceptance](https://github.com/TrillionniumFoundation/Hepta/commit/47dc8d0bf492444ad6825e3ab5f98f157852851a): all 166 original files, 278 recovery pieces, 6,898,354 bytes, and complete source identities verified.
- [Original Core development results](https://github.com/TrillionniumFoundation/Hepta/commit/fe10a8262182cc4068e7e1a444708a62f7f1bdee) and [separate timing-boundary correction](https://github.com/TrillionniumFoundation/Hepta/commit/799109a5d2bd3e504cc75b573fe4fef168c1bdb2).
- [Original e8 CI failures and integration findings](https://github.com/TrillionniumFoundation/Hepta/commit/2d372b91d2691166cdc7464e8e0690f40e0a565d). These remain failures after the source repairs.
- [Actual TimSort preparation HOLD](https://github.com/TrillionniumFoundation/Hepta/commit/32ef14694624f5544d9599a2d2670ec4f14130ec).

Existing FAIL/HOLD/UNKNOWN evidence, including the earlier desktop cold deadline failure, remains authoritative for its original run. This draft has not merged, activated a new default, changed the deployed runtime/configuration, or deleted supported old owners.
