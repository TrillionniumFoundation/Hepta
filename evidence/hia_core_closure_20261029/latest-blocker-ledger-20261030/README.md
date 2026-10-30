# 候选147d39c的严格 blocker 台账：2026-10-30

**27 项原始严格义务、P0–P7 八个阶段全部保持 OPEN。** 本文是新综合台账，绑定公开源码 `147d39c4a9d3ded00fb5d22439493bc006a8b76d`，tree `2050ec5e447ae5191ac2e685ba463292b2d2d3fe`。新增的有限实现和实际通过证据已记录；没有删去或放宽任何原始关闭条件，也没有把有限差分、测试数量或公开提交当作全语言结论。

**范围说明：这份台账只描述147候选及逐项注明的历史证据，不能作为当前全仓库最新状态。** 之后出现的PR405、PR407等新源码及其集成资格不在本次台账中，必须另行绑定实际实现和验收。目录名称中的latest属于当时的工作目录命名，不授予持续更新或最新全仓库结论。

生产准入权威仍为 `hepta.hia_program.verify_program`；Rust 不是生产权威。优化政策仍为 `no_change`。安全合同的八项普遍主张全部精确为 false。

原始标准来自保留的 [699 台账](baseline/ledger-699de39.json)。它的 SHA256 为 `6409d0c3e6de88b515c34c7227e028a5dfd11d53e4f81794ea57114f9966e7d0`。[不可变标准](immutable-criteria.json)和[完整台账](ledger.json)保存全部 27 项 ID、标题与 strict_close_acceptance 原始 JSON 字符串字节；[完整性记录](criteria-integrity.json)逐字段核对 81 个字符串。原始证据没有被改写。

## 已执行证据与源码身份

| 执行源码 | 实际执行/审计范围 | 不能由此推出 |
| --- | --- | --- |
| `699de39` | 官方 candidate 50、standalone 37、NDU 9、integrated 8 gates 完成并经 artifact 内容审计；完整 Python 3628，Rust 88/17 harness | 后来源码自动通过；丢失本地报告被复原；P0–P7 完整关闭 |
| `adbe4a1` / PR390 | 公开 Rust 93/18；API v4 8 项：155 observations、37 raw refusals、72 legacy comparisons；相关 Python 45 | 完整 Python API 域、任意大小输入、Rust 权威切换 |
| `99cf106` / PR391 | 公开 composite v4 13 项：153 Rust observations、4 raw refusals、31 native calls；API v4 8 项；legacy 98；示例返回37 | 完整部分初始化、stored-loan aggregates、一般公开 ABI 或全工程 Core 收敛 |
| `147d39c` | 公开 Rust 96/19；raw-record 9 项：13 精确归一化、43 executions、47 refusals，共103次原生进程；既有 API 8、composite 13、相关 protocol/workflow 20 | 全部126项选择集已执行；完整 integrated/full-release 通过；完整 raw composite 域或 Rust 生产权威 |
| `147d39c` / 两个 hosted run | 7个有限ABI/C组件 job、7个C++上游复用 job；14个原始ZIP逐成员CRC/摘要与实际报告内容审计通过 | direct LLVM一般ABI、原C++实现体已翻译、全进程内存安全、人工成本或完整发布通过 |

表中各方法集、observation、process、gate、harness 是不同分母。重复、子集与堆叠回归不相加成独立测试总数。699 candidate 与 integrated 保留同一组 3628 个 verbose method ID；standalone 只有其 3628 项终端汇总，没有另一个独立逐方法 ID 清单。NDU focused201、安全95和 critical coverage 是各自范围。

699 官方原始 ZIP 为 344,601,243 bytes，7,619 members；5,136 个成员属于当前 workflow 选择，其余 2,483 个历史/其他成员保持原身份。83 个原始分片、内容审计和读回已发布。外部输入清单440项中，8项核对了实际保留字节、1项核对 raw public source，431项仅保留记录的身份；没有声称重新取得或重跑那些未保留的上游源码和工具。

最新 147 实际公开 focused 重跑的 4,398 个 tracked 文件 raw Git blob/mode 前后保持；工具和 Rust binary 保持。其 Rust binary 为 4,204,464 bytes，SHA256 `090ea31c9631aae744d8a72b3eb1f753bba1a36edf887d564145546865761362`。本台账只读取这些冻结记录和源码，不重新执行程序测试。

独立复核分别保留原执行身份：API v4 为 `bf143a7` 的11次 native，composite v4 为 `e21d672` 的独立控制，raw-record 为 `505dd04` 的13次 distinct native。各自公开同树提交分别为 adbe、99cf、147。相同 tree 不会把 local/peer 执行重命名成 public 执行。

## 三个有限增量的准确边界

API v4 增加 exact built-in list/tuple 参数和 canonical positive hexadecimal 宽 allocation_fail_at，沿用同一 Machine。policy wire 仍限1024 bytes，参数仍限8192个 scalar/128 KiB，旧v1–v3保持。这补齐有限 API 差异；并未实现任意大小 Python int 或全部生产输入域。

Composite v4 用已有 nominal elaborator 把 partial-record typestate 与 primitive v8 的参数来源返回借用组合。非 loan nominal 返回展开为对应 null annotations，包含私有 partial token；借用结果只绑定原始 primitive borrowed formal，随后由既有 primitive checker 再验证。stored-loan aggregate 返回、loan-containing partial layout、非法/未初始化字段和逃逸依然拒绝；原 v1–v3 的目标与拒绝规则保留。直接 LLVM 继续按原始 scalar signatures 判断公开资格。

Raw Rust candidate 直接接原始 composite.v1 单态、无环 Copy records，包含嵌套与空记录；在 erasure 前验证 nominal 与零宽 SSA 身份及原公开资格，降为既有 primitive v6，复用 verify_owned 和 execute_owned_bound_v4/Machine。primitive-v6 byte resources 可在内部函数/签名中使用，不能因此放入 Copy-record 字段。resource-bearing/stored-loan records、泛型、enum/task/partial、record.borrow、后续 composite schemas 等仍拒绝。实际控制中 Rust 子进程没有调用 Python normalizer/evaluator；该显式候选入口没有改动生产默认 authority。

Raw-record 两个开发期 precharge finding 在冻结505dd04前已修复；独立13次控制保留原输出。复核者之后的 v6 ledger 字段假设错误经元数据处理修正，没有重跑 native 或修改候选源码；初始异常与脚本仍保留。128MiB RLIMIT_AS 是选定 review 子进程的虚拟地址空间限制，不是 RSS 测量，也不是一般进程内存上界证明。

Composite allocator observer 的原开发断言曾把七字节 payload 输入只分类一字节 payload/24字节 node 的 harness，触发 unknown_sizes=1；返回值及 alloc/free/live/peak 均一致。复制的历史诊断与新的实际复现分别标明身份。独立复核重建相同 Core/IR/object 并实际确认分类前提。observer 回到其声明的一字节 fixture；九模块正常 native corpus 仍包括1/7/19字节。这不是一般 allocator fault coverage。

## 当前 hosted 与注册状态

147 安全矩阵注册17个 capability、126个 unique selector；原116项保留，另加9个 raw-record 和1个 workflow selector。注册与 focused/host 通过都不构成完整126项执行。以下保留早期 [workflow metadata snapshot](observations/workflow-metadata-147d39c.json)，随后完成的host内容审计单独记录在下一段，不改写这个早期快照。

| Workflow run | 快照状态 | conclusion | updated_at |
| --- | --- | --- | --- |
| [40989068224](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40989068224) | in_progress | None | 2026-10-30T01:59:54Z |
| [40989068148](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40989068148) | in_progress | None | 2026-10-30T01:59:51Z |
| [40989068162](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40989068162) | completed | success | 2026-10-30T02:01:27Z |

**随后完成的147宿主内容审计：** 两个host run均completed/success，7个ABI/C组件与7个C++ job共14个原始ZIP，合计27,051,499 bytes、1,370个成员、152,792,171个解压bytes，官方size/digest及CRC全部核对。实际宿主为Linux x86_64/AArch64各gcc/clang、macOS AArch64 clang、Windows x86_64 clang/msvc。完整发布run40989068148在host包封存观察中仍in_progress，未由本host包审计；当前仍不能宣称147完整integrated资格。

**更晚的完整发布元数据：** observation05原始API记录显示run40989068148已于2026-10-30T03:46:46Z更新为completed/success；artifact12952846418为370,966,739 bytes，官方SHA256为 `515b2166e3b47c0b51b46421f67531eb053ac21266a8202cba8ba0ba8dc95c6c`。本台账此时未纳入该工件的完整内容审计，所以不由workflow success推断full gate数量或126项执行。原始[run](observations/full147-later-metadata-run.json)、[jobs](observations/full147-later-metadata-jobs.json)和[artifacts](observations/full147-later-metadata-artifacts.json)与旧in_progress快照分别保留。

每宿主有限ABI为frontend→Rust object：12个scalar types、36个aggregate shapes、12个pointer shapes与spill参数，两优化档每档181 foreign calls，三类C类型反例实际编译拒绝，wrong-echo非零退出。每份原ABI报告记录4份临时object/executable的hash，ZIP实际保留0/4的binary bytes；审核读取的是保留的命令、stdout/stderr、layout和hash绑定，不能说独立重新读取了这些已丢失的binary bytes。

每宿主stb_divide覆盖generic/truncating两配置、六个scalar函数：21,453个唯一输入，42,906个input/configuration pairs，514,872个native function observations包含原C与target两端每行各6次调用；这些不是514,872个独立测试方法。target-only trap24次、interpreter observations696次另列。该host报告明确HIA直接LLVM native未请求、未执行。C++每宿主固定nlohmann/json3.11.3和3.12.0，两版本各98个direct/Hepta对照、32个生命周期案例和1,024次有限concurrent calls。它复用原上游实现；调用之间的取消协议不能替代foreign call内部异步取消。ordinary_live_delta=0仍伴随registry_ordinary_allocations_retained=2，不能推成所有分配均释放。

宿主源码绑定是各报告实际selected set。C++每job157个文件，Linux/macOS均raw Git相同；Windows各150个raw matches加7个明确LF→CRLF hash/表示绑定。stb的276个implementation与6个fixture hashes前后相同且匹配raw Git。它们不是每宿主完整4,398文件的工作树字节摘要。host compiler/rustc安装文件没有随包保存，记录hash不等于审计者重新读取了这些安装bytes。详见[内容审计摘要](observations/hosted147-content-audit-summary.json)与[job/artifact绑定](observations/hosted147-job-artifact-bindings.json)。最初Windows严格LF比较的审计差异、后续显式CRLF绑定和文档计数类别勘误均保留，没有修改源码或重跑原生任务。

## 八阶段仍需什么

| 阶段 | 当前有限实现 | 严格关闭仍缺 |
| --- | --- | --- |
| P0 — 语义与分支收敛 | 生产 standalone v1–v8、composite v1–v4 与有限历史/source adapters 进入既有重验Core；99cf增加partial+returned-loan组合，147增加独立Rust raw composite-v1 Copy-record到v6的显式候选路径。 | 全部历史 source/bridge/local-view/task/I/O 入口的语义收敛、完整版本组合和各入口实际验收。 |
| P1 — 完整资源核心 | 既有byte owner/loan、固定chain、参数绑定返回借用、有限partial typestate与cooperative cleanup保留；composite-v4有限组合有同源Python/Rust/native实测。一般内存、ADT、完整生命周期/初始化/清理仍未覆盖。 | 一般 memory/provenance、任意递归 ADT、完整部分初始化、逃逸/外部生命周期、异步取消和全错误清理。 |
| P2 — 原生编译与 Rust 核心 | 显式帧/逻辑预算与同一Rust Machine保留；adbe补齐有界list/tuple与宽失败索引，147原生检查/归一化有限raw Copy-record并执行既有v6。生产权威仍是Python。 | 全部 API/输入域一致、Rust 生产调用链和部署切换资格、全入口/后端对应与原生资格。 |
| P3 — ABI 与互操作 | 147公开源码的七宿主frontend→Rust object ABI/C组件与七宿主retained C++ bridge工件已实际执行并作内容审计；direct LLVM仍为原scalar exports，另有既定31次有限native调用。一般callback/线程/外部生命周期尚无完整资格。 | direct LLVM 一般公开 ABI、callback/重入/线程模型，以及外部生命周期与真实 foreign 履约。 |
| P4 — C/C++ 渐进迁移 | 147七宿主实际覆盖stb_divide的generic/truncating两配置六个标量函数，及固定nlohmann/json两版本复用桥；完整历史库实现/全部配置迁移与人工维护成本仍未证明。 | 完整历史库实现和全部 build configurations 的实际迁移；独立人员记录全程与维护人时。 |
| P5 — Agent 效率 | 局部查询、原子编辑、诊断机制已有实现/测试；本开发会话的Agent活动不是预注册独立真实任务效率实验，也没有完整测量或归零模型/人工成本。 | 预注册的当前真实任务独立对照；完整正确性、失败、token/工具/人工/时间成本及不确定性。 |
| P6 — 性能与设备 | 保留原native计时、资源账本、RSS诊断与QEMU的各自有限身份；本轮聚焦正确性。没有新代表性吞吐/尾延迟或物理设备资格，no_change维持。 | 代表性真实吞吐/尾延迟、全进程和子进程 RSS，以及明确定义的物理设备协议实际验收。 |
| P7 — 语义证明与发布 | 原始source/tool/platform/evidence身份可追溯；699完整官方gate内容已审计，后来三个源码分别有focused实测和独立review。有限模型/测试不构成完整checker/source/backend对应证明。 | 实际 checker/转换/各后端到模型的完整对应、全语言 soundness 和最终同源发布证据闭包。 |

### 27 项剩余工作（每项均 OPEN）

下面区分实现、集成、形式化研究、部署/平台/项目资格，以及需要独立真实数据的人工、任务、性能和设备测量。各项完整严格验收原文保留在 ledger.json；本段只说明尚需完成的工作。

#### P0 语义与分支收敛

**P0.1 全工程入口收敛 — OPEN。** standalone、已声明历史 adapter 和有限 source profile 使用重验 Core。147 增加显式 Rust raw composite-v1 Copy-record 前置检查/归一化，随后使用既有 v6 checker/Machine；没有把历史 source Rust/C、source-owned LLVM、retained-library bridge、其他 stored-view、hosted task/I/O 全部迁入同一执行合同，生产默认入口仍由 Python 准入。

- **实现缺项：** 把仍独立执行的历史 source Rust/C、source-owned LLVM、retained-library bridge、其他 stored-view、hosted task/I/O 的真实值、控制流、资源和外部效应转换到同一 Core；保留原支持面。
- **语义/入口集成验收：** 逐条实际 CLI/API/backend 路径比较成功、拒绝、错误、取消及原公开资格；有限新 adapter 不足以关闭全部入口。

源码绑定：[R01](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/core.py)、[R02](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_routes.py)、[R04](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_source.py)、[R06](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_source_bridge.py)、[R30](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_PROGRAM.md)、[R59](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/runtime_task_io.py)、[R60](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/runtime_task_tree.py)、[R70](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_COPY_RECORD_CANDIDATE.md)、[R72](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/composite_records.rs)、[R73](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/lib.rs)、[R74](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/main.rs)、[R78](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_rust_copy_records.py)。

**P0.2 统一版本组合与前端行为合同 — OPEN。** 99cf 的显式 composite v4 已把有限 partial-record typestate 与 primitive v8 参数返回借用实际组合；v1–v3 原目标/拒绝条件保持。147 的 raw Rust 候选仅接 monomorphic acyclic Copy-record 子集并到既有 v6，保留 nominal/zero-width 身份及原公开签名。全部历史布局、版本、生命周期和入口/后端组合及 P7 refinement 仍未满足。

- **实现缺项：** 补齐剩余版本、nominal/存储生命周期和入口组合；已执行 composite v4 的部分记录+参数返回借用只解决其中一个有限组合。
- **语义/入口集成验收：** 在同一最终公开源码逐入口/后端保留类型身份、原公开签名、错误、tick、resource 与拒绝行为，并把转换语义保持接入 P7。

源码绑定：[R03](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program.py)、[R04](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_source.py)、[R05](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_composite.py)、[R30](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_PROGRAM.md)、[R31](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SOURCE_LOCAL_VIEWS.md)、[R34](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_PARTIAL_RECORDS_V3.md)、[R36](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_RETURNED_LOANS_V8.md)、[R66](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_COMPOSITE_RETURNED_LOANS_V4.md)、[R67](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tests/test_hia_composite_returned_loans.py)、[R68](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_composite_returned_loans.py)、[R69](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_schema.py)、[R70](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_COPY_RECORD_CANDIDATE.md)、[R72](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/composite_records.rs)、[R75](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/tests/composite_copy_records.rs)、[R77](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tests/test_hia_rust_copy_records.py)。


#### P1 完整资源核心

**P1.1 一般内存与 provenance — OPEN。** 生产 primitive Core 仍是 machine scalars 与 buffer/readbuf/mutbuf/chain 的有限资源语义；新 raw Copy-record normalizer 不引入一般 raw pointer、外部分配、layout/provenance 或初始化模型。其展开前 quota 检查和独立子进程地址空间 cap 都不等于实际 allocator/checker 的一般内存正确性证明。

- **实现缺项：** 实现一般分配身份、范围、对齐、初始化、重用/失效、alias 权限及 foreign 分配边界；目前有限 byte owner/loan 规则不覆盖这些全部域。
- **形式化研究/完整对应证明：** 为实际准入器、allocator、每条内存操作建立表示关系和安全证明，覆盖 stale/OOB/权限/未初始化反例。

源码绑定：[R03](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program.py)、[R07](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_runtime.py)、[R10](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_llvm.py)、[R49](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/formal/README.md)、[R53](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SAFETY_CONTRACT.json)、[R70](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_COPY_RECORD_CANDIDATE.md)、[R72](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/composite_records.rs)。

**P1.2 任意递归 ADT — OPEN。** v7 chain 仍是固定 Nil|Node(buffer,chain) 线性类型；nominal 按值循环仍拒绝。147 raw 候选仅无环、单态、scalar/嵌套/空 Copy records，拒绝泛型和 enum/task/partial 等。函数递归或互递归用例通过，不意味着递归 ADT 布局、构造和释放已实现。

- **实现缺项：** 实现任意递归 ADT 的间接布局、互递归类型、泛型、构造/匹配与递归资源释放；固定 chain、无环 Copy record 或函数互递归不是该能力。
- **语义/入口集成验收：** 把相同完整 ADT 语义接入 source/checker/Core/两 VM/各后端，实际覆盖 nested owner/loan、分配失败、深度和清理边界。

源码绑定：[R04](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_source.py)、[R05](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_composite.py)、[R32](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SOURCE_UNIT_ENUMS.md)、[R35](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RECURSIVE_CHAIN_V7.md)、[R66](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_COMPOSITE_RETURNED_LOANS_V4.md)、[R70](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_COPY_RECORD_CANDIDATE.md)、[R72](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/composite_records.rs)。

**P1.3 完整部分初始化 — OPEN。** source 的 moved-out field 恢复与 composite v3 的 initialized-field/token 模型保留；composite v4 现可与参数返回借用降到 v8 并实际执行。stored-loan partial state、一般动态/递归/借用字段初始化及所有失败点清理仍排除；147 raw Copy-record 候选本身拒绝 partial records。

- **实现缺项：** 补齐一般聚合、动态/嵌套/递归布局和借用字段的初始化、移出/恢复及分支/循环合流；stored-loan partial state 和一般未初始化内存仍未覆盖。
- **语义/入口集成验收：** 对每个失败点实现并验证已初始化子对象的清理；在 source/Core/VM/native 同域验收，包含非法读和双重释放。

源码绑定：[R04](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_source.py)、[R05](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_composite.py)、[R33](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SOURCE_PARTIAL_RESTORATION.md)、[R34](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_PARTIAL_RECORDS_V3.md)、[R66](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_COMPOSITE_RETURNED_LOANS_V4.md)、[R67](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tests/test_hia_composite_returned_loans.py)、[R68](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_composite_returned_loans.py)、[R70](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_COPY_RECORD_CANDIDATE.md)。

**P1.4 逃逸与外部生命周期 — OPEN。** v8 返回 loan 绑定实际参数来源并暂停 caller parent；99cf/147 同源重跑覆盖有限 partial-field 返回借用。stored-loan aggregate 返回、一般异步/foreign 持有与外部生命周期仍未开放。147 raw composite-v1 候选保留不返回 loan 的原规则；原 nominal/private 签名及 resource descriptor 不会因 erasure 获得公共资格。

- **实现缺项：** 实现跨 aggregate 存储、异步/foreign 持有、回调和跨调用保留的生命周期及失效协议；参数绑定内部返回借用不满足一般逃逸生命周期。
- **语义/入口集成验收：** 验证原公开入口的 alias、释放责任、保留/返回和退出顺序；声明 retention=call_only 不等于真实 foreign 端履约。
- **形式化研究/完整对应证明：** 证明跨函数/存储/外部边界的身份和存活关系与实际实现一致。

源码绑定：[R03](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program.py)、[R04](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_source.py)、[R05](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_composite.py)、[R09](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_rust_crosscheck.py)、[R10](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_llvm.py)、[R31](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SOURCE_LOCAL_VIEWS.md)、[R36](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_RETURNED_LOANS_V8.md)、[R39](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/CPP_INTEROP.md)、[R66](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_COMPOSITE_RETURNED_LOANS_V4.md)、[R67](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tests/test_hia_composite_returned_loans.py)、[R70](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_COPY_RECORD_CANDIDATE.md)、[R72](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/composite_records.rs)。

**P1.5 异步取消 — OPEN。** composite task.cancel 通过显式 checked state consumer 协作清理；historical hosted task/I/O 已有真正 wake/cancel、FD 关闭和预算测试。VM 预算停止、信号、外部阻塞和任意调度不自动具备 source cancellation/unwind 语义。

- **实现缺项：** 把任务/I/O 的可中断点、取消结果/owner 交接竞争、不可中断 foreign 操作与完成条件统一入 Core。
- **语义/入口集成验收：** 在所有持有资源阶段和竞争顺序实际注入取消，覆盖 I/O/阻塞/信号/调度边界。
- **形式化研究/完整对应证明：** 建立取消 cleanup 与 liveness 的适用条件及对应证明。

源码绑定：[R05](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_composite.py)、[R37](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/TASK_TREE_IO_COMPOSITION.md)、[R53](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SAFETY_CONTRACT.json)、[R59](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/runtime_task_io.py)、[R60](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/runtime_task_tree.py)。

**P1.6 完整错误清理 — OPEN。** 普通/错误值返回消费或转移 owner，失败空 owner 也保留责任；trap/budget stop 保留停止账本，native abort 无析构展开承诺。新 API/partial/Copy-record 有限失败注入和一字节 allocator observer 增加实证，不能覆盖全部异常、信号、I/O、取消及清理自身失败。

- **实现缺项：** 实现 allocation refusal、中途构造失败、trap/native 异常或信号、I/O 错误、取消和清理自身失败的完整资源责任。
- **语义/入口集成验收：** 逐个可失败转换/退出点执行 fault injection，保留未清债务；有限一字节 observer 和停止账本不是全面故障清理。
- **形式化研究/完整对应证明：** 证明正常/异常退出的资源不变量；只承诺 abort、不承诺 unwind 时本严格条目继续 OPEN。

源码绑定：[R03](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program.py)、[R07](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_runtime.py)、[R10](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_llvm.py)、[R37](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/TASK_TREE_IO_COMPOSITION.md)、[R42](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/CPP_UNIQUE_PROJECT_MIGRATION.md)、[R53](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SAFETY_CONTRACT.json)、[R63](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_BOUND_API_V4.md)、[R66](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_COMPOSITE_RETURNED_LOANS_V4.md)、[R67](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tests/test_hia_composite_returned_loans.py)、[R70](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_COPY_RECORD_CANDIDATE.md)、[R77](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tests/test_hia_rust_copy_records.py)。


#### P2 原生编译与 Rust 核心

**P2.1 完整 API 和输入域一致 — OPEN。** adbe 的显式 bound-v4 已支持 exact built-in list/tuple 和 canonical positive hex 宽 allocation_fail_at，旧 v1–v3 合同保留；完整 policy 仍限1024 bytes，参数仍限8192个scalar/128 KiB，并非任意大小 Python int。147 独立 raw Rust 前端可直接检查/归一化 composite.v1 的单态无环 Copy-record 子集，允许 primitive-v6 byte resources 处于内部函数/签名但不处于 Copy-record 字段；更广 nominal、resource-bearing records、泛型、enum/task/partial/后续schemas仍未具备该原生资格。完整 Python API 域未统一。

- **实现缺项：** 继续对齐全部生产接受/拒绝域与原公开资格；bound-v4 虽补齐 exact list/tuple 和宽失败索引，policy 仍限 1024 bytes、参数仍限 8192 values/128 KiB，不等于任意 Python int 或完整 nominal 域。
- **语义/入口集成验收：** 逐项保留原 schemas、输入、预算、错误与失败索引并实际比较；147 的 raw Rust Copy-record 到 v6 只有明确单态无环子集的公开资格，更广 nominal/resource/partial/task 及完整生产输入域仍需实现和同源对照。

源码绑定：[R03](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program.py)、[R07](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_runtime.py)、[R08](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/scalar_vm.rs)、[R09](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_rust_crosscheck.py)、[R38](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_BOUND_BUDGET_V3.md)、[R61](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tests/test_hia_rust_budget_v3.py)、[R63](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_BOUND_API_V4.md)、[R64](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tests/test_hia_rust_api_v4.py)、[R65](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_rust_api_v4.py)、[R70](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_COPY_RECORD_CANDIDATE.md)、[R72](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/composite_records.rs)、[R73](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/lib.rs)、[R74](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/main.rs)、[R75](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/tests/composite_copy_records.rs)、[R77](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tests/test_hia_rust_copy_records.py)、[R78](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_rust_copy_records.py)。

**P2.2 Rust 生产准入与执行权威切换 — OPEN。** 147 原生子进程在实际控制中不调用 Python normalizer/evaluator，复用 verify_owned 和 execute_owned_bound_v4/Machine；这是独立显式候选入口。生产 verify_program/verify_core、execute_core、hia run、route/LLVM 准入仍由 Python 执行；全部生产域、部署调用链、迁移和故障资格尚未完成。

- **实现缺项：** Rust 必须覆盖全部生产语义、normalization、资源判定、错误路径和部署入口；新增有限 raw 入口不自动接管现有生产调用链。
- **生产权威切换资格：** 在冻结最终源码完成完整回归、反例、各目标资格、独立审查、迁移和实际生产故障拒绝证据后，才能讨论 authority 切换。

源码绑定：[R01](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/core.py)、[R03](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program.py)、[R08](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/scalar_vm.rs)、[R09](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_rust_crosscheck.py)、[R10](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_llvm.py)、[R28](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_integrated.py)、[R53](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SAFETY_CONTRACT.json)、[R55](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_CORE_CLOSURE_20261028.md)、[R63](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_BOUND_API_V4.md)、[R70](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_COPY_RECORD_CANDIDATE.md)、[R72](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/composite_records.rs)、[R73](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/lib.rs)、[R74](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/main.rs)、[R78](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_rust_copy_records.py)。

**P2.3 全入口后端资格与 refinement — OPEN。** 147已有同源raw-record9、API8、composite13、Rust96/19及protocol/workflow20实测，并有七ABI/C与七C++宿主工件内容审计。699的50/37/9/8完整gates仍只属于699；当前147的完整integrated与126项安全矩阵未由这些focused/host结果获得资格。logical1GiB政策、有限差分和内部资源执行不证明全目标refinement、native栈或RSS。

- **语义/入口集成验收：** 在同一最终公开 SHA 执行全部要求入口、平台、toolchain 和失败路径；699 的完整 gates 与后来源码的 focused runs 保持各自身份。
- **形式化研究/完整对应证明：** 将 checker/normalization/Machine/native 行为接入 refinement；logical 1 GiB ceiling 或有限成功分配不能推导所有上界分配、native 栈或 RSS。

源码绑定：[R07](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_runtime.py)、[R08](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/scalar_vm.rs)、[R10](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_llvm.py)、[R28](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_integrated.py)、[R38](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_BOUND_BUDGET_V3.md)、[R53](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SAFETY_CONTRACT.json)、[R61](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tests/test_hia_rust_budget_v3.py)、[R65](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_rust_api_v4.py)、[R68](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_composite_returned_loans.py)、[R70](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_COPY_RECORD_CANDIDATE.md)、[R76](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tests/test_hia_integrated_workflow.py)、[R78](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_rust_copy_records.py)。


#### P3 ABI 与互操作

**P3.1 direct LLVM 一般公开 ABI — OPEN。** 147七宿主有限ABI已完成并审计，路径仍是frontend→Rust object；每宿主两优化档各181foreign calls。每份ABI报告的4个临时object/executable仅保留hash和过程观察，原ZIP实际0/4二进制bytes。直接LLVM仍只公开原scalar C signatures，既有31native调用没有开放nominal/resource/一般多返回公共ABI。

- **实现缺项：** 补齐要求公开类型的 ABI 分类、layout、calling convention、资源转移与错误约定；有限内部 aggregate/loan 降低不扩展 scalar-only 公共 ABI。
- **实际平台/ABI 验收：** 由直接 LLVM 对象在全部要求 OS/架构/compiler 执行独立双向调用、layout/坏签名反例与资源观察；frontend→Rust object 七宿主结果不可替代。

源码绑定：[R10](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_llvm.py)、[R22](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/validate_native_host.py)、[R56](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/.github/workflows/hepta-native-hosts.yml)、[R66](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_COMPOSITE_RETURNED_LOANS_V4.md)、[R67](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tests/test_hia_composite_returned_loans.py)、[R70](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_COPY_RECORD_CANDIDATE.md)、[R72](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/composite_records.rs)。

**P3.2 一般 callback、重入和线程 — OPEN。** existing C++ bridge 有 reentrancy allow/reject、creator_thread/serialized 及 inflight deferred destruction；它不证明 foreign globals、external aliases、callbacks、worker threads 或跨对象锁顺序，亦不等于 Core/native 通用 callback 类型与并发模型。 147固定C++库每版本的1024次有限concurrent calls及调用之间取消已实际观察；不是foreign call内部异步取消或一般线程/并发内存安全资格。

- **实现缺项：** 实现一般 callback/context、跨线程调用与撤销、重入 owner/loan 状态及析构竞争合同。
- **实际平台/ABI 验收：** 在要求原生平台实际测试 callback、跨对象/嵌套重入、线程迁移和取消/销毁竞态。
- **形式化研究/完整对应证明：** 建立一般并发内存和生命周期对应；现有 scoped bridge 的 allow/reject、creator-thread 或串行策略仍有明确外部假设。

源码绑定：[R11](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/cpp_bridge.py)、[R39](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/CPP_INTEROP.md)、[R53](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SAFETY_CONTRACT.json)。

**P3.3 外部生命周期与互操作责任 — OPEN。** borrow_const/mut 仅要求 foreign retention=call_only，文档明确是未证明义务；numeric handle 只在本模块类型关联内有效，abandoned creator-thread handle 直到进程退出不自动回收。缺一般跨模块身份和安全生命周期责任。

- **实现缺项：** 为外部存储、allocator、保留借用、跨模块 handle、回调和延迟销毁实现身份/所有权/失效协议。
- **实际平台/ABI 验收：** 实际覆盖 foreign 方违反合同、错误、shutdown、module unload、竞争和重复释放；验证真实 foreign 端履约。
- **形式化研究/完整对应证明：** 证明协议与跨模块生命周期责任，而不是信任 numeric handle 或 retention 声明。

源码绑定：[R10](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_llvm.py)、[R11](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/cpp_bridge.py)、[R39](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/CPP_INTEROP.md)、[R53](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SAFETY_CONTRACT.json)。


#### P4 C/C++ 渐进迁移

**P4.1 完整历史库实现迁移 — OPEN。** 有限 C 不支持任意 pointer/function pointer/global/union/asm/atomics；C++ unique_ptr 绑定 default deleter 的精确 leaf contract，拒绝 shared_ptr/custom deleter/virtual dispatch/任意模板等。标准库 declaration census 标记 dependency_not_migrated；upstream bridge 成功不是原实现体已迁移。 147七宿主的stb_divide仅六个scalar函数/两声明配置；nlohmann/json两版本是retained upstream复用而非实现体翻译。

- **实现缺项：** 补齐完整选定历史库要求的实现语义，不能把 retained-library bridge 或 dependency_not_migrated 计为实现体迁移。
- **完整真实历史项目验收：** 冻结完整源/依赖/实现体 denominator，逐项说明边界并确保目标未偷偷链接原实现，实际比较功能、ABI、资源、失败/异常及维护升级。

源码绑定：[R12](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/c_migration_project.py)、[R13](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/cpp_project_migrate.py)、[R14](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/cpp_unique_project.py)、[R23](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_cpp_upstream_host.py)、[R40](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/C_MIGRATION.md)、[R41](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/CPP_COMPOSED_PROJECT_MIGRATION.md)、[R42](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/CPP_UNIQUE_PROJECT_MIGRATION.md)。

**P4.2 全部构建配置与原工具语义 — OPEN。** C capture denominator 是每个列出配置中活跃的预处理声明，不是所有 inactive 分支/未列出配置/全仓库文件。所选 Clang 执行 capture；原 gcc/cc 字符串是 metadata，保留 argv 不证明原 driver 默认宏/语义等价。 147新增同源stb的generic/truncating实测；未启用self-test、floor simulation、其他division配置和C++wrapper仍只有保留源码，未计为active迁移。

- **实现缺项：** 保留并实现真实 build variants、宏、target/compiler/依赖/生成步骤，不以某个配置的 active declaration census 代替全项目。
- **完整真实历史项目验收：** 逐个配置独立 capture/转换/原 driver 重放/native differential；未列配置、inactive 分支和原 gcc 默认语义不能由 Clang capture 或 argv metadata 推断。

源码绑定：[R12](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/c_migration_project.py)、[R13](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/cpp_project_migrate.py)、[R14](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/cpp_unique_project.py)、[R40](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/C_MIGRATION.md)、[R41](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/CPP_COMPOSED_PROJECT_MIGRATION.md)。

**P4.3 人工迁移与长期维护成本 — OPEN。** 记录的 capture/migration/qualification wall time、机器成本或零次 target 手改，不含任务澄清、原库理解、标注、调试、review、升级与长期维护的人力；这些不是可从现有计时推导的量。 147 hosted报告的manual_review_hours与agent_tokens为null，不能据此填写零人时或全开发会话零model成本。

- **独立实际人工成本测量：** 预先约定人工与机器的完整成本边界、基线和质量，由独立人员在真实历史库及维护升级中记录澄清、理解、标注、调试、review、返工与恢复人时。自动过程 wall time 和零次目标手改均不能替代该数据。

源码绑定：[R14](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/cpp_unique_project.py)、[R41](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/CPP_COMPOSED_PROJECT_MIGRATION.md)、[R42](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/CPP_UNIQUE_PROJECT_MIGRATION.md)、[R45](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SIX_OUTCOMES_RESULTS_20261028.md)。


#### P5 Agent 效率

**P5.1 当前版本独立真实任务资格 — OPEN。** snapshot-bound query、原子编辑、诊断和整模块重验是机制；本台账没有纳入预注册、独立的当前版本真实任务效率资格。本开发会话实际使用Agent/模型进行实现与复核，但这不是具备固定基线、隐藏任务与公平预算的P5实验。历史40次生成/0成功和后续失败校准保留原源码与分母，不代表当前效率。

- **独立真实模型/任务实验：** 以固定实际有能力模型/工作流取得独立基线资格，预注册代表性真实跨文件/所有权/维护任务、隐藏正确性、权限、公平预算和独立评估；保留所有失败，不人工补答。此轮实现活动和 unittest 并非该实验。

源码绑定：[R15](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_edit_query.py)、[R16](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_edit_batch.py)、[R17](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_patch_impact.py)、[R20](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_agent_factorial.py)、[R43](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_AGENT_CONTROL_CONTEXT_V2.md)、[R44](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/experiments/crossfile_eval/local_study_20261026/README.md)、[R45](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SIX_OUTCOMES_RESULTS_20261028.md)。

**P5.2 有效提效结论与完整成本 — OPEN。** 尚无当前版本通过资格的真实主任务效率对照，不能报告已证明的成功率或成本优势。历史0成功时每成功成本未定义；当前开发中的模型调用、token、工具、人工及准备/恢复成本没有被本台账完整测量，不能设为0或由构建/测试用时推断。

- **独立真实模型/任务实验：** 在已通过当前资格的主任务报告正确率、质量/回归、完成延迟及实际 token/工具/编译/人工成本与完整分母；纳入未知、失败、超时和重试，按预注册标准检验所声称优势及不确定性。历史零成功时每成功成本未定义，不能补零。

源码绑定：[R20](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_agent_factorial.py)、[R43](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_AGENT_CONTROL_CONTEXT_V2.md)、[R44](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/experiments/crossfile_eval/local_study_20261026/README.md)、[R45](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SIX_OUTCOMES_RESULTS_20261028.md)。


#### P6 性能与设备

**P6.1 代表性吞吐与尾延迟资格 — OPEN。** 本轮的新 native/Machine执行、normalization比较、资格运行耗时与正确性结果不是代表性吞吐/p99测量。旧性能实验和失败/不确定结果保持原身份；当前优化政策仍no_change，必须经当前预注册公平负载与基线的实际测量后才能改变。

- **代表性真实性能/资源测量：** 冻结当前源码、代表性真实负载、强 C/C++/Rust 基线、target/native/LTO/PGO 公平配置及冷暖/负载条件，实际收集完整吞吐与端到端尾延迟、质量及失败样本；通过既定标准之前 no_change 保持。

源码绑定：[R19](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_optimization.py)、[R21](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_llvm_owned.py)、[R45](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SIX_OUTCOMES_RESULTS_20261028.md)、[R46](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/LLVM_OWNED_PERFORMANCE_PROTOCOL.md)、[R47](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/PERFORMANCE_PROCESS_OBSERVATIONS.md)、[R54](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_CONTINUATION_20261029.md)、[R65](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_rust_api_v4.py)、[R68](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_composite_returned_loans.py)、[R78](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_rust_copy_records.py)。

**P6.2 RSS 和完整进程资源 — OPEN。** logical payload/node账本排除frame/map、allocator元数据/碎片、foreign/runtime/compiler与子进程开销。147展开前Core quota检查不覆盖一般进程RSS；peer的128MiB RLIMIT_AS只是选定子进程虚拟地址空间限制，不是RSS观测或普遍资源上界证明。1GiB logical policy与旧特定RSS诊断也不能补足本严格条件。 Hosted原始类型preflight的Linux绝对2GiB/macOS额外2GiB虚拟空间与Windows未实施记录也均明确whole_process_rss_bounded=false。

- **实现缺项：** 若主张普遍进程资源上界，需覆盖全部分配来源的强制限额，包括 frame/map、allocator 元数据/碎片、foreign/runtime/compiler 与子进程。
- **代表性真实性能/资源测量：** 在成功/拒绝/长时/并发代表性负载测量全进程/子进程 RSS 与峰值，注明口径及未知；payload ledger 不能换算 RSS。
- **形式化研究/完整对应证明：** 对普遍上界建立限额、分配来源和实际执行的对应证明。

源码绑定：[R07](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_runtime.py)、[R08](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/scalar_vm.rs)、[R21](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_llvm_owned.py)、[R38](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_BOUND_BUDGET_V3.md)、[R45](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SIX_OUTCOMES_RESULTS_20261028.md)、[R46](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/LLVM_OWNED_PERFORMANCE_PROTOCOL.md)、[R47](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/PERFORMANCE_PROCESS_OBSERVATIONS.md)、[R53](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SAFETY_CONTRACT.json)、[R63](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_BOUND_API_V4.md)、[R70](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_COPY_RECORD_CANDIDATE.md)、[R72](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/composite_records.rs)。

**P6.3 物理设备协议 — OPEN。** validate_board 的实际合同是 pinned Cortex-M4 QEMU model，claims 中 physical_board_qualified、DMA/GPU、device_timing 均 false。host native 或 QEMU 执行不建立真实硬件时序、驱动、IRQ/DMA 或电源条件。

- **实现缺项：** 实现目标范围的实际启动、driver/I/O、IRQ、DMA/GPU/NPU、取消和资源合同。
- **实际物理设备验收：** 取得明确物理设备、固件/toolchain/driver 身份，预先定义时序/尾延迟、故障/持续运行协议并在实际设备完整执行；QEMU 或 host native 不能补足设备观测。

源码绑定：[R24](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/validate_board.py)、[R49](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/formal/README.md)、[R53](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SAFETY_CONTRACT.json)。


#### P7 语义证明与发布

**P7.1 形式模型到实际 checker/资源状态的对应 — OPEN。** HeptaCore/HeptaMemory 的有限 theorem 不建模完整 Python checker、provenance/runtime/FFI。selected u32 exporter rechecks Core 并生成 Lean register program，但 exporter refinement 和 Python verifier soundness 明确 false。

- **实现缺项：** 为全部生产接受域、类型/CFG/owner/loan/内存/错误/任务状态提供实际可对应的表示关系与实现接口。
- **形式化研究/完整对应证明：** 真正证明 admission、preservation/progress 和资源不变量，使用 proof checker 重放、依赖审计与错误实现负控绑定实际源码；有限模型 theorem 数不能替代。

源码绑定：[R03](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program.py)、[R25](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/verify_formal.py)、[R26](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/verify_memory.py)、[R27](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_selected_formal.py)、[R48](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/FORMAL_EVIDENCE_GATE.md)、[R49](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/formal/README.md)、[R50](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/formal/HiaSelectedCore.lean)、[R53](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SAFETY_CONTRACT.json)。

**P7.2 完整 source→Core refinement — OPEN。** 原有前端和历史adapter后的Core重验，以及新composite-v4/原生Copy-record有限精确归一化与差分，都不证明全部source→Core行为保持。完整nominal/partial/returned-loan/task/I/O映射和每条真实转换的组成性refinement仍缺。

- **实现缺项：** 逐入口明确 source 与 Core 的完整操作状态和可观察行为，覆盖错误/trap/取消、资源及 foreign 假设。
- **形式化研究/完整对应证明：** 证明每个真实 lowering/adapter 的行为保持及组合，与实际代码绑定；目标 Core 重验和有限差分不能替代 source refinement。

源码绑定：[R01](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/core.py)、[R04](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_source.py)、[R05](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_composite.py)、[R06](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_source_bridge.py)、[R30](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_PROGRAM.md)、[R53](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SAFETY_CONTRACT.json)、[R66](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_COMPOSITE_RETURNED_LOANS_V4.md)、[R67](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tests/test_hia_composite_returned_loans.py)、[R70](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_COPY_RECORD_CANDIDATE.md)、[R72](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/composite_records.rs)、[R75](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/tests/composite_copy_records.rs)、[R77](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tests/test_hia_rust_copy_records.py)。

**P7.3 各实际后端 refinement — OPEN。** SMT 模型只验证有限 scalar/保结构转换；encoder 自身未证明对应。LLVM emitter、Rust/C 路线、allocator、linker/loader 与硬件在 TCB 内；原生有限比对没有构成全部指令、资源、ABI 和目标的 refinement。

- **实现缺项：** 对每个生产 backend 和版本/优化/external 边界落实精确目标语义与验证接口。
- **形式化研究/完整对应证明：** 证明 Core 到发射 IR、对象和机器的对应或有效逐构建验证；LLVM/Rust/C emitter、allocator、linker/loader、OS/硬件未证明部分继续显式属于 TCB。

源码绑定：[R08](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/rust/hia-core-shadow/src/scalar_vm.rs)、[R10](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program_llvm.py)、[R18](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_translation_validation.py)、[R19](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_optimization.py)、[R27](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_selected_formal.py)、[R49](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/formal/README.md)、[R51](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_TRANSLATION_VALIDATION.md)、[R52](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_VERIFIED_OPTIMIZATION.md)、[R53](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SAFETY_CONTRACT.json)、[R67](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tests/test_hia_composite_returned_loans.py)、[R68](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_composite_returned_loans.py)、[R70](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_COPY_RECORD_CANDIDATE.md)。

**P7.4 全语言健全性和未证明普遍主张 — OPEN。** 安全合同中的 8 项 universal claims 全为 false；有限 profile proofs 的 theorem 数不可相加成为全语言结论。并发、完整内存/生命周期、任意 ADT 与全错误清理尚未实现和证明。

- **形式化研究/完整对应证明：** 完成 P0–P3 全语言语义和组成性 soundness，并为其余普遍主张分别提供适用的定理或实证。全部八项 universal claims 精确保持 false；阶段百分比、hash 或测试总数不能代替。

源码绑定：[R03](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/hepta/hia_program.py)、[R48](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/FORMAL_EVIDENCE_GATE.md)、[R49](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/formal/README.md)、[R50](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/formal/HiaSelectedCore.lean)、[R53](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SAFETY_CONTRACT.json)、[R55](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_CORE_CLOSURE_20261028.md)、[R71](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SAFETY_CONTRACT.md)。

**P7.5 最终同源发布验收和证据闭包 — OPEN。** 699官方完整执行与artifact内容审计完成：candidate50、standalone37、NDU9、integrated8，重复Python3628和Rust88/17不相加；丢失本地报告仍未复原。adbe/99cf/147有各自focused实测，147另有14份实际host工件内容审计，但不继承699完整gates。最新host只绑定实际selected source sets，Windows七例显式LF→CRLF，ABI每宿主4份临时二进制bytes未保留；完整147发布/126选择集和所有要求的同源证据闭包仍未由当前纳入记录证明，严格条目OPEN。 后续official metadata已显示full147 run于03:46:46Z completed/success，但本台账封存时其artifact内容审计未纳入，不能推断完整gate计数。

- **最终同源工程发布验收：** 在最终公开 SHA 实际完成要求的完整 8 gates 及必要 native/host/proof gates，核对零失败/跳过、完整分母、工具/外部输入、前后 raw Git blobs 和原始失败/输出。699 的官方完整通过不继承到 adbe/99cf/147；147 focused 与14份有限host工件审计、126项注册都不替代完整发布资格。补齐所要求原始执行证据的保留范围，并明确现有ABI临时binary、host工具字节及Windows表示绑定限制。

源码绑定：[R28](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_integrated.py)、[R29](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_safety_contract.py)、[R53](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SAFETY_CONTRACT.json)、[R54](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_CONTINUATION_20261029.md)、[R55](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_CORE_CLOSURE_20261028.md)、[R56](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/.github/workflows/hepta-native-hosts.yml)、[R57](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/.github/workflows/hepta-cpp-upstream-hosts.yml)、[R58](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/.github/workflows/hepta-qualification.yml)、[R62](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_rust_budget_v3.py)、[R65](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_rust_api_v4.py)、[R68](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_composite_returned_loans.py)、[R70](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_RUST_COPY_RECORD_CANDIDATE.md)、[R71](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/docs/HIA_SAFETY_CONTRACT.md)、[R76](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tests/test_hia_integrated_workflow.py)、[R78](https://github.com/TrillionniumFoundation/Hepta/blob/147d39c4a9d3ded00fb5d22439493bc006a8b76d/tools/qualify_hia_rust_copy_records.py)。

## 测量和证明的解释边界

开发会话使用了 Agent/模型开展实现、调试与复核。它没有被预注册成独立真实任务效率实验，也没有完整记录全会话模型调用、token、工具、人工与恢复成本，所以这些量是未测量，不是零。历史40次生成、0次成功保持原版本与分母；不能推导当前成功率、提效或每成功成本。本台账没有添加新的独立人工迁移成本、代表性吞吐/尾延迟、全进程 RSS 或物理设备测量。

logical payload/node 账本不含全部 frame/map、allocator 元数据/碎片、foreign/runtime/compiler 与子进程开销；逻辑1GiB政策、Core展开quota和RLIMIT_AS都不能替代RSS协议或全进程资源证明。QEMU/host native 也不能替代实际物理设备的驱动、时序、IRQ/DMA、电源和持续运行观测。

有限 proof、重新准入、exact normalization、同一 Machine 差分和 native 成功均是其声明范围内的证据。它们没有证明完整 source→Core、Core→native refinement、并发内存安全、absolute resource safety、native process-memory bound、global optimality、Rust 性能优势或 whole-language soundness。八项普遍主张继续全部为 false。

## 不可变证据定位

| 记录 | 源码提交 | 不可变公开证据 |
| --- | --- | --- |
| E699_COMPLETE_RELEASE | [699de39a8e92](https://github.com/TrillionniumFoundation/Hepta/commit/699de39a8e92e0f083df316ecc5333fb3ecf8571) | [证据入口](https://github.com/TrillionniumFoundation/Hepta/tree/bba259fdc2396e92aaa5d41040984b05b82cfa7c/evidence/hia_core_closure_20261029/official-release-699de39) |
| EADBE_BOUND_API_V4 | [adbe4a1168a8](https://github.com/TrillionniumFoundation/Hepta/commit/adbe4a1168a84d0696749ef54f933994b5dc554c) | [证据入口](https://github.com/TrillionniumFoundation/Hepta/tree/b45b94c9180b5a5d06e6f41d7f7359e5f34ec50f/evidence/hia_core_closure_20261029/rust-api-v4) |
| E99CF_COMPOSITE_V4 | [99cf10658650](https://github.com/TrillionniumFoundation/Hepta/commit/99cf106586509b08bb2b9890ed29cf042336d69e) | [证据入口](https://github.com/TrillionniumFoundation/Hepta/tree/0bf60183b936fe67e7c1ac527ea466b71d5f5edb/evidence/hia_core_closure_20261029/composite-v4) |
| E147_RAW_COPY_RECORDS | [147d39c4a9d3](https://github.com/TrillionniumFoundation/Hepta/commit/147d39c4a9d3ded00fb5d22439493bc006a8b76d) | [证据入口](https://github.com/TrillionniumFoundation/Hepta/tree/907bf0fdcc147e4fcf452326296e11c09bb5ab5b/evidence/hia_core_closure_20261029/rust-copy-records-147d39c) |
| E147_HOSTED_FINITE_MATRIX | [147d39c4a9d3](https://github.com/TrillionniumFoundation/Hepta/commit/147d39c4a9d3ded00fb5d22439493bc006a8b76d) | [证据入口](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40989068224) |

宿主行的链接指向原始official workflow；本台账此时尚未绑定宿主审计包的仓库发布提交。14份工件的实际完成、冻结内容审计及哈希已记录，公开归档可用性与这些结果分别陈述。

每条公开/原始执行身份、摘要、具体分母、文件 SHA256/Git blob、archive member 和限制详见 [evidence-observations.json](evidence-observations.json)。最新 raw-record 证据包 `9e8423331abf794c85f86089db31cbadd172bf607729a62f7b5dc079f19a1980` 共10,012,740 bytes、325个成员，以3个有序分片公开；完整gzip/TAR成员读回已完成。

78个源码引用的 mode、Git blob、SHA256 和不可变 URL 在 [source-references.json](source-references.json)。R01–R62 沿用原引用ID，新增R63–R78；绑定的是当前147源码，不把旧观察自动提升为当前执行。

本次综合进行文件/Git读取、新文档写入与完整性检查，并做了3次只读GitHub refs/commit/path查询；原查询响应保留于[只读定位记录](readonly-publication-lookups.json)。未运行新的项目 build、语义/backend tests、native程序、设备或P5实验；未修改原证据/源码，也未写GitHub。一次早期读取未本地存在的147 Git对象曾触发失败的 promisor fetch；随后根代理正常取得对象，最终绑定使用本地不可变 Git bytes。没有把这个审计边界外推成整个开发会话的零模型/零成本声明。

发布文件及每个文件的 bytes、SHA256、Git blob、mode 和目标路径由 [publication-files.json](publication-files.json)列出。该清单供根代理发布；本台账作者没有远程发布。
