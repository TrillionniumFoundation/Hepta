# 默认 AgentStore 持久化接入调查

## 结论和本轮边界

当前默认持久化仍由 SQLite 连接承担。下一项应落在 **AgentStore.db 这一个共享连接与事务边界**：实现面向现有十表、31 种生产业务 SQL 模板的 HIA 数据库后端，并在真实 HIAAgentService 调用链中接入。首先需要补齐的算法主体是带一致快照、写入、提交、回滚和重开恢复的页事务层；已有 varint、WAL、record 和 selected-cell 算法可作为其内部构件。

仅把 requests 或 artifacts 独立放到另一存储中会破坏现有跨表提交边界。当前 adopt/rollback 的 slots、versions 变更与 requests 中的完成响应位于同一事务；持久化接口必须覆盖这个组合。[实际调用](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/hepta/hia_agent_service.py#L245-L321)。

本轮只读 exact pure **8556199d761540f84c15856a6a9cf1a6f863ffc5**，tree **d60dbcda95d3c06797fae7a4d97c4640fe37f627**，物理路径 `/home/qq/hia-rewrite-20261113-e26e-r1/pc-fixture-successor-r1/source`。没有导入 Hepta、没有运行测试或原生代码、没有修改产品源。42 个初始命中文件均按该 Git tree 核对；后续 23 个实际边界/测试/作者/资格调用器文件也逐全文 SHA-1/SHA-256 绑定。静态 AST 清单中的 179 个 ID 不是新资格分母，也不是执行结果。

## 1. 默认入口实际做了什么

`HIAAgentService.__init__` 直接创建 `AgentStore(state_root)`。AgentStore 的连接设置为：

- 文件 `state.sqlite3`；连接前检查现有数据库是本用户所有、非其他用户可写的普通文件。
- `sqlite3.connect(..., isolation_level=None, timeout=10, check_same_thread=False)`。
- `row_factory=sqlite3.Row`，随后设置 `journal_mode=WAL` 和 `synchronous=FULL`。
- 建立十张用户表；当前代码没有数据库引擎 selector。
- `transaction()` 取得实例的 RLock，执行 BEGIN IMMEDIATE；主体抛出 BaseException 时 ROLLBACK，正常离开时 COMMIT。

来源：[Service 入口](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/hepta/hia_agent_service.py#L82-L94)；[连接、schema、事务](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/hepta/hia_agent_store.py#L273-L358)。

现有 HIA 组件的接入范围很明确：

| 已选 HIA 组件 | 实际由 HIA 决定 | 仍调用的持久化边界 |
|---|---|---|
| Agent journal | 请求 identity、冲突/重放/unknown、ACK 与完成策略 | service.store.transaction、db.execute |
| Store authority | ref/get/URI/profile/put 的查询与拒绝顺序 | db.execute、fetchone、实际文件叶 |
| Artifact page | 页编码、wire 预算、cursor 决策 | 原 SQL callable、cursor 查询与插入 |
| Artifact publication | 不可变 artifact 字节发布、读回 | 不拥有数据库引用、请求 journal 或数据库事务 |

来源：[journal](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/hepta/hia_agent_journal_native.py#L317-L434)；[store authority SQL leaf](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/hepta/hia_agent_store_authority_native.py#L222-L287)；[page SQL leaf](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/hepta/hia_artifact_page_native.py#L181-L249)；[artifact byte layer](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/hepta/artifact_publication_native.py#L169-L188)。

因此真实接线点应保持这些上层调用共享同一个后端。将 Python 的 sqlite3 调用换成一个仍执行 SQLite 引擎的 C leaf，只能改变桥，不会把持久化算法迁入 HIA。

## 2. 十张表及完整生产操作

| 表 | 键及用途 | 当前生产操作 | 需要保持的状态关系 |
|---|---|---|---|
| artifacts | id 主键；uri、content_key 唯一；保存 sha/kind/metadata | 三种键查询；INSERT OR IGNORE | 文件先持久化，再颁发 DB ref；相同字节不同 kind/metadata 可有不同 ref |
| profiles | (id, sha256)；profile 对应 artifact ref | INSERT OR IGNORE；按双键读取 artifact | 预期 profile 比较、已颁发 profile、真实 artifact 三者绑定 |
| contexts | id；冻结 context、created_ns、attempts | INSERT；整行/创建时间读取；条件增加 attempts | attempts 的条件更新须原子，rowcount 决定是否取得候选预算 |
| requests | key；digest/tool/state/response/started_ns | key 查询；插入 running；更新 completed/response | 相同 key 先比较 digest；running 代表未确定；完成 replay 不重演 |
| costs | sequence 自增；tool/request/context/wall/status/details | INSERT；按 sequence 读当前 context 或无归属项，LIMIT 10001 | 原顺序、前 10000 项与显式截断；时长是 TEXT |
| cursors | id；artifact_id/sha/offset | id 查询；INSERT OR IGNORE | 游标必须属于同一个 artifact 身份，错误 storage class 的异常顺序可见 |
| slots | name；context/generation/epoch/ABI | 查询、首次 INSERT、UPDATE | generation/epoch 条件检查；rollback 也推进 epoch |
| versions | (slot, generation)；保留 artifact | 查询、扫描该 slot 的 generation、INSERT | 0 代 baseline 保留；新代 max+1；rollback 不删除后续版本 |
| leases | id；slot/generation/artifact/active | INSERT、查询、active COUNT、UPDATE inactive | 旧 lease 可跨 rollback；调用读取已保存 lease，不能被调用方 mutation 改名 |
| execution_budgets | context_id；used_native_ns/owner | INSERT、查询、owner claim、owner 条件释放并计费 | uncertain owner 继续占用；只由对应终态操作释放 |

DDL 全文在 [AgentStore](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/hepta/hia_agent_store.py#L301-L343)。全部 31 个 SQL 原文及每个实际位置已列入 `PRODUCTION-PERSISTENCE-MAP.json.queries`，没有从当前数据库内容反推出“期望”查询。

这里的“十表”是用户 schema。SQLite 格式兼容还涉及 schema 根页、索引、溢出页和内部元数据。尤其 costs 使用 AUTOINCREMENT，必须保留 sqlite_sequence 的持久序列语义；不能用简单的“当前行数+1”代替。参见 [SQLite file format](https://sqlite.org/fileformat.html) 和 [AUTOINCREMENT](https://sqlite.org/autoinc.html)。

## 3. 事务与故障时的精确行为

### 请求预留与重放

原调用者在输入语义检查和效果执行前，先在 BEGIN IMMEDIATE 中查询 requests。新的有效 request key 写入 running 后提交；已完成请求返回原保存响应；digest 不符得到 conflict；running 得到 unknown/observe_original。重开服务不会自动重试 unknown 请求。[源码](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/hepta/hia_agent_service.py#L245-L293)。

HIA journal 的 reserved/committed_inline ACK 位于实际 SQL 成功之后、事务 COMMIT 之前。不能把这两步融合成“拿到 HIA ACK 就已持久化”。旧测试明确注入“COMMIT 实际成功后抛错”及“先 ROLLBACK 后抛错”，要求前者重放已提交响应、后者保留 running。[原测试](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/tests/test_hia_agent_journal_native.py#L323-L407)。

### 版本切换

adopt/rollback 的业务方法在同一显式事务内执行，完成响应也在事务内写 requests。它们还可能发布 artifact 文件；数据库回滚并不等于删除已经持久化的不可变文件。替代后端必须允许失败留下未被颁发的字节，同时禁止颁发缺少持久字节的引用。[调用边界](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/hepta/hia_agent_service.py#L294-L305)；[版本操作](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/hepta/hia_agent_service.py#L1299-L1377)。

### 原生预算和 lease

evaluate 在短事务中取得 execution_budgets.owner，再离开事务运行 reference/native。只有到达确认终态路径才按 context_id 与原 owner 同时匹配，清除 owner 并累计时间；中途退出保留 fence。[源码](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/hepta/hia_agent_service.py#L1163-L1223)。

lease 的取得与释放各在一个显式事务中。invoke 从保存行重建 identity，当前 slot 改代或 rollback 不改变已经取得的 lease。[源码](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/hepta/hia_agent_service.py#L1379-L1443)。

### Artifact 与 SQL 的先后关系

put 的顺序是：计算内容身份、查重、创建临时文件、写入并 fsync、link 发布、fsync 目录、清理临时名，随后 INSERT OR IGNORE artifacts 并重查。文件/目录 fsync 失败时可以存在原字节，却不能返回成功 DB ref。这一边界已有真实 EIO 原控制。[源码](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/hepta/hia_agent_store.py#L366-L410)；[原控制](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/tests/test_hia_agent_artifact_store_native.py#L284-L306)。

### 现有非原子组合不能在本次调查中改写

context 行与 execution_budgets 行当前是两个 autocommit INSERT。普通请求的 costs INSERT 和最终 requests UPDATE 也是分开的 autocommit 语句。它们是当前行为，不应顺手合并、补跑或退款。可将其列为后续独立设计问题，但替代实现首先应与原调用者一致。[context](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/hepta/hia_agent_service.py#L498-L505)；[terminal writes](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/hepta/hia_agent_service.py#L311-L320)。

## 4. 下一项最小完整接口

建议实现一个固定 schema 的 **HIA AgentStore 数据库后端**，保留现有 AgentStore 的 `db` 外观；上层六个 store authority 方法、journal 和 page 桥继续使用它。生产入口的必要协议为：

| 接口 | 必须提供的实际结果 |
|---|---|
| open / schema bootstrap | 打开原数据库及 WAL 状态，建立一致视图，保留现有路径/权限与 schema 行为 |
| execute(sql, params) | 对当前 31 个业务模板及原初始化/事务语句执行完整读写；保留参数 storage class、绑定错误、结果顺序 |
| cursor.fetchone / fetchall / iteration | 保持 None/行、名称与 ordinal 取值、重复取值观察；不提前缓存 foreign row/getitem 的效果 |
| rowcount | 条件更新确切受影响行数，特别是 attempts 预算 claim |
| BEGIN IMMEDIATE / COMMIT / ROLLBACK | 一个共享文件事务；跨连接/进程互斥和原 busy/timeout 行为；durable commit 后才确认 |
| close / reopen | 未提交变更不被当作提交；恢复最近完整提交视图，保留未知请求与预算 owner |
| set_trace_callback / inspection SQL | 保持既有独立控制所观察的 SQL 跟踪、全表/顺序/计数查询 |

首个算法实现重点应是这个后端的 **页事务会话**：从 schema 根页解析实际布局、按读事务 end mark 叠加 WAL 页面、完成 table/index/overflow 操作、暂存写页、一次提交/回滚、关闭与重开恢复。真实 OS 读写、锁和 fsync 结果可以保持为薄 leaf；选择页面、索引维护、WAL 可见性和提交策略应由 HIA 执行。Python 对象/异常桥和 OS 运行时仍应独立声明，不将其与数据库算法迁移混称。

需要提前固定的接线约束：

1. 替代工厂进入现有 AgentStore 构造路径；新 owner 的实际调用必须由普通 service、journal、store-authority、page、worker 路径证明。单独运行一个 codec 不构成生产接入。
2. 保留实际 SQLite 文件兼容或明确的迁移协议。不能只读 main DB 而忽略已提交 WAL；不能把损坏或未支持的数据库静默送回 SQLite 引擎。
3. 现有实例 RLock 不是跨连接/进程数据库锁。SQLite BEGIN IMMEDIATE 会立即申请写事务；其冲突/可见性语义必须由新的存储协议承担。参考 [SQLite transaction](https://sqlite.org/lang_transaction.html)。
4. 已提交 WAL frame、读者 end mark、checkpoint 及截断尾部判定属于恢复层；checksum 成功本身不决定提交可见性。参考 [SQLite WAL](https://sqlite.org/wal.html)。
5. 固定小缓冲区应承载页或窗口，不成为整个 DB/WAL 的新体积限制。现有 clocks 以任意精度十进制 TEXT 保存，不能因为 native 接口使用 u64 而缩小。
6. 保存原 SQL callable 先绑定、再读取参数的顺序；foreign wrappers/row 对象仍按原操作顺序观察。已有控制会在属性访问时修改参数。
7. 既有 source、caller、installed 门使用原分母、方法体和时间门；新后端应加入真实接线与原件绑定，不把字节内核 finite PASS 移作这些门的 PASS。

### 为什么不能只宣称“31 个模板完成”

31 是生产业务模板数，不是原测试可观察的全部 SQL 域。旧 journal 控制真实创建 effect_probe、写入 effect 并查询回滚结果；旧 store 控制直接改 artifacts 的 uri/metadata；原 campaign/worker 控制读取 sqlite_master、全表和 rowid 排序。page 的独立 SQL fixture 使用一个允许 NULL 的窄 cursor schema。必须在后端验收接口中保留这些原控制，不能删掉它们或 mock 掉真正的数据库提交。[journal](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/tests/test_hia_agent_journal_native.py#L323-L407)；[store](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/tests/test_hia_agent_store_authority_native.py#L215-L319)；[page fixture](https://github.com/TrillionniumFoundation/Hepta/blob/8556199d761540f84c15856a6a9cf1a6f863ffc5/tests/test_hia_artifact_read_native.py#L54-L105)。

## 5. 原调用者清单与必须保持的行为

完整 ID、定义位置和继承来源在 `DB-BOUNDARY-AND-CALLERS.json`。该清单使用 AST 解析，未导入 unittest 模块中的产品，也未加载/执行任何 suite。原调用器的静态 DEFAULT_MODULES 展开为：

| 既有调用器 | 当前静态默认 ID 数 | 本轮结论 |
|---|---:|---|
| qualify_hia_agent_store_authority_callers.py | 67 | 五个原模块；包含两个 machine-choice 子类继承的六个方法 |
| qualify_hia_artifact_read_callers.py | 67 | 同五个完整原模块 |
| qualify_hia_agent_journal_callers.py | 94 | 上述五模块，再加 candidate、worker request、worker review |

这些数字只描述这些脚本的默认模块，不替代当前标准 workflow 其他组的原 89、Core116、UNPACK18 或 Full32 分母。使用显式模块参数的既有 workflow 仍按其自己的原清单执行。

优先直接关联持久化的原方法如下；它们是完整既有 suites 中的定位索引，不是缩小后的测试集合：

| 文件/类 | 原方法与其覆盖的边界 |
|---|---|
| test_hia_agent_native_tools.ArtifactContractTests | test_exact_request_replay_survives_restart_and_changed_body_rejects；test_process_killed_after_effect_leaves_unknown_intent_and_never_replays；test_issued_reference_fields_and_actual_bytes_are_verified；test_utf8_pagination_preserves_bytes_and_rejects_cross_artifact_cursor |
| test_hia_agent_native_tools.NativeLifecycleTests | test_published_version_lease_survives_rollback_and_release_is_checked；test_fresh_context_can_advance_existing_slot_and_stale_error_is_readable；test_expired_evaluation_is_rejected_before_any_reference_or_native_runner；test_reference_loop_cannot_restart_or_overrun_frozen_context_deadline；原 test_native_timeout_is_incomplete_terminated_and_not_adoptable 的 5 秒断言保持 |
| test_hia_agent_native_campaign.QualificationCampaignTests | test_two_campaigns_share_store_but_not_slot_and_reconnect_does_not_reexecute；test_committed_but_lost_reply_retains_original_intent_for_recovery |
| test_hia_agent_native_lease_snapshot.LeaseSnapshotTests | test_caller_mutation_during_native_call_cannot_relabel_result_or_buffers |
| test_hia_agent_journal_native.JournalNativeTests | test_real_SQL_commit_fault_preserves_ack_before_commit_semantics；test_native_protocol_failure_cannot_journal_a_rolled_back_success；test_real_process_kill_after_effect_preserves_running_intent；test_exact_reference_errors_rows_and_arbitrary_precision_clock_TEXT；test_real_SQLite_non_TEXT_observations_preserve_conflict_before_state；test_malformed_cached_response_never_reexecutes_or_rewrites_request |
| test_hia_agent_store_authority_native.StoreAuthorityNativeTests | test_real_issuance_dedup_profile_uri_and_restart_preserve_all_state；test_actual_SQL_failure_boundaries_and_transaction_rollback_keep_original_rows；test_row_getitem_reobservations_and_subclass_dispatch_are_preserved；test_foreign_callables_and_path_attributes_are_bound_before_argument_effects |
| test_hia_artifact_read_native.ArtifactReadNativeTests | test_real_store_ordinary_paging_and_reopen_preserve_bytes_and_cursors；test_SQL_callable_binding_and_all_builtin_corrupt_offset_errors；test_real_SQL_exceptions_and_transaction_boundaries_keep_exact_state |
| test_hia_agent_artifact_store_native.AgentArtifactStoreRouteTests | test_real_store_bytes_metadata_dedup_restart_and_namespace_authority；test_actual_native_fsync_failures_cannot_issue_DB_refs_or_replay_effects |
| test_hia_agent_candidate_native.AgentCandidateNativeTests | test_exact_replay_precedes_bad_manifest_context_work_and_attempt_charge；test_killed_candidate_stages_retain_unknown_and_terminal_reply_replays |
| test_hia_worker_request_native.WorkerRequestNativeTests | test_ordinary_worker_native_admission_retained_replay_conflict_and_unknown |
| test_hia_worker_report_native.WorkerReportNativeTests | test_ordinary_sqlite_reopen_replay_conflict_and_unknown |

另外保留各类原 installed-wheel 方法与 source/resource refusal；本轮没有重审 Root 负责的安装方案，也没有将其视为通过。

## 6. 已有 HIA SQLite 算法证据及缺口

下表引用 Cold 已完整封存、Root 已接收的 exact canonical handoff。本调查没有重复执行这些内核。

| 组件 | 已有有限实际结果 | canonical | 尚不代表的能力 |
|---|---|---|---|
| varint | 8 方法 / 76054 native returns；完整 trace 207481528 B | 091e83392c9076cf7cd2b7cb1f19b46ee45f64f5 | 数据库连接、事务或索引 |
| WAL checksum/header/frame | 10 / 238；476 trace records；1321832 B；38 个拒绝时的 C seed 变化保留 | 7ffcb9375481a29ccffb69b6fdc681be247d539d | WAL-index、锁、commit 可见性、崩溃恢复或 checkpoint |
| record | 12 / 159；24830697 B trace；每 C 2774 个合法 field 调用 | a0d3af18bf0cde0bd6e5e977cc0ce5bd53cb97b3 | 完整非法 record 的 C oracle、SQL affinity/排序/唯一索引、物理写入 |
| B-tree selected cell | 当前已知 source 12 / 339 PASS；native 请求在冻结，尚未执行 | 由 Native 持有新请求 | 多页检索、插入、分裂、溢出链、free list、索引维护及数据库恢复 |

前三项使用历史 development B3；它们不构成当前产品 matching-cold 资格。下一轮若把它们接入 shared database owner，需要当前源码/编译器/图像/桥同一身份，并重新取得原调用者实际结果。

## 7. 还没有被原控制直接闭合的恢复工作

以下是从当前代码与已读控制推导的下一实现风险，不是本轮发现的新的产品执行失败：

- 原“kill after effect”测试验证 journal 的持久 running 语义，但没有穷尽新页写入层在每个 write/fsync/commit-frame/索引页交界的崩溃状态。
- 同一 store 的不同 service 实例和进程需要一致锁与 snapshot；不能仅以 Python 实例锁代替文件事务。
- 需要整体 DB + WAL 恢复、部分尾部、IO/ENOSPC、commit 回执丢失、checkpoint 中断的真实行为；有限 checksum/record 测试没有覆盖这些生命周期。
- 记录与索引必须共同提交；INSERT OR IGNORE、唯一约束、AUTOINCREMENT 和 rowcount 都不能仅靠字节解码器推断。
- 目前没有普通 AgentStore 经 HIA 数据库后端的真实执行、默认激活、installed 数据库资源准入或完整 Full32 通过证据。

## 原件定位

本报告同目录保存：

- `RAW-SOURCE-INDEX.json`：42 个当前源/fixture 命中及 52 个 direct SQL AST 位置。
- `DB-BOUNDARY-AND-CALLERS.json`：23 个全文绑定、13 个测试模块的定义/继承 ID、三个原资格调用器的完整默认清单、127 个宽松 SQL 文本候选。宽松候选中含前缀和普通字符串，不能把 127 当 SQL 执行数量。
- `PRODUCTION-PERSISTENCE-MAP.json`：十表、31 个精确业务 SQL、source 引用、原测试边界和建议接口。
- `UNPACK-ANCHORS.original.json`：已交 Cold 的 2586 B 原扫描输出；921 个当前 tests/tools 文件只读，未发现额外旧 UNPACK 产物大小/SHA 固定断言。
- `inspect_sources.py`、`inspect_db_boundary.py`：只读分析脚本。没有资格或产品运行权。
