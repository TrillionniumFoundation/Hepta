# Hepta v7 适配与有限原生持续负载：最终回执报告

当前冻结源码 `f5b6598bdd88db92c4ef2b17e10deda9a90bdd59`：full35 已记录 35/35 项，通过 34 项；外层 ok=false。独立 hosted profile qualified=false。原17条义务当前有限关闭 3 条，开放 14 条；其中14条更广义务保持开放。

**本次正式有限profile未合格。** 完整epochs=150；attempts=4982，starts=4982，confirmed reaps=4982，**completed observations=4981**。入口有观察=4831，入口结果不可用=151，总入口调用数=null。

本报告由最终回执生成。通过、失败、噪声、退化、未完成和不可用结果分别保留；没有执行新的资格或重跑历史NDU计时。`null` 表示证据不可用，不能解释为零。完整机器结果见 [results.json](results.json)，原17条义务及逐项判定条件见 [blockers.json](blockers.json)。

## 1. 源码与执行身份

- 本轮固定提交：`f5b6598bdd88db92c4ef2b17e10deda9a90bdd59`；两份外层回执、所读报告、审计与归档成员的实际 SHA256 记录在 `results.json.inputs`。
- 历史系统交付为 `de49fe3e0254b7b71dbcb5b2907a3f3145999393`；两次历史NDU计时仍属 `b92141483ca5084691f436d28d4cd0dcbefe4717`。其原始状态、样本、超时、no-change、噪声与成本单独保存，没有重标为本轮结果。
- 本轮 system 身份检查：`{"known": true, "qualified_identity": true, "source_unchanged_recorded": true, "tools_unchanged_recorded": true, "unavailable": {}}`。
- 本轮 hosted 身份检查：`{"known": true, "qualified_identity": true, "source_unchanged_recorded": true, "tools_unchanged_recorded": true, "unavailable": {}}`。
- 外层/子进程尚未确认终止时，生成器拒绝最终输出。已终止进程留下 running checkpoint、缺少或损坏 producer report 时，报告将它记为终止后的未完成/失败；源码或工具收尾缺失阻止有限关闭。

## 2. 本轮 full35 与独立 native-loan

| Gate | passed | returncode | producer status |
| --- | --- | --- | --- |
| unit_regression | true | 0 | completed |
| rust_shadow_cargo | true | 0 | None |
| rust_shadow_parity | true | 0 | None |
| agent_query_semantics | true | 0 | None |
| standalone_native | true | 0 | finite_standalone_core_native_corpus_passed |
| standalone_resources | true | 0 | qualified |
| composite_resources | true | 0 | finite_composite_native_qualification_passed |
| composite_bulk_targets | true | 0 | finite_two_owner_composite_bulk_x86_64_and_qemu_passed |
| recursive_resource_chains | true | 0 | None |
| source_migration | true | 0 | finite_source_to_hia_native_qualification_passed |
| cpp_template_migration | true | 0 | finite_cpp_template_native_qualification_passed |
| c_configuration_matrix | true | 0 | finite_c_scalar_build_matrix_native_qualified |
| cpp_configuration_matrix | true | 0 | finite_cpp_build_matrix_native_qualified |
| upstream_c_resource_matrix | true | 0 | None |
| upstream_cpp_composed_lifetimes | true | 0 | complete_observation_with_foreign_termination |
| cpp_composed_implementation_llvm | true | 0 | native_composed_llvm_qualified |
| llvm_local_stored_views | true | 0 | passed |
| task_io_composition | true | 0 | passed |
| selected_core_formal | true | 0 | passed |
| standalone_aarch64_qemu | true | 0 | finite_standalone_aarch64_qemu_corpus_passed |
| standalone_riscv64_qemu | true | 0 | finite_rv64gc_lp64d_qemu_abi_and_resource_execution_passed |
| legacy_executable_core | true | 0 | finite_native_corpus_passed |
| legacy_hosted_composition | true | 0 | finite_rust_composition_passed |
| legacy_cortex_m4_qemu | true | 0 | passed |
| bounded_concurrency | true | 0 | passed |
| shared_runtime | true | 0 | passed |
| independent_concurrent_ir | true | 0 | passed |
| structured_task_trees | true | 0 | passed |
| bounded_async_io | true | 0 | passed |
| native_host_gcc | true | 0 | passed |
| native_host_clang | true | 0 | passed |
| provenance_and_type_core | true | 0 | passed |
| formal_core | true | 0 | passed |
| application_performance | true | 0 | passed |
| standalone_performance | false | 1 | measurement_inconclusive |

未通过：`["standalone_performance"]`。尚未完成：`[]`。完整固定门槛清单匹配：`true`。

当前唯一单元方法与ID完整性：`{"available": true, "complete_ids": true, "id_inventory_sha256": "8bd8dfa7e9fb16c6c810992f5eff99c9095347d94d42d3b24ee8553761001014", "missing_count_outcomes": [], "module_count": 276, "observed_counts": {"errors": 0, "expected_failures": 0, "failures": 0, "skipped": 0, "tests_run": 2729, "unexpected_successes": 0}, "ok": true, "reported_tests_run": 2729, "schema": "hepta.hia.partitioned-unit-qualification.v1", "scope": "Embedded final module ID lists checked for missing/duplicate/unfinished IDs; this reporter does not rerun tests or independently discover tests from source.", "status": "completed", "unique_finished_ids": 2729}`。
v7 与 soak 模块在本轮单元回执内的精确方法、完成ID及结果保存在 `current_system.unit.selected_modules`；开发回归、独立审阅及重复运行不与这个唯一ID分母相加。

独立 native-loan 当前 qualified=`true`，status=`"passed"`，最终 drained=`true`。
其尝试/启动/回收/完成/入口分母为：`{"attempted_calls": 7, "child_process_start_count_complete": true, "child_processes_reaped": 7, "child_processes_started": 7, "completed_observations": 7, "native_entries_observed": 6, "native_entry_invocations": null, "unavailable_child_start_outcomes": 0, "unavailable_native_entry_outcomes": 1, "unconfirmed_child_reaps": 0}`。诊断插桩观察到借用端点不等于完整内存安全证明；Popen成功也不等于原生入口已经执行。

## 3. v7 有界 NDU 适配

当前代码对已有 `byte-swap.v1` 与 `checked-unsigned-reduction.v1` 接受 primitive v7；`full-view-fill-loop.v1` 仍限 v1–v6。每个 baseline、重放结果、候选以及语义观察入口重新验证完整输入，拒绝同canonical bytes的composite身份替换、伪造结构元数据和不匹配的native receipt。

这增加版本适配，没有新增chain优化。单元控制涵盖chain/head loan经过checked reduction的返回、trap、allocation refusal和完整VM资源账本；当前执行结果以本轮 `test_hia_ndu_v7` 回执为准。开发native/NDU控制保留其各自source和artifact身份；显式synthetic-cost的真实abstain控制不成为计时收益。原两次NDU计时不重跑，不把有限候选选择称为任意程序全局最优。

## 4. 先失败、修复与独立审查

v2 reader曾错误接受7项重算摘要或重链后的证据变异，并有预算/程序角色缺口。独立lifecycle审阅还用3个真实已退出但未确认wait的子进程暴露final statistics、stream.close和Thread构造异常丢失清理owner的问题；审阅端最终实际回收这些子进程，旧失败记录没有回写成成功。

v3 producer把owner保证放入真正最外层finally，Thread构造/启动失败进入同步fallback，空owner恢复幂等；不变的3个真实故障控制随后通过。v3 reader修复原问题，但又暴露4项关系错误接受：build/pacing超出实际事件窗口、观察结束早于最后drained采样，以及同时held的子进程共享PID。

v4 reader把耗时绑定实际单调时钟窗口，要求last drained≤progress≤observation≤run_end，并维护held到terminal的活动PID集合。独立复验21个证据副本加2个profile变异全部符合预期；包括允许顺序PID复用的正例。这些是离线重放控制，没有新增native执行。v4 producer与已通过3个真实故障控制的v3字节完全相同，独立审查据此延续有限生命周期结论；补丁历史身份仍分别保存。

外层wrapper的 `wait_owned` 保持原始Popen对象和wait责任，中断最多转发一次取消，后续wait或signal异常继续保留owner；只在确认子进程结束后返回或重新抛出原异常。没有通过外层强制kill来抹掉未确认清理义务。其独立控制、初始harness失败与修正、报告解析负例保留在归档和审计引用中。

本轮完整单元执行保留六类原始目录；这些故障控制中的failed/running checkpoint是预期负例证据，不能当成一次成功正式soak：

| retained control | present | raw members | saved status | execution_passed |
| --- | --- | --- | --- | --- |
| single-epoch | true | 9 | development_complete | true |
| failed-spawn | true | 9 | incomplete_or_failed | false |
| cleanup-owner-negative | true | 2 | failed_cleanup_recovered | false |
| finalizer-statistics | true | 6 | failed_cleanup_recovered | false |
| finalizer-close | true | 6 | failed_cleanup_recovered | false |
| finalizer-constructor | true | 6 | failed_cleanup_recovered | false |

## 5. 正式有限 hosted profile

profile=`hosted-native-lifecycle-30m.v1`，qualified=`false`。外层status=`"completed"`，producer status=`"incomplete_or_failed"`，stop_reason=`"unexpected_failure"`。

failure_phase=`"admission:baseline-across-close-0"`；原始失败=`{"identity": "147e30728d3c3d2c3d4436d32399b0ff9f5338bd48c002cc04a306700915e687", "message": "E_HIA_LOAN_PROBE: selected native loan was not observed within wait deadline", "type": "HIADifferentialRejected"}`。

完整epochs=150；attempts=4982，starts=4982，confirmed reaps=4982，**completed observations=4981**。入口有观察=4831，入口结果不可用=151，总入口调用数=null。 starts/reaps与completed observations有各自分母；确认清理不把未完成调用变成成功观察。

| 最低验收项 | 实际值 | 注册最低值 | 已达到 |
| --- | --- | --- | --- |
| 完整epochs | 150 | 128 | true |
| 完成观察 | 4981 | 5000 | false |
| 实际观察秒数 | 799.016829047 | 1500.0 | false |

因果调查 `/workspace/scratch/7e691a7ff65f/validation-runtime-soak-next/hosted-failure-investigation-1/causal-review.json`（SHA256 `fecc62da1ffa0847fc502bd0347aaee86e5e93426403b8a43dc74cf8ce66ad84`）绑定本次失败报告与注册。它记录的正常调用观察期限为 **5秒**，来源是冻结producer的 `begin()` 内置策略，并非profile JSON独立字段；注册source snapshot仍绑定这段代码。原生执行期限 **8.0秒** 来自注册profile，并在Popen返回后由observer建立。调查绑定attempt=4982，admission interval=5315938319ns；最终events=[{"bytes": 5, "event": "loan_started", "first_byte": 0, "last_byte": 0, "selected_loan_active": true}]，ack_sent=false，child returncode=-9，cleanup_confirmed=true，observer error={"message": "E_HIA_LOAN_PROBE: native child timed out while loan execution remained tracked; process group terminated", "type": "HIADifferentialRejected"}。原始admission错误与后来的observer错误分别保留。没有per-event、Popen返回或observer首次读取时间戳，不能区分子进程启动/执行延迟与观察线程调度/IO延迟，也不能由最终loan_started反推它在观察期限内已可见。调查结论 code_defect_demonstrated=false，correction_proposed=false，hosted_retries=0。不据这次失败增大阈值或重试追求有利宿主状态。

固定上限为1800秒测量墙时、1620秒停止新epoch、512epochs/16896attempts、2个并发native调用和96MiB证据预算。接受还独立要求至少1500秒实际观察、128完整epochs、5000完整观察以及显式pacing≤60%；预算上限不能充当已完成时长。没有为补足时间而在结尾空转。实际minimum checks=`false`。

当前计数：`{"attempted_calls": 4982, "child_process_start_count_complete": true, "child_processes_reaped": 4982, "child_processes_started": 4982, "completed_observations": 4981, "native_entries_observed": 4831, "native_entry_invocations": null, "unavailable_child_start_outcomes": 0, "unavailable_native_entry_outcomes": 151, "unconfirmed_child_reaps": 0}`。
当前timing：`{"actual_call_observation_wall_sum_ns": 706676899034, "admission_to_host_observation": {"max_ns": 5315938319, "p50_ns": 89859476, "p95_ns": 351384911, "p99_ns": 1009651019, "samples": 4982}, "call_intervals_overlap": true, "completed_observations_per_wall_second": 6.233911250581439, "explicit_pacing_wait_ns": 131572004082, "includes_process_startup_diagnostic_wait_and_cleanup": true, "network_or_service_latency": false, "nonpacing_controller_wall_ns": 667444824965, "observation_wall_ns": 799016829047, "observed_build_control_wall_sum_ns": 127963752753, "outer_process_wall_including_recovery_requires_supervisor_record": true, "parent_cpu_seconds": 88.375479}`。延迟样本数包含已失败的admission观察；吞吐使用completed-observation分母，不能把两者混同。`case_counts`标识已尝试的预定case类别，不是成功返回次数。
当前资源摘要：`{"available_child_samples": 4830, "largest_observed_child_fd_count": 6, "largest_observed_child_rss_kib": 11628, "largest_observed_drained_parent_fd_count": 5, "largest_observed_drained_parent_rss_kib": 31352, "last_drained_parent": {"available": true, "fd_count": 5, "pid": 1061379, "rss_kib": 31352, "starttime_ticks": 9470821, "threads": 1, "vm_hwm_kib": 33888}, "parent_after": {"available": true, "fd_count": 5, "pid": 1061379, "rss_kib": 31360, "starttime_ticks": 9470821, "threads": 1, "vm_hwm_kib": 33888}, "parent_before": {"available": true, "fd_count": 5, "pid": 1061379, "rss_kib": 26644, "starttime_ticks": 9470821, "threads": 1, "vm_hwm_kib": 26644}, "unavailable_or_unrequested_child_samples": 152}`。
当前失败/恢复：`{"cleanup_recovery": null, "drained": true, "evidence_write_error": null, "failure": {"identity": "147e30728d3c3d2c3d4436d32399b0ff9f5338bd48c002cc04a306700915e687", "message": "E_HIA_LOAN_PROBE: selected native loan was not observed within wait deadline", "type": "HIADifferentialRejected"}}`。

负载实际执行每epoch编译/创建、候选取消、baseline活动借用跨激活、candidate双调用、跨回退持有、trap、分配拒绝、withheld ACK timeout及关闭期间持有与排空。资源是独立子进程私有标量入口的有限诊断资源；不代表进程内热补丁、跨调用外部借用、持久回调/任务或共享状态迁移。

FD/RSS阈值在drained-epoch采样点执行；before/after与held child样本是离散观察。吞吐与尾延迟包含进程启动、诊断握手、等待和清理，共享宿主没有排他性证明；这些数据不授予性能收益、网络SLO或生产长期资格。即使有限profile通过，`P7-LONGLOAD`仍开放。

## 6. 性能、失败与成本

当前performance详细保留在 `current_system.performance`：standalone的全部evaluation/quality_failures/performance_failures与原始sample分母，application的全部observed_slowdowns与timing contract均不删去。`measurement_inconclusive`不能写成性能通过；表面更快且未过固定质量门槛的样本不证明收益。历史两次NDU结果完整保存在 `historical.ndu_attempts`，包括中断后未报告工作未知的标记。

成本分层记录在 `costs`：driver main墙时与父CPU、各child step墙时与子CPU、producer观察窗口、pacing、可能重叠的call interval之和以及run进程外层等待。它们有包含/重叠关系，**没有相加成总成本**。driver main还不含模块导入、最后summary序列化及调用者开销。失败后的owner恢复可以超出1800秒测量上限，外层run step的实际wall保留该等待；工程、模型、能耗与人工成本没有因此获得实测。

## 7. 原17条义务与新增有限结论

| 阶段 | obligation | de49历史状态 | f5当前状态 |
| --- | --- | --- | --- |
| P0 | P0-CURRENT-SOURCE | closed_in_declared_profile | closed_in_declared_profile |
| P1 | P1-GENERAL-RESOURCE-MODEL | open | open |
| P1 | P1-ERROR-CANCEL-CONCURRENCY | open | open |
| P2 | P2-CURRENT-SOURCE-EQUIVALENCE | closed_in_declared_profile | closed_in_declared_profile |
| P2 | P2-REFINEMENT-SCOPE | open | open |
| P3 | P3-BROAD-CANDIDATE-SPACE | open | open |
| P4 | P4-REPRODUCIBLE-NET-GAIN | open | open |
| P4 | P4-REAL-WORKLOAD | open | open |
| P5 | P5-CONTRACTS-AND-COVERAGE | open | open |
| P5 | P5-MIGRATION-ECONOMICS | open | open |
| P6 | P6-CURRENT-CLEANUP-RECEIPT | closed_in_declared_profile | closed_in_declared_profile |
| P6 | P6-PERSISTENT-STATE | open | open |
| P7 | P7-ACTUAL-HOSTS | open | open |
| P7 | P7-PHYSICAL-DEVICES | open | open |
| P7 | P7-INDEPENDENT-AGENTS | open | open |
| P7 | P7-LONGLOAD | open | open |
| P7 | P7-DIMENSIONAL-QUALIFICATION | open | open |

3个历史有限closed按当前相关gate、源码/工具身份、唯一ID完整性以及适用的native-loan结果重新判定；无关性能失败不代替语义判断。14个更广目标保持open。若本轮hosted通过，只在 `additional_finite_profile_closures` 增加独立profile closure，不改写原17条及生产P7-LONGLOAD。任意C/C++低成本重写、全语言安全/精化、工业真实热函数净收益、多物理宿主/设备、独立Agent开发经济性与生产长期负载仍需各自证据。

外部访问快照另见 `reviews.development_and_historical.runner_browser_access_snapshot` 与 `cloud_target_capability_snapshot`。这些记录没有新鲜runner探测：所记录GitHub插件能力没有 `fresh_dispatch`，浏览器观察为未登录，历史workflow run不证明runner当前在线。记录中的HTTP400不能解释成权限403。后续授权或新探测必须另留新回执，不改写此快照。访问条件只是部分外部依赖；上述14个广义目标还包含语义、实现、证明、真实工作负载和经济性工作，不可概括成只差登录。

## 8. 原始证据与复现

原始归档：`{"bytes": 14747460, "path": "raw-evidence.tar.xz", "sha256": "6e9e1c01809499659155329790d008e82d5d1cc581dcc67d1e3ae22252ee4d07"}`；4497个成员，19个有序parts。机器结果绑定 [raw-evidence-manifest.json](raw-evidence-manifest.json)、[raw-evidence-parts.json](raw-evidence-parts.json) 与 [source-run-index.json](source-run-index.json)。报告生成器只读取并核对小型回执/index，不重新解包或执行归档内容。Packager已经重开每个归档成员验证身份；运输parts用 [reassemble_raw_evidence.py](reassemble_raw_evidence.py) 的校验入口还原。

`results.json.reviews` 保留开发/历史审查与本轮最终审计的具体路径、schema、status、source范围和SHA。审计文件可单独放入 `audits/`，其源文件同时属于原始归档。报告不是独立运行证明；所有结论的实际执行身份以被冻结的producer与supervisor回执为准。
