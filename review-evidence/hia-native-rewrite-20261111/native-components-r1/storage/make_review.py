from pathlib import Path
from hashlib import sha256
import json,stat
OUT=Path('/workspace/scratch/9acdfa9f5639/agent-persistence-independent-d5')
census_raw=(OUT/'census.json').read_bytes();c=json.loads(census_raw)
tests=c['audited_test_ids']
def ids(*names):
 rows=[r for r in tests if r['id'].rsplit('.',1)[-1] in names]
 assert set(r['id'].rsplit('.',1)[-1] for r in rows)==set(names),(names,rows)
 return rows
report={
 'schema':'hia.agent-persistence-owner-review.v1',
 'status':'READ_ONLY_AUDIT_COMPLETE_NOT_IMPLEMENTED_NOT_QUALIFIED',
 'source_commit':c['source_commit'],'source_tree':c['source_tree'],
 'scope':'Pinned d5 production owners, all SQL call sites, direct runtime callers and existing acceptance assertions; no production changes, no test/native rerun, no stored-data migration.',
 'census':{'path':'census.json','bytes':len(census_raw),'sha256':sha256(census_raw).hexdigest(),'source_pins':26,'tables':10,'sql_call_sites':51,'distinct_sql_texts':37,'DML_call_sites':45,'distinct_DML_texts':31,'DDL_execute_script_sites':1,'transaction_control_sites':3,'pragma_sites':2,'listed_test_methods':156,
 'counts_scope':'156 is the full method inventory in ten inspected test modules, not a claim that all 156 exclusively test persistence or were executed during this audit.'},
 'main_finding':'Selected HIA journal owns journal decisions and canonical instructions. Durable storage, namespace lookup/issuance, full transaction boundaries and all eight tables outside request/cost journaling still depend on hosted AgentStore/service SQL; the native artifact file component already owns optional byte publication, but not database namespace issuance.',
 'production_entry_points':[
  {'path':'hepta/hia_agent_store.py','lines':[266,446],'next_owner':'Replace the complete ten-table storage adapter: initialize/open, transaction, typed row read/insert/update/CAS, stable sequence and close. Keep full put/get/profile/ref/URI behavior.','call_sites':13},
  {'path':'hepta/hia_agent_service.py','lines':[267,1435],'next_owner':'Route all 33 SQL sites to the same native transaction/session owner, including context budget, costs, cursor, slot/version/lease; no second side store.','call_sites':33},
  {'path':'hepta/hia_agent_journal_native.py','lines':[360,432],'next_owner':'Replace only the five mechanical SQL sites and their transaction acknowledgement bindings. Preserve the existing HIA journal decisions, native stages, error/ACK order and fail-stop behavior.','call_sites':5}],
 'tables':[
  {'table':'artifacts','keys':['id','unique uri','unique content_key'],'operations':['lookup content_key','INSERT OR IGNORE then read winning content_key row','lookup exact id and compare id/sha256/uri','lookup issued uri'],'preserve':'Equal bytes with different kind/metadata yield different issued references. Hash/file existence never grants namespace or kind authority. Publication fsync precedes issuance; a rollback can leave unreferenced content bytes.'},
  {'table':'profiles','keys':['(id,sha256)'],'operations':['INSERT OR IGNORE','lookup artifact by exact installed id and sha256'],'preserve':'Installed profile equality is checked before row authority. Profile artifact kind remains required.'},
  {'table':'contexts','keys':['id'],'operations':['insert frozen context/time/attempts=0','read exact context record','read created_ns','single-statement attempts<limit increment with rowcount CAS'],'preserve':'Created time and frozen installation/profile/workload/budget remain unchanged. Exact replay is evaluated before another candidate attempt charge.'},
  {'table':'requests','keys':['key'],'operations':['transactional lookup and running intent INSERT','complete response UPDATE','cached response read'],'preserve':'Claim valid request key before later schema/catalog/context refusals; different digest conflicts before state. Running/unknown never reexecutes. Completed exact replay issues no effect, cost or request rewrite; verification replay retains its separate evidence gate.'},
  {'table':'costs','keys':['INTEGER PRIMARY KEY AUTOINCREMENT sequence'],'operations':['append cost','ordered context-or-unscoped prefix SELECT LIMIT 10001'],'preserve':'Costs retain failed attempts, nullable context and arbitrary decimal wall TEXT. 10001 is an existing report truncation detector, not a global storage limit.'},
  {'table':'cursors','keys':['id'],'operations':['read cursor','INSERT OR IGNORE retained cursor'],'preserve':'Cursor bound to exact artifact id/sha and UTF-8 page byte offset; foreign artifact reuse rejected.'},
  {'table':'slots','keys':['name'],'operations':['read snapshot','insert baseline generation/epoch 0','update current generation/epoch/context'],'preserve':'Conditional generation+epoch guard, ABI identity and currently active baseline required. Snapshot alone grants no adoption authority.'},
  {'table':'versions','keys':['(slot,generation)'],'operations':['read retained artifact','enumerate all generation strings','insert baseline and new versions'],'preserve':'New generation is numeric max(history)+1; rollback only changes active generation and advances epoch. Historical generations remain for leases; no automatic pruning.'},
  {'table':'leases','keys':['id'],'operations':['count active for slot','transactional active INSERT','read exact issued tuple','transactional active=0 update'],'preserve':'Existing lease pins original generation/artifact across rollback, forged/released lease rejects. Admission copies retained row so mutable caller aliases cannot change in-flight identity.'},
  {'table':'execution_budgets','keys':['context_id'],'operations':['insert used=0/owner=NULL','transactional lookup+owner claim','conditional owner match release plus used_native_ns update'],'preserve':'Live or uncertain owner blocks another native evaluation. Only confirmed terminal execution releases; crash cannot refund unknown cost.'}],
 'transaction_and_failure_semantics':[
  'Current constructor uses owned private root/artifact directory, private regular state.sqlite3, WAL, synchronous FULL, 10-second busy timeout and one RLock around BEGIN IMMEDIATE/COMMIT/ROLLBACK. Copy exact constraints; source pins do not by themselves prove crash safety.',
  'Most calls use autocommit. Ordinary context creation consists of artifact publication plus two distinct INSERTs; do not silently describe it as an existing all-or-nothing transaction. Adopt/rollback effects and the exact completed response share a transaction in both retained and native-journal dispatch.',
  'Reservation INSERT ACK and inline response UPDATE ACK occur after SQL success but before COMMIT. Real COMMIT fault controls exercise rollback-before-error and commit-before-error separately. First caller rejection can coexist with a durably completed response that the next call replays.',
  'Native protocol/ACK failures, KeyboardInterrupt, SystemExit or MemoryError must not reenter the failed image from finally or write a terminal response/cost after a rollback. An earlier committed running intent stays UNKNOWN.',
  'Transaction failure recovery is not ordinary replay. File publication, database commit and response delivery have independent durability/acknowledgement boundaries. A possible orphan artifact does not authorize a reference.',
  'Read-only inspect_slot is currently a multi-statement observation outside an explicit transaction; it is labeled non-authoritative. The new engine must not use such a snapshot as adoption authority.',
  'The local RLock serializes explicit transactions, not every direct execute; cross-process serialization currently comes from SQLite. The read-only audit does not establish all-thread linearizability of the current API or prove a new multiwriter engine.',
  'Existing persistent SQL observations include BLOB/non-TEXT values and malformed cached JSON controls. Preserve storage class and conflict-before-state error ordering at migration/recovery boundaries; do not normalize malformed old rows into success.',
  'Clock values deliberately exceed machine integers in existing tests (request start 10**90+7; monotonic origins 10**100). Store decimal TEXT faithfully; only fields already admitted as canonical u64, such as generation and epoch, get u64 limits.'
 ],
 'existing_acceptance_evidence_sources':{
  'restart_replay_unknown':ids('test_exact_request_replay_survives_restart_and_changed_body_rejects','test_process_killed_after_effect_leaves_unknown_intent_and_never_replays','test_real_artifact_restart_replay_alias_and_no_effect_cost_or_update','test_real_process_kill_after_effect_preserves_running_intent'),
  'commit_ack_protocol_failures':ids('test_real_SQL_commit_fault_preserves_ack_before_commit_semantics','test_native_protocol_failure_cannot_journal_a_rolled_back_success','test_ack_order_conflict_unknown_and_special_verification_replay'),
  'row_types_and_clocks':ids('test_real_SQLite_non_TEXT_observations_preserve_conflict_before_state','test_exact_reference_errors_rows_and_arbitrary_precision_clock_TEXT','test_malformed_cached_response_never_reexecutes_or_rewrites_request'),
  'artifact_durability_namespace_race':ids('test_real_store_bytes_metadata_dedup_restart_and_namespace_authority','test_actual_native_fsync_failures_cannot_issue_DB_refs_or_replay_effects','test_real_file_and_directory_fsync_and_post_fsync_receipt_boundary','test_real_post_link_corruption_withdraws_only_own_content_inode','test_real_post_link_competitor_inode_is_never_deleted'),
  'lease_and_attempt_authority':ids('test_published_version_lease_survives_rollback_and_release_is_checked','test_exact_replay_precedes_bad_manifest_context_work_and_attempt_charge','test_fresh_context_can_advance_existing_slot_and_stale_error_is_readable','test_expired_evaluation_is_rejected_before_any_reference_or_native_runner'),
  'ordinary_worker':ids('test_ordinary_worker_native_admission_retained_replay_conflict_and_unknown')
 },
 'caller_gate':{
  'path':'tools/qualify_hia_agent_journal_callers.py',
  'requirements':'Existing eight-module ordinary caller gate retains nonempty chosen set, exact loaded/chosen/executed IDs/count/order, all eleven tools, no failure/error/skip/expected failure/unexpected success. Cold qualification cannot exclude tests. Parent-only native counters do not claim child observations.',
  'additional_direct_paths':'Worker creates HIAAgentService; native qualification, macro campaign/multistep and first-use tools use the same store. Buffer lifecycle qualification calls acquire_slot/invoke_lease/release_slot in separate real consumer processes. Full path/line inventory is in census.json.',
  'compatibility_fixture_note':'Tests currently inject SQLite rows or inspect state.sqlite3 directly. Those are explicit legacy oracles/fault controls; a native replacement needs equivalent raw-state fault controls and an actual old-store importer. Removing or skipping them is not acceptable closure.'},
 'migration_audit':{
  'current_mechanism':'AgentStore creates ten tables IF NOT EXISTS. The inspected production owner files contain no schema version negotiation, ALTER TABLE migration, SQLite-to-native importer, record compactor or finalization receipt.',
  'scope_limit':'This is an exact inspection of these owner files plus repository text search for state.sqlite3/ALTER TABLE/user_version/schema_version. It is not proof that arbitrary SQLite databases or unrelated applications are compatible.',
  'must_preserve':['issued ids, URIs, content keys, metadata and kind authority','all request states/responses, including running/unknown and malformed observations','cost sequence including its high-water mark','all contexts/attempts/execution owner fences','all versions, active leases, epochs, cursors and profiles','actual immutable artifact bytes and ownership/modes'],
  'required_new_evidence':['independent full logical old/new snapshot and per-operation outcomes','multi-process competing reserve/dedup/CAS/lease stress under the same shared namespace','kill/fault at append/fsync/commit/publication/ACK boundaries with reopen and replay','partial/corrupt/torn trailing data and uncertain acknowledgement recovery without fabricated success','migration resumability with complete source readback before activation; original data retained until migration qualifies','no new total record count or aggregate byte quota; large histories must not be folded into the 8MiB JSON or 64MiB artifact channel limits']},
 'recommended_next_owner':{
  'name':'Complete Agent persistence engine and namespace authority',
  'candidate_files':['tools/generate_hia_agent_namespace_store.py (new)','examples/hia_bootstrap/agent_namespace_store.hiaasm (new)','hepta/hia_agent_namespace_store_native.py (custody/mechanical adapter only, new)'],
  'implementation_boundary':'Implement the full ten-table row/key and transaction operation inventory, covering all 31 distinct DML statements plus begin/commit/rollback, open/recovery and close. Native code must own indexes, uniqueness, transaction/replay decisions and durable commit receipts. The bridge may transport bytes and syscall results; it must not choose row matches, CAS outcomes or replay branches.',
  'reuse':'Compose already qualified HIA JSON/identity/binary64 and artifact publication pieces where appropriate; preserve the existing HIA journal owner as client of storage. Do not reimplement journal decisions in Python or make a parallel reduced store for selected demonstrations.',
  'adoption_gate':'Development selection first; exact full API and on-disk migration differential, installed no-SQLite/no-host-storage-owner controls, matching-source cold 180s/2workers, all current modules/caller gate and full retained regression. Only after these pass can old SQLite/Python persistence and migration originals be candidates for removal.'
 },
 'limitations':['No new implementation or persistent data modified.','No new runtime tests executed by this audit. Existing test assertions were read, not relabeled as new PASS.','No general all-input or crash-recovery proof claimed.','Public HIA full-stack rewrite remains incomplete.'],
 'source_before_after_exact':True
}
# Enforce computed counts rather than an independently typed estimate.
sql=c['sql_call_sites']
dml=[x for x in sql if x['sql'].lstrip().split(None,1)[0].upper() in ('SELECT','INSERT','UPDATE','DELETE')]
assert len(dml)==45 and len(set(x['sql'] for x in dml))==31
for path,pin in c['source_pins'].items():
 assert sha256((Path('/workspace/scratch/9acdfa9f5639/native-agent-state-integration')/path).read_bytes()).hexdigest()==pin['sha256'],path
out=(json.dumps(report,sort_keys=True,indent=2,ensure_ascii=False)+'\n').encode()
(OUT/'review.json').write_bytes(out)
custody={'schema':'hia.readonly-review-custody.v1','source_commit':c['source_commit'],'source_tree':c['source_tree'],'source_snapshot_sha256':c['snapshot_sha256'],'source_before_after_exact':True,'files':{}}
for name in ('census.py','make_review.py','census.json','review.json'):
 p=OUT/name;b=p.read_bytes();custody['files'][name]={'bytes':len(b),'sha256':sha256(b).hexdigest(),'mode':stat.S_IMODE(p.stat().st_mode)}
data=(json.dumps(custody,sort_keys=True,indent=2)+'\n').encode();(OUT/'custody.json').write_bytes(data)
print(json.dumps({'review_bytes':len(out),'review_sha256':sha256(out).hexdigest(),'custody_bytes':len(data),'custody_sha256':sha256(data).hexdigest(),'scope':'static only; all 26 pins rechecked'},sort_keys=True))

