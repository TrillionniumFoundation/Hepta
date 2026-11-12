"""Read-only follow36 frontier addendum; no subject import or execution."""
from pathlib import Path
from hashlib import sha256, sha1
import collections, json, lzma, stat

ROOT = Path(__file__).resolve().parent
READ = ROOT / 'readback-r1'
FILES = READ / 'files'
OUT = ROOT / 'frontier-seal-r1'
OUT.mkdir(exist_ok=False)

def identity(path):
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=sha256(raw).hexdigest(),
        gitsha=sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
        mode=stat.S_IMODE(path.stat().st_mode))

report = json.loads((READ/'report.json').read_text())
assert report['all_members_bytes_sha256_modes_verified'] is True
assert report['subject_executed'] is False and report['new_native_entries'] == 0
assert report['all_tar_members'] == 35112
semantic = FILES/'store-values-composition/development/ci-composition-store-semantic-r1'
initial = report['frontiers']['initializer']
pending = initial['pending']; last = initial['last']
assert pending['role'] == last['role'] and pending['label'] == last['label']
assert pending['entry'] == initial['counts'][pending['role']]
assert pending['advertised_work'] == last['advertised_work']
for key, other in [('source','source'),('second','second'),('workspace_before','workspace_before')]:
    assert pending[key+'_sha256'] == last[other]['sha256']
    length_key = 'workspace_bytes' if key == 'workspace_before' else key+'_bytes'
    assert pending[length_key] == last[other]['bytes']
wire = report['frontiers']['wire-methods']
for key in ('entry','label','role','s','r','w'):
    assert wire['pending'][key] == wire['last'][key]
assert initial['trailing_incomplete_bytes'] == wire['trailing_incomplete_bytes'] == 0

logical = collections.defaultdict(lambda: dict(entries=0,before_bytes=0,after_bytes=0,large_workspace_entries=0))
wire_ledger = semantic/'native-wire-methods/entries.jsonl'
for line in wire_ledger.read_text().splitlines():
    row = json.loads(line); target = logical[row['role']]
    target['entries'] += 1
    target['before_bytes'] += sum(row[k]['bytes'] for k in ('s','r','w'))
    target['after_bytes'] += sum(row[k]['bytes'] for k in ('after_r','after_w'))
    target['large_workspace_entries'] += row['w']['bytes'] >= 8388608

groups = []
for group in ('effects','catalog','growth'):
    path = semantic.parent/f'ci-composition-store-{group}-r1/summary.json'
    row = json.loads(path.read_text())
    assert row['status'] == 'PASS' and row['source_unchanged'] is True
    groups.append(dict(group=group,cases=row['cases'],entries=row['total_actual_entries'],
        elapsed_ns=row['elapsed_ns'],original=identity(path)))
assert sum(r['cases'] for r in groups) == 16
assert sum(r['entries'] for r in groups) == 14298

details = dict(schema='hia-worker-initializer-follow36-frontier-readback-v1',
    status='PASS_READONLY_ORIGINAL_CPU_FAILURE_UNCHANGED',
    run=43168832983,job=131016969239,head='23c0d3a3e8ea11d2c6fa1286623b2cfeba1d359f',
    original_artifact=13922316358,original_process=report['semantic_process'],
    original_semantic_stdout=report['semantic_stdout'],
    completed_groups=groups,completed_semantic_case_labels=[x['label'] for x in report['completed_semantic_cases']],
    incomplete_semantic_case='example-assembly-mismatch',
    later_semantic_cases_unrun=['profile-observer-failure-after-native-sql','json-observer-failure-after-native-method'],
    complete_entry_counts={k:{'total':v['complete_records'],'roles':v['counts']} for k,v in report['frontiers'].items()},
    pending_equals_last_completed_all_recorded_fields=True,
    pending_files_do_not_prove_inflight_native_entry=True,
    wire_logical_snapshot_bytes_by_role=dict(logical),
    wire_logical_snapshot_bytes_total=sum(x['before_bytes']+x['after_bytes'] for x in logical.values()),
    logical_bytes_are_measurement_inputs_not_cpu_attribution=True,
    original_full_readback=identity(READ/'report.json'),original_zip=identity(ROOT/'artifact13922316358.zip'),
    subject_imported=False,new_vm_entries=0,new_native_entries=0,
    ordinary_store_closed=False,ordinary_worker_closed=False,
    remaining_namespace_receipts_are_foreign=True,
    note='All 35112 inner members were independently streamed and checked by read_original_r1.py. This addendum binds pending files to completed ledger records. It does not rerun or reinterpret the CPU-90 failure as PASS.')
(OUT/'frontier-analysis.json').write_text(json.dumps(details,sort_keys=True,indent=2)+'\n')
raw=(READ/'report.json').read_bytes()
compressed=lzma.compress(raw,preset=6)
assert lzma.decompress(compressed)==raw
(OUT/'full-readback-report.json.xz').write_bytes(compressed)
index=[identity(p) for p in (ROOT/'read_original_r1.py',Path(__file__),OUT/'frontier-analysis.json',OUT/'full-readback-report.json.xz')]
(OUT/'index.json').write_text(json.dumps(index,sort_keys=True,indent=2)+'\n')
print(json.dumps(dict(status='PASS',files=index,logical_bytes=details['wire_logical_snapshot_bytes_total']),sort_keys=True))
