"""Restore original log-embedded bytes without executing any target."""
from pathlib import Path
from hashlib import sha256, sha1
import base64, json, re

BASE = Path('/workspace/scratch/9acdfa9f5639/native-checker-development/physical56-originals')
OUT = BASE / 'log-originals-r3'
OUT.mkdir(exist_ok=False)

def identity(data):
    return dict(bytes=len(data), sha256=sha256(data).hexdigest(),
                gitsha=sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest())

def save(name, value):
    (OUT / name).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')

raw = (BASE / 'original-job.log').read_bytes()
assert identity(raw) == dict(bytes=1562835, sha256='178bff15daf25896b80898dd19866bd30ca68ced0075066b1298ed3ce80b686e', gitsha='00f03c62dcac33ab2774763f0e16d93fd7064805')
rows, selected, decoded = [], [], {}
seal_receipt = seal_process = None
for line in raw.decode('utf-8').splitlines():
    if 'HIA_PHYSICAL_ORIGINAL ' in line:
        row = json.loads(line.split('HIA_PHYSICAL_ORIGINAL ', 1)[1])
        data = base64.b64decode(row['base64'], validate=True)
        assert identity(data) == {k: row[k] for k in ('bytes', 'sha256', 'gitsha')}
        assert row['label'] not in decoded
        decoded[row['label']] = data
        name = f'{len(rows):03d}-' + row['label'].replace(':', '--').replace('/', '_')
        (OUT / name).write_bytes(data)
        item = {k: v for k, v in row.items() if k != 'base64'}
        item['saved_name'] = name
        rows.append(item)
        if row['label'].endswith(':summary.json'):
            selected.append(dict(item, raw_utf8=data.decode('utf-8')))
    elif 'HIA_EVIDENCE_SEAL_PROCESS ' in line:
        assert seal_process is None
        seal_process = line.split('HIA_EVIDENCE_SEAL_PROCESS ', 1)[1].encode()
    elif '"scope": "backend-physical-after-r1"' in line and '"hia-independent-ci-streamed-artifact-custody-v1"' in line:
        assert seal_receipt is None
        seal_receipt = line[line.index('{'):].encode()
assert len(rows) == 318 and sum(r['bytes'] for r in rows) == 519779
assert len(selected) == 65 and seal_receipt is not None and seal_process is not None
(OUT / 'seal-custody.original.json').write_bytes(seal_receipt)
(OUT / 'seal-process.original.json').write_bytes(seal_process)
save('original-index.json', rows)
with (OUT / 'all-originals.ndjson').open('w', encoding='utf-8') as f:
    for row in rows:
        f.write(json.dumps(dict(row, raw_utf8=decoded[row['label']].decode('utf-8')), ensure_ascii=True, sort_keys=True) + '\n')
with (OUT / 'all-summaries.ndjson').open('w', encoding='utf-8') as f:
    for row in selected:
        f.write(json.dumps(row, ensure_ascii=True, sort_keys=True) + '\n')

compiler = '35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b'
builds, groups, readbacks, process_rows, cbuilds = [], [], [], [], []
for row in selected:
    obj = json.loads(row['raw_utf8'])
    label = row['label'].removesuffix(':summary.json')
    assert obj['status'] in ('PASS', 'PASS_BUILD_ONLY'), label
    assert obj.get('source_pins_unchanged', True), label
    match = re.fullmatch(r'physical-(?:retained|new)-(\d+)-(.+)', label)
    if match:
        role = int(match.group(1))
        assert obj['compilations'] == 1
        if 'components' in obj:
            assert len(obj['components']) == 1
            manifest = next(iter(obj['components'].values()))
        else:
            manifest = obj['manifest']
        receipt = manifest['compile_receipt']
        # Roles 12..16 reuse the original five-role checked-plan compile manifests.
        # Preserve those original local role numbers and bind their new table slots separately.
        local_role = role - 11 if 12 <= role <= 16 else role
        assert manifest.get('role', local_role) == local_role
        assert receipt['status'] == 'returned' and receipt['source_unchanged']
        assert manifest['compiler_sha256'] == receipt['artifact_sha256'] == compiler
        assert manifest['source_sha256'] == receipt['source_sha256'] == receipt['input_sha256']
        assert manifest['source_bytes'] == receipt['input_bytes']
        assert manifest['image_sha256'] == receipt['produced_sha256']
        assert manifest['image_bytes'] == receipt['produced_bytes']
        assert receipt['limits']['cpu_seconds'] == 10 and receipt['limits']['address_bytes'] == 256 << 20
        assert receipt['wall_elapsed_ns'] < 20_000_000_000
        builds.append(dict(role=role, label=label, original={k: row[k] for k in ('bytes', 'sha256', 'gitsha', 'path', 'saved_name')}, manifest=manifest))
    elif label.startswith('physical-native-'):
        assert obj['cases'] == obj['expected_cases'] and obj['private_controls'] == obj['expected_private_controls']
        assert obj['native_entries'] == obj['completed_case_entries'] == sum(obj['by_role'].values())
        assert obj['before_native_entries'] == sum(obj['before_by_role'].values())
        assert obj['failures'] == [] and obj['old_results_inherited'] is False
        groups.append(dict(label=label, summary=obj, original={k: row[k] for k in ('bytes', 'sha256', 'gitsha', 'path', 'saved_name')}))
    elif label.startswith('physical-readback-'):
        assert obj['native_entries_executed'] == obj['VM_entries_executed'] == obj['product_imports'] == 0
        assert obj['all_full_recorded_bytes_read'] and obj['complete_raw_target_trace_and_ACK_comparison']
        assert obj['source_custody']['all_source_before_after_and_snapshots_exact']
        readbacks.append(dict(label=label, summary=obj, original={k: row[k] for k in ('bytes', 'sha256', 'gitsha', 'path', 'saved_name')}))
    elif label.startswith('physical-C-'):
        cbuilds.append(dict(label=label, summary=obj, original={k: row[k] for k in ('bytes', 'sha256', 'gitsha', 'path', 'saved_name')}))
    if label.startswith(('physical-native-', 'physical-readback-')):
        for phase in ('pre_output_budget', 'post_output_budget', 'post_persist_budget'):
            assert obj[phase]['cpu_seconds'] < 90 and obj[phase]['wall_seconds'] < 180
        proc = json.loads(decoded[label + ':process.json'])
        assert proc['status'] == 'PASS' and proc['returncode'] == 0 and not proc['timed_out']
        assert proc['child_cpu_seconds'] < 90 and proc['elapsed_ns'] < 180_000_000_000 and proc['timeout_seconds'] == 180
        assert proc['label'] == label
        process_rows.append(proc)
builds.sort(key=lambda x:x['role'])
assert [x['role'] for x in builds] == list(range(1,24))
assert len(groups) == len(readbacks) == 20 and len(cbuilds) == 2
for g, rb in zip(groups, readbacks):
    a, b = g['summary'], rb['summary']
    assert g['label'].replace('physical-native-', '') == rb['label'].replace('physical-readback-', '')
    for field in ('cases', 'private_controls', 'native_entries', 'by_role', 'before_native_entries', 'before_by_role', 'before_raw_syscalls', 'actual_after_raw_syscalls'):
        assert a[field] == b[field], (g['label'], field)
    assert a['complete_fixed_carrier_crosschecks'] == b['fixed_C_crosschecks']
    assert a['complete_full_CAS_cases'] == b['full_CAS_cases']
save('expected-23-builds.json', builds)
save('exact-group-summary-index.json', groups)
save('exact-readback-summary-index.json', readbacks)
save('exact-process-summary-index.json', process_rows)
seal = json.loads(seal_receipt); proc = json.loads(seal_process)
assert seal['status'] == proc['status'] == proc['subject_status'] == 'PASS'
assert proc['exit_code'] == 0 and not proc['timed_out'] and proc['cleanup_errors'] == []
assert proc['whole_seal_parent_child_CPU_seconds'] < 90 and proc['elapsed_wall_seconds'] < 180
assert proc['limits'] == dict(address=[1<<30,1<<30],core=[0,0],cpu=[90,90],wall=180)
assert seal['members'] == 161887 and seal['original_bytes'] == 1119637158
totals = {field: sum(g['summary'][field] for g in groups) for field in ('cases','private_controls','native_entries','before_native_entries','actual_backend_processes_started','actual_before_processes_started','before_raw_syscalls','actual_after_raw_syscalls','complete_fixed_carrier_crosschecks','complete_full_CAS_cases')}
totals['ordinary_cases'] = totals['cases'] - totals['private_controls']
totals['readback_encoded_original_files'] = sum(r['summary']['encoded_original_files'] for r in readbacks)
totals.update(status='PASS', fresh_B3_compilations=len(builds), C_builds=len(cbuilds), groups=len(groups), independent_readback_groups=len(readbacks),
    source_run=43276498118, source_job=131386199051, source_head='d438a5bf52d2ecddf53850e7f2f0fd0a433d2676', artifact=13971147766,
    derivation='Exact original log bytes and 318 separately hash-checked embedded originals; no target execution.',
    whole_ZIP_readback='PENDING', native_public_Core_admission=False, second_compile_emission=False, publication=False, installed=False, whole_public_build=False,
    old_local_results_inherited=False, bounded_seal=proc,
    max_native_process_CPU=max(p['child_cpu_seconds'] for p in process_rows if p['label'].startswith('physical-native-')),
    max_native_process_wall=max(p['elapsed_ns']/1e9 for p in process_rows if p['label'].startswith('physical-native-')),
    max_readback_process_CPU=max(p['child_cpu_seconds'] for p in process_rows if p['label'].startswith('physical-readback-')),
    max_readback_process_wall=max(p['elapsed_ns']/1e9 for p in process_rows if p['label'].startswith('physical-readback-')))
save('derived-observation.json', totals)
save('artifact-metadata.json', dict(source_run=43276498118, source_job=131386199051, artifact=13971147766,
    ZIP_bytes=349266299,ZIP_sha256='1a87d8a956cfd165a0e3751064615cc23cd2a23cee09e5d056d582098e6d1229',ZIP_member_count=1348,
    archive_bytes=199377588,archive_sha256='4a91beb491c2ae15c50fbace1467954ef6869fe277e04e255686cd15bd5ff13d',
    ledger_bytes=85270025,ledger_sha256='f28fc1fea0bcf8cc33f67d6595708c8f824a4f0d60e7cd5f79c4fd96c80871e2',
    tar_members=161887,original_bytes=1119637158,whole_ZIP_independent_readback='PENDING'))
print(json.dumps(totals,sort_keys=True))
