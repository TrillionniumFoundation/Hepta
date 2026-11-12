"""Read the already completed r4c originals; never execute product code."""
import hashlib
import json
import os
from pathlib import Path
import stat

BASE = Path('/tmp/hia-cli-json-source-r4c-request-r1-20261112-e26e')
ROOT = Path('/workspace/scratch/e26ed3e2edcf/root/cli-r4c-source-actual-r1')
records = {}
joins = 0


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def read(path):
    global joins
    path = Path(path)
    for parent in path.parents:
        assert stat.S_ISDIR(parent.lstat().st_mode), str(parent)
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1, str(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        assert identity(os.fstat(fd)) == identity(before)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read()
        assert identity(os.fstat(fd)) == identity(before) == identity(path.lstat())
    finally:
        os.close(fd)
    assert len(raw) == before.st_size
    row = {'path': str(path), 'bytes': len(raw), 'identity': identity(before),
           'sha256': hashlib.sha256(raw).hexdigest(),
           'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
    if str(path) in records:
        assert records[str(path)] == row
    records[str(path)] = row
    joins += 1
    return row, raw


def obj(path):
    return json.loads(read(path)[1])


def binding(expected, path=None):
    global joins
    row, raw = read(path or expected['path'])
    for key in ('bytes', 'sha256', 'git_blob', 'identity'):
        if key in expected:
            assert row[key] == expected[key], (str(path or expected['path']), key)
            joins += 1
    return raw


def all_bindings(value):
    if isinstance(value, dict):
        if all(k in value for k in ('path', 'bytes', 'sha256')) and value['path'].startswith('/'):
            binding(value)
        for item in value.values():
            all_bindings(item)
    elif isinstance(value, list):
        for item in value:
            all_bindings(item)


pre = obj(ROOT / 'PRETRIGGER.json')
returned = obj(ROOT / 'INVOCATION-RETURN.json')
request = obj(BASE / 'guardian/REQUEST.json')
config = obj(BASE / 'control/CONFIG.json')
guardian = obj(BASE / 'guardian/guardian.json')
report = obj(BASE / 'actual/REPORT.json')
assert returned['returncode'] == 0
all_bindings(returned)
all_bindings(pre)
all_bindings(report)
assert pre['canonical_commit'] == '4787038c3a013357309c22929b268055dc91090c'
assert pre['canonical_tree'] == 'cfc66ec1d1ecd57dca61b42c1e5818cb1c40e4bc'
assert guardian['status'] == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
assert guardian['command'] == request['command'] and guardian['cwd'] == request['cwd']
assert guardian['input_identity_preserved'] is True
assert guardian['source_identities_before'] == guardian['source_identities_after'] == request['source_identities']
assert len(request['source_identities']) == 184
for path, sha in request['source_identities'].items():
    assert read(path)[0]['sha256'] == sha
assert guardian['lifecycle_implementation_sha256'] == '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
life = guardian['lifecycle']
assert life['status'] == 'OWNED_PROCESS_COMPLETED' and life['returncode'] == 0
assert life['qualification_seconds'] == 180 and life['cleanup_seconds'] == 3
assert life['timed_out'] is False and life['exit_observed_before_deadline'] is True
assert life['subreaper_enabled'] is True and life['event_overflow'] is False
assert life['interrupted_signals'] == []
assert [e['kind'] for e in life['events']] == ['qualification_started', 'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped']
assert life['events'][2]['si_status'] == 0 and life['events'][2]['si_code'] == 1
cleanup = life['cleanup']
assert cleanup['complete'] and cleanup['observed_echild'] and cleanup['leader_reaped']
assert cleanup['remaining_direct_children'] == cleanup['errors'] == []
assert cleanup['deadline_exceeded'] is False
for path, sha in guardian['logs'].items():
    assert read(path)[0]['sha256'] == sha
assert report['status'] == 'TWO_HIA_AND_THREE_CODE_PACKETS_PASS_PENDING_OUTER_GUARDIAN'
assert report['errors'] == [] and report['native_executed'] is False
assert report['product_callers_executed'] is False and report['counts_are_plan_only'] is True
assert report['original_cli_ids'] == config['original_cli_ids'] and len(report['original_cli_ids']) == 17
assert report['trace_plan_ids'] == config['trace_plan_ids'] and len(report['trace_plan_ids']) == 46
before = obj(BASE / 'actual/source.before.json')
after = obj(BASE / 'actual/source.after.json')
assert before == after and len(before) == 177
assert set(before) == set(config['source_pins'])
assert sorted(p.relative_to(BASE / 'source').as_posix() for p in (BASE / 'source').rglob('*') if p.is_file()) == sorted(before)
for name, row in before.items():
    binding(row)
    binding(config['source_pins'][name], BASE / 'source' / name)
assert sum(row['bytes'] for row in before.values()) == 2750177
assert [[row['name'], row['module']] for row in report['components']] == config['components']
cap_results = []
for component in report['components']:
    name = component['name']
    assert component['status'] == 'SOURCE_CORE_AND_CAPS_PASS_NOT_NATIVE' and component['error'] is None
    document_raw = binding(component['document'])
    assert document_raw == binding(component['verified_document'])
    document = json.loads(document_raw)
    assembly = binding(component['assembly'])
    caps = json.loads(binding(component['caps']))
    assert caps['limits'] == config['limits'] and caps['within_limits'] is True
    assert caps['compiler_line_gate_executed'] is False
    assert caps['source_lines_diagnostic'] == len(assembly.splitlines())
    fn_rows = []
    for function in document['functions']:
        names = {param['name'] for param in function['params']}
        parameters = len(function['params'])
        arguments = results = operations = 0
        for block in function['blocks']:
            parameters = max(parameters, len(block['params']))
            names.update(param['name'] for param in block['params'])
            for operation in block['ops']:
                operations += 1
                arguments = max(arguments, len(operation['args']))
                results = max(results, len(operation['out']))
                names.update(result['name'] for result in operation['out'])
            term = block['term']
            if term['op'] == 'branch':
                edges = [term['then']['args'], term['else']['args']]
            elif term['op'] == 'jump':
                edges = [term['args']]
            elif term['op'] == 'ret':
                edges = [term['values']]
            else:
                edges = []
            arguments = max([arguments] + [len(edge) for edge in edges])
        fn_rows.append({'name': function['name'], 'blocks': len(function['blocks']),
                        'operations': operations, 'ssa_names': len(names),
                        'parameters': parameters, 'arguments': arguments,
                        'instruction_results': results, 'function_results': len(function['returns'])})
    assert fn_rows == caps['functions']
    measured = {'source_bytes': len(assembly), 'functions': len(fn_rows),
                'blocks_per_function': max(r['blocks'] for r in fn_rows),
                'blocks_total': sum(r['blocks'] for r in fn_rows),
                'parameters_or_arguments': max(max(r['parameters'], r['arguments']) for r in fn_rows),
                'ssa_names_per_function': max(r['ssa_names'] for r in fn_rows),
                'instruction_results': max(r['instruction_results'] for r in fn_rows),
                'function_results': max(r['function_results'] for r in fn_rows),
                'instructions': sum(r['operations'] for r in fn_rows)}
    assert measured == caps['actual'] and all(value <= config['limits'][key] for key, value in measured.items())
    cap_results.append({'name': name, 'actual': measured, 'caps': records[component['caps']['path']]})
packets = obj(BASE / 'actual/packets/REPORT.json')
assert packets['status'] == report['packet_authoring']['status'] == 'THREE_SOURCE_PACKETS_AUTHORED'
assert packets['errors'] == []
assert packets['exact_names'] == config['packet_names'] == [row['name'] for row in packets['code_objects']]
assert len(packets['outputs']) == 6
assert packets['source'] == config['source_pins'][config['encoder_source']]
assert packets['generator_bodies_executed'] is False and packets['runtime_code_objects_admitted'] is False
assert packets['native_executed'] is False and packets['json_values_encoded'] == 0
assert [row for code in packets['code_objects'] for row in code['outputs']] == packets['outputs']
for code in packets['code_objects']:
    assert code['status'] == 'SOURCE_PACKET_AUTHORED_NOT_RUNTIME_ADMITTED' and code['error'] is None
for row in packets['outputs']:
    raw = binding(row, BASE / 'actual/packets' / row['path'])
    if row['path'].endswith('.json'):
        packet = json.loads(raw)
        assert packet['runtime_code_object_admitted'] is False
for folder in ('actual', 'guardian'):
    for path in sorted((BASE / folder).rglob('*')):
        if path.is_file():
            read(path)
result = {'schema': 'hia.root.cli-r4c.actual-readback.v1',
          'status': 'TWO_HIA_SOURCE_AND_THREE_METADATA_PACKETS_PASS',
          'canonical_request_commit': pre['canonical_commit'], 'canonical_request_tree': pre['canonical_tree'],
          'request': records[str(BASE / 'guardian/REQUEST.json')],
          'report': records[str(BASE / 'actual/REPORT.json')],
          'guardian': records[str(BASE / 'guardian/guardian.json')],
          'source_count': 177, 'source_bytes': 2750177, 'all_bound_inputs': 184,
          'source_identity_preserved': True, 'input_identity_preserved': True,
          'components': cap_results, 'packet_names': config['packet_names'],
          'native_executed': False, 'c_compilation_executed': False,
          'original_cli_17_executed': False, 'trace_plan_46_executed': False,
          'whole_rewrite_closed': False, 'lifecycle': life,
          'worker_elapsed_seconds': report['elapsed_ns'] / 1e9,
          'owned_elapsed_seconds': (life['events'][2]['monotonic_ns'] - life['events'][0]['monotonic_ns']) / 1e9,
          'full_read_joins': joins, 'unique_files': len(records),
          'files': sorted(records.values(), key=lambda row: row['path'])}
raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
with (ROOT / 'READBACK.json').open('xb') as stream:
    stream.write(raw)
    stream.flush()
    os.fsync(stream.fileno())
print(json.dumps({key: value for key, value in result.items() if key not in ('files', 'lifecycle')}, sort_keys=True))
