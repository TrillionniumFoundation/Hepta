"""Independent read-only byte and denominator audit of one actual source4 run."""
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import zipfile

BASE = Path('/workspace/scratch/e26ed3e2edcf/native-cli-json-source4-actual-43264350911-r1')
OUT = Path('/workspace/scratch/e26ed3e2edcf/root/cli-source4-actual-audit-r1')
OUT.mkdir(mode=0o700, exist_ok=False)
raw_zip = (BASE / 'ARTIFACT.original.zip').read_bytes()
assert len(raw_zip) == 1498067
assert hashlib.sha256(raw_zip).hexdigest() == '73971a4a092757767c037d65c9e7646c4e9d8efb52c7c647efc1d0c00b970731'
with zipfile.ZipFile(io.BytesIO(raw_zip)) as archive:
    names = archive.namelist()
    assert len(names) == len(set(names)) == 18
    outer = {name: archive.read(name) for name in names}
final = json.loads(outer['FINAL.json'])
custody = json.loads(outer['CUSTODY.json'])
setup = json.loads(outer['SETUP.original.json'])
assert final['status'] == 'REMOTE_FOUR_SOURCE_COMPONENTS_PASS_NOT_NATIVE'
assert final['owned_children_closed'] is True and final['errors'] == []
assert custody['status'] == 'CLOSED_AVAILABLE_ORIGINAL_BYTES_RETAINED'
assert custody['errors'] == [] and custody['typed_without_bytes'] == {}
assert len(custody['namespace']) == 205 and len(custody['captured']) == 197
assert sorted(custody['missing']) == ['actual/cgraph.error.txt', 'actual/error.txt', 'actual/note.error.txt', 'actual/sort.error.txt', 'actual/text.error.txt']
tar_raw = outer['originals.tar']
assert len(tar_raw) == custody['archive']['bytes'] == 12052480
assert hashlib.sha256(tar_raw).hexdigest() == custody['archive']['sha256'] == 'bd1e0ced318ac7ad75f7faf135eb4ad80e5edaaa1a652fcae8227555b57a4985'
with tarfile.open(fileobj=io.BytesIO(tar_raw), mode='r:') as archive:
    members = archive.getmembers()
    assert [member.name for member in members] == ['owned/' + name for name in sorted(custody['captured'])]
    originals = {}
    for member in members:
        assert member.isfile()
        name = member.name.removeprefix('owned/')
        pin = custody['captured'][name]
        body = archive.extractfile(member).read()
        assert len(body) == member.size == pin['bytes']
        assert hashlib.sha256(body).hexdigest() == pin['sha256']
        assert hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest() == pin['git_blob']
        assert custody['namespace'][name]['kind'] == 'regular'
        assert custody['namespace'][name]['identity'] == pin['identity']
        originals[name] = body
assert sum(map(len, originals.values())) == custody['raw_bytes'] == 11896687
load = lambda name: json.loads(originals[name])
policy = load('authority/POLICY.json')
assert hashlib.sha256(originals['authority/POLICY.json']).hexdigest() == '8e66871a71e0ecdb8cca704133d96ec604156aa17d94b5c81f204be3d06950a6'
assert hashlib.sha256(originals['authority/controller.py']).hexdigest() == 'b2a17727804f9ae80f5a8757363a11e33c485fa2a1fd32f48546ac01cc727241'
assert originals['SETUP.json'] == outer['SETUP.original.json']
assert originals['RUN.json'] == outer['RUN.original.json']
before, after = load('actual/source.before.json'), load('actual/source.after.json')
assert before == after and len(before) == len(policy['source_pins']) == 160
assert set(before) == set(policy['source_pins']) == set(setup['source'])
for name, pin in policy['source_pins'].items():
    body = originals['source/' + name]
    assert len(body) == pin['bytes'] and hashlib.sha256(body).hexdigest() == pin['sha256']
    assert hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest() == pin['git_blob']
    assert before[name] == {key: setup['source'][name][key] for key in ('path', 'bytes', 'sha256', 'identity')}
assert sum(len(originals['source/' + name]) for name in before) == 2498584
guard, request, run = load('guardian/guardian.json'), load('guardian/REQUEST.json'), load('RUN.json')
assert guard['status'] == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
assert guard['source_identities_before'] == guard['source_identities_after'] == request['source_identities']
assert guard['command'] == request['command'] and guard['cwd'] == request['cwd']
assert guard['external_controller_seconds'] == request['controller_seconds'] == 180
assert guard['lifecycle_implementation_sha256'] == '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
assert run['returned'] is True and run['returncode'] == 0 and run['errors'] == []
life = guard['lifecycle']
assert life['status'] == 'OWNED_PROCESS_COMPLETED' and life['returncode'] == 0 and life['timed_out'] is False
assert life['qualification_seconds'] == 180 and life['cleanup_seconds'] == 3
assert [event['kind'] for event in life['events']] == ['qualification_started', 'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped']
assert life['cleanup']['complete'] is True and life['cleanup']['observed_echild'] is True
assert life['cleanup']['remaining_direct_children'] == [] and life['cleanup']['errors'] == []
report = load('actual/REPORT.json')
assert report['status'] == 'FOUR_SOURCE_COMPONENTS_PASS_PENDING_OUTER_GUARDIAN' and report['errors'] == []
assert [[r['name'], r['module']] for r in report['components']] == policy['components']
assert report['original_cli_ids'] == policy['original_cli_ids'] and len(report['original_cli_ids']) == 17
assert report['trace_plan_ids'] == policy['trace_plan_ids'] and len(report['trace_plan_ids']) == 46
metrics = []
for component in report['components']:
    name = component['name']
    document = load('actual/' + name + '.verified.json')
    caps = load('actual/' + name + '.caps.json')
    functions = []
    for f in document['functions']:
        ssa = {p['name'] for p in f['params']}
        parameters = len(f['params'])
        args = results = ops = 0
        for block in f['blocks']:
            parameters = max(parameters, len(block['params']))
            ssa.update(p['name'] for p in block['params'])
            for op in block['ops']:
                ops += 1; ssa.update(p['name'] for p in op['out'])
                args = max(args, len(op['args'])); results = max(results, len(op['out']))
            term = block['term']
            if term['op'] == 'jump': args = max(args, len(term['args']))
            elif term['op'] == 'branch': args = max(args, len(term['then']['args']), len(term['else']['args']))
            elif term['op'] == 'ret': args = max(args, len(term['values']))
        functions.append((len(f['blocks']), ops, len(ssa), parameters, args, results, len(f['returns'])))
    measured = {'source_bytes': len(originals['actual/' + name + '.hiaasm']), 'functions': len(functions), 'blocks_per_function': max(x[0] for x in functions), 'blocks_total': sum(x[0] for x in functions), 'instructions': sum(x[1] for x in functions), 'ssa_names_per_function': max(x[2] for x in functions), 'parameters_or_arguments': max(max(x[3], x[4]) for x in functions), 'instruction_results': max(x[5] for x in functions), 'function_results': max(x[6] for x in functions)}
    assert measured == caps['actual'] and caps['limits'] == policy['limits']
    assert caps['within_limits'] is True and all(measured[k] <= policy['limits'][k] for k in measured)
    assert component['status'] == 'SOURCE_CORE_AND_CAPS_PASS_NOT_NATIVE' and component['error'] is None
    metrics.append({'name': name, **measured, 'seconds': component['elapsed_ns'] / 1e9})
out = {'schema': 'root.cli-source4.actual-byte-audit.v1', 'status': 'PASS_FOUR_SOURCE_COMPONENTS_ONLY', 'run_id': 43264350911, 'job_id': 131343797743, 'artifact_id': 13964912684, 'artifact_bytes': len(raw_zip), 'artifact_sha256': hashlib.sha256(raw_zip).hexdigest(), 'all_outer_entries_read': 18, 'typed_namespace': 205, 'complete_tar_regular_originals': 197, 'raw_original_bytes': 11896687, 'source_files_unchanged': 160, 'source_bytes': 2498584, 'metrics': metrics, 'worker_seconds': report['elapsed_ns'] / 1e9, 'owner_seconds': (life['events'][2]['monotonic_ns'] - life['events'][0]['monotonic_ns']) / 1e9, 'qualification_seconds': 180, 'cleanup_seconds': 3, 'closed_ECHILD': True, 'original_cli_methods_executed': 0, 'trace_cases_executed': 0, 'native_executed': False, 'compiler_line_gate_measured': False}
raw = (json.dumps(out, indent=2, sort_keys=True) + '\n').encode()
with (OUT / 'AUDIT.json').open('xb') as stream:
    stream.write(raw); stream.flush(); os.fsync(stream.fileno())
for name in ('FINAL.json', 'CUSTODY.json', 'SETUP.original.json', 'RUN.original.json', 'SMALL.json', 'FRAMING.json'):
    with (OUT / name).open('xb') as stream:
        stream.write(outer[name]); stream.flush(); os.fsync(stream.fileno())
print(json.dumps(out, sort_keys=True))
