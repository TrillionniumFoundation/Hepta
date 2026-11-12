"""Byte and AST-only inverse review; imports no project or frozen controller."""
import ast
from hashlib import sha256, sha1
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OLD = ROOT.with_name('hia-wire89-timeout-diagnostic-local312-r1')
CHANGED = ('timed', 'forbid_owner', 'forbid_encoder', 'encode', 'step', 'session_init',
           'batch', 'popen_init', 'communicate', 'evaluate', 'store_json')


def pin(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha1': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def main_node(source):
    return next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'main')


def indexed(source):
    main = main_node(source)
    nodes = {n.name: n for n in ast.walk(main) if isinstance(n, ast.FunctionDef) and n.name in CHANGED}
    result = next(n for n in main.body if isinstance(n, ast.ClassDef) and n.name == 'Result')
    nodes['Result.startTest'] = next(n for n in result.body if isinstance(n, ast.FunctionDef) and n.name == 'startTest')
    nodes['post-test-process-observation'] = next(n for n in main.body if isinstance(n, ast.For)
        and isinstance(n.target, ast.Tuple) and [x.id for x in n.target.elts] == ['proc', 'row'])
    return nodes


old = (OLD / 'control/worker.py').read_text()
new = (ROOT / 'control/worker.py').read_text()
assert sha256(old.encode()).hexdigest() == 'e30965e9b686b8359bbf1cc3fa7e35e29d256ef175e75d3cb845fde4793f2872'
before, after = indexed(old), indexed(new)
assert set(before) == set(after) == set(CHANGED) | {'Result.startTest', 'post-test-process-observation'}
lines = new.splitlines(keepends=True)
old_lines = old.splitlines(keepends=True)
for name, node in sorted(after.items(), key=lambda x: x[1].lineno, reverse=True):
    original = before[name]
    lines[node.lineno-1:node.end_lineno] = old_lines[original.lineno-1:original.end_lineno]
assert ''.join(lines) == old
assert (ROOT / 'control/launch.py').read_bytes() == (OLD / 'control/launch.py').read_bytes()
assert (ROOT / 'freeze_request.py').read_bytes() == (OLD / 'freeze_request.py').read_bytes()
old_request = json.loads((OLD / 'REQUEST.json').read_bytes())
new_request = json.loads((ROOT / 'REQUEST.json').read_bytes())
protected = set(old_request) - {'input_pins', 'command', 'output_root'}
assert set(new_request) == set(old_request)
assert all(old_request[k] == new_request[k] for k in protected)
old_pins = {p['path']: p for p in old_request['input_pins'] if p['role'] != 'new-unexecuted-diagnostic-control'}
new_pins = {p['path']: p for p in new_request['input_pins'] if p['role'] != 'new-unexecuted-diagnostic-control'}
assert old_pins == new_pins and len(old_pins) == 864
for name in ('ORIGINAL-89-IDS.json', 'original-test-method.txt', 'original-workload-function.txt',
             'reference/ORIGINAL-FAILURE-AUDIT.json', 'reference/ORIGINAL-FULL89-REPORT.json'):
    assert (ROOT / name).read_bytes() == (OLD / name).read_bytes()
source_request = json.loads((ROOT / 'RECORDING-CONTROLS-REQUEST.json').read_bytes())
assert source_request['expected_tests'] == 5 and source_request['qualification_seconds'] == 20
assert source_request['cleanup_seconds'] == 3 and len(source_request['expected_ids']) == 5
result = {'schema': 'hepta.wire89.recorder-r2-static-inverse.v1', 'status': 'AST_AND_BYTES_ONLY_PASS',
          'whole_worker_inverse_exact': True, 'changed_definition_or_block_names': list(after),
          'launcher_and_freezer_byte_identical': True, 'protected_request_fields_equal': sorted(protected),
          'unchanged_complete_input_pins': 864, 'input_pins_total': 866,
          'original_method_5_seconds_256_cases_and_89_ids_byte_identical': True,
          'diagnostic_owner_seconds': 180, 'diagnostic_cleanup_seconds': 3,
          'synthetic_methods': 5, 'synthetic_owner_seconds': 20, 'synthetic_cleanup_seconds': 3,
          'worker': pin(ROOT / 'control/worker.py'), 'request': pin(ROOT / 'REQUEST.json'),
          'recording_controls': pin(ROOT / 'control/check_recording_controls.py'),
          'source_control_execution': False, 'project_import_or_native_execution': False}
with (ROOT / 'R2-STATIC-INVERSE.json').open('x') as stream:
    stream.write(json.dumps(result, sort_keys=True, indent=2) + '\n')
print(json.dumps(result))
