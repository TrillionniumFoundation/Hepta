from __future__ import annotations
import ast
from hashlib import sha1, sha256
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import zlib

ROOT = Path('/tmp/hepta-evaluation-capture-recovery-589c')
BASE = '06d21f6032d7b3a946b1d6581a13c5cfd5fa4375'
BUILD = Path('/tmp/runtime-evaluation-capture-native-build-589c')
V1 = Path('/tmp/runtime-evaluation-capture-controls-v1-589c')
V2 = Path('/tmp/runtime-evaluation-capture-caller-controls-v2-589c')
REVIEW = Path('/tmp/hepta-evaluation-capture-review-589c')
DEST = ROOT / 'docs/qualification/hia-evaluation-capture-recovery-20261127-589c'
sys.path.insert(0, str(ROOT))
from tools.read_hia_cold_native_transport import decode_original_process_streams
from tools.hia_selfhost_native_observer import frame
from tests.hia_evaluation_capture_successor import original_reference

def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}

def blob(raw):
    return sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])

def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

def copy(source, relative):
    target = DEST / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    raw = source.read_bytes()
    target.write_bytes(raw)
    assert target.read_bytes() == raw

assert git('rev-parse', 'HEAD').decode().strip() == BASE
paths = git('diff', '--cached', '--name-only').decode().splitlines()
assert set(paths) == {'hepta/hia_agent_service.py', 'hepta/hia_evaluation_native.py',
    'tests/test_hia_evaluation_native.py', 'tests/hia_evaluation_capture_successor.py',
    'tests/test_hia_evaluation_capture.py'}
assert not git('diff', '--name-only')
v1, v2 = (json.loads((d / 'receipt.json').read_bytes()) for d in (V1, V2))
assert v1['tests'] == 13 and not v1['errors'] and not v1['skips'] and len(v1['failures']) == 1
assert v2['tests'] == 4 and not any(v2[key] for key in ('errors', 'failures', 'skips'))
assert v1['source_unchanged'] and v2['source_unchanged']
for path, expected in v2['sources_after'].items():
    assert pin((ROOT / path).read_bytes()) == expected
for path, expected in v1['sources_after'].items():
    if path != 'tests/test_hia_evaluation_capture.py':
        assert pin((ROOT / path).read_bytes()) == expected
DEST.mkdir(parents=True, exist_ok=False)

for directory, prefix in (
    (Path('/tmp/runtime-evaluation-capture-before-589c'), 'original-before'),
    (Path('/tmp/runtime-evaluation-capture-order-before-589c'), 'two-invalid-before'),
    (Path('/tmp/runtime-evaluation-capture-host-controls-v2-589c'), 'host-control-pilot'),
    (V1, 'controls-v1'), (V2, 'caller-controls-v2'),
):
    for path in sorted(directory.rglob('*')):
        if path.is_file():
            copy(path, prefix + '/' + path.relative_to(directory).as_posix())
for script in ('runtime-evaluation-capture-before-589c.py',
               'runtime-evaluation-capture-order-before-589c.py',
               'runtime-evaluation-capture-build-589c.py',
               'runtime-evaluation-capture-controls-589c.py'):
    copy(Path('/tmp') / script, 'observers/' + script)
copy(BUILD / 'construction-custody.json', 'construction-custody.json')

native = []
for component, label, source_name in (
    ('evaluation', 'evaluation', 'examples/hia_bootstrap/evaluation.hepta'),
    ('admission', 'native_build_admission', 'examples/hia_bootstrap/native_build_admission.hepta'),
):
    directory = BUILD / component
    for name in ('manifest.json', 'build.json', *[label + suffix for suffix in (
        '.request.json', '.receipt.json', '.stdout.log', '.stderr.log',
        '.process-streams.json', '.process.stdout.zlib', '.process.stderr.zlib')]):
        copy(directory / name, 'native-build/' + component + '/' + name)
    request_raw = (directory / (label + '.request.json')).read_bytes()
    request = json.loads(request_raw)
    receipt = json.loads((directory / (label + '.receipt.json')).read_bytes())
    process, streams = decode_original_process_streams(
        (directory / (label + '.process-streams.json')).read_bytes(), request_raw,
        {name: (directory / (label + '.process.' + name + '.zlib')).read_bytes()
         for name in ('stdout', 'stderr')}, label=label)
    assert process['returncode'] == 0 and process['timed_out'] is False and not streams['stderr']
    source = (ROOT / source_name).read_bytes()
    compiler = Path(request['image']).read_bytes()
    assert source == Path(request['source']).read_bytes()
    assert sha256(source).hexdigest() == request['source_sha256']
    assert sha256(compiler).hexdigest() == request['image_sha256']
    raw = streams['stdout']
    assert raw[:8] == b'HIAOBR02'
    assert len(raw) == 24 + len(source) + request['capacity'] + request['workspace_size']
    returned, elapsed = struct.unpack_from('<2Q', raw, 8)
    assert returned == receipt['result_u64'] and elapsed == receipt['native_elapsed_ns']
    assert returned >> 32 == 0 and 0 < returned <= request['capacity']
    assert raw[24:24 + len(source)] == source
    output = raw[24 + len(source):24 + len(source) + request['capacity']]
    image = (directory / (label + '.image.bin')).read_bytes()
    assert output == Path(request['output']).read_bytes() and image == output[:returned]
    # Explicitly derived input reconstruction, matched to the original captured
    # frame hash. It is not represented as a separately retained original stdin.
    request_frame = frame(compiler, source, request['capacity'], request['workspace_size'],
                          request['workspace_fill'], request['shared_output_fd'])
    assert sha256(request_frame).hexdigest() == request['frame_sha256']
    rebuilt_name = 'native-build/' + component + '/' + label + '.reconstructed-stdin.zlib'
    (DEST / rebuilt_name).write_bytes(zlib.compress(request_frame, 9))
    native.append({'component': component, 'source': {'path': source_name, **pin(source)},
        'compiler': pin(compiler), 'original_stdout': pin(raw), 'produced_image': pin(image),
        'original_process_returncode': 0, 'timed_out': False,
        'source_echo_equal': True, 'full_output_equal': True, 'image_exact_output_prefix': True,
        'native_elapsed_ns': elapsed, 'reconstructed_input': pin(request_frame),
        'reconstructed_input_matches_original_frame_hash': True,
        'reconstructed_input_archive': rebuilt_name})
save(DEST / 'native-stream-readback.json', {'schema': 'hepta.hia.evaluation-capture-native-readback.v1',
    'scope': 'actual native development processes; data-only readback',
    'decoder': pin((ROOT / 'tools/read_hia_cold_native_transport.py').read_bytes()),
    'builds': native, 'current_source_cold_qualified': False})

# Complete reverse application is performed in a private copy. The original
# source fixture and all assertions remain independently pinned.
reverse = REVIEW / 'reverse-source'
reverse.mkdir(exist_ok=False)
for path in paths:
    target = reverse / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((ROOT / path).read_bytes())
patch = (REVIEW / 'product.patch').read_bytes()
subprocess.run(['git', 'apply', '--reverse', str(REVIEW / 'product.patch')], cwd=reverse, check=True)
reconstruction = {}
for path in paths:
    old = subprocess.run(['git', '-C', str(ROOT), 'show', BASE + ':' + path], capture_output=True)
    if old.returncode:
        assert not (reverse / path).exists()
        reconstruction[path] = {'new_path_removed': True, 'current': pin((ROOT / path).read_bytes())}
    else:
        assert (reverse / path).read_bytes() == old.stdout
        reconstruction[path] = {'entire_original_file_reconstructed': True, 'original': pin(old.stdout),
                                'current': pin((ROOT / path).read_bytes())}
module = ast.parse((ROOT / 'hepta/hia_agent_service.py').read_bytes())
service = next(node for node in module.body if isinstance(node, ast.ClassDef) and node.name == 'HIAAgentService')
retained = next(node for node in service.body if isinstance(node, ast.FunctionDef) and node.name == '_hia_evaluate_reference')
restored = original_reference(retained)
restored.name = '_hia_evaluate'
fixture_name = 'tests/fixtures/hia_evaluate_19065.py.txt'
fixture = (ROOT / fixture_name).read_bytes()
assert ast.dump(restored) == ast.dump(ast.parse(fixture).body[0])
invariants = {}
for name in ('examples/hia_bootstrap/evaluation.hepta', 'hepta/hia_evaluation_protocol.py',
             'tests/hia_evaluation_oracle.py', 'tests/hia_evaluation_scenarios.py', fixture_name,
             'tests/fixtures/hia_evaluation_value_19065.py.txt',
             'tests/fixtures/evaluation_callers_19065.json'):
    current = (ROOT / name).read_bytes()
    assert current == git('show', BASE + ':' + name)
    invariants[name] = pin(current)
save(DEST / 'source-reconstruction.json', {'schema': 'hepta.hia.evaluation-capture-source-reconstruction.v1',
    'base_commit': BASE, 'patch': pin(patch), 'files': reconstruction,
    'entire_original_reference_AST_equal': True,
    'unchanged_protocol_and_original_oracles': invariants,
    'original_test_assertions_not_replaced': True})
shutil.copyfile(REVIEW / 'product.patch', DEST / 'source.patch')

inventory = {}
index = git('ls-files', '--stage', '-z').split(b'\0')
for item in index:
    if not item:
        continue
    header, path_raw = item.split(b'\t', 1)
    mode, indexed_blob, stage = header.decode().split()
    path = path_raw.decode()
    physical = ROOT / path
    if physical.is_file():
        raw = physical.read_bytes()
        assert blob(raw) == indexed_blob, path
        inventory[path] = {**pin(raw), 'git_blob': indexed_blob, 'mode': mode}
save(DEST / 'source-readback.json', {'schema': 'hepta.hia.component-checkout-source-readback.v1',
    'base_commit': BASE, 'scope': 'post-test complete readback of all physically present indexed files; during-execution captures retained separately',
    'files': inventory, 'changed_paths': paths,
    'absent_tracked_paths': [item.split(b'\t', 1)[1].decode() for item in index
                             if item and item.split(b'\t', 1)[1].decode() not in inventory]})

save(DEST / 'result.json', {'schema': 'hepta.hia.evaluation-capture-recovery.v1',
    'base_commit': BASE, 'historical_feature_commit': 'f587bda212423ae0ad6c4bf238ba32c855c3885a',
    'source_files': {path: pin((ROOT / path).read_bytes()) for path in paths},
    'before_original_public_caller': 'FAIL; candidate was directly read independently of receipt validation',
    'premature_combined_capture_rejected_design': 'two-invalid-before/receipt.json',
    'first_component_run': {'tests': 13, 'passed': 12, 'failures': 1, 'errors': 0, 'skipped': 0,
        'failure': 'new observer incorrectly grouped identically named effect methods from two owner modules'},
    'corrected_observer_run': {'tests': 4, 'passed': 4, 'failures': 0, 'errors': 0, 'skipped': 0,
        'production_source_unchanged': True, 'only_test_observer_module_and_function_identity_corrected': True},
    'unique_controls_with_terminal_pass_across_both_runs': 13,
    'original_foreign_scenarios': 111, 'original_foreign_scenarios_all_passed': True,
    'independent_VM_and_native_full_state_cases': 6,
    'four_actual_caller_routes': ['hosted original Store protocol', 'hosted current typed Store',
        'actual native evaluation', 'actual native evaluation and native build admission'],
    'native_capture_two_event_order_preserved': True,
    'candidate_corruption_precedes_receipt_authority_error': True,
    'capture_bound_to_service_artifact_context_process_thread_and_one_consumption': True,
    'custom_build_providers_keep_original_protocol': True,
    'source_reference_restored_by_exact_reviewed_splice': True,
    'scope': 'finite development component controls; providers and capture adapter remain hosted',
    'whole_stack_rewritten_in_hia': False, 'all_input_equivalence_proved': False,
    'original_hosted_cold_class_construction_gate_executed': False,
    'installed_complete_release_qualified': False, 'new_matching_source_qualification_required': True})
(DEST / 'README.md').write_text('''# Evaluation candidate observation recovery

The retained evaluation read candidate bytes once for execution and a second
time inside build-receipt admission. The original f587 public-caller control
fails on base06d. Directly moving the complete build read earlier also changes
the first error for a physically corrupt candidate and an independently invalid
receipt; the actual counterexample is retained.

The successor captures at the original candidate event and validates that exact
observation at the original receipt event, through the complete existing
`_build_inputs` policy. It never replaces a live service method or shared Store.
Service, artifact/context reference identity and contents, process, thread and
single consumption are checked. Custom build providers retain their original
protocol. The HIA evaluation program and ports are unchanged.

The original public caller is restored in a separate module so the frozen
183-method inventory remains intact. Only the current two-stage owner names
and module identities distinguish direct evaluator reads from independent
claim rechecks. The reference body reverses to the complete original AST;
full reverse application also reconstructs every preexisting source file.

The first 13-control run passed 12 and exposed an overly broad new observer
classification (`effect` occurs in two different native owner modules). That
original failure remains. Correcting only the observer identity then passed
all four actual public-caller routes. The union covers 13 distinct controls,
including the untouched 111 original foreign traces/first errors and six
complete VM/native buffer comparisons. It is not a claim that the initial
13-control command passed.

Both native components were really built with the identified historical native
B1 and native observer, in the official builders' explicit development mode.
Original process records and complete compressed stdout/stderr are retained;
produced images are exact prefixes recoverable from those streams. The separately
marked reconstructed stdin frames match the original captured frame hashes.

No current cold, installed whole release, full-input equivalence, or HIA-only
provider implementation is claimed. The hosted-only original class setup gate
was not substituted: its original control methods were executed with the
explicit native development construction and independent source custody.
''')
copy(Path(__file__), 'observers/archive_evaluation_capture.py')
evidence = {path.relative_to(DEST).as_posix(): pin(path.read_bytes())
            for path in sorted(DEST.rglob('*')) if path.is_file()}
save(DEST / 'evidence-pins.json', {'schema': 'hepta.hia.evaluation-capture-evidence-pins.v1', 'files': evidence})
save(REVIEW / 'source-pins.json', {path: pin((ROOT / path).read_bytes()) for path in paths})
print(json.dumps({'evidence_files': len(evidence) + 1,
                  'evidence_bytes': sum(path.stat().st_size for path in DEST.rglob('*') if path.is_file()),
                  'source_paths': paths, 'native_images': [row['produced_image'] for row in native],
                  'destination': str(DEST)}, sort_keys=True))
