"""Finite original-reader/strengthened-reader controls over synthetic receipts.

No artifact in these fixtures is executable code. No HIA generation, native
compilation, original child, guardian, or 55+8 product case is run here.
"""
import ast
from hashlib import sha1, sha256
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import traceback

ROOT = Path(__file__).absolute().parent.parent
BASE = Path('/workspace/scratch/e26ed3e2edcf/Hepta')
OUT = ROOT / 'authoring/receipt-join-controls-r2'
OUT.mkdir(mode=0o700, exist_ok=False)
sys.path.insert(0, str(ROOT / 'control'))
from source_common import wire

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

old = load('_bounded_read_A1', ROOT / 'authoring/unexecuted-A1/native_support.py')
new = load('_bounded_read_A2', ROOT / 'control/native_support.py')
assert sha256((ROOT / 'authoring/unexecuted-A1/native_support.py').read_bytes()).hexdigest() == 'd231bbdf27de6d909c7e3974ecccef5b8b62577db4de0c99d4012389ef4999be'
source = OUT / 'synthetic-source'
source.mkdir(mode=0o700)
inputs = {'examples/hia_bootstrap/selfhost.hiaasm': b'SYNTHETIC_READBACK_INPUT_NOT_HIA\n',
          new.GENERATED: b'SYNTHETIC_COMPONENT_INPUT_NOT_HIA\n',
          'docs/HIA_SELFHOST_CORE_SUPPORT.json': b'{}\n',
          'hepta/synthetic.py': b'# Not imported or executed\n'}
for name, expected in [('tools/qualify_hia_selfhost.py', new.QUALIFY_SHA),
                       ('tools/hia_selfhost_child.py', new.CHILD_SHA)]:
    raw = (BASE / name).read_bytes()
    assert sha256(raw).hexdigest() == expected
    inputs[name] = raw
for name, raw in inputs.items():
    path = source / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)

producer = ast.parse(inputs['tools/qualify_hia_selfhost.py'])
updates = {}
for function in producer.body:
    if isinstance(function, ast.FunctionDef) and function.name in ('invoke', 'compile_stage'):
        fields = set()
        for node in ast.walk(function):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == 'result'
                    and node.func.attr == 'update' and len(node.args) == 1
                    and isinstance(node.args[0], ast.Dict)):
                fields.update(ast.literal_eval(key) for key in node.args[0].keys)
        updates[function.name] = sorted(fields)
assert updates == {'invoke': sorted(['case', 'input_sha256', 'input_bytes', 'artifact_sha256',
    'format', 'runner_sha256', 'wall_elapsed_ns']),
    'compile_stage': sorted(['produced_image', 'produced_bytes', 'produced_sha256'])}
backend_raw = (BASE / 'hepta/hia_program_native.py').read_bytes()
assert sha256(backend_raw).hexdigest() == 'd58058760c02f65aa406dd54a0d0fa40cea5df0f4b8191696d21a784e71e8344'
backend = ast.parse(backend_raw)
function = next(n for n in backend.body if isinstance(n, ast.FunctionDef) and n.name == 'compile_program_machine')
last_return = next(n for n in reversed(function.body) if isinstance(n, ast.Return))
assert {'artifact_sha256', 'artifact_bytes', 'kind', 'output'} <= {ast.literal_eval(k) for k in last_return.value.keys}

def save(path, value):
    path.write_bytes(wire(value))

def fixture(name):
    directory = OUT / 'fixtures' / name
    directory.mkdir(parents=True, mode=0o700)
    seed = b'NOT_EXECUTABLE_SYNTHETIC_B0'
    (directory / 'B0.so').write_bytes(seed)
    seed_receipt = {'schema': 'hepta.hia.program.direct-native.v1', 'ok': True, 'kind': 'shared',
        'output': str(directory / 'B0.so'), 'artifact_sha256': sha256(seed).hexdigest(),
        'artifact_bytes': len(seed), 'seed_only': True,
        'source_sha256': sha256(inputs['examples/hia_bootstrap/selfhost.hiaasm']).hexdigest(),
        'python': {'isolated': True, 'no_site': True},
        'support_contract_sha256': sha256(inputs['docs/HIA_SELFHOST_CORE_SUPPORT.json']).hexdigest(),
        'loaded_seed_modules': {'hepta/synthetic.py': sha256(inputs['hepta/synthetic.py']).hexdigest()}}
    save(directory / 'B0.receipt.json', seed_receipt)
    predecessor, predecessor_bytes = directory / 'B0.so', seed
    for label, body, image_format in [('B1', inputs['examples/hia_bootstrap/selfhost.hiaasm'], 'seed-shared'),
            ('B2', inputs['examples/hia_bootstrap/selfhost.hiaasm'], 'flat-x86-64'),
            ('bounded-read', inputs[new.GENERATED], 'flat-x86-64')]:
        image = b'NOT_EXECUTABLE_SYNTHETIC_SUCCESSOR' if label != 'bounded-read' else b'NOT_EXECUTABLE_SYNTHETIC_COMPONENT'
        output = image + b'\xa5' * ((1 << 20) - len(image))
        input_path, output_path = directory / (label + '.input.bin'), directory / (label + '.output.bin')
        image_path = directory / (label + '.image.bin')
        input_path.write_bytes(body); output_path.write_bytes(output); image_path.write_bytes(image)
        request = {'format': image_format, 'image': str(predecessor),
            'image_sha256': sha256(predecessor_bytes).hexdigest(), 'source': str(input_path),
            'source_sha256': sha256(body).hexdigest(), 'capacity': 1 << 20,
            'workspace_size': 1 << 20, 'workspace_fill': 0, 'output': str(output_path)}
        save(directory / (label + '.request.json'), request)
        child = {'status': 'returned', 'abi_status': 0, 'core_u32': len(image), 'result_u64': len(image),
            'source_unchanged': True, 'source_sha256': sha256(body).hexdigest(),
            'image_sha256': sha256(predecessor_bytes).hexdigest(), 'output_sha256': sha256(output).hexdigest(),
            'forbidden_compiler_modules_loaded': [], 'limits': new.NATIVE_LIMITS,
            'synthetic_fixture_not_native': True, 'native_elapsed_ns': 1}
        save(directory / (label + '.stdout.log'), child)
        (directory / (label + '.stderr.log')).write_bytes(b'')
        receipt = dict(child, case=label, input_sha256=sha256(body).hexdigest(), input_bytes=len(body),
            artifact_sha256=request['image_sha256'], format=image_format, runner_sha256=new.CHILD_SHA,
            wall_elapsed_ns=2, produced_image=str(image_path), produced_bytes=len(image),
            produced_sha256=sha256(image).hexdigest())
        save(directory / (label + '.receipt.json'), receipt)
        predecessor, predecessor_bytes = image_path, image
    return directory

def change(directory, name, field, value):
    path = directory / name
    data = json.loads(path.read_bytes())
    if value is None:
        del data[field]
    else:
        data[field] = value
    save(path, data)

CASES = [('matching_complete_receipt_bytes', None),
    ('B0_artifact_hash_mismatch', ('B0.receipt.json', 'artifact_sha256', '0' * 64)),
    ('B0_artifact_size_mismatch', ('B0.receipt.json', 'artifact_bytes', 999)),
    ('B1_loaded_image_hash_mismatch', ('B1', 'image_sha256', '0' * 64)),
    ('B2_source_hash_mismatch', ('B2', 'source_sha256', '0' * 64)),
    ('component_full_output_hash_mismatch', ('bounded-read', 'output_sha256', '0' * 64)),
    ('B1_stdout_full_projection_mismatch', ('B1.stdout.log', 'native_elapsed_ns', 999)),
    ('B2_stdout_full_projection_mismatch', ('B2.stdout.log', 'native_elapsed_ns', 999)),
    ('component_stdout_full_projection_mismatch', ('bounded-read.stdout.log', 'native_elapsed_ns', 999)),
    ('producer_appended_field_missing', ('B2.receipt.json', 'wall_elapsed_ns', None))]
results = []
for name, mutation in CASES:
    directory = fixture(name)
    if mutation:
        target, key, value = mutation
        if target in ('B1', 'B2', 'bounded-read'):
            change(directory, target + '.receipt.json', key, value)
            change(directory, target + '.stdout.log', key, value)
        else:
            change(directory, target, key, value)
    observations = {}
    for label, implementation in [('original_A1', old), ('strengthened_A2', new)]:
        try:
            result = implementation.observe_compiler_bundle(source, directory)
            observations[label] = {'accepted': True, 'scope': result['scope'], 'records': len(result['records'])}
        except BaseException as error:
            observations[label] = {'accepted': False, 'type': type(error).__name__, 'text': str(error)}
    wanted = mutation is None
    passed = observations['original_A1']['accepted'] and observations['strengthened_A2']['accepted'] is wanted
    results.append({'id': name, 'status': 'PASS' if passed else 'FAIL', 'mutation': mutation,
        'expected_strengthened_acceptance': wanted, 'observations': observations})

members = []
for path in sorted(OUT.rglob('*')):
    if path.is_file():
        raw = path.read_bytes()
        members.append({'path': path.relative_to(OUT).as_posix(), 'bytes': len(raw),
                        'sha256': sha256(raw).hexdigest()})
archive_path = OUT / 'synthetic-originals.tar.xz'
with tarfile.open(archive_path, 'w:xz', preset=1) as archive:
    for row in members:
        raw = (OUT / row['path']).read_bytes()
        member = tarfile.TarInfo(row['path']); member.mode = 0o400; member.size = len(raw)
        archive.addfile(member, io.BytesIO(raw))
with tarfile.open(archive_path, 'r:xz') as archive:
    assert {m.name for m in archive.getmembers()} == {r['path'] for r in members}
    by_name = {r['path']: r for r in members}
    for member in archive.getmembers():
        raw = archive.extractfile(member).read(); expected = by_name[member.name]
        assert member.isfile() and member.mode == 0o400 and len(raw) == expected['bytes']
        assert sha256(raw).hexdigest() == expected['sha256']
report = {'schema': 'hepta.hia.bounded-read-synthetic-receipt-join-controls.v1',
    'status': 'PASS' if all(r['status'] == 'PASS' for r in results) else 'FAIL',
    'scope': 'READ_ONLY_RECEIPT_VERIFIER_CONTROLS_WITH_NONEXECUTABLE_STANDIN_BYTES',
    'expected_ids': [n for n, _ in CASES], 'executed_ids': [r['id'] for r in results],
    'cases': results, 'original_A1_sha256': sha256((ROOT / 'authoring/unexecuted-A1/native_support.py').read_bytes()).hexdigest(),
    'strengthened_A2_sha256': sha256((ROOT / 'control/native_support.py').read_bytes()).hexdigest(),
    'producer_update_keys_from_actual_AST': updates,
    'actual_producer_pins': {n: sha256((BASE / n).read_bytes()).hexdigest() for n in
        ('tools/qualify_hia_selfhost.py', 'tools/hia_selfhost_child.py', 'hepta/hia_program_native.py')},
    'synthetic_archive': {'path': str(archive_path), 'bytes': archive_path.stat().st_size,
        'sha256': sha256(archive_path.read_bytes()).hexdigest(), 'members': len(members),
        'decoded_bytes': sum(r['bytes'] for r in members), 'all_member_hashes_and_modes_read_back': True},
    'Python': sys.version, 'native_executed': False, 'product_cases_executed': 0,
    'original_child_or_guardian_run': False}
save(OUT / 'report.json', report)
save(OUT / 'member-manifest.json', members)
print(json.dumps({'status': report['status'], 'controls': len(results), 'archive': report['synthetic_archive']}))
raise SystemExit(0 if report['status'] == 'PASS' else 1)
