"""Materialize and pin a small source subset; never run generation or tests."""
from hashlib import sha256, sha1
import ast
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parent
BASE = Path('/workspace/scratch/e26ed3e2edcf/combined-native-v88-r1')
SOURCE = ROOT / 'source'
OUTPUT = Path('/tmp/hia-wire-key-summary-source6-r1-output-20261112-e26e')
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')


def require(value, message):
    if not value:
        raise AssertionError(message)


def blob(raw):
    return sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def record(path):
    path = Path(path)
    first = path.lstat()
    require(path.resolve() == path and stat.S_ISREG(first.st_mode)
            and first.st_nlink == 1 and first.st_size <= 64 << 20, 'ordinary fixed input required: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(all(getattr(first, k) == getattr(os.fstat(fd), k) for k in FIELDS), 'file changed at open')
        pieces, count = [], 0
        while part := os.read(fd, 1 << 20):
            count += len(part)
            require(count <= first.st_size, 'file grew')
            pieces.append(part)
        after, named = os.fstat(fd), path.lstat()
        require(count == first.st_size and all(getattr(first, k) == getattr(after, k) == getattr(named, k)
                                              for k in FIELDS), 'file changed while reading')
    finally:
        os.close(fd)
    raw = b''.join(pieces)
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'identity': {k: getattr(first, k) for k in FIELDS}}, raw


def create(path, raw, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    pin, actual = record(path)
    require(actual == raw, 'new file readback differs')
    return pin


def wire(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def main():
    require(not os.path.lexists(SOURCE) and not os.path.lexists(OUTPUT), 'fresh source and operation namespaces required')
    require(tuple(sys.version_info[:3]) == (3, 12, 14), 'frozen local runtime version required')
    git = json.loads((ROOT / 'BASELINE-SUBSET-GIT.json').read_bytes())
    require(git['commit'] == 'e4fc00a775dab323758d77a2ef4918fd35585cdc'
            and git['tree'] == git['full_tree_recomputed'] == 'd9e8407c70e44a3ea0152b8b4c5eb2ed3833d790'
            and git['full_tree_leaves'] == 4076 and len(git['rows']) == 538, 'actual baseline Git subset differs')
    SOURCE.mkdir(mode=0o700)
    rows = []
    for item in git['rows']:
        name = item['path']
        original_pin, original = record(BASE / name)
        require(blob(original) == item['sha'] and len(original) == item['size'], 'baseline Git blob differs: ' + name)
        require(('100755' if original_pin['identity']['st_mode'] & 0o111 else '100644') == item['mode'],
                'baseline Git mode differs: ' + name)
        overlay = ROOT / 'inputs' / name
        content = record(overlay)[1] if overlay.exists() else original
        after = create(SOURCE / name, content, 0o755 if item['mode'] == '100755' else 0o644)
        rows.append({'path': name, 'baseline_git_blob': item['sha'], 'baseline_sha256': original_pin['sha256'],
                     'source_git_blob': blob(content), 'source': after, 'overlay': overlay.exists()})
    name = 'tests/test_hia_json_wire_key_summary.py'
    require(not (SOURCE / name).exists(), 'new tests unexpectedly present in baseline')
    content = record(ROOT / 'inputs' / name)[1]
    rows.append({'path': name, 'baseline_git_blob': None, 'source_git_blob': blob(content),
                 'source': create(SOURCE / name, content), 'overlay': True})
    require(sum(row['overlay'] for row in rows) == 4 and len(rows) == 539, 'exact four-file source delta required')
    prior = json.loads(Path('/tmp/hia-wire89-timeout-diagnostic-local312-r2/RECORDING-CONTROLS-REQUEST.json').read_bytes())
    owner_pin, owner_raw = record(Path(prior['owner_path']))
    require(owner_pin['sha256'] == prior['input_pins'][prior['owner_path']]['sha256'], 'original owner bytes differ')
    owner_path = ROOT / 'control/process_owner_impl.py'
    copied_owner = create(owner_path, owner_raw)
    require(copied_owner['sha256'] == owner_pin['sha256'], 'owner copy differs')
    expected = []
    tree = ast.parse((SOURCE / name).read_bytes())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'WireKeySummarySourceTests')
    expected = ['tests.test_hia_json_wire_key_summary.WireKeySummarySourceTests.' + node.name
                for node in cls.body if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')]
    expected.sort()
    require(len(expected) == len(set(expected)) == 6, 'six distinct source methods required')
    directories = [str(path.relative_to(SOURCE)) for path in sorted(SOURCE.rglob('*')) if path.is_dir()]
    source_before = {'files': {row['path']: row['source'] for row in rows}, 'directories': directories}
    runtime = Path(sys.executable).resolve(strict=True)
    controls = [ROOT / 'control/source6_worker.py', ROOT / 'control/source6_launch.py', owner_path]
    input_pins = {row['source']['path']: row['source'] for row in rows}
    input_pins.update({str(path): record(path)[0] for path in controls + [runtime]})
    request = {
        'schema': 'hepta.hia.json-wire-key-summary.source6-request.v1',
        'status': 'UNEXECUTED_ROOT_REVIEW_REQUIRED', 'qualification_seconds': 180, 'cleanup_seconds': 3,
        'operation_root': str(OUTPUT), 'source_root': str(SOURCE), 'owner_path': str(owner_path),
        'command': [str(runtime), '-I', '-S', '-B', str(ROOT / 'control/source6_worker.py')],
        'environment': {'PATH': '', 'PYTHONHASHSEED': '0', 'PYTHONDONTWRITEBYTECODE': '1',
                        'PYTHONNOUSERSITE': '1', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'},
        'runtime': {'version': sys.version, 'executable': input_pins[str(runtime)],
                    'scope': 'LOCAL_CPYTHON_3_12_14_SOURCE_CORE_VM_ONLY_NOT_CI_REPRODUCTION'},
        'minimum_free_bytes': 512 << 20, 'minimum_free_inodes': 4096,
        'estimated_output_reserve_bytes': 32 << 20,
        'expected_tests': 6, 'expected_ids': expected, 'input_pins': input_pins,
        'source_before': source_before, 'source_git_reference': {
            'commit': git['commit'], 'tree': git['tree'], 'selected_baseline_files': 538,
            'frozen_source_files': 539, 'complete_product_tree_claimed': False},
        'source_generation': 'tools.generate_hia_json_wire.document + original render_assembly',
        'only_source_addition': 'examples/hia_bootstrap/json_wire.hiaasm',
        'generation_and_6_controls_share_one_owner': True,
        'poison_required': ['subprocess', 'native_image_constructor', 'ctypes_dynamic_loader',
                            'ctypes_function_type', 'executable_mmap'],
        'allowed_native_memory_transport': ['ctypes.string_at', 'ctypes.memmove', 'ctypes arrays', 'private RW mmap'],
        'native_image_or_compiler_or_old89_or_original_native7_or_new_native6_executed': False,
        'old_source4_remains_separate_required_original_gate': True,
        'new_native6_remains_unexecuted': True,
        'original_5_second_assertion_and_256_cases_unchanged': True,
        'no_retry_or_budget_increase_authorized': True,
    }
    materialization = {'schema': 'hepta.hia.json-wire-key-summary.source-materialization.v1',
        'status': 'STATIC_BYTES_ONLY_NOT_GENERATED_OR_EXECUTED', 'baseline_git': git['commit'],
        'baseline_tree': git['tree'], 'files': rows, 'source_file_count': len(rows),
        'source_bytes': sum(row['source']['bytes'] for row in rows),
        'complete_product_tree_claimed': False, 'original_owner': owner_pin, 'copied_owner': copied_owner}
    create(ROOT / 'SOURCE-MATERIALIZATION.json', wire(materialization))
    request_pin = create(ROOT / 'SOURCE6-REQUEST.json', wire(request))
    launch = {'schema': 'hepta.hia.json-wire-key-summary.source6-launch.v1',
        'status': 'UNEXECUTED_ROOT_REVIEW_REQUIRED', 'request': request_pin,
        'argv': [str(runtime), '-I', '-S', '-B', str(ROOT / 'control/source6_launch.py')], 'cwd': str(ROOT)}
    launch_pin = create(ROOT / 'SOURCE6-LAUNCH.json', wire(launch))
    print(json.dumps({'source_files': len(rows), 'source_bytes': materialization['source_bytes'],
        'input_pins': len(input_pins), 'expected_tests': 6,
        'request_sha256': request_pin['sha256'], 'launch_sha256': launch_pin['sha256'],
        'operation_root_created': OUTPUT.exists(), 'execution_performed': False}))


if __name__ == '__main__':
    main()
