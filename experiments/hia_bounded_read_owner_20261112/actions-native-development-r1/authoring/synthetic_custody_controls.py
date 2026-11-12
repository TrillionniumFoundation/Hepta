"""Small actual filesystem controls for evidence transport, never HIA/product tests."""
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import traceback

ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / 'control'))
import actions_custody as custody
from source_common import create, read, wire

evidence = ROOT / 'authoring/custody-controls-r1'
evidence.mkdir(mode=0o700, exist_ok=False)
results = []

def record(name, action):
    try:
        detail = action()
        results.append({'id': name, 'status': 'PASS', 'detail': detail})
    except BaseException as error:
        results.append({'id': name, 'status': 'FAIL', 'type': type(error).__name__,
                        'traceback': traceback.format_exc()})

def typed_roundtrip():
    root = evidence / 'typed'
    root.mkdir(mode=0o700)
    (root / 'public').mkdir(mode=0o700)
    (root / 'nested').mkdir(mode=0o700)
    create(root / 'ordinary.bin', bytes(range(256)))
    create(root / 'nested/empty', b'')
    os.mkfifo(root / 'nested/pipe', 0o600)
    external = evidence / 'outside'
    create(external, b'outside original must never be read through the symlink')
    (root / 'nested/link').symlink_to(external)
    observed = []
    actual_open = os.open
    def audit_open(path, *args, **kwargs):
        observed.append(str(path))
        if str(path) in ('pipe', 'link', str(external)):
            raise AssertionError('custody tried to open a special member or its target')
        return actual_open(path, *args, **kwargs)
    os.open = audit_open
    try:
        value = custody.retain_typed_owned_output(root)
    finally:
        os.open = actual_open
    with tarfile.open(root / 'public/owned-originals.tar', 'r:') as archive:
        assert archive.getmember('nested/pipe').isfifo()
        assert archive.getmember('nested/link').issym()
        assert archive.extractfile('ordinary.bin').read() == bytes(range(256))
        assert archive.extractfile('nested/empty').read() == b''
    assert read(external)[0] == b'outside original must never be read through the symlink'
    return {'receipt': value, 'special_member_open_count': 0,
            'actual_regular_bytes_and_types_read_back': True, 'open_observations': len(observed)}

def refused(operation):
    try:
        operation()
    except (OSError, RuntimeError) as error:
        return {'rejected': True, 'type': type(error).__name__, 'message': str(error)}
    raise AssertionError('unsafe read was accepted')

record('actual_regular_empty_symlink_FIFO_typed_roundtrip', typed_roundtrip)
record('ordinary_reader_refuses_symbolic_link', lambda: refused(
    lambda: read(evidence / 'typed/nested/link')))
record('ordinary_reader_refuses_FIFO_without_blocking', lambda: refused(
    lambda: read(evidence / 'typed/nested/pipe')))
hard = evidence / 'hardlinked'
hard.mkdir(mode=0o700)
(hard / 'public').mkdir(mode=0o700)
create(hard / 'first', b'fixed')
os.link(hard / 'first', hard / 'second')
record('typed_inventory_refuses_multiple_link_regular_member', lambda: refused(
    lambda: custody.retain_typed_owned_output(hard)))
(evidence / 'parent-link').symlink_to(evidence / 'typed/nested', target_is_directory=True)
record('reader_refuses_intermediate_symlink', lambda: refused(
    lambda: read(evidence / 'parent-link/empty')))

report = {'schema': 'hepta.hia.bounded-read-custody-synthetic-controls.v1',
    'status': 'PASS' if all(r['status'] == 'PASS' for r in results) else 'FAIL',
    'scope': 'EVIDENCE_FILESYSTEM_ONLY_NO_PRODUCT_OR_GUARDIAN_EXECUTION',
    'expected_ids': [r['id'] for r in results], 'executed_ids': [r['id'] for r in results],
    'cases': results, 'python': sys.version,
    'sources': {name: {'bytes': len((ROOT / 'control' / name).read_bytes()),
        'sha256': sha256((ROOT / 'control' / name).read_bytes()).hexdigest()}
        for name in ('actions_custody.py', 'source_common.py', 'native_support.py')},
    'actual_outer_ECHILD_supplied_by_this_control': False,
    'native_compiled_or_executed': False, 'test_population_55_plus_8_executed': False}
create(evidence / 'report.json', wire(report))
print(json.dumps({'status': report['status'], 'cases': len(results), 'report': str(evidence / 'report.json')}))
raise SystemExit(0 if report['status'] == 'PASS' else 1)
