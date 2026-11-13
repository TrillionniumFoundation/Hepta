"""Independent static/read-only gate for the first SQLite source8 r2 call."""
from pathlib import Path
import ast
import hashlib
import json
import os
import stat
import sys
import time

OUT = Path(__file__).resolve().parent
ROOT = Path('/home/agent/hia-sqlite-source8-r2-recovery-20261113-e26e')

def read(path):
    path = Path(path)
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not path.is_symlink(), str(path)
    identity = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
                          s.st_size, s.st_mtime_ns, s.st_ctime_ns]
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        assert identity(os.fstat(stream.fileno())) == identity(before)
        raw = stream.read()
        assert identity(os.fstat(stream.fileno())) == identity(before)
    assert identity(path.lstat()) == identity(before)
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'identity': identity(before)}, raw

def write(name, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(OUT / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    return {'path': str(OUT / name), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

plan = json.loads((OUT / 'PLAN.original.json').read_bytes())
assert len(plan['new_files']) == 58 and plan['new_raw_bytes'] == 1542731
local_rows = []
for expected in plan['new_files']:
    actual, body = read(expected['local'])
    remote = (OUT / 'remote-bodies' / expected['git_blob']).read_bytes()
    assert body == remote
    assert all(actual[k] == expected[k] for k in ('bytes', 'sha256', 'git_blob'))
    assert ('100755' if actual['identity'][2] & 0o111 else '100644') == expected['mode']
    local_rows.append(actual)

request_pin, request_raw = read(ROOT / 'REQUEST.json')
launch_pin, launch_raw = read(ROOT / 'LAUNCH.json')
assert request_pin['sha256'] == '7edf8b146dec5aa0acdfe75fa3dbd69aaae4916436de40736c237d2817fffcb7'
assert launch_pin['sha256'] == 'a786a75d340513f81dea1fde83b05d499e80b9412f91948872bdd9aac212ad1c'
request, launch = json.loads(request_raw), json.loads(launch_raw)
assert request['qualification_seconds'] == 180 and request['cleanup_seconds'] == 3
assert request['old_source8_executions'] == request['new_source8_executions'] == 0
assert request['old_mutation_boundary'] == 'UNKNOWN_NOT_REPLAYED'
assert request['expected_methods'] == len(request['expected_ids']) == 8
assert request['expected_vm_returns'] == sum(request['expected_vm_by_id'].values()) == 1618
assert list(request['expected_vm_by_id'].values()) == [0, 573, 816, 36, 180, 12, 1, 0]
for key in ('C_oracle_compilation_permitted', 'SQLite_database_open_permitted',
            'native_compilation_permitted', 'native_execution_permitted', 'network_permitted'):
    assert request[key] is False
assert launch['request'] == {k: request_pin[k] for k in ('path', 'bytes', 'sha256', 'git_blob')}
assert launch['command'] == [request['runtime']['path'], '-I', '-S', '-B', str(ROOT / 'control/launch.py')]
assert launch['environment'] == request['environment'] and launch['cwd'] == str(ROOT)
assert launch['operation_root'] == request['operation_root']
assert not os.path.lexists(request['operation_root'])
runtime, _ = read(Path(sys.executable).resolve())
assert runtime == request['runtime'] and list(sys.version_info[:3]) == [3, 12, 14]

inputs = {}
for name, expected in request['inputs'].items():
    actual, _ = read(ROOT / name)
    assert all(actual[k] == expected[k] for k in ('bytes', 'sha256', 'git_blob'))
    inputs[name] = actual
assert len(inputs) == 46
source_map = json.loads((ROOT / request['source_map']).read_bytes())
assert source_map['commit'] == request['source_commit'] == '0504beb11c0dae875d8590660c42488b7bc634fb'
assert source_map['tree'] == request['source_tree'] == '596ab07e8813e4811a8dca51800cd51eb397aeb2'
assert source_map['root'] == request['source_root'] == str(ROOT / 'source-base')
tree = {r['path']: r for r in json.loads(Path('/workspace/scratch/e26ed3e2edcf/root/environment-recovery-v92-r4-r1/publication/PURE0504-TREE-LEAVES.json').read_bytes())}
source = {}
for expected in source_map['files']:
    actual, _ = read(ROOT / 'source-base' / expected['path'])
    assert all(actual[k] == expected[k] for k in ('bytes', 'sha256', 'git_blob'))
    mode = '100755' if actual['identity'][2] & 0o111 else '100644'
    assert mode == expected['mode'] == tree[expected['path']]['mode']
    assert actual['git_blob'] == tree[expected['path']]['sha']
    source[expected['path']] = actual
assert len(source) == 1686 and sum(x['bytes'] for x in source.values()) == 40890650
assert {str(p.relative_to(ROOT / 'source-base')) for p in (ROOT / 'source-base').rglob('*') if not p.is_dir()} == set(source)
source_pin = write('ROOT-SOURCE-BEFORE.json', source)

test = ast.parse((ROOT / 'candidate/inputs/tests/test_hia_sqlite_varint_source.py').read_bytes())
names = next(ast.literal_eval(n.value) for n in test.body if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == 'EXPECTED_NAMES' for t in n.targets))
cls = next(n for n in test.body if isinstance(n, ast.ClassDef) and n.name == 'SQLiteVarintSourceTests')
actual_names = [n.name for n in cls.body if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')]
assert actual_names == list(names) == [name.rsplit('.', 1)[1] for name in request['expected_ids']]
peer_path = Path('/home/agent/hia-native-peer-reviews-20261113-e26e/sqlite-source8-r2-owner-static-review.json')
peer_pin, peer_raw = read(peer_path)
peer = json.loads(peer_raw)
assert peer['status'] == 'STATIC_CLEAR_LIMITED_SCOPE'
for row in peer['inputs']:
    observed, _ = read(row['path'])
    assert all(observed[k] == row[k] for k in ('path', 'bytes', 'sha256'))

capacity = os.statvfs(Path(request['operation_root']).parent)
assert capacity.f_bavail * capacity.f_frsize >= request['minimum_free_bytes'] == 256 << 20
assert capacity.f_favail >= request['minimum_free_inodes'] == 4096
summary = {
 'schema': 'hia.root.sqlite-source8-r2-static-review.v1',
 'status': 'COMPLETE_REVIEW_FOR_ONE_FIRST_SOURCE8_R2_EXECUTION',
 'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
 'canonical_commit': '045f1ae1e88f9be6680f618bf220857c42a4cbbb',
 'canonical_tree': '39119b916b03d067eb21be97adaa0f9140077eb1',
 'canonical_parent': '7ab75efecb5f00e49fb6b455d7dc119fcddd34e6',
 'all56_remote_bodies_58_paths_4222_tree_and_commit_ref_read': True,
 'all4164_parent_leaves_preserved': True,
 'request': request_pin, 'launch': launch_pin, 'runtime': runtime,
 'publication_inputs': local_rows, 'request_inputs': inputs,
 'source_full_readback': source_pin, 'source_files': 1686, 'source_bytes': 40890650,
 'source_modes_and_pure_tree_matched': True, 'peer': peer_pin,
 'source_methods': 8, 'expected_VM_returns': 1618,
 'first_execution_not_yet_called': True, 'source8_actual_PASS_claimed': False,
 'native_or_C_or_SQL_or_full_product_PASS_claimed': False,
 'review_observations': [
  'Root read the complete new request/launch, all source controls, unchanged generator/ABI/bridge and original eight methods.',
  'Original369 owner plus exact returned/receipt/request join must establish ECHILD before child outputs are read.',
  'Natural nonzero execution preserves whole outputs before success rejection.',
  'All8 expected/loaded/actual/success IDs and ordered1618 full VM buffer records are required.',
  'No network, subprocess, native mapping, C oracle or SQL database operation is allowed in the source worker.',
  'All1686 source bodies and46 inputs are read before and after; actual imported project code must join those pins.',
  'Original180/3, 256MiB/4096 admission and16MiB output gates remain unchanged.',
  'Old source8 remains unexecuted; old Git mutation boundary and old R4 receiver remain UNKNOWN.',
  'No interpretation of source success as current native, installed, database, Full32 or complete rewrite closure.'
 ]
}
pin = write('ROOT-REVIEW.json', summary)
print(json.dumps({'status': summary['status'], 'review': pin, 'source_before': source_pin,
                  'request_sha256': request_pin['sha256'], 'launch_sha256': launch_pin['sha256']}))
