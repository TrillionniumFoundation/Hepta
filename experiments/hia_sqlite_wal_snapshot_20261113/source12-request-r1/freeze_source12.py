"""Freeze WAL snapshot source controls; stdlib AST and byte reads only."""
from pathlib import Path
import ast
import hashlib
import json
import os
import stat
import sys

ROOT = Path(__file__).resolve().parent
DONOR = Path('/home/qq/hia-rewrite-20261113-e26e-r1/varint-native-r3')
SOURCE_ROOT = DONOR / 'source-base'
OUT = ROOT.parent / 'sqlite-wal-snapshot-source12-actual-r1'
EXPECTED_COUNTS = (0, 76, 46, 141, 108, 136, 24, 43, 7, 13, 14, 0)


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def read(path):
    assert path.is_absolute() and path.resolve(strict=True) == path
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 64 << 20
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), 'rb') as f:
        assert identity(os.fstat(f.fileno())) == identity(before)
        raw = f.read()
        assert identity(os.fstat(f.fileno())) == identity(before)
    assert len(raw) == before.st_size and identity(path.lstat()) == identity(before)
    return raw, {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                 'identity': identity(before)}


def create(path, raw):
    with path.open('xb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    os.chmod(path, 0o400)
    body, pin = read(path)
    assert body == raw
    return pin


assert ROOT == Path('/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-wal-snapshot-source-r1')
assert not os.path.lexists(OUT) and not (ROOT / 'REQUEST.json').exists()
assert not (ROOT / 'SOURCE-CATALOG.json').exists()
manifest_raw, manifest_pin = read(DONOR / 'SOURCE-BASE.json')
assert manifest_pin['sha256'] == '024dcc58b18e72b6f093b3de7f1db5112505af6942f9a4bfb108134326c9a023'
manifest = json.loads(manifest_raw)
assert manifest['source_root'] == str(SOURCE_ROOT)
assert manifest['input_count'] == len(manifest['files']) == 1686
assert manifest['bytes'] == 40890650
assert manifest['source_commit'] == '0504beb11c0dae875d8590660c42488b7bc634fb'
assert manifest['source_tree'] == '596ab07e8813e4811a8dca51800cd51eb397aeb2'
catalog = {}
for row in manifest['files']:
    name = row['path']
    assert not name.startswith('/') and '..' not in Path(name).parts and name not in catalog
    body, pin = read(SOURCE_ROOT / name)
    assert all(pin[k] == row[k] for k in ('bytes', 'sha256', 'identity'))
    blob = hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()
    assert blob == row['git_blob']
    assert ('100755' if pin['identity'][2] & 0o111 else '100644') == row['mode']
    catalog[name] = {**pin, 'git_blob': blob}
found = set()
for base, dirs, names in os.walk(SOURCE_ROOT, followlinks=False):
    for name in dirs:
        assert stat.S_ISDIR((Path(base) / name).lstat().st_mode)
    for name in names:
        p = Path(base) / name
        assert stat.S_ISREG(p.lstat().st_mode)
        found.add(str(p.relative_to(SOURCE_ROOT)))
assert found == set(catalog)

runtime = Path(sys.executable).resolve()
runtime_raw, runtime_pin = read(runtime)
assert str(runtime) == '/usr/bin/python3.14'
assert runtime_pin['bytes'] == 7477160
assert runtime_pin['sha256'] == '52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41'
owner = ROOT / 'control/process_owner_impl.py'
assert read(owner)[1]['sha256'] == '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'

test_raw, test_pin = read(ROOT / 'inputs/tests/test_hia_sqlite_wal_snapshot_source.py')
tree = ast.parse(test_raw)
assignments = {target.id: node.value for node in tree.body if isinstance(node, ast.Assign)
               for target in node.targets if isinstance(target, ast.Name)}
names = ast.literal_eval(assignments['EXPECTED_NAMES'])
counts = tuple(json.loads(read(ROOT / 'EXPECTED-VM-COUNTS.json')[0])['counts'])
cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'SQLiteWalSnapshotSourceTests')
assert names == tuple(n.name for n in cls.body if isinstance(n, ast.FunctionDef) and n.name.startswith('test_'))
assert len(names) == len(set(names)) == 12 and counts == EXPECTED_COUNTS and sum(counts) == 608
module = 'tests.hia_sqlite_wal_snapshot_source_r1'
ids = [module + '.SQLiteWalSnapshotSourceTests.' + name for name in names]

# Parse source text, not document(): this section performs no HIA generation,
# Core verification, VM invocation or product-module import.
author_raw, author_pin = read(ROOT / 'inputs/tools/generate_hia_sqlite_wal_snapshot.py')
author_ast = ast.parse(author_raw)
literal = next(node.value for node in author_ast.body if isinstance(node, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == 'SOURCE' for t in node.targets))
source_text = ast.literal_eval(literal)
source_ast = ast.parse(source_text)
functions = [n for n in source_ast.body if isinstance(n, ast.FunctionDef)]
assert len(functions) == 13 and all(len(n.args.args) <= 16 for n in functions)
assert not any(isinstance(n, (ast.Not, ast.Div, ast.FloorDiv)) for n in ast.walk(source_ast))
old_raw, old_pin = read(ROOT / 'reference/retained-generate_hia_sqlite_wal.py')
old_ast = ast.parse(old_raw)
old_literal = next(node.value for node in old_ast.body if isinstance(node, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == 'SOURCE' for t in node.targets))
old_text = ast.literal_eval(old_literal)
def function_text(text, name):
    node = next(n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == name)
    return '\n'.join(text.splitlines()[node.lineno-1:node.end_lineno])
reused = {}
for name in ('checksum_region', 'word', 'control_word'):
    current = function_text(source_text, name)
    assert current == function_text(old_text, name)
    reused[name] = {'bytes': len(current.encode()), 'sha256': hashlib.sha256(current.encode()).hexdigest()}
official = []
for version, size, digest in (
        ('3.46.0',174376,'d4a104b5f3cb807e026a9dbcdb77519358b06b66f76cb6b6ef70e3793379dd62'),
        ('3.53.2',177651,'64d2a6695fbf5d661a9ccb82d160a5fb18698d7175e41828c5ed9428992c7752')):
    full, pin = read(ROOT / 'reference' / ('sqlite-'+version) / 'wal.c.original')
    assert len(full) == size and pin['sha256'] == digest
    excerpts = {}
    for name in ('walIndexRecover','walFindFrame'):
        excerpt, epin = read(ROOT / 'reference' / ('sqlite-'+version) / (name+'.original.c'))
        assert full.count(excerpt) == 1
        excerpts[name] = epin
    official.append({'version':version,'full':pin,'excerpts':excerpts})
assert official[0]['excerpts']['walIndexRecover']['sha256'] == official[1]['excerpts']['walIndexRecover']['sha256']
structure = {'schema':'hia.sqlite.wal-snapshot.static-structure.v1',
             'status':'AST_AND_BYTE_READ_ONLY','source_functions':[n.name for n in functions],
             'complete_reused_functions':reused,'official':official,
             'expected_ids':ids,'expected_vm_by_id':dict(zip(ids,counts)),
             'expected_vm_returns':sum(counts),'actual_HIA_functions_blocks_SSA_caps':'NOT_GENERATED',
             'generated_or_imported_product':False,'executed_tests_VM_C_native':False,
             'author':author_pin,'legacy_author':old_pin}
create(ROOT/'STATIC-STRUCTURE.json',(json.dumps(structure,sort_keys=True,indent=2)+'\n').encode())

fixed_files = []
for directory in ('inputs', 'control', 'reference'):
    for p in sorted((ROOT / directory).rglob('*')):
        if p.name.startswith('.hepta-lock-'):
            continue
        if p.is_dir():
            assert stat.S_ISDIR(p.lstat().st_mode)
            continue
        body, pin = read(p)
        if p.suffix == '.py':
            ast.parse(body)
        fixed_files.append(p)
fixed_files += [ROOT / 'README.md', Path(__file__).resolve(), ROOT / 'SOURCE-ORIGIN.json',
                ROOT / 'EXPECTED-VM-COUNTS.json', ROOT / 'STATIC-STRUCTURE.json']
assert len(fixed_files) == len(set(fixed_files))
environment = {'LANG': 'C', 'LC_ALL': 'C', 'PATH': '', 'PYTHONDONTWRITEBYTECODE': '1',
               'PYTHONHASHSEED': '0', 'PYTHONUNBUFFERED': '1', 'TZ': 'UTC'}
# Source catalog publication happens only after all preceding static checks.
catalog_raw = (json.dumps(catalog, sort_keys=True, indent=2) + '\n').encode()
catalog_pin = create(ROOT / 'SOURCE-CATALOG.json', catalog_raw)
pins = [read(p)[1] for p in fixed_files] + [catalog_pin, runtime_pin]
q = {'schema': 'hia.sqlite-wal-snapshot.source12-request.v1', 'status': 'FROZEN_UNEXECUTED',
     'qualification_seconds': 180, 'cleanup_seconds': 3, 'output_root': str(OUT),
     'source_root': str(SOURCE_ROOT), 'source_catalog': str(ROOT / 'SOURCE-CATALOG.json'),
     'source_commit': manifest['source_commit'], 'source_tree': manifest['source_tree'],
     'source_file_count': 1686, 'source_total_bytes': 40890650,
     'owner_path': str(owner), 'runtime': {'executable': str(runtime), 'version': sys.version},
     'environment': environment, 'test_module': module, 'expected_ids': ids,
     'expected_vm_by_id': dict(zip(ids, counts)), 'expected_vm_returns': 608,
     'inputs': pins, 'actual_source12_runs': 0, 'native_C_SQL_or_network_allowed': False,
     'original_caps': {'assembly_bytes': 1048576, 'assembly_lines': 16384, 'functions': 128,
                       'total_blocks': 1536, 'blocks_per_function': 256, 'operations': 8192,
                       'maximum_ssa': 2047, 'arguments': 16, 'returns': 3},
     'new_source_VM_limits': {'fuel_per_call': 200000, 'allocation_bytes': 1048576, 'depth': 256},
     'output_limits': {'files': 64, 'bytes': 16777216}, 'minimum_free_bytes': 268435456,
     'minimum_free_inodes': 4096, 'old_failures_or_UNKNOWN_reclassified': False,
     'scope': 'New streaming WAL committed-snapshot/page-location source/VM only. No native, C, I/O, locks, checkpoint, SQL, AgentStore activation or installation qualification.'}
request_raw = (json.dumps(q, sort_keys=True, indent=2) + '\n').encode()
request_pin = create(ROOT / 'REQUEST.json', request_raw)
launch = {'schema': 'hia.sqlite-wal-snapshot.source12-launch.v1',
          'command': [str(runtime), '-I', '-S', '-B', str(ROOT / 'control/clean_exec.py'), request_pin['sha256']],
          'cwd': str(ROOT), 'environment': environment, 'request': request_pin, 'additional_timeout': None,
          'automatic_retry': False, 'status': 'UNEXECUTED'}
launch_pin = create(ROOT / 'LAUNCH.json', (json.dumps(launch, sort_keys=True, indent=2) + '\n').encode())
freeze = {'schema': 'hia.sqlite-wal-snapshot.source12-static-freeze.v1', 'status': 'STATIC_ONLY_UNEXECUTED',
          'request': request_pin, 'launch': launch_pin, 'inputs': pins,
          'source_catalog': catalog_pin, 'source_files': 1686, 'source_bytes': 40890650,
          'AST_only': True, 'generator_VM_native_C_SQL_runs': 0, 'expected_methods': 12,
          'expected_VM_returns': 608, 'counts': counts, 'source_donor_manifest': manifest_pin}
freeze_pin = create(ROOT / 'STATIC-FREEZE.json', (json.dumps(freeze, sort_keys=True, indent=2) + '\n').encode())
print(json.dumps({'request': request_pin, 'launch': launch_pin, 'freeze': freeze_pin,
                  'inputs': len(pins), 'expected_methods': 12, 'expected_VM_returns': 608}))
