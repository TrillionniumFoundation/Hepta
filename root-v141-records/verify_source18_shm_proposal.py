import ast, hashlib, json, os, stat, sys
from pathlib import Path

ROOT = Path('/workspace/scratch/dda74a4fae35')
SCOPE = ROOT / 'v132-inspect-machine-entry-r1/successor-r2'
STAGE = Path('/tmp/hia-inspect-source18-evidence-r2-dda7')
OUT = Path('/tmp/hia-root-v141-dda7/ROOT-SOURCE18-SHM-PROPOSAL.json')

def stats(s):
    return dict(device=s.st_dev, inode=s.st_ino, bytes=s.st_size,
                mode=stat.S_IMODE(s.st_mode), nlink=s.st_nlink,
                mtime_ns=s.st_mtime_ns, ctime_ns=s.st_ctime_ns)

def read(p):
    p = Path(p)
    before = p.lstat()
    assert stat.S_ISREG(before.st_mode), str(p)
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        assert stats(os.fstat(fd)) == stats(before), str(p)
        with os.fdopen(fd, 'rb', closefd=False) as f:
            raw = f.read()
        assert stats(os.fstat(fd)) == stats(before) == stats(p.lstat()), str(p)
    finally:
        os.close(fd)
    pin = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
               git_blob=hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
               mode='100755' if before.st_mode & 0o111 else '100644')
    return raw, pin, stats(before)

def obj(p):
    return json.loads(read(p)[0])

def tree(rows):
    root = {}
    for path, row in rows.items():
        d = root
        parts = path.split('/')
        for part in parts[:-1]:
            d = d.setdefault(part, {})
        d[parts[-1]] = (row['mode'], row['git_blob'])
    def finish(d):
        raw = b''
        for name, item in sorted(d.items(), key=lambda x: (x[0] + ('/' if isinstance(x[1], dict) else '')).encode()):
            mode, sha = ('40000', finish(item)) if isinstance(item, dict) else item
            raw += mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(sha)
        return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return finish(root)

assert sys.version_info[:3] == (3, 14, 4)
plan_raw, plan_pin, _ = read(STAGE / 'SOURCE-PLAN.json')
assert plan_pin['git_blob'] == '87a5b6de865ddaec23807db2b9614a66cff457e1'
p = json.loads(plan_raw)
launch = obj(STAGE / 'SOURCE-LAUNCH.json')
assert read(STAGE / 'run_inspect_stages.py')[1] == p['runner']
assert p['runner']['git_blob'] == 'dbd07c1c815641a0a55c4c2fcefef5d41034e369'
assert launch['plan']['pin'] == plan_pin and launch['runner']['pin'] == p['runner']
assert p['active_phase'] == 'source-controls' and p['source_predecessor'] is None
old_stage=SCOPE/'execution-stage-r1'
prior=obj(old_stage/'SOURCE-PLAN.json')
assert set(p)-set(prior)=={'evidence_authority'} and not set(prior)-set(p)
assert {k for k in prior if p[k]!=prior[k]}=={'attempt','contract','runner'}
before=(old_stage/'run_inspect_stages.py').read_text();after=(STAGE/'run_inspect_stages.py').read_text()
def functions(text):return {n.name:ast.get_source_segment(text,n) for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
bf,af=functions(before),functions(after)
assert set(af)-set(bf)=={'evidence_authority'} and not set(bf)-set(af)
assert {n for n in bf if bf[n]!=af[n]}=={'bootstrap','protected_source_fence','execute'}
assert (STAGE/'CONTRACT.md').read_bytes().endswith((old_stage/'CONTRACT.md').read_bytes())
ea=p['evidence_authority'];ep=Path(ea['path'])
assert ep==Path('/dev/shm/hia-inspect-stages-dda7') and ep.resolve(strict=True)==ep
fd=os.open(ep,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 st=os.fstat(fd);named=ep.lstat();assert stat.S_ISDIR(st.st_mode) and st==named
 assert ea==dict(schema='hepta.hia.inspect-fixed-evidence-filesystem.v1',path=str(ep),device=st.st_dev,inode=st.st_ino,mode=stat.S_IMODE(st.st_mode),uid=st.st_uid,gid=st.st_gid)
 space=os.fstatvfs(fd);assert not (space.f_flag&os.ST_NOEXEC) and space.f_bavail*space.f_frsize>=1073741824
finally:os.close(fd)
assert Path(p['attempt']).parent==ep and launch['evidence_authority']==ea

assert p['source_group_order'] == ['source10', 'source8-physical-lease']
assert p['limits'] == dict(cleanup_seconds=3, minimum_free_bytes=1073741824, qualification_seconds=180)
assert not p['automatic_retry'] and p['first_failed_group_or_guard_or_incomplete_cleanup_stops']
assert p['authorized_proposal_counts'] == dict(CLI43=0, Native=0, VM=0, compile=0, original3=0, owners=2, source10=10, source8=8, source_subtests=21)
assert not Path(p['attempt']).exists() and not Path(launch['outer_directory']).exists()
assert not (STAGE / 'NATIVE-PLAN.json').exists()

descriptors = []
def check_descriptors(value):
    if isinstance(value, dict):
        if set(('path', 'pin', 'posix_mode')) <= value.keys():
            raw, got, st = read(value['path'])
            assert got == value['pin'] and st['mode'] == value['posix_mode'], value['path']
            descriptors.append(dict(path=value['path'], pin=got, posix_mode=st['mode']))
        for child in value.values():
            check_descriptors(child)
    elif isinstance(value, list):
        for child in value:
            check_descriptors(child)
check_descriptors(p)
assert len(p['generation_evidence']) == 60
assert len({x['path'] for x in p['generation_evidence']}) == 60
assert sum(x['pin']['bytes'] for x in p['generation_evidence']) == 303083
generation = obj(p['inputs']['generation_result']['path'])
assert generation['status'] == 'GENERATION_ONLY_PASS'
assert (generation['generation_invocations'], generation['check_invocations'], generation['owner_launch_attempts']) == (2, 1, 3)
assert obj(p['inputs']['generation_outer']['path'])['returncode'] == 0
assert obj(p['inputs']['generation_runtime']['path']) == p['runtime']

inodes = {}
for role, descriptor in [('base', 'base_final'), ('source', 'source_final')]:
    root = Path(p[role]['path'])
    capture = obj(p['inputs'][descriptor]['path'])
    assert not capture['errors']
    assert len(capture['files']) == p[role]['files']
    assert tree(capture['files']) == p[role]['tree']
    seen = set()
    inodes[role] = set()
    for folder, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            assert stat.S_ISDIR((Path(folder) / name).lstat().st_mode)
        for name in files:
            seen.add((Path(folder) / name).relative_to(root).as_posix())
    assert seen == set(capture['files'])
    for name, expected in capture['files'].items():
        raw, pin, st = read(root / name)
        assert pin == expected and st == capture['stat'][name], role + '/' + name
        inodes[role].add((st['device'], st['inode']))
        if role == 'source':
            assert st['nlink'] == 1
assert len(inodes['source']) == 3188 and not inodes['source'] & inodes['base']
source_map = obj(p['inputs']['source_map']['path'])
assert source_map == obj(p['inputs']['source_final']['path'])['files']
for path, pin in p['test_source_pins'].items():
    assert read(Path(p['source']['path']) / path)[1] == pin

runtime = p['runtime']
for key in ['executable', 'library']:
    row = runtime[key]
    raw, pin, st = read(row['path'])
    assert pin['bytes'] == row['bytes'] and pin['sha256'] == row['sha256']
    for field in ['device', 'inode', 'mode', 'mtime_ns', 'ctime_ns']:
        assert st[field] == row[field]
argv = launch['argv']
assert argv[:2] == ['/usr/bin/env', '-i']
i = argv.index(runtime['launch_executable'])
assert argv[i:] == [runtime['launch_executable'], '-I', '-B', str(STAGE/'run_inspect_stages.py'), '--execute-stage', 'source-controls', '--plan', str(STAGE/'SOURCE-PLAN.json'), '--plan-sha256', plan_pin['sha256'], '--attempt', p['attempt']]
assert argv[2:i] == ['PATH=/usr/local/bin:/usr/bin:/bin', 'HOME='+p['attempt'], 'LANG=C.UTF-8', 'LC_ALL=C.UTF-8', 'PYTHONDONTWRITEBYTECODE=1', 'TMPDIR=/dev/shm/hia-inspect-stages-dda7/startup-tmp', 'LD_LIBRARY_PATH='+runtime['library_directory']]
for group, count, subcount in [('source10', 10, 12), ('source8-physical-lease', 8, 9)]:
    g = p['groups'][group]
    assert len(g['ids']) == len(set(g['ids'])) == count
    assert len(g['subtest_method_projection']) == g['expected_subtests'] == subcount
    assert set(g['subtest_method_projection']) <= set(g['ids'])
assert p['groups']['source8-physical-lease']['subtest_parameters'] == [dict(route=v) for v in ['step', 'service', 'drive', 'take', 'close', 'retire', 'invoke']] + [dict(lost_return=False), dict(lost_return=True)]
ast.parse(read(STAGE / 'run_inspect_stages.py')[0])
report = dict(schema='hepta.root-source18-proposal-readback.v1',
              status='PASS_STATIC_FULL_PREDECESSOR_AND_SOURCE_READBACK',
              plan=plan_pin, runner=p['runner'], descriptors_checked=len(descriptors),
              generation_evidence_files=60, generation_evidence_bytes=303083,
              base_files=3187, source_files=3188, source_tree=p['source']['tree'],
              full_bytes_modes_and_seven_stats=True,
              private_inodes_unique_nlink1_disjoint_from_base=True,
              runtime_full_files_and_recorded_stats=True,
              stage='source-controls', owners=2, methods=18, subtests=21,
              qualification_seconds=180, cleanup_seconds=3, minimum_free_bytes=1073741824,
              native_plan_absent=True, actual_source18_execution=False, evidence_authority=ea, unchanged_original_functions=len(bf)-3, original_entry_refusal='5fa1f28f2b55a630fcf5d10ce852f0ca1b3e6f49',
              new_product_executions_by_this_reader=0, whole_native=False)
with OUT.open('x') as f:
    f.write(json.dumps(report, sort_keys=True, indent=2)+'\n')
print(json.dumps(dict(status=report['status'], report=str(OUT), pin=read(OUT)[1])))
