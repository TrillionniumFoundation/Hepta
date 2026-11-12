"""Root one-shot review and invocation of the frozen finite source controls."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path('/workspace/scratch/e26ed3e2edcf/core-numeric-source83-generator-repair-r2')
OUT = Path('/workspace/scratch/e26ed3e2edcf/root/fixed-transport-source4-r2-root')
EXPECTED = '232ea939cbe253c5e9265d34d610b10ec7740b1775f63fe5a55ccbb0c41f26cf'

def digest(path, expected=None):
    path = Path(path)
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1, str(path)
    data = path.read_bytes()
    after = path.lstat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid,
                          s.st_gid, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    assert identity(before) == identity(after), str(path)
    row = dict(path=str(path), size=len(data), sha256=hashlib.sha256(data).hexdigest(),
        git_blob_sha1=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest(),
        mode=stat.S_IMODE(before.st_mode), inode=before.st_ino, device=before.st_dev,
        uid=before.st_uid, gid=before.st_gid, nlink=before.st_nlink,
        mtime_ns=before.st_mtime_ns, ctime_ns=before.st_ctime_ns)
    if expected is not None:
        for key, value in expected.items():
            assert key in row and row[key] == value, (str(path), key)
    return data, row

def save(name, data):
    with (OUT/name).open('xb') as stream:
        stream.write(data)

request_raw, request_pin = digest(ROOT/'SOURCE4-REQUEST.json')
assert request_pin['sha256'] == EXPECTED
request = json.loads(request_raw)
launch_raw, launch_pin = digest(ROOT/'SOURCE4-LAUNCH.json')
assert launch_pin['sha256'] == 'fa7104d2c9bb6489bc0c569a680727993b8fda6de35d71b27abdd41dac374832'
launch = json.loads(launch_raw)
assert launch['request'] == request_pin
assert request['qualification_seconds'] == 180 and request['cleanup_seconds'] == 3
assert request['expected_methods'] == 4 and len(set(request['expected_ids'])) == 4
assert request['original_generator_denominator'] == 62
assert request['original_source_method_denominator'] == 83
assert request['runtime_scope'] == 'Observed local CPython 3.12.14 only; not remote3.14.4 qualification'
assert request['runtime_version'] == sys.version
assert str(Path(sys.executable).resolve()) == request['runtime']['path']
rows = []
for group in ('control_pins', 'input_pins'):
    seen = set()
    for expected in request[group]:
        assert expected['path'] not in seen
        seen.add(expected['path'])
        _, row = digest(expected['path'], expected)
        rows.append(dict(group=group, **row))
for key in ('owner', 'runtime', 'source_record'):
    digest(request[key]['path'], request[key])
assert len(request['input_pins']) == 1685 and len(request['control_pins']) == 6
assert request['physical_source_files'] == 1653
source = Path(request['source_root'])
observed = {str(p) for p in source.rglob('*') if p.is_file()}
expected_source = {r['path'] for r in request['input_pins'] if r['path'].startswith(str(source)+'/')}
assert observed == expected_source and len(observed) == 1653
assert not os.path.lexists(request['actual_root'])
assert not os.path.lexists(request['prelaunch_hold'])
assert launch['command'] == [request['runtime']['path'], '-I', '-S', '-B',
    str(ROOT/'control/launch_source4.py'), str(ROOT/'SOURCE4-REQUEST.json'), EXPECTED]
assert launch['cwd'] == str(ROOT)
assert request['minimum_available_bytes'] == 536870912
assert request['minimum_available_inodes'] == 4096
space = os.statvfs(ROOT)
assert space.f_bavail*space.f_frsize >= request['minimum_available_bytes']
assert space.f_favail >= request['minimum_available_inodes']
OUT.mkdir(exist_ok=False)
review = dict(schema='hepta.hia.root-fixed-transport-source4-review.v1',
    status='STATIC_CLEAR_ONE_FROZEN_REQUEST', request=request_pin, launch=launch_pin,
    runtime_scope=request['runtime_scope'], verified_pin_count=len(rows),
    source_files=1653, expected_methods=4, qualification_seconds=180, cleanup_seconds=3,
    closure_correction='Independent bound ECHILD closure precedes natural-zero check; unknown skips all child-body traversal.',
    original_62_generator_83_method_request_executed=False, native_executed=False,
    assembler_oracle_executed=False, available_bytes=space.f_bavail*space.f_frsize,
    available_inodes=space.f_favail, pins=rows)
save('PRETRIGGER.json', (json.dumps(review, sort_keys=True, indent=2)+'\n').encode())
save('REQUEST.original.json', request_raw)
save('LAUNCH.original.json', launch_raw)
save('INVOCATION-INTENT.json', (json.dumps(dict(command=launch['command'],cwd=launch['cwd'],
    one_invocation=True, status='INTENT_ONLY'), sort_keys=True, indent=2)+'\n').encode())
print(json.dumps({'static_review':'PASS','verified_pins':len(rows),'launching_once':True}), flush=True)
os.chdir(launch['cwd'])
os.execv(launch['command'][0], launch['command'])
