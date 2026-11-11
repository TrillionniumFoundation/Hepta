"""Create one private public-file ingress job and exec the original guardian."""
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path('/home/qian-qi/he26v66devr2-ingress-r1')
PYTHON = Path('/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python')
STABLE_KEY = 'hia-e26e-desktop-fdb40f-public-source-ingress-r1'
required = {
    'download_public_source.py': '8af5f677e1ff95d6fe27d29fbb5580f93c73e7957e5787b2141aa2373ceec538',
    'old-input-pins.json': 'abff0927d89f94bfdac0d600315e45dca0ceb719b7d3c28c0af17a7e270c1ffc',
    'guardian.py': 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023',
    'process_owner_impl.py': '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2',
    'workflow_process.py': 'f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80',
}
os.umask(0o077)
raw = sys.stdin.buffer.read(1048577)
assert len(raw) <= 1048576
payload = json.loads(raw)
assert payload['stable_key'] == STABLE_KEY
assert set(payload['files']) == set(required) | {'bootstrap.py'}
assert not os.path.lexists(ROOT)
assert not any(p.is_symlink() for p in (ROOT, *ROOT.parents))
parent = ROOT.parent.lstat()
assert stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and not parent.st_mode & 0o022
capacity = os.statvfs(ROOT.parent)
assert capacity.f_bavail * capacity.f_frsize >= 8 << 30 and capacity.f_favail >= 100000


def read_pin(path, expected):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        before = os.fstat(f.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
        raw = f.read()
        after = os.fstat(f.fileno())
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    bound = path.lstat()
    assert (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) == (
        bound.st_dev, bound.st_ino, bound.st_size, bound.st_mtime_ns, bound.st_ctime_ns)
    assert sha256(raw).hexdigest() == expected


for name, item in payload['files'].items():
    assert Path(name).name == name
    assert sha256(item['source'].encode()).hexdigest() == item['sha256']
    if name in required:
        assert item['sha256'] == required[name]
pins = json.loads(payload['files']['old-input-pins.json']['source'])
assert len(pins) == 12
for path, expected in pins.items():
    read_pin(Path(path), expected)
assert Path(sys.executable).resolve() == PYTHON.resolve()
read_pin(PYTHON.resolve(), 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493')
ROOT.mkdir(mode=0o700)
for name in ('control', 'guard', 'inputs'):
    (ROOT/name).mkdir(mode=0o700)


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    assert path.read_bytes() == raw


identities = dict(pins)
for name, item in payload['files'].items():
    path = ROOT/'control'/name
    create(path, item['source'].encode())
    identities[str(path)] = item['sha256']
config = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 900,
          'command': [str(PYTHON), '-B', str(ROOT/'control/download_public_source.py')],
          'cwd': str(ROOT), 'source_identities': identities}
config_raw = (json.dumps(config, sort_keys=True, indent=2)+'\n').encode()
create(ROOT/'guard/request.json', config_raw)
intent = {'schema': 'hia.fixed-public-source-ingress-intent.v1', 'stable_key': STABLE_KEY,
          'source_package_commit': 'fdb40f161907d0c4722ea14ca933945d33ec4990',
          'private_root': str(ROOT), 'controller_seconds': 900, 'maximum_get_attempts': 2,
          'control_files': {name: item['sha256'] for name, item in payload['files'].items()},
          'capacity_before': {'available_bytes': capacity.f_bavail*capacity.f_frsize,
                              'free_inodes': capacity.f_favail, 'device': parent.st_dev},
          'source_preparation_started': False, 'tests_requested': False,
          'complete_git_object_closure': False, 'whole_native_delivery_qualified': False,
          'older_binary_upload_commit_or_abort_requested': False,
          'outer_guardian_acceptance_required': True,
          'hard_sigkill_or_host_loss_cleanup_claimed': False}
create(ROOT/'launch-intent.json', (json.dumps(intent, sort_keys=True, indent=2)+'\n').encode())
for path in (ROOT/'inputs', ROOT/'guard', ROOT/'control', ROOT, ROOT.parent):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
print(json.dumps({'stage': 'FIXED_PUBLIC_INGRESS_GUARDIAN_LAUNCH', 'root': str(ROOT)}), flush=True)
os.execv(str(PYTHON), [str(PYTHON), '-B', str(ROOT/'control/guardian.py'),
                     '--config', str(ROOT/'guard/request.json'),
                     '--config-sha256', sha256(config_raw).hexdigest(),
                     '--implementation', str(ROOT/'control/process_owner_impl.py')])
