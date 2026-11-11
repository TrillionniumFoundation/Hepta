"""Create only a new private integration root, then exec the reviewed guardian."""
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys

os.umask(0o077)
payload = json.loads(sys.stdin.read())
root = Path('/home/qian-qi/he26v66r1')
control, guard = root / 'control', root / 'guard'
python = Path('/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python')
python_report = Path('/home/qian-qi/hia-e26e-python314-linux-completion-r2/python-linux-preparation.json')
python_guard = Path('/home/qian-qi/hia-e26e-python314-linux-completion-r2/guard/guardian.json')
required = {
    'guardian.py': 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023',
    'process_owner_impl.py': '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2',
    'workflow_process.py': 'f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80',
    'prepare_source.py': '4c380898d0ed9979d3bddaf52e71a5cb06e38ea870517e848e1d499d63760b31',
}
assert payload['stable_key'] == 'hia-e26e-desktop-v66-independent-source-prepare-r1'
assert payload['base_head'] == '4161e8d12d87906fde144f039da07908ad52d98a'
assert payload['base_tree'] == '1c6ab0228f012429149997d1f731833739f433eb'
assert set(payload['files']) == set(required) | {'bootstrap.py'}
assert not any(p.is_symlink() for p in (root, *root.parents))
assert not os.path.lexists(root)
parent = root.parent.lstat()
assert stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and not parent.st_mode & 0o022
capacity = os.statvfs(root.parent)
assert capacity.f_bavail * capacity.f_frsize >= 8 << 30
assert capacity.f_favail >= 100000
identities = {
    str(python): 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493',
    str(python_report): 'f834e072227ed59f06d347772b8db126c1910c574e660d66f9d15c1c1ec43967',
    str(python_guard): 'f4115e59f8a6eb22db8a002960fbca83e248e071e5694d89e93371b2262b036d',
    '/home/qian-qi/he26v65r2/q/QUALIFICATION.json': 'd91d279d192a9fe6b6a7521d8732197bdc37f4af3a03a694cfccb15929748b60',
    '/home/qian-qi/he26v65r2/guard/guardian.json': 'ae721abf9b428acedb43fe99d5b072fed1de3299fd331b457410fdb5858519f1',
}
for path, digest in identities.items():
    assert sha256(Path(path).read_bytes()).hexdigest() == digest
for name, item in payload['files'].items():
    assert Path(name).name == name and name not in ('.', '..')
    raw = item['source'].encode()
    assert sha256(raw).hexdigest() == item['sha256'], name
    if name in required:
        assert item['sha256'] == required[name], name
root.mkdir(mode=0o700)
control.mkdir(mode=0o700)
guard.mkdir(mode=0o700)


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


for name, item in payload['files'].items():
    path = control / name
    raw = item['source'].encode()
    create(path, raw)
    assert path.read_bytes() == raw
    identities[str(path)] = item['sha256']
config = {
    'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 1800,
    'command': [str(python), '-B', str(control / 'prepare_source.py')],
    'cwd': str(root), 'source_identities': identities,
}
raw = (json.dumps(config, indent=2, sort_keys=True) + '\n').encode()
create(guard / 'request.json', raw)
intent = {
    'schema': 'hia.desktop-v66-source-preparation-intent.v1',
    'base_head': payload['base_head'], 'base_tree': payload['base_tree'],
    'stable_key': payload['stable_key'], 'root': str(root),
    'tests_requested': False, 'qualification_requested': False,
    'contract_refresh_requested': False, 'whole_native_delivery_qualified': False,
    'bootstrap_pid': os.getpid(), 'bootstrap_ppid': os.getppid(),
    'own_cgroup': Path('/proc/self/cgroup').read_text(),
    'control_files': {name: item['sha256'] for name, item in payload['files'].items()},
}
create(root / 'launch-intent.json', (json.dumps(intent, indent=2, sort_keys=True) + '\n').encode())
for directory in (control, guard, root, root.parent):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
print(json.dumps({'stage': 'V66_SOURCE_PREPARATION_GUARDIAN_LAUNCH',
    'root': str(root), 'guard': str(guard), 'controller_seconds': 1800}), flush=True)
os.execv(sys.executable, [sys.executable, '-B', str(control / 'guardian.py'),
    '--config', str(guard / 'request.json'), '--config-sha256', sha256(raw).hexdigest(),
    '--implementation', str(control / 'process_owner_impl.py')])
