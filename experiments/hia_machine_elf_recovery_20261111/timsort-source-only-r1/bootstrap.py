"""Pinned stdin-only ELF PowerSort authoring; no native or product execution."""
import base64
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import stat
import sys

PAYLOAD_SHA = 'f91dafe78a7d666d4efdb38a057f338cb2fbbe653edb6cca4c9adb38dac45cdd'
PAYLOAD_BYTES = 412616
ROOT = Path('/home/qian-qi/he26elftimsortr1')
PYTHON = Path('/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python')
PYTHON_SHA = 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493'
B3 = Path('/home/qian-qi/he26v67r2/q/cold.cold/qualification.evidence/B3.image.bin')
B3_SHA = '0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
KEY = 'hia-e26e-desktop-machine-elf-timsort-authoring-r1'
NAMES = {'common.py', 'complete_comparison_trajectories.py', 'complete_comparison_trajectory_inputs.json', 'guardian.py', 'oracle-608.py.txt', 'process_owner_impl.py', 'source-00.py.txt', 'source-01.py.txt', 'source-02.py.txt', 'source-03.py.txt', 'source-04.py.txt', 'source-05.py.txt', 'source-06.py.txt', 'source-07.py.txt', 'source-08.py.txt', 'source_worker.py', 'worker.py'}


def require(okay, text):
    if not okay:
        raise ValueError(text)


def wire(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def duplicate_free(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate input key')
        value[key] = item
    return value


def signature(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def pinned(path, expected, resolve=False):
    selected = path.resolve(strict=True) if resolve else path
    require(selected.is_absolute() and not any(p.is_symlink() for p in (selected, *selected.parents)),
            'ordinary absolute runtime input required')
    before = selected.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
            and before.st_nlink == 1, 'runtime input is not an owned independent regular file')
    fd = os.open(selected, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        require(signature(before) == signature(os.fstat(stream.fileno())), 'runtime input replaced')
        raw = stream.read()
        require(signature(before) == signature(os.fstat(stream.fileno())), 'runtime input changed')
    require(signature(before) == signature(selected.lstat()), 'runtime input identity changed')
    require(sha256(raw).hexdigest() == expected, 'runtime input digest differs')
    if resolve:
        require(path.resolve(strict=True) == selected, 'runtime symlink target changed')
    return str(selected)


def create(path, raw, mode=0o400):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


raw = sys.stdin.buffer.read(1048577)
require(len(raw) == PAYLOAD_BYTES and sha256(raw).hexdigest() == PAYLOAD_SHA, 'stdin identity differs')
payload = json.loads(raw, object_pairs_hook=duplicate_free)
require(payload.get('schema') == 'hepta.hia.machine-elf.sort-authoring-stdin.v1', 'stdin schema differs')
config = payload['config']
require(config['schema'] == 'hepta.hia.machine-elf.sort-authoring-controller.v1'
        and config['root'] == str(ROOT) and config['key'] == KEY
        and config['source'] == '/home/qian-qi/he26elfintegrationr2/source'
        and config['controller_seconds'] == 180 and config['source_generation_seconds'] == 60
        and config['source_count'] == 3932 and config['candidate_count'] == 3936
        and config['staged_source_commit'] == '10de3f0b60b9a31ce4a4428a37e18dca2680c252'
        and config['previous_completed_source_commit'] == '66f00357a9a847c816609238a5d433e5f435023c'
        and config['native_compilation_executed'] is False
        and config['product_tests_executed'] is False
        and config['formal_source_consumer_claimed'] is False,
        'authoring scope or source identity differs')
require(set(payload['files']) == NAMES and set(config['files']) == NAMES, 'private file inventory differs')
contents = {}
for name, entry in payload['files'].items():
    value = base64.b64decode(entry['content_base64'], validate=True)
    pin = {key: entry[key] for key in ('size', 'sha256', 'git_blob_sha1')}
    require(config['files'][name] == pin and len(value) == pin['size']
            and sha256(value).hexdigest() == pin['sha256']
            and sha1(b'blob ' + str(len(value)).encode() + b'\0' + value).hexdigest() == pin['git_blob_sha1'],
            'private file bytes differ')
    contents[name] = value
require(sys.version_info[:3] == (3, 14, 4), 'Python version differs')
python_real = pinned(PYTHON, PYTHON_SHA, resolve=True)
pinned(B3, B3_SHA)
prior_inputs = {
    '/home/qian-qi/he26elfintegrationr2/report.json':
        'be917c1c1702ff4fc9923717f4a3d79944bfc1ff63f357b67996063095e653fe',
    '/home/qian-qi/he26elfintegrationr2/guard/guardian.json':
        '174980724f756690b1fbb2fc0fad5b671e25909b87f93debd07b733fc8c6e7a0',
    '/home/qian-qi/he26elfintegrationr2/source-after-products.json':
        '9cd0f650d20dc3f458e013228a4706c1d746041a63d081169598435b8e6cbcca',
}
for name, digest in prior_inputs.items():
    pinned(Path(name), digest)
home = ROOT.parent
require(not any(p.is_symlink() for p in (home, *home.parents))
        and home.stat().st_uid == os.geteuid() and not home.stat().st_mode & 0o022,
        'owned ordinary home required')
require(not os.path.lexists(ROOT), 'root already exists; reconcile the original job')
space = os.statvfs(home)
require(space.f_bavail * space.f_frsize >= 8 << 30 and space.f_favail >= 100000,
        'original private capacity gate not met')
os.umask(0o077)
ROOT.mkdir(mode=0o700)
ROOT.chmod(0o700)
for name in ('control', 'inputs', 't', 'guard'):
    (ROOT / name).mkdir(mode=0o700)
    (ROOT / name).chmod(0o700)
control = ROOT / 'control'
for name, value in contents.items():
    create(control / name, value)
create(control / 'config.json', wire(config))
create(control / 'stdin-original.json', raw)
require(len(sys.orig_argv) >= 2 and sys.orig_argv[-2] == '-c',
        'actual -c authoring launcher required')
bootstrap_source = sys.orig_argv[-1].encode()
create(control / 'bootstrap-original.py', bootstrap_source)
identities = {str(control / name): sha256(value).hexdigest() for name, value in contents.items()}
identities.update({
    str(control / 'config.json'): sha256(wire(config)).hexdigest(),
    str(control / 'stdin-original.json'): PAYLOAD_SHA,
    str(control / 'bootstrap-original.py'): sha256(bootstrap_source).hexdigest(),
    python_real: PYTHON_SHA, str(B3): B3_SHA,
})
identities.update(prior_inputs)
request = {
    'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
    'command': [str(PYTHON), '-B', str(control / 'worker.py')],
    'cwd': str(ROOT), 'source_identities': identities,
}
request_raw = wire(request)
create(ROOT / 'guard' / 'request.json', request_raw)
create(ROOT / 'bootstrap-receipt.json', wire({
    'schema': 'hepta.hia.machine-elf.sort-authoring-bootstrap.v1',
    'status': 'PREPARED_PENDING_180_SECOND_OWNER', 'key': KEY, 'root': str(ROOT),
    'payload_sha256': PAYLOAD_SHA, 'bootstrap_sha256': sha256(bootstrap_source).hexdigest(),
    'guardian_request_sha256': sha256(request_raw).hexdigest(),
    'native_compilation_executed': False, 'product_tests_executed': False,
    'formal_source_consumer_claimed': False, 'full_git_object_closure_claimed': False,
    'storage_before': {'device': home.stat().st_dev,
        'available_bytes': space.f_bavail * space.f_frsize,
        'available_inodes': space.f_favail},
}))
for directory in (control, ROOT / 'guard', ROOT):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
control.chmod(0o500)
env = {
    'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
    'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUNBUFFERED': '1',
    'TMPDIR': str(ROOT / 't'), 'GIT_CONFIG_NOSYSTEM': '1',
    'GIT_CONFIG_SYSTEM': os.devnull, 'GIT_CONFIG_GLOBAL': os.devnull,
    'GIT_TERMINAL_PROMPT': '0', 'GIT_NO_LAZY_FETCH': '1', 'GIT_OPTIONAL_LOCKS': '0',
    'HEPTA_HIA_TEST_PACKAGING_PYTHON': str(PYTHON),
}
os.execve(str(PYTHON), [str(PYTHON), '-I', '-S', '-B', str(control / 'guardian.py'),
    '--config', str(ROOT / 'guard' / 'request.json'),
    '--config-sha256', sha256(request_raw).hexdigest(),
    '--implementation', str(control / 'process_owner_impl.py')], env)
