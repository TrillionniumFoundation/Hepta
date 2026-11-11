"""Pinned stdin-only, create-only ELF authoring launcher; no native execution."""
import base64
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import stat
import sys

PAYLOAD_SHA = '356f32c13f65364702c771eb70c5a565ffd31edf8508aa51931a1d5ab9f9ebb2'
PAYLOAD_BYTES = 213963
ROOT = Path('/home/qian-qi/he26elfrecoverr1')
PYTHON = Path('/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python')
PYTHON_SHA = 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493'
B3 = Path('/home/qian-qi/he26v67r2/q/cold.cold/qualification.evidence/B3.image.bin')
B3_SHA = '0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
KEY = 'hia-e26e-desktop-machine-elf-reconstruction-r1'
NAMES = {'common.py', 'worker.py', 'guardian.py', 'process_owner_impl.py',
         'source_package.py', 'generator-r2.py.txt', 'observer.py.txt',
         'public-wrapper.py.txt', 'oracle-608.py.txt'}


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
require(payload.get('schema') == 'hepta.hia.machine-elf.authoring-stdin.v1', 'stdin schema differs')
config = payload['config']
require(config['root'] == str(ROOT) and config['key'] == KEY
        and config['source'] == '/home/qian-qi/he26v67r2/s'
        and config['base_commit'] == '608157e52b0b94e0d294f6b99c4e809869f183aa'
        and config['base_tree'] == 'e7c29a60796a1a78946a2c667aa80df86529e532'
        and config['controller_seconds'] == 180, 'authoring scope or source identity differs')
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
home = ROOT.parent
require(not any(p.is_symlink() for p in (home, *home.parents))
        and home.stat().st_uid == os.geteuid() and not home.stat().st_mode & 0o022,
        'owned ordinary home required')
require(not os.path.lexists(ROOT), 'root already exists; reconcile the original job')
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
    '/home/qian-qi/he26v67r2/s/tools/hia_core_source_identity.py':
        '24d88246cac15b63ec93203cf8789742cd801f7dc12c335aba81becddbbd1a87',
})
request = {
    'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
    'command': [str(PYTHON), '-B', str(control / 'worker.py')],
    'cwd': str(ROOT), 'source_identities': identities,
}
request_raw = wire(request)
create(ROOT / 'guard' / 'request.json', request_raw)
create(ROOT / 'bootstrap-receipt.json', wire({
    'schema': 'hepta.hia.machine-elf.authoring-bootstrap.v1',
    'status': 'PREPARED_PENDING_180_SECOND_OWNER', 'key': KEY, 'root': str(ROOT),
    'payload_sha256': PAYLOAD_SHA, 'bootstrap_sha256': sha256(bootstrap_source).hexdigest(),
    'guardian_request_sha256': sha256(request_raw).hexdigest(),
    'native_compilation_executed': False, 'product_tests_executed': False,
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
