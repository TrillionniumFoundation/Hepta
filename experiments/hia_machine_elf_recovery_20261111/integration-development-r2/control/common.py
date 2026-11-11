"""Create-only ELF integration development controls; no qualification claim."""
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import types

ROOT = Path('/home/qian-qi/he26elfintegrationr2')
SOURCE = ROOT / 'source'
ORIGINAL = Path('/home/qian-qi/he26v67r2/s')
COMPILER = Path('/home/qian-qi/he26v67r2/q/cold.cold/qualification.evidence/B3.image.bin')
PYTHON = Path('/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python')
PYTHON_SHA = 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493'
COMPILER_SHA = '0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
HEAD = '608157e52b0b94e0d294f6b99c4e809869f183aa'
TREE = 'e7c29a60796a1a78946a2c667aa80df86529e532'
PRODUCT_COMMIT = '66f00357a9a847c816609238a5d433e5f435023c'
KEY = 'hia-e26e-desktop-machine-elf-integration-r2'
SOURCE_HELPER = 'tools/hia_core_source_identity.py'
SOURCE_HELPER_SHA = '24d88246cac15b63ec93203cf8789742cd801f7dc12c335aba81becddbbd1a87'
PACKAGE_SHA = 'af243e692ee5b6e9289f6226a0269ae40b02e1b460521471e199dfb8981dca5a'
OWNER_SHA = '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
GUARDIAN_SHA = 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023'
WORKFLOW_SHA = 'f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80'
ORACLE_SHA = 'c77cc453d33058ccbeea9e056191001982892a3e59386958090122ccf487c101'
HIA_SHA = 'af122cb4340ca351a07e3148e699730e4ed652f3c3c4deebdc5837dee693c6e3'
IMAGE_SHA = '6d1ee8d10cd39b3019ab6a643e084b6b2fed991e449d1d74d179bda27a44a12c'
GENERATED = 'examples/hia_bootstrap/machine_elf.hiaasm'
BUDGETS = {'overall': 900, 'source_prepare': 180, 'source_methods': 60,
           'native_build': 40, 'private_guard_comparison': 20,
           'native_methods': 180, 'boundary_methods': 180, 'original_51': 180}
SCHEMA = 'hepta.hia.machine-elf.integration-development-controller.v1'

# Exact previously reviewed read/create/ownership helper bodies.
def require(value, message):
    if not value:
        raise RuntimeError(message)

def wire(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()

def no_duplicates(items):
    result = {}
    for name, value in items:
        require(name not in result, 'duplicate JSON key: ' + name)
        result[name] = value
    return result

def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)

def stable_file(path, expected=None, *, collect=False, executable=False, owned=True,
                resolve=False, max_bytes=None, independent=True):
    requested = Path(path)
    path = requested.resolve(strict=True) if resolve else requested
    require(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)),
            'ordinary absolute input required: ' + str(path))
    before_path = path.lstat()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    parts = [] if collect else None
    digest, count = sha256(), 0
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and (not independent or before.st_nlink == 1)
                and (not owned or before.st_uid == os.geteuid())
                and (not executable or before.st_mode & stat.S_IXUSR)
                and identity(before) == identity(before_path), 'ordinary input identity differs: ' + str(path))
        require(max_bytes is None or before.st_size <= max_bytes, 'input exceeds explicit bound')
        if collect:
            require(before.st_size <= 8 << 20, 'collected input exceeds 8 MiB control bound')
        for part in iter(lambda: stream.read(1 << 20), b''):
            count += len(part)
            require(count <= before.st_size, 'input grew during read')
            digest.update(part)
            if parts is not None:
                parts.append(part)
        require(count == before.st_size and identity(before) == identity(os.fstat(stream.fileno())),
                'input changed during read')
    require(identity(before) == identity(path.lstat()), 'input replaced during read')
    if resolve:
        require(requested.resolve(strict=True) == path, 'input symlink resolution changed')
    checksum = digest.hexdigest()
    require(expected is None or checksum == expected, 'input digest differs: ' + str(path))
    return {'path': str(requested), 'resolved': str(path), 'sha256': checksum,
            'bytes': count, 'identity': list(identity(before))}, (b''.join(parts) if parts is not None else None)

def create(path, raw, mode=0o400):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return stable_file(path, sha256(raw).hexdigest())[0]

def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def read_json(path, expected=None):
    pin, raw = stable_file(path, expected, collect=True)
    return json.loads(raw, object_pairs_hook=no_duplicates), pin

def load_exact(name, path, expected):
    _, raw = stable_file(path, expected, collect=True)
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module

def natural_guardian(value):
    life = value.get('lifecycle', {})
    cleanup = life.get('cleanup', {})
    events = life.get('events', [])
    return (value.get('status') == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
            and value.get('input_identity_preserved') is True
            and life.get('status') == 'OWNED_PROCESS_COMPLETED'
            and life.get('returncode') == 0 and life.get('timed_out') is False
            and life.get('exit_observed_before_deadline') is True
            and life.get('subreaper_enabled') is True and life.get('event_overflow') is False
            and not life.get('interrupted_signals') and not life.get('owner_error')
            and cleanup.get('complete') is True and cleanup.get('observed_echild') is True
            and cleanup.get('leader_reaped') is True and cleanup.get('remaining_direct_children') == []
            and cleanup.get('deadline_exceeded') is False
            and cleanup.get('errors') == [] and isinstance(events, list) and bool(events)
            and all(event.get('kind') in {'qualification_started', 'owned_child_observed',
                        'qualification_exit_observed', 'owned_child_reaped'} for event in events))


def natural_lifecycle(value):
    cleanup = value.get('cleanup', {})
    events = value.get('events', [])
    return (value.get('status') == 'OWNED_PROCESS_COMPLETED'
            and value.get('returncode') == 0 and value.get('timed_out') is False
            and value.get('exit_observed_before_deadline') is True
            and value.get('subreaper_enabled') is True and value.get('event_overflow') is False
            and not value.get('interrupted_signals') and not value.get('owner_error')
            and cleanup.get('complete') is True and cleanup.get('observed_echild') is True
            and cleanup.get('leader_reaped') is True and cleanup.get('remaining_direct_children') == []
            and cleanup.get('deadline_exceeded') is False and cleanup.get('errors') == []
            and isinstance(events, list) and bool(events)
            and all(event.get('kind') in {'qualification_started', 'owned_child_observed',
                        'qualification_exit_observed', 'owned_child_reaped'} for event in events))



def environment():
    return {
        'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
        'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUNBUFFERED': '1',
        'TMPDIR': str(ROOT / 't'), 'GIT_CONFIG_NOSYSTEM': '1',
        'GIT_CONFIG_SYSTEM': os.devnull, 'GIT_CONFIG_GLOBAL': os.devnull,
        'GIT_TERMINAL_PROMPT': '0', 'GIT_NO_LAZY_FETCH': '1',
        'GIT_OPTIONAL_LOCKS': '0',
        'HEPTA_HIA_TEST_PACKAGING_PYTHON': str(PYTHON),
    }



def checked_config(path):
    value, _ = read_json(path)
    require(value.get('schema') == SCHEMA and value.get('root') == str(ROOT)
            and value.get('key') == KEY and value.get('base_commit') == HEAD
            and value.get('base_tree') == TREE and value.get('product_commit') == PRODUCT_COMMIT,
            'ELF integration controller identity differs')
    require(value.get('source') == str(SOURCE) and value.get('original_source') == str(ORIGINAL)
            and value.get('compiler') == str(COMPILER) and value.get('python') == str(PYTHON),
            'fixed original and private paths differ')
    require(value.get('budgets') == BUDGETS and value.get('source_file_count') == 3932,
            'fixed denominators or budgets differ')
    for relative, pin in value['files'].items():
        require(type(relative) is str and relative and Path(relative).name == relative,
                'one-component private control filename required')
        info, _ = stable_file(ROOT / 'control' / relative, pin['sha256'])
        require(info['bytes'] == pin['size'], 'control input length differs')
    require(len(value['products']) == 12, 'complete twelve-product overlay required')
    for relative, pin in value['products'].items():
        require(type(relative) is str and not Path(relative).is_absolute()
                and all(part not in {'', '.', '..'} for part in relative.split('/')),
                'unsafe product path')
        require(pin['file'] in value['files']
                and pin['sha256'] == value['files'][pin['file']]['sha256'],
                'product input is not control-bound')
    stable_file(PYTHON, PYTHON_SHA, executable=True, resolve=True)
    stable_file(COMPILER, COMPILER_SHA)
    stable_file(ORIGINAL / SOURCE_HELPER, SOURCE_HELPER_SHA)
    return value
