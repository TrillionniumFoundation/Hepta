"""Private complete-leaf ELF sort authoring controls; no native qualification."""
from hashlib import sha1, sha256
import json
import os
from pathlib import Path, PurePosixPath
import stat
import types

ROOT = Path('/home/qian-qi/he26elftimsortr1')
SOURCE = Path('/home/qian-qi/he26elfintegrationr2/source')
PYTHON = Path('/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python')
PYTHON_SHA = 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493'
COMPILER = Path('/home/qian-qi/he26v67r2/q/cold.cold/qualification.evidence/B3.image.bin')
COMPILER_SHA = '0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
KEY = 'hia-e26e-desktop-machine-elf-timsort-authoring-r1'
PREVIOUS_REPORT = Path('/home/qian-qi/he26elfintegrationr2/report.json')
PREVIOUS_REPORT_SHA = 'be917c1c1702ff4fc9923717f4a3d79944bfc1ff63f357b67996063095e653fe'
PREVIOUS_GUARD = Path('/home/qian-qi/he26elfintegrationr2/guard/guardian.json')
PREVIOUS_GUARD_SHA = '174980724f756690b1fbb2fc0fad5b671e25909b87f93debd07b733fc8c6e7a0'
PREVIOUS_SNAPSHOT = Path('/home/qian-qi/he26elfintegrationr2/source-after-products.json')
PREVIOUS_SNAPSHOT_SHA = '9cd0f650d20dc3f458e013228a4706c1d746041a63d081169598435b8e6cbcca'
OWNER_SHA = '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
GUARDIAN_SHA = 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023'
ORACLE_SHA = 'c77cc453d33058ccbeea9e056191001982892a3e59386958090122ccf487c101'
GENERATED = 'examples/hia_bootstrap/machine_elf.hiaasm'
SOURCE_COUNT = 3932
NEW_COUNT = 3936
OVERLAYS = (
    'tools/generate_hia_machine_elf.py',
    'hepta/hia_machine_elf_native.py',
    'tools/build_hia_machine_elf.py',
    'hepta/hia_program_native.py',
    'tests/test_hia_machine_elf_native.py',
    'tools/hia_machine_elf_sort_control.py',
    'tools/hia_machine_elf_sort_algorithm.py',
    'tools/hia_machine_elf_sort_comparison.py',
    'hepta/hia_machine_elf_sort_observation.py',
)
NEW_PATHS = frozenset(OVERLAYS[5:])
LIMITS = {'source_bytes': 1048576, 'lines': 16384, 'functions': 128,
          'blocks': 1536, 'max_blocks_per_function': 256, 'ops': 8192,
          'max_ssa_index': 2047}

# Exact existing supply/integration helper bodies; task constants are separate.

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
        'TMPDIR': str(ROOT / 't'),
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_SYSTEM': os.devnull,
        'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_TERMINAL_PROMPT': '0',
        'GIT_NO_LAZY_FETCH': '1', 'GIT_OPTIONAL_LOCKS': '0',
        'HEPTA_HIA_TEST_PACKAGING_PYTHON': str(PYTHON),
    }


def checked_relative(value):
    require(type(value) is str and value and '\0' not in value and '\\' not in value,
            'ordinary source path required')
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value
            and all(part not in ('', '.', '..', '.git') for part in path.parts),
            'unsafe source member path')
    return value


def checked_config():
    value, _ = read_json(ROOT / 'control' / 'config.json')
    require(value.get('schema') == 'hepta.hia.machine-elf.sort-authoring-controller.v1'
            and value.get('root') == str(ROOT) and value.get('source') == str(SOURCE)
            and value.get('key') == KEY and value.get('controller_seconds') == 180,
            'fixed authoring configuration differs')
    require(value.get('source_count') == SOURCE_COUNT
            and value.get('candidate_count') == NEW_COUNT
            and value.get('expected_generated_functions') == 62
            and value.get('limits') == LIMITS,
            'fixed source denominator or original limits differ')
    require(set(value['overlays']) == set(OVERLAYS)
            and set(value['new_paths']) == NEW_PATHS,
            'exact nine-source candidate delta differs')
    for name, pin in value['files'].items():
        require(type(name) is str and Path(name).name == name and name not in ('', '.', '..'),
                'single-component control filename required')
        info, raw = stable_file(ROOT / 'control' / name, pin['sha256'], collect=True)
        require(info['bytes'] == pin['size']
                and sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
                    == pin['git_blob_sha1'], 'control input identity differs')
    for name, pin in value['overlays'].items():
        checked_relative(name)
        require({key: pin[key] for key in ('size', 'sha256', 'git_blob_sha1')} == value['files'][pin['file']],
                'overlay is not a fixed control input')
    return value
