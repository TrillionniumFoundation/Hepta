"""Exact original full-source/runtime and owner functions."""
from __future__ import annotations
from hashlib import sha1, sha256
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import retained_observer as observer
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
MINIMUM_FREE = 1073741824
LIMITS = {'owner_seconds': 180, 'cleanup_seconds': 3, 'compile_seconds': 20,
          'native_capacity': 1048576, 'vm_steps': 10000000,
          'vm_heap': 8388608, 'vm_call_depth': 128}

def require(value, message):
    if not value:
        raise AssertionError(message)

def pin(raw, mode='100644'):
    return {'bytes': len(raw), 'mode': mode, 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def seven(info):
    return {key: getattr(info, key) for key in FIELDS}

def pairs(items):
    out = {}
    for key, value in items:
        require(type(key) is str and key not in out, 'duplicate/nonstring JSON key')
        out[key] = value
    return out

def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs)

def fixed(row):
    require(type(row) is dict and set(row) == {'path', 'pin', 'stat'}, 'complete actual binding required')
    path = Path(row['path'])
    require(path.is_absolute() and '..' not in path.parts and set(row['stat']) == set(FIELDS),
            'absolute path and complete new stat required')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and seven(before) == row['stat'] == seven(path.lstat())
                and before.st_size == row['pin']['bytes'], 'held/named input identity differs')
        pieces, remaining = [], before.st_size + 1
        while remaining:
            part = os.read(fd, min(1048576, remaining))
            if not part:
                break
            pieces.append(part)
            remaining -= len(part)
        raw = b''.join(pieces)
        require(seven(os.fstat(fd)) == row['stat'] == seven(path.lstat())
                and pin(raw, row['pin']['mode']) == row['pin'], 'actual input changed during full read')
        return raw
    finally:
        os.close(fd)

def metadata(root):
    """Complete fresh path/regular-mode/seven-stat inventory; no omissions."""
    rows = {'.': seven(root.lstat())}
    require(stat.S_ISDIR(rows['.']['st_mode']), 'source root is not an actual directory')
    def walk(directory, prefix):
        for item in sorted(os.scandir(directory), key=lambda value: value.name):
            info = item.stat(follow_symlinks=False)
            name = prefix + item.name
            require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), 'unknown source member type')
            rows[name] = seven(info)
            if stat.S_ISDIR(info.st_mode):
                walk(Path(item.path), name + '/')
            else:
                require(info.st_nlink == 1, 'source must be an independently bound byte copy')
    walk(root, '')
    return rows

def source_guard(request, observer):
    expected = decode(fixed(request['source_map']))
    state = decode(fixed(request['source_state']))
    root = Path(request['source'])
    require(root.is_absolute() and '..' not in root.parts and len(expected) == 3210,
            'complete 3210 source scope required')
    before = metadata(root)
    require(before == state, 'actual complete source identity differs before read')
    # Reuse the exact original reader. It reads every regular source file;
    # this call never replaces contents by a cached digest or receipt.
    actual = observer.snapshot(root)
    require(actual == expected and metadata(root) == before,
            'source bytes/modes/pathset/seven stats changed')
    return {'files': len(actual), 'source_map': request['source_map']['pin'],
            'source_state': request['source_state']['pin'], 'all_bytes_read': True}

def publish(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    require(Path(path).read_bytes() == raw, 'evidence readback differs')

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def capture(path, *, maximum=16 << 20):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'absolute fixed path required')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 <= info.st_size <= maximum,
            'unique bounded regular input required: ' + str(path))
    raw = observer.read_regular(path, maximum=maximum)
    require(seven(info) == seven(path.lstat()), 'input changed around capture')
    row = {'path': str(path), 'pin': pin(raw, '100755' if info.st_mode & 0o111 else '100644'),
           'stat': seven(info)}
    require(fixed(row) == raw, 'complete capture readback differs')
    return row

def checked(row):
    raw = fixed(row)
    require(row['stat']['st_nlink'] == 1 and
            ('100755' if row['stat']['st_mode'] & 0o111 else '100644') == row['pin']['mode'],
            'captured POSIX/Git mode or link count differs')
    return raw

def floor(path):
    value = os.statvfs(path)
    available = value.f_bavail * value.f_frsize
    require(available >= MINIMUM_FREE, 'original actual-filesystem 1GiB floor not met')
    return available

def directory_binding(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'absolute directory authority required')
    rows = []
    for node in reversed([path, *path.parents]):
        info = node.lstat()
        require(stat.S_ISDIR(info.st_mode), 'directory ancestor must not be a link')
        rows.append({'path': str(node), 'dev': info.st_dev, 'ino': info.st_ino,
                     'mode': info.st_mode, 'uid': info.st_uid, 'gid': info.st_gid})
    return rows

def guard_directories(rows):
    for row in rows:
        info = Path(row['path']).lstat()
        require({'path': row['path'], 'dev': info.st_dev, 'ino': info.st_ino,
                 'mode': info.st_mode, 'uid': info.st_uid, 'gid': info.st_gid} == row
                and stat.S_ISDIR(info.st_mode), 'held path authority changed')

def runtime_files_guard(plan):
    value = decode(checked(plan['runtime_map']))
    root = Path(value['root'])
    wanted = {row['path']: row for row in value['files']}
    before = metadata(root)
    require({name for name, st in before.items() if stat.S_ISREG(st['st_mode'])} == set(wanted)
            and len(wanted) == 2496
            and {name for name, st in before.items() if stat.S_ISDIR(st['st_mode'])}
                == {'.', *value['new_directories']}, 'complete restored runtime pathset differs')
    for name, row in wanted.items():
        old = row['new_file_seven_stat']
        expected_stat = dict(zip(('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'),old))
        wanted_pin = {**row['pin'], 'mode': '100755' if row['mode'] & 0o111 else '100644'}
        require(stat.S_IMODE(before[name]['st_mode']) == row['mode'], 'runtime file mode differs')
        checked({'path': str(root / name), 'pin': wanted_pin, 'stat': expected_stat})
    require(metadata(root) == before, 'restored runtime metadata changed during full read')
    return {'files': len(wanted), 'map': plan['runtime_map']['pin'], 'all_bytes_read': True}

def import_runtime(plan):
    sys.path.insert(0, plan['source'])
    from tools import hia_linux_file_roundtrip_cold as runtime
    from tools import hia_selfhost_process_owner as owner
    for module, name in ((runtime, 'tools/hia_linux_file_roundtrip_cold.py'),
                         (owner, 'tools/hia_selfhost_process_owner.py')):
        require(Path(module.__file__).absolute() == Path(plan['source']) / name,
                'runtime/owner module imported outside complete source view')
    return runtime, owner

def environment(plan):
    runtime, _ = import_runtime(plan)
    base = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': plan['attempt'],
        'TMPDIR': str(Path(plan['attempt']) / 'tmp'), 'LANG': 'C.UTF-8',
        'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONHASHSEED': '0'}
    return runtime.runtime_child_environment(base, plan['runtime'])

def admit_owner(returned, directory, command, env, plan):
    raw = observer.complete_receipt(returned, directory / 'OWNER.json')
    request_raw = checked(capture(directory / 'OWNER.json.request.json'))
    request = decode(request_raw)
    owner_pin = decode(checked(plan['source_map']))['tools/hia_selfhost_process_owner.py']['sha256']
    require(request['command'] == command and request['cwd'] == plan['source']
            and request['env'] == env and request['qualification_seconds'] == 180
            and request['cleanup_seconds'] == 3 and request['deadline_ns'] - request['started_ns'] == 180000000000
            and request['implementation_sha256'] == raw['implementation_sha256'] == owner_pin
            and raw['request_sha256'] == hashlib.sha256(request_raw).hexdigest(),
            'actual original owner request/budget/source binding differs')
    cleanup = raw['cleanup']
    require(not cleanup.get('remaining') and not cleanup.get('errors')
            and not cleanup.get('remaining_pids') and cleanup.get('remaining_direct_children') == []
            and not cleanup.get('deadline_exceeded') and cleanup.get('leader_reaped') is True
            and not raw.get('owner_error') and not raw.get('event_overflow') and cleanup['complete'] is True
            and cleanup['observed_echild'] is True, 'owner cleanup incomplete')
    return raw

