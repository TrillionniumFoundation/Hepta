"""Frozen derive8 file identities and owner admission; no product imports."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

SCHEMA = 'hia.json-wire-leaf05.derive8.v1'
FIELDS = ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns')

def require(value, message):
    if not value:
        raise RuntimeError(message)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result

def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs)

def identity(s):
    return {'dev': s.st_dev, 'ino': s.st_ino, 'mode': stat.S_IMODE(s.st_mode),
            'uid': s.st_uid, 'gid': s.st_gid, 'nlink': s.st_nlink, 'size': s.st_size,
            'mtime_ns': s.st_mtime_ns, 'ctime_ns': s.st_ctime_ns}

def read_regular(path, expected=None):
    path = Path(path).absolute()
    require(path.resolve(strict=True) == path, 'aliased path: ' + str(path))
    for parent in path.parents:
        s = parent.lstat()
        require(stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode),
                'non-directory ancestor: ' + str(parent))
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid in (0, os.geteuid())
                and not stat.S_IMODE(before.st_mode) & 0o022,
                'unsafe regular input: ' + str(path))
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read()
        after = os.fstat(fd)
        require(identity(before) == identity(after) == identity(path.lstat()),
                'input identity changed: ' + str(path))
    finally:
        os.close(fd)
    observed = {'path': str(path), 'bytes': len(raw), 'sha256': digest(raw),
                'identity': identity(before)}
    if expected is not None:
        require(observed == expected, 'pinned input changed: ' + str(path))
    return raw, observed

def save(path, raw):
    path = Path(path)
    require(path.parent.resolve(strict=True) == path.parent.absolute(), 'output parent alias')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    observed, pin = read_regular(path)
    require(observed == raw, 'output readback differs')
    return pin

def save_json(path, value):
    return save(path, wire(value))

def load_request(path, expected_sha):
    raw, pin = read_regular(path)
    require(pin['sha256'] == expected_sha, 'request hash differs')
    request = decode(raw)
    require(request['schema'] == SCHEMA, 'request schema')
    require(Path(sys.executable).resolve(strict=True) == Path(request['runtime']['path']),
            'runtime path differs')
    read_regular(request['runtime']['path'], request['runtime'])
    require(tuple(sys.version_info[:3]) == (3, 14, 4), 'runtime version differs')
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == request['boot_id'],
            'host incarnation differs')
    require(request['qualification_seconds'] == 180 and request['cleanup_seconds'] == 3,
            'original owner budget differs')
    for value in request['inputs']:
        read_regular(value['path'], value)
    template = request['worker_command_template']
    require(request.get('worker_command') is None
            and type(template) is list
            and template == [request['runtime']['path'], '-I', '-S', '-B',
                str(Path(path).parent / 'derive_worker.py'), '--request', str(Path(path)),
                '--sha256', '<REQUEST-SHA256>'], 'literal worker command template differs')
    request['worker_command'] = [*template[:-1], expected_sha]
    materialization = decode(read_regular(request['materialization']['path'],
                                         request['materialization'])[0])
    require(materialization['file_count'] == request['source_file_count']
            and materialization['source_root'] == request['source_root'],
            'materialization binding differs')
    return request, materialization, pin

def source_snapshot(request, materialization):
    root = Path(request['source_root'])
    require(root.resolve(strict=True) == root, 'source root alias')
    wanted = [row['path'] for row in materialization['files']]
    require(len(wanted) == len(set(wanted)) == request['source_file_count'], 'source denominator')
    actual = []
    for p in root.rglob('*'):
        s = p.lstat()
        require(not stat.S_ISLNK(s.st_mode), 'source symlink')
        if stat.S_ISDIR(s.st_mode):
            continue
        require(stat.S_ISREG(s.st_mode), 'source special file')
        actual.append(p.relative_to(root).as_posix())
    require(sorted(actual) == wanted, 'source path population changed')
    return {name: read_regular(root / name)[1] for name in wanted}

def require_source_before(request, materialization, observed):
    for row in materialization['files']:
        pin = observed[row['path']]
        require(pin['bytes'] == row['candidate']['bytes']
                and pin['sha256'] == row['candidate']['sha256']
                and pin['identity'] == row['physical'], 'source-before differs: ' + row['path'])

def require_source_after(request, before, after):
    require(set(before) == set(after), 'source population differs')
    mutable = set(request['generated_write_paths'])
    changes = []
    for name in before:
        a, b = before[name], after[name]
        if name not in mutable:
            require(a == b, 'unapproved source mutation: ' + name)
        else:
            for key in ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink'):
                require(a['identity'][key] == b['identity'][key], 'generated source identity: ' + name)
            if a['sha256'] != b['sha256']:
                changes.append(name)
    require(set(changes) <= set(request['allowed_changed_documents']) == mutable,
            'unapproved derived document delta')
    for name in request['unchanged_generated_paths']:
        require(before[name]['bytes'] == after[name]['bytes']
                and before[name]['sha256'] == after[name]['sha256'], 'unchanged ABI/pool differs')
    return changes

def bind_closed(request, wrapper, owner_path):
    owner_raw, owner_pin = read_regular(owner_path)
    child_request_raw, child_request_pin = read_regular(str(owner_path) + '.request.json')
    owner = decode(owner_raw)
    child = decode(child_request_raw)
    require(type(wrapper) is dict and type(wrapper.get('supervisor_returncode')) is int,
            'bound supervisor return unavailable')
    require(wrapper.get('receipt_sha256') == owner_pin['sha256']
            and wrapper.get('request_sha256') == child_request_pin['sha256']
            and wrapper.get('supervisor_pid') == owner.get('supervisor_pid'),
            'wrapper/owner raw binding differs')
    implementation = request['owner_implementation']['sha256']
    require(owner.get('schema') == child.get('schema') == 'hepta.hia.selfhost-process-owner.v1'
            and owner.get('request_sha256') == child_request_pin['sha256']
            and owner.get('implementation_sha256') == child.get('implementation_sha256') == implementation,
            'owner/request implementation binding differs')
    output = Path(request['output_root'])
    require(child['command'] == request['worker_command']
            and child['cwd'] == request['source_root']
            and child['env'] == request['environment']
            and child['qualification_seconds'] == owner['qualification_seconds'] == 180
            and child['cleanup_seconds'] == owner['cleanup_seconds'] == 3
            and child['deadline_ns'] - child['started_ns'] == 180_000_000_000
            and child['stdout_path'] == str(output / 'child.stdout')
            and child['stderr_path'] == str(output / 'child.stderr')
            and child['receipt_path'] == str(owner_path),
            'owner request context differs')
    cleanup = owner.get('cleanup', {})
    require(owner.get('subreaper_enabled') is True
            and cleanup.get('complete') is True
            and cleanup.get('observed_echild') is True
            and cleanup.get('leader_reaped') is True
            and cleanup.get('remaining_direct_children') == []
            and cleanup.get('errors') == []
            and cleanup.get('deadline_exceeded') is False,
            'current owner descendant closure unconfirmed')
    natural = (wrapper['supervisor_returncode'] == 0
               and wrapper.get('status') == owner.get('status') == 'OWNED_PROCESS_COMPLETED'
               and owner.get('returncode') == 0
               and owner.get('exit_observed_before_deadline') is True
               and owner.get('timed_out') is False
               and owner.get('interrupted_signals') == []
               and owner.get('event_overflow') is False
               and owner.get('owner_error') is None)
    return owner, child, natural
