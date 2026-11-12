"""Read-only identities for the explicitly developmental v86 experiment."""
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def write(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    with Path(path).open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def identity(s):
    # Reading can legitimately update atime. No other identity field is omitted.
    return [s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid, s.st_gid,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def read(path, maximum=1 << 30, independent=True):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum
            and (not independent or before.st_nlink == 1), 'regular bounded file required: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(identity(os.fstat(fd)) == identity(before), 'file changed before read')
        chunks, left = [], before.st_size
        while left:
            block = os.read(fd, min(left, 1 << 20))
            require(bool(block), 'short read: ' + str(path))
            chunks.append(block); left -= len(block)
        require(identity(os.fstat(fd)) == identity(before) == identity(path.lstat()),
                'file changed during read: ' + str(path))
    finally:
        os.close(fd)
    raw = b''.join(chunks)
    return raw, {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
                 'identity': identity(before)}


def small_pin(path, independent=True):
    raw, record = read(path, independent=independent)
    return {'bytes': record['bytes'], 'sha256': record['sha256']}


def source_snapshot(source, config):
    source = Path(source)
    require(source.is_dir() and not source.is_symlink(), 'private source directory required')
    paths = []
    for base, dirs, files in os.walk(source, followlinks=False):
        for name in dirs:
            require(not (Path(base) / name).is_symlink(), 'source directory link refused')
        paths.extend((Path(base) / name).relative_to(source).as_posix() for name in files)
    expected = config['source_pins']
    require(set(paths) == set(expected) and len(paths) == len(expected), 'physical source namespace differs')
    observed = {}
    for name in sorted(paths):
        raw, record = read(source / name)
        want = expected[name]
        require(record['bytes'] == want['bytes'] and record['sha256'] == want['sha256']
                and stat.S_IMODE(record['identity'][2]) == int(want['mode'][-3:], 8),
                'exact canonical source differs: ' + name)
        observed[name] = record
    return observed


def imported_modules(source, config):
    """Every actual repository import must come from a fully pinned source leaf."""
    result = {}
    for name, module in tuple(sys.modules.items()):
        filename = vars(module).get('__file__') if module is not None else None
        if not isinstance(filename, str):
            continue
        path = Path(filename).resolve()
        try:
            relative = path.relative_to(source).as_posix()
        except ValueError:
            continue
        require(relative.endswith('.py') and relative in config['source_pins'],
                'unbound repository import: ' + str(path))
        actual = small_pin(path); want = config['source_pins'][relative]
        require(actual == {key: want[key] for key in ('bytes', 'sha256')}, 'imported source changed')
        result[name] = {'path': relative, **actual}
    return result


def controls(config_path, config, config_sha):
    require(small_pin(config_path)['sha256'] == config_sha, 'CONFIG does not match frozen request')
    root = Path(config_path).parent
    observed = {}
    for name, expected in config['controls'].items():
        observed[name] = small_pin(root / name)
        require(observed[name] == expected, 'control source differs: ' + name)
    require(small_pin(Path(sys.executable).resolve(), False) == config['python']['binary'],
            'actual Python executable differs')
    require(sys.version == config['python']['version'], 'actual Python version differs')
    return observed


def external_inputs(config):
    result = {}
    for name, record in config['inputs'].items():
        result[name] = small_pin(record['path'])
        require(result[name] == {key: record[key] for key in ('bytes', 'sha256')},
                'sealed previous input differs: ' + name)
    return result


def closed(returned):
    c = returned.get('cleanup', {})
    return (c.get('complete') is True and c.get('observed_echild') is True
            and c.get('leader_reaped') is True and c.get('remaining_direct_children') == []
            and c.get('errors') == [] and c.get('deadline_exceeded') is False)


def owner_readback(directory, returned, command, environment, source, config):
    require(closed(returned), 'owned descendants are not confirmed closed; do not read their output')
    raw, original = read(directory / 'owner.json', 4 << 20)
    value = json.loads(raw)
    request_raw, request_pin = read(directory / 'owner.json.request.json', 1 << 20)
    request = json.loads(request_raw)
    supervisor = returned.get('supervisor_returncode')
    require(type(supervisor) is int and returned == dict(value, supervisor_returncode=supervisor,
                                                        receipt_sha256=original['sha256']),
            'owner returned projection differs')
    require(closed(value) and value['request_sha256'] == request_pin['sha256']
            and request['schema'] == value['schema'] == 'hepta.hia.selfhost-process-owner.v1'
            and request['command'] == command and request['cwd'] == str(source)
            and request['env'] == environment and request['qualification_seconds'] == 180
            and request['cleanup_seconds'] == 3
            and request['stdout_path'] == str(directory / 'stdout.log')
            and request['stderr_path'] == str(directory / 'stderr.log')
            and request['receipt_path'] == str(directory / 'owner.json')
            and request['implementation_sha256'] == config['source_pins']['tools/hia_selfhost_process_owner.py']['sha256'],
            'actual owner request binding differs')
    allowed = {'qualification_started', 'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped'}
    kinds = {e['kind'] for e in value['events']}
    natural = (supervisor == 0 and value.get('owner_error') is None and value['returncode'] == 0
               and not value['timed_out'] and value['exit_observed_before_deadline'] is True
               and not value['event_overflow'] and value['interrupted_signals'] == []
               and value['status'] == 'OWNED_PROCESS_COMPLETED' and value['subreaper_enabled'] is True
               and value['qualification_started'] is True and value['qualification_seconds'] == 180
               and value['cleanup_seconds'] == 3
               and {'qualification_started', 'qualification_exit_observed', 'owned_child_reaped'} <= kinds <= allowed)
    return {'natural': natural, 'receipt': original, 'request': request_pin, 'value': value}


def inventory(root):
    """Called only after closed ECHILD; special leaves are metadata, never opened."""
    records = []
    for base, dirs, names in os.walk(root, followlinks=False):
        for name in list(dirs):
            p = Path(base) / name
            if p.is_symlink():
                dirs.remove(name); names.append(name)
        for name in sorted(names):
            p = Path(base) / name; s = p.lstat()
            row = {'path': p.relative_to(root).as_posix(), 'identity': identity(s)}
            if stat.S_ISREG(s.st_mode):
                # A real publisher intentionally creates stage/destination hardlinks.
                _, pin = read(p, independent=False); row.update(kind='regular', bytes=pin['bytes'], sha256=pin['sha256'])
            elif stat.S_ISLNK(s.st_mode):
                row.update(kind='symlink', target=os.readlink(p))
            else:
                row['kind'] = 'special-metadata-only'
            records.append(row)
    return sorted(records, key=lambda r: r['path'])


INVOKE_FIELDS = {'format', 'runner_sha256', 'input_sha256', 'input_bytes', 'wall_elapsed_ns', 'artifact_sha256', 'case'}
COMPILE_FIELDS = {'produced_bytes', 'produced_sha256', 'produced_image'}

def join_child(folder, label, image, source, config, produced=None):
    raw = (folder / (label + '.receipt.json')).read_bytes()
    receipt = json.loads(raw)
    stdout = (folder / (label + '.stdout.log')).read_bytes()
    child = json.loads(stdout)
    stderr = (folder / (label + '.stderr.log')).read_bytes()
    output = (folder / (label + '.output.bin')).read_bytes()
    request = json.loads((folder / (label + '.request.json')).read_bytes())
    image_raw = image.read_bytes()
    source_raw = (folder / (label + '.input.bin')).read_bytes()
    ignored = INVOKE_FIELDS | (COMPILE_FIELDS if produced is not None else set())
    if {key: value for key, value in receipt.items() if key not in ignored} != child:
        raise ValueError('full child stdout differs from producer receipt')
    if (stderr or child['status'] != 'returned' or child['abi_status'] != 0 or
            child['source_unchanged'] is not True or child['forbidden_compiler_modules_loaded'] or
            source_raw != source or len(output) != 1 << 20 or
            child['source_sha256'] != sha256(source).hexdigest() or
            child['image_sha256'] != sha256(image_raw).hexdigest() or
            child['output_sha256'] != sha256(output).hexdigest() or
            receipt['input_sha256'] != sha256(source).hexdigest() or
            receipt['artifact_sha256'] != sha256(image_raw).hexdigest() or
            receipt['runner_sha256'] != config['source_pins']['tools/hia_selfhost_child.py']['sha256'] or
            request != {'format': 'flat-x86-64', 'image': str(image.resolve()),
                        'image_sha256': sha256(image_raw).hexdigest(),
                        'source': str((folder / (label + '.input.bin')).resolve()),
                        'source_sha256': sha256(source).hexdigest(), 'capacity': 1 << 20,
                        'workspace_size': 1 << 20, 'workspace_fill': 0,
                        'output': str((folder / (label + '.output.bin')).resolve())}):
        raise ValueError('actual child/image/input/full-output binding differs')
    if child['limits'] != {'cpu_seconds': 10, 'address_bytes': 256 << 20, 'core_dumpable': False,
                           'stack_bytes': 8 << 20, 'output_capacity': 1 << 20, 'workspace_bytes': 1 << 20}:
        raise ValueError('original child limits differ')
    count = child['core_u32']
    if type(count) is not int or not 0 < count <= len(output):
        raise ValueError('native producer returned invalid extent')
    if produced is not None:
        body = produced.read_bytes()
        if (body != output[:count] or receipt['produced_image'] != str(produced) or
                receipt['produced_bytes'] != len(body) or receipt['produced_sha256'] != sha256(body).hexdigest()):
            raise ValueError('produced image differs from full native output')
    return {'receipt_sha256': sha256(raw).hexdigest(), 'stdout_sha256': sha256(stdout).hexdigest(),
            'output_sha256': sha256(output).hexdigest(), 'returned_bytes': count,
            'input_sha256': sha256(source).hexdigest(), 'image_sha256': sha256(image_raw).hexdigest(),
            'native_elapsed_ns': child['native_elapsed_ns'], 'wall_elapsed_ns': receipt['wall_elapsed_ns']}
