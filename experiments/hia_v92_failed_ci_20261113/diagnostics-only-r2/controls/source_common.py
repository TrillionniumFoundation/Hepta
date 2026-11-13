"""Bounded source/IO evidence helpers; no remote or product entry points."""
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import stat


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def file_pin(path, maximum=64 << 20, *, system=False):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, 'exact lexical input path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum,
                'bounded regular input required')
        if system:
            require(before.st_nlink >= 1 and not stat.S_IMODE(before.st_mode) & 0o022,
                    'pinned interpreter must have no group/other write access')
        else:
            require(before.st_uid == os.geteuid() and before.st_nlink == 1, 'owned single-link input required')
        count, digest = 0, sha256()
        while True:
            block = stream.read(1 << 20)
            if not block:
                break
            count += len(block)
            require(count <= before.st_size, 'input grew')
            digest.update(block)
        require(count == before.st_size and identity(before) == identity(os.fstat(stream.fileno()))
                and identity(before) == identity(path.lstat()), 'input changed during full read')
    return {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest(), 'identity': identity(before)}


def read(path, maximum=4 << 20):
    pin = file_pin(path, maximum)
    raw = Path(path).read_bytes()
    require(len(raw) == pin['bytes'] and sha256(raw).hexdigest() == pin['sha256']
            and file_pin(path, maximum) == pin, 'original changed across readback')
    return raw


def create(path, value):
    raw = value if isinstance(value, bytes) else wire(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o400)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    require(read(path, max(len(raw), 1)) == raw, 'created original full readback differs')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_inputs(request):
    rows = request['inputs']
    require(type(rows) is list and rows and len(rows) == len({row['path'] for row in rows}),
            'complete unique input set required')
    observed = []
    for row in rows:
        system = row.get('role') == 'exact_runtime'
        require(not system or row['path'] == request['runtime']['executable'], 'runtime role cannot be reassigned')
        pin = file_pin(row['path'], system=system)
        require(pin == {key: row[key] for key in pin}, 'frozen complete input pin differs: ' + row['path'])
        observed.append({**pin, 'role': row['role']})
    return observed


def output_inventory(root):
    """After confirmed ECHILD only; preserve typed synthetic damaged fixtures."""
    root = Path(root)
    records, total = [], 0
    def visit(path):
        nonlocal total
        before = path.lstat()
        require(before.st_uid == os.geteuid(), 'synthetic original owner differs')
        row = {'path': str(path.relative_to(root)), 'identity': identity(before)}
        if stat.S_ISLNK(before.st_mode):
            row.update(kind='symlink_fixture_not_followed', target=os.readlink(path))
        elif stat.S_ISDIR(before.st_mode):
            row['kind'] = 'directory'
            records.append(row)
            for name in sorted(os.listdir(path)):
                visit(path / name)
            require(identity(path.lstat()) == identity(before), 'output directory changed')
            return
        else:
            require(stat.S_ISREG(before.st_mode) and 1 <= before.st_nlink <= 2,
                    'unexpected output type outside synthetic regular/hardlink controls')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            with os.fdopen(fd, 'rb') as stream:
                require(identity(os.fstat(stream.fileno())) == identity(before), 'output changed before read')
                count, digest = 0, sha256()
                while True:
                    block = stream.read(1 << 20)
                    if not block:
                        break
                    count += len(block)
                    total += len(block)
                    require(count <= 8 << 20 and total <= 64 << 20, 'source/IO original byte ceiling exceeded')
                    digest.update(block)
                require(count == before.st_size and identity(os.fstat(stream.fileno())) == identity(before),
                        'output changed during complete read')
            row.update(kind='regular', bytes=count, sha256=digest.hexdigest(),
                       synthetic_hardlink_failure=before.st_nlink == 2)
        require(identity(path.lstat()) == identity(before), 'output changed after read')
        records.append(row)
        require(len(records) <= 4096, 'source/IO original count ceiling exceeded')
    visit(root)
    return {'schema': 'hia.v92.diagnostic-source12.original-inventory.v1', 'files_and_directories': records,
            'bytes_fully_read': total, 'bounded_source_IO_only': True, 'product_executed': False}
