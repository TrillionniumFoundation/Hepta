"""Source-only controller primitives; no product owner or native image executes here.

The dirfd IO block is copied from the independently reviewed Pretty A2 control.
The copied IO was exercised by the r4b controller. Path checks are observations, not
a claim of a filesystem lock spanning later interpreter execution.
"""
from __future__ import annotations
from contextlib import contextmanager
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import stat

MAX_RECEIPT = 32 << 20

def require(value, message):
    if not value:
        raise RuntimeError(message)

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')

def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)

def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha1': sha1(b'blob ' + str(len(raw)).encode('ascii')
                                 + b'\0' + raw).hexdigest()}

def _directory_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)

@contextmanager
def _checked_parent(path):
    """Retain the complete absolute directory chain without following symlinks."""
    path = Path(path)
    require(path.is_absolute() and path.anchor == '/' and '..' not in path.parts
            and len(path.parts) > 1, 'noncanonical controlled IO path')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptors = [os.open('/', flags)]
    links = []
    def stable():
        for parent, name, child, expected in links:
            require(_directory_identity(os.fstat(child)) == expected
                    and _directory_identity(os.stat(name, dir_fd=parent,
                                                     follow_symlinks=False)) == expected,
                    'controlled IO directory chain changed')
    try:
        for name in path.parts[1:-1]:
            parent = descriptors[-1]
            child = os.open(name, flags, dir_fd=parent)
            descriptors.append(child)
            info = os.fstat(child)
            require(stat.S_ISDIR(info.st_mode), 'controlled IO ancestor is not a directory')
            links.append((parent, name, child, _directory_identity(info)))
        stable()
        yield descriptors[-1], path.parts[-1], stable
        stable()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)

def _read_extent(descriptor, size):
    chunks, remaining = [], size
    while remaining:
        block = os.read(descriptor, min(1 << 20, remaining))
        if not block:
            break
        chunks.append(block)
        remaining -= len(block)
    require(remaining == 0, 'controlled IO original ended before its declared extent')
    return b''.join(chunks)

def _create_bytes(path, raw, mode):
    """Create through the retained parent; read back the same open descriptor."""
    with _checked_parent(path) as (parent, name, stable):
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent)
        try:
            os.fchmod(descriptor, mode)
            remaining = memoryview(raw)
            while remaining:
                count = os.write(descriptor, remaining)
                require(count > 0, 'controlled IO write made no progress')
                remaining = remaining[count:]
            os.fsync(descriptor)
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                    and before.st_nlink == 1 and before.st_size == len(raw),
                    'create-only controlled output identity differs')
            expected = (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                        before.st_gid, before.st_nlink, before.st_size,
                        before.st_mtime_ns, before.st_ctime_ns)
            def same_leaf(info):
                return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                        info.st_gid, info.st_nlink, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns) == expected
            require(same_leaf(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'create-only output name changed')
            stable()
            os.lseek(descriptor, 0, os.SEEK_SET)
            require(_read_extent(descriptor, len(raw)) == raw
                    and same_leaf(os.fstat(descriptor))
                    and same_leaf(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'create-only descriptor readback differs')
            stable()
        finally:
            os.close(descriptor)

def _create_directory(path, mode=0o700):
    with _checked_parent(path) as (parent, name, stable):
        os.mkdir(name, mode=mode, dir_fd=parent)
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                             | os.O_CLOEXEC, dir_fd=parent)
        try:
            observed = os.fstat(descriptor)
            require(stat.S_ISDIR(observed.st_mode) and observed.st_uid == os.geteuid()
                    and not stat.S_IMODE(observed.st_mode) & 0o077
                    and _directory_identity(os.stat(name, dir_fd=parent,
                                                     follow_symlinks=False))
                        == _directory_identity(observed),
                    'create-only private directory differs')
            stable()
        finally:
            os.close(descriptor)

def read(path, maximum=MAX_RECEIPT, *, system_binary=False):
    with _checked_parent(path) as (parent, name, stable):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                             | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode), 'regular input required: ' + str(path))
            if system_binary:
                require(before.st_uid in (0, os.geteuid()) and before.st_nlink >= 1
                        and not stat.S_IMODE(before.st_mode) & 0o022,
                        'runner tool is writable or has unexpected ownership')
            else:
                require(before.st_uid == os.geteuid() and before.st_nlink == 1,
                        'owned single-link input required')
            require(0 <= before.st_size <= maximum, 'bounded original input required')
            require(identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                        == identity(before), 'input changed before reading')
            stable()
            raw = _read_extent(descriptor, before.st_size)
            require(identity(os.fstat(descriptor)) == identity(before)
                    and identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                        == identity(before), 'input changed during reading')
            stable()
            return raw, {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
                         'identity': list(identity(before))}
        finally:
            os.close(descriptor)

def create(path, raw):
    _create_bytes(path, raw, 0o400)
    copied, record = read(path, max(len(raw), 1))
    require(copied == raw, 'create-only original readback differs')
    return record

def save(path, value):
    return create(path, wire(value))


def fixed_read(path, expected):
    raw, observed = read(path, max(1, expected['bytes']))
    require(observed['bytes'] == expected['bytes']
            and observed['sha256'] == expected['sha256']
            and ('git_blob_sha1' not in expected
                 or pin(raw)['git_blob_sha1'] == expected['git_blob_sha1']),
            'fixed controlled source bytes differ: ' + str(path))
    return raw, observed

def _namespace(source):
    root = source.lstat()
    require(stat.S_ISDIR(root.st_mode), 'source root is not an ordinary directory')
    expected_root = _directory_identity(root)
    files, directories = set(), set()
    def failed(error):
        raise error
    for directory, names, leaves in os.walk(source, followlinks=False, onerror=failed):
        relative = Path(directory).relative_to(source)
        if relative == Path('.'):
            require('.git' not in leaves, 'checkout .git must be an ordinary directory')
            if '.git' in names:
                require(stat.S_ISDIR((source / '.git').lstat().st_mode),
                        'checkout .git is not an ordinary directory')
                names.remove('.git')
        for name in names:
            path = Path(directory) / name
            require(stat.S_ISDIR(path.lstat().st_mode),
                    'source directory is a link or special')
            directories.add(path.relative_to(source).as_posix())
        for name in leaves:
            files.add((Path(directory) / name).relative_to(source).as_posix())
    require(_directory_identity(source.lstat()) == expected_root,
            'source root identity changed during namespace observation')
    return files, directories, expected_root

def snapshot(source, rows):
    expected_files = {row['path'] for row in rows}
    expected_directories = set()
    for name in expected_files:
        parts = name.split('/')
        expected_directories.update('/'.join(parts[:index])
                                    for index in range(1, len(parts)))
    namespace_before = _namespace(source)
    require(namespace_before[:2] == (expected_files, expected_directories),
            'complete source namespace differs')
    result = []
    for row in rows:
        path = source / row['path']
        raw, observed = read(path, max(1, row['size']))
        actual = pin(raw)
        expected_mode = 0o644 if row['mode'] == '100644' else 0o755
        require(observed['bytes'] == row['size']
                and stat.S_IMODE(observed['identity'][2]) == expected_mode
                and actual['git_blob_sha1'] == row['git_blob_sha1']
                and ('sha256' not in row or actual['sha256'] == row['sha256']),
                'fixed source bytes or mode differ: ' + row['path'])
        result.append({'path': row['path'], 'mode': row['mode'],
                       **actual, 'identity': observed['identity']})
    require(_namespace(source) == namespace_before,
            'source namespace changed while reading all members')
    return result

def measurements(document, assembly):
    functions = []
    for function in document["functions"]:
        values = list(function["params"])
        edges, blocks, operands, returns = [], [], [], []
        for block in function["blocks"]:
            values.extend(block["params"])
            blocks.append(len(block["params"]))
            for operation in block["ops"]:
                values.extend(operation["out"])
                operands.append(len(operation["args"]))
            term = block["term"]
            if term["op"] == "jump":
                edges.append(len(term["args"]))
            elif term["op"] == "branch":
                edges.extend((len(term["then"]["args"]), len(term["else"]["args"])))
            elif term["op"] == "ret":
                returns.append(len(term["values"]))
        names = {value["name"] for value in values}
        indices = [int(name[1:]) for name in names
                   if type(name) is str and name.startswith("v")
                   and name[1:].isascii() and name[1:].isdecimal()]
        functions.append({
            "name": function["name"], "blocks": len(function["blocks"]),
            "operations": sum(len(block["ops"]) for block in function["blocks"]),
            "unique_ssa_names": len(names),
            "function_parameters": len(function["params"]),
            "max_block_parameters": max(blocks, default=0),
            "max_edge_arguments": max(edges, default=0),
            "max_operation_arguments": max(operands, default=0),
            "max_return_arguments": max(returns, default=0),
            "largest_numeric_ssa_index_diagnostic": max(indices, default=None),
        })
    summary = {
        "source_bytes": len(assembly), "source_lines": len(assembly.splitlines()),
        "functions": len(functions), "blocks": sum(row["blocks"] for row in functions),
        "max_blocks_per_function": max((row["blocks"] for row in functions), default=0),
        "operations": sum(row["operations"] for row in functions),
        "max_unique_ssa_names_per_function": max(
            (row["unique_ssa_names"] for row in functions), default=0),
    }
    for name in ("function_parameters", "max_block_parameters", "max_edge_arguments",
                 "max_operation_arguments", "max_return_arguments"):
        output = "max_function_parameters" if name == "function_parameters" else name
        summary[output] = max((row[name] for row in functions), default=0)
    return summary, functions


