"""Exact source-custody functions reused from acknowledged Proof R2 driver.

Original driver Git blob 51a1bfe0c6aea6b686d646ebda4c8a988e8365f4.
These are preparation/observation functions, not product semantic policy.
"""
from __future__ import annotations
from hashlib import sha1, sha256
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile

def digest(raw):
    return sha256(raw).hexdigest()


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def write(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
    if path.read_bytes() != raw:
        raise ValueError('publication readback differs: ' + str(path))


def safe(name):
    if type(name) is not str or not name or '\\' in name or '\x00' in name:
        raise ValueError('ordinary relative source path required')
    p = PurePosixPath(name)
    if p.is_absolute() or '.git' in p.parts or p.as_posix() != name or any(x in ('', '.', '..') for x in p.parts):
        raise ValueError('ordinary relative source path required')
    return name


def metadata(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('regular source file required: ' + str(path))
    raw = path.read_bytes()
    after = path.lstat()
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if any(getattr(before, key) != getattr(after, key) for key in keys) or len(raw) != before.st_size:
        raise ValueError('source changed during read: ' + str(path))
    return {'bytes': len(raw), 'sha256': digest(raw),
            'git_blob_sha': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'git_mode': '100755' if before.st_mode & 0o111 else '100644',
            'posix_mode': format(stat.S_IMODE(before.st_mode), '04o')}


def files(root):
    result = {}
    for folder, dirs, names in os.walk(root):
        dirs[:] = [name for name in dirs if name not in ('.git', '__pycache__')]
        for name in dirs:
            if (Path(folder) / name).is_symlink():
                raise ValueError('source directory symlink refused')
        for name in names:
            path = Path(folder) / name
            result[safe(path.relative_to(root).as_posix())] = metadata(path)
    return result


def admit_git_snapshot(root, observed, tree_records):
    tracked = {}
    for row in tree_records.split(b'\0'):
        if not row:
            continue
        header, name = row.split(b'\t', 1)
        mode, kind, blob = header.decode('ascii').split()
        if kind != 'blob' or mode not in ('100644', '100755'):
            raise ValueError('regular Git blob required')
        path = safe(name.decode('utf-8'))
        if path in tracked:
            raise ValueError('duplicate Git source path')
        tracked[path] = {'git_mode': mode, 'git_blob_sha': blob}
    if set(tracked) != set(observed):
        raise ValueError('Git and actual source inventories differ')
    for path, expected in tracked.items():
        if any(observed[path][key] != value for key, value in expected.items()):
            raise ValueError('Git source bytes or mode differs: ' + path)
    return tracked


def source_identity(row):
    return {'bytes': row['bytes'], 'sha256': row['sha256'],
            'git_blob_sha': row['git_blob_sha'], 'mode': row.get('mode', row.get('git_mode'))}


def apply_files(root, rows):
    for name, row in rows.items():
        target = root / safe(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(row['text'].encode('utf-8')); target.chmod(0o644)
        if source_identity(metadata(target)) != source_identity(row):
            raise ValueError('source publication differs: ' + name)


def export_source(root, output, observed):
    target = output / 'complete-development-source.tar.gz'
    with tarfile.open(target, 'x:gz') as archive:
        for name in sorted(observed):
            archive.add(root / name, arcname='source/' + name, recursive=False)
    with tarfile.open(target, 'r:gz') as archive:
        members = archive.getmembers()
        if len(members) != len(observed):
            raise ValueError('complete source export count differs')
        for member in members:
            name = member.name.removeprefix('source/')
            row = observed[name]
            if (not member.isfile() or member.size != row['bytes']
                    or format(member.mode & 0o777, '04o') != row['posix_mode']
                    or digest(archive.extractfile(member).read()) != row['sha256']):
                raise ValueError('source export bytes or mode differ: ' + name)
    return metadata(target)
