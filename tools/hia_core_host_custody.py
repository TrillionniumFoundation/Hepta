"""Explicit complete host binding identity data for the native Core release.

These six Python files are never compiled or executed by the native release.
Their actual bytes are retained in a typed archive solely because the original
eight-field companion manifest binds the full bridge and selection identities.
The HIA decoder admits every record before releasing a selected raw byte view.
"""
from __future__ import annotations

from hashlib import sha1, sha256
import os
from pathlib import Path
import stat
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_PATH = 'examples/hia_bootstrap/core_host_custody.hiadat'
DECODER_SOURCE = 'examples/hia_bootstrap/source_core_host_custody.hepta'
BAG_MAGIC = b'HIAHCB01'
RECORD_MAGIC = b'HIAHCST1'
REQUEST_MAGIC = b'HIAHCQR1'
HEADER = struct.Struct('<8s6Q20s32s20s')
MAX_RAW = 1048576
MAX_PATH = 4095
MAX_ARCHIVE = 16 + 6 * (8 + HEADER.size + MAX_PATH + MAX_RAW)
FAMILIES = ((11, 'compare'), (12, 'integer'), (13, 'unpack'))
KINDS = ((1, 'native'), (2, 'selection'))
ENTRIES = tuple((role, kind, 'hepta/hia_core_' + family + '_' + suffix + '.py')
                for role, family in FAMILIES for kind, suffix in KINDS)


def git_blob(raw):
    return sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).digest()


def encode_record(role, kind, logical_path, raw):
    """Authoring representation; admission is independently implemented in HIA."""
    if (type(role) is not int or type(kind) is not int
            or (role, kind, logical_path) not in ENTRIES or type(raw) is not bytes
            or not 1 <= len(raw) <= MAX_RAW):
        raise ValueError('invalid complete Core host identity input')
    name = logical_path.encode('ascii')
    return (HEADER.pack(RECORD_MAGIC, 1, role, kind, 0o644, len(name), len(raw),
                        git_blob(raw), sha256(raw).digest(), bytes(20)) + name + raw)


def parse_archive(raw):
    """Development inspection only; the installed path uses the HIA decoder."""
    if type(raw) is not bytes or not 16 <= len(raw) <= MAX_ARCHIVE:
        raise ValueError('invalid complete host identity archive extent')
    if struct.unpack_from('<8sQ', raw) != (BAG_MAGIC, 6):
        raise ValueError('invalid complete host identity archive header')
    at, records = 16, []
    for expected_role, expected_kind, expected_path in ENTRIES:
        if len(raw) - at < 8:
            raise ValueError('truncated host identity record extent')
        extent, = struct.unpack_from('<Q', raw, at)
        at += 8
        if not HEADER.size <= extent <= len(raw) - at:
            raise ValueError('host identity record exceeds its archive')
        record = raw[at:at + extent]
        magic, version, role, kind, mode, path_bytes, size, blob, digest, reserved = HEADER.unpack_from(record)
        if (magic != RECORD_MAGIC or version != 1 or role != expected_role
                or kind != expected_kind or mode != 0o644 or reserved != bytes(20)
                or not 1 <= path_bytes <= MAX_PATH or not 1 <= size <= MAX_RAW
                or path_bytes > extent - HEADER.size
                or size != extent - HEADER.size - path_bytes):
            raise ValueError('invalid complete host identity record')
        name = record[HEADER.size:HEADER.size + path_bytes]
        if name != expected_path.encode('ascii'):
            raise ValueError('host identity role and original logical path differ')
        body = record[HEADER.size + path_bytes:]
        if git_blob(body) != blob or sha256(body).digest() != digest:
            raise ValueError('host identity complete byte digest differs')
        records.append(dict(role=role, kind=kind, path=expected_path, mode=mode,
                            bytes=size, git_blob_sha1=blob.hex(), sha256=digest.hex(),
                            raw=body, record_sha256=sha256(record).hexdigest()))
        at += extent
    if at != len(raw):
        raise ValueError('unclaimed host identity archive bytes')
    return records


def metadata(raw):
    return [{key: value for key, value in row.items() if key != 'raw'}
            for row in parse_archive(raw)]


def request(role, kind, raw):
    if (type(role) is not int or type(kind) is not int
            or not any((role, kind) == row[:2] for row in ENTRIES)):
        raise ValueError('unknown host identity selection')
    parse_archive(raw)
    return struct.pack('<8s2Q', REQUEST_MAGIC, role, kind) + raw


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def _capture(path):
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o644
            or not 1 <= before.st_size <= MAX_RAW):
        raise ValueError('host identity source is not one bounded regular 0644 file')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        if identity(os.fstat(fd)) != identity(before):
            raise ValueError('host identity source changed during open')
        chunks = []
        left = before.st_size
        while left:
            part = os.read(fd, min(left, 65536))
            if not part:
                raise ValueError('host identity source shortened during read')
            chunks.append(part)
            left -= len(part)
        if os.read(fd, 1) or identity(os.fstat(fd)) != identity(before):
            raise ValueError('host identity source changed during capture')
    finally:
        os.close(fd)
    if identity(path.lstat()) != identity(before):
        raise ValueError('host identity path changed during capture')
    return b''.join(chunks), identity(before)


def capture_archive(root=ROOT):
    """Capture only the six explicit, current Git objects and recheck all bytes."""
    root = Path(root).resolve(strict=True)
    command = ['git', '-C', str(root)]
    env = dict(os.environ, GIT_NO_LAZY_FETCH='1', GIT_OPTIONAL_LOCKS='0')
    def git(*args):
        return subprocess.check_output(command + list(args), env=env, timeout=30)
    head, tree = (git('rev-parse', suffix).decode('ascii').strip()
                  for suffix in ('HEAD', 'HEAD^{tree}'))
    captures, records = [], []
    for role, kind, name in ENTRIES:
        raw, observed = _capture(root / name)
        blob = git_blob(raw).hex()
        staged = git('ls-files', '--stage', '--', name).decode('ascii')
        expected_stage = '100644 ' + blob + ' 0\t' + name + '\n'
        expected_tree = '100644 blob ' + blob + '\t' + name + '\n'
        if staged != expected_stage or git('ls-tree', 'HEAD', '--', name).decode('ascii') != expected_tree:
            raise ValueError('host identity bytes differ from exact current Git HEAD/index: ' + name)
        captures.append((name, raw, observed, staged))
        records.append(encode_record(role, kind, name, raw))
    archive = struct.pack('<8sQ', BAG_MAGIC, len(records)) + b''.join(
        struct.pack('<Q', len(raw)) + raw for raw in records)
    rows = metadata(archive)
    for name, raw, observed, staged in captures:
        terminal, actual = _capture(root / name)
        if terminal != raw or actual != observed or git('ls-files', '--stage', '--', name).decode('ascii') != staged:
            raise ValueError('host identity input changed at terminal: ' + name)
    if (git('rev-parse', 'HEAD').decode('ascii').strip() != head
            or git('rev-parse', 'HEAD^{tree}').decode('ascii').strip() != tree):
        raise ValueError('host identity Git source changed at terminal')
    return archive, dict(schema='hepta.hia.complete-host-identity-capture.v1',
                         source_head=head, source_tree=tree, records=rows,
                         archive_bytes=len(archive), archive_sha256=sha256(archive).hexdigest(),
                         physical_initial_terminal_identical=True,
                         git_head_index_and_blob_identical=True,
                         compiled_or_executed_host_source=False)
