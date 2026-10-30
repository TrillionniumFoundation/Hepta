#!/usr/bin/env python3
"""Package the preserved 3533 observation without executing or copying a repository."""
from hashlib import sha1, sha256
from pathlib import Path
import io
import json
import os
import stat
import subprocess
import tarfile
import time

ROOT = Path('/workspace/scratch/f0c12f106c89')
HERE = Path(__file__).resolve().parent
REPO = ROOT / 'hepta-integration'
HEAD = '3533b95c53d23de2d22c91fcc05cb601b8448eb3'
ARCHIVE = HERE / 'p3-p6-json-checkpoint-3533.tar.xz'


def need(ok, why):
    if not ok:
        raise ValueError(why)


def git(*args, input=None):
    return subprocess.check_output(['git', '--no-replace-objects', *args], cwd=REPO,
        input=input, env={**os.environ, 'GIT_NO_LAZY_FETCH': '1', 'GIT_OPTIONAL_LOCKS': '0'})


def regular(path):
    path = Path(path)
    need(all(not p.is_symlink() for p in (path, *path.parents)), 'symlink input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= 16 * 1024 * 1024, 'bounded regular input required')
        chunks, count = [], 0
        while True:
            block = os.read(fd, min(65536, 16 * 1024 * 1024 + 1 - count))
            if not block:
                break
            chunks.append(block); count += len(block)
            need(count <= 16 * 1024 * 1024, 'input grew')
        after = os.fstat(fd)
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
             == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'input changed')
        data = b''.join(chunks)
        need(len(data) == before.st_size, 'input length changed')
        return data
    finally:
        os.close(fd)


def main():
    started = time.monotonic_ns()
    need(not ARCHIVE.exists() and not (HERE / 'MANIFEST.json').exists(), 'new archive attempt required')
    formal = ROOT / 'p3-p6-json-checkpoint-integrated-launches-20261030'
    report = json.loads(regular(formal / 'run/checkpoint/qualification/qualification.json'))
    need(report['expected_head'] == HEAD and report['ok'] is True and not report['development_only'], 'formal source differs')
    tree = git('rev-parse', HEAD + '^{tree}').decode().strip()
    need(tree == report['source_before']['tree'], 'original tree differs')
    source_ledger = report['source_before']['files']
    object_types = {HEAD: 'commit', tree: 'tree'}
    entries = {}
    for row in git('ls-tree', '-r', '-t', '-z', tree).split(b'\0'):
        if not row:
            continue
        metadata, name = row.split(b'\t', 1)
        mode, kind, object_id = metadata.decode().split()
        name = name.decode()
        if kind == 'tree':
            object_types[object_id] = kind
        elif name in source_ledger:
            need(kind == 'blob' and mode in {'100644', '100755'}, 'nonregular profile source')
            object_types[object_id] = kind
            entries[name] = {'mode': mode, 'blob': object_id}
    need(set(entries) == set(source_ledger), 'source closure missing from raw tree')
    ids = sorted(object_types)
    raw = git('cat-file', '--batch', input=('\n'.join(ids) + '\n').encode())
    objects, offset = {}, 0
    for object_id in ids:
        end = raw.index(b'\n', offset)
        fields = raw[offset:end].decode().split()
        need(len(fields) == 3 and fields[:2] == [object_id, object_types[object_id]], 'raw object header differs')
        size = int(fields[2]); offset = end + 1
        data = raw[offset:offset + size]; offset += size
        need(size >= 0 and len(data) == size and raw[offset:offset + 1] == b'\n', 'raw object length differs')
        offset += 1
        need(sha1((object_types[object_id] + ' ' + str(size)).encode() + b'\0' + data).hexdigest() == object_id,
             'raw Git object hash differs')
        objects[object_id] = data
    need(offset == len(raw), 'extra Git batch bytes')
    need(all(sha256(objects[row['blob']]).hexdigest() == source_ledger[name] for name, row in entries.items()),
         'source ledger differs from original blobs')
    inputs = {}
    for prefix, base in (
        ('formal', formal),
        ('development', ROOT / 'p3-p6-next2-development-20261030'),
        ('independent-peer-audit', ROOT / 'p1-p2-scoped-cleanup-integrated-launches-20261030/peer-p3-readback')):
        need(base.is_dir(), 'missing retained input directory')
        for path in sorted(base.rglob('*')):
            need(not path.is_symlink(), 'retained symlink')
            if path.is_file():
                inputs[prefix + '/' + path.relative_to(base).as_posix()] = path
    for name in ('INDEX.json', 'README.md', 'AUDIT_EXECUTION.json', 'audit.stdout', 'audit.stderr', 'build_evidence.py'):
        inputs['local-audit/' + name] = HERE / name
    manifest = {'schema': 'hepta.cpp-json-checkpoint.3533-evidence-manifest.v1',
        'implementation_head': HEAD, 'implementation_tree': tree, 'members': {},
        'source_objects': object_types, 'source_closure': entries,
        'full_repository_blob_payload_packaged': False,
        'profile_source_blob_closure_packaged': True,
        'source_scope': report['source_before']['scope'],
        'original_payloads_removed_or_modified': False,
        'source_upgrade_requalified': False,
        'foreign_sigabrt_relabelled_as_recovered': False}
    with tarfile.open(ARCHIVE, 'w:xz', format=tarfile.USTAR_FORMAT, preset=3) as archive:
        def add(name, data):
            need(name not in manifest['members'] and len(data) <= 16 * 1024 * 1024, 'duplicate or oversized member')
            info = tarfile.TarInfo(name); info.size = len(data); info.mode = 0o644; info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
            manifest['members'][name] = {'bytes': len(data), 'sha256': sha256(data).hexdigest()}
        for name, path in sorted(inputs.items()):
            add(name, regular(path))
        for object_id, data in sorted(objects.items()):
            add('source/git-objects/' + object_id, data)
    archive_bytes = ARCHIVE.read_bytes()
    manifest['archive'] = {'name': ARCHIVE.name, 'bytes': len(archive_bytes), 'sha256': sha256(archive_bytes).hexdigest()}
    manifest['uncompressed_member_bytes'] = sum(row['bytes'] for row in manifest['members'].values())
    manifest['archive_build_wall_ns'] = time.monotonic_ns() - started
    data = json.dumps(manifest, indent=2, sort_keys=True).encode() + b'\n'
    (HERE / 'MANIFEST.json').write_bytes(data)
    print(json.dumps({'archive': manifest['archive'], 'manifest_sha256': sha256(data).hexdigest(),
        'members': len(manifest['members']), 'source_closure': len(entries), 'source_objects': len(objects),
        'uncompressed_member_bytes': manifest['uncompressed_member_bytes'],
        'archive_build_wall_ns': manifest['archive_build_wall_ns'], 'archive_readback_pending': True}, sort_keys=True))


if __name__ == '__main__':
    main()
