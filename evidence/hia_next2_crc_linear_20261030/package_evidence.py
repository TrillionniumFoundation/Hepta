#!/usr/bin/env python3
"""Package retained local CRC evidence; never execute archived code or binaries."""
from __future__ import annotations
import argparse
from hashlib import sha1, sha256
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile
import time

BASE = Path('/workspace/scratch/f0c12f106c89')
REPO = BASE / 'hepta-integration'
HEAD = '953fa62dee5aa563551d57b1374ab95b6d548b45'
ROOTS = {
    'raw/development': 'hia-next2-crc-linear-development',
    'raw/qualification-failed-2f7052c': 'hia-next2-crc-linear-2f7052c-qualification-20261030',
    'raw/qualification-legacy-7e69323': 'hia-next2-crc-linear-7e69323-qualification-20261030',
    'raw/qualification-timed-1873755': 'hia-next2-crc-linear-1873755-timed-qualification-20261030',
    'raw/formal': 'p4-crc-linear-study-953fa62d-20261030',
}
STAGES = {
    'failed': ('raw/qualification-failed-2f7052c/RESULT.json', '2f7052c669353d1dd0fb3480923a63f165ae821d'),
    'legacy': ('raw/qualification-legacy-7e69323/RESULT.json', '7e69323101135f5742cef866dbd2f215f4a43dea'),
    'timed': ('raw/qualification-timed-1873755/RESULT.json', '1873755fbb70e6b4153b9a09cc0e30df45bc618b'),
    'formal': ('raw/formal/run/RESULT.json', HEAD),
}
MAX_MEMBER = 8 << 20


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= MAX_MEMBER:
            raise ValueError('not a bounded regular input: ' + str(path))
        with os.fdopen(fd, 'rb', closefd=False) as f:
            raw = f.read(MAX_MEMBER + 1)
        if len(raw) != info.st_size or len(raw) > MAX_MEMBER:
            raise ValueError('input grew or changed size')
        return raw
    finally:
        os.close(fd)


def git(*args):
    return subprocess.check_output(['git', '--no-replace-objects', *args], cwd=REPO)


def object_id(kind, raw):
    return sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-directory', type=Path, required=True)
    out = parser.parse_args().output_directory.resolve()
    started = time.monotonic_ns()
    if git('rev-parse', 'HEAD').decode().strip() != HEAD or git('status', '--porcelain', '--untracked-files=all'):
        raise ValueError('exact clean frozen integration required')
    members = {}

    def add(name, raw):
        path = PurePosixPath(name)
        if name != path.as_posix() or path.is_absolute() or '..' in path.parts or name in members:
            raise ValueError('unsafe/duplicate member: ' + name)
        if len(raw) > MAX_MEMBER:
            raise ValueError('oversized member')
        members[name] = raw

    for prefix, folder in ROOTS.items():
        source = BASE / folder
        if source.is_symlink() or not source.is_dir():
            raise ValueError('raw root changed')
        for path in sorted(source.rglob('*')):
            if path.is_symlink():
                raise ValueError('raw evidence link rejected')
            if path.is_dir():
                continue
            add(prefix + '/' + path.relative_to(source).as_posix(), read(path))
    for filename in ('REPORT_ZH.md', 'ARCHIVE_PLAN.json', 'STATIC_REVIEW_INPUTS.json',
                     'package_evidence.py', 'verify_evidence.py'):
        add('metadata/' + filename, read(out / filename))
    for path in sorted((out / 'reviews').glob('*.json')) if (out / 'reviews').exists() else ():
        add('metadata/reviews/' + path.name, read(path))

    sources, queries = {}, set()
    for stage, (report_name, head) in STAGES.items():
        report = json.loads(members[report_name])
        source = report['source_before']
        if source['head'] != head or source != report['source_after']:
            raise ValueError('stage source identity differs')
        sources[stage] = {'head': head, 'tree': source['tree'], 'report': report_name,
                          'files': source['files']}
        queries.add(head)
        queries.add(source['tree'])
        for name in source['files']:
            path = PurePosixPath(name)
            if name != path.as_posix() or path.is_absolute() or '..' in path.parts or '\n' in name:
                raise ValueError('unsafe source path')
            queries.add(head + ':' + name)
            for parent in path.parents:
                if parent.as_posix() != '.':
                    queries.add(head + ':' + parent.as_posix())
    queries = sorted(queries)
    result = subprocess.run(['git', '--no-replace-objects', 'cat-file', '--batch'], cwd=REPO,
        input=('\n'.join(queries) + '\n').encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    if len(result.stdout) > 96 << 20 or result.stderr:
        raise ValueError('unexpected Git batch size/error')
    stream, objects = io.BytesIO(result.stdout), {}
    for query in queries:
        fields = stream.readline(256).decode().strip().split()
        if len(fields) != 3 or fields[1] not in ('blob', 'tree', 'commit'):
            raise ValueError('missing/invalid exact Git object')
        oid, kind, size = fields[0], fields[1], int(fields[2])
        if not 0 <= size <= MAX_MEMBER:
            raise ValueError('Git object size limit')
        raw = stream.read(size)
        if len(raw) != size or stream.read(1) != b'\n' or object_id(kind, raw) != oid:
            raise ValueError('Git payload identity mismatch')
        objects[query] = (oid, kind, raw)
    if stream.read(1):
        raise ValueError('trailing Git batch bytes')
    tree_payloads = {}
    for stage, source in sources.items():
        head = source['head']
        oid, kind, raw = objects[head]
        if oid != head or kind != 'commit' or raw.splitlines()[0] != ('tree ' + source['tree']).encode():
            raise ValueError('commit/tree binding differs')
        add('git/commits/' + head + '.raw', raw)
        for name, expected in source['files'].items():
            oid, kind, raw = objects[head + ':' + name]
            if kind != 'blob' or sha256(raw).hexdigest() != expected:
                raise ValueError('source bytes differ from acquired binding')
            add('source/' + head + '/' + name, raw)
        for query, (oid, kind, raw) in objects.items():
            if kind == 'tree':
                tree_payloads[oid] = raw
    for oid, raw in tree_payloads.items():
        add('git/trees/' + oid + '.raw', raw)
    if len(members) > 4096 or sum(map(len, members.values())) > 96 << 20:
        raise ValueError('archive payload budget exceeded')
    manifest = {'schema': 'hepta.hia.crc-linear.evidence-manifest.v1', 'frozen_source_head': HEAD,
        'sources': sources, 'raw_roots': ROOTS,
        'members': {name: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()} for name, raw in sorted(members.items())},
        'member_count': len(members), 'payload_bytes': sum(map(len, members.values())),
        'claims': {'archived_payload_executed': False, 'proof_solver_reexecuted_by_offline_verifier': False,
                   'machine_code_refinement_proved': False, 'performance_timing_qualified': False,
                   'positive_cold_benefit': False, 'NDU_incremental_value_established': False,
                   'future_filecheck_direction_executed': False, 'preparation_receipts_are_per_case_raw_transcripts': False}}
    archive = out / 'crc-linear-evidence.tar.xz'
    with archive.open('xb') as destination:
        with tarfile.open(fileobj=destination, mode='w:xz', preset=6, format=tarfile.USTAR_FORMAT) as tar:
            for name, raw in sorted(members.items()):
                item = tarfile.TarInfo(name)
                item.size, item.mode, item.uid, item.gid, item.mtime = len(raw), 0o644, 0, 0, 0
                tar.addfile(item, io.BytesIO(raw))
    manifest_raw = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    with (out / 'MANIFEST.json').open('xb') as target:
        target.write(manifest_raw)
    archive_raw = read(archive)
    receipt = {'schema': 'hepta.hia.crc-linear.packaging-receipt.v1',
        'archive': archive.name, 'archive_bytes': len(archive_raw), 'archive_sha256': sha256(archive_raw).hexdigest(),
        'manifest': 'MANIFEST.json', 'manifest_bytes': len(manifest_raw), 'manifest_sha256': sha256(manifest_raw).hexdigest(),
        'member_count': len(members), 'payload_bytes': manifest['payload_bytes'],
        'wall_ns': time.monotonic_ns() - started, 'raw_directories_modified': False,
        'native_or_model_execution': False, 'all_member_readback_completed': False}
    with (out / 'PACKAGING.json').open('x') as target:
        json.dump(receipt, target, sort_keys=True, indent=2)
        target.write('\n')
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()
