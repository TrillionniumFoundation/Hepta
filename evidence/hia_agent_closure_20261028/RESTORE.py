#!/usr/bin/env python3
"""Verify/restore retained observations. Never execute any archived program."""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
from pathlib import Path, PurePosixPath
import stat
import tarfile
import tempfile
import zipfile


def safe_name(name):
    p = PurePosixPath(name)
    if not name or p.is_absolute() or '..' in p.parts or '\\' in name or ':' in p.parts[0]:
        raise ValueError('unsafe relative path')
    if p.as_posix() != name:
        raise ValueError('noncanonical relative path')
    return p


def read_json(path):
    return json.loads(path.read_text())


def hashed_copy(src, dst=None):
    h, size = hashlib.sha256(), 0
    for data in iter(lambda: src.read(1024 * 1024), b''):
        h.update(data)
        size += len(data)
        if dst is not None:
            dst.write(data)
    return size, h.hexdigest()


def verify_identity(size, sha, row, label):
    if size != row['bytes'] or sha != row['sha256']:
        raise ValueError('identity mismatch: ' + label)


def create_file(root, name):
    path = root / safe_name(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path, path.open('xb')


def run():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--verify-only', action='store_true', help='Read every archive member without restoring it.')
    ap.add_argument('--output', type=Path, help='New output directory; existing paths are refused.')
    ap.add_argument('--expand-ci', action='store_true', help='Also reconstruct and verify original CI extraction trees.')
    args = ap.parse_args()
    if args.verify_only == (args.output is not None):
        ap.error('choose exactly one of --verify-only and --output')
    if args.expand_ci and args.output is None:
        ap.error('--expand-ci requires --output')

    base = Path(__file__).resolve().parent
    archive = read_json(base / 'ARCHIVE.json')
    index_path = base / safe_name(archive['index']['path'])
    with index_path.open('rb') as f:
        verify_identity(*hashed_copy(f), archive['index'], 'RAW-INDEX.json')
    index = read_json(index_path)
    if archive['source_commit'] != index['source_commit']:
        raise ValueError('archive/index source identities differ')
    expected = {}
    for row in index['files']:
        name = safe_name(row['path']).as_posix()
        if name in expected or not 0 <= row['mode'] <= 0o777:
            raise ValueError('duplicate path or invalid mode in index')
        expected[name] = row
    if len(expected) != index['file_count'] or sum(r['bytes'] for r in expected.values()) != index['bytes']:
        raise ValueError('index totals differ')
    if archive['file_count'] != index['file_count'] or archive['uncompressed_file_bytes'] != index['bytes']:
        raise ValueError('archive/index totals differ')
    output = None
    if args.output is not None:
        output = args.output.absolute()
        if output.exists() or output.is_symlink():
            raise FileExistsError('output must not exist')
        output.mkdir(parents=True, exist_ok=False)

    with tempfile.TemporaryFile() as combined:
        joined_hash, joined_size, seen_parts = hashlib.sha256(), 0, set()
        for part in archive['parts']:
            name = safe_name(part['path']).as_posix()
            if name in seen_parts:
                raise ValueError('duplicate archive part')
            seen_parts.add(name)
            h, size = hashlib.sha256(), 0
            with (base / name).open('rb') as source:
                for data in iter(lambda: source.read(1024 * 1024), b''):
                    h.update(data)
                    size += len(data)
                    joined_hash.update(data)
                    joined_size += len(data)
                    combined.write(data)
            verify_identity(size, h.hexdigest(), part, name)
        verify_identity(joined_size, joined_hash.hexdigest(), archive, 'joined archive')
        combined.seek(0)
        observed = set()
        with lzma.LZMAFile(combined, 'rb') as decompressed:
            with tarfile.open(fileobj=decompressed, mode='r|') as tar:
                for member in tar:
                    name = safe_name(member.name).as_posix()
                    if not member.isfile() or name in observed or name not in expected:
                        raise ValueError('unexpected/nonregular/duplicate member: ' + name)
                    row = expected[name]
                    if member.size != row['bytes'] or member.mode != row['mode']:
                        raise ValueError('member metadata differs: ' + name)
                    source = tar.extractfile(member)
                    if source is None:
                        raise ValueError('missing regular file payload: ' + name)
                    with source:
                        if output is None:
                            size, sha = hashed_copy(source)
                        else:
                            path, target = create_file(output, name)
                            with target:
                                size, sha = hashed_copy(source, target)
                            path.chmod(row['mode'])
                    verify_identity(size, sha, row, name)
                    observed.add(name)
            # Complete the XZ checksum, including bytes after tar end markers.
            for _ in iter(lambda: decompressed.read(1024 * 1024), b''):
                pass
        if observed != expected.keys():
            raise ValueError('archive does not contain every indexed file')

    expanded_files = expanded_bytes = 0
    if args.expand_ci:
        for expansion in index['zip_expansions']:
            target = output / safe_name(expansion['destination'])
            if target.exists() or target.is_symlink():
                raise FileExistsError('CI extraction destination already exists')
            target.mkdir(parents=True)
            members = {row['path']: row for row in expansion['members']}
            if len(members) != expansion['member_count']:
                raise ValueError('duplicate CI index member')
            seen = set()
            with zipfile.ZipFile(output / safe_name(expansion['archive'])) as z:
                for info in z.infolist():
                    name = info.filename.rstrip('/') if info.is_dir() else info.filename
                    safe_name(name)
                    if info.is_dir():
                        continue
                    if name in seen or name not in members or stat.S_ISLNK(info.external_attr >> 16):
                        raise ValueError('unexpected CI ZIP member')
                    row = members[name]
                    if info.file_size != row['bytes']:
                        raise ValueError('CI member metadata differs')
                    path, destination = create_file(target, name)
                    with z.open(info) as src, destination:
                        size, sha = hashed_copy(src, destination)
                    verify_identity(size, sha, row, name)
                    if row['mode']:
                        path.chmod(row['mode'])
                    seen.add(name)
                    expanded_files += 1
                    expanded_bytes += size
            if seen != members.keys():
                raise ValueError('missing CI ZIP member')

    print(json.dumps({
        'schema': 'hepta.hia-agent-closure.restore-verification.v1',
        'source_commit': archive['source_commit'], 'all_passed': True,
        'archive_sha256': archive['sha256'], 'parts': len(archive['parts']),
        'raw_files': len(observed), 'raw_file_bytes': index['bytes'],
        'ci_expanded_files': expanded_files, 'ci_expanded_bytes': expanded_bytes,
        'project_code_executed': False, 'output': str(output) if output else None,
    }, indent=2, sort_keys=True))


if __name__ == '__main__':
    run()
