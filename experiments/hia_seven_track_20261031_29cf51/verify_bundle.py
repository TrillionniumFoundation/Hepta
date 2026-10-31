#!/usr/bin/env python3
"""Verify every part, concatenated archive, inventory, and retained file.

No retained programs are executed. Optional extraction requires a new directory.
"""
import argparse
import hashlib
import json
import lzma
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile


def sha256_file(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def safe_path(value):
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(p in ('', '.', '..') for p in path.parts):
        raise ValueError('unsafe relative path: ' + value)
    return path


def verify_archive(root, bundle, extract_root=None):
    inventory_path = root / safe_path(bundle['inventory']['path'])
    if sha256_file(inventory_path) != bundle['inventory']['sha256']:
        raise ValueError('inventory hash mismatch')
    inventory = json.loads(inventory_path.read_text())
    expected = {row['path']: row for row in inventory['files']}
    if len(expected) != len(inventory['files']) or len(expected) != bundle['file_count']:
        raise ValueError('duplicate or wrong inventory count')
    archive_hash = hashlib.sha256()
    archive_bytes = 0
    with tempfile.TemporaryFile() as assembled:
        for part in bundle['parts']:
            path = root / safe_path(part['path'])
            if path.stat().st_size != part['bytes'] or sha256_file(path) != part['sha256']:
                raise ValueError('part mismatch: ' + part['path'])
            with path.open('rb') as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    archive_hash.update(block)
                    archive_bytes += len(block)
                    assembled.write(block)
        if archive_bytes != bundle['archive_bytes'] or archive_hash.hexdigest() != bundle['archive_sha256']:
            raise ValueError('concatenated archive mismatch')
        assembled.seek(0)
        found = set()
        with lzma.LZMAFile(assembled, 'rb') as decompressed:
            with tarfile.open(fileobj=decompressed, mode='r|') as archive:
                for member in archive:
                    name = str(safe_path(member.name))
                    if not member.isfile() or name in found or name not in expected:
                        raise ValueError('unexpected archive member: ' + name)
                    row = expected[name]
                    if member.size != row['bytes'] or member.mode != int(row['mode'], 8):
                        raise ValueError('member metadata mismatch: ' + name)
                    h = hashlib.sha256()
                    count = 0
                    with archive.extractfile(member) as stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b''):
                            h.update(block)
                            count += len(block)
                    if count != row['bytes'] or h.hexdigest() != row['sha256']:
                        raise ValueError('member bytes mismatch: ' + name)
                    found.add(name)
        if found != set(expected):
            raise ValueError('missing archive members')
        if extract_root is not None:
            assembled.seek(0)
            with lzma.LZMAFile(assembled, 'rb') as decompressed:
                with tarfile.open(fileobj=decompressed, mode='r|') as archive:
                    for member in archive:
                        output = extract_root / safe_path(member.name)
                        output.parent.mkdir(parents=True, exist_ok=True)
                        with output.open('xb') as target, archive.extractfile(member) as stream:
                            shutil.copyfileobj(stream, target, length=1024 * 1024)
                        output.chmod(member.mode)
        return {'lane': bundle['lane'], 'verified_files': len(found),
                'verified_archive_bytes': archive_bytes, 'archive_sha256': archive_hash.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lane', action='append', choices=['semantics', 'migration', 'ndu',
                        'performance', 'integration', 'agent', 'ci'])
    parser.add_argument('--extract', type=Path, help='New directory for verified retained files')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / 'MANIFEST.json').read_text())
    for record in manifest.get('document_files', []):
        path = root / safe_path(record['path'])
        if path.stat().st_size != record['bytes'] or sha256_file(path) != record['sha256']:
            raise ValueError('document mismatch: ' + record['path'])
    bundles = [b for b in manifest['bundles'] if not args.lane or b['lane'] in args.lane]
    if args.extract is not None:
        if args.extract.exists():
            raise ValueError('--extract destination must not already exist')
        args.extract.mkdir(parents=True, mode=0o700)
    for bundle in bundles:
        print(json.dumps(verify_archive(root, bundle, args.extract), sort_keys=True), flush=True)
    print(json.dumps({'ok': True, 'lanes': len(bundles), 'retained_programs_executed': 0}))


if __name__ == '__main__':
    main()
