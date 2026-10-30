#!/usr/bin/env python3
"""Restore the official ZIP from downloaded immutable part files, never execute it."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os

parser = argparse.ArgumentParser()
parser.add_argument('--manifest', type=Path, default=Path(__file__).with_name('raw-parts.json'))
parser.add_argument('--part-directory', type=Path, required=True,
                    help='Directory containing the raw-artifacts/ paths in the manifest')
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
manifest = json.loads(args.manifest.read_text())
assert manifest['schema'] == 'hepta.hosted147-official-zip-offset-parts.v1'
assert manifest['part_count'] == len(manifest['parts'])
assert not args.output.exists(), 'Refusing to overwrite an existing destination'
partial = args.output.with_name(args.output.name + '.partial')
whole = hashlib.sha256()
whole_blob = hashlib.sha1(f"blob {manifest['source_archive']['bytes']}\0".encode())
total = 0
with partial.open('xb') as output:
    for number, row in enumerate(manifest['parts'], 1):
        path = PurePosixPath(row['path'])
        assert not path.is_absolute() and '..' not in path.parts and '\\' not in row['path']
        assert row['part'] == number and row['offset'] == total
        source_path = args.part_directory / Path(*path.parts)
        assert source_path.is_file() and not source_path.is_symlink()
        digest = hashlib.sha256()
        blob = hashlib.sha1(f"blob {row['bytes']}\0".encode())
        count = 0
        with source_path.open('rb') as source:
            for chunk in iter(lambda: source.read(1024*1024), b''):
                count += len(chunk)
                assert count <= row['bytes']
                digest.update(chunk)
                blob.update(chunk)
                whole.update(chunk)
                whole_blob.update(chunk)
                output.write(chunk)
        assert count == row['bytes'] and digest.hexdigest() == row['sha256']
        assert blob.hexdigest() == row['git_blob_sha1']
        total += count
assert total == manifest['source_archive']['bytes']
assert whole.hexdigest() == manifest['source_archive']['sha256']
assert whole_blob.hexdigest() == manifest['source_archive']['git_blob_sha1']
# link() refuses any existing destination, including one created during restoration.
os.link(partial, args.output)
partial.unlink()
print(json.dumps({'artifact_id': manifest['artifact_id'], 'parts_verified': manifest['part_count'],
                  'output': str(args.output), 'bytes': total, 'sha256': whole.hexdigest(),
                  'git_blob_sha1': whole_blob.hexdigest(), 'original_exactly_restored': True,
                  'archive_code_executed': False}, indent=2))
