#!/usr/bin/env python3
"""Verify archive bytes only; never import, compile, or run archived programs."""
from pathlib import Path, PurePosixPath
import argparse
from collections import Counter
import gzip
import hashlib
import json
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify(root, check_originals=False):
    manifest_path = root / 'manifest.json'
    manifest = json.loads(manifest_path.read_bytes())
    require(manifest['schema'] == 'hepta.historical-evidence-archive.v1', 'wrong schema')
    require(manifest['manifest_self_exclusion'] == 'manifest.json', 'manifest exclusion changed')
    names = set()
    original_total = stored_total = 0
    categories = Counter()
    compressed = filesystem_originals = 0
    for entry in manifest['entries']:
        stored, original = entry['stored'], entry['original']
        name = stored['path']
        rel = PurePosixPath(name)
        require(isinstance(name, str) and not rel.is_absolute() and '..' not in rel.parts and name == rel.as_posix(), 'invalid stored path')
        require(name not in names and name != 'manifest.json', 'duplicate or self-referential path')
        names.add(name)
        path = root.joinpath(*rel.parts)
        require(path.is_file() and not path.is_symlink(), 'missing or symbolic payload: ' + name)
        data = path.read_bytes()
        require(len(data) == stored['bytes'] and digest(data) == stored['sha256'], 'stored bytes differ: ' + name)
        if stored['encoding'] == 'identity':
            raw = data
        elif stored['encoding'] == 'gzip':
            require(data[:3] == b'\x1f\x8b\x08', 'wrong gzip header: ' + name)
            require(int.from_bytes(data[4:8], 'little') == 0 and stored['gzip_mtime'] == 0, 'nonzero gzip mtime: ' + name)
            require((data[3] & 8) == 0 and stored['gzip_original_filename'] == '', 'gzip contains original filename: ' + name)
            raw = gzip.decompress(data)
            compressed += 1
        else:
            raise ValueError('unknown encoding: ' + name)
        require(len(raw) == original['bytes'] and digest(raw) == original['sha256'], 'original bytes differ after decode: ' + name)
        require(not raw.startswith((b'\x7fELF', b'!<arch>\n', b'MZ')), 'direct native binary archived: ' + name)
        if check_originals and entry['origin']['kind'] == 'filesystem':
            source = Path(entry['origin']['path'])
            require(source.is_file() and not source.is_symlink(), 'original unavailable: ' + str(source))
            source_bytes = source.read_bytes()
            require(len(source_bytes) == original['bytes'] and digest(source_bytes) == original['sha256'], 'source original differs: ' + str(source))
            filesystem_originals += 1
        original_total += original['bytes']
        stored_total += stored['bytes']
        categories[entry['category']] += 1
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    require(actual == names | {'manifest.json'}, 'extra or missing files: ' + repr(sorted(actual ^ (names | {'manifest.json'}))))
    require(not any(p.is_symlink() for p in root.rglob('*')), 'archive contains symbolic path')
    totals = manifest['totals']
    require(totals['payload_file_count'] == len(names), 'payload count differs')
    require(totals['payload_original_bytes'] == original_total and totals['payload_stored_bytes'] == stored_total, 'payload totals differ')
    require(totals['compressed_payload_count'] == compressed, 'compression count differs')
    require(totals['category_payload_counts'] == dict(sorted(categories.items())), 'category counts differ')
    omitted = manifest['omitted_native_binaries']
    require(totals['omitted_native_binary_count'] == len(omitted), 'omitted binary count differs')
    require(totals['omitted_native_binary_bytes'] == sum(x['bytes'] for x in omitted), 'omitted binary bytes differ')
    if check_originals:
        for item in omitted:
            source = Path(item['origin']['path'])
            require(source.is_file(), 'omitted binary original unavailable: ' + str(source))
            data = source.read_bytes()
            require(len(data) == item['bytes'] and digest(data) == item['sha256'], 'omitted binary identity differs: ' + str(source))
    return {'status': 'passed', 'verification': 'archive integrity only; no qualification replay or native execution', 'payload_files': len(names), 'total_files_including_manifest': len(names) + 1, 'payload_original_bytes': original_total, 'payload_stored_bytes': stored_total, 'archive_bytes_including_manifest': stored_total + manifest_path.stat().st_size, 'compressed_files': compressed, 'omitted_native_binaries': len(omitted), 'filesystem_originals_checked': filesystem_originals, 'manifest_sha256': digest(manifest_path.read_bytes())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--check-originals', action='store_true', help='Also compare still-available original filesystem records and omitted binary identities; reads only.')
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.archive.resolve(), args.check_originals), sort_keys=True))
    except (OSError, KeyError, TypeError, ValueError) as exc:
        print(json.dumps({'status': 'failed', 'error': str(exc)}, sort_keys=True))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
