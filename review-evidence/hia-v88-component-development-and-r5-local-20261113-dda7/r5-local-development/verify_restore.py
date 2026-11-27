"""Verify the complete R5 archive from fetched wrappers; optionally restore it."""
from __future__ import annotations

import argparse
import base64
import gzip
from hashlib import sha1, sha256
import io
import json
from pathlib import Path, PurePosixPath
import stat
import tarfile
import time


def strict(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)


def identity(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def check_identity(raw, expected):
    actual = identity(raw)
    if any(type(expected.get(key)) is not type(value) or expected[key] != value
           for key, value in actual.items()):
        raise ValueError('content identity mismatch')


def safe_path(value):
    if type(value) is not str or '\0' in value or '\\' in value:
        raise ValueError('invalid archive path')
    path = PurePosixPath(value)
    if str(path) != value or path.is_absolute() or not path.parts or '..' in path.parts:
        raise ValueError('unsafe archive path')
    return path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--transport', type=Path, required=True)
    parser.add_argument('--wrappers', type=Path, required=True)
    parser.add_argument('--original-archive', type=Path)
    parser.add_argument('--original-workspace', type=Path)
    parser.add_argument('--restore', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    started = time.monotonic()
    transport = strict(args.transport.read_bytes())
    if transport['schema'] != 'hia.local-r5-custody-transport.v1':
        raise ValueError('transport schema differs')
    blocks = []
    offset = 0
    for index, row in enumerate(transport['chunks']):
        path = args.wrappers / safe_path(row['path'])
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            raise ValueError('wrapper is not an ordinary file')
        raw = path.read_bytes()
        check_identity(raw, row)
        wrapper = strict(raw)
        if (wrapper['schema'] != 'hia.binary-archive.base64-chunk.v1'
                or type(wrapper['index']) is not int or wrapper['index'] != index
                or type(wrapper['offset']) is not int or wrapper['offset'] != offset
                or row['offset'] != offset or wrapper['encoding'] != 'base64'):
            raise ValueError('chunk order or schema differs')
        block = base64.b64decode(wrapper['data'], validate=True)
        check_identity(block, wrapper)
        check_identity(block, row['raw'])
        if base64.b64encode(block).decode() != wrapper['data']:
            raise ValueError('noncanonical base64')
        blocks.append(block)
        offset += len(block)
    archive = b''.join(blocks)
    check_identity(archive, transport['archive'])
    if args.original_archive is not None and archive != args.original_archive.read_bytes():
        raise ValueError('fetched archive differs from preserved original')
    # Consume every compressed byte and validate gzip CRC/ISIZE before tar parsing.
    tar_bytes = gzip.decompress(archive)
    members = {}
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode='r:') as tar:
        for member in tar:
            safe_path(member.name)
            if (not member.isfile() or member.mode != 0o644 or member.name in members
                    or member.size < 0 or member.uid != 0 or member.gid != 0):
                raise ValueError('noncanonical archive member')
            raw = tar.extractfile(member).read()
            if len(raw) != member.size:
                raise ValueError('truncated member')
            members[member.name] = raw
    manifest_raw = members.pop('MANIFEST.json')
    check_identity(manifest_raw, transport['manifest'])
    manifest = strict(manifest_raw)
    if manifest['schema'] != 'hia.local-r5-custody-manifest.v1':
        raise ValueError('manifest schema differs')
    expected_objects = {row['object'] for row in manifest['files']}
    if set(members) != expected_objects or len(members) != transport['unique_objects']:
        raise ValueError('object pool member set differs')
    checked_objects = {}
    for name, raw in members.items():
        record = identity(raw)
        if name != 'objects/' + record['sha256'] + '.bin':
            raise ValueError('pool object name differs')
        checked_objects[name] = record
    seen = set()
    compared = 0
    total = 0
    if args.restore is not None:
        args.restore.mkdir(parents=False, exist_ok=False)
    for row in manifest['files']:
        path = safe_path(row['path'])
        if row['path'] in seen or type(row['mode']) is not int or not 0 <= row['mode'] <= 0o777:
            raise ValueError('logical path or mode differs')
        seen.add(row['path'])
        if checked_objects[row['object']] != {key: row[key] for key in ('bytes', 'sha256', 'git_blob')}:
            raise ValueError('logical member identity differs')
        raw = members[row['object']]
        total += len(raw)
        if args.original_workspace is not None:
            root = {'r5': 'v87-union-r5', 'integration': 'v86-launcher-integration-r1',
                    'machine-plan-repair': 'v87-machine-plan-custody-repair-r1'}[path.parts[0]]
            original = args.original_workspace / root / Path(*path.parts[1:])
            if (original.is_symlink() or not stat.S_ISREG(original.stat().st_mode)
                    or stat.S_IMODE(original.stat().st_mode) != row['mode']
                    or original.read_bytes() != raw):
                raise ValueError('original byte/mode comparison differs: ' + str(original))
            compared += 1
        if args.restore is not None:
            output = args.restore / path
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open('xb') as stream:
                stream.write(raw)
            output.chmod(row['mode'])
            if output.read_bytes() != raw:
                raise ValueError('restore readback differs')
    if (len(seen) != manifest['all_original_files'] or len(seen) != transport['logical_members']
            or total != manifest['all_original_bytes']):
        raise ValueError('complete logical member counts differ')
    report = {'schema': 'hia.local-r5-fetched-archive-readback.v1',
        'status': 'COMPLETE_FETCHED_WRAPPERS_ARCHIVE_AND_LOGICAL_MEMBERS_PASS',
        'archive': identity(archive), 'chunks': len(blocks), 'logical_members': len(seen),
        'logical_bytes': total, 'unique_objects': len(members),
        'all_wrappers_full_identity_and_strict_base64': True,
        'gzip_crc_and_tar_member_modes_checked': True,
        'all_logical_members_bytes_mode_sha256_git_checked': True,
        'original_archive_equal': args.original_archive is not None,
        'original_files_compared': compared, 'restored_files': len(seen) if args.restore is not None else 0,
        'source_or_product_execution': 0, 'whole_native': False,
        'elapsed_seconds': time.monotonic() - started}
    with args.report.open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
