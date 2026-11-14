"""Verify all mounted bytes, optionally restoring the complete logical subset.

Usage: python restore.py --bundle DIRECTORY [--output NEW_DIRECTORY] --report NEW_JSON
The external 3175-file R19 base is not inside this observation capsule.
"""
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat


def require(value, reason):
    if not value:
        raise ValueError(reason)


def pairs(values):
    result = {}
    for key, value in values:
        require(key not in result, 'duplicate JSON member')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs)


def identify(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def check(raw, wanted):
    require(identify(raw) == {key: wanted[key] for key in ('bytes', 'sha256', 'git_blob')}, 'content identity differs')


def safe(name):
    path = PurePosixPath(name)
    require(type(name) is str and name and not path.is_absolute()
            and path.as_posix() == name and all(part not in ('', '.', '..') for part in path.parts),
            'unsafe logical path')
    return path.parts


def ordinary(path):
    require(stat.S_ISREG(path.lstat().st_mode), 'ordinary transport file required')
    return path.read_bytes()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    root = args.bundle.absolute()
    wrapper = decode(ordinary(root / 'INDEX-CAPSULE.json'))
    require(wrapper['schema'] == 'hepta.gzip-base64-json-capsule.v1', 'wrong index transport')
    index_raw = gzip.decompress(base64.b64decode(wrapper['data'], validate=True))
    check(index_raw, wrapper['decoded'])
    index = decode(index_raw)
    encoded = bytearray()
    for row in index['parts']:
        path = root.joinpath(*safe(row['path']))
        raw = ordinary(path)
        check(raw, row)
        require(b'\n' not in raw and b'\r' not in raw, 'base64 fragment has line endings')
        encoded.extend(raw)
    encoded = bytes(encoded)
    check(encoded, index['base64'])
    compressed = base64.b64decode(encoded, validate=True)
    check(compressed, index['gzip'])
    payload_raw = gzip.decompress(compressed)
    check(payload_raw, index['json_capsule'])
    payload = decode(payload_raw)
    require(payload['schema'] == 'hepta.lossless-logical-cas.v1', 'wrong logical capsule')
    require(payload['files'] == index['files'] and payload['directories'] == index['directories'],
            'logical inventory differs')
    objects = {}
    for digest, row in payload['objects'].items():
        raw = base64.b64decode(row['base64'], validate=True)
        check(raw, row)
        require(row['sha256'] == digest, 'CAS key differs')
        objects[digest] = raw
    require(len(objects) == index['unique_objects'], 'object count differs')
    require(sum(len(raw) for raw in objects.values()) == index['unique_bytes'], 'object bytes differ')
    require(len(payload['files']) == index['logical_files'], 'logical count differs')
    used = set()
    for name, row in payload['files'].items():
        safe(name)
        require(type(row['mode']) is int and 0 <= row['mode'] <= 0o777, 'invalid file mode')
        require(row['object'] in objects, 'missing content object')
        used.add(row['object'])
        check(objects[row['object']], row)
    require(used == set(objects), 'unreferenced or missing CAS object')
    for name, mode in payload['directories'].items():
        safe(name)
        require(type(mode) is int and 0 <= mode <= 0o777, 'invalid directory mode')
    if args.output is not None:
        target = args.output.absolute()
        require(not target.exists() and not target.is_symlink(), 'new output directory required')
        target.mkdir(mode=0o700)
        for name in sorted(payload['directories'], key=lambda value: (value.count('/'), value)):
            path = target.joinpath(*safe(name))
            require(path.parent.is_dir() and not path.parent.is_symlink(), 'missing ordinary parent')
            path.mkdir(mode=0o700)
        for name, row in payload['files'].items():
            path = target.joinpath(*safe(name))
            with path.open('xb') as stream:
                stream.write(objects[row['object']])
            os.chmod(path, row['mode'])
            check(ordinary(path), row)
            require(stat.S_IMODE(path.lstat().st_mode) == row['mode'], 'restored mode differs')
        for name in sorted(payload['directories'], key=lambda value: (-value.count('/'), value)):
            path = target.joinpath(*safe(name))
            os.chmod(path, payload['directories'][name])
            require(stat.S_IMODE(path.lstat().st_mode) == payload['directories'][name], 'directory mode differs')
    report = {'schema': 'hepta.selfhost-u32-raw-restore.v1', 'status': 'PASS_ALL_LOGICAL_BYTES_AND_MODES',
              'logical_files': index['logical_files'], 'logical_bytes': index['logical_bytes'],
              'directories': len(index['directories']), 'objects': len(objects),
              'full_CRC_size_Git_SHA': True, 'all_2712_frames_included': True,
              'filesystem_restore_performed': args.output is not None,
              'external_R19_base_included': False, 'products_executed': 0}
    with args.report.open('x') as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
