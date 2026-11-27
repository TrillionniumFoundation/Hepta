"""Restore one complete raw inventory into a new, exclusive directory.

Run with the directory containing INDEX.json and parts/, and an absent target.
This is data custody only: no imported project modules or product execution.
"""
from pathlib import Path, PurePosixPath
import argparse
import base64
import hashlib
import io
import json
import stat
import tarfile

def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def checked(raw, expected):
    assert identity(raw) == {key: expected[key] for key in ('bytes', 'sha256', 'git_blob')}

def safe(name):
    path = PurePosixPath(name)
    assert name and not path.is_absolute() and '..' not in path.parts and str(path) == name
    return path

def restore(publication, target):
    index = json.loads((publication / 'INDEX.json').read_bytes())
    assert index['schema'] == 'hia.compact-render-R1-R5.present-raw-publication.v1'
    complete = bytearray()
    for number, row in enumerate(index['parts']):
        safe(row['path'])
        wrapped = (publication / row['path']).read_bytes()
        checked(wrapped, row)
        packet = json.loads(wrapped)
        assert packet['schema'] == 'hia.complete-raw.archive-part.v1'
        assert packet['number'] == number and packet['offset'] == row['offset'] == len(complete)
        assert packet['encoding'] == 'base64'
        data = base64.b64decode(packet['payload'], validate=True)
        checked(data, row['decoded']); checked(data, packet['decoded'])
        complete.extend(data)
    checked(bytes(complete), index['archive'])
    target.mkdir(exist_ok=False)
    seen = set()
    files = None
    aliases = {}
    with tarfile.open(fileobj=io.BytesIO(complete), mode='r:gz') as tar:
        for member in tar:
            safe(member.name)
            assert member.name not in seen and member.isreg()
            assert member.mode == 0o644 and member.uid == member.gid == member.mtime == 0
            seen.add(member.name)
            data = tar.extractfile(member).read()
            assert len(data) == member.size
            if member.name == 'RAW-MANIFEST.json':
                assert files is None and len(seen) == 1
                checked(data, index['manifest'])
                manifest = json.loads(data)
                assert manifest['schema'] == 'hia.compact-render-R1-R5.present-originals-CAS.v1'
                files = manifest['files']
                assert len(files) == index['logical_files']
                assert sum(row['bytes'] for row in files.values()) == index['logical_bytes']
                for name, row in files.items():
                    safe(name)
                    assert row['git_mode'] in ('100644', '100755')
                    aliases.setdefault(row['sha256'], []).append(name)
                continue
            assert files is not None and member.name.startswith('objects/')
            digest = member.name[len('objects/'):]
            assert digest in aliases and hashlib.sha256(data).hexdigest() == digest
            for name in aliases[digest]:
                checked(data, files[name])
                path = target / name
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open('xb') as stream:
                    stream.write(data)
                path.chmod(files[name]['mode_bits'])
    assert files is not None
    assert seen == {'RAW-MANIFEST.json'} | {'objects/' + key for key in aliases}
    actual = set()
    for path in target.rglob('*'):
        mode = path.lstat().st_mode
        assert not stat.S_ISLNK(mode)
        if stat.S_ISREG(mode):
            name = path.relative_to(target).as_posix()
            actual.add(name)
            checked(path.read_bytes(), files[name])
            assert ('100755' if mode & 0o111 else '100644') == files[name]['git_mode']
            assert stat.S_IMODE(mode) == files[name]['mode_bits']
        else:
            assert stat.S_ISDIR(mode)
    assert actual == set(files)
    return {'status': 'PASS', 'logical_files': len(files), 'logical_bytes': index['logical_bytes'],
            'archive': index['archive'], 'manifest': index['manifest'],
            'all_paths_bytes_modes_SHA_Git_verified': True, 'new_product_executions': 0,
            'known_missing_originals': manifest['known_missing_originals'],
            'all_historical_originals_retained': False}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('publication', type=Path)
    parser.add_argument('target', type=Path)
    args = parser.parse_args()
    print(json.dumps(restore(args.publication, args.target), indent=2))
