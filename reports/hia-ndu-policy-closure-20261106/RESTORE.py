"""Restore the terminal policy evidence and verify every original file byte."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile


ROOT = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def restore(name, output):
    manifest = json.loads((ROOT / (name + '-manifest.json')).read_bytes())
    parts = json.loads((ROOT / (name + '-parts.json')).read_bytes())
    archive = output / 'archives' / manifest['archive']
    total = 0
    combined = hashlib.sha256()
    with archive.open('xb') as stream:
        for index, part in enumerate(parts):
            expected_name = f'{name}-{index:03d}.tar.xz.part'
            require(part['file'] == expected_name, 'part order/name mismatch')
            data = (ROOT / 'raw' / part['file']).read_bytes()
            require(len(data) == part['bytes'], 'part length mismatch: ' + part['file'])
            require(hashlib.sha256(data).hexdigest() == part['sha256'], 'part SHA-256 mismatch')
            git_blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            require(git_blob == part['git_blob_sha'], 'part Git blob mismatch')
            stream.write(data)
            combined.update(data)
            total += len(data)
    require(total == manifest['archive_bytes'], 'archive size mismatch')
    require(combined.hexdigest() == manifest['archive_sha256'], 'archive SHA-256 mismatch')
    expected = {entry['path']: entry for entry in manifest['members']}
    require(len(expected) == len(manifest['members']) == manifest['member_count'], 'duplicate manifest members')
    restored = set()
    destination = output / name
    destination.mkdir()
    with tarfile.open(archive, 'r:xz') as bundle:
        for member in bundle:
            path = PurePosixPath(member.name)
            require(member.isfile() and not path.is_absolute() and '..' not in path.parts,
                    'unsafe or nonregular archive member')
            require(member.name in expected and member.name not in restored, 'unexpected/duplicate archive member')
            data = bundle.extractfile(member).read()
            record = expected[member.name]
            require(len(data) == record['bytes'] == member.size, 'member length mismatch: ' + member.name)
            require(hashlib.sha256(data).hexdigest() == record['sha256'], 'member SHA-256 mismatch: ' + member.name)
            target = destination.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(data)
            restored.add(member.name)
    require(restored == set(expected), 'missing archive members')
    return {'archive': name, 'bytes': total, 'sha256': combined.hexdigest(),
            'verified_members': len(restored), 'parts': len(parts)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='A new destination directory; existing paths are refused.')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'archives').mkdir()
    result = [restore(name, args.output) for name in ('policy-raw',)]
    print(json.dumps({'verified': True, 'archives': result}, indent=2))


if __name__ == '__main__':
    main()
