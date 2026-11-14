"""Read every immutable custody member; optionally reconstruct its exact logical files."""
from pathlib import Path, PurePosixPath
import argparse
import base64
import hashlib
import io
import json
import tarfile


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('publication', type=Path)
    parser.add_argument('--destination', type=Path)
    args = parser.parse_args()
    index = json.loads((args.publication / 'INDEX.json').read_bytes())
    assert index['schema'] == 'hia.R6.field-cost-complete-custody.v1'
    archive = bytearray()
    for number, row in enumerate(index['parts']):
        packet = (args.publication / row['path']).read_bytes()
        assert identity(packet) == {k: row[k] for k in ('bytes', 'sha256', 'git_blob')}
        value = json.loads(packet)
        assert value['number'] == number and value['offset'] == len(archive)
        raw = base64.b64decode(value['payload'], validate=True)
        assert identity(raw) == row['decoded'] == value['decoded']
        archive.extend(raw)
    assert identity(archive) == index['archive']
    if args.destination:
        args.destination.mkdir(exist_ok=False)
    seen = set()
    aliases = None
    files = None
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        for member in tar:
            assert member.isreg() and member.name not in seen
            assert member.uid == member.gid == member.mtime == 0 and member.mode == 0o644
            seen.add(member.name)
            raw = tar.extractfile(member).read()
            assert len(raw) == member.size
            if member.name == 'RAW-MANIFEST.json':
                assert files is None and identity(raw) == index['manifest']
                files = json.loads(raw)['files']
                aliases = {}
                for name, row in files.items():
                    path = PurePosixPath(name)
                    assert not path.is_absolute() and '..' not in path.parts and str(path) == name
                    assert type(row['mode']) is int and row['mode'] in (0o600, 0o644)
                    aliases.setdefault(row['sha256'], []).append(name)
                continue
            assert files is not None and member.name.startswith('objects/')
            digest = member.name[8:]
            assert digest in aliases and hashlib.sha256(raw).hexdigest() == digest
            for name in aliases[digest]:
                row = files[name]
                assert identity(raw) == {k: row[k] for k in ('bytes', 'sha256', 'git_blob')}
                if args.destination:
                    path = args.destination / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with path.open('xb') as output:
                        output.write(raw)
                    path.chmod(row['mode'])
                    assert path.read_bytes() == raw and path.stat().st_mode & 0o7777 == row['mode']
    assert seen == {'RAW-MANIFEST.json'} | {'objects/' + digest for digest in aliases}
    assert len(files) == index['logical_files']
    assert sum(row['bytes'] for row in files.values()) == index['logical_bytes']
    print(json.dumps({'status': 'PASS', 'members': len(seen), 'logical_files': len(files),
                      'logical_bytes': index['logical_bytes'], 'archive': index['archive'],
                      'materialized': bool(args.destination), 'new_product_executions': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
