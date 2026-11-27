"""Reconstruct or verify the complete retained CLI development evidence.

Reads only immutable UTF-8 parts, the transport and their contained raw archive.
It imports no project module and executes no compiled image or project test.
"""
from pathlib import Path, PurePosixPath
import argparse
import base64
import hashlib
import io
import json
import tarfile


def sha(raw): return hashlib.sha256(raw).hexdigest()
def git(raw): return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('transport', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    if (args.output is None) == (not args.verify_only):
        parser.error('choose exactly one of --output or --verify-only')
    root = args.transport.parent
    transport = json.loads(args.transport.read_text())
    assert transport['schema'] == 'hia.archive-utf8-transport.v1'
    chunks = []
    offset = 0
    for index, record in enumerate(transport['parts']):
        raw = (root / record['path']).read_bytes()
        assert len(raw) == record['wrapper_bytes'] and sha(raw) == record['wrapper_sha256'] and git(raw) == record['git_blob']
        row = json.loads(raw)
        assert row['schema'] == 'hia.archive-utf8-part.v1' and row['encoding'] == 'base64'
        assert type(row['index']) is int and row['index'] == index == record['index']
        assert type(row['offset']) is int and row['offset'] == offset == record['offset']
        assert row['archive_sha256'] == transport['archive_sha256']
        block = base64.b64decode(row['data'], validate=True)
        assert type(row['bytes']) is int and len(block) == row['bytes'] == record['bytes']
        assert sha(block) == row['sha256'] == record['sha256']
        chunks.append(block); offset += len(block)
    archive = b''.join(chunks)
    assert len(archive) == transport['archive_bytes'] and sha(archive) == transport['archive_sha256']
    manifest = None
    seen = {}
    retained = {} if not args.verify_only else None
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        for member in tar:
            assert member.isfile() and member.mode == 0o444
            raw = tar.extractfile(member).read()
            assert len(raw) == member.size
            if member.name == 'MANIFEST.json':
                assert manifest is None
                assert len(raw) == transport['manifest_bytes'] and sha(raw) == transport['manifest_sha256'] and git(raw) == transport['manifest_git_blob']
                manifest = json.loads(raw)
                assert manifest['schema'] == 'hia.logical-full-evidence-cas.v1'
                continue
            assert manifest is not None and member.name.startswith('objects/') and member.name.endswith('.raw')
            digest = member.name[8:-4]
            assert digest in manifest['objects'] and digest not in seen
            record = manifest['objects'][digest]
            assert sha(raw) == digest and len(raw) == record['bytes'] and git(raw) == record['git_blob']
            seen[digest] = {'bytes': len(raw), 'git_blob': git(raw)}
            if retained is not None: retained[digest] = raw
    assert manifest is not None and seen == manifest['objects']
    assert len(seen) == transport['unique_objects']
    assert len(manifest['logical_files']) == transport['logical_files']
    assert sum(row['bytes'] for row in manifest['logical_files'].values()) == transport['logical_bytes']
    if args.output is not None: args.output.mkdir(exist_ok=False)
    for name, record in manifest['logical_files'].items():
        relative = PurePosixPath(name)
        assert not relative.is_absolute() and name == relative.as_posix() and '..' not in relative.parts and '\0' not in name
        assert seen[record['sha256']] == {'bytes': record['bytes'], 'git_blob': record['git_blob']}
        assert type(record['mode']) is str and len(record['mode']) == 4 and record['mode'][0] == '0'
        mode = int(record['mode'], 8); assert mode <= 0o777
        if args.output is not None:
            target = args.output / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream: stream.write(retained[record['sha256']])
            target.chmod(mode)
            actual = target.read_bytes()
            assert sha(actual) == record['sha256'] and len(actual) == record['bytes'] and git(actual) == record['git_blob']
            assert target.stat().st_mode & 0o777 == mode
    print(json.dumps({'status': 'PASS', 'logical_files': len(manifest['logical_files']),
        'objects': len(seen), 'archive_sha256': sha(archive), 'project_executed': False,
        'restored': args.output is not None}, sort_keys=True))


if __name__ == '__main__': main()
