"""Restore the exact retained Future test inputs into a new private directory.

This is a development fixture reader. It neither executes the retained oracle
nor qualifies a candidate, and it is not part of the native source authority.
"""
from __future__ import annotations

import argparse
from hashlib import sha1, sha256
import io
import json
from pathlib import Path, PurePosixPath
import tarfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/hia_future_original_20261125'
ARCHIVE_PIN = (56998, '2fe655ee40a1a85a6f117bb110c7a7e3b646ca258bbfcd1a2ff700867dfdedd1')
ORACLE_PIN = (29432, 'd5a3c81eb0d7907fe872565b6ca6605708f8a6f13fd5a8d55788a9a13a095f7b')
ORACLE_BLOB = '808135dc72c5a3d7b24954fde3383d3ba2337c42'
ORACLE_COMMIT = '2bd473f6ff51c2afac7b7bb009402368af2afdee'
ORACLE_NAME = 'future-public-inherited-source/hepta/hia_background_optimizer.py'
ORIGINAL_PREFIX = '/home/qian-qi/.local/state/hia-native-final-custody-20261125'


def identity(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def checked_bytes(path, expected):
    raw = path.read_bytes()
    if (len(raw), sha256(raw).hexdigest()) != expected:
        raise ValueError('retained Future fixture bytes differ: ' + str(path))
    return raw


def load_sources(fixture_directory=FIXTURES):
    archive = checked_bytes(fixture_directory / 'fixtures.tar.gz', ARCHIVE_PIN)
    oracle = checked_bytes(fixture_directory / 'hia_background_optimizer.py.txt', ORACLE_PIN)
    if sha1(b'blob ' + str(len(oracle)).encode('ascii') + b'\0' + oracle).hexdigest() != ORACLE_BLOB:
        raise ValueError('retained Future oracle differs from its original Git blob')
    sources = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as reader:
        members = reader.getmembers()
        if len(members) != 40 or sum(member.size for member in members) != 258274:
            raise ValueError('retained Future archive inventory differs')
        for member in members:
            path = PurePosixPath(member.name)
            if (not member.isfile() or member.name in sources or path.is_absolute()
                    or path.as_posix() != member.name or not path.parts
                    or any(part in ('', '.', '..') for part in path.parts)
                    or member.mode != 0o400 or not 0 < member.size <= 62319):
                raise ValueError('retained Future archive has an invalid member')
            stream = reader.extractfile(member)
            if stream is None:
                raise ValueError('retained Future archive member is missing')
            with stream:
                raw = stream.read(member.size + 1)
            if len(raw) != member.size:
                raise ValueError('retained Future archive member has an invalid extent')
            sources[member.name] = raw
    custody = json.loads(sources['fixture-source-custody.json'])
    if (custody['schema'] != 'hepta.hia.retained-future-fixture-source-custody.v1'
            or custody['original_prefix'] != ORIGINAL_PREFIX
            or set(custody['files']) != set(sources) - {'fixture-source-custody.json'}):
        raise ValueError('retained Future fixture custody inventory differs')
    for name, expected in custody['files'].items():
        if identity(sources[name]) != expected:
            raise ValueError('retained Future fixture source pin differs: ' + name)
    sources[ORACLE_NAME] = oracle
    return sources


def materialize(output, fixture_directory=FIXTURES):
    # Admit the complete immutable archive and independent original oracle
    # before creating anything. Never overwrite or remove an existing output.
    sources = load_sources(fixture_directory)
    output = Path(output)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, raw in sorted(sources.items()):
        path = output / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw)
        path.chmod(0o400)
    actual = {name: identity((output / name).read_bytes()) for name in sources}
    if actual != {name: identity(raw) for name, raw in sources.items()}:
        raise ValueError('retained Future fixtures changed during materialization')
    return {'schema': 'hepta.hia.future-original-fixture-materialization.v1',
            'original_root_prefix': ORIGINAL_PREFIX, 'original_oracle_commit': ORACLE_COMMIT,
            'original_oracle_git_blob': ORACLE_BLOB, 'files': actual,
            'fixture_count': len(actual), 'behavior_qualified': False,
            'whole_native_delivery_qualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(materialize(arguments.output), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
