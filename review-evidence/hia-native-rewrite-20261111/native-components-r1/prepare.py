"""Verify and publish a development checkpoint; never promote it to qualification."""
from pathlib import Path, PurePosixPath
from hashlib import sha256, sha1
import io
import json
import tarfile

ROOT = Path(__file__).resolve().parent.parent
HERE = Path(__file__).resolve().parent
PREFIX = 'review-evidence/hia-native-rewrite-20261111/native-components-r1'
files = []
verified = []

def read_json(path):
    return json.loads(Path(path).read_bytes())

def verify_archive(path, rows, expected_sha):
    raw = Path(path).read_bytes()
    assert sha256(raw).hexdigest() == expected_sha
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:xz') as archive:
        members = archive.getmembers()
        assert len(members) == len(rows)
        expected = {row['path']: row for row in rows}
        assert len(expected) == len(rows)
        assert {member.name for member in members} == set(expected)
        for member in members:
            assert member.isfile()
            parsed = PurePosixPath(member.name)
            assert not parsed.is_absolute() and '..' not in parsed.parts
            row = expected[member.name]
            content = archive.extractfile(member).read()
            assert len(content) == row['bytes'] and sha256(content).hexdigest() == row['sha256']
            assert member.mode == row['mode']
        verified.append({'path': str(path), 'archive_bytes': len(raw),
            'archive_sha256': expected_sha, 'members': len(members),
            'raw_bytes': sum(row['bytes'] for row in rows), 'every_byte_size_mode_read_back': True})
    return raw

def add(path, name):
    path = Path(path).resolve()
    raw = path.read_bytes()
    files.append({'local_path': str(path), 'path': PREFIX + '/' + name,
        'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
        'git_sha': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
        'mode': '100644'})

for stage in (8, 9):
    directory = ROOT / 'native-composite-driver-next/checkpoints' / ('stage' + str(stage))
    manifest = read_json(directory / 'source.json')
    custody = read_json(directory / 'custody.json')
    assert sha256((directory / 'source.json').read_bytes()).hexdigest() == custody['source_manifest_sha256']
    archive = directory / ('native-composite-driver-stage' + str(stage) + '-development.tar.xz')
    verify_archive(archive, manifest['members'], custody['sha256'])
    add(archive, archive.name)
    add(directory / 'source.json', 'driver-stage' + str(stage) + '-source.json')
    add(directory / 'custody.json', 'driver-stage' + str(stage) + '-custody.json')

type_archive = ROOT / 'hia-composite-type-transport-r1-development.tar.xz'
type_custody_path = ROOT / 'hia-composite-type-transport-r1-development-custody.json'
type_custody = read_json(type_custody_path)
type_raw = verify_archive(type_archive, type_custody['files'], type_custody['sha256'])
with tarfile.open(fileobj=io.BytesIO(type_raw), mode='r:xz') as outer:
    nested_name = 'development/large-actual-response-r1-r2.tar.xz'
    nested = outer.extractfile(nested_name).read()
    custody = json.loads(outer.extractfile('development/large-actual-response-r1-r2-custody.json').read())
    assert sha256(nested).hexdigest() == custody['sha256']
    with tarfile.open(fileobj=io.BytesIO(nested), mode='r:xz') as inner:
        rows = custody['files']
        expected = {row['path']: row for row in rows}
        assert len(rows) == len(expected) == len(inner.getmembers())
        for member in inner.getmembers():
            assert member.isfile() and member.name in expected
            row = expected[member.name]
            content = inner.extractfile(member).read()
            assert len(content) == row['bytes'] and sha256(content).hexdigest() == row['sha256']
            assert member.mode == row['mode']
        verified.append({'path': str(type_archive) + ':' + nested_name, 'archive_bytes': len(nested),
            'archive_sha256': custody['sha256'], 'members': len(rows),
            'raw_bytes': sum(row['bytes'] for row in rows), 'every_byte_size_mode_read_back': True})
add(type_archive, type_archive.name)
add(type_custody_path, type_custody_path.name)

directory = ROOT / 'native-linked-observer-next/checkpoints/stage1'
manifest = read_json(directory / 'source.json')
custody = read_json(directory / 'custody.json')
assert sha256((directory / 'source.json').read_bytes()).hexdigest() == custody['source_manifest_sha256']
archive = directory / 'native-linked-observer-stage1-development.tar.xz'
verify_archive(archive, manifest['members'], custody['sha256'])
add(archive, archive.name)
add(directory / 'source.json', 'linked-observer-stage1-source.json')
add(directory / 'custody.json', 'linked-observer-stage1-custody.json')

storage = ROOT / 'agent-persistence-independent-d5'
custody = read_json(storage / 'custody.json')
for name, row in custody['files'].items():
    path = storage / name
    raw = path.read_bytes()
    assert len(raw) == row['bytes'] and sha256(raw).hexdigest() == row['sha256']
    assert path.stat().st_mode & 511 == row['mode']
    add(path, 'storage/' + name)
add(storage / 'custody.json', 'storage/custody.json')

readback = {'scope': 'INDEPENDENT_ARCHIVE_READBACK_NOT_NATIVE_TEST_RERUN',
    'archives': verified, 'all_archive_member_bytes_sha256_and_modes_verified': True,
    'production_activated': False, 'whole_stack_closed': False}
(HERE / 'independent-readback.json').write_text(json.dumps(readback, indent=2, sort_keys=True) + '\n')
add(HERE / 'independent-readback.json', 'independent-readback.json')
add(HERE / 'README.md', 'README.md')
add(Path(__file__), 'prepare.py')
plan = {'schema': 'hepta.hia.recovery-publication-plan.v1',
    'repository': 'TrillionniumFoundation/Hepta', 'branch': 'recovery/hia-function-9acdfa-20261111',
    'parent': '29a1680140cfe65636539af63440c79f86ff0321',
    'base_tree': '097c4af045470435cecded38c4b8387f4fa8134f',
    'main_preserved': '5831f52fada45e076f8f68f198a15c0585e6104f', 'files': files,
    'whole_stack_closed': False}
(HERE / 'publication-plan.json').write_text(json.dumps(plan, indent=2, sort_keys=True) + '\n')
print(json.dumps({'files': len(files), 'bytes': sum(row['bytes'] for row in files),
    'verified_archives': len(verified), 'verified_members': sum(row['members'] for row in verified)}))
