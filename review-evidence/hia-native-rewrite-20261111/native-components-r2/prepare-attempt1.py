"""Freeze complete originals and independently verify this recovery checkpoint."""
from pathlib import Path, PurePosixPath
from hashlib import sha256, sha1
import io, json, stat, tarfile

ROOT = Path(__file__).resolve().parent.parent
HERE = Path(__file__).resolve().parent
PREFIX = 'review-evidence/hia-native-rewrite-20261111/native-components-r2'
files, verified = [], []

def read_json(path):
    return json.loads(Path(path).read_bytes())

def verify_archive(path, rows, expected_sha):
    path = Path(path)
    assert sha256(path.read_bytes()).hexdigest() == expected_sha
    expected = {row['path']: row for row in rows}
    assert len(expected) == len(rows)
    with tarfile.open(path, 'r:xz') as archive:
        members = archive.getmembers()
        assert len(members) == len(rows) and {m.name for m in members} == set(expected)
        for member in members:
            assert member.isfile()
            parsed = PurePosixPath(member.name)
            assert not parsed.is_absolute() and '..' not in parsed.parts
            row = expected[member.name]
            raw = archive.extractfile(member).read()
            assert len(raw) == row['bytes'] and sha256(raw).hexdigest() == row['sha256']
            assert member.mode == row['mode']
    verified.append({'path': str(path), 'archive_bytes': path.stat().st_size,
        'archive_sha256': expected_sha, 'members': len(rows),
        'raw_bytes': sum(row['bytes'] for row in rows), 'every_byte_size_mode_read_back': True})

def add(path, name):
    path = Path(path).resolve()
    raw = path.read_bytes()
    files.append({'local_path': str(path), 'path': PREFIX + '/' + name,
        'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
        'git_sha': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), 'mode': '100644'})

# This bundle deliberately excludes the still-running second source attempt.
dev = ROOT / 'hia-linked-observer-integration-development'
sources = [(p, 'integration/' + p.name) for p in sorted(dev.iterdir())
           if p.is_file() and not p.name.startswith('source-attempt2-controller.')]
for name in ('source-v66-complete-attempt1', 'observer-v66-complete-attempt1'):
    sources.extend((p, 'integration/' + str(p.relative_to(dev)))
                   for p in sorted((dev / name).rglob('*')) if p.is_file())
for name in ('flat-actual', 'linked-actual'):
    folder = Path('/dev/shm/hia-v66-observer-tests') / name
    sources.extend((p, 'actual-observer-tests/' + name + '/' + str(p.relative_to(folder)))
                   for p in sorted(folder.rglob('*')) if p.is_file())
for dirname in ('hia-type-transport-r2-independent-review', 'd684-original-preservation'):
    folder = ROOT / dirname
    sources.extend((p, dirname + '/' + str(p.relative_to(folder)))
                   for p in sorted(folder.rglob('*')) if p.is_file())
rows = []
archive = HERE / 'integration-and-independent-originals.tar.xz'
with tarfile.open(archive, 'x:xz', preset=3) as tf:
    for path, name in sources:
        assert not path.is_symlink()
        raw = path.read_bytes()
        mode = stat.S_IMODE(path.stat().st_mode)
        rows.append({'path': name, 'bytes': len(raw), 'mode': mode,
                     'sha256': sha256(raw).hexdigest(), 'origin': str(path)})
        info = tarfile.TarInfo(name)
        info.size, info.mode, info.mtime = len(raw), mode, 0
        tf.addfile(info, io.BytesIO(raw))
manifest_path = HERE / 'integration-and-independent-originals-source.json'
manifest_path.write_text(json.dumps({'scope': 'COMPLETE_COMPONENT_ORIGINALS_AND_FIRST_FAILED_SOURCE_GATE_NOT_COLD',
    'members': rows}, indent=2, sort_keys=True) + '\n')
verify_archive(archive, rows, sha256(archive.read_bytes()).hexdigest())
add(archive, archive.name)
add(manifest_path, manifest_path.name)

for label in ('9-joint', '10', '11'):
    directory = ROOT / 'native-composite-driver-next/checkpoints' / ('stage' + label)
    manifest = read_json(directory / 'source.json')
    custody = read_json(directory / 'custody.json')
    assert sha256((directory / 'source.json').read_bytes()).hexdigest() == custody['source_manifest_sha256']
    archive = directory / ('native-composite-driver-stage' + label + '-development.tar.xz')
    verify_archive(archive, manifest.get('members', manifest.get('files')), custody['sha256'])
    add(archive, archive.name)
    add(directory / 'source.json', 'driver-stage' + label + '-source.json')
    add(directory / 'custody.json', 'driver-stage' + label + '-custody.json')

for stage in (2, 3):
    directory = ROOT / 'native-linked-observer-next/checkpoints' / ('stage' + str(stage))
    manifest = read_json(directory / 'source.json')
    custody = read_json(directory / 'custody.json')
    assert sha256((directory / 'source.json').read_bytes()).hexdigest() == custody['source_manifest_sha256']
    archive = directory / ('native-linked-observer-stage' + str(stage) + '-development.tar.xz')
    verify_archive(archive, manifest['members'], custody['sha256'])
    add(archive, archive.name)
    add(directory / 'source.json', 'linked-observer-stage' + str(stage) + '-source.json')
    add(directory / 'custody.json', 'linked-observer-stage' + str(stage) + '-custody.json')

for stem, hash_key in [('hia-composite-type-transport-r2-development', 'sha256'),
                       ('hia-observer-linked-flat-independent-review', 'archive_sha256')]:
    archive = ROOT / (stem + '.tar.xz')
    custody_path = ROOT / (stem + '-custody.json')
    custody = read_json(custody_path)
    verify_archive(archive, custody['files'], custody[hash_key])
    add(archive, archive.name)
    add(custody_path, custody_path.name)

directory = ROOT / 'hia-agent-namespace-store-development'
archive = directory / 'values-r2-development.tar.xz'
custody_path = directory / 'values-r2-development.custody.json'
custody = read_json(custody_path)
with tarfile.open(archive, 'r:xz') as tf:
    raw = tf.extractfile('member-manifest.json').read()
    assert sha256(raw).hexdigest() == custody['manifest_sha256']
    member_map = json.loads(raw)['members']
    rows = [{'path': name, **row} for name, row in member_map.items()]
    rows.append({'path': 'member-manifest.json', 'bytes': len(raw),
                 'mode': tf.getmember('member-manifest.json').mode, 'sha256': custody['manifest_sha256']})
verify_archive(archive, rows, custody['sha256'])
add(archive, 'namespace-values-r2-development.tar.xz')
add(custody_path, 'namespace-values-r2-development-custody.json')

readback = {'scope': 'INDEPENDENT_ARCHIVE_READBACK_NOT_NATIVE_TEST_RERUN', 'archives': verified,
    'all_archive_member_bytes_sha256_and_modes_verified': True,
    'production_activated': False, 'whole_stack_closed': False}
(HERE / 'independent-readback.json').write_text(json.dumps(readback, indent=2, sort_keys=True) + '\n')
add(HERE / 'independent-readback.json', 'independent-readback.json')
add(HERE / 'README.md', 'README.md')
add(Path(__file__), 'prepare.py')
plan = {'schema': 'hepta.hia.recovery-publication-plan.v1',
    'repository': 'TrillionniumFoundation/Hepta', 'branch': 'recovery/hia-function-9acdfa-20261111',
    'parent': 'c71d82ff026d5bbb9bca28576b7301f2c505f3d4',
    'base_tree': 'cdd03d737ecf74715b9980f8a64b0978a733aeb6',
    'main_preserved': '5831f52fada45e076f8f68f198a15c0585e6104f', 'files': files,
    'whole_stack_closed': False}
(HERE / 'publication-plan.json').write_text(json.dumps(plan, indent=2, sort_keys=True) + '\n')
print(json.dumps({'files': len(files), 'bytes': sum(row['bytes'] for row in files),
    'verified_archives': len(verified), 'verified_members': sum(row['members'] for row in verified),
    'raw_bytes_read_back': sum(row['raw_bytes'] for row in verified)}))
