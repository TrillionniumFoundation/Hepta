"""Bind independent page development to exact d2 members and canonical wire delta."""
from hashlib import sha1, sha256
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import zipfile

ROOT = Path('/tmp/hia-e26e-artifact-page-r4')
SOURCE = ROOT / 'source'
PACKAGE = Path('/workspace/scratch/hia-machine-encoder-native-20261111/source/experiments/hia_v66_desktop_development_20261111/source-package-r2')
EXECUTED = Path('/workspace/scratch/hia-machine-encoder-native-20261111/source/experiments/hia_v66_integration_20261111/source-controls-r3/executed-source.zip')
HANDOFF = Path('/tmp/hia-wire-e26e-r8-cache-r1/handoff')
PINS = {
    'tools/generate_hia_artifact_page.py': 'e30b021f9510a2de18d2d68dce8d89a56a81e3a0c1ab95069ef0cf17344d2405',
    'examples/hia_bootstrap/artifact_page.hiaasm': '4cedc0e1442d6f2cb479e194cb1d5c14898055651ccaaa0afb3b907a91dea0b6',
    'hepta/hia_artifact_page_native.py': '91baeeb4f63c5cf4d223730bb3c16687127357f99076a4157c9a0df9c8355758',
}

def digest(raw):
    return sha256(raw).hexdigest()

def blob(raw):
    return sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

def name(value):
    p = PurePosixPath(value)
    assert str(p) == value and value and not p.is_absolute() and '..' not in p.parts
    return value

def read(path, expected=None):
    raw = path.read_bytes()
    if expected is not None:
        assert digest(raw) == expected, str(path)
    return raw

def create(path, raw, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
    assert path.read_bytes() == raw and stat.S_IMODE(path.stat().st_mode) == mode

def tar_rows(path, expected):
    result = {}
    with tarfile.open(path, 'r:xz') as archive:
        for member in archive:
            n = name(member.name)
            assert n not in result and member.isfile() and not member.issparse()
            row = expected[n]
            raw = archive.extractfile(member).read()
            assert len(raw) == row['size'] and digest(raw) == row['sha256']
            assert member.mode == (int(row.get('mode', '100644'), 8) & 0o777)
            if 'git_blob_sha1' in row:
                assert blob(raw) == row['git_blob_sha1']
            result[n] = (raw, member.mode)
    assert set(result) == set(expected)
    return result

os.umask(0o077)
assert not SOURCE.exists()
manifest_raw = read(PACKAGE / 'canonical-e09-development-package.json', '7a45af0a08d837c3ecba97cd47b54e1a3eb8838c838d03a14a82d58df3e799af')
manifest = json.loads(manifest_raw)
assert manifest['canonical_commit'] == 'e09c6faf5507fc4e38d8b7c36ba2650a1c0a10d6'
assert manifest['member_count'] == len(manifest['files']) == 1666
archive = PACKAGE / 'e09-program-and-declared-source.tar.xz'
read(archive, 'f0f0a0fd570fa2d260d95f25193b1d9571d9614bbc7ab1c22607f23112ae5428')
base_rows = {name(row['path']): row for row in manifest['files']}
assert len(base_rows) == 1666
files = tar_rows(archive, base_rows)
read(EXECUTED, '862c1cae8df60172296def6531dbfc28e10d30eb679f2a8bcab752cc038a59b8')
with zipfile.ZipFile(EXECUTED) as z:
    for n in ('docs/HIA_SELFHOST_CORE_SUPPORT.json', 'docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json'):
        files[n] = (z.read(n), 0o644)
canonical = json.loads((ROOT / 'inputs/d2-canonical-blobs.json').read_bytes())
for n, (raw, mode) in files.items():
    row = canonical[n]
    assert len(raw) == row['size'] and blob(raw) == row['sha'] and mode == int(row['mode'], 8) & 0o777, n
base_snapshot = {n: {'bytes': len(raw), 'sha256': digest(raw), 'git_blob': blob(raw), 'mode': mode}
                 for n, (raw, mode) in files.items()}
delta = json.loads((HANDOFF / 'source-delta-package.json').read_bytes())
read(HANDOFF / delta['archive']['path'], '9328766f8c1fb6f508eb8b6be2b4ea3bd962a77249a96054a13b48ae7bc30e47')
delta_rows = {name(row['path']): row for row in delta['files']}
for n, row in delta_rows.items():
    if row['base_entry'] is None:
        assert n not in files
    else:
        assert digest(files[n][0]) == row['base_entry']['sha256']
files.update(tar_rows(HANDOFF / delta['archive']['path'], delta_rows))
for n, expected in PINS.items():
    assert n not in files
    files[n] = (read(ROOT / 'page-inputs' / n, expected), 0o644)
SOURCE.mkdir(mode=0o700)
for n, (raw, mode) in files.items():
    create(SOURCE / n, raw, mode)
actual = {p.relative_to(SOURCE).as_posix() for p in SOURCE.rglob('*') if p.is_file()}
assert actual == set(files)
assert not any(p.is_symlink() for p in SOURCE.rglob('*'))
image = json.loads((HANDOFF / 'wire-development-image.json').read_bytes())
read(HANDOFF / image['archive']['path'], 'e12e152ae14147f1981d1b8015e2574646ff3b45c0a5106a34bb3643ae0d9b88')
image_files = tar_rows(HANDOFF / image['archive']['path'], image['files'])
for n, (raw, mode) in image_files.items():
    create(ROOT / 'wire' / n, raw, mode)
compiler = Path('/tmp/hia-e26e-desktop-b3-input/B3.image.bin')
create(ROOT / 'inputs/B3.image.bin', read(compiler, '0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'))
snapshot = {n: {'bytes': len(raw), 'sha256': digest(raw), 'git_blob': blob(raw), 'mode': mode}
            for n, (raw, mode) in files.items()}
report = {'schema': 'hia.artifact-page.development-materialization.v1',
          'status': 'EXACT_INPUT_BYTES_MATERIALIZED', 'scope': 'DEVELOPMENT_ONLY_NO_PRODUCT_EXECUTION',
          'base_commit': 'd2c22d0c4caea145295a8213c6c718eb55546ec9',
          'base_tree': '082ab925e16a1c89e2ada2ba9b6662e73dd60e00',
          'source': str(SOURCE), 'base_members': base_snapshot, 'final_members': snapshot,
          'canonical_wire_handoff': '514a13be3c4f956a8efa95bbfeb8bc43be896e49',
          'wire_delta': delta, 'page_source_pins': PINS, 'wire_image': image,
          'complete_git_object_closure': False, 'updated_global_contract': False,
          'whole_native_delivery_qualified': False}
create(ROOT / 'MATERIALIZATION.json', (json.dumps(report, indent=2, sort_keys=True) + '\n').encode())
print(json.dumps({'status': report['status'], 'base_members': len(base_snapshot),
                  'final_members': len(snapshot), 'wire_image_sha256': image['image_sha256']}))
