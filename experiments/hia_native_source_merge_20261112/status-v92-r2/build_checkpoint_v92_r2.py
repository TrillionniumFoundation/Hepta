"""Preserve exact post-v92-r1 records, including complete finite actual originals."""
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile

sys.dont_write_bytecode = True
sys.path.insert(0, '/workspace/scratch/e26ed3e2edcf/root')
from audit_cli_r2b_actual_publication import read, pin, save, identity, blob

BASE = Path('/workspace/scratch/e26ed3e2edcf')
ROOT = BASE / 'root'
OUT = ROOT / 'checkpoint-v92-r2'
assert not OUT.exists()
selected = {}


def add(path, name):
    assert name not in selected and path.is_file()
    assert '/private/' not in str(path)
    selected[name] = path


def folder(path, prefix):
    assert path.is_dir()
    for current, directories, files in os.walk(path):
        # Full remote raw caches duplicate canonical source bodies. Preserve
        # their complete recorded readback metadata, without more cache copies.
        directories[:] = sorted(d for d in directories if d not in ('raw', 'private', '__pycache__'))
        for name in sorted(files):
            item = Path(current) / name
            assert stat.S_ISREG(item.lstat().st_mode)
            add(item, prefix + '/' + item.relative_to(path).as_posix())


for name in (
    'PR888-v92-r2-proposed.md', 'PR888-v92-r2-BODY-PIN.json',
    'PR888-v92-r2-draft-before-actual-updates.md', 'PR888-v92-r2-LEASE.provider.json',
    'build_checkpoint_v92_r2.py', 'git_object_helpers_v2.js',
    'audit_cli_r2b_actual_publication.py', 'audit_cli_r3_actual_publication.py',
    'review_cli_finite_r4b_inputs.py', 'invoke_cli_source28_r4b_once.py',
    'audit_cli_source28_r4b_actual.py', 'invoke_cli_finite_r4b_once.py',
    'audit_cli_finite_r4b_actual.py', 'audit_cli_finite_r4b_actual_reader_r2.py',
    'review_v92_failed_ci_recovery_r1.py', 'audit_v92_recovery_small_actual_r1.py',
    'invoke_full32_stream_receiver_r2_once.py', 'preserve_full32_stream_r2_preexec_hold.py',
    'audit_rust195_source8_r2_publication.py', 'reclaim_verified_checkpoint_carriers_v92.py',
):
    add(ROOT / name, 'workspace/root/' + name)
for name in (
    'cli-c-runtime-lifetime-review-r2b', 'cli-c-runtime-lifetime-invocation-r2b',
    'cli-c-runtime-lifetime-actual-r2b-git-review',
    'cli-c-runtime-lifetime-review-r3', 'cli-c-runtime-lifetime-invocation-r3',
    'cli-c-runtime-lifetime-actual-r3-git-review',
    'cli-c-runtime-lifetime-review-r4b', 'cli-runtime-layout-source28-r4b-invocation',
    'cli-runtime-layout-source28-r4b-owner', 'cli-c-runtime-lifetime-invocation-r4b',
    'v92-standard-ci-r1', 'v92-ci-recovery-r1-review', 'v92-ci-recovery-r1-actual',
    'v92-ci-recovery-r1-actual-git-review',
    'full32-rust195-source8-r2-review', 'full32-rust195-source8-r2-invocation',
    'full32-rust195-source8-r2-actual-git-review',
    'full32-stream-r2-review', 'full32-stream-source24-r2-invocation',
    'full32-stream-r2-preexec-hold', 'derived-checkpoint-transport-cleanup-r2',
):
    folder(ROOT / name, 'workspace/root/' + name)
folder(BASE / 'native-cli-c-runtime-lifetime-actual-r4b', 'external/cli-r4b-finite-actual')
folder(BASE / 'native-cli-runtime-layout-source-controls-r4b', 'external/cli-r4b-source28-actual')
folder(Path('/tmp/hia-full32-r4-stream-source-controls-r2-20261112-e26e'), 'external/full32-r2-source24-actual')
folder(Path('/tmp/hia-full32-r4-stream-source-controls-r2-owner-20261112-e26e'), 'external/full32-r2-source24-owner')
for name in ('COLLECTION-READBACK.json',):
    add(Path('/tmp/hia-full32-r4-ten-reference-receipts-r2-20261113-e26e') / name,
        'external/full32-ten-reference-public-receipts/' + name)
add(Path('/tmp/hia-v92-standard-ci-readonly-43324913647-r1/cli-peer/ELF-R4B-ADDRESS-ORIGINS-STATIC-REVIEW.json'),
    'external/cli-r4b-peer/ELF-R4B-ADDRESS-ORIGINS-STATIC-REVIEW.json')


def digest(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'git_blob': blob(raw)}


rows, bodies = [], {}
for name, path in sorted(selected.items()):
    for parent in path.parents:
        assert stat.S_ISDIR(parent.lstat().st_mode)
    before = identity(path.lstat())
    raw = read(path)
    assert identity(path.lstat()) == before
    rows.append({'path': name, 'original_path': str(path), 'original_identity': before,
                 'mode': stat.S_IMODE(before['mode']), **digest(raw)})
    bodies[name] = raw
OUT.mkdir(mode=0o700)
archive_path = OUT / 'root-originals.tar.gz'
with archive_path.open('xb') as stream, gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as compressed, tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
    for row in rows:
        info = tarfile.TarInfo(row['path'])
        info.size, info.mode, info.mtime = row['bytes'], row['mode'], 0
        archive.addfile(info, io.BytesIO(bodies[row['path']]))
with tarfile.open(archive_path, mode='r:gz') as archive:
    entries = archive.getmembers()
    assert len(entries) == len(rows)
    for row, entry in zip(rows, entries, strict=True):
        assert entry.isfile() and entry.name == row['path'] and entry.mode == row['mode']
        assert archive.extractfile(entry).read() == bodies[row['path']] == read(Path(row['original_path']))
compressed = read(archive_path)
parts = []
for i, offset in enumerate(range(0, len(compressed), 320 << 10)):
    chunk = compressed[offset:offset + (320 << 10)]
    payload = base64.b64encode(chunk) + b'\n'
    name = f'root-originals-{i:03d}.base64'
    with (OUT / name).open('xb') as stream:
        stream.write(payload)
    parts.append({'path': name, 'offset': offset, 'raw_bytes': len(chunk), **digest(payload)})
assert b''.join(base64.b64decode(read(OUT / p['path'])[:-1], validate=True) for p in parts) == compressed
report = {'schema': 'hia.root.actual-progress-checkpoint.v4',
    'parent': '0031fc8f535a4f883945d3e061d37a0c9b442092',
    'parent_tree': 'ddd13deccd683cfca2541d41d83fe20a181e1a03',
    'originals': rows, 'original_count': len(rows), 'original_bytes': sum(r['bytes'] for r in rows),
    'archive': digest(compressed), 'parts': parts, 'all_archive_members_equal_to_originals': True,
    'complete_cli_r4b_actual_preserved': True, 'complete_cli_source28_actual_preserved': True,
    'complete_full32_stream_r2_source24_actual_preserved': True,
    'existing_canonical_actual_branches': {'cli_r2b': '666a01b759ab7e01cde7d4432c8909b06ce8484a',
        'cli_r3': 'f9afe31e640ec51d8fdcf7bd35a54e18bb4ccb12',
        'rust195_source8': 'e83c8201bd5a2decaabea2c1080a27e4cf3dabb0',
        'v92_recovery_small_actual': 'b32b3e5ff65e8161cd705c3e90724559c7aa04a8'},
    'source_native_ci_rerun': False, 'private_provider_refs_or_proxy_configuration_included': False,
    'old_failures_UNKNOWN_and_reader_authoring_failures_preserved': True,
    'whole_native_rewrite_closed': False, 'default_activated': False, 'legacy_product_deleted': False}
save(OUT / 'ARCHIVE.json', report)
for name in ('PR888-v92-r2-proposed.md', 'PR888-v92-r2-BODY-PIN.json', 'build_checkpoint_v92_r2.py'):
    with (OUT / name).open('xb') as stream:
        stream.write(read(ROOT / name))
prefix = 'experiments/hia_native_source_merge_20261112/status-v92-r2/'
files = [{'path': prefix + path.name, 'local': str(path), 'mode': '100644', **digest(read(path))}
         for path in sorted(OUT.iterdir()) if path.name != 'root-originals.tar.gz']
save(OUT / 'FILES.json', files)
print(json.dumps({'files': len(files), 'originals': len(rows), 'original_bytes': report['original_bytes'], 'archive': report['archive'], 'parts': len(parts)}))
