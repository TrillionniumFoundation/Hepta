"""Package the explicit recovered-CI public allowlist; execute no evidence code."""
from datetime import datetime, timezone
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
from zipfile import ZipFile

BASE = Path('/workspace/scratch/bf7d454bbc83/round6-ci-publication')
SOURCE = Path('/workspace/scratch/bf7d454bbc83/round6-ci-recovery')
PREFIX = 'evidence/hia_round5_recovered_20261029'
DEST = BASE / PREFIX
PAYLOAD = BASE / 'payload'
HEAD = '70179fcc54e2195f9966ca3f98428a6540d50a41'
TREE = '13cc41cc64be27856119a942c166b8a9a690f32d'
EXPECTED_MANIFEST = '93fa8f3bc6f62721f68ce32d34510aa5fecb30819145dd1027f8220955ba4745'
EXPECTED_FREEZE = 'ff4ded3995a231d8cdaa87e5e399881f10a8ecb15652e9ff8e7cb9171998f54f'
PART_SIZE = 6 * 1024 * 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


def dump(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def safe_name(name):
    p = PurePosixPath(name)
    assert p.parts and not p.is_absolute() and '..' not in p.parts and '\\' not in name
    assert ':' not in p.parts[0] and p.as_posix() == name
    assert 'private-artifacts' not in p.parts
    return p


manifest_bytes = (SOURCE / 'PUBLIC_FILE_MANIFEST.json').read_bytes()
freeze_bytes = (SOURCE / 'PUBLIC_FREEZE.json').read_bytes()
assert sha(manifest_bytes) == EXPECTED_MANIFEST and sha(freeze_bytes) == EXPECTED_FREEZE
manifest = json.loads(manifest_bytes)
assert manifest['file_count'] == len(manifest['files']) == 366
assert manifest['total_bytes'] == sum(r['bytes'] for r in manifest['files']) == 60836946
rows = list(manifest['files']) + [
    {'archive_relative': 'PUBLIC_FILE_MANIFEST.json', 'bytes': len(manifest_bytes), 'sha256': sha(manifest_bytes)},
    {'archive_relative': 'PUBLIC_FREEZE.json', 'bytes': len(freeze_bytes), 'sha256': sha(freeze_bytes)},
]
assert len({r['archive_relative'] for r in rows}) == 368
DEST.mkdir(parents=True, exist_ok=True)
PAYLOAD.mkdir(parents=True, exist_ok=True)
index_rows, expansions = [], []
for row in sorted(rows, key=lambda x: x['archive_relative']):
    name = safe_name(row['archive_relative']).as_posix()
    original = SOURCE / name
    assert original.is_file() and not original.is_symlink()
    data = original.read_bytes()
    assert len(data) == row['bytes'] and sha(data) == row['sha256'], name
    target = PAYLOAD / name
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        try:
            os.link(original, target)
        except OSError:
            shutil.copyfile(original, target)
    assert target.read_bytes() == data
    index_rows.append({'path': name, 'bytes': len(data), 'sha256': sha(data), 'mode': 0o644,
                       'original_abs': str(original)})
    if name.endswith('.zip'):
        members = []
        with ZipFile(original) as z:
            assert len(z.namelist()) == len(set(z.namelist()))
            for member in z.infolist():
                n = member.filename.rstrip('/') if member.is_dir() else member.filename
                safe_name(n)
                mode = member.external_attr >> 16
                assert not stat.S_ISLNK(mode) and stat.S_IFMT(mode) in [0, stat.S_IFREG, stat.S_IFDIR]
                if member.is_dir():
                    continue
                payload = z.read(member)
                members.append({'path': n, 'bytes': len(payload), 'sha256': sha(payload), 'mode': mode & 0o777})
        expansions.append({'archive': name, 'destination': name.removesuffix('.zip') + '.expanded',
                           'member_count': len(members), 'bytes': sum(m['bytes'] for m in members), 'members': members})
index = {'schema': 'hepta.hia-round5-recovered.raw-index.v1', 'source_commit': HEAD, 'source_tree': TREE,
         'file_count': len(index_rows), 'bytes': sum(r['bytes'] for r in index_rows),
         'files': index_rows, 'zip_expansions': expansions,
         'selection': {'allowlist_sha256': EXPECTED_MANIFEST, 'freeze_sha256': EXPECTED_FREEZE,
                       'allowlist_files': 366, 'additional_original_outer_records': 2},
         'original_file_bytes_modified': False,
         'private_artifacts_included': False, 'lost_local_raw_restored': False,
         'note': 'Paths and file modes in the outer archive are packaging metadata; every original payload byte is unchanged. Original absolute report paths remain provenance.'}
assert index['file_count'] == 368 and len(expansions) == 17
dump(DEST / 'RAW-INDEX.json', index)
archive_path = BASE / 'work' / 'raw-evidence.tar.xz'
archive_path.parent.mkdir(parents=True, exist_ok=True)
with lzma.open(archive_path, 'wb', format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, preset=6) as out:
    with tarfile.open(fileobj=out, mode='w|', format=tarfile.PAX_FORMAT) as tar:
        for row in index_rows:
            info = tarfile.TarInfo(row['path'])
            info.size, info.mode, info.mtime, info.uid, info.gid = row['bytes'], row['mode'], 0, 0, 0
            info.uname = info.gname = ''
            with (PAYLOAD / row['path']).open('rb') as f:
                tar.addfile(info, f)
parts, combined_hash, combined_size = [], hashlib.sha256(), 0
with archive_path.open('rb') as source:
    for number, data in enumerate(iter(lambda: source.read(PART_SIZE), b'')):
        name = f'raw-evidence.tar.xz.part-{number:04d}'
        (DEST / name).write_bytes(data)
        parts.append({'path': name, 'bytes': len(data), 'sha256': sha(data)})
        combined_hash.update(data)
        combined_size += len(data)
index_bytes = (DEST / 'RAW-INDEX.json').read_bytes()
archive = {'schema': 'hepta.hia-round5-recovered.archive.v1', 'source_commit': HEAD, 'source_tree': TREE,
           'publication_parent': HEAD, 'format': 'tar.xz', 'compression': 'LZMA2 preset 6, 8 MiB dictionary, XZ CRC64',
           'bytes': combined_size, 'sha256': combined_hash.hexdigest(), 'file_count': len(index_rows),
           'uncompressed_file_bytes': index['bytes'], 'part_size': PART_SIZE, 'parts': parts,
           'index': {'path': 'RAW-INDEX.json', 'bytes': len(index_bytes), 'sha256': sha(index_bytes)},
           'public_ci_zip_count': len(expansions), 'public_ci_zip_member_count': sum(e['member_count'] for e in expansions),
           'public_ci_zip_uncompressed_member_bytes': sum(e['bytes'] for e in expansions),
           'private_original_zip_excluded': True, 'lost_local_raw_restored': False}
dump(DEST / 'ARCHIVE.json', archive)
reference = (BASE / 'reference/RESTORE.py').read_bytes()
reader = reference.decode().replace('hepta.hia-agent-closure.restore-verification.v1', 'hepta.hia-round5-recovered.restore-verification.v1')
reader = reader.replace('"""Verify/restore retained observations. Never execute any archived program."""',
    '"""Verify/restore recovered CI observations. Never execute archived programs.\n\nReader adapted from Hepta 3cfe761f0fa455679d0203f309c5adb5197a89a3.\n"""')
(DEST / 'RESTORE.py').write_text(reader)
dump(DEST / 'RESTORE-PROVENANCE.json', {'source_commit': '3cfe761f0fa455679d0203f309c5adb5197a89a3',
    'source_path': 'evidence/hia_agent_closure_20261028/RESTORE.py', 'original_reader_sha256': sha(reference),
    'adapted_reader_sha256': sha(reader.encode()),
    'changes': ['docstring describes recovered CI scope', 'output schema uses recovered round5 identity'],
    'validation_and_restoration_algorithm_unchanged': True, 'old_archive_downloaded': False})
for name in ['FINAL_STATUS.json', 'CI_RECOVERY_HANDOFF.json', 'RECOVERED_ARTIFACT_REVIEWS.json', 'UNRECOVERED_LOCAL_EVIDENCE.json']:
    (DEST / name).write_bytes((SOURCE / name).read_bytes())
(DEST / 'PACKAGER.py').write_bytes(Path(__file__).read_bytes())
(DEST / '.gitattributes').write_text('* -text\n')
dump(BASE / 'checkpoints/PACKAGE_READY.json', {'state': 'package_built_awaiting_complete_verify_only',
    'branch': 'codex/evidence-hia-round5-recovered-20261029', 'parent': HEAD, 'parent_tree': TREE,
    'prefix': PREFIX, 'archive': archive, 'published_remote': False})
print(json.dumps({'file_count': len(index_rows), 'raw_bytes': index['bytes'],
                  'archive_bytes': combined_size, 'archive_sha256': combined_hash.hexdigest(),
                  'parts': len(parts), 'zip_count': len(expansions),
                  'zip_members': sum(e['member_count'] for e in expansions)}), flush=True)
