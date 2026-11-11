from pathlib import Path
from hashlib import sha256
import json, os, shutil, stat, sys

root = Path('/tmp/hia-e26e-agent-store-authority-r1')
evidence = Path(__file__).resolve().parent
publication = json.loads((evidence / 'canonical-publication.json').read_bytes())
assert publication['status'] == 'PASS' and publication['canonical_commit'] == '5810de1daef676ed81da4a4a15b188726040e504'
archive = evidence / 'raw-development-originals.tar.zst'
expected_sha = '6fd8ce8a891dff4839a54b71af29fa0dfb2a64fb8716ca1d6ca9f7c55737df3b'
assert sha256(archive.read_bytes()).hexdigest() == expected_sha
inventory = json.loads((evidence / 'originals-manifest.json').read_bytes())
by_name = {row['path']: row for row in inventory['entries']}
targets = ['complete-development-r1/fixtures', 'complete-development-r2/fixtures', 'frozen-controls-r1/fixtures']

def scan(path):
    yield path
    if path.is_dir() and not path.is_symlink():
        for child in sorted(path.iterdir()): yield from scan(child)

def digest(path):
    h = sha256()
    with path.open('rb') as stream:
        while raw := stream.read(1 << 20): h.update(raw)
    return h.hexdigest()

sys.path.insert(0, str(root / 'source'))
from tools.build_hia_json_preflight import current_sources
source_before = current_sources()
rows = []
for name in targets:
    target = root / name
    assert target.is_dir() and not target.is_symlink() and target.resolve().is_relative_to(root.resolve())
    actual_paths = list(scan(target))
    expected_names = {n for n in by_name if n == name or n.startswith(name + '/')}
    assert {p.relative_to(root).as_posix() for p in actual_paths} == expected_names
    regular_files = raw_bytes = allocated_bytes = 0
    for p in actual_paths:
        item = by_name[p.relative_to(root).as_posix()]; info = p.lstat()
        assert (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid) == (item['mode'], item['uid'], item['gid'])
        allocated_bytes += info.st_blocks * 512
        if item['type'] == 'file':
            assert stat.S_ISREG(info.st_mode) and info.st_size == item['size'] and digest(p) == item['sha256']
            regular_files += 1; raw_bytes += info.st_size
        elif item['type'] == 'directory': assert stat.S_ISDIR(info.st_mode)
        else: assert stat.S_ISLNK(info.st_mode) and os.readlink(p) == item['target']
    rows.append({'path': name, 'entries': len(actual_paths), 'regular_files': regular_files,
                 'regular_bytes': raw_bytes, 'allocated_bytes_before': allocated_bytes,
                 'every_live_byte_mode_uid_gid_matches_published_archive': True})
space = os.statvfs(root)
record = {'schema': 'hia.agent-store-authority-reclaimed-verified-duplicates.v1',
    'canonical_evidence_commit': publication['canonical_commit'], 'canonical_evidence_tree': publication['tree'],
    'published_archive_sha256': expected_sha, 'targets': rows,
    'free_bytes_before': space.f_bavail * space.f_frsize, 'status': 'VERIFIED_BEFORE_RECLAIM',
    'active_source_compiler_manifest_and_venv_removed': False,
    'original_bytes_lost': False, 'old_fixture_absolute_paths_require_restoration_from_archive': True}
(evidence / 'reclamation-before.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
for row in rows:
    shutil.rmtree(root / row['path'])
    row['expanded_copy_absent_after'] = not (root / row['path']).exists()
source_after = current_sources()
assert source_before == source_after
assert sha256(archive.read_bytes()).hexdigest() == expected_sha
space = os.statvfs(root)
record.update(status='PASS', complete_source_closure_unchanged=True,
              free_bytes_after=space.f_bavail * space.f_frsize,
              archived_regular_bytes_reclaimed=sum(r['regular_bytes'] for r in rows))
(evidence / 'reclamation.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
print(json.dumps(record, indent=2, sort_keys=True))
