"""Seal completed custody-controls' bytes and special-node metadata only."""
from pathlib import Path
from hashlib import sha256
import io
import json
import os
import stat
import sys
import tarfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'source'))
from tools.hia_artifact_publication_custody import identity, parent_fd, read_file, write_json
from tools.qualify_hia_artifact_publication_tests import typed_inventory

roots = []
external = {}
for revision in range(1, 5):
    path = ROOT / ('custody-controls-r%d' % revision)
    result = json.loads((path / 'RESULT.json').read_bytes())
    assert result['returncode'] in (0, 1) and result['product_executed'] is False
    roots.append({'label': path.name, 'path': path})
    for registry in path.rglob('fixture-*.json'):
        value = json.loads(registry.read_bytes())
        candidate = Path(value['path'])
        if candidate.is_relative_to(path):
            continue
        assert candidate.parent == Path('/tmp') and candidate.name.startswith(('publication-retained-', 'publication-custody-original-fs-'))
        external[str(candidate)] = candidate
    for registry in path.rglob('replaced-root-locations.json'):
        value = json.loads(registry.read_bytes())
        for key in ('recorded', 'original_preserved'):
            candidate = Path(value[key])
            assert candidate.parent == Path('/tmp') and candidate.name.startswith('publication-custody-original-fs-')
            external[str(candidate)] = candidate
for index, path in enumerate(sorted(external.values())):
    roots.append({'label': 'external-%03d' % index, 'path': path})

for root in roots:
    with parent_fd(root['path']) as (parent, name):
        value = os.stat(name, dir_fd=parent, follow_symlinks=False)
        assert stat.S_ISDIR(value.st_mode) and value.st_uid == os.geteuid()
        root['identity'] = identity(value)

def inventory():
    result = []
    for root in roots:
        for row in typed_inventory(root['path'], root['identity']):
            result.append({**row, 'path': root['label'] + '/' + row['path'],
                           'original_path': str(root['path'] / row['path'])})
    return result

rows = inventory()
out = ROOT / 'custody-control-originals-r1.tar.gz'
with out.open('xb') as stream:
    with tarfile.open(fileobj=stream, mode='w:gz', format=tarfile.PAX_FORMAT) as archive:
        for row in rows:
            if row['kind'] != 'regular':
                continue
            raw, observed = read_file(Path(row['original_path']), 32 << 20)
            assert observed == row['identity']
            row['sha256'] = sha256(raw).hexdigest()
            member = tarfile.TarInfo('regular/' + row['path'])
            member.size = len(raw); member.mode = stat.S_IMODE(observed['mode'])
            member.uid = observed['uid']; member.gid = observed['gid']; member.mtime = 0
            archive.addfile(member, io.BytesIO(raw))
        manifest = (json.dumps(rows, sort_keys=True, indent=2) + '\n').encode()
        member = tarfile.TarInfo('TYPED-MANIFEST.json'); member.size = len(manifest); member.mode = 0o600
        archive.addfile(member, io.BytesIO(manifest))
    stream.flush(); os.fsync(stream.fileno())
assert [{k: v for k, v in row.items() if k != 'sha256'} for row in rows] == inventory()
expected = {'regular/' + row['path']: row for row in rows if row['kind'] == 'regular'}
seen = set(); manifests = 0
with tarfile.open(out, 'r:gz') as archive:
    for member in archive:
        assert member.isreg()
        raw = archive.extractfile(member).read()
        if member.name == 'TYPED-MANIFEST.json':
            manifests += 1; assert raw == manifest
        else:
            assert member.name not in seen; seen.add(member.name); row = expected[member.name]
            assert len(raw) == row['identity']['size'] and sha256(raw).hexdigest() == row['sha256']
            assert member.mode == stat.S_IMODE(row['identity']['mode'])
            assert member.uid == row['identity']['uid'] and member.gid == row['identity']['gid']
assert seen == set(expected) and manifests == 1
raw = out.read_bytes()
receipt = {'schema': 'hia.publication-custody-control-originals.v1', 'status': 'ORIGINALS_READBACK_PASS',
           'roots': [{**r, 'path': str(r['path'])} for r in roots], 'typed_members': len(rows),
           'regular_members': len(expected), 'regular_bytes': sum(r['identity']['size'] for r in expected.values()),
           'archive': {'path': str(out), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()},
           'special_entries_metadata_only': True, 'all_regular_bytes_read_and_rechecked': True,
           'source_r1_11_of_12_HOLD_preserved': True, 'product_executed': False}
write_json(ROOT / 'CUSTODY-CONTROL-ORIGINALS.json', receipt)
print(json.dumps({k: v for k, v in receipt.items() if k != 'roots'}))
