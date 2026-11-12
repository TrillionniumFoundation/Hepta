"""Seal the completed launch-identity controls; do not execute any product."""
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent
sys.path.insert(0, str(BASE / 'source'))
from tools.hia_artifact_publication_custody import identity, parent_fd, read_file, write_json
from tools.qualify_hia_artifact_publication_tests import typed_inventory

returns = json.loads((ROOT / 'CONTROL-RETURNS.json').read_bytes())
assert [x['returncode'] for x in returns] == [0, 1, 0]
fixed = json.loads((ROOT / 'fixed-controls-r1/REPORT.json').read_bytes())
assert fixed['status'] == 'PASS' and fixed['tests_run'] == 19
assert fixed['loaded_ids'] == fixed['executed_ids'] and len(set(fixed['loaded_ids'])) == 19
assert fixed['actual_product_tests_executed'] is False
original = json.loads((ROOT / 'original-refusal-control/REPORT.json').read_bytes())
assert original['status'] == 'HOLD_EXPECTED_REFUSAL_NOT_OBSERVED'
assert original['test_harness_later_reaped_child'] is True
source = json.loads((ROOT / 'SOURCE-READBACK.json').read_bytes())
assert source['status'] == 'SOURCE_ONLY_READBACK_PASS' and source['methods_executed'] == 0

roots = [{'label': 'launch-identity-r5', 'path': ROOT}]
external = {}
for registry in ROOT.rglob('fixture-*.json'):
    candidate = Path(json.loads(registry.read_bytes())['path'])
    if candidate.is_relative_to(ROOT):
        continue
    assert candidate.parent == Path('/tmp')
    assert candidate.name.startswith(('publication-retained-', 'publication-custody-original-fs-'))
    external[str(candidate)] = candidate
for registry in ROOT.rglob('replaced-root-locations.json'):
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
output = BASE / 'launch-identity-r5-originals.tar.gz'
with output.open('xb') as stream:
    with tarfile.open(fileobj=stream, mode='w:gz', format=tarfile.PAX_FORMAT) as archive:
        for row in rows:
            if row['kind'] != 'regular':
                continue
            raw, observed = read_file(Path(row['original_path']), 32 << 20)
            assert observed == row['identity']
            row['sha256'] = sha256(raw).hexdigest()
            member = tarfile.TarInfo('regular/' + row['path'])
            member.size = len(raw)
            member.mode = stat.S_IMODE(observed['mode'])
            member.uid = observed['uid']; member.gid = observed['gid']; member.mtime = 0
            archive.addfile(member, io.BytesIO(raw))
        manifest = (json.dumps(rows, indent=2, sort_keys=True) + '\n').encode()
        member = tarfile.TarInfo('TYPED-MANIFEST.json')
        member.size = len(manifest); member.mode = 0o600
        archive.addfile(member, io.BytesIO(manifest))
    stream.flush(); os.fsync(stream.fileno())
assert [{k: v for k, v in row.items() if k != 'sha256'} for row in rows] == inventory()
expected = {'regular/' + row['path']: row for row in rows if row['kind'] == 'regular'}
seen = set(); manifests = 0
with tarfile.open(output, 'r:gz') as archive:
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
raw = output.read_bytes()
receipt = {
    'schema': 'hia.publication-launch-identity-control-originals.v1',
    'status': 'COMPLETED_CONTROL_ORIGINALS_READBACK_PASS',
    'roots': [{**r, 'path': str(r['path'])} for r in roots],
    'typed_members': len(rows), 'regular_members': len(expected),
    'regular_bytes': sum(row['identity']['size'] for row in expected.values()),
    'archive': {'path': str(output), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()},
    'manifest_sha256': sha256(manifest).hexdigest(),
    'all_regular_bytes_and_modes_read_back': True,
    'special_entries_metadata_only': True,
    'original_actual_refusal_control_HOLD_preserved': True,
    'source_readback_r1_import_error_preserved': True,
    'fixed_controls_passed': 19, 'original_custody_controls': 14, 'new_controls': 5,
    'source_methods_loaded': 39, 'source_methods_executed': 0,
    'product_or_native_executed': False,
}
write_json(BASE / 'LAUNCH-IDENTITY-R5-ORIGINALS.json', receipt)
print(json.dumps({k: v for k, v in receipt.items() if k != 'roots'}, sort_keys=True))
