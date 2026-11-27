"""Independent readback of the original final launcher CI artifact; no product execution."""
import hashlib
import io
import json
import pathlib
import tarfile
import zipfile

ROOT = pathlib.Path('/workspace/scratch/dda74a4fae35')
BASE = ROOT / 'v86-native-entry-development-r1/cpython314-ci43397081929-originals'
OUT = ROOT / 'v86-launcher-root-review-r1'
EXPECTED_ZIP = '012b4f72c56f91dc5407d7fe81b7ddc1802d4cfb23ed82e7aa304950ba92bb3a'
EXPECTED_TREE = 'c22da5f1cba08c7dec45185f2185d6caf61618db'

def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

def tree(entries):
    direct, groups = [], {}
    for path, mode, sha in entries:
        first, sep, rest = path.partition('/')
        if sep:
            groups.setdefault(first, []).append((rest, mode, sha))
        else:
            direct.append((first, mode, sha, False))
    for name, rows in groups.items():
        direct.append((name, '40000', tree(rows), True))
    direct.sort(key=lambda x: x[0].encode() + (b'/' if x[3] else b''))
    raw = b''.join(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(sha)
                   for name, mode, sha, _ in direct)
    return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

zip_path = BASE / 'original-artifact.zip'
zip_raw = zip_path.read_bytes()
assert len(zip_raw) == 47138986
assert hashlib.sha256(zip_raw).hexdigest() == EXPECTED_ZIP
archive = zipfile.ZipFile(io.BytesIO(zip_raw))
assert len(archive.infolist()) == 61
assert len(set(archive.namelist())) == 61
assert archive.testzip() is None
manifest_raw = archive.read('evidence/COMPLETE-ARTIFACT-MANIFEST.json')
assert blob(manifest_raw) == 'a1b3530f08b9175c987584c401a76314e2154393'
manifest = json.loads(manifest_raw)
expected = {r['path']: r for r in manifest}
assert len(expected) == len(manifest) == 3716
packed = archive.read('evidence/COMPLETE-DEVELOPMENT-INPUTS-OUTPUTS.tar.gz')
tar = tarfile.open(fileobj=io.BytesIO(packed), mode='r:gz')
observed, sources, controls = {}, {}, {}
for member in tar:
    row = expected[member.name]
    assert member.name not in observed
    assert not pathlib.PurePosixPath(member.name).is_absolute()
    assert '..' not in pathlib.PurePosixPath(member.name).parts
    assert member.mode == row['mode']
    if member.isdir():
        assert row['kind'] == 'directory'
    elif member.issym():
        assert row['kind'] == 'symlink' and member.linkname == row['target']
    else:
        assert member.isfile() and row['kind'] == 'regular'
        raw = tar.extractfile(member).read()
        assert len(raw) == row['bytes'] == member.size
        assert hashlib.sha256(raw).hexdigest() == row['sha256']
        assert blob(raw) == row['git_blob']
        if member.name.startswith('source/'):
            sources[member.name.removeprefix('source/')] = row
        if member.name in {'controls/local-observations/REPORT.json', 'controls/required-ptrace/REPORT.json'}:
            controls[member.name] = json.loads(raw)
    observed[member.name] = row['kind']
assert set(observed) == set(expected)
assert len(sources) == 2990
assert all(r['mode'] == 0o644 for r in sources.values())
source_tree = tree([(p, '100644', r['git_blob']) for p, r in sources.items()])
assert source_tree == EXPECTED_TREE
packet = json.loads((ROOT / 'recovered-v85/LAUNCHER-FINAL-R3-DECODED.json').read_bytes())
ids, reports = [], []
for group, count, wanted in [('local-observations', 21, packet['local_control_ids']),
                             ('required-ptrace', 5, packet['pending_required_ids'])]:
    r = controls['controls/' + group + '/REPORT.json']
    assert r['status'] == 'PASS' and r['tests_run'] == count
    assert r['loaded_ids'] == r['executed_ids'] == wanted
    assert len(set(r['loaded_ids'])) == count
    assert all(not v for v in r['anomalies'].values())
    assert r['source_unchanged'] and r['source_before'] == r['source_after']
    assert set(r['source_before']) == set(sources)
    for name, pin in r['source_before'].items():
        assert pin == {k: sources[name][k] for k in ('bytes', 'mode', 'sha256')}
    assert r['python'].startswith('3.14.4 ')
    assert not r['matching_cold'] and not r['whole_native']
    ids.extend(r['loaded_ids'])
    reports.append({'group': group, 'count': count, 'status': 'PASS', 'wall_ns': r['wall_ns']})
assert len(ids) == len(set(ids)) == 26
for name, row in packet['files'].items():
    raw = row['text'].encode('utf-8')
    assert len(raw) == row['bytes'] and blob(raw) == row['git_blob']
    assert hashlib.sha256(raw).hexdigest() == row['sha256']
    assert sources[name]['git_blob'] == row['git_blob']
report = {'schema': 'hia.release-launch.root-original-readback.v1',
          'run': 43397081929, 'job': 131790520359, 'status': 'PASS',
          'scope': 'READ_ONLY_ORIGINAL_ARTIFACT_VERIFICATION_NO_PRODUCT_EXECUTION',
          'zip_bytes': len(zip_raw), 'zip_sha256': EXPECTED_ZIP,
          'outer_members': 61, 'outer_all_crc': True,
          'inner_members': len(observed), 'all_inner_bytes_modes_hashes': True,
          'source_files': len(sources), 'source_tree': source_tree,
          'source_before_after_tar_equal': True, 'actual_methods': 26,
          'exact_loaded_executed_declared_ids_equal': True, 'test_ids': ids,
          'groups': reports, 'matching_source_cold': False,
          'original_native_110_qualified': False, 'whole_native': False}
(OUT / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps({k: v for k, v in report.items() if k != 'test_ids'}, sort_keys=True))
