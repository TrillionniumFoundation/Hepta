"""Independently validate the actual Source R3 artifact and prepare a read-only publish plan."""
import gzip
import hashlib
import io
import json
import pathlib
import tarfile
import zipfile

BASE = pathlib.Path('/workspace/scratch/dda74a4fae35/recovered-v85')
OUT = BASE / 'source-r3-artifact'
RAW = OUT / 'raw'
TREE = '279c5459c9cc7746d5e347d90285eebfe21986d2'
OURS = 'f33d8da316de8fdf27b504371f1a5310997ff548'
OURS_TREE = '378bc0dc613befc7006f1514bd2229357ae0d07c'

def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def unique(pairs):
    value = {}
    for k, v in pairs:
        assert k not in value, ('duplicate JSON key', k)
        value[k] = v
    return value

def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)

def put(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        assert path.is_file() and not path.is_symlink() and path.read_bytes() == raw
    else:
        with path.open('xb') as stream:
            stream.write(raw)
        path.chmod(0o644)

def tree(rows):
    direct, groups = [], {}
    for path, mode, sha in rows:
        name, sep, rest = path.partition('/')
        if sep:
            groups.setdefault(name, []).append((rest, mode, sha))
        else:
            direct.append((name, mode, sha, False))
    for name, children in groups.items():
        direct.append((name, '40000', tree(children), True))
    direct.sort(key=lambda r: r[0].encode() + (b'/' if r[3] else b''))
    raw = b''.join(m.lstrip('0').encode() + b' ' + n.encode() + b'\0' + bytes.fromhex(s)
                   for n, m, s, _ in direct)
    return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

packed_zip = (BASE / 'third-build.zip').read_bytes()
assert len(packed_zip) == 120474423
assert digest(packed_zip) == 'c35fe52511aa48ed187011bd531bdd2adf57838cdf4965af00e38b4866d32886'
archive = zipfile.ZipFile(io.BytesIO(packed_zip))
assert len(archive.namelist()) == len(set(archive.namelist())) == 3939
assert archive.testzip() is None
manifest_raw = archive.read('EVIDENCE-MANIFEST.json')
assert blob(manifest_raw) == '97e52715891c1c498fd765cf009abb3247277d0a'
assert manifest_raw == (BASE / 'source-r3-diagnostics/EVIDENCE-MANIFEST.json').read_bytes()
manifest = parse(manifest_raw)
compressed = archive.read('FROZEN-SOURCE-EVIDENCE.tar.gz')
assert len(compressed) == manifest['bytes'] == 38854610
assert digest(compressed) == manifest['sha256'] == '22a8029c4ecbb161a1b1c44dc5e05f0b042a5a53fbaf48605256217758104fb8'
assert len(manifest['chunks']) == 75
for i, chunk in enumerate(manifest['chunks']):
    assert chunk['index'] == i and chunk['offset'] == i * 524288
    raw = compressed[chunk['offset']:chunk['offset'] + chunk['bytes']]
    assert len(raw) == chunk['bytes'] and digest(raw) == chunk['sha256'] and blob(raw) == chunk['blob']
    assert chunk['full_readback_equal'] is True
    receipt = parse(archive.read('raw/upload-readbacks/' + chunk['blob'] + '.json'))
    assert receipt['blob'] == chunk['blob'] and receipt['bytes'] == len(raw)
    assert receipt['sha256'] == digest(raw) and receipt['full_readback_equal'] is True
tar_raw = gzip.decompress(compressed)
members = {m['path']: m for m in manifest['members']}
assert len(members) == len(manifest['members']) == 3554
seen = set()
with tarfile.open(fileobj=io.BytesIO(tar_raw), mode='r:') as packed:
    for member in packed:
        path = pathlib.PurePosixPath(member.name)
        assert not path.is_absolute() and '..' not in path.parts and str(path) == member.name
        assert member.isfile() and member.mode == 0o644 and member.name not in seen
        pin = members[member.name]
        raw = packed.extractfile(member).read()
        assert len(raw) == pin['bytes'] == member.size
        assert digest(raw) == pin['sha256'] and blob(raw) == pin['blob']
        assert raw == archive.read('raw/' + member.name)
        put(RAW / path, raw)
        seen.add(member.name)
assert seen == set(members)
result = parse((RAW / 'RESULT.json').read_bytes())
assert result == manifest['result'] and result['status'] == 'SOURCE_PASS' and not result['failures']
assert result['python'].startswith('3.14.4 ')
assert result['generation'] == {'tree': TREE, 'generator_count': 109,
    'real_generation_passes': 2, 'physical_paths_retired_in_development_tree': 55}
assert result['syntax'] == {'checked': 1441, 'failures': 0}
assert not result['whole_native'] and not result['default_changed'] and not result['product_ref_changed']
assert result['native_qualification_jobs_executed'] == result['cold_qualifications'] == 0
assert blob((RAW / 'harness/INPUTS.json').read_bytes()) == '0359ebeb13a8f3f618a2b50db5d59ad034ea6879'
assert blob((RAW / 'harness/DRIVER.py').read_bytes()) == '03249a2c928055f5451a3ab8bbfbccf47eee8a91'
assert blob((RAW / 'harness/tools/run_source_gate.py').read_bytes()) == '40b230288e6db39817aeee26b616d5a613af4f2c'
ids_raw = (RAW / 'harness/inputs/ORIGINAL-SOURCE-IDS.json').read_bytes()
assert blob(ids_raw) == 'ca3fe97c2baaafc519d2fe3705062c1e8c13a577'
originals = parse(ids_raw)
plan = parse((RAW / 'harness/INPUTS.json').read_bytes())
source = parse((RAW / 'checks/SOURCE-TESTS.json').read_bytes())
assert source == result['source_tests'] and source['status'] == 'PASS' and source['complete'] is True
assert source['expected'] == source['tests_run'] == result['product_tests_executed'] == 1172
assert len(source['ordered_ids']) == len(set(source['ordered_ids'])) == 1172
assert source['ordered_ids'] == source['actual_started_ids'] == source['actual_stopped_ids']
assert source['selectors'] == plan['source_registration']['selectors'] and len(source['selectors']) == 213
for key in ('errors', 'failures', 'skipped', 'expected_failures', 'unexpected_successes',
            'duplicate_ids', 'missing_main_ids', 'missing_a733_ids', 'missing_frozen_main_ids', 'missing_frozen_a733_ids'):
    assert not source[key], key
assert all(not v for v in source['loader_errors'].values())
assert source['frozen_original_main_ids'] == originals['main']['ids'] and len(originals['main']['ids']) == 530
renames = plan['source_registration']['selector_renames']
def mapped(name):
    prefixes = [p for p in renames if name == p or name.startswith(p + '.')]
    if not prefixes:
        return name
    prefix = max(prefixes, key=len)
    return renames[prefix] + name[len(prefix):]
assert source['frozen_original_a733_projected_ids'] == list(map(mapped, originals['a733']['ids']))
assert len(originals['a733']['ids']) == 973
events = [parse(line) for line in (RAW / 'checks/SOURCE-TESTS.events.jsonl').read_bytes().splitlines()]
assert [(r['event'], r['id']) for r in events] == [(event, name) for name in source['ordered_ids'] for event in ('start', 'stop')]
inventory = parse((RAW / 'sources/candidate-final.json').read_bytes())
leaves = {r['path']: r for r in inventory['entries'] if r['type'] != 'tree'}
assert len(leaves) == inventory['files'] == 2989 and inventory['tree'] == TREE
assert all(r['type'] == 'blob' for r in leaves.values())
assert tree([(p, r['mode'], r['oid']) for p, r in leaves.items()]) == TREE
before = parse((RAW / 'checks/before-complete-source-tests-raw-worktree.json').read_bytes())
after = parse((RAW / 'checks/after-complete-source-tests-raw-worktree.json').read_bytes())
assert not before['failures'] and not after['failures']
assert before['frozen_tree'] == after['frozen_tree'] == TREE and before['files'] == after['files']
assert len(before['files']) == len(leaves)
for row in before['files']:
    pin = leaves[row['path']]
    assert row['expected_mode'] == row['actual_mode'] == pin['mode']
    assert row['expected_blob'] == row['actual_blob'] == pin['oid']
ours = parse((RAW / 'sources/ours.json').read_bytes())
assert ours['commit'] == OURS and ours['tree'] == OURS_TREE and ours['files'] == 2580
old = {r['path']: r for r in ours['entries'] if r['type'] != 'tree'}
assert tree([(p, r['mode'], r['oid']) for p, r in old.items()]) == OURS_TREE
delta_raw = (RAW / 'publication/TREE-DELTA.json').read_bytes()
assert blob(delta_raw) == '8ccc393c067cdd6ea34ecddad8156437b79b6197'
delta = parse(delta_raw)
assert len(delta) == len({r['path'] for r in delta}) == 518
expected_delta = []
for name in sorted(set(old) | set(leaves)):
    a, b = old.get(name), leaves.get(name)
    if a and b and (a['mode'], a['type'], a['oid']) == (b['mode'], b['type'], b['oid']):
        continue
    expected_delta.append({'path': name, 'mode': (b or a)['mode'], 'type': (b or a)['type'], 'sha': b['oid'] if b else None})
assert delta == expected_delta
uploads = parse((RAW / 'publication/UPLOADED-BLOBS.json').read_bytes())
assert len(uploads) == result['candidate']['new_blobs_full_readback'] == 303
assert all(row['blob'] == sha and row['full_readback_equal'] is True for sha, row in uploads.items())
terminal = parse((RAW / 'terminal-worktree/INDEX.json').read_bytes())
assert len(terminal['files']) == len(leaves)
changes, restored = [], []
for row in terminal['files']:
    name = row['path']; pin = leaves[name]
    assert row['kind'] == 'regular' and row['mode'] == 0o644 and pin['mode'] == '100644'
    assert row['blob'] == pin['oid']
    custody = row['content_custody']
    raw = (RAW / custody['file']).read_bytes() if 'file' in custody else (BASE / 'candidate-r4' / name).read_bytes()
    assert len(raw) == row['bytes'] and blob(raw) == row['blob'] and digest(raw) == row['sha256']
    local = (BASE / 'candidate-r4' / name).read_bytes()
    if local != raw:
        changes.append({'path': name, 'local_blob': blob(local), 'ci_blob': row['blob'], 'local_bytes': len(local), 'ci_bytes': len(raw)})
    put(BASE / 'candidate-r4-ci314' / name, raw)
    restored.append({'path': name, 'mode': pin['mode'], 'type': 'blob', 'sha': pin['oid']})
report = {'schema': 'hepta.source-r3.independent-publish-readback.v1', 'status': 'PASS',
    'run': 43396616508, 'job': 131788970461, 'harness_commit': '68a30237e870d41d2403f9dc3857bcf3e80b376a',
    'zip_bytes': len(packed_zip), 'zip_sha256': digest(packed_zip), 'outer_members': 3939, 'outer_all_crc': True,
    'archive_bytes': len(compressed), 'archive_sha256': digest(compressed), 'archive_chunks': 75,
    'inner_members': len(members), 'all_inner_bytes_modes_hashes_and_zip_copies_equal': True,
    'source_status': 'PASS', 'actual_source_methods': 1172, 'source_wall_seconds': source['wall_seconds'],
    'original_main_ids': 530, 'original_development_ids': 973, 'exact_events': len(events),
    'source_before_after_equal': True, 'candidate_tree': TREE, 'candidate_files': len(restored),
    'changed_paths_vs_fixed_main': len(delta), 'new_source_blobs_full_get': len(uploads),
    'restored_source': str(BASE / 'candidate-r4-ci314'), 'local312_vs_actual314_differences': changes,
    'candidate_commit_created': False, 'product_ref_changed': False, 'native_qualification': False, 'whole_native': False}
put(OUT / 'ARTIFACT-FULL-READBACK.json', (json.dumps(report, indent=2, sort_keys=True) + '\n').encode())
put(OUT / 'CANDIDATE-LEAVES.json', (json.dumps(restored, indent=2, sort_keys=True) + '\n').encode())
put(OUT / 'TREE-DELTA.json', delta_raw)
print(json.dumps(report, sort_keys=True), flush=True)
