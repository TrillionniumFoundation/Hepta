"""Independently validate the actual R11 partial generation failure including R14 exact permission capture; expected pins are supplied only from the terminal run."""
import gzip
import os
import stat
import hashlib
import io
import json
import pathlib
import tarfile
import zipfile

BASE = pathlib.Path(__file__).resolve().parent
CONFIG = json.loads((BASE / 'EXPECTED.json').read_bytes())
OUT = BASE / 'artifact'
RAW = OUT / 'raw'
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

packed_zip = (BASE / 'artifact.zip').read_bytes()
assert len(packed_zip) == CONFIG['zip_bytes']
assert digest(packed_zip) == CONFIG['zip_sha256']
archive = zipfile.ZipFile(io.BytesIO(packed_zip))
outer_count = len(archive.namelist())
assert outer_count == len(set(archive.namelist()))
assert archive.testzip() is None

outer_rows = []
for member in archive.infolist():
    path = pathlib.PurePosixPath(member.filename)
    assert not path.is_absolute() and '..' not in path.parts and str(path) == member.filename
    assert not member.is_dir()
    content = archive.read(member)
    assert len(content) == member.file_size
    outer_rows.append({'path': member.filename, 'bytes': len(content), 'blob': blob(content),
                       'sha256': digest(content), 'crc32': member.CRC,
                       'external_attr': member.external_attr, 'create_system': member.create_system})
    put(OUT / path, content)
put(OUT / 'OUTER-MEMBERS.json', (json.dumps(outer_rows, indent=2, sort_keys=True) + '\n').encode())

manifest_raw = archive.read('EVIDENCE-MANIFEST.json')
assert blob(manifest_raw) == CONFIG['manifest_blob']
assert len(manifest_raw) == CONFIG['manifest_bytes']
assert digest(manifest_raw) == CONFIG['manifest_sha256']
assert parse(archive.read('EVIDENCE-PIN.json'))['full_readback_equal'] is True
manifest = parse(manifest_raw)
compressed = archive.read('FROZEN-SOURCE-EVIDENCE.tar.gz')
assert len(compressed) == manifest['bytes']
assert digest(compressed) == manifest['sha256']
assert manifest['schema'] == 'hepta.combined-source-build-evidence.v2'
assert len(manifest['chunks']) == (len(compressed) + 524287) // 524288
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
assert len(members) == len(manifest['members'])
directories = {row['path']: row for row in manifest['directories']}
assert len(directories) == len(manifest['directories'])
assert not set(directories) & set(members)
seen_directories = set()
seen = set()
with tarfile.open(fileobj=io.BytesIO(tar_raw), mode='r:') as packed:
    for member in packed:
        path = pathlib.PurePosixPath(member.name)
        assert not path.is_absolute() and '..' not in path.parts and str(path) == member.name
        if member.isdir():
            assert member.name in directories and member.name not in seen_directories
            assert member.mode == directories[member.name]['mode']
            assert type(member.mode) is int and 0 <= member.mode <= 0o777
            destination = RAW / path
            destination.mkdir(parents=True, exist_ok=True)
            assert destination.is_dir() and not destination.is_symlink()
            seen_directories.add(member.name)
            continue
        assert member.isfile() and member.name not in seen
        pin = members[member.name]
        assert member.mode == pin['mode'] and type(member.mode) is int and 0 <= member.mode <= 0o777
        raw = packed.extractfile(member).read()
        assert len(raw) == pin['bytes'] == member.size
        assert digest(raw) == pin['sha256'] and blob(raw) == pin['blob']
        assert raw == archive.read('raw/' + member.name)
        put(RAW / path, raw)
        (RAW / path).chmod(pin['mode'])
        assert stat.S_IMODE((RAW / path).lstat().st_mode) == pin['mode']
        seen.add(member.name)
assert seen == set(members) and seen_directories == set(directories)
for name, row in sorted(directories.items(), key=lambda item: item[0].count('/'), reverse=True):
    (RAW / name).chmod(row['mode'])
    assert stat.S_IMODE((RAW / name).lstat().st_mode) == row['mode']
assert type(manifest['root_mode']) is int and 0 <= manifest['root_mode'] <= 0o777
RAW.chmod(manifest['root_mode'])
assert stat.S_IMODE(RAW.lstat().st_mode) == manifest['root_mode']
result = parse((RAW / 'RESULT.json').read_bytes())
assert result == manifest['result'] and result['status'] == 'FAIL'
assert result['python'].startswith('3.14.4 ')
assert result['syntax'] == {'checked': 1518, 'failures': 0}
assert result['product_tests_executed'] == 0
assert result['native_qualification_jobs_executed'] == result['cold_qualifications'] == 0
for key in ('whole_native', 'default_changed', 'product_ref_changed', 'legacy_host_implementation_deleted'):
    assert result[key] is False, key
assert 'generation' not in result and 'candidate' not in result and 'source_tests' not in result
assert len(result['failures']) == 1
assert result['failures'][0]['error'] == 'unexpected command return code: generate-122-cli_parser_context'
assert blob((RAW / 'harness/INPUTS.json').read_bytes()) == CONFIG['plan_blob']
assert blob((RAW / 'harness/DRIVER.py').read_bytes()) == CONFIG['driver_blob']
assert blob((RAW / 'harness/tools/run_source_gate.py').read_bytes()) == '40b230288e6db39817aeee26b616d5a613af4f2c'
assert blob((RAW / 'harness/inputs/ORIGINAL-SOURCE-IDS.json').read_bytes()) == 'ca3fe97c2baaafc519d2fe3705062c1e8c13a577'
assert not (RAW / 'checks/SOURCE-TESTS.json').exists()
assert not (RAW / 'checks/SOURCE-TESTS.events.jsonl').exists()
assert not (RAW / 'publication/TREE-DELTA.json').exists()
plan = parse((RAW / 'harness/INPUTS.json').read_bytes())
assert len(plan['generators']) == 123
generator_commands = []
for path in sorted((RAW / 'commands').glob('*.json')):
    command = parse(path.read_bytes())
    argv = command.get('argv', [])
    if len(argv) == 4 and argv[1:3] == ['-B', '-m'] and argv[3].startswith('tools.generate_hia_'):
        generator_commands.append((path.name, command))
assert len(generator_commands) == 123
for index, (name, command) in enumerate(generator_commands):
    assert command['argv'][3] == 'tools.generate_hia_' + plan['generators'][index]
    assert command['limit_seconds'] == 300 and command['timed_out'] is False
    assert command['authenticated_git'] is False
    assert command['returncode'] == (1 if index == 122 else 0)
    for stream in ('stdout', 'stderr'):
        pin = command[stream]
        raw = (RAW / pin['file']).read_bytes()
        assert len(raw) == pin['bytes'] and blob(raw) == pin['blob'] and digest(raw) == pin['sha256']
failed = generator_commands[-1][1]
stderr = (RAW / failed['stderr']['file']).read_bytes()
assert b'ValueError: unsupported authoring graph value: _colorize.Argparse' in stderr
assert failed['argv'][-1] == 'tools.generate_hia_cli_parser_context'
assert blob(stderr) == '6ad34acdfc4b75ef5402167c977e0dc91c05770a'
fixed_blobs = set()
fixed_sources = {}
for label, expected_commit in (
    ('ours', 'f33d8da316de8fdf27b504371f1a5310997ff548'),
    ('theirs', 'a733926a2786a3d4a37304bd2d18ebb2eac57ac9'),
    ('base-5831f52fada45e076f8f68f198a15c0585e6104f', '5831f52fada45e076f8f68f198a15c0585e6104f'),
    ('base-93d66bcc3acb88212c9b153d7852ba22eeab24c8', '93d66bcc3acb88212c9b153d7852ba22eeab24c8'),
):
    original = parse((RAW / 'sources' / (label + '.json')).read_bytes())
    assert original['commit'] == expected_commit
    entries = [row for row in original['entries'] if row['type'] != 'tree']
    assert all(row['type'] == 'blob' for row in entries)
    assert len(entries) == original['files']
    assert tree([(row['path'], row['mode'], row['oid']) for row in entries]) == original['tree']
    fixed_blobs.update(row['oid'] for row in entries)
    fixed_sources[label] = {'commit': original['commit'], 'tree': original['tree'], 'files': len(entries)}
assert fixed_sources['ours']['tree'] == OURS_TREE
assert fixed_sources['theirs']['tree'] == '1c5ba7e1217f46f2b95512640d08f19e2cc8b1fd'
terminal = parse((RAW / 'terminal-worktree/INDEX.json').read_bytes())
assert len(terminal['files']) == CONFIG['terminal_source_files'] == 3155
assert result['terminal_source_snapshot'] == {
    'all_partial_generated_bytes_captured': True,
    'files': 3155,
    'fixed_original_git_dependencies_retained': True,
    'new_or_changed_byte_records': 441,
}
local_rows = parse((BASE / 'FIXED-ORIGINAL-LOCAL-MATCHES.json').read_bytes())
local_map = {row['path']: row for row in local_rows}
assert len(local_map) == len(local_rows) == 2656
missing = parse((BASE / 'FIXED-ORIGINAL-MISSING.json').read_bytes())
assert len(missing) == 58 and not set(local_map) & {row['path'] for row in missing}
restored = []
included_count = fixed_count = 0
for row in terminal['files']:
    name = row['path']
    safe = pathlib.PurePosixPath(name)
    assert not safe.is_absolute() and '..' not in safe.parts and str(safe) == name
    assert row['kind'] == 'regular' and row['mode'] == 0o644
    custody = row['content_custody']
    if 'file' in custody:
        raw = (RAW / custody['file']).read_bytes()
        included_count += 1
    else:
        assert custody['kind'] == 'exact_fixed_original_git_blob'
        assert custody['blob'] == row['blob'] and row['blob'] in fixed_blobs
        raw = pathlib.Path(local_map[name]['local_file']).read_bytes() if name in local_map else (BASE / 'fixed-original-blobs' / row['blob']).read_bytes()
        fixed_count += 1
    assert len(raw) == row['bytes'] and blob(raw) == row['blob'] and digest(raw) == row['sha256']
    put(BASE / 'partial-ci314' / name, raw)
    assert stat.S_IMODE((BASE / 'partial-ci314' / name).lstat().st_mode) == row['mode']
    restored.append({'path': name, 'mode': '100644', 'type': 'blob', 'sha': row['blob']})
assert len(restored) == len({row['path'] for row in restored}) == 3155
assert included_count == 441 and fixed_count == 2714
partial_tree = tree([(row['path'], row['mode'], row['sha']) for row in restored])
report = {
    'schema': 'hepta.source-r11.independent-partial-generation-failure-readback.v1',
    'status': 'PASS',
    'formal_result_status': 'FAIL',
    'source_status': 'NOT_STARTED',
    'actual_source_methods': 0,
    'run': CONFIG['run'], 'job': CONFIG['job'], 'harness_commit': CONFIG['harness_commit'],
    'zip_bytes': len(packed_zip), 'zip_sha256': digest(packed_zip),
    'outer_members': outer_count, 'outer_all_crc': True,
    'archive_bytes': len(compressed), 'archive_sha256': digest(compressed), 'archive_chunks': len(manifest['chunks']),
    'inner_members': len(members), 'directory_count': len(directories),
    'all_inner_bytes_modes_hashes_and_zip_copies_equal': True,
    'all_evidence_directory_and_root_modes_restored': True,
    'uid_gid_mtime_normalized_explicitly': True,
    'source_files_in_partial_terminal_snapshot': len(restored),
    'partial_terminal_tree': partial_tree,
    'partial_snapshot_is_generated_final_tree': False,
    'retained_pre_migration_hiaasm_files': len([row for row in restored if row['path'].endswith('.hiaasm')]),
    'fixed_original_blob_dependencies': fixed_count,
    'fixed_original_existing_local_full_hash_matches': len(local_rows),
    'fixed_original_additional_full_gets': len(missing),
    'included_partial_generated_or_new_bytes': included_count,
    'fixed_dependency_trees_recomputed': fixed_sources,
    'actual_first_pass_generator_commands': len(generator_commands),
    'successful_first_pass_commands': 122,
    'failed_generator': 'cli_parser_context',
    'failed_generator_index': 122,
    'failed_stderr_blob': blob(stderr),
    'source_tests_absent': True,
    'native_qualification': False, 'whole_native': False,
    'product_ref_changed': False, 'legacy_host_implementation_deleted': False,
    'restored_source': str(BASE / 'partial-ci314'),
}
put(OUT / 'ARTIFACT-FULL-READBACK.json', (json.dumps(report, indent=2, sort_keys=True) + '\n').encode())
put(OUT / 'PARTIAL-SOURCE-LEAVES.json', (json.dumps(restored, indent=2, sort_keys=True) + '\n').encode())
print(json.dumps(report, sort_keys=True), flush=True)
