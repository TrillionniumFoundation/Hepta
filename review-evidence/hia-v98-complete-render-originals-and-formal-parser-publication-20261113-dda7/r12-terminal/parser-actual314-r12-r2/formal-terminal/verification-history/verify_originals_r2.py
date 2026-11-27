"""Read-only qualification-custody verification; executes no project code."""
import collections
import gzip
import hashlib
import json
import pathlib
import re
import stat
import tarfile
import time
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent
BASE = ROOT.parent / 'v94-union-r12-r2'
LOCAL = BASE / 'source'
OUT = ROOT / 'readback-r1'
TREE = '2e4f2b681b8e15f8cc978134819943c583a591fd'
CONFIG = {
    'combined-source': (348764589, '40643d872e44db483c0dc9cd8e6968e21bad1e42299001c51dd06eef574fecde', 8282),
    'parser-bounded': (46573349, '469a366e4ed0502bff5c0129f20d8a2e7b19f78fc001fca3117503da0c5a514e', 2609),
}


def unique(pairs):
    answer = {}
    for key, value in pairs:
        assert key not in answer, ('duplicate JSON key', key)
        answer[key] = value
    return answer


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def check_pin(raw, expected):
    actual = pin(raw)
    assert actual['bytes'] == expected['bytes']
    assert actual['sha256'] == expected['sha256']
    assert actual['git_blob'] == expected.get('git_blob', expected.get('blob'))
    return actual


def safe(name):
    path = pathlib.PurePosixPath(name)
    assert name and not path.is_absolute() and '\\' not in name and '\0' not in name
    assert '..' not in path.parts and '.' not in path.parts and str(path) == name
    return path


def put(path, raw, mode=0o644):
    assert type(mode) is int and 0 <= mode <= 0o777
    path.parent.mkdir(parents=True, exist_ok=True)
    assert not path.is_symlink()
    if path.exists():
        assert path.is_file() and path.read_bytes() == raw
    else:
        with path.open('xb') as stream:
            stream.write(raw)
    path.chmod(mode)
    assert stat.S_IMODE(path.stat().st_mode) == mode


def write_json(path, value):
    put(path, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())


def tree(rows):
    direct, groups = [], {}
    for path, mode, oid in rows:
        name, sep, rest = path.partition('/')
        if sep:
            groups.setdefault(name, []).append((rest, mode, oid))
        else:
            direct.append((name, mode, oid, False))
    for name, children in groups.items():
        direct.append((name, '40000', tree(children), True))
    direct.sort(key=lambda row: row[0].encode() + (b'/' if row[3] else b''))
    raw = b''.join(mode.lstrip('0').encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(oid)
                   for name, mode, oid, _ in direct)
    return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def validate_outer(label):
    path = ROOT / (label + '.zip')
    size, sha256, count = CONFIG[label]
    with path.open('rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == sha256
    assert path.stat().st_size == size
    rows = []
    archive = zipfile.ZipFile(path)
    infos = archive.infolist()
    assert len(infos) == count and len({row.filename for row in infos}) == count
    for item in infos:
        safe(item.filename)
        file_mode = (item.external_attr >> 16) & 0xffff
        assert not item.is_dir() and stat.S_ISREG(file_mode), (item.filename, file_mode)
        assert not item.flag_bits & 1
        raw = archive.read(item)  # ZipExtFile reads to EOF and verifies the CRC.
        actual = pin(raw)
        assert actual['bytes'] == item.file_size
        rows.append({'path': item.filename, **actual, 'crc32': item.CRC,
                     'external_attr': item.external_attr, 'create_system': item.create_system,
                     'zip_unix_file_mode': file_mode, 'permission_mode': stat.S_IMODE(file_mode)})
        if label == 'parser-bounded':
            put(OUT / label / safe(item.filename), raw, stat.S_IMODE(file_mode))
    write_json(OUT / (label + '-OUTER-MEMBERS.json'), rows)
    return archive, {row['path']: row for row in rows}


def main():
    started = time.monotonic()
    OUT.mkdir(exist_ok=True)  # Reuse only byte-checked restored files; retain the original failed verifier and logs.
    source_zip, source_outer = validate_outer('combined-source')
    parser_zip, parser_outer = validate_outer('parser-bounded')
    manifest = parse(source_zip.read('EVIDENCE-MANIFEST.json'))
    assert manifest['schema'] == 'hepta.combined-source-build-evidence.v2'
    assert pin(source_zip.read('EVIDENCE-MANIFEST.json'))['git_blob'] == '848c7b43f108213a138fb02fb36cbdb05b7582f8'
    assert parse(source_zip.read('EVIDENCE-PIN.json'))['full_readback_equal'] is True
    compressed_pin = source_outer['FROZEN-SOURCE-EVIDENCE.tar.gz']
    assert compressed_pin['bytes'] == manifest['bytes'] == 112790967
    assert compressed_pin['sha256'] == manifest['sha256']
    with source_zip.open('FROZEN-SOURCE-EVIDENCE.tar.gz') as stream:
        offset = 0
        for index, chunk in enumerate(manifest['chunks']):
            assert chunk['index'] == index and chunk['offset'] == offset
            raw = stream.read(chunk['bytes'])
            check_pin(raw, chunk)
            assert chunk['full_readback_equal'] is True
            receipt = parse(source_zip.read('raw/upload-readbacks/' + chunk['blob'] + '.json'))
            check_pin(raw, receipt)
            assert receipt['full_readback_equal'] is True
            offset += len(raw)
        assert offset == manifest['bytes'] and stream.read() == b''
    members = {row['path']: row for row in manifest['members']}
    directories = {row['path']: row for row in manifest['directories']}
    assert len(members) == len(manifest['members']) == 7192
    assert len(directories) == len(manifest['directories']) == 1284
    assert not set(members) & set(directories)
    raw_root = OUT / 'source-raw'
    raw_root.mkdir()
    seen, seen_dirs = set(), set()
    with source_zip.open('FROZEN-SOURCE-EVIDENCE.tar.gz') as stream, gzip.GzipFile(fileobj=stream) as inflated:
        with tarfile.open(fileobj=inflated, mode='r|') as packed:
            for member in packed:
                name = member.name
                path = safe(name)
                if member.isdir():
                    assert name in directories and name not in seen_dirs
                    assert member.mode == directories[name]['mode']
                    (raw_root / path).mkdir(parents=True, exist_ok=True)
                    seen_dirs.add(name)
                    continue
                assert member.isfile() and name not in seen and name in members
                assert member.mode == members[name]['mode']
                raw = packed.extractfile(member).read()
                assert len(raw) == member.size
                check_pin(raw, members[name])
                assert raw == source_zip.read('raw/' + name)
                put(raw_root / path, raw, member.mode)
                seen.add(name)
        while inflated.read(1024 * 1024):
            pass  # Complete gzip CRC/trailer validation, after the tar end marker.
    assert seen == set(members) and seen_dirs == set(directories)
    for name, row in sorted(directories.items(), key=lambda item: item[0].count('/'), reverse=True):
        (raw_root / name).chmod(row['mode'])
        assert stat.S_IMODE((raw_root / name).stat().st_mode) == row['mode']
    raw_root.chmod(manifest['root_mode'])
    assert stat.S_IMODE(raw_root.stat().st_mode) == manifest['root_mode']
    read = lambda name: parse((raw_root / name).read_bytes())
    result = read('RESULT.json')
    assert result == manifest['result'] and result['status'] == 'SOURCE_PASS' and not result['failures']
    assert result['python'].startswith('3.14.4 ')
    assert result['generation'] == {'tree': TREE, 'generator_count': 126,
        'real_generation_passes': 2, 'physical_paths_retired_in_development_tree': 55}
    assert result['syntax'] == {'checked': 1523, 'failures': 0}
    assert result['cold_qualifications'] == result['native_qualification_jobs_executed'] == 0
    for key in ('default_changed', 'legacy_host_implementation_deleted', 'product_ref_changed', 'whole_native'):
        assert result[key] is False
    assert result['product_tests_executed'] == 1342
    harness_pins = {'harness/INPUTS.json': '2712736a2cfbdea235356b419b6813000277a995',
        'harness/DRIVER.py': 'cfe319279641b124bcd724437857686f36d1aa07',
        'harness/tools/run_source_gate.py': '40b230288e6db39817aeee26b616d5a613af4f2c',
        'harness/inputs/ORIGINAL-SOURCE-IDS.json': 'ca3fe97c2baaafc519d2fe3705062c1e8c13a577'}
    for name, oid in harness_pins.items():
        assert pin((raw_root / name).read_bytes())['git_blob'] == oid, name
    plan = read('harness/INPUTS.json')
    expected = parse((BASE / 'FORMAL-EXPECTED-IDS.json').read_bytes())
    source = read('checks/SOURCE-TESTS.json')
    assert source == result['source_tests'] and source['status'] == 'PASS' and source['complete'] is True
    assert type(source['expected']) is type(source['tests_run']) is int
    assert source['expected'] == source['tests_run'] == 1342
    ids = source['ordered_ids']
    assert ids == expected['r12_expected_ordered_ids'] == source['actual_started_ids'] == source['actual_stopped_ids']
    assert len(ids) == len(set(ids)) == 1342
    for key in ('errors', 'failures', 'skipped', 'expected_failures', 'unexpected_successes', 'duplicate_ids',
                'missing_main_ids', 'missing_a733_ids', 'missing_frozen_main_ids', 'missing_frozen_a733_ids'):
        assert not source[key], key
    assert all(not value for value in source['loader_errors'].values())
    assert source['selectors'] == plan['source_registration']['selectors'] and len(source['selectors']) == 230
    old_r11 = expected['required_r11_ordered_projection']
    old_r10 = expected['original_r10_r2_ordered_ids']
    assert len(old_r11) == 1329 and [name for name in ids if name in set(old_r11)] == old_r11
    assert len(old_r10) == 1319 and [name for name in ids if name in set(old_r10)] == old_r10
    events = [parse(line) for line in (raw_root / 'checks/SOURCE-TESTS.events.jsonl').read_bytes().splitlines()]
    assert [(row['event'], row['id']) for row in events] == [(event, name) for name in ids for event in ('start', 'stop')]
    generations = {}
    for phase in ('generate', 'reproduce'):
        found = {}
        for path in (raw_root / 'commands').glob('*.json'):
            match = re.search(r'-' + phase + r'-(\d+)-', path.name)
            if match:
                index = int(match.group(1)); assert index not in found
                receipt = parse(path.read_bytes())
                assert type(receipt['returncode']) is int and receipt['returncode'] == 0
                assert receipt['timed_out'] is False
                for channel in ('stdout', 'stderr'):
                    check_pin((raw_root / receipt[channel]['file']).read_bytes(), receipt[channel])
                found[index] = receipt['argv']
        assert sorted(found) == list(range(126)), (phase, sorted(found))
        generations[phase] = found
    assert generations['generate'] == generations['reproduce']
    inventory = read('sources/candidate-final.json')
    leaves = {row['path']: row for row in inventory['entries'] if row['type'] != 'tree'}
    assert len(leaves) == inventory['files'] == 3108 and inventory['tree'] == TREE
    assert tree([(name, row['mode'], row['oid']) for name, row in leaves.items()]) == TREE
    before = read('checks/before-complete-source-tests-raw-worktree.json')
    after = read('checks/after-complete-source-tests-raw-worktree.json')
    assert not before['failures'] and not after['failures']
    assert before['frozen_tree'] == after['frozen_tree'] == TREE and before['files'] == after['files']
    assert len(before['files']) == len(leaves)
    for row in before['files']:
        leaf = leaves[row['path']]
        assert row['expected_mode'] == row['actual_mode'] == leaf['mode']
        assert row['expected_blob'] == row['actual_blob'] == leaf['oid']
    terminal = read('terminal-worktree/INDEX.json')
    assert len(terminal['files']) == len(leaves)
    restored, changes = {}, []
    for row in terminal['files']:
        name = row['path']; safe(name); leaf = leaves[name]
        assert row['kind'] == 'regular' and row['mode'] == 0o644 and leaf['mode'] == '100644'
        assert row['blob'] == leaf['oid']
        custody = row['content_custody']
        raw = (raw_root / safe(custody['file'])).read_bytes() if 'file' in custody else (LOCAL / name).read_bytes()
        p = check_pin(raw, row)
        local = (LOCAL / name).read_bytes()
        if local != raw:
            changes.append({'path': name, 'local': pin(local), 'actual314': p})
        put(OUT / 'candidate-ci314' / name, raw, row['mode'])
        restored[name] = {**p, 'mode': row['mode'], 'git_mode': leaf['mode']}
    assert tree([(name, row['git_mode'], row['git_blob']) for name, row in restored.items()]) == TREE
    bounded = parse(parser_zip.read('RESULT.json'))
    controls = parse(parser_zip.read('PARSER-CONTROLS.json'))
    assert parser_zip.read('PARSER-CONTROLS.json') == (BASE / 'formal-harness/inputs/PARSER-CONTROLS.json').read_bytes()
    assert parser_zip.read('FORMAL-EXPECTED-IDS.json') == (BASE / 'FORMAL-EXPECTED-IDS.json').read_bytes()
    assert parser_zip.read('FULL-SOURCE-RESULT.json') == (raw_root / 'RESULT.json').read_bytes()
    assert parser_zip.read('FULL-SOURCE-TESTS.json') == (raw_root / 'checks/SOURCE-TESTS.json').read_bytes()
    assert parse(parser_zip.read('FIXED-SOURCE-MANIFEST.json')) == parse(parser_zip.read('FINAL-SOURCE-MANIFEST.json')) == restored
    assert bounded['status'] == 'PASS' and not bounded['failures'] and bounded['source_unchanged'] is True
    assert bounded['required_tests'] == bounded['tests_run'] == 62
    assert bounded['python'].startswith('3.14.4 ') and '/Python/3.14.4/' in bounded['executable']
    assert bounded['compiler_scope'] == 'EXPLICIT_DEVELOPMENT_B3_NOT_COLD'
    assert bounded['current_source_cold_qualification'] is False and bounded['whole_native'] is False
    assert bounded['product_refs_changed'] is False
    assert bounded['source_authority']['source_tree'] == TREE
    assert bounded['source_authority']['source_files'] == 3108
    assert bounded['source_authority']['required_original_projection'] == 1329
    check_pin((raw_root / 'RESULT.json').read_bytes(), bounded['source_authority']['result'])
    check_pin((raw_root / 'checks/SOURCE-TESTS.json').read_bytes(), bounded['source_authority']['source_tests'])
    assert controls['budgets'] == {'capacity': 1048576, 'cleanup_seconds': 3,
        'compile_seconds': 20, 'qualification_seconds': 180, 'vm_fuel': 10000000}
    group_paths = {'source': 'source10', 'original43': 'original43', 'native': 'native9', 'build': 'build', 'fresh5': 'fresh5'}
    group_summary = {}
    for key, stem in group_paths.items():
        record = bounded['groups'][key]
        owner_raw = parser_zip.read('evidence/' + stem + '-owner/owner.json')
        report_raw = parser_zip.read('evidence/' + stem + '/REPORT.json')
        check_pin(owner_raw, record['owner_pin']); check_pin(report_raw, record['report_pin'])
        owner, report = parse(owner_raw), parse(report_raw)
        assert record['owner'] == owner and record['report'] == report and record['status'] == 'PASS'
        assert record['owner_admitted'] is True and record['command']['returncode'] == 0
        assert owner['qualification_seconds'] == 180 and owner['cleanup_seconds'] == 3
        assert owner['status'] == 'OWNED_PROCESS_COMPLETED' and type(owner['returncode']) is int and owner['returncode'] == 0
        assert owner['qualification_started'] is True and owner['subreaper_enabled'] is True
        assert owner['exit_observed_before_deadline'] is True and owner['timed_out'] is False
        assert not owner['interrupted_signals'] and owner['event_overflow'] is False
        cleanup = owner['cleanup']
        assert cleanup['complete'] is True and cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True
        assert cleanup['deadline_exceeded'] is False and not cleanup['errors'] and not cleanup['remaining_direct_children']
        assert report['status'] == 'PASS' and report['source_unchanged'] is True and report['python'].startswith('3.14.4 ')
        if key in controls['groups']:
            wanted = expected['bounded_groups'][key]
            assert report['loaded'] == report['tests_run'] == controls['groups'][key] == len(wanted)
            assert report['loaded_ids'] == report['started_ids'] == report['stopped_ids'] == wanted
            for field in ('errors', 'failures', 'skipped', 'expected_failures', 'unexpected_successes', 'loader_errors'):
                assert not report[field]
            assert bounded['fixed_test_admissions'][key] is True
        group_summary[key] = {'report': pin(report_raw), 'owner': pin(owner_raw), 'status': 'PASS',
                              'tests': report.get('tests_run'), 'wall_ns': report.get('wall_ns')}
    original43 = parse(parser_zip.read('evidence/original43/REPORT.json'))
    assert original43['declared_packaging_interpreter'] == bounded['executable']
    assert original43['packaging_scope'] == 'Actual CPython3.14.4 is used for packaging, original test bodies and installed children'
    for expected_pin in controls['original_test_files']:
        check_pin((OUT / 'candidate-ci314' / safe(expected_pin['path'])).read_bytes(), expected_pin)
    fresh = parse(parser_zip.read('evidence/fresh5/REPORT.json'))
    assert len(fresh['records']) == 5
    build_requests = [name for name in parser_zip.namelist() if name.startswith('evidence/build/') and name.endswith('.request.json')]
    assert len(build_requests) == 5
    # Full original payloads, outputs and receipts are preserved byte-for-byte in the restored parser artifact.
    for name in build_requests:
        request = parse(parser_zip.read(name))
        assert request['capacity'] == request['workspace_size'] == 1048576
        assert request['image_sha256'] == 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
        stem = name.removesuffix('.request.json')
        receipt = parse(parser_zip.read(stem + '.receipt.json'))
        stdout = parse(parser_zip.read(stem + '.stdout.log'))
        extras = {'case', 'input_sha256', 'input_bytes', 'artifact_sha256', 'format',
                  'runner_sha256', 'wall_elapsed_ns', 'produced_image', 'produced_bytes', 'produced_sha256'}
        assert set(receipt) - set(stdout) == extras and not (set(stdout) - set(receipt))
        assert all(receipt[key] == value for key, value in stdout.items())
        assert parser_zip.read(stem + '.stderr.log') == b''
        assert receipt['case'] == pathlib.PurePosixPath(stem).name
        assert receipt['format'] == request['format'] == 'flat-x86-64'
        assert receipt['runner_sha256'] == hashlib.sha256((OUT / 'candidate-ci314/tools/hia_selfhost_child.py').read_bytes()).hexdigest()
        assert receipt['artifact_sha256'] == request['image_sha256']
        assert receipt['produced_image'] == request['output'].removesuffix('.output.bin') + '.image.bin'
        assert receipt['produced_bytes'] == receipt['core_u32']
        assert type(receipt['wall_elapsed_ns']) is int and receipt['wall_elapsed_ns'] > 0
        assert receipt['status'] == 'returned' and receipt['abi_status'] == 0 and receipt['source_unchanged'] is True
        assert receipt['limits']['output_capacity'] == receipt['limits']['workspace_bytes'] == 1048576
        assert receipt['wall_elapsed_ns'] < 20_000_000_000
        assert not receipt['forbidden_compiler_modules_loaded']
        inp, output, image = (parser_zip.read(stem + suffix) for suffix in ('.input.bin', '.output.bin', '.image.bin'))
        assert len(output) == 1048576 and image == output[:receipt['produced_bytes']]
        assert len(inp) == receipt['input_bytes']
        assert hashlib.sha256(inp).hexdigest() == request['source_sha256'] == receipt['source_sha256'] == receipt['input_sha256']
        assert hashlib.sha256(output).hexdigest() == receipt['output_sha256']
        assert hashlib.sha256(image).hexdigest() == receipt['produced_sha256']
    summary = {'schema': 'hepta.r12-r2.complete-original-independent-readback.v1', 'status': 'PASS',
        'run': 43488127451, 'job': 132101891247, 'harness_commit': 'b35ef1d4e53533f75f09ff46b7d88a1341c95546',
        'source_tree': TREE, 'source_files': 3108, 'source_tests': 1342, 'source_wall_seconds': source['wall_seconds'],
        'source_events': len(events), 'original1329_projection_preserved': True, 'original1319_projection_preserved': True,
        'generators': 126, 'actual_complete_passes': 2, 'syntax_files': 1523,
        'bounded_tests': 62, 'bounded_groups': group_summary, 'actual_python': bounded['python'],
        'packaging_interpreter': original43['declared_packaging_interpreter'], 'packaging_versions': bounded['packaging_versions'],
        'both_source_and_bounded_sources_unchanged': True, 'local_vs_actual314_source_differences': changes,
        'outer_archives': {name: {'bytes': row[0], 'sha256': row[1], 'members': row[2], 'all_crc_bytes_hashes_verified': True}
                           for name, row in CONFIG.items()},
        'inner_source_members': len(seen), 'inner_source_directories': len(seen_dirs),
        'inner_source_archive_and_all216_git_transport_receipts_verified': True,
        'all_original_file_modes_preserved': True, 'source_inner_directory_modes_preserved': True,
        'parser_zip_original_directory_modes': 'NOT_RECORDED_BY_ORIGINAL_ZIP; extraction-created directory modes are not original evidence',
        'qualification_scope': 'SOURCE_PLUS_ACTUAL314_BOUNDED_DEVELOPMENT_IMAGE_CONTROLS_NOT_COLD',
        'current_source_cold_qualification': False, 'whole_native': False, 'new_product_execution': 0,
        'elapsed_seconds_for_evidence_verification_only': time.monotonic() - started}
    write_json(OUT / 'REPORT.json', summary)
    write_json(OUT / 'CANDIDATE-MANIFEST.json', restored)
    print(json.dumps(summary, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
