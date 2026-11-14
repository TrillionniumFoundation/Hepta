"""Read the completed Source18 evidence; create and fully read back a lossless archive."""
from pathlib import Path
import base64, gzip, hashlib, io, json, os, stat, tarfile, time

AUTHOR = Path(__file__).absolute().parent
RAW = Path('/dev/shm/hia-inspect-stages-dda7')
ATTEMPT = RAW / 'source-controls-attempt-r1'
OUT = Path('/tmp/hia-inspect-source18-raw-custody-r1-dda7')

def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()

def pin(raw):
    return {'bytes': len(raw), 'mode': '100644', 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def seven(value):
    return {'device': value.st_dev, 'inode': value.st_ino, 'nlink': value.st_nlink,
            'mode': value.st_mode, 'bytes': value.st_size,
            'mtime_ns': value.st_mtime_ns, 'ctime_ns': value.st_ctime_ns}

def full(path):
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode)
    raw = path.read_bytes()
    assert seven(path.lstat()) == seven(before) and len(raw) == before.st_size
    return raw

def create(name, raw):
    path = OUT / name
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    assert full(path) == raw
    return pin(raw)

plan_raw = full(AUTHOR / 'SOURCE-PLAN.json')
plan = json.loads(plan_raw)
result_raw = full(ATTEMPT / 'RESULT.json')
result = json.loads(result_raw)
assert pin(result_raw)['git_blob'] == 'cecd5958bda4f9138af4714c955c0b3b02891f99'
assert result['status'] == 'SOURCE_CONTROLS_PASS' and result['complete_source_guard_pass'] is True
assert result['owner_launch_attempts'] == 2 and result['plan_pin'] == pin(plan_raw)
assert result['source_files'] == 3188 and result['source_tree'] == plan['source']['tree']
assert result['runtime'] == plan['runtime'] and result['matching_current_cold'] is False
assert [row['label'] for row in result['stages']] == plan['source_group_order']
groups = []
for row in result['stages']:
    name = row['label']; directory = Path(row['directory']); expected = plan['groups'][name]
    assert row['status'] == 'PASS' and row['source_guard_pass'] is True
    tests = json.loads(full(directory / 'child/TESTS.json'))
    subtests = json.loads(full(directory / 'child/SUBTESTS.json'))
    assert tests == row['tests'] and subtests == row['subtests']
    for key in ('declared_ids', 'loaded_ids', 'started_ids', 'stopped_ids'):
        assert tests[key] == expected['ids']
    assert tests['status'] == 'PASS' and tests['tests_run'] == len(expected['ids'])
    assert tests['events'] == [[event, identifier] for identifier in expected['ids'] for event in ('start', 'stop')]
    for key in ('errors', 'failures', 'expected_failures', 'unexpected_successes', 'loader_errors', 'skipped'):
        assert tests[key] == []
    actual_subs = subtests['actual_subtests']
    assert len(actual_subs) == expected['expected_subtests']
    assert [sub['method_id'] for sub in actual_subs] == expected['subtest_method_projection']
    assert all(sub['success'] is True and sub['exception_type'] is None for sub in actual_subs)
    if 'subtest_parameters' in expected:
        assert [sub['parameters'] for sub in actual_subs] == expected['subtest_parameters']
    owner_raw = full(directory / 'OWNER.json')
    owner = json.loads(owner_raw)
    returned = json.loads(full(directory / 'OWNER-RETURNED.json'))
    assert returned == row['owner_returned']
    assert returned == {**owner, 'receipt_sha256': hashlib.sha256(owner_raw).hexdigest(), 'supervisor_returncode': 0}
    assert owner['qualification_seconds'] == 180 and owner['cleanup_seconds'] == 3
    assert owner['returncode'] == 0 and owner['timed_out'] is False
    assert owner['status'] == 'OWNED_PROCESS_COMPLETED' and owner['event_overflow'] is False
    cleanup = owner['cleanup']
    assert cleanup['complete'] is True and cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True
    assert cleanup['errors'] == [] and cleanup['remaining_direct_children'] == []
    command = json.loads(full(directory / 'COMMAND.json'))
    owner_request_raw = full(directory / 'OWNER.json.request.json')
    owner_request = json.loads(owner_request_raw)
    assert hashlib.sha256(owner_request_raw).hexdigest() == owner['request_sha256']
    assert owner_request['command'] == command['argv'] and owner_request['cwd'] == command['cwd'] == plan['source']['path']
    assert owner_request['env'] == command['environment'] == command['supervisor_environment']
    assert command['argv'][:3] == [plan['runtime']['launch_executable'], '-I', '-B']
    request_raw = full(directory / 'REQUEST.json')
    child = json.loads(full(directory / 'child/RESULT.json'))
    assert child['status'] == 'PASS' and child['request_pin'] == pin(request_raw)
    assert child['all_original_and_generated_source_bytes_modes_stats_unchanged'] is True
    space = json.loads(full(ATTEMPT / ('SPACE-' + name + '.json')))
    assert space['minimum_available_bytes'] == 1073741824 and space['available_bytes'] >= 1073741824
    groups.append({'label': name, 'methods': len(expected['ids']), 'events': len(tests['events']),
                   'subtests': len(actual_subs), 'actual_child_request': pin(request_raw),
                   'raw_owner': pin(owner_raw), 'all_exact_ordered_ids': True,
                   'raw_plus_two_fields_equals_returned': True, 'cleanup_ECHILD': True})

outer = json.loads(full(RAW / 'source-controls-outer-r1/OUTER.json'))
assert outer['returncode'] == 0 and outer['status'] == 'OUTER_EXIT_ZERO'
assert outer['argv'] == json.loads(full(AUTHOR / 'SOURCE-LAUNCH.json'))['argv']
assert outer['entry_available_bytes'] >= 1073741824

OUT.mkdir(mode=0o700)
readback = {'schema': 'hepta.hia.inspect-shm-Source18-actual-readback.v1', 'status': 'PASS',
            'result': pin(result_raw), 'plan': pin(plan_raw), 'groups': groups,
            'methods': 18, 'events': 36, 'subtests': 21, 'outer_elapsed_ns': outer['elapsed_ns'],
            'source_tree': result['source_tree'], 'source_files': 3188,
            'source_capture_guards_pass': True, 'source_capture_full_bytes_are_archived': True,
            'qualification': 'Source18 only; Source8 synthetic transport is not Native17',
            'new_compile_Native_VM': 0, 'matching_current_cold': False,
            'CLI_op10_connected': False, 'whole_native': False,
            'old_workspace_prelaunch_refusal_preserved': '5fa1f28f2b55a630fcf5d10ce852f0ca1b3e6f49'}
create('ACTUAL-READBACK.json', encoded(readback))

nodes, cas = [], {}
def capture(path, logical):
    before = path.lstat()
    row = {'path': logical, 'source': str(path), 'posix_mode': stat.S_IMODE(before.st_mode), 'stat': seven(before)}
    if stat.S_ISDIR(before.st_mode):
        row['type'] = 'directory'; nodes.append(row)
        for child in sorted(path.iterdir(), key=lambda value: value.name):
            capture(child, logical + '/' + child.name)
        assert seven(path.lstat()) == seven(before)
    elif stat.S_ISREG(before.st_mode):
        raw = full(path); row.update(type='file', pin=pin(raw)); nodes.append(row)
        key = row['pin']['sha256']
        assert key not in cas or cas[key] == raw
        cas[key] = raw
    elif stat.S_ISLNK(before.st_mode):
        row.update(type='symlink', target=os.readlink(path)); nodes.append(row)
        assert seven(path.lstat()) == seven(before)
    else:
        raise AssertionError('Unexpected retained node type: ' + str(path))

capture(RAW, 'evidence')
for name in ('launch_source18_shm_once.py', 'SESSION-TOOLS.json'):
    capture(AUTHOR / name, 'transport/' + name)
manifest = {'schema': 'hepta.hia.complete-node-and-byte-custody.v1', 'source_root': str(RAW),
            'nodes': nodes, 'files': sum(row['type'] == 'file' for row in nodes),
            'directories': sum(row['type'] == 'directory' for row in nodes),
            'symlinks': sum(row['type'] == 'symlink' for row in nodes),
            'logical_bytes': sum(row.get('pin', {}).get('bytes', 0) for row in nodes),
            'unique_blobs': len(cas), 'unique_bytes': sum(map(len, cas.values())),
            'all_actual_remaining_evidence_nodes': True,
            'test_created_temporary_files_already_cleaned_by_original_tests_are_not_fabricated': True,
            'source_copies_or_links_created': 0, 'archiver_product_executions': 0}
manifest_raw = encoded(manifest); create('MANIFEST.json', manifest_raw)
tar_buffer = io.BytesIO()
with tarfile.open(fileobj=tar_buffer, mode='w', format=tarfile.USTAR_FORMAT) as tar:
    for name, raw in [('MANIFEST.json', manifest_raw)] + [('CAS/' + key, cas[key]) for key in sorted(cas)]:
        info = tarfile.TarInfo(name); info.size = len(raw); info.mode = 0o644
        info.uid = info.gid = info.mtime = 0; info.uname = info.gname = ''
        tar.addfile(info, io.BytesIO(raw))
tar_bytes = tar_buffer.getvalue()
gzip_buffer = io.BytesIO()
with gzip.GzipFile(fileobj=gzip_buffer, filename='', mode='wb', compresslevel=1, mtime=0) as gz:
    gz.write(tar_bytes)
archive = gzip_buffer.getvalue(); archive_pin = create('COMPLETE-ACTUAL.tar.gz', archive)
decoded = gzip.decompress(full(OUT / 'COMPLETE-ACTUAL.tar.gz'))
assert decoded == tar_bytes
restored_cas = {}
with tarfile.open(fileobj=io.BytesIO(decoded), mode='r:') as tar:
    members = tar.getmembers()
    assert len(members) == len(cas) + 1 and all(member.isfile() for member in members)
    assert tar.extractfile('MANIFEST.json').read() == manifest_raw
    for member in members:
        if member.name.startswith('CAS/'):
            raw = tar.extractfile(member).read(); key = member.name[4:]
            assert hashlib.sha256(raw).hexdigest() == key and raw == cas[key]
            restored_cas[key] = raw
assert set(restored_cas) == set(cas)
for row in nodes:
    path = Path(row['source'])
    assert seven(path.lstat()) == row['stat'] and stat.S_IMODE(path.lstat().st_mode) == row['posix_mode']
    if row['type'] == 'file':
        raw = restored_cas[row['pin']['sha256']]
        assert pin(raw) == row['pin'] and full(path) == raw
    elif row['type'] == 'symlink':
        assert os.readlink(path) == row['target']

parts = []
for index, begin in enumerate(range(0, len(archive), 196608)):
    piece = archive[begin:begin + 196608]
    name = 'SOURCE18-RAW-PART-%03d.json' % index
    wrapper = encoded({'schema': 'hepta.hia.lossless-archive-part.v1', 'index': index,
                       'archive_sha256': archive_pin['sha256'], 'decoded_offset': begin,
                       'decoded_bytes': len(piece), 'decoded_sha256': hashlib.sha256(piece).hexdigest(),
                       'base64': base64.b64encode(piece).decode('ascii')})
    parts.append({'index': index, 'file': name, 'pin': create(name, wrapper), 'decoded_bytes': len(piece),
                  'decoded_sha256': hashlib.sha256(piece).hexdigest()})
rebuilt = b''.join(base64.b64decode(json.loads(full(OUT / part['file']))['base64'], validate=True) for part in parts)
assert rebuilt == archive
create('PARTS-INDEX.json', encoded({'archive': archive_pin, 'parts': parts, 'complete': True}))
final = {'schema': 'hepta.hia.complete-actual-archive-full-readback.v1', 'status': 'PASS',
         'manifest': pin(manifest_raw), 'archive': archive_pin, 'files': manifest['files'],
         'directories': manifest['directories'], 'symlinks': manifest['symlinks'],
         'logical_bytes': manifest['logical_bytes'], 'unique_blobs': len(cas),
         'all_gzip_CRC_and_bytes_and_Git_SHA_and_modes_equal': True,
         'all_current_source_evidence_seven_stat_fields_unchanged': True,
         'physical_restored_duplicate_created': False, 'parts': len(parts),
         'raw_evidence_files': 52, 'raw_evidence_logical_bytes': 9817685,
         'product_execution_by_archiver': 0}
create('READBACK.json', encoded(final))
print(json.dumps(final, sort_keys=True))
