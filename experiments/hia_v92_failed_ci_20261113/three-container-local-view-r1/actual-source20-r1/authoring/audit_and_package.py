"""Independent readback/packaging of an already closed source20 operation.

Never imports a frozen control, invokes a source/receiver/product entry, reads
private network inputs, or requests a provider reference. All writes are new
publication evidence. Original source, request, outputs and root evidence stay
unchanged. Archive metadata is a carrier; exact original identities are retained
in the manifest and every original body is read back in full.
"""
from pathlib import Path
import gzip
import hashlib
import io
import json
import os
import stat
import tarfile

WORK = Path('/workspace/scratch/e26ed3e2edcf')
PLAN = WORK / 'v92-three-part-view-plan-r1-20261113-e26e'
ACTUAL = Path('/tmp/hia-v92-three-view-source20-r1-20261113-e26e')
ROOT = WORK / 'root'
INVOCATION = ROOT / 'v92-three-view-source20-r1-invocation'
ROOT_REVIEW = ROOT / 'v92-three-part-view-r1-review'
OUT = WORK / 'core/v92-source20-actual-publication-r1-20261113-e26e'
ENTRY = Path('/tmp/hia-core-peer-reviews-20261113/v92-source20-entry-gate-static-review-r1.json')
PARENT = '81325ef09af975bce51912b9173a369070da340d'
PARENT_TREE = '92df965de9a48e22611ea36545dbad215c819470'


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def digest(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def read(path, maximum=64 << 20):
    path = Path(path)
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
    assert 0 <= before.st_size <= maximum
    for parent in path.parents:
        assert stat.S_ISDIR(parent.lstat().st_mode)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        assert identity(os.fstat(fd)) == identity(before)
        chunks = []
        remaining = before.st_size
        while remaining:
            part = os.read(fd, min(remaining, 1 << 20))
            assert part
            chunks.append(part)
            remaining -= len(part)
        assert os.read(fd, 1) == b''
        assert identity(os.fstat(fd)) == identity(path.lstat()) == identity(before)
        raw = b''.join(chunks)
        return raw, dict(path=str(path), identity=identity(before), **digest(raw))
    finally:
        os.close(fd)


def js(path):
    return json.loads(read(path)[0])


def save(path, value):
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    actual, pin = read(path)
    assert actual == raw
    return pin


def verify_record(record):
    raw, actual = read(record['path'])
    assert all(record[k] == actual[k] for k in ('path', 'bytes', 'sha256'))
    if 'identity' in record:
        assert record['identity'] == actual['identity']
    if 'git_blob' in record:
        assert record['git_blob'] == actual['git_blob_sha1']
    if 'mode' in record:
        assert record['mode'] == stat.S_IMODE(actual['identity'][2])
    return raw, actual


def main():
    assert not (OUT / 'INDEPENDENT-ACTUAL-READBACK.json').exists()
    request = js(PLAN / 'CONTROL-REQUEST.json')
    launch = js(PLAN / 'CONTROL-LAUNCH.json')
    intent = js(INVOCATION / 'INTENT.json')
    returned = js(INVOCATION / 'RETURNED.json')
    assert intent['canonical_request'] == PARENT
    assert returned['returncode'] == 0 and returned['exact_launcher_returned'] is True
    assert intent['command'] == launch['command']
    assert intent['cwd'] == launch['cwd'] == str(PLAN)
    assert intent['environment'] == launch['environment'] == request['environment']
    assert intent['expected_ids'] == request['expected_ids']
    assert (intent['owner_seconds'], intent['cleanup_seconds']) == (20, 3)
    assert request['operation_root'] == str(ACTUAL)
    for key in ('request', 'launch', 'invoker', 'review'):
        verify_record(intent[key])
    for key in ('stdout', 'stderr'):
        verify_record(returned[key])

    # Establish actual bound owner closure before any child report/body census.
    life = js(ACTUAL / 'lifecycle.json')
    owner_return = js(ACTUAL / 'OWNER-RETURN.json')
    actual_request = js(ACTUAL / 'lifecycle.json.request.json')
    projected = dict(owner_return)
    assert projected.pop('supervisor_returncode') == 0
    assert projected.pop('receipt_sha256') == read(ACTUAL / 'lifecycle.json')[1]['sha256']
    assert projected == life
    assert life['request_sha256'] == read(ACTUAL / 'lifecycle.json.request.json')[1]['sha256']
    assert life['implementation_sha256'] == actual_request['implementation_sha256'] == request['inputs']['control/process_owner_impl.py']['sha256']
    assert actual_request['command'] == request['command']
    assert actual_request['cwd'] == str(PLAN) and actual_request['env'] == request['environment']
    assert life['qualification_seconds'] == actual_request['qualification_seconds'] == 20
    assert life['cleanup_seconds'] == actual_request['cleanup_seconds'] == 3
    assert actual_request['deadline_ns'] - actual_request['started_ns'] == 20_000_000_000
    cleanup = life['cleanup']
    assert all(cleanup[k] is True for k in ('attempted', 'complete', 'leader_reaped', 'observed_echild'))
    assert cleanup['remaining_direct_children'] == cleanup['errors'] == []
    assert cleanup['deadline_exceeded'] is False
    assert life['subreaper_enabled'] is True and life['event_overflow'] is False
    assert life['status'] == 'OWNED_PROCESS_COMPLETED' and type(life['returncode']) is int and life['returncode'] == 0
    assert life['exit_observed_before_deadline'] is True and life['timed_out'] is False
    assert life['interrupted_signals'] == [] and life.get('owner_error') is None
    events = life['events']
    assert [e['kind'] for e in events] == ['qualification_started', 'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped']
    assert all(e['pid'] == life['qualification_pid'] for e in events)
    assert events[2]['si_code'] == 1 and events[2]['si_status'] == events[3]['returncode'] == 0
    assert events[1]['start_ticks'] == events[3]['start_ticks']
    assert [e['monotonic_ns'] for e in events] == sorted(e['monotonic_ns'] for e in events)
    assert events[2]['monotonic_ns'] < actual_request['deadline_ns']
    assert life['direct_and_adopted_children'] == [{k: events[1][k] for k in ('pgid', 'pid', 'ppid', 'sid', 'start_ticks')}]

    final = js(ACTUAL / 'FINAL.json')
    report = js(ACTUAL / 'tests/REPORT.json')
    assert final['status'] == 'TWENTY_SOURCE_IO_PASS_ONLY' and final['errors'] == []
    assert final['closed_owner'] is final['natural_owner'] is True
    assert final['product_execution'] is final['receiver_executed'] is False
    for key in ('request', 'lifecycle', 'report'):
        verify_record(final[key])
    ids = request['expected_ids']
    assert len(ids) == len(set(ids)) == 20
    assert report['status'] == 'TWENTY_SOURCE_IO_CONTROLS_PASS_ONLY' and report.get('exception') is None
    assert all(report[k] == ids for k in ('expected_ids', 'loaded_ids', 'actual_ids', 'success_ids'))
    assert type(report['tests_run']) is int and report['tests_run'] == 20
    anomalies = ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes', 'denied_effects')
    assert all(report[k] == [] for k in anomalies)
    assert type(report['network_bytes']) is int and report['network_bytes'] == 0
    assert all(report[k] is False for k in ('private_proxy_capture_performed', 'product_execution', 'receiver_executed'))
    assert report['inputs_before'] == report['inputs_after'] == request['inputs']
    assert 0 <= report['elapsed_seconds'] < 20

    before = js(ACTUAL / 'INPUTS-BEFORE.json')
    after = js(ACTUAL / 'INPUTS-AFTER.json')
    assert before == after and len(before) == len(request['inputs']) == 35
    assert set(before) == {str(PLAN / n) for n in request['inputs']}
    for path, record in before.items():
        assert record['path'] == path
        _, pin = verify_record(record)
        expected = request['inputs'][str(Path(path).relative_to(PLAN))]
        assert {k: pin[k] for k in ('bytes', 'sha256')} == expected
    runtime = read(request['runtime']['path'])[1]
    assert all(runtime[k] == request['runtime'][k] for k in ('path', 'bytes', 'sha256', 'identity'))
    assert read(ACTUAL / 'REQUEST.original.json')[0] == read(PLAN / 'CONTROL-REQUEST.json')[0]
    original = js(ACTUAL / 'ORIGINALS.json')
    assert original['after_bound_ECHILD'] is True
    assert len(original['files']) == len({r['path'] for r in original['files']}) == 10
    assert sum(r['bytes'] for r in original['files']) == original['bytes'] == 51335
    for record in original['files']:
        verify_record(record)

    actual_files = []
    actual_dirs = []
    for path in sorted(ACTUAL.rglob('*')):
        old = path.lstat()
        if stat.S_ISDIR(old.st_mode):
            actual_dirs.append({'path': str(path), 'identity': identity(old)})
        else:
            actual_files.append(read(path)[1])
    assert len(actual_files) == 13 and sum(r['bytes'] for r in actual_files) == 74043
    assert {r['path'] for r in original['files']} == {r['path'] for r in actual_files} - {str(ACTUAL / n) for n in ('FINAL.json', 'INPUTS-AFTER.json', 'ORIGINALS.json')}
    stderr = read(ACTUAL / 'stderr.log')[0].decode()
    ok_lines = [line for line in stderr.splitlines() if line.endswith(' ... ok')]
    assert len(ok_lines) == 20 and stderr.splitlines()[-1] == 'OK'
    assert [line.split(' ', 1)[0] for line in ok_lines] == [s.split('.', 1)[1] for s in ids]
    assert json.loads(read(ACTUAL / 'stdout.log')[0]) == {'status': 'TWENTY_SOURCE_IO_CONTROLS_PASS_ONLY', 'tests_run': 20, 'network_bytes': 0}
    assert read(INVOCATION / 'launcher.stderr.log')[0] == b''
    assert json.loads(read(INVOCATION / 'launcher.stdout.log')[0]) == {'status': 'TWENTY_SOURCE_IO_PASS_ONLY', 'closed_owner': True, 'receiver_executed': False}

    root_readback = js(INVOCATION / 'READBACK.json')
    assert root_readback['status'] == 'ROOT_ALL20_SOURCE_IO_CONTROLS_AND_ORIGINAL_OWNER_PASS'
    assert root_readback['expected_loaded_actual_success_ids'] == ids
    assert root_readback['source_seconds'] == report['elapsed_seconds']
    assert root_readback['qualification_elapsed_ns'] == events[2]['monotonic_ns'] - events[0]['monotonic_ns']
    for record in root_readback['actual_files']:
        verify_record(record)
    assert {r['path'] for r in root_readback['actual_files']} == {r['path'] for r in actual_files}

    frozen = js(PLAN / 'publication/PLAN-FINAL.json')
    assert len(frozen['files']) == 44
    for row in frozen['files']:
        _, pin = read(row['local'])
        assert pin['bytes'] == row['bytes'] and pin['sha256'] == row['sha256'] and pin['git_blob_sha1'] == row['sha']
    hold = js(ROOT_REVIEW / 'reader-authoring-history-r1/HOLD.json')
    assert hold['status'] == 'ROOT_READONLY_REVIEW_AUTHORING_HOLD'
    assert hold['script_sha256'] == read(ROOT_REVIEW / 'reader-authoring-history-r1/review_v92_three_part_view_r1.py')[1]['sha256']

    audit = {'schema': 'hia.peer.source20-actual-complete-readback.v1',
        'status': 'INDEPENDENT_ALL20_SOURCE_IO_ACTUAL_READBACK_PASS',
        'parent_request': PARENT, 'parent_tree': PARENT_TREE,
        'exact_ids': ids, 'source_seconds': report['elapsed_seconds'],
        'qualification_elapsed_ns': events[2]['monotonic_ns'] - events[0]['monotonic_ns'],
        'launcher_elapsed_ns': returned['elapsed_ns'], 'original_owner_seconds': 20,
        'cleanup_seconds': 3, 'natural_zero_bound_ECHILD': True,
        'actual_files': actual_files, 'actual_directories': actual_dirs,
        'actual_count': 13, 'actual_bytes': 74043,
        'original_index_count_at_capture': 10, 'original_index_bytes_at_capture': 51335,
        'index_additions_after_capture': ['FINAL.json', 'INPUTS-AFTER.json', 'ORIGINALS.json'],
        'input_count': 35, 'source_bytes_and_physical_identities_stable': True,
        'frozen_request_files': 44, 'frozen_request_bytes': 954486,
        'all_unit_anomalies_and_denied_effects_empty': True,
        'root_readback': read(INVOCATION / 'READBACK.json')[1],
        'root_unique_invocation': read(INVOCATION / 'INTENT.json')[1],
        'authoring_history_is_not_a_control_failure': hold,
        'network_bytes': 0, 'product_execution': False, 'receiver_execution': False,
        'additional_control_invocations_by_this_reader': 0,
        'private_network_input_content_read': False,
        'private_capture_or_provider_reference_requests': 0, 'large_part_GETs': 0,
        'original_CI_and_remote_recovery_failures_preserved': True,
        'real_receiver_still_requires_fresh_capacity_and_private_inputs': True}
    save(OUT / 'INDEPENDENT-ACTUAL-READBACK.json', audit)

    targets = []
    def add_tree(prefix, root):
        for path in sorted(root.rglob('*')):
            if path.is_file():
                targets.append((prefix + '/' + str(path.relative_to(root)), path))
            else:
                assert stat.S_ISDIR(path.lstat().st_mode)
    add_tree('actual', ACTUAL)
    add_tree('root-review', ROOT_REVIEW)
    add_tree('root-invocation', INVOCATION)
    for name in ('invoke_v92_three_view_source20_r1_once.py', 'audit_v92_three_view_source20_r1_actual.py',
                 'review_v92_three_part_view_r1.py', 'audit_cli_r2b_actual_publication.py',
                 'review_v92_failed_ci_recovery_r1.py'):
        targets.append(('root-authoring/' + name, ROOT / name))
    targets.extend([('peer/ENTRY-GATE-STATIC-REVIEW.json', ENTRY),
                    ('peer/INDEPENDENT-ACTUAL-READBACK.json', OUT / 'INDEPENDENT-ACTUAL-READBACK.json'),
                    ('peer/audit_and_package.py', Path(__file__))])
    names = [name for name, _ in targets]
    assert len(names) == len(set(names))
    rows = []
    for name, path in targets:
        _, pin = read(path)
        rows.append(dict(archive_path=name, **pin))
    manifest = {'schema': 'hia.complete-source20-custody-inventory.v1',
        'parent': PARENT, 'parent_tree': PARENT_TREE, 'actual_files': 13, 'actual_bytes': 74043,
        'files': rows, 'file_count': len(rows), 'file_bytes': sum(r['bytes'] for r in rows),
        'actual_directories': actual_dirs,
        'carrier_metadata': 'USTAR mode is original permission bits; uid/gid/mtime fields normalized only in the carrier. Full original physical identities are listed here; every original body is unchanged.',
        'includes_original_root_reader_authoring_HOLD': True,
        'includes_original_unique_invocation_and_root_readback': True,
        'private_or_signed_URL_inputs_included': False}
    save(OUT / 'ARCHIVE-MANIFEST.json', manifest)
    manifest_raw = read(OUT / 'ARCHIVE-MANIFEST.json')[0]
    archive = OUT / 'source20-complete-originals.tar.gz'
    with archive.open('xb') as raw_stream:
        with gzip.GzipFile(filename='', fileobj=raw_stream, mode='wb', compresslevel=6, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode='w|', format=tarfile.USTAR_FORMAT) as tar:
                for row, (name, path) in zip(rows, targets):
                    body, pin = read(path)
                    assert pin == {k: v for k, v in row.items() if k != 'archive_path'}
                    item = tarfile.TarInfo(name)
                    item.size = len(body); item.mode = stat.S_IMODE(pin['identity'][2])
                    item.uid = item.gid = item.mtime = 0
                    tar.addfile(item, io.BytesIO(body))
                item = tarfile.TarInfo('ARCHIVE-MANIFEST.json')
                item.size = len(manifest_raw); item.mode = 0o600
                tar.addfile(item, io.BytesIO(manifest_raw))
        raw_stream.flush(); os.fsync(raw_stream.fileno())
    wanted = {row['archive_path']: row for row in rows}
    seen = []
    with tarfile.open(archive, 'r:gz') as tar:
        for member in tar:
            assert member.isfile() and member.name not in seen
            seen.append(member.name)
            body = tar.extractfile(member).read()
            if member.name == 'ARCHIVE-MANIFEST.json':
                assert body == manifest_raw
                continue
            row = wanted[member.name]
            assert digest(body) == {k: row[k] for k in ('bytes', 'sha256', 'git_blob_sha1')}
            assert body == read(row['path'])[0]
            assert member.mode == stat.S_IMODE(row['identity'][2])
    assert set(seen) == set(wanted) | {'ARCHIVE-MANIFEST.json'}
    # A second complete gzip read consumes/verifies the checksum/trailer.
    with gzip.open(archive, 'rb') as stream:
        expanded = hashlib.sha256(); expanded_bytes = 0
        while chunk := stream.read(1 << 20):
            expanded.update(chunk); expanded_bytes += len(chunk)
    archive_pin = read(archive)[1]
    package = {'schema': 'hia.source20-complete-custody-package.v1',
        'status': 'ALL_ARCHIVE_BODIES_AND_LIVE_ORIGINALS_READBACK_PASS',
        'archive': archive_pin, 'manifest': read(OUT / 'ARCHIVE-MANIFEST.json')[1],
        'independent_audit': read(OUT / 'INDEPENDENT-ACTUAL-READBACK.json')[1],
        'archive_members': len(seen), 'original_file_count': len(rows),
        'original_file_bytes': manifest['file_bytes'],
        'uncompressed_tar_bytes': expanded_bytes, 'uncompressed_tar_sha256': expanded.hexdigest(),
        'actual13': {'count': 13, 'bytes': 74043},
        'source_control_invocations_by_packager': 0,
        'provider_requests_or_receiver_runs_by_packager': 0}
    save(OUT / 'PACKAGE-READBACK.json', package)
    print(json.dumps({'status': package['status'], 'archive': archive_pin,
                      'members': len(seen), 'original_bytes': manifest['file_bytes']}))


if __name__ == '__main__':
    main()
