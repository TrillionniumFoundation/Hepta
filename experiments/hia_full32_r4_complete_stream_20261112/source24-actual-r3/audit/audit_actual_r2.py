"""Read-only verification of the already completed SOURCE24 r3 invocation.

This program does not import project code, launch a process, access the network,
capture private configuration, or execute any control or qualification. The
optional collection step copies only the fixed public originals listed below.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import traceback

ROOT = Path('/workspace/scratch/e26ed3e2edcf/root')
PLAN = Path('/workspace/scratch/e26ed3e2edcf/full32-stream-private-proxy-plan-r3-20261113-e26e')
ACTUAL = Path('/tmp/hia-full32-r4-stream-source-controls-r3-20261113-e26e')
OWNER = Path('/tmp/hia-full32-r4-stream-source-controls-r3-owner-20261113-e26e')
CANONICAL = 'c448d90f6bc7ec8db4dab3d11d85c20a89b55aa9'
TREE = '8983e55a8e2d58f39756bc5b825a004be40cbaf2'
PARENT = 'e83c8201bd5a2decaabea2c1080a27e4cf3dabb0'
PREFIX = 'experiments/hia_full32_r4_complete_stream_20261112/local-receiver-plan-r3'
REQUEST_SHA = '06a1659bc9620ce685faa0ed3fc6abffb41f26946c8789bc3fd98468d015af7b'
OWNER_SHA = '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def identity(s):
    return {k: getattr(s, 'st_' + k) for k in
            ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns')}


def git_blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def digest(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'git_blob': git_blob(raw)}


def read_regular(path, maximum=2 << 20):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'regular/single-link: ' + str(path))
    require(0 <= before.st_size <= maximum, 'bounded size: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(identity(os.fstat(fd)) == identity(before), 'open identity: ' + str(path))
        out = bytearray()
        while len(out) < before.st_size:
            chunk = os.read(fd, min(1 << 20, before.st_size - len(out)))
            require(bool(chunk), 'short input: ' + str(path))
            out.extend(chunk)
        require(os.read(fd, 1) == b'', 'input grew: ' + str(path))
        require(identity(os.fstat(fd)) == identity(before) == identity(path.lstat()), 'final input identity: ' + str(path))
        return bytes(out), identity(before)
    finally:
        os.close(fd)


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        require(stream.write(raw) == len(raw), 'short new write')
        stream.flush()
        os.fsync(stream.fileno())
    require(read_regular(path, max(len(raw), 1))[0] == raw, 'new file readback')


def encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def fixed_sources():
    result = {'actual/REPORT.json': ACTUAL / 'REPORT.json'}
    for name in ('process-owner.json', 'process-owner.json.request.json',
                 'process-owner.json.stderr.log', 'process-owner.json.stdout.log',
                 'qualification.stderr.log', 'qualification.stdout.log'):
        result['owner/' + name] = OWNER / name
    for name in ('INTENT.json', 'WRAPPER.json', 'RETURNED.json', 'READBACK.json'):
        result['root-invocation/' + name] = ROOT / 'full32-stream-source24-r3-invocation' / name
    for name in ('COMMIT.provider.json', 'PLAN.original.json', 'REF-ACK.json',
                 'REF-GET.provider.json', 'REF-INTENT.json', 'REF-PREFLIGHT.provider.json',
                 'ROOT-REVIEW.json', 'TREE.provider.json'):
        result['root-review/' + name] = ROOT / 'full32-stream-r3-review' / name
    for name in ('invoke_full32_stream_source24_r3_once.py',
                 'audit_full32_stream_source24_r3_actual.py',
                 'review_full32_stream_receiver_r3.py',
                 'audit_cli_r2b_actual_publication.py',
                 'review_full32_stream_receiver_r2.py',
                 'review_v92_failed_ci_recovery_r1.py'):
        result['root-scripts/' + name] = ROOT / name
    result['frozen/CONTROL-REQUEST.json'] = PLAN / 'CONTROL-REQUEST.json'
    request_raw, _ = read_regular(PLAN / 'CONTROL-REQUEST.json')
    require(hashlib.sha256(request_raw).hexdigest() == REQUEST_SHA, 'fixed request seal')
    request = json.loads(request_raw)
    require(len(request['inputs']) == 11, 'eleven original control inputs')
    for relative in request['inputs']:
        require(not relative.startswith('/') and '..' not in Path(relative).parts, 'safe input relative path')
        result['frozen/' + relative] = PLAN / relative
    return result


def collect(destination):
    require(not (destination / 'ORIGINALS-MANIFEST.json').exists(), 'collection already exists; no replay')
    # Bound the raw owner before reading any child-owned output.
    owner_raw, _ = read_regular(OWNER / 'process-owner.json')
    owner = json.loads(owner_raw)
    require(owner['cleanup']['complete'] is True and owner['cleanup']['observed_echild'] is True
            and owner['cleanup']['remaining_direct_children'] == [], 'actual owner not closed')
    require({p.name for p in OWNER.iterdir()} == {
        'process-owner.json', 'process-owner.json.request.json',
        'process-owner.json.stderr.log', 'process-owner.json.stdout.log',
        'qualification.stderr.log', 'qualification.stdout.log'}, 'complete six owner originals')
    require({p.name for p in ACTUAL.iterdir()} == {'REPORT.json', 'tmp'}, 'complete child output directory')
    temporary = ACTUAL / 'tmp'
    tmp_before = temporary.lstat()
    require(stat.S_ISDIR(tmp_before.st_mode) and not list(temporary.iterdir()), 'only retained empty synthetic tmp directory')
    require(identity(temporary.lstat()) == identity(tmp_before), 'empty tmp directory stable')
    directory_records = [{'path': str(p), 'original_identity': identity(p.lstat()),
                          'kind': 'directory', 'entries': sorted(c.name for c in p.iterdir())}
                         for p in (ACTUAL, OWNER, temporary)]
    records = []
    for relative, original in fixed_sources().items():
        raw, before = read_regular(original)
        write_new(destination / 'originals' / relative, raw)
        records.append({'relative': relative, 'original_path': str(original),
                        'original_identity': before, **digest(raw)})
    manifest = {'schema': 'hia.cold.source24-r3.original-custody.v1',
                'canonical_request': CANONICAL, 'count': len(records),
                'bytes': sum(r['bytes'] for r in records), 'files': records,
                'actual_directory_records': directory_records,
                'original_metadata_is_historical_not_copy_identity': True,
                'private_provider_references_or_proxy_contents_included': False,
                'source_controls_executed_by_collector': False}
    require(len(records) == 37, 'fixed 37 public source/actual/proof records')
    write_new(destination / 'ORIGINALS-MANIFEST.json', encode(manifest))


def hash_live_runtime(path, expected):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == expected['bytes'], 'runtime regular size')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    sha = hashlib.sha256()
    blob = hashlib.sha1(b'blob ' + str(before.st_size).encode() + b'\0')
    try:
        require(identity(os.fstat(fd)) == identity(before), 'runtime open identity')
        count = 0
        while count < before.st_size:
            raw = os.read(fd, min(1 << 20, before.st_size - count))
            require(bool(raw), 'runtime short read')
            count += len(raw); sha.update(raw); blob.update(raw)
        require(os.read(fd, 1) == b'', 'runtime extra bytes')
        require(identity(os.fstat(fd)) == identity(before) == identity(path.lstat()), 'runtime stable')
    finally:
        os.close(fd)
    require(sha.hexdigest() == expected['sha256'] and blob.hexdigest() == expected['git_blob'], 'runtime full digest')
    return {'path': str(path), 'bytes': count, 'sha256': sha.hexdigest(),
            'git_blob': blob.hexdigest(), 'actual_identity': identity(before)}


def merkle(document):
    require(document['sha'] == TREE and document['truncated'] is False, 'canonical complete tree')
    entries = document['tree']
    require(len(entries) == len({r['path'] for r in entries}), 'unique Git paths')
    by_path = {r['path']: r for r in entries}
    directories = {'': []}
    for row in entries:
        require(row['type'] in ('blob', 'tree') and '..' not in Path(row['path']).parts, 'Git entry type/path')
        parent, _, name = row['path'].rpartition('/')
        directories.setdefault(parent, []).append((name, row))
        if row['type'] == 'tree':
            directories.setdefault(row['path'], [])
    actual = {}
    for directory in sorted(directories, key=lambda p: (p.count('/') + (1 if p else 0), p), reverse=True):
        contents = bytearray()
        for name, row in sorted(directories[directory], key=lambda p: (p[0] + ('/' if p[1]['type'] == 'tree' else '')).encode()):
            mode = '40000' if row['type'] == 'tree' else row['mode']
            child_sha = actual[row['path']] if row['type'] == 'tree' else row['sha']
            require(child_sha == row['sha'], 'subtree SHA: ' + row['path'])
            contents.extend(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(child_sha))
        actual[directory] = hashlib.sha1(b'tree ' + str(len(contents)).encode() + b'\0' + contents).hexdigest()
    require(actual[''] == TREE, 'whole Git tree SHA')
    require(sum(r['type'] == 'blob' for r in entries) == 4364, '4364 fixed leaves')
    return by_path, len(actual)


def audit(destination, live):
    manifest_raw, _ = read_regular(destination / 'ORIGINALS-MANIFEST.json')
    manifest = json.loads(manifest_raw)
    require(manifest['count'] == len(manifest['files']) == 37, 'original record denominator')
    require(len({r['relative'] for r in manifest['files']}) == 37, 'unique original aliases')
    raws = {}
    for row in manifest['files']:
        relative = row['relative']
        require(not relative.startswith('/') and '..' not in Path(relative).parts, 'safe custody alias')
        raw, _ = read_regular(destination / 'originals' / relative)
        require(digest(raw) == {k: row[k] for k in ('bytes', 'sha256', 'git_blob')}, 'original full hash: ' + relative)
        raws[relative] = raw
    def obj(alias):
        return json.loads(raws[alias])
    checks = []
    def check(condition, name):
        require(condition, name); checks.append(name)
    request = obj('frozen/CONTROL-REQUEST.json')
    check(hashlib.sha256(raws['frozen/CONTROL-REQUEST.json']).hexdigest() == REQUEST_SHA, 'frozen request external seal')
    commit = obj('root-review/COMMIT.provider.json')
    check(commit['sha'] == CANONICAL and commit['tree']['sha'] == TREE and [r['sha'] for r in commit['parents']] == [PARENT], 'canonical commit/sole parent/tree')
    by_path, tree_count = merkle(obj('root-review/TREE.provider.json'))
    checks.append('complete 4364-leaf Git tree and all subtrees recomputed')
    check(by_path[PREFIX + '/CONTROL-REQUEST.json']['sha'] == git_blob(raws['frozen/CONTROL-REQUEST.json']), 'actual request canonical Git leaf')
    expected = request['expected_ids']
    check(len(expected) == len(set(expected)) == request['expected_methods'] == 24, 'complete ordered twenty-four IDs')
    check(request['qualification_seconds'] == 180 and request['cleanup_seconds'] == 3 and request['real_receiver_execution_permitted_by_this_request'] is False, 'source-only original 180/3')
    intent = obj('root-invocation/INTENT.json')
    returned = obj('root-invocation/RETURNED.json')
    wrapper = obj('root-invocation/WRAPPER.json')
    owner = obj('owner/process-owner.json')
    actual_request = obj('owner/process-owner.json.request.json')
    check(intent['canonical_request'] == CANONICAL and intent['status'] == 'ISSUED_ONCE_NO_REPLAY', 'unique Root intent canonical binding')
    check(intent['real_receiver_execution'] is False and intent['expected_ids'] == expected, 'intent source-only population')
    for key in ('command', 'qualification_seconds', 'cleanup_seconds'):
        check(actual_request[key] == intent[key] == request[key], 'actual owner request ' + key)
    check(actual_request['env'] == intent['environment'] == request['environment'], 'exact clean environment')
    check(set(actual_request['env']) == {'LANG', 'LC_ALL', 'PATH', 'PYTHONDONTWRITEBYTECODE', 'PYTHONNOUSERSITE', 'PYTHONUNBUFFERED'} and actual_request['env']['PATH'] == '', 'no HOME/proxy/credential inheritance')
    check(actual_request['cwd'] == intent['cwd'] == str(PLAN), 'original cwd')
    check({k: actual_request[k] for k in intent['paths']} == intent['paths'], 'actual output paths')
    check(actual_request['implementation_sha256'] == owner['implementation_sha256'] == request['owner_sha256'] == OWNER_SHA, 'original 369 implementation')
    check(owner['request_sha256'] == hashlib.sha256(raws['owner/process-owner.json.request.json']).hexdigest(), 'owner actual request full SHA')
    check(owner['parent_pid'] == actual_request['parent_pid'] == intent['parent_pid'], 'original parent PID')
    check(actual_request['deadline_ns'] - actual_request['started_ns'] == 180_000_000_000, 'original 180-second deadline arithmetic')
    for key, value in (('qualification_seconds', 180), ('cleanup_seconds', 3), ('subreaper_enabled', True), ('qualification_started', True), ('event_overflow', False), ('timed_out', False), ('exit_observed_before_deadline', True), ('returncode', 0), ('interrupted_signals', [])):
        check(owner.get(key) == value and type(owner.get(key)) is type(value), 'owner exact ' + key)
    cleanup = owner['cleanup']
    for key, value in (('complete', True), ('observed_echild', True), ('remaining_direct_children', []), ('leader_reaped', True), ('errors', []), ('deadline_exceeded', False), ('attempted', True)):
        check(cleanup.get(key) == value and type(cleanup.get(key)) is type(value), 'closed cleanup ' + key)
    check(type(cleanup['elapsed_ns']) is int and 0 <= cleanup['elapsed_ns'] <= 3_000_000_000, 'actual cleanup duration')
    check(owner['status'] == 'OWNED_PROCESS_COMPLETED', 'natural owner status')
    events = owner['events']
    check([e['kind'] for e in events] == ['qualification_started', 'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped'], 'exact four natural events/no signal')
    check(all(e['pid'] == owner['qualification_pid'] for e in events), 'all events original child')
    check(all(type(e['monotonic_ns']) is int for e in events) and [e['monotonic_ns'] for e in events] == sorted(e['monotonic_ns'] for e in events), 'ordered monotonic event times')
    check(events[2]['si_status'] == events[3]['returncode'] == 0 and events[2]['si_code'] == 1, 'actual natural exit and reap')
    check(actual_request['started_ns'] <= events[0]['monotonic_ns'] <= events[2]['monotonic_ns'] < actual_request['deadline_ns'], 'exit within original deadline')
    check(events[1]['ppid'] == owner['supervisor_pid'] == events[1]['pgid'] == events[1]['sid'], 'owned child supervisor/group identity')
    child_record = {k: events[1][k] for k in ('pid', 'ppid', 'pgid', 'sid', 'start_ticks')}
    check(owner['direct_and_adopted_children'] == [child_record] and events[3]['start_ticks'] == child_record['start_ticks'], 'original process identity inventory')
    projection = {k: v for k, v in wrapper.items() if k not in ('supervisor_returncode', 'receipt_sha256')}
    check(projection == owner and len(wrapper) == len(owner) + 2, 'returned wrapper equals complete raw owner plus exactly two fields')
    check(wrapper['supervisor_returncode'] == 0 and wrapper['receipt_sha256'] == hashlib.sha256(raws['owner/process-owner.json']).hexdigest(), 'wrapper supervisor and receipt digest')
    check(returned['owner_function_returned'] is True and returned['qualification_returncode'] == returned['supervisor_returncode'] == 0, 'Root call actually returned')
    check(returned['wrapper']['sha256'] == hashlib.sha256(raws['root-invocation/WRAPPER.json']).hexdigest(), 'Root returned wrapper raw join')
    check(raws['owner/process-owner.json.stdout.log'] == raws['owner/process-owner.json.stderr.log'] == b'', 'complete empty supervisor logs')
    # Only after verifying actual closed and natural owner do child results qualify.
    report = obj('actual/REPORT.json')
    check(report['schema'] == 'hia.full32.stream-reader-finite-controls.v1' and report['status'] == 'SOURCE_FORMAT_IO_24_PASS_ONLY' and report.get('exception') is None, 'actual source report status/no exception')
    for key in ('expected_ids', 'loaded_ids', 'actual_ids', 'success_ids'):
        check(report[key] == expected, 'complete exact ordered ' + key)
    check(type(report['tests_run']) is int and report['tests_run'] == 24, 'actual twenty-four methods')
    for key in ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes', 'denied_effects'):
        check(report[key] == [], 'zero ' + key)
    for key in ('network_used', 'product_executed', 'supplier_executed'):
        check(report[key] is False, 'no actual ' + key)
    check(type(report['provider_bytes_read']) is int and report['provider_bytes_read'] == 0, 'zero provider bytes')
    check(type(report['elapsed_ns']) is int and 0 <= report['elapsed_ns'] <= 180_000_000_000, 'finite source elapsed')
    check(report['inputs_before'] == report['inputs_after'] == request['inputs'], 'eleven complete frozen inputs before/after')
    current_inputs = []
    for relative, expected_pin in request['inputs'].items():
        frozen = raws['frozen/' + relative]
        pin = digest(frozen)
        check({k: pin[k] for k in ('bytes', 'sha256')} == expected_pin, 'full archived input ' + relative)
        check(by_path[PREFIX + '/' + relative]['sha'] == pin['git_blob'] == intent['source_inputs'][relative]['git_blob'], 'canonical/intent input Git join ' + relative)
        check(pin['sha256'] == intent['source_inputs'][relative]['sha256'], 'intent input SHA ' + relative)
        if live:
            live_raw, live_id = read_regular(PLAN / relative)
            check(live_raw == frozen, 'fresh actual input unchanged ' + relative)
            current_inputs.append({'relative': relative, **pin, 'actual_identity': live_id})
    stdout = json.loads(raws['owner/qualification.stdout.log'])
    check(stdout == {'status': 'SOURCE_FORMAT_IO_24_PASS_ONLY', 'tests_run': 24, 'provider_bytes_read': 0}, 'actual complete child stdout')
    stderr = raws['owner/qualification.stderr.log'].decode()
    observed = []
    for line in stderr.splitlines():
        match = re.fullmatch(r'(test_\w+) \([^.]*(?:\.[^.]*)*\.([^.]*)\.\1\) \.\.\. ok', line)
        if match:
            observed.append(match.group(2) + '.' + match.group(1))
    check(observed == expected, 'complete ordered stderr twenty-four OK lines')
    check('\nRan 24 tests in ' in stderr and stderr.rstrip().endswith('\nOK'), 'original unittest final summary')
    root_audit = obj('root-invocation/READBACK.json')
    check(root_audit['canonical_request'] == CANONICAL and root_audit['actual_ids'] == expected and root_audit['source_test_elapsed_ns'] == report['elapsed_ns'], 'independent result joins Root readback')
    root_review = obj('root-review/ROOT-REVIEW.json')
    check(root_review['canonical'] == CANONICAL and root_review['tree'] == TREE and root_review['source_controls_executed'] is False, 'prior Root review remains preexecution record')
    actual_rows = [r for r in manifest['files'] if r['relative'].startswith(('actual/', 'owner/'))]
    check(len(actual_rows) == 7 and sum(r['bytes'] for r in actual_rows) == 16258, 'complete seven actual originals / 16258 bytes')
    runtime = hash_live_runtime(Path(request['runtime']['path']), request['runtime']) if live else None
    if live:
        check(list(runtime['actual_identity'].values()) == request['runtime']['identity'], 'fresh runtime full identity')
    return {'schema': 'hia.cold.source24-r3.independent-actual-readback.v1',
            'status': 'SOURCE24_ACTUAL_ORIGINALS_INDEPENDENT_READBACK_PASS_ONLY',
            'canonical_request': CANONICAL, 'tree': TREE,
            'expected_ids': expected, 'expected': 24, 'loaded': 24, 'executed': 24, 'successful': 24,
            'anomalies_and_denied_effects': 0, 'source_elapsed_ns': report['elapsed_ns'],
            'owner_qualification_seconds': 180, 'owner_cleanup_seconds': 3,
            'owner_qualification_exit_elapsed_ns': events[2]['monotonic_ns'] - events[0]['monotonic_ns'],
            'owner_cleanup_elapsed_ns': cleanup['elapsed_ns'],
            'root_wrapper_elapsed_ns': returned['elapsed_ns'],
            'complete_actual_originals': actual_rows, 'all37_public_record_bytes': manifest['bytes'],
            'all_subtrees_recomputed': tree_count, 'checks_passed': len(checks), 'checks': checks,
            'live_input_readback_performed': live, 'live_input_records': current_inputs, 'live_runtime': runtime,
            'provider_bytes_read_by_original_controls': 0, 'receiver_executed': False,
            'private_proxy_capture_executed_by_this_audit': False,
            'source_tests_or_owner_reexecuted_by_this_audit': False,
            'historical_receiver_HOLD_and_supplier_HOLD_unchanged': True,
            'ten_gzip_ranges_full_read_or_full_ZIP_closure_claimed': False,
            'qualification_or_implementation_scope_expanded': False,
            'audit_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--collect', action='store_true')
    parser.add_argument('--check-live-inputs', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not os.path.lexists(args.output), 'new audit output required; do not overwrite')
    report = {'schema': 'hia.cold.source24-r3.independent-actual-readback.v1', 'status': 'HOLD'}
    try:
        if args.collect:
            collect(args.root)
        report = audit(args.root, args.check_live_inputs)
    except BaseException as exc:
        report['status'] = 'HOLD'
        report['exception'] = {'type': type(exc).__name__, 'message': str(exc), 'traceback': traceback.format_exc()}
        write_new(args.output, encode(report))
        raise
    write_new(args.output, encode(report))
    print(json.dumps({'status': report['status'], 'checks_passed': report['checks_passed'],
                      'actual_files': 7, 'actual_bytes': 16258, 'output': str(args.output),
                      'sha256': hashlib.sha256(read_regular(args.output)[0]).hexdigest()}))


if __name__ == '__main__':
    main()
