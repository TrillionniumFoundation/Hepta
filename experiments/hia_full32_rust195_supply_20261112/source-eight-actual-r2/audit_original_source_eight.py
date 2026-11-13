"""Independent read-only joins of Root's already closed source-eight run.

Does not import any candidate, execute a test, or launch a process. The complete
17 actual files and original lifecycle/request are read from their closed paths.
"""
from pathlib import Path
import hashlib
import json
import os
import stat
import traceback

HERE = Path(__file__).resolve().parent
ACTUAL = Path('/tmp/hia-full32-rust195-source-eight-actual-r2-20261112-e26e')
SOURCE = Path('/tmp/hia-full32-rust195-source-eight-plan-r2-20261112-e26e')
ROOT = Path('/workspace/scratch/e26ed3e2edcf/root')
EXPECTED_REQUEST_SHA = '2818142cea6592022bb0d54fc7d3de93c8c19a548834e82c244869f2c55389a3'
EXPECTED_ROOT_REVIEW_SHA = 'e0abf73200b12021b3986eb4e065cb2c4d9cc0219d85c2574c5dfe7eb922db3c'
EXPECTED = {
    'CAPACITY-BEFORE.json', 'FINAL.json', 'INPUTS-AFTER.json', 'INPUTS-BEFORE.json',
    'ORIGINAL-CATALOG.json', 'OWNER-RETURN.json', 'REQUEST.original.json',
    'lifecycle.json', 'lifecycle.json.request.json', 'lifecycle.json.stderr.log',
    'lifecycle.json.stdout.log', 'stderr.log', 'stdout.log', 'tests/INPUTS-AFTER.json',
    'tests/INPUTS-BEFORE.json', 'tests/REPORT.json', 'tests/TEST-EVENTS.json',
}


def identity(value):
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def read(path, maximum=1 << 20):
    old = path.lstat()
    if not stat.S_ISREG(old.st_mode) or old.st_nlink != 1 or not 0 <= old.st_size <= maximum:
        raise RuntimeError('bounded regular original required: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if identity(os.fstat(fd)) != identity(old):
            raise RuntimeError('opened original changed')
        chunks, count = [], 0
        while True:
            chunk = os.read(fd, min(65536, maximum + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            chunks.append(chunk)
            if count > maximum:
                raise RuntimeError('whole original bound exceeded')
        if count != old.st_size or identity(os.fstat(fd)) != identity(old) or identity(path.lstat()) != identity(old):
            raise RuntimeError('original changed during full read')
    finally:
        os.close(fd)
    body = b''.join(chunks)
    return {'path': str(path), 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest(),
            'identity': identity(old)}, body


def value(raw):
    def pairs(items):
        out = {}
        for key, item in items:
            if key in out:
                raise RuntimeError('duplicate original JSON key')
            out[key] = item
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(RuntimeError('nonfinite JSON')))


def main():
    report = {'schema': 'hia.cold.independent-rust195-source-eight-readback.v1', 'status': 'HOLD',
              'checks': [], 'originals': [], 'request_canonical': '20bcabac0a7c6be1d5afc2d333622bbed3135dfa',
              'new_test_or_supplier_or_native_execution': False, 'original_HOLD_and_UNKNOWN_unchanged': True,
              'current_product_binding': None, 'Full32_pass_claimed': False}
    def check(name, condition):
        report['checks'].append({'check': name, 'passed': bool(condition)})
        if not condition:
            raise RuntimeError(name)
    try:
        actual_paths = {str(p.relative_to(ACTUAL)) for p in ACTUAL.rglob('*') if p.is_file() or p.is_symlink()}
        check('exact17 actual original files', actual_paths == EXPECTED)
        pins, bodies = {}, {}
        for name in sorted(EXPECTED):
            pins[name], bodies[name] = read(ACTUAL / name)
            report['originals'].append(pins[name])
        request_pin, request_raw = read(SOURCE / 'REQUEST.json')
        check('frozen request body and actual original', request_pin['sha256'] == EXPECTED_REQUEST_SHA
              and request_raw == bodies['REQUEST.original.json'])
        request = value(request_raw)
        final = value(bodies['FINAL.json'])
        worker = value(bodies['tests/REPORT.json'])
        life = value(bodies['lifecycle.json'])
        owner_request = value(bodies['lifecycle.json.request.json'])
        returned = value(bodies['OWNER-RETURN.json'])
        check('returned wrapper contains only original two extra fields',
              {k: v for k, v in returned.items() if k not in ('supervisor_returncode', 'receipt_sha256')} == life
              and returned['supervisor_returncode'] == 0
              and returned['receipt_sha256'] == pins['lifecycle.json']['sha256'])
        check('owner request exact command/cwd/env', owner_request['command'] == request['command']
              and owner_request['cwd'] == str(SOURCE) and owner_request['env'] == request['environment']
              and 'HOME' not in owner_request['env'])
        check('original1803 implementation and request binding',
              owner_request['qualification_seconds'] == life['qualification_seconds'] == 180
              and owner_request['cleanup_seconds'] == life['cleanup_seconds'] == 3
              and owner_request['deadline_ns'] - owner_request['started_ns'] == 180 * 10**9
              and life['request_sha256'] == pins['lifecycle.json.request.json']['sha256']
              and life['implementation_sha256'] == owner_request['implementation_sha256']
                  == request['inputs']['control/process_owner_impl.py']['sha256'])
        cleanup = life['cleanup']
        check('complete actual ECHILD', cleanup['complete'] is True and cleanup['observed_echild'] is True
              and cleanup['leader_reaped'] is True and cleanup['remaining_direct_children'] == []
              and cleanup['errors'] == [] and cleanup['deadline_exceeded'] is False)
        check('natural actual owner', life['status'] == 'OWNED_PROCESS_COMPLETED' and life['returncode'] == 0
              and life['timed_out'] is False and life['exit_observed_before_deadline'] is True
              and life['interrupted_signals'] == [] and life.get('owner_error') is None
              and life['subreaper_enabled'] is True and life['event_overflow'] is False)
        events = life['events']
        check('four actual owner events', [e['kind'] for e in events] == [
            'qualification_started', 'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped'])
        check('leader/PID/clock natural chain', all(e['pid'] == life['qualification_pid'] for e in events)
              and owner_request['started_ns'] <= events[0]['monotonic_ns']
              <= events[1]['monotonic_ns'] <= events[2]['monotonic_ns']
              <= events[3]['monotonic_ns'] <= owner_request['deadline_ns']
              and events[2]['si_status'] == events[3]['returncode'] == 0)
        ids = request['expected_ids']
        check('all eight exact IDs in original declared order', len(ids) == len(set(ids)) == request['expected_methods'] == 8
              and all(worker[k] == ids for k in ('expected_ids', 'loaded_ids', 'actual_ids', 'success_ids'))
              and worker['tests_run'] == 8)
        check('five anomalies and denied effects zero', all(worker[k] == [] for k in (
            'failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes', 'denied_effects'))
              and worker.get('exception') is None)
        check('all execution boundary flags remain false', all(worker[k] is False for k in (
            'APT_executed', 'Rustup_executed', 'native_executed', 'network_used', 'supplier_executed',
            'supplier_module_imported', 'product_qualification_executed', 'original_product_results_reclassified'))
              and worker['product_source_binding'] is None)
        test_events = value(bodies['tests/TEST-EVENTS.json'])
        check('all16 actual start/stop records', len(test_events) == 16
              and [(e['id'], e['kind']) for e in test_events] == [(i, k) for i in ids for k in ('start', 'stop')]
              and all(events[0]['monotonic_ns'] <= e['monotonic_ns'] <= events[2]['monotonic_ns'] for e in test_events)
              and [e['monotonic_ns'] for e in test_events] == sorted(e['monotonic_ns'] for e in test_events))
        check('worker and parent bind exact request/report originals', worker['request'] == request_pin
              and final['request'] == request_pin and final['report'] == pins['tests/REPORT.json'])
        snapshots = [value(bodies[name]) for name in ('INPUTS-BEFORE.json', 'INPUTS-AFTER.json',
                                                    'tests/INPUTS-BEFORE.json', 'tests/INPUTS-AFTER.json')]
        check('four original input snapshots identical', all(s == snapshots[0] for s in snapshots))
        current_inputs = {}
        for name, expected in request['inputs'].items():
            actual, _ = read(SOURCE / name)
            check('fresh whole input ' + name, all(actual[k] == v for k, v in expected.items()))
            current_inputs[name] = actual
        check('all15 whole input identities equal recorded snapshots', len(current_inputs) == 15 and current_inputs == snapshots[0]
              and worker['inputs_before'] == worker['inputs_after'] == current_inputs)
        catalog = value(bodies['ORIGINAL-CATALOG.json'])
        expected_catalog = EXPECTED - {'FINAL.json', 'INPUTS-AFTER.json', 'ORIGINAL-CATALOG.json'}
        check('original custody catalog exact pre-final population', catalog['after_current_ECHILD'] is True
              and catalog['complete_observed_namespace'] is True
              and len(catalog['records']) == len(expected_catalog)
              and {str(Path(r['path']).relative_to(ACTUAL)) for r in catalog['records']} == expected_catalog)
        for row in catalog['records']:
            name = str(Path(row['path']).relative_to(ACTUAL))
            check('full original catalog record ' + name, row == pins[name])
        check('catalog full regular-byte sum', catalog['regular_bytes'] == sum(pins[x]['bytes'] for x in expected_catalog))
        check('source-only final classification', final['status'] == 'SOURCE_EIGHT_PASS_ONLY_NOT_FULL32'
              and worker['status'] == 'EIGHT_INERT_SOURCE_CONTROLS_PASS_ONLY'
              and all(final[k] is True for k in ('closed_owner', 'natural_owner', 'complete_output_custody', 'source_eight_pass'))
              and final['errors'] == [] and final['product_source_binding'] is None)
        root_pin, root_raw = read(ROOT / 'full32-rust195-source8-r2-invocation/READBACK.json')
        check('Root independent raw receipt unchanged', root_pin['sha256'] == EXPECTED_ROOT_REVIEW_SHA)
        root_review = value(root_raw)
        check('independent all17 pins equal Root full readback', root_review['originals'] == report['originals']
              and root_review['original_files'] == 17 and root_review['original_bytes'] == 70304)
        report.update(status='INDEPENDENT_EIGHT_SOURCE_ONLY_READBACK_PASS', input_files=15,
                      request=request_pin, original_files=17, original_bytes=sum(p['bytes'] for p in pins.values()),
                      owner_seconds_to_exit=(events[2]['monotonic_ns']-events[0]['monotonic_ns'])/10**9,
                      worker_elapsed_ns=worker['elapsed_ns'], source_expected=8, source_executed=8,
                      all_five_anomalies_zero=True, root_readback=root_pin)
    except BaseException as error:
        report['status'] = 'HOLD'
        report['error'] = {'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
    report['checks_count'] = len(report['checks'])
    raw = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(HERE / 'AUDIT.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    print(json.dumps({'status': report['status'], 'checks': report['checks_count'],
                      'report_sha256': hashlib.sha256(raw).hexdigest()}))
    return 0 if report['status'] == 'INDEPENDENT_EIGHT_SOURCE_ONLY_READBACK_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
