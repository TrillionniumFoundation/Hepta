"""Strict data readback for the independent worker terminal controls.

This reader imports no product or test body. Every consumed JSON byte string
is captured once, hashed against its producer authority when available, then
parsed and re-read unchanged at the terminal boundary. It never upgrades an
absent report, incomplete input inventory, or failed child into PASS.
"""
from __future__ import annotations
import argparse
import base64
import csv
from hashlib import sha256
import io
import json
from pathlib import Path
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_SHA256 = '5ae994e97ee7542921047ee763eeab7c180dad7d222b1f8648b96fe6fedce392'
FIXTURE = ROOT / 'tests/fixtures/worker_unknown_original_r17b/manifest.json'
CASES = ROOT / 'tests/fixtures/worker_unknown_cases.json'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


class Capture:
    def __init__(self):
        self.raw = {}
        self.streams = {}
    def take(self, path, expected=None):
        path = Path(path)
        key = str(path)
        if key in self.raw:
            raw = self.raw[key]
        else:
            raw = path.read_bytes()
            self.raw[key] = raw
        if expected is not None and pin(raw) != expected:
            raise ValueError('captured bytes differ: ' + key)
        return raw
    def parse(self, path, expected=None):
        raw = self.take(path, expected)
        return json.loads(raw)
    def take_stream(self, path, expected):
        key = str(Path(path))
        if key in self.streams:
            if self.streams[key] != expected:
                raise ValueError('stream authority changed: ' + key)
            return expected
        actual = _stream_pin(path)
        if actual != expected:
            raise ValueError('consumed stream differs: ' + key)
        self.streams[key] = dict(expected)
        return actual
    def stable(self):
        for path, raw in self.raw.items():
            if Path(path).read_bytes() != raw:
                raise ValueError('consumed evidence changed: ' + path)
        for path, expected in self.streams.items():
            if _stream_pin(path) != expected:
                raise ValueError('consumed stream changed: ' + path)
    def ledger(self):
        return {**self.streams, **{path: pin(raw) for path, raw in self.raw.items()}}


def fixture(capture):
    raw = capture.take(FIXTURE)
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('fixed worker input authority changed')
    value = json.loads(raw)
    expected = {str(FIXTURE): pin(raw)}
    for name, identity in value['originals'].items():
        path = FIXTURE.parent / name
        capture.take(path, identity)
        expected[str(path)] = identity
    for name, identity in value['candidate_runtime'].items():
        path = ROOT / name
        capture.take(path, identity)
        expected[str(path)] = identity
    generator = ROOT / 'tools/generate_hia_worker_report.py'
    capture.take(generator, value['HIA_policy_generator_unchanged'])
    expected[str(generator)] = value['HIA_policy_generator_unchanged']
    cases = capture.parse(CASES, value['cases'])
    expected[str(CASES)] = value['cases']
    return value, cases, expected


def completed(record, expected_code, timeout):
    if (record['returncode'] != expected_code or record['expected_returncode'] != expected_code
            or record['timeout'] is not False or record['timeout_seconds'] != timeout
            or record['cleanup_seconds'] != 3 or record['cleanup_error'] is not None
            or record['cleanup']['after'] != [] or record['cleanup']['reaped'] is not True
            or type(record['pid']) is not int or record['pid'] <= 0
            or record['pgid'] != record['pid']
            or record['ended_time_ns'] < record['started_time_ns']):
        raise ValueError('child has no complete expected natural terminal')


def read_source(parent, mode, expected_execution):
    parent = Path(parent)
    capture = Capture()
    original, cases, sources = fixture(capture)
    if mode not in ('ordinary', 'unknown', 'scope'):
        raise ValueError('unknown worker source control')
    execution = capture.parse(parent / (mode + '.result.json'), expected_execution)
    completed(execution, 0, 180)
    stdout = capture.take(parent / (mode + '.stdout.log'))
    stderr = capture.take(parent / (mode + '.stderr.log'))
    if (sha256(stdout).hexdigest() != execution['stdout_sha256']
            or sha256(stderr).hexdigest() != execution['stderr_sha256']):
        raise ValueError('source child streams differ from actual execution')
    terminal = json.loads(stdout)
    if set(terminal) != {'report', 'count'}:
        raise ValueError('source child terminal shape differs')
    output = parent / mode
    planned = cases[mode] if mode == 'scope' else [row['id'] for row in cases[mode]]
    start = capture.parse(parent / (mode + '.start.json'))
    command = [str(execution['command'][0]), '-I', '-B',
               str(ROOT / 'tests/hia_worker_unknown_controls.py'),
               '--mode', mode, '--output', str(output)]
    if execution['command'] != command or start['command'] != command:
        raise ValueError('source child invocation differs')
    if any(start[key] != execution[key] for key in
           ('cwd', 'pid', 'pgid', 'started_time_ns', 'timeout_seconds', 'cleanup_seconds')):
        raise ValueError('source child launch and terminal differ')
    plan = capture.parse(output / 'planned.json')
    report_raw = capture.take(output / 'report.json', terminal['report'])
    report = json.loads(report_raw)
    if (report['schema'] != 'hepta.hia.worker-unknown-source-controls.v1'
            or report['status'] != 'PASS' or report['mode'] != mode
            or report['planned'] != planned or report['started'] != planned
            or report['stopped'] != planned or report['failures'] != []
            or report['source_before'] != sources or report['source_after'] != sources
            or report['actual_native_entries'] != 0
            or report['source_foreign_outcome_loss_only'] is not True
            or report['whole_native_stack_qualified'] is not False
            or plan != {'mode': mode, 'ordered_ids': planned, 'source': sources}
            or terminal['count'] != len(planned)):
        raise ValueError('source result does not cover the frozen complete inputs')
    observations = capture.parse(output / 'observations.json', report['observations'])
    if [row['id'] for row in observations] != planned:
        raise ValueError('source observation inventory differs')
    if any(row['control_status'] != 'PASS' for row in observations):
        raise ValueError('source control contains a failure')
    events = [json.loads(line) for line in capture.take(output / 'events.jsonl').splitlines()]
    expected_events = []
    for identifier in planned:
        expected_events += [{'event': 'started', 'id': identifier},
                            {'event': 'stopped', 'id': identifier, 'status': 'PASS'}]
    if events != expected_events:
        raise ValueError('actual per-case source completion journal differs')
    if mode == 'ordinary':
        for row in observations:
            if (row['original'] != row['candidate'] or row['byte_equal'] is not True
                    or row['candidate']['diagnostics'] != []):
                raise ValueError('ordinary worker original comparison differs')
    elif mode == 'unknown':
        for definition, row in zip(cases['unknown'], observations):
            actual = row['candidate']
            if row['expected_unknown'] != definition['expected_unknown']:
                raise ValueError('terminal fact classification differs')
            if (actual['close_attempts'], actual['close_effects']) != tuple(definition['close']):
                raise ValueError('actual original close attempt/effect differs')
            if definition['expected_unknown']:
                if actual['outcome'] != {'kind': 'return', 'value': 2} or actual['stdout_hex']:
                    raise ValueError('actual unknown emitted an ordinary terminal')
                diagnostic, = actual['diagnostics']
                if not all(diagnostic[key] for key in
                           ('origin_is_actual', 'primary_is_actual', 'cleanup_is_actual')):
                    raise ValueError('unknown lost its real exception/origin identities')
                if (actual['retained_actual_losses'] <= 0
                        or 'HIA_WORKER_DELIVERY_UNKNOWN' not in actual['stderr']):
                    raise ValueError('unknown lost retained custody or diagnostic')
            elif row['original'] != actual:
                raise ValueError('an unrelated or ordinary error became unknown')
    capture.stable()
    return {'schema': 'hepta.hia.worker-unknown-source-readback.v1',
            'status': 'PASS', 'mode': mode, 'count': len(planned),
            'producer_report': {'path': str(output / 'report.json'),
                                **pin(report_raw)},
            'files': capture.ledger(), 'whole_native_stack_qualified': False}


def _stream_pin(path):
    total, digest = 0, sha256()
    with Path(path).open('rb') as stream:
        for raw in iter(lambda: stream.read(1024 * 1024), b''):
            total += len(raw)
            digest.update(raw)
    return {'bytes': total, 'sha256': digest.hexdigest()}


def _wheel(capture, report):
    wheel = Path(report['wheel'])
    initial = _stream_pin(wheel)
    if initial['sha256'] != report['wheel_sha256']:
        raise ValueError('actual wheel bytes differ')
    capture.streams[str(wheel)] = dict(initial)
    installed = Path(report['installed'])
    expected_files = report['wheel_files_checked_against_installed']
    with zipfile.ZipFile(wheel) as archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        if len(names) != len(set(names)):
            raise ValueError('duplicate wheel member')
        records = [name for name in names if name.endswith('.dist-info/RECORD')]
        record_name, = records
        record_raw = archive.read(record_name)
        if sha256(record_raw).hexdigest() != report['wheel_RECORD_sha256']:
            raise ValueError('wheel RECORD differs')
        recorded = list(csv.reader(io.StringIO(record_raw.decode('utf-8'))))
        if {row[0] for row in recorded} != set(names):
            raise ValueError('wheel member inventory differs from RECORD')
        if len(recorded) != len(names) or set(expected_files) != set(names) - {record_name}:
            raise ValueError('installed wheel report omitted or duplicated a file')
        for name, digest, size in recorded:
            path = Path(name)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('wheel member path escapes')
            info = archive.getinfo(name)
            if stat.S_ISLNK(info.external_attr >> 16):
                raise ValueError('wheel member is a symbolic link')
            raw = archive.read(name)
            if name != record_name:
                expected = 'sha256=' + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode()
                if digest != expected or size != str(len(raw)):
                    raise ValueError('wheel RECORD digest/extent differs')
                if sha256(raw).hexdigest() != expected_files[name]:
                    raise ValueError('wheel bytes differ from producer file inventory')
                # Stream, do not retain the entire installed wheel in memory.
                capture.take_stream(installed / name, pin(raw))
    installed_record = capture.take(installed / record_name)
    if sha256(installed_record).hexdigest() != report['installed_RECORD_sha256']:
        raise ValueError('installed RECORD differs')
    return {'path': str(wheel), **initial, 'members': len(names)}


def _tag(stderr, prefix):
    rows = [line[len(prefix):] for line in stderr.splitlines() if line.startswith(prefix)]
    if len(rows) != 1:
        raise ValueError('installed child evidence marker differs')
    return json.loads(rows[0])


def read_installed(output, expected_receipt, profile):
    output = Path(output)
    capture = Capture()
    originals, cases, sources = fixture(capture)
    receipt = capture.parse(output / 'completion-receipt.json', expected_receipt)
    if receipt['profile'] != profile:
        raise ValueError('installed worker profile differs')
    raw = capture.take(output / 'installed.json', receipt['installed_report'])
    report = json.loads(raw)
    schema = ('hepta.hia.service-verification-installed-worker.v1' if profile == 'v1'
              else 'hepta.hia.worker-unknown-installed-v2.v1' if profile == 'v2' else None)
    if report['schema'] != schema or schema is None:
        raise ValueError('installed producer schema differs')
    if (report['whole_native_stack_qualified'] is not False
            or report['runtime_authoring_imports_forbidden'] is not True
            or report['every_request_has_all_three_expected_identity_flags'] is not True):
        raise ValueError('installed scope/identity obligation missing')
    labels = ['wheel', 'install', 'identity', 'normal', 'completed-replay',
              'lost-receipt', 'unknown-replay']
    if profile == 'v2':
        labels += ['lost-swallowed', 'lost-replaced']
        if (report['explicit_worker_profile'] != 'v2'
                or report['hosted_worker_policy_poisoned'] is not True
                or report['original_workload_sha256'] != 'b882d10dabf2a99a9590cdb3189bf5eb5be46f1bfe9b4b9c7f444093fc3e9fd4'):
            raise ValueError('explicit v2 original workload scope differs')
    labels += ['source-drift']
    if len(report['commands']) != len(labels):
        raise ValueError('installed command inventory differs')
    streams = {}
    for label, command in zip(labels, report['commands']):
        code = 2 if label in ('lost-receipt', 'lost-swallowed', 'lost-replaced', 'source-drift') else 0
        completed(command, code, 60)
        stored = capture.parse(output / (label + '.result.json'))
        if stored != command:
            raise ValueError('installed command summary differs from raw result')
        start = capture.parse(output / (label + '.start.json'))
        if any(start[key] != command[key] for key in
               ('command', 'cwd', 'pid', 'pgid', 'started_time_ns', 'timeout_seconds', 'cleanup_seconds')):
            raise ValueError('installed command launch differs')
        out = capture.take(output / (label + '.stdout.log'))
        err = capture.take(output / (label + '.stderr.log'))
        if (sha256(out).hexdigest() != command['stdout_sha256']
                or sha256(err).hexdigest() != command['stderr_sha256']):
            raise ValueError('installed command raw streams differ')
        if label not in ('wheel', 'install'):
            counts = _tag(err, b'VERIFICATION_COUNTS=')
            if profile == 'v2':
                terminal = _tag(err, b'WORKER_UNKNOWN_COUNTS=')
                if any(row[1] not in (0, 1) or row[2] not in (0, 1)
                       or row[1] and row[2] for row in terminal['regions']):
                    raise ValueError('actual HIA call/close regions are not exclusive')
                if label in ('identity', 'normal', 'completed-replay', 'lost-receipt',
                             'unknown-replay', 'lost-swallowed', 'lost-replaced'):
                    if terminal['native_worker_entries'] <= 0:
                        raise ValueError('explicit v2 did not execute the native worker')
                if label in ('lost-receipt', 'lost-swallowed', 'lost-replaced'):
                    if (terminal['close_attempts'], terminal['close_body_entries']) != (1, 0):
                        raise ValueError('unknown close was skipped, repeated, or pretended complete')
                    diagnostic, = terminal['diagnostics']
                    if not all(diagnostic[key] for key in
                               ('primary_same', 'cleanup_same', 'actual_origin_error_same', 'origin_lost')):
                        raise ValueError('installed primary/cleanup/origin evidence differs')
                    if ([9, 1, 0, 1] not in terminal['regions']
                            or [8, 0, 1, 1] not in terminal['regions']):
                        raise ValueError('actual HIA call/close exception packets missing')
            if label in ('lost-receipt', 'lost-swallowed', 'lost-replaced'):
                if out or counts['lost'] != [True] or counts['counts']['request'].get('3', 0) <= 0:
                    raise ValueError('installed lost receipt was not real or emitted stdout')
                if b'HIA_WORKER_DELIVERY_UNKNOWN' not in err:
                    raise ValueError('installed unknown diagnostic missing')
            if label == 'source-drift' and (out or counts['counts']['request'] != {}):
                raise ValueError('source drift reached actual request effects')
        streams[label] = (out, err)
    identity = json.loads(streams['identity'][0])
    if identity != report['identity'] or set(identity) != {'worker_sha256','backend_sha256','catalog_sha256','native_helpers_sha256'}:
        raise ValueError('actual installed identity differs')
    bundle_raw = capture.take(output / 'bundle.json')
    if sha256(bundle_raw).hexdigest() != report['bundle_sha256'] or identity['native_helpers_sha256'] != report['bundle_sha256']:
        raise ValueError('administrator bundle identity differs')
    for label, command in zip(labels, report['commands']):
        if label in ('wheel', 'install', 'identity'):
            continue
        argv = command['command']
        for field in ('worker', 'backend', 'catalog'):
            flag = '--expected-' + field + '-sha256'
            if argv.count(flag) != 1 or argv[argv.index(flag) + 1] != identity[field + '_sha256']:
                raise ValueError('actual request lacks exact installed source authority')
        flag = '--expected-native-helpers-sha256'
        if argv.count(flag) != 1 or argv[argv.index(flag)+1] != report['bundle_sha256']:
            raise ValueError('actual request bundle pin differs')
    observed = report['observations']
    normal = json.loads(streams['normal'][0])
    replay = json.loads(streams['completed-replay'][0])
    unknown = json.loads(streams['unknown-replay'][0])
    if (normal != observed['normal'] or replay != observed['replay'] or unknown != observed['unknown']
            or any(value.get('complete') is not True for value in (normal, replay, unknown))
            or normal['response']['status'] != 'completed'
            or replay['response'] != normal['response']
            or unknown['response']['error']['code'] != 'E_HIA_REQUEST_UNKNOWN'):
        raise ValueError('original normal/replay/unknown public results differ')
    for key, label in (('normal_counts','normal'),('replay_counts','completed-replay'),
                       ('lost_counts','lost-receipt'),('unknown_counts','unknown-replay')):
        if observed[key] != _tag(streams[label][1], b'VERIFICATION_COUNTS='):
            raise ValueError('producer replaced actual entry counts')
    if (observed['normal_state'] != observed['replay_state']
            or observed['lost_state']['request'] != ['running']
            or observed['unknown_state']['request'] != observed['lost_state']['request']
            or observed['unknown_state']['artifacts'] != observed['lost_state']['artifacts']
            or observed['unknown_state']['costs'] != observed['lost_state']['costs'] + 1
            or observed['replay_counts']['counts']['request'].get('3',0) != 0
            or observed['unknown_counts']['counts']['request'].get('3',0) != 0):
        raise ValueError('actual original durable/replay evidence differs')
    if profile == 'v2':
        request_labels = labels[3:]
        if set(report['request_inputs']) != set(request_labels):
            raise ValueError('v2 actual request-byte inventory differs')
        requests = {}
        for label in request_labels:
            request_raw = capture.take(output/(label+'.stdin.bin'), report['request_inputs'][label])
            request = json.loads(request_raw)
            if (set(request) != {'schema','tool','arguments','profile_sha256','catalog_sha256','request_sha256'}
                    or request['schema'] != 'hia-agent-worker-request-v1'
                    or request['tool'] != 'hia_verify' or request['catalog_sha256'] != identity['catalog_sha256']):
                raise ValueError('actual v2 request fields differ')
            body = {key:value for key,value in request.items() if key != 'request_sha256'}
            wire = json.dumps(body,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')
            if sha256(wire).hexdigest() != request['request_sha256']:
                raise ValueError('actual v2 request digest differs')
            requests[label] = request_raw
        if (requests['normal'] != requests['completed-replay']
                or requests['lost-receipt'] != requests['unknown-replay']
                or requests['normal'] != requests['source-drift']):
            raise ValueError('original v2 normal/lost replay request bytes changed')
        for key, label in (('identity_terminal','identity'),('normal_terminal','normal'),
                           ('lost_terminal','lost-receipt')):
            if observed[key] != _tag(streams[label][1], b'WORKER_UNKNOWN_COUNTS='):
                raise ValueError('producer terminal evidence differs from actual stderr')
        extra = observed['additional_actual_losses']
        if [row['mode'] for row in extra] != ['lost-swallowed','lost-replaced']:
            raise ValueError('additional loss inventory differs')
        for row in extra:
            if (row['terminal'] != _tag(streams[row['mode']][1], b'WORKER_UNKNOWN_COUNTS=')
                    or row['counts'] != _tag(streams[row['mode']][1], b'VERIFICATION_COUNTS=')
                    or row['state']['request'] != ['running']):
                raise ValueError('additional actual loss evidence differs')
        for path, digest in report['additional_manifests'].items():
            if sha256(capture.take(path)).hexdigest() != digest:
                raise ValueError('explicit native companion manifest changed')
    wheel = _wheel(capture, report)
    capture.stable()
    return {'schema':'hepta.hia.worker-unknown-installed-readback.v1','status':'PASS',
            'profile':profile,'commands':labels,'producer_report':{'path':str(output/'installed.json'),**pin(raw)},
            'wheel':wheel,'files':capture.ledger(),'whole_native_stack_qualified':False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('ordinary','unknown','scope','v1','v2'), required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--expected-receipt-bytes', type=int, required=True)
    parser.add_argument('--expected-receipt-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    expected = {'bytes':args.expected_receipt_bytes,'sha256':args.expected_receipt_sha256}
    result = (read_installed(args.evidence,expected,args.mode) if args.mode in ('v1','v2')
              else read_source(args.evidence,args.mode,expected))
    with args.output.open('xb') as stream:
        stream.write(canonical(result)+b'\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
