"""Owned original-first qualification for the separate 16 temporary inputs."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / 'tests/fixtures/hia_service_inspection_public_lifetime_v1'
FREEZE = DIRECTORY / 'source-identity.json'
OBSERVER = ROOT / 'tests/hia_service_inspection_public_lifetime_observer.py'
ORIGINAL_SECONDS = 600
NATIVE_SECONDS = 1800
CLEANUP_SECONDS = 3


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def put(path, value):
    with Path(path).open('xb') as stream:
        stream.write(encoded(value))


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def clean_environment():
    return {k: v for k, v in os.environ.items()
            if not k.startswith(('HEPTA_HIA_', 'PYTHON'))}


def group_exists(pid):
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return False
    return True


def child(root, label, backend, freeze_sha, *, expected=None, expected_sha=None, manifest=None):
    control = root / (label + '-control')
    control.mkdir(mode=0o700)
    destination = root / label
    command = [sys.executable, '-I', '-B', str(OBSERVER),
        '--backend', backend, '--source-freeze-sha256', freeze_sha,
        '--output', str(destination)]
    if expected is not None:
        command += ['--expected', str(expected), '--expected-sha256', expected_sha]
    if manifest is not None:
        command += ['--manifest', str(manifest)]
    seconds = NATIVE_SECONDS if backend == 'native' else ORIGINAL_SECONDS
    started_ns, started_clock = time.time_ns(), time.monotonic()
    process = None
    stdout = stderr = b''
    problem = None
    cleanup = []
    signals = []
    timed_out = False
    try:
        process = subprocess.Popen(command, cwd=ROOT, env=clean_environment(),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True)
        put(control / 'command.json', {'command': command, 'cwd': str(ROOT),
            'pid': process.pid, 'pgid': process.pid, 'parent_pid': os.getpid(),
            'started_time_ns': started_ns, 'timeout_seconds': seconds,
            'cleanup_seconds': CLEANUP_SECONDS})
        stdout, stderr = process.communicate(timeout=seconds)
    except BaseException as error:
        timed_out = isinstance(error, subprocess.TimeoutExpired)
        problem = {'class': type(error).__name__, 'message': str(error)}
    finally:
        if process is not None:
            try:
                if process.poll() is None or group_exists(process.pid):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                        signals.append('SIGKILL')
                    except ProcessLookupError:
                        pass
                # Always bounded, including post-launch bookkeeping failure.
                stdout, stderr = process.communicate(timeout=CLEANUP_SECONDS)
            except BaseException as error:
                if isinstance(error, subprocess.TimeoutExpired):
                    if error.output is not None:
                        stdout = error.output
                    if error.stderr is not None:
                        stderr = error.stderr
                cleanup.append({'class': type(error).__name__, 'message': str(error)})
        gone = process is not None and not group_exists(process.pid)
        code = None if process is None else process.poll()
        (control / 'stdout.log').write_bytes(stdout)
        (control / 'stderr.log').write_bytes(stderr)
        inner_raw = (destination / 'report.json').read_bytes() if (destination / 'report.json').is_file() else None
        inner = None if inner_raw is None else json.loads(inner_raw)
        good = (problem is None and not cleanup and not timed_out and not signals
                and code == 0 and gone and inner is not None and inner['status'] == 'PASS'
                and inner['backend'] == backend and inner['pid'] == process.pid
                and inner['pgid'] == process.pid and inner['parent_pid'] == os.getpid()
                and inner['argv'] == command[3:] and inner['cwd'] == str(ROOT)
                and inner['planned'] == inner['started'] == inner['stopped'])
        record = {'schema': 'hepta.hia.service-inspection-public-lifetime-process.v1',
            'status': 'PASS' if good else 'HOLD', 'backend': backend, 'command': command,
            'pid': None if process is None else process.pid, 'returncode': code,
            'owned_group_absent': gone, 'reaped': code is not None,
            'timeout': timed_out, 'signals': signals, 'supervisor_error': problem,
            'cleanup_errors': cleanup, 'timeout_seconds': seconds, 'cleanup_seconds': CLEANUP_SECONDS,
            'started_time_ns': started_ns, 'finished_time_ns': time.time_ns(),
            'wall_seconds': time.monotonic() - started_clock,
            'stdout_pin': pin(stdout), 'stderr_pin': pin(stderr),
            'inner_report_pin': None if inner_raw is None else pin(inner_raw)}
        if inner_raw is not None and (destination / 'report.json').read_bytes() != inner_raw:
            record['status'] = 'HOLD'
            record['inner_report_changed'] = True
        put(control / 'execution.json', record)
    return record, inner, inner_raw


def admit_sources(wanted):
    raw = FREEZE.read_bytes()
    if sha256(raw).hexdigest() != wanted:
        raise ValueError('supplemental source freeze differs from external pin')
    value = json.loads(raw)
    if value['schema'] != 'hepta.hia.service-inspection-public-lifetime-source.v1' or value['base_count'] != 16:
        raise ValueError('supplemental source scope differs')
    captured = {}
    for name, expected in value['files'].items():
        path = Path(name)
        if path.is_absolute() or '..' in path.parts:
            raise ValueError('source path escapes repository')
        body = (ROOT / name).read_bytes()
        if pin(body) != expected:
            raise ValueError('source bytes differ: ' + name)
        captured[name] = body
    return raw, value, captured


def admit_bundle(path, wanted, source_sha, planned):
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != wanted:
        raise ValueError('original bundle is not the supplied exact pin')
    value = json.loads(raw)
    if (value.get('schema') != 'hepta.hia.service-inspection-public-lifetime-originals.v1'
            or value.get('status') != 'PASS' or value.get('planned') != planned
            or value.get('source_freeze_sha256') != source_sha
            or value.get('two_fresh_original_children_equal') is not True
            or len(value.get('commands', [])) != 2
            or any(v['status'] != 'PASS' for v in value['commands'])):
        raise ValueError('complete original bundle is unavailable')
    files = {}
    for name, expected in value['files'].items():
        item = Path(name)
        if item.is_absolute() or '..' in item.parts:
            raise ValueError('original bundle member escapes')
        body = (path.parent / name).read_bytes()
        if pin(body) != expected:
            raise ValueError('original bundle member changed: ' + name)
        files[name] = body
    if path.read_bytes() != raw:
        raise ValueError('original bundle changed during admission')
    return raw, value, files


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--backend', choices=('originals', 'unselected', 'native'), required=True)
    parser.add_argument('--source-freeze-sha256', required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--original-report', type=Path)
    parser.add_argument('--original-report-sha256')
    parser.add_argument('--manifest', type=Path)
    args = parser.parse_args(argv)
    if args.backend == 'originals':
        if any(v is not None for v in (args.original_report, args.original_report_sha256, args.manifest)):
            raise ValueError('original mode cannot take candidate capability')
    elif args.original_report is None or not args.original_report_sha256:
        raise ValueError('public candidate requires prior complete original bundle')
    if (args.backend == 'native') != (args.manifest is not None):
        raise ValueError('only native mode requires manifest')
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    freeze_raw, freeze, captured = admit_sources(args.source_freeze_sha256)
    cases = json.loads(captured['tests/fixtures/hia_service_inspection_public_lifetime_v1/cases.json'])['cases']
    planned = [c['id'] for c in cases]
    if len(planned) != 16 or len(set(planned)) != 16:
        raise ValueError('fixed supplemental input scope differs')
    if args.backend == 'originals':
        records = []
        reports = []
        raw_reports = []
        for label in ('original-first', 'original-second'):
            record, inner, raw = child(args.evidence, label, 'original', args.source_freeze_sha256)
            records.append(record)
            reports.append(inner)
            raw_reports.append(raw)
        ready = (all(r['status'] == 'PASS' for r in records)
                 and all(r is not None and r['planned'] == planned for r in reports))
        equal = False
        files, observed_files = {}, {}
        for label in ('original-first', 'original-second'):
            for name in ('report.json', 'observations.jsonl', 'raw-tracebacks.jsonl'):
                path = args.evidence / label / name
                if path.is_file():
                    body = path.read_bytes()
                    observed_files[label + '/' + name] = body
                    files[label + '/' + name] = pin(body)
            for name in ('command.json', 'execution.json', 'stdout.log', 'stderr.log'):
                path = args.evidence / (label + '-control') / name
                if path.is_file():
                    body = path.read_bytes()
                    observed_files[label + '-control/' + name] = body
                    files[label + '-control/' + name] = pin(body)
        if ready:
            equal = (reports[0]['runtime'] == reports[1]['runtime']
                and all(observed_files['original-first/' + name] ==
                        observed_files['original-second/' + name]
                        for name in ('observations.jsonl', 'raw-tracebacks.jsonl')))
        stable = (all((args.evidence/n).read_bytes() == b for n,b in observed_files.items())
            and FREEZE.read_bytes() == freeze_raw and all((ROOT/n).read_bytes() == b for n,b in captured.items())
            and all(raw is None or (args.evidence/label/'report.json').read_bytes() == raw
                for label,raw in zip(('original-first','original-second'),raw_reports)))
        report = {'schema': 'hepta.hia.service-inspection-public-lifetime-originals.v1',
            'status': 'PASS' if ready and equal and stable else 'HOLD',
            'source_freeze_sha256': sha256(freeze_raw).hexdigest(),
            'source_pins': freeze['files'], 'source_unchanged': stable,
            'planned': planned, 'commands': records, 'files': files,
            'runtime': None if reports[0] is None else reports[0]['runtime'],
            'two_fresh_original_children_equal': equal,
            'actual_original_invocations': sum(len(r['started']) for r in reports if r is not None),
            'candidate_executed': False, 'old_116_and_9_basis_replaced': False,
            'whole_qualification': False}
    else:
        bundle_raw, bundle, original_files = admit_bundle(
            args.original_report, args.original_report_sha256,
            args.source_freeze_sha256, planned)
        original_path = args.original_report.parent / 'original-first/report.json'
        original_raw = original_files['original-first/report.json']
        put(args.evidence / 'accepted-original-bundle.json', {
            'pin': pin(bundle_raw), 'source_freeze_sha256': args.source_freeze_sha256,
            'planned': planned, 'files': bundle['files'],
            'original_bundle_status': bundle['status'],
            'candidate_child_not_yet_started': True})
        record, inner, inner_raw = child(args.evidence, 'candidate', args.backend,
            args.source_freeze_sha256, expected=original_path,
            expected_sha=sha256(original_raw).hexdigest(), manifest=args.manifest)
        stable = (FREEZE.read_bytes() == freeze_raw
            and all((ROOT/n).read_bytes() == b for n,b in captured.items())
            and args.original_report.read_bytes() == bundle_raw
            and all((args.original_report.parent/n).read_bytes() == b
                    for n,b in original_files.items())
            and (inner_raw is None or
                 (args.evidence/'candidate/report.json').read_bytes() == inner_raw))
        full = (inner is not None and inner['planned'] == planned
            and inner['started'] == inner['stopped'] == planned
            and inner['original_report_pin'] == pin(original_raw)
            and inner['source_freeze_sha256'] == args.source_freeze_sha256)
        report = {'schema': 'hepta.hia.service-inspection-public-lifetime-candidate.v1',
            'status': 'PASS' if record['status'] == 'PASS' and full and stable else 'HOLD',
            'backend': args.backend, 'planned': planned, 'command': record,
            'source_freeze_sha256': args.source_freeze_sha256,
            'source_pins': freeze['files'], 'source_and_originals_unchanged': stable,
            'original_bundle_pin': pin(bundle_raw),
            'candidate_report_pin': None if inner_raw is None else pin(inner_raw),
            'started': [] if inner is None else inner['started'],
            'stopped': [] if inner is None else inner['stopped'],
            'runtime': None if inner is None else inner['runtime'],
            'mismatches': None if inner is None else inner['mismatches'],
            'observer_errors': None if inner is None else inner['observer_errors'],
            'all_16_public_invocations_accounted': full,
            'old_116_and_9_basis_replaced': False, 'whole_qualification': False}
    put(args.evidence / 'report.json', report)
    print(encoded({'status': report['status'], 'backend': args.backend,
                   'report_pin': pin((args.evidence/'report.json').read_bytes())}).decode(), end='')
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
