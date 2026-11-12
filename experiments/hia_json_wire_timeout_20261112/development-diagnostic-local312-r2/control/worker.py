"""One original caller with bounded in-memory timing; never a wire89 gate."""
from __future__ import annotations

from collections import Counter
from contextlib import ExitStack
from functools import wraps
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
REQUEST = json.loads((ROOT / 'REQUEST.json').read_bytes())
SOURCE = Path(REQUEST['source_root'])
OUT = Path(REQUEST['output_root'])
TEST_ID = REQUEST['test_id']
RAW_CAP = REQUEST['diagnostic_raw_bytes_limit']


def create(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('xb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def main():
    if tuple(sys.version_info[:3]) != (3, 12, 14):
        raise RuntimeError('this diagnostic is pinned to local CPython 3.12.14')
    sys.path.insert(0, str(SOURCE))
    from hepta import hia_agent_service as service, hia_agent_runner as runner
    from hepta import hia_agent_store as store, hia_json_wire_native as wire
    from hepta import hia_program_tools as program_tools
    from tools import hia_agent_native_qualification as client
    from tests import test_hia_agent_native_tools as original_tests

    expected_image = REQUEST['wire_image_sha256']
    phase = ['outside-test']
    clock_stack = []
    metrics, counts = {}, Counter()
    process_records, processes, raw_events, batches, evaluation_results = [], [], [], [], []
    recording_errors, retained_entries, encoder_entries = [], [], []
    recording_failed = [False]
    preserved = []
    raw_total = [0]
    active_cases = []
    original_observer = dict(wire._BUILTIN_OBSERVER_METHODS)
    original_functions = {n: getattr(wire.ForeignGraphObserver, n) for n in original_observer}

    def record_error(where, error):
        recording_failed[0] = True
        try:
            recording_errors.append({'where': where, 'type': type(error).__name__})
        except BaseException:
            pass

    def timed(name, fn, *, phase_name=None):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            old = phase[0]
            item = None
            outcome = 'returned'
            try:
                if phase_name is not None:
                    phase[0] = phase_name
                started = time.monotonic_ns()
                candidate = [started, 0]
                clock_stack.append(candidate)
                item = candidate
            except BaseException as error:
                record_error('timer-begin', error)
            try:
                return fn(*args, **kwargs)
            except BaseException:
                outcome = 'raised'
                raise
            finally:
                try:
                    if item is not None:
                        elapsed = time.monotonic_ns() - item[0]
                        if clock_stack.pop() is not item:
                            raise RuntimeError('diagnostic timing stack changed')
                        if clock_stack:
                            clock_stack[-1][1] += elapsed
                        row = metrics.setdefault(phase[0] + '/' + name, Counter())
                        row['calls'] += 1
                        row[outcome] += 1
                        row['inclusive_ns'] += elapsed
                        row['exclusive_instrumented_ns'] += elapsed - item[1]
                except BaseException as error:
                    record_error('timer-end', error)
                finally:
                    phase[0] = old
        return wrapped

    def forbid_owner(*args, **kwargs):
        try:
            retained_entries.append(phase[0])
        except BaseException as error:
            record_error('retained-owner-guard', error)
        raise AssertionError('retained bounded-wire decision owner entered')

    def forbid_encoder(*args, **kwargs):
        try:
            encoder_entries.append(phase[0])
        except BaseException as error:
            record_error('encoder-guard', error)
        raise AssertionError('host JSON encoder entered selected native wire')

    original_encode = wire.NativeJsonWire.encode_ordinary
    def encode(owner, *values, **options):
        if owner.image_sha256 != expected_image:
            raise AssertionError('ordinary wire selected a different executable')
        try:
            counts[phase[0] + '/ordinary_wire_calls'] += 1
        except BaseException as error:
            record_error('ordinary-wire-count', error)
        with patch.object(json.JSONEncoder, 'iterencode', forbid_encoder):
            return original_encode(owner, *values, **options)

    original_step = wire.WireSession.step
    def step(session, packet=None):
        result = original_step(session, packet)
        # No clock or I/O in the primitive loop. Count only real normal returns.
        try:
            counts[phase[0] + '/native_step_status_' + str(result)] += 1
        except BaseException as error:
            record_error('native-step-count', error)
        return result

    original_session_init = wire.WireSession.__init__
    def session_init(session, *args, **kwargs):
        result = original_session_init(session, *args, **kwargs)
        try:
            counts[phase[0] + '/actual_key_cache_' + str(session.key_cache)] += 1
        except BaseException as error:
            record_error('key-cache-count', error)
        return result

    original_batch = runner.run_native_batch
    def batch(artifact_bytes, signatures, cases, **kwargs):
        row = None
        call = original_batch
        try:
            row = {'phase': phase[0], 'mode': kwargs.get('_mode', 'native'),
                   'artifact': artifact_bytes, 'signatures': signatures, 'cases': cases,
                   'options': dict(kwargs), 'result': None, 'exception': None}
            batches.append(row)
            call = timed('runner/' + row['mode'], original_batch)
        except BaseException as error:
            record_error('batch-begin', error)
        try:
            result = call(artifact_bytes, signatures, cases, **kwargs)
        except BaseException as error:
            try:
                if row is not None:
                    row['exception'] = type(error).__name__
            except BaseException as recording_error:
                record_error('batch-exception', recording_error)
            raise
        try:
            if row is not None:
                row['result'] = result
        except BaseException as error:
            record_error('batch-return', error)
        return result

    original_popen_init = subprocess.Popen.__init__
    def popen_init(proc, *args, **kwargs):
        row = None
        try:
            row = {'index': len(process_records), 'phase': phase[0], 'argv': args[0] if args else kwargs.get('args'),
                   'cwd': str(kwargs.get('cwd') or os.getcwd()),
                   'env': dict(os.environ if kwargs.get('env') is None else kwargs['env']),
                   'start_new_session': kwargs.get('start_new_session', False), 'pid': None, 'exception': None}
            process_records.append(row)
        except BaseException as error:
            record_error('popen-begin', error)
        try:
            result = original_popen_init(proc, *args, **kwargs)
        except BaseException as error:
            try:
                if row is not None:
                    row['exception'] = type(error).__name__
            except BaseException as recording_error:
                record_error('popen-exception', recording_error)
            raise
        try:
            if row is not None:
                row['pid'] = proc.pid
                processes.append((proc, row))
        except BaseException as error:
            record_error('popen-return', error)
        return result

    original_communicate = subprocess.Popen.communicate
    def communicate(proc, input=None, timeout=None):
        item = None
        call = original_communicate
        try:
            item = {'index': len(raw_events), 'phase': phase[0], 'pid': proc.pid, 'timeout': timeout,
                    'input': input, 'stdout': None, 'stderr': None, 'returncode': None, 'exception': None}
            raw_events.append(item)
            call = timed('process_communicate', original_communicate)
        except BaseException as error:
            record_error('communicate-begin', error)
        try:
            result = call(proc, input=input, timeout=timeout)
        except BaseException as error:
            try:
                if item is not None:
                    item['exception'] = type(error).__name__
                    if isinstance(error, subprocess.TimeoutExpired):
                        item.update(stdout=error.output, stderr=error.stderr)
                    item['returncode'] = proc.returncode
            except BaseException as recording_error:
                record_error('communicate-exception', recording_error)
            raise
        try:
            if item is not None:
                stdout, stderr = result
                item.update(stdout=stdout, stderr=stderr, returncode=proc.returncode)
        except BaseException as error:
            record_error('communicate-return', error)
        return result

    original_evaluate = client.Session.evaluate
    def evaluate(*args, **kwargs):
        result = original_evaluate(*args, **kwargs)
        try:
            evaluation_results.append(result)
        except BaseException as error:
            record_error('evaluate-return', error)
        return result

    def retain(name, raw):
        if type(raw) is not bytes:
            raise TypeError('diagnostic raw output must be bytes')
        if raw_total[0] + len(raw) > RAW_CAP:
            raise RuntimeError('diagnostic raw preservation cap reached; no truncation')
        create(OUT / name, raw)
        raw_total[0] += len(raw)
        preserved.append({'path': name, 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()})

    original_teardown = original_tests.AgentToolCase.tearDown
    def teardown(case):
        # This runs after the original method's 5s assertion, before its unchanged cleanup.
        try:
            retain('client-records.json', encoded(case.client.records))
            artifact_dir = case.state_root / 'artifacts'
            for path in sorted(artifact_dir.iterdir()):
                before = path.lstat()
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid()
                        or len(path.name) != 64 or any(c not in '0123456789abcdef' for c in path.name)):
                    raise RuntimeError('unexpected owned test artifact')
                raw = path.read_bytes()
                after = path.lstat()
                fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                if (any(getattr(before, key) != getattr(after, key) for key in fields)
                        or sha256(raw).hexdigest() != path.name):
                    raise RuntimeError('test artifact changed during diagnostic read')
                retain('test-artifacts/' + path.name, raw)
        except BaseException as error:
            record_error('retain-before-original-teardown', error)
        return original_teardown(case)

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            try:
                active_cases.append(test.id())
            except BaseException as error:
                record_error('test-start-record', error)
            super().startTest(test)

    test = original_tests.NativeLifecycleTests(TEST_ID.rsplit('.', 1)[1])
    if test.id() != TEST_ID:
        raise RuntimeError('original test ID changed')
    with ExitStack() as stack:
        patches = [
            (program_tools, '_reference_bounded_json_wire', forbid_owner),
            (wire.NativeJsonWire, 'encode_ordinary', timed('encode_ordinary', encode)),
            (wire.WireSession, 'step', step),
            (wire.WireSession, '__init__', timed('wire_session_init', session_init)),
            (wire, '_installed_json_image', timed('wire_source_admission', wire._installed_json_image)),
            (original_tests.AgentToolCase, 'setUp', timed('test_setup', original_tests.AgentToolCase.setUp, phase_name='setup')),
            (original_tests.AgentToolCase, 'build_pair', timed('build_pair', original_tests.AgentToolCase.build_pair, phase_name='build_pair')),
            (original_tests.AgentToolCase, 'tearDown', timed('test_teardown', teardown, phase_name='teardown')),
            (client.Session, 'evaluate', timed('Session.evaluate', evaluate, phase_name='evaluate')),
            (runner, 'run_native_batch', batch),
            (subprocess.Popen, '__init__', popen_init),
            (subprocess.Popen, 'communicate', communicate),
        ]
        for name in ('_hia_evaluate', '_context', '_native', '_build_receipt', '_required_claims'):
            patches.append((service.HIAAgentService, name, timed(name, getattr(service.HIAAgentService, name))))
        original_store_json = store.AgentStore.json
        def store_json(owner, value, kind, metadata=None):
            call = original_store_json
            try:
                call = timed('store_json/' + str(kind), original_store_json)
            except BaseException as error:
                record_error('store-json-begin', error)
            return call(owner, value, kind, metadata)
        patches.append((store.AgentStore, 'json', store_json))
        for obj, name, replacement in patches:
            stack.enter_context(patch.object(obj, name, replacement))
        with (OUT / 'unittest.stderr.log').open('x') as log:
            result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=Result).run(unittest.TestSuite([test]))

    for proc, row in processes:
        try:
            row['final_returncode_observed'] = proc.returncode
        except BaseException as error:
            record_error('popen-final-observation', error)
    try:
        for row in raw_events:
            for field in ('input', 'stdout', 'stderr'):
                value = row[field]
                if value is None:
                    continue
                raw = value.encode('utf-8') if type(value) is str else value
                path = f"process-io/{row['index']:03d}.{field}.{'utf8' if type(value) is str else 'bin'}"
                retain(path, raw)
                row[field] = {'path': path, 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(), 'original_type': type(value).__name__}
        for i, row in enumerate(batches):
            body = row.pop('artifact')
            retain(f'batches/{i:03d}.artifact.bin', body)
            row['artifact'] = {'bytes': len(body), 'sha256': sha256(body).hexdigest()}
            retain(f'batches/{i:03d}.json', encoded(row))
        retain('evaluation-results.json', encoded(evaluation_results))
        retain('processes.json', encoded(process_records))
        retain('process-communications.json', encoded(raw_events))
    except BaseException as error:
        record_error('retain-complete-diagnostic', error)
    observer_stable = all(getattr(wire.ForeignGraphObserver, name) is value for name, value in original_functions.items())
    test_ok = result.wasSuccessful() and result.testsRun == 1 and active_cases == [TEST_ID] and not any((
        result.failures, result.errors, result.skipped, result.expectedFailures, result.unexpectedSuccesses))
    report = {'schema': 'hepta.wire89.original-timeout-development-diagnostic.v1',
        'status': 'DIAGNOSTIC_TEST_PASS' if test_ok and not recording_failed[0] else 'DIAGNOSTIC_FAIL_OR_INCOMPLETE',
        'original_test_id': TEST_ID, 'tests_run': result.testsRun, 'executed_ids': active_cases,
        'failures': [{'id': t.id(), 'trace': trace} for t, trace in result.failures],
        'errors': [{'id': t.id(), 'trace': trace} for t, trace in result.errors],
        'skipped': [(t.id(), why) for t, why in result.skipped],
        'expected_failures': [(t.id(), trace) for t, trace in result.expectedFailures],
        'unexpected_successes': [t.id() for t in result.unexpectedSuccesses],
        'metrics': {name: dict(value) for name, value in metrics.items()}, 'counts': dict(counts),
        'observer_binding_unchanged': observer_stable, 'recording_errors': recording_errors,
        'recording_failed': recording_failed[0],
        'retained_owner_entries': retained_entries, 'host_encoder_entries': encoder_entries,
        'processes': process_records, 'raw_originals': preserved, 'raw_bytes': raw_total[0],
        'wire_image_sha256': expected_image, 'python': sys.version,
        'original_5s_assertion_unchanged': True, 'workload_cases_from_frozen_source': 256,
        'instrumentation_cost_included_in_5s': True, 'per_primitive_clock_or_IO': False,
        'full_wire89_qualification_claimed': False, 'historical_3_14_4_failure_reproduced_claimed': False,
        'fresh_cold_or_compiler_claimed': False, 'new_selfhost_B3_invocation': False,
        'original_test_codegen_preserved': True}
    create(OUT / 'diagnostic-report.json', encoded(report))
    return 0 if test_ok and observer_stable and not (recording_failed[0] or retained_entries or encoder_entries) else 1


if __name__ == '__main__':
    raise SystemExit(main())
