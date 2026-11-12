"""Finite recorder controls: standard library only, no project or native entry.

The real frozen wrapper definitions are extracted from their AST. Their original
callees are inert sentinels; no subprocess is created by any case.
"""
from __future__ import annotations

import ast
from collections import Counter
from contextlib import ExitStack
from functools import wraps
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / 'control/worker.py'
NAMES = ('record_error', 'timed', 'forbid_owner', 'forbid_encoder', 'encode',
         'step', 'session_init', 'batch', 'popen_init', 'communicate',
         'evaluate', 'store_json')
REQUEST = json.loads((ROOT / 'RECORDING-CONTROLS-REQUEST.json').read_bytes())


class RecordingFailure(BaseException):
    pass


class RefusingAppend(list):
    def append(self, value):
        raise RecordingFailure('synthetic append failure')


class RefusingCount(Counter):
    def __getitem__(self, key):
        raise RecordingFailure('synthetic counter failure')


class RefusingMetrics(dict):
    def setdefault(self, *args):
        raise RecordingFailure('synthetic metric failure')


class RefusingName(type):
    def __getattribute__(cls, name):
        if name == '__name__':
            raise RecordingFailure('synthetic exception-name failure')
        return super().__getattribute__(name)


class OriginalError(Exception, metaclass=RefusingName):
    pass


class PartialTimeout(subprocess.TimeoutExpired):
    def __getattribute__(self, name):
        if name in ('output', 'stderr'):
            raise RecordingFailure('synthetic partial-output observation failure')
        return super().__getattribute__(name)


def namespace():
    raw = WORKER.read_bytes()
    expected = REQUEST['worker']
    if len(raw) != expected['bytes'] or hashlib.sha256(raw).hexdigest() != expected['sha256']:
        raise RuntimeError('frozen diagnostic wrapper bytes differ')
    module = ast.parse(raw, filename=str(WORKER))
    main = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
    functions = {n.name: n for n in ast.walk(main) if isinstance(n, ast.FunctionDef) and n.name in NAMES}
    if set(functions) != set(NAMES):
        raise RuntimeError('wrapper extraction denominator differs')
    result_class = next(n for n in main.body if isinstance(n, ast.ClassDef) and n.name == 'Result')
    fragment = ast.Module(body=[functions[n] for n in NAMES] + [result_class], type_ignores=[])
    env = {'__builtins__': __builtins__, 'Counter': Counter, 'wraps': wraps, 'patch': patch,
           'time': time, 'json': json, 'os': os, 'subprocess': subprocess, 'unittest': unittest,
           'phase': ['outside-test'], 'clock_stack': [], 'metrics': {}, 'counts': Counter(),
           'process_records': [], 'processes': [], 'raw_events': [], 'batches': [],
           'evaluation_results': [], 'recording_errors': [], 'recording_failed': [False],
           'retained_entries': [], 'encoder_entries': [], 'active_cases': [],
           'expected_image': 'frozen-image-sentinel'}
    # Only definitions are evaluated. The project's imports and main body are
    # neither compiled into this fragment nor executed.
    exec(compile(ast.fix_missing_locations(fragment), str(WORKER) + ':recorder-definitions-only', 'exec'), env)
    return env


def original(env, name, *, result=None, error=None):
    calls = []
    def call(*args, **kwargs):
        calls.append((args, kwargs))
        if error is not None:
            raise error
        return result
    env[name] = call
    return calls


class WireDiagnosticRecordingControls(unittest.TestCase):
    def same_exception(self, invoke, expected):
        try:
            invoke()
        except BaseException as caught:
            self.assertIs(caught, expected)
        else:
            self.fail('original exception was swallowed')

    def test_timeout_exception_identity_and_partial_capture_fault(self):
        env = namespace()
        error = PartialTimeout(['inert'], 0.001, output=b'partial', stderr=b'error')
        calls = original(env, 'original_communicate', error=error)
        proc = types.SimpleNamespace(pid=101, returncode=None)
        self.same_exception(lambda: env['communicate'](proc, input=b'input', timeout=0.001), error)
        self.assertEqual(calls, [((proc,), {'input': b'input', 'timeout': 0.001})])
        self.assertTrue(env['recording_failed'][0])
        self.assertEqual(env['recording_errors'][-1]['where'], 'communicate-exception')
        self.assertEqual(env['raw_events'][0]['exception'], 'PartialTimeout')
        # Failed recorder startup also leaves the same original timeout active.
        env = namespace(); env['raw_events'] = RefusingAppend()
        error = subprocess.TimeoutExpired(['inert'], 7, output=b'x', stderr=b'y')
        calls = original(env, 'original_communicate', error=error)
        self.same_exception(lambda: env['communicate'](proc, input=b'in', timeout=7), error)
        self.assertEqual(len(calls), 1)
        self.assertTrue(env['recording_failed'][0])

    def test_popen_and_batch_exception_identity(self):
        for wrapper, callee, arguments, options, where in (
            ('popen_init', 'original_popen_init', (types.SimpleNamespace(pid=12), ['inert']),
             {'env': {'FIXTURE': '1'}, 'cwd': '/inert'}, 'popen-exception'),
            ('batch', 'original_batch', (b'artifact', ('signature',), ('case',)),
             {'_mode': 'reference', 'budget_ms': 1}, 'batch-exception')):
            with self.subTest(wrapper=wrapper):
                env = namespace(); error = OriginalError('original sentinel')
                calls = original(env, callee, error=error)
                self.same_exception(lambda: env[wrapper](*arguments, **options), error)
                self.assertEqual(calls, [(arguments, options)])
                self.assertTrue(env['recording_failed'][0])
                self.assertEqual(env['recording_errors'][-1]['where'], where)
        # Even the secondary diagnostic-error list can refuse allocation.
        env = namespace(); env['recording_errors'] = RefusingAppend()
        env['raw_events'] = RefusingAppend()
        error = subprocess.TimeoutExpired(['inert'], 1)
        calls = original(env, 'original_communicate', error=error)
        self.same_exception(lambda: env['communicate'](types.SimpleNamespace(pid=1, returncode=None)), error)
        self.assertEqual(len(calls), 1)
        self.assertTrue(env['recording_failed'][0])

    def test_normal_return_identity_after_observer_failure(self):
        token = object()
        class BrokenCache:
            @property
            def key_cache(self):
                raise RecordingFailure('cache observation')
        class BrokenPid:
            @property
            def pid(self):
                raise RecordingFailure('pid observation')
        class BrokenReturncode:
            pid = 42
            @property
            def returncode(self):
                raise RecordingFailure('returncode observation')
        class BrokenKind:
            def __str__(self):
                raise RecordingFailure('kind label observation')
        cases = (
            ('step', 'original_step', (object(),), {}, 'counts', RefusingCount()),
            ('session_init', 'original_session_init', (BrokenCache(),), {}, None, None),
            ('evaluate', 'original_evaluate', (object(),), {}, 'evaluation_results', RefusingAppend()),
            ('batch', 'original_batch', (b'a', (), ()), {'_mode': 'native'}, 'batches', RefusingAppend()),
            ('popen_init', 'original_popen_init', (BrokenPid(), ['inert']),
             {'env': {'FIXTURE': '1'}, 'cwd': '/inert'}, None, None),
            ('store_json', 'original_store_json', (object(), object(), BrokenKind()), {}, None, None),
            ('encode', 'original_encode', (types.SimpleNamespace(image_sha256='frozen-image-sentinel'), object()),
             {}, 'counts', RefusingCount()))
        for wrapper, callee, arguments, options, target, replacement in cases:
            with self.subTest(wrapper=wrapper):
                env = namespace()
                if target: env[target] = replacement
                calls = original(env, callee, result=token)
                self.assertIs(env[wrapper](*arguments, **options), token)
                self.assertEqual(len(calls), 1)
                self.assertTrue(env['recording_failed'][0])
        env = namespace(); result = (b'whole-out', b'whole-err')
        calls = original(env, 'original_communicate', result=result)
        self.assertIs(env['communicate'](BrokenReturncode(), input=b'input', timeout=3), result)
        self.assertEqual(len(calls), 1)
        self.assertTrue(env['recording_failed'][0])
        env = namespace(); env['active_cases'] = RefusingAppend()
        result = env['Result'](io.StringIO(), True, 0)
        case = unittest.FunctionTestCase(lambda: None)
        result.startTest(case); result.stopTest(case)
        self.assertEqual(result.testsRun, 1)
        self.assertTrue(env['recording_failed'][0])

    def test_timer_failures_never_replace_callee_outcome(self):
        def bad_clock():
            raise RecordingFailure('clock observation')
        for at_start in (True, False):
            for raised in (True, False):
                with self.subTest(at_start=at_start, raised=raised):
                    env = namespace()
                    if at_start: env['time'] = types.SimpleNamespace(monotonic_ns=bad_clock)
                    else: env['metrics'] = RefusingMetrics()
                    token = object(); error = ValueError('original')
                    calls = original(env, 'callee', result=token, error=error if raised else None)
                    invoke = env['timed']('fixture', env['callee'], phase_name='evaluate')
                    if raised: self.same_exception(invoke, error)
                    else: self.assertIs(invoke(), token)
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(env['phase'], ['outside-test'])
                    self.assertTrue(env['recording_failed'][0])

    def test_required_guards_and_successful_recording_are_unchanged(self):
        for name, target, message in (
            ('forbid_owner', 'retained_entries', 'retained bounded-wire decision owner entered'),
            ('forbid_encoder', 'encoder_entries', 'host JSON encoder entered selected native wire')):
            env = namespace(); env[target] = RefusingAppend()
            with self.assertRaises(AssertionError) as caught: env[name]()
            self.assertEqual(str(caught.exception), message)
            self.assertTrue(env['recording_failed'][0])
        env = namespace(); calls = original(env, 'original_encode', result=object())
        with self.assertRaises(AssertionError): env['encode'](types.SimpleNamespace(image_sha256='different'))
        self.assertEqual(calls, [])
        env = namespace(); proc = types.SimpleNamespace(pid=123, returncode=0)
        expected = (b'out', b'err'); calls = original(env, 'original_communicate', result=expected)
        self.assertIs(env['communicate'](proc, input=b'input', timeout=2), expected)
        row = env['raw_events'][0]
        self.assertEqual((row['input'], row['stdout'], row['stderr'], row['returncode'], row['exception']),
                         (b'input', b'out', b'err', 0, None))
        self.assertEqual(calls, [((proc,), {'input': b'input', 'timeout': 2})])
        self.assertFalse(env['recording_failed'][0])
        self.assertEqual(env['clock_stack'], [])
        self.assertEqual(env['metrics']['outside-test/process_communicate']['returned'], 1)


def main():
    output = Path(REQUEST['output_root'])
    output.mkdir(mode=0o700)
    before = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in REQUEST['source_pins']}
    expected = REQUEST['expected_ids']
    actual = []
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            actual.append(test.id())
            super().startTest(test)
    stream = io.StringIO()
    with patch.object(subprocess, 'Popen', side_effect=AssertionError('synthetic controls cannot create processes')):
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(WireDiagnosticRecordingControls)
        result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
    after = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in before}
    report = {'schema': 'hepta.wire89.recorder-synthetic-controls.v1',
        'status': 'PASS' if result.wasSuccessful() and result.testsRun == len(expected) and actual == expected
             and before == after and not any((result.failures, result.errors, result.skipped,
                                              result.expectedFailures, result.unexpectedSuccesses)) else 'HOLD',
        'expected_ids': expected, 'actual_ids': actual, 'tests_run': result.testsRun,
        'failures': [(t.id(), trace) for t, trace in result.failures],
        'errors': [(t.id(), trace) for t, trace in result.errors], 'skipped': [(t.id(), why) for t, why in result.skipped],
        'expected_failures': [(t.id(), trace) for t, trace in result.expectedFailures],
        'unexpected_successes': [t.id() for t in result.unexpectedSuccesses],
        'source_before': before, 'source_after': after, 'project_imported': False,
        'wire_test_executed': False, 'subprocess_created_by_tests': False, 'native_executed': False}
    (output / 'unittest.log').write_text(stream.getvalue())
    (output / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'tests_run': result.testsRun, 'output': str(output)}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
