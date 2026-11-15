"""Original-handler lifetime controls, with an independent VM continuation.

The six observed values have no external strong owner. The observer stores
only weakrefs, primitive events and, in the explicit retention cases, the
caller's requested traceback. All fixture classes are fixed module globals.
No expected release order is obtained from the candidate's storage probe.
"""
from __future__ import annotations

import builtins
import gc
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import traceback
import sys
import unittest
from unittest.mock import patch
import weakref

from hepta import hia_agent_service as api
from hepta import hia_service_artifact_native as native
from hepta.hia_agent_assembly import assemble_program
from tests import hia_service_artifact_oracle as oracle
from tests.hia_service_artifact_observer import original_inputs
from tests.test_hia_service_artifact_native import vm_image

ORIGINAL_SHA256 = 'a1a85bb10bc4a56f1d145372dca122005586108a50f7a07fa13678d9432503d8'
LOCAL_NAMES = ('service', 'arguments', 'source', 'data', 'expected', 'ref')


class _Failure(Exception):
    def __init__(self, state, point):
        super().__init__(point)
        self.point = point
        state.error_ids[point] = id(self)


class _Outer(Exception):
    def __init__(self, state):
        super().__init__('outer')
        state.outer_id = id(self)


class _Observation:
    def __init__(self, failure):
        self.failure, self.phase = failure, 'invoke'
        self.events, self.created, self.refs = [], [], {}
        self.error_ids, self.outer_id = {}, None
        self.snapshots = {}

    def error(self, value):
        if value is None:
            return None
        identity = (id(value) == self.error_ids.get(value.point)
                    if type(value) is _Failure else id(value) == self.outer_id)
        return {'type': type(value).__name__, 'args': list(value.args),
                'is_created_exception': identity}

    def note(self, name, *values):
        self.events.append([name, self.phase, self.error(sys.exception()), *values])

    def alive(self, label):
        self.snapshots[label] = {name: reference() is not None
                                 for name, reference in self.refs.items()}

    def capture(self, path, roots, maximum):
        self.note('capture', path, list(roots), maximum)
        return _Data(self, 'data')

    def digest(self, data):
        self.note('hash', data.name)
        return _Digest(self)

    def stringify(self, value):
        self.note('str', value)
        if self.failure == 'str':
            raise _Failure(self, 'str')
        return str(value)

    def reject(self, code, message):
        raise AssertionError((code, message))

    def namespace(self):
        return {'__builtins__': vars(builtins), 'capture_path': self.capture,
                'sha256': self.digest, 'str': self.stringify, 'reject': self.reject}


class _Local:
    __slots__ = ('state', 'name', '__weakref__')

    def __init__(self, state, name):
        self.state, self.name = state, name
        state.created.append(name)
        state.refs[name] = weakref.ref(self)

    def __del__(self):
        self.state.note(self.name + '.delete')


class _Service(_Local):
    __slots__ = ()

    def _profile(self, ref, kind):
        self.state.note('profile', ref, kind)

    @property
    def artifact_roots(self):
        return ('FAKE_ROOT',)

    @property
    def store(self):
        return _Store(self.state)


class _Arguments(_Local):
    __slots__ = ()

    def __getitem__(self, name):
        if name == 'artifact_profile':
            return 'profile'
        if name == 'source':
            return _Source(self.state, 'source')
        raise KeyError(name)


class _Source(_Local):
    __slots__ = ()

    def __getitem__(self, name):
        if name == 'kind':
            return 'path'
        if name == 'path':
            return 'FAKE_INPUT'
        if name == 'max_bytes':
            return 19
        if name == 'expected_sha256':
            return _Expected(self.state, 'expected')
        raise KeyError(name)


class _Data(_Local):
    __slots__ = ()

    def __len__(self):
        self.state.note('len')
        if self.state.failure == 'len':
            raise _Failure(self.state, 'len')
        return 3


class _Expected(_Local):
    __slots__ = ()

    def __ne__(self, other):
        self.state.note('expected.compare', other)
        return False


class _Digest:
    __slots__ = ('state',)

    def __init__(self, state):
        self.state = state

    def hexdigest(self):
        self.state.note('hexdigest')
        return 'digest'


class _Store:
    __slots__ = ('state',)

    def __init__(self, state):
        self.state = state

    def put(self, data, kind):
        self.state.note('put', data.name, kind)
        return _Local(self.state, 'ref')


def _forbid_mapping(*arguments, **keywords):
    raise AssertionError('local-release Source controls cannot map a native image')


def _forbid_retained(*arguments, **keywords):
    raise AssertionError('VM candidate cannot call the retained artifact handler')


def _candidate_factory(image):
    def factory(namespace):
        def invoke(service, arguments):
            frame = native.ServiceArtifactFrame(image, service, arguments, namespace=namespace)
            # These are harness-forwarder copies, not handler cleanup. Remove
            # them before any provider so only the real frame owns its locals.
            del service, arguments
            return frame.finish()
        return invoke
    return factory


def _invoke(function, state, retained, retain_traceback):
    try:
        # Neither temporary is placed in an observer local or container.
        result = function(_Service(state, 'service'), _Arguments(state, 'arguments'))
    except BaseException as error:
        state.phase = 'caller-exception'
        outcome = {'status': 'raised', 'error': state.error(error),
                   'cause': state.error(error.__cause__),
                   'context': state.error(error.__context__),
                   'suppress_context': error.__suppress_context__}
        state.note('caught')
        state.alive('inside-except')
        if retain_traceback:
            retained.append(error.__traceback__)
    else:
        state.phase = 'after-handler'
        outcome = {'status': 'returned', 'keys': list(result),
                   'artifact_is_issued_reference': result['artifact'] is state.refs['ref'](),
                   'byte_length': result['byte_length'],
                   'content_admitted_as_program': result['content_admitted_as_program'],
                   'execution_authority_granted': result['execution_authority_granted']}
        state.alive('after-handler')
        state.phase = 'return-value-release'
        del result
        state.alive('after-return-value')
    state.phase = 'after-handler'
    state.note('handler-left')
    state.alive('after-handler-exit')
    return outcome


def _observe_six(factory, *, failure=None, outer=False, retain=False, release_inside=False):
    # Drain earlier test garbage before creating this new independent fixture.
    # Collection inside the observed fixture is separately recorded below.
    gc.collect()
    state, retained, unraisable = _Observation(failure), [], []
    function = factory(state.namespace())

    def note_unraisable(record):
        unraisable.append([type(record.exc_value).__name__, record.err_msg])

    def release():
        state.phase = 'traceback-release-inside' if release_inside else 'traceback-release-outside'
        state.note('traceback-release')
        retained.clear()
        state.alive('after-traceback-release')

    with patch.object(sys, 'unraisablehook', note_unraisable):
        if outer:
            try:
                raise _Outer(state)
            except _Outer:
                outcome = _invoke(function, state, retained, retain)
                if retain and release_inside:
                    release()
                state.phase = 'outer-handler'
                state.note('outer-left')
        else:
            outcome = _invoke(function, state, retained, retain)
            if retain and release_inside:
                release()
        if retain and not release_inside:
            release()
        state.phase = 'caller-function-release'
        del function
        state.alive('before-gc')
        state.phase = 'explicit-gc'
        collected = gc.collect()
        state.note('observer.gc', collected)
        state.alive('after-gc')
    # No exception/traceback, callable, result or local value enters the record.
    return json.loads(oracle.canonical({'outcome': outcome, 'created': state.created,
        'trace': state.events, 'snapshots': state.snapshots, 'unraisable': unraisable}))


class ServiceArtifactLocalReleaseSourceTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        raw = (oracle.ROOT / 'artifact.5bf.py.txt').read_bytes()
        if len(raw) != 749 or sha256(raw).hexdigest() != ORIGINAL_SHA256:
            raise AssertionError('independent original 749-byte artifact body changed')

    def check_six(self, record):
        self.assertEqual(record['created'], list(LOCAL_NAMES))
        self.assertEqual(record['unraisable'], [])
        self.assertEqual(record['snapshots']['after-gc'], dict.fromkeys(LOCAL_NAMES, False))
        destroyed = [row[0] for row in record['trace'] if row[0].endswith('.delete')]
        self.assertEqual(sorted(destroyed), sorted(name + '.delete' for name in LOCAL_NAMES))

    def test_01_success_all_six_original_locals_and_active_exception(self):
        expected = {outer: _observe_six(oracle.original_factory, outer=outer) for outer in (False, True)}
        with patch.object(native.NativeServiceArtifact, '__init__', _forbid_mapping), \
                patch.object(api, '_NATIVE_SERVICE_ARTIFACT_REFERENCE', _forbid_retained):
            image = vm_image(assemble_program(native.SOURCE.read_bytes()))
            for outer in (False, True):
                with self.subTest(outer=outer):
                    original = expected[outer]
                    self.check_six(original)
                    self.assertEqual(original['snapshots']['after-handler'],
                                     {name: name == 'ref' for name in LOCAL_NAMES})
                    actual = _observe_six(_candidate_factory(image), outer=outer)
                    self.check_six(actual)
                    self.assertEqual(oracle.canonical(actual), oracle.canonical(original))
            self.assertGreater(image.entry_count, 0)

    def test_02_len_str_failure_traceback_retention_and_final_release(self):
        cases = [dict(failure=point, outer=outer, retain=retain, release_inside=inside)
                 for point in ('len', 'str') for outer in (False, True)
                 for retain, inside in ((False, False), (True, True), (True, False))]
        expected = [_observe_six(oracle.original_factory, **case) for case in cases]
        with patch.object(native.NativeServiceArtifact, '__init__', _forbid_mapping), \
                patch.object(api, '_NATIVE_SERVICE_ARTIFACT_REFERENCE', _forbid_retained):
            image = vm_image(assemble_program(native.SOURCE.read_bytes()))
            for case, original in zip(cases, expected):
                with self.subTest(**case):
                    self.check_six(original)
                    self.assertEqual(original['outcome']['error'], {'type': '_Failure',
                        'args': [case['failure']], 'is_created_exception': True})
                    self.assertEqual(original['snapshots']['inside-except'], dict.fromkeys(LOCAL_NAMES, True))
                    self.assertEqual(original['snapshots']['after-handler-exit'],
                                     dict.fromkeys(LOCAL_NAMES, case['retain']))
                    actual = _observe_six(_candidate_factory(image), **case)
                    self.check_six(actual)
                    self.assertEqual(oracle.canonical(actual), oracle.canonical(original))
            self.assertGreater(image.entry_count, 0)

    def test_03_complete_original_146_same_runtime_before_independent_VM(self):
        root = Path(__file__).resolve().parents[1]
        helper = root / 'tests/hia_service_artifact_local_release_observer.py'
        evidence = os.environ.get('HEPTA_HIA_SERVICE_ARTIFACT_LOCAL_RELEASE_EVIDENCE')
        if evidence == '':
            raise ValueError('local-release evidence must not be empty')
        parent_sources = {name: sha256((root / name).read_bytes()).hexdigest() for name in (
            'tests/test_hia_service_artifact_local_release.py',
            'tests/hia_service_artifact_local_release_observer.py')}
        with tempfile.TemporaryDirectory(prefix='hia-local-release-source-') as temporary:
            base = Path(evidence).absolute() if evidence is not None else Path(temporary) / 'runs'
            base.mkdir(mode=0o700, parents=True, exist_ok=True)
            # Both full-harness Source invocations retain independent outputs.
            # Their owner PID/argv/times, not this random name, bind the stage.
            directory = Path(tempfile.mkdtemp(prefix='invocation-' + str(os.getpid()) + '-', dir=base))
            finite = directory / 'finite'
            command = [sys.executable, '-I', '-B', str(helper), '--output', str(finite)]
            cleared = sorted(name for name in os.environ if name.startswith(('HEPTA_HIA_', 'PYTHON')))
            environment = {name: value for name, value in os.environ.items() if name not in cleared}
            environment['PYTHONDONTWRITEBYTECODE'] = '1'
            started_ns, started = time.time_ns(), time.monotonic()
            declaration = {'schema': 'hepta.hia.local-release-child-command.v1',
                'test_id': self.id(), 'parent_pid': os.getpid(), 'parent_pgid': os.getpgrp(),
                'parent_argv': sys.argv, 'parent_runtime': sys.version, 'parent_executable': sys.executable,
                'parent_cwd': str(Path.cwd()), 'started_time_ns': started_ns,
                'command': command, 'cwd': str(root), 'deadline_seconds': 180,
                'cleanup_deadline_seconds': 3, 'start_new_session': False,
                'child_inherits_parent_process_group': True, 'provider_descendants_forbidden': True,
                'cleared_environment_names': cleared, 'parent_source_pins': parent_sources,
                'enclosing_source_build_observations': os.environ.get('HEPTA_HIA_SOURCE_BUILD_OBSERVATIONS'),
                'runtime_library_path': environment.get('LD_LIBRARY_PATH')}
            (directory / 'parent-command.json').write_bytes(oracle.canonical(declaration))
            process, timed_out, supervisor_error, cleanup_error = None, False, None, None
            signals = []
            try:
                with (directory / 'stdout.log').open('xb') as stdout, (directory / 'stderr.log').open('xb') as stderr:
                    process = subprocess.Popen(command, cwd=root, env=environment,
                        stdout=stdout, stderr=stderr, start_new_session=False)
                    process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                timed_out = True
            except BaseException:
                supervisor_error = traceback.format_exc()
                raise
            finally:
                try:
                    if process is not None and process.poll() is None:
                        try:
                            process.kill()
                            signals.append('SIGKILL')
                        except ProcessLookupError:
                            pass
                        process.wait(timeout=3)
                except BaseException:
                    cleanup_error = traceback.format_exc()
                parent_result = {'schema': 'hepta.hia.local-release-child-result.v1',
                    'parent_pid': os.getpid(), 'parent_pgid': os.getpgrp(),
                    'pid': None if process is None else process.pid,
                    'returncode': None if process is None else process.returncode,
                    'child_reaped': process is not None and process.returncode is not None,
                    'timed_out': timed_out, 'signals': signals, 'exception': supervisor_error,
                    'cleanup_exception': cleanup_error,
                    'started_time_ns': started_ns, 'finished_time_ns': time.time_ns(),
                    'elapsed_seconds': time.monotonic() - started,
                    'stdout_sha256': sha256((directory / 'stdout.log').read_bytes()).hexdigest()
                        if (directory / 'stdout.log').exists() else None,
                    'stderr_sha256': sha256((directory / 'stderr.log').read_bytes()).hexdigest()
                        if (directory / 'stderr.log').exists() else None}
                (directory / 'parent-result.json').write_bytes(oracle.canonical(parent_result))
            self.assertFalse(timed_out, str(directory))
            self.assertEqual(parent_result['returncode'], 0,
                str(directory) + '\n' + (directory / 'stdout.log').read_text() + (directory / 'stderr.log').read_text())
            self.assertTrue(parent_result['child_reaped'])
            self.assertIsNone(cleanup_error)
            self.assertEqual(signals, [])
            report = json.loads((finite / 'report.json').read_bytes())
            self.assertEqual(report['schema'], 'hepta.hia.service-artifact-local-release-observer.v1')
            self.assertEqual(report['status'], 'PASS', report)
            self.assertEqual((report['pid'], report['ppid'], report['pgid']),
                             (process.pid, os.getpid(), os.getpgrp()))
            self.assertEqual(report['runtime'], sys.version)
            self.assertEqual(report['executable'], sys.executable)
            cases = original_inputs()
            self.assertEqual(report['case_order'], [case['id'] for case in cases])
            self.assertEqual((report['original_count'], report['actual_count'], report['actual_vm_frames']), (146, 146, 146))
            originals = (finite / 'originals-146.json').read_bytes()
            actuals = (finite / 'actuals-146.json').read_bytes()
            self.assertEqual(originals, actuals)
            original_pin = {'bytes': len(originals), 'sha256': sha256(originals).hexdigest()}
            self.assertEqual(report['originals_before'], original_pin)
            self.assertEqual(report['originals_after'], original_pin)
            self.assertEqual(report['actuals'], original_pin)
            complete_raw = (finite / 'complete-observations.json').read_bytes()
            complete = json.loads(complete_raw)
            self.assertEqual(report['complete_observations'],
                {'bytes': len(complete_raw), 'sha256': sha256(complete_raw).hexdigest()})
            self.assertEqual([row['case'] for row in complete], report['case_order'])
            expected, actual = json.loads(originals), json.loads(actuals)
            for case, row, left, right in zip(cases, complete, expected, actual):
                with self.subTest(case=case['id']):
                    self.assertIs(row['equal'], True)
                    self.assertEqual(oracle.canonical(row['expected']), oracle.canonical(left))
                    self.assertEqual(oracle.canonical(row['actual']), oracle.canonical(right))
                    self.assertEqual(oracle.canonical(left), oracle.canonical(right))
            difference_raw = (finite / 'differences.json').read_bytes()
            self.assertEqual(json.loads(difference_raw), [])
            self.assertEqual(report['differences'],
                {'bytes': len(difference_raw), 'sha256': sha256(difference_raw).hexdigest()})
            self.assertTrue(report['expected_file_unchanged_after_candidate'])
            self.assertTrue(report['expected_written_before_candidate_imports'])
            self.assertEqual(report['product_modules_before_originals'], [])
            self.assertGreater(report['actual_vm_entries'], 0)
            self.assertEqual(report['actual_native_entries'], 0)
            for name in ('original_late_events', 'all_late_events', 'reference_calls',
                         'mapping_calls', 'audit_refusals', 'remaining_delivery_custody'):
                self.assertEqual(report[name], [], name)
            self.assertEqual(report['source_before'], report['source_after'])
            for name, item in report['source_before'].items():
                raw = (root / name).read_bytes()
                self.assertEqual(item, {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}, name)
            self.assertEqual(parent_sources,
                {name: sha256((root / name).read_bytes()).hexdigest() for name in parent_sources})


if __name__ == '__main__':
    unittest.main()
