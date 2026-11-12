"""Real unittest/descriptor controls with inert fixtures and no native entry."""
from __future__ import annotations

import ast
from contextlib import contextmanager, ExitStack
from copy import deepcopy
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch

from tools import hia_core_unpack_progress as progress

ROOT = Path(__file__).resolve().parents[1]


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestCase):
            yield test
        else:
            yield from flatten(test)


@contextmanager
def fixture_modules(*, failure=None, shape=None, unrelated=False):
    """Two real modules/four classes; all nested suites come from the loader."""
    trace, modules = [], {}
    names = ('_hia_unpack_progress_first', '_hia_unpack_progress_second')
    auxiliary_name = '_hia_unpack_progress_auxiliary'
    def event(kind, subject):
        trace.append([kind, subject])
        if failure is not None and failure[0:2] == (kind, subject):
            raise failure[2]
    for name in names:
        module = ModuleType(name)
        module.setUpModule = lambda name=name: event('module_setup', name)
        module.tearDownModule = lambda name=name: event('module_teardown', name)
        for label in ('Alpha', 'Beta'):
            full = name + '.' + label
            def method(self, full=full):
                event('method', full + '.test_body')
                if unrelated:
                    loader = unittest.TestLoader()
                    inner = loader.loadTestsFromNames([auxiliary_name])
                    result = unittest.TextTestRunner(stream=io.StringIO()).run(inner)
                    if not result.wasSuccessful():
                        raise AssertionError('unrelated inert inner suite failed')
            def setup(cls, full=full):
                event('class_setup', full)
            def teardown(cls, full=full):
                event('class_teardown', full)
            cls = type(label, (unittest.TestCase,), {'__module__': name, '__qualname__': label,
                'test_body': method, 'setUpClass': classmethod(setup), 'tearDownClass': classmethod(teardown)})
            setattr(module, label, cls)
        def load_tests(loader, suite, pattern, name=name):
            if shape == 'uncovered' and name == names[0]:
                return unittest.TestSuite([suite])
            if shape == 'reordered' and name == names[0]:
                return loader.suiteClass(list(suite)[::-1])
            return loader.suiteClass([suite])
        module.load_tests = load_tests
        modules[name] = module
    if unrelated:
        auxiliary = ModuleType(auxiliary_name)
        auxiliary.Auxiliary = type('Auxiliary', (unittest.TestCase,), {
            '__module__': auxiliary_name, '__qualname__': 'Auxiliary',
            'setUpClass': classmethod(lambda cls: event('unrelated_setup', auxiliary_name)),
            'tearDownClass': classmethod(lambda cls: event('unrelated_teardown', auxiliary_name)),
            'test_body': lambda self: event('unrelated_method', auxiliary_name)})
        modules[auxiliary_name] = auxiliary
    ids = [name + '.' + label + '.test_body' for name in names for label in ('Alpha', 'Beta')]
    groups = [{'label': 'synthetic', 'modules': list(names), 'ids': ids}]
    with patch.dict(sys.modules, modules):
        yield groups, trace


def run_original_group(group):
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(group['modules'])
    loaded = [test.id() for test in flatten(suite)]
    result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=2).run(suite)
    return loaded, result


def original_report(directory):
    path = directory / 'core-callers/report.json'
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(progress.wire({'schema': 'hepta.synthetic-progress-control.v1',
        'native_executed': False, 'qualification_claimed': False}))
    return progress.plain_pin(progress.read_file(path)[1])


def replace_original(path, raw):
    path.chmod(0o600)
    path.write_bytes(raw)
    path.chmod(0o400)


class UnpackQualificationProgressTests(unittest.TestCase):
    def setUp(self):
        self.folders = []

    def folder(self):
        root = os.environ.get('HEPTA_PROGRESS_CONTROL_EVIDENCE')
        if root:
            value = Path(root) / self._testMethodName / str(len(self.folders))
            value.mkdir(parents=True, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory(prefix='hia-unpack-progress-')
            self.addCleanup(temporary.cleanup)
            value = Path(temporary.name)
        self.folders.append(value)
        return value

    def completed(self, directory):
        with fixture_modules(unrelated=True) as (groups, trace):
            recorder = progress.ProgressRecorder(directory, groups, lambda: 0)
            with recorder.observe():
                loaded, result = run_original_group(groups[0])
            self.assertTrue(result.wasSuccessful())
            self.assertEqual(loaded, groups[0]['ids'])
            pin = original_report(directory)
            binding = recorder.finish(complete=True, original_report=pin)
        self.assertTrue(binding['complete'])
        return groups, pin, binding, trace

    def test_nested_suite_fixture_order_and_original_callbacks(self):
        with fixture_modules(unrelated=True) as (groups, trace):
            loaded, baseline = run_original_group(groups[0])
            expected = list(trace)
            trace.clear()
            folder = self.folder()
            recorder = progress.ProgressRecorder(folder, groups, lambda: 0)
            with recorder.observe():
                actual_ids, actual = run_original_group(groups[0])
            pin = original_report(folder)
            binding = recorder.finish(complete=True, original_report=pin)
            self.assertEqual(trace, expected)
            self.assertEqual(loaded, actual_ids)
            self.assertEqual(actual.testsRun, baseline.testsRun)
            self.assertTrue(actual.wasSuccessful() and baseline.wasSuccessful())
            self.assertEqual(progress.inspect_progress(folder, groups, pin), binding)
            rows = [json.loads(line) for line in (folder / progress.LOG_NAME).read_bytes().splitlines()]
            begin = next(row for row in rows if row['event'] == 'group_begin')
            self.assertGreaterEqual(begin['detail']['nested_suite_count'], 7)
            self.assertEqual([row['subject'] for row in rows if row['event'] == 'test_start'], loaded)
            self.assertEqual([row['subject'] for row in rows if row['event'] == 'test_stop'], loaded)
            kinds = {row['detail']['kind'] for row in rows if row['event'] == 'fixture_begin'}
            self.assertEqual(kinds, progress.FIXTURES)
            self.assertTrue(all(row['detail']['outcome'] == 'normal_return' for row in rows
                                if row['event'] == 'fixture_end'))
            self.assertTrue(all(row['native_returns'] == 0 for row in rows))
            self.assertFalse(any('auxiliary' in row['subject'] for row in rows))

    def test_fixture_failures_and_baseexceptions_are_distinct(self):
        for kind, subject in (
            ('class_setup', '_hia_unpack_progress_first.Alpha'),
            ('class_teardown', '_hia_unpack_progress_first.Alpha'),
            ('module_setup', '_hia_unpack_progress_first'),
            ('module_teardown', '_hia_unpack_progress_first')):
            for failure in (RuntimeError('original inert fixture'), MemoryError('caught by unittest')):
                with self.subTest(kind=kind, failure=type(failure).__name__):
                    with fixture_modules(failure=(kind, subject, failure)) as (groups, trace):
                        folder = self.folder()
                        recorder = progress.ProgressRecorder(folder, groups, lambda: 0)
                        with recorder.observe():
                            _, result = run_original_group(groups[0])
                        self.assertFalse(result.wasSuccessful())
                        self.assertTrue(result.errors)
                        binding = recorder.finish(complete=False)
                        rows = [json.loads(line) for line in (folder / progress.LOG_NAME).read_bytes().splitlines()]
                        outcomes = [row['detail']['outcome'] for row in rows if row['event'] == 'fixture_end']
                        self.assertIn('fixture_error', outcomes)
                        self.assertNotIn('base_exception', outcomes)
                        self.assertFalse(binding['complete'])
                        self.assertEqual(binding['status'], 'HOLD')
                        with self.assertRaises(ValueError):
                            progress.inspect_progress(folder, groups, None)
        for kind, subject in (
            ('class_setup', '_hia_unpack_progress_first.Alpha'),
            ('class_teardown', '_hia_unpack_progress_first.Alpha'),
            ('module_setup', '_hia_unpack_progress_first'),
            ('module_teardown', '_hia_unpack_progress_first')):
            for exception in (KeyboardInterrupt('fixture'), SystemExit('fixture')):
                with fixture_modules(failure=(kind, subject, exception)) as (groups, _):
                    folder = self.folder()
                    recorder = progress.ProgressRecorder(folder, groups, lambda: 0)
                    with self.assertRaises(type(exception)) as caught:
                        with recorder.observe():
                            run_original_group(groups[0])
                    self.assertIs(caught.exception, exception)
                    binding = recorder.finish(complete=False)
                    rows = [json.loads(line) for line in (folder / progress.LOG_NAME).read_bytes().splitlines()]
                    self.assertTrue(any(row['event'] == 'fixture_end' and
                        row['detail']['outcome'] == 'base_exception' for row in rows))
                    self.assertFalse(binding['complete'])

    def test_diagnostic_failure_preserves_original_exception(self):
        for exception in (KeyboardInterrupt('same original object'), SystemExit('same original object')):
            with fixture_modules(failure=('class_setup', '_hia_unpack_progress_first.Alpha', exception)) as (groups, _):
                folder = self.folder()
                recorder = progress.ProgressRecorder(folder, groups, lambda: 0)
                write = progress.os.write
                def fail_end(fd, raw):
                    if fd == recorder.fd and b'"event":"fixture_end"' in raw:
                        raise OSError('secondary progress failure')
                    return write(fd, raw)
                with patch.object(progress.os, 'write', fail_end):
                    with self.assertRaises(type(exception)) as caught:
                        with recorder.observe():
                            run_original_group(groups[0])
                self.assertIs(caught.exception, exception)
                binding = recorder.finish(complete=False)
                receipt = json.loads((folder / progress.RECEIPT_NAME).read_bytes())
                self.assertFalse(binding['complete'])
                self.assertTrue(receipt['logging_errors'])
                self.assertEqual(receipt['status'], 'HOLD')
        with fixture_modules(failure=('class_setup', '_hia_unpack_progress_first.Alpha',
                                      RuntimeError('caught original fixture'))) as (groups, _):
            folder = self.folder()
            recorder = progress.ProgressRecorder(folder, groups, lambda: 0)
            write = progress.os.write
            def fail_caught_end(fd, raw):
                if fd == recorder.fd and b'"outcome":"fixture_error"' in raw:
                    raise OSError('secondary after result already holds original error')
                return write(fd, raw)
            with patch.object(progress.os, 'write', fail_caught_end):
                # Diagnostic failure must not replace the caught fixture error.
                with recorder.observe():
                    _, result = run_original_group(groups[0])
            self.assertIn('caught original fixture', result.errors[0][1])
            self.assertFalse(recorder.finish(complete=False)['complete'])

    def test_uncovered_or_reordered_inner_suite_is_rejected(self):
        for shape in ('uncovered', 'reordered'):
            with fixture_modules(shape=shape) as (groups, trace):
                folder = self.folder()
                recorder = progress.ProgressRecorder(folder, groups, lambda: 0)
                with self.assertRaisesRegex(ValueError, 'inner suite|loader IDs'):
                    with recorder.observe():
                        run_original_group(groups[0])
                self.assertEqual(trace, [])
                self.assertFalse(recorder.finish(complete=False)['complete'])

    def test_complete_readback_rejects_missing_truncated_duplicated_events(self):
        folder = self.folder()
        groups, pin, _, _ = self.completed(folder)
        raw = (folder / progress.LOG_NAME).read_bytes()
        lines = raw.splitlines(keepends=True)
        for invalid in (raw[:-1], b''.join(lines[:-1]), lines[0] + raw, b''.join(lines[1:])):
            with self.assertRaises(ValueError):
                progress.validate_events(invalid, groups, True, pin)
        rows = [json.loads(line) for line in lines]
        missing_stop = next(index for index, row in enumerate(rows) if row['event'] == 'test_stop')
        del rows[missing_stop]
        for index, row in enumerate(rows):
            row['sequence'] = index
        with self.assertRaises(ValueError):
            progress.validate_events(b''.join(progress.wire(row) for row in rows), groups, True, pin)
        duplicate_end = [json.loads(line) for line in lines]
        duplicate_end.append(deepcopy(duplicate_end[-1]))
        duplicate_end[-1]['sequence'] += 1
        with self.assertRaises(ValueError):
            progress.validate_events(b''.join(progress.wire(row) for row in duplicate_end), groups, True, pin)

    def test_receipt_cannot_substitute_original_report_or_current_bytes(self):
        for change in ('missing', 'truncated', 'receipt_only', 'report', 'forged_bytes'):
            with self.subTest(change=change):
                folder = self.folder()
                groups, pin, binding, _ = self.completed(folder)
                log, receipt_path = folder / progress.LOG_NAME, folder / progress.RECEIPT_NAME
                if change == 'missing':
                    log.unlink()
                elif change == 'truncated':
                    replace_original(log, log.read_bytes()[:-1])
                elif change == 'receipt_only':
                    log.unlink()
                    replace_original(receipt_path, progress.wire(binding))
                elif change == 'report':
                    (folder / 'core-callers/report.json').write_text('{"different":true}\n')
                else:
                    rows = [json.loads(line) for line in log.read_bytes().splitlines()]
                    rows.insert(1, deepcopy(rows[0]))
                    for index, row in enumerate(rows):
                        row['sequence'] = index
                    forged = b''.join(progress.wire(row) for row in rows)
                    replace_original(log, forged)
                    receipt = json.loads(receipt_path.read_bytes())
                    receipt.update(progress=progress.read_file(log, progress.MAX_BYTES, owned=True)[1],
                        writer_bytes=len(forged), writer_sha256=sha256(forged).hexdigest(),
                        writer_event_count=len(rows))
                    replace_original(receipt_path, progress.wire(receipt))
                with self.assertRaises((ValueError, OSError)):
                    progress.inspect_progress(folder, groups, pin)

    def test_bounds_and_write_failures_leave_hold_originals(self):
        for failure in ('bounds', 'event_count', 'total_bytes', 'short_write'):
            folder = self.folder()
            with fixture_modules() as (groups, trace):
                recorder = progress.ProgressRecorder(folder, groups, lambda: 0)
                write = progress.os.write
                def short(fd, raw):
                    if fd == recorder.fd:
                        return write(fd, raw[:2])
                    return write(fd, raw)
                bounds = {'bounds': ('MAX_EVENT_BYTES', 1), 'event_count': ('MAX_EVENTS', 1),
                          'total_bytes': ('MAX_BYTES', 1)}
                context = (patch.object(progress, *bounds[failure]) if failure in bounds
                           else patch.object(progress.os, 'write', short))
                with context:
                    with self.assertRaises(ValueError):
                        with recorder.observe():
                            run_original_group(groups[0])
                self.assertEqual(trace, [])
                self.assertFalse(recorder.finish(complete=False)['complete'])
                self.assertTrue((folder / progress.LOG_NAME).is_file())
                self.assertTrue((folder / progress.RECEIPT_NAME).is_file())
        self.assertEqual((progress.MAX_BYTES, progress.MAX_EVENT_BYTES, progress.MAX_EVENTS,
                          progress.MAX_RECEIPT_BYTES), (524288, 1024, 1024, 131072))

    def test_unpack_wrapper_keeps_default_main_and_old_gate_paths(self):
        source = ast.parse((ROOT / 'tools/qualify_hia_core_unpack_callers.py').read_bytes())
        calls = [node for node in ast.walk(source) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                 and node.func.value.id == 'original' and node.func.attr == 'main']
        self.assertEqual(len(calls), 1)
        self.assertEqual((calls[0].args, calls[0].keywords), ([], []))
        observations = [node for node in ast.walk(source) if isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == 'progress' and node.func.attr == 'observe']
        self.assertEqual(len(observations), 1)
        original = (ROOT / 'tools/qualify_hia_core_lowering_callers.py').read_text()
        self.assertNotIn('hia_core_unpack_progress', original)
        self.assertNotIn('ProgressRecorder', original)
        previous = (ROOT / 'tools/hia_compiler_owner_gates.py').read_text()
        self.assertNotIn('hia_core_unpack_progress', previous)
        from tools import hia_core_unpack_gates as gates
        self.assertEqual(gates.SUCCESSOR_GATES[:30], gates.previous.SUCCESSOR_GATES)
        self.assertEqual(len(gates.previous.SUCCESSOR_GATES), 30)
        self.assertIn('tools/hia_core_unpack_progress.py', gates.SOURCE_FILES)
        self.assertIn('tests/test_hia_core_unpack_progress.py', gates.SOURCE_FILES)

    def test_new_gate_rereads_progress_and_cannot_accept_summary_alone(self):
        from tools import hia_core_unpack_gates as gates
        base = self.folder()
        folder = base / 'callers'
        folder.mkdir()
        groups, original_pin, binding, _ = self.completed(folder)
        installed = folder / 'core-callers/component-fixture/installed-control/report.json'
        installed.parent.mkdir(parents=True)
        installed.write_bytes(progress.wire({'unpack_observations': {'synthetic': True}}))
        producer = {'original_report': original_pin, 'progress': binding,
            'installed_report': gates.size_pin(installed), 'installed_observation': {'synthetic': True},
            'actual_UNPACK_step_returns': []}
        (folder / 'report.json').write_bytes(progress.wire(producer))
        companion = {'files': [{'path': '/fixed/inert/manifest.json'}]}
        with ExitStack() as stack:
            for target, name, value in (
                (gates, 'admit_dependencies', None), (gates, 'caller_groups', groups),
                (gates, 'companion_build', companion), (gates, 'validate_callers', {}),
                (gates.previous, 'inspect_core_callers', {}), (gates, 'validate_installed', {}),
                (gates, 'source_now', None)):
                stack.enter_context(patch.object(target, name, return_value=value))
            observed = gates.inspect_callers(base, Path('/fixed/inert/cold.json'), {})
            self.assertEqual(observed['progress'], binding)
            (folder / progress.LOG_NAME).unlink()
            with self.assertRaises(OSError):
                gates.inspect_callers(base, Path('/fixed/inert/cold.json'), {})


if __name__ == '__main__':
    unittest.main()
