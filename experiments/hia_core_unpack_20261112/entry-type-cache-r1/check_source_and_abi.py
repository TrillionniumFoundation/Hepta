"""Source and pointer-structure controls; no executable entry is invoked."""
from __future__ import annotations

import ast
from collections import Counter
from contextlib import ExitStack
import ctypes
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import platform
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
BASELINE = ROOT / 'baseline/hepta/hia_core_unpack_native.py'
CANDIDATE = ROOT / 'inputs/hepta/hia_core_unpack_native.py'
FORBIDDEN = Counter()
OBSERVATIONS = {}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_source(path, label):
    spec = importlib.util.spec_from_file_location('type_cache_control_' + label, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def forbid(label):
    def rejected(*args, **kwargs):
        FORBIDDEN[label] += 1
        raise AssertionError('forbidden executable/CPython transaction entry: ' + label)
    return rejected


class ImageAddress:
    def __init__(self, address):
        self.address = address
        self.reads = 0

    @property
    def _entry(self):
        self.reads += 1
        return ctypes.c_void_p(self.address)


class TypeCacheSourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.legacy = load_source(BASELINE, 'baseline')
        cls.candidate = load_source(CANDIDATE, 'candidate')
        cls.stack = ExitStack()
        for module in (cls.legacy, cls.candidate):
            for name in ('_step', '_primitive', '_transaction'):
                cls.stack.enter_context(patch.object(module.UnpackSession, name,
                    forbid(module.__name__ + '.' + name)))
            cls.stack.enter_context(patch.object(module.CpythonLeaves, '__init__',
                forbid(module.__name__ + '.CpythonLeaves')))

    @classmethod
    def tearDownClass(cls):
        cls.stack.close()

    def session(self, module, image=None, count=2, source=None):
        # Deliberately inert integer pointer values. No real image or shim is
        # loaded and no pointer object is called anywhere in these controls.
        image = ImageAddress(0x1000) if image is None else image
        source = ('first', 'second') if source is None else source
        return module.UnpackSession(image, SimpleNamespace(profile=31404), source, count)

    def test_exact_source_projection_and_unchanged_inputs(self):
        change = json.loads((ROOT / 'MECHANICAL-REPLACEMENTS.json').read_bytes())
        original, new = BASELINE.read_text(), CANDIDATE.read_text()
        self.assertEqual(original.count(change['insert_after']), 1)
        self.assertEqual(new.count(change['new_line']), 1)
        self.assertEqual(new.replace(change['insertion'], '').replace(
            change['new_line'], change['old_line']), original)
        originals = json.loads((ROOT / 'BASELINE-PINS.json').read_bytes())
        for row in originals['files']:
            with self.subTest(path=row['path']):
                self.assertEqual(sha(Path(row['local_path'])), row['sha256'])
        for module in (self.legacy, self.candidate):
            self.assertEqual(module.SHIM_SHA256, '7cae34a202e02d184ddc60a8ea386c2b65a0686b9f5f35033ebbe3242332c811')
        self.assertEqual(self.legacy.TRANSACTION, self.candidate.TRANSACTION)
        self.assertEqual(self.legacy.LOAD_WORD, self.candidate.LOAD_WORD)
        self.assertEqual(self.legacy.TRANSACTION_ABI, self.candidate.TRANSACTION_ABI)
        self.assertEqual(self.legacy.FRAME.format, self.candidate.FRAME.format)

    def test_fixed_factory_type_reused_and_old_per_session_calls_observed(self):
        actual_factory = ctypes.PYFUNCTYPE
        calls = []
        def observed(*args):
            calls.append(args)
            return actual_factory(*args)
        sessions = []
        try:
            with patch.object(ctypes, 'PYFUNCTYPE', observed):
                old = load_source(BASELINE, 'factory_baseline')
                self.assertEqual(len(calls), 0)
                new = load_source(CANDIDATE, 'factory_candidate')
                self.assertEqual(len(calls), 1)
                for module in (old, new):
                    module.UnpackSession._step = forbid(module.__name__ + '._step')
                    module.UnpackSession._primitive = forbid(module.__name__ + '._primitive')
                    module.UnpackSession._transaction = forbid(module.__name__ + '._transaction')
                    module.CpythonLeaves.__init__ = forbid(module.__name__ + '.CpythonLeaves')
                old_sessions = [self.session(old) for _ in range(4)]
                sessions.extend(old_sessions)
                self.assertEqual(len(calls), 5)
                new_sessions = [self.session(new) for _ in range(4)]
                sessions.extend(new_sessions)
                self.assertEqual(len(calls), 5)
                self.assertEqual(len({type(x.entry) for x in old_sessions}), 4)
                self.assertEqual(len({type(x.entry) for x in new_sessions}), 1)
                self.assertEqual(len({id(x.entry) for x in new_sessions}), 4)
                OBSERVATIONS['type_factory'] = {
                    'baseline_import_calls': 0, 'candidate_import_calls': 1,
                    'baseline_four_sessions_new_type_calls': 4,
                    'candidate_four_sessions_new_type_calls': 0,
                    'candidate_pointer_instances': 4,
                    'measured_time_saving': None}
        finally:
            for session in sessions:
                session.close()

    def test_actual_entry_address_is_read_for_each_new_session(self):
        image = ImageAddress(0x1000)
        values = []
        try:
            for address in (0x1000, 0x2000, 0x3000):
                image.address = address
                session = self.session(self.candidate, image=image)
                values.append(session)
                self.assertEqual(ctypes.cast(session.entry, ctypes.c_void_p).value, address)
            self.assertEqual(image.reads, 3)
            self.assertEqual([ctypes.cast(x.entry, ctypes.c_void_p).value for x in values],
                             [0x1000, 0x2000, 0x3000])
        finally:
            for session in values:
                session.close()

    def test_fresh_buffers_and_initial_packet_equal_original_for_all_arities(self):
        sessions = []
        try:
            for count in range(1, 5):
                value = tuple(range(count))
                old = self.session(self.legacy, count=count, source=value)
                new = self.session(self.candidate, count=count, source=value)
                sessions.extend((old, new))
                self.assertEqual(old.initial, new.initial)
                self.assertEqual(list(old.cells), list(new.cells))
                self.assertEqual(list(old.transaction), list(new.transaction))
                for field in ('input', 'output', 'state'):
                    self.assertEqual(bytes(getattr(old, field)), bytes(getattr(new, field)))
                for field in ('finished', 'pending', 'finish_pending', 'busy', 'aborting',
                              'returned', 'status', 'request', 'actual_steps', 'actual_primitives',
                              'abort_failure', 'type_word', 'name_word'):
                    self.assertEqual(getattr(old, field), getattr(new, field))
            for field in ('cells', 'transaction', 'state', 'output', 'input'):
                addresses = [ctypes.addressof(getattr(session, field)) for session in sessions]
                self.assertEqual(len(set(addresses)), len(addresses))
            sessions[-1].state[7] = b'X'
            self.assertTrue(all(bytes(s.state)[7] == 0 for s in sessions[:-1]))
        finally:
            for session in sessions:
                session.close()

    def test_pointer_abi_and_python_error_gil_flags_equal_original(self):
        old, new = self.session(self.legacy), self.session(self.candidate)
        try:
            before, after = type(old.entry), type(new.entry)
            self.assertEqual(before._argtypes_, after._argtypes_)
            self.assertEqual(before._restype_, after._restype_)
            self.assertEqual(before._flags_, after._flags_)
            self.assertEqual(after._argtypes_, tuple([ctypes.c_void_p, ctypes.c_uint64] * 3))
            self.assertIs(after._restype_, ctypes.c_uint64)
            self.assertTrue(after._flags_ & ctypes._FUNCFLAG_PYTHONAPI)
            self.assertEqual(ctypes.cast(new.entry, ctypes.c_void_p).value, 0x1000)
            OBSERVATIONS['pointer_abi'] = {'arguments': ['void*', 'u64'] * 3,
                'return': 'u64', 'flags': after._flags_, 'pythonapi_flag': ctypes._FUNCFLAG_PYTHONAPI,
                'actual_native_or_transaction_calls': 0}
        finally:
            old.close(); new.close()

    def test_invalid_type_and_entry_lookup_errors_preserve_original_boundary(self):
        for count in (True, False, 2.0, '2', None):
            errors = []
            for module in (self.legacy, self.candidate):
                image = ImageAddress(0x1000)
                with self.assertRaises(TypeError) as caught:
                    self.session(module, image=image, count=count)
                errors.append(caught.exception.args)
                self.assertEqual(image.reads, 0)
            self.assertEqual(errors[0], errors[1])
        sentinel = RuntimeError('actual image property failure')
        class BrokenImage:
            @property
            def _entry(self):
                raise sentinel
        for module in (self.legacy, self.candidate):
            with self.assertRaises(RuntimeError) as caught:
                self.session(module, image=BrokenImage())
            self.assertIs(caught.exception, sentinel)


def main():
    destination = ROOT / 'actual-source-controls-r1'
    destination.mkdir(mode=0o700)
    started = time.monotonic()
    paths = [BASELINE, CANDIDATE, Path(__file__), ROOT / 'BASELINE-PINS.json',
             ROOT / 'MECHANICAL-REPLACEMENTS.json']
    before = {str(path): sha(path) for path in paths}
    expected = ['__main__.TypeCacheSourceControls.' + name for name in sorted(
        node.name for node in ast.parse(Path(__file__).read_bytes()).body
        if isinstance(node, ast.ClassDef) and node.name == 'TypeCacheSourceControls'
        for node in node.body if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'))]
    executed = []
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            executed.append(test.id())
            super().startTest(test)
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TypeCacheSourceControls)
    loaded = [test.id() for test in suite]
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
    after = {str(path): sha(path) for path in paths}
    anomalies = {'failures': [test.id() for test, _ in result.failures],
                 'errors': [test.id() for test, _ in result.errors],
                 'skips': [test.id() for test, _ in result.skipped],
                 'expected_failures': [test.id() for test, _ in result.expectedFailures],
                 'unexpected_successes': [test.id() for test in result.unexpectedSuccesses]}
    passed = (expected == loaded == executed and len(expected) == 6
              and not loader.errors and not any(anomalies.values())
              and before == after and not FORBIDDEN)
    report = {'schema': 'hia.core-unpack-entry-type-source-control.v1',
              'status': 'SOURCE_ABI_STRUCTURE_PASS' if passed else 'HOLD',
              'seconds': time.monotonic() - started, 'expected_ids': expected,
              'loaded_ids': loaded, 'executed_ids': executed, 'loader_errors': loader.errors,
              'anomalies': anomalies, 'forbidden_executable_calls': dict(FORBIDDEN),
              'runtime': {'implementation': platform.python_implementation(),
                          'version': list(sys.version_info[:3]), 'executable': sys.executable},
              'input_before': before, 'input_after': after, 'observations': OBSERVATIONS,
              'HIA_image_loaded_or_executed': False, 'transaction_shim_executed': False,
              'compiler_executed': False, 'complete116_executed': False,
              'runtime31404_native_qualified': False, 'time_saving_measured': False}
    (destination / 'unittest.log').write_text(stream.getvalue())
    (destination / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'seconds', 'anomalies', 'forbidden_executable_calls')}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
