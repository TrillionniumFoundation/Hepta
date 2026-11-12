"""Additional experimental controls; never replace the original 116 callers.

Run only from a frozen revision. --phase shim uses the real fixed primitive
image; --phase native additionally requires an actual separately compiled HIA
image. Every phase writes a create-only report, complete IDs and input hashes.
"""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import weakref


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def original(value, count):
    # Independent spelling of the existing exact opcode 14 assignment body.
    observed = value
    if count == 1:
        a, = observed
        results = (a,)
    elif count == 2:
        a, b = observed
        results = (a, b)
    elif count == 3:
        a, b, c = observed
        results = (a, b, c)
    elif count == 4:
        a, b, c, d = observed
        results = (a, b, c, d)
    else:
        raise RuntimeError('native lowering unpack arity differs')
    return results


def context_name():
    value = sys.exception()
    return None if value is None else (type(value).__name__, value.args)


def observed(call, factory, count, ambient=False):
    events = []
    value = factory(events)
    def execute():
        try:
            answer = call(value, count)
            return {'returned': tuple(getattr(item, 'label', item) for item in answer),
                    'events': events}
        except BaseException as error:
            return {'error': (type(error).__name__, error.args),
                    'cause': None if error.__cause__ is None else (type(error.__cause__).__name__, error.__cause__.args),
                    'context': None if error.__context__ is None else (type(error.__context__).__name__, error.__context__.args),
                    'suppress': error.__suppress_context__, 'events': events}
    if ambient:
        try:
            raise LookupError('ambient')
        except LookupError:
            return execute()
    return execute()


def iterable_factory(size, failure=None):
    def factory(events):
        class Item:
            def __init__(self, label):
                self.label = label
            def __del__(self):
                events.append(('del-item', self.label, context_name()))
        class Iterator:
            def __init__(self):
                self.index = 0
            def __iter__(self):
                return self
            def __next__(self):
                index = self.index
                self.index += 1
                events.append(('next', index, context_name()))
                if failure is not None and index == failure:
                    raise KeyboardInterrupt('next')
                if index == size:
                    raise StopIteration
                return Item(index)
            def __del__(self):
                events.append(('del-iterator', context_name()))
        class Iterable:
            def __iter__(self):
                events.append(('iter', context_name()))
                return Iterator()
        return Iterable()
    return factory


class ShimControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.leaves = BRIDGE.CpythonLeaves()

    def temporary(self, value):
        session = object.__new__(BRIDGE.UnpackSession)
        session.source, session.leaves = value, self.leaves
        session.cells = (ctypes.c_uint64 * 10)()
        session.cells[1] = id(value)
        session.transaction = (ctypes.c_uint64 * 14)()
        # No session destructor: these direct primitive controls explicitly
        # account for each created reference, outside product semantics.
        session.busy, session.aborting = False, True
        session.finished, session.pending, session.finish_pending = True, False, False
        return session

    def test_exact_assembly_literal(self):
        with tempfile.TemporaryDirectory() as directory:
            obj = Path(directory) / 'shim.o'
            raw = Path(directory) / 'shim.bin'
            result = subprocess.run(['as', '--64', '-o', str(obj), str(SHIM_SOURCE)],
                                    capture_output=True, timeout=20)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))
            result = subprocess.run(['objcopy', '-O', 'binary', '--only-section=.text', str(obj), str(raw)],
                                    capture_output=True, timeout=20)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))
            self.assertEqual(raw.read_bytes(), BRIDGE.SHIM)

    def test_gil_and_error_transfer(self):
        session = self.temporary(None)
        self.assertEqual(session._transaction(self.leaves.functions['PyGILState_Check'], ()), 1)
        self.assertEqual((session.transaction[13], session.cells[9]), (4, 0))
        returned = session._transaction(self.leaves.functions['PyObject_GetIter'], (id(None),), destination=2)
        self.assertEqual(returned, 0)
        pointer = session.cells[9]
        self.assertNotEqual(pointer, 0)
        self.assertEqual(session._transaction(self.leaves.functions['PyGILState_Check'], ()), 1)
        self.assertEqual(session.cells[9], pointer)
        session.cells[9] = 0
        with self.assertRaises(TypeError) as caught:
            self.leaves.raise_error(pointer)
        self.assertEqual(str(caught.exception), "'NoneType' object is not iterable")

    def test_pending_error_cleanup_preserves_handled_context(self):
        events = []
        class Iterator:
            def __iter__(self):
                return self
            def __next__(self):
                raise KeyboardInterrupt('leaf')
            def __del__(self):
                events.append(context_name())
        class Source:
            def __iter__(self):
                return Iterator()
        session = self.temporary(Source())
        try:
            raise LookupError('ambient')
        except LookupError as ambient:
            session._transaction(self.leaves.functions['PyObject_GetIter'], (id(session.source),), destination=2)
            session._transaction(self.leaves.functions['PyIter_Next'], (session.cells[2],), destination=3)
            pointer = session.cells[9]
            self.assertNotEqual(pointer, 0)
            session._transaction(self.leaves.functions['Py_DecRef'], (session.cells[2],), consumed=2)
            self.assertIs(sys.exception(), ambient)
            self.assertEqual(session.cells[9], pointer)
            self.assertEqual(events, [('LookupError', ('ambient',))])
            session.cells[9] = 0
            try:
                self.leaves.raise_error(pointer)
            except KeyboardInterrupt as error:
                self.assertEqual(error.args, ('leaf',))
                self.assertIs(error.__context__, ambient)
            else:
                self.fail('owned raised exception was not propagated')

    def test_post_entry_exception_still_adopts_owned_result(self):
        session = self.temporary([1])
        entry = self.leaves.entry
        def interrupt(frame):
            entry(frame)
            raise MemoryError('after actual primitive')
        self.leaves.entry = interrupt
        try:
            with self.assertRaisesRegex(MemoryError, 'after actual primitive'):
                session._transaction(self.leaves.functions['PyObject_GetIter'], (id(session.source),), destination=2)
        finally:
            self.leaves.entry = entry
        self.assertNotEqual(session.cells[2], 0)
        self.assertEqual(session.transaction[13], 4)
        session._transaction(self.leaves.functions['Py_DecRef'], (session.cells[2],), consumed=2)
        self.assertEqual(tuple(session.cells[2:]), (0,) * 8)


class NativeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        raw = IMAGE.read_bytes()
        cls.owner = BRIDGE.NativeUnpack(NativeHiaJsonImage(raw, sha256(raw).hexdigest()))

    def compare(self, factory, count, ambient=False):
        self.assertEqual(observed(self.owner.unpack, factory, count, ambient),
                         observed(original, factory, count, ambient))

    def test_builtin_cardinality_and_version_messages(self):
        for count in range(1, 5):
            for size in range(7):
                for container in (tuple, list, dict):
                    with self.subTest(count=count, size=size, container=container.__name__):
                        factory = lambda events: container((i, i) for i in range(size)) if container is dict else container(range(size))
                        self.compare(factory, count)

    def test_generic_next_count_and_release_order(self):
        for count in range(1, 5):
            for size in range(7):
                for ambient in (False, True):
                    with self.subTest(count=count, size=size, ambient=ambient):
                        self.compare(iterable_factory(size), count, ambient)

    def test_foreign_failure_cleanup_and_ambient_context(self):
        for count in range(1, 5):
            for at in range(count + 1):
                for ambient in (False, True):
                    with self.subTest(count=count, at=at, ambient=ambient):
                        self.compare(iterable_factory(10, at), count, ambient)

    def test_noniterable_and_iter_errors(self):
        def noniterable(events):
            class Value:
                pass
            return Value()
        def iter_error(events):
            class Value:
                def __iter__(self):
                    events.append(('iter', context_name()))
                    raise TypeError('custom iterator')
            return Value()
        def sequence_error(events):
            class Value:
                def __getitem__(self, index):
                    events.append(('getitem', index, context_name()))
                    raise RuntimeError('sequence')
            return Value()
        for factory in (lambda events: None, noniterable, iter_error, sequence_error):
            for ambient in (False, True):
                self.compare(factory, 2, ambient)

    def test_duplicate_observe_and_terminal_result(self):
        session = self.owner.session((1, 2), 2)
        self.assertEqual(session.step(session.initial), 1)
        session.observe()
        count = len(session.actual_primitives)
        with self.assertRaises(RuntimeError):
            session.observe()
        # The abort may execute new cleanup primitives, never another GET_ITER.
        self.assertEqual(sum(op == 1 for _, op, _ in session.actual_primitives), 1)
        self.assertTrue(session.finished)
        self.assertFalse(any(session.cells[2:]))
        self.assertIsNone(session.abort_failure)
        completed = self.owner.session((1, 2), 2)
        self.assertEqual(completed.run(), (1, 2))
        after = list(completed.actual_primitives)
        with self.assertRaises(RuntimeError):
            completed.finish()
        with self.assertRaises(RuntimeError):
            completed.observe()
        self.assertEqual(completed.actual_primitives, after)

    def test_bad_ack_closes_and_hia_releases(self):
        session = self.owner.session((1, 2), 2)
        session.step(session.initial)
        packet = session.observe()
        words = list(BRIDGE.FRAME.unpack(packet))
        words[2] += 1
        with self.assertRaises(RuntimeError):
            session.step(BRIDGE.FRAME.pack(*words))
        self.assertTrue(session.finished)
        self.assertFalse(any(session.cells[2:]))
        self.assertIsNone(session.abort_failure)


class RecordingResult(unittest.TextTestResult):
    def startTest(self, test):
        EXECUTED.append(test.id())
        super().startTest(test)


def main():
    global BRIDGE, SHIM_SOURCE, IMAGE, EXECUTED
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=('shim', 'native'), required=True)
    parser.add_argument('--bridge', type=Path, required=True)
    parser.add_argument('--shim-source', type=Path, required=True)
    parser.add_argument('--image', type=Path)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    args = parser.parse_args()
    args.evidence_dir.mkdir(mode=0o700)
    paths = [Path(__file__).resolve(), args.bridge.resolve(), args.shim_source.resolve()]
    if args.phase == 'native':
        if args.image is None:
            raise ValueError('actual image is required for native controls')
        paths.append(args.image.resolve())
    before = {str(path): sha256(path.read_bytes()).hexdigest() for path in paths}
    BRIDGE, SHIM_SOURCE, IMAGE, EXECUTED = load('experimental_core_unpack', args.bridge), args.shim_source, args.image, []
    selected = ShimControls if args.phase == 'shim' else NativeControls
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(selected)
    loaded = [case.id() for case in suite]
    started = time.monotonic()
    with (args.evidence_dir / 'unittest.log').open('x') as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=RecordingResult).run(suite)
    after = {str(path): sha256(path.read_bytes()).hexdigest() for path in paths}
    report = {'schema': 'hepta.hia.core-unpack-experimental-control.v1',
              'phase': args.phase, 'seconds': time.monotonic() - started,
              'python': sys.version, 'loaded_test_ids': loaded, 'executed_test_ids': EXECUTED,
              'tests_run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
              'skipped': len(result.skipped), 'expected_failures': len(result.expectedFailures),
              'unexpected_successes': len(result.unexpectedSuccesses),
              'source_before': before, 'source_after': after,
              'source_stable': before == after, 'shim_sha256': BRIDGE.SHIM_SHA256,
              'status': 'EXPERIMENTAL_CONTROL_PASS' if result.wasSuccessful() and not result.skipped and loaded == EXECUTED and before == after else 'HOLD',
              'ordinary_entry_116_executed': False, 'cold_qualified': False,
              'whole_python_object_runtime_in_hia': False}
    (args.evidence_dir / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': report['status'], 'tests_run': result.testsRun, 'report': str(args.evidence_dir / 'report.json')}))
    return 0 if report['status'] == 'EXPERIMENTAL_CONTROL_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
