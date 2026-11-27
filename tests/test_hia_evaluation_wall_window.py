"""Actual evaluation window custody and original runner boundaries.

These controls use an admitted native evaluation image. The existing frozen
deadline tests and 111 original foreign traces remain separate unchanged gates.
"""
from __future__ import annotations

from contextvars import copy_context
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch

from hepta import hia_agent_service as api
from hepta import hia_evaluation_native as native
from tests.hia_evaluation_oracle import World
from tests.test_hia_evaluation_native import fixture_by_name, original, encoded

ROOT = Path(__file__).resolve().parents[1]


class EvaluationWallWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_evaluation import build
        from tools.hia_cold_compiler import compiler_from_cold_report
        cold = os.environ.get('HEPTA_HIA_EVALUATION_COLD_REPORT')
        development = os.environ.get('HEPTA_HIA_EVALUATION_DEVELOPMENT_COMPILER')
        if (cold is None) == (development is None) or cold == '' or development == '':
            raise ValueError('choose matching cold custody or an explicit development compiler')
        cls.temporary = None
        evidence = os.environ.get('HEPTA_HIA_EVALUATION_WINDOW_EVIDENCE')
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-evaluation-window-')
            cls.root = Path(cls.temporary.name)
        else:
            cls.root = Path(evidence)
            cls.root.mkdir(mode=0o700, exist_ok=False)
        compiler = compiler_from_cold_report(cold) if cold is not None else Path(development)
        cls.manifest = build(cls.root / 'built', compiler, cold, development=cold is None)
        cls.image = native.installed_evaluation(str(cls.manifest))
        cls.inputs = {name: (ROOT / name).read_bytes() for name in (
            'hepta/hia_agent_service.py', 'hepta/hia_evaluation_native.py',
            'examples/hia_bootstrap/evaluation.hepta', __file__.removeprefix(str(ROOT) + '/'))}
        cls.records = []

    @classmethod
    def tearDownClass(cls):
        stable = all((ROOT / name).read_bytes() == raw for name, raw in cls.inputs.items())
        (cls.root / 'window-custody.json').write_text(json.dumps({
            'schema': 'hepta.hia.evaluation-window-custody.v1',
            'source_sha256': {name: sha256(raw).hexdigest() for name, raw in cls.inputs.items()},
            'sources_unchanged': stable, 'records': cls.records,
            'manifest': str(cls.manifest),
            'test_outcome_owned_by_supervisor': True,
            'all_input_equivalence_proved': False}, indent=2, sort_keys=True) + '\n')
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not stable:
            raise AssertionError('evaluation window inputs changed')

    def setUp(self):
        self.assertIsNone(api._EVALUATION_WALL_WINDOW.get())
        self.world = World(fixture_by_name()['artifact_improved'], api)
        self.frame = None

    def invoke(self, service, args):
        self.frame = native.EvaluationFrame(self.image, service, args)
        return self.frame.finish()

    def observe(self):
        result = self.world.observe(self.invoke)
        self.records.append({'test': self.id(), 'observation': result})
        self.assertIsNone(api._EVALUATION_WALL_WINDOW.get())
        return result

    def test_actual_service_boundary_reads_one_clock_and_keeps_hia_arithmetic(self):
        expected = World(fixture_by_name()['artifact_improved'], api).observe(original())
        windows = []
        boundary = self.world.service._wall_window
        def observed(context, *, created_ns=None):
            before = self.world.wall_calls
            result = boundary(context, created_ns=created_ns)
            self.assertEqual(self.world.wall_calls, before + 1)
            self.assertEqual(created_ns, 1_000_000_000)
            self.assertIs(context, self.world.context)
            windows.append((created_ns, result))
            return result
        with patch.object(self.world.service, '_wall_window', observed), patch.object(
                api, '_reference_wall_window', side_effect=AssertionError('hosted deadline entered')):
            actual = self.observe()
        self.assertEqual(encoded(actual), encoded(expected))
        self.assertTrue(windows)
        self.assertTrue(all(type(expired) is bool and type(remaining) is int
                            for _, (expired, remaining) in windows))

    def test_actual_boundary_result_supplies_each_reference_timeout(self):
        boundary = self.world.service._wall_window
        returned = []
        def observed(context, *, created_ns=None):
            expired, remaining = boundary(context, created_ns=created_ns)
            returned.append(remaining - 7)
            return expired, remaining - 7
        with patch.object(self.world.service, '_wall_window', observed):
            result = self.observe()
        self.assertEqual(result['outcome']['status'], 'returned')
        calls = [row for row in result['trace'] if row['effect'] == 'run_reference_batch']
        self.assertEqual(len(calls), 2)
        self.assertEqual([row['kwargs']['timeout_ms'] for row in calls], returned[:2])

    def test_window_exception_precedes_runner_and_does_not_keep_owner(self):
        held = []
        def refused(context, *, created_ns=None):
            held.append(api._EVALUATION_WALL_WINDOW.get())
            raise OSError('original window provider failed')
        with patch.object(self.world.service, '_wall_window', refused):
            result = self.observe()
        self.assertEqual(result['outcome']['type'], 'builtins.OSError')
        self.assertEqual(result['outcome']['args'], ['original window provider failed'])
        self.assertFalse(any(row['effect'] == 'run_reference_batch' for row in result['trace']))
        self.assertEqual(len(held), 1)
        self.assertFalse(held[0].active)
        self.assertTrue(self.frame.finished)

    def test_copied_context_cannot_revive_a_completed_window(self):
        contexts = []
        boundary = self.world.service._wall_window
        def observed(context, *, created_ns=None):
            contexts.append((copy_context(), context, created_ns,
                             api._EVALUATION_WALL_WINDOW.get()))
            return boundary(context, created_ns=created_ns)
        with patch.object(self.world.service, '_wall_window', observed):
            result = self.observe()
        self.assertEqual(result['outcome']['status'], 'returned')
        held, context, created, owner = contexts[0]
        self.assertFalse(owner.active)
        with patch.object(self.image, 'arithmetic', side_effect=AssertionError('ended owner revived')), \
             patch.object(api, '_reference_wall_window', return_value=(False, 19)) as ordinary:
            self.assertEqual(held.run(boundary, context, created_ns=created), (False, 19))
        ordinary.assert_called_once()

    def test_unrelated_service_and_context_keep_their_own_window_policy(self):
        boundary = self.world.service._wall_window
        other = object.__new__(api.HIAAgentService)
        calls = []
        def observed(context, *, created_ns=None):
            with patch.object(api, '_reference_wall_window', return_value=(False, 23)) as ordinary:
                calls.append(other._wall_window(context, created_ns=created_ns))
                calls.append(boundary(dict(context), created_ns=created_ns))
                self.assertEqual(ordinary.call_count, 2)
            return boundary(context, created_ns=created_ns)
        with patch.object(self.world.service, '_wall_window', observed):
            result = self.observe()
        self.assertEqual(result['outcome']['status'], 'returned')
        self.assertTrue(calls)
        self.assertTrue(all(value == (False, 23) for value in calls))

    def test_copied_context_in_another_thread_cannot_transfer_native_owner(self):
        boundary = self.world.service._wall_window
        answers, failures = [], []
        def observed(context, *, created_ns=None):
            held = copy_context()
            def child():
                try:
                    with patch.object(api, '_reference_wall_window', return_value=(False, 29)):
                        answers.append(held.run(boundary, context, created_ns=created_ns))
                except BaseException as error:
                    failures.append(repr(error))
            worker = threading.Thread(target=child)
            worker.start()
            worker.join(10)
            self.assertFalse(worker.is_alive())
            return boundary(context, created_ns=created_ns)
        with patch.object(self.world.service, '_wall_window', observed):
            result = self.observe()
        self.assertEqual(result['outcome']['status'], 'returned')
        self.assertEqual(failures, [])
        self.assertTrue(answers)
        self.assertTrue(all(value == (False, 29) for value in answers))

    def test_lost_native_window_return_fences_before_any_runner_or_replay(self):
        entry, lost = self.image._entry, []
        def deliver(source, size, output, capacity, state, extent):
            magic, operation = struct.unpack('<2Q', ctypes.string_at(source, 16))
            answer = entry(source, size, output, capacity, state, extent)
            if (magic == native.MATH_MAGIC and operation == 2
                    and api._EVALUATION_WALL_WINDOW.get() is not None):
                lost.append(True)
                raise OSError('actual native window return lost')
            return answer
        with patch.object(self.image, '_entry', deliver):
            result = self.observe()
            self.assertEqual(result['outcome']['type'],
                             'hepta.hia_evaluation_native.EvaluationUnknown')
            self.assertEqual(lost, [True])
            self.assertFalse(any(row['effect'] == 'run_reference_batch' for row in result['trace']))
            with self.assertRaises(native.EvaluationUnknown):
                self.frame.finish()
            self.assertEqual(lost, [True])
        self.assertTrue(self.frame.fenced)

    def test_nested_evaluation_restores_the_exact_outer_window_owner(self):
        boundary = self.world.service._wall_window
        nested = []
        def observed(context, *, created_ns=None):
            outer = api._EVALUATION_WALL_WINDOW.get()
            if not nested:
                child = World(fixture_by_name()['artifact_improved'], api)
                nested.append(child.observe(lambda service, args:
                    native.EvaluationFrame(self.image, service, args).finish()))
                self.assertIs(api._EVALUATION_WALL_WINDOW.get(), outer)
            return boundary(context, created_ns=created_ns)
        with patch.object(self.world.service, '_wall_window', observed):
            result = self.observe()
        self.assertEqual(result['outcome']['status'], 'returned')
        self.assertEqual(nested[0]['outcome']['status'], 'returned')


if __name__ == '__main__':
    unittest.main()
