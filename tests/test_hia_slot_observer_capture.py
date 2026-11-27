"""Regression controls for the explicit observer snapshot revision."""
from __future__ import annotations

import ast
import copy
import gc
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tests.hia_slot_observer_capture import (
    bind_snapshot_functions, rewrite_snapshot_calls,
)

ROOT = Path(__file__).resolve().parents[1]
ORACLE = ROOT / 'tests/fixtures/hia_slot_operations_original_r1/observe_originals.py'


class World:
    def __init__(self):
        self.events = [{'event': 'consumer.end'}]
        self.phase = 'retained-traceback-release'
        self.case = {'id': 'probe', 'template': 'snapshot-present',
                     'method': 'snapshot', 'outer_exception': False}
        self.effects, self.requests, self.unraisable = [], [], []
        self.sql_at, self.fault_hits = 0, 0

    def alive(self):
        if gc.isenabled():
            raise AssertionError('weakref snapshot was taken outside the capture section')
        return ['subject#1']


class SnapshotCaptureTests(unittest.TestCase):
    def setUp(self):
        self.enabled, self.thresholds = gc.isenabled(), gc.get_threshold()

    def tearDown(self):
        self.assertEqual(gc.get_threshold(), self.thresholds)
        if self.enabled:
            gc.enable()
        else:
            gc.disable()

    def namespace(self, fail=False):
        calls = []

        def copy_json(value):
            calls.append(gc.isenabled())
            if fail:
                raise RuntimeError('actual capture failure')
            return json.loads(json.dumps(value))

        def canonical(value):
            calls.append(gc.isenabled())
            if fail:
                raise RuntimeError('actual capture failure')
            return json.dumps(value, ensure_ascii=True, sort_keys=True,
                              allow_nan=False).encode('ascii')

        namespace = {'copy_json': copy_json, 'canonical': canonical, 'json': json}
        bind_snapshot_functions(namespace)
        return namespace, calls

    def test_snapshots_are_detached_and_gc_is_restored(self):
        gc.enable()
        namespace, calls = self.namespace()
        world, outcome = World(), {'kind': 'returned', 'value': 7}
        first = namespace['_HIA_OBSERVER_CAPTURE_CONSUMER'](world, outcome)
        self.assertIs(type(first), bytes)
        world.events.append({'event': 'after-consumer'})
        outcome['value'] = 8
        second = namespace['_HIA_OBSERVER_CAPTURE_FINAL'](world, outcome, first)
        first = json.loads(first)
        self.assertTrue(gc.isenabled())
        self.assertEqual(calls, [False, False])
        world.events.append({'event': 'after-seal.delete'})
        outcome['value'] = 9
        self.assertEqual(first['events'], [{'event': 'consumer.end'}])
        self.assertEqual(first['outcome']['value'], 7)
        self.assertEqual(second['events'], first['events'] + [{'event': 'after-consumer'}])
        self.assertEqual(second['consumer_snapshot'], first)
        self.assertEqual(second['outcome']['value'], 8)
        self.assertEqual(second['alive_at_seal'], ['subject#1'])

    def test_previously_disabled_gc_stays_disabled(self):
        gc.disable()
        namespace, calls = self.namespace()
        world = World()
        first = namespace['_HIA_OBSERVER_CAPTURE_CONSUMER'](world, {})
        namespace['_HIA_OBSERVER_CAPTURE_FINAL'](world, {}, first)
        self.assertFalse(gc.isenabled())
        self.assertEqual(calls, [False, False])

    def test_capture_error_preserves_gc_and_exception(self):
        for enabled in (False, True):
            (gc.enable if enabled else gc.disable)()
            namespace, _ = self.namespace(fail=True)
            for name, args in (
                ('_HIA_OBSERVER_CAPTURE_CONSUMER', (World(), {})),
                ('_HIA_OBSERVER_CAPTURE_FINAL', (World(), {}, b'{}')),
            ):
                with self.assertRaisesRegex(RuntimeError, 'actual capture failure'):
                    namespace[name](*args)
                self.assertEqual(gc.isenabled(), enabled)
            good, _ = self.namespace()
            with self.assertRaises(json.JSONDecodeError):
                good['_HIA_OBSERVER_CAPTURE_FINAL'](World(), {}, b'{')
            self.assertEqual(gc.isenabled(), enabled)

    def test_exact_snapshot_and_seal_ast_revision(self):
        original = ast.parse(ORACLE.read_bytes())
        changed = copy.deepcopy(original)
        declaration = rewrite_snapshot_calls(changed)
        self.assertEqual(declaration, {'version': 'deferred-json-snapshots-v3',
            'changed_snapshot_expressions': 2, 'changed_seal_statements': 2,
            'changed_product_expressions': 0, 'changed_case_inputs': 0,
            'consumer_representation': 'canonical-json-bytes'})
        def assignments(module):
            world = next(node for node in module.body
                         if isinstance(node, ast.ClassDef) and node.name == 'World')
            observe = next(node for node in world.body
                           if isinstance(node, ast.FunctionDef) and node.name == 'observe')
            return {node.targets[0].id: node for node in observe.body
                    if isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id in ('consumer_snapshot', 'record')}
        before, after = assignments(original), assignments(changed)
        for name in ('consumer_snapshot', 'record'):
            self.assertNotEqual(ast.dump(before[name].value), ast.dump(after[name].value))
            after[name].value = copy.deepcopy(before[name].value)
        def method(module):
            world = next(node for node in module.body
                         if isinstance(node, ast.ClassDef) and node.name == 'World')
            return next(node for node in world.body
                        if isinstance(node, ast.FunctionDef) and node.name == 'observe')
        old, new = method(original), method(changed)
        for index, node in enumerate(old.body):
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Attribute)
                    and (node.targets[0].attr == 'sealed_event_count'
                         or (node.targets[0].attr == 'phase'
                             and isinstance(node.value, ast.Constant)
                             and node.value.value == 'case-sealed'))):
                new.body.insert(index, copy.deepcopy(node))
        self.assertEqual(ast.dump(original, include_attributes=True),
                         ast.dump(changed, include_attributes=True))

    def test_missing_or_already_revised_snapshot_is_rejected(self):
        source = ORACLE.read_text()
        missing = ast.parse(source.replace('consumer_snapshot = copy_json(', 'unrelated = copy_json('))
        with self.assertRaisesRegex(ValueError, 'both original snapshots'):
            rewrite_snapshot_calls(missing)
        revised = ast.parse(source)
        rewrite_snapshot_calls(revised)
        with self.assertRaisesRegex(ValueError, 'original snapshot expression'):
            rewrite_snapshot_calls(revised)
        for before, after in (
            ('"alive": self.alive()', '"alive": []'),
            ('"events": self.events, "alive": self.alive()',
             '"alive": self.alive(), "events": self.events'),
            ('self.sealed_event_count = len(self.events)',
             'self.sealed_event_count = len(self.events) + 1'),
            ('self.sealed_event_count = len(self.events)',
             'self.sealed_event_count = len(self.events)\n        self.sealed_event_count = len(self.events)'),
        ):
            with self.subTest(change=after):
                with self.assertRaisesRegex(ValueError, 'original (snapshot expression|seal statements)'):
                    rewrite_snapshot_calls(ast.parse(source.replace(before, after)))

    def test_final_seal_partitions_actual_cyclic_finalizers(self):
        gc.enable()
        world = World()

        class Cycle:
            def __init__(self, name):
                self.name, self.cycle = name, self

            def __del__(self):
                world.events.append({'event': self.name, 'phase': world.phase})

        # A finalizer immediately before helper entry belongs to the primary
        # record and retains the pre-seal phase.
        gc.disable()
        before = Cycle('before-entry.delete')
        del before
        gc.enable()
        gc.collect()
        self.assertEqual(world.events[-1], {
            'event': 'before-entry.delete', 'phase': 'retained-traceback-release'})
        real_enable = gc.enable

        def enable_and_collect():
            real_enable()
            gc.collect()

        def copy_json(value):
            self.assertFalse(gc.isenabled())
            result = json.loads(json.dumps(value))
            if 'alive_at_seal' in value:
                after = Cycle('after-copy.delete')
                del after
            return result

        namespace = {'copy_json': copy_json,
                     'canonical': lambda value: json.dumps(value).encode('ascii'),
                     'json': json}
        bind_snapshot_functions(namespace)
        first = namespace['_HIA_OBSERVER_CAPTURE_CONSUMER'](world, {})
        with patch.object(gc, 'enable', side_effect=enable_and_collect):
            final = namespace['_HIA_OBSERVER_CAPTURE_FINAL'](world, {}, first)
        self.assertTrue(gc.isenabled())
        self.assertEqual(final['events'], [
            {'event': 'consumer.end'},
            {'event': 'before-entry.delete', 'phase': 'retained-traceback-release'}])
        late = world.events[world.sealed_event_count:]
        self.assertEqual(late, [{'event': 'after-copy.delete', 'phase': 'case-sealed'}])
        self.assertEqual(final['events'] + late, world.events)

    def test_reader_rejects_mixed_revision_and_implementation_pin(self):
        from tools.read_hia_slot_mechanical_observations import admit_capture_revision
        name = 'tests/hia_slot_observer_capture.py'
        implementation = {'bytes': 123, 'sha256': 'a' * 64}
        capture = {'version': 'deferred-json-snapshots-v3', 'changed_snapshot_expressions': 2,
                   'changed_seal_statements': 2, 'changed_product_expressions': 0,
                   'changed_case_inputs': 0,
                   'consumer_representation': 'canonical-json-bytes',
                   'implementation': {'path': name, **implementation}}
        report = {'original_observer_definitions_or_cases_modified': True,
                  'observer_capture': capture}
        runtime = {'argv': ['observer.py', '--capture-version', 'deferred-json-snapshots-v3']}
        pins = {name: implementation}
        admit_capture_revision(report, runtime, pins, 'deferred-json-snapshots-v3')
        for changed_report, changed_runtime, changed_pins, version in (
            (report, runtime, pins, 'original-v1'),
            (report, {'argv': ['observer.py']}, pins, 'deferred-json-snapshots-v3'),
            (report, runtime, {name: {'bytes': 123, 'sha256': 'b' * 64}}, 'deferred-json-snapshots-v3'),
            ({**report, 'observer_capture': {**capture, 'changed_seal_statements': 0}},
             runtime, pins, 'deferred-json-snapshots-v3'),
        ):
            with self.assertRaises(ValueError):
                admit_capture_revision(changed_report, changed_runtime, changed_pins, version)
        original = {'original_observer_definitions_or_cases_modified': False,
                    'observer_capture': {'version': 'original-v1',
                        'changed_snapshot_expressions': 0, 'changed_seal_statements': 0,
                        'changed_product_expressions': 0, 'changed_case_inputs': 0}}
        admit_capture_revision(original, {'argv': ['observer.py']}, pins, 'original-v1')
        with self.assertRaises(ValueError):
            admit_capture_revision(original, runtime, pins, 'original-v1')


if __name__ == '__main__':
    unittest.main()
