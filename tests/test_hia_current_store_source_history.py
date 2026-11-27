"""Actual captures and explicit prior views for the current Store source domain.

These source controls stage verified fixture bytes. They execute no product
and do not claim that a source projection is a production build.
"""
from copy import deepcopy
from hashlib import sha256
import ast
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from tools import hia_current_store_source_history as current
from tools import hia_frozen_component_sources as frozen
from tools import hia_evaluation_window_history as window
from tools import hia_evaluation_cold_source_history as cold

ROOT = Path(__file__).resolve().parents[1]
DEPENDENCIES = (
    current.SELF, current.WINDOW_HELPER, window.FIXTURE, current.ENGINE,
    frozen.SOURCE_HISTORY_FIXTURE, frozen.HOST_SUPPORT, frozen.EVALUATION_QUALIFIER,
    current.COLD_HELPER, current.COLD_FIXTURE,
)
PATHS = (*frozen.CURRENT, *DEPENDENCIES, frozen.FIXTURE)


COMPOSITION_FIXTURE = 'tests/fixtures/hia_current_store_evaluation_cold_v1.json'
COMPOSITION_PIN = {"bytes":10114,"sha256":"1b2cea5f51d3f023f02ea7f64f3e07cc86b7aaa1995ebaa4a95c506a7ec7ce4c"}
COMPOSITION_LEGACY_PATHS = {'tools/hia_current_store_source_history.py',
                            'tests/test_hia_store_source_history.py'}
COMPOSITION_PATHS = COMPOSITION_LEGACY_PATHS | {'tools/read_hia_store_file_capture_callers.py'}


def composition_predecessor(name, physical):
    from tools import hia_current_store_broad_cold_preparation as preparation
    original_physical = physical
    physical = preparation.predecessor(name, physical, root=ROOT)
    if name == 'tools/read_hia_store_file_capture_callers.py':
        return preparation.consumer_predecessor(name, physical, root=ROOT)
    path = ROOT / COMPOSITION_FIXTURE
    raw = path.read_bytes()
    if current.pin(raw) != COMPOSITION_PIN:
        raise ValueError('current Store evaluation composition authority differs')
    value = json.loads(raw)
    if (value.get('schema') != 'hepta.hia.current-store-evaluation-cold-composition.v1'
            or value.get('original_sixteen_test_methods_modified') is not False
            or value.get('original_fixed_fixtures_modified') is not False
            or value.get('prior_projection_is_physical_source') is not False
            or set(value.get('files', {})) != COMPOSITION_LEGACY_PATHS):
        raise ValueError('current Store evaluation composition scope differs')
    row = value['files'][name]
    reviewed = frozen.history_inverse(physical, row,
        {'bytes': row['old_bytes'], 'sha256': row['old_sha256']})
    if path.read_bytes() != raw or (ROOT / name).read_bytes() != original_physical:
        raise ValueError('current Store evaluation composition changed during readback')
    return reviewed


def forward(raw, row):
    if current.pin(raw) != row['original']:
        raise ValueError('fixture forward input is not its complete original')
    rebuilt = raw
    for hunk in reversed(row['hunks']):
        at = hunk['old_offset']
        before, after = bytes.fromhex(hunk['old_hex']), bytes.fromhex(hunk['new_hex'])
        if rebuilt[at:at + len(before)] != before:
            raise ValueError('fixture forward splice differs')
        rebuilt = rebuilt[:at] + after + rebuilt[at + len(before):]
    if current.pin(rebuilt) != row['current']:
        raise ValueError('fixture forward result is not its complete current')
    return rebuilt


class CurrentStoreSourceCompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.live = {name: (ROOT / name).read_bytes() for name in PATHS}
        cls.previous = dict(cls.live)
        group = {name: cls.live[name] for name in frozen.CURRENT}
        if all(current.pin(group[name]) == identity
               for name, identity in current.PHYSICAL_CURRENT.items()):
            group, cold_history = cold.prepare(ROOT, group)
            projected, history = window.prepare(ROOT, group, take=cold_history['prior_take'])
            cls.previous.update(projected)
            window.verify_unchanged(history)
            cold.verify_unchanged(cold_history)
        if any(current.pin(cls.previous[name]) != identity
               for name, identity in frozen.CURRENT.items()):
            raise ValueError('source controls require the complete current or prior five-file group')
        value = json.loads(cls.live[window.FIXTURE])
        cls.successor = dict(cls.previous)
        for name, row in value['files'].items():
            cls.successor[name] = forward(cls.previous[name], row)
        value = json.loads(cls.live[cold.FIXTURE])
        for name, row in value['files'].items():
            cls.successor[name] = forward(cls.successor[name], row)

    @classmethod
    def tearDownClass(cls):
        for name, raw in cls.live.items():
            if (ROOT / name).read_bytes() != raw:
                raise AssertionError('source controls changed actual repository bytes: ' + name)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hia-current-store-source-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stage(self.successor)

    def stage(self, sources):
        for name, raw in sources.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    def captured(self):
        return {name: (self.root / name).read_bytes() for name in frozen.CURRENT}

    def test_complete_current_group_keeps_physical_and_prior_capture_views_distinct(self):
        physical = self.captured()
        restored, history = current.restore(physical, root=self.root)
        self.assertEqual({name: current.pin(restored[name]) for name in frozen.CURRENT},
                         frozen.PREDECESSORS)
        self.assertEqual(history['review']['complete_current'], current.PHYSICAL_CURRENT)
        self.assertEqual(history['review']['prior_source_history_review']['complete_current'],
                         frozen.CURRENT)
        self.assertFalse(history['review']['physical_capture_rewritten'])
        self.assertFalse(history['review']['prior_projection_is_physical_source'])
        for name, raw in physical.items():
            self.assertEqual(history['captures'][name], raw)
            self.assertEqual(current.pin(history['prior_history']['captures'][name]),
                             frozen.CURRENT[name])
        self.assertTrue(history['review']['terminal_reread_identical'])
        current.verify_unchanged(history)

    def test_every_single_current_member_requires_and_restores_the_complete_group(self):
        for name in frozen.CURRENT:
            with self.subTest(path=name):
                restored, history = current.restore(
                    {name: self.successor[name]}, root=self.root)
                self.assertEqual({key: current.pin(restored[key]) for key in frozen.CURRENT},
                                 frozen.PREDECESSORS)
                self.assertEqual(history['review']['complete_current'], current.PHYSICAL_CURRENT)
                self.assertEqual(set(history['captures']) & set(frozen.CURRENT), set(frozen.CURRENT))

    def test_each_missing_changed_or_partially_reverted_member_is_refused(self):
        for name in frozen.CURRENT:
            target = self.root / name
            modes = ('missing', 'changed', 'prior') if name in current.WINDOW_CURRENT else ('missing', 'changed')
            for mode in modes:
                with self.subTest(path=name, mode=mode):
                    if mode == 'missing':
                        target.unlink()
                    else:
                        target.write_bytes(self.successor[name] + b'\n'
                            if mode == 'changed' else self.previous[name])
                    try:
                        # Pass the caller's original exact captures as well as
                        # the physical selected root; neither can substitute for the other.
                        with self.assertRaises((ValueError, OSError)):
                            current.restore({key: self.successor[key] for key in frozen.CURRENT},
                                            root=self.root)
                    finally:
                        target.write_bytes(self.successor[name])

    def test_every_required_reader_and_authority_is_bound_to_its_complete_bytes(self):
        for name in DEPENDENCIES:
            target = self.root / name
            for missing in (False, True):
                with self.subTest(path=name, missing=missing):
                    if missing:
                        target.unlink()
                    else:
                        target.write_bytes(self.successor[name] + b'\n')
                    try:
                        with self.assertRaises((ValueError, OSError)):
                            current.restore(self.captured(), root=self.root)
                    finally:
                        target.write_bytes(self.successor[name])

    def test_reader_restores_current_caller_and_preserves_caller_only_original_domain(self):
        saved = {}
        def take(path):
            raw = path.read_bytes()
            saved[path] = raw
            return raw
        raw = self.successor[frozen.EVALUATION_TEST]
        reviewed = current.reviewed_source(self.root, frozen.EVALUATION_TEST, raw, take=take)
        self.assertEqual(current.pin(reviewed)['sha256'],
                         '673b1e330b48df5915a4a544188397e33055ac023986cb136e8b067e4574b9d3')
        self.assertTrue({self.root / name for name in frozen.CURRENT} <= set(saved))
        self.assertEqual(saved[self.root / frozen.EVALUATION_TEST], raw)
        prior, history = current.restore(self.captured(), root=self.root)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture = root / frozen.FIXTURE
            fixture.parent.mkdir(parents=True)
            fixture.write_bytes(self.successor[frozen.FIXTURE])
            observed = []
            def old_take(path):
                observed.append(path)
                return path.read_bytes()
            self.assertEqual(current.reviewed_source(root, frozen.EVALUATION_TEST,
                prior[frozen.EVALUATION_TEST], take=old_take), reviewed)
            self.assertNotIn(root / window.FIXTURE, observed)
        current.verify_unchanged(history)

    def test_prior_complete_group_requires_no_new_reader_or_fixture(self):
        self.stage(self.previous)
        for name in (current.SELF, current.WINDOW_HELPER, window.FIXTURE):
            (self.root / name).unlink()
        restored, history = current.restore(self.captured(), root=self.root)
        self.assertEqual({name: current.pin(restored[name]) for name in frozen.CURRENT},
                         frozen.PREDECESSORS)
        self.assertEqual(history['review']['schema'], 'hepta.hia.store-source-history-review.v2')
        self.assertNotIn('evaluation_window_review', history['review'])
        current.verify_unchanged(history)

    def test_each_physical_capture_is_rechecked_after_the_older_reader_returns(self):
        original_restore = frozen.restore
        names = (*frozen.CURRENT, *DEPENDENCIES)
        for name in names:
            late = [False]
            def restored(*args, **kwargs):
                result = original_restore(*args, **kwargs)
                late[0] = True
                return result
            def take(path):
                raw = path.read_bytes()
                return raw + b'\n' if late[0] and path == self.root / name else raw
            with self.subTest(path=name), patch.object(frozen, 'restore', restored):
                with self.assertRaises(ValueError):
                    current.restore(self.captured(), root=self.root, take=take)

    def test_changed_review_cannot_relabel_actual_physical_captures(self):
        _, history = current.restore(self.captured(), root=self.root)
        before = deepcopy(history['review'])
        for changed in (
                {**before, 'complete_current': deepcopy(frozen.CURRENT)},
                {**before, 'physical_capture_rewritten': 0},
                {**before, 'prior_projection_is_physical_source': 0},
                {**before, 'schema': 'hepta.hia.store-source-history-review.v2'}):
            history['review'] = changed
            with self.assertRaises(ValueError):
                current.verify_unchanged(history)
        history['review'] = before
        current.verify_unchanged(history)
        unchanged, proof = current.restore({'hepta/hia_agent_service.py': b'unknown source'},
            root=self.root, take=lambda path: self.fail('unknown bytes borrowed an authority'))
        self.assertEqual(unchanged, {'hepta/hia_agent_service.py': b'unknown source'})
        self.assertIsNone(proof)

    def test_fresh_reader_imports_no_product_tests_builder_generator_or_oracle(self):
        script = """import importlib.abc,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname in ('hepta','tests') or fullname.startswith(('hepta.','tests.','tools.build_','tools.generate_')) or 'oracle' in fullname:
            raise AssertionError(fullname)
sys.meta_path.insert(0,Guard())
from tools import hia_current_store_source_history as current
root=Path(sys.argv[2]);name='tests/test_hia_evaluation_native.py'
result=current.reviewed_source(root,name,(root/name).read_bytes())
assert current.pin(result)['sha256']=='673b1e330b48df5915a4a544188397e33055ac023986cb136e8b067e4574b9d3'
"""
        proc = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(ROOT), str(self.root)],
                              capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_fixed_consumer_relation_keeps_all_sixteen_original_test_methods(self):
        fixture = ROOT / 'tests/fixtures/hia_current_store_consumers_v1.json'
        raw = fixture.read_bytes()
        self.assertEqual({'bytes': len(raw), 'sha256': sha256(raw).hexdigest()},
                         {"bytes":6157,"sha256":"842f695e691c4e17b045fe691474c47b20737f42e6a87bec2524513a793b01c8"})
        value = json.loads(raw)
        self.assertEqual(value['schema'], 'hepta.hia.current-store-consumer-source-history.v1')
        self.assertIs(value['retained_engine_modified'], False)
        self.assertIs(value['original_sixteen_test_methods_modified'], False)
        self.assertIs(value['whole_native_delivery_qualified'], False)
        self.assertEqual(set(value['files']), {
            'tests/hia_store_source_history.py', 'tests/test_hia_store_source_history.py',
            'tools/read_hia_store_file_capture_callers.py'})
        for name, row in value['files'].items():
            physical = (ROOT / name).read_bytes()
            reviewed = (composition_predecessor(name, physical)
                        if name in COMPOSITION_PATHS else physical)
            if name == 'tools/read_hia_store_file_capture_callers.py':
                core_path = ROOT / 'tests/fixtures/hia_current_store_core_reader_v1.json'
                core_raw = core_path.read_bytes()
                self.assertEqual({'bytes': len(core_raw), 'sha256': sha256(core_raw).hexdigest()},
                                 {"bytes":8315,"sha256":"09aa48b2a4304b80e9999819d2364e28fd4db94dfa0947b236550c261b88afb0"})
                core = json.loads(core_raw)
                self.assertEqual(core['schema'], 'hepta.hia.current-store-core-reader-source-history.v1')
                self.assertIs(core['original_source_history_fixtures_modified'], False)
                self.assertIs(core['original_callers_and_limits_modified'], False)
                self.assertIs(core['whole_native_delivery_qualified'], False)
                self.assertEqual(set(core['files']), {name})
                reviewed = frozen.history_inverse(reviewed, core['files'][name],
                    {'bytes': row['new_bytes'], 'sha256': row['new_sha256']})
                self.assertEqual(core_path.read_bytes(), core_raw)
            prior = frozen.history_inverse(reviewed, row,
                {'bytes': row['old_bytes'], 'sha256': row['old_sha256']})
            if name == 'tests/test_hia_store_source_history.py':
                def methods(source):
                    return {node.name: ast.dump(node, include_attributes=False)
                            for cls in ast.parse(source).body if isinstance(cls, ast.ClassDef)
                            for node in cls.body if isinstance(node, ast.FunctionDef)
                            and node.name.startswith('test_')}
                self.assertEqual(len(methods(prior)), 16)
                self.assertEqual(methods(prior), methods(physical))
            self.assertEqual((ROOT / name).read_bytes(), physical)
        self.assertEqual(fixture.read_bytes(), raw)


    def test_readback_preparation_keeps_original_test_ids_assertions_and_method_bodies(self):
        path = ROOT / 'tests/fixtures/hia_current_store_readback_preparation_v1.json'
        raw = path.read_bytes()
        self.assertEqual({'bytes': len(raw), 'sha256': sha256(raw).hexdigest()},
                         {"bytes":3245,"sha256":"ae4fdf817db1b65b243e837be948262d33dc739b3fa82d67b35c3ba1696a14c5"})
        value = json.loads(raw)
        self.assertEqual(value['schema'], 'hepta.hia.current-store-readback-preparation-history.v1')
        self.assertIs(value['original_test_assertions_and_ids_modified'], False)
        self.assertIs(value['original_fixed_fixtures_modified'], False)
        self.assertIs(value['historical_projection_is_physical_source'], False)
        self.assertEqual(set(value['files']), {
            'tools/hia_current_store_source_history.py',
            'tests/test_hia_caller_terminal_readback.py',
            'tests/test_hia_store_file_capture_native_readback.py'})
        for name, row in value['files'].items():
            physical = (ROOT / name).read_bytes()
            reviewed = (composition_predecessor(name, physical)
                        if name in COMPOSITION_PATHS else physical)
            original = frozen.history_inverse(reviewed, row,
                {'bytes': row['old_bytes'], 'sha256': row['old_sha256']})
            if name.startswith('tests/'):
                def methods(source):
                    return {cls.name + '.' + node.name: node
                            for cls in ast.parse(source).body if isinstance(cls, ast.ClassDef)
                            for node in cls.body if isinstance(node, ast.FunctionDef)}
                before, after = methods(original), methods(physical)
                self.assertEqual(set(before), set(after))
                for key in before:
                    previous = before[key]
                    if key == 'FileCaptureCurrentSourceTests.test_actual_complete_reader_refuses_mixed_evaluation_root':
                        count = 0
                        for node in ast.walk(previous):
                            if (isinstance(node, ast.Attribute) and node.attr == 'restore'
                                    and isinstance(node.value, ast.Name) and node.value.id == 'history'):
                                node.value.id = 'current_history'
                                count += 1
                        self.assertEqual(count, 1)
                    self.assertEqual(ast.dump(previous, include_attributes=False),
                                     ast.dump(after[key], include_attributes=False), key)
            self.assertEqual((ROOT / name).read_bytes(), physical)
        self.assertEqual(path.read_bytes(), raw)


if __name__ == '__main__':
    unittest.main()
