"""Original Store source gates plus explicit broad-cold physical custody controls."""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import ast
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from tools import hia_current_store_source_history as current
from tools import hia_current_store_broad_cold_preparation as preparation
from tools import hia_native_cold_caller_history as broad
from tools import hia_frozen_component_sources as frozen
from tests import test_hia_current_store_source_history as original_controls

ROOT = Path(__file__).resolve().parents[1]
GENERIC = 'tests/test_hia_store_file_capture_native.py'
GENERIC_REVIEWED = {
    'bytes': 14447, 'sha256': '89abd068044dae5fe3900d3c5888310b9352871e383e0e542a1f4687b5bb8e10',
}
NEW_DEPENDENCIES = (current.BROAD_HELPER, broad.SOURCE, broad.FIXTURE, broad.PREVIOUS_FIXTURE)


def original_consumer_source(name):
    from tools import hia_native_cold_composition_history as composition
    physical = (ROOT / name).read_bytes()
    if current.pin(physical) == composition.CURRENT[name]:
        projected, history = composition.prepare(ROOT, {name: physical})
        composition.verify_unchanged(history)
        return projected[name]
    if current.pin(physical) != composition.PREVIOUS[name]:
        raise ValueError('source controls require an exact consumer source domain')
    return physical


class CurrentStoreBroadColdTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original_controls.CurrentStoreSourceCompositionTests.setUpClass()
        cls.old = dict(original_controls.CurrentStoreSourceCompositionTests.previous)
        cls.window = dict(original_controls.CurrentStoreSourceCompositionTests.successor)
        cls.seed = preparation.staged_inputs(root=ROOT)
        cls.extra = {name: (ROOT / name).read_bytes() for name in NEW_DEPENDENCIES}
        cls.base = {**cls.old, **cls.extra, **cls.seed}
        if {name: current.pin(cls.base[name]) for name in frozen.CURRENT} != current.BASE_COLD_CURRENT:
            raise ValueError('cold controls did not stage the complete independent five-file input')

    @classmethod
    def tearDownClass(cls):
        original_controls.CurrentStoreSourceCompositionTests.tearDownClass()
        for name, raw in cls.extra.items():
            if (ROOT / name).read_bytes() != raw:
                raise AssertionError('cold controls changed an actual authority: ' + name)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hia-store-broad-cold-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stage(self.base)

    def stage(self, data):
        for name, raw in data.items():
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(raw)

    def captured(self):
        return {name: (self.root / name).read_bytes() for name in frozen.CURRENT}

    def test_base_complete_group_projects_only_evaluation_before_original_store_group(self):
        physical = self.captured()
        restored, history = current.restore(physical, root=self.root)
        self.assertEqual({n: current.pin(restored[n]) for n in frozen.CURRENT}, frozen.PREDECESSORS)
        self.assertEqual(history['review']['complete_current'], current.BASE_COLD_CURRENT)
        self.assertEqual(history['prior_history']['review']['complete_current'], frozen.CURRENT)
        self.assertEqual(history['review']['schema'], current.BASE_COLD_SCHEMA)
        self.assertEqual(history['review']['actual_physical_current'], current.BASE_COLD_CURRENT)
        self.assertEqual(history['review']['historical_current_inputs'], frozen.CURRENT)
        self.assertEqual(set(history['review']['native_cold_caller_sources']), {frozen.EVALUATION_TEST})
        native = history['base_cold_view']['native_cold_history']
        self.assertEqual(set(native['review']['native_cold_caller_sources']), {frozen.EVALUATION_TEST})
        self.assertNotIn('hepta/hia_agent_service.py', native['captures'])
        self.assertEqual(current.pin(history['captures']['hepta/hia_agent_service.py']),
                         frozen.CURRENT['hepta/hia_agent_service.py'])
        self.assertEqual(current.pin(history['prior_history']['captures']['hepta/hia_agent_service.py']),
                         frozen.CURRENT['hepta/hia_agent_service.py'])
        for name, raw in physical.items():
            self.assertEqual(history['captures'][name], raw)
        self.assertEqual(physical, self.captured())
        current.verify_unchanged(history)

    def test_every_single_base_member_requires_the_same_complete_physical_group(self):
        for name in frozen.CURRENT:
            with self.subTest(path=name):
                restored, history = current.restore({name: self.base[name]}, root=self.root)
                self.assertEqual({n: current.pin(restored[n]) for n in frozen.CURRENT}, frozen.PREDECESSORS)
                self.assertEqual(history['review']['complete_current'], current.BASE_COLD_CURRENT)
                self.assertEqual(set(history['captures']) & set(frozen.CURRENT), set(frozen.CURRENT))

    def test_base_group_missing_changed_and_mixed_current_window_sources_are_rejected(self):
        physical = self.captured()
        for name in frozen.CURRENT:
            original = self.base[name]
            cases = [None, original + b'\n']
            if self.window[name] != original:
                cases.append(self.window[name])
            for raw in cases:
                with self.subTest(path=name, mode='missing' if raw is None else current.pin(raw)):
                    p = self.root / name
                    p.unlink() if raw is None else p.write_bytes(raw)
                    try:
                        with self.assertRaises((ValueError, OSError)):
                            current.restore(physical, root=self.root)
                    finally:
                        p.write_bytes(original)

    def test_base_reader_preserves_physical_captures_and_reaches_original_reviewed_file(self):
        seen = {}
        def take(path):
            raw = path.read_bytes()
            seen[path] = raw
            return raw
        reviewed = current.reviewed_source(
            self.root, frozen.EVALUATION_TEST, self.base[frozen.EVALUATION_TEST], take=take)
        self.assertEqual(current.pin(reviewed)['sha256'],
                         '673b1e330b48df5915a4a544188397e33055ac023986cb136e8b067e4574b9d3')
        for name in frozen.CURRENT:
            self.assertEqual(seen[self.root / name], self.base[name])

    def test_nonproduction_current_source_gets_explicit_prior_view_with_real_captures(self):
        observed = {}
        def take(path):
            raw = path.read_bytes()
            observed[path] = raw
            return raw
        reviewed = current.reviewed_source(self.root, GENERIC, self.base[GENERIC], take=take)
        self.assertEqual(current.pin(reviewed), GENERIC_REVIEWED)
        self.assertEqual(observed[self.root / GENERIC], self.base[GENERIC])
        self.assertNotEqual(observed[self.root / GENERIC], reviewed)
        self.assertEqual(observed[self.root / current.SELF], self.base[current.SELF])

    def test_generic_dependency_reader_never_projects_any_of_the_five_production_members(self):
        original = frozen.reviewed_source
        observed = {}
        def read(root, name, raw, *, take):
            for member in frozen.CURRENT:
                observed[member] = take(root / member)
            return original(root, name, raw, take=take)
        with patch.object(frozen, 'reviewed_source', read):
            result = current.reviewed_source(self.root, GENERIC, self.base[GENERIC])
        self.assertEqual(current.pin(result), GENERIC_REVIEWED)
        self.assertEqual(observed, self.captured())
        self.assertEqual(current.pin(observed['hepta/hia_agent_service.py']),
                         frozen.CURRENT['hepta/hia_agent_service.py'])

    def test_both_new_paths_bind_all_fixed_helpers_and_authorities_in_selected_root(self):
        names = (current.SELF, current.ENGINE, *NEW_DEPENDENCIES)
        for name in names:
            for operation in ('base', 'generic'):
                for missing in (False, True):
                    with self.subTest(path=name, operation=operation, missing=missing):
                        p = self.root / name
                        original = p.read_bytes()
                        p.unlink() if missing else p.write_bytes(original + b'\n')
                        try:
                            with self.assertRaises((ValueError, OSError)):
                                if operation == 'base':
                                    current.restore(self.captured(), root=self.root)
                                else:
                                    current.reviewed_source(self.root, GENERIC, self.base[GENERIC])
                        finally:
                            p.write_bytes(original)

    def test_original_group_still_needs_no_new_reader_or_new_authority(self):
        self.stage(self.old)
        for name in NEW_DEPENDENCIES:
            (self.root / name).unlink()
        (self.root / current.SELF).unlink()
        restored, history = current.restore(self.captured(), root=self.root)
        self.assertEqual({n: current.pin(restored[n]) for n in frozen.CURRENT}, frozen.PREDECESSORS)
        self.assertEqual(history['review']['schema'], 'hepta.hia.store-source-history-review.v2')
        current.verify_unchanged(history)

    def test_current_active_window_group_remains_separate_from_base_cold_history(self):
        self.stage(self.window)
        for name in NEW_DEPENDENCIES:
            (self.root / name).unlink()
        restored, history = current.restore(self.captured(), root=self.root)
        self.assertEqual({n: current.pin(restored[n]) for n in frozen.CURRENT}, frozen.PREDECESSORS)
        self.assertEqual(history['review']['complete_current'], current.PHYSICAL_CURRENT)
        self.assertNotIn('base_cold_view', history)
        current.verify_unchanged(history)

    def test_supplied_old_view_cannot_substitute_for_actual_new_base_capture(self):
        physical = self.captured()
        for name in (frozen.EVALUATION_TEST, 'hepta/hia_agent_service.py'):
            supplied = dict(physical)
            supplied[name] = self.old[name] if name == frozen.EVALUATION_TEST else b'unknown'
            with self.subTest(path=name), self.assertRaises(ValueError):
                current.restore(supplied, root=self.root)

    def test_base_late_source_or_authority_change_after_original_restore_is_rejected(self):
        original_restore = frozen.restore
        for name in (*frozen.CURRENT, current.SELF, current.ENGINE, *NEW_DEPENDENCIES,
                     frozen.SOURCE_HISTORY_FIXTURE, frozen.HOST_SUPPORT, frozen.EVALUATION_QUALIFIER):
            p = self.root / name
            original = p.read_bytes()
            def restored(*args, **kwargs):
                result = original_restore(*args, **kwargs)
                p.write_bytes(original + b'\n')
                return result
            try:
                with self.subTest(path=name), patch.object(frozen, 'restore', restored):
                    with self.assertRaises(ValueError):
                        current.restore(self.captured(), root=self.root)
            finally:
                p.write_bytes(original)

    def test_generic_late_source_or_authority_change_after_original_reader_is_rejected(self):
        original_read = frozen.reviewed_source
        for name in (GENERIC, current.SELF, current.ENGINE, *NEW_DEPENDENCIES, frozen.FIXTURE):
            p = self.root / name
            original = p.read_bytes()
            def read(*args, **kwargs):
                result = original_read(*args, **kwargs)
                p.write_bytes(original + b'\n')
                return result
            try:
                with self.subTest(path=name), patch.object(frozen, 'reviewed_source', read):
                    with self.assertRaises(ValueError):
                        current.reviewed_source(self.root, GENERIC, self.base[GENERIC])
            finally:
                p.write_bytes(original)

    def test_base_review_cannot_relabel_physical_sources_or_boolean_claims(self):
        _, history = current.restore(self.captured(), root=self.root)
        original = deepcopy(history['review'])
        for change in (
                {'complete_current': deepcopy(frozen.CURRENT)},
                {'physical_capture_rewritten': 0},
                {'prior_projection_is_physical_source': 0},
                {'schema': current.SCHEMA}):
            history['review'] = {**deepcopy(original), **change}
            with self.assertRaises(ValueError):
                current.verify_unchanged(history)
        history['review'] = original
        current.verify_unchanged(history)
        proof = history['base_cold_view']['native_cold_history']['review']['native_cold_caller_sources'][frozen.EVALUATION_TEST]
        prior = proof['complete_current_replayed']
        proof['complete_current_replayed'] = 1
        history['review']['base_native_cold_review'] = deepcopy(
            history['base_cold_view']['native_cold_history']['review'])
        with self.assertRaises(ValueError):
            current.verify_unchanged(history)
        proof['complete_current_replayed'] = prior

    def test_other_roots_and_noncanonical_prior_paths_cannot_supply_authority(self):
        with tempfile.TemporaryDirectory() as folder:
            other = Path(folder)
            for name, raw in self.base.items():
                if name in NEW_DEPENDENCIES:
                    continue
                p = other / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(raw)
            with self.assertRaises((ValueError, OSError)):
                current.restore({frozen.EVALUATION_TEST: self.base[frozen.EVALUATION_TEST]}, root=other)
        original = frozen.reviewed_source
        def read(root, name, raw, *, take):
            take(root.parent / broad.FIXTURE)
            return original(root, name, raw, take=take)
        with patch.object(frozen, 'reviewed_source', read), self.assertRaises(ValueError):
            current.reviewed_source(self.root, GENERIC, self.base[GENERIC])

    def test_actual_module_change_after_import_before_first_restore_is_rejected(self):
        # The imported module and supplied root are the same isolated physical
        # file, so matching two newly-read disk copies cannot satisfy this test.
        script = """import sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from tools import hia_current_store_source_history as current
root=Path(sys.argv[1]);p=root/current.SELF
before=p.read_bytes();p.write_bytes(before+b'\\n# post-import mutation\\n')
try:
    current.restore({name:(root/name).read_bytes() for name in current.frozen.CURRENT},root=root)
except ValueError:
    pass
else:
    raise AssertionError('post-import source mutation was accepted')
finally:
    p.write_bytes(before)
result,history=current.restore({name:(root/name).read_bytes() for name in current.frozen.CURRENT},root=root)
current.verify_unchanged(history)
"""
        proc = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(self.root)],
                              capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_fresh_both_domain_reader_imports_no_products_tests_generators_or_oracles(self):
        script = """import importlib.abc,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname in ('hepta','tests') or fullname.startswith(('hepta.','tests.','tools.build_','tools.generate_')) or 'oracle' in fullname:
            raise AssertionError(fullname)
sys.meta_path.insert(0,Guard())
from tools import hia_current_store_source_history as current
root=Path(sys.argv[2])
for name,digest in [('tests/test_hia_evaluation_native.py','673b1e330b48df5915a4a544188397e33055ac023986cb136e8b067e4574b9d3'),('tests/test_hia_store_file_capture_native.py','89abd068044dae5fe3900d3c5888310b9352871e383e0e542a1f4687b5bb8e10')]:
    raw=(root/name).read_bytes()
    assert current.pin(current.reviewed_source(root,name,raw))['sha256']==digest
"""
        proc = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(ROOT), str(self.root)],
                              capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_new_preparation_restores_complete_old_files_and_original_method_bodies(self):
        for name, expected in preparation.PREVIOUS.items():
            raw = (ROOT / name).read_bytes()
            old = preparation.predecessor(name, raw, root=ROOT)
            self.assertEqual(current.pin(old), expected)
            self.assertEqual((ROOT / name).read_bytes(), raw)
            if name.startswith('tests/'):
                def methods(source):
                    return {cls.name+'.'+node.name: ast.dump(node, include_attributes=False)
                            for cls in ast.parse(source).body if isinstance(cls, ast.ClassDef)
                            for node in cls.body if isinstance(node, ast.FunctionDef)
                            and node.name.startswith('test_')}
                old_tree = ast.parse(old)
                changed = 0
                for node in ast.walk(old_tree):
                    if (isinstance(node, ast.Call) and len(node.args) >= 2
                            and ast.dump(node.args[1]) == ast.dump(ast.parse("core['files'][name]", mode='eval').body)
                            and isinstance(node.args[0], ast.Name) and node.args[0].id == 'physical'):
                        node.args[0].id = 'reviewed'
                        changed += 1
                self.assertEqual(changed, 1)
                self.assertEqual(methods(ast.unparse(old_tree)), methods(raw))
                self.assertEqual(len(methods(old)), 11)

    def test_preparation_missing_changed_late_or_other_root_authority_is_rejected(self):
        names = (preparation.SELF, preparation.FIXTURE, preparation.ENGINE, *preparation.CURRENT)
        sources = {name: (ROOT / name).read_bytes() for name in names}
        self.stage(sources)
        target = current.SELF
        for name in names:
            p = self.root / name
            original = sources[name]
            p.unlink()
            try:
                with self.subTest(path=name), self.assertRaises((ValueError, OSError)):
                    preparation.predecessor(target, sources[target], root=self.root)
            finally:
                p.write_bytes(original)
        original_inverse = frozen.history_inverse
        for name in names:
            p = self.root / name
            def inverse(*args, **kwargs):
                result = original_inverse(*args, **kwargs)
                p.write_bytes(sources[name] + b'\n')
                return result
            try:
                with self.subTest(late=name), patch.object(frozen, 'history_inverse', inverse):
                    with self.assertRaises(ValueError):
                        preparation.predecessor(target, sources[target], root=self.root)
            finally:
                p.write_bytes(sources[name])


    def test_integrated_consumer_uses_explicit_composition_before_older_reader(self):
        from tools import hia_native_cold_composition_history as composition
        name = preparation.CONSUMER
        old = original_consumer_source(name)
        self.assertEqual(current.pin(old), composition.PREVIOUS[name])
        fixture_raw = (ROOT / composition.FIXTURE).read_bytes()
        record = json.loads(fixture_raw)['files'][name]
        physical = old
        for hunk in reversed(record['hunks']):
            at = hunk['old_offset']
            before, after = bytes.fromhex(hunk['old_hex']), bytes.fromhex(hunk['new_hex'])
            self.assertEqual(physical[at:at+len(before)], before)
            physical = physical[:at] + after + physical[at+len(before):]
        self.assertEqual(current.pin(physical), composition.CURRENT[name])
        self.stage({name: physical, composition.SELF: (ROOT / composition.SELF).read_bytes(),
                    composition.FIXTURE: fixture_raw,
                    preparation.SELF: (ROOT / preparation.SELF).read_bytes(),
                    preparation.FIXTURE: (ROOT / preparation.FIXTURE).read_bytes()})
        seen = {}
        def take(path):
            raw = path.read_bytes()
            seen[path] = raw
            return raw
        result = current.reviewed_source(self.root, name, physical, take=take)
        self.assertEqual(result, old)
        self.assertEqual(seen[self.root / name], physical)
        self.stage({path: (ROOT / path).read_bytes() for path in preparation.CURRENT})
        self.assertEqual(preparation.consumer_predecessor(name, physical, root=self.root), old)

    def test_composition_selected_root_and_late_authority_changes_are_rejected(self):
        from tools import hia_native_cold_composition_history as composition
        name = preparation.CONSUMER
        old = original_consumer_source(name)
        record = json.loads((ROOT / composition.FIXTURE).read_bytes())['files'][name]
        physical = old
        for hunk in reversed(record['hunks']):
            at = hunk['old_offset'];before=bytes.fromhex(hunk['old_hex']);after=bytes.fromhex(hunk['new_hex'])
            physical = physical[:at] + after + physical[at+len(before):]
        self.stage({name: physical, composition.SELF: (ROOT / composition.SELF).read_bytes(),
                    composition.FIXTURE: (ROOT / composition.FIXTURE).read_bytes()})
        for member in (name, composition.SELF, composition.FIXTURE, current.SELF, current.ENGINE):
            p = self.root / member
            raw = p.read_bytes()
            p.unlink()
            try:
                with self.subTest(missing=member), self.assertRaises((ValueError, OSError)):
                    current.reviewed_source(self.root, name, physical)
            finally:
                p.write_bytes(raw)
            original_read = frozen.reviewed_source
            def read(*args, **kwargs):
                result = original_read(*args, **kwargs)
                p.write_bytes(raw + b'\n')
                return result
            try:
                with self.subTest(late=member), patch.object(frozen, 'reviewed_source', read):
                    with self.assertRaises(ValueError):
                        current.reviewed_source(self.root, name, physical)
            finally:
                p.write_bytes(raw)


if __name__ == '__main__':
    unittest.main()
