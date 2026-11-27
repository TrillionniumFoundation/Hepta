"""Exact-source and capture controls for strict caller cold-selection history."""
import ast
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tests import hia_cold_caller_selection_history as history

ROOT = Path(__file__).resolve().parents[1]


class ColdCallerSelectionHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.hia_scoped_selection_original_fixture import install_class_view
        install_class_view(cls, globals(), subjects=(history,))

    def source(self, name):
        return (ROOT / name).read_bytes()

    def fixture(self):
        return (ROOT / history.FIXTURE).read_bytes()

    def test_all_seven_complete_predecessors_and_original_definitions_are_exact(self):
        self.assertEqual(len(history.EXPECTED), 7)
        for name, expected in history.EXPECTED.items():
            current = self.source(name)
            original, proof = history.reviewed(name, current)
            self.assertEqual(history.pin(current), history.current_pin(name), name)
            self.assertEqual(history.pin(original), expected['old'], name)
            self.assertEqual(proof['exact_selection_splices'], 2)
            self.assertFalse(proof['whole_native_delivery_qualified'])
            definitions = lambda raw: [(type(node).__name__, node.name)
                for node in ast.walk(ast.parse(raw))
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
            selection, _, _ = history._integrated_predecessor(name, current, ROOT, Path.read_bytes)
            self.assertEqual(definitions(original), definitions(selection), name)

    def test_an_unknown_source_byte_cannot_borrow_the_original_full_file_pin(self):
        for name, expected in history.EXPECTED.items():
            raw = self.source(name)
            for changed in (raw + b'# unreviewed\n', b'# unreviewed\n' + raw,
                            raw[:len(raw) // 2] + b' ' + raw[len(raw) // 2:]):
                restored, proof = history.reviewed(name, changed,
                    take=lambda path: self.fail('unknown source attempted an authority read'))
                self.assertIsNone(proof)
                self.assertEqual(restored, changed)
                self.assertNotEqual(history.pin(restored), expected['old'])

    def test_earlier_and_unrelated_sources_keep_their_original_authorities(self):
        name = 'tools/qualify_hia_emission_callers.py'
        original = history.predecessor(name, self.source(name))
        for selected, raw in ((name, original), ('unrelated.py', b'original\n')):
            restored, proof = history.reviewed(selected, raw,
                take=lambda path: self.fail('old source borrowed a new authority'))
            self.assertEqual(restored, raw)
            self.assertIsNone(proof)
        with self.assertRaises(ValueError):
            history.reviewed(name, False)

    def test_explicit_reader_root_and_captures_are_used_for_the_entire_fixture(self):
        name = 'tools/qualify_hia_emission_callers.py'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / history.FIXTURE
            path.parent.mkdir(parents=True)
            path.write_bytes(self.fixture())
            captured = []
            def take(selected):
                captured.append(selected)
                return selected.read_bytes()
            original, proof = history.reviewed(name, self.source(name), root=root, take=take)
            self.assertEqual(captured, [path, path])
            self.assertEqual(history.pin(original), history.EXPECTED[name]['old'])
            path.write_bytes(self.fixture() + b' ')
            with self.assertRaises(ValueError):
                history.reviewed(name, self.source(name), root=root, take=take)

    def test_fixture_change_after_first_capture_is_refused(self):
        name = 'tools/qualify_hia_emission_callers.py'
        calls = []
        def take(path):
            calls.append(path)
            return self.fixture() if len(calls) == 1 else b'changed'
        with self.assertRaises(ValueError):
            history.reviewed(name, self.source(name), root=Path('/independent-source'), take=take)
        self.assertEqual(len(calls), 2)

    def test_rebound_fixture_cannot_change_the_fixed_whole_source_pins(self):
        name = 'tools/qualify_hia_emission_callers.py'
        value = json.loads(self.fixture())
        value['files'][name]['old']['bytes'] += 1
        changed = (json.dumps(value, indent=2) + '\n').encode()
        with patch.object(history, 'FIXTURE_SHA256', sha256(changed).hexdigest()):
            with self.assertRaises(ValueError):
                history.reviewed(name, self.source(name), take=lambda path: changed)

    def test_invalid_offsets_and_splice_bytes_never_recover_a_predecessor(self):
        name = 'tools/qualify_hia_emission_callers.py'
        for value in (False, -1, 1 << 30):
            fixture = json.loads(self.fixture())
            fixture['files'][name]['hunks'][0]['new_offset'] = value
            changed = (json.dumps(fixture, indent=2) + '\n').encode()
            with patch.object(history, 'FIXTURE_SHA256', sha256(changed).hexdigest()):
                with self.assertRaises(ValueError):
                    history.reviewed(name, self.source(name), take=lambda path: changed)
        fixture = json.loads(self.fixture())
        fixture['files'][name]['hunks'][0]['old_hex'] = '00'
        changed = (json.dumps(fixture, indent=2) + '\n').encode()
        with patch.object(history, 'FIXTURE_SHA256', sha256(changed).hexdigest()):
            with self.assertRaises(ValueError):
                history.reviewed(name, self.source(name), take=lambda path: changed)

    def test_actual_source_adjustment_preserves_the_prior_review(self):
        for name, expected in history.EXPECTED.items():
            raw = self.source(name)
            original, proof = history.reviewed(name, raw)
            prior = {'path': name, 'current_bytes': len(original),
                     'current_sha256': sha256(original).hexdigest(),
                     'original_sha256': '0' * 64, 'original_bytes': 123,
                     'original_methods_budgets_and_order_unchanged': True}
            current = history.bind_adjustment(prior, raw, proof)
            self.assertEqual(current['current_bytes'], len(raw))
            self.assertEqual(current['current_sha256'], history.current_pin(name)['sha256'])
            self.assertEqual(current['original_sha256'], prior['original_sha256'])
            self.assertEqual(current['original_bytes'], prior['original_bytes'])
            self.assertTrue(current['original_methods_budgets_and_order_unchanged'])
            with self.assertRaises(ValueError):
                history.bind_adjustment(prior, raw + b' ', proof)

    def test_source_adjustment_refuses_a_different_or_missing_path(self):
        names = tuple(history.EXPECTED)
        for name in names:
            raw = self.source(name)
            original, proof = history.reviewed(name, raw)
            prior = {'path': name, 'current_bytes': len(original),
                     'current_sha256': sha256(original).hexdigest()}
            for other in names:
                if other != name:
                    with self.assertRaises(ValueError):
                        history.bind_adjustment({**prior, 'path': other}, raw, proof)
            for changed in ({key: value for key, value in prior.items() if key != 'path'},
                            {**prior, 'path': False}, {**prior, 'path': '../' + name}):
                with self.assertRaises(ValueError):
                    history.bind_adjustment(changed, raw, proof)

    def test_fresh_reader_imports_no_product_builder_generator_or_oracle(self):
        script = """import importlib.abc,sys
sys.path.insert(0,sys.argv[1])
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='hepta' or fullname.startswith(('hepta.','tools.build_','tools.generate_')) or 'oracle' in fullname:
            raise AssertionError(fullname)
sys.meta_path.insert(0,Guard())
from tests import hia_cold_caller_selection_history as history
for name in history.EXPECTED:
    raw=(history.ROOT/name).read_bytes()
    assert history.predecessor(name,raw)!=raw
"""
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(ROOT)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
