"""Negative controls for complete Store history and the actual data-only reader."""
from copy import deepcopy
from hashlib import sha256
import ast
import json
from pathlib import Path
import tempfile
import unittest

from tools import hia_frozen_component_sources as history
from tools.read_hia_store_file_capture_callers import Captures

ROOT = Path(__file__).resolve().parents[1]


class StoreSourceHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        names = (*history.CURRENT, history.SOURCE_HISTORY_FIXTURE,
                 history.HOST_SUPPORT, history.EVALUATION_QUALIFIER, history.FIXTURE)
        actual = {name: (ROOT / name).read_bytes() for name in names}
        from tools import hia_evaluation_window_history as window
        if any(history.history_pin(actual[name]) == expected
               for name, expected in window.CURRENT.items()):
            # These original sixteen controls exercise their unchanged v2
            # domain. Verify the actual successor first, then stage its
            # explicit prior bytes only in this test-owned historical fixture.
            from tools import hia_evaluation_cold_source_history as cold
            group = {name: actual[name] for name in history.CURRENT}
            group, cold_history = cold.prepare(ROOT, group)
            projected, composition = window.prepare(
                ROOT, group, take=cold_history['prior_take'])
            window.verify_unchanged(composition)
            cold.verify_unchanged(cold_history)
            actual.update(projected)
        for name in names:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(actual[name])
        self.current = {name: (self.root / name).read_bytes() for name in history.CURRENT}
        self.prior, self.review = history.restore(self.current, root=self.root)

    def write(self, name, raw):
        (self.root / name).write_bytes(raw)

    def reader(self, raw=None):
        captured = Captures()
        path = self.root / history.EVALUATION_TEST
        physical = captured.take(path) if raw is None else raw
        result = history.reviewed_source(self.root, history.EVALUATION_TEST, physical,
                                         take=captured.take)
        return result, captured

    def test_complete_five_files_restore_exact_git_predecessors(self):
        self.assertEqual({name: history.history_pin(self.prior[name]) for name in history.CURRENT},
                         history.PREDECESSORS)
        self.assertTrue(self.review['review']['terminal_reread_identical'])
        self.assertEqual(len(self.review['review']['exact_extracted_definitions']), 2)

    def test_actual_reader_restores_current_evaluation_and_captures_complete_group(self):
        result, captured = self.reader()
        self.assertEqual(sha256(result).hexdigest(),
                         '673b1e330b48df5915a4a544188397e33055ac023986cb136e8b067e4574b9d3')
        self.assertTrue({self.root / name for name in history.CURRENT} <= set(captured.raw))
        self.assertIn(self.root / history.HOST_SUPPORT, captured.raw)
        captured.unchanged()

    def test_each_partially_reverted_member_is_refused(self):
        for name in history.CURRENT:
            with self.subTest(name=name):
                self.write(name, self.prior[name])
                changed = {key: (self.root / key).read_bytes() for key in history.CURRENT}
                with self.assertRaises(ValueError):
                    history.restore(changed, root=self.root)
                self.write(name, self.current[name])

    def test_peer_mixed_old_evaluation_is_refused_by_actual_reader(self):
        self.write(history.EVALUATION_TEST, self.prior[history.EVALUATION_TEST])
        with self.assertRaisesRegex(ValueError, 'partially reverted'):
            self.reader()

    def test_each_missing_production_member_is_refused_by_actual_reader(self):
        for name in history.PRODUCTION_PATHS:
            with self.subTest(name=name):
                (self.root / name).unlink()
                with self.assertRaises(ValueError):
                    self.reader()
                self.write(name, self.current[name])

    def test_current_evaluation_cannot_borrow_caller_only_legacy_fixture(self):
        for name in history.PRODUCTION_PATHS:
            (self.root / name).unlink()
        with self.assertRaisesRegex(ValueError, 'lacks its production'):
            self.reader()

    def test_original_caller_only_fixture_remains_admitted(self):
        for name in history.PRODUCTION_PATHS:
            (self.root / name).unlink()
        self.write(history.EVALUATION_TEST, self.prior[history.EVALUATION_TEST])
        restored, captured = self.reader()
        self.assertEqual(sha256(restored).hexdigest(),
                         '673b1e330b48df5915a4a544188397e33055ac023986cb136e8b067e4574b9d3')
        captured.unchanged()

    def test_complete_predecessor_reader_keeps_production_capture_and_reread(self):
        for name in history.CURRENT:
            self.write(name, self.prior[name])
        _, captured = self.reader()
        self.assertTrue({self.root / name for name in history.PRODUCTION_PATHS} <= set(captured.raw))
        name = history.PRODUCTION_PATHS[0]
        self.write(name, self.prior[name] + b'\n')
        with self.assertRaises(ValueError):
            captured.unchanged()

    def test_unknown_old_production_cannot_borrow_legacy_evaluation(self):
        for name in history.PRODUCTION_PATHS:
            self.write(name, b'unknown source\n')
        self.write(history.EVALUATION_TEST, self.prior[history.EVALUATION_TEST])
        with self.assertRaisesRegex(ValueError, 'unreviewed predecessor'):
            self.reader()

    def test_each_complete_current_file_tamper_is_refused(self):
        for name in history.CURRENT:
            with self.subTest(name=name):
                self.write(name, self.current[name] + b'\n')
                with self.assertRaises(ValueError):
                    self.reader()
                self.write(name, self.current[name])

    def test_fixed_fixture_and_both_dependency_tampers_are_refused(self):
        for name in (history.SOURCE_HISTORY_FIXTURE, history.HOST_SUPPORT,
                     history.EVALUATION_QUALIFIER):
            with self.subTest(name=name):
                original = (self.root / name).read_bytes()
                self.write(name, original + b'\n')
                with self.assertRaises(ValueError):
                    self.reader()
                self.write(name, original)

    def test_argument_bytes_must_match_selected_root(self):
        with self.assertRaisesRegex(ValueError, 'partially reverted'):
            self.reader(raw=self.prior[history.EVALUATION_TEST])

    def test_source_change_during_terminal_reread_is_refused(self):
        count = {}
        def take(path):
            name = path.relative_to(self.root).as_posix()
            count[name] = count.get(name, 0) + 1
            raw = path.read_bytes()
            if name == history.HOST_SUPPORT and count[name] > 1:
                return raw + b'\n'
            return raw
        with self.assertRaisesRegex(ValueError, 'terminal'):
            history.restore(self.current, root=self.root, take=take)

    def test_exact_integer_splice_coordinates_reject_boolean_aliases(self):
        value = json.loads((self.root / history.SOURCE_HISTORY_FIXTURE).read_bytes())
        name = history.EVALUATION_TEST
        for field in ('old_offset', 'new_offset'):
            record = deepcopy(value['files'][name])
            record['hunks'][0][field] = False
            with self.assertRaises(ValueError):
                history.history_inverse(self.current[name], record, history.PREDECESSORS[name])

    def test_full_inverse_refuses_extent_and_overlap_forgery(self):
        value = json.loads((self.root / history.SOURCE_HISTORY_FIXTURE).read_bytes())
        name = history.PRODUCTION_PATHS[0]
        record = deepcopy(value['files'][name])
        record['hunks'].append(deepcopy(record['hunks'][0]))
        with self.assertRaises(ValueError):
            history.history_inverse(self.current[name], record, history.PREDECESSORS[name])
        record = deepcopy(value['files'][name])
        record['new_bytes'] += 1
        with self.assertRaises(ValueError):
            history.history_inverse(self.current[name], record, history.PREDECESSORS[name])

    def test_data_only_module_imports_no_product_builder_or_test_helpers(self):
        tree = ast.parse((ROOT / 'tools/hia_frozen_component_sources.py').read_bytes())
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or '')
        self.assertFalse(any(name.startswith(('hepta', 'tests', 'tools.build_', 'tools.generate_'))
                             for name in imports), imports)


if __name__ == '__main__':
    unittest.main()
