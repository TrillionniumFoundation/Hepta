"""Physical current-source and prior-view controls for the cold selector."""
import ast
import builtins
import json
from pathlib import Path
import tempfile
import unittest

from tools import hia_evaluation_cold_source_history as cold
from tools import hia_evaluation_window_history as window

ROOT = Path(__file__).resolve().parents[1]


class EvaluationColdSourceHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = (ROOT / cold.FIXTURE).read_bytes()
        cls.relation = json.loads(cls.fixture)
        cls.current = {n: (ROOT / n).read_bytes() for n in cold.PATHS}
        for n, raw in cls.current.items():
            if cold.pin(raw) != cold.CURRENT[n]:
                raise ValueError('actual current test composition differs: ' + n)
        cls.previous = dict(cls.current)
        cls.previous[cold.PATH] = cold._inverse(
            cls.current[cold.PATH], cls.relation['files'][cold.PATH],
            cold.PREVIOUS[cold.PATH])
        earlier = json.loads((ROOT / window.FIXTURE).read_bytes())
        cls.original = {n: window._inverse(cls.previous[n], earlier['files'][n], p)
                        for n, p in window.ORIGINAL.items()}
        cls.support = {n: (ROOT / n).read_bytes() for n in
                       (cold.FIXTURE, window.FIXTURE, window.ENGINE, *window.UNCHANGED)}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='hia-evaluation-cold-history-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.write({**self.support, **self.current})

    def write(self, values):
        for name, raw in values.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    def prepare(self):
        return cold.prepare(self.root, {cold.PATH: (self.root / cold.PATH).read_bytes()})

    def test_current_projection_preserves_complete_physical_capture(self):
        projected, history = self.prepare()
        self.assertEqual(projected[cold.PATH], self.previous[cold.PATH])
        self.assertEqual(history['captures'][cold.PATH], self.current[cold.PATH])
        self.assertEqual(history['prior_take'](self.root / cold.PATH), self.previous[cold.PATH])
        self.assertTrue(history['review']['successor_applied'])
        self.assertFalse(history['review']['physical_capture_rewritten'])
        self.assertFalse(history['review']['prior_projection_is_physical_source'])
        cold.verify_unchanged(history)

    def test_previous_domain_needs_no_new_authority(self):
        self.write(self.previous)
        (self.root / cold.FIXTURE).unlink()
        projected, history = self.prepare()
        self.assertEqual(projected[cold.PATH], self.previous[cold.PATH])
        self.assertFalse(history['review']['successor_applied'])
        self.assertNotIn(cold.FIXTURE, history['captures'])

    def test_original_domain_needs_no_new_authority(self):
        self.write(self.original)
        (self.root / cold.FIXTURE).unlink()
        projected, history = self.prepare()
        self.assertEqual(projected[cold.PATH], self.original[cold.PATH])
        self.assertFalse(history['review']['successor_applied'])

    def test_mixed_complete_members_are_rejected(self):
        for name in cold.PATHS:
            with self.subTest(path=name):
                self.write(self.current)
                self.write({name: self.original[name]})
                with self.assertRaises(ValueError):
                    self.prepare()

    def test_independent_root_missing_or_changed_fixed_relation_refuses(self):
        (self.root / cold.FIXTURE).unlink()
        with self.assertRaises(FileNotFoundError):
            self.prepare()
        self.assertEqual((ROOT / cold.FIXTURE).read_bytes(), self.fixture)
        self.write({cold.FIXTURE: self.fixture + b' '})
        with self.assertRaises(ValueError):
            self.prepare()

    def test_projected_argument_is_never_accepted_as_physical(self):
        with self.assertRaises(ValueError):
            cold.prepare(self.root, {cold.PATH: self.previous[cold.PATH]})

    def test_unknown_source_outside_the_splice_is_rejected(self):
        for name in cold.PATHS:
            with self.subTest(path=name):
                self.write(self.current)
                self.write({name: self.current[name] + b'\n'})
                with self.assertRaises(ValueError):
                    self.prepare()

    def test_each_physical_member_and_relation_has_terminal_readback(self):
        for name in (*cold.PATHS, cold.FIXTURE):
            with self.subTest(path=name):
                self.write({**self.support, **self.current})
                _, history = self.prepare()
                self.write({name: (self.root / name).read_bytes() + b' '})
                with self.assertRaises(ValueError):
                    cold.verify_unchanged(history)

    def test_prior_view_rechecks_the_actual_test_before_projecting(self):
        _, history = self.prepare()
        self.write({cold.PATH: self.previous[cold.PATH]})
        with self.assertRaises(ValueError):
            history['prior_take'](self.root / cold.PATH)

    def test_extra_captured_source_is_also_bound_at_terminal(self):
        name = 'qualification/extra.json'
        self.write({name: b'{"original":true}\n'})
        _, history = cold.prepare(self.root, {
            cold.PATH: self.current[cold.PATH], name: (self.root / name).read_bytes()})
        self.write({name: b'{"changed":true}\n'})
        with self.assertRaises(ValueError):
            cold.verify_unchanged(history)

    def test_paths_cannot_escape_to_another_source_root(self):
        for name in ('../other', '/other', '.git/config'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                cold.prepare(self.root, {name: b''})
        with self.assertRaises(ValueError):
            cold.prepare(self.root, {})

    def test_unchanged_window_layer_receives_only_explicit_prior_view(self):
        projected, history = self.prepare()
        old, earlier = window.prepare(
            self.root, projected, take=history['prior_take'])
        self.assertEqual(old[cold.PATH], self.original[cold.PATH])
        self.assertEqual(history['captures'][cold.PATH], self.current[cold.PATH])
        self.assertEqual(earlier['captures'][cold.PATH], self.previous[cold.PATH])
        window.verify_unchanged(earlier)
        cold.verify_unchanged(history)

    def test_data_only_composition_imports_no_product_or_oracle(self):
        real = builtins.__import__
        attempted = []
        def guarded(name, *args, **kwargs):
            if name == 'hepta' or name.startswith(('hepta.', 'tests.', 'tools.build_', 'tools.generate_', 'tools.qualify_')) or 'oracle' in name:
                attempted.append(name)
                raise AssertionError('unexpected product import: ' + name)
            return real(name, *args, **kwargs)
        builtins.__import__ = guarded
        try:
            projected, history = self.prepare()
            _, earlier = window.prepare(self.root, projected, take=history['prior_take'])
            window.verify_unchanged(earlier)
            cold.verify_unchanged(history)
        finally:
            builtins.__import__ = real
        self.assertEqual(attempted, [])
        tree = ast.parse((ROOT / 'tools/hia_evaluation_cold_source_history.py').read_bytes())
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(a.name.split('.')[0] for a in node.names)
            if isinstance(node, ast.ImportFrom):
                imported.append((node.module or '').split('.')[0])
        self.assertLessEqual(set(imported), {'hashlib', 'json', 'pathlib', 're'})


if __name__ == '__main__':
    unittest.main()
