"""Physical custody controls for explicit native-cold consumer compositions."""
from contextlib import contextmanager
from copy import deepcopy
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools import hia_native_cold_composition_history as history

ROOT = Path(__file__).resolve().parents[1]
PATHS = (*history.CURRENT, history.SELF, history.FIXTURE, history.ENGINE,
         history.SLOT_FIXTURE, history.SLOT_HELPER, *history.SLOT_COMPONENTS,
         'tools/hia_cold_compiler.py',
         'tests/fixtures/hia_installed_distribution_sources.json')


class NativeColdCompositionHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual = {name: (ROOT / name).read_bytes() for name in PATHS}
        if any(history.pin(cls.actual[name]) != expected for name, expected in history.CURRENT.items()):
            raise AssertionError('composition controls require exact complete current source files')

    @classmethod
    def tearDownClass(cls):
        for name, raw in cls.actual.items():
            if (ROOT / name).read_bytes() != raw:
                raise AssertionError('composition controls changed actual source: ' + name)

    @contextmanager
    def tree(self):
        with tempfile.TemporaryDirectory(prefix='hia-cold-composition-control-') as directory:
            root = Path(directory)
            for name, raw in self.actual.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            yield root

    def test_all_four_complete_current_sources_restore_without_rewriting_captures(self):
        with self.tree() as root:
            supplied = {name: self.actual[name] for name in history.CURRENT}
            projected, proof = history.prepare(root, supplied)
            self.assertEqual({name: history.pin(raw) for name, raw in projected.items()}, history.PREVIOUS)
            for name, raw in supplied.items():
                self.assertEqual(proof['captures'][name], raw)
                self.assertEqual((root / name).read_bytes(), raw)
            self.assertFalse(proof['review']['prior_projection_is_physical_source'])
            self.assertFalse(proof['review']['physical_capture_rewritten'])
            self.assertFalse(proof['review']['whole_native_delivery_qualified'])
            history.verify_unchanged(proof)
            self.assertTrue(proof['review']['terminal_reread_identical'])

    def test_every_physical_source_and_authority_is_checked_at_terminal(self):
        with self.tree() as root:
            supplied = {name: self.actual[name] for name in history.CURRENT}
            _, first = history.prepare(root, supplied)
            names = tuple(first['captures'])
            for name in names:
                with self.subTest(path=name):
                    _, proof = history.prepare(root, supplied)
                    target = root / name
                    original = target.read_bytes()
                    target.write_bytes(original + b'\n')
                    try:
                        with self.assertRaises((ValueError, OSError)):
                            history.verify_unchanged(proof)
                    finally:
                        target.write_bytes(original)

    def test_each_required_dependency_missing_or_changed_is_refused(self):
        for name in PATHS:
            modes = (True,) if name == 'tools/hia_cold_compiler.py' else (False, True)
            for missing in modes:
                with self.subTest(path=name, missing=missing), self.tree() as root:
                    target = root / name
                    if missing:
                        target.unlink()
                    else:
                        target.write_bytes(self.actual[name] + b'\n')
                    with self.assertRaises((ValueError, OSError)):
                        history.prepare(root, {key: self.actual[key] for key in history.CURRENT})

    def test_projected_arguments_cannot_replace_current_physical_sources(self):
        with self.tree() as root:
            actual = {name: self.actual[name] for name in history.CURRENT}
            projected, proof = history.prepare(root, actual)
            # Include an exact-current member so this is a selected current
            # composition, then substitute another member's prior view.
            names = tuple(actual)
            for name in names:
                supplied = dict(actual)
                supplied[name] = projected[name]
                with self.subTest(path=name), self.assertRaises(ValueError):
                    history.prepare(root, supplied)
            history.verify_unchanged(proof)

    def test_lazy_prior_view_always_rereads_the_actual_file(self):
        with self.tree() as root:
            first, second = tuple(history.CURRENT)[:2]
            _, proof = history.prepare(root, {first: self.actual[first]})
            self.assertEqual(history.pin(proof['prior_take'](root / second)), history.PREVIOUS[second])
            self.assertEqual(proof['captures'][second], self.actual[second])
            (root / second).write_bytes(self.actual[second] + b'\n')
            with self.assertRaises(ValueError):
                proof['prior_take'](root / second)
            with self.assertRaises(ValueError):
                history.verify_unchanged(proof)

    def test_late_capture_changes_are_not_admitted_as_stable_inputs(self):
        with self.tree() as root:
            for name in (history.SELF, history.FIXTURE, history.ENGINE, history.SLOT_FIXTURE):
                fired = []
                def take(path):
                    raw = path.read_bytes()
                    if path == root / name and not fired:
                        fired.append(name)
                        path.write_bytes(raw + b'\n')
                    return raw
                with self.subTest(path=name):
                    try:
                        with self.assertRaises(ValueError):
                            history.prepare(root,
                                {key: self.actual[key] for key in history.CURRENT}, take=take)
                        self.assertEqual(fired, [name])
                    finally:
                        (root / name).write_bytes(self.actual[name])

    def test_loaded_reader_cannot_adopt_replaced_bytes_before_first_prepare(self):
        with self.tree() as root:
            path = root / history.SELF
            spec = importlib.util.spec_from_file_location('isolated_cold_composition_history', path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            source = path.read_bytes()
            path.write_bytes(source + b'\n# not the executed module\n')
            selected = {name: self.actual[name] for name in history.CURRENT}
            with self.assertRaises(ValueError):
                module.prepare(root, selected)
            path.write_bytes(source)
            _, proof = module.prepare(root, selected)
            module.verify_unchanged(proof)
            path.write_bytes(source + b'\n')
            with self.assertRaises(ValueError):
                module.verify_unchanged(proof)

    def test_unknown_domains_borrow_no_current_authority(self):
        def forbidden(path):
            self.fail('unknown source borrowed a new source authority')
        supplied = {'unlisted.py': b'unknown old source'}
        self.assertEqual(history.prepare(ROOT, supplied, take=forbidden), (supplied, None))
        history.verify_unchanged(None)

    def test_independent_slot_view_imports_no_product_or_test_helper(self):
        script = """import importlib.abc,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname in ('hepta','tests') or fullname.startswith(('hepta.','tests.','tools.build_','tools.generate_')) or 'oracle' in fullname:
            raise AssertionError(fullname)
sys.meta_path.insert(0,Guard())
from tools import hia_native_cold_composition_history as subject
root=Path(sys.argv[2]);name=subject.SLOT_PATH
projected,history=subject.prepare(root,{name:(root/name).read_bytes()})
assert subject.pin(projected[name])==subject.PREVIOUS[name]
subject.verify_unchanged(history)
"""
        with self.tree() as root:
            result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(ROOT), str(root)],
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
