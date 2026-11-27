"""Current physical source controls around the retained selection domain."""
from contextlib import contextmanager
from hashlib import sha256
import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools import hia_scoped_caller_admission_history as current
from tests import hia_cold_caller_selection_history as previous
from tests import hia_scoped_selection_original_fixture as fixture

ROOT = Path(__file__).resolve().parents[1]
NAME = previous.EVALUATION_CAPTURE_PATH


class ScopedAdmissionCurrentHistoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hia-current-scoped-history-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        names = (*current.CURRENT, current.SELF, current.FIXTURE, current.ENGINE)
        self.files = {name: (ROOT / name).read_bytes() for name in names}
        self.raw = {name: self.files[name] for name in current.CURRENT}
        self.write(self.files)

    def write(self, files):
        for name, raw in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    def prepare(self, **kwargs):
        return current.prepare(self.root, self.raw, **kwargs)

    def pair_inputs(self):
        names = (*previous.EVALUATION_CAPTURE_EXPECTED,
                 previous.EVALUATION_CAPTURE_FIXTURE, previous.EVALUATION_DOMAINS_FIXTURE,
                 previous.INVERSE_HELPER, previous.FIXTURE)
        files = {name: (ROOT / name).read_bytes() for name in names}
        self.write(files)
        return files

    def compose(self, **kwargs):
        projected, history = current.prepare(self.root, {NAME: self.raw[NAME]}, **kwargs)
        try:
            original, proof = previous.reviewed(
                NAME, projected[NAME], root=self.root, take=history['prior_take'])
        finally:
            current.verify_unchanged(history)
        return original, proof, history

    def test_all_three_complete_files_restore_the_exact_prior_and_retain_actual_capture(self):
        projected, history = self.prepare()
        self.assertEqual({name: current.pin(raw) for name, raw in projected.items()}, current.PRIOR)
        for name, raw in self.raw.items():
            self.assertEqual(history['captures'][name], raw)
            self.assertEqual(history['prior_take'](self.root / name), projected[name])
            self.assertNotEqual(projected[name], raw)
        current.verify_unchanged(history)
        self.assertEqual(history['review']['actual_physical_current'], current.CURRENT)
        self.assertEqual(history['review']['historical_current_inputs'], current.PRIOR)
        self.assertTrue(history['review']['terminal_reread_identical'])
        self.assertFalse(history['review']['physical_capture_rewritten'])
        self.assertFalse(history['review']['whole_native_delivery_qualified'])

    def test_each_initial_missing_changed_and_partially_reverted_physical_input_is_refused(self):
        projected, _ = self.prepare()
        for name in self.files:
            for missing in (False, True):
                with self.subTest(name=name, missing=missing):
                    self.write(self.files)
                    path = self.root / name
                    if missing:
                        path.unlink()
                    else:
                        path.write_bytes(self.files[name] + b' ')
                    with self.assertRaises((ValueError, OSError)):
                        self.prepare()
        for name in current.CURRENT:
            with self.subTest(partially_reverted=name):
                self.write(self.files)
                self.write({name: projected[name]})
                with self.assertRaises(ValueError):
                    self.prepare()

    def test_real_change_after_first_source_read_is_rejected_before_return(self):
        for selected in self.raw:
            with self.subTest(name=selected):
                self.write(self.files)
                changed = [False]
                def take(path):
                    raw = path.read_bytes()
                    if path == self.root / selected and not changed[0]:
                        changed[0] = True
                        path.write_bytes(raw + b'\n')
                    return raw
                with self.assertRaises(ValueError):
                    self.prepare(take=take)
                self.assertTrue(changed[0])

    def test_every_initial_and_lazily_read_capture_is_rechecked_at_terminal(self):
        for selected in (*self.files, 'independent.txt'):
            with self.subTest(name=selected):
                self.write(self.files)
                self.write({'independent.txt': b'independent physical bytes\n'})
                _, history = self.prepare()
                self.assertEqual(history['prior_take'](self.root / 'independent.txt'),
                                 b'independent physical bytes\n')
                path = self.root / selected
                path.write_bytes(path.read_bytes() + b' ')
                with self.assertRaises(ValueError):
                    current.verify_unchanged(history)

    def test_prior_take_rechecks_current_source_before_returning_its_old_bytes(self):
        projected, history = self.prepare()
        name = next(iter(self.raw))
        self.assertEqual(history['prior_take'](self.root / name), projected[name])
        self.write({name: self.raw[name] + b' '})
        with self.assertRaises(ValueError):
            history['prior_take'](self.root / name)

    def test_old_unknown_and_noncanonical_sources_cannot_borrow_the_new_relation(self):
        projected, _ = self.prepare()
        def forbidden(path):
            self.fail('an unknown source borrowed a current authority')
        for name, raw in projected.items():
            with self.subTest(name=name):
                self.assertEqual(current.prepare(self.root, {name: raw}, take=forbidden),
                                 ({name: raw}, None))
                changed = self.raw[name] + b' '
                self.assertEqual(current.prepare(self.root, {name: changed}, take=forbidden),
                                 ({name: changed}, None))
        for source in (False, [], {NAME: bytearray(self.raw[NAME])}, {False: b''},
                       {'../' + NAME: self.raw[NAME]}, {'/tmp/' + NAME: self.raw[NAME]},
                       {'tools//qualify_hia_evaluation_callers.py': self.raw[NAME]}):
            with self.subTest(source_type=type(source).__name__), self.assertRaises(ValueError):
                current.prepare(self.root, source, take=forbidden)
        _, history = self.prepare()
        for path in (Path(NAME), self.root / '..' / NAME, self.root.parent / NAME):
            with self.subTest(path=str(path)), self.assertRaises(ValueError):
                history['prior_take'](path)

    def test_a_second_root_or_cached_relation_cannot_hide_a_missing_authority(self):
        self.prepare()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for name, raw in self.files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            (root / current.FIXTURE).unlink()
            with self.assertRaises(FileNotFoundError):
                current.prepare(root, self.raw)

    def test_current_evaluation_composes_the_complete_retained_pair_and_original_selection(self):
        self.pair_inputs()
        original, proof, history = self.compose()
        self.assertEqual(previous.pin(original), previous.EXPECTED[NAME]['old'])
        self.assertEqual(proof['exact_selection_splices'], 2)
        self.assertEqual(proof['evaluation_caller_capture']['original_complete_callers'], 81)
        self.assertEqual(history['captures'][NAME], self.raw[NAME])
        self.assertEqual(current.pin(history['view'][NAME]), current.PRIOR[NAME])
        self.assertTrue(history['review']['terminal_reread_identical'])
        raw, unknown = previous.reviewed(NAME, self.raw[NAME],
            take=lambda path: self.fail('old reader borrowed authority for a new source'))
        self.assertEqual(raw, self.raw[NAME])
        self.assertIsNone(unknown)
        self.assertNotEqual(previous.pin(raw), previous.EXPECTED[NAME]['old'])

    def test_every_retained_pair_authority_remains_required_and_terminally_bound(self):
        pair = self.pair_inputs()
        for selected in pair:
            with self.subTest(missing=selected):
                self.write(self.files)
                self.write(pair)
                (self.root / selected).unlink()
                with self.assertRaises((ValueError, OSError)):
                    self.compose()
            with self.subTest(late=selected):
                self.write(self.files)
                self.write(pair)
                _, _, history = self.compose()
                path = self.root / selected
                path.write_bytes(path.read_bytes() + b' ')
                with self.assertRaises(ValueError):
                    current.verify_unchanged(history)

    def test_import_time_bytes_reject_replacement_before_the_first_prepare(self):
        module_path = self.root / current.SELF
        spec = importlib.util.spec_from_file_location('_hia_scoped_import_boundary', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module_path.write_bytes(self.files[current.SELF] + b'\n# after import\n')
        with self.assertRaises(ValueError):
            module.prepare(self.root, self.raw)

    def test_fresh_current_reader_imports_no_product_test_builder_generator_or_oracle(self):
        script = """import importlib.abc,sys
sys.path.insert(0,sys.argv[1])
from pathlib import Path
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname in ('hepta','tests') or fullname.startswith(('hepta.','tests.','tools.build_','tools.generate_')) or 'oracle' in fullname:
            raise AssertionError(fullname)
sys.meta_path.insert(0,Guard())
from tools import hia_scoped_caller_admission_history as current
root=Path(sys.argv[1]);source={n:(root/n).read_bytes()for n in current.CURRENT}
projected,history=current.prepare(root,source)
assert {n:current.pin(b)for n,b in projected.items()}==current.PRIOR
current.verify_unchanged(history)
"""
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(ROOT)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)


class OriginalSelectionFixtureBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with fixture.original_view(ROOT) as (stage, review):
            cls.files = {name: (ROOT / name).read_bytes()
                         for name in review['actual_captured_files']}
        cls.review = review

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hia-selection-fixture-control-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.write(self.files)

    def write(self, files):
        for name, raw in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    def test_complete_original_test_methods_and_physical_inputs_remain_distinct(self):
        relation = json.loads(self.files[fixture.FIXTURE])
        from tools.hia_frozen_component_sources import history_inverse
        counts = {}
        for name, row in relation['test_files'].items():
            raw = self.files[name]
            old = history_inverse(raw, row, {'bytes': row['old_bytes'], 'sha256': row['old_sha256']})
            original = fixture._methods(old)
            self.assertEqual(fixture._methods(raw), original)
            counts[name] = len(original)
        self.assertEqual(counts, {
            'tests/test_hia_cold_caller_selection_history.py': 10,
            'tests/test_hia_evaluation_caller_capture_history.py': 8,
            'tests/test_hia_installed_evaluation_source_history.py': 11,
        })
        with fixture.original_view(self.root) as (stage, review):
            self.assertEqual(current.pin((stage / NAME).read_bytes()), current.PRIOR[NAME])
            self.assertEqual(current.pin((self.root / NAME).read_bytes()), current.CURRENT[NAME])
            self.assertEqual(review['actual_captured_files'][NAME], current.CURRENT[NAME])
            self.assertFalse(review['historical_view_is_current_repository'])
        self.assertTrue(review['terminal_reread_identical'])

    def test_every_declared_original_view_input_is_bound_before_preparation(self):
        for selected in self.files:
            for missing in (False, True):
                with self.subTest(name=selected, missing=missing):
                    self.write(self.files)
                    path = self.root / selected
                    if missing:
                        path.unlink()
                    else:
                        path.write_bytes(self.files[selected] + b' ')
                    with self.assertRaises((ValueError, OSError)):
                        with fixture.original_view(self.root):
                            pass

    def test_all_actual_and_staged_bytes_are_rechecked_at_close(self):
        selected_names = (fixture.FIXTURE, fixture.SELF, current.SELF, NAME,
                          'tests/hia_installed_distribution_history.py')
        for selected in selected_names:
            with self.subTest(physical=selected):
                self.write(self.files)
                with self.assertRaises(ValueError):
                    with fixture.original_view(self.root):
                        path = self.root / selected
                        path.write_bytes(path.read_bytes() + b' ')
            with self.subTest(stage=selected):
                self.write(self.files)
                with self.assertRaises(ValueError):
                    with fixture.original_view(self.root) as (stage, _):
                        path = stage / selected
                        path.write_bytes(path.read_bytes() + b' ')

    def test_preparation_import_snapshot_is_bound_before_the_first_view(self):
        module_path = self.root / fixture.SELF
        spec = importlib.util.spec_from_file_location('_hia_selection_fixture_import', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module_path.write_bytes(self.files[fixture.SELF] + b'\n# post import replacement\n')
        with self.assertRaises(ValueError):
            with module.original_view(self.root):
                pass


if __name__ == '__main__':
    unittest.main()
