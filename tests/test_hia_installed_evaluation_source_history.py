"""Independent-root composition tests for installed Evaluation source readers."""
from pathlib import Path
from hashlib import sha256
import json
import tempfile
import unittest

from tests import hia_installed_distribution_history as installed
from tests import hia_component_authoring_history as component
from tests import test_hia_evaluation_window_history as composition
from tools import hia_evaluation_window_history as window
from tools import hia_native_result_caller_history as results

ROOT = Path(__file__).resolve().parents[1]
EVALUATION = 'tests/test_hia_evaluation_native.py'
RESULTS = 'tests/test_hia_agent_native_tools.py'


class InstalledEvaluationHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        composition.EvaluationWindowHistoryTests.setUpClass()
        cls.old = dict(composition.EvaluationWindowHistoryTests.old)
        cls.new = dict(composition.EvaluationWindowHistoryTests.new)
        cls.files = {**composition.EvaluationWindowHistoryTests.support, **cls.new}
        for name in (installed.FIXTURE, component.FIXTURE,
                     'tools/hia_evaluation_window_history.py',
                     'tools/hia_native_result_caller_history.py', results.FIXTURE, RESULTS):
            cls.files[name] = (ROOT / name).read_bytes()
        cls.original = json.loads(cls.files[installed.FIXTURE])['files'][EVALUATION]['original']

    def setUp(self):
        if self._testMethodName == 'test_fixed_capture_history_restores_both_complete_prior_source_files':
            from tests.hia_scoped_selection_original_fixture import install_test_view
            install_test_view(self, globals())
        temporary = tempfile.TemporaryDirectory(prefix='hia-installed-evaluation-history-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.write(self.files)

    def write(self, values):
        for name, raw in values.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    def test_complete_current_three_member_relation_composes_all_old_layers(self):
        captures = {}
        def take(path):
            raw = path.read_bytes()
            if path in captures:
                self.assertEqual(captures[path], raw)
            captures[path] = raw
            return raw
        raw = installed.predecessor(EVALUATION, self.new[EVALUATION], root=self.root, take=take)
        self.assertEqual(window.pin(raw), self.original)
        for name in window.PATHS:
            self.assertEqual(captures[self.root / name], self.files[name])
        self.assertIn(self.root / installed.FIXTURE, captures)
        self.assertIn(self.root / component.FIXTURE, captures)
        self.assertIn(self.root / window.FIXTURE, captures)

    def test_six_result_current_caller_recovers_exact_complete_predecessor(self):
        raw = installed.predecessor(RESULTS, self.files[RESULTS], root=self.root)
        self.assertEqual(len(raw), 47052)
        self.assertEqual(sha256(raw).hexdigest(),
                         '64462e8735d8be3838396808dc05391e4437b2dba093fcc265468df6abb4cb70')

    def test_already_projected_six_result_predecessor_is_not_unwrapped_twice(self):
        prior = results.unwrap(self.root, RESULTS, self.files[RESULTS])
        self.assertEqual(installed.predecessor(RESULTS, prior, root=self.root), prior)

    def test_each_missing_independent_root_relation_is_rejected(self):
        names = (installed.FIXTURE, component.FIXTURE, window.FIXTURE)
        for name in names:
            with self.subTest(name=name):
                self.write(self.files)
                (self.root / name).unlink()
                with self.assertRaises(FileNotFoundError):
                    installed.predecessor(EVALUATION, self.new[EVALUATION], root=self.root)

    def test_each_altered_independent_root_relation_is_rejected(self):
        for name in (installed.FIXTURE, component.FIXTURE, window.FIXTURE):
            with self.subTest(name=name):
                self.write(self.files)
                self.write({name: self.files[name] + b' '})
                with self.assertRaises(ValueError):
                    installed.predecessor(EVALUATION, self.new[EVALUATION], root=self.root)

    def test_each_new_data_reader_is_bound_to_its_complete_physical_bytes(self):
        for name, caller in (('tools/hia_evaluation_window_history.py', EVALUATION),
                             ('tools/hia_native_result_caller_history.py', RESULTS)):
            with self.subTest(name=name):
                self.write(self.files)
                self.write({name: self.files[name] + b'\n'})
                with self.assertRaises(ValueError):
                    installed.predecessor(caller, self.files[caller], root=self.root)

    def test_partially_reverted_production_cannot_gain_installed_source_admission(self):
        for name in ('hepta/hia_agent_service.py', 'hepta/hia_evaluation_native.py'):
            with self.subTest(name=name):
                self.write(self.files)
                self.write({name: self.old[name]})
                with self.assertRaises(ValueError):
                    installed.predecessor(EVALUATION, self.new[EVALUATION], root=self.root)

    def test_physical_successor_change_during_retained_fixture_read_is_rejected(self):
        count = 0
        def take(path):
            nonlocal count
            raw = path.read_bytes()
            if path == self.root / installed.FIXTURE:
                count += 1
                if count == 2:
                    name = 'hepta/hia_agent_service.py'
                    self.write({name: self.new[name] + b'\n'})
            return raw
        with self.assertRaises(ValueError):
            installed.predecessor(EVALUATION, self.new[EVALUATION], root=self.root, take=take)
        self.assertEqual(count, 2)

    def test_caller_argument_cannot_hide_different_physical_current_source(self):
        self.write({EVALUATION: self.new[EVALUATION] + b'\n'})
        with self.assertRaises(ValueError):
            installed.predecessor(EVALUATION, self.new[EVALUATION], root=self.root)

    def test_fixed_capture_history_restores_both_complete_prior_source_files(self):
        from tools.hia_frozen_component_sources import history_inverse
        path = ROOT / 'tests/fixtures/hia_evaluation_caller_capture_history_v1.json'
        raw = path.read_bytes()
        self.assertEqual(sha256(raw).hexdigest(),
                         '12ad0d799e09f93eddab590ed0d5e68a5053d44a1406a5f7bc2856a98d0fb157')
        value = json.loads(raw)
        expected = {
            'tools/qualify_hia_evaluation_callers.py': {
                'bytes': 15063,
                'sha256': '29c40723460571b2d336e6f23adec005b3f4a89aead62c826efb391d9de762d9'},
            'tests/hia_installed_distribution_history.py': {
                'bytes': 4355,
                'sha256': '8a69299935e247a8bab59c6c030d9356110c709c196cc187f986eef5df19613d'},
        }
        self.assertEqual(set(value['files']), set(expected))
        for name, old in expected.items():
            physical = (ROOT / name).read_bytes()
            admitted = physical
            if name == 'tools/qualify_hia_evaluation_callers.py':
                successor = ROOT / 'tests/fixtures/hia_evaluation_original_source_domains_v1.json'
                successor_raw = successor.read_bytes()
                self.assertEqual(sha256(successor_raw).hexdigest(), 'ce9b082ed9d9496b5939767687df89e2c550b7d28419fa8f77f16626037bfe33')
                current_record = json.loads(successor_raw)['files'][name]
                admitted = history_inverse(physical, current_record, {
                    'bytes': 15168,
                    'sha256': '8a0f66a01385fce272205551af0722c31dc92197346f86e757693565d7952757'})
                self.assertEqual(successor.read_bytes(), successor_raw)
            restored = history_inverse(admitted, value['files'][name], old)
            self.assertEqual(window.pin(restored), old)
            self.assertEqual((ROOT / name).read_bytes(), physical)
        self.assertEqual(path.read_bytes(), raw)

    def test_exact_qualifier_root_capture_preserves_original_complete_inventory(self):
        from tools.qualify_hia_evaluation_callers import admit_original_sources, FIXTURE_NAME
        inventory = json.loads((ROOT / FIXTURE_NAME).read_bytes())
        records = {row['path']: row['sha256'] for row in inventory['modules'].values()}
        proof = {}
        admit_original_sources(ROOT, records, source_proof=proof)
        self.assertTrue(proof['terminal_reread_identical'])
        self.assertEqual(proof['original_source_sha256'], records)
        physical = proof['captured_source_sha256']
        self.assertEqual(physical[RESULTS], sha256((ROOT / RESULTS).read_bytes()).hexdigest())
        self.assertIn(results.FIXTURE, physical)
        self.assertIn('tools/hia_native_result_caller_history.py', physical)


if __name__ == '__main__':
    unittest.main()
