"""Actual root, late-change and precise-type controls for cold caller history."""
import ast
from collections import Counter
from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import hia_cold_caller_sources as cold
from tools import hia_native_cold_caller_history as subject

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'tests/test_hia_store_native_delivery.py'
SECOND = 'tests/test_hia_evaluation_native.py'


class NativeColdPhysicalHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.hia_native_cold_original_fixture import install_original_view
        install_original_view(cls, globals())
        cls.records = cold.read_relations(
            (ROOT / cold.FIXTURE).read_bytes(),
            previous_raw=(ROOT / cold.PREVIOUS_FIXTURE).read_bytes())
        cls.original = {
            name: cold.restore_caller_source(name, (ROOT / name).read_bytes(), cls.records)
            for name in (SOURCE, SECOND)
        }

    @contextmanager
    def tree(self, extra=()):
        names = set((SOURCE, SECOND, *subject.DEPENDENCIES, *extra))
        with tempfile.TemporaryDirectory(prefix='hia-cold-physical-independent-') as directory:
            root = Path(directory)
            for name in names:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / name).read_bytes())
            yield root.resolve()

    def test_complete_131_views_restore_and_keep_all_actual_captures(self):
        self.assertEqual(len(subject.KNOWN_CURRENT), 131)
        supplied = {name: (ROOT / name).read_bytes() for name in subject.PATHS}
        projected, history = subject.prepare(ROOT, supplied)
        self.assertEqual(set(projected), set(supplied))
        self.assertEqual(set(history['review']['native_cold_caller_sources']), set(supplied))
        for name, raw in supplied.items():
            with self.subTest(path=name):
                self.assertEqual(subject.pin(raw), subject.KNOWN_CURRENT[name])
                self.assertEqual(subject.pin(projected[name]), self.records[name]['predecessor'])
                self.assertEqual(history['captures'][name], raw)
                self.assertEqual((ROOT / name).read_bytes(), raw)
                proof = history['review']['native_cold_caller_sources'][name]
                self.assertTrue(proof['complete_current_replayed'])
                self.assertFalse(proof['whole_native_delivery_qualified'])
        subject.verify_unchanged(history)
        self.assertTrue(history['review']['terminal_reread_identical'])

    def test_three_reproduced_original_counterexamples_now_refuse(self):
        for mode in ('changed-physical', 'missing-physical', 'supplied-predecessor-over-current'):
            with self.subTest(mode=mode), self.tree() as root:
                raw = (root / SOURCE).read_bytes()
                path = root / SOURCE
                if mode == 'changed-physical':
                    path.write_bytes(raw + b'\n# changed physical bytes\n')
                    with self.assertRaises(ValueError):
                        cold.original_caller_source(root, SOURCE, raw)
                elif mode == 'missing-physical':
                    path.unlink()
                    with self.assertRaises(FileNotFoundError):
                        cold.original_caller_source(root, SOURCE, raw)
                else:
                    with self.assertRaises(ValueError):
                        subject.cold_caller_source(root, SOURCE, self.original[SOURCE])

    def test_original_entry_rereads_actual_source_and_both_authorities(self):
        for name in (SOURCE, cold.FIXTURE, cold.PREVIOUS_FIXTURE):
            with self.subTest(path=name), self.tree() as root:
                source = (root / SOURCE).read_bytes()
                fired = []

                def take(path):
                    raw = path.read_bytes()
                    if path == root / name and not fired:
                        fired.append(name)
                        path.write_bytes(raw + b'\n')
                    return raw

                with self.assertRaises(ValueError):
                    cold.original_caller_source(root, SOURCE, source, take=take)
                self.assertEqual(fired, [name])

    def test_late_changes_to_all_physical_inputs_are_refused(self):
        for name in (SOURCE, cold.FIXTURE, cold.PREVIOUS_FIXTURE,
                     cold.SOURCE, subject.HISTORY_SOURCE):
            with self.subTest(path=name), self.tree() as root:
                source = (root / SOURCE).read_bytes()
                fired = []

                def take(path):
                    raw = path.read_bytes()
                    if path == root / name and not fired:
                        fired.append(name)
                        path.write_bytes(raw + b'\n')
                    return raw

                with self.assertRaises(ValueError):
                    subject.prepare(root, {SOURCE: source}, take=take)
                self.assertEqual(fired, [name])

    def test_outer_terminal_reread_refuses_every_late_input_change(self):
        for name in (SOURCE, cold.FIXTURE, cold.PREVIOUS_FIXTURE,
                     cold.SOURCE, subject.HISTORY_SOURCE):
            with self.subTest(path=name), self.tree() as root:
                source = (root / SOURCE).read_bytes()
                _, history = subject.prepare(root, {SOURCE: source})
                before = dict(history['captures'])
                path = root / name
                path.write_bytes(path.read_bytes() + b'\n')
                with self.assertRaises(ValueError):
                    subject.verify_unchanged(history)
                self.assertEqual(history['captures'], before)

    def test_lazy_other_caller_is_freshly_read_and_stays_physical(self):
        with self.tree() as root:
            counts = Counter()

            def take(path):
                counts[path.relative_to(root).as_posix()] += 1
                return path.read_bytes()

            raw = (root / SOURCE).read_bytes()
            _, history = subject.prepare(root, {SOURCE: raw}, take=take)
            self.assertNotIn(SECOND, history['captures'])
            current = (root / SECOND).read_bytes()
            old = history['prior_take'](root / SECOND)
            self.assertEqual(old, self.original[SECOND])
            self.assertEqual(history['captures'][SECOND], current)
            count = counts[SECOND]
            self.assertEqual(history['prior_take'](root / SECOND), old)
            self.assertGreater(counts[SECOND], count)
            subject.verify_unchanged(history)
            (root / SECOND).write_bytes(current + b'\n')
            with self.assertRaises(ValueError):
                history['prior_take'](root / SECOND)
            with self.assertRaises(ValueError):
                subject.verify_unchanged(history)

    def test_lazy_initial_read_drift_is_refused(self):
        with self.tree() as root:
            fired = []

            def take(path):
                data = path.read_bytes()
                if path == root / SECOND and not fired:
                    fired.append(True)
                    path.write_bytes(data + b'\n')
                return data

            _, history = subject.prepare(root, {SOURCE: (root / SOURCE).read_bytes()}, take=take)
            with self.assertRaises(ValueError):
                history['prior_take'](root / SECOND)
            self.assertEqual(fired, [True])

    def test_known_new_domain_requires_complete_authority_and_reader(self):
        for name in subject.DEPENDENCIES:
            with self.subTest(path=name), self.tree() as root:
                raw = (root / SOURCE).read_bytes()
                (root / name).unlink()
                with self.assertRaises(FileNotFoundError):
                    subject.prepare(root, {SOURCE: raw})
                with self.assertRaises(FileNotFoundError):
                    subject.cold_caller_source(root, SOURCE, raw)

    def test_legacy_domain_grants_no_exception_or_new_dependency(self):
        with self.tree() as root:
            old = self.original[SOURCE]
            (root / SOURCE).write_bytes(old)
            for name in subject.DEPENDENCIES:
                (root / name).unlink()
            result, proof = subject.cold_caller_source(root, SOURCE, old)
            self.assertEqual(result, old)
            self.assertIsNone(proof)
            unknown = old + b'\n# unreviewed\n'
            (root / SOURCE).write_bytes(unknown)
            result, proof = subject.cold_caller_source(root, SOURCE, unknown)
            self.assertEqual(result, unknown)
            self.assertIsNone(proof)
            with self.assertRaises(ValueError):
                cold.restore_caller_source(SOURCE, result, self.records)
            with self.assertRaises(FileNotFoundError):
                subject.prepare(root, {SOURCE: unknown})

    def test_explicit_root_never_falls_back_and_views_cannot_escape(self):
        with self.tree() as root:
            raw = (root / SOURCE).read_bytes()
            with self.assertRaises(FileNotFoundError):
                subject.prepare(root / 'missing', {SOURCE: raw})
            _, history = subject.prepare(root, {SOURCE: raw})
            with self.assertRaises(ValueError):
                history['prior_take'](ROOT / SECOND)
            for name in ('../outside.py', '/outside.py', './test.py', 'tests//test.py'):
                with self.subTest(path=name), self.assertRaises(ValueError):
                    subject.prepare(root, {name: raw})
            with self.assertRaises(ValueError):
                subject.prepare(root, {SOURCE: bytearray(raw)})
            subject.verify_unchanged(None)

    def test_different_reader_or_authoring_helper_is_refused(self):
        for name in (subject.HISTORY_SOURCE, cold.SOURCE):
            with self.subTest(path=name), self.tree() as root:
                raw = (root / SOURCE).read_bytes()
                path = root / name
                path.write_bytes(path.read_bytes() + b'\n# different helper\n')
                with self.assertRaises(ValueError):
                    subject.prepare(root, {SOURCE: raw})

    def test_distinct_executing_reader_is_bound_at_initial_and_terminal(self):
        with self.tree() as root, tempfile.TemporaryDirectory(prefix='hia-reader-code-') as directory:
            module_path = Path(directory) / 'independent_reader.py'
            original = (ROOT / subject.HISTORY_SOURCE).read_bytes()
            module_path.write_bytes(original)
            spec = importlib.util.spec_from_file_location('cold_independent_physical_control', module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            _, history = module.prepare(root, {SOURCE: (root / SOURCE).read_bytes()})
            module_path.write_bytes(original + b'\n# after module capture\n')
            with self.assertRaises(ValueError):
                module.verify_unchanged(history)
            with self.assertRaises(ValueError):
                module.prepare(root, {SOURCE: (root / SOURCE).read_bytes()})


    def test_reader_bytes_cannot_change_after_import_before_first_prepare(self):
        with self.tree() as root, tempfile.TemporaryDirectory(prefix='hia-reader-import-gap-') as directory:
            module_path = Path(directory) / 'independent_reader.py'
            original = (ROOT / subject.HISTORY_SOURCE).read_bytes()
            module_path.write_bytes(original)
            spec = importlib.util.spec_from_file_location('cold_import_boundary_control', module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            changed = original + b'\n# changed after import, before first prepare\n'
            module_path.write_bytes(changed)
            (root / subject.HISTORY_SOURCE).write_bytes(changed)
            with self.assertRaises(ValueError):
                module.prepare(root, {SOURCE: (root / SOURCE).read_bytes()})
            module_path.write_bytes(original)
            (root / subject.HISTORY_SOURCE).write_bytes(original)
            _, history = module.prepare(root, {SOURCE: (root / SOURCE).read_bytes()})
            self.assertEqual(
                history['captures'][subject.HISTORY_SOURCE], original)
            module_path.write_bytes(changed)
            (root / subject.HISTORY_SOURCE).write_bytes(changed)
            with self.assertRaises(ValueError):
                module.verify_unchanged(history)

    def test_typed_splices_pins_and_rebound_authority_cannot_use_numeric_aliases(self):
        raw = (ROOT / SECOND).read_bytes()
        for mode in ('offset-float', 'offset-bool', 'bytes-float'):
            with self.subTest(mode=mode):
                row = deepcopy(self.records[SECOND])
                if mode == 'offset-float':
                    row['splices'][0]['offset'] = float(row['splices'][0]['offset'])
                elif mode == 'offset-bool':
                    row['splices'][0]['offset'] = False
                else:
                    row['current']['bytes'] = float(row['current']['bytes'])
                with self.assertRaises(ValueError):
                    subject._inverse(SECOND, raw, row)
        frozen = (ROOT / cold.FIXTURE).read_bytes()
        previous = (ROOT / cold.PREVIOUS_FIXTURE).read_bytes()
        value = json.loads(frozen)
        value['previous_authority']['bytes'] = float(value['previous_authority']['bytes'])
        changed = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        with mock.patch.object(subject, 'FIXTURE_PIN', subject.pin(changed)):
            with self.assertRaises(ValueError):
                subject._relations(changed, previous)

    def test_binding_rejects_cross_paths_numeric_aliases_and_false_terminal_claims(self):
        with self.tree() as root:
            raw = (root / SOURCE).read_bytes()
            prior, proof = subject.cold_caller_source(root, SOURCE, raw)
            entry = {'path': SOURCE, 'current_bytes': len(prior),
                     'current_sha256': sha256(prior).hexdigest()}
            bound = subject.bind_cold_caller_adjustment(entry, raw, proof)
            self.assertEqual(bound['current_sha256'], sha256(raw).hexdigest())
            for field in ('complete_predecessor_restored', 'complete_current_replayed',
                          'terminal_reread_identical', 'whole_native_delivery_qualified'):
                with self.subTest(field=field):
                    changed = deepcopy(proof)
                    changed[field] = int(changed[field])
                    with self.assertRaises(ValueError):
                        subject.bind_cold_caller_adjustment(entry, raw, changed)
            for mode in ('path', 'entry-bytes', 'authority-bytes', 'capture-bytes', 'reader'):
                with self.subTest(mode=mode):
                    changed = deepcopy(proof)
                    changed_entry = dict(entry)
                    if mode == 'path':
                        changed_entry['path'] = SECOND
                    elif mode == 'entry-bytes':
                        changed_entry['current_bytes'] = float(len(prior))
                    elif mode == 'authority-bytes':
                        changed['authority']['bytes'] = float(changed['authority']['bytes'])
                    elif mode == 'capture-bytes':
                        changed['actual_captured_files'][SOURCE]['bytes'] = float(len(raw))
                    else:
                        changed['reader']['sha256'] = '0' * 64
                    with self.assertRaises(ValueError):
                        subject.bind_cold_caller_adjustment(changed_entry, raw, changed)

    def test_actual_journal_gate_keeps_original_21_methods_and_budgets(self):
        from tests import hia_journal_installed_preparation as journal
        from tests.hia_installed_distribution_history import FIXTURE as installed_fixture
        from tests.hia_component_authoring_history import FIXTURE as component_fixture
        names = (*journal.SOURCE_PATHS, installed_fixture, component_fixture)
        with self.tree(names) as root:
            physical = (root / journal.PATH).read_bytes()
            prior = cold.original_caller_source(root, journal.PATH, physical)
            counts = Counter()

            def take(path):
                self.assertTrue(path.is_relative_to(root))
                counts[path.relative_to(root).as_posix()] += 1
                return path.read_bytes()

            proof = cold.journal_preparation_from_predecessor(
                root, physical, prior, journal.ORIGINAL, take=take)
            self.assertEqual(proof['original_method_count'], 21)
            self.assertEqual(len(proof['original_method_ids']), 21)
            self.assertEqual(proof['original_build_timeout_seconds'], 120)
            self.assertEqual(proof['original_install_timeout_seconds'], 120)
            self.assertEqual(proof['original_probe_timeout_seconds'], 30)
            self.assertEqual(proof['original_scope_budget_seconds'], 1800)
            physical_proof = proof['native_cold_source_projection']
            self.assertEqual(physical_proof['actual_captured_files'][journal.PATH], cold.pin(physical))
            self.assertEqual(physical_proof['historical_view_files'][journal.PATH], cold.pin(prior))
            self.assertNotEqual(physical, prior)
            self.assertTrue(all(counts[name] >= 2 for name in names))
            self.assertTrue(physical_proof['terminal_reread_identical'])

    def test_actual_journal_late_real_inputs_and_supplied_predecessor_cannot_drift(self):
        from tests import hia_journal_installed_preparation as journal
        from tests.hia_installed_distribution_history import FIXTURE as installed_fixture
        from tests.hia_component_authoring_history import FIXTURE as component_fixture
        names = (*journal.SOURCE_PATHS, installed_fixture, component_fixture)
        for name in names:
            with self.subTest(path=name), self.tree(names) as root:
                physical = (root / journal.PATH).read_bytes()
                prior = cold.original_caller_source(root, journal.PATH, physical)
                counts = Counter()
                fired = []

                def take(path):
                    data = path.read_bytes()
                    counts[path] += 1
                    if path == root / name and counts[path] == 2:
                        path.write_bytes(data + b'\n')
                        fired.append(name)
                    return data

                with self.assertRaises(ValueError):
                    cold.journal_preparation_from_predecessor(
                        root, physical, prior, journal.ORIGINAL, take=take)
                self.assertEqual(fired, [name])
        with self.tree(names) as root:
            physical = (root / journal.PATH).read_bytes()
            prior = cold.original_caller_source(root, journal.PATH, physical)
            with self.assertRaises(ValueError):
                cold.journal_preparation_from_predecessor(
                    root, physical, prior + b'\n', journal.ORIGINAL)


if __name__ == '__main__':
    unittest.main()
