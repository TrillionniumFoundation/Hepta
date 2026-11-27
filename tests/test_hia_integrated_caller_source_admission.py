"""Whole current caller-history controls; source admission grants no execution pass."""
from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_cost_ledger_callers as cost
from tools import qualify_hia_service_context_callers as context
from tools import qualify_hia_store_lifecycle_callers as lifecycle
from tools import hia_frozen_component_sources as history

ROOT = Path(__file__).resolve().parents[1]
SUBJECTS = (cost, context, lifecycle)


def admit(subject, root):
    if subject is lifecycle:
        original = json.loads((root / subject.FIXTURE_NAME).read_bytes())
        return original, subject.admit_original_sources(root, original['source_sha256'])
    return subject.admit_original_callers(root)


def pins(proof):
    if 'captured_files' in proof:
        return {name: value['sha256'] for name, value in proof['captured_files'].items()}
    return proof['captured_source_sha256']


class IntegratedCallerSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        names = {cost._INTEGRATED_HELPER, cost._INTEGRATED_AUTHORITY,
                 cost._DIAGNOSTICS_HELPER, cost._DIAGNOSTICS_AUTHORITY}
        for subject in SUBJECTS:
            names.add(subject.FIXTURE_NAME)
            original = json.loads((ROOT / subject.FIXTURE_NAME).read_bytes())
            if subject is cost:
                names.update(module.replace('.', '/') + '.py' for module in original['modules'])
            else:
                names.update(original['source_sha256'])
        cls.sources = {name: (ROOT / name).read_bytes() for name in names}
        cls.qualifiers = {Path(subject.__file__): Path(subject.__file__).read_bytes()
                          for subject in SUBJECTS}

    @classmethod
    def tearDownClass(cls):
        if cls.sources != {name: (ROOT / name).read_bytes() for name in cls.sources}:
            raise AssertionError('integrated source-control input changed')
        if cls.qualifiers != {path: path.read_bytes() for path in cls.qualifiers}:
            raise AssertionError('qualifier changed during source controls')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hia-integrated-caller-sources-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name, raw in self.sources.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    @contextmanager
    def change(self, name, raw):
        path = self.root / name
        original = path.read_bytes()
        if raw is None:
            path.unlink()
        else:
            path.write_bytes(raw)
        try:
            yield
        finally:
            path.write_bytes(original)

    def test_01_actual_current_sources_keep_complete_original_tables_and_distinct_proofs(self):
        for subject, count in zip(SUBJECTS, (81, 50, 50)):
            with self.subTest(subject=subject.__name__):
                original, proof = admit(subject, self.root)
                self.assertEqual(len(original['ordered_ids']), count)
                integrated = proof['reviewed_integrated_source_adjustments']
                self.assertEqual(set(integrated), set(cost._INTEGRATED_CURRENT) & set(pins(proof)))
                for name, entry in integrated.items():
                    self.assertEqual(entry['physical'], cost._INTEGRATED_CURRENT[name])
                    self.assertEqual(entry['reviewed_predecessor'], cost._INTEGRATED_REVIEWED[name])
                    self.assertEqual(pins(proof)[name], sha256(self.sources[name]).hexdigest())
                    self.assertFalse(entry['whole_native_delivery_qualified'])
                diagnostic = proof['reviewed_diagnostic_source_adjustments'][cost._DIAGNOSTICS_CALLER]
                self.assertEqual(diagnostic['current'], cost._INTEGRATED_REVIEWED[cost._DIAGNOSTICS_CALLER])
                self.assertEqual(diagnostic['original_deadline_seconds'], 5)
                self.assertEqual(diagnostic['original_native_budget_ms'], 1)
                self.assertEqual(diagnostic['exact_splices'], 2)
                self.assertEqual(proof['production_source_exceptions'], [])
                self.assertIn(cost._INTEGRATED_HELPER, pins(proof))
                self.assertIn(cost._INTEGRATED_AUTHORITY, pins(proof))

    def test_02_selected_root_missing_or_changed_history_cannot_use_default_repository(self):
        for subject in SUBJECTS:
            for name in (cost._INTEGRATED_HELPER, cost._INTEGRATED_AUTHORITY):
                for raw in (None, self.sources[name] + b'\n'):
                    with self.subTest(subject=subject.__name__, path=name, missing=raw is None):
                        with self.change(name, raw), self.assertRaises((ValueError, FileNotFoundError)):
                            admit(subject, self.root)

    def test_03_every_actual_capture_is_reread_and_refuses_terminal_drift(self):
        real_read = Path.read_bytes
        for subject in SUBJECTS:
            _, proof = admit(subject, self.root)
            for name in pins(proof):
                target, reads = self.root / name, []
                def changed(path):
                    raw = real_read(path)
                    if path == target:
                        reads.append(True)
                        if len(reads) > 1:
                            return raw + b'\n'
                    return raw
                with self.subTest(subject=subject.__name__, path=name):
                    with patch.object(Path, 'read_bytes', changed), self.assertRaises(ValueError):
                        admit(subject, self.root)
                    self.assertGreaterEqual(len(reads), 2)

    def test_04_unknown_whole_sources_do_not_enter_fixed_history(self):
        for subject in SUBJECTS:
            _, proof = admit(subject, self.root)
            for name in set(cost._INTEGRATED_CURRENT) & set(pins(proof)):
                with self.subTest(subject=subject.__name__, path=name):
                    with self.change(name, self.sources[name] + b'\n'):
                        with patch.object(history, 'reviewed_source', wraps=history.reviewed_source) as reviewed:
                            with self.assertRaises(ValueError):
                                admit(subject, self.root)
                            self.assertNotIn(name, [call.args[1] for call in reviewed.call_args_list])

    def test_05_complete_reviewed_output_pin_cannot_be_substituted(self):
        for subject in SUBJECTS:
            with self.subTest(subject=subject.__name__):
                with patch.object(history, 'reviewed_source', return_value=b'partial original'):
                    with self.assertRaises(ValueError):
                        admit(subject, self.root)

    def test_06_actual_capture_binding_retains_physical_current_bytes(self):
        for subject in (cost, context):
            _, proof = admit(subject, self.root)
            current = pins(proof)
            subject.bind_admission_to_source_capture(proof, current)
            for name in proof['reviewed_integrated_source_adjustments']:
                wrong = dict(current)
                wrong[name] = cost._INTEGRATED_REVIEWED[name]['sha256']
                with self.subTest(subject=subject.__name__, path=name), self.assertRaises(ValueError):
                    subject.bind_admission_to_source_capture(proof, wrong)

    def test_07_old_source_domains_do_not_gain_history_captures_or_proofs(self):
        for name in cost._INTEGRATED_CURRENT:
            restored = history.reviewed_source(ROOT, name, self.sources[name])
            (self.root / name).write_bytes(restored)
        for subject in SUBJECTS:
            _, proof = admit(subject, self.root)
            self.assertNotIn('reviewed_integrated_source_adjustments', proof)
            self.assertNotIn(cost._INTEGRATED_HELPER, pins(proof))
            self.assertNotIn(cost._INTEGRATED_AUTHORITY, pins(proof))
        self.assertEqual(len(admit(cost, self.root)[1]['captured_files']), 10)

    def test_08_all_captured_members_refuse_missing_or_tampered_bytes(self):
        for subject in SUBJECTS:
            _, proof = admit(subject, self.root)
            for name in pins(proof):
                for raw in (None, self.sources[name] + b'\n'):
                    with self.subTest(subject=subject.__name__, path=name, missing=raw is None):
                        with self.change(name, raw), self.assertRaises((ValueError, FileNotFoundError)):
                            admit(subject, self.root)


if __name__ == '__main__':
    unittest.main()
