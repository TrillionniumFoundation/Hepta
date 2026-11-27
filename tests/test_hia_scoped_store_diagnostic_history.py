"""Actual Store diagnostic admission through the scoped qualifier source view."""
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import hia_native_transport_worker_successor as transport
from tools import hia_scoped_caller_admission_history as scoped

ROOT = Path(__file__).resolve().parents[1]
QUALIFIER = 'tools/qualify_hia_evaluation_callers.py'
SCOPED_INPUTS = (
    QUALIFIER,
    'tools/hia_scoped_caller_admission_history.py',
    'tests/fixtures/hia_scoped_evaluation_cold_preparation_v1.json',
    'tools/hia_frozen_component_sources.py',
)


BROAD_CALLERS = (
    'tests/test_hia_candidate_budget_native.py',
    'tests/test_hia_emission_native.py',
    'tests/test_hia_execution_budget_native.py',
    'tests/test_hia_execution_observation_native.py',
    'tests/test_hia_native_build_dispatch.py',
    'tests/test_hia_service_context_native.py',
    'tests/test_hia_slot_ledger_native_integration.py',
    'tests/test_hia_store_artifact_profile_native.py',
    'tools/qualify_hia_agent_journal_callers.py',
)
SHARED_CALLER = 'tools/qualify_hia_native_delivery.py'


class ScopedStoreDiagnosticHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.captured = {}
        read_bytes = Path.read_bytes

        def capture(path):
            raw = read_bytes(path)
            try:
                name = path.relative_to(ROOT).as_posix()
            except ValueError:
                return raw
            if name in cls.captured and cls.captured[name][0] != raw:
                raise ValueError('Store diagnostic fixture changed while captured')
            cls.captured[name] = (raw, path.stat().st_mode & 0o777)
            return raw

        with patch.object(Path, 'read_bytes', capture):
            cls.original = json.loads((ROOT / transport.ORIGINALS['store'][0]).read_bytes())
            cls.actual = transport.admit_terminal_sources(cls.original, original_kind='store')
            projected, history = scoped.prepare(ROOT, {QUALIFIER: capture(ROOT / QUALIFIER)})
            if history is None:
                raise AssertionError('the actual qualifier needs its scoped source relation')
            cls.prior = projected[QUALIFIER]
            scoped.verify_unchanged(history)
        if any(read_bytes(ROOT / name) != raw for name, (raw, _) in cls.captured.items()):
            raise ValueError('Store diagnostic original fixture changed at terminal')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hia-store-scoped-diagnostic-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name, (raw, mode) in self.captured.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(mode)

    def admit(self):
        with patch.object(transport, 'ROOT', self.root):
            return transport.admit_terminal_sources(self.original, original_kind='store')

    def test_actual_qualifier_preserves_original_and_physical_source_identity(self):
        result = self.admit()
        self.assertEqual(result, self.actual)
        entry = result['source_adjustments'][QUALIFIER]
        raw = (self.root / QUALIFIER).read_bytes()
        self.assertEqual(
            {'bytes': entry['current_bytes'], 'sha256': entry['current_sha256']},
            transport._pin(raw))
        self.assertEqual(
            {'bytes': entry['original_bytes'], 'sha256': entry['original_sha256']},
            transport.DIAGNOSTIC_RECORDS[QUALIFIER]['old'])
        self.assertIn('scoped_caller_source_history', entry)
        review = result['caller_diagnostic_source_admission']
        for name in SCOPED_INPUTS:
            self.assertEqual(review['actual_captured_files'][name],
                             transport._pin((self.root / name).read_bytes()))
        self.assertNotEqual(transport._pin(raw), transport._pin(self.prior))
        self.assertEqual(review['complete_old_source_pins'][QUALIFIER],
                         transport.DIAGNOSTIC_RECORDS[QUALIFIER]['old'])

    def test_missing_or_tampered_scoped_inputs_are_rejected(self):
        for name in SCOPED_INPUTS:
            for missing in (True, False):
                with self.subTest(path=name, missing=missing):
                    path = self.root / name
                    raw = path.read_bytes()
                    try:
                        if missing:
                            path.unlink()
                        else:
                            path.write_bytes(raw + b' ')
                        with self.assertRaises((ValueError, FileNotFoundError)):
                            self.admit()
                    finally:
                        path.write_bytes(raw)

    def test_changes_after_the_complete_diagnostic_inverse_are_rejected(self):
        reverse = transport.reverse_diagnostic_source
        cases = [(name, self.captured[name][0] + b' ') for name in SCOPED_INPUTS]
        cases.append((QUALIFIER, self.prior))
        for name, replacement in cases:
            with self.subTest(path=name, replacement_sha256=sha256(replacement).hexdigest()):
                path = self.root / name
                raw = path.read_bytes()
                fired = []

                def changed_after_inverse(source, record, selected):
                    result = reverse(source, record, selected)
                    if selected == QUALIFIER and not fired:
                        fired.append(True)
                        path.write_bytes(replacement)
                    return result

                try:
                    with patch.object(transport, 'reverse_diagnostic_source', changed_after_inverse):
                        with self.assertRaises(ValueError):
                            self.admit()
                    self.assertEqual(fired, [True])
                finally:
                    path.write_bytes(raw)

    def test_unreviewed_qualifier_cannot_gain_the_original_diagnostic_identity(self):
        path = self.root / QUALIFIER
        path.write_bytes(path.read_bytes() + b'\n# unreviewed current source\n')
        with self.assertRaises(ValueError):
            self.admit()


    def test_complete_cold_and_component_callers_keep_fixed_original_identities(self):
        result = self.admit()
        for name in BROAD_CALLERS:
            with self.subTest(path=name):
                entry = result['source_adjustments'][name]
                self.assertEqual(
                    {'bytes': entry['original_bytes'], 'sha256': entry['original_sha256']},
                    self.original['unchanged_files'][name])
                self.assertEqual(
                    {'bytes': entry['current_bytes'], 'sha256': entry['current_sha256']},
                    transport._pin((self.root / name).read_bytes()))
                self.assertNotEqual(entry['original_sha256'], entry['current_sha256'])
                self.assertTrue(
                    'native_cold_caller_source' in entry or
                    'native_composition_source_history' in entry)
        shared = result['shared_adjustments'][SHARED_CALLER]
        self.assertEqual(
            {'bytes': shared['original_bytes'], 'sha256': shared['original_sha256']},
            self.original['shared_dependency_review'][SHARED_CALLER])
        self.assertEqual(result['shared_dependency_review'][SHARED_CALLER],
                         transport._pin((self.root / SHARED_CALLER).read_bytes()))

    def test_unreviewed_broad_callers_receive_no_original_source_adjustment(self):
        for name in (*BROAD_CALLERS, SHARED_CALLER):
            with self.subTest(path=name):
                path = self.root / name
                raw = path.read_bytes()
                try:
                    path.write_bytes(raw + b'\n# unreviewed caller source\n')
                    try:
                        result = self.admit()
                    except ValueError:
                        continue
                    entries = result['shared_adjustments' if name == SHARED_CALLER
                                     else 'source_adjustments']
                    self.assertNotIn(name, entries)
                finally:
                    path.write_bytes(raw)

    def test_late_caller_and_authority_changes_after_binding_are_rejected(self):
        bind = transport._bind_cold
        cases = (
            (BROAD_CALLERS[0], BROAD_CALLERS[0]),
            (BROAD_CALLERS[6], BROAD_CALLERS[6]),
            (SHARED_CALLER, SHARED_CALLER),
            (BROAD_CALLERS[0], 'tests/fixtures/hia_native_cold_caller_integration_20261127.json'),
            (BROAD_CALLERS[6], 'tools/hia_native_cold_composition_history.py'),
        )
        for bound, name in cases:
            with self.subTest(bound=bound, changed=name):
                path = self.root / name
                raw = path.read_bytes()
                fired = []

                def changed_after_binding(entry, physical, proof):
                    result = bind(entry, physical, proof)
                    if entry['path'] == bound and not fired:
                        fired.append(True)
                        path.write_bytes(raw + b' ')
                    return result

                try:
                    with patch.object(transport, '_bind_cold', changed_after_binding):
                        with self.assertRaises(ValueError):
                            self.admit()
                    self.assertEqual(fired, [True])
                finally:
                    path.write_bytes(raw)


if __name__ == '__main__':
    unittest.main()
