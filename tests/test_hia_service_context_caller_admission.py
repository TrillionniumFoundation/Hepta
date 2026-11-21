"""Retained fifty-caller authority and exact diagnostic source admission."""
from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
from tests.hia_historical_diagnostic_controls import diagnostic_predecessor
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_service_context_callers as subject

ROOT = Path(__file__).resolve().parents[1]


def inverse(raw, value):
    original = raw
    for item in reversed(value['splices']):
        at = item['new_offset']
        before, after = bytes.fromhex(item['old_hex']), bytes.fromhex(item['new_hex'])
        if original[at:at + len(after)] != after:
            raise AssertionError('fixed current diagnostic splice differs')
        original = original[:at] + before + original[at + len(after):]
    if {'bytes': len(original), 'sha256': sha256(original).hexdigest()} != value['original']:
        raise AssertionError('full retained diagnostic caller differs')
    replay = original
    for item in reversed(value['splices']):
        at = item['old_offset']
        before, after = bytes.fromhex(item['old_hex']), bytes.fromhex(item['new_hex'])
        if replay[at:at + len(before)] != before:
            raise AssertionError('fixed retained diagnostic splice differs')
        replay = replay[:at] + after + replay[at + len(before):]
    if replay != raw:
        raise AssertionError('whole diagnostic forward replay differs')
    return original


class ServiceContextCallerAdmissionSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = (ROOT / subject.FIXTURE_NAME).read_bytes()
        if sha256(fixture).hexdigest() != subject.FIXTURE_SHA256:
            raise AssertionError('retained fifty-caller authority changed')
        cls.frozen = json.loads(fixture)
        names = set(cls.frozen['source_sha256']) | {
            subject.FIXTURE_NAME, subject._DIAGNOSTICS_HELPER,
            subject._DIAGNOSTICS_AUTHORITY,
            'tools/qualify_hia_service_context_callers.py',
            'tests/test_hia_service_context_caller_admission.py'}
        cls.sources = {name: (ROOT / name).read_bytes() for name in sorted(names)}
        cls.actual_diagnostic = cls.sources[subject._DIAGNOSTICS_CALLER]
        cls.sources[subject._DIAGNOSTICS_CALLER] = diagnostic_predecessor(ROOT, cls.actual_diagnostic)
        cls.original = inverse(cls.sources[subject._DIAGNOSTICS_CALLER],
                               json.loads(cls.sources[subject._DIAGNOSTICS_AUTHORITY]))

    @classmethod
    def tearDownClass(cls):
        pinned = {**cls.sources, subject._DIAGNOSTICS_CALLER:cls.actual_diagnostic}
        if pinned != {name: (ROOT / name).read_bytes() for name in pinned}:
            raise AssertionError('context caller Source inputs changed')

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='hia-context-callers-source-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for name, raw in self.sources.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    @contextmanager
    def change(self, name, raw):
        path = self.root / name
        before = path.read_bytes()
        if raw is None:
            path.unlink()
        else:
            path.write_bytes(raw)
        try:
            yield
        finally:
            path.write_bytes(before)

    def test_01_complete_literal_and_current_fifty_callers_keep_original_authority(self):
        for current in (False, True):
            raw = self.sources[subject._DIAGNOSTICS_CALLER] if current else self.original
            with self.subTest(current=current), self.change(subject._DIAGNOSTICS_CALLER, raw):
                actual, proof = subject.admit_original_callers(self.root)
                self.assertEqual(actual, self.frozen)
                self.assertEqual(proof['original_ordered_ids'], self.frozen['ordered_ids'])
                self.assertEqual(len(proof['original_ordered_ids']), 50)
                self.assertEqual(proof['original_modules'], self.frozen['modules'])
                self.assertEqual(proof['original_files'], self.frozen['source_sha256'])
                self.assertEqual(proof['production_source_exceptions'], [])
                self.assertTrue(proof['terminal_reread_identical'])
                self.assertTrue(proof['original_inventory_bytes_unchanged'])
                self.assertFalse(proof['whole_native'])
                adjustments = proof['reviewed_diagnostic_source_adjustments']
                self.assertEqual(set(adjustments), {subject._DIAGNOSTICS_CALLER} if current else set())
                if current:
                    relation = adjustments[subject._DIAGNOSTICS_CALLER]
                    self.assertEqual(relation['original_deadline_seconds'], 5)
                    self.assertEqual(relation['original_native_budget_ms'], 1)
                    self.assertEqual(relation['exact_splices'], 2)
        with self.change(subject._DIAGNOSTICS_CALLER, self.original), \
                self.change(subject._DIAGNOSTICS_HELPER, None), \
                self.change(subject._DIAGNOSTICS_AUTHORITY, None):
            actual, proof = subject.admit_original_callers(self.root)
            self.assertEqual(actual, self.frozen)
            self.assertEqual(proof['reviewed_diagnostic_source_adjustments'], {})

    def test_02_every_capture_refuses_missing_tamper_repeat_and_terminal_drift(self):
        _, proof = subject.admit_original_callers(self.root)
        self.assertEqual(len(proof['captured_files']), 7)
        for name in proof['captured_files']:
            for mode in ('missing', 'tamper', 'no-cache', 'terminal-drift'):
                with self.subTest(path=name, mode=mode):
                    if mode == 'no-cache':
                        subject.admit_original_callers(self.root)
                    if mode == 'terminal-drift':
                        target = self.root / name
                        real_read, calls = Path.read_bytes, []
                        def changed(path):
                            raw = real_read(path)
                            if path == target:
                                calls.append(True)
                                if len(calls) > 1:
                                    return raw + b'\n'
                            return raw
                        with patch.object(Path, 'read_bytes', changed), self.assertRaises(ValueError):
                            subject.admit_original_callers(self.root)
                        self.assertGreaterEqual(len(calls), 2)
                    else:
                        raw = None if mode == 'missing' else self.sources[name] + b'\n'
                        with self.change(name, raw), self.assertRaises((ValueError, FileNotFoundError)):
                            subject.admit_original_callers(self.root)

    def test_03_complete_before_and_after_capture_binding_rejects_gaps_and_changes(self):
        _, proof = subject.admit_original_callers(self.root)
        captured = {name: sha256((self.root / name).read_bytes()).hexdigest()
                    for name in proof['captured_files']}
        subject.bind_admission_to_source_capture(proof, captured)
        for name in captured:
            missing, changed = dict(captured), dict(captured)
            missing.pop(name)
            changed[name] = '0' * 64
            for altered in (missing, changed):
                with self.subTest(path=name), self.assertRaises(ValueError):
                    subject.bind_admission_to_source_capture(proof, altered)
        with self.change(subject._DIAGNOSTICS_AUTHORITY,
                         self.sources[subject._DIAGNOSTICS_AUTHORITY] + b'\n'):
            actual = {name: sha256((self.root / name).read_bytes()).hexdigest()
                      for name in proof['captured_files']}
            with self.assertRaises(ValueError):
                subject.bind_admission_to_source_capture(proof, actual)


if __name__ == '__main__':
    unittest.main()
