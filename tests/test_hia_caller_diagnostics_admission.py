"""Pure source controls: retain the old caller and admit only reviewed diagnostics."""
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import hia_caller_diagnostics_admission as producer
from tools import read_hia_store_file_capture_callers as reader
from tools import qualify_hia_store_lifecycle_callers as store

ROOT = Path(__file__).resolve().parents[1]


class CallerDiagnosticsSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.current = (ROOT / producer.PATH).read_bytes()
        cls.provenance = (ROOT / producer.FIXTURE).read_bytes()
        if producer.pin(cls.current) != producer.CURRENT:
            raise AssertionError('exact current diagnostic caller differs')
        if sha256(cls.provenance).hexdigest() != producer.FIXTURE_SHA256:
            raise AssertionError('exact diagnostic provenance differs')
        # Independent construction from data; never execute reconstructed tests.
        restored = cls.current
        for row in reversed(json.loads(cls.provenance)['splices']):
            at = row['new_offset']
            after, before = bytes.fromhex(row['new_hex']), bytes.fromhex(row['old_hex'])
            if restored[at:at + len(after)] != after:
                raise AssertionError('diagnostic control splice differs')
            restored = restored[:at] + before + restored[at + len(after):]
        if producer.pin(restored) != producer.ORIGINAL:
            raise AssertionError('complete original diagnostic caller was not restored')
        cls.original = restored

    def test_exact_complete_source_inverse_and_independent_reader(self):
        self.assertEqual(producer.restore(self.current, self.provenance), self.original)
        admitted = producer.admit(producer.PATH, self.current,
                                  producer.ORIGINAL['sha256'], self.provenance)
        self.assertEqual(reader.diagnostic_source_admission(
            self.current, producer.ORIGINAL['sha256'], self.provenance), admitted)
        self.assertEqual(admitted['original_deadline_seconds'], 5)
        self.assertEqual(admitted['original_native_budget_ms'], 1)
        self.assertIs(admitted['production_source_exception'], False)
        self.assertEqual((ROOT / producer.PATH).read_bytes(), self.current)
        self.assertEqual((ROOT / producer.FIXTURE).read_bytes(), self.provenance)

    def test_unreviewed_source_provenance_and_expected_pin_are_refused(self):
        changed_budget = self.current.replace(b'self.assertLess(elapsed, 5, details)',
                                              b'self.assertLess(elapsed, 6, details)')
        self.assertNotEqual(changed_budget, self.current)
        for raw, provenance, expected in (
                (self.current + b'\n', self.provenance, producer.ORIGINAL['sha256']),
                (changed_budget, self.provenance, producer.ORIGINAL['sha256']),
                (self.current, self.provenance + b'\n', producer.ORIGINAL['sha256']),
                (self.current, self.provenance, producer.CURRENT['sha256']),
                (self.original, self.provenance, producer.ORIGINAL['sha256'])):
            with self.subTest(source=sha256(raw).hexdigest(), expected=expected):
                with self.assertRaises(ValueError):
                    producer.admit(producer.PATH, raw, expected, provenance)
                with self.assertRaises(ValueError):
                    reader.diagnostic_source_admission(raw, expected, provenance)
        with self.assertRaises(ValueError):
            producer.admit('hepta/hia_agent_service.py', self.current,
                           producer.ORIGINAL['sha256'], self.provenance)

    def test_complete_store_sources_old_current_and_drift_without_loading_tests(self):
        frozen = (ROOT / store.FIXTURE_NAME).read_bytes()
        original = json.loads(frozen)
        records = original['source_sha256']
        self.assertEqual(len(original['ordered_ids']), 50)
        with tempfile.TemporaryDirectory(prefix='hia-diagnostic-admission-') as temporary:
            root = Path(temporary)
            for name in (*records, store.FIXTURE_NAME, producer.FIXTURE):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / name).read_bytes())
            for raw, expected_adjustments in ((self.original, {}), (self.current, {
                    producer.PATH: producer.admit(producer.PATH, self.current,
                        producer.ORIGINAL['sha256'], self.provenance)})):
                (root / producer.PATH).write_bytes(raw)
                result = store.admit_original_sources(root, records)
                self.assertEqual(result['original_source_sha256'], records)
                self.assertEqual(result['reviewed_diagnostic_source_adjustments'],
                                 expected_adjustments)
                self.assertEqual((root / store.FIXTURE_NAME).read_bytes(), frozen)
                self.assertEqual(result['captured_source_sha256'][producer.PATH],
                                 sha256(raw).hexdigest())
            refreshed = dict(records)
            refreshed[producer.PATH] = producer.CURRENT['sha256']
            with self.assertRaises(ValueError):
                store.admit_original_sources(root, refreshed)
            (root / producer.PATH).write_bytes(self.current + b'\n')
            with self.assertRaises(ValueError):
                store.admit_original_sources(root, records)
            (root / producer.PATH).write_bytes(self.current)
            captured_read = Path.read_bytes
            reads = [0]
            def drift(path):
                if path == root / producer.FIXTURE:
                    reads[0] += 1
                    if reads[0] > 1:
                        return self.provenance + b'\n'
                return captured_read(path)
            with patch.object(Path, 'read_bytes', drift), self.assertRaises(ValueError):
                store.admit_original_sources(root, records)


if __name__ == '__main__':
    unittest.main()
