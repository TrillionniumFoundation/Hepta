"""Exercise real Delivery source custody across the native cold caller history."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import hia_component_authoring_history as component_history
from tests import hia_installed_distribution_history as installed_history
from tests import hia_native_transport_worker_successor as subject
from tests import test_hia_native_delivery as native
from tests import test_hia_store_native_delivery as store
from tools import hia_cold_caller_sources as cold


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_FIXTURE = 'tests/fixtures/hia_caller_terminal_cold_admission_20261128.json'
TARGET = 'tests/test_hia_candidate_budget_native.py'
OUTERS = (('native', native, 64), ('store', store, 89))


class DeliveryColdSourceCustodyTests(unittest.TestCase):
    def test_actual_current_complete_outer_inventories_bind_cold_physical_sources(self):
        for kind, outer, count in OUTERS:
            with self.subTest(kind=kind):
                value = outer.admit_originals()
                self.assertEqual(len(value['unchanged_files']), count)
                entry = value['transport_terminal_successor']['source_adjustments'][TARGET]
                proof = entry['native_cold_caller_source']
                self.assertEqual(entry['original_sha256'],
                                 value['unchanged_files'][TARGET]['sha256'])
                self.assertEqual(entry['original_bytes'],
                                 value['unchanged_files'][TARGET]['bytes'])
                physical = subject._pin((ROOT / TARGET).read_bytes())
                self.assertEqual(proof['physical_current'], physical)
                self.assertEqual(entry['current_sha256'], physical['sha256'])
                self.assertEqual(entry['current_bytes'], physical['bytes'])
                self.assertTrue(proof['complete_predecessor_restored'])
                self.assertTrue(proof['complete_current_replayed'])
                self.assertTrue(proof['terminal_reread_identical'])
                self.assertFalse(proof['whole_native_delivery_qualified'])
                for name, expected in proof['actual_captured_files'].items():
                    self.assertEqual(subject._pin((ROOT / name).read_bytes()), expected)

    def test_missing_tampered_and_cached_authorities_fail_closed(self):
        original_read = Path.read_bytes
        for kind, outer, _ in OUTERS:
            outer.admit_originals()
            for name in (RUNTIME_FIXTURE, cold.FIXTURE, cold.PREVIOUS_FIXTURE, cold.SOURCE):
                for action in ('missing', 'tamper'):
                    target = ROOT / name

                    def read(path):
                        if path == target:
                            if action == 'missing':
                                raise FileNotFoundError(str(path))
                            return original_read(path) + b'\n'
                        return original_read(path)

                    with self.subTest(kind=kind, path=name, action=action):
                        with patch.object(Path, 'read_bytes', read):
                            with self.assertRaises((AssertionError, ValueError, FileNotFoundError)):
                                outer.admit_originals()

    def test_selected_root_cannot_borrow_a_live_cold_caller(self):
        inventory = json.loads(native.ORIGINAL.read_bytes())
        selected = {'unchanged_files': {TARGET: inventory['unchanged_files'][TARGET]}}
        authorities = (installed_history.FIXTURE, component_history.FIXTURE,
                       cold.FIXTURE, cold.PREVIOUS_FIXTURE, cold.SOURCE)
        with tempfile.TemporaryDirectory(prefix='delivery-cold-root-') as temporary:
            root = Path(temporary)
            for name in authorities:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / name).read_bytes())
            with self.assertRaises(FileNotFoundError):
                subject.delivery_sources(root, selected, {'source_adjustments': {}})
            target = root / TARGET
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / TARGET).read_bytes() + b'\n')
            refused = subject.delivery_sources(root, selected, {'source_adjustments': {}})
            self.assertNotIn(TARGET, refused['source_adjustments'])
            target.write_bytes((ROOT / TARGET).read_bytes())
            accepted = subject.delivery_sources(root, selected, {'source_adjustments': {}})
            self.assertIn(TARGET, accepted['source_adjustments'])
            (root / cold.FIXTURE).write_bytes((ROOT / cold.FIXTURE).read_bytes() + b'\n')
            with self.assertRaises(ValueError):
                subject.delivery_sources(root, selected, {'source_adjustments': {}})

    def test_runtime_history_binds_the_callers_selected_physical_root(self):
        raw = (ROOT / subject.QUALIFIER_DEPENDENCY_PATH).read_bytes()
        with tempfile.TemporaryDirectory(prefix='delivery-runtime-root-') as temporary:
            root = Path(temporary)
            fixture = root / RUNTIME_FIXTURE
            fixture.parent.mkdir(parents=True, exist_ok=True)
            fixture.write_bytes((ROOT / RUNTIME_FIXTURE).read_bytes())
            with self.assertRaises(FileNotFoundError):
                subject.reviewed_qualifier_dependency(raw, lambda name: (root / name).read_bytes())
            target = root / subject.QUALIFIER_DEPENDENCY_PATH
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw + b'\n')
            with self.assertRaises(ValueError):
                subject.reviewed_qualifier_dependency(raw, lambda name: (root / name).read_bytes())

    def test_every_new_authority_and_runtime_are_reread_at_terminal(self):
        original_read = Path.read_bytes
        for kind, outer, _ in OUTERS:
            for name in (RUNTIME_FIXTURE, subject.QUALIFIER_DEPENDENCY_PATH,
                         cold.FIXTURE, cold.PREVIOUS_FIXTURE, cold.SOURCE, TARGET):
                seen = []
                target = ROOT / name

                def read(path):
                    raw = original_read(path)
                    if path == target:
                        seen.append(True)
                        if len(seen) > 1:
                            return raw + b'\n'
                    return raw

                with self.subTest(kind=kind, path=name):
                    with patch.object(Path, 'read_bytes', read):
                        with self.assertRaises((AssertionError, ValueError)):
                            outer.admit_originals()
                    self.assertGreaterEqual(len(seen), 2)

    def test_cold_adjustment_cannot_erase_outer_physical_source_binding(self):
        real_admit = subject.admit_terminal_sources
        for kind, outer, _ in OUTERS:
            completed = []

            def alter(*args, **kwargs):
                value = deepcopy(real_admit(*args, **kwargs))
                completed.append(True)
                value['source_adjustments'][TARGET]['current_sha256'] = '0' * 64
                return value

            with self.subTest(kind=kind):
                with patch.object(subject, 'admit_terminal_sources', alter):
                    with self.assertRaises(AssertionError):
                        outer.admit_originals()
                self.assertTrue(completed)


if __name__ == '__main__':
    unittest.main()
