"""Physical custody controls for the unchanged first caller authority."""
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest

from tools import hia_cold_caller_sources as cold
from tools import hia_frozen_component_sources as history

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'tests/test_hia_store_native_delivery.py'


class NativeColdCallerIntegrationTests(unittest.TestCase):
    @contextmanager
    def tree(self):
        names = (SOURCE, cold.SOURCE, cold.FIXTURE, cold.PREVIOUS_FIXTURE)
        with tempfile.TemporaryDirectory(prefix='hia-caller-integration-') as directory:
            root = Path(directory)
            for name in names:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / name).read_bytes())
            yield root

    def test_original_authority_is_captured_and_tampering_or_absence_is_refused(self):
        with self.tree() as root:
            raw = (root / SOURCE).read_bytes()
            path = root / cold.PREVIOUS_FIXTURE
            previous = path.read_bytes()
            old, proof = history.cold_caller_source(root, SOURCE, raw, take=Path.read_bytes)
            records = cold.read_relations((root / cold.FIXTURE).read_bytes(), previous_raw=previous)
            self.assertEqual(cold.pin(old), records[SOURCE]['predecessor'])
            self.assertEqual(proof['actual_captured_files'][cold.PREVIOUS_FIXTURE], cold.PREVIOUS_PIN)
            self.assertEqual(proof['original_authority'], {'path': cold.PREVIOUS_FIXTURE, **cold.PREVIOUS_PIN})
            for at in (0, len(previous) // 2, len(previous) - 1):
                with self.subTest(offset=at):
                    changed = bytearray(previous)
                    changed[at] ^= 1
                    path.write_bytes(changed)
                    with self.assertRaises(ValueError):
                        history.cold_caller_source(root, SOURCE, raw, take=Path.read_bytes)
            path.unlink()
            with self.assertRaises(FileNotFoundError):
                history.cold_caller_source(root, SOURCE, raw, take=Path.read_bytes)

    def test_original_authority_drift_after_capture_is_refused_and_restore_is_not_cached(self):
        with self.tree() as root:
            raw = (root / SOURCE).read_bytes()
            path = root / cold.PREVIOUS_FIXTURE
            previous = path.read_bytes()
            fired = []

            def take(current):
                data = current.read_bytes()
                if current == path and not fired:
                    fired.append(True)
                    current.write_bytes(data + b'\n')
                return data

            with self.assertRaises(ValueError):
                history.cold_caller_source(root, SOURCE, raw, take=take)
            self.assertEqual(fired, [True])
            path.write_bytes(previous)
            _, proof = history.cold_caller_source(root, SOURCE, raw, take=Path.read_bytes)
            self.assertTrue(proof['terminal_reread_identical'])
            path.write_bytes(previous + b'\n')
            with self.assertRaises(ValueError):
                history.cold_caller_source(root, SOURCE, raw, take=Path.read_bytes)

    def test_pre_migration_observer_cannot_replace_current_native_caller(self):
        from tools import hia_cold_native_transport_evidence as producer
        from tools import read_hia_cold_native_transport as independent
        name = 'tests/test_hia_selfhost_linked_observer.py'
        current = (ROOT / name).read_bytes()
        records = cold.read_relations((ROOT / cold.FIXTURE).read_bytes(),
                                     previous_raw=(ROOT / cold.PREVIOUS_FIXTURE).read_bytes())
        previous = cold.restore_caller_source(name, current, records)
        old = producer.OBSERVER_SUCCESSORS[name]['old']
        self.assertNotEqual(current, previous)
        self.assertEqual(producer.restore_observer_source(name, current, old),
                         independent.restore_observer_source(name, current, old))
        for reader in (producer.restore_observer_source, independent.restore_observer_source):
            with self.assertRaises(ValueError):
                reader(name, previous, old)


if __name__ == '__main__':
    unittest.main()
