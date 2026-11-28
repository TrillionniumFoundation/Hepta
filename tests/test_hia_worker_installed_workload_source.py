"""Additional captured-root refusal controls; original worker gates are intact."""
from pathlib import Path
import tempfile
import unittest
from tools import hia_worker_installed_workload_source as workload

ROOT = Path(__file__).resolve().parents[1]


class InstalledWorkloadSourceCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admission = workload.capture_workload_source(ROOT)

    def setUp(self):
        owner = tempfile.TemporaryDirectory(prefix="hia-workload-source-controls-")
        self.addCleanup(owner.cleanup)
        self.root = Path(owner.name)
        for name, raw in self.admission["captured"].items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    def test_01_complete_explicit_foreign_root_retains_exact_original_workload(self):
        admitted = workload.capture_workload_source(self.root)
        self.assertEqual(admitted["original"], self.admission["original"])
        self.assertEqual(workload.pin(admitted["original"]), workload.ORIGINAL)
        self.assertEqual(workload.pin(admitted["physical"]), workload.CURRENT)
        self.assertEqual(admitted["proof"]["source_root"], str(self.root))
        self.assertFalse(admitted["proof"]["historical_bytes_executed"])
        self.assertFalse(admitted["proof"]["native_distribution_qualified"])
        workload.verify_workload_source(admitted)

    def test_02_current_source_requires_both_complete_history_authorities(self):
        fixtures = [name for name in self.admission["captured"] if name.endswith(".json")]
        self.assertEqual(set(fixtures), {
            "tests/fixtures/hia_component_authoring_successor_v1.json",
            "tests/fixtures/hia_installed_distribution_sources.json"})
        for name in fixtures:
            with self.subTest(name=name):
                path = self.root / name
                raw = path.read_bytes()
                path.unlink()
                try:
                    with self.assertRaises(ValueError):
                        workload.capture_workload_source(self.root)
                finally:
                    path.write_bytes(raw)
                path.write_bytes(raw + b"\n")
                try:
                    with self.assertRaises(ValueError):
                        workload.capture_workload_source(self.root)
                finally:
                    path.write_bytes(raw)

    def test_03_exact_original_alone_needs_no_migration_authority(self):
        with tempfile.TemporaryDirectory(prefix="hia-original-workload-") as temporary:
            root = Path(temporary)
            path = root / workload.WORKLOAD
            path.parent.mkdir(parents=True)
            path.write_bytes(self.admission["original"])
            admitted = workload.capture_workload_source(root)
            self.assertEqual(admitted["proof"]["mode"], "EXACT_ORIGINAL_WITHOUT_MIGRATION")
            self.assertEqual(set(admitted["captured"]), {workload.WORKLOAD})
            workload.verify_workload_source(admitted)

    def test_04_physical_source_and_history_terminal_drift_are_rejected(self):
        for name in (workload.WORKLOAD, "tests/fixtures/hia_installed_distribution_sources.json"):
            with self.subTest(name=name):
                admitted = workload.capture_workload_source(self.root)
                path = self.root / name
                raw = path.read_bytes()
                path.write_bytes(raw + b"\n")
                try:
                    with self.assertRaisesRegex(ValueError, "terminal readback"):
                        workload.verify_workload_source(admitted)
                finally:
                    path.write_bytes(raw)

    def test_05_unrecognized_source_foreign_reader_and_symlinks_are_rejected(self):
        for name in (workload.WORKLOAD, workload.SOURCE, *workload.READERS):
            with self.subTest(name=name):
                path = self.root / name
                raw = path.read_bytes()
                path.write_bytes(raw + b"\n")
                try:
                    with self.assertRaises(ValueError):
                        workload.capture_workload_source(self.root)
                finally:
                    path.write_bytes(raw)
        path = self.root / workload.WORKLOAD
        raw = path.read_bytes()
        path.unlink()
        path.symlink_to(ROOT / workload.WORKLOAD)
        try:
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                workload.capture_workload_source(self.root)
        finally:
            path.unlink()
            path.write_bytes(raw)

    def test_06_cached_foreign_bytes_cannot_replace_physical_source_capture(self):
        def take(path):
            raw = Path(path).read_bytes()
            if Path(path) == self.root / workload.WORKLOAD:
                return self.admission["original"]
            return raw
        with self.assertRaisesRegex(ValueError, "physical source"):
            workload.capture_workload_source(self.root, take=take)
