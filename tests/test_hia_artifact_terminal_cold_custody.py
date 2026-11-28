"""Capture controls for cold-wired installed artifact history.

These source checks do not qualify native execution or installed behavior.
"""
from pathlib import Path
import tempfile
import unittest

from tests import hia_component_authoring_history as component
from tests import hia_installed_distribution_history as installed
from tests import hia_service_artifact_worker_terminal as producer
from tools import hia_cold_caller_sources as cold
from tools import read_hia_service_artifact_worker_terminal as reader

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "tests/test_hia_service_artifact_native.py"
HISTORY = (
    cold.FIXTURE,
    cold.PREVIOUS_FIXTURE,
    cold.SOURCE,
    installed.FIXTURE,
    component.FIXTURE,
    "tests/hia_installed_distribution_history.py",
    "tests/hia_component_authoring_history.py",
)


def stage(root, captures):
    for name, raw in captures.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)


class ArtifactTerminalColdCustodyTests(unittest.TestCase):
    def setUp(self):
        self.original = producer.SourceAuthority(ROOT)
        self.addCleanup(self.original.finish)

    def test_both_readers_capture_the_complete_selected_root(self):
        self.assertTrue(set(HISTORY) <= set(self.original.captured))
        with tempfile.TemporaryDirectory(prefix="hia-artifact-cold-root-") as temporary:
            root = Path(temporary)
            stage(root, self.original.captured)
            actual = producer.SourceAuthority(root)
            captures = reader.Captures()
            independent = reader.admit_source_authority(captures, root)
            self.assertEqual(actual.summary(), independent)
            self.assertEqual(independent, self.original.summary())
            for name in HISTORY:
                self.assertEqual(actual.captured[name], (root / name).read_bytes())
                self.assertEqual(captures.records[root / name], actual.captured[name])
            self.assertNotEqual(actual.captured[SOURCE], actual.originals[SOURCE])
            self.assertEqual(independent["current_sources"][SOURCE],
                             producer.pin(actual.captured[SOURCE]))
            self.assertEqual(independent["original_sources"][SOURCE],
                             producer.pin(actual.originals[SOURCE]))
            self.assertIs(independent["legacy_pass_transferred"], False)
            self.assertIs(independent["original_Native8_replaced"], False)
            actual.finish()
            captures.stable()

    def test_missing_or_changed_history_cannot_borrow_the_live_tree(self):
        with tempfile.TemporaryDirectory(prefix="hia-artifact-cold-missing-") as temporary:
            root = Path(temporary)
            stage(root, self.original.captured)
            for name in HISTORY:
                path = root / name
                original = path.read_bytes()
                for operation in ("missing", "changed"):
                    with self.subTest(path=name, operation=operation):
                        if operation == "missing":
                            path.unlink()
                        else:
                            path.write_bytes(original + b"\n")
                        try:
                            with self.assertRaises((ValueError, OSError)):
                                producer.SourceAuthority(root)
                            with self.assertRaises((ValueError, OSError)):
                                reader.admit_source_authority(reader.Captures(), root)
                        finally:
                            path.write_bytes(original)

    def test_shared_current_dependencies_keep_their_original_semantics(self):
        for name in ("hepta/hia_agent_service.py",
                     "tests/test_hia_native_delivery.py"):
            with self.subTest(path=name):
                physical = (ROOT / name).read_bytes()
                self.assertEqual(installed.predecessor(name, physical, root=ROOT), physical)

    def test_each_consumed_history_file_remains_bound_until_terminal(self):
        with tempfile.TemporaryDirectory(prefix="hia-artifact-cold-terminal-") as temporary:
            root = Path(temporary)
            stage(root, self.original.captured)
            actual = producer.SourceAuthority(root)
            captures = reader.Captures()
            reader.admit_source_authority(captures, root)
            for name in HISTORY:
                path = root / name
                original = path.read_bytes()
                with self.subTest(path=name):
                    path.write_bytes(original + b"\n")
                    try:
                        with self.assertRaises(ValueError):
                            actual.finish()
                        with self.assertRaises(ValueError):
                            captures.stable()
                    finally:
                        path.write_bytes(original)
            actual.finish()
            captures.stable()


if __name__ == "__main__":
    unittest.main()
