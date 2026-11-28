"""Physical-source custody for the current Evaluation caller composition."""
from hashlib import sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tools import hia_cold_caller_sources as cold
from tools import qualify_hia_evaluation_callers as subject

ROOT = Path(__file__).resolve().parents[1]


class EvaluationColdCallerAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = (ROOT / subject.FIXTURE_NAME).read_bytes()
        if sha256(raw).hexdigest() != subject.FIXTURE_SHA256:
            raise AssertionError("the original caller inventory changed")
        cls.inventory = json.loads(raw)
        cls.records = {row["path"]: row["sha256"]
                       for row in cls.inventory["modules"].values()}
        cls.proof = {}
        subject.admit_original_sources(ROOT, cls.records, source_proof=cls.proof)

    def test_current_callers_keep_complete_original_inventory_and_physical_proofs(self):
        self.assertEqual(self.inventory["all_original_tests"], 183)
        self.assertEqual(self.inventory["ordinary_count"], 81)
        self.assertEqual(self.proof["original_source_sha256"], self.records)
        self.assertTrue(self.proof["terminal_reread_identical"])
        self.assertEqual(self.proof["production_source_exceptions"], [])
        changes = self.proof["reviewed_native_cold_caller_sources"]
        self.assertIn("tests/test_hia_candidate_budget_native.py", changes)
        relations = cold.read_relations((ROOT / cold.FIXTURE).read_bytes(),
            previous_raw=(ROOT / cold.PREVIOUS_FIXTURE).read_bytes())
        for name, proof in changes.items():
            with self.subTest(path=name):
                raw = (ROOT / name).read_bytes()
                self.assertEqual(proof["physical_current"], cold.pin(raw))
                self.assertEqual(proof["predecessor"], relations[name]["predecessor"])
                self.assertTrue(proof["complete_predecessor_restored"])
                self.assertTrue(proof["complete_current_replayed"])
                self.assertTrue(proof["terminal_reread_identical"])
                self.assertFalse(proof["whole_native_delivery_qualified"])
                for captured, expected in proof["actual_captured_files"].items():
                    self.assertEqual(self.proof["captured_source_sha256"][captured],
                                     expected["sha256"])
                    self.assertEqual(cold.pin((ROOT / captured).read_bytes()), expected)

    def test_missing_and_changed_current_authorities_and_callers_are_rejected(self):
        names = set(self.proof["reviewed_native_cold_caller_sources"])
        names.update((cold.FIXTURE, cold.PREVIOUS_FIXTURE, cold.SOURCE))
        actual_read = Path.read_bytes
        for name in sorted(names):
            target = ROOT / name
            for missing in (False, True):
                with self.subTest(path=name, missing=missing):
                    def changed(path):
                        raw = actual_read(path)
                        if path != target:
                            return raw
                        if missing:
                            raise FileNotFoundError(str(path))
                        at = len(raw) // 2
                        return raw[:at] + bytes((raw[at] ^ 1,)) + raw[at + 1:]
                    with patch.object(Path, "read_bytes", changed):
                        with self.assertRaises((ValueError, FileNotFoundError)):
                            subject.admit_original_sources(ROOT, self.records)

    def test_late_current_input_changes_cannot_reuse_a_successful_admission(self):
        names = set(self.proof["reviewed_native_cold_caller_sources"])
        names.update((cold.FIXTURE, cold.PREVIOUS_FIXTURE, cold.SOURCE))
        actual_read = Path.read_bytes
        for name in sorted(names):
            target = ROOT / name
            observed = []
            with self.subTest(path=name):
                def drift(path):
                    raw = actual_read(path)
                    if path != target:
                        return raw
                    observed.append(1)
                    return raw if len(observed) == 1 else raw + b"\n"
                with patch.object(Path, "read_bytes", drift):
                    with self.assertRaises(ValueError):
                        subject.admit_original_sources(ROOT, self.records)
                self.assertGreaterEqual(len(observed), 2)


    def test_current_source_root_cannot_borrow_history_from_the_checkout(self):
        from tempfile import TemporaryDirectory
        from tests import hia_installed_distribution_history as installed
        from tests import hia_component_authoring_history as authoring
        with TemporaryDirectory(prefix="hia-evaluation-cold-root-") as directory:
            stage = Path(directory) / "source"
            unrelated = Path(directory) / "unrelated"
            stage.mkdir()
            unrelated.mkdir()
            for name in self.proof["captured_source_sha256"]:
                path = stage / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / name).read_bytes())
            with patch.object(installed, "ROOT", unrelated), patch.object(authoring, "ROOT", unrelated):
                actual = {}
                subject.admit_original_sources(stage, self.records, source_proof=actual)
                self.assertEqual(actual, self.proof)
            for name in (installed.FIXTURE, authoring.FIXTURE):
                with self.subTest(missing_history=name):
                    self.assertIn(name, self.proof["captured_source_sha256"])
                    path = stage / name
                    raw = path.read_bytes()
                    path.unlink()
                    try:
                        with self.assertRaises((ValueError, FileNotFoundError)):
                            subject.admit_original_sources(stage, self.records)
                    finally:
                        path.write_bytes(raw)


if __name__ == "__main__":
    unittest.main()
