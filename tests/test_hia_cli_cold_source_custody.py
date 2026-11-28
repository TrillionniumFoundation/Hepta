"""Real CLI caller custody through the native cold migration."""
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools import hia_cold_caller_sources as cold
from tools import hia_cli_discovery_compat as compat

ROOT = Path(__file__).resolve().parents[1]
CALLER = "tests/test_hia_cli_native.py"


class CliColdSourceCustodyTests(unittest.TestCase):
    def selected(self, root=ROOT, **kwargs):
        return compat.before_default_cli(CALLER, (root / CALLER).read_text(),
                                         root=root, with_source_admission=True, **kwargs)

    def test_complete_current_source_is_bound_to_the_retained_cli_predecessor(self):
        restored, proof = self.selected()
        raw = (ROOT / CALLER).read_bytes()
        self.assertEqual(proof["physical_current"], {"bytes": len(raw), "sha256": sha256(raw).hexdigest()})
        self.assertEqual(proof["native_cold_caller_source"]["physical_current"], proof["physical_current"])
        self.assertEqual(proof["restored_predecessor"]["sha256"], sha256(restored.encode()).hexdigest())
        self.assertTrue(proof["terminal_reread_identical"])
        self.assertFalse(proof["whole_native_delivery_qualified"])
        for name, expected in proof["captured_files"].items():
            physical = (ROOT / name).read_bytes()
            self.assertEqual(expected, {"bytes": len(physical), "sha256": sha256(physical).hexdigest()})
        self.assertTrue({CALLER, cold.FIXTURE, cold.PREVIOUS_FIXTURE, cold.SOURCE}
                        <= proof["captured_files"].keys())

    def test_every_consumed_authority_missing_tampered_or_changed_late_is_refused(self):
        _, proof = self.selected()
        for name in proof["captured_files"]:
            target = ROOT / name
            for mode in ("missing", "tamper", "late"):
                seen = []
                def take(path):
                    if path == target:
                        seen.append(path)
                        if mode == "missing":
                            raise FileNotFoundError(str(path))
                        if mode == "tamper" or len(seen) > 1:
                            return path.read_bytes() + b"\n"
                    return path.read_bytes()
                with self.subTest(path=name, mode=mode), self.assertRaises(ValueError):
                    self.selected(take=take)

    def test_explicit_root_never_borrows_the_live_caller_or_authority(self):
        expected, proof = self.selected()
        with tempfile.TemporaryDirectory(prefix="cli-cold-root-") as temp:
            root = Path(temp)
            for name in proof["captured_files"]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / name).read_bytes())
            with patch.object(compat, "ROOT", root / "unusable"):
                restored, _ = self.selected(root)
                self.assertEqual(restored, expected)
                (root / cold.FIXTURE).unlink()
                with self.assertRaises(ValueError):
                    self.selected(root)

    def test_unreviewed_current_caller_cannot_acquire_a_cold_exception(self):
        raw = (ROOT / CALLER).read_text()
        for altered in (raw + "\n", raw.replace("compiler_from_cold_report", "compiler_from_wrong_report", 1)):
            self.assertNotEqual(altered, raw)
            with self.assertRaisesRegex(ValueError, "pinned default CLI successor"):
                compat.before_default_cli(CALLER, altered, root=ROOT)
