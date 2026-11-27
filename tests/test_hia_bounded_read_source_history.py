"""Whole-file and refusal checks for the explicit bounded-read history view."""
from hashlib import sha256
from pathlib import Path
import unittest
from tools.hia_bounded_read_source_history import prior_take

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/hia_legacy_byte_components_ff636"

class BoundedReadHistoryTests(unittest.TestCase):
    def test_both_complete_original_files_are_exact(self):
        for name in ("tests/test_hia_program_tools.py", "tools/hia_core_reference.py"):
            with self.subTest(path=name):
                actual = (ROOT / name).read_bytes()
                original = (FIXTURES / (name + ".txt")).read_bytes()
                self.assertEqual(prior_take(name, actual), original)
                self.assertEqual((ROOT / name).read_bytes(), actual)

    def test_late_added_or_changed_current_bytes_are_refused(self):
        for name in ("tests/test_hia_program_tools.py", "tools/hia_core_reference.py"):
            actual = (ROOT / name).read_bytes()
            for changed in (actual + b"\n", actual.replace(b"import", b"Import", 1)):
                with self.subTest(path=name, sha256=sha256(changed).hexdigest()):
                    with self.assertRaises(ValueError):
                        prior_take(name, changed)

    def test_undeclared_sources_and_mutable_inputs_are_refused(self):
        name = "tests/test_hia_program_tools.py"
        actual = (ROOT / name).read_bytes()
        with self.assertRaises(ValueError):
            prior_take("hepta/hia_program_tools.py", actual)
        with self.assertRaises(TypeError):
            prior_take(name, bytearray(actual))

if __name__ == "__main__":
    unittest.main()
