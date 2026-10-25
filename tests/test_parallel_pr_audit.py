"""Unit tests for exact-source parallel PR integration audit."""
import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "tools" / "audit_parallel_prs.py"
spec = importlib.util.spec_from_file_location("audit_parallel_prs", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

A = "a" * 40
B = "b" * 40
C = "c" * 40

class AuditTests(unittest.TestCase):
    def test_rejects_partial_sha(self):
        with self.assertRaises(ValueError):
            module.check_commit("a" * 39)

    def test_rejects_duplicate_labels_before_git(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(module.main([
                "--base", A, "--candidate", "p14=" + B,
                "--candidate", "p14=" + C, "--output", str(pathlib.Path(d) / "a.json")
            ]), 2)

    def test_exact_diff_and_overlap_including_semantic(self):
        # No real git needed for structural negative-control tests.
        outputs = {
            ("cat-file", "-e", A + "^{commit}"): b"",
            ("cat-file", "-e", B + "^{commit}"): b"",
            ("cat-file", "-e", C + "^{commit}"): b"",
            ("rev-parse", A + "^{commit}"): (A + "\n").encode(),
            ("rev-parse", B + "^{commit}"): (B + "\n").encode(),
            ("rev-parse", C + "^{commit}"): (C + "\n").encode(),
            ("merge-base", A, B): (A + "\n").encode(),
            ("merge-base", A, C): (A + "\n").encode(),
            ("merge-base", B, C): (A + "\n").encode(),
            ("merge-base", C, B): (A + "\n").encode(),
            ("diff", "--name-only", "-z", A, B): b"hepta/checker.py\0some file\nwith newline\0",
            ("diff", "--name-only", "-z", A, C): b"hepta/checker.py\0docs/SPEC.md\0",
        }
        def fake_git(*args):
            return outputs[args]
        with patch.object(module, "git", side_effect=fake_git):
            result = module.audit(A, {"pr14": B, "pr36": C})
        self.assertEqual(result["duplicate_semantic_path_owners"]["hepta/checker.py"],
                         ["pr14", "pr36"])
        self.assertEqual(result["overlaps"][0]["shared_semantic_paths"],
                         ["hepta/checker.py"])
        self.assertIn("some file\nwith newline", result["changed_files"]["pr14"])
        self.assertFalse(result["automatic_merge_approved"])
        self.assertFalse(result["whole_project_blockers_closed"])

    def test_rejects_base_not_ancestor(self):
        def fake_git(*args):
            if args[0] == "cat-file":
                return b""
            if args[0] == "rev-parse":
                return (args[1][:40] + "\n").encode()
            if args[0] == "merge-base":
                return (C + "\n").encode()
            raise AssertionError(args)
        with patch.object(module, "git", side_effect=fake_git):
            with self.assertRaises(ValueError):
                module.audit(A, {"pr14": B, "pr36": C})

    def test_existing_output_never_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "audit.json"
            p.write_text("original")
            with patch.object(module, "audit", return_value={"ok": True}):
                code = module.main(["--base", A, "--candidate", "p14=" + B,
                                    "--candidate", "p36=" + C, "--output", str(p)])
            self.assertEqual(code, 2)
            self.assertEqual(p.read_text(), "original")

if __name__ == "__main__":
    unittest.main()
