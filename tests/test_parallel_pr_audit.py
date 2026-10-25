"""Offline and native-git regression coverage for Hepta PR integration audit."""
import importlib.util
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "tools" / "audit_parallel_prs.py"
spec = importlib.util.spec_from_file_location("audit_parallel_prs", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
A, B, C = "a" * 40, "b" * 40, "c" * 40


class AuditTests(unittest.TestCase):
    def test_sha_and_candidate_input_refusals(self):
        with self.assertRaises(ValueError):
            module.check_commit("a" * 39)
        with self.assertRaises(ValueError):
            module.audit(A, {"x": B})
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(module.main(["--base", A, "--candidate", "p14=" + B,
                                          "--candidate", "p14=" + C,
                                          "--output", str(pathlib.Path(d) / "a.json")]), 2)

    def test_truncated_tree_rejected(self):
        with patch.object(module, "git", return_value=b"100644 blob " + A.encode() + b"\ta.py"):
            with self.assertRaisesRegex(ValueError, "truncated"):
                module.tree_entries(A)

    def test_unusual_path_and_submodule_entry(self):
        path = b"some file\nwith newline\t.txt"
        data = b"100644 blob " + B.encode() + b"\t" + path + b"\0" + \
               b"160000 commit " + C.encode() + b"\tsubmodule\0"
        with patch.object(module, "git", return_value=data):
            result = module.tree_entries(A)
        self.assertIn(os.fsdecode(path), result)
        self.assertEqual(result["submodule"]["kind"], "commit")

    def test_overlap_and_semantic_family_detect_disjoint_names(self):
        def listing(*items):
            return b"".join((b"100644 blob " + sha.encode() + b"\t" + name.encode() + b"\0")
                            for name, sha in items)
        trees = {
            A: listing(("hepta/semantic_ir.py", A), ("hepta/hsir.py", A),
                       ("hepta/cli.py", A), ("docs/readme.md", A)),
            B: listing(("hepta/semantic_ir.py", B), ("hepta/hsir.py", A),
                       ("hepta/cli.py", B), ("docs/readme.md", A)),
            C: listing(("hepta/semantic_ir.py", A), ("hepta/hsir.py", C),
                       ("hepta/cli.py", C), ("docs/readme.md", A)),
        }
        def fake_git(*args):
            if args[0] == "cat-file":
                return b""
            if args[0] == "rev-parse":
                return (args[1][:40] + "\n").encode()
            if args[0] == "merge-base":
                return (A + "\n").encode()
            if args[0] == "ls-tree":
                return trees[args[-1]]
            raise AssertionError(args)
        with patch.object(module, "git", side_effect=fake_git):
            report = module.audit(A, {"pr14": B, "pr36": C})
        self.assertEqual(report["overlaps"][0]["different_final_paths"], ["hepta/cli.py"])
        self.assertIn("typed_hsir", report["semantic_family_review"])
        self.assertNotIn("hepta/hsir.py", report["duplicate_semantic_path_owners"])
        self.assertEqual(report["duplicate_semantic_path_owners"]["hepta/cli.py"],
                         ["pr14", "pr36"])
        self.assertFalse(report["automatic_merge_approved"])

    def test_existing_and_dangling_output_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "audit.json"
            p.write_text("original")
            argv = ["--base", A, "--candidate", "pr14=" + B,
                    "--candidate", "pr36=" + C, "--output", str(p)]
            with patch.object(module, "audit", return_value={"ok": True}):
                self.assertEqual(module.main(argv), 2)
                self.assertEqual(p.read_text(), "original")
                p.unlink()
                p.symlink_to(pathlib.Path(d) / "missing.json")
                self.assertEqual(module.main(argv), 2)
                self.assertFalse((pathlib.Path(d) / "missing.json").exists())

    def test_real_git_no_rename_hiding_and_byte_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            def git(*args):
                p = subprocess.run(["git", "-C", directory, *args], check=True,
                                   capture_output=True)
                return p.stdout.decode().strip()
            git("init", "-q")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.com")
            (root / "hepta").mkdir()
            (root / "hepta" / "semantic_ir.py").write_text("legacy\n")
            git("add", ".")
            git("commit", "-qm", "base")
            base = git("rev-parse", "HEAD")
            git("checkout", "-qb", "left")
            (root / "hepta" / "semantic_ir.py").rename(root / "hepta" / "hsir.py")
            git("add", "-A")
            git("commit", "-qm", "rename")
            left = git("rev-parse", "HEAD")
            git("checkout", "-q", base)
            git("checkout", "-qb", "right")
            (root / "hepta" / "semantic_ir.py").write_text("changed\n")
            git("add", "-A")
            git("commit", "-qm", "change")
            right = git("rev-parse", "HEAD")
            with patch.dict(os.environ, {"GIT_DIR": str(root / ".git"),
                                              "GIT_WORK_TREE": str(root)}):
                r = module.audit(base, {"left": left, "right": right})
            self.assertIn("hepta/semantic_ir.py", r["overlaps"][0]["shared_paths"])
            self.assertIn("typed_hsir", r["semantic_family_review"])
            self.assertIn("hepta/hsir.py", r["changes"]["left"])
            self.assertFalse(r["whole_project_blockers_closed"])


if __name__ == "__main__":
    unittest.main()
