"""Offline and native-git regression coverage for Hepta PR integration audit."""
import importlib.util
import os
import pathlib
import subprocess
import sys
import time
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

    def test_git_tree_stdout_budget_kills_oversized_producer(self):
        # A fake git executable emits more than the intentionally reduced
        # audit budget, then remains alive. The auditor must reject promptly
        # instead of waiting to capture its entire stdout in memory.
        if os.name != "posix":
            self.skipTest("POSIX executable shim required")
        with tempfile.TemporaryDirectory() as directory:
            binary = pathlib.Path(directory) / "git"
            binary.write_text(
                f"#!{sys.executable}\n"
                "import sys, time\n"
                "sys.stdout.buffer.write(b'x' * 8192)\n"
                "sys.stdout.buffer.flush()\n"
                "time.sleep(4)\n",
                encoding="utf-8",
            )
            binary.chmod(0o755)
            environment = {"PATH": directory + os.pathsep + os.environ.get("PATH", "")}
            with patch.dict(os.environ, environment), patch.object(
                module, "_MAX_GIT_TREE_BYTES", 4096, create=True
            ):
                started = time.monotonic()
                with self.assertRaisesRegex(ValueError, "bounded|budget"):
                    module.git("ls-tree", "-r", "-z", "--full-tree", A)
                self.assertLess(time.monotonic() - started, 3.0)

    def test_git_overflow_reaps_inherited_pipe_descendant(self):
        # The bounded leader may exit while a child still owns both pipes.
        # A failed audit must not leave that producer running after refusal.
        if os.name != "posix":
            self.skipTest("POSIX process-group isolation required")
        with tempfile.TemporaryDirectory() as directory:
            marker = pathlib.Path(directory) / "survived.txt"
            binary = pathlib.Path(directory) / "git"
            child_code = (
                "import pathlib,sys,time; time.sleep(0.65); "
                "pathlib.Path(sys.argv[1]).write_text('survived')"
            )
            binary.write_text(
                f"#!{sys.executable}\n"
                "import subprocess,sys\n"
                f"subprocess.Popen([sys.executable, '-c', {child_code!r}, {str(marker)!r}], "
                "stdin=subprocess.DEVNULL)\n"
                "sys.stdout.buffer.write(b'x' * 8192)\n"
                "sys.stdout.buffer.flush()\n",
                encoding="utf-8",
            )
            binary.chmod(0o755)
            environment = {"PATH": directory + os.pathsep + os.environ.get("PATH", "")}
            with patch.dict(os.environ, environment), patch.object(
                module, "_MAX_GIT_TREE_BYTES", 4096
            ):
                with self.assertRaisesRegex(ValueError, "bounded|budget"):
                    module.git("ls-tree", "-r", "-z", "--full-tree", A)
            time.sleep(0.9)
            self.assertFalse(marker.exists(), "refused Git left an inherited-pipe child alive")

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


    def test_failed_report_write_never_exposes_partial_artifact(self):
        # A real OS file-size limit forces a short/failed write after a report
        # file has been created. Failed reports must never become visible at
        # the requested output path, even as truncated JSON.
        if os.name != "posix":
            self.skipTest("POSIX RLIMIT_FSIZE required")
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "audit.json"
            script = (
                "import importlib.util, resource, signal\n"
                f"spec = importlib.util.spec_from_file_location('audit_parallel_prs', {str(MODULE_PATH)!r})\n"
                "mod = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(mod)\n"
                "mod.audit = lambda base, candidates: {'large': 'x' * 1000000}\n"
                "signal.signal(signal.SIGXFSZ, signal.SIG_IGN)\n"
                "resource.setrlimit(resource.RLIMIT_FSIZE, (4096, 4096))\n"
                f"assert mod.main(['--base', {A!r}, '--candidate', 'left={B}', "
                f"'--candidate', 'right={C}', '--output', {str(output)!r}]) == 2\n"
            )
            run = subprocess.run([sys.executable, "-c", script],
                                 capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertFalse(output.exists(),
                             "failed report publication left a truncated JSON artifact")
            self.assertEqual(list(pathlib.Path(directory).iterdir()), [],
                             "failed report publication leaked a staging artifact")

    def test_successful_report_publication_is_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "audit.json"
            args = ["--base", A, "--candidate", "left=" + B,
                    "--candidate", "right=" + C, "--output", str(output)]
            with patch.object(module, "audit", return_value={"ok": True}):
                self.assertEqual(module.main(args), 0)
            self.assertEqual(output.read_text(encoding="utf-8"),
                             '{\n  "ok": true\n}\n')


    def test_report_parent_symlink_rebinding_cannot_publish_forged_evidence(self):
        # Real path adversary: after staging a legitimate report, retarget
        # its directory symlink immediately before hard-link publication.
        # An unpinned source/destination can publish attacker bytes and
        # leave the legitimate staging file orphaned while returning 0.
        if os.name != "posix" or os.link not in os.supports_dir_fd:
            self.skipTest("POSIX dir_fd hard-link operations required")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            trusted = root / "trusted"
            attacker = root / "attacker"
            trusted.mkdir()
            attacker.mkdir()
            alias = root / "alias"
            alias.symlink_to(trusted, target_is_directory=True)
            output = alias / "audit.json"
            original_link = os.link
            switched = []

            def redirect_at_publication(source, destination, **kwargs):
                # The old two-path link resolves both paths *after* the
                # attacker switches the directory. A same-basename forged
                # staging file makes the attack succeed, not merely error.
                if not kwargs.get("src_dir_fd"):
                    (attacker / pathlib.Path(source).name).write_text(
                        '{"forged":true}\n', encoding="utf-8")
                alias.unlink()
                alias.symlink_to(attacker, target_is_directory=True)
                switched.append(True)
                return original_link(source, destination, **kwargs)

            argv = ["--base", A, "--candidate", "left=" + B,
                    "--candidate", "right=" + C, "--output", str(output)]
            with patch.object(module, "audit", return_value={"ok": True}), patch.object(
                module.os, "link", side_effect=redirect_at_publication
            ):
                result = module.main(argv)
            self.assertTrue(switched, "publication attack hook did not execute")
            self.assertEqual(result, 2, "rebinding was wrongly accepted as a valid audit")
            self.assertFalse((attacker / "audit.json").exists(),
                             "attacker-controlled forged report was published")
            self.assertFalse((trusted / "audit.json").exists(),
                             "refused audit must not leave a qualified report")
            self.assertEqual(list(trusted.iterdir()), [],
                             "refused audit leaked its pinned staging artifact")

if __name__ == "__main__":
    unittest.main()
