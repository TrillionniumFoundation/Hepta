"""Concrete identity regressions; no HIA workload or timing campaign."""
from hashlib import sha256
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from hepta.hia_result_cache import CacheError
from tools.qualify_hia_result_cache import (bound_inputs, check_frozen_evidence,
    git_state, require_clean_source, require_same_bindings)


class ResultCacheBindingTests(unittest.TestCase):
    def git(self, root, *args):
        return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL, text=True).strip()

    def initialize(self, root):
        self.git(root, "init", "-q")
        (root / "tracked").write_text("fixed source\n")
        self.git(root, "add", "tracked")
        self.git(root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-qm", "initial fixture")

    def test_untracked_source_is_not_a_clean_registration(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); self.initialize(root)
            require_clean_source(git_state(root))
            (root / "untracked_module.py").write_text("value = 1\n")
            with self.assertRaisesRegex(CacheError, "untracked"):
                require_clean_source(git_state(root))

    def test_head_change_with_identical_tree_is_still_detected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); self.initialize(root)
            before = git_state(root)
            self.git(root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                     "commit", "--allow-empty", "-qm", "different identity, same tree")
            after = git_state(root)
            self.assertEqual(before["tree"], after["tree"])
            with self.assertRaisesRegex(CacheError, "source"):
                require_same_bindings({"source": before}, {"source": after})

    def test_protocol_and_each_tool_path_are_checked_after_observation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            paths = {name: root / name for name in ("planner", "planner_manifest", "clang", "protocol")}
            for path in paths.values(): path.write_bytes(b"original observed bytes")
            args = SimpleNamespace(**{name: paths[name] for name in ("planner", "planner_manifest", "clang")})
            for changed in paths:
                before = bound_inputs(args, protocol=paths["protocol"])
                paths[changed].write_bytes(b"different bytes")
                after = bound_inputs(args, protocol=paths["protocol"])
                with self.assertRaisesRegex(CacheError, changed):
                    require_same_bindings(before, after)
                paths[changed].write_bytes(b"original observed bytes")

    def test_restoring_a_registration_does_not_erase_detected_corruption(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); original = b'{"source":"pinned"}\n'
            path = root / "registration.json"; path.write_bytes(original)
            report = {"registration_sha256": sha256(original).hexdigest()}
            check_frozen_evidence(report, root)
            path.write_bytes(b'{"source":"changed"}\n')
            with self.assertRaisesRegex(CacheError, "registration"):
                check_frozen_evidence(report, root)
            path.write_bytes(original)
            with self.assertRaisesRegex(CacheError, "registration"):
                check_frozen_evidence(report, root)

if __name__ == "__main__": unittest.main()
