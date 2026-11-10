"""Concrete identity regressions; no HIA workload or timing campaign."""
from hashlib import sha256
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from hepta.hia_result_cache import CacheError


class ResultCacheBindingTests(unittest.TestCase):
    def git(self, root, *args):
        return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL, text=True).strip()

    def initialize(self, root):
        self.git(root, "init", "-q")
        (root / "tracked").write_text("fixed source\n")
        self.git(root, "add", "tracked")
        self.git(root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-qm", "initial fixture")





if __name__ == "__main__": unittest.main()
