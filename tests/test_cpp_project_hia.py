"""Concrete C++ project migration uses real capture, instantiation and HIA."""
from copy import deepcopy
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_program import execute_program


CLANG = os.environ.get("CLANG") or shutil.which("clang")
CLANGXX = os.environ.get("CLANGXX") or (str(Path(CLANG).with_name("clang++")) if CLANG else None)


@unittest.skipUnless(CLANG and CLANGXX, "Actual Clang 20 is required")
class CPPProjectHIATests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-cpp-project-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def database(self, sources, flags=None):
        commands = []
        for name, content in sources.items():
            (self.root / name).write_text(content)
            if name.endswith(".cpp"):
                commands.append({"directory": str(self.root), "file": name,
                                 "arguments": ["clang++", "-std=c++20", *(flags or []), "-c", name, "-o", name + ".o"]})
        db = self.root / "compile_commands.json"
        db.write_text(json.dumps(commands))
        return db








if __name__ == "__main__":
    unittest.main()
