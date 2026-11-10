"""Fresh bounded C++ ownership implementation -> standalone HIA -> native."""
from copy import deepcopy
import os
from pathlib import Path
import shutil
import tempfile
import unittest


CLANG = os.environ.get("CLANG") or shutil.which("clang")
CLANGXX = os.environ.get("CLANGXX") or (str(Path(CLANG).with_name("clang++")) if CLANG else None)
CC, CXX = shutil.which("gcc"), shutil.which("g++")


@unittest.skipUnless(CLANG and CLANGXX and CC and CXX, "Clang 20 and native C/C++ references required")
class HIAOwnedMigrationIntegrationTests(unittest.TestCase):
    pass


if __name__ == "__main__":
    unittest.main()
