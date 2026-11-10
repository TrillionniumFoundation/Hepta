"""A real native recovery race; scheduling control does not fake native work."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest



@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "memfd_create"), "Linux memfd required")
class HostRegionRaceTests(unittest.TestCase):
    pass


if __name__ == "__main__":
    unittest.main()
