"""Discriminating controls for heterogeneous forecast and native attribution."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest







@unittest.skipUnless(os.environ.get("HEPTA_NDU_STREAM_IDENTITY"), "requires real c4 native NDU stream")
class ActivationNativeTests(unittest.TestCase):
    pass


if __name__ == "__main__":
    unittest.main()
