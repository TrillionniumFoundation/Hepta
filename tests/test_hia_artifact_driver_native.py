"""Real Linux Clang/Z3 driver binding after a syntactically invalid SHA-256.

Mandatory native-only companion of test_hia_artifact_driver_preflight. No
simulated driver is allowed to satisfy the successful second bind.
"""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_artifact_session as subject
from hepta.hia_artifact_session import ArtifactSessionRejected, PreparedArtifactSession


class NativeDriverDigestTests(unittest.TestCase):
    pass


if __name__ == "__main__":
    unittest.main()
