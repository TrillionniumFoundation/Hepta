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
from tools.qualify_hia_ndu_activation import DRIVER


class NativeDriverDigestTests(unittest.TestCase):
    def test_real_compiled_driver_still_binds_after_rejected_malformed_digest(self):
        self.assertEqual(platform.system(), "Linux")
        self.assertIn(platform.machine().lower(), {"x86_64", "amd64"})
        clang = os.environ.get("CLANG", "/usr/bin/clang-20")
        with tempfile.TemporaryDirectory(prefix="hia-driver-digest-") as temporary:
            root = Path(temporary)
            (root / "driver.c").write_text(DRIVER)
            driver = root / "driver"
            build = subprocess.run(
                [clang, "-O3", "-std=c11", str(root / "driver.c"),
                 "-ldl", "-o", str(driver)],
                check=True, capture_output=True, text=True, timeout=60)
            self.assertEqual(build.returncode, 0)
            expected = sha256(driver.read_bytes()).hexdigest()
            owner = PreparedArtifactSession(root / "owner", clang=clang)
            try:
                with patch.object(subject, "_pin_native_artifact",
                                  side_effect=AssertionError("native pin before SHA preflight")) as pin:
                    with self.assertRaisesRegex(ArtifactSessionRejected, "expected SHA-256"):
                        owner.bind_driver(driver, "G" * 64)
                    pin.assert_not_called()
                self.assertFalse(owner._driver_attempted)
                self.assertFalse(owner._closed)
                self.assertEqual(owner._reserved, 0)

                # The same live owner must still admit a real, exact-byte
                # compiled driver; do not replace this path with a fake receipt.
                owner.bind_driver(driver, expected)
                self.assertTrue(owner._driver_attempted)
                self.assertEqual(owner._driver["sha256"], expected)
                self.assertEqual(owner._charged, driver.stat().st_size)
                self.assertEqual(owner._reserved, 0)
            finally:
                owner.close()
            self.assertTrue(owner.snapshot()["owned_native_release_complete"])


if __name__ == "__main__":
    unittest.main()
