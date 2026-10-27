"""Actual Linux RLIMIT execution controls for the opt-in pinned Rust shadow.

These tests execute the REAL kernel resource policy around a Python probe to
avoid confusing an available Rust compiler with a required sandbox validation.
They do not certify the HIA Rust/LLVM compiler or malicious-executable isolation.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from hepta.hia_rust_crosscheck import _limited_shadow_command, _run_bounded_shadow


@unittest.skipUnless(sys.platform == "linux", "Linux RLIMIT behavior required")
class RustShadowResourceLimits(unittest.TestCase):
    def test_real_child_observes_hard_address_cpu_file_fd_and_core_limits(self):
        code = (
            "import json,resource;"
            "print(json.dumps({name: resource.getrlimit(getattr(resource,name)) "
            "for name in ('RLIMIT_AS','RLIMIT_CPU','RLIMIT_FSIZE',"
            "'RLIMIT_CORE','RLIMIT_NOFILE')}))"
        )
        cmd = _limited_shadow_command(Path(sys.executable), "scalar", 2.5)
        cmd.extend(["-I", "-S", "-c", code])
        output, stderr, returncode = _run_bounded_shadow(cmd, b"", timeout=5)
        self.assertEqual((stderr, returncode), (b"", 0), output)
        limits = json.loads(output)
        self.assertEqual(limits["RLIMIT_AS"], [1024 * 1024 * 1024] * 2)
        self.assertEqual(limits["RLIMIT_CPU"], [4, 4])
        self.assertEqual(limits["RLIMIT_FSIZE"], [0, 0])
        self.assertEqual(limits["RLIMIT_CORE"], [0, 0])
        self.assertEqual(limits["RLIMIT_NOFILE"], [64, 64])

    def test_actual_regular_file_write_is_denied_even_on_successful_transport(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "forbidden-write"
            code = (
                f"with open({str(target)!r}, 'wb') as output:\n"
                "    output.write(b'UNEXPECTED')\n"
                "print('should-not-run')"
            )
            cmd = _limited_shadow_command(Path(sys.executable), "scalar", 2)
            cmd.extend(["-I", "-S", "-c", code])
            stdout, stderr, status = _run_bounded_shadow(cmd, b"", timeout=5)
            self.assertNotEqual(status, 0)
            self.assertNotIn(b"should-not-run", stdout)
            self.assertEqual(target.read_bytes(), b"")
            self.assertTrue(stderr or status < 0)

    def test_invalid_policy_is_rejected_before_launch(self):
        for profile, timeout in (("arbitrary", 1), ("scalar", 0),
                                 ("owned", float("nan")), ("scalar", True),
                                 ("scalar", 30)):
            with self.subTest(profile=profile, timeout=timeout):
                with self.assertRaises(ValueError):
                    _limited_shadow_command(Path(sys.executable), profile, timeout)


if __name__ == "__main__":
    unittest.main()
