"""Real Linux sealed-image and script execution regression for HIA Rust shadow.

Tests are finite kernel/transport identity controls using a deliberately fake
reporting script. They are NOT Rust compiler, whole-program safety, or hostile-
executable isolation proof.
"""
from __future__ import annotations

import errno
import fcntl
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_rust_crosscheck as shadow
from tests.test_hia_rust_crosscheck import (
    RustShadowCrosscheckProtocol, owned_program
)


@unittest.skipUnless(
    sys.platform == "linux" and hasattr(os, "memfd_create")
    and hasattr(fcntl, "F_ADD_SEALS") and Path("/proc/self/fd").is_dir(),
    "Linux /proc + sealable memfd required; never claim passed when unavailable",
)
class RustShadowSealedExecutable(unittest.TestCase):
    def test_kernel_refuses_write_resize_and_descriptor_closes(self):
        content = b"#! /bin/sh\nexit 0\n"
        with shadow._sealed_shadow_executable(content) as fd:
            wanted = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                      fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            self.assertEqual(fcntl.fcntl(fd, fcntl.F_GET_SEALS) & wanted, wanted)
            self.assertEqual(os.pread(fd, len(content), 0), content)
            for mutation in (
                lambda: os.pwrite(fd, b"X", 0),
                lambda: os.ftruncate(fd, 0),
                lambda: os.pwrite(fd, b"X", len(content)),
            ):
                with self.subTest(mutation=mutation):
                    with self.assertRaises(OSError) as denied:
                        mutation()
                    self.assertIn(denied.exception.errno,
                                  (errno.EPERM, errno.EACCES))
        with self.assertRaises(OSError) as closed:
            os.fstat(fd)
        self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_original_path_replacement_cannot_change_executed_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            exe, digest = RustShadowCrosscheckProtocol().make_fake(Path(td))
            original_transport = shadow._run_bounded_shadow
            observed = []

            def attack_in_window(command, payload, timeout, *, pass_fds=()):
                # This hook runs AFTER SHA-256 validation and SEALED staging,
                # but BEFORE the real kernel exec. Legacy temp-path staging
                # allowed a same-UID attacker to modify that executable.
                self.assertEqual(len(pass_fds), 1)
                fd = pass_fds[0]
                self.assertIn(f"/proc/self/fd/{fd}", command)
                self.assertEqual(os.pread(fd, 2, 0), b"#!")
                with self.assertRaises(OSError) as denied:
                    os.pwrite(fd, b"attacker", 0)
                self.assertIn(denied.exception.errno, (errno.EPERM, errno.EACCES))
                exe.write_bytes(b"malicious-replacement-that-is-not-executable")
                observed.append(fd)
                return original_transport(command, payload, timeout, pass_fds=pass_fds)

            with patch.object(shadow, "_run_bounded_shadow",
                              side_effect=attack_in_window):
                report = shadow.crosscheck_rust_shadow(
                    owned_program(), exe, executable_sha256=digest)
            self.assertEqual(report["status"], "shadow_corroborated_not_authority")
            self.assertEqual(report["shadow_executable_sha256"], digest)
            self.assertEqual(len(observed), 1)
            self.assertIs(report["claims"]["rust_is_production_admission_authority"], False)

    def test_seal_failure_refuses_without_falling_back_to_temp_path(self):
        with tempfile.TemporaryDirectory() as td:
            exe, digest = RustShadowCrosscheckProtocol().make_fake(Path(td))
            with (
                patch.object(shadow.os, "memfd_create",
                             side_effect=OSError(errno.ENOSYS, "unavailable")),
                patch.object(shadow, "_run_bounded_shadow") as transport,
            ):
                with self.assertRaisesRegex(
                    shadow.HIARustCrosscheckRejected, "sealed shadow image"
                ):
                    shadow.crosscheck_rust_shadow(
                        owned_program(), exe, executable_sha256=digest)
                transport.assert_not_called()


if __name__ == "__main__":
    unittest.main()
