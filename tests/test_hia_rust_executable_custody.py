"""Real sealed-image execution and failure custody for the Rust shadow runner."""
from __future__ import annotations

import errno
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from hepta import hia_rust_crosscheck as runner

try:
    import fcntl
except ImportError:
    fcntl = None

GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
REQUIRED_SEALS = (getattr(fcntl, "F_SEAL_WRITE", 0x0008)
                  | getattr(fcntl, "F_SEAL_GROW", 0x0004)
                  | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
                  | getattr(fcntl, "F_SEAL_SEAL", 0x0001))


@unittest.skipUnless(sys.platform == "linux", "Sealed shadow execution requires Linux; NOT qualified")
class RustShadowExecutableCustody(unittest.TestCase):
    admitted = b"#!/bin/sh\nprintf 'admitted\\n'\n"
    replacement = b"#!/bin/sh\nprintf 'replacement\\n'\n"

    def assert_closed(self, descriptor):
        with self.assertRaises(OSError) as closed:
            os.fstat(descriptor)
        self.assertEqual(closed.exception.errno, errno.EBADF)

    def capture_descriptors(self):
        descriptors = []
        create = os.memfd_create

        def retain(name, flags):
            descriptor = create(name, flags)
            descriptors.append(descriptor)
            return descriptor

        return descriptors, retain

    def test_replacement_at_exec_boundary_cannot_change_admitted_bytes(self):
        actual = runner._run_bounded_shadow
        descriptors = []

        def challenge(command, *args, **kwargs):
            # This write succeeded against the former temporary executable
            # pathname. A real kernel seal now refuses truncation/replacement.
            with self.assertRaises(OSError) as refused:
                Path(command[0]).write_bytes(self.replacement)
            self.assertEqual(refused.exception.errno, errno.EPERM)
            descriptor, = kwargs["pass_fds"]
            descriptors.append(descriptor)
            self.assertEqual(command[0], f"/proc/self/fd/{descriptor}")
            seals = fcntl.fcntl(descriptor, GET_SEALS)
            self.assertEqual(seals & REQUIRED_SEALS, REQUIRED_SEALS)
            result = actual(command, *args, **kwargs)
            # The image remains owned after all real child/group cleanup.
            self.assertEqual(os.pread(descriptor, len(self.admitted), 0), self.admitted)
            return result

        with patch.object(runner, "_run_bounded_shadow", challenge):
            observed = runner._run_pinned_shadow(self.admitted, [], b"", 2.0)
        self.assertEqual(observed, (b"admitted\n", b"", 0))
        self.assertEqual(len(descriptors), 1)
        self.assert_closed(descriptors[0])

    def test_unavailable_sealing_refuses_before_launch(self):
        with patch.object(runner.os, "memfd_create", None), \
                patch.object(runner, "_run_bounded_shadow") as launch:
            with self.assertRaisesRegex(runner.HIARustCrosscheckRejected, "sealed.*unavailable"):
                runner._run_pinned_shadow(self.admitted, [], b"", 2.0)
            launch.assert_not_called()
        descriptors, retain = self.capture_descriptors()
        with patch.object(runner.os, "memfd_create", retain), \
                patch.object(fcntl, "fcntl", side_effect=OSError(errno.ENOSYS, "unavailable")), \
                patch.object(runner, "_run_bounded_shadow") as launch:
            with self.assertRaisesRegex(runner.HIARustCrosscheckRejected, "sealed.*unavailable"):
                runner._run_pinned_shadow(self.admitted, [], b"", 2.0)
            launch.assert_not_called()
        self.assertEqual(len(descriptors), 1)
        self.assert_closed(descriptors[0])

    def test_incomplete_seals_or_changed_readback_refuse_and_close_image(self):
        real_fcntl = fcntl.fcntl

        def incomplete(descriptor, operation, *args):
            result = real_fcntl(descriptor, operation, *args)
            return 0 if operation == GET_SEALS else result

        for target, attribute, replacement in (
                (fcntl, "fcntl", incomplete), (runner.os, "pread", lambda *_: b"different")):
            with self.subTest(check=attribute):
                descriptors, retain = self.capture_descriptors()
                with patch.object(runner.os, "memfd_create", retain), \
                        patch.object(target, attribute, replacement), \
                        patch.object(runner, "_run_bounded_shadow") as launch:
                    with self.assertRaisesRegex(runner.HIARustCrosscheckRejected, "bytes or seals differ"):
                        runner._run_pinned_shadow(self.admitted, [], b"", 2.0)
                    launch.assert_not_called()
                self.assertEqual(len(descriptors), 1)
                self.assert_closed(descriptors[0])

    def test_real_success_failure_timeout_and_output_stop_release_image(self):
        excessive = (f"#!{sys.executable}\nimport os\nos.write(1, b'x' * 2048)\n").encode()
        for raw, timeout, budget, error, expected in (
                (self.admitted, 2.0, 1024, None, (b"admitted\n", b"", 0)),
                (b"#!/bin/sh\nexit 7\n", 2.0, 1024, None, (b"", b"", 7)),
                (b"#!/bin/sh\nexec /bin/sleep 5\n", 0.25, 1024, "deadline", None),
                (excessive, 2.0, 1024, "output budget", None)):
            with self.subTest(error=error, expected=expected):
                descriptors, retain = self.capture_descriptors()
                with patch.object(runner.os, "memfd_create", retain):
                    if error:
                        with self.assertRaisesRegex(runner.HIARustCrosscheckRejected, error):
                            runner._run_pinned_shadow(raw, [], b"", timeout, maximum_output=budget)
                    else:
                        self.assertEqual(runner._run_pinned_shadow(
                            raw, [], b"", timeout, maximum_output=budget), expected)
                self.assertEqual(len(descriptors), 1)
                self.assert_closed(descriptors[0])

    def test_uncertain_descriptor_close_refuses_and_never_retries_number(self):
        descriptors, retain = self.capture_descriptors()
        actual_close = os.close
        releases = []

        def uncertain_close(descriptor):
            actual_close(descriptor)
            if descriptor in descriptors:
                releases.append(descriptor)
                raise OSError(errno.EIO, "release completion unknown")

        with patch.object(runner.os, "memfd_create", retain), \
                patch.object(runner.os, "close", uncertain_close):
            with self.assertRaisesRegex(runner.HIARustCrosscheckRejected, "release unconfirmed"):
                runner._run_pinned_shadow(self.admitted, [], b"", 2.0)
        self.assertEqual(releases, descriptors)
        self.assertEqual(len(releases), 1)
        self.assert_closed(descriptors[0])


if __name__ == "__main__":
    unittest.main()
