"""The Agent scorer must execute an immutable image on every admitted host."""
import errno
import os
from unittest import TestCase
from unittest.mock import patch

from experiments.hia_agent_assembly_v4_20261030 import evaluator


class SealedExecutionTests(TestCase):
    def test_real_sealed_image_rejects_writes_and_size_changes(self):
        fd = os.memfd_create("hia-agent-seal-regression", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            os.write(fd, b"original")
            self.assertEqual(evaluator.seal_execution_image(fd) & 15, 15)
            for action in (lambda: os.write(fd, b"changed"), lambda: os.ftruncate(fd, 0),
                           lambda: os.ftruncate(fd, 64)):
                with self.assertRaises(OSError) as error:
                    action()
                self.assertEqual(error.exception.errno, errno.EPERM)
            self.assertEqual(os.pread(fd, 64, 0), b"original")
        finally:
            os.close(fd)

    def test_partial_or_malformed_seal_readback_refuses(self):
        for observed in (0, 1, 7, 14, True, None):
            with self.subTest(observed=observed), patch.object(
                    evaluator.fcntl, "fcntl", side_effect=[0, observed]):
                with self.assertRaisesRegex(RuntimeError, "NOT_SEALED"):
                    evaluator.seal_execution_image(123)

    def test_sealing_error_is_not_downgraded(self):
        with patch.object(evaluator.fcntl, "fcntl", side_effect=OSError(errno.EINVAL, "unsupported")):
            with self.assertRaises(OSError):
                evaluator.seal_execution_image(123)
