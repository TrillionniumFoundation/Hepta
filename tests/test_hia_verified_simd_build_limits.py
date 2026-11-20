"""Bounded linker failures and identity changes never publish a SIMD library."""
from __future__ import annotations

from hashlib import sha256
import importlib.util
from pathlib import Path
import platform
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.artifact_publication import publish_verified
from hepta.clang_capture import CaptureRejected
from hepta.hia_verified_kernel import (
    MAX_SIMD_IMAGE_BYTES, VerifiedKernelRejected, build_verified_kernel,
    select_verified_kernel,
)
from hepta.hia_verified_simd import simd_kernel_program
from hepta.native_tool_identity import digest_executable


AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class VerifiedSIMDBuildLimitsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-simd-build-limits-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.core = simd_kernel_program("sum_u8")

    def linker(self, body, *, version="print('GNU ld test wrapper')"):
        path = self.root / ("linker-" + str(len(list(self.root.glob("linker-*")))))
        path.write_text("#!" + sys.executable + "\n"
                        "import os, pathlib, subprocess, sys\n"
                        "if '--version' in sys.argv:\n"
                        + "\n".join("    " + line for line in version.splitlines()) + "\n"
                        "    raise SystemExit(0)\n" + body + "\n")
        path.chmod(0o700)
        return path

    def build(self, output, **kwargs):
        return build_verified_kernel(self.core, output, strategy="simd", simd_unroll=1, **kwargs)

    def test_linker_version_and_link_output_are_bounded(self):
        cases = (("version", "raise AssertionError('link must not start')",
                  "os.write(1, b'V' * 65537)"),
                 ("stdout", "os.write(1, b'O' * 65537)", "print('GNU ld test wrapper')"),
                 ("stderr", "os.write(2, b'E' * 1048577)", "print('GNU ld test wrapper')"))
        for name, body, version in cases:
            with self.subTest(stream=name):
                linker = self.linker(body, version=version)
                output = self.root / (name + ".so")
                with patch("hepta.hia_verified_simd_check.validate_verified_simd_artifact",
                           side_effect=AssertionError("oversized output reached verification")):
                    with self.assertRaises(CaptureRejected) as caught:
                        self.build(output, linker=str(linker))
                self.assertEqual(caught.exception.code, "E_CAPTURE_OUTPUT_SIZE")
                self.assertFalse(output.exists())

    def test_oversized_sparse_image_is_rejected_before_read_or_verification(self):
        linker = self.linker("with open(sys.argv[-1], 'wb') as stream:\n"
                             "    stream.truncate(" + str(MAX_SIMD_IMAGE_BYTES + 1) + ")")
        output = self.root / "oversized.so"
        with patch("hepta.hia_verified_simd_check.validate_verified_simd_artifact",
                   side_effect=AssertionError("oversized image reached verification")):
            with self.assertRaisesRegex(VerifiedKernelRejected, "bounded regular ELF"):
                self.build(output, linker=str(linker))
        self.assertFalse(output.exists())

    def test_linker_fifo_or_symlink_image_cannot_wait_or_publish(self):
        target = self.root / "untouched-input"
        target.write_bytes(b"existing caller bytes")
        for name, body in (("fifo", "os.mkfifo(sys.argv[-1])"),
                           ("symlink", "os.symlink(" + repr(str(target)) + ", sys.argv[-1])")):
            with self.subTest(kind=name):
                linker = self.linker(body)
                output = self.root / (name + ".so")
                with patch("hepta.hia_verified_simd_check.validate_verified_simd_artifact",
                           side_effect=AssertionError("nonregular image reached verification")):
                    with self.assertRaises(VerifiedKernelRejected):
                        self.build(output, linker=str(linker))
                self.assertFalse(output.exists())
        self.assertEqual(target.read_bytes(), b"existing caller bytes")

    def forwarding_linker(self, *, mutate=False):
        real = str(Path(shutil.which("ld")).resolve())
        body = "result = subprocess.run([" + repr(real) + ", *sys.argv[1:]], check=False)\n"
        if mutate:
            body += "with open(__file__, 'a') as stream:\n    stream.write('# changed after link\\n')\n"
        body += "raise SystemExit(result.returncode)"
        return self.linker(body)

    def test_linker_change_during_build_rejects_valid_final_image_before_publication(self):
        linker = self.forwarding_linker(mutate=True)
        output = self.root / "changed-linker.so"
        with patch("hepta.hia_verified_kernel.publish_verified",
                   side_effect=AssertionError("changed linker reached publication")):
            with self.assertRaisesRegex(VerifiedKernelRejected, "producer or linker changed"):
                self.build(output, linker=str(linker))
        self.assertFalse(output.exists())

    def test_linker_change_at_publication_withdraws_only_this_output(self):
        linker = self.forwarding_linker()
        output = self.root / "withdrawn.so"
        unrelated = self.root / "unrelated.so"
        unrelated.write_bytes(b"keep this file")

        def mutate_after_publish(*args):
            result = publish_verified(*args)
            self.assertTrue(output.is_file())
            with linker.open("a") as stream:
                stream.write("# changed at publication\n")
            return result

        with patch("hepta.hia_verified_kernel.publish_verified", side_effect=mutate_after_publish):
            with self.assertRaisesRegex(VerifiedKernelRejected, "producer or linker changed"):
                self.build(output, linker=str(linker))
        self.assertFalse(output.exists())
        self.assertEqual(unrelated.read_bytes(), b"keep this file")

    def test_producer_change_after_emission_never_reaches_linking(self):
        output = self.root / "changed-producer.so"
        with patch("hepta.hia_verified_kernel._simd_producer_identity", side_effect=[{"source": "before"}, {"source": "after"}]), \
                patch("hepta.hia_verified_kernel.run_bounded", side_effect=AssertionError("changed producer reached linker")):
            with self.assertRaisesRegex(VerifiedKernelRejected, "producer changed during emission"):
                self.build(output)
        self.assertFalse(output.exists())

    def test_success_binds_final_bytes_linker_and_producer(self):
        output = self.root / "stable.so"
        result = self.build(output)
        tool = Path(result["toolchain"]["path"])
        self.assertTrue(tool.is_absolute())
        self.assertEqual(result["toolchain"]["sha256"], digest_executable(tool))
        self.assertTrue(result["toolchain"]["version"].startswith("GNU ld "))
        self.assertEqual(result["artifact_sha256"], sha256(output.read_bytes()).hexdigest())
        self.assertEqual(result["validation"]["subject"]["final_image_sha256"], result["artifact_sha256"])
        self.assertIn("hia_verified_simd.py", result["source_identity"])
        self.assertIn("selected_native_encoder", result["source_identity"])
        self.assertEqual(result["simd_unroll"], 1)
        self.assertTrue(result["validation"]["ok"] and result["validation"]["complete"])

    def test_unroll_option_rejects_bool_unknown_and_noninteger_values(self):
        for value in (True, False, 0, 2, 3, 5, "4", None, 4.0):
            with self.subTest(unroll=value), self.assertRaisesRegex(VerifiedKernelRejected, "exactly 1 or 4"):
                select_verified_kernel(self.core, strategy="simd", simd_unroll=value)


if __name__ == "__main__":
    unittest.main()
