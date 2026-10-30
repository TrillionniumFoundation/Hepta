"""Linux executable-identity controls; the C fixture is not an NDU evaluator.

These exercise real memfds, real processes and kernel seals without requiring a
Rust toolchain. Existing test_hia_ndu_session.py separately runs the original
native NDU algorithm and compares every returned response with one-shot mode.
"""
from __future__ import annotations

import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from hepta.hia_native_differential import _pin_native_artifact
from hepta.hia_ndu import NduBridgeError
from hepta.hia_ndu_session import NduSession


_CC = shutil.which("cc")
_LINUX = os.path.exists("/proc/self/exe") and hasattr(os, "memfd_create")
_IDENTITY = {"scope": "transport-control-only", "source": "linux-sealed-identity-fixture"}
_FIXTURE = r'''#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(void) {
  puts("{\"schema\":\"hepta.hia.ndu.stream.v1\",\"identity\":{\"scope\":\"transport-control-only\",\"source\":\"linux-sealed-identity-fixture\"},\"max_requests\":256,\"authority\":\"DENY_ALL\",\"safety_certificate\":false}");
  fflush(stdout);
  char line[128];
  while (fgets(line, sizeof(line), stdin)) {
    if (!strcmp(line, "exec\n")) {
      char *args[] = {"cat", NULL};
      execv("/bin/cat", args);
      return 17;
    }
    puts("{\"status\":\"fixture-is-not-an-evaluator\"}");
    fflush(stdout);
  }
  return 0;
}
'''


@unittest.skipUnless(_LINUX and _CC, "requires Linux memfd/proc and a C compiler")
class SealedNduIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-sealed-identity-")
        cls.root = Path(cls.temporary.name)
        cls.source, cls.binary = cls.root / "fixture.c", cls.root / "fixture"
        cls.source.write_text(_FIXTURE)
        subprocess.run([_CC, "-O2", str(cls.source), "-o", str(cls.binary)],
                       capture_output=True, check=True, timeout=30)
        cls.manifest = {"schema": "hepta.hia.ndu.build.v1", "binary": str(cls.binary),
                        "binary_sha256": sha256(cls.binary.read_bytes()).hexdigest(),
                        "identity": _IDENTITY}
        cls.manifest_path = cls.root / "identity.json"
        cls.manifest_path.write_text(json.dumps(cls.manifest))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def session(self, **kwargs):
        result = NduSession(self.binary, self.manifest_path, **kwargs)
        self.addCleanup(result.close)
        return result

    def test_real_sealed_process_checks_do_not_reread_the_image(self):
        stream = self.session()
        with patch("hepta.hia_ndu_session.os.pread", side_effect=AssertionError("image reread")):
            for _ in range(16):
                stream._verify_binary()
        snapshot = stream.snapshot()
        self.assertEqual(snapshot["image_identity_checks"], 17)
        self.assertEqual(snapshot["requests"], 0)
        self.assertEqual(snapshot["authority"], "DENY_ALL")
        self.assertFalse(snapshot["safety_certificate"])

    def test_real_kernel_prevents_write_growth_and_shrink(self):
        stream = self.session()
        size = os.fstat(stream._fd).st_size
        for operation in (lambda: os.pwrite(stream._fd, b"x", 0),
                          lambda: os.ftruncate(stream._fd, size + 1),
                          lambda: os.ftruncate(stream._fd, size - 1)):
            with self.assertRaises(PermissionError):
                operation()
        stream._verify_binary()

    def test_reusing_same_descriptor_number_for_equal_bytes_is_rejected(self):
        stream = self.session()
        _, _, replacement = _pin_native_artifact(self.binary)
        try:
            self.assertEqual(os.fstat(replacement).st_size, os.fstat(stream._fd).st_size)
            os.dup2(replacement, stream._fd)
            with self.assertRaisesRegex(NduBridgeError, "descriptor changed"):
                stream._verify_binary()
        finally:
            os.close(replacement)

    def test_missing_any_immutable_seal_is_rejected(self):
        stream = self.session()
        real = fcntl.fcntl
        for seal in (fcntl.F_SEAL_WRITE, fcntl.F_SEAL_GROW, fcntl.F_SEAL_SHRINK, fcntl.F_SEAL_SEAL):
            def missing(fd, command, *args, seal=seal):
                value = real(fd, command, *args)
                return value & ~seal if command == fcntl.F_GET_SEALS else value
            with patch("hepta.hia_ndu_session.fcntl.fcntl", side_effect=missing):
                with self.assertRaisesRegex(NduBridgeError, "seals changed"):
                    stream._verify_binary()

    def test_actual_child_exec_into_a_different_image_is_rejected(self):
        stream = self.session()
        before = os.stat(f"/proc/{stream._process.pid}/exe")
        os.write(stream._process.stdin.fileno(), b"exec\n")
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            after = os.stat(f"/proc/{stream._process.pid}/exe")
            if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
                break
            time.sleep(0.001)
        else:
            self.fail("fixture never executed the second image")
        with self.assertRaisesRegex(NduBridgeError, "different image"):
            stream._verify_binary()

    def test_manifest_mutation_closes_before_native_dispatch(self):
        for field in ("identity", "binary_sha256"):
            stream = self.session()
            if field == "identity":
                stream.manifest[field]["source"] = "different-source"
            else:
                stream.manifest[field] = "0" * 64
            with patch.object(stream, "_invoke", side_effect=AssertionError("dispatched")):
                with self.assertRaisesRegex(NduBridgeError, "bindings changed"):
                    stream.evaluate({"generation": 1, "candidates": []})
            self.assertTrue(stream.snapshot()["closed"])
            self.assertEqual(stream.snapshot()["identity"], _IDENTITY)
            self.assertEqual(stream.snapshot()["binary_sha256"], self.manifest["binary_sha256"])
            self.assertIsNone(stream._fd)
            self.assertIsNotNone(stream._process.poll())

    def test_constructor_failure_releases_child_and_descriptor(self):
        descriptors, processes = [], []
        real_pin, real_popen = _pin_native_artifact, subprocess.Popen
        def pin(*args, **kwargs):
            result = real_pin(*args, **kwargs)
            descriptors.append(result[2])
            return result
        def popen(*args, **kwargs):
            result = real_popen(*args, **kwargs)
            processes.append(result)
            return result
        with patch("hepta.hia_ndu_session._pin_native_artifact", side_effect=pin), \
             patch("hepta.hia_ndu_session.subprocess.Popen", side_effect=popen), \
             patch.object(NduSession, "_exchange", return_value={"bad": "handshake"}):
            with self.assertRaisesRegex(NduBridgeError, "handshake"):
                NduSession(self.binary, self.manifest_path)
        self.assertEqual(len(descriptors), 1)
        self.assertEqual(len(processes), 1)
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])
        self.assertIsNotNone(processes[0].poll())

    def test_cleanup_error_preserves_original_rejection_and_releases_fd(self):
        stream = self.session()
        real_close = stream._process.stdout.close
        try:
            with patch.object(stream, "_invoke", side_effect=NduBridgeError("original rejection")), \
                 patch.object(stream._process.stdout, "close", side_effect=OSError("cleanup fault")):
                with self.assertRaisesRegex(NduBridgeError, "original rejection"):
                    stream.evaluate({"generation": 1, "candidates": []})
            self.assertTrue(stream.snapshot()["closed"])
            self.assertEqual(stream.snapshot()["cleanup_errors"], ["OSError: cleanup fault"])
            self.assertIsNone(stream._fd)
            self.assertIsNotNone(stream._process.poll())
        finally:
            real_close()


if __name__ == "__main__":
    unittest.main()
