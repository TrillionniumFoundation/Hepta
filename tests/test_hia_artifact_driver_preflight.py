"""P7 fail-closed SHA-256 driver admission before any one-shot/native attempt.

This tests the real PreparedArtifactSession.bind_driver entry point with a
minimal, already-initialized owner state to avoid optional solver/compiler
setup in the *input boundary* tests. Actual native driver execution is a
separate required workflow gate; these mocks do not certify native loading.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
import threading
import unittest
from unittest.mock import patch

from hepta import hia_artifact_session as subject
from hepta.hia_artifact_session import ArtifactSessionRejected, PreparedArtifactSession


class DriverDigestPreflightTests(unittest.TestCase):
    def owner(self):
        """Model only the already-created owner state read by bind_driver."""
        owner = object.__new__(PreparedArtifactSession)
        owner._writer = threading.Lock()
        owner._lock = threading.RLock()
        owner._driver_attempted = False
        owner._closed = False
        owner._invalidated = False
        owner._charged = 0
        owner._reserved = 0
        owner._limits = {"artifact": 4096, "bytes": 8192}
        owner._entries = {}
        owner._pending = {}
        owner._driver = None
        return owner

    def test_invalid_equal_length_digests_do_not_probe_native_path_or_burn_attempt(self):
        invalid = (
            "g" * 64,                 # non-hex
            "A" * 64,                 # noncanonical uppercase
            "0" * 63 + "\x00",      # embedded control
            "é" * 64,                 # Unicode, not hexdigest output
            " " + "0" * 63,           # leading whitespace, same length
        )
        for digest in invalid:
            with self.subTest(digest=repr(digest)):
                owner = self.owner()
                with patch.object(Path, "stat", return_value=SimpleNamespace(st_size=1)) as stat, \
                     patch.object(subject, "_pin_native_artifact", side_effect=AssertionError(
                         "unqualified digest reached native pin")) as pin:
                    with self.assertRaisesRegex(ArtifactSessionRejected, "expected SHA-256"):
                        owner.bind_driver("untrusted-driver", digest)
                    stat.assert_not_called()
                    pin.assert_not_called()
                self.assertFalse(owner._driver_attempted)
                self.assertFalse(owner._closed)
                self.assertEqual(owner._reserved, 0)
                self.assertEqual(owner._charged, 0)
                self.assertIsNone(owner._driver)

    def test_invalid_digest_does_not_consume_single_valid_binding_attempt(self):
        owner = self.owner()
        with self.assertRaises(ArtifactSessionRejected):
            owner.bind_driver("not-a-driver", "z" * 64)
        self.assertFalse(owner._driver_attempted)
        valid = sha256(b"valid-driver").hexdigest()
        with patch.object(Path, "stat", return_value=SimpleNamespace(st_size=8)), \
             patch.object(subject, "_pin_native_artifact", side_effect=RuntimeError(
                 "injected later native pin failure")) as pin:
            with self.assertRaisesRegex(RuntimeError, "later native pin failure"):
                owner.bind_driver("allowed-path", valid)
            pin.assert_called_once()
        self.assertTrue(owner._driver_attempted)
        self.assertTrue(owner._closed)
        self.assertEqual(owner._reserved, 0)

    def test_original_short_long_and_string_subclass_rejection_remains(self):
        class SpoofedDigest(str):
            def __eq__(self, other):
                return True

        invalid = ("a" * 63, "a" * 65, SpoofedDigest("a" * 64), b"a" * 64)
        for value in invalid:
            with self.subTest(case=repr(value)[:72]):
                owner = self.owner()
                with patch.object(Path, "stat") as stat:
                    with self.assertRaises(ArtifactSessionRejected):
                        owner.bind_driver("untrusted-driver", value)
                    stat.assert_not_called()
                self.assertFalse(owner._driver_attempted)

    def test_exact_lowercase_digest_reaches_pinning_without_preflight_rewriting(self):
        owner = self.owner()
        valid = sha256(b"arbitrary-internal-driver-bytes").hexdigest()
        with patch.object(Path, "stat", return_value=SimpleNamespace(st_size=14)) as stat, \
             patch.object(subject, "_pin_native_artifact", side_effect=RuntimeError("pin failed")) as pin:
            with self.assertRaisesRegex(RuntimeError, "pin failed"):
                owner.bind_driver("valid-driver", valid)
            stat.assert_called_once()
            pin.assert_called_once()
        self.assertTrue(owner._driver_attempted)
        self.assertTrue(owner._closed)
        self.assertEqual(owner._reserved, 0)


if __name__ == "__main__":
    unittest.main()
