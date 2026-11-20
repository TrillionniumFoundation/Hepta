"""Actual native input mappings and custody records, using explicit fixtures.

The tiny executable writes one fixed digest for one fixed test input. It is
only a mapping/selector fixture, never a qualified HIA SHA implementation or
evidence for the semantic correctness of native input helpers.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_json_preflight_native import _load_manifest
from hepta.hia_native_helpers import ABI, SCHEMA as BUNDLE_SCHEMA, TARGET, native_helpers_scope
from hepta.hia_sha256_native import SCHEMA, SOURCE, installed_hasher, payload_sha256
from hepta.hia_verified_input_identity import INPUT_SOURCE_FILES, VerifiedInputRejected, input_execution_scope


SELECTOR = "HEPTA_HIA_SHA256_MANIFEST"
PAYLOAD = b"actual native input identity fixture"
DIGEST = sha256(PAYLOAD).digest()
AVAILABLE = platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}


def fixture_code(digest=DIGEST):
    # RDX is the output pointer in the existing six-argument byte ABI.
    code = bytearray()
    for offset in range(0, 32, 8):
        code.extend(b"\x48\xb8" + digest[offset:offset + 8])
        code.extend(b"\x48\x89\x82" + offset.to_bytes(4, "little"))
    code.extend(b"\xb8\x20\x00\x00\x00\xc3")
    return bytes(code)


@unittest.skipUnless(AVAILABLE, "actual native input mapping controls require Linux x86-64")
class NativeInputIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-input-native-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.code = fixture_code()
        self.image = self.root / "fixture.bin"
        self.image.write_bytes(self.code)
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps({"schema": SCHEMA,
            "source_sha256": sha256(SOURCE.read_bytes()).hexdigest(),
            "image_path": self.image.name, "image_sha256": sha256(self.code).hexdigest(),
            "compiler_sha256": "0" * 64}))
        clean = {key: value for key, value in os.environ.items()
                 if not (key.startswith("HEPTA_HIA_") and key.endswith("_MANIFEST"))}
        environment = patch.dict(os.environ, clean, clear=True)
        environment.start(); self.addCleanup(environment.stop)

    def select(self):
        os.environ[SELECTOR] = str(self.manifest)

    def test_actual_executed_mapping_is_recorded_instead_of_changed_disk_bytes(self):
        self.select()
        with input_execution_scope() as scope:
            self.assertEqual(payload_sha256(PAYLOAD), DIGEST)
            actual = installed_hasher(str(self.manifest))
            # The warm loader deliberately keeps its admitted immutable image.
            # A later disk file cannot masquerade as the bytes actually used.
            self.image.write_bytes(fixture_code(b"\xa5" * 32))
            self.assertEqual(payload_sha256(PAYLOAD), DIGEST)
            report = scope.finish()
        self.assertEqual(len(report["native_helpers"]), 1)
        record = report["native_helpers"][0]
        self.assertEqual(record["mapped_image_sha256"], sha256(self.code).hexdigest())
        self.assertNotEqual(record["mapped_image_sha256"], sha256(self.image.read_bytes()).hexdigest())
        self.assertEqual(record["entry_address"], ctypes.cast(actual._entry, ctypes.c_void_p).value)
        self.assertEqual(record["image_bytes"], len(self.code))
        self.assertEqual(record["source_sha256"], sha256(SOURCE.read_bytes()).hexdigest())
        self.assertTrue(record["mapping"]["permissions"].startswith("r-x"))
        self.assertFalse(record["native_semantic_refinement_proved"])
        self.assertTrue(set(INPUT_SOURCE_FILES).issubset(report["python_sources"]))

    def test_same_selected_manifest_cannot_change_its_loaded_instance_mid_proof(self):
        self.select()
        with input_execution_scope():
            self.assertEqual(payload_sha256(PAYLOAD), DIGEST)
            # A new valid manifest byte spelling changes the actual loader's
            # cache key and makes it construct a second RX instance.
            self.manifest.write_text(self.manifest.read_text() + "\n")
            with self.assertRaisesRegex(VerifiedInputRejected, "changed its actual mapping"):
                payload_sha256(PAYLOAD)

    def test_selection_changes_are_rejected_before_new_native_invocation(self):
        self.select()
        other = self.root / "other.json"
        other.write_bytes(self.manifest.read_bytes())
        with input_execution_scope():
            self.assertEqual(payload_sha256(PAYLOAD), DIGEST)
            os.environ[SELECTOR] = str(other)
            with self.assertRaisesRegex(VerifiedInputRejected, "selection changed"):
                payload_sha256(PAYLOAD)

    def test_end_of_scope_rechecks_actual_callable_and_admitted_source(self):
        self.select()
        for field, replacement, pattern in (
            ("_image_address", 0, "does not address"),
            ("admitted_source_sha256", "0" * 64, "source binding"),
            ("image_sha256", "0" * 64, "differs from its admitted image"),
        ):
            with input_execution_scope() as scope:
                self.assertEqual(payload_sha256(PAYLOAD), DIGEST)
                selected = installed_hasher(str(self.manifest))
                original = getattr(selected, field)
                try:
                    setattr(selected, field, replacement)
                    with self.assertRaisesRegex(VerifiedInputRejected, pattern):
                        scope.finish()
                finally:
                    setattr(selected, field, original)

    def test_operator_pinned_bundle_records_the_actual_legacy_helper_mapping(self):
        bundle = self.root / "bundle.json"
        bundle.write_text(json.dumps({"schema": BUNDLE_SCHEMA, "target": TARGET, "abi": ABI,
            "helpers": [{"selector": SELECTOR, "manifest_path": str(self.manifest),
                         "manifest_sha256": sha256(self.manifest.read_bytes()).hexdigest()}]}))
        bundle_hash = sha256(bundle.read_bytes()).hexdigest()
        with native_helpers_scope(str(bundle), bundle_hash):
            with input_execution_scope() as scope:
                self.assertEqual(payload_sha256(PAYLOAD), DIGEST)
                selected = installed_hasher(str(self.manifest))
                report = scope.finish()
        self.assertEqual(report["native_bundle"], {"native_helpers_sha256": bundle_hash})
        self.assertEqual(len(report["native_helpers"]), 1)
        self.assertEqual(report["native_helpers"][0]["mapped_image_sha256"], sha256(self.code).hexdigest())
        self.assertEqual(report["native_helpers"][0]["entry_address"], selected._image_address)
        self.assertEqual(selected.admitted_source_sha256, sha256(SOURCE.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
