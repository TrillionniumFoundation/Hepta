"""Composed raw-byte Core admission, without hosted decode/structure policy."""
from __future__ import annotations
from contextlib import ExitStack
from hashlib import sha256
import json
import os
import unittest
from unittest.mock import patch

from hepta.hia_program import HIAProgramRejected, VerifiedProgram
from hepta.hia_core_bytes_native import CompositeCoreBytes
from tests.test_hia_core_bytes_native import (
    CoreBytesFixture, clean_environment, observe_entry, record,
)


class CoreBytesIntegrationTests(CoreBytesFixture, unittest.TestCase):
    def test_all_primitive_versions_use_both_images_without_host_json_or_verifier(self):
        from tests.test_hia_returned_loan_interfaces import scalar
        from hepta import hia_program as program
        rows = []
        for version in range(1, 9):
            document = scalar(version)
            wire = json.dumps(document, ensure_ascii=False, indent=2).encode()
            with patch.dict(os.environ, clean_environment(), clear=True):
                expected = program.verify_program(wire)
            with ExitStack() as stack:
                for name in ("_decode", "_structure", "_primitive_structure",
                             "_function_interfaces", "_verify_function"):
                    stack.enter_context(patch.object(program, name,
                        side_effect=AssertionError("hosted Core authority: " + name)))
                stack.enter_context(patch.object(program.json, "loads",
                    side_effect=AssertionError("foreign JSON decoder")))
                stack.enter_context(patch.object(program.json, "dumps",
                    side_effect=AssertionError("foreign canonical encoder")))
                with observe_entry(self.frontend) as first, observe_entry(self.core) as second:
                    actual = self.verifier.verify_bytes(wire)
            self.assertIs(type(actual), VerifiedProgram)
            self.assertEqual(actual.canonical_bytes, expected.canonical_bytes)
            self.assertIsNone(actual.structured_bytes)
            self.assertEqual(len(first), 1)
            self.assertEqual(len(second), 1)
            self.assertEqual(second[0]["input"], actual.canonical_bytes)
            self.assertEqual(first[0]["input"], first[0]["input_after"])
            self.assertEqual(second[0]["input"], second[0]["input_after"])
            rows.append({"version": version, "frontend_calls": 1, "core_calls": 1,
                "input_sha256": sha256(wire).hexdigest(),
                "canonical_sha256": sha256(actual.canonical_bytes).hexdigest()})
        record(self.directory() / "accepted.json", rows)

    def test_complete_declaration_body_and_name_errors_still_come_from_core_image(self):
        from copy import deepcopy
        from tests.test_hia_returned_loan_interfaces import scalar
        from hepta import hia_program as program
        base = scalar(8)
        fixtures = []
        bad = deepcopy(base); bad["functions"][0]["name"] = "é"; fixtures.append(bad)
        bad = deepcopy(base); bad["functions"][0]["blocks"][0]["term"]["values"] = ["unknown"]; fixtures.append(bad)
        bad = deepcopy(base); bad["functions"][0]["blocks"][0]["ops"][0]["op"] = "unsupported-λ"; fixtures.append(bad)
        rows = []
        for document in fixtures:
            wire = json.dumps(document, ensure_ascii=False, indent=2).encode()
            with patch.dict(os.environ, clean_environment(), clear=True):
                with self.assertRaises(HIAProgramRejected) as expected:
                    program.verify_program(wire)
            with patch.object(program, "_decode", side_effect=AssertionError("host decode")), \
                 patch.object(program, "_primitive_structure", side_effect=AssertionError("host declarations")), \
                 patch.object(program, "_verify_function", side_effect=AssertionError("host body")), \
                 observe_entry(self.frontend) as first, observe_entry(self.core) as second:
                with self.assertRaises(HIAProgramRejected) as actual:
                    self.verifier.verify_bytes(wire)
            self.assertEqual((type(actual.exception), actual.exception.code, str(actual.exception)),
                             (type(expected.exception), expected.exception.code, str(expected.exception)))
            self.assertEqual(len(first), 1)
            self.assertEqual(len(second), 1)
            rows.append({"input_sha256": sha256(wire).hexdigest(), "frontend_calls": 1, "core_calls": 1,
                         "code": actual.exception.code, "message": str(actual.exception)})
        record(self.directory() / "core-errors.json", rows)

    def test_frontend_refusal_and_composite_handoff_never_call_core_admission(self):
        rows = []
        for wire in (b"\xff", b'{"a":1,"a":2}', b"1.5"):
            with patch.object(self.core, "admit", side_effect=AssertionError("Core called before JSON admission")) as core:
                with self.assertRaises(HIAProgramRejected):
                    self.verifier.verify_bytes(wire)
                self.assertEqual(core.call_count, 0)
            rows.append({"input_sha256": sha256(wire).hexdigest(), "core_calls": 0})
        wire = b'{"schema":"hepta.hia.composite.v4","functions":[]}'
        with patch.object(self.core, "admit", side_effect=AssertionError("composite sent to primitive Core")) as core:
            result = self.verifier.verify_bytes(wire)
            self.assertIs(type(result), CompositeCoreBytes)
            self.assertEqual(core.call_count, 0)
        record(self.directory() / "routes.json", rows)

    def test_caller_owned_and_wrapped_objects_remain_outside_exact_byte_transport(self):
        from tests.test_hia_returned_loan_interfaces import scalar
        from hepta import hia_program as program
        with patch.dict(os.environ, clean_environment(), clear=True):
            checked = program.verify_program(scalar(8))
        for value in (scalar(8), checked, checked.canonical_json, bytearray(checked.canonical_bytes)):
            with self.subTest(kind=type(value).__name__):
                with patch.object(self.frontend, "_entry", side_effect=AssertionError("foreign type reached native")) as entry:
                    with self.assertRaises(TypeError):
                        self.verifier.verify_bytes(value)
                    self.assertEqual(entry.call_count, 0)
        record(self.directory() / "typed-boundary.json", {
            "exact_bytes_only": True, "typed_object_owner_replaced": False,
            "composite_owner_replaced": False, "whole_verify_program_replaced": False})

        folder = self.folder / self._testMethodName

        # Both image inputs enter the original manifest/factory/scope protocol.
        # Private copies permit drift controls without altering fixture originals.
        from hepta.hia_core_bytes_native import installed_core_bytes_verifier
        from hepta.hia_core_admission_native import installed_core_admission
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from hepta.hia_native_helpers import native_helpers_scope, SCHEMA, TARGET, ABI
        pair = folder / "custody"
        pair.mkdir(mode=0o700)
        manifests = []
        images = []
        expected_fields = {"schema", "source_sha256", "image_path",
                           "image_sha256", "compiler_sha256"}
        for label, original in (("frontend", self.manifest),
                                ("admission", self.admission_manifest)):
            document = json.loads(original.read_bytes())
            self.assertEqual(set(document), expected_fields)
            image = (original.parent / document["image_path"]).read_bytes()
            self.assertEqual(sha256(image).hexdigest(), document["image_sha256"])
            image_path = pair / (label + ".image.bin")
            image_path.write_bytes(image)
            document["image_path"] = image_path.name
            path = pair / (label + "-manifest.json")
            record(path, document)
            manifests.append(path)
            images.append(image_path)
        self.assertEqual(json.loads(manifests[0].read_bytes())["compiler_sha256"],
                         json.loads(manifests[1].read_bytes())["compiler_sha256"])

        def bundle(name, selected):
            path = pair / (name + ".json")
            record(path, {"schema": SCHEMA, "target": TARGET, "abi": ABI,
                "helpers": [{"selector": selector, "manifest_path": str(manifest),
                             "manifest_sha256": sha256(manifest.read_bytes()).hexdigest()}
                            for selector, manifest in selected]})
            return path, sha256(path.read_bytes()).hexdigest()

        front = ("HEPTA_HIA_CORE_BYTES_MANIFEST", manifests[0])
        admission = ("HEPTA_HIA_CORE_ADMISSION_MANIFEST", manifests[1])
        neighbor = pair / "other-admission.json"
        neighbor.write_bytes(manifests[1].read_bytes())
        for name, selected in (
                ("missing-dependency", [front]),
                ("wrong-neighbor", [front, (admission[0], neighbor)])):
            path, digest = bundle(name, selected)
            with patch.dict(os.environ, clean_environment(), clear=True), \
                 patch.object(NativeHiaJsonImage, "__init__",
                              side_effect=AssertionError("mapped before dependency closure")):
                with self.assertRaisesRegex(ValueError, "exact adjacent admission"):
                    with native_helpers_scope(str(path), digest):
                        self.fail("incomplete dependency bundle was admitted")

        canonical = checked.canonical_bytes
        path, digest = bundle("complete", [front, admission])
        with patch.dict(os.environ, clean_environment(), clear=True):
            with native_helpers_scope(str(path), digest) as binding:
                selected = installed_core_bytes_verifier(str(manifests[0]))
                self.assertEqual(set(binding.selections), {front[0], admission[0]})
                with observe_entry(selected.frontend) as first, observe_entry(selected.core) as second:
                    actual = selected.verify_bytes(canonical)
                self.assertEqual(actual.canonical_bytes, canonical)
                self.assertEqual((len(first), len(second)), (1, 1))
                self.assertEqual(first[0]["input"], first[0]["input_after"])
                self.assertEqual(second[0]["input"], second[0]["input_after"])
                self.assertEqual(second[0]["input"], canonical)
            with patch.object(selected.frontend, "_entry",
                              side_effect=AssertionError("escaped bundle reached native")):
                with self.assertRaisesRegex(ValueError, "captured helper scope"):
                    selected.verify_bytes(canonical)

        with patch.dict(os.environ, clean_environment(), clear=True):
            with native_helpers_scope(str(path), digest):
                with patch.object(selected.frontend, "_entry",
                                  side_effect=AssertionError("old scope reached native")):
                    with self.assertRaisesRegex(ValueError, "captured helper scope"):
                        selected.verify_bytes(canonical)

        drift_rows = []
        for index, victim in enumerate([*manifests, *images]):
            original = victim.read_bytes()
            path, digest = bundle("drift-" + str(index), [front, admission])
            with patch.dict(os.environ, clean_environment(), clear=True):
                with native_helpers_scope(str(path), digest):
                    selected = installed_core_bytes_verifier(str(manifests[0]))
                    try:
                        victim.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                        with patch.object(selected.frontend, "_entry",
                                          side_effect=AssertionError("drift reached native")):
                            with self.assertRaisesRegex(ValueError, "native helper inputs changed"):
                                selected.verify_bytes(canonical)
                    finally:
                        victim.write_bytes(original)
                self.assertEqual(victim.read_bytes(), original)
            drift_rows.append({"path": str(victim), "native_calls_after_drift": 0})

        # The original Core v4 single-image scope remains an independent entry.
        path, digest = bundle("core-alone", [admission])
        with patch.dict(os.environ, clean_environment(), clear=True):
            with native_helpers_scope(str(path), digest):
                original_core = installed_core_admission(str(manifests[1]))
                with observe_entry(original_core) as calls:
                    original_core.admit(canonical)
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0]["input"], calls[0]["input_after"])
        record(pair / "custody.json", {
            "standard_manifest_fields": sorted(expected_fields),
            "complete_pair_actual_calls": [1, 1],
            "front_only_and_wrong_neighbor_rejected_before_mapping": True,
            "scope_escape_rejected_before_native": True,
            "same_bundle_new_scope_rejects_old_verifier": True, "drift": drift_rows,
            "original_core_single_image_actual_calls": 1})
