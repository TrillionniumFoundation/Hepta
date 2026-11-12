"""Ordinary exact-byte verification with actual selected HIA images.

Host references are captured with every manifest selector absent before the
selected call. These controls keep composite/typed owners explicit; no
namespace handoff is counted as a complete native verification.
"""
from __future__ import annotations
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from hashlib import sha256
import json
import os
import struct
import unittest
from unittest.mock import patch

from hepta import hia_program as program
from hepta import hia_core_bytes_native as byte_owner
from hepta.hia_program import HIAProgramRejected, VerifiedProgram
from tests.test_hia_core_bytes_native import (
    CoreBytesFixture, clean_environment, integer_limit, observe_entry, record,
)
from tests.test_hia_returned_loan_interfaces import scalar


def outcome(value):
    try:
        checked = program.verify_program(value)
    except HIAProgramRejected as error:
        return ("error", type(error), error.code, str(error))
    return ("accepted", checked.canonical_bytes, checked.structured_bytes)


def reference(value):
    with patch.dict(os.environ, clean_environment(), clear=True):
        return outcome(value)


def wire(document):
    return json.dumps(document, ensure_ascii=False, indent=2).encode("utf-8")


class CoreBytesOrdinaryTests(CoreBytesFixture, unittest.TestCase):
    @contextmanager
    def selected(self):
        environment = clean_environment()
        environment[byte_owner.SELECTOR] = str(self.manifest)
        with patch.dict(os.environ, environment, clear=True):
            actual = byte_owner.selected_core_bytes_verifier()
            self.assertIs(type(actual), byte_owner.NativeCoreBytesVerifier)
            yield actual

    def assert_calls(self, first, second, expected):
        self.assertEqual((len(first), len(second)), expected)
        for row in [*first, *second]:
            self.assertEqual(row["input"], row["input_after"])
        if expected == (1, 1):
            self.assertEqual(first[0]["published"][64:], second[0]["input"])

    def test_selected_ordinary_all_primitive_versions_bypass_host_authorities(self):
        rows = []
        for version in range(1, 9):
            original = wire(scalar(version))
            expected = reference(original)
            self.assertEqual(expected[0], "accepted")
            with self.selected() as selected, ExitStack() as stack:
                for name in ("_decode", "_structure", "_primitive_structure",
                             "_function_interfaces", "_verify_function"):
                    stack.enter_context(patch.object(program, name,
                        side_effect=AssertionError("hosted Core authority: " + name)))
                with observe_entry(selected.frontend) as first, observe_entry(selected.core) as second:
                    actual = program.verify_program(original)
            self.assertIs(type(actual), VerifiedProgram)
            self.assertEqual(("accepted", actual.canonical_bytes, actual.structured_bytes), expected)
            self.assert_calls(first, second, (1, 1))
            rows.append({"version": version, "input_sha256": sha256(original).hexdigest(),
                         "canonical_sha256": sha256(actual.canonical_bytes).hexdigest(),
                         "frontend_calls": len(first), "core_calls": len(second)})
        record(self.directory() / "ordinary-primitive.json", rows)

    def test_selected_ordinary_complete_errors_keep_reference_type_code_and_message(self):
        base = scalar(8)
        fixtures = []
        for name in ("a" * 129, "é", "__hia_private"):
            bad = deepcopy(base); bad["functions"][0]["name"] = name; fixtures.append(bad)
        bad = deepcopy(base)
        bad["functions"][0]["blocks"][0]["term"]["values"] = ["missing"]
        fixtures.append(bad)
        bad = deepcopy(base)
        bad["functions"][0]["blocks"][0]["ops"][0]["op"] = "unsupported-λ"
        fixtures.append(bad)
        bad = deepcopy(base)
        bad["functions"][0]["returns"] = ["readbuf"]
        bad["functions"][0]["blocks"][0]["term"]["values"] = ["missing"]
        fixtures.append(bad)
        rows = []
        for document in fixtures:
            original = wire(document)
            expected = reference(original)
            self.assertEqual(expected[0], "error")
            with self.selected() as selected, ExitStack() as stack:
                for name in ("_decode", "_primitive_structure", "_verify_function"):
                    stack.enter_context(patch.object(program, name,
                        side_effect=AssertionError("reference fallback: " + name)))
                with observe_entry(selected.frontend) as first, observe_entry(selected.core) as second:
                    actual = outcome(original)
            self.assertEqual(actual, expected)
            self.assert_calls(first, second, (1, 1))
            rows.append({"input_sha256": sha256(original).hexdigest(),
                         "exception_type": actual[1].__name__, "code": actual[2],
                         "complete_message": actual[3]})
        record(self.directory() / "ordinary-errors.json", rows)

    def test_selected_ordinary_frontend_order_and_actual_integer_limit(self):
        large = b"9" * 641
        cases = [
            (640, b"\xff", 0), (640, b'{"a":1,"a":2}', 0),
            (640, b"1.5", 0), (640, large, 0), (0, large, 1),
            (640, b"[" + large + b",\xff]", 0),
            (640, b"[" + large + b",]", 0),
            (640, b"[" + large + b"," + b"[" * 65 + b"0" + b"]" * 65 + b"]", 0),
            (640, b" " * (byte_owner.MAX_BYTES + 1), 0),
        ]
        rows = []
        for limit, original, expected_core in cases:
            with integer_limit(limit):
                expected = reference(original)
                self.assertEqual(expected[0], "error")
                with self.selected() as selected, \
                     patch.object(program, "_decode", side_effect=AssertionError("host decode")), \
                     observe_entry(selected.frontend) as first, observe_entry(selected.core) as second:
                    actual = outcome(original)
            self.assertEqual(actual, expected)
            self.assert_calls(first, second, (1, expected_core))
            header = struct.unpack("<8Q", first[0]["published"][:64])
            self.assertEqual(header[5:7], (len(original), limit))
            rows.append({"input_sha256": sha256(original).hexdigest(), "digit_limit": limit,
                         "stage": header[7], "status": header[2], "core_calls": len(second),
                         "code": actual[2], "complete_message": actual[3]})
        record(self.directory() / "ordinary-stage-order.json", rows)

    def test_composite_handoff_retains_all_original_elaborators_and_wrapper_recheck(self):
        from hepta import hia_program_composite as composite
        from tests.test_hia_program_composite import stored_loan_program, enum_owner_program
        rows = []
        for factory in (stored_loan_program, enum_owner_program):
            for version in range(1, 5):
                document = factory()
                document["schema"] = "hepta.hia.composite.v" + str(version)
                original = wire(document)
                expected = reference(original)
                self.assertEqual(expected[0], "accepted")
                with self.selected() as selected, \
                     patch.object(composite, "elaborate_program", wraps=composite.elaborate_program) as elaborator, \
                     observe_entry(selected.frontend) as first, observe_entry(selected.core) as second:
                    actual = program.verify_program(original)
                self.assertEqual(("accepted", actual.canonical_bytes, actual.structured_bytes), expected)
                self.assertEqual(elaborator.call_count, 1)
                self.assert_calls(first, second, (1, 0))
                self.assertEqual(struct.unpack("<8Q", first[0]["published"][:64])[2], 1)
                self.assertEqual(first[0]["published"][64:], actual.structured_bytes)
                # A structured VerifiedProgram is still reparsed and elaborated.
                with self.selected() as selected, \
                     patch.object(composite, "elaborate_program", wraps=composite.elaborate_program) as elaborator, \
                     observe_entry(selected.frontend) as first, observe_entry(selected.core) as second:
                    rechecked = program.verify_program(actual)
                self.assertEqual(rechecked, actual)
                self.assertEqual(elaborator.call_count, 1)
                self.assert_calls(first, second, (1, 0))
                forged = VerifiedProgram(actual.canonical_bytes + b" ", actual.structured_bytes)
                refused = reference(forged)
                self.assertEqual(refused[0], "error")
                with self.selected():
                    self.assertEqual(outcome(forged), refused)
                rows.append({"factory": factory.__name__, "schema": document["schema"],
                             "canonical_sha256": sha256(actual.canonical_bytes).hexdigest(),
                             "structured_sha256": sha256(actual.structured_bytes).hexdigest(),
                             "composite_owner_replaced": False})
        record(self.directory() / "ordinary-composite.json", rows)

    def test_unselected_and_nonexact_inputs_keep_original_snapshot_owners(self):
        original = wire(scalar(8))
        expected = reference(original)
        with patch.dict(os.environ, clean_environment(), clear=True), \
             patch.object(byte_owner, "installed_core_bytes_verifier",
                          side_effect=AssertionError("unselected image factory")) as factory:
            self.assertEqual(outcome(original), expected)
            self.assertEqual(factory.call_count, 0)
        checked = VerifiedProgram(expected[1])
        class BytesSubclass(bytes):
            pass
        class StringSubclass(str):
            pass
        values = [scalar(8), original.decode(), checked, BytesSubclass(original),
                  bytearray(original), StringSubclass(original.decode()), [], None]
        rows = []
        for value in values:
            expected = reference(value)
            environment = clean_environment()
            environment[byte_owner.SELECTOR] = str(self.manifest)
            with patch.dict(os.environ, environment, clear=True), \
                 patch.object(byte_owner, "selected_core_bytes_verifier",
                              side_effect=AssertionError("nonexact input selected byte owner")) as selector:
                actual = outcome(value)
            self.assertEqual(actual, expected)
            self.assertEqual(selector.call_count, 0)
            rows.append({"type": type(value).__name__, "outcome": actual[0],
                         "frontend_calls": 0, "typed_object_owner_replaced": False})
        record(self.directory() / "ordinary-type-boundary.json", rows)

    def test_explicit_empty_invalid_or_incomplete_selection_never_falls_back(self):
        folder = self.directory()
        invalid = folder / "invalid.json"
        invalid.write_bytes(b"{}")
        orphan = folder / "orphan"; orphan.mkdir(mode=0o700)
        manifest = json.loads(self.manifest.read_bytes())
        raw_image = (self.manifest.parent / manifest["image_path"]).read_bytes()
        (orphan / "frontend.bin").write_bytes(raw_image)
        manifest["image_path"] = "frontend.bin"
        lone = orphan / "core-bytes-manifest.json"; record(lone, manifest)
        original = wire(scalar(8))
        rows = []
        for label, path in (("empty", ""), ("missing", str(folder / "absent.json")),
                            ("invalid", str(invalid)), ("missing-neighbor", str(lone))):
            environment = clean_environment()
            environment[byte_owner.SELECTOR] = path
            with patch.dict(os.environ, environment, clear=True), \
                 patch.object(program, "_decode", side_effect=AssertionError("selected host fallback")):
                with self.assertRaises((ValueError, OSError)):
                    program.verify_program(original)
            rows.append({"case": label, "fallback": False})
        record(folder / "ordinary-selection-refusals.json", rows)

    def private_bundle(self, folder):
        from hepta.hia_native_helpers import SCHEMA, TARGET, ABI
        copies = []
        for label, original in (("frontend", self.manifest), ("admission", self.admission_manifest)):
            value = json.loads(original.read_bytes())
            image = (original.parent / value["image_path"]).read_bytes()
            target = folder / (label + ".bin")
            target.write_bytes(image)
            value["image_path"] = target.name
            manifest = folder / (label + "-manifest.json")
            record(manifest, value)
            copies.extend((manifest, target))
        path = folder / "bundle.json"
        record(path, {"schema": SCHEMA, "target": TARGET, "abi": ABI,
                      "helpers": [{"selector": selector, "manifest_path": str(manifest),
                                   "manifest_sha256": sha256(manifest.read_bytes()).hexdigest()}
                                  for selector, manifest in (
                                      (byte_owner.SELECTOR, copies[0]),
                                      ("HEPTA_HIA_CORE_ADMISSION_MANIFEST", copies[2]))]})
        return path, sha256(path.read_bytes()).hexdigest(), copies

    def test_ordinary_bundle_checks_every_bound_input_before_native(self):
        from hepta.hia_native_helpers import native_helpers_scope
        folder = self.directory()
        path, digest, copies = self.private_bundle(folder)
        original = wire(scalar(8))
        expected = reference(original)
        rows = []
        for victim in copies:
            prior = victim.read_bytes()
            with patch.dict(os.environ, clean_environment(), clear=True):
                with native_helpers_scope(str(path), digest):
                    selected = byte_owner.selected_core_bytes_verifier()
                    try:
                        victim.write_bytes(prior[:-1] + bytes([prior[-1] ^ 1]))
                        with observe_entry(selected.frontend) as first, observe_entry(selected.core) as second:
                            with self.assertRaisesRegex(ValueError, "native helper inputs changed"):
                                program.verify_program(original)
                        self.assert_calls(first, second, (0, 0))
                    finally:
                        victim.write_bytes(prior)
                self.assertEqual(victim.read_bytes(), prior)
            rows.append({"victim": victim.name, "frontend_calls": 0, "core_calls": 0})
        with patch.dict(os.environ, clean_environment(), clear=True):
            with native_helpers_scope(str(path), digest):
                selected = byte_owner.selected_core_bytes_verifier()
                with observe_entry(selected.frontend) as first, observe_entry(selected.core) as second:
                    self.assertEqual(outcome(original), expected)
                self.assert_calls(first, second, (1, 1))
        record(folder / "ordinary-preflight-custody.json", rows)

    def test_ordinary_bundle_postflight_drift_cannot_publish_verified_result(self):
        from hepta.hia_native_helpers import native_helpers_scope
        folder = self.directory()
        path, digest, copies = self.private_bundle(folder)
        original = wire(scalar(8))
        for index, victim in enumerate(copies):
            prior = victim.read_bytes()
            with patch.dict(os.environ, clean_environment(), clear=True):
                with native_helpers_scope(str(path), digest):
                    selected = byte_owner.selected_core_bytes_verifier()
                    with observe_entry(selected.frontend) as first, observe_entry(selected.core) as second:
                        entry = selected.core._entry
                        def mutate_after_actual_call(*args):
                            returned = entry(*args)
                            victim.write_bytes(prior[:-1] + bytes([prior[-1] ^ 1]))
                            return returned
                        try:
                            with patch.object(selected.core, "_entry", mutate_after_actual_call), \
                                 patch.object(program, "_decode", side_effect=AssertionError("postflight fallback")):
                                with self.assertRaisesRegex(ValueError, "native helper inputs changed"):
                                    program.verify_program(original)
                            self.assert_calls(first, second, (1, 1))
                        finally:
                            victim.write_bytes(prior)
                    self.assertEqual(victim.read_bytes(), prior)
            record(folder / ("postflight-" + str(index) + ".json"), {
                "victim": victim.name, "frontend_calls": 1, "core_calls": 1,
                "returned_verified_program": False,
                "frontend_input_sha256": sha256(first[0]["input"]).hexdigest(),
                "core_input_sha256": sha256(second[0]["input"]).hexdigest()})
