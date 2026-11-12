"""Real exact-byte prelude witnesses; no implicit compiler or native image."""
from __future__ import annotations
from contextlib import contextmanager
import ast
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_core_bytes_native import (
    SOURCE, SCHEMA, MAX_BYTES, MAX_NODES, MAX_DEPTH, REQUEST_MAGIC,
    RESULT_MAGIC, FRAMING, NativeCoreBytes, NativeCoreBytesVerifier,
    CompositeCoreBytes, capture_bytes, scratch_sizes, installed_core_bytes,
)
from hepta.hia_core_admission_native import SOURCE as CORE_SOURCE, SCHEMA as CORE_SCHEMA, NativeCoreAdmission
from hepta.hia_program import HIAProgramRejected

ROOT = Path(__file__).resolve().parents[1]
COLD = "HEPTA_HIA_CORE_BYTES_COLD_REPORT"
DEVELOPMENT = "HEPTA_HIA_CORE_BYTES_DEVELOPMENT_COMPILER"
EVIDENCE = "HEPTA_HIA_CORE_BYTES_EVIDENCE"


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if not (key.startswith("HEPTA_HIA_") and key.endswith("_MANIFEST"))}


def record(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def reference_decode(wire):
    from hepta.hia_program import _decode
    with patch.dict(os.environ, clean_environment(), clear=True):
        try:
            _document, canonical = _decode(wire)
        except HIAProgramRejected as error:
            return ("error", type(error), error.code, str(error))
        return ("canonical", canonical)


@contextmanager
def integer_limit(value):
    original = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(value)
    try:
        yield
    finally:
        sys.set_int_max_str_digits(original)


@contextmanager
def observe_entry(image):
    original = image._entry
    calls = []
    def observed(source, size, output, capacity, workspace, workspace_size):
        before = ctypes.string_at(source, size)
        result = original(source, size, output, capacity, workspace, workspace_size)
        extent = result if type(result) is int and 64 < result <= capacity else 0
        calls.append({"return": result, "input": before,
            "input_after": ctypes.string_at(source, size),
            "published": ctypes.string_at(output, extent), "capacity": capacity,
            "workspace_size": workspace_size})
        return result
    image._entry = observed
    try:
        yield calls
    finally:
        image._entry = original


def vm_frontend(wire):
    """Use public execution and observe each real owner before its one drop."""
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    from hepta import hia_program_runtime as runtime
    capture = capture_bytes(wire)
    output_size, workspace_size = scratch_sizes(capture)
    workspace_initial = struct.pack("<8Q", REQUEST_MAGIC, 1, capture.original_size,
                                    capture.digit_limit, 0, 0, 0, 0)
    body, owners, views = Body(0), [], []
    for size, initial in ((max(1, len(capture.prefix)), capture.prefix),
                           (output_size, b""), (workspace_size, workspace_initial)):
        owner = body.value("buffer", "buffer.new", [body.const("usize", size)])
        view = body.value("mutbuf", "borrow.mut", [owner])
        for offset, value in enumerate(initial):
            if value:
                body.effect("buffer.store", [view, body.const("usize", offset), body.const("u8", value)])
        owners.append(owner)
        views.append(view)
    body.effect("loan.end", [views[0]])
    views[0] = body.value("readbuf", "borrow.read", [owners[0]])
    result = body.value("u32", "call", views, {"function": "f0"})
    for view in views:
        body.effect("loan.end", [view])
    for owner in owners:
        body.effect("owner.drop", [owner])
    wrapper = ("hia-asm.v1 hepta.hia.program.v8 core_bytes_vm\n"
        "fn observe() -> (u32) effects(alloc,read,write,trap) entry(b0)\nblock b0()\n"
        + body.text() + "  ret(" + result + ")\nend\n" + SOURCE.read_text().split("\n", 1)[1])
    drops, capture_errors = [], []
    original_drop = runtime._Machine.drop
    def observed_drop(machine, owner):
        snapshot = None
        try:
            if type(owner) is runtime._Owner:
                snapshot = (machine, owner.ident, bytes(owner.data))
        except BaseException as error:
            capture_errors.append(error)
        returned = original_drop(machine, owner)
        if snapshot is not None:
            drops.append(snapshot)
        return returned
    with patch.object(runtime._Machine, "drop", observed_drop):
        actual = execute_program(assemble_program(wrapper), "observe", [], max_steps=3_000_000)
    if capture_errors:
        raise capture_errors[0]
    assert actual["status"] == "returned"
    assert len(drops) == 3 and [row[1] for row in drops] == [1, 2, 3]
    assert all(row[0] is drops[0][0] for row in drops)
    assert drops[0][2][:len(capture.prefix)] == capture.prefix
    resources = actual["resources"]
    assert resources == drops[0][0].resources()
    assert resources["owners_created"] == resources["owners_dropped"] == 3
    assert resources["allocations"] == resources["frees"] == 3
    assert resources["live_owners"] == resources["live_local_loans"] == 0
    returned, = actual["values"]
    assert 64 < returned <= output_size
    return drops[1][2][:returned], {"max_steps": 3_000_000, "resources": resources,
        "dropped_owner_ids": [row[1] for row in drops], "returned": returned,
        "full_output_sha256": sha256(drops[1][2][:returned]).hexdigest()}


class CoreBytesFixture:
    @classmethod
    def setUpClass(cls):
        present = [name for name in (COLD, DEVELOPMENT) if name in os.environ]
        if len(present) != 1 or not os.environ[present[0]]:
            raise ValueError("exactly one nonempty Core bytes cold/development compiler selection is required")
        cls.temporary = None
        if EVIDENCE in os.environ:
            if not os.environ[EVIDENCE]:
                raise ValueError("Core bytes evidence directory is empty")
            cls.folder = Path(os.environ[EVIDENCE]) / cls.__name__
            cls.folder.mkdir(mode=0o700, parents=True)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix="hia-core-bytes-")
            cls.folder = Path(cls.temporary.name)
        cls.inputs = {str(path): path.read_bytes() for path in (SOURCE, CORE_SOURCE)}
        if present[0] == COLD:
            from tools.build_hia_core_bytes import build
            cold = Path(os.environ[COLD])
            report = json.loads(cold.read_bytes())
            nested = json.loads(Path(report["nested_report"]).read_bytes())
            compiler = Path(nested["generations"][-1]["produced_image"])
            cls.manifest = build(cls.folder / "frontend", compiler, cold)
            cls.admission_manifest = cls.manifest.parent / "admission-manifest.json"
        else:
            from tools.qualify_hia_selfhost import compile_stage
            compiler = Path(os.environ[DEVELOPMENT])
            compiler_bytes = compiler.read_bytes()
            cls.manifest = cls.folder / "core-bytes-manifest.json"
            cls.admission_manifest = cls.folder / "admission-manifest.json"
            for label, source, schema in (("core-bytes", SOURCE, SCHEMA),
                                          ("core-admission", CORE_SOURCE, CORE_SCHEMA)):
                image, receipt = compile_stage(cls.folder, label, compiler, cls.inputs[str(source)])
                image_bytes = image.read_bytes()
                digest = sha256(image_bytes).hexdigest()
                record(cls.manifest if label == "core-bytes" else cls.admission_manifest, {
                    "schema": schema, "source_sha256": sha256(cls.inputs[str(source)]).hexdigest(),
                    "image_path": image.name, "image_sha256": digest,
                    "compiler_sha256": sha256(compiler_bytes).hexdigest()})
                record(cls.folder / (label + "-build-observation.json"), {
                    "scope": "explicit development compiler; not matching current source cold",
                    "native_compile_receipt": receipt, "image_bytes": len(image_bytes),
                    "image_sha256": digest})
            if compiler.read_bytes() != compiler_bytes:
                raise ValueError("Core bytes development compiler changed")
        from hepta.hia_core_bytes_native import installed_core_bytes_verifier
        cls.verifier = installed_core_bytes_verifier(str(cls.manifest))
        cls.frontend = cls.verifier.frontend
        cls.core = cls.verifier.core
        for path, raw in cls.inputs.items():
            if Path(path).read_bytes() != raw:
                raise ValueError("Core bytes source changed while building")

    @classmethod
    def tearDownClass(cls):
        for path, raw in cls.inputs.items():
            if Path(path).read_bytes() != raw:
                raise AssertionError("Core bytes source changed")
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def directory(self):
        path = self.folder / self._testMethodName
        path.mkdir(mode=0o700)
        return path

    def assert_reference_decode(self, wire):
        expected = reference_decode(wire)
        with observe_entry(self.frontend) as calls:
            if expected[0] == "error":
                with self.assertRaises(HIAProgramRejected) as found:
                    self.frontend.prepare(wire)
                self.assertEqual((type(found.exception), found.exception.code, str(found.exception)),
                                 expected[1:])
            else:
                actual = self.frontend.prepare(wire)
                self.assertEqual(actual.payload, expected[1])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["input"], calls[0]["input_after"])
        return calls[0]


class CoreBytesSourceTests(unittest.TestCase):
    def test_generator_and_canonical_tail_are_exact_structural_reproductions(self):
        from tools.generate_hia_core_bytes import document, source_program, DECODE_PREFIX
        from tools.generate_hia_json_canonical import SOURCE as canonical_source
        from tools.generate_hia_json_decode import source_program as decoder_source
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        doc = document()
        self.assertEqual(render_assembly(doc).encode(), SOURCE.read_bytes())
        self.assertEqual(assemble_program(SOURCE.read_bytes()).as_dict(), doc)
        current = {node.name: node for node in ast.parse(source_program()).body}
        original = ast.parse(canonical_source).body
        first = original[0]
        first.name = "emit_canonical"
        first.body = first.body[len(ast.parse(DECODE_PREFIX).body):]
        for function in original + ast.parse(decoder_source()).body:
            self.assertEqual(ast.dump(current[function.name], include_attributes=False),
                             ast.dump(function, include_attributes=False))

    def test_exact_byte_capture_is_bounded_and_does_not_coerce_objects(self):
        class Foreign:
            def __bytes__(self):
                raise AssertionError("foreign coercion")
        with self.assertRaises(TypeError):
            capture_bytes(Foreign())
        class ByteSubclass(bytes):
            pass
        with self.assertRaises(TypeError):
            capture_bytes(ByteSubclass(b"{}"))
        raw = b"x" * (MAX_BYTES + 129)
        capture = capture_bytes(raw)
        self.assertEqual(capture.original_size, len(raw))
        self.assertEqual(capture.prefix, raw[:MAX_BYTES + 1])
        self.assertEqual(len(capture.prefix), MAX_BYTES + 1)
        self.assertEqual(capture.digit_limit, sys.get_int_max_str_digits())

    def test_wrong_cold_is_rejected_before_build_output_creation(self):
        from tools.build_hia_core_bytes import build
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            compiler, cold, output = root / "compiler", root / "cold.json", root / "output"
            compiler.write_bytes(b"not a qualified compiler")
            cold.write_text("{}")
            with self.assertRaisesRegex(ValueError, "completed matching native cold qualification"):
                build(output, compiler, cold)
            self.assertFalse(output.exists())

    def test_composition_does_not_accept_foreign_approval_objects(self):
        with self.assertRaises(TypeError):
            NativeCoreBytesVerifier(object(), object())


class CoreBytesNativeTests(CoreBytesFixture, unittest.TestCase):
    def test_complete_canonical_bytes_match_original_strict_decoder(self):
        corpus = [b"{}", b" [true,false,null,-0,0,-17,18446744073709551615] ",
                  b'{"z":"\\u00e9","a":"\\ud83d\\ude00","n":"\\u0000\\b\\n"}',
                  '{"é":1,"z":2,"😀":3,"a":4}'.encode(),
                  b'{"nested":{"b":2,"a":1},"empty":[],"slash":"\\/"}']
        rows = []
        for wire in corpus:
            with self.subTest(wire=wire):
                call = self.assert_reference_decode(wire)
                rows.append({"input_sha256": sha256(wire).hexdigest(),
                             "published_sha256": sha256(call["published"]).hexdigest()})
        record(self.directory() / "canonical.json", rows)

    def test_invalid_utf8_json_and_duplicate_keys_keep_complete_original_errors(self):
        corpus = [b"", b"\xff", b'{"x":1,"\\u0078":2}', b"1.0", b"1e2",
                  b"NaN", b"Infinity", b'{"x":"\\ud800"}', b'{"x":"\\udc00"}',
                  b'"\xed\xa0\x80"', b'"\xf4\x90\x80\x80"', b"01", b"-",
                  b'{"x":}', b'{"x":1} trailing']
        rows = []
        for wire in corpus:
            with self.subTest(wire=wire):
                call = self.assert_reference_decode(wire)
                rows.append({"input_sha256": sha256(wire).hexdigest(),
                             "published": call["published"].hex()})
        record(self.directory() / "refusals.json", rows)

    def test_integer_limits_capture_zero_and_real_allowed_runtime_settings(self):
        current = sys.get_int_max_str_digits()
        minimum = sys.int_info.str_digits_check_threshold
        limits = list(dict.fromkeys([0, minimum, max(minimum, current), minimum + 37]))
        rows = []
        for limit in limits:
            with integer_limit(limit):
                for digits in (minimum, minimum + 1, max(minimum, limit) + 1):
                    wire = b"[" + b"7" * digits + b",-" + b"8" * digits + b"]"
                    with self.subTest(limit=limit, digits=digits):
                        call = self.assert_reference_decode(wire)
                        words = struct.unpack("<8Q", call["published"][:64])
                        self.assertEqual(words[6], limit)
                        self.assertEqual(words[7], 3 if limit and digits > limit else 5)
                        rows.append({"limit": limit, "digits": digits, "status": words[2], "stage": words[7]})
        self.assertEqual(sys.get_int_max_str_digits(), current)
        record(self.directory() / "digit-limits.json", rows)

    def test_full_utf8_and_preflight_refuse_before_large_integer_conversion(self):
        minimum = sys.int_info.str_digits_check_threshold
        integer = b"7" * (minimum + 1)
        deep = b"[" * 66 + b"0" + b"]" * 66
        cases = [
            (b"[" + integer + b"," + deep + b"]", 4, 2),
            (b"[" + integer + b"," + deep + b',"\xff"]', 2, 1),
            (b"[" + integer + b',{"a":1,"a":2}]', 2, 2),
            (b"[" + integer + b",]", 2, 2),
            (b"[" + integer + b",0]", 2, 3),
        ]
        rows = []
        with integer_limit(minimum):
            for wire, status, stage in cases:
                with self.subTest(status=status, stage=stage, wire_sha=sha256(wire).hexdigest()):
                    call = self.assert_reference_decode(wire)
                    words = struct.unpack("<8Q", call["published"][:64])
                    self.assertEqual((words[2], words[7]), (status, stage))
                    rows.append({"input_sha256": sha256(wire).hexdigest(),
                                 "status": status, "stage": stage, "message": call["published"][64:].decode()})
        record(self.directory() / "first-errors.json", rows)

    def test_original_byte_node_and_depth_boundaries_are_not_narrowed(self):
        corpus = [
            b"{}" + b" " * (MAX_BYTES - 2),
            b"\xff" + b" " * MAX_BYTES,
            b"[" + b"0," * (MAX_NODES - 2) + b"0]",
            b"[" + b"0," * (MAX_NODES - 1) + b"0]",
            b"[" * 64 + b"0" + b"]" * 64,
            b"[" * 65 + b"0" + b"]" * 65,
        ]
        rows = []
        for wire in corpus:
            with self.subTest(size=len(wire)):
                call = self.assert_reference_decode(wire)
                rows.append({"size": len(wire), "input_sha256": sha256(wire).hexdigest(),
                             "published_bytes": len(call["published"]),
                             "published_sha256": sha256(call["published"]).hexdigest()})
        record(self.directory() / "boundaries.json", rows)

    def test_composite_namespace_handoff_and_legacy_collision_remain_explicit(self):
        rows = []
        for version in range(1, 5):
            wire = ('{"schema":"hepta.hia.composite.v%d","functions":[]}' % version).encode()
            receipt = self.frontend.prepare(wire)
            self.assertEqual(receipt.status, 1)
            self.assertEqual(receipt.payload, reference_decode(wire)[1])
            result = self.verifier.verify_bytes(wire)
            self.assertIs(type(result), CompositeCoreBytes)
            self.assertEqual(result.canonical_bytes, receipt.payload)
            rows.append({"version": version, "route": receipt.status})
        legacy = b'{"types":[],"schema":"hepta.hia.program.v2","functions":[]}'
        from hepta.hia_program import verify_program
        with patch.dict(os.environ, clean_environment(), clear=True):
            with self.assertRaises(HIAProgramRejected) as expected:
                verify_program(legacy)
        with self.assertRaises(HIAProgramRejected) as actual:
            self.verifier.verify_bytes(legacy)
        self.assertEqual((type(actual.exception), actual.exception.code, str(actual.exception)),
                         (type(expected.exception), expected.exception.code, str(expected.exception)))
        record(self.directory() / "namespaces.json", rows)

    def test_real_vm_and_native_publish_identical_full_bytes_and_cleanup(self):
        wire = b'{"z":-0,"a":"\\u00e9"}'
        native = self.frontend.receipt(wire)
        vm, observation = vm_frontend(wire)
        self.assertEqual(vm, native.raw)
        self.assertEqual(observation["resources"]["live_owners"], 0)
        self.assertEqual(observation["resources"]["live_local_loans"], 0)
        directory = self.directory()
        (directory / "actual-vm.bin").write_bytes(vm)
        (directory / "actual-native.bin").write_bytes(native.raw)
        record(directory / "vm.json", observation)

    def test_published_identity_and_private_framing_cannot_authorize_corrupt_bytes(self):
        original = self.frontend._entry
        mutations = [(0, RESULT_MAGIC ^ 1), (8, 2), (16, 99), (24, 1 << 63),
                     (32, 0), (40, 99), (48, 1 << 63), (56, 99)]
        rows = []
        for offset, value in mutations:
            calls = []
            def corrupted(source, size, output, capacity, workspace, workspace_size):
                result = original(source, size, output, capacity, workspace, workspace_size)
                calls.append(result)
                ctypes.memmove(ctypes.addressof(output) + offset, struct.pack("<Q", value), 8)
                return result
            with self.subTest(offset=offset), patch.object(self.frontend, "_entry", corrupted):
                with self.assertRaises(RuntimeError):
                    self.frontend.receipt(b"{}")
            self.assertEqual(len(calls), 1)
            rows.append({"offset": offset, "native_calls": 1})
        source = ctypes.create_string_buffer(b"{}")
        output = ctypes.create_string_buffer(b"\xa5" * 256, 256)
        small = ctypes.create_string_buffer(127)
        code = original(source, 2, output, 256, small, 127)
        self.assertEqual(code, FRAMING)
        self.assertEqual(output.raw, b"\xa5" * 256)
        record(self.directory() / "framing.json", rows)
