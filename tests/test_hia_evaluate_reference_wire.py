"""Compare the Evaluate HIA projector against the independent scalar wire encoder."""

import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_scalar_reference_wire as scalar_wire
from hepta.hia_evaluate_reference_wire_native import NativeEvaluateReferenceWire, SCHEMA, SELECTOR
from hepta.hia_native_helpers import native_helpers_scope
from hepta.hia_program import integer_range, verify_program
from hepta.hia_scalar_reference_native import OPCODES
from hepta.hia_scalar_reference_wire import MAX_PACKET_BYTES, TYPES, program_wire
from tests.test_hia_program import arithmetic, b, branch, c, f, i, jump, m, ret
from tools.qualify_hia_selfhost import build_seed, compile_stage


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "examples/hia_bootstrap/evaluate_reference_wire.hepta"
WORK_BYTES = 48 << 20
REFUSED = 0xFFFFFFFD
HEADER = struct.Struct("<8Q")


class EvaluateReferenceWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="hia-evaluate-wire-")
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        seed, _ = build_seed(directory)
        compiler_source = SOURCE.with_name("selfhost.hepta").read_bytes()
        first, _ = compile_stage(directory, "B1", seed, compiler_source, image_format="seed-shared")
        compiler, _ = compile_stage(directory, "B2", first, compiler_source)
        if first.read_bytes() != compiler.read_bytes():
            raise AssertionError("self-hosted compiler generations differ")
        image, _ = compile_stage(directory, "evaluate-wire", compiler, SOURCE.read_bytes())
        image_bytes = image.read_bytes()
        image_digest = sha256(image_bytes).hexdigest()
        cls.image = NativeEvaluateReferenceWire(image_bytes, image_digest)
        cls.manifest = directory / "manifest.json"
        cls.record = {"schema": SCHEMA, "source_sha256": sha256(SOURCE.read_bytes()).hexdigest(),
                      "image_path": image.name, "image_sha256": image_digest,
                      "compiler_sha256": sha256(compiler.read_bytes()).hexdigest()}
        cls.manifest.write_text(json.dumps(cls.record))
        bundle = {"schema": "hepta.hia.native-helpers.v1", "target": "linux-x86_64-lp64",
                  "abi": "hia-byte-six-argument-v1",
                  "helpers": [{"selector": SELECTOR, "manifest_path": str(cls.manifest),
                               "manifest_sha256": sha256(cls.manifest.read_bytes()).hexdigest()}]}
        cls.bundle = directory / "bundle.json"
        cls.bundle.write_text(json.dumps(bundle))
        cls.bundle_digest = sha256(cls.bundle.read_bytes()).hexdigest()

    def invoke(self, wire, *, capacity=MAX_PACKET_BYTES, workspace=WORK_BYTES):
        output = ctypes.create_string_buffer(capacity)
        work = ctypes.create_string_buffer(workspace)
        source = ctypes.create_string_buffer(wire)
        extent = self.image._entry(source, len(wire), output, capacity, work, workspace)
        if extent == REFUSED:
            return None
        self.assertLessEqual(extent, capacity)
        self.assertGreaterEqual(extent, HEADER.size)
        return ctypes.string_at(output, extent)

    def compare(self, document, entry):
        canonical = verify_program(document).canonical_bytes
        encoded = program_wire(canonical, entry)
        wire = b"[" + canonical + b"," + json.dumps(entry).encode("ascii") + b"]"
        actual = self.invoke(wire)
        self.assertEqual(self.image.project(canonical, entry), encoded)
        if encoded is None:
            self.assertIsNone(actual)
            return
        body, registers, bounce, returns, resource_sites = encoded
        self.assertFalse(resource_sites)
        expected = (HEADER.pack(int.from_bytes(b"HIAERW01", "little"), registers, bounce,
                                len(body), len(returns), 0, 0, 0) + body[HEADER.size:]
                    + struct.pack(f"<{len(returns)}Q", *(TYPES.index(name) for name in returns)))
        self.assertEqual(actual, expected)

    def test_integer_boundaries_boolean_and_unit(self):
        for typ in TYPES:
            bounds = ((False, True) if typ == "bool" else
                      (None,) if typ == "unit" else integer_range(typ))
            for value in bounds:
                with self.subTest(typ=typ, value=value):
                    self.compare(m(f("constant", [], [typ], [], [
                        b("start", [], [c("x", typ, value)], ret("x"))])), "constant")

    def test_breadth_first_calls_edges_and_unreachable_resources(self):
        # Entry calls left/right; both call leaf. Declaration order is the reverse
        # of discovery order. The duplicate target must occupy a single wire slot.
        params = [("x", "i32")]
        def called(name, target):
            return f(name, params, ["i32"], ["trap"], [b("start", params, [
                i("call", ["x"], [("out", "i32")], function=target)], ret("out"))])
        entry = f("dispatch", params, ["i32"], ["trap"], [
            b("start", params, [c("zero", "i32", 0),
              i("compare.lt", ["x", "zero"], [("neg", "bool")])],
              branch("neg", ("lhs", "x"), ("rhs", "x"))),
            b("lhs", [("x_lhs", "i32")], [i("call", ["x_lhs"], [("l", "i32")], function="left")], jump("done", "l")),
            b("rhs", [("x_rhs", "i32")], [i("call", ["x_rhs"], [("r", "i32")], function="right")], jump("done", "r")),
            b("done", [("result", "i32")], [], ret("result")),
        ])
        leaf = f("leaf", params, ["i32"], ["trap"], [
            b("start", params, [i("int.neg.checked", ["x"], [("y", "i32")])], ret("y"))])
        resource = f("borrowed", [("s", "readbuf")], ["usize"], ["read"], [
            b("start", [("s", "readbuf")], [i("buffer.len", ["s"], [("n", "usize")])], ret("n"))])
        doc = m(resource, leaf, called("right", "leaf"), called("left", "leaf"), entry)
        for selected in ("dispatch", "right", "leaf", "borrowed"):
            with self.subTest(entry=selected):
                self.compare(doc, selected)

    def test_multi_result_call_casts_and_empty_lists(self):
        params = [("x", "i32")]
        pair = f("pair", params, ["i8", "u64"], ["trap"], [b("start", params, [
            i("int.cast", ["x"], [("a", "i8")], mode="wrap"),
            i("int.cast", ["x"], [("z", "u64")], mode="checked")], ret("a", "z"))])
        entry = f("entry", params, ["u64", "i8"], ["trap"], [b("start", params, [
            i("call", ["x"], [("a", "i8"), ("z", "u64")], function="pair")], ret("z", "a"))])
        empty = f("empty", [], [], [], [b("start", [], [], ret())])
        self.compare(m(pair, entry, empty), "entry")
        self.compare(m(empty), "empty")

    def test_traps_and_recursive_call_projection(self):
        params = [("x", "i32")]
        recursive = f("recur", params, ["i32"], ["trap"], [
            b("start", params, [i("call", ["x"], [("next", "i32")], function="recur")], ret("next"))])
        self.compare(m(recursive), "recur")
        for reason in ("user", "overflow", "division_by_zero", "bounds", "allocation"):
            with self.subTest(reason=reason):
                self.compare(m(f("failure", [], ["u32"], ["trap"], [
                    b("start", [], [], {"op": "trap", "code": reason})])), "failure")

    def test_complete_scalar_opcode_set(self):
        # Use independent operand and result types. In particular, a comparison
        # returns bool even when its two operands carry signed integer flags.
        for opcode in OPCODES:
            with self.subTest(opcode=opcode):
                name, attrs = opcode, {}
                operand_types = ["i16", "i16"]
                result_type = "i16"
                if opcode.startswith("cast."):
                    name, attrs = "int.cast", {"mode": opcode.removeprefix("cast.")}
                    operand_types, result_type = ["i16"], "u8"
                elif opcode.startswith("bool."):
                    operand_types = ["bool"] if opcode == "bool.not" else ["bool", "bool"]
                    result_type = "bool"
                elif opcode.startswith("compare."):
                    result_type = "bool"
                elif opcode in ("int.neg.checked", "bit.not"):
                    operand_types = ["i16"]
                elif opcode == "select":
                    operand_types = ["bool", "i16", "i16"]
                params = [(f"arg{n}", typ) for n, typ in enumerate(operand_types)]
                inputs = [param for param, _ in params]
                operation = i(name, inputs, [("out", result_type)], **attrs)
                self.compare(m(f("apply", params, [result_type], ["trap"], [
                    b("entry", params, [operation], ret("out"))])), "apply")

    def test_argument_bounce_and_unused_resource_parameter(self):
        params = [(f"arg{n}", "u32") for n in range(5)]
        accept = f("accept", params, [], [], [b("start", params, [], ret())])
        caller = f("caller", params, [], [], [b("start", params, [
            i("call", [name for name, _ in reversed(params)], [], function="accept")], ret())])
        self.compare(m(accept, caller), "caller")
        borrowed = [("never_read", "readbuf")]
        unused = f("unused", borrowed, [], [], [b("start", borrowed, [], ret())])
        self.compare(m(unused), "unused")

    def test_pinned_worker_selects_native_and_preserves_resource_encoder(self):
        scalar = verify_program(arithmetic()).canonical_bytes
        expected = program_wire(scalar, "calculate")
        resource_fn = f("borrowed", [("s", "readbuf")], ["usize"], ["read"], [
            b("start", [("s", "readbuf")], [i("buffer.len", ["s"], [("n", "usize")])], ret("n"))])
        resource = verify_program(m(resource_fn)).canonical_bytes
        resource_expected = program_wire(resource, "borrowed", allow_resources=True)
        self.assertIsNotNone(resource_expected)
        with native_helpers_scope(str(self.bundle), self.bundle_digest):
            self.assertEqual(os.environ[SELECTOR], str(self.manifest))
            with patch.object(scalar_wire, "program_wire", side_effect=AssertionError("hosted scalar encoder called")):
                self.assertEqual(scalar_wire.selected_program_wire(scalar, "calculate"), expected)
                self.assertEqual(scalar_wire.selected_program_wire(scalar, "calculate", allow_resources=True), expected)
            with patch.object(scalar_wire, "program_wire", wraps=program_wire) as legacy:
                self.assertEqual(scalar_wire.selected_program_wire(resource, "borrowed", allow_resources=True),
                                 resource_expected)
                legacy.assert_called_once_with(resource, "borrowed", allow_resources=True)

    def test_explicit_pin_and_manifest_errors_propagate(self):
        scalar = verify_program(arithmetic()).canonical_bytes
        with self.assertRaises(ValueError):
            with native_helpers_scope(str(self.bundle), "0" * 64):
                self.fail("wrong worker bundle digest admitted")
        for field in ("source_sha256", "image_sha256"):
            with self.subTest(field=field):
                manifest = self.manifest.with_name(field + ".json")
                manifest.write_text(json.dumps({**self.record, field: "0" * 64}))
                with patch.dict(os.environ, {SELECTOR: str(manifest)}), \
                     patch.object(scalar_wire, "program_wire", side_effect=AssertionError("invalid manifest fell back")):
                    with self.assertRaises(RuntimeError) as failure:
                        scalar_wire.selected_program_wire(scalar, "calculate")
                    self.assertIsInstance(failure.exception.__cause__, ValueError)

    def test_missing_entry_malformed_input_and_short_buffers(self):
        checked = verify_program(arithmetic()).canonical_bytes
        valid = b"[" + checked + b',"calculate"]'
        for wire in (b"[]", b'{', b"[" + checked + b',"missing"]'):
            with self.subTest(wire=wire[:30]):
                self.assertIsNone(self.invoke(wire))
        self.assertIsNone(self.invoke(valid, capacity=MAX_PACKET_BYTES - 1))
        self.assertIsNone(self.invoke(valid, workspace=WORK_BYTES - 1))
