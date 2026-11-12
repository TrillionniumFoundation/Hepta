"""Complete native body diagnostics; original declaration and host boundaries stay explicit."""
from __future__ import annotations
from copy import deepcopy
import ctypes
from hashlib import sha256
import struct
import unittest
from unittest.mock import patch
from tests import test_hia_core_admission_diagnostics as controls
from hepta.hia_core_admission_native import (
    NativeCoreAdmission, ERROR_CODES, SELECTOR, MAX_BYTES, scratch_sizes,
    DIAGNOSTIC_MAGIC, DIAGNOSTIC_BYTES, BODY_DIAGNOSTIC_KIND,
    BODY_DIAGNOSTIC_OFFSET,
)
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_opcodes import OPCODES


def simple(params=(), ops=(), returns=(), effects=(), term=None):
    return controls.program(params=params, returns=returns, effects=effects,
                            blocks=[controls.block(params=params, ops=ops, term=term)])


def call_case(caller_params=(), callee_params=(), args=(), outputs=(), returns=(), origins=None):
    value = simple(caller_params, [controls.instruction("call", args, outputs, function="g")])
    callee = controls.program(name="g", params=callee_params, returns=returns)["functions"][0]
    if origins is not None:
        callee["return_loans"] = list(origins)
    value["functions"].append(callee)
    return value


def opcode_cases():
    ins = controls.instruction
    version = simple(ops=[ins("buffer.copy_range")])
    version["schema"] = "hepta.hia.program.v4"
    return [
        ("unknown_unicode", simple(ops=[ins("not\x00an_\u00e9_\U0001d11e_opcode")])),
        ("version_before_arity", version),
        ("wrong_attribute_count", simple([("x", "u32")],
                                          [ins("int.add.wrap", ["x", "x"], [("y", "u32")], value=1)])),
        ("wrong_attribute_key", simple(ops=[ins("const", (), [("x", "u32")], wrong=1)])),
        ("operand_count", simple([("x", "u32")], [ins("int.add.wrap", ["x"], [("y", "u32")])])),
        ("operand_types", simple([("x", "u32"), ("y", "i32")],
                                  [ins("int.add.wrap", ["x", "y"], [("z", "u32")])])),
        ("output_count", simple([("x", "u32")], [ins("int.add.wrap", ["x", "x"])])),
        ("output_types", simple([("x", "u32")], [ins("int.add.wrap", ["x", "x"], [("y", "u64")])])),
        ("constant_exact_type", simple(ops=[ins("const", (), [("x", "u32")], value=True)])),
        ("cast_mode", simple([("x", "u32")], [ins("int.cast", ["x"], [("y", "u64")], mode="unsupported")])),
        ("borrow_operand_policy", simple([("v", "readbuf")],
                                          [ins("borrow.mut", ["v"], [("child", "mutbuf")])])),
    ]


def call_return_cases():
    ins = controls.instruction
    duplicate_loan = simple([("v", "readbuf")], returns=["readbuf", "readbuf"],
                            term={"op": "ret", "values": ["v", "v"]})
    duplicate_loan["functions"][0]["return_loans"] = ["v", "v"]
    origin = simple([("a", "readbuf"), ("b", "readbuf")], returns=["readbuf"],
                    term={"op": "ret", "values": ["a"]})
    origin["functions"][0]["return_loans"] = ["b"]
    return [
        ("callee_identifier", simple(ops=[ins("call", function="__hia_reserved")])),
        ("unknown_callee", simple(ops=[ins("call", function="missing")])),
        ("call_arity", call_case(callee_params=[("formal", "u32")])),
        ("call_argument", call_case([("x", "bool")], [("formal", "u32")], ["x"])),
        ("call_duplicate_owner", call_case([("owner", "buffer")],
                                           [("a", "buffer"), ("b", "buffer")], ["owner", "owner"])),
        ("call_exclusive_alias", call_case([("view", "mutbuf")],
                                           [("a", "mutbuf"), ("b", "mutbuf")], ["view", "view"])),
        ("call_output_count", call_case(returns=["u32"])),
        ("call_output_type", call_case(outputs=[("out", "u64")], returns=["u32"])),
        ("return_count", simple([("x", "u32")], term={"op": "ret", "values": ["x"]})),
        ("return_type", simple([("x", "u32")], returns=["u64"], term={"op": "ret", "values": ["x"]})),
        ("return_duplicate_loan", duplicate_loan),
        ("return_origin", origin),
        ("return_duplicate_owner", simple([("owner", "buffer")], returns=["buffer", "buffer"],
                                          term={"op": "ret", "values": ["owner", "owner"]})),
        ("return_live_owner", simple([("owner", "buffer")])),
    ]


def loan_cfg_cases():
    ins = controls.instruction
    owner = [("owner", "buffer")]
    suspended_params = [("view", "mutbuf"), ("index", "usize")]
    wrong_condition = controls.program(params=[("condition", "u32")], blocks=[
        controls.block(params=[("condition", "u32")], term={
            "op": "branch", "cond": "condition", "then": {"target": "left", "args": []},
            "else": {"target": "right", "args": []}}),
        controls.block("left"), controls.block("right")])
    mismatch = controls.program(params=[("x", "u32")], blocks=[
        controls.block(params=[("x", "u32")], term={"op": "jump", "target": "tail", "args": ["x"]}),
        controls.block("tail", [("y", "u64")])])
    duplicate = controls.program(params=owner, blocks=[
        controls.block(params=owner, term={"op": "jump", "target": "tail", "args": ["owner", "owner"]}),
        controls.block("tail", [("a", "buffer"), ("b", "buffer")])])
    dropped = controls.program(params=owner, blocks=[
        controls.block(params=owner, term={"op": "jump", "target": "tail", "args": []}),
        controls.block("tail")])
    graph = controls.program(params=[("view", "readbuf")], blocks=[
        controls.block(params=[("view", "readbuf")],
            ops=[ins("borrow.read", ["view"], [("child", "readbuf")])],
            term={"op": "jump", "target": "tail", "args": ["child"]}),
        controls.block("tail", [("later", "readbuf")])])
    predecessor_params = [("condition", "bool"), ("a", "readbuf"), ("b", "readbuf")]
    predecessor = controls.program(params=predecessor_params, returns=["readbuf"], blocks=[
        controls.block(params=predecessor_params, term={
            "op": "branch", "cond": "condition", "then": {"target": "join", "args": ["a"]},
            "else": {"target": "join", "args": ["b"]}}),
        controls.block("join", [("value", "readbuf")], term={"op": "ret", "values": ["value"]})])
    predecessor["functions"][0]["return_loans"] = ["a"]
    all_effects_params = [("owner", "buffer"), ("view", "mutbuf"),
                          ("shared", "readbuf"), ("index", "usize"), ("byte", "u8")]
    return [
        ("owner_borrowed", simple(owner, [ins("borrow.read", ["owner"], [("view", "readbuf")]),
                                          ins("owner.drop", ["owner"])])),
        ("parent_suspended", simple(suspended_params,
            [ins("borrow.read", ["view"], [("child", "readbuf")]),
             ins("buffer.load", ["view", "index"], [("byte", "u8")])])),
        ("borrow_conflict", simple(owner,
            [ins("borrow.read", ["owner"], [("a", "readbuf")]),
             ins("borrow.mut", ["owner"], [("b", "mutbuf")])])),
        ("end_external", simple([("view", "readbuf")], [ins("loan.end", ["view"])])),
        ("end_children", simple(owner,
            [ins("borrow.mut", ["owner"], [("parent", "mutbuf")]),
             ins("borrow.read", ["parent"], [("child", "readbuf")]), ins("loan.end", ["parent"])])),
        ("branch_condition", wrong_condition), ("edge_types", mismatch),
        ("edge_duplicate", duplicate), ("edge_live", dropped), ("edge_loan_graph", graph),
        ("edge_predecessors", predecessor),
        ("effect_alloc", simple(owner, [ins("owner.drop", ["owner"])])),
        ("effect_write", simple([("view", "mutbuf"), ("byte", "u8")],
                                 [ins("buffer.fill", ["view", "byte"])])),
        ("effect_read_trap", simple([("view", "readbuf"), ("index", "usize")],
                                     [ins("buffer.load", ["view", "index"], [("byte", "u8")])])),
        ("effect_all_sorted", simple(all_effects_params, [
            ins("owner.drop", ["owner"]), ins("buffer.fill", ["view", "byte"]),
            ins("buffer.load", ["shared", "index"], [("loaded", "u8")])])),
    ]


class CoreBodyDiagnosticNativeTests(controls._NativeFixture, unittest.TestCase):
    def retain(self, suffix, data):
        path = self.folder / (self._testMethodName + "." + suffix)
        with path.open("xb") as stream:
            stream.write(data)
        return {"path": str(path), "bytes": len(data), "sha256": sha256(data).hexdigest()}

    def compare_body(self, value, *, raw=None, family=BODY_DIAGNOSTIC_KIND, expected_code=None):
        raw = controls.wire(value) if raw is None else raw
        expected = controls.reference_error(raw)
        if expected_code is not None:
            self.assertEqual(expected[1], expected_code, "fixture must reach its intended original refusal")
        observed = []
        original = self.native.receipt
        def capture(*args, **kwargs):
            receipt = original(*args, **kwargs)
            observed.append(receipt)
            return receipt
        with patch.object(self.native, "receipt", capture):
            with self.assertRaises(HIAProgramRejected) as found:
                self.native.admit(raw)
        self.assertEqual(len(observed), 1)
        receipt = observed[0]
        ordinal = len(self.observations)
        self.observations.append({
            "input": self.retain("%03d.input.json" % ordinal, raw),
            "native_frame": self.retain("%03d.frame.bin" % ordinal, receipt.raw),
            "reference_message": self.retain("%03d.reference.utf8" % ordinal, expected[2].encode("utf-8")),
            "actual_message": self.retain("%03d.actual.utf8" % ordinal, str(found.exception).encode("utf-8")),
            "native_image_sha256": self.image_sha256, "native_status": receipt.status,
            "diagnostic_kind": receipt.diagnostic_kind, "expected_code": expected[1],
            "actual_code": found.exception.code, "actual_type": type(found.exception).__name__})
        self.assertEqual((type(found.exception), found.exception.code, str(found.exception)), expected)
        self.assertTrue(receipt.native_executed)
        self.assertEqual(receipt.diagnostic_kind, family)
        self.assertEqual(receipt.message, expected[2][len(expected[1]) + 2:])
        self.assertEqual(receipt.raw[64:], receipt.message.encode("utf-8"))
        return receipt

    def test_complete_opcode_contract_messages_match_original(self):
        codes = {"unknown_unicode": "E_HIA_OPCODE", "version_before_arity": "E_HIA_OPCODE",
                 "wrong_attribute_count": "E_HIA_FORMAT", "wrong_attribute_key": "E_HIA_FORMAT",
                 "operand_count": "E_HIA_TYPE", "operand_types": "E_HIA_TYPE",
                 "output_count": "E_HIA_TYPE", "output_types": "E_HIA_TYPE",
                 "constant_exact_type": "E_HIA_TYPE", "cast_mode": "E_HIA_TYPE",
                 "borrow_operand_policy": "E_HIA_LOAN"}
        for label, value in opcode_cases():
            with self.subTest(case=label):
                if label != "unknown_unicode":
                    self.assertIn(value["functions"][0]["blocks"][0]["ops"][0]["op"], OPCODES)
                self.compare_body(value, expected_code=codes[label])

    def test_complete_call_and_return_messages_match_original(self):
        for label, value in call_return_cases():
            with self.subTest(case=label):
                self.compare_body(value)

    def test_complete_loan_cfg_and_effect_messages_match_original(self):
        for label, value in loan_cfg_cases():
            with self.subTest(case=label):
                self.compare_body(value)

    def test_unicode_maximum_wire_and_long_type_lists_are_complete(self):
        value = simple(ops=[controls.instruction("\x00\u00e9\U0001d11e\\\n" * 20000)])
        receipt = self.compare_body(value)
        self.assertGreater(len(receipt.raw), 512)
        value = simple(ops=[controls.instruction("")])
        overhead = len(controls.wire(value))
        value["functions"][0]["blocks"][0]["ops"][0]["op"] = "x" * (MAX_BYTES - overhead)
        raw = controls.wire(value)
        self.assertEqual(len(raw), MAX_BYTES)
        receipt = self.compare_body(value, raw=raw)
        self.assertEqual(receipt.message, "unsupported opcode " + value["functions"][0]["blocks"][0]["ops"][0]["op"])
        many = call_case([("view", "readbuf")], [("formal", "readbuf")], ["view"],
                         returns=["readbuf"] * 4096, origins=["formal"] * 4096)
        receipt = self.compare_body(many)
        self.assertEqual(receipt.message, "call: output types must be " + repr(["readbuf"] * 4096))
        self.assertGreater(len(receipt.raw), 40000)

    def test_original_first_refusal_and_breadth_first_order_are_preserved(self):
        value = simple(ops=[controls.instruction("unknown", ["missing"])])
        self.compare_body(value, family=1)
        value = simple(ops=[controls.instruction("first_unknown")])
        second = simple(ops=[controls.instruction("second_unknown")])["functions"][0]
        second["name"] = "another"
        value["functions"].append(second)
        self.assertEqual(self.compare_body(value).message, "unsupported opcode first_unknown")
        params = [("condition", "bool")]
        value = controls.program(params=params, blocks=[
            controls.block(params=params, term={
                "op": "branch", "cond": "condition", "then": {"target": "left", "args": []},
                "else": {"target": "right", "args": []}}),
            controls.block("right", ops=[controls.instruction("right_unknown")]),
            controls.block("left", ops=[controls.instruction("left_unknown")])])
        self.assertEqual(self.compare_body(value).message, "unsupported opcode left_unknown")
        value = simple([("x", "u32")], [controls.instruction("int.add.wrap", ["x"], (), wrong=1)])
        self.assertEqual(self.compare_body(value, expected_code="E_HIA_FORMAT").message,
                         "int.add.wrap: expected exactly  attributes")

    def test_dynamic_prefix_and_private_header_preserve_bounds(self):
        raw = controls.wire(simple(ops=[controls.instruction("\u00e9_" * 1024)]))
        expected = controls.reference_error(raw)
        payload = expected[2][len(expected[1]) + 2:].encode("utf-8")
        state_size, arena_size = scratch_sizes(len(raw))
        source = ctypes.create_string_buffer(raw)
        state = ctypes.create_string_buffer(state_size + 16)
        arena = ctypes.create_string_buffer(arena_size + 16)
        ctypes.memset(ctypes.addressof(state), 0xa5, state_size + 16)
        ctypes.memset(ctypes.addressof(arena) + arena_size, 0x6b, 16)
        code = self.native._entry(source, len(raw), state, state_size, arena, arena_size)
        base = state_size - DIAGNOSTIC_BYTES
        header = state.raw[base:base + 64]
        values = struct.unpack("<8Q", header)
        self.assertEqual(values, (DIAGNOSTIC_MAGIC, 2, code, BODY_DIAGNOSTIC_KIND,
                                  len(payload), base - BODY_DIAGNOSTIC_OFFSET,
                                  BODY_DIAGNOSTIC_OFFSET, 0))
        self.assertEqual(ERROR_CODES[code], expected[1])
        self.assertEqual(state.raw[BODY_DIAGNOSTIC_OFFSET:BODY_DIAGNOSTIC_OFFSET + len(payload)], payload)
        self.assertEqual(state.raw[base + 72:state_size], b"\xa5" * (DIAGNOSTIC_BYTES - 72))
        self.assertEqual(state.raw[state_size:], b"\xa5" * 16)
        self.assertEqual(arena.raw[arena_size:], b"\x6b" * 16)
        self.assertEqual(source.raw[:len(raw)], raw)
        self.observations.append({"actual_frame": self.retain("bounds.frame.bin", header + payload),
                                  "input": self.retain("bounds.input.json", raw), "outer_canaries_preserved": True})
        state = ctypes.create_string_buffer(b"\x71" * state_size, state_size)
        arena = ctypes.create_string_buffer(b"\x39" * arena_size, arena_size)
        before = (state.raw, arena.raw)
        code = self.native._entry(source, len(raw), state, state_size - 1, arena, arena_size)
        self.assertEqual(code, 0xfffffffd)
        self.assertEqual((state.raw, arena.raw), before)
        self.assertEqual(source.raw[:len(raw)], raw)

    def test_body_frame_corruption_cannot_authorize_a_message(self):
        raw = controls.wire(simple(ops=[controls.instruction("unknown")]))
        original = self.native._entry
        state_size, _ = scratch_sizes(len(raw))
        capacity = state_size - DIAGNOSTIC_BYTES - BODY_DIAGNOSTIC_OFFSET
        for label, field, value in [
            ("magic", 0, 0), ("version", 8, 1), ("status", 16, 0), ("kind", 24, 1),
            ("empty", 32, 0), ("overflow", 32, capacity + 1), ("capacity", 40, capacity + 1),
            ("capacity_small", 40, capacity - 1),
            ("pool_offset", 48, 0), ("tail_offset", 48, state_size - DIAGNOSTIC_BYTES),
            ("reserved", 56, 1),
        ]:
            with self.subTest(case=label):
                calls = []
                def corrupt(*args):
                    returned = original(*args)
                    address = ctypes.addressof(args[2]) + int(args[3]) - DIAGNOSTIC_BYTES
                    ctypes.memmove(address + field, struct.pack("<Q", value), 8)
                    calls.append(returned)
                    return returned
                with patch.object(self.native, "_entry", corrupt):
                    with self.assertRaises(RuntimeError):
                        self.native.admit(raw)
                self.assertEqual(calls, [0xfffffff0])
        calls = []
        def corrupt_utf8(*args):
            returned = original(*args)
            ctypes.memmove(ctypes.addressof(args[2]) + BODY_DIAGNOSTIC_OFFSET, b"\xff", 1)
            calls.append(returned)
            return returned
        with patch.object(self.native, "_entry", corrupt_utf8):
            with self.assertRaises(RuntimeError):
                self.native.admit(raw)
        self.assertEqual(calls, [0xfffffff0])

    def test_selected_ordinary_verify_publishes_complete_native_body_error(self):
        from tools.hia_agent_native_qualification import exhaustive_u8_workload
        value = simple(ops=[controls.instruction("unsupported_\u00e9_\U0001d11e")])
        expected = controls.reference_error(controls.wire(value))
        calls = []
        original = NativeCoreAdmission.receipt
        def observe(instance, *args, **kwargs):
            receipt = original(instance, *args, **kwargs)
            calls.append(receipt)
            return receipt
        with controls.reference_environment(), patch.dict("os.environ", {SELECTOR: str(self.manifest)}):
            with (patch("hepta.hia_program._reference_primitive_structure",
                        side_effect=AssertionError("reference declarations called")),
                  patch("hepta.hia_program._verify_function", side_effect=AssertionError("reference body called"))):
                with self.assertRaises(HIAProgramRejected) as found:
                    verify_program(value)
                self.assertEqual((type(found.exception), found.exception.code, str(found.exception)), expected)
            with controls.CoreValueDiagnosticAgentTests.service(self) as (service, session, replies):
                session.freeze(exhaustive_u8_workload())
                reference = session.artifact(value)
                before = service.store.db.execute(
                    "SELECT COUNT(*) FROM artifacts WHERE kind='verification-receipt'").fetchone()[0]
                with (patch.object(NativeCoreAdmission, "receipt", observe),
                      patch("hepta.hia_program._verify_function", side_effect=AssertionError("reference body called"))):
                    try:
                        session.verify(reference)
                    except Exception:
                        pass
                responses = [reply for tool, reply in replies if tool == "hia_verify"]
                self.assertEqual(len(responses), 1)
                response = responses[0]
                self.assertEqual(response["status"], "rejected")
                self.assertEqual(response["error"]["code"], expected[1])
                self.assertEqual(response["error"]["message"], expected[2])
                self.assertEqual(service.store.db.execute(
                    "SELECT COUNT(*) FROM artifacts WHERE kind='verification-receipt'").fetchone()[0], before)
                state, encoded = service.store.db.execute(
                    "SELECT state,response FROM requests WHERE tool='hia_verify'").fetchone()
                self.assertEqual(state, "completed")
                self.assertEqual(controls.json.loads(encoded), response)
        self.assertTrue(calls)
        self.assertTrue(all(r.native_executed and r.diagnostic_kind == BODY_DIAGNOSTIC_KIND
                            and r.message == expected[2][len(expected[1]) + 2:] for r in calls))
        self.observations.append({"caller": "_hia_verify", "complete_error": response["error"],
                                  "native_calls": len(calls), "frames": [r.raw.hex() for r in calls]})
