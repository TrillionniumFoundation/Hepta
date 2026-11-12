"""Complete native declaration messages with the original primitive policy oracle.

These controls retain the original JSON/snapshot/legacy boundaries.  They do
not claim that Core admission owns canonicalization or composite elaboration.
"""
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
    DIAGNOSTIC_MAGIC, DIAGNOSTIC_BYTES, BODY_DIAGNOSTIC_OFFSET,
    DECLARATION_DIAGNOSTIC_KIND,
)
from hepta.hia_program import HIAProgramRejected, verify_program

FN = ("functions", 0)
BLOCK = FN + ("blocks", 0)
INS = BLOCK + ("ops", 0)
EMPTY = controls.program()
ONE_INSTRUCTION = controls.program(blocks=[controls.block(ops=[
    controls.instruction("const", (), [("value", "u32")], value=1)])])


def replace(path, value, source=None):
    result = deepcopy(EMPTY if source is None else source)
    parent = result
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = deepcopy(value)
    return result


def remove(path, source=None):
    result = deepcopy(EMPTY if source is None else source)
    parent = result
    for key in path[:-1]:
        parent = parent[key]
    del parent[path[-1]]
    return result


def declaration_cases():
    """Independent fixtures for each original declaration message family."""
    fields = "expected exactly "
    name = "invalid/reserved ASCII identifier"
    typ = "type is outside the closed primitive profile"
    plain = controls.program()
    export = {**plain, "exports": []}
    resource = controls.program(params=[("view", "readbuf")])
    resource["exports"] = ["f"]
    duplicate_fn = replace(("functions",), [plain["functions"][0], plain["functions"][0]])
    groups = {}
    groups["program"] = [
        ("program_fields", remove(("module",)), "E_HIA_FORMAT",
         "program: " + fields + "functions, module, schema"),
        ("program_fields_exports", remove(("module",), export), "E_HIA_FORMAT",
         "program: " + fields + "exports, functions, module, schema"),
        ("program_schema", replace(("schema",), "hepta.hia.program.v99"), "E_HIA_SCHEMA",
         "unsupported program schema"),
        ("module_identifier", replace(("module",), []), "E_HIA_NAME", "module: " + name),
        ("function_inventory", replace(("functions",), []), "E_HIA_FORMAT", "invalid function inventory"),
        ("duplicate_function", duplicate_fn, "E_HIA_NAME", "duplicate function"),
        ("exports_list", replace(("exports",), None), "E_HIA_FORMAT",
         "explicit scalar exports: expected value list"),
        ("exports_identifier", replace(("exports",), ["__hia_reserved"]), "E_HIA_NAME",
         "explicit scalar exports: " + name),
        ("duplicate_export", replace(("exports",), ["f", "f"]), "E_HIA_NAME",
         "duplicate explicit scalar export"),
        ("missing_export", replace(("exports",), ["missing"]), "E_HIA_CALL",
         "explicit export names a missing function"),
        ("resource_export", resource, "E_HIA_TYPE", "public exports cannot carry resource descriptors"),
    ]
    with_loans = replace(FN + ("return_loans",), [])
    pre_v8_loan = replace(FN + ("returns",), ["readbuf"])
    pre_v8_loan["schema"] = "hepta.hia.program.v7"
    wrong_arity = replace(FN + ("return_loans",), [], replace(FN + ("returns",), ["u32"]))
    wrong_origin = replace(FN + ("return_loans",), ["x"], replace(FN + ("returns",), ["u32"]))
    groups["interface"] = [
        ("function_fields", remove(FN + ("effects",)), "E_HIA_FORMAT",
         "function: " + fields + "blocks, effects, entry, name, params, returns"),
        ("function_fields_loans", remove(FN + ("entry",), with_loans), "E_HIA_FORMAT",
         "function: " + fields + "blocks, effects, entry, name, params, return_loans, returns"),
        ("function_identifier", replace(FN + ("name",), "__hia_reserved"), "E_HIA_NAME", "function: " + name),
        ("function_runtime_collision", replace(FN + ("name",), "malloc"), "E_HIA_NAME",
         "function collides with native runtime symbol"),
        ("returns_list", replace(FN + ("returns",), None), "E_HIA_TYPE", "returns must be a list"),
        ("closed_primitive_type", replace(FN + ("returns",), ["not_a_type"]), "E_HIA_TYPE", typ),
        ("loan_version", pre_v8_loan, "E_HIA_LOAN", "call loans require the v8 parameter-return contract"),
        ("return_origin_arity", wrong_arity, "E_HIA_LOAN", "return_loans must match the return arity"),
        ("nonloan_origin", wrong_origin, "E_HIA_LOAN", "nonloan result requires a null return_loans entry"),
        ("invalid_loan_origin", replace(FN + ("returns",), ["readbuf"]), "E_HIA_LOAN",
         "borrowed result must name an input loan with sufficient permission"),
        ("declared_effects", replace(FN + ("effects",), ["read", "read"]), "E_HIA_EFFECT",
         "unknown/duplicate function effect"),
        ("entry_identifier", replace(FN + ("entry",), "__hia_entry"), "E_HIA_NAME", "entry: " + name),
        ("block_inventory", replace(FN + ("blocks",), []), "E_HIA_CFG", "invalid block inventory"),
    ]
    groups["parameters"] = []
    for label, path, where, source in (
        ("function_parameters", FN + ("params",), "function parameters", EMPTY),
        ("block_parameters", BLOCK + ("params",), "block parameters", EMPTY),
        ("instruction_outputs", INS + ("out",), "instruction outputs", ONE_INSTRUCTION),
    ):
        groups["parameters"].extend([
            (label + "_list", replace(path, None, source), "E_HIA_FORMAT", where + ": expected parameter list"),
            (label + "_fields", replace(path, [{"name": "x"}], source), "E_HIA_FORMAT",
             where + ": " + fields + "name, type"),
            (label + "_identifier", replace(path, [{"name": "__hia_value", "type": "u32"}], source),
             "E_HIA_NAME", where + ": " + name),
            (label + "_duplicate", replace(path, [{"name": "x", "type": "u32"}] * 2, source),
             "E_HIA_SSA", where + ": duplicate parameter x"),
        ])
    duplicate_value = controls.program(params=[("x", "u32")], blocks=[
        controls.block(params=[("x", "u32")], ops=[controls.instruction("const", (), [("x", "u32")], value=1)])])
    groups["blocks"] = [
        ("block_fields", remove(BLOCK + ("ops",)), "E_HIA_FORMAT", "block: " + fields + "id, ops, params, term"),
        ("block_identifier", replace(BLOCK + ("id",), "__hia_block"), "E_HIA_NAME", "block id: " + name),
        ("duplicate_block", replace(FN + ("blocks",), [controls.block(), controls.block()]),
         "E_HIA_CFG", "duplicate block"),
        ("operations_list", replace(BLOCK + ("ops",), None), "E_HIA_FORMAT", "block operations must be a list"),
        ("instruction_fields", remove(INS + ("attrs",), ONE_INSTRUCTION), "E_HIA_FORMAT",
         "instruction: " + fields + "args, attrs, op, out"),
        ("opcode_text", replace(INS + ("op",), None, ONE_INSTRUCTION), "E_HIA_FORMAT", "opcode must be text"),
        ("attributes_object", replace(INS + ("attrs",), [], ONE_INSTRUCTION), "E_HIA_FORMAT",
         "instruction attributes must be an object"),
        ("duplicate_definition", duplicate_value, "E_HIA_SSA", "SSA value x is defined more than once"),
        ("entry_parameters", replace(FN + ("entry",), "absent"), "E_HIA_CFG",
         "entry parameters must equal the function signature"),
    ]
    branch = controls.program(blocks=[
        controls.block(term={"op": "branch", "cond": "condition",
                             "then": {"target": "tail", "args": []},
                             "else": {"target": "tail", "args": []}}),
        controls.block("tail")])
    edge_path = BLOCK + ("term", "then")
    groups["references"] = []
    for label, path, where, source in (
        ("instruction_arguments", INS + ("args",), "instruction arguments", ONE_INSTRUCTION),
        ("return_values", BLOCK + ("term", "values"), "return values", EMPTY),
        ("edge_arguments", edge_path + ("args",), "edge arguments", branch),
    ):
        groups["references"].extend([
            (label + "_list", replace(path, None, source), "E_HIA_FORMAT", where + ": expected value list"),
            (label + "_identifier", replace(path, ["__hia_value"], source), "E_HIA_NAME", where + ": " + name),
        ])
    groups["terminators"] = [
        ("cfg_edge_fields", remove(edge_path + ("args",), branch), "E_HIA_FORMAT",
         "CFG edge: " + fields + "args, target"),
        ("edge_target_identifier", replace(edge_path + ("target",), "__hia_target", branch),
         "E_HIA_NAME", "edge target: " + name),
        ("missing_terminator", replace(BLOCK + ("term",), None), "E_HIA_CFG", "missing terminator"),
        ("unknown_terminator", replace(BLOCK + ("term",), {"op": "unknown"}), "E_HIA_CFG", "unknown terminator"),
        ("ret_fields", replace(BLOCK + ("term",), {"op": "ret"}), "E_HIA_FORMAT", "ret: " + fields + "op, values"),
        ("jump_fields", replace(BLOCK + ("term",), {"op": "jump"}), "E_HIA_FORMAT",
         "jump: " + fields + "args, op, target"),
        ("branch_fields", replace(BLOCK + ("term",), {"op": "branch"}), "E_HIA_FORMAT",
         "branch: " + fields + "cond, else, op, then"),
        ("trap_fields", replace(BLOCK + ("term",), {"op": "trap"}), "E_HIA_FORMAT", "trap: " + fields + "code, op"),
        ("branch_condition_identifier", replace(BLOCK + ("term", "cond"), "__hia_condition", branch),
         "E_HIA_NAME", "branch condition: " + name),
        ("unknown_trap", replace(BLOCK + ("term",), {"op": "trap", "code": "not_a_trap"}),
         "E_HIA_CFG", "unknown trap code"),
    ]
    jump = controls.program(blocks=[
        controls.block(term={"op": "jump", "target": "tail", "args": []}),
        controls.block("tail")])
    chain = controls.program(params=[("owner", "chain")])
    chain["schema"] = "hepta.hia.program.v6"
    groups["cfg"] = [
        ("missing_block", replace(BLOCK + ("term", "target"), "missing", jump), "E_HIA_CFG", "jump to missing block"),
        ("incoming_entry", replace(BLOCK + ("term", "target"), "entry", jump), "E_HIA_CFG",
         "entry cannot have incoming CFG edges; use a loop header"),
        ("edge_arity", replace(FN + ("blocks", 1, "params"), [{"name": "x", "type": "u32"}], jump),
         "E_HIA_CFG", "edge arity differs from block parameters"),
        ("unreachable_block", replace(FN + ("blocks",), [controls.block(), controls.block("unused")]),
         "E_HIA_CFG", "unreachable blocks are not admitted"),
        ("chain_version", chain, "E_HIA_TYPE", "recursive chain types require HIA program v7"),
    ]
    return groups


class CoreDeclarationDiagnosticNativeTests(controls._NativeFixture, unittest.TestCase):
    def retain(self, suffix, data):
        path = self.folder / (self._testMethodName + "." + suffix)
        with path.open("xb") as stream:
            stream.write(data)
        return {"path": str(path), "bytes": len(data), "sha256": sha256(data).hexdigest()}

    def compare_declaration(self, value, *, code, message, raw=None, label=None):
        raw = controls.wire(value) if raw is None else raw
        expected = controls.reference_error(raw)
        self.assertEqual(expected, (HIAProgramRejected, code, code + ": " + message),
                         "the unchanged independent reference must reach this complete intended refusal")
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
            "label": label,
            "input": self.retain("%03d.input.json" % ordinal, raw),
            "native_frame": self.retain("%03d.frame.bin" % ordinal, receipt.raw),
            "reference_message": self.retain("%03d.reference.utf8" % ordinal, expected[2].encode("utf-8")),
            "actual_message": self.retain("%03d.actual.utf8" % ordinal, str(found.exception).encode("utf-8")),
            "native_image_sha256": self.image_sha256, "native_status": receipt.status,
            "diagnostic_kind": receipt.diagnostic_kind, "expected_code": expected[1],
            "actual_code": found.exception.code, "actual_type": type(found.exception).__name__,
        })
        self.assertEqual((type(found.exception), found.exception.code, str(found.exception)), expected)
        self.assertTrue(receipt.native_executed)
        self.assertEqual(receipt.diagnostic_kind, DECLARATION_DIAGNOSTIC_KIND)
        self.assertEqual(receipt.message, message)
        self.assertEqual(receipt.raw[64:], message.encode("utf-8"))
        self.assertEqual(len(receipt.raw), 64 + len(message.encode("utf-8")))
        self.assertEqual(struct.unpack_from("<8Q", receipt.raw)[1:5],
                         (2, receipt.status, DECLARATION_DIAGNOSTIC_KIND, len(message.encode("utf-8"))))
        return receipt

    def check_groups(self, *wanted):
        groups = declaration_cases()
        all_rows = [row for rows in groups.values() for row in rows]
        self.assertEqual(len(all_rows), 66)
        self.assertEqual(len({row[0] for row in all_rows}), 66)
        for group in wanted:
            for label, value, code, message in groups[group]:
                with self.subTest(group=group, refusal=label):
                    self.compare_declaration(value, code=code, message=message, label=label)

    def test_complete_program_and_export_messages_match_original(self):
        self.check_groups("program")

    def test_complete_function_interface_and_parameter_messages_match_original(self):
        self.check_groups("interface", "parameters")

    def test_complete_block_instruction_and_reference_messages_match_original(self):
        self.check_groups("blocks", "references")

    def test_complete_terminator_and_cfg_messages_match_original(self):
        self.check_groups("terminators", "cfg")
        for value in ([], {}, {"op": None}, {"op": False}, {"op": 1}, {"op": []}):
            with self.subTest(nontext_terminator=value):
                self.compare_declaration(replace(BLOCK + ("term",), value),
                                         code="E_HIA_CFG", message="missing terminator")
        for effects in (None, [], [None], ["not_an_effect"], ["read", "read"]):
            if effects == []:
                continue
            with self.subTest(effects=effects):
                self.compare_declaration(replace(FN + ("effects",), effects),
                                         code="E_HIA_EFFECT", message="unknown/duplicate function effect")
        for origin in (None, 1, "missing", "owner"):
            value = controls.program(params=[("owner", "buffer")], returns=["readbuf"])
            value["functions"][0]["return_loans"] = [origin]
            with self.subTest(origin=origin):
                self.compare_declaration(value, code="E_HIA_LOAN",
                    message="borrowed result must name an input loan with sufficient permission")
        value = controls.program(params=[("view", "readbuf")], returns=["mutbuf"])
        value["functions"][0]["return_loans"] = ["view"]
        self.compare_declaration(value, code="E_HIA_LOAN",
            message="borrowed result must name an input loan with sufficient permission")

    def test_names_keep_full_original_domain_and_maximum_duplicate_spelling(self):
        name = "V" * 128
        for path, where, source in (
            (FN + ("params",), "function parameters", EMPTY),
            (BLOCK + ("params",), "block parameters", EMPTY),
            (INS + ("out",), "instruction outputs", ONE_INSTRUCTION),
        ):
            value = replace(path, [{"name": name, "type": "u32"}] * 2, source)
            message = where + ": duplicate parameter " + name
            self.compare_declaration(value, code="E_HIA_SSA", message=message)
            raw = controls.wire(value).replace(b'"' + name.encode() + b'"', b'"' + b"\\u0056" * 128 + b'"')
            self.compare_declaration(value, code="E_HIA_SSA", message=message, raw=raw)
        value = controls.program(params=[(name, "u32")], blocks=[controls.block(
            params=[(name, "u32")], ops=[controls.instruction("const", (), [(name, "u32")], value=1)])])
        self.compare_declaration(value, code="E_HIA_SSA", message="SSA value " + name + " is defined more than once")
        for bad in (None, False, 0, [], {}, "", "a" * 129, "\u00e9", "\U0001d11e",
                    "x\x00y", "x\n", "__hia_private"):
            for where, path in (("module", ("module",)), ("function", FN + ("name",)),
                                ("entry", FN + ("entry",)), ("block id", BLOCK + ("id",))):
                with self.subTest(where=where, name=bad):
                    self.compare_declaration(replace(path, bad), code="E_HIA_NAME",
                                             message=where + ": invalid/reserved ASCII identifier")

    def test_first_declaration_refusal_and_source_function_block_order_are_preserved(self):
        value = replace(("module",), "__hia_module")
        value["functions"] = []
        self.compare_declaration(value, code="E_HIA_NAME", message="module: invalid/reserved ASCII identifier")
        value = replace(INS + ("args",), ["__hia_argument"], ONE_INSTRUCTION)
        value["functions"][0]["blocks"][0]["ops"][0]["out"] = None
        value["functions"][0]["blocks"][0]["ops"][0]["attrs"] = []
        self.compare_declaration(value, code="E_HIA_NAME",
                                 message="instruction arguments: invalid/reserved ASCII identifier")
        value = replace(FN + ("name",), "source_first")
        value["functions"][0]["blocks"][0]["ops"] = [controls.instruction("not_an_opcode")]
        later = replace(FN + ("name",), "alphabetically_earlier")["functions"][0]
        later["params"] = None
        value["functions"].append(later)
        self.compare_declaration(value, code="E_HIA_FORMAT", message="function parameters: expected parameter list")
        first = controls.block("z_first", term={"op": "ret", "values": ["__hia_return"]})
        later = controls.block("a_later")
        later["ops"] = None
        value = controls.program(entry="z_first", blocks=[first, later])
        self.compare_declaration(value, code="E_HIA_NAME", message="return values: invalid/reserved ASCII identifier")
        value = controls.program(blocks=[
            controls.block(term={"op": "branch", "cond": "condition",
                "then": {"target": "then_missing", "args": ["__hia_then"]},
                "else": {"target": "__hia_else", "args": []}})])
        self.compare_declaration(value, code="E_HIA_NAME", message="edge arguments: invalid/reserved ASCII identifier")
        value = controls.program(blocks=[
            controls.block(term={"op": "branch", "cond": "condition",
                "then": {"target": "missing", "args": []},
                "else": {"target": "entry", "args": []}})])
        self.compare_declaration(value, code="E_HIA_CFG", message="jump to missing block")
        value = replace(FN + ("blocks",), [controls.block(), controls.block()])
        value["functions"].append(deepcopy(value["functions"][0]))
        self.compare_declaration(value, code="E_HIA_CFG", message="duplicate block")
        value = replace(FN + ("params",), [{"name": "x", "type": "u32"}, {"name": "x", "type": "not_a_type"}])
        self.compare_declaration(value, code="E_HIA_TYPE", message="type is outside the closed primitive profile")

    def test_maximum_wire_and_original_function_block_limits_keep_complete_messages(self):
        value = replace(("module",), "")
        raw = controls.wire(value)
        value["module"] = "a" * (MAX_BYTES - len(raw))
        raw = controls.wire(value)
        self.assertEqual(len(raw), MAX_BYTES)
        self.compare_declaration(value, raw=raw, code="E_HIA_NAME",
                                 message="module: invalid/reserved ASCII identifier")
        functions = []
        for index in range(1025):
            fn = deepcopy(EMPTY["functions"][0])
            fn["name"] = "f" + str(index)
            functions.append(fn)
        self.compare_declaration(replace(("functions",), functions), code="E_HIA_FORMAT",
                                 message="invalid function inventory")
        blocks = [controls.block("b" + str(index)) for index in range(4097)]
        self.compare_declaration(replace(FN + ("blocks",), blocks), code="E_HIA_CFG",
                                 message="invalid block inventory")

    def test_declaration_payload_and_tail_preserve_exact_publication_bounds(self):
        raw = controls.wire(replace(("module",), "__hia_bad"))
        expected = controls.reference_error(raw)
        payload = expected[2][len(expected[1]) + 2:].encode("utf-8")
        state_size, arena_size = scratch_sizes(len(raw))
        source = ctypes.create_string_buffer(raw, len(raw))
        state = ctypes.create_string_buffer(state_size + 16)
        arena = ctypes.create_string_buffer(arena_size + 16)
        ctypes.memset(ctypes.addressof(state), 0xa5, state_size + 16)
        ctypes.memset(ctypes.addressof(arena) + arena_size, 0x6b, 16)
        code = self.native._entry(source, len(raw), state, state_size, arena, arena_size)
        base = state_size - DIAGNOSTIC_BYTES
        header = state.raw[base:base + 64]
        self.assertEqual(struct.unpack("<8Q", header),
            (DIAGNOSTIC_MAGIC, 2, code, DECLARATION_DIAGNOSTIC_KIND, len(payload),
             base - BODY_DIAGNOSTIC_OFFSET, BODY_DIAGNOSTIC_OFFSET, 0))
        self.assertEqual(ERROR_CODES[code], expected[1])
        self.assertEqual(state.raw[BODY_DIAGNOSTIC_OFFSET:BODY_DIAGNOSTIC_OFFSET + len(payload)], payload)
        self.assertEqual(state.raw[base + 72:state_size], b"\xa5" * (DIAGNOSTIC_BYTES - 72))
        self.assertEqual(state.raw[state_size:], b"\xa5" * 16)
        self.assertEqual(arena.raw[arena_size:], b"\x6b" * 16)
        self.assertEqual(source.raw, raw)
        self.observations.append({"input": self.retain("bounds.input.json", raw),
                                  "actual_frame": self.retain("bounds.frame.bin", header + payload),
                                  "source_and_outer_canaries_preserved": True})
        state = ctypes.create_string_buffer(b"\x71" * state_size, state_size)
        arena = ctypes.create_string_buffer(b"\x39" * arena_size, arena_size)
        before = (state.raw, arena.raw)
        code = self.native._entry(source, len(raw), state, state_size - 1, arena, arena_size)
        self.assertEqual(code, 0xfffffffd)
        self.assertEqual((state.raw, arena.raw), before)
        self.assertEqual(source.raw, raw)
        # The original decoder permits some smaller scratch arenas when the
        # actual document fits.  Only its explicit 128-byte ABI minimum is
        # tested here; no new allocation threshold is invented.
        state = ctypes.create_string_buffer(b"\x71" * state_size, state_size)
        arena = ctypes.create_string_buffer(b"\x39" * arena_size, arena_size)
        code = self.native._entry(source, len(raw), state, state_size, arena, 127)
        self.assertEqual(code, 0xfffffffd)
        self.assertEqual(arena.raw, b"\x39" * arena_size)
        self.assertEqual(state.raw[:base], b"\x71" * base)
        self.assertEqual(state.raw[base + 64:], b"\x71" * 512)
        self.assertEqual(struct.unpack("<8Q", state.raw[base:base + 64]),
                         (DIAGNOSTIC_MAGIC, 1, 0xfffffffd, 0, 0, 512, 0, 0))
        self.assertEqual(source.raw, raw)

    def test_declaration_frame_corruption_cannot_authorize_partial_or_wrong_messages(self):
        raw = controls.wire(replace(("schema",), "unsupported"))
        original = self.native._entry
        state_size, _ = scratch_sizes(len(raw))
        capacity = state_size - DIAGNOSTIC_BYTES - BODY_DIAGNOSTIC_OFFSET
        for label, field, value in (
            ("magic", 0, 0), ("version", 8, 1), ("status", 16, 0), ("no_family", 24, 0),
            ("body_family_wrong_status", 24, 16), ("empty", 32, 0), ("overflow", 32, capacity + 1),
            ("capacity_small", 40, capacity - 1), ("capacity_large", 40, capacity + 1),
            ("pool", 48, 0), ("tail", 48, state_size - DIAGNOSTIC_BYTES), ("reserved", 56, 1),
        ):
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
                self.assertEqual(calls, [0xfffffff4])
        calls = []
        def corrupt_utf8(*args):
            returned = original(*args)
            ctypes.memmove(ctypes.addressof(args[2]) + BODY_DIAGNOSTIC_OFFSET, b"\xff", 1)
            calls.append(returned)
            return returned
        with patch.object(self.native, "_entry", corrupt_utf8):
            with self.assertRaises(RuntimeError):
                self.native.admit(raw)
        self.assertEqual(calls, [0xfffffff4])

    def test_selected_ordinary_verify_uses_complete_native_declaration_error(self):
        from tools.hia_agent_native_qualification import exhaustive_u8_workload
        value = replace(FN + ("name",), "__hia_invalid_function")
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
                      patch("hepta.hia_program._reference_primitive_structure",
                            side_effect=AssertionError("reference declarations called")),
                      patch("hepta.hia_program._verify_function",
                            side_effect=AssertionError("reference body called"))):
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
        self.assertTrue(all(receipt.native_executed and receipt.diagnostic_kind == DECLARATION_DIAGNOSTIC_KIND
                            and receipt.message == expected[2][len(expected[1]) + 2:] for receipt in calls))
        self.observations.append({"caller": "_hia_verify", "complete_error": response["error"],
                                  "native_calls": len(calls), "frames": [receipt.raw.hex() for receipt in calls]})
