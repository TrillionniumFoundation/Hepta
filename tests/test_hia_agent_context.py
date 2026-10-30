"""Focused information never substitutes for whole-module patch admission."""
from copy import deepcopy
from hashlib import sha256
import unittest

from hepta.hia_agent_context import focused_context, measure_payloads
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_opcodes import opcode_catalog
from hepta.hia_program import verify_program
from hepta.hia_program_tools import MAX_INPUT_BYTES, apply_program_patch, bounded_json_wire
from tools.qualify_hia_agent_maintenance import TASK_MODULE


class FocusedContextTests(unittest.TestCase):
    def test_selected_definitions_are_complete_and_patch_compatible(self):
        source = TASK_MODULE.source("wrapped_stride")
        view = focused_context(source, ["stride"])
        self.assertEqual(view["functions"], [source["functions"][1]])
        self.assertEqual(view["snapshot_sha256"], verify_program(source).sha256)
        self.assertEqual(view["incoming_calls"], [{"caller": "target", "callee": "stride", "block": "entry", "index": 0}])
        self.assertEqual(view["omitted_body_count"], 25)
        self.assertFalse(view["claims"]["complete_behavioral_dependencies"])
        request = TASK_MODULE.author_patch("wrapped_stride", view["snapshot_sha256"])
        changed, receipt = apply_program_patch(source, request)
        self.assertTrue(receipt["claims"]["whole_module_rechecked"])
        with self.assertRaisesRegex(ValueError, "stale"):
            apply_program_patch(changed, request)

    def test_omitted_invalid_body_is_checked_even_when_view_would_not_send_it(self):
        source = TASK_MODULE.source("wrapped_stride")
        source["functions"][-1]["blocks"][0]["term"]["values"] = ["undefined"]
        with self.assertRaisesRegex(ValueError, "undefined|nonlocal"):
            focused_context(source, ["stride"])

    def test_v8_direct_callee_contract_preserves_formal_loan_origin(self):
        source = TASK_MODULE.source("returned_view_byte")
        view = focused_context(source, ["target"])
        helper = next(row for row in view["boundary_interfaces"] if row["name"] == "store_then_view")
        self.assertEqual(helper["return_loans"], ["writer"])
        self.assertEqual(helper["returns"], ["readbuf"])
        self.assertEqual(helper["params"][0], {"name": "writer", "type": "mutbuf"})
        self.assertEqual(helper["effects"], ["write", "trap"])

    def test_slice_has_own_identity_and_explicit_missing_instructions(self):
        source = TASK_MODULE.source("wrapped_stride")
        view = focused_context(source, ["stride"])
        sliced = view["opcode_slice"]
        complete = opcode_catalog(source["schema"])
        self.assertFalse(sliced["complete_catalog"])
        self.assertNotEqual(sliced["schema"], complete["schema"])
        self.assertEqual(sliced["complete_catalog_sha256"], complete["catalog_sha256"])
        self.assertNotIn("int.mul.wrap", {row["name"] for row in sliced["instructions"]})
        extended = focused_context(source, ["stride"], extra_opcodes=["int.mul.wrap"])
        self.assertIn("int.mul.wrap", {row["name"] for row in extended["opcode_slice"]["instructions"]})
        self.assertNotEqual(view["context_sha256"], extended["context_sha256"])
        self.assertEqual(view["snapshot_sha256"], extended["snapshot_sha256"])

    def test_unknown_duplicate_unbounded_and_wrong_typed_queries_reject(self):
        source = TASK_MODULE.source("wrapped_stride")
        for names in ([], ["missing"], ["stride", "stride"], [False], "stride", [str(i) for i in range(33)]):
            with self.subTest(names=names), self.assertRaises(ValueError):
                focused_context(source, names)
        for extra in (["invented.operation"], [False], ["const", "const"]):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                focused_context(source, ["stride"], extra_opcodes=extra)

    def test_view_is_detached_and_order_deterministic(self):
        source = TASK_MODULE.source("wrapped_stride")
        original = deepcopy(source)
        first = focused_context(source, ["target", "stride"])
        second = focused_context(source, ["stride", "target"])
        self.assertEqual(first, second)
        first["functions"][0]["blocks"][0]["ops"][0]["attrs"]["value"] = 999
        self.assertEqual(source, original)

    def test_payload_measurement_is_exact_wire_size_not_token_estimate(self):
        source = TASK_MODULE.source("wrapped_stride")
        view = focused_context(source, ["stride"])
        measurement = measure_payloads(source, ["stride"])
        wire = lambda value: bounded_json_wire(value, MAX_INPUT_BYTES, ensure_ascii=False)
        full = wire({"program": source, "opcode_catalog": opcode_catalog(source["schema"])})
        self.assertEqual(measurement["bytes"]["focused_json_with_opcode_slice"], len(wire(view)))
        self.assertEqual(measurement["bytes"]["complete_json_with_catalog"], len(full))
        self.assertEqual(measurement["bytes"]["assembly_source"], len(render_assembly(source).encode()))
        self.assertEqual(measurement["envelope_sha256"]["complete_json"], sha256(full).hexdigest())
        self.assertEqual(measurement["model_requests"], 0)
        self.assertIsNone(measurement["model_tokens"])
        self.assertFalse(measurement["claims"]["model_efficiency_improvement"])

    def test_snapshot_view_is_not_a_standalone_program_or_admission_receipt(self):
        view = focused_context(TASK_MODULE.source("wrapped_stride"), ["stride"])
        with self.assertRaises(ValueError):
            verify_program(view)
        changed = TASK_MODULE.source("wrapped_stride")
        changed["functions"][-1]["blocks"][0]["ops"][0]["attrs"]["value"] += 2
        self.assertNotEqual(focused_context(changed, ["stride"])["snapshot_sha256"], view["snapshot_sha256"])


if __name__ == "__main__":
    unittest.main()
