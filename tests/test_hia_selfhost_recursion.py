"""Original-source and independent VM controls for native recursive frames."""
from __future__ import annotations
import unittest
from tools.hia_selfhost_recursion import independent_reference, former_refusals, full_frame_source

class SelfhostRecursionSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = independent_reference()

    def test_every_original_recursive_refusal_is_retained_with_its_source_identity(self):
        from hashlib import sha256
        originals = {row["id"]: row for row in former_refusals()}
        self.assertEqual(len(originals), 10)
        for row in self.reference["former_refusals"]:
            self.assertEqual(row["source_sha256"], sha256(originals[row["id"]]["source"]).hexdigest())
            self.assertEqual(row["native_profile_expected"], "compiled")
        by_name = {row["id"]: row for row in self.reference["cases"]}
        for name in ("recursion-non-tail-direct-recursion", "recursion-mutual-recursion"):
            self.assertEqual(by_name[name]["reference_result"]["status"], "budget_exceeded")
            self.assertEqual(by_name[name]["reference_result"]["error"]["code"], "calls")
        self.assertEqual(by_name["recursion-unreachable-cycle"]["reference_result"]["result"], 7)
        for name in ("tail-returned-other-value", "tail-instruction-after-call", "tail-edge-after-call"):
            self.assertEqual(by_name[name]["reference_result"]["status"], "returned")

    def test_depth_boundaries_preserve_vm_calls_and_expose_native_byte_budget(self):
        rows = {row["id"]: row for row in self.reference["cases"]}
        self.assertEqual(len(rows), 20)
        for prefix in ("mutual-finite-", "non-tail-finite-"):
            self.assertEqual(rows[prefix + "254"]["reference_result"]["status"], "returned")
            self.assertFalse(rows[prefix + "254"]["native_budget_trap"])
            self.assertEqual(rows[prefix + "255"]["reference_result"]["status"], "budget_exceeded")
            self.assertTrue(rows[prefix + "255"]["native_budget_trap"])
        self.assertEqual(rows["full-frame-188"]["reference_result"]["status"], "returned")
        self.assertTrue(rows["full-frame-188"]["native_budget_trap"])
        self.assertFalse(self.reference["exception_reports_equal"])
        self.assertFalse(self.reference["unbounded_recursion_claimed"])

    def test_stack_witness_has_all_2048_slots_and_exact_charged_boundary(self):
        from hepta.hia_agent_assembly import assemble_program
        from tools.hia_selfhost_limits import MAX_CALL_DEPTH, MAX_CALL_STACK_BYTES
        doc = assemble_program(full_frame_source(187)).as_dict()
        helper = doc["functions"][1]
        names = {p["name"] for block in helper["blocks"]
            for p in [*block["params"], *[out for op in block["ops"] for out in op["out"]]]}
        self.assertEqual(len(names), 2048)
        self.assertEqual(MAX_CALL_DEPTH, 256)
        self.assertEqual(MAX_CALL_STACK_BYTES, 6 << 20)
        self.assertLessEqual(752 + 188 * 33440, MAX_CALL_STACK_BYTES)
        self.assertGreater(752 + 189 * 33440, MAX_CALL_STACK_BYTES)

if __name__ == "__main__":
    unittest.main()
