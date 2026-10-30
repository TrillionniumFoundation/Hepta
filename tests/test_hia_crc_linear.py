"""All-input and fault controls for the separate CRC linear proposal lane."""
from __future__ import annotations

import copy
import unittest

from hepta.hia_crc_kernel import (POLYNOMIALS, candidates as legacy_candidates,
                                  kernel, step)
from hepta.hia_crc_linear import LABELS, basis, candidates
from hepta.hia_finite_context import checked_profile
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import emit_program_llvm
from hepta.hia_program_runtime import execute_program
from hepta.hia_scalar_lowering_check import MAX_OPERATIONS, verify_scalar_lowering
from hepta.hia_translation_validation import validate_translation


class CRCLinearTests(unittest.TestCase):
    def test_basis_uses_all_eight_steps_and_unsigned_boundaries(self):
        for polynomial in (*POLYNOMIALS, 0, 1, 0x80000000, 0xFFFFFFFF):
            self.assertEqual(basis(polynomial), tuple(step(1 << i, polynomial) for i in range(8)))
        self.assertEqual(basis(POLYNOMIALS[0]), (0x77073096, 0xEE0E612C, 0x076DC419,
            0x0EDB8832, 0x1DB71064, 0x3B6E20C8, 0x76DC4190, 0xEDB88320))
        for bad in (True, -1, 2**32, 1.0, "1"):
            with self.assertRaises(ValueError):
                basis(bad)

    def test_all_six_candidates_preserve_legacy_pool_and_existing_bounds(self):
        pool = candidates()
        self.assertEqual(tuple(pool), LABELS)
        for name, old in legacy_candidates().items():
            self.assertEqual(pool[name], old)
        for document in pool.values():
            checked_profile(document)
        self.assertEqual(pool, candidates())

    def test_fresh_all_u32_value_and_first_trap_translation(self):
        for name, document in candidates().items():
            receipt = validate_translation(kernel(), document, function="calculate", timeout_ms=10000)
            self.assertEqual(receipt["status"], "proved", (name, receipt.get("reason")))
            self.assertTrue(receipt["claims"]["all_input_behavior_equivalence_proved"])
            self.assertTrue(receipt["claims"]["first_trap_code_preserved"])

    def test_every_actual_llvm_body_respects_unchanged_128_operation_gate(self):
        self.assertEqual(MAX_OPERATIONS, 128)
        for name, document in candidates().items():
            count = sum(len(b["ops"]) for b in document["functions"][0]["blocks"])
            self.assertLessEqual(count, MAX_OPERATIONS, name)
            emitted = emit_program_llvm(verify_program(document))
            receipt = verify_scalar_lowering(document, function="calculate", llvm_text=emitted.text,
                                             timeout_ms=10000)
            self.assertEqual(receipt["status"], "verified", name)
            self.assertEqual(receipt["llvm_sha256"], emitted.sha256)

    def test_guarded_and_arbitrary_fallback_values_and_known_crc(self):
        states = (0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x80000000, 0xFFFFFFFF)
        polynomials = (*POLYNOMIALS, 0, 1, 0xFFFFFFFF, 0x80000000, 0x12345678)
        for name, document in candidates().items():
            for state in states:
                for polynomial in polynomials:
                    result = execute_program(document, "calculate", [state, polynomial])
                    self.assertEqual(result["result"], step(state, polynomial), name)
            for polynomial, expected in zip(POLYNOMIALS, (0xCBF43926, 0xE3069283)):
                state = 0xFFFFFFFF
                for byte in b"123456789":
                    state = execute_program(document, "calculate", [state ^ byte, polynomial])["result"]
                self.assertEqual(state ^ 0xFFFFFFFF, expected, name)

    def test_wrong_basis_constant_is_disproved(self):
        changed = candidates()["linear_ieee"]
        block = next(b for b in changed["functions"][0]["blocks"] if b["id"].startswith("crc_linear"))
        operation = next(op for op in block["ops"] if "_basis_0_" in op["out"][0]["name"])
        operation["attrs"]["value"] ^= 1
        verify_program(changed)
        receipt = validate_translation(kernel(), changed, function="calculate", timeout_ms=10000)
        self.assertEqual(receipt["status"], "disproved", receipt.get("reason"))
        self.assertIsNotNone(receipt["counterexample"])

    def test_erased_guard_cannot_claim_arbitrary_polynomial_equivalence(self):
        changed = candidates()["linear_dual"]
        entry = changed["functions"][0]["blocks"][0]
        condition = next(op for op in entry["ops"] if op["out"][0]["name"] == entry["term"]["cond"])
        condition.update(op="const", args=[], attrs={"value": True})
        verify_program(changed)
        receipt = validate_translation(kernel(), changed, function="calculate", timeout_ms=10000)
        self.assertEqual(receipt["status"], "disproved", receipt.get("reason"))

    def test_bad_shift_preserves_no_false_first_trap_qualification(self):
        changed = copy.deepcopy(candidates()["linear_castagnoli"])
        block = next(b for b in changed["functions"][0]["blocks"] if b["id"].startswith("crc_linear"))
        operation = next(op for op in block["ops"] if "_eight_" in op["out"][0]["name"])
        operation["attrs"]["value"] = 32
        verify_program(changed)
        receipt = validate_translation(kernel(), changed, function="calculate", timeout_ms=10000)
        self.assertEqual(receipt["status"], "disproved", receipt.get("reason"))


if __name__ == "__main__":
    unittest.main()
