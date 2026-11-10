"""Captured application bridge and full-input guarded CRC transformations."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
import zlib

from hepta.hia_crc_kernel import POLYNOMIALS, candidates, kernel, source_wrapper, step, validate_source_bridge
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_translation_validation import validate_translation


class CRCKernelTests(unittest.TestCase):
    def test_known_vectors_and_canonical_vm(self):
        for polynomial, expected in zip(POLYNOMIALS, (0xCBF43926, 0xE3069283)):
            for label, program in candidates().items():
                state = 0xFFFFFFFF
                for byte in b"123456789":
                    oracle = step(state ^ byte, polynomial)
                    state = execute_program(program, "calculate", [state ^ byte, polynomial])["result"]
                    self.assertEqual(state, oracle, label)
                self.assertEqual(state ^ 0xFFFFFFFF, expected, label)
        payload = bytes(range(256))
        state = 0xFFFFFFFF
        for byte in payload:
            state = step(state ^ byte, POLYNOMIALS[0])
        self.assertEqual(state ^ 0xFFFFFFFF, zlib.crc32(payload))

    def test_every_candidate_reproves_arbitrary_polynomial_generic_fallback(self):
        for label, program in candidates().items():
            result = validate_translation(kernel(), program, function="calculate", timeout_ms=10000)
            self.assertEqual(result["status"], "proved", (label, result))
            for state in (0, 1, 0xFFFFFFFF, 0x80000000):
                for polynomial in (*POLYNOMIALS, 0, 1, 0xFFFFFFFF, 0x12345678):
                    self.assertEqual(execute_program(program, "calculate", [state, polynomial])["result"],
                                     step(state, polynomial))

    def test_removed_guard_is_rejected_by_all_input_proof(self):
        changed = candidates()["ieee_guard"]
        condition = changed["functions"][0]["blocks"][0]["ops"][-1]
        condition.update(op="const", args=[], attrs={"value": True})
        verify_program(changed)
        self.assertEqual(validate_translation(kernel(), changed, function="calculate", timeout_ms=10000)["status"], "disproved")

    def test_oracle_rejects_non_u32(self):
        for bad in (True, -1, 2**32, 1.5):
            with self.assertRaises(ValueError): step(bad, 1)
            with self.assertRaises(ValueError): step(1, bad)



if __name__ == "__main__":
    unittest.main()
