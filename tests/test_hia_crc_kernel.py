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
from hepta.hia_program_source import lower_c_multi_owner
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

    @unittest.skipUnless(os.environ.get("CLANG") or shutil.which("clang"), "actual Clang required")
    def test_real_c_capture_bound_and_all_input_bridge_and_mutation(self):
        fixture = Path(__file__).resolve().parents[1] / "examples/hia_filecheck"
        with tempfile.TemporaryDirectory(prefix="hia-crc-source-") as temporary:
            database = Path(temporary) / "compile_commands.json"
            database.write_text(json.dumps([{"directory": str(fixture), "file": name,
                "arguments": ["clang", "-std=c11", "-I.", "-c", name, "-o", name + ".o"]}
                for name in ("checksum.c", "chunk.c")]))
            source = lower_c_multi_owner(database, clang=os.environ.get("CLANG", "clang"))["program"]
            receipt = validate_source_bridge(source)
            self.assertEqual(receipt["status"], "proved", receipt)
            self.assertTrue(receipt["claims"]["all_input_bound_proved"])
            self.assertFalse(receipt["claims"]["frontend_refinement_proved"])
            self.assertEqual(receipt["kernel_sha256"], verify_program(kernel()).sha256)
            bad_kernel = kernel()
            bad_kernel["functions"][0]["blocks"][0]["ops"][0]["attrs"]["value"] = 2
            self.assertEqual(validate_source_bridge(source, kernel_document=bad_kernel)["status"], "disproved")
            wrapper = source_wrapper(source)
            for byte in (0, 1, 127, 255):
                args = [0xF1234567, byte, POLYNOMIALS[0]]
                self.assertEqual(execute_program(wrapper, "c_checksum_byte", args)["result"], step(args[0] ^ byte, args[2]))
            mutated = source.as_dict()
            checksum = next(f for f in mutated["functions"] if f["name"] == "c_checksum_byte")
            for block in checksum["blocks"]:
                for op in block["ops"]:
                    if op["op"] == "const" and op["attrs"]["value"] == 8:
                        op["attrs"]["value"] = 9
            self.assertEqual(validate_source_bridge(mutated)["status"], "disproved")


if __name__ == "__main__":
    unittest.main()
