"""Real unchanged stb capture, all-input proposals and tiny native delivery."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.hia_finite_context import build_bank
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_stb_specialization import LABELS, candidates, capture, edge_cases, oracle
from hepta.hia_translation_validation import validate_translation


def observation(program, args):
    try:
        return {"status": "returned", "values": execute_program(program, "calculate", args, max_steps=1000)["values"]}
    except HIAProgramTrap as error:
        return {"status": "trapped", "code": error.code}


class StbOracleTests(unittest.TestCase):
    def test_unsigned_bit_pattern_inputs_map_to_signed_euclidean_math(self):
        self.assertEqual(oracle(0xFFFFFFFF, 8), 7)
        self.assertEqual(oracle(0xFFFFFFF7, 10), 1)
        self.assertEqual(oracle(0x80000000, 0x80000000), 0)
        self.assertEqual(oracle(0x80000000, 0xFFFFFFFF), {"status": "trapped", "code": "overflow"})
        self.assertEqual(oracle(0, 0), {"status": "trapped", "code": "division_by_zero"})
        for value in (True, -1, 2**32, 1.5):
            with self.assertRaises(ValueError): oracle(value, 8)
            with self.assertRaises(ValueError): oracle(1, value)
        self.assertEqual(len(edge_cases()), 64)
        self.assertEqual(len({tuple(x) for x in edge_cases()}), 64)


@unittest.skipUnless(os.environ.get("CLANG") or shutil.which("clang"), "actual Clang20+ required")
class StbCapturedNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-stb-native-")
        cls.root = Path(cls.temporary.name)
        cls.clang = os.environ.get("CLANG", "clang")
        cls.base, cls.capture_receipt = capture(cls.root / "capture", clang=cls.clang)
        cls.bank = candidates(cls.base)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_exact_captured_closure_is_proved_without_modifying_upstream(self):
        receipt = self.capture_receipt
        self.assertTrue(receipt["complete_component_capture"])
        self.assertEqual(receipt["upstream"]["source_modifications"], [])
        proof = receipt["adapter"]["call_closure_bridge"]
        self.assertEqual(proof["status"], "proved")
        self.assertEqual(len(proof["call_closures"][0]), 3)
        self.assertEqual(proof["call_closures"][1], ["calculate"])
        self.assertFalse(receipt["adapter"]["source_C_equivalence_proved"])

    def test_all_candidates_keep_the_existing_structural_budget_and_all_input_gate(self):
        self.assertEqual(tuple(self.bank), LABELS)
        self.assertEqual([len(v["functions"][0]["blocks"]) for v in self.bank.values()], [8, 17, 17, 26])
        for label, program in self.bank.items():
            with self.subTest(label=label):
                self.assertEqual(validate_translation(self.base, program, function="calculate", timeout_ms=10000)["status"], "proved")
                for args in edge_cases():
                    expected = oracle(*args)
                    if type(expected) is int:
                        expected = {"status": "returned", "values": [expected]}
                    self.assertEqual(observation(program, args), expected)

    def test_removed_runtime_guard_is_not_a_trusted_input_assumption(self):
        wrong = copy.deepcopy(self.bank["guard_8"])
        guard = wrong["functions"][0]["blocks"][0]["ops"][-1]
        guard.update(op="const", args=[], attrs={"value": True})
        verify_program(wrong)
        self.assertEqual(validate_translation(self.base, wrong, function="calculate", timeout_ms=10000)["status"], "disproved")

    def test_actual_native_bank_keeps_full_width_map_and_repeat_counts(self):
        folder = self.root / "bank"
        folder.mkdir()
        report = {}
        bank = build_bank(self.base, self.bank, folder, clang=self.clang, cases=edge_cases(), oracle=oracle,
                          report=report, reuse_oracle=True, allow_map_repeat=True)
        try:
            values = [0, 1, 7, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
            for index, label in enumerate(LABELS):
                trace = bank.prepare_trace([{"id": index, "candidate": label, "seed": 0,
                    "mode": "map_repeat", "parameter": 8 if index % 2 else 10,
                    "values": values, "repetitions": 5}])
                row = bank.run(trace)
                self.assertEqual(row["status"], "completed")
                result = row["prefix"]["completed_requests"][0]
                self.assertEqual(result["calls"], 30)
                self.assertEqual(result["repetitions"], 5)
                self.assertGreater(result["kernel_ns"], 0)
                with self.assertRaises(ValueError): bank.run(trace)
            self.assertEqual(len({r["code"]["sha256"] for r in report["candidates"].values()}), 4)
        finally:
            self.assertTrue(bank.close()["complete"])


if __name__ == "__main__":
    unittest.main()
