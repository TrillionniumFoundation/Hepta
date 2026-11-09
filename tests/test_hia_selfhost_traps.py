"""Explicit terminal errors preserve verified codes, earlier writes and lifetimes."""
import unittest
from tools.hia_selfhost_traps import CODES, independent_reference
from hepta.hia_opcodes import TRAP_CODES


class SelfhostExplicitTrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = independent_reference()

    def test_all_core_trap_codes_and_prior_stores_are_observed_by_vm(self):
        self.assertEqual(set(CODES), TRAP_CODES)
        rows = self.reference["cases"]
        self.assertEqual(len(rows), 16)
        for code in CODES:
            for prior in (0, 1):
                row = next(r for r in rows if r["id"] == f"explicit-{code}-{prior}")
                self.assertEqual(row["reference_result"]["error"]["code"], code)
                self.assertEqual(row["reference_output_hex"], ("4d" if prior else "a5") + "a5" * 7)
        self.assertFalse(self.reference["all_input_correctness_proved"])
        self.assertFalse(self.reference["native_trap_code_word_returned"])

    def test_branch_choice_callees_and_live_owners_do_not_forge_normal_return(self):
        rows = {r["id"]: r for r in self.reference["cases"]}
        self.assertEqual(rows["explicit-branch-0"]["reference_result"]["values"], [7])
        for value in (1, 255):
            self.assertEqual(rows[f"explicit-branch-{value}"]["reference_result"]["error"]["code"], "user")
        live = rows["explicit-live-owner-and-loan"]["reference_result"]
        self.assertEqual(live["resources"]["live_owners"], 1)
        self.assertEqual(live["resources"]["live_local_loans"], 1)
        self.assertEqual(rows["explicit-scalar-callee"]["reference_result"]["error"]["code"], "bounds")
        self.assertEqual(rows["explicit-void-callee"]["reference_result"]["error"]["code"], "overflow")

    def test_malformed_terminators_and_missing_trap_effect_stay_rejected(self):
        self.assertEqual(len(self.reference["refusals"]), 6)
        self.assertTrue(all(r["reference_result"]["status"] == "rejected" for r in self.reference["refusals"]))


if __name__ == "__main__":
    unittest.main()
