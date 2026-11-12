"""Actual Core export, retained proof attacks, and optional local kernel runner.

The standalone qualification command requires Lean and never skips. Unit tests
without a toolchain exercise only input boundaries and make no theorem claim.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest

from hepta.hia_program import HIAProgramRejected
from tools import qualify_hia_register_safety as safety


class RegisterSafetyInputTests(unittest.TestCase):
    def setUp(self):
        self.core = json.loads(safety.SELECTED.read_bytes())

    def test_actual_instructions_and_distinct_before_after_are_exported(self):
        source, candidate, generated, mapping = safety.export_pair(self.core)
        self.assertNotEqual(source.sha256, candidate.sha256)
        self.assertEqual(len(mapping["source"]["instructions"]), 5)
        self.assertEqual(len(mapping["candidate"]["instructions"]), 4)
        self.assertIn(".literal (BitVec.ofNat 32 99)", generated)
        self.assertIn("sourceProgram = appendDeadLiteral candidateProgram", generated)
        self.assertEqual(mapping["source"]["result_register"], mapping["candidate"]["result_register"])

    def test_used_last_literal_or_invalid_forward_reference_cannot_inherit_safety(self):
        changed = deepcopy(self.core)
        changed["functions"][0]["blocks"][0]["term"]["values"] = ["unused"]
        with self.assertRaisesRegex(ValueError, "actually unused"):
            safety.export_pair(changed)
        changed = deepcopy(self.core)
        changed["functions"][0]["blocks"][0]["ops"][0]["args"][0] = "unused"
        with self.assertRaises(HIAProgramRejected):
            safety.export_pair(changed)

    def test_three_negative_controls_reach_their_intended_definition_or_actual_core(self):
        positive = safety.export_pair(self.core)
        mutants = safety.mutation_inputs(self.core)
        self.assertEqual(set(mutants), set(safety.MUTATIONS))
        for name, (source, candidate, generated, _) in mutants.items():
            self.assertEqual(source.sha256, positive[0].sha256)
            self.assertNotEqual(generated, positive[2])
            self.assertEqual(candidate.sha256 == positive[1].sha256,
                             name != "actual_candidate_add_becomes_sub")

    def test_unpinned_executable_is_rejected_before_any_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            fake = Path(temp) / "lean"
            fake.write_text("#!/bin/sh\ntouch should-never-exist\n")
            fake.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "pinned binary"):
                safety.qualify(fake, Path(temp) / "evidence")
            self.assertFalse((Path(temp) / "evidence").exists())


@unittest.skipUnless(os.environ.get("LEAN"), "run standalone qualification with pinned --lean for theorem evidence")
class RegisterSafetyKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="hepta-register-proof-")
        cls.output = Path(cls.temp.name) / "evidence"
        cls.report = safety.qualify(os.environ["LEAN"], cls.output)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_real_kernel_checks_generic_theorems_actual_rewrite_and_all_controls(self):
        self.assertTrue(self.report["ok"])
        self.assertEqual(set(self.report["theorems"]), safety.THEOREMS)
        self.assertEqual(len(self.report["negative_controls"]), 3)
        self.assertEqual(len(self.report["vm_cases"]), 272)
        self.assertFalse(self.report["claims"]["exporter_or_python_verifier_refinement_proved"])

    def test_retained_scope_inventory_and_numeric_substitutions_are_rejected(self):
        for mutate in (
            lambda r: r["negative_controls"].pop(),
            lambda r: r["claims"].update(whole_language_soundness_proved=True),
            lambda r: r["claims"].update(exact_register_growth_proved=1),
            lambda r: r["positive"].update(returncode=False),
            lambda r: r["vm_cases"].pop(),
            lambda r: r.update(candidate_core_sha256="0" * 64),
        ):
            changed = deepcopy(self.report)
            mutate(changed)
            with self.assertRaises(ValueError):
                safety.validate_report(changed, self.output)


if __name__ == "__main__":
    unittest.main()
