"""Fail-closed admission controls for the mathematical prefix proof tool."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from tools import qualify_hia_initialization_prefix as proof


class InitializationPrefixFormalInputTests(unittest.TestCase):
    def test_bad_schedules_mutate_the_actual_definition_and_early_exit_claim(self):
        source = proof.MODEL.read_text()
        mutants = proof.negative_sources(source)
        self.assertEqual(set(mutants), {"starts_at_one", "stride_two", "early_exit_claim"})
        self.assertIn("(count + 1) (values count)", mutants["starts_at_one"])
        self.assertIn("(count * 2) (values count)", mutants["stride_two"])
        self.assertIn("fillPrefix empty (fun _ => BitVec.ofNat 8 0) 2 2", mutants["early_exit_claim"])
        for mutant in mutants.values():
            self.assertNotEqual(source, mutant)

    def test_missing_or_ambiguous_mutation_point_refuses(self):
        source = proof.MODEL.read_text()
        for changed in ("", source + source):
            with self.subTest(changed=len(changed)), self.assertRaisesRegex(ValueError, "mutation point"):
                proof.negative_sources(changed)

    def test_incomplete_or_placeholder_theorem_inventory_refuses(self):
        valid_shape = "\n".join("'HiaInitializationPrefix." + name + "' does not depend on any axioms"
                                for name in sorted(proof.THEOREMS))
        self.assertEqual(set(proof.theorem_dependencies(valid_shape)), proof.THEOREMS)
        for changed in (valid_shape.split("\n", 1)[1], valid_shape + "\nerror: placeholder proof",
                        valid_shape + "\nsorryAx"):
            with self.subTest(changed=changed[-40:]), self.assertRaises(ValueError):
                proof.theorem_dependencies(changed)

    def test_unpinned_fake_checker_is_rejected_before_execution_or_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            executable = root / "lean"
            marker = root / "executed"
            executable.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n")
            executable.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "pinned Lean binary"):
                proof.qualify(executable, root / "output")
            self.assertFalse(marker.exists())
            self.assertFalse((root / "output").exists())


if __name__ == "__main__":
    unittest.main()
