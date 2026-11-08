"""Instruction-boundary and real supplied-byte checks for the CMOVNE leaf."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hepta.hia_safe_core_x64 import decode, SafeCoreMachineRejected
from tools.qualify_hia_safe_core_cmovne import ROOT, cases, decoder_refusals, qualify_decoder


class CmovneLeafTests(unittest.TestCase):
    def test_all_register_fields_include_rex_extensions_and_aliases(self):
        report = qualify_decoder()
        self.assertEqual(len(report["register_combinations"]), 256)
        self.assertEqual(len({(row["destination"], row["source"])
                              for row in report["register_combinations"]}), 256)

    def test_unreviewed_forms_fail_even_when_unreachable(self):
        for name, encoded in decoder_refusals().items():
            with self.subTest(name=name), self.assertRaises(SafeCoreMachineRejected):
                decode(bytes.fromhex(encoded))

    def test_branch_cannot_enter_a_cmov_operand(self):
        # A valid CMOVNE ends at offset 4; the following JNE targets byte 3.
        with self.assertRaisesRegex(SafeCoreMachineRejected, "instruction boundary"):
            decode(bytes.fromhex("480f45c10f85f9ffffffc3"))

    def test_actual_subject_proofs_refutations_and_native_witnesses(self):
        with tempfile.TemporaryDirectory(prefix="hia-cmovne-test-") as temporary:
            output = Path(temporary) / "qualification"
            process = subprocess.run([sys.executable, "-B", str(ROOT / "tools/qualify_hia_safe_core_cmovne.py"),
                                      "--output", str(output)], cwd=ROOT, text=True, capture_output=True,
                                     timeout=200, check=False)
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            report = json.loads((output / "qualification.json").read_text())
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["counts"], {"smt_validated": 13, "refuted": 6, "unsupported": 3,
                "native_calls": 492, "decoded_register_combinations": 256, "decoder_refusals": 17})
            self.assertEqual(len(report["cases"]), len(cases()))
            self.assertFalse(report["whole_compiler_or_original_agent_delta_proved"])
            self.assertEqual(report["original_agent_four_claim_gate"], "HOLD")
            for row in report["cases"]:
                proof = json.loads((output / row["id"] / "validation.json").read_text())
                if row["expected"] == "smt_validated":
                    self.assertEqual([ob["result"] for ob in proof["obligations"]],
                                     ["sat", "unsat", "unsat", "unsat", "unsat"])
                    self.assertTrue(all(key in proof for key in
                                        ("subject", "property", "profile", "assumptions", "checker", "unproved_obligations")))
                elif row["expected"] == "refuted":
                    self.assertFalse(proof["validation"]["ok"])
                    self.assertEqual(proof["validation"]["obligations"][-1]["result"], "sat")
                else:
                    self.assertFalse(proof["proof_issued"])


if __name__ == "__main__":
    unittest.main()
