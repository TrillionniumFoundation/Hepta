"""Valid-Core and lifetime controls for the finite bootstrap feature matrix."""
from copy import deepcopy
import unittest

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program import HIAProgramRejected
from tools.hia_selfhost_feature_matrix import cases, reference


class SelfhostFeatureMatrixTests(unittest.TestCase):
    def test_every_witness_keeps_the_real_entry_and_runs_the_unmodified_core(self):
        rows = cases()
        self.assertEqual(len({row["id"] for row in rows}), 9)
        for row in rows:
            with self.subTest(row=row["id"]):
                admitted = assemble_program(row["source"])
                observed = reference(row)
                self.assertEqual(observed["core_sha256"], admitted.sha256)
                self.assertEqual(observed["entry_types"], ["readbuf", "mutbuf", "mutbuf"])
                self.assertEqual(observed["execution"]["result"], row["expected_result"])
                self.assertTrue(all(observed["execution"]["external_bytes_unchanged"]))

    def test_unsupported_cases_are_valid_core_and_isolate_the_declared_feature(self):
        rows = {row["id"]: row for row in cases()}
        self.assertEqual({name for name, row in rows.items() if row["expected_compiler_acceptance"]},
            {"unsigned-call-cfg", "owned-argument-scalar-return"})
        for name, row in rows.items():
            admitted = assemble_program(row["source"]).as_dict()
            if name != "named-module-preserved-entry":
                self.assertIn(admitted["module"], {"selfhost", "selfhost_elf"})
            if name.startswith("named-helper") or name.startswith("named-pair"):
                self.assertEqual(admitted["functions"][1]["name"], "combine")
            elif not name.startswith("named-module"):
                self.assertEqual(admitted["functions"][1]["name"], "f1")
        signed = assemble_program(rows["signed-helper-preserved-entry"]["source"]).as_dict()
        self.assertEqual(signed["functions"][0]["returns"], ["u32"])
        self.assertEqual(signed["functions"][1]["returns"], ["i32"])
        pair = assemble_program(rows["scalar-pair-helper-preserved-entry"]["source"]).as_dict()
        self.assertEqual(pair["functions"][1]["returns"], ["u32", "u32"])

    def test_returned_loan_witness_does_not_hide_an_unclosed_parent(self):
        row = next(deepcopy(row) for row in cases() if row["id"].startswith("returned-loan"))
        row["source"] = row["source"].replace("  _ = loan.end(v3)\n", "")
        with self.assertRaises(HIAProgramRejected):
            reference(row)


if __name__ == "__main__":
    unittest.main()
