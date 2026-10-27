"""Fresh bounded C++ ownership implementation -> standalone HIA -> native."""
from copy import deepcopy
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from tools.qualify_hia_migration import qualify_cpp_owned_to_hia, validate_cpp_owned_hia_receipt

CLANG = os.environ.get("CLANG") or shutil.which("clang")
CLANGXX = os.environ.get("CLANGXX") or (str(Path(CLANG).with_name("clang++")) if CLANG else None)
CC, CXX = shutil.which("gcc"), shutil.which("g++")


@unittest.skipUnless(CLANG and CLANGXX and CC and CXX, "Clang 20 and native C/C++ references required")
class HIAOwnedMigrationIntegrationTests(unittest.TestCase):
    def test_real_migrator_all_475_native_vectors_and_receipt_mutations(self):
        with tempfile.TemporaryDirectory() as td:
            report = qualify_cpp_owned_to_hia(Path(td) / "owned", clang=CLANG,
                                             clangxx=CLANGXX, cc=CC, cxx=CXX)
            self.assertTrue(report["ok"], report.get("diagnostic"))
            self.assertEqual(report["source_declarations"], 2)
            self.assertEqual(len(report["declaration_inventory"]), 15)
            self.assertEqual(report["case_count"], 475)
            self.assertEqual(report["native_result_executions"], 950)
            self.assertEqual(report["actual_fault_executions"], 196)
            self.assertEqual(report["observed"]["standalone_hia"]["allocations"], 359)
            self.assertEqual(report["observed"]["standalone_hia"]["frees"], 359)
            self.assertEqual(report["observed"]["standalone_hia"]["live"], 0)
            self.assertTrue(report["interpreter_cases"])
            for mutation in (lambda r: r["observed"]["standalone_hia"].update(frees=0),
                             lambda r: r.update(cpp_class_abi_preserved=True),
                             lambda r: r.update(foreign_cpp_link_inputs=["original.cpp"]),
                             lambda r: r["target_link_argv"].append("original.cpp")):
                forged = deepcopy(report)
                mutation(forged)
                with self.assertRaises(ValueError):
                    validate_cpp_owned_hia_receipt(forged)
            forged = deepcopy(report)
            forged["expected_target_link_argv"] = [*forged["expected_target_link_argv"], "original.o"]
            forged["target_link_argv"] = [*forged["target_link_argv"], "original.o"]
            forged["processes"][0]["argv"] = list(forged["target_link_argv"])
            with self.assertRaisesRegex(ValueError, "Target must link the standalone HIA object"):
                validate_cpp_owned_hia_receipt(forged)


if __name__ == "__main__":
    unittest.main()
