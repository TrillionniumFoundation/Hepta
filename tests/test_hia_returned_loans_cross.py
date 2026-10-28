"""Actual v8 AArch64/RV64 execution and retained-evidence refusal controls."""
from copy import deepcopy
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from tools.qualify_hia_returned_loans_cross import (case_plan, corpus_document, expected_counts,
    independent_spec, qualify, trap_plan, validate_qualification)


def configured_tool(variable, fallback):
    selected = os.environ.get(variable, fallback)
    return shutil.which(selected) or selected


TOOLS = {"clang": configured_tool("CLANG", "clang"),
         "linker": configured_tool("HEPTA_LLD", "ld.lld"),
         "readobj": configured_tool("HEPTA_LLVM_READOBJ", "llvm-readobj"),
         "qemu_aarch64": configured_tool("HEPTA_QEMU_AARCH64", "qemu-aarch64"),
         "qemu_riscv64": configured_tool("HEPTA_QEMU_RISCV64", "qemu-riscv64")}


class ReturnedLoanCrossContract(unittest.TestCase):
    def test_fixed_corpus_has_only_scalar_exports_and_keeps_internal_loans(self):
        document = corpus_document()
        verify_program(document)
        functions = {fn["name"]: fn for fn in document["functions"]}
        self.assertEqual(len(document["exports"]), 19)
        self.assertTrue(any(fn.get("return_loans") for fn in functions.values()))
        for name in document["exports"]:
            fn = functions[name]
            self.assertEqual(fn["returns"], ["u8"])
            self.assertTrue(all(p["type"] in {"u8", "usize"} for p in fn["params"]))
        document["exports"].append("loan_return_read_forward")
        with self.assertRaisesRegex(HIAProgramRejected, "public exports cannot carry"):
            verify_program(document)

    def test_oracle_retains_wraparound_and_distinct_stopped_allocation_states(self):
        cases = case_plan()
        selected = next(case for case in cases if case["family"] == "chain_mut_forward" and case["arguments"] == [250])
        self.assertEqual(independent_spec(selected)["result"], 254)
        selected = next(case for case in cases if case["family"] == "loan_mut" and case["arguments"] == [17, 255])
        self.assertEqual(independent_spec(selected)["result"], 4)
        observed = [independent_spec(case) for case in trap_plan()]
        self.assertEqual([(r["attempts"], r["allocations"], r["frees"], r["live_bytes"], r["peak_bytes"])
                         for r in observed], [(1, 1, 0, 1, 1), (2, 1, 0, 1, 1),
                                             (1, 0, 0, 0, 0), (2, 1, 1, 0, 1)])

    def test_missing_declared_tool_retains_failure_and_cannot_reuse_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "qualification"
            tools = {key: str(Path(temporary) / key) for key in TOOLS}
            report = qualify(directory=output, **tools)
            self.assertFalse(report["ok"])
            self.assertEqual(report["status"], "rejected")
            self.assertTrue((output / "qualification.json").is_file())
            self.assertEqual(report["native"], {})
            with self.assertRaises(FileExistsError):
                qualify(directory=output, **tools)


@unittest.skipUnless(all(shutil.which(path) for path in TOOLS.values()),
                     "actual Clang, LLD, LLVM reader and both QEMU targets required")
class ReturnedLoanCrossNative(unittest.TestCase):
    def test_actual_targets_traps_mutations_and_retained_identity_controls(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = qualify(directory=Path(temporary) / "qualification", **TOOLS)
            self.assertTrue(report["ok"], report.get("error"))
            self.assertEqual(report["counts"], expected_counts())
            self.assertEqual(report["counts"]["positive_native_calls"], 256)
            self.assertEqual(report["counts"]["all_native_execution_processes"], 14)
            for target in ("aarch64", "riscv64"):
                self.assertEqual([row["execution"]["returncode"] for row in report["native"][target]["executions"]],
                                 [0, 134, 134, 134, 134, 41, 92])
            self.assertTrue(validate_qualification(report)["ok"])

            def changed(function):
                forged = deepcopy(report)
                function(forged)
                with self.assertRaises(ValueError):
                    validate_qualification(forged)

            changed(lambda r: r["reference"][0]["expected"].update(allocations=True))
            changed(lambda r: r["reference"].pop())
            changed(lambda r: r["counts"].update(positive_native_calls=257))
            changed(lambda r: r["claims"].update(physical_hardware_executed=True))
            changed(lambda r: r["claims"].pop("general_foreign_lifetimes_qualified"))
            changed(lambda r: r["reference"][0]["vm"].update(status="trapped"))
            changed(lambda r: r["native"]["aarch64"]["executions"][0]["execution"].update(returncode=1))
            changed(lambda r: r["native"]["riscv64"]["objects"]["positive"].update(target="aarch64-unknown-linux-gnu"))
            changed(lambda r: r["native"]["riscv64"]["objects"]["removed_free"]["build"].update(qualified_hia_artifact=True))
            changed(lambda r: r["native"]["aarch64"]["executions"][0]["binary_inventory"].update(machine=243))
            changed(lambda r: r["native"]["riscv64"]["objects"]["positive"]["build"].update(status="native_executed"))
            executable = Path(report["workdir"]) / "aarch64/positive/program.elf"
            executable.write_bytes(executable.read_bytes() + b"changed")
            with self.assertRaisesRegex(ValueError, "artifact"):
                validate_qualification(report)


if __name__ == "__main__":
    unittest.main()
