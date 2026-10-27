"""V7 HIA runtime/static call-depth parity; runs without Rust/Cargo.

The root call counts as one live frame. This is not a stack-byte, CPU,
termination or native LLVM proof. The HIA Core verifier stays authoritative.
"""
import unittest

from hepta.hia_program import SCHEMA_V7, verify_program
from hepta.hia_program_runtime import execute_program, HIAProgramBudgetExceeded
from hepta.hia_static_budget import analyze_static_budget, HIAStaticBudgetRejected
from tests.test_hia_vm_call_depth import sequential_calls, recursively_nested


def v7(document, *, exports):
    document["schema"] = SCHEMA_V7
    document["exports"] = exports
    return document


class V7RootInclusiveCallDepthTests(unittest.TestCase):
    def test_v7_static_two_frames_matches_dynamic_gate(self):
        source = v7(sequential_calls(), exports=["inner", "outer"])
        core = verify_program(source)
        rows = {row["function"]: row for row in
                analyze_static_budget(core)["functions"]}
        self.assertEqual(rows["inner"]["max_call_depth"], 1)
        self.assertEqual(rows["outer"]["max_call_depth"], 2)
        self.assertEqual(execute_program(core, "inner", [9], max_call_depth=1)["result"], 9)
        with self.assertRaises(HIAProgramBudgetExceeded) as caught:
            execute_program(core, "outer", [9], max_call_depth=1)
        self.assertEqual(caught.exception.code, "calls")
        self.assertEqual(caught.exception.report["steps"], 2)
        self.assertEqual(caught.exception.report["resources"]["live_owners"], 0)
        self.assertEqual(execute_program(core, "outer", [9], max_call_depth=2)["result"], 9)
        with self.assertRaises(HIAStaticBudgetRejected):
            analyze_static_budget(core, max_call_depth=1)

    def test_v7_recursive_frames_count_root_before_tick(self):
        core = verify_program(v7(recursively_nested(), exports=["again"]))
        for limit in (1, 2, 3, 5, 32):
            with self.subTest(limit=limit):
                with self.assertRaises(HIAProgramBudgetExceeded) as caught:
                    execute_program(core, "again", [7], max_call_depth=limit)
                self.assertEqual(caught.exception.code, "calls")
                self.assertEqual(caught.exception.report["steps"], 2 * limit)


if __name__ == "__main__":
    unittest.main()
