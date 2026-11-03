"""Integer dispatch semantics remain exact at every Core machine width."""
import unittest

from hepta.hia_program import integer_range
from hepta.hia_program_runtime import (
    _BINARY_ARITHMETIC_OPS, HIAProgramTrap, execute_program,
)
from tests.test_hia_program import arithmetic


class RuntimeDispatchTests(unittest.TestCase):
    def test_dispatch_group_is_exact_and_immutable(self):
        expected = {f"int.{kind}.{mode}" for kind in ("add", "sub", "mul")
                    for mode in ("checked", "wrap")}
        self.assertIs(type(_BINARY_ARITHMETIC_OPS), frozenset)
        self.assertEqual(_BINARY_ARITHMETIC_OPS, expected)

    def test_dispatch_controls_are_in_both_complete_regression_gates(self):
        from tools.qualify_hia_composition import CORE_TESTS
        from tools.qualify_hia_verified_increment import MODULES
        self.assertIn("tests.test_hia_runtime_dispatch", CORE_TESTS)
        self.assertIn("tests.test_hia_runtime_dispatch", MODULES)

    def test_checked_and_wrapped_operations_match_independent_integer_oracle(self):
        for typ in ("i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "isize", "usize"):
            low, high = integer_range(typ)
            vectors = {(low, low), (low, high), (high, high), (high, 1), (0, 0),
                       (0, high), (1, 1), (high - 1, 1), (low, 1)}
            for op in sorted(_BINARY_ARITHMETIC_OPS):
                program = arithmetic(op, typ)
                for left, right in sorted(vectors):
                    with self.subTest(type=typ, op=op, left=left, right=right):
                        kind = op.split(".")[1]
                        value = (left + right if kind == "add" else
                                 left - right if kind == "sub" else left * right)
                        if op.endswith("checked") and not low <= value <= high:
                            with self.assertRaises(HIAProgramTrap) as caught:
                                execute_program(program, "calculate", [left, right])
                            self.assertEqual(caught.exception.code, "overflow")
                            self.assertEqual(caught.exception.report["status"], "trapped")
                            self.assertEqual(caught.exception.report["steps"], 2)
                        else:
                            expected = low + (value - low) % (high - low + 1)
                            result = execute_program(program, "calculate", [left, right])
                            self.assertEqual(result["result"], expected)
                            self.assertEqual(result["steps"], 3)
                            self.assertEqual(result["resources"]["live_owners"], 0)


if __name__ == "__main__":
    unittest.main()
