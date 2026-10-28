"""Reject malformed or unbounded independently constructed scalar IR literals."""
import unittest

from hepta.migration_ir import (
    Expr, Function, IRValidationError, Stmt, check_function,
    emit_function, function_hash,
)


class MigrationIRLiteralGuard(unittest.TestCase):
    @staticmethod
    def scalar(value, ty="u32"):
        return Function("scalar", (), ty,
                        (Stmt("return", Expr("literal", ty, value)),))

    def assert_rejected_by_all_public_gates(self, value, ty="u32"):
        fn = self.scalar(value, ty)
        for gate in (check_function, function_hash, emit_function):
            with self.subTest(value=str(value)[:40], ty=ty, gate=gate.__name__):
                with self.assertRaises(IRValidationError):
                    gate(fn)

    def test_unbounded_digit_string_is_rejected_before_integer_conversion(self):
        # Exceeds CPython's usual 4,300-digit conversion limit. This must be
        # an IRValidationError, not a raw ValueError or a backend crash.
        self.assert_rejected_by_all_public_gates("9" * 5000)
        self.assert_rejected_by_all_public_gates("0" * 5000)

    def test_malformed_and_non_string_values_fail_closed(self):
        for value in (None, 1, True, "", "-1", "+1", "1_0", "1e0",
                      "0x10", "٣", "1\n2", [], "1" * 11):
            self.assert_rejected_by_all_public_gates(value)

    def test_out_of_range_values_fail_closed(self):
        self.assert_rejected_by_all_public_gates("2147483648", "i32")
        self.assert_rejected_by_all_public_gates("4294967296", "u32")

    def test_exact_boundary_values_still_emit_and_hash(self):
        for value, ty in (("0", "i32"), ("2147483647", "i32"),
                          ("0", "u32"), ("4294967295", "u32"),
                          ("0000000001", "u32")):
            with self.subTest(value=value, ty=ty):
                fn = self.scalar(value, ty)
                self.assertEqual(check_function(fn), frozenset())
                self.assertEqual(len(function_hash(fn)), 64)
                self.assertIn(f"({value} as {ty})", emit_function(fn))


if __name__ == "__main__":
    unittest.main()
