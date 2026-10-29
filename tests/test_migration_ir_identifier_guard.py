"""Fail-closed identifier admission for independently constructed migration IR."""
import unittest

from hepta.migration_ir import (
    Expr, Function, IRValidationError, Stmt, check_function,
    emit_function, function_hash,
)


class MigrationIRIdentifierGuard(unittest.TestCase):
    @staticmethod
    def literal_function(name: str) -> Function:
        return Function(name, (), "i32",
                        (Stmt("return", Expr("literal", "i32", "1")),))

    @staticmethod
    def parameter_function(name: str) -> Function:
        return Function("safe", ((name, "i32"),), "i32",
                        (Stmt("return", Expr("var", "i32", name)),))

    def test_function_name_injection_and_invalid_tokens_are_refused(self):
        bad = (
            'safe) -> i32 effects {} { return 1; } export "C" fn injected',
            "fn", "if", "return", "repr", "raw", "in",
            "main", "wrapping_add", "_hidden", "__internal",
            "9invalid", "non-ascii-é", "new\nline",
        )
        for name in bad:
            with self.subTest(name=name):
                fn = self.literal_function(name)
                for operation in (check_function, function_hash, emit_function):
                    with self.assertRaises(IRValidationError):
                        operation(fn)

    def test_parameter_name_injection_and_reserved_tokens_are_refused(self):
        for name in ("x, injected: i32", "fn", "true", "resources", "_private",
                     "x; return 0", "x\nother", "7bad"):
            with self.subTest(name=name):
                fn = self.parameter_function(name)
                for operation in (check_function, function_hash, emit_function):
                    with self.assertRaises(IRValidationError):
                        operation(fn)

    def test_safe_scalar_identifiers_remain_accepted(self):
        fn = self.parameter_function("value_2")
        fn = Function("safe_1", fn.params, fn.result, fn.body)
        self.assertEqual(check_function(fn), frozenset())
        self.assertEqual(len(function_hash(fn)), 64)
        generated = emit_function(fn)
        self.assertIn("fn safe_1(value_2: i32)", generated)
        self.assertIn("return value_2;", generated)

    def test_duplicate_parameters_still_rejected(self):
        fn = Function("ok", (("same", "i32"), ("same", "u32")), "i32",
                      (Stmt("return", Expr("literal", "i32", "1")),))
        with self.assertRaises(IRValidationError):
            emit_function(fn)


if __name__ == "__main__":
    unittest.main()
