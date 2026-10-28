"""Structural fail-closed/bounded-work tests for the public scalar migration IR."""
import unittest

from hepta.migration_ir import (
    Expr, Function, IRValidationError, Stmt, check_function,
    emit_function, function_hash,
)


class StructuralMigrationIRBudget(unittest.TestCase):
    @staticmethod
    def wrap(expr, result="i32"):
        return Function("safe", (), result, (Stmt("return", expr),))

    def assert_all_reject(self, function):
        for gate in (check_function, function_hash, emit_function):
            with self.subTest(gate=gate.__name__):
                with self.assertRaises(IRValidationError):
                    gate(function)

    def test_malformed_containers_and_unhashable_tokens_reject(self):
        base = self.wrap(Expr("literal", "i32", "1"))
        bad = (
            Function("safe", [], "i32", base.body),
            Function("safe", (["x", "i32"],), "i32", base.body),
            Function("safe", (), [], base.body),
            Function("safe", (), "i32", list(base.body)),
            self.wrap(Expr([], "i32", "1")),
            self.wrap(Expr("literal", [], "1")),
            self.wrap(Expr("var", "i32", [])),
            self.wrap(Expr("neg", "i32", "", [Expr("literal", "i32", "1")])),
            self.wrap(Expr("var", "i32", "x" * 100000)),
            Function("f" * 100000, (), "i32", base.body),
            Function("safe", (), "i32" * 100000, base.body),
            Function("safe", (("x", "i32" * 100000),), "i32", base.body),
            self.wrap(Expr("literal" * 100000, "i32", "1")),
            self.wrap(Expr("literal", "i32" * 100000, "1")),
        )
        for function in bad:
            self.assert_all_reject(function)

    def test_deep_recursion_rejects_without_recursion_error(self):
        expr = Expr("literal", "i32", "1")
        for _ in range(1200):
            expr = Expr("neg", "i32", "", (expr,))
        self.assert_all_reject(self.wrap(expr))

    def test_shared_dag_expansion_rejects_before_hashing(self):
        expr = Expr("literal", "u32", "1")
        for _ in range(15):
            expr = Expr("arith", "u32", "+", (expr, expr))
        self.assert_all_reject(self.wrap(expr, "u32"))

    def test_cyclic_object_graph_rejects_without_recursion_error(self):
        expr = Expr("neg", "i32")
        object.__setattr__(expr, "args", (expr,))
        self.assert_all_reject(self.wrap(expr))

    def test_bounded_nested_scalar_behavior_is_preserved(self):
        expr = Expr("literal", "i32", "1")
        for _ in range(20):
            expr = Expr("neg", "i32", "", (expr,))
        function = self.wrap(expr)
        self.assertEqual(check_function(function), frozenset({"panic"}))
        self.assertEqual(len(function_hash(function)), 64)
        self.assertIn('export "C" fn safe(', emit_function(function))


if __name__ == "__main__":
    unittest.main()
