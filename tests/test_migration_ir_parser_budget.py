"""Keep independently constructed migration IR inside the actual Hepta parser budget."""
import unittest

from hepta.ast import HeptaError
from hepta.migration_ir import (
    Expr, Function, IRValidationError, Stmt, check_function, emit_function,
    function_hash,
)
from hepta.parser import parse


class MigrationIRParserBudget(unittest.TestCase):
    @staticmethod
    def wrap(expr):
        return Function("safe", (), "i32", (Stmt("return", expr),))

    @staticmethod
    def nested_negations(count):
        expr = Expr("literal", "i32", "1")
        for _ in range(count):
            expr = Expr("neg", "i32", "", (expr,))
        return expr

    @staticmethod
    def nested_right_arithmetic(count):
        expr = Expr("literal", "i32", "1")
        for _ in range(count):
            expr = Expr("arith", "i32", "+",
                        (Expr("literal", "i32", "1"), expr))
        return expr

    def assert_all_public_gates_reject(self, function):
        for gate in (check_function, function_hash, emit_function):
            with self.subTest(gate=gate.__name__):
                with self.assertRaises(IRValidationError):
                    gate(function)

    def test_negation_emitted_parser_depth_is_bounded(self):
        # Old preflight accepted this 50-node tree (under its IR depth 128),
        # although each emitted (-expr) adds two recursive parser frames.
        self.assert_all_public_gates_reject(self.wrap(self.nested_negations(50)))

    def test_binary_right_operand_emitted_parser_depth_is_bounded(self):
        # Pratt parsing adds an expression frame for a binary right operand
        # in addition to the parentheses emitted for signed arithmetic.
        self.assert_all_public_gates_reject(
            self.wrap(self.nested_right_arithmetic(50)))

    def test_original_emitted_syntax_actually_exceeds_parser_limit(self):
        source = ('export "C" fn safe() -> i32 effects { panic } { return '
                  + '(-' * 50 + '(1 as i32)' + ')' * 50 + '; }')
        with self.assertRaises(HeptaError) as raised:
            parse(source)
        self.assertEqual(raised.exception.diagnostic.code, "E_PARSE_DEPTH")

    def test_bounded_negation_still_checks_hashes_and_parses(self):
        function = self.wrap(self.nested_negations(20))
        self.assertEqual(check_function(function), frozenset({"panic"}))
        self.assertEqual(len(function_hash(function)), 64)
        program = parse(emit_function(function))
        self.assertEqual(program.functions[0].name, "safe")

    def test_bounded_signed_arithmetic_still_checks_and_parses(self):
        function = self.wrap(self.nested_right_arithmetic(20))
        self.assertEqual(check_function(function), frozenset({"panic"}))
        self.assertEqual(len(function_hash(function)), 64)
        program = parse(emit_function(function))
        self.assertEqual(program.functions[0].name, "safe")


if __name__ == "__main__":
    unittest.main()
