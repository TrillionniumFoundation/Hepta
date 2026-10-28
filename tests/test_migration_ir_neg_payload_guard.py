"""Negation IR has no payload: reject covert inactive fields at every public gate."""
import unittest

from hepta.migration_ir import (
    Expr, Function, IRValidationError, Stmt, check_function,
    emit_function, function_hash,
)


class NegationIRCanonicalGuard(unittest.TestCase):
    @staticmethod
    def function(payload=""):
        # This value field is not used by the negative expression emitter,
        # so admitting arbitrary values makes distinct IR hashes represent
        # identical generated Hepta. Reject it before hashing or publishing.
        child = Expr("var", "i32", "x")
        return Function("safe", (("x", "i32"),), "i32",
                        (Stmt("return", Expr("neg", "i32", payload, (child,))),))

    def test_unused_neg_payload_is_rejected_by_every_public_gate(self):
        for payload in ("ignored", "+", "metadata", "inert\nextra"):
            fn = self.function(payload)
            for gate in (check_function, function_hash, emit_function):
                with self.subTest(payload=payload, gate=gate.__name__):
                    with self.assertRaises(IRValidationError):
                        gate(fn)

    def test_valid_negation_keeps_effect_hash_and_source(self):
        fn = self.function()
        self.assertEqual(check_function(fn), frozenset({"panic"}))
        self.assertEqual(len(function_hash(fn)), 64)
        self.assertIn("return (-x);", emit_function(fn))

    def test_nested_negation_without_payload_remains_supported(self):
        inner = Expr("neg", "i32", "", (Expr("literal", "i32", "1"),))
        outer = Expr("neg", "i32", "", (inner,))
        fn = Function("safe", (), "i32", (Stmt("return", outer),))
        self.assertEqual(check_function(fn), frozenset({"panic"}))
        self.assertIn("(-(-", emit_function(fn))
        self.assertEqual(len(function_hash(fn)), 64)


if __name__ == "__main__":
    unittest.main()
