"""P1/P5: one finite typed resource-clause oracle for IR and Owned LLVM."""
from __future__ import annotations

from types import SimpleNamespace
import unittest

from hepta.static_resource_contracts import finite_static_contract_allowed


def allowed(clauses, *, declared=(), inferred=()):
    fn = SimpleNamespace(name="example", resources=clauses, effects=set(declared))
    checked = SimpleNamespace(effects={"example": set(inferred)})
    return finite_static_contract_allowed(fn, checked)


class StaticResourcePolicyTests(unittest.TestCase):
    def test_empty_contract_is_allowed(self):
        self.assertTrue(allowed({}))

    def test_four_explicit_zero_cost_clauses_are_allowed(self):
        self.assertTrue(allowed({"heap_allocations": 0, "may_block": False,
                                 "may_spawn": False, "may_suspend": False},
                                declared=("panic",)))

    def test_ordinary_nonallocating_effects_are_allowed(self):
        self.assertTrue(allowed({"heap_allocations": 0, "may_block": False},
                                declared=("write",), inferred=("panic",)))

    def test_bool_is_not_integer_zero(self):
        self.assertFalse(allowed({"heap_allocations": False}))

    def test_numeric_zero_is_not_boolean_false(self):
        for key in ("may_block", "may_spawn", "may_suspend"):
            with self.subTest(key=key):
                self.assertFalse(allowed({key: 0}))

    def test_true_is_not_a_no_cost_resource_guarantee(self):
        for key in ("may_block", "may_spawn", "may_suspend"):
            with self.subTest(key=key):
                self.assertFalse(allowed({key: True}))

    def test_transitive_heap_allocation_is_rejected(self):
        self.assertFalse(allowed({"heap_allocations": 0}, inferred=("alloc",)))

    def test_declared_blocking_is_rejected(self):
        self.assertFalse(allowed({"may_block": False}, declared=("block",)))

    def test_spawn_and_suspend_effects_are_rejected(self):
        self.assertFalse(allowed({"may_spawn": False}, inferred=("spawn",)))
        self.assertFalse(allowed({"may_suspend": False}, declared=("suspend",)))

    def test_arbitrary_budgets_must_not_be_reinterpreted(self):
        for kind in ("max_rss_bytes", "max_tasks", "stack_bytes", "cpu_cycles"):
            with self.subTest(kind=kind):
                self.assertFalse(allowed({kind: 1}))

    def test_malformed_contexts_fail_closed(self):
        fn = SimpleNamespace(name="example", resources={}, effects=set())
        self.assertFalse(finite_static_contract_allowed(fn, SimpleNamespace(effects=[])))
        self.assertFalse(finite_static_contract_allowed(fn, SimpleNamespace(effects={})))
        self.assertFalse(finite_static_contract_allowed(
            SimpleNamespace(name="example", resources=[], effects=set()),
            SimpleNamespace(effects={"example": set()})))
        self.assertFalse(finite_static_contract_allowed(
            SimpleNamespace(name="example", resources={}, effects=[]),
            SimpleNamespace(effects={"example": set()})))
        self.assertFalse(finite_static_contract_allowed(
            fn, SimpleNamespace(effects={"example": ["alloc"]})))
        self.assertFalse(finite_static_contract_allowed(
            fn, SimpleNamespace(effects={"example": {42}})))

    def test_transitively_unconstrained_legacy_effects_preserved(self):
        # Reject only explicitly requested no-cost bounds. This helper must
        # not invent a process-wide resource budget for unconstrained code.
        self.assertTrue(allowed({}, inferred=("alloc", "block", "spawn")))


if __name__ == "__main__":
    unittest.main()
