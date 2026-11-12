"""Shared exit accounting at real interpreter and transformation boundaries.

Stopped prefixes deliberately retain capabilities. These tests distinguish
program errors, fallible allocation, cooperative cancellation and evaluator
quotas; they do not imply asynchronous cancellation or native unwinding.
"""
from copy import deepcopy
import unittest
from unittest.mock import patch

from hepta import hia_program_runtime as runtime
from hepta.hia_call_expansion import propose_leaf_call_expansion
from hepta.hia_opcodes import ExecutionObservationRejected, validate_execution_observation
from hepta.hia_optimization_contract import execute_contracted_expansion
from hepta.hia_program import HIAProgramRejected
from tests.test_hia_bulk_memory import bulk_program
from tests.test_hia_optimization_contract import cleanup_module, policy
from tests.test_hia_program import b, f, i, m, ret


def held_program():
    params = [("n", "usize"), ("index", "usize")]
    source = m(f("held", params, ["u8"], ["alloc", "read", "trap"], [
        b("entry", params, [
            i("buffer.new", ["n"], [("owned", "buffer")]),
            i("borrow.read", ["owned"], [("view", "readbuf")]),
            i("buffer.load", ["view", "index"], [("value", "u8")]),
            i("loan.end", ["view"]), i("owner.drop", ["owned"]),
        ], ret("value")),
    ]))
    source["schema"] = "hepta.hia.program.v8"
    return source


def observe(source, entry, args, **limits):
    try:
        return runtime.execute_program(source, entry, args, **limits)
    except (runtime.HIAProgramTrap, runtime.HIAProgramBudgetExceeded) as exc:
        return exc.report


class SharedExecutionContractTests(unittest.TestCase):
    def test_real_return_error_value_cancel_and_allocation_failure_use_one_contract(self):
        source = cleanup_module()
        proposal = propose_leaf_call_expansion(source, callees=["make"])
        cases = (([False, 3], None, 4), ([True, 0], None, 2), ([False, 0], 1, 1))
        for args, failure, value in cases:
            with self.subTest(args=args, failure=failure):
                before = observe(source, "run", args, allocation_fail_at=failure)
                after = execute_contracted_expansion(source, proposal, "run", args,
                    policy=policy(), allocation_fail_at=failure)["execution"]
                self.assertEqual(before["status"], "returned")
                self.assertEqual(before["values"], [value])
                self.assertEqual(before["resources"], after["resources"])
                self.assertEqual(after["values"], [value])
                self.assertEqual(before["resources"]["live_owners"], 0)
                self.assertEqual(before["resources"]["live_local_loans"], 0)
        trapped = observe(held_program(), "held", [4, 0], allocation_fail_at=1)
        self.assertEqual((trapped["status"], trapped["error"]["code"]), ("trapped", "allocation"))
        self.assertEqual(trapped["resources"]["allocation_attempts"], 1)
        self.assertEqual(trapped["resources"]["owners_created"], 0)

    def test_real_trap_and_each_quota_preserve_the_stopped_resource_prefix(self):
        for args, limits, outcome in (
            ([4, 4], {}, ("trapped", "bounds")),
            ([4, 0], {"max_steps": 3}, ("budget_exceeded", "steps")),
            ([4, 0], {"max_heap_bytes": 3}, ("budget_exceeded", "heap")),
        ):
            with self.subTest(outcome=outcome):
                result = observe(held_program(), "held", args, **limits)
                self.assertEqual((result["status"], result["error"]["code"]), outcome)
                ledger = result["resources"]
                retained = 0 if outcome[1] == "heap" else 1
                self.assertEqual(ledger["live_owners"], retained)
                self.assertEqual(ledger["live_local_loans"], retained)
                self.assertEqual(ledger["live_bytes"], 4 * retained)
                self.assertEqual(ledger["owners_dropped"], 0)
        result = observe(cleanup_module(), "run", [False, 3], max_call_depth=1)
        self.assertEqual((result["status"], result["error"]["code"]), ("budget_exceeded", "calls"))

    def test_host_scratch_failure_is_a_separate_python_only_evaluator_stop(self):
        # Fault injection, not an actual machine running out of RAM.
        with patch.object(runtime, "fill_bytes", side_effect=MemoryError("injected host scratch failure")):
            result = observe(bulk_program(), "bulk", [4, 4, 37])
        self.assertEqual((result["status"], result["error"]["code"]), ("budget_exceeded", "host_memory"))
        self.assertGreater(result["resources"]["live_bytes"], 0)
        with self.assertRaises(ExecutionObservationRejected):
            validate_execution_observation(result["status"], result["resources"], steps=result["steps"],
                max_steps=1_000_000, max_heap_bytes=16 * 1024 * 1024,
                error_code="host_memory")

    def test_python_report_cannot_emit_contradictory_loan_or_payload_counters(self):
        real_resources = runtime._Machine.resources
        for change in ({"live_local_loans": 0}, {"loans_ended": 2}, {"live_bytes": 0},
                       {"owners_dropped": 1, "live_owners": 0}, {"allocations": 0}):
            def malformed(machine):
                return {**real_resources(machine), **change}
            with self.subTest(change=change), patch.object(runtime._Machine, "resources", malformed):
                with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_EXECUTION_CONTRACT") as caught:
                    observe(held_program(), "held", [4, 4])
                self.assertEqual(caught.exception.code, "E_HIA_RUNTIME_INVARIANT")

    def test_unknown_misclassified_nonexact_and_extra_observations_fail_closed(self):
        result = observe(held_program(), "held", [4, 4])
        ledger = result["resources"]
        common = dict(steps=result["steps"], max_steps=1_000_000,
                      max_heap_bytes=16 * 1024 * 1024, with_chains=True)
        for status, code in (("cancelled", None), ("unknown", "bounds"),
                             ("returned", "bounds"), ("trapped", "heap"),
                             ("budget_exceeded", "allocation"), ("trapped", "future_trap")):
            with self.subTest(status=status, code=code), self.assertRaises(ExecutionObservationRejected):
                validate_execution_observation(status, ledger, error_code=code, **common)
        for value in (True, 1.0, -1, 1 << 64):
            malformed = {**ledger, "loans_started": value}
            with self.subTest(value=value), self.assertRaises(ExecutionObservationRejected):
                validate_execution_observation("trapped", malformed, error_code="bounds", **common)
        for change in ({"future_resource": 0}, {"live_chain_nodes": 1}):
            with self.subTest(change=change), self.assertRaises(ExecutionObservationRejected):
                validate_execution_observation("trapped", {**ledger, **change}, error_code="bounds", **common)
        orphan = {**ledger, "frees": 1, "owners_dropped": 1, "live_owners": 0, "live_bytes": 0}
        with self.assertRaisesRegex(ExecutionObservationRejected, "no live byte owner"):
            validate_execution_observation("trapped", orphan, error_code="bounds", **common)
        missing = deepcopy(ledger)
        del missing["loans_ended"]
        with self.assertRaises(ExecutionObservationRejected):
            validate_execution_observation("trapped", missing, error_code="bounds", **common)


if __name__ == "__main__":
    unittest.main()
