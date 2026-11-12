"""Actual before/after execution and rejection at expansion resource boundaries."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from hepta.hia_call_expansion import propose_leaf_call_expansion
from hepta.hia_optimization_contract import (
    HIAOptimizationContractRejected, POLICY_SCHEMA, execute_contracted_expansion,
    qualify_expansion_contract as qualify_contract, validate_expansion_contract as validate_contract,
)
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program
from hepta.hia_static_budget import HIAStaticBudgetRejected
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret


def policy(mode="both_fit_same_quotas", **changed):
    result = {"schema": POLICY_SCHEMA, "budget_mode": mode,
              "max_allocator_interactions": 2, "max_vm_ticks": 64,
              "max_call_depth": 2, "max_live_heap_bytes": 4}
    result.update(changed)
    return result


def qualify_expansion_contract(base, proposal, *, policy, arguments=(False, 3)):
    return qualify_contract(base, proposal, function="run", arguments=arguments, policy=policy)


def validate_expansion_contract(base, proposal, receipt, *, policy, arguments=(False, 3)):
    return validate_contract(base, proposal, receipt, function="run", arguments=arguments, policy=policy)


def cleanup_module():
    maker = f("make", [], ["buffer", "bool"], ["alloc"], [b("entry", [], [
        c("size", "usize", 4),
        i("buffer.try_new", ["size"], [("owner", "buffer"), ("ok", "bool")]),
    ], ret("owner", "ok"))])
    entry = f("run", [("cancel", "bool"), ("denominator", "u8")], ["u8"],
              ["alloc", "trap"], [
        b("entry", [("cancel", "bool"), ("denominator", "u8")], [
            i("call", [], [("owned", "buffer"), ("success", "bool")], function="make"),
        ], branch("success", ("accepted", "owned", "cancel", "denominator"), ("failed", "owned"))),
        b("failed", [("empty", "buffer")], [
            i("owner.drop", ["empty"]), c("failure", "u8", 1),
        ], ret("failure")),
        b("accepted", [("buffer", "buffer"), ("requested", "bool"), ("divisor", "u8")], [],
          branch("requested", ("cancelled", "buffer"), ("compute", "buffer", "divisor"))),
        b("cancelled", [("cancel_owner", "buffer")], [
            i("owner.drop", ["cancel_owner"]), c("cancel_value", "u8", 2),
        ], ret("cancel_value")),
        b("compute", [("compute_owner", "buffer"), ("compute_divisor", "u8")], [
            c("zero", "u8", 0),
            i("compare.eq", ["compute_divisor", "zero"], [("invalid", "bool")]),
        ], branch("invalid", ("abort", "compute_owner"), ("finish", "compute_owner"))),
        b("abort", [("aborted_owner", "buffer")], [],
          {"op": "trap", "code": "division_by_zero"}),
        b("finish", [("finished_owner", "buffer")], [
            c("answer", "u8", 4), i("owner.drop", ["finished_owner"]),
        ], ret("answer")),
    ])
    document = m(maker, entry)
    document["schema"] = "hepta.hia.program.v7"
    return document


def observe(core, arguments, **limits):
    try:
        return execute_program(core, "run", arguments, **limits)
    except (HIAProgramTrap, HIAProgramBudgetExceeded) as error:
        return error.report


class ExpansionResourceContractTests(unittest.TestCase):
    def setUp(self):
        self.base = cleanup_module()
        self.proposal = propose_leaf_call_expansion(self.base, callees=["make"])

    def test_actual_normal_failure_and_cooperative_cancel_cleanup_composes(self):
        receipt = qualify_expansion_contract(self.base, self.proposal, policy=policy())
        self.assertTrue(receipt["source_fits_same_quotas"])
        self.assertEqual(receipt["deltas"][0]["max_call_depth"], -1)
        for arguments, failure, expected in (([False, 3], None, 4), ([True, 0], None, 2),
                                              ([False, 0], 1, 1), ([True, 0], 1, 1)):
            with self.subTest(arguments=arguments, allocation_failure=failure):
                receipt = qualify_expansion_contract(self.base, self.proposal,
                                                     policy=policy(), arguments=arguments)
                source = observe(self.base, arguments, allocation_fail_at=failure)
                result = execute_contracted_expansion(self.base, self.proposal, "run", arguments,
                    policy=policy(), receipt=receipt, allocation_fail_at=failure)
                candidate = result["execution"]
                self.assertEqual(candidate["status"], "returned")
                self.assertEqual(candidate["result"], expected)
                self.assertEqual(source["values"], candidate["values"])
                self.assertEqual(source["resources"], candidate["resources"])
                self.assertEqual(candidate["resources"]["live_owners"], 0)
                self.assertEqual(candidate["resources"]["live_local_loans"], 0)
                self.assertFalse(result["automatic_cleanup_or_retry_claimed"])
                self.assertFalse(receipt["claims"]["source_cancellation_or_host_cleanup_proved"])

    def test_first_trap_keeps_live_resource_ledger_without_inventing_cleanup(self):
        before = observe(self.base, [False, 0])
        after = execute_contracted_expansion(self.base, self.proposal, "run", [False, 0],
                                              policy=policy())["execution"]
        self.assertEqual(before["status"], after["status"])
        self.assertEqual(after["status"], "trapped")
        self.assertEqual(before["error"]["code"], after["error"]["code"])
        self.assertEqual(after["error"]["code"], "division_by_zero")
        self.assertEqual(before["resources"], after["resources"])
        self.assertEqual(after["resources"]["live_owners"], 1)
        self.assertEqual(after["resources"]["owners_dropped"], 0)

    def test_budget_mode_distinguishes_actual_changed_call_failure(self):
        limited = policy("candidate_requalified", max_call_depth=1)
        receipt = qualify_expansion_contract(self.base, self.proposal, policy=limited)
        source = observe(self.base, [False, 3], max_call_depth=1)
        candidate = execute_contracted_expansion(self.base, self.proposal, "run", [False, 3],
                                                   policy=limited)["execution"]
        self.assertEqual(source["status"], "budget_exceeded")
        self.assertEqual(source["error"]["code"], "calls")
        self.assertEqual(candidate["status"], "returned")
        self.assertEqual(candidate["result"], 4)
        self.assertFalse(receipt["source_fits_same_quotas"])
        self.assertFalse(receipt["claims"]["exact_budget_stop_behavior_preserved"])
        with self.assertRaisesRegex(HIAOptimizationContractRejected, "source does not fit"):
            qualify_expansion_contract(self.base, self.proposal,
                policy=policy(max_call_depth=1))

    def test_actual_tick_reduction_requires_fresh_limits(self):
        preliminary = qualify_expansion_contract(self.base, self.proposal, policy=policy())
        after = {row["function"]: row for row in preliminary["after"]["functions"]}
        maximum = max(row["max_vm_ticks"] for row in after.values())
        tight = policy("candidate_requalified", max_vm_ticks=maximum)
        result = execute_contracted_expansion(self.base, self.proposal, "run", [False, 3],
                                                policy=tight)
        self.assertEqual(result["execution"]["status"], "returned")
        self.assertEqual(observe(self.base, [False, 3], max_steps=maximum)["status"], "budget_exceeded")
        with self.assertRaisesRegex(HIAOptimizationContractRejected, "candidate exceeds"):
            qualify_expansion_contract(self.base, self.proposal,
                policy=policy("candidate_requalified", max_vm_ticks=maximum - 1))

    def test_each_resource_cap_refuses_before_runtime(self):
        for key, value in (("max_allocator_interactions", 1), ("max_live_heap_bytes", 3),
                           ("max_vm_ticks", 1)):
            with self.subTest(key=key), patch("hepta.hia_program_runtime.execute_program") as runtime:
                with self.assertRaisesRegex(HIAOptimizationContractRejected, "candidate exceeds"):
                    execute_contracted_expansion(self.base, self.proposal, "run", [False, 3],
                                                 policy=policy(**{key: value}))
                runtime.assert_not_called()

    def test_receipt_cannot_change_budget_claim_policy_or_base_identity(self):
        receipt = qualify_expansion_contract(self.base, self.proposal, policy=policy())
        self.assertEqual(validate_expansion_contract(self.base, self.proposal, receipt, policy=policy()), receipt)
        for mutate in (
            lambda r: r["after"]["functions"][0].update(max_vm_ticks=0),
            lambda r: r["claims"].update(whole_language_soundness_proved=True),
            lambda r: r.update(candidate_fits_same_quotas=1),
            lambda r: r["policy"].update(max_call_depth=1),
            lambda r: r.update(base_sha256="0" * 64),
            lambda r: r["not_qualified"].clear(),
        ):
            changed = deepcopy(receipt)
            mutate(changed)
            with self.assertRaisesRegex(HIAOptimizationContractRejected, "independent actual-Core replay"):
                validate_expansion_contract(self.base, self.proposal, changed, policy=policy())

    def test_valid_but_different_resource_operation_and_unresolved_import_refused(self):
        changed = deepcopy(self.proposal)
        changed["candidate_core"]["functions"][1]["blocks"][0]["ops"][0]["attrs"]["value"] = 3
        verify_program(changed["candidate_core"])
        with self.assertRaisesRegex(HIAOptimizationContractRejected, "transformation rejected"):
            qualify_expansion_contract(self.base, changed, policy=policy())
        missing = deepcopy(self.base)
        missing["functions"] = missing["functions"][1:]
        with self.assertRaises(HIAProgramRejected):
            qualify_expansion_contract(missing, self.proposal, policy=policy())

    def test_exact_policy_rejects_missing_extra_and_numeric_boolean_fields(self):
        for changed in (policy(max_call_depth=True), policy(max_live_heap_bytes=-1),
                        policy(budget_mode="pretend_equivalent"), policy(extra="unproved")):
            with self.subTest(policy=changed), self.assertRaises(ValueError):
                qualify_expansion_contract(self.base, self.proposal, policy=changed)
        changed = policy()
        del changed["max_live_heap_bytes"]
        with self.assertRaises(ValueError):
            qualify_expansion_contract(self.base, self.proposal, policy=changed)

    def test_proposal_is_detached_before_semantic_checker_can_observe_caller_changes(self):
        from hepta import hia_call_expansion
        actual = hia_call_expansion.verify_leaf_call_expansion
        original_candidate = verify_program(self.proposal["candidate_core"]).sha256
        def change_caller_after_snapshot(base, frozen):
            self.proposal["candidate_core"]["module"] = "changed_outside"
            return actual(base, frozen)
        with patch.object(hia_call_expansion, "verify_leaf_call_expansion", change_caller_after_snapshot):
            result = qualify_expansion_contract(self.base, self.proposal, policy=policy())
        self.assertEqual(result["candidate_sha256"], original_candidate)
        self.assertNotEqual(result["candidate_sha256"], verify_program(self.proposal["candidate_core"]).sha256)

    def test_receipt_for_another_typed_invocation_cannot_authorize_execution(self):
        receipt = qualify_expansion_contract(self.base, self.proposal, policy=policy())
        self.assertFalse(receipt["claims"]["resource_bounds_for_all_input_values"])
        with patch("hepta.hia_program_runtime.execute_program") as runtime:
            with self.assertRaisesRegex(HIAOptimizationContractRejected, "retained contract differs"):
                execute_contracted_expansion(self.base, self.proposal, "run", [True, 3],
                                             policy=policy(), receipt=receipt)
            runtime.assert_not_called()

    def test_finite_contract_rejects_a_valid_owner_carrying_cycle(self):
        changed = deepcopy(self.base)
        blocks = changed["functions"][1]["blocks"]
        finish = next(block for block in blocks if block["id"] == "finish")
        finish["ops"] = []
        finish["term"] = jump("spin", "finished_owner")
        blocks.append(b("spin", [("loop_owner", "buffer")], [], jump("spin", "loop_owner")))
        verify_program(changed)
        proposal = propose_leaf_call_expansion(changed, callees=["make"])
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_UNBOUNDED"):
            qualify_expansion_contract(changed, proposal, policy=policy())

    def test_recursive_chain_in_unused_definition_does_not_inherit_byte_profile(self):
        changed = deepcopy(self.base)
        changed["functions"].append(f("destroy_chain", [("chain_owner", "chain")], [], ["alloc"], [
            b("entry", [("chain_owner", "chain")], [i("owner.drop", ["chain_owner"])], ret())]))
        verify_program(changed)
        proposal = propose_leaf_call_expansion(changed, callees=["make"])
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_PROFILE"):
            qualify_expansion_contract(changed, proposal, policy=policy())

    def test_cancel_cleanup_cannot_be_deleted_and_legacy_owner_return_is_not_upgraded(self):
        changed = deepcopy(self.proposal)
        block = next(block for block in changed["candidate_core"]["functions"][1]["blocks"]
                     if block["id"] == "cancelled")
        block["ops"].pop(0)
        with self.assertRaisesRegex(HIAOptimizationContractRejected, "transformation rejected"):
            qualify_expansion_contract(self.base, changed, policy=policy())
        legacy = deepcopy(self.base)
        legacy["schema"] = "hepta.hia.program.v6"
        proposal = propose_leaf_call_expansion(legacy, callees=["make"])
        with self.assertRaisesRegex(ValueError, "owned return needs a caller-size invariant"):
            qualify_expansion_contract(legacy, proposal, policy=policy())


if __name__ == "__main__":
    unittest.main()
