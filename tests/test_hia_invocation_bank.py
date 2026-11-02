"""Prepared bounds equal the original gate and cannot skip a modeled profit."""
from copy import deepcopy
import random
import unittest
from unittest.mock import patch

from hepta.hia_invocation_bank import InvocationBoundBank, prepare_invocation_bank
from hepta.hia_ndu_stateful import (
    SCHEMA, SCHEMA_V2, SCHEMA_V3, StatefulPlanningError, invocation_gate, validate_model)
from tools.qualify_hia_ndu_stateful import fixtures
from tools.qualify_hia_ndu_stateful_reference import exact_dp_control


def models(schema=SCHEMA_V2):
    result = {}
    for size in (64, 4096, 65536):
        model = deepcopy(fixtures()[-1])
        model["schema"] = schema
        if schema != SCHEMA:
            model["future_decision_cost_ns"] = 0
        if schema == SCHEMA_V3:
            model["variants"] = model["variants"][:2]
        model["baseline"]["latency_ns"] = [500 + size % 31 + k * 13 for k in range(4)]
        for index, row in enumerate(model["variants"]):
            row.update(preparation_ns=30 + index * 11,
                       latency_ns=[70 + index * 17 + (size + k * 23) % 137 for k in range(4)],
                       holding_ns=[(index + k) * 3 for k in range(4)])
            if schema == SCHEMA_V3:
                row["eviction_ns"] = 7 + index
        result[size] = validate_model(model)
    return result


def query_model(template, *, horizon, ready_mask, budget_ns, generation=5, sunk_cost_ns=13,
                future_decision_cost_ns=0):
    model = deepcopy(template)
    model.update(generation=generation, sunk_cost_ns=sunk_cost_ns, budget_ns=budget_ns)
    model["initial_ready"] = [row["id"] for index, row in enumerate(model["variants"])
                              if ready_mask & (1 << index)]
    model["baseline"]["latency_ns"] = model["baseline"]["latency_ns"][:horizon]
    for row in model["variants"]:
        for key in ("latency_ns", "holding_ns"):
            row[key] = row[key][:horizon]
    if model["schema"] != SCHEMA:
        model["future_decision_cost_ns"] = future_decision_cost_ns
    return model


class InvocationBankTests(unittest.TestCase):
    def test_all_registered_masks_sizes_horizons_and_budget_boundaries_match_original_gate(self):
        fields = ("invoke", "reason", "incumbent_delivery_ns", "optimistic_delivery_lower_bound_ns",
                  "gross_savings_upper_bound_ns", "incumbent_ready", "cost_basis", "future_decision_cost_ns")
        for schema in (SCHEMA, SCHEMA_V2, SCHEMA_V3):
            source = models(schema)
            owner = prepare_invocation_bank(source, epoch=7)
            for size, template in source.items():
                for mask in range(1 << len(template["variants"])):
                    for horizon in range(1, 5):
                        future = 0 if schema == SCHEMA else 11
                        raw = query_model(template, horizon=horizon, ready_mask=mask,
                                          budget_ns=10_000, future_decision_cost_ns=future)
                        initial = invocation_gate(raw, invocation_cost_ns=0)
                        upper, lower = initial["gross_savings_upper_bound_ns"], initial["optimistic_delivery_lower_bound_ns"]
                        for invocation in sorted({0, max(0, upper - 1), upper, upper + 1}):
                            for budget in sorted({0, max(0, invocation + lower - 1), invocation + lower,
                                                  invocation + lower + 1, 10_000}):
                                raw["budget_ns"] = budget
                                expected = invocation_gate(raw, invocation_cost_ns=invocation)
                                actual = owner.lookup(size=size, horizon=horizon, ready_mask=mask,
                                    budget_ns=budget, invocation_cost_ns=invocation,
                                    epoch=7, generation=5, sunk_cost_ns=13, future_decision_cost_ns=future)
                                with self.subTest(schema=schema, size=size, mask=mask, horizon=horizon,
                                                  invocation=invocation, budget=budget):
                                    self.assertEqual({key: actual[key] for key in fields},
                                                     {key: expected[key] for key in fields})
                                    self.assertEqual(actual["generation"], 5)
                                    self.assertEqual(actual["budget_ns"], budget)
                                    self.assertFalse(actual["execution_authorized"])
            self.assertGreater(owner.snapshot()["lookups"], 0)
            self.assertTrue(owner.close()["closed"])

    def test_skips_cannot_discard_a_profitable_budget_feasible_exact_dp_plan(self):
        rng = random.Random(104759)
        for case in range(72):
            schema = (SCHEMA, SCHEMA_V2, SCHEMA_V3)[case % 3]
            source = models(schema)
            template = source[64]
            horizon = case % 4 + 1
            for row in template["variants"]:
                row["latency_ns"] = [rng.randrange(1, 900) for _ in range(4)]
                row["holding_ns"] = [rng.randrange(0, 40) for _ in range(4)]
            # Other sizes share source/quota facts; only this forecast changes.
            owner = prepare_invocation_bank(source, epoch=2)
            mask = rng.randrange(1 << len(template["variants"]))
            budget, invocation = rng.randrange(0, 5000), rng.randrange(0, 1500)
            raw = query_model(template, horizon=horizon, ready_mask=mask, budget_ns=budget,
                              future_decision_cost_ns=0 if schema == SCHEMA else case * 3)
            result = owner.lookup(size=64, horizon=horizon, ready_mask=mask, budget_ns=budget,
                invocation_cost_ns=invocation, epoch=2, generation=5, sunk_cost_ns=13,
                future_decision_cost_ns=raw.get("future_decision_cost_ns", 0))
            if not result["invoke"] and invocation <= budget:
                raw["budget_ns"] -= invocation
                independent = exact_dp_control(raw)
                for winner in independent["winners"]:
                    self.assertGreaterEqual(winner["cost_ns"] + invocation,
                                            result["incumbent_delivery_ns"], (case, result, winner))
            owner.close()

    def test_current_budget_generation_and_invocation_cost_are_never_cached(self):
        source = models()
        owner = prepare_invocation_bank(source, epoch=9)
        first = owner.lookup(size=64, horizon=4, ready_mask=0, budget_ns=10_000,
                             invocation_cost_ns=0, epoch=9, generation=1)
        second = owner.lookup(size=64, horizon=4, ready_mask=0, budget_ns=0,
                              invocation_cost_ns=3000, epoch=9, generation=2, sunk_cost_ns=999)
        self.assertTrue(first["invoke"])
        self.assertFalse(second["invoke"])
        self.assertEqual(second["generation"], 2)
        self.assertEqual(second["sunk_cost_ns"], 999)
        self.assertEqual(first["binding_sha256"], second["binding_sha256"])

    def test_preparation_detaches_inputs_and_hot_lookup_avoids_model_intake(self):
        source = models()
        owner = prepare_invocation_bank(source, epoch=1)
        expected = owner.lookup(size=64, horizon=4, ready_mask=0, budget_ns=10_000,
                                invocation_cost_ns=0, epoch=1, generation=1)
        source[64]["variants"][0]["latency_ns"] = [999999] * 4
        with patch("hepta.hia_invocation_bank.stateful.validate_model", side_effect=AssertionError("no model intake")), \
                patch("hepta.hia_invocation_bank.bounded_json_wire", side_effect=AssertionError("no JSON")), \
                patch("hepta.hia_ndu_stateful.invocation_gate", side_effect=AssertionError("no old gate")), \
                patch("tools.qualify_hia_ndu_stateful_reference.exact_dp_control", side_effect=AssertionError("no DP")):
            actual = owner.lookup(size=64, horizon=4, ready_mask=0, budget_ns=10_000,
                                  invocation_cost_ns=0, epoch=1, generation=1)
        self.assertEqual(actual, expected)

    def test_epoch_unknown_state_and_closed_owner_refuse(self):
        owner = prepare_invocation_bank(models(), epoch=3)
        options = dict(size=64, horizon=4, ready_mask=0, budget_ns=10_000,
                       invocation_cost_ns=1, epoch=3, generation=1)
        for update in ({"epoch": 4}, {"size": 65}, {"ready_mask": 8}, {"horizon": 5},
                       {"budget_ns": True}, {"generation": 0}, {"ready_mask": False}):
            with self.subTest(update=update), self.assertRaises(StatefulPlanningError):
                owner.lookup(**(options | update))
        self.assertEqual(owner.snapshot()["rejections"], 7)
        owner.close()
        with self.assertRaises(StatefulPlanningError):
            owner.lookup(**options)
        with self.assertRaises(StatefulPlanningError):
            InvocationBoundBank()

    def test_unverified_or_memory_infeasible_resident_masks_refuse(self):
        source = models()
        for model in source.values():
            model["variants"][0]["status"] = "unknown"
            model["memory_budget_bytes"] = 16
        owner = prepare_invocation_bank(source, epoch=1)
        for mask in (1, 6):
            with self.subTest(mask=mask), self.assertRaises(StatefulPlanningError):
                owner.lookup(size=64, horizon=1, ready_mask=mask, budget_ns=10_000,
                             invocation_cost_ns=1, epoch=1, generation=1)

    def test_complete_envelope_and_historical_schema_rules_remain_checked(self):
        v1 = prepare_invocation_bank(models(SCHEMA), epoch=1)
        with self.assertRaisesRegex(StatefulPlanningError, "v1 has no future"):
            v1.lookup(size=64, horizon=1, ready_mask=0, budget_ns=10_000,
                      invocation_cost_ns=1, epoch=1, generation=1, future_decision_cost_ns=1)
        v2 = prepare_invocation_bank(models(), epoch=1)
        with self.assertRaisesRegex(StatefulPlanningError, "complete cost envelope"):
            v2.lookup(size=64, horizon=4, ready_mask=0, budget_ns=10_000,
                      invocation_cost_ns=1, epoch=1, generation=1,
                      future_decision_cost_ns=1_000_000_000_000)

    def test_preparation_rejects_mixed_banks_and_noncanonical_intake(self):
        mixed = models()
        mixed[4096]["variants"][0]["source_sha256"] = "a" * 64
        with self.assertRaisesRegex(StatefulPlanningError, "different source"):
            prepare_invocation_bank(mixed, epoch=1)
        class Foreign(dict):
            pass
        with self.assertRaises(StatefulPlanningError):
            prepare_invocation_bank(Foreign(models()), epoch=1)
        cyclic = models()
        cyclic[64]["observations"] = [cyclic]
        with self.assertRaises(StatefulPlanningError):
            prepare_invocation_bank(cyclic, epoch=1)

    def test_ready_identity_mapping_and_bank_metadata_have_distinct_contracts(self):
        source = models()
        owner = prepare_invocation_bank(source, epoch=1)
        names = tuple(row["id"] for row in source[64]["variants"])
        self.assertEqual(owner.mask_for(tuple(reversed(names))), 7)
        self.assertEqual(owner.mask_for(frozenset(names[:1])), 1)
        for invalid in (list(names), set(names), (names[0], names[0]), ("unknown",)):
            with self.subTest(invalid=invalid), self.assertRaises(StatefulPlanningError):
                owner.mask_for(invalid)
        state = owner.snapshot()
        self.assertEqual(state["schema"], "hepta.hia.ndu.invocation-bound-bank.v1")
        self.assertEqual(state["model_schema"], SCHEMA_V2)
        self.assertFalse(state["execution_authorized"])


if __name__ == "__main__":
    unittest.main()
