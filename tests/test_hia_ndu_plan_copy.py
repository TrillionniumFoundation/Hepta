"""Internal finite plan copies must retain complete values and isolation."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from hepta import hia_ndu_cost as cost
from tests.test_hia_ndu_cost import fixture


def mutable_ids(value):
    found = set()
    if isinstance(value, (dict, list)):
        found.add(id(value))
        for child in value.values() if isinstance(value, dict) else value:
            found.update(mutable_ids(child))
    return found


class PlanCopyTests(unittest.TestCase):
    def test_complete_values_and_no_mutable_aliases(self):
        for horizon in range(1, 5):
            model = fixture(horizon)
            model["memory_budget_bytes"] = 2
            planner = cost._Planner(cost.validate_model(model))
            for charge in (None, 0, 100):
                originals = planner.frontier(committed_call_ns=charge)
                copies = [cost._copy_plan(plan) for plan in originals]
                self.assertEqual(copies, deepcopy(originals))
                original_ids = mutable_ids(originals)
                seen = set()
                for plan in copies:
                    ids = mutable_ids(plan)
                    self.assertFalse(ids & original_ids)
                    self.assertFalse(ids & seen)
                    seen.update(ids)

    def test_generated_schema_has_only_the_copied_mutable_fields(self):
        model = fixture(4)
        model["memory_budget_bytes"] = 2
        for plan in cost._Planner(cost.validate_model(model)).frontier(committed_call_ns=100):
            self.assertEqual({k for k, v in plan.items() if type(v) in (dict, list)}, {"actions"})
            for action in plan["actions"]:
                self.assertEqual({k for k, v in action.items() if type(v) is list},
                                 {"ready_before", "ready_after", "acquired", "retired", "invalidated"})
                self.assertEqual({k for k, v in action.items() if type(v) is dict}, {"costs"})
                self.assertTrue(all(type(v) is int for v in action["costs"].values()))
                for key in ("ready_before", "ready_after", "acquired", "retired", "invalidated"):
                    self.assertTrue(all(type(v) is str for v in action[key]))

    def test_evolved_schema_falls_back_without_mutable_aliases(self):
        plan = cost._Planner(cost.validate_model(fixture(2))).frontier()[0]
        cases = []
        extra = deepcopy(plan); extra["future"] = {"nested": []}; cases.append(extra)
        extra = deepcopy(plan); extra["actions"][0]["future"] = []; cases.append(extra)
        extra = deepcopy(plan); extra["actions"][0]["mode"] = []; cases.append(extra)
        extra = deepcopy(plan); extra["close_ns"] = []; cases.append(extra)
        extra = deepcopy(plan); extra["actions"][0]["costs"]["gate_ns"] = []; cases.append(extra)
        extra = deepcopy(plan); extra["actions"][0]["ready_after"] = [[]]; cases.append(extra)
        extra = deepcopy(plan); extra["actions"] = tuple(extra["actions"]); cases.append(extra)
        for evolved in cases:
            with self.subTest(evolved=evolved), patch.object(cost, "deepcopy", wraps=deepcopy) as fallback:
                copied = cost._copy_plan(evolved)
                fallback.assert_called_once_with(evolved)
                self.assertEqual(copied, deepcopy(evolved))
                if type(evolved["actions"]) is list:
                    self.assertFalse(mutable_ids(copied) & mutable_ids(evolved))
        with patch.object(cost, "deepcopy", side_effect=AssertionError("unexpected fallback")):
            self.assertEqual(cost._copy_plan(plan), plan)

    def test_bundle_mutation_cannot_change_reused_planner_or_other_plans(self):
        model = cost.validate_model(fixture(4))
        planner = cost._Planner(model)
        before = deepcopy(planner.exact())
        bundle = cost._build_request(model, planner)
        expected = deepcopy(bundle)
        plans = list(bundle["plans"].values())
        siblings = deepcopy(plans[1:])
        action = plans[0]["actions"][-1]
        for key in ("ready_before", "ready_after", "acquired", "retired", "invalidated"):
            action[key].append("mutation")
        action["costs"]["execution_ns"] = -1
        self.assertEqual(plans[1:], siblings)
        self.assertEqual(planner.exact(), before)
        self.assertEqual(cost._build_request(model, planner), expected)


if __name__ == "__main__":
    unittest.main()
