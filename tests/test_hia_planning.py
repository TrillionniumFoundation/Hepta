"""Independent exhaustive/native checks of finite-graph candidate compression."""
from copy import deepcopy
from fractions import Fraction
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import unittest

from hepta.hia_ndu import NduBridge, NduBridgeError, Q32, finite_plan_request
from hepta.hia_planning import compact_finite_plan_request, exact_finite_plan


def fields(*, states=3, horizon=3):
    names = [f"state-{i}" for i in range(states)]
    return {"objective_digest": "1" * 64, "snapshot_digest": "2" * 64, "generation": 1,
            "initial_state": names[0],
            "states": {name: {"source_sha256": f"{i + 3:064x}",
                               "verification_sha256": f"{i + 13:064x}", "status": "verified"}
                       for i, name in enumerate(names)},
            "transitions": [{"id": f"move-{i}-{j}", "source": source, "target": target,
                             "setup_ns": 1_000_000 + 73 * i + 19 * j,
                             "status": "verified", "verification_sha256": f"{j + 13:064x}",
                             "support_sha256": f"{i * states + j + 101:064x}"}
                            for i, source in enumerate(names) for j, target in enumerate(names) if i != j],
            "batch_costs_ns": {name: [(i + 1) * 1_000_000 + 31 * batch for batch in range(horizon)]
                               for i, name in enumerate(names)},
            "remaining_budget_ns": 100_000_000, "completion_value_ns": 200_000_000,
            "decision_cost_ns": 50_000, "observations": []}


def exact_value(row):
    """Rational, ties-to-even recursion independent of the pruning debit sum."""
    value = row["terminal_q32"]
    for step in reversed(row["events"]):
        value = step["instant_q32"] + round(Fraction(step["discount_q32"] * value, Q32))
    return value


def oracle(request):
    feasible = [row for row in request["candidates"] if row["verified"]
                and row["resource_cost_q32"] <= request["resource_budget_q32"]
                and row["risk_q32"] <= request["risk_ceiling_q32"]]
    values = {row["id"]: exact_value(row) for row in feasible}
    maximum = max(values.values())
    return {name for name, value in values.items() if value == maximum}


def best_per_first_action(bundle):
    groups = {}
    for row in bundle["request"]["candidates"]:
        if row["id"] == "abstain" or not row["verified"]:
            continue
        if row["resource_cost_q32"] > bundle["request"]["resource_budget_q32"]:
            continue
        first = bundle["plans"][row["id"]]["actions"][0]["id"]
        groups.setdefault(first, []).append(row)
    result = set()
    for rows in groups.values():
        value = max(exact_value(row) for row in rows)
        result.update(row["id"] for row in rows if exact_value(row) == value)
    return result


def independent_large_oracle(item):
    """Direct path expansion, with no production DP or wire-builder calls.

    Return every best feasible path per first action, including every tie. The
    separate representation expands a stop into all remaining delivery steps.
    Its Fraction conversion computes the declared profile's integer wire value.
    """
    horizon = len(item["batch_costs_ns"][item["initial_state"]])
    paths = []

    def visit(state, batch, prefix):
        if batch == horizon:
            paths.append(prefix)
            return
        remainder = [("stop" if k == batch else "stopped", "stop", state, state, k, 0,
                      "verified", item["states"][state]["verification_sha256"])
                     for k in range(batch, horizon)]
        paths.append(prefix + remainder)
        for edge in item["transitions"]:
            if edge["source"] == state:
                step = ("transition", edge["id"], state, edge["target"], batch,
                        edge["setup_ns"], edge["status"], edge["verification_sha256"])
                visit(edge["target"], batch + 1, prefix + [step])
        if batch + 1 < horizon:
            step = ("hold", "hold", state, state, batch, 0, "verified",
                    item["states"][state]["verification_sha256"])
            visit(state, batch + 1, prefix + [step])

    visit(item["initial_state"], 0, [])
    groups = {}
    verified_count = 0
    for path in paths:
        if any(status != "verified" or item["states"][target]["status"] != "verified"
               for _, _, _, target, _, _, status, _ in path):
            continue
        verified_count += 1
        actions = []
        debit, cost = 0, 0
        for mode, identity, source, target, batch, setup, status, proof in path:
            decision = item["decision_cost_ns"] if batch > 0 and mode != "stopped" else 0
            execution = item["batch_costs_ns"][target][batch]
            actions.append({"id": identity, "mode": mode, "source": source, "target": target,
                            "batch": batch, "setup_ns": setup, "decision_ns": decision,
                            "execution_ns": execution, "status": status, "verification_sha256": proof})
            cost += setup + decision + execution
            for value in (setup + decision, execution):
                fraction = Fraction(value * Q32, 1_000_000)
                debit += fraction.numerator // fraction.denominator
        if cost > item["remaining_budget_ns"]:
            continue
        identity = "plan-" + sha256(json.dumps(actions, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:24]
        groups.setdefault(actions[0]["id"], []).append((debit, identity))
    selected = set()
    for candidates in groups.values():
        minimum = min(value for value, _ in candidates)
        selected.update(identity for value, identity in candidates if value == minimum)
    return len(paths), verified_count, selected


def cases(count=80):
    rng = random.Random(76129)
    for index in range(count):
        item = fields(states=2 + index % 2, horizon=1 + index % 4)
        item["remaining_budget_ns"] = rng.randrange(0, 120)
        item["completion_value_ns"] = rng.randrange(0, 120)
        item["decision_cost_ns"] = rng.randrange(0, 5)
        for costs in item["batch_costs_ns"].values():
            costs[:] = [rng.randrange(0, 35) for _ in costs]
        for edge in item["transitions"]:
            edge["setup_ns"] = rng.randrange(0, 9)
            edge["status"] = rng.choice(("verified", "verified", "unknown", "rejected", "timeout"))
        if index % 7 == 0:
            item["states"]["state-1"]["status"] = "unknown"
        yield item


class FiniteCompressionTests(unittest.TestCase):
    def assert_same_frontier(self, item):
        full = finite_plan_request(**item)
        compact = compact_finite_plan_request(**item)
        self.assertEqual(set(compact["plans"]), best_per_first_action(full))
        self.assertEqual(oracle(full["request"]), oracle(compact["request"]))
        exact = exact_finite_plan(**item)
        self.assertEqual(set(exact["advice"]["pareto_candidate_ids"]), oracle(full["request"]))
        self.assertNotIn("request", exact)
        self.assertFalse(exact["native_evaluation"])
        evidence = compact["search_evidence"]
        self.assertEqual(evidence["covered_path_count"], len(full["plans"]))
        self.assertEqual(evidence["verified_path_count"], sum(p["verified"] for p in full["plans"].values()))
        self.assertEqual(evidence["covered_path_count"] - evidence["verified_path_count"],
                         sum(row["count"] for row in evidence["excluded_verification_path_counts"]))
        self.assertEqual(full["graph_sha256"], compact["graph_sha256"])
        self.assertFalse(compact["enumeration_complete"])
        self.assertTrue(compact["search_complete"])
        self.assertEqual(compact["authority"], "DENY_ALL")
        return full, compact

    def test_differential_against_exhaustive_paths_with_costs_ties_and_rejections(self):
        for index, item in enumerate(cases()):
            with self.subTest(case=index):
                self.assert_same_frontier(item)

    def test_q32_per_event_rounding_is_not_total_nanosecond_tie_breaking(self):
        item = fields(states=2, horizon=1)
        item["batch_costs_ns"] = {"state-0": [2], "state-1": [1]}
        item["transitions"] = [dict(item["transitions"][0], setup_ns=1)]
        full, compact = self.assert_same_frontier(item)
        stop = next(row for row in full["plans"].values() if row["actions"][0]["id"] == "stop")
        move = next(row for row in full["plans"].values() if row["actions"][0]["id"] == "move-0-1")
        self.assertEqual(stop["estimated_cost_ns"], move["estimated_cost_ns"])
        self.assertEqual(oracle(full["request"]), {move["id"]})
        values = {row["id"]: exact_value(row) for row in compact["request"]["candidates"]}
        self.assertEqual(values[move["id"]] - values[stop["id"]], 1)

    def test_complete_native_ties_are_preserved_even_with_different_first_actions(self):
        item = fields(states=2, horizon=2)
        item["decision_cost_ns"] = 0
        item["batch_costs_ns"] = {name: [1_000_000, 1_000_000] for name in item["states"]}
        for edge in item["transitions"]:
            edge["setup_ns"] = 0
        full, compact = self.assert_same_frontier(item)
        self.assertGreater(len(oracle(compact["request"])), 1)
        self.assertEqual(set(full["plans"]), set(compact["plans"]))

    def test_large_graph_exceeds_enumeration_cap_but_compresses_without_partial_search(self):
        item = fields(states=5, horizon=4)
        with self.assertRaisesRegex(NduBridgeError, "complete enumeration"):
            finite_plan_request(**item)
        compact = compact_finite_plan_request(**item)
        self.assertEqual(compact["search_evidence"]["covered_path_count"], 656)
        self.assertLess(len(compact["plans"]), 127)
        self.assertTrue(compact["search_evidence"]["complete_native_winning_frontier_preserved"])
        winner = next(iter(oracle(compact["request"])))
        self.assertEqual(compact["plans"][winner]["actions"][0]["mode"], "stop")

    def test_656_path_graph_matches_independent_exhaustive_all_first_action_oracle(self):
        rng = random.Random(901)
        for case in range(8):
            item = fields(states=5, horizon=4)
            item["remaining_budget_ns"] = 80 + case * 11
            item["decision_cost_ns"] = case % 4
            for costs in item["batch_costs_ns"].values():
                costs[:] = [rng.randrange(1, 70) for _ in costs]
            for edge in item["transitions"]:
                edge["setup_ns"] = rng.randrange(0, 20)
                edge["status"] = rng.choice(("verified", "verified", "verified", "unknown", "timeout"))
            with self.subTest(case=case):
                count, verified, expected = independent_large_oracle(item)
                compact = compact_finite_plan_request(**item)
                self.assertEqual(count, 656)
                self.assertEqual(compact["search_evidence"]["covered_path_count"], count)
                self.assertEqual(compact["search_evidence"]["verified_path_count"], verified)
                self.assertEqual(set(compact["plans"]), expected)

    def test_exponential_equal_value_frontier_is_refused_without_laundering_ambiguity(self):
        item = fields(states=5, horizon=4)
        item["decision_cost_ns"] = 0
        item["batch_costs_ns"] = {name: [0] * 4 for name in item["states"]}
        for edge in item["transitions"]:
            edge["setup_ns"] = 0
        with self.assertRaisesRegex(NduBridgeError, "complete tied witnesses"):
            compact_finite_plan_request(**item)

    def test_stop_delivers_remaining_work_and_literal_abstention_stays_distinct(self):
        item = fields(states=2, horizon=2)
        item["transitions"] = []
        item["remaining_budget_ns"] = 0
        compact = compact_finite_plan_request(**item)
        self.assertEqual(set(row["id"] for row in compact["request"]["candidates"]), {"abstain"})
        item["remaining_budget_ns"] = 100_000_000
        item["completion_value_ns"] = 0
        full, compact = self.assert_same_frontier(item)
        self.assertTrue(compact["plans"])
        self.assertEqual(oracle(compact["request"]), {"abstain"})
        self.assertGreater(next(iter(compact["plans"].values()))["estimated_cost_ns"], 0)

    def test_current_state_and_intake_cannot_bypass_original_validator(self):
        item = fields()
        item["states"][item["initial_state"]]["status"] = "unknown"
        with self.assertRaisesRegex(NduBridgeError, "current executable"):
            compact_finite_plan_request(**item)
        with self.assertRaises(NduBridgeError):
            finite_plan_request(**fields(), search=[])
        with self.assertRaises(NduBridgeError):
            compact_finite_plan_request(**fields(), search="enumerate")


@unittest.skipUnless(os.environ.get("HEPTA_FINITE_NDU_IDENTITY") and os.environ.get("HEPTA_FINITE_NDU_BRIDGE"),
                     "requires the separately pinned finite NDU executable and identity")
class NativeFiniteCompressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bridge = NduBridge.from_finite_environment()

    def test_native_full_and_compact_requests_have_identical_complete_winning_frontiers(self):
        for index, item in enumerate(cases(24)):
            with self.subTest(case=index):
                full = finite_plan_request(**item)
                compact = compact_finite_plan_request(**item)
                a = self.bridge.evaluate(full["request"])
                b = self.bridge.evaluate(compact["request"])
                exact = exact_finite_plan(**item)["advice"]
                self.assertEqual(a["identity"], b["identity"])
                self.assertEqual(a["disposition"], b["disposition"])
                self.assertEqual(a["advisory_candidate_id"], b["advisory_candidate_id"])
                self.assertEqual(a["pareto_candidate_ids"], b["pareto_candidate_ids"])
                for key in ("advisory_candidate_id", "pareto_candidate_ids", "disposition"):
                    self.assertEqual(a[key], exact[key])
                self.assertEqual(set(a["pareto_candidate_ids"]), oracle(full["request"]))
                self.assertFalse(b["safety_certificate"])


if __name__ == "__main__":
    unittest.main()
