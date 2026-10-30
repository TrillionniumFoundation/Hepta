"""Independent choice enumeration and adversarial portfolio contract checks."""
from copy import deepcopy
import random
import unittest

from hepta.hia_portfolio import (PortfolioRejected, Q32, canonical, digest,
    exact_portfolio, exhaustive_portfolio_oracle, lightweight_portfolio,
    native_portfolio_request, selected_plan, validate_problem)


def problem(costs=((9, 4, 3), (9, 3, 6), (9, 5, 2)), *, activation=(0, 2, 5)):
    names = ("base", "small", "wide")
    return {"schema": "hepta.hia.portfolio.problem.v1",
        "objective_sha256": digest("fixed-completion-value-and-resource-contract"),
        "snapshot_sha256": digest(costs), "generation": 1,
        "artifacts": {name: {"activation_ns": setup, "retained_bytes": i + 1,
            "verification_sha256": digest([name, "upstream-proof"]),
            "source_sha256": digest([name, "source"]), "status": "verified"}
            for i, (name, setup) in enumerate(zip(names, activation, strict=True))},
        "regions": [{"id": f"r{i}", "options": [
            {"artifact": name, "run_ns": run, "scratch_bytes": 1 + j,
             "support_sha256": digest([i, name, run])}
            for j, (name, run) in enumerate(zip(names, row, strict=True))]}
            for i, row in enumerate(costs)],
        "initial_artifacts": [], "budget_ns": 10_000_000,
        "retained_bytes_limit": 6, "scratch_bytes_limit": 3,
        "completion_value_ns": 20_000_000}


def normalized(result):
    return {"plans": result["plans"], "values_q32": result["values_q32"],
            "pareto_candidate_ids": result["pareto_candidate_ids"],
            "advisory_candidate_id": result["advisory_candidate_id"]}


class PortfolioTests(unittest.TestCase):
    def test_independent_oracle_matches_multiresource_dp(self):
        rng = random.Random(920613)
        for case in range(80):
            regions = rng.randrange(1, 6)
            p = problem(tuple(tuple(rng.randrange(0, 1000) for _ in range(3)) for _ in range(regions)),
                        activation=tuple(rng.randrange(0, 1000) for _ in range(3)))
            p.update(budget_ns=rng.randrange(100, 6500), retained_bytes_limit=rng.randrange(1, 7),
                     scratch_bytes_limit=rng.randrange(1, 4))
            if case % 3 == 0:
                p["initial_artifacts"] = ["base"]
            with self.subTest(case=case):
                self.assertEqual(normalized(exact_portfolio(p)), normalized(exhaustive_portfolio_oracle(p)))

    def test_shared_build_is_charged_once_not_once_per_region(self):
        p = problem(((20, 2, 100), (20, 2, 100), (20, 2, 100)), activation=(0, 15, 0))
        plan = selected_plan(exact_portfolio(p))
        self.assertEqual(plan["choices"], ["small"] * 3)
        self.assertEqual(plan["cost_ns"], 21)
        self.assertEqual([e["id"] for e in plan["events"] if e["kind"] == "activation"], ["small"])

    def test_paid_artifact_stays_retained_without_double_setup_charge(self):
        p = problem(((20, 2, 100),), activation=(0, 15, 0))
        p["initial_artifacts"] = ["small"]
        plan = selected_plan(exact_portfolio(p))
        self.assertEqual(plan["cost_ns"], 2)
        self.assertEqual(plan["retained_bytes"], 2)
        self.assertEqual([e for e in plan["events"] if e["kind"] == "activation"], [])

    def test_paid_artifact_prevents_incorrect_capacity_release(self):
        p = problem(((50, 100, 1),), activation=(0, 0, 0))
        p.update(initial_artifacts=["small"], retained_bytes_limit=3)
        result = exact_portfolio(p)
        self.assertTrue(all("wide" not in x["choices"] for x in result["plans"]))
        self.assertEqual(selected_plan(result)["choices"], ["base"])

    def test_cheap_unverified_and_over_scratch_candidates_cannot_win(self):
        p = problem(((10, 0, 0),), activation=(0, 0, 0))
        p["artifacts"]["small"]["status"] = "rejected"
        p["scratch_bytes_limit"] = 1
        result = exact_portfolio(p)
        self.assertEqual(selected_plan(result)["choices"], ["base"])
        self.assertGreater(result["work"]["verification_exclusions"], 0)
        self.assertGreater(result["work"]["capacity_exclusions"], 0)

    def test_exact_budget_equality_and_plus_one_failure(self):
        p = problem(((10, 20, 30),), activation=(0, 0, 0))
        p["budget_ns"] = 10
        self.assertEqual(selected_plan(exact_portfolio(p))["cost_ns"], 10)
        p["budget_ns"] = 9
        self.assertEqual(exact_portfolio(p)["pareto_candidate_ids"], ["abstain"])

    def test_all_equal_value_witnesses_remain_explicit(self):
        p = problem(((1, 1, 1), (1, 1, 1)), activation=(0, 0, 0))
        result = exact_portfolio(p)
        self.assertEqual(len(result["plans"]), 9)
        self.assertEqual(len(result["pareto_candidate_ids"]), 9)
        self.assertIsNone(selected_plan(result))
        self.assertEqual(normalized(result), normalized(exhaustive_portfolio_oracle(p)))

    def test_witness_limit_does_not_manufacture_unique_optimum(self):
        p = problem(((1, 1, 1),) * 5, activation=(0, 0, 0))
        with self.assertRaisesRegex(PortfolioRejected, "witness|frontier"):
            exact_portfolio(p)

    def test_q32_per_event_rounding_not_round_total(self):
        p = problem(((2, 100, 100), (2, 100, 100)), activation=(2, 0, 0))
        plan = selected_plan(exact_portfolio(p))
        self.assertEqual(plan["debit_q32"], 3 * (2 * Q32 // 1_000_000))
        self.assertNotEqual(plan["debit_q32"], 6 * Q32 // 1_000_000)

    def test_all_net_negative_paths_choose_literal_abstain(self):
        p = problem(((100, 100, 100),), activation=(0, 0, 0))
        p["completion_value_ns"] = 50
        self.assertEqual(exact_portfolio(p)["pareto_candidate_ids"], ["abstain"])

    def test_work_and_state_exhaustion_have_no_partial_receipt(self):
        for kwargs in ({"max_work": 1}, {"max_states": 1}, {"max_witnesses": 1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(PortfolioRejected):
                exact_portfolio(problem(), **kwargs)

    def test_small_oracle_refuses_large_cartesian_space(self):
        with self.assertRaisesRegex(PortfolioRejected, "oracle bound"):
            exhaustive_portfolio_oracle(problem(((2, 3, 4),) * 20))

    def test_bounded_large_graph_is_exact_without_enumerating_every_path(self):
        p = problem(tuple((100000 + i * 71, 20000 + i * 41, 30000 + i * 53) for i in range(20)),
                    activation=(0, 600, 900))
        result = exact_portfolio(p)
        self.assertEqual(selected_plan(result)["choices"], ["small"] * 20)
        self.assertLess(result["work"]["generated_labels"], 20_000)
        self.assertTrue(result["complete_within_declared_model"])

    def test_lightweight_control_is_compared_as_heuristic(self):
        p = problem()
        dp, light = exact_portfolio(p), lightweight_portfolio(p)
        self.assertFalse(light["complete_within_declared_model"])
        self.assertGreaterEqual(max(dp["values_q32"].values()), max(light["values_q32"].values()))
        with self.assertRaises(PortfolioRejected):
            native_portfolio_request(p, light)

    def test_unknown_fields_boolean_costs_and_bad_identity_reject(self):
        variants = []
        p = problem(); p["hidden_future_times"] = []; variants.append(p)
        p = problem(); p["budget_ns"] = True; variants.append(p)
        p = problem(); p["snapshot_sha256"] = "0" * 64; variants.append(p)
        p = problem(); p["generation"] = 0; variants.append(p)
        p = problem(); p["regions"][0]["options"].append(deepcopy(p["regions"][0]["options"][0])); variants.append(p)
        p = problem(); p["initial_artifacts"] = ["base", "base"]; variants.append(p)
        p = problem(); p["artifacts"]["small"]["activation_ns"] = -1; variants.append(p)
        for p in variants:
            with self.subTest(problem=p), self.assertRaises(PortfolioRejected):
                validate_problem(p)

    def test_complete_model_snapshot_binds_paths_and_native_request(self):
        p = problem()
        result = exact_portfolio(p)
        request = native_portfolio_request(p, result)
        self.assertEqual(request["schema"], "hepta.hia.ndu.request.v1")
        self.assertEqual(len(request["candidates"]), len(result["plans"]) + 1)
        for plan, candidate in zip(result["plans"], request["candidates"], strict=False):
            self.assertEqual(candidate["id"], plan["id"])
            self.assertEqual(candidate["terminal_q32"] + sum(e["instant_q32"] for e in candidate["events"]), plan["value_q32"])
        changed = deepcopy(p); changed["artifacts"]["small"]["activation_ns"] += 1
        with self.assertRaisesRegex(PortfolioRejected, "matching"):
            native_portfolio_request(changed, result)
        tampered = deepcopy(result); tampered["plans"][0]["cost_ns"] = 0
        with self.assertRaisesRegex(PortfolioRejected, "drift"):
            native_portfolio_request(p, tampered)
        self.assertEqual(canonical(p), canonical(deepcopy(p)))

    def test_unknown_native_advice_cannot_select_executable(self):
        with self.assertRaises(PortfolioRejected):
            selected_plan(exact_portfolio(problem()), {"advisory_candidate_id": "not-retained"})


if __name__ == "__main__":
    unittest.main()
