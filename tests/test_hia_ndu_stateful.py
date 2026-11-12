"""Independent finite-model and refusal-accounting tests, without NDU imitation."""
from copy import deepcopy
import random
import unittest
from unittest.mock import patch

from hepta.hia_ndu import NduBridgeError
from hepta.hia_ndu_stateful import (
    SCHEMA_V2, StatefulPlanningError, build_request, digest, graph_fields, invocation_gate, observe_refusal,
    separability_diagnostic, validate_model)
from tools.qualify_hia_ndu_stateful import (
    SCALE, assert_agreement, canonical_schedules, fixtures)
from tools.qualify_hia_ndu_stateful_reference import (
    exact_dp_control, exhaustive_oracle, fixed_configuration_control, greedy_control,
    score_schedule)


class StatefulPreparationTests(unittest.TestCase):
    def test_v2_requires_explicit_future_cost_and_v1_rejects_new_fields(self):
        original = fixtures()[0]
        before = build_request(original)
        self.assertEqual(graph_fields(original)[0]["decision_cost_ns"], 0)
        self.assertNotIn("future_decision_cost_ns", before["stateful_binding"])
        for mutate in (
            lambda m: m.update(future_decision_cost_ns=0),
            lambda m: m.update(schema=SCHEMA_V2),
            lambda m: m.update(schema=SCHEMA_V2, future_decision_cost_ns=True),
            lambda m: m.update(schema=SCHEMA_V2, future_decision_cost_ns=-1),
            lambda m: m.update(schema=SCHEMA_V2, future_decision_cost_ns=1_000_000_000_000),
        ):
            bad = deepcopy(original)
            mutate(bad)
            with self.assertRaises(StatefulPlanningError):
                validate_model(bad)
        zero = {**original, "schema": SCHEMA_V2, "future_decision_cost_ns": 0}
        self.assertEqual(canonical_schedules(exhaustive_oracle(original)),
                         canonical_schedules(exhaustive_oracle(zero)))
        self.assertEqual(before, build_request(original))

    def test_future_decision_charge_changes_delayed_acquisition_and_stopping(self):
        model = fixtures()[1]
        cheap = {**model, "schema": SCHEMA_V2, "future_decision_cost_ns": SCALE}
        costly = {**model, "schema": SCHEMA_V2, "future_decision_cost_ns": 100 * SCALE}
        self.assertEqual(canonical_schedules(exhaustive_oracle(cheap)), {((), (), ("late",), ("late",))})
        self.assertEqual(canonical_schedules(exhaustive_oracle(costly)), {(("late",),) * 4})
        for value in (cheap, costly):
            oracle = exhaustive_oracle(value)
            dp = exact_dp_control(value)
            self.assertEqual(canonical_schedules(oracle), canonical_schedules(dp))
            self.assertEqual(oracle["best_value_q32"], dp["best_value_q32"])
            bundle = build_request(value, search="dynamic-light")
            assert_agreement(bundle, bundle["advice"], oracle, native=False)
        held = {**costly, "initial_ready": ["late"]}
        incumbent = score_schedule(held, [["late"]] * 4)
        self.assertEqual(incumbent["cost_ns"], 84 * SCALE)
        delayed = score_schedule(cheap, [[], [], ["late"], ["late"]])
        self.assertEqual(delayed["cost_ns"], (46 + 3) * SCALE)

    def test_nonzero_future_cost_enumeration_dp_and_graph_agree_on_independent_lengths(self):
        rng = random.Random(20261031)
        for number in range(32):
            model = deepcopy(fixtures()[2])
            horizon = number % 4 + 1
            model.update(schema=SCHEMA_V2, future_decision_cost_ns=rng.randrange(1, 3000),
                         budget_ns=rng.randrange(500, 14000), completion_value_ns=rng.randrange(0, 12000))
            model["baseline"]["latency_ns"] = [rng.randrange(1, 2000) for _ in range(horizon)]
            model["memory_budget_bytes"] = 64 if number % 2 else 128
            for variant in model["variants"]:
                variant.update(preparation_ns=rng.randrange(0, 2000),
                               latency_ns=[rng.randrange(1, 2000) for _ in range(horizon)],
                               holding_ns=[rng.randrange(0, 100) for _ in range(horizon)])
            if number % 5 == 0:
                model["initial_ready"] = ["early"]
            oracle = exhaustive_oracle(model)
            dp = exact_dp_control(model)
            with self.subTest(number=number, horizon=horizon):
                self.assertEqual(oracle["best_value_q32"], dp["best_value_q32"])
                self.assertEqual(canonical_schedules(oracle), canonical_schedules(dp))
                bundle = build_request(model, search="dynamic-light")
                assert_agreement(bundle, bundle["advice"], oracle, native=False)
                full = build_request(model, search="enumerate")
                values = [model["completion_value_ns"] * (1 << 32) // 1_000_000
                          - sum((a["setup_ns"] + a["decision_ns"]) * (1 << 32) // 1_000_000
                                + a["execution_ns"] * (1 << 32) // 1_000_000 for a in p["actions"])
                          for p in full["plans"].values() if p["verified"]
                          and p["estimated_cost_ns"] <= model["budget_ns"]]
                self.assertEqual(max([0, *values]), oracle["best_value_q32"])

    def test_strong_fixed_precommitment_is_not_charged_a_future_planner_stop(self):
        model = {**fixtures()[1], "schema": SCHEMA_V2, "future_decision_cost_ns": 100 * SCALE}
        original = deepcopy(model)
        fixed = fixed_configuration_control(model)
        active = exact_dp_control(model)
        self.assertEqual({row["cost_ns"] for row in fixed["winners"]}, {104 * SCALE})
        self.assertEqual({row["cost_ns"] for row in active["winners"]}, {204 * SCALE})
        self.assertGreater(fixed["best_value_q32"], active["best_value_q32"])
        self.assertEqual(fixed["future_controller_calls"], 0)
        self.assertEqual(model, original)

    def test_invocation_gate_uses_optimistic_complete_savings_not_current_batch_only(self):
        model = fixtures()[0]
        before = deepcopy(model)
        result = invocation_gate(model, invocation_cost_ns=100 * SCALE)
        self.assertTrue(result["invoke"])
        self.assertEqual(result["gross_savings_upper_bound_ns"], 347 * SCALE)
        result = invocation_gate(model, invocation_cost_ns=347 * SCALE)
        self.assertFalse(result["invoke"])
        self.assertEqual(result["reason"], "optimistic_savings_cannot_repay_invocation")
        self.assertEqual(model, before)
        self.assertEqual(result["authority"], "DENY_ALL")
        self.assertFalse(result["safety_certificate"])
        for bad in (True, -1, 1.5, 1_000_000_000_001):
            with self.assertRaises(StatefulPlanningError):
                invocation_gate(model, invocation_cost_ns=bad)

    def test_invocation_gate_respects_refusal_residency_and_prepared_reuse(self):
        model = fixtures()[0]
        model["variants"][0]["status"] = "rejected"
        self.assertFalse(invocation_gate(model, invocation_cost_ns=0)["invoke"])
        model = fixtures()[0]
        model["memory_budget_bytes"] = 0
        self.assertFalse(invocation_gate(model, invocation_cost_ns=0)["invoke"])
        model = fixtures()[4]
        result = invocation_gate(model, invocation_cost_ns=1)
        self.assertEqual(result["gross_savings_upper_bound_ns"], 0)
        self.assertEqual(result["incumbent_delivery_ns"], 4 * SCALE)
        self.assertFalse(result["invoke"])
        model = fixtures()[0]
        model["budget_ns"] = 1
        self.assertEqual(invocation_gate(model, invocation_cost_ns=1)["reason"],
                         "invocation_and_optimistic_delivery_exceed_budget")

    def test_invocation_savings_bound_is_optimistic_against_independent_complete_schedules(self):
        for original in fixtures():
            model = {**original, "schema": SCHEMA_V2, "future_decision_cost_ns": 11 * SCALE}
            result = invocation_gate(model, invocation_cost_ns=5 * SCALE)
            oracle = exhaustive_oracle(model)
            for winner in oracle["winners"]:
                self.assertLessEqual(result["optimistic_delivery_lower_bound_ns"], winner["cost_ns"])
                if not result["invoke"] and result["reason"] == "optimistic_savings_cannot_repay_invocation":
                    self.assertLessEqual(result["incumbent_delivery_ns"],
                                         winner["cost_ns"] + result["invocation_cost_ns"])

    def test_independent_oracle_resource_dp_and_existing_q32_planner_agree(self):
        for model in fixtures():
            with self.subTest(case=model["name"]):
                oracle = exhaustive_oracle(model)
                independent = exact_dp_control(model)
                self.assertEqual(oracle["best_value_q32"], independent["best_value_q32"])
                self.assertEqual(canonical_schedules(oracle), canonical_schedules(independent))
                bundle = build_request(model, search="dynamic-light")
                assert_agreement(bundle, bundle["advice"], oracle, native=False)

    def test_nanosecond_rounding_constraints_and_holding_match_independent_enumeration(self):
        randomizer = random.Random(20261030)
        for number in range(32):
            model = deepcopy(fixtures()[2])
            model["baseline"]["latency_ns"] = [randomizer.randrange(1, 2000) for _ in range(4)]
            model["budget_ns"] = randomizer.randrange(100, 10_000)
            model["completion_value_ns"] = randomizer.randrange(0, 10_000)
            model["memory_budget_bytes"] = 128 if number % 2 else 64
            for variant in model["variants"]:
                variant["preparation_ns"] = randomizer.randrange(0, 2000)
                variant["latency_ns"] = [randomizer.randrange(1, 2000) for _ in range(4)]
                variant["holding_ns"] = [randomizer.randrange(0, 100) for _ in range(4)]
            with self.subTest(number=number):
                oracle = exhaustive_oracle(model)
                independent = exact_dp_control(model)
                self.assertEqual(oracle["best_value_q32"], independent["best_value_q32"])
                self.assertEqual(canonical_schedules(oracle), canonical_schedules(independent))
                bundle = build_request(model, search="dynamic-light")
                assert_agreement(bundle, bundle["advice"], oracle, native=False)

    def test_delayed_payback_defeats_myopic_control_but_not_strong_fixed_configuration(self):
        model = fixtures()[0]
        oracle = exhaustive_oracle(model)
        fixed = fixed_configuration_control(model)
        greedy = greedy_control(model)
        self.assertGreater(oracle["best_value_q32"], greedy["best_value_q32"])
        self.assertEqual(oracle["best_value_q32"], fixed["best_value_q32"])
        self.assertEqual({row["cost_ns"] for row in oracle["winners"]}, {173 * SCALE})
        self.assertEqual(greedy["attempted_schedule"]["cost_ns"], 400 * SCALE)

    def test_residency_makes_waiting_meaningful_but_same_information_greedy_also_succeeds(self):
        model = fixtures()[1]
        oracle = exhaustive_oracle(model)
        fixed = fixed_configuration_control(model)
        greedy = greedy_control(model)
        self.assertGreater(oracle["best_value_q32"], fixed["best_value_q32"])
        self.assertEqual(oracle["best_value_q32"], greedy["best_value_q32"])
        self.assertEqual(canonical_schedules(oracle), {((), (), ("late",), ("late",))})
        self.assertEqual({row["cost_ns"] for row in oracle["winners"]}, {46 * SCALE})
        self.assertEqual({row["cost_ns"] for row in fixed["winners"]}, {104 * SCALE})

    def test_preparation_is_paid_once_and_residency_survives_stop(self):
        model = fixtures()[1]
        model["initial_ready"] = ["late"]
        model["sunk_cost_ns"] = 20 * SCALE
        fields, binding = graph_fields(model)
        self.assertEqual(fields["transitions"], [])
        self.assertEqual(binding["sunk_cost_ns"], 20 * SCALE)
        bundle = build_request(model, search="enumerate")
        for plan in bundle["plans"].values():
            self.assertEqual(sum(action["setup_ns"] for action in plan["actions"]), 0)
            self.assertEqual(plan["estimated_cost_ns"], 84 * SCALE)
            self.assertEqual([action["execution_ns"] for action in plan["actions"]],
                             [39 * SCALE, 39 * SCALE, 3 * SCALE, 3 * SCALE])

    def test_resident_memory_excludes_combined_specializations_for_every_control(self):
        model = fixtures()[2]
        fields, binding = graph_fields(model)
        combined = [state for state, row in binding["states"].items() if len(row["ready"]) == 2]
        self.assertEqual(len(combined), 1)
        self.assertEqual(fields["states"][combined[0]]["status"], "rejected")
        for control in (exhaustive_oracle, exact_dp_control, fixed_configuration_control, greedy_control):
            self.assertTrue(all(len(ready) <= 1 for row in control(model)["winners"] for ready in row["schedule"]))
        with self.assertRaises(ValueError):
            score_schedule(model, [["early", "late"]] * 4)

    def test_refusal_updates_generation_budget_snapshot_and_never_reuses_projected_benefit(self):
        original = fixtures()[0]
        old = deepcopy(original)
        before = build_request(original)
        refusal_digest = digest("actual-caller-supplied-refusal-event")
        observed = observe_refusal(original, variant_id="fast", actual_attempt_ns=30 * SCALE,
                                   observation_digest=refusal_digest)
        self.assertEqual(original, old)
        self.assertEqual(observed["generation"], 2)
        self.assertEqual(observed["budget_ns"], original["budget_ns"] - 30 * SCALE)
        self.assertEqual(observed["sunk_cost_ns"], 30 * SCALE)
        self.assertEqual(observed["variants"][0]["status"], "rejected")
        after = build_request(observed, search="dynamic-light")
        after_fields, _ = graph_fields(observed)
        self.assertNotEqual(before["request"]["snapshot_digest"], after_fields["snapshot_digest"])
        oracle = exhaustive_oracle(observed)
        self.assertEqual(canonical_schedules(oracle), {((), (), (), ())})
        self.assertEqual({row["cost_ns"] for row in oracle["winners"]}, {400 * SCALE})
        assert_agreement(after, after["advice"], oracle, native=False)
        with self.assertRaisesRegex(StatefulPlanningError, "already consumed"):
            observe_refusal(observed, variant_id="fast", actual_attempt_ns=30 * SCALE,
                            observation_digest=refusal_digest)

    def test_refusal_overrun_preserves_the_loss_and_forces_literal_abstention(self):
        model = fixtures()[0]
        model["budget_ns"] = 10
        observed = observe_refusal(model, variant_id="fast", actual_attempt_ns=20,
                                   observation_digest=digest("overrun"))
        self.assertEqual(observed["budget_ns"], 0)
        self.assertEqual(observed["sunk_cost_ns"], 20)
        self.assertEqual(observed["observations"][-1]["budget_overrun_ns"], 10)
        oracle = exhaustive_oracle(observed)
        self.assertTrue(oracle["abstain_is_optimal"])
        self.assertEqual(oracle["winners"], [])
        bundle = build_request(observed, search="dynamic-light")
        assert_agreement(bundle, bundle["advice"], oracle, native=False)

    def test_already_prepared_additive_profile_has_a_separability_certificate_only(self):
        model = fixtures()[4]
        diagnostic = separability_diagnostic(model)
        self.assertTrue(diagnostic["stepwise_minimum_is_finite_global_minimum"])
        self.assertEqual(diagnostic["minimum_execution_ns"], 4 * SCALE)
        self.assertFalse(diagnostic["continuation_advantage_established"])
        self.assertFalse(separability_diagnostic(fixtures()[0])["stepwise_minimum_is_finite_global_minimum"])

    def test_original_uncompressed_path_limit_refuses_without_a_partial_optimum(self):
        model = fixtures()[-1]
        with self.assertRaisesRegex(NduBridgeError, "complete enumeration exceeds"):
            build_request(model, search="enumerate")
        bundle = build_request(model, search="dynamic-frontier")
        self.assertTrue(bundle["search_complete"])
        self.assertFalse(bundle["enumeration_complete"])
        self.assertLessEqual(len(bundle["request"]["candidates"]), 128)

    def test_intake_rejects_incomplete_unknown_boolean_and_unhashable_fields(self):
        mutations = [
            lambda model: model.update(budget_ns=True),
            lambda model: model.update(budget_ns=1.5),
            lambda model: model.update(cost_basis=[]),
            lambda model: model.update(unknown=1),
            lambda model: model["variants"][0].update(status=[]),
            lambda model: model["variants"][0].update(verification_sha256="0" * 64),
            lambda model: model.update(initial_ready=["missing"]),
            lambda model: model["variants"][0].pop("holding_ns"),
        ]
        for number, mutate in enumerate(mutations):
            model = fixtures()[0]
            mutate(model)
            with self.subTest(number=number), self.assertRaises(StatefulPlanningError):
                validate_model(model)
        with self.assertRaises(StatefulPlanningError):
            observe_refusal(fixtures()[0], variant_id=[], actual_attempt_ns=1,
                            observation_digest=digest("bad-id"))

    def test_bounded_intake_detaches_before_validation_and_rejects_subclasses_and_depth(self):
        from hepta.hia_program_tools import bounded_json_wire
        model = fixtures()[0]
        expected = deepcopy(model)
        def mutate_after_snapshot(value, *args, **kwargs):
            encoded = bounded_json_wire(value, *args, **kwargs)
            value["budget_ns"] = -1
            value["variants"][0]["status"] = "rejected"
            return encoded
        with patch("hepta.hia_program_tools.bounded_json_wire", side_effect=mutate_after_snapshot):
            admitted = validate_model(model)
        self.assertEqual(admitted, expected)
        self.assertEqual(model["budget_ns"], -1)
        class CustomDict(dict):
            pass
        malformed = fixtures()[0]
        malformed["baseline"] = CustomDict(malformed["baseline"])
        with self.assertRaises(StatefulPlanningError):
            validate_model(malformed)
        malformed = fixtures()[0]
        nested = {}
        for _ in range(34):
            nested = {"nested": nested}
        malformed["observations"] = [nested]
        with self.assertRaises(StatefulPlanningError):
            validate_model(malformed)


if __name__ == "__main__":
    unittest.main()
