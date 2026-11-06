"""Mechanism coverage without modifying or relabelling the earlier episode study."""
from copy import deepcopy
from dataclasses import asdict, replace
from fractions import Fraction
import itertools
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiments.hia_ndu_feedback_20261106 import model, coverage


class RecordingBackend:
    def __init__(self):
        self.calls = 0
    def evaluate(self, candidates, **kwargs):
        self.calls += 1
        return model.scalar_backend(candidates, **kwargs)


def state(scenario, observation, families=("supplied-boundary",)):
    raw = {"scenario": asdict(scenario), "observation": asdict(observation)}
    return {"id": model.digest(raw), **raw, "families": list(families)}


class StateCoverageTests(unittest.TestCase):
    def test_complete_declared_supplied_grid_is_not_a_winner_sample(self):
        p = coverage.load_protocol()
        cases = list(coverage.supplied_states(p))
        self.assertEqual(len(cases), 3030)
        self.assertEqual(sum(m["family"] == "supplied-grid" for _, _, m in cases), 1080)
        self.assertEqual(sum(m["family"] == "supplied-boundary" for _, _, m in cases), 1950)
        self.assertEqual(len({m["id"] for _, _, m in cases}), 3030)
        self.assertTrue(all(m["natural_posterior_claim"] is False for _, _, m in cases))
        boundary = [o for _, o, m in cases if m["family"] == "supplied-boundary"]
        self.assertEqual({o.belief for o in boundary}, {Fraction(n, 64) for n in range(65)})
        self.assertEqual({o.budget for o in boundary}, set(range(9, 14)))

    def test_whole_natural_request_signal_support_has_exact_mass(self):
        p = coverage.load_protocol()
        profiles = list(coverage.natural_profiles(p))
        self.assertEqual(len(profiles), 54)
        for name, scenario in profiles:
            tapes = list(itertools.product(p["natural_support"]["alphabet"], repeat=3))
            probabilities = [coverage.tape_probability(scenario, t) for t in tapes]
            self.assertEqual(len(tapes), 64)
            self.assertEqual(sum(probabilities), 1, name)
            self.assertTrue(all(v > 0 for v in probabilities))

    def test_natural_posterior_is_derived_from_prefix_not_supplied_guess(self):
        scenario = model.SCENARIOS["adaptive"]
        seen = []
        def choose(s, observation):
            seen.append(observation)
            return model.plan(s, observation, "state-greedy")
        tape = [(0, 1), (1, 0), (0, 0)]
        result = coverage.observe_tape(scenario, tape, choose)
        self.assertEqual(seen[0].belief, Fraction(9, 13))
        self.assertEqual(seen[1].belief, Fraction(1, 2))
        self.assertEqual(seen[2].belief, Fraction(36, 37))
        self.assertEqual(result["planned_requests"], 3)

    def test_future_tape_intervention_cannot_change_prefix_action(self):
        scenario = model.SCENARIOS["adaptive"]
        def run(tape):
            records = []
            def choose(s, observation):
                answer = model.plan(s, observation, "same-objective")
                records.append((asdict(observation), answer["action"], answer["candidate_values_q32"]))
                return answer
            coverage.observe_tape(scenario, tape, choose)
            return records
        first = run([(0, 1), (1, 0), (0, 0)])
        changed = run([(0, 1), (1, 0), (1, 1)])
        self.assertEqual(first[:2], changed[:2])

    def test_early_abstention_keeps_complete_future_and_denominator(self):
        s = replace(model.SCENARIOS["adaptive"], initial_budget=0, initial_deadline=0)
        result = coverage.observe_tape(s, [(0, 1), (1, 0), (0, 0)],
            lambda sc, ob: model.plan(sc, ob, "same-objective"))
        self.assertEqual(len(result["tape"]), 3)
        self.assertEqual(len(result["steps"]), 1)
        self.assertEqual(result["planned_requests"], 3)
        self.assertEqual(result["delivered"], 0)
        self.assertEqual(result["missing_requests"], 3)
        self.assertGreater(Fraction(*result["probability"]), 0)

    def test_existing_objective_has_actual_preference_action_boundary(self):
        s = replace(model.SCENARIOS["adaptive"], horizon=2, initial_budget=24, initial_deadline=24)
        o = model.Observation(0, 0, 0, 1, 11, 24, 17, 64)
        backend = RecordingBackend()
        row = coverage.qualify_state(state(s, o), coverage.load_protocol(), backend=backend)
        self.assertEqual(row["status"], "passed")
        self.assertEqual(row["answers"]["dynamic-ndu"]["action"], 0)
        self.assertEqual(row["answers"]["fixed-preference-ndu"]["action"], 1)
        self.assertTrue(row["flags"]["same_feasibility"])
        self.assertTrue(row["flags"]["preference_external_gain"])
        self.assertTrue(row["flags"]["strict_preference_action_reversal"])
        self.assertGreater(row["external_conditional_regret_q32"]["fixed-preference-ndu"], 0)
        self.assertGreater(backend.calls, 2)  # Calls occur inside both searches.

    def test_wrong_belief_can_change_real_action_with_same_external_objective(self):
        s = replace(model.SCENARIOS["adaptive"], load_cost=8, initial_budget=24, initial_deadline=24)
        o = model.Observation(0, 0, 0, -1, 12, 24, 1, 10)
        row = coverage.qualify_state(state(s, o), coverage.load_protocol())
        self.assertEqual(row["answers"]["dynamic-ndu"]["action"], -1)
        self.assertEqual(row["answers"]["wrong-forecast"]["action"], 0)
        self.assertTrue(row["flags"]["misleading_belief_cost"])
        self.assertFalse(row["original_native_executed"])

    def test_fixed_sufficient_requires_full_policy_value_equality(self):
        s = replace(model.SCENARIOS["fixed"], load_cost=8, initial_budget=24, initial_deadline=24)
        o = model.Observation(0, 0, 0, 0, 24, 24, 1, 2)
        fixed = coverage.fixed_policy_value(s, o, fixed_action=0)
        exact = model.independent_oracle(s, o)
        self.assertEqual(fixed["value_q32"], exact["value_q32"])
        self.assertGreater(fixed["states"], 1)

    def test_same_root_action_alone_does_not_establish_fixed_sufficiency(self):
        s = replace(model.SCENARIOS["adaptive"], initial_budget=24, initial_deadline=24)
        o = model.Observation(0, 0, 0, 0, 24, 24, 1, 2)
        fixed = coverage.fixed_policy_value(s, o, fixed_action=0)
        exact = model.independent_oracle(s, o)
        self.assertEqual(exact["action"], 0)
        self.assertLess(fixed["value_q32"], exact["value_q32"])

    def test_witness_order_does_not_depend_on_latency_or_effect_size(self):
        flags = {k: False for k in ("root_preference_numeric_change", "recursive_numeric_change", "preference_action_change",
                 "preference_external_gain", "state_information_value", "planning_value_over_greedy", "misleading_belief_cost", "fixed_policy_sufficient", "strict_preference_action_reversal")}
        flags["strict_preference_action_reversal"] = True
        rows = [{"id": name, "environment": "adaptive", "families": ["supplied-boundary"],
                 "flags": flags.copy(), "status": "passed", "wall_ns": wall}
                for name, wall in (("b", 1), ("a", 999999999))]
        registry = {"protocol": coverage.load_protocol(), "natural_profiles": [], "natural_tapes": []}
        result = coverage.summarize_rows(rows, registry)
        self.assertEqual(result["witnesses"]["supplied-boundary/adaptive"]["strict_preference_action_reversal"]["first_state_id"], "a")
        rows[0]["wall_ns"], rows[1]["wall_ns"] = rows[1]["wall_ns"], rows[0]["wall_ns"]
        self.assertEqual(result["witnesses"], coverage.summarize_rows(rows, registry)["witnesses"])

    def test_recording_backend_does_not_mint_original_native_evidence(self):
        s = replace(model.SCENARIOS["adaptive"], horizon=2)
        o = model.Observation(0, 0, 0, 1, 20, 20, 1, 2)
        r = coverage.qualify_state(state(s, o), coverage.load_protocol(), backend=RecordingBackend())
        self.assertFalse(r["original_native_executed"])
        self.assertEqual(r["qualification_type"], "reference-only")

    def test_native_inputs_are_frozen_by_exact_bytes_not_just_path(self):
        with tempfile.TemporaryDirectory() as td:
            binary, manifest = Path(td)/"binary", Path(td)/"manifest.json"
            binary.write_bytes(b"test-only-binary")
            report = {"schema": "hepta.hia.ndu-build.v1", "binary_sha256": coverage.input_identity(binary)["sha256"],
                      "original_rust_sources_unchanged": True, "all_original_non_manifest_inputs_unchanged": True,
                      "build_inputs_unchanged": True}
            manifest.write_text(json.dumps(report))
            inputs = coverage.bind_native_inputs(binary, manifest)
            registry = {"native_inputs": inputs}
            self.assertEqual(coverage.check_native_inputs(registry), inputs)
            binary.write_bytes(b"changed-test-only-binary")
            with self.assertRaises(model.FeedbackError):
                coverage.check_native_inputs(registry)

    def test_failed_native_state_is_checkpointed_with_full_remaining_denominator(self):
        p = coverage.load_protocol()
        s = replace(model.SCENARIOS["adaptive"], horizon=2, initial_budget=24, initial_deadline=24)
        states = [state(s, model.Observation(0, 0, 0, 1, b, 24, 17, 64)) for b in (11, 12, 13)]
        registry = {"protocol": p, "source": {"fixture": True}, "states": states,
                    "registration_sha256": "test-only-registration", "memberships": [],
                    "natural_profiles": [], "natural_tapes": []}
        class BrokenBackend(RecordingBackend):
            def evaluate(self, candidates, **kwargs):
                self.calls += 1
                if self.calls == 2:
                    raise OSError("intentional transport failure")
                return model.scalar_backend(candidates, **kwargs)
        with tempfile.TemporaryDirectory() as td, patch.object(coverage, "validate_registry", return_value=p), patch.object(coverage, "source_identity", return_value=registry["source"]):
            output = Path(td)/"result.json"
            result = coverage.qualify(registry, backend=BrokenBackend(), output=output)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["planned_distinct_states"], 3)
            self.assertEqual(result["failed_states"], 1)
            self.assertEqual(result["not_run_states"], 2)
            self.assertEqual(result["native_calls"], 2)
            self.assertGreater(result["work"]["dynamic-ndu"], 0)
            self.assertGreater(result["work"]["same-objective"], 0)
            self.assertEqual(len(result["rows"][0]["attempts"]), 7)
            self.assertTrue(output.is_file())
            checkpoint = output.with_suffix(".states.jsonl")
            retained = [json.loads(line) for line in checkpoint.read_text().splitlines()]
            self.assertEqual([r["id"] for r in retained], [s["id"] for s in states])
            self.assertEqual([r["status"] for r in retained], ["failed", "not_run", "not_run"])
            self.assertFalse(result["all_states_original_native_qualified"])

    def test_partial_support_summary_records_unknown_state_references(self):
        registry = {"protocol": coverage.load_protocol(), "natural_profiles": [{"id": "p", "scenario": {"name": "adaptive"}}],
                    "natural_tapes": [{"profile": "p", "probability": [1, 1], "missing_requests": 0,
                                       "steps": [{"coverage_state_id": "missing"}]}]}
        result = coverage.summarize_rows([], registry)
        self.assertEqual(result["natural_profile_coverage"][0]["unqualified_state_references"], 1)
        self.assertEqual(result["natural_profile_coverage"][0]["tape_event_counts"]["preference_action_change"], 0)

    def test_native_value_corruption_is_not_accepted_as_model_gain(self):
        s = replace(model.SCENARIOS["adaptive"], horizon=2)
        o = model.Observation(0, 0, 0, 1, 20, 20, 1, 2)
        def corrupt(candidates, **kwargs):
            result = model.scalar_backend(candidates, **kwargs)
            result["values"] = {k: v+1 for k, v in result["values"].items()}
            return result
        result = coverage.qualify_state(state(s, o), coverage.load_protocol(), backend=corrupt)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["flags"]["same_objective_exact"])


if __name__ == "__main__":
    unittest.main()
