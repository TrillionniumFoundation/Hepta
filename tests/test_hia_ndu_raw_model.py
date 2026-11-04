"""Actual native differential checks; qualification requires both environment pins.

The exhaustive oracle is the previously independent schedule enumeration, not
another translation of the Rust recurrence. Old experiments are never changed.
"""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import subprocess
import unittest
from unittest.mock import patch

from hepta.hia_ndu_cost import CostModelError, build_request, digest
from hepta.hia_ndu_raw_model import invoke, request_bytes, validate_response
from tests.test_hia_ndu_cost import fixture, independent_frontier

BINARY = os.environ.get("HEPTA_RAW_MODEL_BRIDGE")
BUILD = os.environ.get("HEPTA_RAW_MODEL_BUILD")
OBSERVATIONS = []
RANDOM_MODELS_COMPLETED = []


def record(row):
    OBSERVATIONS.append({"kind": row["kind"], "returncode": row.get("returncode", 0),
                         "mode": row.get("mode")})
    destination = os.environ.get("HEPTA_RAW_MODEL_TRANSCRIPT")
    if destination:
        with open(destination, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


@unittest.skipUnless(BINARY and BUILD, "raw-model native binary and source-bound build receipt required")
class RawModelNativeTests(unittest.TestCase):
    def run_raw(self, payload, mode=None):
        result = subprocess.run([BINARY], input=payload, capture_output=True, timeout=10, check=False)
        record({"kind": "actual-native", "mode": mode, "request": payload.decode("utf-8"),
                "request_sha256": sha256(payload).hexdigest(), "returncode": result.returncode,
                "stdout": result.stdout.decode("utf-8"), "stderr": result.stderr.decode("utf-8")})
        return result

    def native(self, model, mode):
        detached, raw = request_bytes(model, mode)
        result = self.run_raw(raw, mode)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        response = json.loads(result.stdout)
        validate_response(detached, mode, raw, response)
        return response

    def assert_pair(self, model):
        expected = build_request(model)
        responses = [self.native(model, mode) for mode in ("exact_dp", "ndu")]
        for response in responses:
            self.assertEqual(response["bundle"], expected)
            actual = {}
            for plan in response["bundle"]["plans"].values():
                first = plan["actions"][0]
                key = (first["mode"], tuple(first["ready_after"]) if first["mode"] == "invoke" else ())
                actual[key] = plan["total_ns"]
            self.assertEqual(actual, independent_frontier(model, committed_call=True))
            self.assertLessEqual(response["search"]["states"], 40)
        self.assertEqual(responses[0]["pareto_candidate_ids"], responses[1]["pareto_candidate_ids"])
        self.assertEqual(responses[0]["selected_first_action"], responses[1]["selected_first_action"])
        self.assertIsNone(responses[0]["ndu_evaluation"])
        self.assertEqual(len(responses[1]["ndu_evaluation"]["paths"]), len(expected["request"]["candidates"]))
        return responses

    def test_complete_first_action_frontiers_match_exhaustive_schedules(self):
        rng = random.Random(86028121)
        for case in range(128):
            model = fixture(1 + case % 4)
            horizon = len(model["baseline"]["latency_ns"])
            if case % 5 == 0:
                model["variants"] = model["variants"][:1]
            if case % 7 == 0:
                model["variants"].reverse()
            model["session_ready"] = bool(case % 2)
            model["memory_budget_bytes"] = case % 3
            model["budget_ns"] = rng.randrange(0, 25_000)
            model["completion_value_ns"] = rng.randrange(0, 30_000)
            model["baseline"]["latency_ns"] = [rng.randrange(0, 2_000) for _ in range(horizon)]
            for v in model["variants"]:
                v["status"] = rng.choice(["verified"] * 5 + ["rejected", "unknown", "timeout"])
                v["valid"] = [rng.randrange(4) != 0 for _ in range(horizon)]
                v["latency_ns"] = [rng.randrange(0, 2_000) for _ in range(horizon)]
                for key in ("prepare_ns", "proof_ns", "holding_ns", "retire_ns"):
                    v[key] = rng.randrange(0, 1_000)
            model["ready"] = [v["id"] for v in model["variants"]][:case % 3]
            model["memory_budget_bytes"] = max(model["memory_budget_bytes"], len(model["ready"]))
            for key in model["decision"]:
                model["decision"][key] = rng.randrange(0, 800)
            with self.subTest(case=case):
                self.assert_pair(model)
                RANDOM_MODELS_COMPLETED.append(case)

    def test_committed_skip_startup_and_terminal_close_are_paid_once(self):
        for warm in (False, True):
            model = fixture(4)
            model["session_ready"] = warm
            model["ready"] = ["a"]
            for v in model["variants"]:
                v["status"] = "rejected"
            result = self.assert_pair(model)[0]
            skips = [p for p in result["bundle"]["plans"].values() if p["actions"][0]["mode"] == "skip"]
            self.assertEqual(len(skips), 1)
            plan = skips[0]
            self.assertEqual(plan["close_ns"], model["decision"]["close_ns"])
            call = sum(model["decision"][k] for k in ("search_ns", "native_ns", "transport_ns", "validation_ns"))
            call += 0 if warm else model["decision"]["startup_ns"]
            self.assertEqual(plan["current_committed_ns"], call)
            self.assertEqual(plan["actions"][0]["retired"], ["a"])
            self.assertEqual(plan["total_ns"], sum(a["total_ns"] for a in plan["actions"]) + call + plan["close_ns"])

    def test_exact_budget_edge_and_literal_abstain(self):
        original = fixture(4)
        best = min(p["total_ns"] for p in build_request(original)["plans"].values())
        for budget in (0, best - 1, best, best + 1):
            model = deepcopy(original)
            model["budget_ns"] = budget
            result = self.assert_pair(model)[0]
            self.assertEqual(bool(result["bundle"]["plans"]), budget >= best)
        model = fixture(1)
        model["completion_value_ns"] = 0
        result = self.assert_pair(model)[0]
        self.assertIn("abstain", result["pareto_candidate_ids"])
        self.assertIsNone(result["selected_first_action"])

    def test_q32_floor_conversion_and_zero_ties(self):
        for ns in (0, 1, 999, 1000, 1001, 999_999, 1_000_000, 1_000_001):
            model = fixture(1)
            model["baseline"]["latency_ns"] = [ns]
            for v in model["variants"]:
                v.update(prepare_ns=0, proof_ns=0, holding_ns=0, retire_ns=0, latency_ns=[ns])
            model["decision"] = dict.fromkeys(model["decision"], 0)
            model["budget_ns"] = 5_000_000
            model["completion_value_ns"] = ns
            result = self.assert_pair(model)[0]
            self.assertIn("abstain", result["pareto_candidate_ids"])
            self.assertIsNone(result["selected_first_action"])

    def test_invalidation_reacquisition_and_sunk_cost(self):
        model = fixture(4)
        model["ready"] = ["a"]
        model["variants"][0]["valid"] = [True, False, True, True]
        result = self.assert_pair(model)
        model["sunk_cost_ns"] = 1_000_000_000_000
        repeated = self.assert_pair(model)
        # Lineage changes, while every plan's physical accounting is unchanged.
        self.assertEqual(list(result[0]["bundle"]["plans"].values()), list(repeated[0]["bundle"]["plans"].values()))

    def test_maximum_declared_integer_domain_and_overflow_refusal(self):
        model = fixture(1)
        model["decision"] = dict.fromkeys(model["decision"], 0)
        for v in model["variants"]:
            v.update(prepare_ns=0, proof_ns=0, holding_ns=0, retire_ns=0, latency_ns=[1_000_000_000_000])
        model["baseline"]["latency_ns"] = [1_000_000_000_000]
        model["budget_ns"] = model["completion_value_ns"] = 1_000_000_000_000
        self.assert_pair(model)
        model["decision"]["close_ns"] = 1
        self.assert_native_reject(model)

    def assert_native_reject(self, model):
        raw = json.dumps({"schema": "hepta.hia.ndu.raw-model.request.v1", "mode": "ndu", "model": model}).encode()
        result = self.run_raw(raw, "ndu")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(json.loads(result.stderr)["authority"], "DENY_ALL")

    def test_native_rejects_unsupported_models_and_typed_json(self):
        mutants = []
        for key, value in (("generation", True), ("generation", 1.0), ("generation", 0),
                           ("budget_ns", -1), ("budget_ns", 2**64), ("memory_budget_bytes", 0),
                           ("session_ready", 1), ("objective_digest", "0" * 64)):
            m = fixture()
            m[key] = value
            if key == "memory_budget_bytes": m["ready"] = ["a"]
            mutants.append(m)
        m = fixture(5); mutants.append(m)
        m = fixture(); m["variants"].append(deepcopy(m["variants"][0])); mutants.append(m)
        m = fixture(); m["variants"][0]["valid"][0] = 1; mutants.append(m)
        m = fixture(); m["variants"][0]["extra"] = 0; mutants.append(m)
        m = fixture(); m["ready"] = ["a", "a"]; mutants.append(m)
        m = fixture(); m["variants"][1]["id"] = "a"; mutants.append(m)
        for index, model in enumerate(mutants):
            with self.subTest(index=index): self.assert_native_reject(model)
        _, raw = request_bytes(fixture(), "ndu")
        for invalid in (raw.replace(b'"generation":1', b'"generation":1,"generation":1'),
                        raw[:-1], raw + b"{}", b" " * 1_048_577,
                        raw.replace(b'"mode":"ndu"', b'"mode":"learned"')):
            self.assertNotEqual(self.run_raw(invalid).returncode, 0)

    def test_sealed_runner_does_not_call_python_dp(self):
        for mode in ("exact_dp", "ndu"):
            with patch("hepta.hia_ndu_cost._Planner", side_effect=AssertionError("Python DP called")), \
                 patch("hepta.hia_ndu_cost._exact", side_effect=AssertionError("Python DP called")), \
                 patch("hepta.hia_ndu_cost._build_request", side_effect=AssertionError("Python DP called")):
                result, receipt = invoke(BINARY, BUILD, fixture(), mode=mode)
                self.assertEqual(result["mode"], mode)
                self.assertGreater(receipt["outer_wall_ns"], 0)
                record({"kind": "sealed-native", **receipt})
        # The evidence-supported default must not pay for an unrequested NDU
        # evaluation. This is an actual call through the sealed native runner.
        with patch("hepta.hia_ndu_cost._Planner", side_effect=AssertionError("Python DP called")), \
             patch("hepta.hia_ndu_cost._build_request", side_effect=AssertionError("Python DP called")):
            result, receipt = invoke(BINARY, BUILD, fixture())
        self.assertEqual(result["mode"], "exact_dp")
        self.assertIs(result["native_evaluation"], False)
        self.assertIsNone(result["ndu_evaluation"])
        self.assertEqual(receipt["mode"], "exact_dp")
        record({"kind": "sealed-native", **receipt})

    def test_response_replay_rejects_generation_costs_and_authority_changes(self):
        model, raw = request_bytes(fixture(), "ndu")
        response = self.native(model, "ndu")
        cases = []
        for key, value in (("generation", 2), ("generation", True), ("authority", "ALLOW"),
                           ("safety_certificate", True), ("request_sha256", "0" * 64),
                           ("native_evaluation", False), ("pareto_candidate_ids", ["abstain"])):
            changed = deepcopy(response); changed[key] = value; cases.append(changed)
        changed = deepcopy(response)
        next(iter(changed["bundle"]["plans"].values()))["total_ns"] += 1
        cases.append(changed)
        changed = deepcopy(response); changed["selected_first_action"]["dispatch"] = "baseline"; cases.append(changed)
        for i, changed in enumerate(cases):
            with self.subTest(i=i), self.assertRaises(CostModelError):
                validate_response(model, "ndu", raw, changed)

    def test_selected_action_rejects_type_equal_numeric_substitutions(self):
        for mode in ("exact_dp", "ndu"):
            model, raw = request_bytes(fixture(), mode)
            response = self.native(model, mode)
            action = response["selected_first_action"]
            self.assertIs(type(action["batch"]), int)
            self.assertEqual(action["batch"], 0)
            self.assertIs(action["session_after"], True)
            substitutions = [("batch", False), ("batch", 0.0),
                             ("session_after", 1), ("session_after", 1.0),
                             ("total_ns", float(action["total_ns"]))]
            for key, value in action["costs"].items():
                substitutions.append((("costs", key), float(value)))
                if value in (0, 1):
                    substitutions.append((("costs", key), bool(value)))
            for key, value in substitutions:
                with self.subTest(mode=mode, field=key, replacement_type=type(value).__name__):
                    changed = deepcopy(response)
                    selected = changed["selected_first_action"]
                    if isinstance(key, tuple):
                        selected[key[0]][key[1]] = value
                    else:
                        selected[key] = value
                    # These variants were accepted by the former final == check.
                    self.assertEqual(selected, action)
                    self.assertNotEqual(digest(selected), digest(action))
                    with self.assertRaisesRegex(CostModelError, "selected action mismatch"):
                        validate_response(model, mode, raw, changed)


class RawModelInputTests(unittest.TestCase):
    def test_request_contains_only_raw_model_and_mode(self):
        original = fixture()
        detached, payload = request_bytes(original, "ndu")
        self.assertEqual(set(json.loads(payload)), {"schema", "mode", "model"})
        original["variants"][0]["latency_ns"][0] += 1
        self.assertNotEqual(original, detached)
        for mode in (None, "python", True):
            with self.assertRaises(CostModelError): request_bytes(fixture(), mode)


if __name__ == "__main__":
    unittest.main()
