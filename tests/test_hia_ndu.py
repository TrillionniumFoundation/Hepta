"""Registered transformation and real upstream NDU decision boundaries.

Synthetic timings below test arithmetic only. Integration tests execute the
actual pinned Rust evaluator and native compiler; no mock supplies a pass.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta.clang_capture import run_bounded
from hepta.hia_ndu import (HIANDURejected, assess_samples, invoke_ndu, make_plan,
                          observe_semantics, prepare_candidate)
from hepta.hia_program import verify_program
from hepta.native_tool_identity import digest_executable
from tests.test_hia_swap_opt import source_program

ROOT = Path(__file__).resolve().parents[1]
BRIDGE = Path(os.environ.get("HIA_NDU_BRIDGE", ROOT / "rust/hia-ndu-bridge/target/release/hia-ndu-bridge"))


def request(*, feasible=True, candidate_cost=5_000_000_000, live_bytes=5):
    return {"schema": "hepta.hia.ndu-request.v1", "objective_sha256": "a" * 64,
            "generation": 1, "maximum_live_bytes": 100, "maximum_artifact_bytes": 100_000,
            "candidates": [
                {"id": "abstain", "core_sha256": "b" * 64, "artifact_sha256": "c" * 64,
                 "evidence_sha256": "d" * 64, "feasible": True,
                 "projected_total_ns": 10_000_000_000, "peak_live_bytes": 5, "artifact_bytes": 1000},
                {"id": "byte_swap", "core_sha256": "e" * 64, "artifact_sha256": "f" * 64,
                 "evidence_sha256": "1" * 64, "feasible": feasible,
                 "projected_total_ns": candidate_cost, "peak_live_bytes": live_bytes, "artifact_bytes": 1000}]}


class CandidatePlanTests(unittest.TestCase):
    def setUp(self):
        self.source = source_program()
        self.plan = make_plan(self.source, entry="swap_candidate")

    def test_candidate_is_reproduced_from_exact_core(self):
        prepared = prepare_candidate(self.source, self.plan)
        self.assertEqual(prepared.replacements, 1)
        self.assertNotEqual(prepared.baseline.sha256, prepared.candidate.sha256)
        again = prepare_candidate(prepared.baseline, prepared.plan,
                                  candidate_bytes=prepared.candidate.canonical_bytes)
        self.assertEqual(again.candidate.sha256, prepared.candidate.sha256)
        self.plan["objective"]["horizon_calls"] = 1
        self.assertEqual(prepared.plan["objective"]["horizon_calls"], 100_000_000)

    def test_type_safe_behavior_change_is_not_registered_rewrite(self):
        prepared = prepare_candidate(self.source, self.plan)
        changed = prepared.candidate.as_dict()
        op = next(op for op in changed["functions"][0]["blocks"][0]["ops"]
                  if op["op"] == "const" and op["attrs"]["value"] == 11)
        op["attrs"]["value"] = 99
        type_safe = verify_program(changed)
        with self.assertRaisesRegex(HIANDURejected, "differs from"):
            prepare_candidate(self.source, self.plan, candidate_bytes=type_safe.canonical_bytes)

    def test_stale_identity_unknown_plan_and_zero_generation_refused(self):
        edits = [("baseline_sha256", "f" * 64), ("generation", 0),
                 ("generation", True), ("pass_id", "model-says-safe"),
                 ("permission", True)]
        for key, value in edits:
            plan = copy.deepcopy(self.plan)
            plan[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(HIANDURejected):
                prepare_candidate(self.source, plan)

    def test_v7_does_not_silently_downgrade(self):
        source = copy.deepcopy(self.source)
        source["schema"] = "hepta.hia.program.v7"
        # Use the actual registered schema spelling, not a forged version name.
        from hepta.hia_schema import SCHEMA_V7
        source["schema"] = SCHEMA_V7
        plan = make_plan(source, entry="swap_candidate")
        with self.assertRaisesRegex(HIANDURejected, "primitive v1-v6"):
            prepare_candidate(source, plan)

    def test_actual_values_traps_failure_and_full_resource_observations(self):
        prepared = prepare_candidate(self.source, self.plan)
        observed = observe_semantics(prepared, [[5, 0, 4, 0], [5, 2, 2, 2]],
                                    negative_cases=[[4, 0, 3, 0], [5, 5, 0, 0], [5, 0, 5, 0], [5, 0, 4, 5]])
        self.assertTrue(observed["ok"])
        self.assertEqual(len(observed["observations"]), 12)
        self.assertTrue(all(row["match"] for row in observed["observations"]))
        self.assertTrue(any(row["baseline"].get("trap_code") == "allocation"
                            for row in observed["observations"]))
        self.assertTrue(any(row["baseline"].get("trap_code") == "bounds"
                            for row in observed["observations"]))


class MeasurementPolicyTests(unittest.TestCase):
    def setUp(self):
        self.objective = make_plan(source_program(), entry="swap_candidate")["objective"]

    def assess(self, pairs, cost=0):
        return assess_samples([{"baseline_ns": b, "candidate_ns": c} for b, c in pairs],
                              calls_per_sample=1000, objective=self.objective, search_cost_ns=cost)

    def test_synthetic_clear_gain_and_cost_projection_arithmetic(self):
        report = self.assess([(1_000_000, 500_000)] * 31)
        self.assertTrue(report["eligible"])
        self.assertEqual(report["projected_baseline_total_ns"], 100_000_000_000)
        self.assertEqual(report["projected_candidate_total_ns"], 52_000_000_000)
        self.assertFalse(report["statistical_confidence_proved"])

    def test_synthetic_regression_tie_and_paid_cost_retain_baseline(self):
        for candidate in (1_000_000, 1_500_000):
            with self.subTest(candidate=candidate):
                self.assertFalse(self.assess([(1_000_000, candidate)] * 31)["eligible"])
        self.objective["horizon_calls"] = 1
        report = self.assess([(1_000_000, 500_000)] * 31)
        self.assertIn("experiment_cost_not_recovered", report["reasons"])

    def test_synthetic_noisy_and_over_budget_measurements_rejected(self):
        report = self.assess([(v, 500_000) for v in [800_000, 1_000_000, 1_200_000] * 10 + [1_000_000]])
        self.assertIn("baseline_timing_noise", report["reasons"])
        self.assertIn("search_cost_budget", self.assess([(1_000_000, 500_000)] * 31,
                                                       cost=60_000_000_000)["reasons"])

    def test_no_sample_trimming_invalid_samples_rejected(self):
        for pairs in ([(1, 1)] * 14, [(1, 1)] * 16, [(1, 1)] * 65, [(1, 0)] * 31):
            with self.subTest(count=len(pairs)), self.assertRaises(HIANDURejected):
                self.assess(pairs)

    def test_objective_must_remain_in_the_declared_profile(self):
        for key, value in (("maximum_mad_ppm", 1_000_000), ("horizon_calls", True),
                           ("minimum_gain_ppm", -1), ("model_override", True)):
            original = copy.deepcopy(self.objective)
            self.objective[key] = value
            with self.subTest(key=key), self.assertRaises(HIANDURejected):
                self.assess([(1_000_000, 500_000)] * 31)
            self.objective = original


class EvidencePublicationTests(unittest.TestCase):
    def arguments(self, output):
        return ["qualify_hia_ndu", "--program", str(ROOT / "examples/hia_ndu/byte_swap.json"),
                "--cases", str(ROOT / "examples/hia_ndu/byte_swap_cases.json"),
                "--entry", "swap_candidate", "--bridge", str(BRIDGE),
                "--bridge-sha256", "a" * 64, "--output", str(output)]

    def test_existing_output_refused_before_experiment_is_paid(self):
        from tools.qualify_hia_ndu import main
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            output.write_text("existing evidence\n")
            with patch("sys.argv", self.arguments(output)), patch("tools.qualify_hia_ndu.qualify") as search:
                with self.assertRaises(FileExistsError):
                    main()
                search.assert_not_called()
            self.assertEqual(output.read_text(), "existing evidence\n")

    def test_interrupted_experiment_leaves_explicit_failure_record(self):
        from tools.qualify_hia_ndu import main
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            with patch("sys.argv", self.arguments(output)), patch("tools.qualify_hia_ndu.qualify",
                    side_effect=KeyboardInterrupt("injected publication control")):
                with self.assertRaises(KeyboardInterrupt):
                    main()
            report = json.loads(output.read_text())
            self.assertFalse(report["ok"])
            self.assertEqual(report["status"], "interrupted_no_change")
            self.assertFalse(report["activated"])


@unittest.skipUnless(BRIDGE.is_file(), "build the pinned real NDU bridge to execute integration tests")
class ActualNDUBridgeTests(unittest.TestCase):
    def call(self, value):
        return invoke_ndu(value, bridge=BRIDGE, expected_binary_sha256=digest_executable(BRIDGE))

    def test_actual_ndu_recommends_only_advisory_and_binds_support(self):
        report = self.call(request())
        self.assertEqual(report["response"]["advisory_recommendation"], "byte_swap")
        self.assertEqual(report["response"]["authority"], "DENY_ALL")
        self.assertFalse(report["activated"])
        self.assertEqual(report["response"]["generation"], 1)

    def test_receipt_is_bound_to_submitted_snapshot(self):
        from hepta.hia_ndu import identity
        value = request()
        report = self.call(value)
        value["candidates"][1]["projected_total_ns"] = 999
        self.assertEqual(report["request"]["candidates"][1]["projected_total_ns"], 5_000_000_000)
        self.assertEqual(report["request_sha256"], identity(report["request"]))

    def test_actual_ndu_rejects_hard_failure_and_resource_overflow(self):
        for req in (request(feasible=False), request(live_bytes=101)):
            with self.subTest(req=req):
                reply = self.call(req)["response"]
                self.assertEqual(reply["advisory_recommendation"], "abstain")
                self.assertEqual(reply["rejected"][0]["id"], "byte_swap")

    def test_actual_ndu_retains_tie_frontier(self):
        reply = self.call(request(candidate_cost=10_000_000_000))["response"]
        self.assertIsNone(reply["advisory_recommendation"])
        self.assertEqual(reply["disposition"], "ParetoSetRequiresSlowPath")

    def test_missing_or_infeasible_abstain_refused(self):
        missing, infeasible = request(), request()
        missing["candidates"] = missing["candidates"][1:]
        infeasible["candidates"][0]["feasible"] = False
        for value in (missing, infeasible):
            with self.subTest(value=value), self.assertRaises(HIANDURejected):
                self.call(value)

    def test_duplicate_json_and_unknown_fields_refused_by_real_rust(self):
        payload = json.dumps(request())
        payload = payload.replace('"generation": 1', '"generation": 1, "generation": 1')
        result = run_bounded([str(BRIDGE)], input_text=payload)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(json.loads(result.stdout)["ok"])
        value = request()
        value["model_claims_proved"] = True
        with self.assertRaises(HIANDURejected):
            self.call(value)

    def test_wrong_binary_identity_refused_before_launch(self):
        with patch("hepta.hia_ndu.run_bounded") as launch:
            with self.assertRaisesRegex(HIANDURejected, "identity mismatch"):
                invoke_ndu(request(), bridge=BRIDGE, expected_binary_sha256="a" * 64)
            launch.assert_not_called()

    def test_tampered_reply_cannot_change_evidence_generation_or_authority(self):
        reply = self.call(request())["response"]
        for mode in ("generation", "authority", "artifact", "support", "duplicate"):
            changed = copy.deepcopy(reply)
            if mode == "generation":
                changed["generation"] = 2
            elif mode == "authority":
                changed["authority"] = "ALLOW"
            elif mode == "duplicate":
                changed["bindings"][1] = copy.deepcopy(changed["bindings"][0])
            else:
                changed["bindings"][0]["artifact_sha256" if mode == "artifact" else "support_sha256"] = "2" * 64
            with self.subTest(mode=mode), patch("hepta.hia_ndu.run_bounded", return_value=
                    SimpleNamespace(returncode=0, stdout=json.dumps(changed), stderr="")):
                with self.assertRaises(HIANDURejected):
                    self.call(request())

    @unittest.skipUnless(Path("/usr/bin/clang-20").is_file(), "Clang 20 native integration")
    def test_complete_native_candidate_loop_can_select_no_change(self):
        from tools.qualify_hia_ndu import qualify
        source = source_program()
        plan = make_plan(source, entry="swap_candidate", horizon_calls=1)
        report = qualify(source, plan, [[5, 0, 4, 0], [5, 2, 2, 2]],
                         negative_cases=[[5, 5, 0, 0]], bridge=BRIDGE,
                         expected_bridge_sha256=digest_executable(BRIDGE),
                         clang="/usr/bin/clang-20", samples=15, iterations=1000)
        self.assertTrue(report["ok"], report["diagnostics"])
        self.assertEqual(report["decision"], "no_change")
        self.assertTrue(report["claims"]["real_ndu_evaluator_executed"])
        self.assertFalse(report["activated"])
        self.assertIn("experiment_cost_not_recovered", report["assessment"]["reasons"])
        self.assertEqual(report["ndu"]["response"]["advisory_recommendation"], "abstain")
        self.assertEqual(len(report["measurement"]["raw_samples"]), 15)


if __name__ == "__main__":
    unittest.main()
