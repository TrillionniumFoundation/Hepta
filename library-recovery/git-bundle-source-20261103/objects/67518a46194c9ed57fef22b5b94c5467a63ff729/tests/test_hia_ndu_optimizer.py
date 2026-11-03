"""Real native NDU decisions cannot replace independent HIA behavior proofs."""
from __future__ import annotations

import copy
from fractions import Fraction
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_ndu_optimizer import OptimizationRejected, ns_to_ms_q32, rank_candidates
from hepta.hia_program import verify_program
from hepta.hia_translation_validation import validate_translation
from tests.test_hia_program import arithmetic, b, f, i, jump, m, ret
from tests.test_hia_translation_validation import identity


BRIDGE = os.environ.get("HEPTA_NDU_BRIDGE")
BUILD = os.environ.get("HEPTA_NDU_BUILD")
AVAILABLE = bool(BRIDGE and BUILD and importlib.util.find_spec("z3"))


def baseline_program():
    program = arithmetic("int.add.wrap", "u32")
    block = program["functions"][0]["blocks"][0]
    block["ops"].append(i("int.sub.wrap", ["r", "z"], [("cancel", "u32")]))
    block["term"] = ret("cancel")
    return program


def proposal(program=None, cid="cancel"):
    return {"id": cid, "action": "wrapping-add-sub-cancel", "program": program or identity("u32")}


def observation(program, runtime_ns, uncertainty_ns=0, search_ns=0):
    return {"program_sha256": verify_program(program).sha256, "runtime_ns": runtime_ns,
            "uncertainty_ns": uncertainty_ns, "search_ns": search_ns}


class FixedPointTests(unittest.TestCase):
    def test_integer_conversion_matches_exact_fraction_without_clipping(self):
        for number in (0, 1, 117, 15625, 999999, 1_000_000, 123_456_789, 2_000_000_000_000_000):
            self.assertEqual(ns_to_ms_q32(number), round(Fraction(number * (1 << 32), 1_000_000)))
        for bad in (True, -1, 1.5, "12", 1 << 63, 3_000_000_000_000_000):
            with self.subTest(bad=bad), self.assertRaises(OptimizationRejected):
                ns_to_ms_q32(bad)


@unittest.skipUnless(AVAILABLE, "actual source-bound NDU bridge and Z3 are required")
class NativeProofGatedRankingTests(unittest.TestCase):
    def setUp(self):
        self.baseline = baseline_program()
        self.candidates = [proposal()]
        self.observations = {"abstain": observation(self.baseline, 100_000),
                             "cancel": observation(identity("u32"), 1_000)}
        self.objective = {"expected_calls": 1_000_000, "resource_cap_ns": 5_000_000_000,
                          "target": "x86_64-unknown-linux-gnu", "measurement_profile": "synthetic-cost-admission-test"}
        self.bridge = {"binary": BRIDGE, "build_receipt": str(Path(BUILD) / "build-receipt.json")}

    def rank(self, **kwargs):
        params = dict(baseline=self.baseline, candidates=self.candidates,
                      observations=self.observations, function="calculate", bridge=self.bridge,
                      objective=self.objective)
        params.update(kwargs)
        return rank_candidates(**params)

    def test_real_ndu_selects_only_a_freshly_proved_candidate(self):
        result = self.rank()
        self.assertTrue(result["admitted"], result)
        self.assertEqual(result["selected_id"], "cancel")
        self.assertEqual(result["selected_fresh_proof"]["status"], "proved")
        self.assertGreater(result["net_margin_ns"], 0)
        self.assertGreater(result["costs"]["actual_adapter_ns"], 0)
        self.assertEqual(result["request_sha256"], result["native_response"]["request_sha256"])
        self.assertFalse(result["claims"]["incremental_advantage_established"])
        self.assertEqual(verify_program(result["selected_program"]).sha256,
                         self.observations["cancel"]["program_sha256"])

    def test_structurally_safe_wrong_cheapest_candidate_is_rejected(self):
        wrong = arithmetic("int.sub.wrap", "u32")
        self.candidates.append(proposal(wrong, "wrong"))
        self.observations["wrong"] = observation(wrong, 0)
        result = self.rank()
        self.assertEqual(result["selected_id"], "cancel")
        report = next(r for r in result["candidate_reports"] if r["id"] == "wrong")
        self.assertTrue(report["core_verified"])
        self.assertEqual(report["proof"]["status"], "disproved")
        self.assertFalse(report["equivalence_proved"])
        self.assertIn("wrong", [r["id"] for r in result["native_response"]["rejected"]])

    def test_identical_unsupported_loop_never_becomes_an_identity_proof(self):
        loop = m(f("forever", [], [], [], [b("entry", [], [], jump("loop")), b("loop", [], [], jump("loop"))]))
        result = self.rank(baseline=loop, candidates=[proposal(loop)], function="forever",
                           observations={"abstain": observation(loop, 100_000), "cancel": observation(loop, 0)})
        self.assertFalse(result["admitted"])
        self.assertEqual(result["candidate_reports"][0]["proof"]["status"], "unknown")

    def test_unselected_export_cannot_change_behind_a_selected_function_proof(self):
        helper = copy.deepcopy(self.baseline["functions"][0])
        helper["name"] = "other"
        self.baseline["functions"].append(helper)
        candidate = copy.deepcopy(self.baseline)
        candidate["functions"][0] = identity("u32")["functions"][0]
        candidate["functions"][1]["blocks"][0]["term"] = ret("z")
        self.candidates = [proposal(candidate)]
        self.observations = {"abstain": observation(self.baseline, 100_000), "cancel": observation(candidate, 0)}
        result = self.rank()
        self.assertFalse(result["admitted"])
        self.assertEqual(result["candidate_reports"][0]["reason"], "unselected_function_or_module_changed")

    def test_native_uncertainty_is_explicitly_applied_before_pareto_ranking(self):
        self.observations["abstain"].update(runtime_ns=100, uncertainty_ns=20)
        self.observations["cancel"].update(runtime_ns=70, uncertainty_ns=20)
        result = self.rank()
        self.assertEqual(result["selected_id"], "abstain")

    def test_search_of_losing_candidates_and_baseline_measurement_is_charged(self):
        self.observations["abstain"]["search_ns"] = 60_000_000_000
        self.observations["cancel"]["search_ns"] = 60_000_000_000
        self.objective["resource_cap_ns"] = 200_000_000_000
        result = self.rank()
        self.assertEqual(result["costs"]["supplied_search_ns"], 120_000_000_000)
        self.assertEqual(result["selected_id"], "abstain")

    def test_actual_search_budget_overrun_keeps_incumbent(self):
        self.objective["resource_cap_ns"] = 0
        result = self.rank()
        self.assertFalse(result["admitted"])
        self.assertEqual(result["selected_program"], verify_program(self.baseline).as_dict())

    def test_fresh_selected_proof_can_still_refuse_native_recommendation(self):
        def proof(before, after, **kwargs):
            proof.calls += 1
            result = validate_translation(before, after, **kwargs)
            if proof.calls == 2:
                result.update(status="unknown", reason="simulated_solver_unavailable")
            return result
        proof.calls = 0
        with patch("hepta.hia_ndu_optimizer.validate_translation", side_effect=proof):
            result = self.rank()
        self.assertEqual(proof.calls, 2)
        self.assertEqual(result["native_response"]["advisory_recommendation"], "cancel")
        self.assertFalse(result["admitted"])
        self.assertEqual(result["reason"], "selected_candidate_fresh_proof_failed")

    def test_complete_matching_hashes_with_wrong_proof_scope_do_not_authorize(self):
        def wrong_scope(before, after, **kwargs):
            result = validate_translation(before, after, **kwargs)
            result["scope"] = "some_other_scope"
            return result
        with patch("hepta.hia_ndu_optimizer.validate_translation", side_effect=wrong_scope):
            result = self.rank()
        self.assertFalse(result["admitted"])

    def test_identity_mismatches_and_authority_flags_are_not_accepted(self):
        cases = []
        obs = copy.deepcopy(self.observations)
        obs["cancel"]["program_sha256"] = "1" * 64
        cases.append({"observations": obs})
        obs = copy.deepcopy(self.observations)
        obs["cancel"]["runtime_ns"] = True
        cases.append({"observations": obs})
        candidate = copy.deepcopy(self.candidates)
        candidate[0]["proved"] = True
        cases.append({"candidates": candidate})
        cases.extend(({"generation": 0}, {"generation": True}, {"bridge_timeout_s": float("nan")},
                      {"timeout_ms": True}, {"candidates": self.candidates * 2}))
        for params in cases:
            with self.subTest(params=params), self.assertRaises(OptimizationRejected):
                self.rank(**params)

    def test_modified_build_receipt_or_binary_does_not_rank(self):
        receipt = json.loads(Path(self.bridge["build_receipt"]).read_text())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "build.json"
            for field, value in (("binary_sha256", "1" * 64), ("adapter_files", {}),
                                 ("locked_dependencies", False), ("builder_sha256", "2" * 64)):
                changed = dict(receipt, **{field: value})
                path.write_text(json.dumps(changed))
                with self.subTest(field=field), self.assertRaises(OptimizationRejected):
                    self.rank(bridge={"binary": BRIDGE, "build_receipt": path})

    def test_empty_finite_action_set_returns_existing_baseline(self):
        result = self.rank(candidates=[], observations={"abstain": self.observations["abstain"]})
        self.assertEqual(result["selected_id"], "abstain")
        self.assertFalse(result["admitted"])


if __name__ == "__main__":
    unittest.main()
