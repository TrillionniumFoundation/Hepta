"""Native numeric-domain regressions, separate from the frozen pilot suite.

Set HEPTA_FINITE_NDU_IDENTITY and HEPTA_FINITE_NDU_BRIDGE to the separately
pinned finite Rust bridge profile. Optional
HEPTA_NDU_BOUNDARY_EVIDENCE records exact requests, responses and source hashes.
Fixtures have declared synthetic costs; all native replies are real execution.
"""
from base64 import b64encode
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import time
import unittest
from unittest.mock import patch

from hepta.hia_ndu import NduBridge, NduBridgeError, Q32, finite_plan_request
from hepta.hia_planning import compact_finite_plan_request, exact_finite_plan

NS_BOUND = 10**12
I64_MAX = 2**63 - 1
UTILITY_LIMIT = 1_000_000 * Q32
ROOT = Path(__file__).resolve().parents[1]


class _RecordingNativeBridge(NduBridge):
    """Record the real subprocess bytes without changing any admission check."""

    def __init__(self, *args, **kwargs):
        self.calls = []
        super().__init__(*args, **kwargs)

    def _invoke(self, arguments, payload):
        actual_run = subprocess.run

        def record(*args, **kwargs):
            started = time.monotonic_ns()
            completed = actual_run(*args, **kwargs)
            self.calls.append({
                "argv": [str(value) for value in args[0]],
                "stdin_base64": b64encode(kwargs.get("input", b"")).decode(),
                "stdin_sha256": sha256(kwargs.get("input", b"")).hexdigest(),
                "stdout_base64": b64encode(completed.stdout).decode(),
                "stderr_base64": b64encode(completed.stderr).decode(),
                "returncode": completed.returncode,
                "wall_ns": time.monotonic_ns() - started,
                "source": "actual subprocess.run result, returned unchanged to NduBridge",
            })
            return completed

        # Only wrap the OS runner for byte capture. Never supply a fake response
        # or bypass NduBridge's binary/request/identity checks.
        with patch("hepta.hia_ndu.subprocess.run", side_effect=record):
            return super()._invoke(arguments, payload)


def _fields():
    return {
        "objective_digest": "1" * 64, "snapshot_digest": "2" * 64, "generation": 1,
        "initial_state": "base",
        "states": {"base": {"source_sha256": "3" * 64,
                              "verification_sha256": "4" * 64, "status": "verified"}},
        "transitions": [], "batch_costs_ns": {"base": [0]},
        "remaining_budget_ns": 0, "completion_value_ns": NS_BOUND,
        "decision_cost_ns": 0, "observations": [],
    }


def _expanded_cost_fields(*, setup, batch_cost, completion):
    result = _fields()
    result["states"]["costly"] = {"source_sha256": "5" * 64,
        "verification_sha256": "6" * 64, "status": "verified"}
    result["transitions"] = [
        {"id": "install-costly", "source": "base", "target": "costly", "setup_ns": setup,
         "status": "verified", "verification_sha256": "6" * 64, "support_sha256": "7" * 64},
        {"id": "return-base", "source": "costly", "target": "base", "setup_ns": 0,
         "status": "verified", "verification_sha256": "4" * 64, "support_sha256": "8" * 64},
    ]
    result.update(batch_costs_ns={"base": [1] * 4, "costly": [batch_cost] * 4},
                  remaining_budget_ns=NS_BOUND, completion_value_ns=completion, decision_cost_ns=1)
    return result


@unittest.skipUnless(os.environ.get("HEPTA_FINITE_NDU_IDENTITY") and os.environ.get("HEPTA_FINITE_NDU_BRIDGE"),
                     "requires the separately pinned finite native NDU profile")
class NativePlanningNumericBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.paths = ("hepta/hia_ndu.py", "hepta/hia_planning.py", "tests/test_hia_planning_boundaries.py")
        cls.source_identity = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in cls.paths}
        evidence = os.environ.get("HEPTA_NDU_BOUNDARY_EVIDENCE")
        cls.evidence = Path(evidence).resolve() if evidence else None
        if cls.evidence:
            cls.evidence.mkdir(parents=True, exist_ok=True)
            if (cls.evidence / "SOURCE_IDENTITY.json").exists():
                raise RuntimeError("use a fresh boundary evidence directory")
            cls._write("SOURCE_IDENTITY.json", cls.source_identity)
            for name in cls.paths:
                destination = cls.evidence / "sources" / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                raw = (ROOT / name).read_bytes()
                if sha256(raw).hexdigest() != cls.source_identity[name]:
                    raise RuntimeError("source changed while freezing boundary gate")
                destination.write_bytes(raw)
        identity = Path(os.environ["HEPTA_FINITE_NDU_IDENTITY"])
        manifest = json.loads(identity.read_bytes())
        cls.bridge = _RecordingNativeBridge.from_finite_environment()
        cls._write("NATIVE_BUILD_IDENTITY.json", manifest)
        cls._write("NATIVE_HANDSHAKE.json", cls.bridge.calls)
        cls._write("SCOPE.json", {
            "schema": "hepta.hia.ndu.numeric-boundary-gate.v1",
            "input_scope": "synthetic boundary fixtures with actual original native execution",
            "production_sources_modified": False,
            "request_level_acceptance_equivalence_claim": False,
            "candidate_equivalence_scope": "shared-validated finite-graph.v1 feasible paths",
            "expected_tests": 11,
            "original_nine_test_pilot_source_changed": True,
            "pilot_change_scope": "explicit finite environment and pinned admission; fixtures and comparison assertions unchanged",
        })

    @classmethod
    def _write(cls, name, value):
        if cls.evidence:
            (cls.evidence / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    @classmethod
    def tearDownClass(cls):
        current = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in cls.paths}
        cls._write("SOURCE_RECHECK.json", {"before": cls.source_identity, "after": current,
                    "unchanged": current == cls.source_identity,
                    "actual_native_invocations": len(cls.bridge.calls)})
        if current != cls.source_identity:
            raise AssertionError("source drift during native boundary qualification")

    def _evaluate_compact(self, case, fields, *, full_record=None):
        bundle = compact_finite_plan_request(**fields)
        light = exact_finite_plan(**fields)["advice"]
        start = len(self.bridge.calls)
        response = self.bridge.evaluate(bundle["request"])
        self._write(case + ".json", {
            "fields": fields, "compact_bundle": bundle, "exact_q32_advice": light,
            "native_response": response, "native_processes": self.bridge.calls[start:],
            "full_request_probe": full_record,
        })
        for key in ("advisory_candidate_id", "pareto_candidate_ids", "disposition"):
            self.assertEqual(response[key], light[key], key)
        self.assertEqual(response["authority"], "DENY_ALL")
        self.assertFalse(response["safety_certificate"])
        self.assertTrue(all(row["resource_cost_q32"] <= bundle["request"]["resource_budget_q32"] <= I64_MAX
                            for row in bundle["request"]["candidates"]))
        self.assertTrue(all(row["projection_count"] == 0 for row in response["paths"]))
        values = [value for row in response["paths"] for value in row["values_q32"]]
        self.assertTrue(all(-UTILITY_LIMIT <= value <= UTILITY_LIMIT for value in values))
        return bundle, response, values

    def _endpoint(self, case, costs, budget, completion, decision=0):
        fields = _fields()
        fields.update(batch_costs_ns={"base": costs}, remaining_budget_ns=budget,
                      completion_value_ns=completion, decision_cost_ns=decision)
        return self._evaluate_compact(case, fields)

    def test_maximum_terminal_with_zero_cost_is_inclusive_native_upper_bound(self):
        _, response, values = self._endpoint("upper-terminal-zero-cost", [0], 0, NS_BOUND)
        self.assertEqual(max(values), UTILITY_LIMIT)
        self.assertEqual(response["disposition"], "UniqueParetoRecommendation")
        self.assertNotEqual(response["advisory_candidate_id"], "abstain")

    def test_maximum_cost_with_zero_terminal_is_inclusive_native_lower_bound(self):
        _, response, values = self._endpoint("lower-utility-at-budget", [NS_BOUND], NS_BOUND, 0)
        self.assertEqual(min(values), -UTILITY_LIMIT)
        self.assertEqual(response["advisory_candidate_id"], "abstain")

    def test_equal_maximum_cost_and_terminal_preserve_zero_value_tie(self):
        _, response, _ = self._endpoint("equal-terminal-and-cost", [NS_BOUND], NS_BOUND, NS_BOUND)
        self.assertIsNone(response["advisory_candidate_id"])
        self.assertEqual(len(response["pareto_candidate_ids"]), 2)
        self.assertIn("abstain", response["pareto_candidate_ids"])

    def test_four_large_phases_with_total_at_budget_do_not_project(self):
        bundle, _, values = self._endpoint("four-large-phases", [250_000_000_000] * 4, NS_BOUND, 0)
        self.assertEqual(len(bundle["plans"]), 4)
        self.assertEqual(min(values), -UTILITY_LIMIT)

    def test_nonintegral_q32_phases_at_budget_do_not_project(self):
        costs = [249_999_999_999, 250_000_000_001, 250_000_000_003, 249_999_999_997]
        self.assertEqual(sum(costs), NS_BOUND)
        _, _, values = self._endpoint("nonintegral-q32-phases", costs, NS_BOUND, 0)
        self.assertEqual(min(values), -UTILITY_LIMIT + 2)

    def test_unaffordable_later_decision_is_removed_before_native_evaluation(self):
        bundle, response, _ = self._endpoint("unaffordable-later-decision",
                                             [500_000_000_000] * 2, NS_BOUND, NS_BOUND, NS_BOUND)
        self.assertEqual(len(bundle["plans"]), 1)
        self.assertEqual(next(iter(bundle["plans"].values()))["actions"][0]["mode"], "stop")
        self.assertIsNone(response["advisory_candidate_id"])

    def test_all_delivery_paths_above_small_budget_leave_literal_abstention(self):
        bundle, response, _ = self._endpoint("all-delivery-over-budget", [NS_BOUND] * 4, 1, NS_BOUND)
        self.assertEqual(bundle["plans"], {})
        self.assertEqual(response["disposition"], "InfeasibleExplicitAbstain")
        self.assertEqual(response["advisory_candidate_id"], "abstain")

    def _full_rejection(self, fields, expected_error):
        full = finite_plan_request(**fields)
        start = len(self.bridge.calls)
        with self.assertRaisesRegex(NduBridgeError, expected_error) as caught:
            self.bridge.evaluate(full["request"])
        return full, {"request": full["request"], "status": "expected-request-level-rejection",
                      "error": str(caught.exception), "native_processes": self.bridge.calls[start:],
                      "request_level_equivalence_claim": False}

    def test_full_i64_resource_overflow_rejects_while_feasible_compact_succeeds(self):
        fields = _expanded_cost_fields(setup=NS_BOUND, batch_cost=NS_BOUND, completion=NS_BOUND)
        full, refusal = self._full_rejection(fields, "expected i64")
        self.assertEqual(len(full["plans"]), 23)
        self.assertGreater(max(row["resource_cost_q32"] for row in full["request"]["candidates"]), I64_MAX)
        self._evaluate_compact("full-i64-overflow", fields, full_record=refusal)

    def test_full_utility_projection_rejects_while_feasible_compact_succeeds(self):
        fields = _expanded_cost_fields(setup=0, batch_cost=300_000_000_000, completion=0)
        full, refusal = self._full_rejection(fields, "projected utility")
        self.assertEqual(len(full["plans"]), 23)
        self.assertLessEqual(max(row["resource_cost_q32"] for row in full["request"]["candidates"]), I64_MAX)
        _, response, _ = self._evaluate_compact("full-utility-projection", fields, full_record=refusal)
        self.assertEqual(response["advisory_candidate_id"], "abstain")

    def _common_bound_refusal(self, name):
        fields = deepcopy(_fields())
        fields[name] = NS_BOUND + 1
        start = len(self.bridge.calls)
        refusals = []
        for entry in (compact_finite_plan_request, exact_finite_plan):
            with self.assertRaises(NduBridgeError) as caught:
                entry(**fields)
            refusals.append({"entry": entry.__name__, "error": str(caught.exception)})
        self.assertEqual(len(self.bridge.calls), start)
        self._write(name + "-out-of-profile.json", {"fields": fields, "refusals": refusals,
                                                    "native_invocations": 0})

    def test_budget_above_public_bound_is_rejected_by_both_entries(self):
        self._common_bound_refusal("remaining_budget_ns")

    def test_terminal_above_public_bound_is_rejected_by_both_entries(self):
        self._common_bound_refusal("completion_value_ns")


if __name__ == "__main__":
    unittest.main()
