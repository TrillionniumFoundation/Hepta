"""Finite continuation graph contract tests; these are not performance samples."""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import unittest
import tempfile
import shutil

from hepta.hia_ndu import NduBridge, NduBridgeError, finite_plan_request
from hepta.hia_optimization import OptimizationRejected
from hepta.hia_program import verify_program
from tools.qualify_hia_ndu_loop import program

MS = 1_000_000


def fixture():
    return {
        "objective_digest": "1" * 64, "snapshot_digest": "2" * 64, "generation": 3,
        "initial_state": "base",
        "states": {
            "base": {"source_sha256": "3" * 64, "verification_sha256": "4" * 64, "status": "verified"},
            "fast": {"source_sha256": "5" * 64, "verification_sha256": "6" * 64, "status": "verified"},
        },
        "transitions": [{"id": "install-fast", "source": "base", "target": "fast",
                         "setup_ns": 20 * MS, "status": "verified",
                         "verification_sha256": "6" * 64, "support_sha256": "7" * 64}],
        "batch_costs_ns": {"base": [10 * MS, 200 * MS], "fast": [50 * MS, MS]},
        "remaining_budget_ns": 60 * MS, "completion_value_ns": 1000 * MS,
        "decision_cost_ns": MS,
        "observations": [{"stage": "completed-calibration", "wall_ns": 2000 * MS}],
    }


class FiniteGraphTests(unittest.TestCase):
    def test_full_future_plan_can_defer_a_real_transition(self):
        result = finite_plan_request(**fixture())
        self.assertTrue(result["enumeration_complete"])
        best = min(result["plans"].values(), key=lambda row: row["estimated_cost_ns"])
        # First deliver on the existing code, then pay setup before the larger
        # second workload: 10 + 1 decision + 20 setup + 1 execution = 32 ms.
        self.assertEqual([row["id"] for row in best["actions"]], ["hold", "install-fast"])
        self.assertEqual(best["estimated_cost_ns"], 32 * MS)
        stop = next(row for row in result["plans"].values() if row["actions"][0]["mode"] == "stop")
        self.assertEqual([row["mode"] for row in stop["actions"]], ["stop", "stopped"])
        self.assertEqual(stop["estimated_cost_ns"], 210 * MS)
        self.assertEqual(result["authority"], "DENY_ALL")

    def test_sunk_observations_bind_support_without_changing_future_values(self):
        earlier = fixture()
        later = deepcopy(earlier)
        later["observations"][0]["wall_ns"] *= 100
        first = finite_plan_request(**earlier)
        second = finite_plan_request(**later)
        self.assertEqual(first["plans"], second["plans"])
        for a, b in zip(first["request"]["candidates"], second["request"]["candidates"]):
            self.assertEqual(a["events"], b["events"])
            self.assertEqual(a["terminal_q32"], b["terminal_q32"])
            self.assertNotEqual(a["support_digest"], b["support_digest"])

    def test_known_rejection_cannot_be_laundered_by_later_verified_states(self):
        request = fixture()
        request["transitions"][0]["status"] = "rejected"
        result = finite_plan_request(**request)
        for plan in result["plans"].values():
            if any(action["id"] == "install-fast" for action in plan["actions"]):
                self.assertFalse(plan["verified"])

    def test_path_budget_exhaustion_is_not_silent_partial_search(self):
        request = fixture()
        with self.assertRaisesRegex(NduBridgeError, "complete enumeration"):
            finite_plan_request(**request, max_paths=1)

    def test_invalid_units_shapes_costs_and_unverified_current_state_reject(self):
        for change in (lambda data: data["transitions"][0].update(setup_ns=-1),
                       lambda data: data["batch_costs_ns"].update(base=[True, 2]),
                       lambda data: data["states"]["base"].update(status="unknown"),
                       lambda data: data["transitions"][0].update(unknown_field=1),
                       lambda data: data["states"]["fast"].update(source_sha256="0" * 64),
                       lambda data: data.update(generation=0),
                       lambda data: data["states"].update(fast=7),
                       lambda data: data.update(transitions=[7]),
                       lambda data: data["observations"].append({"value": float("nan")})):
            with self.subTest(change=change):
                request = fixture()
                change(request)
                with self.assertRaises(NduBridgeError):
                    finite_plan_request(**request)


def measured_bank_fixture():
    candidates = {}
    for index, (name, costs, setup, status) in enumerate((
        ("base", [10, 200, 200], 0, "verified"),
        ("guard-small", [50, 180, 180], 20, "verified"),
        ("guard-wide", [50, 1, 1], 20, "verified"),
        ("refused-unguarded", [0, 0, 0], 2, "rejected")), 1):
        candidates[name] = {"source_sha256": str(index) * 64,
            "verification": {"verification_sha256": str(index + 4) * 64, "status": status},
            "setup_ns": setup * MS, "latency_ns": {str(n): value * MS for n, value in zip((3, 17, 33), costs)}}
    return {"bank_sha256": "a" * 64, "candidates": candidates}


class CompilerGraphBoundaryTests(unittest.TestCase):


    def test_completed_measurements_update_only_the_observed_state(self):
        before = self.bundle()["support_evidence"]["graph"]["batch_costs_ns"]
        after = self.bundle([{"state": "base", "n": 3, "status": "measured", "outer_wall_ns": 20 * MS}])
        costs = after["support_evidence"]["graph"]["batch_costs_ns"]
        self.assertEqual(costs["base"], [value * 2 for value in before["base"]])
        self.assertEqual(costs["guard-wide"], before["guard-wide"])






@unittest.skipUnless(os.environ.get("HEPTA_FINITE_NDU_IDENTITY") and os.environ.get("HEPTA_FINITE_NDU_BRIDGE"),
                     "requires the separate finite-graph native source/tool profile")
class NativeFiniteGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bridge = NduBridge.from_finite_environment()

    def test_original_ndu_plans_two_batches_then_replans_and_stops(self):
        request = fixture()
        first = finite_plan_request(**request)
        response = self.bridge.evaluate(first["request"])
        plan = first["plans"][response["advisory_candidate_id"]]
        self.assertEqual([row["id"] for row in plan["actions"]], ["hold", "install-fast"])
        self.assertTrue(any("ResourceCeilingExceeded" in row["reasons"] for row in response["rejected"]))
        request.update(generation=4, snapshot_digest="8" * 64,
                       batch_costs_ns={"base": [200 * MS], "fast": [MS]})
        request["observations"].append({"stage": "delivered-first-batch", "wall_ns": 10 * MS})
        second = finite_plan_request(**request)
        response = self.bridge.evaluate(second["request"])
        self.assertEqual(second["plans"][response["advisory_candidate_id"]]["actions"][0]["id"], "install-fast")
        request.update(generation=5, snapshot_digest="9" * 64, initial_state="fast",
                       batch_costs_ns={"base": [200 * MS, 200 * MS], "fast": [MS, MS]})
        final = finite_plan_request(**request)
        response = self.bridge.evaluate(final["request"])
        self.assertEqual(final["plans"][response["advisory_candidate_id"]]["actions"][0]["mode"], "stop")

    def test_original_ndu_rejects_a_high_value_unverified_transition(self):
        request = fixture()
        request["remaining_budget_ns"] = 1000 * MS
        request["transitions"][0]["status"] = "rejected"
        result = finite_plan_request(**request)
        response = self.bridge.evaluate(result["request"])
        selected = result["plans"][response["advisory_candidate_id"]]
        self.assertEqual(selected["actions"][0]["mode"], "stop")
        self.assertTrue(any("HardConstraintViolation" in row["reasons"] for row in response["rejected"]))


_IDENTITY = os.environ.get("HEPTA_FINITE_NDU_IDENTITY")
_CLANG = os.environ.get("HEPTA_CLANG") or shutil.which("clang-20") or shutil.which("clang")
_FULL_READY = bool(_IDENTITY and os.environ.get("HEPTA_FINITE_NDU_BRIDGE")
                   and _CLANG and importlib.util.find_spec("z3"))






if __name__ == "__main__":
    unittest.main()
