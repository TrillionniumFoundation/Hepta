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
from tools.qualify_hia_ndu_graph import (ARMS, PROTOCOL, arithmetic_choice,
    graph_bundle, light_bundle, qualify, run_episode, selected_native_plan)
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
    def bundle(self, observations=None):
        return graph_bundle(measured_bank_fixture(), current="base", remaining_sizes=[3, 17, 33],
            observations=[] if observations is None else observations, remaining_ns=1000 * MS,
            decision_ns=MS, protocol=PROTOCOL, snapshot="b" * 64, generation=1)

    def test_lightweight_control_searches_complete_future_paths(self):
        bundle = self.bundle()
        plan = arithmetic_choice(bundle, remaining_ns=1000 * MS, completion_ns=1000 * MS)
        self.assertEqual([a["mode"] for a in plan["actions"]], ["hold", "transition", "stop"])
        self.assertEqual(plan["actions"][1]["target"], "guard-wide")
        self.assertEqual(plan["estimated_cost_ns"], 34 * MS)
        self.assertTrue(bundle["enumeration_complete"])
        self.assertTrue(any(not p["verified"] for p in bundle["plans"].values()))

    def test_completed_measurements_update_only_the_observed_state(self):
        before = self.bundle()["support_evidence"]["graph"]["batch_costs_ns"]
        after = self.bundle([{"state": "base", "n": 3, "status": "measured", "outer_wall_ns": 20 * MS}])
        costs = after["support_evidence"]["graph"]["batch_costs_ns"]
        self.assertEqual(costs["base"], [value * 2 for value in before["base"]])
        self.assertEqual(costs["guard-wide"], before["guard-wide"])

    def test_efficient_control_matches_complete_enumeration_without_native_wire(self):
        for seed in range(20):
            bank = measured_bank_fixture()
            for offset, row in enumerate(bank["candidates"].values()):
                row["setup_ns"] = ((seed * 19 + offset * 7) % 53) * MS
                for n in row["latency_ns"]:
                    row["latency_ns"][n] = (1 + (seed * int(n) + offset * 17) % 211) * MS
            arguments = dict(current="base", remaining_sizes=[3, 17, 33], observations=[],
                remaining_ns=1000 * MS, decision_ns=(seed % 4) * MS,
                protocol=PROTOCOL, snapshot="b" * 64, generation=1)
            native = graph_bundle(bank, **arguments)
            light = light_bundle(bank, **arguments)
            a = arithmetic_choice(native, remaining_ns=1000 * MS, completion_ns=1000 * MS)
            b = arithmetic_choice(light, remaining_ns=1000 * MS, completion_ns=1000 * MS)
            self.assertEqual(a["actions"], b["actions"])
            self.assertEqual(a["estimated_cost_ns"], b["estimated_cost_ns"])
            self.assertEqual(len(native["plans"]), light["covered_path_count"])
            self.assertNotIn("request", light)

    def test_all_fixed_light_and_native_arms_refuse_exhausted_actual_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = verify_program(program())
            for arm in ARMS:
                result = run_episode(arm, 0, base, {"bank_sha256": "a" * 64}, Path(temporary),
                    None, None, "must-not-be-invoked", dict(PROTOCOL, episode_budget_ns=0), {})
                self.assertEqual(result["status"], "budget-exhausted")
                self.assertFalse(result["completion_admitted"])
                self.assertEqual(result["ledger"], [])
            self.assertEqual(list(Path(temporary).rglob("*.so")), [])

    def test_native_unresolved_and_ineligible_advice_never_mints_authority(self):
        bundle = self.bundle()
        with self.assertRaisesRegex(OptimizationRejected, "UNRESOLVED"):
            selected_native_plan(bundle, {"advisory_candidate_id": None})
        bad = next(p["id"] for p in bundle["plans"].values() if not p["verified"])
        with self.assertRaisesRegex(OptimizationRejected, "INELIGIBLE"):
            selected_native_plan(bundle, {"advisory_candidate_id": bad})
        self.assertIsNone(selected_native_plan(bundle, {"advisory_candidate_id": "abstain"}))

    def test_control_does_not_deliver_unaffordable_or_negative_value_paths(self):
        bundle = self.bundle()
        self.assertIsNone(arithmetic_choice(bundle, remaining_ns=1, completion_ns=1000 * MS))
        self.assertIsNone(arithmetic_choice(bundle, remaining_ns=1000 * MS, completion_ns=1))


@unittest.skipUnless(os.environ.get("HEPTA_NDU_IDENTITY"), "requires a built original native NDU bridge")
class NativeFiniteGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(os.environ["HEPTA_NDU_IDENTITY"])
        cls.bridge = NduBridge(json.loads(path.read_bytes())["binary"], path)

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


_IDENTITY = os.environ.get("HEPTA_NDU_IDENTITY")
_CLANG = os.environ.get("HEPTA_CLANG") or shutil.which("clang-20") or shutil.which("clang")
_FULL_READY = bool(_IDENTITY and _CLANG and importlib.util.find_spec("z3"))


@unittest.skipUnless(_FULL_READY, "requires original NDU identity, pinned Z3 and Clang for actual compiler graph")
class ActualCompilerGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name) / "graph"
        protocol = dict(PROTOCOL, groups=1, calls=17, probe_size=7, batch_sizes=[7, 31, 257],
                        calibration_repetitions=1, guard_limits={"guard-small": 16, "guard-wide": 512})
        cls.result = qualify(cls.root, identity=_IDENTITY, clang=_CLANG, protocol=protocol)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_actual_independent_proof_build_and_sealed_execution_complete(self):
        result = self.result
        self.assertTrue(result["all_episodes_completed"], [(r["arm"], r["status"], r.get("error")) for r in result["episodes"]])
        self.assertTrue(result["all_outputs_correct"])
        self.assertTrue(result["all_actual_budgets_passed"])
        self.assertGreaterEqual(result["actual_transitions"], 2)
        for row in result["episodes"]:
            self.assertEqual(len(row["observations"]), 4)
            for sample in row["observations"]:
                self.assertTrue(sample["loaded_snapshot_sealed"])
                self.assertEqual(sample["artifact_sha256"], sample["expected_artifact_sha256"])
            for transition in row["transitions"]:
                self.assertEqual(transition["receipt"]["verification"]["status"], "verified")
                self.assertTrue(transition["receipt"]["claims"]["final_artifact_bound"])

    def test_native_multi_batch_paths_and_controls_use_same_calibration(self):
        result = self.result
        self.assertEqual({r["same_initial_information"] for r in result["episodes"]}, {result["bank_sha256"]})
        ndu = next(r for r in result["episodes"] if r["arm"] == "ndu")
        first = ndu["decisions"][0]
        self.assertEqual(first["native_response"]["identity"], result["native_identity"])
        self.assertEqual(first["native_response"]["authority"], "DENY_ALL")
        self.assertTrue(first["bundle"]["enumeration_complete"])
        self.assertEqual(first["bundle"]["support_evidence"]["graph"]["horizon"], 3)
        self.assertTrue(any(len(c["events"]) == 6 for c in first["bundle"]["request"]["candidates"]))
        self.assertTrue(any("HardConstraintViolation" in r["reasons"] for r in first["native_response"]["rejected"]))
        self.assertFalse(result["global_optimality_claim"])
        self.assertFalse(result["statistical_superiority_established"])

    def test_actual_rejection_drift_timeout_and_artifact_mismatch_fail_closed(self):
        bank = json.loads((self.root / "BANK.json").read_bytes())
        invalid = bank["candidates"]["refused-unguarded"]
        self.assertEqual(invalid["verification"]["status"], "rejected")
        self.assertIsNone(invalid["artifact"])
        faults = json.loads((self.root / "FAULTS.json").read_bytes())
        self.assertEqual(faults["verifier_timeout"]["status"], "timeout")
        self.assertEqual(faults["process_timeout"]["status"], "timeout")
        self.assertFalse(faults["snapshot_drift"]["execution_attempted"])
        self.assertFalse(faults["artifact_mismatch"]["execution_attempted"])


@unittest.skipUnless(_FULL_READY and os.environ.get("HEPTA_NDU_STREAM_IDENTITY"),
                     "requires sealed original streaming NDU, pinned Z3 and Clang")
class ActualStreamingNarrowingGraphTests(ActualCompilerGraphTests):
    """A different native candidate chain and actual persistent evaluator process."""

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name) / "stream-graph"
        protocol = dict(PROTOCOL, groups=1, calls=19, probe_size=5, batch_sizes=[5, 19, 47],
                        calibration_repetitions=1, guard_limits={"guard-small": 8, "guard-wide": 32},
                        native_transport="stream", narrow_targets=["guard-wide"])
        cls.result = qualify(cls.root, identity=os.environ["HEPTA_NDU_STREAM_IDENTITY"],
                             clang=_CLANG, protocol=protocol)

    def test_actual_persistent_requests_and_chained_artifacts_are_accounted(self):
        self.assertEqual(self.result["native_transport"], "stream")
        session = self.result["native_session"]
        self.assertTrue(session["closed"])
        self.assertGreaterEqual(session["requests"], 4)
        self.assertEqual(session["authority"], "DENY_ALL")
        labels = {r["label"] for r in self.result["controller_setup_ledger"]["ndu"]}
        self.assertTrue({"native.admission", "native.shutdown", "native.snapshot"} <= labels)
        bank = json.loads((self.root / "BANK.json").read_bytes())
        proof = bank["candidates"]["guard-wide"]["receipt"]["verification"]
        self.assertEqual(proof["status"], "verified")
        self.assertEqual(len(proof["stages"]), 2)
        for row in self.result["episodes"]:
            for sample in row["observations"]:
                self.assertTrue(sample["loaded_mapping_verified"])


if __name__ == "__main__":
    unittest.main()
