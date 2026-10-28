"""Actual finite compiler-loop tests; native/solver prerequisites are explicit."""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_ndu import NduBridge
from tools.qualify_hia_ndu_loop import (ARMS, PROTOCOL, decision_request, digest,
                                      execute_sample, oracle, program, qualify, run_episode)


class LoopBoundaryTests(unittest.TestCase):
    def test_checksum_oracle_against_direct_integer_work(self):
        for multiplier in (13, 17, 23, 255):
            for n, calls, seed in ((0, 1, 0), (19, 31, 91), (257, 263, 255)):
                expected = sum(sum((i * multiplier + ((seed + call) & 255)) & 255
                                   for i in range(n)) for call in range(calls))
                self.assertEqual(oracle(n, calls, seed, multiplier), expected)
        with self.assertRaises(ValueError):
            oracle(1, 1, 1, 2)

    def test_all_controls_refuse_an_exhausted_budget_before_build(self):
        protocol = dict(PROTOCOL, episode_budget_ns=0)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for arm in ARMS:
                result = run_episode(arm, 0, 11, 17, program(17), {"bank_sha256": "a" * 64},
                                     root, None, None, "must-not-be-invoked", protocol)
                self.assertEqual(result["status"], "budget-exhausted")
                self.assertFalse(result["completion_admitted"])
                self.assertEqual(result["ledger"], [])
            self.assertEqual(list(root.rglob("*.so")), [])


_IDENTITY = os.environ.get("HEPTA_RECURSIVE_NDU_IDENTITY")
_BRIDGE = os.environ.get("HEPTA_RECURSIVE_NDU_BRIDGE")
_CLANG = os.environ.get("HEPTA_CLANG") or shutil.which("clang-20") or shutil.which("clang")
_READY = bool(_IDENTITY and _BRIDGE and _CLANG and importlib.util.find_spec("z3"))


@unittest.skipUnless(_READY, "requires recursive NDU identity/binary, Z3 and Clang for actual native execution")
class NativeFiniteLoopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name) / "run"
        cls.protocol = dict(PROTOCOL, groups=1, calls=31, training_sizes=[7, 19], holdout_sizes=[11])
        cls.result = qualify(cls.root, identity=_IDENTITY, executable=_BRIDGE,
                             clang=_CLANG, protocol=cls.protocol)
        cls.bank = json.loads((cls.root / "BANK.json").read_bytes())
        cls.faults = json.loads((cls.root / "FAULTS.json").read_bytes())

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_actual_candidates_are_built_rejected_and_executed(self):
        result = self.result
        self.assertTrue(result["all_actual_outputs_correct"], result["episodes"])
        self.assertTrue(result["all_episodes_completed"], result["episodes"])
        self.assertTrue(result["all_actual_budgets_passed"])
        rejected = self.bank["candidates"]["invalid-constant"]["receipt"]
        self.assertEqual(rejected["verification"]["status"], "rejected")
        self.assertFalse(rejected["artifact_created"])
        self.assertFalse((self.root / "calibration-invalid-constant.so").exists())
        folded = next(row for row in result["episodes"] if row["arm"] == "fixed-fold")
        self.assertEqual(folded["selected"], "constant-fold")
        self.assertTrue((self.root / "episode-0-11-fixed-fold/folded.so").is_file())
        self.assertEqual(folded["chosen"]["native"]["verification"]["status"], "verified")
        self.assertIn("continuation.verify-build", [stage["label"] for stage in folded["ledger"]])

    def test_native_recursion_uses_current_proofs_and_actual_refusal_cost(self):
        row = next(row for row in self.result["episodes"] if row["arm"] == "ndu")
        self.assertEqual(row["selection"]["identity"], self.result["native_identity"])
        self.assertEqual(row["selection"]["authority"], "DENY_ALL")
        admission = row["current_candidate_admission"]
        self.assertEqual(admission["folded"]["base_sha256"], row["baseline"]["verification"]["base_sha256"])
        self.assertEqual(admission["invalid"]["status"], "rejected")
        candidates = {candidate["id"]: candidate for candidate in row["request"]["candidates"]}
        self.assertEqual(candidates["constant-fold"]["verification_digest"], admission["folded"]["verification_sha256"])
        self.assertFalse(candidates["invalid-constant"]["verified"])
        self.assertEqual(len(candidates["stop"]["events"]), 2)
        self.assertLess(candidates["stop"]["events"][1]["instant_q32"], 0)
        support = row["forecast"]["support_evidence"]
        self.assertEqual(candidates["stop"]["support_digest"], digest(support))
        refusal = next(step for step in support["completed_steps"] if step["label"] == "planning.reject-invalid")
        self.assertGreater(refusal["wall_ns"], 0)
        self.assertFalse(row["forecast"]["future_observed"])
        self.assertFalse(row["future_access"])

    def test_long_sunk_cost_does_not_cancel_an_affordable_continuation(self):
        row = next(row for row in self.result["episodes"] if row["arm"] == "ndu")
        admission = row["current_candidate_admission"]
        first = dict(row["initial"], outer_wall_ns=4_280_000)
        observed = deepcopy(row["forecast"]["support_evidence"]["completed_steps"])
        bridge = NduBridge.from_environment()
        requests, responses = [], []
        # This is a protocol regression, not a performance measurement: only a
        # past cost changes; the current code, future estimates and budget agree.
        for sunk in (10_000, 2_000_000_000):
            evidence = deepcopy(observed)
            evidence[0]["wall_ns"] = sunk
            request, forecast = decision_request(self.bank, first, evidence,
                snapshot=row["request"]["snapshot_digest"], verification=row["baseline"]["verification"],
                folded_verification=admission["folded"], rejected_verification=admission["invalid"],
                remaining_ns=20_000_000_000, protocol=self.protocol)
            requests.append(request)
            responses.append(bridge.evaluate(request))
            self.assertGreaterEqual(forecast["observed_sunk_cost_ns"], sunk)
        self.assertEqual([response["advisory_candidate_id"] for response in responses], ["stop", "stop"])
        for earlier, later in zip(requests[0]["candidates"], requests[1]["candidates"]):
            self.assertEqual(earlier["events"], later["events"])
            self.assertEqual(earlier["terminal_q32"], later["terminal_q32"])
            self.assertNotEqual(earlier["support_digest"], later["support_digest"])

    def test_actual_child_loads_pinned_bytes_when_source_path_is_replaced(self):
        library = self.root / "calibration-identity.so"
        original = library.read_bytes()
        expected = self.bank["candidates"]["identity"]["receipt"]["native"]["native"]["artifact_sha256"]
        from tools import qualify_hia_ndu_loop as loop
        real_run = loop.subprocess.run
        def replace_then_execute(*args, **kwargs):
            library.write_bytes(b"unverified replacement, never eligible for dlopen")
            return real_run(*args, **kwargs)
        try:
            with patch.object(loop.subprocess, "run", replace_then_execute):
                result = execute_sample(self.root / "driver", library, n=11, calls=31, seed=91,
                                        expected_artifact_sha256=expected)
            self.assertEqual(result["status"], "measured")
            self.assertEqual(result["artifact_sha256"], expected)
            self.assertEqual(result["artifact_load"], "sealed-memfd")
            self.assertTrue(result["command"][1].startswith("/proc/self/fd/"))
            rejected = execute_sample(self.root / "driver", library, n=11, calls=31, seed=91,
                                      expected_artifact_sha256=expected)
            self.assertEqual(rejected["status"], "artifact-rejected")
            self.assertFalse(rejected["execution_attempted"])
        finally:
            library.write_bytes(original)

    def test_real_timeout_and_drift_fail_closed(self):
        faults = self.faults
        self.assertEqual(faults["verifier_timeout"]["verification"]["status"], "timeout")
        self.assertFalse(faults["verifier_timeout"]["artifact_created"])
        self.assertFalse((self.root / "timeout-must-not-exist.so").exists())
        self.assertEqual(faults["snapshot_drift"]["status"], "rejected")
        self.assertFalse(faults["snapshot_drift"]["execution_attempted"])
        self.assertEqual(faults["process_timeout"]["status"], "timeout")
        self.assertGreater(faults["process_timeout"]["outer_wall_ns"], 0)

    def test_costs_include_all_stages_and_fixed_controls_avoid_optional_work(self):
        result = self.result
        for row in result["episodes"]:
            self.assertEqual(row["same_initial_information"], self.bank["bank_sha256"])
            self.assertGreaterEqual(row["episode_wall_ns"], sum(stage["wall_ns"] for stage in row["ledger"]))
            self.assertEqual(row["net_cost_ns"], row["episode_wall_ns"])
            self.assertGreater(result["standalone_total_cost_ns"][row["arm"]], row["net_cost_ns"])
            if row["arm"] in ("fixed-stop", "fixed-selected", "light") and row["selected"] == "stop":
                self.assertFalse(any(stage["label"].startswith("planning.") for stage in row["ledger"]))
        self.assertTrue(result["setup_accounting"]["shared_charged_once_per_standalone_strategy"])
        self.assertFalse(result["statistical_superiority_established"])
        self.assertFalse(result["global_optimality_claim"])
        self.assertFalse(result["safety_from_ndu_claim"])


if __name__ == "__main__":
    unittest.main()
