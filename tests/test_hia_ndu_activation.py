"""Discriminating controls for heterogeneous forecast and native attribution."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.qualify_hia_ndu_activation import (
    MODULES, TARGETS, PROTOCOL_PATH, PROFILE, DRIVER, CompilationCredits,
    allocation_model, calibration_order, checksum, decision_analysis, episode,
    lower_source, validate_protocol, calibrate)


def fixture_bank():
    return {"bank_sha256": "a" * 64, "modules": {module: {"candidates": {
        target: {"setup_ns": 20, "verification": {"status": "verified"},
                 "latency_ns": {"127": 100, "4093": 1_000, "32749": 10_000}}
        for target in TARGETS}} for module in MODULES}}


class ActivationForecastTests(unittest.TestCase):
    def setUp(self):
        self.p = json.loads(PROTOCOL_PATH.read_bytes())

    def test_protocol_bounds_and_authority_are_enforced(self):
        validate_protocol(self.p)
        for key, value in (("authority", "ALLOW_ALL"), ("calls", True),
                           ("native_source_pin", "1" * 40), ("controller_timeout_s", float("nan")),
                           ("previous_negative_results_replaced", True)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_protocol(dict(self.p, **{key: value}))
        changed = deepcopy(self.p)
        changed["application_profiles"]["shared-budget"]["modules"] = ["byte_sum", "byte_sum"]
        with self.assertRaises(ValueError):
            validate_protocol(changed)

    def test_small_input_observation_does_not_reprice_large_or_other_module(self):
        bank = fixture_bank()
        spec = {"modules": list(MODULES), "module_sizes": [[127,32749], [127,32749]]}
        artifacts = {(module, "base"): object() for module in MODULES}
        before = allocation_model(bank, spec, 0, [], artifacts, CompilationCredits(1))
        obs = [{"module": "byte_sum", "state": "base", "n": 127,
                "status": "measured", "outer_wall_ns": 1, "delivery_cost_ns": 1}]
        after = allocation_model(bank, spec, 0, obs, artifacts, CompilationCredits(1))
        self.assertEqual(before["modules"][0][0]["cost_ns"], 10_100)
        self.assertEqual(after["modules"][0][0]["cost_ns"], 10_001)
        self.assertEqual(before["modules"][0][1:], after["modules"][0][1:])
        self.assertEqual(before["modules"][1], after["modules"][1])
        future = allocation_model(bank, spec, 1, obs, artifacts, CompilationCredits(1))
        self.assertEqual(future["modules"][0][0]["cost_ns"], 10_000)

    def test_failed_observation_cannot_update_forecast(self):
        bank = fixture_bank()
        spec = {"modules": ["byte_sum"], "module_sizes": [[127,127]]}
        args = (bank, spec, 0)
        artifacts = {("byte_sum", "base"): object()}
        before = allocation_model(*args, [], artifacts, CompilationCredits(1))
        after = allocation_model(*args, [{"module": "byte_sum", "state": "base", "n": 127,
             "status": "wrong-output", "outer_wall_ns": 0, "delivery_cost_ns": 0}], artifacts, CompilationCredits(1))
        self.assertEqual(before["modules"], after["modules"])

    def test_fresh_proof_cost_is_included_in_forecast_observation(self):
        bank = fixture_bank()
        spec = {"modules": ["byte_sum"], "module_sizes": [[127,127]]}
        artifacts = {("byte_sum", "base"): object()}
        result = allocation_model(bank, spec, 0, [{"module": "byte_sum", "state": "base", "n": 127,
            "status": "measured", "outer_wall_ns": 1, "delivery_cost_ns": 901}], artifacts, CompilationCredits(1))
        self.assertEqual(result["modules"][0][0]["cost_ns"], 1_802)

    def test_calibration_interleaves_all_distinct_module_and_target_pairs(self):
        expected = {(m, t) for m in MODULES for t in TARGETS}
        starts = set()
        for repetition in range(3):
            for size in range(3):
                order = calibration_order(repetition, size)
                self.assertEqual(len(order), 6)
                self.assertEqual(set(order), expected)
                starts.add(order[0])
        self.assertGreater(len(starts), 1)

    def test_checksum_matches_direct_independent_loops_including_period_boundaries(self):
        for module in MODULES:
            for n in (0, 1, 127, 255, 256, 257, 4093):
                for calls in (1, 3, 257):
                    seed = 251
                    total = 0
                    for call in range(calls):
                        s = (seed + call) % 256
                        for i in range(n):
                            total += ((i + s) % 256 if module == "byte_sum" else
                                      ((13 * i + s) % 256) ^ ((i + (s ^ 90)) % 256))
                    self.assertEqual(checksum(module, n, calls, seed), total)

    def test_semantic_modules_are_distinct_canonical_cores(self):
        cores = [lower_source((PROFILE / (m + ".hepta")).read_text()) for m in MODULES]
        self.assertNotEqual(cores[0].sha256, cores[1].sha256)
        count = lambda p: sum(op["op"] == "buffer.try_new" for f in p.as_dict()["functions"] for b in f["blocks"] for op in b["ops"])
        self.assertEqual([count(p) for p in cores], [1, 2])

    def test_selection_and_activation_are_not_inferred_from_elapsed_time(self):
        result = decision_analysis([])
        self.assertFalse(result["ndu_candidate_activation_observed"])
        self.assertFalse(result["ndu_shared_budget_competition_executed"])
        self.assertFalse(result["ndu_selections_match_complete_dp"])
        self.assertFalse(result["activation_implies_net_benefit"])


@unittest.skipUnless(os.environ.get("HEPTA_NDU_STREAM_IDENTITY"), "requires real c4 native NDU stream")
class ActivationNativeTests(unittest.TestCase):
    def test_two_semantic_modules_execute_in_every_arm_and_preserve_shared_credit(self):
        p = json.loads(PROTOCOL_PATH.read_bytes())
        p.update(calls=3, calibration_repetitions=1)
        p["application_profiles"] = {"shared-budget": {
            "modules": list(MODULES), "module_sizes": [[127,4093],[4093,127]], "compile_credits": 1}}
        clang = os.environ.get("CLANG", "clang")
        identity = Path(os.environ["HEPTA_NDU_STREAM_IDENTITY"])
        manifest = json.loads(identity.read_bytes())
        bases = {m: lower_source((PROFILE / (m + ".hepta")).read_text()) for m in MODULES}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "driver.c").write_text(DRIVER)
            driver = root / "driver"
            subprocess.run([clang, "-O3", "-std=c11", str(root / "driver.c"), "-ldl", "-o", str(driver)],
                           capture_output=True, check=True, timeout=60)
            bank = calibrate(bases, root / "calibration", driver, clang, p)
            rows = []
            for arm in p["arms"]:
                row = episode(root / arm, arm, "shared-budget", 0, p, manifest, identity,
                              bases, bank, driver, clang)
                self.assertTrue(row["admitted"], row.get("error"))
                self.assertEqual(len(row["observations"]), 6)
                self.assertEqual({o["module"] for o in row["observations"]}, set(MODULES))
                self.assertLessEqual(row["compile_credit"]["used"], 1)
                rows.append(row)
            self.assertTrue(decision_analysis(rows)["ndu_selections_match_complete_dp"])


if __name__ == "__main__":
    unittest.main()
