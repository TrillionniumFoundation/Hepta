"""Cost-study correctness and actual native I/O; no timing acceptance assertions."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from hashlib import sha256
from itertools import product
import json
import os
from pathlib import Path
import random
import subprocess
import tempfile
import unittest

from hepta.hia_ndu import Q32
from tools.qualify_hia_ndu_net_value import (PROTOCOL_PATH, CompilationCredits,
    complete_budget_dp, controller_model, native_request, plan_key, validate_protocol,
    new_bridge, select_native, controller_episode, application_episode, calibration,
    DRIVER, ROOT, lower_source, standalone_totals, application_profile_totals)


class NetValueProtocolTests(unittest.TestCase):
    def setUp(self):
        self.protocol = json.loads(PROTOCOL_PATH.read_bytes())

    def test_complete_dp_matches_an_independent_exhaustive_budget_oracle(self):
        rng = random.Random(29)
        for _ in range(80):
            model = {"remaining_credits": rng.randrange(4), "modules": [
                [{"target": "base", "credits": 0, "cost_ns": rng.randrange(50), "verified": True},
                 {"target": "fast", "credits": 1, "cost_ns": rng.randrange(50), "verified": True},
                 {"target": "refused", "credits": 0, "cost_ns": 0, "verified": False}]
                for _ in range(3)]}
            feasible = []
            for choices in product(*model["modules"]):
                credits = sum(c["credits"] for c in choices)
                if credits <= model["remaining_credits"] and all(c["verified"] for c in choices):
                    feasible.append((sum(c["cost_ns"] for c in choices), credits,
                                     tuple(c["target"] for c in choices)))
            self.assertEqual(plan_key(complete_budget_dp(model)), min(feasible))

    def test_actual_shared_permit_has_one_owner_and_failed_attempt_is_not_refunded(self):
        credits = CompilationCredits(1)
        def attempt(module):
            try:
                credits.consume(module, "guard-wide")
                return True
            except RuntimeError:
                return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(attempt, range(32))), 1)
        self.assertEqual(credits.remaining, 0)
        self.assertEqual(len(credits.attempts), 1)
        # No success callback or refund operation exists. A later failed build
        # cannot cause this owner's consumed permit to be issued again.
        self.assertFalse(attempt("after-build-failure"))

    def test_request_binds_budget_support_generation_and_preserves_refusal(self):
        model = controller_model(1)
        request, _ = native_request(model, self.protocol, 7)
        self.assertEqual(request["resource_budget_q32"], Q32)
        refused = next(r for r in request["candidates"] if r["id"] == "known-refused")
        self.assertFalse(refused["verified"])
        changed = deepcopy(model)
        changed["remaining_credits"] = 0
        request2, _ = native_request(changed, self.protocol, 7)
        request3, _ = native_request(model, self.protocol, 8)
        self.assertNotEqual(request["snapshot_digest"], request2["snapshot_digest"])
        self.assertNotEqual(request["snapshot_digest"], request3["snapshot_digest"])
        self.assertEqual(request2["resource_budget_q32"], 0)

    def test_protocol_rejects_authority_source_and_unbounded_changes(self):
        validate_protocol(self.protocol)
        for key, value in (("authority", "ALLOW_ALL"), ("native_source_pin", "1" * 40),
                           ("calls", True), ("controller_timeout_s", float("nan")),
                           ("cache_entries", 129), ("default_cache_enabled", True)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_protocol(dict(self.protocol, **{key: value}))

    def test_aggregate_win_cannot_hide_a_losing_registered_profile(self):
        # Native wins the combined workload but loses the second standalone
        # workload once its actual cold cost is included. The acceptance text
        # requires every profile to win, not merely the sum of their work.
        protocol = {"groups": 1, "application_profiles": {"large-win": {}, "small-loss": {}}}
        rows = [{"profile": profile, "group": 0, "arm": arm, "wall_ns": cost, "admitted": True}
                for profile, costs in (("large-win", (100, 100, 20)), ("small-loss", (20, 20, 30)))
                for arm, cost in zip(("fixed", "dp", "native-stream-sealed"), costs)]
        combined = standalone_totals(rows, ("fixed", "dp", "native-stream-sealed"), 5, 2, 3, 10)
        self.assertLess(combined["standalone_cold_ns"]["native-stream-sealed"],
                        combined["standalone_cold_ns"]["fixed"])
        profiles = application_profile_totals(rows, protocol, 5, 2, 3, 10, source_unchanged=True)
        self.assertTrue(profiles["large-win"]["full_cost_advantage"])
        self.assertFalse(profiles["small-loss"]["full_cost_advantage"])
        self.assertFalse(all(row["full_cost_advantage"] for row in profiles.values()))
        self.assertEqual(profiles["small-loss"]["standalone_warm_ns"]["native-stream-sealed"], 40)
        self.assertEqual(profiles["small-loss"]["standalone_cold_ns"]["native-stream-sealed"], 50)
        self.assertEqual(profiles["small-loss"]["standalone_cold_ns"]["fixed"], 25)
        incomplete = application_profile_totals(rows[:-1], protocol, 5, 2, 3, 10, source_unchanged=True)
        self.assertFalse(incomplete["small-loss"]["all_application_outputs_and_budgets_admitted"])


@unittest.skipUnless(os.environ.get("HEPTA_NDU_STREAM_IDENTITY"), "requires actual c4 native stream")
class NetValueNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.identity = Path(os.environ["HEPTA_NDU_STREAM_IDENTITY"])
        cls.manifest = json.loads(cls.identity.read_bytes())
        cls.protocol = json.loads(PROTOCOL_PATH.read_bytes())

    def test_real_oneshot_rehash_and_sealed_select_budget_feasible_allocation_and_retain_io(self):
        with tempfile.TemporaryDirectory() as temporary:
            for arm in ("native-oneshot", "native-stream-rehash", "native-stream-sealed"):
                folder = Path(temporary) / arm
                bridge = new_bridge(arm, self.manifest, self.identity, folder, self.protocol)
                try:
                    chosen, evidence = select_native(controller_model(2), self.protocol, 1, bridge)
                    self.assertEqual(chosen["targets"], ["base", "fast"])
                    self.assertEqual(evidence["response"]["authority"], "DENY_ALL")
                    self.assertTrue(any(r["id"] == "known-refused" for r in evidence["response"]["rejected"]))
                    self.assertGreater(len(list(folder.glob("*.stdout"))), 1)
                    self.assertTrue(any(b"objective_digest" in p.read_bytes() for p in folder.glob("*.stdin")))
                finally:
                    if hasattr(bridge, "close"):
                        bridge.close()

    def test_exact_reuse_and_changed_generation_use_real_expected_request_counts(self):
        with tempfile.TemporaryDirectory() as temporary:
            p = dict(self.protocol, controller_keys=2, controller_repetitions=2)
            for profile, expected in (("identical-retries", 2), ("changed-generation", 4)):
                row = controller_episode(Path(temporary) / profile, "native-stream-sealed-cache",
                                         profile, 0, p, self.manifest, self.identity)
                self.assertEqual(row["status"], "completed", row.get("error"))
                self.assertEqual(row["native_session"]["requests"], expected)
                self.assertEqual(row["cache_closed"]["hits"], 4 - expected)

    def test_tiny_functional_application_runs_fresh_proofs_and_actual_loaded_outputs(self):
        # A deliberately tiny nonregistered fixture, distinct from the formal
        # workload. Timing is not compared and cannot qualify economic benefit.
        clang = os.environ.get("CLANG", "clang")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "driver.c").write_text(DRIVER)
            driver = root / "driver"
            subprocess.run([clang, "-O3", "-std=c11", str(root / "driver.c"), "-ldl", "-o", str(driver)],
                           capture_output=True, check=True, timeout=60)
            p = dict(self.protocol, calls=3, calibration_repetitions=1)
            p["application_profiles"] = {"functional-only": {"module_sizes": [[31, 31]], "compile_credits": 1}}
            base = lower_source((ROOT / "experiments/hia_optimizer_eval/kernels.hepta").read_text())
            bank = calibration(base, root, driver, clang,
                dict(p, probe_size=31, batch_sizes=p["calibration_sizes"]), [])
            for target in p["guard_limits"]:
                bank["candidates"][target]["proposal"] = json.loads((root / (target + ".proposal.json")).read_bytes())
            for arm in ("fixed", "dp", "native-stream-sealed"):
                result = application_episode(root / arm, arm, "functional-only", 0, p,
                    self.manifest, self.identity, base, bank, driver, clang)
                self.assertTrue(result["admitted"], result.get("error"))
                self.assertEqual(len(result["observations"]), 3)
                self.assertTrue(all(r["loaded_mapping_verified"] for r in result["observations"]))
                self.assertGreaterEqual(sum(r["label"].startswith("fresh-proof.") for r in result["ledger"]), 3)
                self.assertLessEqual(result["compile_credit"]["used"], 1)


if __name__ == "__main__":
    unittest.main()
