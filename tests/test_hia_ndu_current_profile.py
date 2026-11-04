"""Source selection and measured costs across stream revisions."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import call, patch
from hepta.hia_ndu import NduBridgeError
from hepta.hia_ndu_session import NduSession, STREAM_PROFILE_PINS
from tools.qualify_hia_ndu_cost import (full_cost_totals, policy_model_evidence,
                                      episodes_without_native_start)
from tools import qualify_hia_ndu_cost as cost
from tools import qualify_hia_ndu_budget_erasure as planner


class CurrentProfileTests(unittest.TestCase):
    def test_explicit_profiles_require_distinct_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            for profile, expected in STREAM_PROFILE_PINS.items():
                for actual in (*STREAM_PROFILE_PINS.values(), "1" * 40):
                    manifest = {"identity": {"source_commit": actual}}
                    path.write_text(json.dumps(manifest))
                    def fake_init(instance, *_args, **_kwargs):
                        instance.manifest = manifest
                    with self.subTest(profile=profile, source=actual), patch.object(NduSession, "__init__", fake_init):
                        if actual == expected:
                            session = NduSession.for_stream_profile("unused", path, profile=profile)
                            self.assertEqual(session.manifest, manifest)
                        else:
                            with self.assertRaisesRegex(NduBridgeError, "explicitly selected"):
                                NduSession.for_stream_profile("unused", path, profile=profile)

    def test_unknown_profile_refuses_before_io(self):
        for value in (None, False, [], {}, "auto", "1" * 40):
            with self.subTest(value=value), patch("hepta.hia_ndu_session._manifest_bytes", side_effect=AssertionError("read")):
                with self.assertRaisesRegex(NduBridgeError, "unknown native stream"):
                    NduSession.for_stream_profile("unused", "missing", profile=value)

    def rows(self, invoked=False, matches=True):
        rows = [{"policy": p, "service_wall_ns": 7, "steps": [{"decision": {
            "native_invoked": invoked if p == "native_ndu" else False,
            "native_matches_exact_model": matches}}]}
            for p in ("fixed", "exact_dp", "lightweight", "native_ndu")]
        if invoked:
            # Unit-level completed-response marker, never a real native receipt.
            rows[-1]["steps"][0]["decision"]["response"] = {"fixture": "completed response"}
        return rows

    def test_no_invocation_is_unknown_agreement(self):
        result = policy_model_evidence(self.rows())
        self.assertIsNone(result["native_matches_same_information_exact_model"])
        self.assertEqual(result["native_model_attempted_count"], 0)
        self.assertEqual(result["native_model_evaluated_count"], 0)
        self.assertEqual(result["native_model_failed_count"], 0)
        self.assertIsNone(result["native_model_all_attempts_completed"])
        self.assertFalse(result["native_policy_evidence_present"])
        for matches in (True, False, None):
            result = policy_model_evidence(self.rows(True, matches))
            self.assertEqual(result["native_model_attempted_count"], 1)
            self.assertEqual(result["native_model_evaluated_count"], 1)
            self.assertEqual(result["native_model_failed_count"], 0)
            self.assertTrue(result["native_model_all_attempts_completed"])
            self.assertIs(result["native_matches_same_information_exact_model"], matches is True)

    def test_failed_attempt_does_not_count_as_a_completed_model_evaluation(self):
        mutations = (
            lambda d: d.pop("response"),
            lambda d: d.update(response=None),
            lambda d: d.update(response={}),
            lambda d: d.update(native_error="native request failed"),
        )
        for mutate in mutations:
            rows = self.rows(True)
            mutate(rows[-1]["steps"][0]["decision"])
            result = policy_model_evidence(rows)
            self.assertEqual(result["native_model_attempted_count"], 1)
            self.assertEqual(result["native_model_evaluated_count"], 0)
            self.assertEqual(result["native_model_failed_count"], 1)
            self.assertFalse(result["native_policy_evidence_present"])
            self.assertFalse(result["native_model_all_attempts_completed"])
            self.assertIsNone(result["native_matches_same_information_exact_model"])

    def test_failed_call_cannot_be_hidden_by_a_matching_successful_subset(self):
        rows = self.rows(True)
        rows[-1]["steps"].append({"decision": {
            "native_invoked": True, "native_error": "timeout", "native_matches_exact_model": True}})
        result = policy_model_evidence(rows)
        self.assertEqual(result["native_model_attempted_count"], 2)
        self.assertEqual(result["native_model_evaluated_count"], 1)
        self.assertEqual(result["native_model_failed_count"], 1)
        self.assertTrue(result["native_policy_evidence_present"])
        self.assertFalse(result["native_model_all_attempts_completed"])
        self.assertFalse(result["native_matches_same_information_exact_model"])

    def test_unknown_build_never_becomes_zero_cost(self):
        manifests = [{}, {"build_cost": None}, {"build_cost": {}}]
        manifests += [{"build_cost": {"wall_ns": x}} for x in (None, False, -1, "7", 7.0)]
        for manifest in manifests:
            with self.subTest(manifest=manifest):
                result = full_cost_totals(self.rows(), 100, manifest)
                self.assertFalse(result["build_cost_observed"])
                self.assertIsNone(result["arm_full_cost_ns"]["native_ndu"])
                self.assertFalse(result["execution_scope_cost_complete"])
                self.assertEqual(result["arm_full_cost_ns"]["exact_dp"], 107)
                self.assertEqual(result["unknown_costs"], ["native_bridge_build_wall_ns"])

    def test_known_build_is_charged_once_only_to_native(self):
        result = full_cost_totals(self.rows(), 100, {"build_cost": {"wall_ns": 23}})
        self.assertTrue(result["build_cost_observed"])
        self.assertEqual(result["arm_full_cost_ns"], {
            "fixed": 107, "exact_dp": 107, "lightweight": 107, "native_ndu": 130})
        self.assertEqual(result["unknown_costs"], [])
        self.assertTrue(result["execution_scope_cost_complete"])

    def test_known_execution_cost_does_not_fill_unmeasured_lifecycle_costs(self):
        for manifest in ({}, {"build_cost": {"wall_ns": 23}}):
            result = full_cost_totals(self.rows(), 100, manifest)
            self.assertIn("separate composition outer receipts", result["cost_scope"])
            self.assertEqual(result["unknown_costs_scope"], "declared execution scope only")
            self.assertFalse(result["full_lifecycle_cost_complete"])
            self.assertGreaterEqual(len(result["unmeasured_lifecycle_costs"]), 4)
            self.assertTrue(all(value is None for value in result["unmeasured_lifecycle_costs"].values()))

    def test_started_session_without_evaluation_is_not_a_no_start_episode(self):
        row = {"policy": "native_ndu", "native_invocations": 0,
               "steps": [{"decision": {"native_invoked": False, "startup_ns": 0,
                                       "startup_attempted": False, "session_ready_before": False}}]}
        self.assertEqual(episodes_without_native_start([row]), 1)
        self.assertEqual(episodes_without_native_start([{**row, "native_session": {"requests": 0}}]), 0)
        row["steps"][0]["decision"]["startup_ns"] = 10
        self.assertEqual(episodes_without_native_start([row]), 0)


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "memfd_create"),
                     "real Linux memfd seals and readable fd aliases required")
class ResidentArtifactIdentityTests(unittest.TestCase):
    """Actual fd identity checks; dispatch is a unit stub, not native execution."""
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.library = Path(directory.name) / "c.so"
        self.library.write_bytes(b"unit-native-artifact-original")
        self.product = cost.native.file_identity(self.library)

    def pin(self, path=None):
        _, _, descriptor = cost._pin_native_artifact(path or self.library)
        self.addCleanup(os.close, descriptor)
        return descriptor, f"/proc/self/fd/{descriptor}"

    def bound(self):
        descriptor, alias = self.pin()
        return cost.ResidentDriver.bind_product(self.product, descriptor, alias)

    def owner(self):
        owner = cost.ResidentDriver.__new__(cost.ResidentDriver)
        owner.loaded, owner.path_ids = set(), {}
        return owner

    def test_real_sealed_alias_load_retire_reload_keeps_both_paths(self):
        product = self.bound()
        owner = self.owner()
        with patch.object(owner, "ask", side_effect=[{"loaded": 0}, {"unloaded": 0}, {"loaded": 0}]) as dispatch, \
                patch.object(owner, "mapping", return_value={"unit_mapping": True}):
            first = owner.load("c", {"c": product})
            owner.unload("c", {"c": product})
            second = owner.load("c", {"c": product})
        dispatch.assert_has_calls([call(f"L 0 {product['path']}"), call("U 0"), call(f"L 0 {product['path']}")])
        self.assertEqual(owner.path_ids, {product["path"]: 0})
        self.assertEqual(product["original_path"], self.product["path"])
        identity = first["artifact_identity"]
        self.assertEqual(identity, second["artifact_identity"])
        self.assertEqual(identity["access_path"], product["path"])
        self.assertNotEqual(identity["path"], identity["access_path"])
        self.assertEqual(identity["path"], str(Path(product["path"]).resolve()))
        self.assertEqual(identity["sha256"], self.product["sha256"])
        self.assertEqual(identity["bytes"], self.product["bytes"])

    def test_real_seals_prevent_content_changes(self):
        product = self.bound()
        descriptor = product["sealed_identity"]["descriptor"]
        with self.assertRaises(OSError):
            os.pwrite(descriptor, b"changed", 0)
        self.assertEqual(hashlib.sha256(Path(product["path"]).read_bytes()).hexdigest(), self.product["sha256"])

    def test_changed_bound_product_refuses_before_dispatch(self):
        product = self.bound()
        changes = ({"sha256": "0" * 64}, {"bytes": product["bytes"] + 1},
                   {"path": self.product["path"]},
                   {"path": product["path"].replace("/fd/", "/fd/./")})
        for change in changes:
            owner = self.owner()
            changed = {**deepcopy(product), **change}
            with self.subTest(change=change), patch.object(owner, "ask") as dispatch:
                with self.assertRaisesRegex(ValueError, "identity differs|access path differs"):
                    owner.load("c", {"c": changed})
            dispatch.assert_not_called()

    def test_changed_original_content_refuses_before_binding(self):
        self.library.write_bytes(self.library.read_bytes().replace(b"original", b"modified"))
        descriptor, alias = self.pin()
        with self.assertRaisesRegex(ValueError, "identity differs before sealed binding"):
            cost.ResidentDriver.bind_product(self.product, descriptor, alias)

    def test_different_sealed_content_cannot_replace_fixed_build_product(self):
        other = self.library.with_name("other.so")
        other.write_bytes(self.library.read_bytes().replace(b"original", b"modified"))
        descriptor, alias = self.pin(other)
        with self.assertRaisesRegex(ValueError, "differs from fixed build product"):
            cost.ResidentDriver.bind_product(self.product, descriptor, alias)

    def test_unsealed_matching_bytes_are_not_admitted(self):
        descriptor = os.memfd_create("hia-unit-unsealed", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        self.addCleanup(os.close, descriptor)
        os.write(descriptor, self.library.read_bytes())
        with self.assertRaisesRegex(ValueError, "not fully sealed"):
            cost.ResidentDriver.bind_product(self.product, descriptor, f"/proc/self/fd/{descriptor}")


class FrozenPlannerInputTests(unittest.TestCase):
    def test_frozen_baseline_and_inventory_do_not_require_git_history(self):
        protocol = json.loads(planner.PROTOCOL.read_bytes())
        with patch("subprocess.check_output", side_effect=AssertionError("Git history is unavailable")):
            historical, raw = planner.historical_model(protocol)
            source = planner.inventory()
            model = planner.fixture(3)
            before, after = historical.exact_control(model), planner.current.exact_control(model)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), protocol["baseline_sha256"])
        self.assertEqual(protocol["baseline_sha256"], "0b17b31d6863662b06e14597ac25961cdd301cedfec6deb036dff98059b03ef0")
        self.assertEqual(source[str(planner.BASELINE.relative_to(planner.ROOT))], protocol["baseline_sha256"])
        self.assertEqual({k: v for k, v in before.items() if k != "search"},
                         {k: v for k, v in after.items() if k != "search"})

    def test_changed_historical_fixture_is_rejected_before_execution(self):
        protocol = json.loads(planner.PROTOCOL.read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / "historical.py"
            changed.write_bytes(planner.BASELINE.read_bytes() + b"\n# changed fixture\n")
            with patch.object(planner, "BASELINE", changed):
                with self.assertRaisesRegex(ValueError, "frozen baseline source mismatch"):
                    planner.historical_model(protocol)
