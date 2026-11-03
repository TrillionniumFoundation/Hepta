"""Source selection and measured costs across stream revisions."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from hepta.hia_ndu import NduBridgeError
from hepta.hia_ndu_session import NduSession, STREAM_PROFILE_PINS
from tools.qualify_hia_ndu_cost import (full_cost_totals, policy_model_evidence,
                                      episodes_without_native_start)


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
        return [{"policy": p, "service_wall_ns": 7, "steps": [{"decision": {
            "native_invoked": invoked if p == "native_ndu" else False,
            "native_matches_exact_model": matches}}]}
            for p in ("fixed", "exact_dp", "lightweight", "native_ndu")]

    def test_no_invocation_is_unknown_agreement(self):
        result = policy_model_evidence(self.rows())
        self.assertIsNone(result["native_matches_same_information_exact_model"])
        self.assertEqual(result["native_model_evaluated_count"], 0)
        self.assertFalse(result["native_policy_evidence_present"])
        for matches in (True, False, None):
            result = policy_model_evidence(self.rows(True, matches))
            self.assertEqual(result["native_model_evaluated_count"], 1)
            self.assertIs(result["native_matches_same_information_exact_model"], matches is True)

    def test_unknown_build_never_becomes_zero_cost(self):
        manifests = [{}, {"build_cost": None}, {"build_cost": {}}]
        manifests += [{"build_cost": {"wall_ns": x}} for x in (None, False, -1, "7", 7.0)]
        for manifest in manifests:
            with self.subTest(manifest=manifest):
                result = full_cost_totals(self.rows(), 100, manifest)
                self.assertFalse(result["build_cost_observed"])
                self.assertIsNone(result["arm_full_cost_ns"]["native_ndu"])
                self.assertEqual(result["arm_full_cost_ns"]["exact_dp"], 107)
                self.assertEqual(result["unknown_costs"], ["native_bridge_build_wall_ns"])

    def test_known_build_is_charged_once_only_to_native(self):
        result = full_cost_totals(self.rows(), 100, {"build_cost": {"wall_ns": 23}})
        self.assertTrue(result["build_cost_observed"])
        self.assertEqual(result["arm_full_cost_ns"], {
            "fixed": 107, "exact_dp": 107, "lightweight": 107, "native_ndu": 130})
        self.assertEqual(result["unknown_costs"], [])

    def test_started_session_without_evaluation_is_not_a_no_start_episode(self):
        row = {"policy": "native_ndu", "native_invocations": 0,
               "steps": [{"decision": {"native_invoked": False, "startup_ns": 0}}]}
        self.assertEqual(episodes_without_native_start([row]), 1)
        self.assertEqual(episodes_without_native_start([{**row, "native_session": {"requests": 0}}]), 0)
        row["steps"][0]["decision"]["startup_ns"] = 10
        self.assertEqual(episodes_without_native_start([row]), 0)
