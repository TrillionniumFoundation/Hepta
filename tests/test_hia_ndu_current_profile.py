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
