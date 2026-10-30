"""Actual eight-arm integration after merging sealed/cache and compact/Q32 work.

These deliberately tiny workloads qualify composition, never performance.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

from tools.qualify_hia_ndu_graph import ARMS, PROTOCOL, qualify


@unittest.skipUnless(os.environ.get("HEPTA_NDU_STREAM_IDENTITY") and os.environ.get("HEPTA_CLANG")
                     and importlib.util.find_spec("z3"), "requires actual stream identity, Clang and Z3")
class ConvergedNativeGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-ndu-convergence-")
        cls.root = Path(cls.temporary.name) / "graph"
        protocol = dict(PROTOCOL, groups=1, calls=7, probe_size=3, batch_sizes=[3, 11, 29],
                        calibration_repetitions=1, guard_limits={"guard-small": 8, "guard-wide": 32},
                        native_transport="stream", narrow_targets=["guard-wide"],
                        arms=[*ARMS, "q32-dp", "ndu-compact"])
        cls.result = qualify(cls.root, identity=os.environ["HEPTA_NDU_STREAM_IDENTITY"],
                             clang=os.environ["HEPTA_CLANG"], protocol=protocol, decision_cache_entries=2)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_all_eight_arms_execute_and_keep_sealed_artifacts_and_resource_gates(self):
        result = self.result
        self.assertEqual({r["arm"] for r in result["episodes"]}, {*ARMS, "q32-dp", "ndu-compact"})
        self.assertTrue(result["all_episodes_completed"], [(r["arm"], r["status"], r.get("error")) for r in result["episodes"]])
        self.assertTrue(result["all_outputs_correct"])
        for episode in result["episodes"]:
            for sample in episode["observations"]:
                self.assertTrue(sample["loaded_snapshot_sealed"])
                self.assertEqual(sample["artifact_sha256"], sample["expected_artifact_sha256"])

    def test_native_representations_have_distinct_owned_sessions_and_caches(self):
        result = self.result
        self.assertEqual(set(result["native_sessions"]), {"ndu", "ndu-compact"})
        self.assertEqual(set(result["exact_advisory_reuse_by_arm"]), {"ndu", "ndu-compact"})
        self.assertNotEqual(result["native_sessions"]["ndu"]["pid"], result["native_sessions"]["ndu-compact"]["pid"])
        for arm in ("ndu", "ndu-compact"):
            session = result["native_sessions"][arm]
            self.assertTrue(session["closed"])
            self.assertFalse(session["cleanup_errors"])
            self.assertGreater(session["image_identity_checks"], 1)
            self.assertEqual(session["image_check_profile"], "sealed")
            labels = {r["label"] for r in result["controller_setup_ledger"][arm]}
            self.assertTrue({"native.admission", "native.exact-reuse-admission", "native.exact-reuse-close", "native.shutdown", "native.snapshot"} <= labels)
        for episode in result["episodes"]:
            if episode["arm"] == "q32-dp":
                self.assertTrue(all(row["native_response"] is None and row["exact_advisory_reuse"] is None for row in episode["decisions"]))


if __name__ == "__main__":
    unittest.main()
