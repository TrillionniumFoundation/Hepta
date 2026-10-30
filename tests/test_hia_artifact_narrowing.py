"""Real native controls for the prepared guarded+narrowed artifact route."""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_artifact_session as session_module
from hepta import hia_narrowing as narrowing_module
from hepta.hia_artifact_session import ArtifactSessionRejected, PreparedArtifactSession
from hepta.hia_multiversion import PublicationCancellation
from hepta.hia_narrowing import propose_guarded_narrowing
from hepta.hia_optimization import DEFAULT_POLICY, OptimizationRejected
from hepta.hia_program_source import lower_source
from tools.qualify_hia_ndu_activation import checksum, PROFILE as WORKLOADS, DRIVER


@unittest.skipUnless(os.environ.get("HEPTA_RUN_ARTIFACT_SESSION") == "1"
                     and platform.system() == "Linux", "requires actual Linux native compiler/solver")
class PreparedArtifactNarrowingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory()
        cls.root = Path(cls.workspace.name)
        cls.clang = os.environ.get("CLANG", "clang")
        (cls.root / "driver.c").write_text(DRIVER)
        cls.driver = cls.root / "driver"
        subprocess.run([cls.clang, "-O3", "-std=c11", str(cls.root / "driver.c"),
                        "-ldl", "-o", str(cls.driver)], check=True, capture_output=True, timeout=60)
        cls.driver_sha = sha256(cls.driver.read_bytes()).hexdigest()
        cls.base = lower_source((WORKLOADS / "packet_xor.hepta").read_text())
        cls.other = lower_source((WORKLOADS / "byte_sum.hepta").read_text())

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(self.directory.cleanup)
        self.counter = 0

    def owner(self, **limits):
        self.counter += 1
        owner = PreparedArtifactSession(Path(self.directory.name) / str(self.counter),
            clang=self.clang, policy=dict(DEFAULT_POLICY, timeout_ms=30000), **limits)
        self.addCleanup(owner.close)
        owner.bind_driver(self.driver, self.driver_sha)
        return owner

    def check_output(self, row, n, seed=113):
        self.assertEqual(row["status"], "completed", row)
        output = json.loads(row["stdout"])
        self.assertTrue(output["loaded_mapping_verified"])
        self.assertEqual(output["checksum"], checksum("packet_xor", n, 3, seed))
        self.assertFalse(row["new_solver_call"])

    def test_both_stage_proofs_once_and_native_guard_boundary_fallback_reuse(self):
        owner = self.owner()
        base = owner.prepare_base(self.base)
        proposal = propose_guarded_narrowing(self.base, maximum=128)
        with patch.object(narrowing_module, "verify_guarded_narrowing",
                          wraps=narrowing_module.verify_guarded_narrowing) as prove:
            candidate = owner.prepare_guarded_narrowed(base["token"], proposal)
            proof = owner._entries[candidate["token"]].image.receipt["verification"]
            self.assertEqual(proof["schema"], "hepta.hia.guarded-narrowing-verification.v1")
            self.assertEqual([row["proof"]["status"] for row in proof["stages"]], ["verified", "verified"])
            self.assertEqual(proof["base_sha256"], base["core_sha256"])
            self.assertEqual(proof["candidate_sha256"], candidate["core_sha256"])
            self.assertNotEqual(base["core_sha256"], candidate["core_sha256"])
            for n in (0, 127, 128, 129, 4093):
                with owner.lease(candidate["token"]) as lease:
                    self.check_output(lease.run(n, 3, 113), n)
            self.assertEqual(prove.call_count, 1)
        self.assertEqual(owner.snapshot()["proof_attempts"], 2)
        self.assertEqual(owner.snapshot()["execution_attempts"], 5)
        owner.close()
        self.assertTrue(owner.snapshot()["owned_native_release_complete"])
        self.assertEqual(owner.snapshot()["charged_retained_bytes"], 0)

    def test_wrong_baseline_or_missing_chain_cannot_reach_native_builder(self):
        owner = self.owner()
        base = owner.prepare_base(self.base)
        cases = [propose_guarded_narrowing(self.other, maximum=128),
                 propose_guarded_narrowing(self.base, maximum=128)["guarded"]]
        for proposal in cases:
            with self.subTest(schema=proposal["schema"]), \
                 patch.object(session_module, "build_guarded_narrowed_native") as build:
                with self.assertRaises(ValueError):
                    owner.prepare_guarded_narrowed(base["token"], proposal)
                build.assert_not_called()
        self.assertEqual(owner.snapshot()["successful_admissions"], 1)
        self.assertEqual(owner.snapshot()["reserved_bytes"], 0)

    def test_wider_guard_without_new_invariant_is_rejected_by_actual_proof(self):
        owner = self.owner()
        base = owner.prepare_base(self.base)
        proposal = propose_guarded_narrowing(self.base, maximum=128)
        proposal["guarded"]["guards"][0]["maximum"] = 129
        with self.assertRaises((ValueError, OptimizationRejected)):
            owner.prepare_guarded_narrowed(base["token"], proposal)
        self.assertEqual(owner.snapshot()["successful_admissions"], 1)
        self.assertEqual(owner.snapshot()["reserved_bytes"], 0)
        self.assertFalse((owner._directory / "generation-2.so").exists())

    def test_second_stage_receipt_tampering_refuses_before_execution(self):
        owner = self.owner()
        base = owner.prepare_base(self.base)
        candidate = owner.prepare_guarded_narrowed(base["token"],
            propose_guarded_narrowing(self.base, maximum=128))
        image = owner._entries[candidate["token"]].image
        original = deepcopy(image.receipt)
        image.receipt["verification"]["stages"][1]["proof"]["candidate_sha256"] = "0" * 64
        with patch.object(session_module.subprocess, "run") as launch:
            with self.assertRaises(ArtifactSessionRejected):
                owner.lease(candidate["token"])
            launch.assert_not_called()
        self.assertEqual(owner.snapshot()["execution_attempts"], 0)
        image.receipt = original

    def test_chain_checker_drift_invalidates_existing_prepared_admission(self):
        owner = self.owner()
        base = owner.prepare_base(self.base)
        candidate = owner.prepare_guarded_narrowed(base["token"],
            propose_guarded_narrowing(self.base, maximum=128))
        with patch.object(session_module, "chain_checker_identity", return_value="0" * 64):
            with self.assertRaises(ArtifactSessionRejected):
                owner.lease(candidate["token"])
        self.assertTrue(owner.snapshot()["invalidated"])
        with self.assertRaises(ArtifactSessionRejected):
            owner.lease(candidate["token"])

    def test_cancellation_after_real_chain_build_never_publishes_token(self):
        owner = self.owner()
        base = owner.prepare_base(self.base)
        cancel = PublicationCancellation()
        real_build = session_module.build_guarded_narrowed_native
        def cancel_after(*args, **kwargs):
            result = real_build(*args, **kwargs)
            self.assertTrue(cancel.cancel())
            return result
        with patch.object(session_module, "build_guarded_narrowed_native", side_effect=cancel_after):
            with self.assertRaises(ArtifactSessionRejected):
                owner.prepare_guarded_narrowed(base["token"],
                    propose_guarded_narrowing(self.base, maximum=128), cancellation=cancel)
        self.assertEqual(owner.snapshot()["successful_admissions"], 1)
        self.assertEqual(owner.snapshot()["reserved_bytes"], 0)
        owner.close()
        self.assertTrue(owner.snapshot()["owned_native_release_complete"])

    def test_close_with_live_chain_lease_retains_ancestor_until_release(self):
        owner = self.owner()
        base = owner.prepare_base(self.base)
        candidate = owner.prepare_guarded_narrowed(base["token"],
            propose_guarded_narrowing(self.base, maximum=128))
        lease = owner.lease(candidate["token"])
        self.addCleanup(lease.close)
        owner.close()
        self.assertFalse(owner.snapshot()["owned_native_release_complete"])
        with self.assertRaises(ArtifactSessionRejected):
            owner.lease(candidate["token"])
        self.check_output(lease.run(4093, 3, 113), 4093)
        lease.close()
        self.assertTrue(owner.snapshot()["owned_native_release_complete"])
        self.assertEqual(owner.snapshot()["charged_retained_bytes"], 0)

    def test_chain_entry_budget_refuses_without_another_native_build(self):
        owner = self.owner(max_entries=1)
        base = owner.prepare_base(self.base)
        with patch.object(session_module, "build_guarded_narrowed_native") as build:
            with self.assertRaises(ArtifactSessionRejected):
                owner.prepare_guarded_narrowed(base["token"],
                    propose_guarded_narrowing(self.base, maximum=128))
            build.assert_not_called()
        self.assertEqual(owner.snapshot()["successful_admissions"], 1)


if __name__ == "__main__":
    unittest.main()
