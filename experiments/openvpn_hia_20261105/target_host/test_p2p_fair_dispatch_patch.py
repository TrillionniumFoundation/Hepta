#!/usr/bin/env python3
"""Offline source-lock and receipt regressions for the P2P fairness patch.

These tests do not create a namespace, use TUN, load a module or claim
performance. The build-only workflow applies the patch to the exact upstream
archive and compiles the complete C and HIA applications.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def load_verifier():
    spec = importlib.util.spec_from_file_location("verify_result", HERE / "verify_result.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verifier = load_verifier()


class P2PFairDispatchPatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lock = json.loads((HERE / "source-lock.json").read_text())
        cls.plan = json.loads((HERE / "plan.json").read_text())
        cls.patch_path = HERE / cls.lock["p2p_fair_dispatch"]["path"]
        cls.patch = cls.patch_path.read_text()
        cls.build_source = (HERE / "build.py").read_text()
        cls.matrix_source = (HERE / "run_matrix.py").read_text()
        cls.verifier_source = (HERE / "verify_result.py").read_text()

    def valid_build(self):
        expected = self.lock["p2p_fair_dispatch"]
        files = expected["files"]
        return {
            "ok": True,
            "p2p_fair_dispatch": {
                "enabled": True,
                "patch_path": expected["path"],
                "patch_sha256": expected["sha256"],
                "upstream_commit": self.lock["openvpn"]["commit"],
                "source_archive_sha256": self.lock["openvpn"]["archive_sha256"],
                "policy": expected["policy"],
                "original_files": {name: "a" * 64 for name in files},
                "patched_files": {name: "b" * 64 for name in files},
                "context_reset_verified": True,
                "pending_write_priority_preserved": True,
                "dco_read_branch_present": True,
            },
        }

    def test_patch_digest_and_upstream_commit_are_pinned(self):
        expected = self.lock["p2p_fair_dispatch"]
        self.assertEqual(hashlib.sha256(self.patch_path.read_bytes()).hexdigest(),
                         expected["sha256"])
        self.assertEqual(expected["upstream_commit"], self.lock["openvpn"]["commit"])
        self.assertEqual(expected["files"],
                         ["src/openvpn/openvpn.h", "src/openvpn/forward.c"])

    def test_patch_only_changes_the_reviewed_context_and_dispatch_files(self):
        changed = re.findall(r"^diff --git a/(.*?) b/", self.patch, re.M)
        self.assertEqual(changed, self.lock["p2p_fair_dispatch"]["files"])
        self.assertIn("bool prefer_tun_read;", self.patch)
        self.assertIn("status &= ~SOCKET_READ;", self.patch)
        self.assertIn("c->c2.prefer_tun_read = true;", self.patch)
        self.assertIn("c->c2.prefer_tun_read = false;", self.patch)
        self.assertNotIn("DCO_READ", self.patch)
        self.assertNotIn("SOCKET_WRITE", self.patch)
        self.assertNotIn("TUN_WRITE", self.patch)

    def test_fairness_patch_is_shared_without_relaxing_the_fixed_matrix(self):
        self.assertEqual(
            self.plan["p2p_dispatch"]["patch_sha256"],
            self.lock["p2p_fair_dispatch"]["sha256"])
        self.assertEqual(
            self.plan["p2p_dispatch"]["applies_identically_to"],
            ["c-user", "hia-user", "c-dco"])
        behavior = (len(self.plan["behavior"]["epoch_pairs"])
                    + len(self.plan["behavior"]["common_profile_clients"]))
        auth = len(self.plan["behavior"]["negative_clients"])
        profiles = len(self.plan["profile"]["arms"])
        performance = (self.plan["performance"]["rounds"]
                       * len(self.plan["performance"]["orders"])
                       * len(self.plan["performance"]["client_arms"]))
        workloads = performance * len(self.plan["performance"]["workloads"])
        self.assertEqual((behavior, auth, profiles, performance, behavior + auth + profiles + performance),
                         (7, 2, 2, 54, 65))
        self.assertEqual(workloads, 216)
        self.assertEqual(self.plan["performance"]["udp_acceptance"]["minimum_offered_rate_fraction"], 0.95)
        self.assertEqual(self.plan["performance"]["udp_acceptance"]["maximum_receiver_loss_percent"], 1.0)

    def test_build_applies_patch_to_a_private_copy_and_keeps_archive_pristine(self):
        self.assertIn("shutil.copytree(source, build_source)", self.build_source)
        self.assertIn('"git", "apply", "--check", patch_path', self.build_source)
        self.assertIn('"git", "apply", patch_path', self.build_source)
        self.assertIn("baseline.source_freeze(source, archive)", self.build_source)
        self.assertIn('"build_source": str(build_source)', self.build_source)
        self.assertIn('"p2p_fair_dispatch": dispatch_receipt', self.build_source)
        self.assertIn("context_clear_2", self.build_source)
        self.assertIn('os.environ.get("HEPTA_EXPECTED_SHA") or os.environ["GITHUB_SHA"]',
                      self.build_source)

    def test_target_result_binds_the_build_receipt_and_patch_identity(self):
        self.assertIn("build_receipt_path = args.build.parent.parent/'public'/'build.json'",
                      self.matrix_source)
        self.assertIn("report['inputs']['build_receipt_sha256']", self.matrix_source)
        self.assertIn("report['inputs']['p2p_fair_dispatch']", self.matrix_source)
        self.assertIn("verify_p2p_fair_dispatch(build, report, public)", self.verifier_source)

    def test_independent_verifier_accepts_only_the_pinned_build_receipt(self):
        build = self.valid_build()
        observed = verifier.verify_p2p_fair_dispatch_build(build)
        self.assertEqual(observed["patch_sha256"], self.lock["p2p_fair_dispatch"]["sha256"])
        for mutate in (
            lambda value: value["p2p_fair_dispatch"].update(patch_sha256="0" * 64),
            lambda value: value["p2p_fair_dispatch"].update(context_reset_verified=False),
            lambda value: value["p2p_fair_dispatch"].update(dco_read_branch_present=False),
            lambda value: value["p2p_fair_dispatch"]["patched_files"].pop("src/openvpn/forward.c"),
            lambda value: value["p2p_fair_dispatch"]["patched_files"].update(
                {"src/openvpn/forward.c": "a" * 64}),
        ):
            bad = copy.deepcopy(build)
            mutate(bad)
            with self.assertRaises(ValueError):
                verifier.verify_p2p_fair_dispatch_build(bad)

    def test_target_matrix_receipt_hash_is_recomputed(self):
        build = self.valid_build()
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory)
            receipt = public / "build.json"
            receipt.write_text(json.dumps(build, sort_keys=True))
            report = {"inputs": {
                "build_receipt_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
                "p2p_fair_dispatch": build["p2p_fair_dispatch"],
            }}
            verifier.verify_p2p_fair_dispatch(build, report, public)
            report["inputs"]["build_receipt_sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                verifier.verify_p2p_fair_dispatch(build, report, public)


if __name__ == "__main__":
    unittest.main(verbosity=2)
