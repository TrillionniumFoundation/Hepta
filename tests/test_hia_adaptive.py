"""Actual empty-state native switching and strict unsafe-profile refusals."""
from __future__ import annotations

import copy
import fcntl
import importlib.util
import os
import platform
from pathlib import Path
from hashlib import sha256
import shutil
import tempfile
import unittest

from hepta.hia_adaptive import AdaptiveRejected, AdaptiveRuntime, _profile
from tools.qualify_hia_adaptive import programs, qualify

CLANG = os.environ.get("CLANG", "/usr/bin/clang-20")
NATIVE = (shutil.which(CLANG) and platform.system() == "Linux"
          and platform.machine().lower() in {"x86_64", "amd64"}
          and hasattr(os, "memfd_create")
          and importlib.util.find_spec("z3") is not None)
# Python need not export every Linux UAPI seal name. The runtime's shared
# pinning path must actually add and read back kernel seals; failure there is
# a failed native test, not a reason to skip this entire suite.


class AdaptiveProfileTests(unittest.TestCase):
    def test_possibly_trapping_and_resource_profiles_are_not_native_dispatchable(self):
        from tests.test_hia_program import resource_program
        base, _ = programs()
        variants = [resource_program()]
        trapped = copy.deepcopy(base)
        trapped["functions"][0]["effects"] = ["trap"]
        trapped["functions"][0]["blocks"][0]["ops"][-1]["op"] = "int.add.checked"
        variants.append(trapped)
        called = copy.deepcopy(base)
        called["functions"].append(copy.deepcopy(base["functions"][0]))
        called["functions"][-1]["name"] = "second"
        variants.append(called)
        for value in variants:
            with self.subTest(value=value["functions"][0]["effects"]):
                with self.assertRaises(ValueError):
                    _profile(value)
        checked, state = _profile(base)
        self.assertEqual(state["live_owners"], [])
        self.assertEqual(state["live_loans"], [])
        self.assertEqual(state["persistent_values"], [])
        self.assertEqual(checked.as_dict(), base)


@unittest.skipUnless(NATIVE, "Pinned Z3, Linux memfd seals and Clang20+ required")
class AdaptiveNativeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hia-adaptive-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def runtime(self, name="runtime"):
        base, _ = programs()
        runtime = AdaptiveRuntime(base, self.root / name, clang=CLANG)
        self.addCleanup(runtime.close)
        return runtime

    def test_actual_native_concurrency_switching_tamper_and_cost_gates(self):
        report = qualify(self.root / "qualification", clang=CLANG)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["native_pairs"], 131)
        self.assertTrue(report["distinct_native_artifacts"])
        self.assertEqual(sum(row["calls"] for row in report["concurrent_workers"]), 262144)
        self.assertTrue(all(report["controls"].values()))
        self.assertEqual(report["automatic_without_measurement"]["reason"],
                         "automatic_profitable_selection_not_implemented")
        self.assertEqual(report["automatic_after_measuring"]["reason"],
                         "automatic_profitable_selection_not_implemented")
        self.assertEqual(report["automatic_after_measuring"]["evidence_reason"],
                         "conservative_shadow_costs_not_deployment_benefit")
        self.assertFalse(report["general_live_state_or_owner_migration"])
        self.assertEqual(report["final"]["active_calls"], 0)
        self.assertEqual(len(report["admitted_native_images"]), 2)
        for retained in report["retained_native_artifacts"].values():
            admitted = report["admitted_native_images"][retained["image_token"]]
            self.assertEqual(retained["loaded_mapping"], admitted["loaded_mapping"])
            self.assertEqual(retained["sha256"], admitted["artifact_sha256"])
            self.assertEqual(retained["bytes"], admitted["loaded_mapping"]["file_bytes"])
        self.assertEqual(report["post_close"]["native_images"], {})

    def test_each_native_mapping_receipt_matches_real_descriptor_and_is_detached(self):
        runtime = self.runtime()
        _, candidate = programs()
        token = runtime.prepare(candidate)
        snapshot = runtime.snapshot()
        self.assertEqual(set(snapshot["native_images"]), {"baseline", token})
        inodes = set()
        for name, image in runtime._images.items():
            row = snapshot["native_images"][name]
            mapping = row["loaded_mapping"]
            identity = os.fstat(image.fd)
            self.assertEqual(mapping["inode"], identity.st_ino)
            self.assertEqual(mapping["file_bytes"], identity.st_size)
            self.assertEqual((mapping["device_major"], mapping["device_minor"]),
                             (os.major(identity.st_dev), os.minor(identity.st_dev)))
            self.assertEqual(set(mapping["symbols"]), {image.state["entry"]})
            self.assertEqual(mapping["symbols"][image.state["entry"]]["permissions"], "r-xp")
            self.assertEqual(row["artifact_sha256"], sha256(os.pread(image.fd, identity.st_size, 0)).hexdigest())
            self.assertEqual(len(mapping["checker_sha256"]), 64)
            self.assertFalse(row["serialized_evidence_is_authority"])
            inodes.add(mapping["inode"])
            mapping["inode"] = -1
            row["artifact_sha256"] = "0" * 64
        self.assertEqual(len(inodes), 2)
        fresh = runtime.snapshot()
        self.assertTrue(all(row["loaded_mapping"]["inode"] in inodes
                            for row in fresh["native_images"].values()))
        self.assertEqual(runtime.call(7, 2), 9)
        self.assertTrue(runtime.select(token, mode="explicit")["selected"])
        self.assertEqual(runtime.call(7, 2), 9)
        runtime.close()
        closed = runtime.snapshot()
        self.assertEqual(closed["native_images"], {})
        self.assertTrue(closed["cleanup"]["owned_native_release_complete"])
        self.assertEqual(closed["cleanup"]["pending_resource_count"], 0)

    def test_complete_abi_state_and_bad_argument_refusals_preserve_baseline(self):
        runtime = self.runtime()
        base, candidate = programs()
        renamed = copy.deepcopy(candidate)
        renamed["functions"][0]["name"] = "changed_interface"
        with self.assertRaisesRegex(AdaptiveRejected, "E_ADAPT_STATE"):
            runtime.prepare(renamed)
        self.assertEqual(runtime.snapshot()["current"], "baseline")
        for args in ([True, 3], [-1, 3], [2**64, 3], [1], [1, 2, 3]):
            with self.subTest(args=args), self.assertRaises(AdaptiveRejected):
                runtime.call(*args)
        self.assertEqual(runtime.snapshot()["completed_native_calls"], 0)
        self.assertEqual(runtime.call(2**64 - 1, 1), 0)
        snap = runtime.snapshot()
        snap["state_schema"]["live_owners"].append("forged")
        snap["state_schema"]["params"][0]["type"] = "buffer"
        self.assertEqual(runtime.snapshot()["state_schema"]["live_owners"], [])
        self.assertEqual(runtime.snapshot()["state_schema"]["params"][0]["type"], "u64")

    def test_measurement_becomes_stale_after_actual_generation_change(self):
        runtime = self.runtime()
        _, candidate = programs()
        token = runtime.prepare(candidate)
        runtime.measure(token, [[3, 5]])
        self.assertTrue(runtime.select(token, mode="explicit")["selected"])
        self.assertTrue(runtime.select("baseline", mode="explicit")["selected"])
        refused = runtime.select(token)
        self.assertEqual(refused["evidence_reason"], "missing_or_expired_internal_measurement")
        self.assertEqual(runtime.call(3, 5), 8)

    def test_close_releases_native_descriptors_without_rebinding_later_runtime(self):
        runtime = self.runtime("first")
        fd = runtime._images["baseline"].fd
        self.assertEqual(runtime.call(7, 2), 9)
        runtime.close()
        with self.assertRaises(OSError):
            os.fstat(fd)
        with self.assertRaises(AdaptiveRejected):
            runtime.call(7, 2)
        base, _ = programs()
        base["functions"][0]["blocks"][0]["ops"][-1]["op"] = "int.sub.wrap"
        reopened = AdaptiveRuntime(base, self.root / "second", clang=CLANG)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.call(7, 2), 5)

    def test_raw_audit_ring_is_bounded_while_native_call_totals_remain_exact(self):
        runtime = self.runtime()
        for index in range(4200):
            self.assertEqual(runtime.call(index, 1), index + 1)
        snapshot = runtime.snapshot()
        self.assertEqual(snapshot["completed_native_calls"], 4200)
        self.assertEqual(snapshot["event_counts"]["call_batch_finished"], 4200)
        self.assertEqual(len(snapshot["events"]), 4096)
        self.assertEqual(snapshot["raw_events_dropped"], snapshot["event_count"] - 4096)


if __name__ == "__main__":
    unittest.main()
