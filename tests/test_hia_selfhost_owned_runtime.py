"""Finite qualification of experimental helpers; no default-profile expansion."""
from __future__ import annotations

import os
from pathlib import Path
import platform
import shutil
import tempfile
import unittest

from tools.hia_selfhost_owned_cases import run_reference


class OwnedCoreReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_reference()
        cls.cases = {row["name"]: row["observation"] for row in cls.report["cases"]}

    def test_zero_owner_does_not_consume_allocator_failure(self):
        observed = self.cases["empty-does-not-consume-failure-sequence"]
        self.assertEqual(observed["values"], [True, False, 0, 0])
        self.assertEqual(observed["resources"]["allocation_attempts"], 1)
        self.assertEqual(observed["resources"]["allocations"], 0)
        self.assertEqual(observed["resources"]["owners_created"], 2)
        self.assertEqual(observed["resources"]["owners_dropped"], 2)

    def test_budget_stop_is_not_optional_allocation_failure(self):
        observed = self.cases["heap-budget-is-not-allocation-failure"]
        self.assertEqual(observed["status"], "budget_exceeded")
        self.assertEqual(observed["error"]["code"], "heap")
        self.assertEqual(observed["resources"]["allocation_attempts"], 0)
        self.assertNotIn("values", observed)

    def test_push_failure_preserves_payload_and_ends_all_ownership(self):
        observed = self.cases["chain-node-failure-retains-payload"]
        self.assertEqual(observed["values"], [False, True, 1, 173])
        self.assertEqual(observed["resources"]["allocation_attempts"], 2)
        self.assertEqual(observed["resources"]["chain_nodes_created"], 0)
        self.assertEqual(observed["resources"]["live_owners"], 0)

    def test_dynamic_chain_exceeds_ssa_bound_and_drops_iteratively(self):
        resources = self.cases["iterative-5000-node-drop"]["resources"]
        self.assertEqual(resources["chain_nodes_created"], 5000)
        self.assertEqual(resources["chain_nodes_dropped"], 5000)
        self.assertEqual(resources["allocations"], 10000)
        self.assertEqual(resources["frees"], 10000)
        self.assertEqual(resources["peak_bytes"], 125000)
        self.assertEqual(resources["live_bytes"], 0)

    def test_well_typed_duplicate_edge_is_rejected_as_resource_error(self):
        rejected = {row["name"]: row for row in self.report["rejections"]}
        self.assertEqual(len(rejected), 16)
        self.assertEqual(rejected["chain-duplicate-edge-capability"]["code"], "E_HIA_RESOURCE")
        self.assertEqual(rejected["missing-allocation-effect"]["code"], "E_HIA_EFFECT")


@unittest.skipUnless(platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
                     and shutil.which("ld"), "conditional Linux-x86-64 runtime and ld required")
class OwnedNativeHelperTests(unittest.TestCase):
    def test_native_hia_author_emits_and_executes_all_frozen_fixtures(self):
        from tools.qualify_hia_selfhost_owned_runtime import qualify
        retained = os.environ.get("HIA_SELFHOST_OWNED_EVIDENCE")
        if retained:
            report = qualify(Path(retained))
        else:
            with tempfile.TemporaryDirectory(prefix="hia-owned-runtime-") as temporary:
                report = qualify(Path(temporary) / "qualification")
        self.assertEqual(report["status"], "PASS_CONDITIONAL_RUNTIME_HELPERS_ONLY")
        self.assertEqual(len(report["native"]), 11)
        self.assertTrue(all(row["pass"] for row in report["native"]))
        self.assertFalse(report["selfhost_owned_opcodes_admitted"])
        self.assertFalse(report["full_core_closed"])
        self.assertFalse(report["default_allocator_profile_changed"])


if __name__ == "__main__":
    unittest.main()
