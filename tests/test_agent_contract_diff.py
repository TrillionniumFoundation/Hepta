"""Contract comparison is pinned, conservative, deterministic, and read-only."""
from __future__ import annotations

import copy
import unittest
from unittest.mock import call, patch

from hepta import agent_contract_diff
from hepta.workspace import WorkspaceError


class AgentContractDiffTests(unittest.TestCase):
    BEFORE = "a" * 64
    AFTER = "b" * 64
    COMPILER = "c" * 64

    def report(self, version):
        return {
            "schema": "hepta.agent-semantics.v1",
            "status": "published_native_prevalidated_read_only",
            "ok": True,
            "workspace_version": version,
            "compiler_sha256": self.COMPILER,
            "interface_sha256": "d" * 64,
            "source_semantic_sha256": "e" * 64 if version == self.BEFORE else "f" * 64,
            "validated_sources": ["src/main.hepta"],
            "external_obligations": [],
            "foreign_assumptions": [],
            "functions": [{
                "path": "src/main.hepta", "name": "compute",
                "return_type": "i32",
                "parameter_modes": [{"name": "x", "type": "i32", "mode": "value"}],
                "declared_effects": [], "inferred_effects": [], "resources": {},
            }],
            "claims": {
                "native_validation_occurred_at_publication": True,
                "native_validation_reexecuted_this_query": False,
                "whole_language_soundness_proved": False,
                "functional_equivalence_proved": False,
            },
        }

    def compare(self, before, after):
        with patch.object(agent_contract_diff, "inspect_pinned_semantics",
                          side_effect=[before, after]) as inspection:
            result = agent_contract_diff.compare_pinned_contracts(
                "immutable/base", "immutable/candidate",
                expected_before_version=self.BEFORE,
                expected_after_version=self.AFTER)
            self.assertEqual(inspection.call_args_list, [
                call("immutable/base", expected_version=self.BEFORE),
                call("immutable/candidate", expected_version=self.AFTER)])
            return result

    def test_effect_resource_contract_diff_is_source_bound(self):
        a, b = self.report(self.BEFORE), self.report(self.AFTER)
        b["functions"][0]["declared_effects"] = ["panic"]
        b["functions"][0]["resources"] = {"heap_allocations": 0}
        b["interface_sha256"] = "1" * 64
        result = self.compare(a, b)
        self.assertTrue(result["interface_identity_changed"])
        self.assertEqual(result["reported_contract_changes"], [{
            "path": "src/main.hepta", "name": "compute",
            "change": "contract_modified",
            "changed_fields": ["declared_effects", "resources"],
        }])
        self.assertRegex(result["sha256"], r"^[a-f0-9]{64}$")
        self.assertFalse(result["claims"]["functional_equivalence_proved"])
        self.assertFalse(result["claims"]["function_bodies_compared"])

    def test_no_contract_delta_does_not_claim_unchanged_behavior(self):
        result = self.compare(self.report(self.BEFORE), self.report(self.AFTER))
        self.assertEqual(result["reported_contract_changes"], [])
        self.assertNotEqual(result["before_semantic_sha256"], result["after_semantic_sha256"])
        self.assertFalse(result["claims"]["function_bodies_compared"])
        self.assertFalse(result["claims"]["functional_equivalence_proved"])

    def test_addition_and_removal_are_deterministically_ordered(self):
        a, b = self.report(self.BEFORE), self.report(self.AFTER)
        a["functions"][0]["name"] = "old"
        b["functions"][0]["name"] = "new"
        self.assertEqual([(x["name"], x["change"]) for x in
                          self.compare(a, b)["reported_contract_changes"]],
                         [("new", "added"), ("old", "removed")])

    def test_different_compiler_fails_closed(self):
        a, b = self.report(self.BEFORE), self.report(self.AFTER)
        b["compiler_sha256"] = "0" * 64
        with self.assertRaisesRegex(WorkspaceError, "different compiler"):
            self.compare(a, b)

    def test_duplicate_function_identity_rejected(self):
        a, b = self.report(self.BEFORE), self.report(self.AFTER)
        b["functions"].append(copy.deepcopy(b["functions"][0]))
        with self.assertRaisesRegex(WorkspaceError, "Duplicate"):
            self.compare(a, b)

    def test_receipt_claims_cannot_be_elevated(self):
        a, b = self.report(self.BEFORE), self.report(self.AFTER)
        b["claims"]["functional_equivalence_proved"] = True
        with self.assertRaisesRegex(WorkspaceError, "claims"):
            self.compare(a, b)

    def test_invalid_exact_version_rejected_without_reading_workspace(self):
        with patch.object(agent_contract_diff, "inspect_pinned_semantics") as read:
            with self.assertRaisesRegex(WorkspaceError, "exact version"):
                agent_contract_diff.compare_pinned_contracts(
                    "immutable/a", "immutable/b",
                    expected_before_version="not a digest",
                    expected_after_version=self.AFTER)
            read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
