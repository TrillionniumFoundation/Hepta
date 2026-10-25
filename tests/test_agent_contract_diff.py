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
            "source_sha256": "1" * 64 if version == self.BEFORE else "2" * 64,
            "checked_graph_sha256": "3" * 64 if version == self.BEFORE else "4" * 64,
            "validated_sources": ["src/main.hepta"],
            "external_obligations": [],
            "foreign_assumptions": [],
            "functions": [{
                "path": "src/main.hepta", "name": "compute",
                "return_type": "i32",
                "parameter_modes": [{"name": "x", "type": "i32", "mode": "value"}],
                "declared_effects": [], "inferred_effects": [], "resources": {},
                "public": False, "extern_c": False, "export_c": False,
                "return_mode": "value", "return_origin": None,
                "parameter_lifetimes": [None], "lifetime_params": [],
                "type_params": [], "type_bounds": {},
            }],
            "claims": {
                "native_validation_occurred_at_publication": True,
                "native_validation_reexecuted_this_query": False,
                "all_foreign_contracts_proved": False,
                "whole_language_soundness_proved": False,
                "functional_equivalence_proved": False,
            },
        }

    def compare(self, before, after):
        with patch.object(agent_contract_diff, "inspect_historical_semantics",
                          side_effect=[before, after]) as inspection:
            result = agent_contract_diff.compare_pinned_contracts(
                "immutable/base", "immutable/candidate",
                expected_before_version=self.BEFORE,
                expected_after_version=self.AFTER)
            self.assertEqual(inspection.call_args_list, [
                call("immutable/base", version=self.BEFORE),
                call("immutable/candidate", version=self.AFTER)])
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

    def test_abi_visibility_return_loan_and_generic_drift_detected(self):
        a, b = self.report(self.BEFORE), self.report(self.AFTER)
        current = b["functions"][0]
        current["public"] = True
        current["export_c"] = True
        current["return_mode"] = "read"
        current["return_origin"] = "x"
        current["parameter_lifetimes"] = ["source"]
        current["lifetime_params"] = ["source"]
        current["type_params"] = ["T"]
        current["type_bounds"] = {"T": "Copy"}
        result = self.compare(a, b)
        self.assertEqual(result["reported_contract_changes"][0]["changed_fields"], [
            "public", "export_c", "return_mode", "return_origin",
            "parameter_lifetimes", "lifetime_params", "type_params", "type_bounds",
        ])
        self.assertTrue(result["source_identity_changed"])
        self.assertTrue(result["checked_graph_changed"])
        self.assertTrue(result["entry_source_changed"])
        self.assertEqual(result["source_identity_scope"],
                         "loaded_hepta_module_graph_not_full_workspace")
        self.assertFalse(result["claims"]["functional_equivalence_proved"])

    def test_foreign_contract_elevation_rejected(self):
        a, b = self.report(self.BEFORE), self.report(self.AFTER)
        b["claims"]["all_foreign_contracts_proved"] = True
        with self.assertRaisesRegex(WorkspaceError, "claims"):
            self.compare(a, b)

    def test_missing_contract_field_rejected(self):
        a, b = self.report(self.BEFORE), self.report(self.AFTER)
        b["functions"][0].pop("return_origin")
        with self.assertRaisesRegex(WorkspaceError, "Malformed function"):
            self.compare(a, b)

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

    def test_dependency_edit_changes_checked_graph_not_entry(self):
        a, b = self.report(self.BEFORE), self.report(self.AFTER)
        b["source_sha256"] = a["source_sha256"]
        result = self.compare(a, b)
        self.assertFalse(result["entry_source_changed"])
        self.assertTrue(result["checked_graph_changed"])
        self.assertTrue(result["source_identity_changed"])
        self.assertTrue(result["workspace_snapshot_changed"])

    def test_snapshot_only_change_is_not_checked_graph_change(self):
        a, b = self.report(self.BEFORE), self.report(self.AFTER)
        b["source_sha256"] = a["source_sha256"]
        b["checked_graph_sha256"] = a["checked_graph_sha256"]
        result = self.compare(a, b)
        self.assertFalse(result["entry_source_changed"])
        self.assertFalse(result["checked_graph_changed"])
        self.assertFalse(result["source_identity_changed"])
        self.assertTrue(result["workspace_snapshot_changed"])

    def test_bad_graph_sha_rejected(self):
        a, b = self.report(self.BEFORE), self.report(self.AFTER)
        b["checked_graph_sha256"] = "bad"
        with self.assertRaisesRegex(WorkspaceError, "bound digest"):
            self.compare(a, b)

    def test_absolute_snapshot_paths_are_not_comparable_function_keys(self):
        a, b = self.report(self.BEFORE), self.report(self.AFTER)
        a["functions"][0]["path"] = (
            "/store/versions/" + self.BEFORE + "/tree/src/main.hepta")
        with self.assertRaisesRegex(WorkspaceError, "nonportable"):
            self.compare(a, b)

    def test_path_missing_from_validated_source_inventory_is_rejected(self):
        a, b = self.report(self.BEFORE), self.report(self.AFTER)
        b["validated_sources"] = ["src/other.hepta"]
        with self.assertRaisesRegex(WorkspaceError, "nonportable"):
            self.compare(a, b)

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

    def test_same_store_can_compare_old_and_new_immutable_versions(self):
        a, b = self.report(self.BEFORE), self.report(self.AFTER)
        with patch.object(agent_contract_diff, "inspect_historical_semantics",
                          side_effect=[a, b]) as inspection:
            result = agent_contract_diff.compare_pinned_contracts(
                "immutable/one-store", "immutable/one-store",
                expected_before_version=self.BEFORE,
                expected_after_version=self.AFTER)
            self.assertEqual(inspection.call_args_list, [
                call("immutable/one-store", version=self.BEFORE),
                call("immutable/one-store", version=self.AFTER)])
            self.assertTrue(result["workspace_snapshot_changed"])

    def test_invalid_exact_version_rejected_without_reading_workspace(self):
        with patch.object(agent_contract_diff, "inspect_historical_semantics") as read:
            with self.assertRaisesRegex(WorkspaceError, "exact version"):
                agent_contract_diff.compare_pinned_contracts(
                    "immutable/a", "immutable/b",
                    expected_before_version="not a digest",
                    expected_after_version=self.AFTER)
            read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
