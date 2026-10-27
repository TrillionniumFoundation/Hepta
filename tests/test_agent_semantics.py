"""Agent semantic inspection must preserve v4 pin and honest proof flags."""
from __future__ import annotations

from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta import agent_semantics
from hepta.workspace import WorkspaceError


class AgentSemanticTests(unittest.TestCase):
    VERSION = "a" * 64
    COMPILER = "b" * 64
    SEMANTIC = "c" * 64

    def setUp(self):
        self.snapshot = {
            "ok": True,
            "snapshot": {
                "version": self.VERSION,
                "entry": "/immutable/versions/tree/main.hepta",
                "root": "/immutable/versions/tree",
                "manifest": {
                    "compiler_sha256": self.COMPILER,
                    "interface_sha256": "d" * 64,
                    "validated_sources": ["main.hepta"],
                    "validation": {
                        "ok": True, "status": "checked",
                        "checks": {"rust_borrows_types": "rustc_checked"},
                    },
                },
            },
            "nodes": {"main.hepta": [{"kind": "fn", "id": "immutable-id"}]},
        }
        self.graph = SimpleNamespace(program=object(), identity="f" * 64, unchanged=lambda: True)
        self.checked = SimpleNamespace(ok=True)
        self.hsir = {
            "schema": "hepta.hsir.v0",
            "profile": "checked_typed_ast_not_verified_mir",
            "claims": {"native_borrow_validation": False,
                       "translation_correctness_proved": False,
                       "whole_language_soundness_proved": False,
                       "foreign_contracts_proved": False},
            "project_sha256": self.VERSION,
            "all_expressions_typed": True, "untyped_expressions": [],
            "sha256": self.SEMANTIC, "source_sha256": "e" * 64,
            "functions": [{
                "name": "add", "path": "main.hepta",
                "declaration_span": {"start": 0, "end": 100},
                "returns": "i32",
                "params": [{"name": "a", "mode": "value", "type": "i32"}],
                "declared_effects": [], "inferred_effects": [],
                "resources": {}, "body": [],
                "public": True, "extern_c": False, "export_c": False,
                "return_mode": "value", "return_origin": None,
                "type_params": [], "type_bounds": {},
            }],
            "external_obligations": [], "foreign_assumptions": [], "volatile_accesses": [],
        }
        self._reseal_hsir()

    def _reseal_hsir(self):
        self.SEMANTIC = agent_semantics.sha256(agent_semantics._stable_json(
            {k: v for k, v in self.hsir.items() if k != "sha256"})).hexdigest()
        self.hsir["sha256"] = self.SEMANTIC

    def _inspect(self, **kwargs):
        with (patch.object(agent_semantics, "inspect_workspace", return_value=self.snapshot),
              patch.object(agent_semantics, "load_project", return_value=self.graph) as load,
              patch.object(agent_semantics, "check", return_value=self.checked),
              patch.object(agent_semantics, "compiler_hash", return_value=self.COMPILER),
              patch.object(agent_semantics, "lower_checked_program", return_value=self.hsir)):
            result = agent_semantics.inspect_pinned_semantics("/immutable/store", **kwargs)
            load.assert_called_once_with(agent_semantics.Path(self.snapshot["snapshot"]["entry"]))
            return result

    def test_current_version_and_nodes_are_bound_to_canonical_ir(self):
        result = self._inspect(expected_version=self.VERSION)
        self.assertEqual(result["workspace_version"], self.VERSION)
        self.assertEqual(result["source_semantic_sha256"], self.SEMANTIC)
        self.assertEqual(result["source_graph_sha256"], "f" * 64)
        self.assertEqual(result["nodes"], self.snapshot["nodes"])
        self.assertEqual(result["functions"][0]["path"], "main.hepta")
        self.assertEqual(result["functions"][0]["parameter_modes"], [
            {"name": "a", "mode": "value", "type": "i32"}])
        self.assertTrue(result["functions"][0]["public"])
        self.assertFalse(result["functions"][0]["export_c"])
        self.assertEqual(result["functions"][0]["return_mode"], "value")
        self.assertIsNone(result["functions"][0]["return_origin"])
        self.assertIsNone(result["functions"][0]["return_lifetime"])
        self.assertEqual(result["volatile_accesses"], [])
        self.assertEqual(result["functions"][0]["parameter_lifetimes"], [None])
        self.assertFalse(result["claims"]["native_validation_reexecuted_this_query"])
        self.assertTrue(result["claims"]["native_validation_occurred_at_publication"])
        self.assertFalse(result["claims"]["whole_language_soundness_proved"])

    def test_return_lifetime_and_source_bound_volatile_sites_exposed(self):
        self.hsir["functions"][0]["return_lifetime"] = "borrow_source"
        self.hsir["functions"][0]["lifetime_params"] = ["borrow_source"]
        self.hsir["volatile_accesses"] = [{
            "function": "add", "operation": "volatile_load",
            "status": "external_obligation_not_proved",
        }]
        self._reseal_hsir()
        result = self._inspect()
        self.assertEqual(result["functions"][0]["return_lifetime"], "borrow_source")
        self.assertEqual(result["volatile_accesses"][0]["operation"], "volatile_load")
        self.assertFalse(result["claims"]["all_foreign_contracts_proved"])

    def test_missing_canonical_volatile_or_foreign_inventory_rejected(self):
        for key in ("volatile_accesses", "external_obligations", "foreign_assumptions"):
            with self.subTest(key=key):
                original = self.hsir.pop(key)
                try:
                    self._reseal_hsir()
                    with self.assertRaisesRegex(WorkspaceError, "obligation inventory"):
                        self._inspect()
                finally:
                    self.hsir[key] = original
                    self._reseal_hsir()

    def test_stale_expected_version_rejected_before_semantic_load(self):
        with (patch.object(agent_semantics, "inspect_workspace", return_value=self.snapshot),
              patch.object(agent_semantics, "load_project") as load):
            with self.assertRaisesRegex(WorkspaceError, "Expected workspace version"):
                agent_semantics.inspect_pinned_semantics("store", expected_version="f" * 64)
            load.assert_not_called()

    def test_foreign_or_unverified_native_publication_never_certified(self):
        self.snapshot["snapshot"]["manifest"]["validation"]["checks"]["rust_borrows_types"] = "not_run"
        with (patch.object(agent_semantics, "inspect_workspace", return_value=self.snapshot),
              patch.object(agent_semantics, "compiler_hash", return_value=self.COMPILER)):
            with self.assertRaisesRegex(WorkspaceError, "Rust-qualified"):
                agent_semantics.inspect_pinned_semantics("store")

    def test_malformed_native_receipt_rejected(self):
        self.snapshot["snapshot"]["manifest"]["validation"]["checks"] = None
        with (patch.object(agent_semantics, "inspect_workspace", return_value=self.snapshot),
              patch.object(agent_semantics, "compiler_hash", return_value=self.COMPILER)):
            with self.assertRaisesRegex(WorkspaceError, "Rust-qualified"):
                agent_semantics.inspect_pinned_semantics("store")

    def test_modified_semantic_payload_rejected(self):
        self.hsir["functions"][0]["returns"] = "u64"
        with self.assertRaisesRegex(WorkspaceError, "checksum"):
            self._inspect()

    def test_forged_proof_claim_rejected_even_if_rehashed(self):
        self.hsir["claims"]["whole_language_soundness_proved"] = True
        self._reseal_hsir()
        with self.assertRaisesRegex(WorkspaceError, "profile/claims"):
            self._inspect()

    def test_absolute_source_path_is_normalized_across_versions(self):
        self.hsir["functions"][0]["path"] = "/immutable/versions/tree/main.hepta"
        self._reseal_hsir()
        result = self._inspect()
        self.assertEqual(result["functions"][0]["path"], "main.hepta")
        for invalid in ("/outside/secret.hepta",
                        "/immutable/versions/tree/../secret.hepta",
                        "../secret.hepta", "other.hepta"):
            with self.subTest(path=invalid):
                self.hsir["functions"][0]["path"] = invalid
                self._reseal_hsir()
                with self.assertRaises(WorkspaceError):
                    self._inspect()

    def test_missing_or_invalid_source_graph_identity_rejected(self):
        for invalid in (None, "", "not-a-digest", True):
            with self.subTest(identity=repr(invalid)):
                self.graph.identity = invalid
                with (patch.object(agent_semantics, "inspect_workspace", return_value=self.snapshot),
                      patch.object(agent_semantics, "load_project", return_value=self.graph),
                      patch.object(agent_semantics, "compiler_hash", return_value=self.COMPILER)):
                    with self.assertRaisesRegex(WorkspaceError, "source graph identity"):
                        agent_semantics.inspect_pinned_semantics("/immutable/store")

    def test_compiler_identity_change_rejected(self):
        self.snapshot["snapshot"]["manifest"]["compiler_sha256"] = "f" * 64
        with (patch.object(agent_semantics, "inspect_workspace", return_value=self.snapshot),
              patch.object(agent_semantics, "compiler_hash", return_value=self.COMPILER)):
            with self.assertRaisesRegex(WorkspaceError, "Rust-qualified"):
                agent_semantics.inspect_pinned_semantics("store")

    def test_source_graph_race_after_lowering_rejected(self):
        states = iter([True, False])
        self.graph = SimpleNamespace(program=object(), identity="f" * 64,
                                     unchanged=lambda: next(states))
        with (patch.object(agent_semantics, "inspect_workspace", return_value=self.snapshot),
              patch.object(agent_semantics, "load_project", return_value=self.graph),
              patch.object(agent_semantics, "check", return_value=self.checked),
              patch.object(agent_semantics, "compiler_hash", return_value=self.COMPILER),
              patch.object(agent_semantics, "lower_checked_program", return_value=self.hsir)):
            with self.assertRaisesRegex(WorkspaceError, "changed after semantic"):
                agent_semantics.inspect_pinned_semantics("store")

    def test_canonical_project_hash_cannot_be_rebound(self):
        self.hsir["project_sha256"] = "0" * 64
        with (patch.object(agent_semantics, "inspect_workspace", return_value=self.snapshot),
              patch.object(agent_semantics, "load_project", return_value=self.graph),
              patch.object(agent_semantics, "check", return_value=self.checked),
              patch.object(agent_semantics, "compiler_hash", return_value=self.COMPILER),
              patch.object(agent_semantics, "lower_checked_program", return_value=self.hsir)):
            with self.assertRaisesRegex(WorkspaceError, "HSIR"):
                agent_semantics.inspect_pinned_semantics("store")


if __name__ == "__main__":
    unittest.main()
