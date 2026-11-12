"""Proof identities must change with actual admission owners, including caches."""
from __future__ import annotations

import ast
from contextlib import ExitStack
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_checker_identity as identity
from hepta import hia_scalar_proof_contract as scalar
from hepta.hia_safe_core import _checker_source_identity


INTEGRATED_OWNERS = (
    'HEPTA_HIA_PROGRAM_EXECUTION_MANIFEST',
    'HEPTA_HIA_STATIC_BUDGET_MANIFEST',
    'HEPTA_HIA_NOMINAL_ADMISSION_MANIFEST', 'HEPTA_HIA_NOMINAL_FUNCTION_MANIFEST',
    'HEPTA_HIA_NOMINAL_MODULE_MANIFEST', 'HEPTA_HIA_NOMINAL_TERMINATORS_MANIFEST',
    'HEPTA_HIA_CALL_PRIMITIVE_MANIFEST', 'HEPTA_HIA_RECORD_TRANSITIONS_MANIFEST',
    'HEPTA_HIA_RECORD_OPERATIONS_MANIFEST', 'HEPTA_HIA_ENUM_OPERATIONS_MANIFEST',
    'HEPTA_HIA_ENUM_MATCH_MANIFEST', 'HEPTA_HIA_TASK_OPERATIONS_MANIFEST',
    'HEPTA_HIA_TASK_HELPER_CACHE_MANIFEST',
)


class CheckerDependencyIdentityTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ, {
            key: "" for key in identity.NATIVE_OWNERS}))
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="checker-identity-")))

    def manifest(self, name, image_bytes, module=None):
        if module is None:
            from hepta import hia_json_preflight_native as module
        image = self.root / (name + ".bin")
        image.write_bytes(image_bytes)
        manifest = self.root / (name + ".json")
        manifest.write_text(json.dumps({"schema": module.SCHEMA,
            "source_sha256": sha256(module.SOURCE.read_bytes()).hexdigest(),
            "image_path": image.name, "image_sha256": sha256(image_bytes).hexdigest(),
            "compiler_sha256": "a" * 64}))
        return str(manifest)

    def test_reviewed_inventory_covers_verifier_imports_and_explicit_selectors(self):
        root = Path(identity.__file__).parent
        imports, selectors = set(), set()
        for name in identity.CORE_SOURCE_FILES:
            tree = ast.parse((root / name).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module:
                    imports.add(node.module + ".py")
                if (name != "hia_native_helpers.py" and isinstance(node, ast.Constant) and type(node.value) is str
                        and node.value.startswith("HEPTA_HIA_") and node.value.endswith("_MANIFEST")):
                    selectors.add(node.value)
        # hia_program.execute is a public VM convenience wrapper, not Core
        # admission; semantic proof consumers bind their replay module separately.
        self.assertEqual(imports - set(identity.CORE_SOURCE_FILES), {"hia_program_runtime.py"})
        self.assertEqual(selectors, set(identity.NATIVE_OWNERS) | set(identity.HELD_NATIVE_OWNERS))
        self.assertFalse(set(identity.NATIVE_OWNERS) & set(identity.HELD_NATIVE_OWNERS))

    def test_every_checker_binds_the_previously_omitted_source_dependencies(self):
        from hepta import (hia_optimization, hia_program_llvm, hia_program_native,
            hia_bounded_unroll, hia_scalar_lowering_check, hia_x86_search, hia_finite_context)
        checkers = (hia_optimization.checker_identity, hia_program_llvm._implementation_hash,
            hia_program_native._implementation_hash, hia_bounded_unroll.checker_identity,
            hia_scalar_lowering_check.checker_identity, hia_x86_search._implementation_hash,
            hia_finite_context._implementation, _checker_source_identity,
            lambda: scalar._source_identity("validate_translation"))
        original_read = Path.read_bytes
        for filename in ("hia_json_decode.py", "hia_json_canonical_native.py",
                         "hia_sha256_native.py", "hia_core_admission_native.py",
                         "hia_composite_function_tokens.py", "hia_native_value_graph.py",
                         "hia_nominal_function_native.py", "hia_task_helper_cache_native.py",
                         "hia_program_execution_native.py", "hia_static_budget.py",
                         "hia_static_budget_native.py", "hia_heap_bound.py"):
            def changed(path):
                data = original_read(path)
                return data + b"\n# dependency drift\n" if path.name == filename else data
            for checker in checkers:
                with self.subTest(source=filename, checker=checker.__module__):
                    before = checker()
                    with patch.object(Path, "read_bytes", changed):
                        self.assertNotEqual(before, checker())

    def test_every_integrated_owner_binds_mapping_bytes_without_running_them(self):
        # These short executable mappings test custody only. The retained HIA
        # review image is exercised separately; no stub is native qualification.
        for key in INTEGRATED_OWNERS:
            with self.subTest(selector=key):
                module_name, loader_name = identity.NATIVE_OWNERS[key]
                module = importlib.import_module('hepta.' + module_name)
                path = self.manifest(module_name, bytes.fromhex('31c0c3'), module)
                owner = getattr(module, loader_name)(path)
                owner._entry = lambda *args: self.fail('identity capture executed native code')
                with patch.dict(os.environ, {key: path}):
                    selected = identity.checker_native_selection()[key]
                    self.assertEqual(selected['schema'], module.SCHEMA)
                    self.assertEqual(selected['sources'], {
                        'image': sha256(module.SOURCE.read_bytes()).hexdigest()})
                    self.assertEqual(selected['images']['image'], {
                        'image_sha256': sha256(owner._mapping[:]).hexdigest(), 'image_bytes': 3})
                    Path(path).with_suffix('.bin').write_bytes(b'changed backing bytes')
                    self.assertEqual(selected, identity.checker_native_selection()[key])
                self.assertIsNone(identity.checker_native_selection()[key])

    def test_selected_identity_uses_actual_immutable_mapping_and_never_calls_it(self):
        from hepta.hia_json_preflight_native import NativeJsonPreflight
        key = "HEPTA_HIA_JSON_PREFLIGHT_MANIFEST"
        first = self.manifest("first", bytes.fromhex("31c0c3"))
        second = self.manifest("second", bytes.fromhex("b801000000c3"))
        with patch.object(NativeJsonPreflight, "status", side_effect=AssertionError("native execution forbidden")):
            with patch.dict(os.environ, {key: first}):
                before = identity.checker_native_selection()
                self.assertEqual(before[key]["images"]["image"]["image_sha256"],
                                 sha256(bytes.fromhex("31c0c3")).hexdigest())
                # A warm cached image intentionally retains its original bytes.
                Path(first).with_suffix(".bin").write_bytes(b"different backing bytes")
                self.assertEqual(before, identity.checker_native_selection())
            with patch.dict(os.environ, {key: second}):
                self.assertNotEqual(before, identity.checker_native_selection())
        self.assertTrue(all(value is None for value in identity.checker_native_selection().values()))

    def test_missing_or_invalid_selected_manifest_cannot_become_an_unselected_checker(self):
        key = "HEPTA_HIA_JSON_PREFLIGHT_MANIFEST"
        with patch.dict(os.environ, {key: str(self.root / "absent.json")}):
            with self.assertRaises(OSError):
                identity.checker_native_selection()
            scope = scalar.begin_scalar_proof("validate_translation")
            self.assertIsNone(scope["native_selection"])
            self.assertIn("identity_error", scope)

    def test_selection_drift_revokes_a_scalar_conclusion(self):
        key = "HEPTA_HIA_JSON_PREFLIGHT_MANIFEST"
        scope = scalar.begin_scalar_proof("validate_translation")
        result = {"status": "proved", "claims": {"equivalence": True},
                  "solver": {"binding_sha256": "a" * 64, "library_sha256": "b" * 64}}
        with patch.dict(os.environ, {key: self.manifest("changed", bytes.fromhex("31c0c3"))}):
            result = scalar.finish_scalar_proof(result, scope)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "scope_checker_identity_changed_or_unavailable")
        self.assertFalse(result["claims"]["equivalence"])

    def test_invalid_selected_image_cannot_produce_checker_digest(self):
        path = self.manifest("invalid", bytes.fromhex("31c0c3"))
        Path(path).with_suffix(".bin").write_bytes(b"hash differs before first load")
        with patch.dict(os.environ, {"HEPTA_HIA_JSON_PREFLIGHT_MANIFEST": path}):
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                identity.checker_digest()


if __name__ == "__main__":
    unittest.main()
