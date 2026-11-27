"""Keep ordinary Core v1-v9 separate from explicit experimental kernel profiles."""
from __future__ import annotations
import ast
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta import hia_opcodes as opcodes
from hepta import hia_schema as schema
from hepta.hia_incremental import IncrementalVerifier
from hepta.hia_program import HIAProgramRejected, verify_program

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "tests/fixtures/hia_core_v9_kernel_isolation_baseline_v1.json"
BASELINE_SHA256 = "1bfe2daa7d46668c1bd7ca025cde1bc8a50d75156be1575b3a0ef0dfcde1f8ee"

def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

class KernelCoreVersionIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = BASELINE.read_bytes()
        if len(raw) != 237685 or sha256(raw).hexdigest() != BASELINE_SHA256:
            raise AssertionError("complete original v9 baseline fixture changed")
        cls.original = json.loads(raw)

    def test_all_nine_complete_ordinary_catalogs_and_registry_unchanged(self):
        for name, expected in self.original["catalogs"].items():
            with self.subTest(schema=name):
                self.assertEqual(wire(opcodes.opcode_catalog(name)), wire(expected))
        self.assertEqual(wire(schema.schema_registry()), wire(self.original["registry"]))
        self.assertEqual(len(opcodes.opcode_catalog(schema.SCHEMA_V9)["instructions"]), 54)
        self.assertEqual(len(opcodes.opcode_catalog(schema.SCHEMA_V8)["instructions"]), 50)

    def test_original_code_function_and_emitter_ast_remain_exact(self):
        for key, expected in self.original["ordinary_classes"].items():
            name, subject = key.split(":")
            nodes = [n for n in ast.parse((ROOT / name).read_bytes()).body
                     if isinstance(n, ast.ClassDef) and n.name == subject]
            self.assertEqual(len(nodes), 1)
            raw = ast.dump(nodes[0], include_attributes=False).encode()
            self.assertEqual({"bytes": len(raw), "sha256": sha256(raw).hexdigest()}, expected)

    def test_kernel_catalogs_have_exact_independent_v8_plus_extensions(self):
        base = self.original["catalogs"][schema.SCHEMA_V8]
        base_names = {row["name"] for row in base["instructions"]}
        for name, added in (
            (schema.KERNEL_FENCE_SCHEMA, {"x86.fence.mfence"}),
            (schema.KERNEL_TLB_SCHEMA, {"x86.fence.mfence", "x86.tlb.invlpg"}),
        ):
            with self.subTest(schema=name):
                actual = opcodes.opcode_catalog(name)
                self.assertEqual({row["name"] for row in actual["instructions"]}, base_names | added)
                self.assertEqual(wire([row for row in actual["instructions"] if row["name"] in base_names]),
                                 wire(base["instructions"]))
                for word in opcodes.WORD_MEMORY:
                    with self.assertRaises(opcodes.OpcodeRejected):
                        opcodes.opcode_spec(word, name)
        with self.assertRaises(opcodes.OpcodeRejected):
            opcodes.opcode_spec("x86.tlb.invlpg", schema.KERNEL_FENCE_SCHEMA)

    def test_all_ordinary_schemas_refuse_privilege_and_atomic_effect_only(self):
        from tests.test_hia_kernel_fence_core import example
        from tests.test_hia_kernel_invlpg_core import sample
        for ordinary in self.original["catalogs"]:
            for factory in (example, sample):
                for only_effect in (False, True):
                    document = factory()
                    document["schema"] = ordinary
                    if only_effect:
                        document["functions"][0]["blocks"][0]["ops"] = []
                    with self.subTest(schema=ordinary, factory=factory.__name__, only_effect=only_effect):
                        with self.assertRaises(HIAProgramRejected):
                            verify_program(document)
            for op in ("x86.fence.mfence", "x86.tlb.invlpg"):
                with self.subTest(schema=ordinary, opcode=op), self.assertRaises(opcodes.OpcodeRejected):
                    opcodes.opcode_spec(op, ordinary)

    def test_kernel_registries_are_bound_to_incremental_cache_policy(self):
        from tests.test_hia_kernel_fence_core import example
        document = example()
        document["schema"] = schema.SCHEMA_V8
        document["functions"][0]["effects"] = []
        document["functions"][0]["blocks"][0]["ops"] = []
        session = IncrementalVerifier(document)
        session.verify(document)
        versions = dict(opcodes._KERNEL_VERSIONS)
        versions[schema.SCHEMA_V8] = 9
        with patch.object(opcodes, "_KERNEL_VERSIONS", versions):
            checked, report = session.verify(document)
            self.assertEqual(report["mode"], "full")
            self.assertEqual(report["fallback_reason"], "verifier_or_registry_changed")
            self.assertEqual(report["functions_body_reused"], [])
            self.assertEqual(checked.canonical_bytes, verify_program(document).canonical_bytes)
        session.verify(document)
        changed = dict(opcodes.KERNEL_OPCODES)
        changed["x86.fence.mfence"] = opcodes.OpcodeSpec(
            "x86.fence.mfence", (), (), effects=("atomic",), since=9,
            semantic_rule="changed-test-only-kernel-policy")
        with patch.object(opcodes, "KERNEL_OPCODES", changed):
            checked, report = session.verify(document)
            self.assertEqual(report["mode"], "full")
            self.assertEqual(report["fallback_reason"], "verifier_or_registry_changed")
            self.assertEqual(report["functions_body_reused"], [])
            self.assertEqual(checked.canonical_bytes, verify_program(document).canonical_bytes)

    def test_unknown_kernel_aliases_and_inexact_schemas_never_grant_admission(self):
        from tests.test_hia_kernel_fence_core import example
        for name in ("hepta.hia.program.kernel-fence.v2", "hepta.hia.program.v10",
                     "hepta.hia.program.kernel-tlb.v01", "", None, True, []):
            document = example()
            document["schema"] = name
            with self.subTest(schema=repr(name)), self.assertRaises(HIAProgramRejected):
                verify_program(document)

if __name__ == "__main__":
    unittest.main()
