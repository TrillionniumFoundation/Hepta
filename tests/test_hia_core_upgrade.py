"""Executable HIA lineage can upgrade only without changing instruction meaning."""
from __future__ import annotations

from copy import deepcopy
import unittest

from hepta.hia_core_upgrade import upgrade_core_to_v6, upgrade_core_to_v7
from hepta.hia_schema import SCHEMA_V7, PROFILE_V2
from hepta.hia_program import (
    HIAProgramRejected, SCHEMA, SCHEMA_V2, SCHEMA_V3,
    SCHEMA_V4, SCHEMA_V5, SCHEMA_V6, verify_program,
)
from hepta.hia_program_runtime import execute_program


def scalar(schema=SCHEMA):
    return {"schema": schema, "module": "upgrade_case", "functions": [{
        "name": "compute", "params": [{"name": "a", "type": "i32"},
                                      {"name": "b", "type": "i32"}],
        "returns": ["i32"], "effects": [], "entry": "entry", "blocks": [{
            "id": "entry", "params": [{"name": "a", "type": "i32"},
                                        {"name": "b", "type": "i32"}],
            "ops": [{"op": "int.add.wrap", "args": ["a", "b"],
                     "out": [{"name": "sum", "type": "i32"}], "attrs": {}}],
            "term": {"op": "ret", "values": ["sum"]},
        }],
    }]}


def owned(schema=SCHEMA):
    return {"schema": schema, "module": "owned_case", "functions": [{
        "name": "use_owner", "params": [{"name": "value", "type": "u8"}],
        "returns": ["u8"], "effects": ["alloc", "read", "write", "trap"],
        "entry": "entry", "blocks": [{"id": "entry",
            "params": [{"name": "value", "type": "u8"}],
            "ops": [
                {"op": "const", "args": [], "out": [{"name": "n", "type": "usize"}],
                 "attrs": {"value": 1}},
                {"op": "buffer.new", "args": ["n"],
                 "out": [{"name": "owner", "type": "buffer"}], "attrs": {}},
                {"op": "borrow.mut", "args": ["owner"],
                 "out": [{"name": "writer", "type": "mutbuf"}], "attrs": {}},
                {"op": "const", "args": [], "out": [{"name": "at", "type": "usize"}],
                 "attrs": {"value": 0}},
                {"op": "buffer.store", "args": ["writer", "at", "value"],
                 "out": [], "attrs": {}},
                {"op": "loan.end", "args": ["writer"], "out": [], "attrs": {}},
                {"op": "borrow.read", "args": ["owner"],
                 "out": [{"name": "reader", "type": "readbuf"}], "attrs": {}},
                {"op": "buffer.load", "args": ["reader", "at"],
                 "out": [{"name": "readback", "type": "u8"}], "attrs": {}},
                {"op": "loan.end", "args": ["reader"], "out": [], "attrs": {}},
                {"op": "owner.drop", "args": ["owner"], "out": [], "attrs": {}},
            ],
            "term": {"op": "ret", "values": ["readback"]},
        }],
    }]}


class UpgradeTests(unittest.TestCase):
    def test_explicit_v7_preserves_old_payload_and_v6_does_not_downgrade(self):
        for version in (SCHEMA, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6, SCHEMA_V7):
            with self.subTest(version=version):
                source = owned(version)
                upgraded, receipt = upgrade_core_to_v7(source)
                self.assertEqual(upgraded.as_dict(), {**source, "schema": SCHEMA_V7})
                self.assertEqual(execute_program(upgraded, "use_owner", [37])["result"], 37)
                self.assertEqual(receipt["target_schema"], SCHEMA_V7)
        with self.assertRaises(HIAProgramRejected):
            upgrade_core_to_v6(upgraded)

    def test_v7_upgrade_preserves_explicit_legacy_selection_requirement(self):
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_VERSION_COLLISION"):
            upgrade_core_to_v7(scalar(SCHEMA_V2))
        upgraded, _ = upgrade_core_to_v7(scalar(SCHEMA_V2), legacy_profile=PROFILE_V2)
        self.assertEqual(execute_program(upgraded, "compute", [7, 9])["result"], 16)
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_VERSION_COLLISION"):
            upgrade_core_to_v7(upgraded, legacy_profile=PROFILE_V2)

    def test_safe_versions_are_reverified_and_payload_is_identical(self):
        for version in (SCHEMA, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6):
            with self.subTest(version=version):
                source = scalar(version)
                before = deepcopy(source)
                upgraded, receipt = upgrade_core_to_v6(source)
                self.assertEqual(source, before)
                self.assertEqual(upgraded.as_dict(), {**source, "schema": SCHEMA_V6})
                self.assertTrue(receipt["claims"]["operational_payload_unchanged_excluding_schema"])
                self.assertFalse(receipt["claims"]["llvm_backend_refinement_proved"])
                self.assertEqual(receipt["source_program_sha256"], verify_program(source).sha256)
                for a, b in ((0, 2), (-1, 2), (2**31 - 1, 1)):
                    self.assertEqual(execute_program(source, "compute", [a, b])["result"],
                                     execute_program(upgraded, "compute", [a, b])["result"])

    def test_owner_loan_drop_transition_unmodified(self):
        source = owned()
        upgraded, _ = upgrade_core_to_v6(source)
        before = execute_program(source, "use_owner", [17])
        after = execute_program(upgraded, "use_owner", [17])
        self.assertEqual(before["result"], after["result"])
        self.assertEqual(before["resources"], after["resources"])

    def test_v2_collision_is_rejected_even_for_accepted_local_v2_bytes(self):
        old = scalar(SCHEMA_V2)
        verify_program(old)  # Its current local interpretation is well formed.
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_VERSION_COLLISION"):
            upgrade_core_to_v6(old)
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_VERSION_COLLISION"):
            upgrade_core_to_v6(verify_program(old))

    def test_unknown_shape_or_forged_safety_claims_fail_closed(self):
        for name, value in (("legacy_profile", "trusted"), ("proof", True)):
            with self.subTest(name=name):
                old = scalar()
                old[name] = value
                with self.assertRaises(HIAProgramRejected):
                    upgrade_core_to_v6(old)
        damaged = owned()
        damaged["functions"][0]["blocks"][0]["ops"] = damaged["functions"][0]["blocks"][0]["ops"][:-1]
        with self.assertRaises(HIAProgramRejected):
            upgrade_core_to_v6(damaged)


if __name__ == "__main__":
    unittest.main()
