"""Version selection cannot substitute for source-free semantic verification."""
from __future__ import annotations

import copy
import json
import unittest

from hepta.hia_core_upgrade import import_legacy_composite_v2, upgrade_core_to_v6
from hepta.hia_program import HIAProgramRejected, verify_core
from hepta.hia_program_runtime import execute_program
from hepta.hia_schema import (
    CANONICAL_CORE_SCHEMA, COMPOSITE_SCHEMA, LEGACY_COMPOSITE_PROFILE,
    PRIMITIVE_PROFILES, PRIMITIVE_SCHEMAS, PROFILE_V2, SCHEMA_V2, SCHEMA_V6,
    profile_for_schema, schema_registry, supports_feature,
)
from tests.test_hia_core_upgrade import scalar
from tests.test_hia_program_composite import enum_owner_program, stored_loan_program, task_program
from tests.test_hia_composite_v6_resources import composite_bulk_program, composite_range_task_program


class SchemaUnificationTests(unittest.TestCase):
    def test_registry_and_primitive_reports_use_the_exact_schema(self):
        self.assertNotIn(COMPOSITE_SCHEMA, PRIMITIVE_SCHEMAS)
        for schema in PRIMITIVE_SCHEMAS:
            checked = verify_core(scalar(schema))
            report = checked.normalization_report
            self.assertEqual(report["input_schema"], schema)
            self.assertEqual(report["core_schema"], schema)
            self.assertEqual(checked.report()["profile"], profile_for_schema(schema))
        self.assertFalse(supports_feature(SCHEMA_V2, "range_fill"))
        self.assertTrue(supports_feature(SCHEMA_V6, "range_fill"))
        with self.assertRaises(TypeError):
            PRIMITIVE_PROFILES[SCHEMA_V2] = "forged"
        report = schema_registry()
        report["primitive"][0]["features"].append("forged")
        self.assertNotIn("forged", schema_registry()["primitive"][0]["features"])

    def test_legacy_nominal_namespace_is_never_guessed_from_its_shape(self):
        legacy = task_program()
        legacy["schema"] = SCHEMA_V2
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_VERSION_COLLISION"):
            verify_core(legacy)
        with self.assertRaises(HIAProgramRejected):
            upgrade_core_to_v6(legacy, legacy_profile=PROFILE_V2)
        self.assertEqual(verify_core(scalar(SCHEMA_V2)).as_dict()["schema"], SCHEMA_V2)

    def test_explicit_legacy_nominal_adapter_preserves_real_resources_and_results(self):
        for builder, function, arguments in ((stored_loan_program, "stored", [True]),
                                               (enum_owner_program, "choose", [False, 7]),
                                               (task_program, "task_case", [2])):
            current = builder()
            legacy = copy.deepcopy(current)
            legacy["schema"] = SCHEMA_V2
            original = copy.deepcopy(legacy)
            imported, receipt = import_legacy_composite_v2(json.dumps(legacy))
            self.assertEqual(legacy, original)
            self.assertEqual(imported.as_dict()["schema"], CANONICAL_CORE_SCHEMA)
            self.assertEqual(json.loads(imported.structured_bytes)["schema"], COMPOSITE_SCHEMA)
            self.assertTrue(receipt["claims"]["legacy_v1_instruction_set_reverified"])
            self.assertEqual(imported, verify_core(imported))
            expected = execute_program(current, function, arguments)
            actual = execute_program(imported.canonical_bytes, function, arguments)
            self.assertEqual(actual["result"], expected["result"])
            self.assertEqual(actual["resources"], expected["resources"])

    def test_legacy_adapter_cannot_gain_new_primitive_or_nominal_opcodes(self):
        for builder in (composite_bulk_program, composite_range_task_program):
            legacy = builder()
            legacy["schema"] = SCHEMA_V2
            with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_OPCODE"):
                import_legacy_composite_v2(legacy)
        # Even a primitive-only nominal program must obey the old v1
        # instruction set; selecting the nominal adapter does not grant bulk.
        legacy = stored_loan_program()
        legacy["schema"] = SCHEMA_V2
        operation = legacy["functions"][0]["blocks"][1]["ops"][5]
        self.assertEqual(operation["op"], "buffer.store")
        operation["op"] = "buffer.fill"
        operation["args"] = ["parent", "byte"]
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_OPCODE"):
            import_legacy_composite_v2(legacy)

    def test_selected_primitive_v2_upgrade_is_explicit_and_cannot_choose_nominal_profile(self):
        before = scalar(SCHEMA_V2)
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_VERSION_COLLISION"):
            upgrade_core_to_v6(before)
        upgraded, report = upgrade_core_to_v6(before, legacy_profile=PROFILE_V2)
        self.assertEqual(upgraded.as_dict(), {**before, "schema": SCHEMA_V6})
        self.assertTrue(report["claims"]["legacy_v2_wire_ambiguity_resolved"])
        for profile in (LEGACY_COMPOSITE_PROFILE, "trusted", False):
            with self.subTest(profile=profile), self.assertRaises(HIAProgramRejected):
                upgrade_core_to_v6(before, legacy_profile=profile)
        with self.assertRaises(HIAProgramRejected):
            upgrade_core_to_v6(scalar(SCHEMA_V6), legacy_profile=PROFILE_V2)

    def test_no_malformed_or_forged_receipt_can_import_a_program(self):
        legacy = task_program()
        legacy["schema"] = SCHEMA_V2
        legacy["functions"][1]["blocks"][0]["ops"].pop()
        with self.assertRaises(HIAProgramRejected):
            import_legacy_composite_v2(legacy)
        with self.assertRaises(HIAProgramRejected):
            import_legacy_composite_v2(scalar(SCHEMA_V2))
        with self.assertRaises(HIAProgramRejected):
            import_legacy_composite_v2(task_program())
        for value in (None, False, [], {}, [SCHEMA_V6]):
            bad = scalar()
            bad["schema"] = value
            with self.subTest(value=value), self.assertRaises(HIAProgramRejected):
                verify_core(bad)


if __name__ == "__main__":
    unittest.main()
