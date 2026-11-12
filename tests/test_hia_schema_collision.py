"""Closed HIA schema-version collision regressions: no source execution."""
import tempfile
import unittest
from pathlib import Path
from tools.audit_hia_schema_collision import (
    HIAWireAuditRejected, compare, declarations, main,
)


# Exact schema/profile literals observed in PR #179 (composite) and PR #196
# (bulk-memory verifier). These are source-profile facts, not a safety theorem.
NOMINAL = b'SCHEMA = "hepta.hia.program.v2"\nPROFILE = "nominal-products-enums-cooperative-tasks-over-closed-ssa-v2"\n'
BULK = b'SCHEMA = "hepta.hia.program.v1"\nPROFILE = "closed-ssa-integer-byte-resources-64-v1"\nSCHEMA_V2 = "hepta.hia.program.v2"\nPROFILE_V2 = "closed-ssa-integer-byte-resources-bulk-64-v2"\n'


class SchemaCollisionTests(unittest.TestCase):
    def test_real_parallel_v2_wire_version_has_conflicting_semantics(self):
        report = compare(declarations(NOMINAL), declarations(BULK))
        self.assertEqual(len(report["semantic_profile_collisions"]), 1)
        self.assertEqual(report["semantic_profile_collisions"][0]["schema"], "hepta.hia.program.v2")
        self.assertEqual(report["status"], "incompatible_schema_label_requires_versioned_adapter")
        self.assertFalse(report["safe_to_merge_without_source_and_consumer_review"])

    def test_relabelled_distinct_schema_does_not_prove_equivalence(self):
        renamed = NOMINAL.replace(b'hepta.hia.program.v2', b'hepta.hia.program.v7')
        result = compare(declarations(renamed), declarations(BULK))
        self.assertEqual(result["semantic_profile_collisions"], [])
        self.assertFalse(result["safe_to_merge_without_source_and_consumer_review"])

    def test_matching_profile_still_not_a_compatibility_proof(self):
        result = compare(declarations(NOMINAL), declarations(NOMINAL))
        self.assertEqual(result["shared_schema_labels"], ["hepta.hia.program.v2"])
        self.assertFalse(result["unreviewed_profiles_automatically_compatible"])

    def test_text_in_comment_is_not_a_declaration(self):
        with self.assertRaisesRegex(HIAWireAuditRejected, "no explicit"):
            declarations(b'# SCHEMA = "hepta.hia.program.v2"\n# PROFILE = "trick"\n')

    def test_dynamic_and_duplicate_profile_refuse(self):
        for raw in (
            b'SCHEMA = get_schema()\nPROFILE = "valid"\n',
            b'SCHEMA = "hepta.hia.program.v2"\nPROFILE = "one"\nPROFILE = "two"\n',
            b'SCHEMA: str = "hepta.hia.program.v2"\nPROFILE = "valid"\n',
            b'SCHEMA, X = ("hepta.hia.program.v2", 3)\nPROFILE = "valid"\n',
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(HIAWireAuditRejected):
                    declarations(raw)

    def test_invalid_missing_duplicate_schema_and_parse_errors(self):
        for raw in (
            b'SCHEMA = "hepta.hia.program.v2"\n',
            b'SCHEMA = "not.hia.v2"\nPROFILE = "p"\n',
            b'SCHEMA = "hepta.hia.program.v2"\nPROFILE = "p"\nSCHEMA_V2 = "hepta.hia.program.v2"\nPROFILE_V2 = "p2"\n',
            b'\xff', b'def broken(:\n',
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(HIAWireAuditRejected):
                    declarations(raw)

    def test_cli_collision_exit_three_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            (base / 'composite.py').write_bytes(NOMINAL)
            (base / 'bulk.py').write_bytes(BULK)
            report = base / 'audit.json'
            argv = ['--left', str(base / 'composite.py'), '--right', str(base / 'bulk.py'),
                    '--output', str(report)]
            self.assertEqual(main(argv), 3)
            self.assertIn('incompatible_schema', report.read_text())
            self.assertEqual(main(argv), 2)

    def test_cli_refuses_symlink_and_corrupt_input(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            (base / 'actual.py').write_bytes(NOMINAL)
            (base / 'alias.py').symlink_to(base / 'actual.py')
            (base / 'bulk.py').write_bytes(BULK)
            self.assertEqual(main(['--left', str(base / 'alias.py'), '--right', str(base / 'bulk.py'),
                                   '--output', str(base / 'out.json')]), 2)
            self.assertFalse((base / 'out.json').exists())


if __name__ == '__main__':
    unittest.main()
