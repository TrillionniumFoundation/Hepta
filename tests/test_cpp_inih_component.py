from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.inih_component import (
    FIXTURES, LATEST, PREVIOUS, MEMBERS, InihMigrationRejected,
    _boolean_literals, _callback_shape, _definitions, generate,
    materialize, verify_sources,
)
from hepta.parser import parse
from hepta.checker import check
from hepta.c_backend import emit_c


class InihSourceMigrationTests(unittest.TestCase):
    def test_two_real_source_graphs_and_complete_member_dispositions(self):
        for version in (PREVIOUS, LATEST):
            generated = generate(version)
            report = generated["report"]
            self.assertEqual(report["upstream"]["commit"], version)
            self.assertEqual(len(report["upstream"]["files"]), 5)
            self.assertEqual(Counter(row["name"] for row in report["member_definitions"]), MEMBERS)
            self.assertEqual(report["member_definition_count"], 18)
            self.assertFalse(report["whole_component_translated"])
            self.assertFalse(report["general_cpp_memory_safety_proved"])
            self.assertEqual(sum(row["disposition"] == "hepta_decisions_with_explicit_foreign_data_operations"
                                 for row in report["member_definitions"]), 3)

    def test_source_tampering_cannot_keep_the_upstream_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "capture"
            shutil.copytree(FIXTURES, root)
            source = root / LATEST / "cpp/INIReader.cpp"
            source.write_text(source.read_text().replace('valstr == "true"', 'valstr == "evil"'))
            with self.assertRaisesRegex(InihMigrationRejected, "identity mismatch"):
                generate(LATEST, fixture_root=root)

    def test_forged_pin_is_not_a_new_translation_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "capture"
            shutil.copytree(FIXTURES, root)
            pin = root / "UPSTREAM.json"
            document = json.loads(pin.read_text())
            document["versions"][0]["files"][0]["bytes"] += 1
            pin.write_text(json.dumps(document))
            with self.assertRaisesRegex(InihMigrationRejected, "source pin changed"):
                verify_sources(LATEST, fixture_root=root)

    def test_new_uninventoried_member_and_top_level_work_are_rejected(self):
        source = (FIXTURES / LATEST / "cpp/INIReader.cpp").read_text()
        for extra in ("\nint INIReader::Unseen() const { return 0; }\n",
                      "\nint side_effect = arbitrary_initializer();\n"):
            with self.assertRaises(InihMigrationRejected):
                _definitions(source + extra)

    def test_literal_extraction_refuses_hidden_work_or_ambiguous_rules(self):
        source = (FIXTURES / LATEST / "cpp/INIReader.cpp").read_text()
        body = next(row["body"] for row in _definitions(source) if row["name"] == "GetBoolean")
        for altered in (body + "\nleak_pointer();\n", body.replace('valstr == "false"', 'valstr == "true"'),
                        body.replace('valstr == "true"', 'other == "true"')):
            with self.assertRaises(InihMigrationRejected):
                _boolean_literals(altered)

    def test_callback_extractor_rejects_escaping_user_pointer(self):
        source = (FIXTURES / LATEST / "cpp/INIReader.cpp").read_text()
        body = next(row["body"] for row in _definitions(source) if row["name"] == "ValueHandler")
        _callback_shape(body)
        with self.assertRaisesRegex(InihMigrationRejected, "closed branch/storage contract"):
            _callback_shape(body.replace("return 1;", "saved_user = user; return 1;", 1))

    def test_new_upstream_error_is_extracted_instead_of_hardcoded_old_semantics(self):
        old, new = (generate(version)["report"] for version in (PREVIOUS, LATEST))
        self.assertNotIn(-3, {row["code"] for row in old["error_cases"]})
        self.assertEqual(next(row["text"] for row in new["error_cases"] if row["code"] == -3),
                         "unable to read file")

    def test_real_frontend_and_independent_backend_admit_both_generated_programs(self):
        for version in (PREVIOUS, LATEST):
            generated = generate(version)
            program = parse(generated["hepta"], "source-pinned-inih.hepta")
            checked = check(program)
            self.assertTrue(checked.ok, [row.to_dict() for row in checked.diagnostics])
            self.assertEqual(len(program.functions), 5)
            c_source = emit_c(program, checked, crate_type="obj")
            self.assertIn("hia_ini_lease_step", c_source)
            self.assertNotIn("rustc", c_source)

    def test_fresh_output_preserves_foreign_files_and_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated"
            materialize(LATEST, output)
            for path in ("ini.c", "ini.h", "LICENSE.txt", "cpp/INIReader.h"):
                self.assertEqual((output / path).read_bytes(), (FIXTURES / LATEST / path).read_bytes())
            self.assertIn("borrow.rethrow_pending();", (output / "cpp/INIReader.cpp").read_text())
            with self.assertRaisesRegex(InihMigrationRejected, "fresh directory"):
                materialize(LATEST, output)


if __name__ == "__main__":
    unittest.main()
