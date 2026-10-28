"""Real separately compiled owner transfer, inventory, ODR and matrix boundaries."""
from __future__ import annotations
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.cpp_composed_project import lower_composed_matrix
from tools.qualify_cpp_composed_project import EXAMPLE, qualify

CLANGXX = os.environ.get("CLANGXX", "/usr/bin/clang++-20")
CLANG = os.environ.get("CLANG", "/usr/bin/clang-20")

@unittest.skipUnless(shutil.which(CLANGXX), "Actual Clang20+ C++ capture required")
class ComposedProjectTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hepta-cpp-project-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.project = self.root / "project"
        shutil.copytree(EXAMPLE, self.project)

    def lower(self):
        return lower_composed_matrix(self.project / "matrix.json", clangxx=CLANGXX)

    def rewrite(self, filename, before, after):
        path = self.project / filename
        text = path.read_text()
        self.assertIn(before, text)
        path.write_text(text.replace(before, after))

    def test_all_configurations_native_original_and_standalone_hia(self):
        if not all(shutil.which(tool) for tool in (CLANG, "gcc", "g++")):
            self.skipTest("Actual native C/C++ tools required")
        report = qualify(self.root / "native", clangxx=CLANGXX, clang=CLANG)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(len(report["variants"]), 2)
        digests = []
        for row in report["variants"]:
            self.assertEqual(row["case_count"], 437)
            self.assertEqual(row["migration"]["unconverted_declarations"], [])
            self.assertEqual(row["migration"]["translation_statistics"]["cross_unit_owner_transfers"], 1)
            self.assertEqual(len(row["reference"]["linked_original_objects"]), 3)
            self.assertEqual(row["standalone_hia"]["original_cpp_link_inputs"], [])
            self.assertEqual(row["expected"]["live"], 0)
            self.assertEqual(row["expected"]["allocations"], 401)
            self.assertEqual(row["expected"]["refusals"], 196)
            digests.append(row["expected"]["observations_fnv64"])
        self.assertNotEqual(*digests)
        self.assertTrue(all(row["rejected"] and not row["artifact_exists"] for row in report["negative_controls"].values()))

    def test_moved_from_owner_observation_in_separate_consumer_rejects(self):
        self.rewrite("consume.cpp", "return final_owner.score(index);", "return owned.score(index);")
        with self.assertRaisesRegex(ValueError, "moved-from|live local"):
            self.lower()

    def test_unsequenced_move_and_observation_in_call_arguments_rejects(self):
        self.rewrite("entry.cpp", "(second), index, early)", "(second), second.limit(), early)")
        with self.assertRaisesRegex(ValueError, "Unsequenced"):
            self.lower()

    def test_active_extra_declaration_and_missing_body_are_not_dropped(self):
        source = self.project / "consume.cpp"
        original = source.read_text()
        source.write_text(original + "\nint unmodeled_global = 3;\n")
        with self.assertRaisesRegex(ValueError, "Unmodeled active"):
            self.lower()
        source.write_text('#include "owners.h"\n')
        with self.assertRaises(ValueError):
            self.lower()

    def test_class_odr_mismatch_across_actual_translation_units_rejects(self):
        self.rewrite("consume.cpp", '#include "owners.h"', '#undef PROJECT_VARIANT\n#define PROJECT_VARIANT 2\n#include "owners.h"')
        with self.assertRaisesRegex(ValueError, "differs between translation units"):
            self.lower()

    def test_forward_attributes_and_defaults_are_not_inventory_support(self):
        self.rewrite("owners.h", "unsigned long long consume_pair(", "__attribute__((weak)) unsigned long long consume_pair(")
        with self.assertRaisesRegex(ValueError, "attributes"):
            self.lower()

    def test_omitted_actual_configuration_rejects(self):
        path = self.project / "matrix.json"
        document = json.loads(path.read_text())
        document["variants"].pop()
        path.write_text(json.dumps(document))
        with self.assertRaises(ValueError):
            self.lower()

    def test_cli_captured_matrix_binds_all_variants_and_publishes_actual_core(self):
        from hepta.cli import main
        from hepta.core import execute_core
        from hepta.hia_program import verify_program
        output, ledger_path = self.root / "selected.core.json", self.root / "capture.json"
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = main(["hia", "import-cpp-composed-matrix", str(self.project / "matrix.json"),
                         "--clangxx", CLANGXX, "--variant", "five_weight",
                         "--output", str(output), "--report", str(ledger_path)])
        self.assertEqual(code, 0, stream.getvalue())
        core = verify_program(output.read_bytes())
        ledger = json.loads(ledger_path.read_text())
        variants = {row["name"]: row for row in ledger["variants"]}
        self.assertEqual(set(variants), {"three_weight", "five_weight"})
        self.assertEqual(core.sha256, variants["five_weight"]["program_sha256"])
        self.assertTrue(all(row["unconverted_declarations"] == [] for row in variants.values()))
        self.assertTrue(all("program" not in row for row in variants.values()))
        self.assertEqual(ledger["admission_authority"], "hepta.hia_program.verify_program")
        self.assertFalse(ledger["native_executed"])
        # Real Clang capture and generated Core run through the public CLI;
        # native source/target comparison remains the separate full qualifier.
        entry, = sorted(core.scalar_entrypoints)
        lowered = {row["name"] for row in variants["five_weight"]["source_lowering"]["functions"]
                   if row["status"] == "lowered"}
        self.assertIn(entry, lowered)
        early = execute_core(core, entry, [3, 4, 7, 0, 0, 1])
        self.assertEqual(early["result"], 2001)
        self.assertEqual(early["resources"]["live_owners"], 0)
        self.assertEqual(early["resources"]["live_local_loans"], 0)

if __name__ == "__main__":
    unittest.main()
