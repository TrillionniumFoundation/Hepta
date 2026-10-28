"""Real library-backed owner migration and fail-closed source boundaries."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.cpp_unique_project import lower_unique_matrix
from tools.qualify_cpp_unique_project import EXAMPLE, qualify

CLANGXX = os.environ.get("CLANGXX", "/usr/bin/clang++-20")
CLANG = os.environ.get("CLANG", "/usr/bin/clang-20")


@unittest.skipUnless(shutil.which(CLANGXX), "Actual Clang20+ and standard C++ headers required")
class UniqueProjectTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-cpp-unique-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.project = self.root / "project"
        shutil.copytree(EXAMPLE, self.project)

    def lower(self):
        return lower_unique_matrix(self.project / "matrix.json", clangxx=CLANGXX)

    def rewrite(self, name, before, after):
        path = self.project / name
        text = path.read_text()
        self.assertIn(before, text)
        path.write_text(text.replace(before, after))

    def test_actual_unique_array_all_configurations_native(self):
        if not all(shutil.which(tool) for tool in (CLANG, "gcc", "g++")):
            self.skipTest("Actual native C/C++ compilers required")
        report = qualify(self.root / "native", clangxx=CLANGXX, clang=CLANG)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(len(report["variants"]), 2)
        for row in report["variants"]:
            migration = row["migration"]
            self.assertEqual(row["case_count"], 437)
            self.assertEqual(migration["unconverted_declarations"], [])
            self.assertGreater(migration["standard_library_declaration_count"], 0)
            self.assertTrue(all(r["status"] == "standard_library_dependency_not_migrated"
                                for r in migration["standard_library_declarations"]))
            self.assertTrue(all(r["reference_equal"] for r in migration["standard_library_expansion"]))
            self.assertTrue(migration["claims"]["standard_library_contract_is_trusted"])
            self.assertFalse(migration["claims"]["standard_library_implementation_migrated"])
            self.assertEqual(row["standalone_hia"]["original_cpp_link_inputs"], [])
            self.assertEqual(row["expected"]["allocations"], row["expected"]["frees"])
            self.assertEqual(row["expected"]["live"], 0)
        self.assertTrue(all(r["rejected"] and not r["artifact_exists"]
                            for r in report["negative_controls"].values()))
        self.assertGreater(report["costs"]["migration_wall_ns"], 0)
        self.assertIsNone(report["costs"]["human_engineering_seconds"])

    def test_release_before_constructor_failure_rejects(self):
        self.rewrite("owners.h", "if (reject) { throw 2; }",
                     "if (reject) { (void)data_.release(); throw 2; }")
        with self.assertRaisesRegex(ValueError, "unique-array wrapper"):
            self.lower()

    def test_active_extra_namespace_and_deleter_specialization_reject(self):
        self.rewrite("owners.h", "// Complete default-deleter", '''namespace std {
template <> struct default_delete<unsigned char[]> {
    void operator()(unsigned char* value) const noexcept { delete[] value; }
};
}
// Complete default-deleter''')
        with self.assertRaisesRegex(ValueError, "Unmodeled active project declaration"):
            self.lower()

    def test_macro_changed_standard_header_semantics_reject(self):
        self.rewrite("owners.h", "#include <memory>",
                     "#define _GLIBCXX_ASSERTIONS 1\n#include <memory>")
        with self.assertRaisesRegex(ValueError, "expanded standard-library contract"):
            self.lower()

    def test_moved_from_and_unsequenced_owner_use_reject(self):
        self.rewrite("consume.cpp", "return final_owner.score(index);", "return owned.score(index);")
        with self.assertRaisesRegex(ValueError, "moved-from|live local"):
            self.lower()
        self.rewrite("consume.cpp", "return owned.score(index);", "return final_owner.score(index);")
        self.rewrite("entry.cpp", "(second), index, early)", "(second), second.limit(), early)")
        with self.assertRaisesRegex(ValueError, "Unsequenced"):
            self.lower()

    def test_missing_definition_and_macro_odr_change_reject(self):
        path = self.project / "consume.cpp"
        original = path.read_text()
        path.write_text('#include "owners.h"\n')
        # Missing use may also leave the compiler-generated default destructor
        # uninstantiated, causing an earlier exact owner-shape refusal. Either
        # is a valid refusal of this incomplete project; do not weaken the
        # destructor contract merely to force one diagnostic phase.
        with self.assertRaises(ValueError):
            self.lower()
        path.write_text(original.replace('#include "owners.h"',
                                        '#undef PROJECT_VARIANT\n#define PROJECT_VARIANT 2\n#include "owners.h"'))
        with self.assertRaisesRegex(ValueError, "differs between translation units"):
            self.lower()

    def test_omitted_declared_configuration_rejects(self):
        path = self.project / "matrix.json"
        document = json.loads(path.read_text())
        document["variants"].pop()
        path.write_text(json.dumps(document))
        with self.assertRaises(ValueError):
            self.lower()


if __name__ == "__main__":
    unittest.main()
