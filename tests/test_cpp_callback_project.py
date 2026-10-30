"""Actual callback bodies, error cleanup and unsupported lifetime boundaries."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.cpp_callback_project import lower_callback_matrix
from tools.qualify_cpp_callback_project import EXAMPLE, oracle, qualify

CLANGXX = os.environ.get("CLANGXX", "/usr/bin/clang++-20")
CLANG = os.environ.get("CLANG", "/usr/bin/clang-20")


class CallbackOracleTests(unittest.TestCase):
    def test_callback_error_still_releases_both_owners_in_reverse_order(self):
        row = oracle((3, 5, 7, 0, 0, 3, 0), "three_weight")
        self.assertEqual(row["expected"], 4001)
        self.assertEqual(row["events"], [[1, 1, 3], [1, 2, 5], [2, 2, 5], [2, 1, 3]])

    def test_second_allocation_refusal_releases_the_completed_first_member(self):
        row = oracle((3, 5, 7, 0, 0, 0, 2), "three_weight")
        self.assertEqual(row["expected"], 1001)
        self.assertEqual(row["events"], [[1, 1, 3], [3, 2, 5], [2, 1, 3]])


@unittest.skipUnless(shutil.which(CLANGXX), "Actual Clang20+ and C++ headers required")
class CallbackProjectTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-cpp-callback-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.project = self.root / "project"
        shutil.copytree(EXAMPLE, self.project)

    def rewrite(self, filename, old, new):
        path = self.project / filename
        text = path.read_text()
        self.assertIn(old, text)
        path.write_text(text.replace(old, new))

    def lower(self):
        return lower_callback_matrix(self.project / "matrix.json", clangxx=CLANGXX)

    def test_closed_callback_implementation_and_native_cleanup(self):
        if not all(shutil.which(tool) for tool in (CLANG, "gcc", "g++")):
            self.skipTest("Actual native C/C++ compilers required")
        report = qualify(self.root / "native", clangxx=CLANGXX, clang=CLANG,
                         iterations=10000, repeats=3)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(len(report["variants"]), 2)
        for row in report["variants"]:
            self.assertGreater(row["case_count"], 1000)
            self.assertEqual(row["migration"]["translation_statistics"]["borrowed_callback_calls"], 1)
            self.assertEqual(row["migration"]["translation_statistics"]["closed_callback_bindings"], 1)
            self.assertEqual(row["standalone_hia"]["original_cpp_link_inputs"], [])
            self.assertEqual(row["migration"]["unconverted_declarations"], [])
            self.assertEqual(row["expected"]["allocations"], row["expected"]["frees"])
            self.assertEqual(row["expected"]["live"], 0)
            self.assertGreater(row["families"]["callback_error_then_owner_cleanup"], 0)
            self.assertGreater(row["families"]["cancel_after_owner_transfer"], 0)
        for label, control in report["negative_controls"].items():
            if label.endswith("missing_drop"):
                self.assertTrue(control["rejected"])
                self.assertFalse(control["artifact_exists"])
            else:
                self.assertTrue(control["resource_check_passed"])
                self.assertTrue(control["detected"])
        self.assertTrue(report["performance"]["ok"])
        self.assertTrue(report["allocation_high_water"]["ok"])
        for row in report["performance"]["variants"]:
            for workload in row["workloads"]:
                self.assertIn("cpp_lto", workload["samples"])
        self.assertIsNone(report["migration_coverage"]["human_engineering_seconds"])
        self.assertFalse(report["performance"]["universal_performance_superiority_claimed"])

    def test_null_callback_binding_rejects(self):
        self.rewrite("entry.cpp", "), read_pair, index, early)", "), nullptr, index, early)")
        with self.assertRaisesRegex(ValueError, "Callback must be|binding"):
            self.lower()

    def test_borrowing_the_moved_from_owner_rejects(self):
        self.rewrite("consume.cpp", "callback(final_owner, index", "callback(owned, index")
        with self.assertRaisesRegex(ValueError, "moved-from|live local"):
            self.lower()

    def test_mutating_callback_borrow_rejects(self):
        self.rewrite("entry.cpp", "return borrowed.score(index);",
                     "const_cast<PairedBytes&>(borrowed).prepare(0); return borrowed.score(index);")
        with self.assertRaises(ValueError):
            self.lower()

    def test_pointer_escape_rejects_the_complete_project(self):
        self.rewrite("entry.cpp", '#include "owners.h"',
                     '#include "owners.h"\nconst PairedBytes* escaped;')
        self.rewrite("entry.cpp", "if (reject) { return 4001; }",
                     "escaped = &borrowed; if (reject) { return 4001; }")
        with self.assertRaisesRegex(ValueError, "Unmodeled active project declaration"):
            self.lower()

    def test_second_callback_execution_outside_profile_rejects(self):
        self.rewrite("consume.cpp", "return callback(final_owner, index, early == 3);",
                     "const unsigned long long first = callback(final_owner, index, early == 3);\n"
                     "    return callback(final_owner, index, early == 3);")
        with self.assertRaises(ValueError):
            self.lower()

    def test_callback_definition_cannot_be_omitted(self):
        self.rewrite("entry.cpp", "unsigned long long read_pair(const PairedBytes& borrowed, unsigned long index, bool reject) noexcept {\n"
                     "    if (reject) { return 4001; }\n    return borrowed.score(index);\n}\n", "")
        with self.assertRaisesRegex(ValueError, "Complete cross-unit|definition"):
            self.lower()


if __name__ == "__main__":
    unittest.main()
