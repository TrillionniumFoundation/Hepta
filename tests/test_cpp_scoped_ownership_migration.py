"""Real scoped C++ RAII, branch joins and native fault-path observations."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.cpp_composed_migrate import migrate_cpp_composed
from tools.qualify_cpp_scoped_ownership import EXAMPLE, cases, qualify

CLANGXX = os.environ.get("CLANGXX", "/usr/bin/clang++-20")
CLANG = os.environ.get("CLANG", "/usr/bin/clang-20")
RUSTC = os.environ.get("RUSTC", "rustc")
NATIVE = all(shutil.which(tool) for tool in (CLANGXX, CLANG, RUSTC, "gcc", "g++"))


@unittest.skipUnless(shutil.which(CLANGXX), "Clang20+ is required for actual source ASTs")
class ScopedOwnershipMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-scoped-cpp-tests-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = (EXAMPLE / "scoped.cpp").read_text()

    def migrate(self, text, name="candidate"):
        source, target = self.root / (name + ".cpp"), self.root / (name + ".hepta")
        source.write_text(text)
        return migrate_cpp_composed(source, target, clangxx=CLANGXX), target

    def with_body(self, body):
        prefix = self.source.split("    try {", 1)[0]
        return (prefix + "    try {\n" + body + "\n"
                "    } catch (int code) { return 1000 + static_cast<unsigned long long>(code); }\n"
                "      catch (...) { return 1001; }\n}\n")

    def test_nested_resource_implementation_has_complete_inventory(self):
        report, target = self.migrate(self.source)
        self.assertTrue(report["ok"], report["diagnostics"])
        self.assertEqual(report["active_declarations"], 64)
        self.assertEqual(len(report["declaration_inventory"]), 64)
        self.assertEqual(report["unconverted_declarations"], [])
        self.assertEqual(report["translation_statistics"]["owner_constructions"], 4)
        self.assertEqual(report["translation_statistics"]["owner_moves"], 1)
        self.assertTrue(report["resource_verification"]["ok"])
        self.assertFalse(report["foreign_cpp_implementation_retained"])
        self.assertNotIn("unsafe", target.read_text())

    def test_both_branch_local_moves_consume_the_outer_owner(self):
        text = self.with_body("""
        PairedBytes outer(left, right, 0);
        if (early == 1) {
            PairedBytes branch(static_cast<PairedBytes&&>(outer));
            branch.prepare(value);
        } else {
            PairedBytes branch(static_cast<PairedBytes&&>(outer));
            branch.prepare(value);
        }
        return 777;
""")
        report, _ = self.migrate(text)
        self.assertTrue(report["ok"], report["diagnostics"])
        changed, output = self.migrate(text.replace("return 777;", "return outer.limit();"), "used_after_both_branches")
        self.assertFalse(changed["ok"])
        self.assertFalse(output.exists())

    def test_unbalanced_branch_consumption_and_moved_from_access_reject(self):
        cases_ = {
            "one_branch": self.with_body("""
                PairedBytes outer(left, right, 0);
                if (early == 1) { PairedBytes inner(static_cast<PairedBytes&&>(outer)); }
                return 17;
            """),
            "moved_from": self.source.replace("if (early == 2) {", "if (early == 2) { return first.limit();"),
            "conditional_escape": self.source.replace("if (index >= outer.limit())", "if (index >= probe.limit())"),
            "nested_handler": self.source.replace("inner.prepare(7);", "try { inner.prepare(7); } catch (...) {}"),
            "loop": self.source.replace("inner.prepare(7);", "while (early == 8) { inner.prepare(7); }"),
            "reference_alias": self.source.replace("inner.prepare(7);", "PairedBytes& alias = inner; alias.prepare(7);"),
        }
        for name, text in cases_.items():
            with self.subTest(name=name):
                report, output = self.migrate(text, name)
                self.assertFalse(report["ok"], name)
                self.assertFalse(output.exists())

    def test_source_scope_bound_and_unreachable_declarations_fail_closed(self):
        excessive = self.source.replace("inner.prepare(7);", "{" * 17 + "inner.prepare(7);" + "}" * 17)
        report, output = self.migrate(excessive, "excessive")
        self.assertFalse(report["ok"])
        self.assertEqual(report["diagnostics"][0]["code"], "E_CPP_COMPOSED_SCOPE")
        self.assertFalse(output.exists())
        unreachable = self.with_body("PairedBytes owner(left, right, 0); { return 7; } int hidden = 1;")
        report, output = self.migrate(unreachable, "unreachable")
        self.assertFalse(report["ok"])
        self.assertFalse(output.exists())

    @unittest.skipUnless(NATIVE, "All four actual native toolchains are required")
    def test_original_rust_c_and_direct_llvm_match_all_cleanup_and_fault_paths(self):
        report = qualify(self.root / "native", clangxx=CLANGXX, clang=CLANG, rustc=RUSTC)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["case_count"], len(cases()))
        self.assertEqual(set(report["routes"]), {"cpp_reference", "rust", "c", "llvm"})
        self.assertEqual(set(report["negative_controls"]), {"leak", "destruction_order"})
        self.assertEqual(report["expected"]["allocations"], report["expected"]["frees"])
        self.assertGreater(report["expected"]["refusals"], 0)
        self.assertEqual(report["expected"]["live"], 0)
        self.assertFalse(report["claims"]["original_cpp_objects_in_targets"])


if __name__ == "__main__":
    unittest.main()
