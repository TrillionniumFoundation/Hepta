"""Real C record/slice contracts across complete multi-TU build variants."""
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.c_migrate import migrate_c_project
from hepta.c_resource_matrix import migrate_c_resource_matrix
from tools.qualify_c_resource_matrix import VARIANTS, contracts, make_inputs, qualify


CLANG = os.environ.get("CLANG") or shutil.which("clang")
RUSTC = os.environ.get("RUSTC") or shutil.which("rustc")


@unittest.skipUnless(CLANG and RUSTC, "native Clang and locked Rust required")
class CResourceMatrixTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-c-resource-matrix-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_real_module_cross_unit_contracts_and_actual_abi(self):
        report = qualify(self.root / "qualification", clang=CLANG, rustc=RUSTC, steps=16)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["native_hia_implementations"], 0)
        self.assertEqual(report["native_safe_hepta_rust_variants"], 2)
        self.assertEqual(len(report["negative_contracts"]), 3)
        self.assertEqual(report["migration"]["matrix_capture"]["command_count"], 4)
        for variant in report["variants"]:
            self.assertEqual(len(variant["actual_export_symbols"]), 10)
            self.assertEqual(variant["cross_module_sequences"]["state_transitions"], 96)
            self.assertEqual(len(variant["boundary_controls"]), 5)
        for coverage in report["all_activity_dispositions"]:
            self.assertEqual(coverage["active_project_declarations"], 37)
            self.assertEqual(coverage["status_counts"]["repeated_inline_definition_resolved"], 3)
            self.assertEqual(coverage["status_counts"]["function_converted"], 10)

    def test_one_refused_variant_does_not_disappear_or_erase_other_inventory(self):
        manifest = make_inputs(self.root / "inputs")
        selected = {name: contracts() for name, _, _ in VARIANTS}
        selected["masked"]["functions"]["ring_transfer"]["records"]["buffer"]["access"] = "read"
        original = deepcopy(selected)
        report = migrate_c_resource_matrix(manifest, self.root / "output", contracts_by_variant=selected,
                                           clang=CLANG, rustc=RUSTC)
        self.assertFalse(report["ok"])
        self.assertEqual([v["status"] for v in report["variants"]], ["passed", "rejected"])
        self.assertTrue(report["claims"]["all_active_declarations_have_disposition"])
        self.assertEqual(selected, original)
        self.assertEqual(report["variants"][0]["migration"]["build"]["schema"], "hepta.c-build-selection.v1")
        self.assertEqual(report["variants"][1]["migration"]["build"]["command_indices"], [2, 3])
        self.assertTrue((self.root / "output/matrix-migration.json").is_file())

    def test_existing_output_is_never_modified_even_by_rejection_report(self):
        existing = self.root / "existing"
        existing.mkdir()
        (existing / "keep").write_bytes(b"original")
        report = migrate_c_resource_matrix(self.root / "missing", existing, contracts_by_variant={}, clang=CLANG)
        self.assertFalse(report["ok"])
        self.assertEqual([p.name for p in existing.iterdir()], ["keep"])
        self.assertEqual((existing / "keep").read_bytes(), b"original")

    def test_inline_header_with_different_preprocessing_is_not_coalesced(self):
        header = self.root / "view.h"
        header.write_text("struct View {unsigned char *data; unsigned long n;};\n"
                          "inline unsigned long inspect(struct View *view) {return view->n+BIAS;}\n")
        (self.root / "one.c").write_text('#include "view.h"\nextern inline unsigned long inspect(struct View *view);\n')
        (self.root / "two.c").write_text('#include "view.h"\nunsigned long inspect_twice(struct View *view) {return inspect(view)+inspect(view);}\n')
        commands = [{"directory": str(self.root), "file": unit,
                     "arguments": ["clang", "-std=c11", "-DBIAS=" + str(bias), "-c", unit]}
                    for unit, bias in (("one.c", 1), ("two.c", 2))]
        database = self.root / "compile_commands.json"
        database.write_text(json.dumps(commands))
        selected = {"schema": "hepta.c-record-views.v1", "records": {"View": {"buffers": {"data": {"length_field": "n", "add": 0}}}},
                    "functions": {name: {"records": {"view": {"access": "read"}}, "slices": {}}
                                  for name in ("inspect", "inspect_twice")}}
        result = migrate_c_project(database, self.root / "different", contracts=selected, clang=CLANG)
        self.assertFalse(result["ok"])
        self.assertIn("E_C_FUNCTION", [d["code"] for d in result["diagnostics"]])
        # The same header body can be shared only after the macros agree.
        commands[1]["arguments"][2] = "-DBIAS=1"
        database.write_text(json.dumps(commands))
        same = migrate_c_project(database, self.root / "identical", contracts=selected, clang=CLANG, rustc=RUSTC, verify_native=True)
        self.assertTrue(same["ok"], same["diagnostics"])
        self.assertEqual(same["coverage"]["status_counts"]["repeated_inline_definition_resolved"], 1)

    def test_unused_active_declaration_and_generated_name_collision_refuse(self):
        manifest = make_inputs(self.root / "inputs")
        header = manifest.parent / "source/client.h"
        header.write_text(header.read_text() + "\nunsigned unsupported_global;\n")
        report = migrate_c_resource_matrix(manifest, self.root / "globals", clang=CLANG,
            contracts_by_variant={name: contracts() for name, _, _ in VARIANTS})
        self.assertFalse(report["ok"])
        for row in report["variants"]:
            rejected = [d for d in row["migration"]["declarations"] if d["status"] == "rejected"]
            self.assertTrue(any(d["name"] == "unsupported_global" for d in rejected))
        source = self.root / "collision.c"
        source.write_text("struct View {unsigned char *data; unsigned long n;};\n"
                          "void conflict(struct View *view, unsigned char *view_f_data, unsigned long n) {view_f_data[0]=view->data[0];}\n")
        database = self.root / "collision.json"
        database.write_text(json.dumps([{"directory": str(self.root), "file": source.name,
                                        "arguments": ["clang", "-std=c11", "-c", source.name]}]))
        selected = {"schema": "hepta.c-record-views.v1", "records": {"View": {"buffers": {"data": {"length_field": "n", "add": 0}}}},
                    "functions": {"conflict": {"records": {"view": {"access": "read"}},
                                                "slices": {"view_f_data": {"access": "mut", "length": "n"}}}}}
        result = migrate_c_project(database, self.root / "names", contracts=selected, clang=CLANG)
        self.assertFalse(result["ok"])
        self.assertIn("E_C_VIEW_NAME", [d["code"] for d in result["diagnostics"]])


if __name__ == "__main__":
    unittest.main()
