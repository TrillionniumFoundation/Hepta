"""C and C++ matrix qualification have separate executed denominators."""
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.clang_capture import run_bounded
from hepta.c_migrate import MigrationRejected
from hepta.c_scalar_matrix import lower_c_project_matrix
from hepta.hia_program_llvm import build_program_native
from hepta.object_symbols import inspect_object_symbols
from tools.qualify_c_project_matrix import (make_c_inputs, qualify_c_matrix,
                                            validate_c_matrix_receipt)

CLANG = os.environ.get("CLANG") or shutil.which("clang")


@unittest.skipUnless(CLANG, "Actual Clang toolchain required")
class CScalarMatrixTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-c-matrix-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_real_two_by_two_c_native_keeps_c_symbols_without_original_implementation(self):
        report = qualify_c_matrix(self.root / "run", clang=CLANG)
        self.assertTrue(report["ok"], report.get("diagnostic"))
        self.assertEqual(report["native_result_executions"], 816)
        self.assertEqual(report["interpreter_results"], 408)
        self.assertEqual(report["matrix_capture"]["command_count"], 4)
        self.assertEqual(report["matrix_capture"]["language"], "c")
        self.assertEqual([row["command_indices"] for row in report["variants"]], [[0, 1], [2, 3]])
        self.assertEqual(len(report["negative_controls"]), 5)
        self.assertFalse(report["claims"]["resource_contracts_qualified"])
        self.assertTrue(report["claims"]["original_c_defined_symbols_match_hia"])
        for row in report["variants"]:
            self.assertEqual(row["original_defined_symbols"], ["matrix_cross", "matrix_wide", "matrix_word"])
            self.assertEqual(row["original_defined_symbols"], row["native_build"]["exports"])
            self.assertEqual(len(row["original_object_symbols"]), 2)
        forged = deepcopy(report)
        row = forged["variants"][0]
        row["target_link_argv"].append(str(self.root / "run/small/original-0.o"))
        row["processes"][row["target_link_process"]]["argv"] = row["target_link_argv"][:]
        with self.assertRaisesRegex(ValueError, "only directly generated HIA"):
            validate_c_matrix_receipt(forged)
        forged = deepcopy(report)
        forged["claims"]["resource_contracts_qualified"] = True
        with self.assertRaisesRegex(ValueError, "scope or claims"):
            validate_c_matrix_receipt(forged)
        forged = deepcopy(report)
        forged["variants"][0]["original_defined_symbols"].append("invented_inline_export")
        with self.assertRaisesRegex(ValueError, "Original C defined symbols"):
            validate_c_matrix_receipt(forged)

    def test_unmodeled_c_record_is_rejected_instead_of_silently_discarded(self):
        manifest = make_c_inputs(self.root)
        header = self.root / "source/model.h"
        header.write_text(header.read_text() + "\nstruct UnusedRecord { unsigned field; };\n")
        with self.assertRaises(MigrationRejected) as caught:
            lower_c_project_matrix(manifest, clang=CLANG)
        self.assertEqual(caught.exception.code, "E_C_MATRIX_PROFILE")

    def test_c_static_helper_stays_private_in_each_hia_variant(self):
        manifest = make_c_inputs(self.root)
        source = self.root / "source/word.c"
        source.write_text(source.read_text() + "\nstatic unsigned hidden_step(unsigned x) {return x+1u;}\n")
        migration = lower_c_project_matrix(manifest, clang=CLANG)
        for variant in migration["variants"]:
            hidden = next(fn["hepta_name"] for fn in variant["functions"] if fn["name"] == "hidden_step")
            self.assertNotIn(hidden, variant["program"].scalar_entrypoints)
            self.assertTrue(any(fn["name"] == hidden for fn in variant["program"].as_dict()["functions"]))

    def small_c_project(self, name, sources, standard="c17"):
        directory = self.root / name
        directory.mkdir()
        commands = []
        for filename, source in sources.items():
            (directory / filename).write_text(source)
            commands.append({"directory": str(directory), "file": filename,
                             "arguments": ["clang", "-std=" + standard, "-c", filename,
                                           "-o", filename + ".o"]})
        (directory / "compile_commands.json").write_text(json.dumps(commands))
        manifest = directory / "matrix.json"
        manifest.write_text(json.dumps({"schema": "hepta.build-matrix.v1", "language": "c",
                                        "database": "compile_commands.json",
                                        "variants": [{"name": "only", "command_indices": list(range(len(commands)))}]}))
        return manifest

    def compile_symbols(self, source, standard="c17"):
        obj = source.with_suffix(".o")
        process = run_bounded([CLANG, "-std=" + standard, "-O0", "-fPIC", "-c", str(source), "-o", str(obj)],
                              timeout=30, stdout_limit=65536, stderr_limit=65536)
        self.assertEqual(process.returncode, 0, process.stderr)
        return inspect_object_symbols(obj.read_bytes(), "ELF64", 62)

    def test_plain_inline_has_no_external_definition_and_is_rejected_in_all_c_standards(self):
        source = ("inline unsigned helper(unsigned x) { return x + 1u; }\n"
                  "unsigned entry(unsigned x) { return helper(x); }\n")
        for standard in ("c99", "c11", "c17"):
            with self.subTest(standard=standard):
                manifest = self.small_c_project(standard, {"module.c": source}, standard)
                symbols = self.compile_symbols(manifest.parent / "module.c", standard)
                # The original has an unresolved reference, not a definition.
                # Silently exporting helper from HIA changes the native ABI.
                self.assertEqual(symbols["defined"], {"entry"})
                self.assertEqual(symbols["undefined"], {"helper"})
                with self.assertRaises(MigrationRejected) as caught:
                    lower_c_project_matrix(manifest, clang=CLANG)
                self.assertEqual(caught.exception.code, "E_C_MATRIX_INLINE")

    def test_every_inline_redeclaration_is_checked_before_prototype_merging(self):
        bodies = {
            "before": "inline unsigned helper(unsigned x);\nunsigned helper(unsigned x) { return x + 1u; }\n",
            "after": "unsigned helper(unsigned x) { return x + 1u; }\ninline unsigned helper(unsigned x);\n",
            "extern": "extern inline unsigned helper(unsigned x) { return x + 1u; }\n",
        }
        for name, body in bodies.items():
            with self.subTest(declaration=name):
                manifest = self.small_c_project(name, {"module.c": body + "unsigned entry(unsigned x) { return helper(x); }\n"})
                self.compile_symbols(manifest.parent / "module.c")
                with self.assertRaises(MigrationRejected) as caught:
                    lower_c_project_matrix(manifest, clang=CLANG)
                self.assertEqual(caught.exception.code, "E_C_MATRIX_INLINE")
        # A separately captured prototype must not disappear behind a body
        # selected from another translation unit either.
        manifest = self.small_c_project("cross_unit", {
            "body.c": "unsigned helper(unsigned x) { return x + 1u; }\n",
            "decl.c": "inline unsigned helper(unsigned x);\nunsigned entry(unsigned x) { return x; }\n",
        })
        with self.assertRaises(MigrationRejected) as caught:
            lower_c_project_matrix(manifest, clang=CLANG)
        self.assertEqual(caught.exception.code, "E_C_MATRIX_INLINE")

    def test_explicit_static_inline_retains_actual_original_defined_symbol_inventory(self):
        manifest = self.small_c_project("static_inline", {"module.c":
            "static inline unsigned helper(unsigned x) { return x + 1u; }\n"
            "unsigned entry(unsigned x) { return helper(x); }\n"})
        original = self.compile_symbols(manifest.parent / "module.c")
        self.assertEqual(original["defined"], {"entry"})
        self.assertEqual(original["undefined"], set())
        program = lower_c_project_matrix(manifest, clang=CLANG)["variants"][0]["program"]
        output = manifest.parent / "hia.o"
        build_program_native(program, output, clang=CLANG, kind="object")
        generated = inspect_object_symbols(output.read_bytes(), "ELF64", 62)
        self.assertEqual(generated["defined"], original["defined"])
        self.assertEqual(program.scalar_entrypoints, original["defined"])


if __name__ == "__main__":
    unittest.main()
