"""Original parameter types must not lose VLA evaluation during migration."""
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.c_migrate import migrate_c_project
from hepta.clang_capture import CaptureResult, run_bounded


class OriginalParameterTypeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-original-parameter-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.clang = shutil.which("clang")
        self.assertIsNotNone(self.clang, "Clang is required for original parameter type admission")
        self.contracts = {"schema": "hepta.c-contracts.v1", "functions": {
            "probe": {"slices": {"data": {"length": "n", "access": "read"}}}}}

    def project(self, source, name="input.c"):
        (self.root / name).write_text(source)
        database = self.root / "compile_commands.json"
        database.write_text(json.dumps([{"directory": str(self.root), "file": name,
            "arguments": ["clang", "-std=c11", "-O0", "-c", name, "-o", "input.o"]}]))
        return database

    def migrate(self, database, output, **kwargs):
        return migrate_c_project(database, output, contracts=self.contracts,
                                 clang=self.clang, rustc=os.environ.get("RUSTC"), **kwargs)

    def original_result(self, name, *, flags=()):
        artifact = self.root / (name + ".so")
        command = [self.clang, "-std=c11", "-O0", *flags,
                   "-shared", "-fPIC", "input.c", "-o", str(artifact)]
        compiled = subprocess.run(command, cwd=self.root, capture_output=True, text=True, timeout=60)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        return self.call(artifact)

    def call(self, artifact):
        library = ctypes.CDLL(str(artifact))
        library.probe.argtypes = [ctypes.c_uint, ctypes.POINTER(ctypes.c_uint)]
        library.probe.restype = ctypes.c_uint
        data = (ctypes.c_uint * 8)(*range(8))
        return int(library.probe(7, data))

    def test_vla_entry_effects_reject_including_pragma_macro_and_typeof(self):
        sources = (
            ("plain", "", "const unsigned int data[++n]", ()),
            ("pragma", '#pragma clang diagnostic ignored "-Wvla"\n',
             "const unsigned int data[++n]", ("-Werror=vla",)),
            ("macro", "#define EXTENT (++n)\n", "const unsigned int data[EXTENT]", ()),
            ("typeof", "", "__typeof__(const unsigned int[++n]) data", ()),
        )
        for name, prefix, parameter, flags in sources:
            with self.subTest(form=name):
                database = self.project(prefix + "unsigned int probe(unsigned int n, "
                                        + parameter + ") { return n; }\n")
                self.assertEqual(self.original_result(name, flags=flags), 8)
                output = self.root / (name + "-converted")
                report = self.migrate(database, output)
                self.assertFalse(report["ok"], report)
                self.assertFalse(output.exists())
                self.assertIn("E_C_VLA_PARAMETER", [x["code"] for x in report["diagnostics"]], report)
                receipt = report["source_type_admission"][0]
                self.assertEqual(receipt["capture_sha256"], report["build"]["sha256"])
                self.assertEqual(receipt["functions"][0]["parameters"][1]["state"], "variable")
                self.assertEqual(receipt["reader"]["version"], report["build"]["compiler"]["version"])

    def test_fixed_array_and_pointer_parameters_preserve_native_results(self):
        for index, parameter in enumerate(("const unsigned int *data",
                                           "const unsigned int data[8]",
                                           "const unsigned int data[]")):
            with self.subTest(parameter=parameter):
                database = self.project("unsigned int probe(unsigned int n, "
                                        + parameter + ") { return n + data[0]; }\n")
                original = self.original_result("fixed-" + str(index))
                output = self.root / ("fixed-" + str(index))
                report = self.migrate(database, output, verify_native=True)
                self.assertTrue(report["ok"], report)
                self.assertEqual(original, 7)
                self.assertEqual(self.call(output / "libtranslated.so"), original)
                receipt = report["source_type_admission"][0]
                self.assertEqual(receipt["cwd"], str(self.root))
                self.assertIn("input.c", receipt["argv"])
                self.assertEqual(receipt["functions"][0]["parameters"][1]["state"], "fixed")
                self.assertRegex(receipt["reader"]["sha256"], r"^[a-f0-9]{64}$")
                self.assertRegex(receipt["serialized_ast"]["sha256"], r"^[a-f0-9]{64}$")

    def test_record_view_rewrite_cannot_hide_original_vla_parameter(self):
        database = self.project(
            "struct State { unsigned int *data; unsigned int length; };\n"
            "unsigned int probe(unsigned int n, const struct State ctx[++n]) { return n; }\n")
        contracts = {"schema": "hepta.c-record-views.v1",
            "records": {"State": {"buffers": {"data": {"length_field": "length", "add": 0}}}},
            "functions": {"probe": {"slices": {}, "records": {"ctx": {"access": "read"}}}}}
        output = self.root / "record-vla"
        report = migrate_c_project(database, output, contracts=contracts, clang=self.clang)
        self.assertFalse(report["ok"], report)
        self.assertFalse(output.exists())
        self.assertIn("E_C_VLA_PARAMETER", [x["code"] for x in report["diagnostics"]], report)
        self.assertEqual(report["source_type_admission"][0]["functions"][0]
                         ["parameters"][1]["state"], "variable")

    def test_probe_preserves_lexical_source_operand_and_header_binding(self):
        (self.root / "extent.h").write_text("#define EXTENT 8\n")
        source = ('#include "extent.h"\n'
                  'unsigned int probe(unsigned int n, const unsigned int data[EXTENT]) {\n'
                  '#if __has_include(__FILE__)\nreturn n + data[0];\n'
                  '#else\nreturn n + 2u;\n#endif\n}\n')
        self.project(source, "source.c")
        (self.root / "alias.c").symlink_to("source.c")
        database = self.root / "compile_commands.json"
        database.write_text(json.dumps([{"directory": str(self.root), "file": "alias.c",
            "arguments": ["clang", "-std=c11", "-O0", "-c", "alias.c", "-o", "input.o"]}]))
        report = self.migrate(database, self.root / "alias-converted", verify_native=True)
        self.assertTrue(report["ok"], report)
        receipt = report["source_type_admission"][0]
        self.assertEqual(receipt["argv"][-3], "alias.c")
        self.assertEqual(receipt["cwd"], str(self.root))
        self.assertEqual(self.call(self.root / "alias-converted/libtranslated.so"), 7)
        self.assertEqual(receipt["functions"][0]["declaration"]["file"], str(self.root / "source.c"))

    def test_changed_dependency_after_probe_rejects_without_publication(self):
        header = self.root / "extent.h"
        header.write_text("#define EXTENT 8\n")
        database = self.project('#include "extent.h"\n'
            'unsigned int probe(unsigned int n, const unsigned int data[EXTENT]) { return n; }\n')

        def changed(argv, **kwargs):
            result = run_bounded(argv, **kwargs)
            if argv[-1] == "--worker":
                header.write_text("#define EXTENT 9\n")
            return result

        output = self.root / "changed"
        with patch("hepta.clang_capture.run_bounded", side_effect=changed):
            report = self.migrate(database, output)
        self.assertFalse(report["ok"], report)
        self.assertFalse(output.exists())
        self.assertIn("E_C_BUILD_CHANGED", [x["code"] for x in report["diagnostics"]], report)

    def test_incomplete_or_mismatched_probe_receipt_rejects(self):
        database = self.project("unsigned int probe(unsigned int n, const unsigned int *data) { return n; }\n")
        for mutation in ("missing", "duplicate", "command", "unknown_type"):
            with self.subTest(mutation=mutation):
                def altered(argv, **kwargs):
                    result = run_bounded(argv, **kwargs)
                    if argv[-1] != "--worker" or result.returncode:
                        return result
                    value = json.loads(result.stdout)
                    if mutation == "missing":
                        value["functions"] = []
                    elif mutation == "duplicate":
                        value["functions"] *= 2
                    elif mutation == "command":
                        value["argv"][-3] = str(self.root / "input.c")
                    else:
                        value["functions"][0]["parameters"][1]["state"] = "unmodeled"
                    return CaptureResult(result.returncode, json.dumps(value), result.stderr)

                output = self.root / ("forged-" + mutation)
                with patch("hepta.clang_capture.run_bounded", side_effect=altered):
                    report = self.migrate(database, output)
                self.assertFalse(report["ok"], report)
                self.assertFalse(output.exists())
                self.assertIn("E_C_ORIGINAL_TYPE", [x["code"] for x in report["diagnostics"]], report)


if __name__ == "__main__":
    unittest.main()
