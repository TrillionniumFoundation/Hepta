"""Real source/AST/native controls for erased C parameter-entry effects."""
from __future__ import annotations

import copy
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.c_migrate import MigrationRejected, migrate_c_project
from hepta.c_translation import reject_adjusted_pointer_parameter


class CParameterEntryEffectsTests(unittest.TestCase):
    def setUp(self):
        self.clang = shutil.which("clang")
        self.assertIsNotNone(self.clang, "Real Clang is required for parameter-source admission")
        temp = tempfile.TemporaryDirectory(prefix="hepta-parameter-entry-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.index = 0

    def capture_parameter(self, text):
        source = self.root / "parameter.c"
        source.write_text(text, encoding="utf-8")
        process = subprocess.run([self.clang, "-std=c11", "-fsyntax-only", "-Xclang",
                                  "-ast-dump=json", str(source)],
                                 check=True, capture_output=True, text=True, timeout=30)
        ast = json.loads(process.stdout)
        function = next(node for node in ast["inner"] if node.get("name") == "probe")
        parameter = [node for node in function["inner"] if node.get("kind") == "ParmVarDecl"][-1]
        return parameter, source.read_bytes()

    def migrate(self, source, *, records=False, header=None, native=False):
        self.index += 1
        work = self.root / str(self.index)
        work.mkdir()
        (work / "input.c").write_text(source, encoding="utf-8")
        if header is not None:
            (work / "api.h").write_text(header, encoding="utf-8")
        database = work / "compile_commands.json"
        database.write_text(json.dumps([{"directory": str(work), "file": "input.c",
            "arguments": [self.clang, "-std=c11", "-O0", "-c", "input.c", "-o", "input.o"]}]))
        if records:
            contracts = {"schema": "hepta.c-record-views.v1",
                "records": {"State": {"buffers": {"data": {"length_field": "n", "add": 0}}}},
                "functions": {"probe": {"records": {"ctx": {"access": "read"}}, "slices": {}}}}
        else:
            contracts = {"schema": "hepta.c-contracts.v1", "functions": {
                "probe": {"slices": {"data": {"length": "n", "access": "read"}}}}}
        report = migrate_c_project(database, work / "translated", contracts=contracts,
                                   clang=self.clang, verify_native=native, rustc=os.environ.get("RUSTC"))
        return report, work

    def assert_declarator_refused(self, report, work):
        self.assertFalse(report["ok"], report)
        self.assertFalse((work / "translated").exists())
        self.assertTrue(report["declaration_inventory_complete"])
        self.assertIn("E_C_PARAMETER_DECLARATOR", [row["code"] for row in report["diagnostics"]])
        rejected = [row for row in report["declarations"] if row["status"] == "rejected"]
        self.assertEqual([(row["name"], row["reason"]) for row in rejected],
                         [("probe", "E_C_PARAMETER_DECLARATOR")])

    def test_typeof_array_has_plain_pointer_type_and_identifier_end_but_refuses(self):
        source = "unsigned int probe(unsigned int n, const __typeof__(unsigned int[++n]) data) { return n; }"
        parameter, raw = self.capture_parameter(source)
        self.assertEqual(parameter["type"]["qualType"], "const unsigned int *")
        self.assertEqual(parameter["loc"]["offset"], parameter["range"]["end"]["offset"])
        with self.assertRaises(MigrationRejected) as error:
            reject_adjusted_pointer_parameter(parameter, raw)
        self.assertEqual(error.exception.code, "E_C_PARAMETER_DECLARATOR")
        report, work = self.migrate(source)
        self.assert_declarator_refused(report, work)
        for optimization in ("-O0", "-O2"):
            library = work / (optimization[1:] + ".so")
            subprocess.run([self.clang, "-std=c11", optimization, "-shared", "-fPIC",
                            str(work / "input.c"), "-o", str(library)],
                           check=True, capture_output=True, text=True, timeout=30)
            function = ctypes.CDLL(str(library)).probe
            function.argtypes, function.restype = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)], ctypes.c_uint32
            data = (ctypes.c_uint32 * 16)()
            self.assertEqual([function(n, data) for n in (1, 3, 7, 12)], [2, 4, 8, 13])

    def test_record_view_adapter_cannot_erase_array_or_typeof_source_contract(self):
        prefix = "struct State { unsigned char *data; unsigned int n; };\n"
        for parameter in ("const struct State ctx[++n]", "const __typeof__(struct State[++n]) ctx"):
            with self.subTest(parameter=parameter):
                report, work = self.migrate(prefix + "unsigned int probe(unsigned int n, " + parameter + ") { return n; }", records=True)
                self.assert_declarator_refused(report, work)
        report, work = self.migrate(prefix + "unsigned int probe(unsigned int n, const struct State *ctx) { return n; }", records=True, native=True)
        self.assertTrue(report["ok"], report)
        class State(ctypes.Structure):
            _fields_ = [("data", ctypes.POINTER(ctypes.c_uint8)), ("n", ctypes.c_uint32)]
        function = ctypes.CDLL(str(work / "translated/libtranslated.so")).probe
        function.argtypes, function.restype = [ctypes.c_uint32, ctypes.POINTER(State)], ctypes.c_uint32
        state = State()
        self.assertEqual([function(n, ctypes.byref(state)) for n in (0, 1, 7)], [0, 1, 7])

    def test_header_prototype_is_checked_against_its_own_captured_bytes(self):
        source = '#include "api.h"\nunsigned int probe(unsigned int n, const unsigned int *data) { return n; }\n'
        report, work = self.migrate(source, header="unsigned int probe(unsigned int n, const unsigned int data[n]);\n")
        self.assert_declarator_refused(report, work)
        rejected = next(row for row in report["declarations"] if row["status"] == "rejected")
        self.assertEqual(rejected["file"], str(work / "api.h"))
        report, _ = self.migrate(source, header="unsigned int probe(unsigned int n, const unsigned int *data);\n")
        self.assertTrue(report["ok"], report)

    def test_plain_pointer_comments_splices_and_scalar_alias_keep_admission(self):
        for parameter in ("const unsigned int *data", "const unsigned int /* array[++n] */ *data",
                          "const unsigned int * /* [++n] */ data", "const unsigned int * // [++n]\n data",
                          "const unsigned \\\nint *data", "const Word *data"):
            with self.subTest(parameter=parameter):
                source = "typedef unsigned int Word;\nunsigned int probe(unsigned int n, " + parameter + ") { return n; }\n"
                node, raw = self.capture_parameter(source)
                reject_adjusted_pointer_parameter(node, raw)
                report, _ = self.migrate(source)
                self.assertTrue(report["ok"], report)

    def test_macro_computed_type_and_pointer_token_are_not_assumed_plain(self):
        for definition, parameter in (("#define TYPE __typeof__(unsigned int[++n])", "const TYPE data"),
                                      ("#define POINTER *", "const unsigned int POINTER data")):
            with self.subTest(definition=definition):
                source = definition + "\nunsigned int probe(unsigned int n, " + parameter + ") { return n; }\n"
                report, work = self.migrate(source)
                self.assert_declarator_refused(report, work)

    def test_source_spelling_offsets_and_names_are_not_trusted(self):
        node, raw = self.capture_parameter("unsigned int probe(unsigned int n, const unsigned int *data) { return n; }")
        for mutate in (lambda v: v["range"]["begin"].update(offset=True),
                       lambda v: v["range"]["begin"].update(offset=-1),
                       lambda v: v["loc"].update(tokLen=10000),
                       lambda v: v.update(name="other"),
                       lambda v: v["range"]["begin"].update(spellingLoc={"offset": 0})):
            altered = copy.deepcopy(node)
            mutate(altered)
            with self.subTest(altered=altered):
                with self.assertRaises(MigrationRejected) as error:
                    reject_adjusted_pointer_parameter(altered, raw)
                self.assertEqual(error.exception.code, "E_C_PARAMETER_DECLARATOR")
        with self.assertRaises(MigrationRejected):
            reject_adjusted_pointer_parameter(node, raw.replace(b"data", b"fake"))


if __name__ == "__main__":
    unittest.main()
