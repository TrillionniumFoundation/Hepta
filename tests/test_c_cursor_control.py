"""Actual C/native regressions for cursor-loop sequencing and lazy returns."""
import copy
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.c_migrate import migrate_c_project
from hepta.c_project import verify_capture
from tools.qualify_c_musl_compare import FIXTURE, capture_fixture, verify_upstream


class CCursorControlTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-c-cursor-control-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.clang = os.environ.get("CLANG") or shutil.which("clang")
        self.rustc = os.environ.get("RUSTC") or shutil.which("rustc")
        self.assertTrue(self.clang and self.rustc, "Actual Clang and Rust are required")
        self.counter = 0

    def migrate(self, source, contracts=None, native=False):
        self.counter += 1
        work = self.root / str(self.counter)
        work.mkdir()
        (work / "input.c").write_text(source)
        database = work / "compile_commands.json"
        database.write_text(json.dumps([{"directory": str(work), "file": "input.c",
            "arguments": ["clang", "-std=c11", "-O2", "-c", "input.c"]}]))
        report = migrate_c_project(database, work / "translated", contracts=contracts,
            clang=self.clang, rustc=self.rustc, verify_native=native)
        return report, work

    def native_pair(self, source, name, argument_types, result_type, contracts=None):
        report, work = self.migrate(source, contracts, native=True)
        self.assertTrue(report["ok"], report)
        subprocess.run([self.clang, "-std=c11", "-O2", "-fPIC", "-shared",
                        str(work / "input.c"), "-o", str(work / "original.so")],
                       check=True, capture_output=True, timeout=60)
        functions = []
        # Keep the library objects alive along with their function pointers.
        for path in (work / "original.so", work / "translated/libtranslated.so"):
            library = ctypes.CDLL(str(path))
            function = getattr(library, name)
            function.argtypes, function.restype = argument_types, result_type
            functions.append(function)
        return functions

    def test_omitted_init_and_comma_increment_preserve_left_to_right_sequence(self):
        source = ('unsigned probe(unsigned n) { unsigned x=1u; '
                  'for (;n;n--,x=x*10u,x=x+2u) {} return x; }\n')
        native, translated = self.native_pair(source, "probe", [ctypes.c_uint], ctypes.c_uint)
        for n in range(13):
            expected = 1
            for _ in range(n):
                expected = (expected * 10 + 2) % (1 << 32)
            self.assertEqual(native(n), expected)
            self.assertEqual(translated(n), expected)

    def test_conditional_return_is_lazy_and_preserves_common_unsigned_type(self):
        source = 'unsigned probe(unsigned n) { return n ? -1 : 2u; }\n'
        native, translated = self.native_pair(source, "probe", [ctypes.c_uint], ctypes.c_uint)
        for n, expected in ((0, 2), (1, (1 << 32) - 1), (9, (1 << 32) - 1)):
            self.assertEqual(native(n), expected)
            self.assertEqual(translated(n), expected)
        source = ('unsigned probe(unsigned n, const unsigned *data) { '
                  'return n ? (data[0] ? data[0] : 7u) : 3u; }\n')
        contracts = {"schema": "hepta.c-contracts.v1", "functions": {"probe": {
            "slices": {"data": {"access": "read", "length": "n"}}}}}
        native, translated = self.native_pair(source, "probe",
            [ctypes.c_uint, ctypes.POINTER(ctypes.c_uint)], ctypes.c_uint, contracts)
        # An allocated empty-range input is valid for both actual source routes.
        data = (ctypes.c_uint * 1)(0)
        for n, value, expected in ((0, 0, 3), (1, 0, 7), (1, 23, 23)):
            data[0] = value
            self.assertEqual(native(n, data), expected)
            self.assertEqual(translated(n, data), expected)
        # This is the generated bridge's explicit empty-range policy only.
        self.assertEqual(translated(0, None), 3)

    def test_expression_comma_and_missing_loop_parts_still_reject(self):
        cases = [
            ('unsigned probe(unsigned x) { return (x++, x); }', "E_C_UNARY"),
            ('unsigned probe(unsigned x) { for (;;x--) {} return x; }', "E_C_FOR"),
            ('unsigned probe(unsigned x) { for (;x;) {x--;} return x; }', "E_C_FOR"),
            ('unsigned probe(unsigned x) { return x++ ? 1u : 2u; }', "E_C_UNARY"),
            ('unsigned probe(unsigned x) { unsigned y=x ? 1u : 2u; return y; }', "E_C_EXPRESSION"),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                report, work = self.migrate(source)
                self.assertFalse(report["ok"], report)
                self.assertFalse((work / "translated").exists())
                self.assertIn(expected, [d["code"] for d in report["diagnostics"]])

    def test_real_component_has_complete_inventory_and_no_record_fabrication(self):
        metadata = verify_upstream()
        self.assertEqual(sum(row["bytes"] for row in metadata["files"] if row["local_path"].endswith(".c")), 319)
        work = self.root / "musl"
        database = capture_fixture(work)
        report = migrate_c_project(database, work / "translated",
            contracts=json.loads((FIXTURE / "contracts.json").read_text()),
            clang=self.clang, rustc=self.rustc, verify_native=True)
        self.assertTrue(report["ok"], report)
        self.assertTrue(report["declaration_inventory_complete"])
        self.assertEqual(report["coverage"]["status_counts"], {"function_converted": 2, "prototype_resolved": 3})
        self.assertEqual(report["record_views"]["records"], {})
        self.assertEqual(report["cost"]["caller_slice_contracts"], 4)
        for config in report["build"]["configurations"]:
            self.assertIn("-fno-builtin", config["frontend_arguments"])
            self.assertIn("-fno-builtin", config["abi_model_arguments"])
        verify_capture(report["build"])
        source = (work / "translated/source.hepta").read_text()
        self.assertNotIn("raw ", source)
        self.assertNotIn("struct ", source)
        self.assertIn("return c_memcmp(read p_s1", source)

    def test_cursor_only_contracts_do_not_admit_missing_or_invented_records(self):
        base = {"schema": "hepta.c-record-views.v1", "records": {}, "functions": {
            "probe": {"records": {}, "slices": {"data": {"access": "read", "length": "n"}}}}}
        for altered in ("missing_slice", "invented_record"):
            contract = copy.deepcopy(base)
            if altered == "missing_slice":
                contract["functions"]["probe"]["slices"] = {}
            else:
                contract["functions"]["probe"]["records"] = {"data": {"access": "read"}}
            report, work = self.migrate('unsigned probe(const unsigned *data, unsigned n) { return n; }', contract)
            self.assertFalse(report["ok"], report)
            self.assertFalse((work / "translated").exists())
            self.assertIn("E_C_VIEW_CONTRACT", [d["code"] for d in report["diagnostics"]])


if __name__ == "__main__":
    unittest.main()
