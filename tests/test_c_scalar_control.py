"""Actual source/compiler checks for deferred locals and lazy scalar values."""
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.c_migrate import migrate_c_project


class CScalarControlTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-scalar-control-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.clang = os.environ.get("CLANG") or shutil.which("clang")
        self.rustc = os.environ.get("RUSTC") or shutil.which("rustc")
        self.assertTrue(self.clang and self.rustc, "Actual Clang and pinned Rust are required")
        self.sequence = 0

    def migrate(self, source, *, native=False):
        self.sequence += 1
        work = self.root / str(self.sequence)
        work.mkdir()
        (work / "input.c").write_text(source)
        database = work / "compile_commands.json"
        database.write_text(json.dumps([{"directory": str(work), "file": "input.c",
            "arguments": ["clang", "-std=c11", "-O2", "-c", "input.c"]}]))
        result = migrate_c_project(database, work / "translated", clang=self.clang,
                                   rustc=self.rustc, verify_native=native)
        return result, work

    def compare(self, source, cases, *, unsigned=False):
        report, work = self.migrate(source, native=True)
        self.assertTrue(report["ok"], report)
        subprocess.run([self.clang, "-std=c11", "-O2", "-shared", "-fPIC",
                        str(work / "input.c"), "-o", str(work / "original.so")],
                       capture_output=True, check=True, timeout=60)
        outputs = [ctypes.CDLL(str(path)) for path in
                   (work / "original.so", work / "translated/libtranslated.so")]
        for library in outputs:
            function = library.probe
            function.argtypes = [ctypes.c_int32, ctypes.c_int32]
            function.restype = ctypes.c_uint32 if unsigned else ctypes.c_int32
            for args, expected in cases:
                self.assertEqual(function(*args), expected, (args, expected))
        return report

    def test_deferred_local_merges_only_reachable_branches(self):
        report = self.compare('int probe(int c,int a){int x; if(c){x=a;}else{return 7;}return x;}',
                              [((0, -8), 7), ((1, -8), -8), ((-1, 123), 123)])
        self.assertEqual(report["functions"][0]["definite_assignment"]["deferred_scalar_initializers"], 1)

    def test_branch_assignments_and_comma_sequence_keep_original_reads(self):
        self.compare('int probe(int c,int a){int x,y;if(c){x=a,y=x+1;}else{x=3,y=x+2;}return y;}',
                     [((0, 900), 5), ((1, 100), 101), ((-7, -100), -99)])

    def test_nested_conditional_values_do_not_execute_unused_division(self):
        self.compare('int probe(int c,int a){int x=1+(c ? (a ? 24/a : 9) : 7);return x;}',
                     [((0, 0), 8), ((1, 0), 10), ((1, 3), 9), ((-1, -3), -7)])

    def test_unused_negation_of_int_min_is_not_evaluated(self):
        self.compare('int probe(int c,int a){return 2+(a==(-2147483647-1) ? 1 : -a);}',
                     [((0, -(1 << 31)), 3), ((0, -5), 7), ((0, 5), -3)])

    def test_conditional_common_unsigned_conversion_is_retained(self):
        self.compare('unsigned probe(int c,int a){unsigned x=c ? -1 : 2u;return x;}',
                     [((0, 0), 2), ((1, 0), (1 << 32) - 1)], unsigned=True)

    def test_missing_branch_loop_and_compound_initialization_reject(self):
        sources = [
            'int probe(int c,int a){int x;if(c)x=a;return x;}',
            'int probe(int c,int a){int x;while(c){x=a;c=0;}return x;}',
            'int probe(int c,int a){int x;x+=a;return x;}',
            'int probe(int c,int a){int x;while(x){x=a;}return 0;}',
            'int probe(int c,int a){int x;int y=x;x=a;return y;}',
            'int probe(int c,int a){int x;if(c){x=a;}else{x=x+1;}return x;}',
        ]
        for source in sources:
            with self.subTest(source=source):
                report, work = self.migrate(source)
                self.assertFalse(report["ok"], report)
                self.assertIn("E_C_UNINITIALIZED", [item["code"] for item in report["diagnostics"]])
                self.assertFalse((work / "translated").exists())

    def test_unknown_control_does_not_escape_initialization_check(self):
        report, work = self.migrate('int probe(int c,int a){int x;goto end;x=a;end:return x;}')
        self.assertFalse(report["ok"], report)
        self.assertIn("E_C_UNINITIALIZED_CONTROL", [item["code"] for item in report["diagnostics"]])
        self.assertFalse((work / "translated").exists())

    def test_mutating_scalar_conditional_still_rejects(self):
        for source in ('int probe(int c,int a){return 1+(c?a++:a);}',
                       'int probe(int c,int a){int x=c++?a:1;return x;}'):
            report, work = self.migrate(source)
            self.assertFalse(report["ok"], report)
            self.assertFalse((work / "translated").exists())

    def test_extra_unsupported_declaration_rejects_entire_bundle(self):
        report, work = self.migrate('int probe(int c,int a){return c?1:a;} int unsupported_global;')
        self.assertFalse(report["ok"], report)
        self.assertTrue(report["declaration_inventory_complete"])
        self.assertEqual(report["coverage"]["active_project_declarations"], 2)
        self.assertFalse((work / "translated").exists())


if __name__ == "__main__":
    unittest.main()
