"""C++20 L1 strictly reuses the C scalar lowering authority."""
from __future__ import annotations

import ctypes
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.cpp2hepta import migrate_cpp
from hepta.pipeline import analyze


@unittest.skipUnless(shutil.which("clang++"), "Clang++ is required for exact C++ AST")
class CppStrictL1Tests(unittest.TestCase):
    _GOOD = """
int add(int a, int b) noexcept { return a + b; }
int clamp(int x) noexcept {
    if (x < 0) { return 0; }
    return x;
}
"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.src = self.root / "project.cc"
        self.dst = self.root / "migrated.hepta"

    def test_strict_cpp_ast_reuses_c_expression_lowering(self):
        self.src.write_text(self._GOOD)
        report = migrate_cpp(self.src, self.dst)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["tier"], "L1")
        self.assertFalse(report["cpp_abi_preserved"])
        self.assertFalse(report["behavioral_equivalence_proved"])
        self.assertEqual(report["native_validation"], "not_run")
        source = self.dst.read_text()
        self.assertIn('export "C" fn add(', source)
        self.assertIn('export "C" fn clamp(', source)
        self.assertEqual(analyze(source, str(self.dst), native=False).report["status"], "frontend_only")
        first_hash = report["output_sha256"]
        self.dst.unlink()
        self.assertEqual(first_hash, migrate_cpp(self.src, self.dst)["output_sha256"])

    def test_complete_active_toplevel_declaration_inventory(self):
        self.src.write_text(self._GOOD)
        accepted = migrate_cpp(self.src, self.dst)
        self.assertTrue(accepted["ok"], accepted)
        self.assertTrue(accepted["top_level_inventory_complete"])
        self.assertEqual(accepted["top_level_declaration_count"], 2)
        self.assertEqual(accepted["top_level_L1_candidates"], 2)
        self.assertEqual(accepted["top_level_unsupported"], 0)
        self.assertEqual([e["status"] for e in accepted["top_level_declarations"]],
                         ["L1_ast_candidate", "L1_ast_candidate"])
        self.dst.unlink()
        self.src.write_text("struct Unconverted { int value; };\n" + self._GOOD)
        rejected = migrate_cpp(self.src, self.dst)
        self.assertFalse(rejected["ok"], rejected)
        self.assertTrue(rejected["top_level_inventory_complete"])
        self.assertEqual(rejected["top_level_declaration_count"], 3)
        self.assertEqual(rejected["top_level_L1_candidates"], 2)
        self.assertEqual(rejected["top_level_unsupported"], 1)
        self.assertEqual(rejected["converted"], [])
        self.assertFalse(self.dst.exists())
        self.assertEqual(rejected["top_level_declarations"][0]["kind"], "CXXRecordDecl")
        self.assertEqual(rejected["top_level_declarations"][0]["status"], "unsupported")

    def test_source_ranged_toplevel_without_location_is_not_silently_ignored(self):
        from unittest.mock import patch
        from hepta import cpp2hepta
        self.src.write_text(self._GOOD)
        original_run = cpp2hepta._run
        def corrupt_one_clang_decl(argv, **kwargs):
            content = original_run(argv, **kwargs)
            if "-ast-dump=json" in argv:
                ast = json.loads(content)
                for node in ast["inner"]:
                    loc = node.get("loc", {})
                    if node.get("kind") == "FunctionDecl" and isinstance(loc.get("offset"), int):
                        loc.pop("offset")
                        break
                else:
                    self.fail("Clang AST fixture has no source-located function")
                return json.dumps(ast)
            return content
        with patch.object(cpp2hepta, "_run", side_effect=corrupt_one_clang_decl):
            report = migrate_cpp(self.src, self.dst)
        self.assertFalse(report["ok"])
        self.assertFalse(report["top_level_inventory_complete"])
        self.assertEqual(report["converted"], [])
        self.assertFalse(self.dst.exists())
        self.assertEqual(report["rejected"][0]["code"], "E_CPP2HEPTA_LOCATION")

    def test_unsafe_cpp_constructs_never_partially_publish(self):
        negative = [
            'class Foo { public: int x; }; int f(int a) noexcept {return a;}',
            'int *f(int *p) noexcept {return p;}',
            'int f(int a) {return a;}',
            'int f(int a) noexcept {return a;} int f(int a,int b) noexcept {return a+b;}',
            'int f(int a=1) noexcept {return a;}',
            '#define FLAG 1\nint f(int a) noexcept {return a+FLAG;}',
            'int shared=4; int f(int a) noexcept{return a+shared;}',
            'template<typename T> T f(T x) noexcept {return x;}',
            'int f(int a) noexcept { return a; } int g(int a) noexcept { int x; return a; }',
            'int f(int a) noexcept { int x = a; int x = 1; return x; }',
            'int f(int a) noexcept { if (a > 0) { int y = a; return y; } return a; }',
            'int f(int a) noexcept { int x = a; x += 1; return x; }',
            'int f(int a) noexcept { static int x = 0; x = x + a; return x; }',
            'int f(int a) noexcept { static thread_local int x = 0; x = x + a; return x; }',
        ]
        for text in negative:
            with self.subTest(text=text):
                self.src.write_text(text)
                result = migrate_cpp(self.src, self.dst)
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["converted"], [])
                self.assertFalse(self.dst.exists())
        self.assertTrue(len(negative) >= 9)

    def test_checked_stateful_locals_and_while_translate(self):
        self.src.write_text("""
int sum_to(int n) noexcept {
    int total = 0;
    int i = 0;
    while (i < n) { total = total + i; i = i + 1; }
    return total;
}
int clamp_local(int x) noexcept {
    int y = x;
    if (y < 0) { y = 0; }
    return y;
}
""")
        report = migrate_cpp(self.src, self.dst)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["tier"], "L1")
        self.assertFalse(report["behavioral_equivalence_proved"])
        self.assertEqual(report["native_validation"], "not_run")
        generated = self.dst.read_text()
        self.assertIn("let mut total: i32 = 0;", generated)
        self.assertIn("resources {heap_allocations=0;may_block=false;", generated)
        self.assertIn("may_suspend=false;may_spawn=false;}", generated)
        self.assertIn("while (i < n)", generated)
        self.assertIn("y = 0;", generated)
        self.assertEqual(analyze(generated, str(self.dst), native=False).report["status"], "frontend_only")

    @unittest.skipUnless(shutil.which("gcc"), "GCC is needed for C ABI native differential")
    def test_stateful_cpp_vs_hepta_native_differential(self):
        self.src.write_text("""
int sum_to(int n) noexcept {
    int total = 0;
    int i = 0;
    while (i < n) { total = total + i; i = i + 1; }
    return total;
}
int clamp_local(int x) noexcept {
    int y = x;
    if (y < 0) { y = 0; }
    return y;
}
""")
        migrated = migrate_cpp(self.src, self.dst)
        self.assertTrue(migrated["ok"], migrated)
        wrapper = self.root / "wrapped.cc"
        wrapper.write_text("""
int sum_to(int) noexcept;
int clamp_local(int) noexcept;
extern "C" int cpp_sum_to(int n) { return sum_to(n); }
extern "C" int cpp_clamp_local(int x) { return clamp_local(x); }
""")
        original = self.root / "liboriginal.so"
        result = subprocess.run(["clang++", "-std=c++20", "-O2", "-fPIC", "-shared",
                                 str(self.src), str(wrapper), "-o", str(original)],
                                capture_output=True, text=True, timeout=50)
        self.assertEqual(result.returncode, 0, result.stderr)
        translated = self.root / "libhepta.so"
        result = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.dst),
                                 "--backend", "c", "--crate-type", "cdylib", "-o",
                                 str(translated)], capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        cpp, hepta = ctypes.CDLL(str(original)), ctypes.CDLL(str(translated))
        cases = {"sum_to": [(-10,), (0,), (1,), (2,), (7,), (100,), (1000,)],
                 "clamp_local": [(-100,), (-1,), (0,), (1,), (1234,)]}
        for name, args_list in cases.items():
            left, right = getattr(cpp, "cpp_" + name), getattr(hepta, name)
            for fn in (left, right):
                fn.restype = ctypes.c_int32
                fn.argtypes = [ctypes.c_int32]
            for args in args_list:
                with self.subTest(name=name, args=args):
                    self.assertEqual(left(*args), right(*args))

    def test_cpp_counted_for_original_vs_hepta_native(self):
        self.src.write_text("""
int sum_for(int n) noexcept {
    int total = 0;
    int i = 0;
    for (i = 0; i < n; ++i) { total = total + i; }
    return total;
}
""")
        migrated = migrate_cpp(self.src, self.dst)
        self.assertTrue(migrated["ok"], migrated)
        self.assertFalse(migrated["cpp_abi_preserved"])
        generated = self.dst.read_text()
        self.assertIn("while (i < n)", generated)
        self.assertIn("i = (i + 1);", generated)
        wrapper = self.root / "for_wrapper.cc"
        wrapper.write_text("""
int sum_for(int) noexcept;
extern "C" int cpp_sum_for(int n) { return sum_for(n); }
""")
        original_so = self.root / "for_original.so"
        hepta_so = self.root / "for_hepta.so"
        original = subprocess.run(["clang++", "-std=c++20", "-O2", "-shared",
                                   "-fPIC", str(self.src), str(wrapper),
                                   "-o", str(original_so)],
                                  capture_output=True, text=True, timeout=60)
        self.assertEqual(original.returncode, 0, original.stdout + original.stderr)
        native = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.dst),
                                 "--backend", "c", "--crate-type", "cdylib",
                                 "-o", str(hepta_so)],
                                capture_output=True, text=True, timeout=90)
        self.assertEqual(native.returncode, 0, native.stdout + native.stderr)
        cpp = ctypes.CDLL(str(original_so)).cpp_sum_for
        hp = ctypes.CDLL(str(hepta_so)).sum_for
        for fn in (cpp, hp):
            fn.argtypes = [ctypes.c_int32]
            fn.restype = ctypes.c_int32
        for n in (-8, 0, 1, 2, 9, 100, 1000):
            self.assertEqual(cpp(n), hp(n), n)

    def test_nested_scoped_for_shadowing_native_abi(self):
        self.src.write_text("""
int nested(int n) noexcept {
    int total = 0;
    for (int i = 0; i < n; ++i) {
        for (int i = 0; i < 2; ++i) { total = total + 1; }
    }
    return total;
}
""")
        migrated = migrate_cpp(self.src, self.dst)
        self.assertTrue(migrated["ok"], migrated)
        self.assertFalse(migrated["behavioral_equivalence_proved"])
        generated = self.dst.read_text()
        names = __import__("re").findall(r"let mut (hepta_for_\\d+_i)", generated)
        self.assertEqual(len(set(names)), 2, generated)
        self.assertNotIn("let mut i:", generated)
        wrapper = self.root / "nested_bridge.cc"
        wrapper.write_text("""
int nested(int) noexcept;
extern "C" int cpp_nested(int n) { return nested(n); }
""")
        original = self.root / "original_nested.so"
        output = self.root / "hepta_nested.so"
        compiled = subprocess.run(["clang++", "-std=c++20", "-O2", "-fPIC", "-shared",
                                   str(self.src), str(wrapper), "-o", str(original)],
                                  capture_output=True, text=True, timeout=60)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        built = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.dst),
                                "--backend", "c", "--crate-type", "cdylib",
                                "-o", str(output)], capture_output=True, text=True, timeout=90)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        left = ctypes.CDLL(str(original)).cpp_nested
        right = ctypes.CDLL(str(output)).nested
        for fn in (left, right):
            fn.argtypes = [ctypes.c_int32]
            fn.restype = ctypes.c_int32
        for n in (-50, -1, 0, 1, 2, 19, 100, 1000):
            with self.subTest(n=n):
                self.assertEqual(left(n), right(n))
        self.assertEqual(right(19), 38)

    def test_scoped_loop_shadow_does_not_override_parameter(self):
        self.src.write_text("""
int shadow(int i) noexcept {
    int total = 0;
    for (int i = 0; i < 4; ++i) { total = total + i; }
    return total + i;
}
""")
        result = migrate_cpp(self.src, self.dst)
        self.assertTrue(result["ok"], result)
        output = self.dst.read_text()
        self.assertRegex(output, r"let mut hepta_for_\d+_i: i32 = 0;")
        # Source ParmVarDecl 'i' and for-local VarDecl 'i' carry distinct Clang IDs.
        self.assertIn("return (total + i);", output)
        self.assertIn("hepta_for_", output)
        self.assertFalse(result["cpp_abi_preserved"])
        self.assertFalse(result["behavioral_equivalence_proved"])

    def test_forged_source_local_ast_identity_rejected(self):
        # Model a corrupted Clang capture by changing one local reference ID:
        # equality of source spelling is not evidence of the same declaration.
        import copy
        from hepta.c_migrate import MigrationRejected, _function
        from hepta.cpp2hepta import _model
        self.src.write_text("""
int sum(int n) noexcept {
    int total = 0;
    for (int i = 0; i < n; ++i) { total = total + i; }
    return total;
}
""")
        capture = subprocess.run(
            ["clang++", "-std=c++20", "-Werror", "-fsyntax-only",
             "-Xclang", "-ast-dump=json", str(self.src)],
            capture_output=True, text=True, timeout=40)
        self.assertEqual(capture.returncode, 0, capture.stderr)
        ast = json.loads(capture.stdout)
        fn = next(n for n in ast["inner"] if n.get("kind") == "FunctionDecl"
                  and n.get("name") == "sum" and n.get("loc", {}).get("offset") is not None)
        mutated = copy.deepcopy(fn)
        def damage(node):
            if isinstance(node, dict):
                if (node.get("kind") == "DeclRefExpr"
                        and node.get("referencedDecl", {}).get("kind") == "VarDecl"
                        and node["referencedDecl"].get("name") == "i"):
                    node["referencedDecl"]["id"] = "0xforged-identity"
                    return True
                return any(damage(part) for part in node.get("inner", []))
            return False
        self.assertTrue(damage(mutated))
        with self.assertRaisesRegex(MigrationRejected, "not a checked parameter"):
            _function(mutated, _model("clang++"))
        self.assertFalse(self.dst.exists())

    def test_forged_clang_parameter_id_rejected(self):
        import copy
        from hepta.c_migrate import MigrationRejected, _function
        from hepta.cpp2hepta import _model
        self.src.write_text("""
int signed_diff(int x, int y) noexcept { return x - y; }
""")
        capture = subprocess.run(
            ["clang++", "-std=c++20", "-Werror", "-fsyntax-only",
             "-Xclang", "-ast-dump=json", str(self.src)],
            capture_output=True, text=True, timeout=40)
        self.assertEqual(capture.returncode, 0, capture.stderr)
        ast = json.loads(capture.stdout)
        original = next(n for n in ast["inner"] if n.get("kind") == "FunctionDecl"
                        and n.get("name") == "signed_diff"
                        and n.get("loc", {}).get("offset") is not None)
        model = _model("clang++")
        self.assertIn("signed_diff", _function(copy.deepcopy(original), model)["name"])
        tampered = copy.deepcopy(original)
        def damage(node):
            if isinstance(node, dict):
                ref = node.get("referencedDecl", {})
                if (node.get("kind") == "DeclRefExpr" and ref.get("kind") == "ParmVarDecl"
                        and ref.get("name") == "x"):
                    ref["id"] = "0xforged-parameter"
                    return True
                return any(damage(child) for child in node.get("inner", []))
            return False
        self.assertTrue(damage(tampered))
        with self.assertRaisesRegex(MigrationRejected, "not a checked parameter"):
            _function(tampered, model)
        self.assertFalse(self.dst.exists())

    def test_scoped_for_special_storage_and_multiple_declarators_rejected(self):
        sources = [
            "int f(int n) noexcept { int x=0;for (static int i=0;i<n;++i){x=x+i;}return x;}",
            "int f(int n) noexcept { int x=0;for (int i=0,j=0;i<n;++i){x=x+i;}return x;}",
            "int f(int n) noexcept { int x=0;for (int i;i<n;++i){x=x+i;}return x;}",
            "int f(int n) noexcept { int x=0;for (int i=0;i<n;++i){continue;}return x;}",
            "int f(int n) noexcept { int x=0;for (int i=0;i<n;++i){break;}return x;}",
            "int f(int n) noexcept { int x=0;for (int i=0;i<n;++i){int j=1;x=x+j;}return x;}",
        ]
        for src in sources:
            with self.subTest(src=src):
                self.src.write_text(src)
                result = migrate_cpp(self.src, self.dst)
                self.assertFalse(result["ok"], result)
                self.assertFalse(self.dst.exists())

    def test_hidden_preprocessor_forms_never_publish(self):
        sources = [
            '%:define FLAG 1\nint f(int a) noexcept {return a + FLAG;}',
            '/*comment*/ #define FLAG 1\nint f(int a) noexcept {return a + FLAG;}',
            '%\\' + '\n:define FLAG 1\nint f(int a) noexcept {return a + FLAG;}',
        ]
        for source in sources:
            with self.subTest(source=source):
                self.src.write_text(source)
                report = migrate_cpp(self.src, self.dst)
                self.assertFalse(report["ok"], report)
                self.assertEqual(report["rejected"][0]["code"], "E_CPP2HEPTA_PREPROCESSOR")
                self.assertFalse(self.dst.exists())

    def test_dangling_output_alias_and_existing_source_are_not_replaced(self):
        self.src.write_text(self._GOOD)
        target = self.root / "redirected.hepta"
        self.dst.symlink_to(target)
        report = migrate_cpp(self.src, self.dst)
        self.assertFalse(report["ok"])
        self.assertTrue(self.dst.is_symlink())
        self.assertFalse(target.exists())

    @unittest.skipUnless(shutil.which("gcc"), "C native differential runner requires GCC")
    def test_defined_cpp_vs_hepta_native_c_abi_differential(self):
        self.src.write_text(self._GOOD)
        migrated = migrate_cpp(self.src, self.dst)
        self.assertTrue(migrated["ok"], migrated)
        # Test C++ original through an explicit C ABI wrapper: NEVER infer
        # preservation of C++ mangled ABI from the generated Hepta exports.
        wrap = self.root / "wrapped.cc"
        wrap.write_text("""
int add(int, int) noexcept;
int clamp(int) noexcept;
extern "C" int cpp_add(int a,int b) { return add(a,b); }
extern "C" int cpp_clamp(int x) { return clamp(x); }
""")
        reference = self.root / "libreference.so"
        build_original = subprocess.run(["clang++", "-std=c++20", "-O2", "-fPIC", "-shared",
                                         str(self.src), str(wrap), "-o", str(reference)],
                                        capture_output=True, text=True, timeout=50)
        self.assertEqual(build_original.returncode, 0, build_original.stderr)
        translated = self.root / "libhepta.so"
        build_hepta = subprocess.run([sys.executable, "-m", "hepta", "build", str(self.dst),
                                      "--backend", "c", "--crate-type", "cdylib", "-o", str(translated)],
                                      capture_output=True, text=True, timeout=90)
        self.assertEqual(build_hepta.returncode, 0, build_hepta.stderr+build_hepta.stdout)
        cpp, hepta = ctypes.CDLL(str(reference)), ctypes.CDLL(str(translated))
        cases = {"add": [(0, 0), (2, 3), (-12, 55), (129, -22)],
                 "clamp": [(-3,), (-1,), (0,), (40,)]}
        for name, vals in cases.items():
            original_fn, converted_fn = getattr(cpp, "cpp_"+name), getattr(hepta, name)
            for fn in (original_fn, converted_fn):
                fn.restype = ctypes.c_int32
                fn.argtypes = [ctypes.c_int32] * len(vals[0])
            for args in vals:
                with self.subTest(function=name,args=args):
                    self.assertEqual(original_fn(*args), converted_fn(*args))
