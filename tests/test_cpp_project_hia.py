"""Concrete C++ project migration uses real capture, instantiation and HIA."""
from copy import deepcopy
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.c_migrate import MigrationRejected
from hepta.c_project import capture_project, verify_capture
from hepta.cpp_project_migrate import lower_cpp_project
from hepta.hia_program import execute_program
from tools.qualify_cpp_project_hia import qualify_cpp_templates_to_hia, validate_cpp_project_receipt


CLANG = os.environ.get("CLANG") or shutil.which("clang")
CLANGXX = os.environ.get("CLANGXX") or (str(Path(CLANG).with_name("clang++")) if CLANG else None)


@unittest.skipUnless(CLANG and CLANGXX, "Actual Clang 20 is required")
class CPPProjectHIATests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-cpp-project-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def database(self, sources, flags=None):
        commands = []
        for name, content in sources.items():
            (self.root / name).write_text(content)
            if name.endswith(".cpp"):
                commands.append({"directory": str(self.root), "file": name,
                                 "arguments": ["clang++", "-std=c++20", *(flags or []), "-c", name, "-o", name + ".o"]})
        db = self.root / "compile_commands.json"
        db.write_text(json.dumps(commands))
        return db

    def test_actual_two_units_templates_overloads_scalar_abi_and_native_overflow(self):
        report = qualify_cpp_templates_to_hia(self.root / "qualification", clang=CLANG, clangxx=CLANGXX)
        self.assertTrue(report["ok"], report.get("diagnostic"))
        self.assertEqual(report["case_count"], 227)
        self.assertEqual(report["native_result_executions"], 454)
        self.assertEqual(report["concrete_template_instance_count"], 4)
        self.assertEqual(report["active_project_declarations"], 70)
        self.assertEqual(len(report["capture"]["configurations"]), 2)
        self.assertFalse(any(row["status"].endswith("pending") for row in report["declarations"]))
        self.assertEqual(report["overflow_control"]["native_returncode"], -6)
        self.assertFalse(report["overflow_control"]["original_cpp_executed_outside_defined_domain"])
        forged = deepcopy(report)
        forged["target_link_argv"].append(str(self.root / "qualification/original-0.o"))
        forged["processes"][forged["target_link_process"]]["argv"] = forged["target_link_argv"][:]
        with self.assertRaisesRegex(ValueError, "only the directly generated HIA object"):
            validate_cpp_project_receipt(forged)
        for mutate in (
            lambda r: r["observed"]["standalone_hia"].__setitem__(0, -1),
            lambda r: r["claims"].update(arbitrary_templates_stl_raii_qualified=True),
            lambda r: r["cases"].pop(),
        ):
            forged = deepcopy(report); mutate(forged)
            with self.assertRaises(ValueError):
                validate_cpp_project_receipt(forged)

    def test_captured_header_macro_and_schema_replay_are_not_receipt_authority(self):
        db = self.database({"values.hpp": "#define OFFSET 9u\n",
                            "main.cpp": '#include "values.hpp"\nextern "C" unsigned int f(unsigned int x) noexcept {return x+OFFSET+EXTRA;}\n'}, ["-DEXTRA=3u"])
        capture = capture_project(db, clang=CLANGXX, language="c++")
        self.assertEqual(capture["schema"], "hepta.cpp-build.v1")
        verify_capture(capture)
        forged = deepcopy(capture); forged["schema"] = "hepta.c-build.v1"
        forged["sha256"] = hashlib.sha256(json.dumps({k: v for k, v in forged.items() if k != "sha256"}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with self.assertRaises(MigrationRejected):
            verify_capture(forged)
        (self.root / "values.hpp").write_text("#define OFFSET 10u\n")
        with self.assertRaises(MigrationRejected) as caught:
            verify_capture(capture)
        self.assertEqual(caught.exception.code, "E_C_BUILD_CHANGED")

    def test_signed_unsigned_overloads_resolve_by_clang_declaration_not_spelling(self):
        db = self.database({"main.cpp": '''
namespace n {
int select(int x) noexcept { return x + 1; }
unsigned int select(unsigned int x) noexcept { return x + 2u; }
}
extern "C" int signed_entry(int x) noexcept { return n::select(x); }
extern "C" unsigned int unsigned_entry(unsigned int x) noexcept { return n::select(x); }
'''} )
        migrated = lower_cpp_project(db, clangxx=CLANGXX)
        program = migrated["program"]
        self.assertEqual(execute_program(program, "signed_entry", [-7])["result"], -6)
        self.assertEqual(execute_program(program, "unsigned_entry", [(1 << 32) - 1])["result"], 1)
        targets = [row["hia_function"] for row in migrated["declarations"] if row["name"] == "select"]
        self.assertEqual(len(set(targets)), 2)

    def test_repeated_inline_template_definition_requires_same_instantiated_semantics(self):
        header = "template<class T> T f(T x) noexcept { return x + VALUE; }\n"
        db = self.database({"header.hpp": header,
                            "one.cpp": '#include "header.hpp"\nextern "C" unsigned a(unsigned x) noexcept {return f<unsigned>(x);}',
                            "two.cpp": '#include "header.hpp"\nextern "C" unsigned b(unsigned x) noexcept {return f<unsigned>(x);}'}, ["-DVALUE=3u"])
        result = lower_cpp_project(db, clangxx=CLANGXX)
        self.assertEqual(execute_program(result["program"], "a", [10])["result"], 13)
        self.assertTrue(any(row["status"] == "identical_inline_or_template_definition_resolved" for row in result["declarations"]))
        commands = json.loads(db.read_text()); commands[1]["arguments"][2] = "-DVALUE=7u"
        db.write_text(json.dumps(commands))
        with self.assertRaises(MigrationRejected) as caught:
            lower_cpp_project(db, clangxx=CLANGXX)
        self.assertEqual(caught.exception.code, "E_CPP_PROJECT_ODR")

    def test_shared_scalar_lowering_is_lazy_and_does_not_shadow_source_function(self):
        source = '''
extern "C" int migration_conditional_1(int x) noexcept { return x+5; }
extern "C" int probe(int c,int a) noexcept {
    int x;
    if(c) x=a; else return 7;
    return migration_conditional_1(x)+(a ? 12/a : 0);
}
'''
        db = self.database({"main.cpp": source})
        migrated = lower_cpp_project(db, clangxx=CLANGXX)
        from hepta.hia_program_llvm import build_program_native
        target = self.root / "target.so"
        build = build_program_native(migrated["program"], target, clang=CLANG)
        self.assertTrue(build["ok"], build)
        original = self.root / "original.so"
        compiled = subprocess.run([CLANGXX, "-std=c++20", "-O2", "-shared", "-fPIC",
                                   str(self.root / "main.cpp"), "-o", str(original)], capture_output=True)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        cases = [([0, 0], 7), ([1, 0], 5), ([1, 3], 12), ([-1, -3], -2)]
        for path in (original, target):
            library = ctypes.CDLL(str(path))
            library.probe.argtypes, library.probe.restype = [ctypes.c_int32, ctypes.c_int32], ctypes.c_int32
            for arguments, expected in cases:
                self.assertEqual(library.probe(*arguments), expected)
                self.assertEqual(execute_program(migrated["program"], "probe", arguments)["result"], expected)

    def test_all_active_declarations_and_uncaptured_operations_fail_closed(self):
        examples = [
            ("uninstantiated", "template<class T> T f(T x) noexcept {return x;}\n", "E_CPP_PROJECT_UNINSTANTIATED"),
            ("global", "unsigned hidden=9; unsigned f(unsigned x) noexcept {return x;}", "E_CPP_PROJECT_DECLARATION"),
            ("class", "struct Hidden {unsigned x;}; unsigned f(unsigned x) noexcept {return x;}", "E_CPP_PROJECT_DECLARATION"),
            ("unresolved", 'unsigned external(unsigned x) noexcept; extern "C" unsigned f(unsigned x) noexcept {return external(x);}', "E_CPP_PROJECT_EXTERNAL"),
            ("throwing", "unsigned f(unsigned x) {return x;}", "E_CPP_PROJECT_PROFILE"),
            ("default", "unsigned f(unsigned x=7u) noexcept {return x;}", "E_CPP_PROJECT_PROFILE"),
            ("pack", 'template<class... T> unsigned f(T... x) noexcept {return 7u;} extern "C" unsigned g(unsigned x) noexcept {return f(x);}', "E_CPP_PROJECT_PROFILE"),
            ("if_constexpr_init", 'template<class T> T f(T x) noexcept {if constexpr (constexpr unsigned n=sizeof(T); n==4) return x; else return x+x;} extern "C" unsigned g(unsigned x) noexcept {return f(x);}', "E_CPP_PROJECT_CONSTEXPR"),
        ]
        for label, source, code in examples:
            with self.subTest(case=label):
                db = self.database({"main.cpp": source})
                with self.assertRaises(MigrationRejected) as caught:
                    lower_cpp_project(db, clangxx=CLANGXX)
                self.assertEqual(caught.exception.code, code)


if __name__ == "__main__":
    unittest.main()
