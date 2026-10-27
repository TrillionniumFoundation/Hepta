"""Compilation flags must select the same source in C/C++ and standalone HIA."""
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
from hepta.c_translation import CTranslator
from hepta.cpp_project_migrate import lower_cpp_project
from hepta.hia_program import execute_program
from hepta.hia_program_llvm import build_program_native
from hepta.hia_program_source import lower_source


CLANG = os.environ.get("CLANG") or shutil.which("clang")
CLANGXX = os.environ.get("CLANGXX") or (str(Path(CLANG).with_name("clang++")) if CLANG else None)

# These compiler-provided macros affect both the body and the dependency graph.
# Observe the original compiler's answer instead of assuming host PIE defaults.
MACROS = """
#ifdef __OPTIMIZE__
#define OPTIMIZED 1u
#else
#define OPTIMIZED 0u
#endif
#ifdef __OPTIMIZE_SIZE__
#define SIZE_OPTIMIZED 2u
#else
#define SIZE_OPTIMIZED 0u
#endif
#ifdef __NO_INLINE__
#define NO_INLINE 4u
#else
#define NO_INLINE 0u
#endif
#ifdef __PIC__
#define PIC_LEVEL (8u * __PIC__)
#else
#define PIC_LEVEL 0u
#endif
#ifdef __PIE__
#define PIE_LEVEL (32u * __PIE__)
#else
#define PIE_LEVEL 0u
#endif
"""


@unittest.skipUnless(CLANG and CLANGXX, "Actual Clang C and C++ frontends are required")
class CapturedSemanticFlagsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-semantic-flags-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def project(self, language, flags, body, *, label="source", standard=None):
        directory = self.root / label
        directory.mkdir()
        source = directory / ("input.cpp" if language == "c++" else "input.c")
        source.write_text(body, encoding="utf-8")
        standard = standard or ("-std=c++20" if language == "c++" else "-std=c11")
        compiler = CLANGXX if language == "c++" else CLANG
        argv = ["clang++" if language == "c++" else "clang", standard, *flags,
                "-c", source.name, "-o", "original.o"]
        database = directory / "compile_commands.json"
        database.write_text(json.dumps([{"directory": str(directory), "file": source.name,
                                        "arguments": argv}]), encoding="utf-8")
        return directory, database, source, compiler, [standard, *flags]

    @staticmethod
    def function(language, expression):
        prefix = 'extern "C" ' if language == "c++" else ""
        suffix = " noexcept" if language == "c++" else ""
        return f"{prefix}unsigned probe(unsigned x){suffix} {{ return {expression}; }}\n"

    def lower(self, language, database, compiler):
        if language == "c++":
            migrated = lower_cpp_project(database, clangxx=compiler)
            return migrated["program"], "probe", migrated["capture"]
        capture = capture_project(database, clang=compiler, language=language)
        source, _, _ = CTranslator(capture).emit()
        return lower_source(source), "c_probe", capture

    @staticmethod
    def native_command(argv, directory):
        return subprocess.run([str(x) for x in argv], cwd=directory, check=True,
                              capture_output=True, text=True, timeout=60)

    @staticmethod
    def observe(library, symbol, value=7):
        loaded = ctypes.CDLL(str(library))
        function = getattr(loaded, symbol)
        function.argtypes, function.restype = [ctypes.c_uint32], ctypes.c_uint32
        return function(value)

    def test_original_interpreter_and_native_hia_preserve_macro_selected_bodies(self):
        configurations = [
            ["-O0"], ["-O1"], ["-O2"], ["-O3"], ["-Os"], ["-Oz"],
            ["-fPIC"], ["-fpic"], ["-O2", "-O0"], ["-O0", "-O2"],
            ["-fPIC", "-fpic"], ["-fpic", "-fPIC"],
        ]
        for language in ("c", "c++"):
            observed = []
            for index, flags in enumerate(configurations):
                with self.subTest(language=language, flags=flags):
                    body = MACROS + self.function(language,
                        "x + OPTIMIZED + SIZE_OPTIMIZED + NO_INLINE + PIC_LEVEL + PIE_LEVEL")
                    directory, database, source, compiler, options = self.project(
                        language, flags, body, label=language.replace("+", "p") + str(index))
                    # Compile the real source under the database's exact semantic
                    # options. Linking separately must not add -fPIC/-O2 to its
                    # preprocessing or replace the user's final option.
                    self.native_command([compiler, *options, "-c", source, "-o", "original.o"], directory)
                    self.native_command([compiler, "-shared", "original.o", "-o", "original.so"], directory)
                    original = self.observe(directory / "original.so", "probe")
                    observed.append(original)
                    program, symbol, capture = self.lower(language, database, compiler)
                    interpreted = execute_program(program, symbol, [7])
                    self.assertEqual(interpreted["status"], "returned")
                    self.assertEqual(interpreted["result"], original)
                    build_program_native(program, directory / "hia.o", clang=CLANG, kind="object")
                    self.native_command([CLANG, "-shared", "hia.o", "-o", "hia.so"], directory)
                    self.assertEqual(self.observe(directory / "hia.so", symbol), original)
                    verify_capture(capture)
            # The oracle genuinely exercised different preprocessing paths.
            self.assertNotEqual(observed[0], observed[2])
            self.assertNotEqual(observed[2], observed[4])
            self.assertNotEqual(observed[6], observed[7])
            self.assertEqual(observed[8], observed[0])
            self.assertEqual(observed[9], observed[2])
            self.assertEqual(observed[10], observed[7])
            self.assertEqual(observed[11], observed[6])

    def test_optimization_selected_dependencies_cannot_hide_rejected_declarations(self):
        for language, code in (("c", "E_C_TOPLEVEL"), ("c++", "E_CPP_PROJECT_DECLARATION")):
            with self.subTest(language=language):
                body = '#ifdef __OPTIMIZE__\n#include "active.h"\n#endif\n'
                body += self.function(language, "x")
                directory, database, _, compiler, _ = self.project(
                    language, ["-O2"], body, label=language.replace("+", "p"))
                header = directory / "active.h"
                header.write_text("unsigned unsupported_global = 9u;\n", encoding="utf-8")
                capture = capture_project(database, clang=compiler, language=language)
                self.assertIn(str(header), capture["configurations"][0]["local_dependencies"])
                with self.assertRaises(MigrationRejected) as caught:
                    self.lower(language, database, compiler)
                self.assertEqual(caught.exception.code, code)

    def test_pedantic_errors_preserves_feature_selected_body_without_macro_dump_changes(self):
        # __has_extension is a builtin preprocessing operator, not an ordinary
        # macro definition. -dM alone cannot detect its changed answer.
        body = ("#if __has_extension(c_static_assert)\n"
                + self.function("c", "x + 1u") + "#else\n"
                + self.function("c", "x + 2u") + "#endif\n")
        observed, macros = [], []
        for index, flags in enumerate(([], ["-pedantic-errors"])):
            with self.subTest(flags=flags):
                directory, database, source, compiler, options = self.project(
                    "c", flags, body, label="pedantic" + str(index), standard="-std=c99")
                macros.append(self.native_command(
                    [compiler, *options, "-dM", "-E", "-x", "c", "/dev/null"], directory).stdout)
                self.native_command([compiler, *options, "-c", source, "-o", "original.o"], directory)
                self.native_command([compiler, "-shared", "original.o", "-o", "original.so"], directory)
                original = self.observe(directory / "original.so", "probe")
                observed.append(original)
                program, symbol, capture = self.lower("c", database, compiler)
                interpreted = execute_program(program, symbol, [7])
                self.assertEqual(interpreted["status"], "returned")
                self.assertEqual(interpreted["result"], original)
                build_program_native(program, directory / "hia.o", clang=CLANG, kind="object")
                self.native_command([CLANG, "-shared", "hia.o", "-o", "hia.so"], directory)
                self.assertEqual(self.observe(directory / "hia.so", symbol), original)
                verify_capture(capture)
        self.assertEqual(observed, [8, 9])
        self.assertEqual(macros[0], macros[1])

    def test_feature_selected_dependencies_cannot_hide_rejected_declarations(self):
        body = '#if !__has_extension(c_static_assert)\n#include "active.h"\n#endif\n'
        body += self.function("c", "x")
        directory, database, _, compiler, _ = self.project(
            "c", ["-pedantic-errors"], body, standard="-std=c99")
        header = directory / "active.h"
        header.write_text("unsigned unsupported_global = 9u;\n", encoding="utf-8")
        capture = capture_project(database, clang=compiler)
        self.assertIn(str(header), capture["configurations"][0]["local_dependencies"])
        with self.assertRaises(MigrationRejected) as caught:
            self.lower("c", database, compiler)
        self.assertEqual(caught.exception.code, "E_C_TOPLEVEL")

    def test_resealed_capture_cannot_reclassify_semantic_options_as_omitted(self):
        _, database, _, compiler, _ = self.project(
            "c++", ["-O2", "-fpic", "-pedantic-errors"], self.function("c++", "x"))
        capture = capture_project(database, clang=compiler, language="c++")
        for option in ("-O2", "-fpic", "-pedantic-errors"):
            with self.subTest(option=option):
                forged = deepcopy(capture)
                row = forged["configurations"][0]
                row["frontend_arguments"].remove(option)
                row["abi_model_arguments"].remove(option)
                row["omitted_arguments"].append({"argument": option,
                    "reason": "driver_output_or_diagnostic_flag"})
                forged["sha256"] = hashlib.sha256(json.dumps(
                    {k: v for k, v in forged.items() if k != "sha256"},
                    sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
                with self.assertRaises(MigrationRejected) as caught:
                    verify_capture(forged)
                self.assertEqual(caught.exception.code, "E_C_BUILD_IDENTITY")

    def test_unmodeled_semantic_flags_remain_rejected(self):
        _, database, _, compiler, _ = self.project(
            "c", ["-fwrapv"], self.function("c", "x"))
        with self.assertRaises(MigrationRejected) as caught:
            capture_project(database, clang=compiler)
        self.assertEqual(caught.exception.code, "E_C_BUILD_FLAG")


if __name__ == "__main__":
    unittest.main()
