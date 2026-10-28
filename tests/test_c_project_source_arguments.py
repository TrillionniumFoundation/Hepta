"""Real compiler/HIA agreement requires the original source operand and cwd."""
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
from hepta.c_project import capture_project, captured_source_argument, invoke, verify_capture
from hepta.c_translation import CTranslator
from hepta.cpp_project_migrate import lower_cpp_project
from hepta.hia_program import execute_program
from hepta.hia_program_llvm import build_program_native
from hepta.hia_program_source import lower_source


CLANG = os.environ.get("CLANG") or shutil.which("clang")
CLANGXX = os.environ.get("CLANGXX") or (str(Path(CLANG).with_name("clang++")) if CLANG else None)


@unittest.skipUnless(CLANG and CLANGXX, "Actual Clang C and C++ frontends are required")
class CapturedSourceArgumentsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-source-argument-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    @staticmethod
    def function(language, expression):
        prefix = 'extern "C" ' if language == "c++" else ""
        suffix = " noexcept" if language == "c++" else ""
        return f"{prefix}unsigned probe(unsigned x){suffix} {{ return {expression}; }}\n"

    def project(self, language, label, body, *, spelling="relative", symlink=False):
        directory = self.root / label
        (directory / "sub").mkdir(parents=True)
        source = directory / ("sub/input.cpp" if language == "c++" else "sub/input.c")
        source.write_text(body, encoding="utf-8")
        operand = "sub/" + source.name
        if symlink:
            (directory / "alias").mkdir()
            (directory / "alias" / source.name).symlink_to(source)
            operand = "alias/" + source.name
        elif spelling == "absolute":
            operand = str(source)
        elif spelling == "dot_relative":
            operand = "./" + operand
        compiler = CLANGXX if language == "c++" else CLANG
        arguments = ["clang++" if language == "c++" else "clang",
                     "-std=c++20" if language == "c++" else "-std=c11",
                     "-c", operand, "-o", "original.o"]
        database = directory / "compile_commands.json"
        # The database's file identity may use a different spelling from argv.
        database.write_text(json.dumps([{"directory": str(directory), "file": str(source),
                                         "arguments": arguments}]), encoding="utf-8")
        return directory, database, source, operand, compiler, arguments

    @staticmethod
    def command(argv, directory):
        return subprocess.run(list(map(str, argv)), cwd=directory, check=True,
                              capture_output=True, text=True, timeout=60)

    @staticmethod
    def observe(library, symbol):
        loaded = ctypes.CDLL(str(library))
        function = getattr(loaded, symbol)
        function.argtypes, function.restype = [ctypes.c_uint32], ctypes.c_uint32
        return function(7)

    def assert_three_way(self, language, project):
        directory, database, _, operand, compiler, arguments = project
        # Execute the actual source operand from the database, in its cwd.
        self.command([compiler, *arguments[1:]], directory)
        self.command([compiler, "-shared", "original.o", "-o", "original.so"], directory)
        original = self.observe(directory / "original.so", "probe")
        if language == "c++":
            migrated = lower_cpp_project(database, clangxx=compiler)
            program, capture, symbol = migrated["program"], migrated["capture"], "probe"
        else:
            capture = capture_project(database, clang=compiler)
            generated, _, _ = CTranslator(capture).emit()
            program, symbol = lower_source(generated), "c_probe"
        self.assertEqual(captured_source_argument(capture["configurations"][0], language=language), operand)
        interpreted = execute_program(program, symbol, [7])
        self.assertEqual(interpreted["status"], "returned")
        self.assertEqual(interpreted["result"], original)
        self.assertTrue(build_program_native(program, directory / "hia.o", clang=CLANG, kind="object")["ok"])
        self.command([CLANG, "-shared", "hia.o", "-o", "hia.so"], directory)
        self.assertEqual(self.observe(directory / "hia.so", symbol), original)
        verify_capture(capture)
        return original, capture

    def test_relative_and_absolute_file_macro_select_the_original_body(self):
        for language in ("c", "c++"):
            values = []
            for spelling in ("relative", "absolute"):
                with self.subTest(language=language, spelling=spelling):
                    body = ("#if __has_include(__FILE__)\n" + self.function(language, "x + 1u")
                            + "#else\n" + self.function(language, "x + 2u") + "#endif\n")
                    project = self.project(language, language.replace("+", "p") + spelling,
                                           body, spelling=spelling)
                    original, _ = self.assert_three_way(language, project)
                    values.append(original)
            self.assertEqual(values, [9, 8])

    def test_source_symlink_preserves_quoted_include_search_and_dependency_identity(self):
        for language in ("c", "c++"):
            with self.subTest(language=language):
                project = self.project(language, language.replace("+", "p"),
                                       '#include "local.h"\n' + self.function(language, "x + OFFSET"),
                                       symlink=True)
                directory, _, _, _, _, _ = project
                (directory / "sub/local.h").write_text("#define OFFSET 1u\n")
                chosen = directory / "alias/local.h"
                chosen.write_text("#define OFFSET 2u\n")
                original, capture = self.assert_three_way(language, project)
                self.assertEqual(original, 9)
                self.assertIn(str(chosen), capture["configurations"][0]["local_dependencies"])
                self.assertNotIn(str(directory / "sub/local.h"), capture["configurations"][0]["all_dependencies"])
                chosen.write_text("#define OFFSET 3u\n")
                with self.assertRaises(MigrationRejected) as caught:
                    verify_capture(capture)
                self.assertEqual(caught.exception.code, "E_C_BUILD_CHANGED")

    def test_concrete_template_file_basefile_line_and_sizeof_constants(self):
        for spelling in ("relative", "dot_relative", "absolute"):
            with self.subTest(spelling=spelling):
                body = ("template<unsigned N> unsigned selected(unsigned x) noexcept { return x + N; }\n"
                        'extern "C" unsigned probe(unsigned x) noexcept { '
                        "return selected<sizeof(__FILE__) + sizeof(__BASE_FILE__) + __LINE__ + sizeof(unsigned)>(x); }\n")
                project = self.project("c++", spelling, body, spelling=spelling)
                original, _ = self.assert_three_way("c++", project)
                self.assertEqual(original, 7 + 2 * (len(project[3].encode()) + 1) + 2 + 4)

    def test_resealed_capture_cannot_replace_original_spelling_or_old_preprocessing(self):
        project = self.project("c", "reseal", self.function("c", "x"))
        directory, database, source, _, compiler, _ = project
        capture = capture_project(database, clang=compiler)
        rewritten = invoke([capture["compiler"]["path"], *capture["configurations"][0]["frontend_arguments"],
                            "-E", str(source)], directory)
        for change, code in (("source_argument", "E_C_BUILD_IDENTITY"),
                             ("old_preprocessing", "E_C_BUILD_CHANGED")):
            with self.subTest(change=change):
                forged = deepcopy(capture)
                config = forged["configurations"][0]
                if change == "source_argument":
                    config["original_arguments"][3] = str(source)
                else:
                    config["preprocessed_sha256"] = hashlib.sha256(rewritten.encode()).hexdigest()
                    self.assertNotEqual(config["preprocessed_sha256"], capture["configurations"][0]["preprocessed_sha256"])
                forged["sha256"] = hashlib.sha256(json.dumps(
                    {key: value for key, value in forged.items() if key != "sha256"},
                    sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
                with self.assertRaises(MigrationRejected) as caught:
                    verify_capture(forged)
                self.assertEqual(caught.exception.code, code)

    def test_source_replay_cannot_introduce_response_expansion_options_or_stdin(self):
        for index, operand in enumerate(("@input.c", "-input.c", "-")):
            with self.subTest(operand=operand):
                directory = self.root / str(index)
                directory.mkdir()
                source = directory / (operand if operand != "-" else "input.c")
                source.write_text(self.function("c", "x"))
                database = directory / "compile_commands.json"
                database.write_text(json.dumps([{"directory": str(directory), "file": str(source),
                    "arguments": ["clang", "-std=c11", "-c", operand]}]))
                with self.assertRaises(MigrationRejected) as caught:
                    capture_project(database, clang=CLANG)
                self.assertEqual(caught.exception.code, "E_C_BUILD_FLAG")
        _, database, _, _, _, _ = self.project("c", "response_output", self.function("c", "x"))
        entry = json.loads(database.read_text())
        entry[0]["arguments"][-1] = "@output-options.rsp"
        database.write_text(json.dumps(entry))
        with self.assertRaises(MigrationRejected) as caught:
            capture_project(database, clang=CLANG)
        self.assertEqual(caught.exception.code, "E_C_BUILD_FLAG")


if __name__ == "__main__":
    unittest.main()
