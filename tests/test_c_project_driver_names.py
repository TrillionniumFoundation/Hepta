"""GNU driver spelling in a database must not select the executable run."""
from pathlib import Path
import json
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta import c_project
from hepta.c_migrate import MigrationRejected


class CProjectDriverNamesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-database-driver-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "input.c"
        self.source.write_text("unsigned int probe(unsigned int x) { return x + 1u; }\n")

    def test_exe_database_driver_is_recorded_but_only_selected_clang_runs(self):
        clang = shutil.which("clang")
        self.assertIsNotNone(clang, "Clang is required for actual capture/replay")
        actual_compiler = str(Path(clang).resolve())
        for language, driver, suffix, standard in (
                ("c", "clang.exe", ".c", "-std=c11"),
                ("c++", "clang++.exe", ".cpp", "-std=c++20")):
            with self.subTest(language=language):
                source = self.root / ("input with spaces" + suffix)
                source.write_text(self.source.read_text())
                # This database-only executable does not exist on the host.
                # A successful capture must actually use the caller's Clang.
                metadata_driver = self.root / "Compiler Metadata With Spaces" / driver
                self.assertFalse(metadata_driver.exists())
                argv = [str(metadata_driver), standard, "-O0", "-c", source.name,
                        "-o", "output with spaces.o"]
                database = self.root / "compile_commands.json"
                database.write_text(json.dumps([{
                    "directory": str(self.root), "file": source.name,
                    "arguments": argv,
                }]))
                with patch.object(c_project, "invoke", wraps=c_project.invoke) as invoked:
                    captured = c_project.capture_project(database, clang=clang, language=language)
                    c_project.verify_capture(captured)
                self.assertEqual(captured["compiler"]["path"], actual_compiler)
                self.assertEqual(captured["configurations"][0]["original_arguments"], argv)
                self.assertEqual(captured["configurations"][0]["frontend_arguments"],
                                 [standard, "-O0"])
                self.assertEqual(c_project.captured_source_argument(
                                     captured["configurations"][0], language=language),
                                 source.name)
                self.assertGreater(invoked.call_count, 2)
                self.assertTrue(all(call.args[0][0] == actual_compiler
                                    for call in invoked.call_args_list))
                self.assertTrue(any("-E" in call.args[0] for call in invoked.call_args_list))

    def test_existing_gnu_driver_names_gain_only_the_exe_suffix(self):
        for language, names, standard in (
                ("c", ("cc", "gcc", "clang", "clang-18", "clang-19", "clang-20"), "-std=c11"),
                ("c++", ("c++", "g++", "clang++", "clang++-18", "clang++-19", "clang++-20"),
                 "-std=c++20")):
            for name in names:
                for suffix in ("", ".exe"):
                    with self.subTest(language=language, driver=name + suffix):
                        argv = [str(self.root / "GNU tools" / (name + suffix)),
                                standard, "-O2", "-c", self.source.name, "-o", "input.o"]
                        flags, omitted, source = c_project._command_arguments(
                            argv, self.source, self.root, language=language)
                        self.assertEqual(flags, [standard, "-O2"])
                        self.assertEqual(source, self.source.name)
                        self.assertEqual(omitted, [
                            {"argument": "-c", "reason": "driver_output_or_diagnostic_flag"},
                            {"argument": "-o", "operand": "input.o", "reason": "object_output_not_executed"},
                        ])

    def test_wrappers_and_other_driver_families_still_reject(self):
        common = ("ccache", "ccache.exe", "sccache.exe", "clang-cl", "clang-cl.exe",
                  "cl", "cl.exe", "clang.exe.exe", "clang-21.exe", "gcc-14.exe",
                  "clang.cmd", "clang.bat", "CLANG.EXE", "clang.exe --driver-mode=cl")
        for language, standard, wrong_language in (("c", "-std=c11", "clang++.exe"),
                                                    ("c++", "-std=c++20", "clang.exe")):
            for name in (*common, wrong_language):
                with self.subTest(language=language, driver=name):
                    argv = [str(self.root / "tools" / name), standard, "-c", self.source.name]
                    with self.assertRaises(MigrationRejected) as refused:
                        c_project._command_arguments(argv, self.source, self.root, language=language)
                    self.assertEqual(refused.exception.code, "E_C_BUILD_COMMAND")

    def test_exe_spelling_does_not_admit_response_files_or_driver_mode_flags(self):
        for extra in (("@flags.rsp",), ("-o", "@output.rsp"), ("-I", "@includes.rsp"),
                      ("--driver-mode=cl",), ("-Xclang", "-load", "plugin.dll"),
                      ("/c",), ("/clang:-load",)):
            with self.subTest(extra=extra):
                argv = ["clang.exe", "-std=c11", *extra, "-c", self.source.name]
                with self.assertRaises(MigrationRejected) as refused:
                    c_project._command_arguments(argv, self.source, self.root)
                self.assertEqual(refused.exception.code, "E_C_BUILD_FLAG")


if __name__ == "__main__":
    unittest.main()
