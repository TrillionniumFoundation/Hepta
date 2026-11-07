"""Real GCC/archive build-tool routing; no Hepta lowering or research workload."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.ast import HeptaError
from hepta.c_backend import compile_c


GCC = shutil.which("gcc")
AR = shutil.which("ar")
ASSEMBLER = shutil.which("as")
LINKER = shutil.which("ld")
SOURCE = "int hepta_answer(void) { return 42; }\n"


@unittest.skipUnless(os.name == "posix" and all((GCC, AR, ASSEMBLER, LINKER)),
                     "POSIX GCC, ar, as and ld required")
class CArchiverSelectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-archiver-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        (self.bin / "as").symlink_to(ASSEMBLER)
        (self.bin / "ld").symlink_to(LINKER)
        # Exercise real tool lookup with no bare ar on PATH, not a mocked lookup.
        environment = patch.dict(os.environ, {"PATH": str(self.bin)})
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop("AR", None)
        self.archive = self.root / "answer.a"
        self.log = self.root / "archiver.json"

    def wrapper(self, name="selected-ar", *, exit_code=None):
        path = self.bin / name
        action = (f"raise SystemExit({exit_code})" if exit_code is not None else
                  f"os.execv({AR!r}, [{AR!r}, *sys.argv[1:]])")
        path.write_text(
            f"#!{sys.executable}\nimport json, os, pathlib, sys\n"
            f"pathlib.Path({str(self.log)!r}).write_text(json.dumps(sys.argv[1:]))\n"
            + action + "\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def build(self, **kwargs):
        return compile_c(SOURCE, cc=GCC, crate_type="staticlib",
                         output=self.archive, **kwargs)

    def assert_archive_usable(self, report):
        self.assertTrue(report["ok"], report)
        self.assertGreater(report["artifact_bytes"], 0)
        members = subprocess.run([AR, "t", str(self.archive)], check=True,
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(members.stdout.splitlines(), ["artifact"])
        client = self.root / "client.c"
        client.write_text("int hepta_answer(void);\n"
                          "int main(void) { return hepta_answer() != 42; }\n")
        executable = self.root / "client"
        subprocess.run([GCC, str(client), str(self.archive), "-o", str(executable)],
                       check=True, capture_output=True, timeout=30)
        result = subprocess.run([str(executable)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_absolute_archiver_works_without_bare_ar(self):
        os.environ["AR"] = AR
        self.assertIsNone(shutil.which("ar"))
        self.assert_archive_usable(self.build())

    def test_named_archiver_on_path_is_used(self):
        self.wrapper()
        os.environ["AR"] = "selected-ar"
        self.assert_archive_usable(self.build())
        self.assertEqual(json.loads(self.log.read_text())[0], "rcs")

    def test_archiver_path_with_spaces_is_one_executable(self):
        os.environ["AR"] = str(self.wrapper("chosen ar"))
        self.assert_archive_usable(self.build())
        self.assertEqual(len(json.loads(self.log.read_text())), 3)

    def test_unset_selection_retains_bare_ar_default(self):
        self.wrapper("ar")
        self.assert_archive_usable(self.build())
        self.assertTrue(self.log.is_file())

    def test_invalid_selection_does_not_fall_back(self):
        self.wrapper("ar")
        for value in ("missing-archiver", "", "ar --version"):
            with self.subTest(selection=value):
                os.environ["AR"] = value
                with self.assertRaises(HeptaError) as caught:
                    self.build()
                self.assertEqual(caught.exception.diagnostic.code, "E_C_TOOLCHAIN")
                self.assertFalse(self.archive.exists())
                self.assertFalse(self.log.exists())

    def test_selected_archiver_failure_propagates(self):
        os.environ["AR"] = str(self.wrapper(exit_code=17))
        with self.assertRaises(subprocess.CalledProcessError) as caught:
            self.build()
        self.assertEqual(caught.exception.returncode, 17)
        self.assertFalse(self.archive.exists())
        self.assertTrue(self.log.is_file())

    def test_check_only_does_not_need_archiver(self):
        os.environ["AR"] = "missing-archiver"
        report = self.build(check_only=True)
        self.assertTrue(report["ok"], report)
        self.assertGreater(report["artifact_bytes"], 0)
        self.assertFalse(self.log.exists())

    def test_object_build_does_not_need_archiver(self):
        os.environ["AR"] = "missing-archiver"
        report = compile_c(SOURCE, cc=GCC, crate_type="obj",
                           output=self.root / "answer.o")
        self.assertTrue(report["ok"], report)
        self.assertGreater(report["artifact_bytes"], 0)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
