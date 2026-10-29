"""Execute the public C pilot against bounded real compiler processes."""
from __future__ import annotations

import os
import ctypes
from pathlib import Path
import platform
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from tools import c2hepta


class C2HeptaCompilerCapture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-pilot-capture-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "input.c"
        self.output = self.root / "output.hepta"
        self.report = self.root / "report.json"
        self.source.write_text("int identity(int x) { return x; }\n")
        self.output.write_text("previous accepted artifact\n")
        self.original = self.source.read_bytes()
        self.previous = self.output.read_bytes()

    def compiler(self, stage="version", action="noise", stream=1):
        executable = self.root / "compiler"
        marker = self.root / "escaped-child"
        child = ("import pathlib,time; time.sleep(.5); "
                 + f"pathlib.Path({str(marker)!r}).write_text('survived')")
        executable.write_text(
            f"#!{sys.executable}\n"
            "import os, subprocess, sys, time\n"
            "args = sys.argv[1:]\n"
            "stage = ('version' if '--version' in args else 'target' if "
            "'-dumpmachine' in args else 'defines' if '-dM' in args else 'ast')\n"
            f"if stage == {stage!r}:\n"
            f"    action = {action!r}\n"
            "    if action == 'noise':\n"
            "        for _ in range(160):\n"
            f"            os.write({stream}, b'x' * 65536)\n"
            "            time.sleep(.001)\n"
            "    elif action in {'child', 'timeout'}:\n"
            f"        subprocess.Popen([sys.executable, '-c', {child!r}])\n"
            "        if action == 'timeout': time.sleep(3)\n"
            "    elif action == 'exit':\n"
            "        sys.stderr.write('deliberate compiler failure')\n"
            "        sys.exit(23)\n"
            "    elif action == 'invalid_utf8':\n"
            "        os.write(1, b'\\xff')\n"
            "        sys.exit(0)\n"
            "    elif action == 'empty':\n"
            "        sys.exit(0)\n"
            "if stage == 'version': print('clang public-pilot-process-probe')\n"
            "elif stage == 'target': print('x86_64-unknown-linux-gnu')\n"
            "elif stage == 'defines': print('#define __SIZEOF_INT__ 4\\n#define __CHAR_BIT__ 8')\n"
            "else: print('{\"kind\":\"TranslationUnitDecl\",\"inner\":[]}')\n")
        executable.chmod(0o755)
        return executable, marker

    def reject(self, executable, reason):
        result = c2hepta.migrate(self.source, self.output, self.report,
                                clang=str(executable))
        self.assertEqual(result["status"], "rejected")
        self.assertIn(reason, result["reason"])
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(self.output.read_bytes(), self.previous)
        self.assertTrue(self.report.is_file())
        return result

    @unittest.skipUnless(os.name == "posix", "executable process probes require POSIX")
    def test_every_clang_stage_enforces_stdout_budget_while_running(self):
        for stage in ("version", "target", "defines", "ast"):
            with self.subTest(stage=stage):
                executable, _ = self.compiler(stage)
                self.reject(executable, "E_CAPTURE_OUTPUT_SIZE")

    @unittest.skipUnless(os.name == "posix", "executable process probes require POSIX")
    def test_ast_diagnostics_enforce_stderr_budget_while_running(self):
        executable, _ = self.compiler("ast", stream=2)
        self.reject(executable, "E_CAPTURE_OUTPUT_SIZE")

    @unittest.skipUnless(os.name == "posix", "executable process probes require POSIX")
    def test_query_timeout_reaps_its_descendant(self):
        executable, marker = self.compiler(action="timeout")
        started = time.monotonic()
        with patch.object(c2hepta, "_CLANG_QUERY_TIMEOUT", .15, create=True):
            self.reject(executable, "E_CAPTURE_TIMEOUT")
        self.assertLess(time.monotonic() - started, 2)
        time.sleep(.65)
        self.assertFalse(marker.exists(), "timed-out compiler descendant survived")

    @unittest.skipUnless(os.name == "posix", "process-group cleanup requires POSIX")
    def test_successful_query_also_reaps_its_descendant(self):
        executable, marker = self.compiler(action="child")
        self.reject(executable, "no source definitions")
        time.sleep(.65)
        self.assertFalse(marker.exists(), "successful compiler query left a descendant")

    @unittest.skipUnless(os.name == "posix", "executable process probes require POSIX")
    def test_nonzero_query_remains_an_explicit_rejection(self):
        executable, _ = self.compiler(action="exit")
        self.reject(executable, "23")

    @unittest.skipUnless(os.name == "posix", "executable process probes require POSIX")
    def test_invalid_utf8_query_is_rejected(self):
        executable, _ = self.compiler(action="invalid_utf8")
        self.reject(executable, "E_CAPTURE_ENCODING")

    @unittest.skipUnless(os.name == "posix", "executable process probes require POSIX")
    def test_empty_successful_version_is_rejected_without_index_error(self):
        executable, _ = self.compiler(action="empty")
        self.reject(executable, "empty version")

    def test_actual_clang_still_converts_and_checks_the_frontend(self):
        compiler = shutil.which("clang")
        self.assertIsNotNone(compiler, "actual Clang is required for this qualification")
        result = c2hepta.migrate(self.source, self.output, self.report, clang=compiler)
        self.assertEqual(result["status"], "converted", result)
        self.assertEqual(result["frontend_validation"], "passed")
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertIn('export "C" fn identity', self.output.read_text())

    @unittest.skipUnless(platform.system() == "Linux", "native ELF differential profile")
    def test_original_c_and_emitted_hepta_have_matching_native_results(self):
        from hepta.backend import compile_rust
        from hepta.clang_capture import run_bounded
        from hepta.pipeline import analyze

        compiler = shutil.which("clang")
        self.assertIsNotNone(compiler, "actual Clang is required for this qualification")
        self.source.write_text("int identity(int x) { return x; }\n"
                               "unsigned int wrap(unsigned int x) { return x + 1U; }\n")
        result = c2hepta.migrate(self.source, self.output, self.report,
                                clang=compiler, verify_native=True)
        self.assertEqual(result["status"], "converted", result)
        self.assertEqual(result["backend_validation"], "passed")
        lowered = analyze(self.output.read_text(), str(self.output), native=False,
                          crate_type="cdylib")
        self.assertIsNotNone(lowered.rust, lowered.report)
        generated = self.root / "generated.so"
        built = compile_rust(lowered.rust, output=generated, crate_type="cdylib")
        self.assertTrue(built["ok"], built)
        original = self.root / "original.so"
        reference = run_bounded([compiler, "-std=c11", "-O2", "-shared", "-fPIC",
                                 str(self.source), "-o", str(original)], timeout=30,
                                stdout_limit=64_000, stderr_limit=256_000)
        self.assertEqual(reference.returncode, 0, reference.stderr)
        c_library, h_library = ctypes.CDLL(str(original)), ctypes.CDLL(str(generated))
        for name, kind, inputs in (
            ("identity", ctypes.c_int32, (-2**31, -1, 0, 1, 2**31-1)),
            ("wrap", ctypes.c_uint32, (0, 1, 255, 2**31, 2**32-1)),
        ):
            expected, actual = getattr(c_library, name), getattr(h_library, name)
            expected.argtypes = actual.argtypes = [kind]
            expected.restype = actual.restype = kind
            for value in inputs:
                with self.subTest(function=name, value=value):
                    self.assertEqual(expected(value), actual(value))


if __name__ == "__main__":
    unittest.main()
