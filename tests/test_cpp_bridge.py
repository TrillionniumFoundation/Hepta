"""Actual C -> C++ runtime ABI round-trip for narrow, fail-closed L0 bridge."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.cpp_bridge import generate_cpp_bridge, main
from hepta.c2hepta import MigrationRejected


CLANGXX = shutil.which("clang++")
CC = shutil.which("gcc") or shutil.which("clang")


@unittest.skipUnless(CLANGXX and CC, "Requires actual clang++ and a C compiler")
class CppBridgeTests(unittest.TestCase):
    SOURCE = """int native_add(int a, int b) noexcept { return a + b; }
int native_square(int x) noexcept { return x * x; }
"""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.original = self.root / "original.cc"
        self.original.write_text(self.SOURCE)

    def test_actual_c_cxx_link_and_run(self):
        result = generate_cpp_bridge(self.original, clangxx=CLANGXX)
        self.assertEqual(result.report["interop_level"], "L0")
        self.assertEqual(result.report["status"], "candidate_unverified")
        self.assertFalse(result.report["foreign_cpp_memory_safe"])
        self.assertFalse(result.report["cpp_abi_qualified"])
        self.assertEqual(result.report["exception_translation"], "not_implemented")
        bridge = self.root / "bridge.cc"
        header = self.root / "bridge.h"
        caller = self.root / "caller.c"
        bridge.write_text(result.source)
        header.write_text(result.c_header)
        caller.write_text('''#include "bridge.h"
int main(void) {
    return (hepta_cxx_native_add(7,4) == 11 &&
            hepta_cxx_native_add(-7,4) == -3 &&
            hepta_cxx_native_square(12) == 144) ? 0 : 1;
}
''')
        for optimization in ("-O0", "-O2"):
            c_obj = self.root / f"caller{optimization}.o"
            exe = self.root / f"caller{optimization}"
            subprocess.run([CC, "-std=c11", optimization, "-Wall", "-Wextra", "-Werror",
                            "-c", str(caller), "-o", str(c_obj)], check=True, capture_output=True, timeout=20)
            subprocess.run([CLANGXX, "-std=c++20", optimization, str(c_obj), str(self.original),
                            str(bridge), "-o", str(exe)], check=True, capture_output=True, timeout=30)
            self.assertEqual(subprocess.run([str(exe)], timeout=10).returncode, 0)

    def test_status_bridge_catches_exception_and_runs_raii_cleanup(self):
        # The original implementation keeps C++ RAII semantics inside the boundary.
        self.original.write_text("""int guarded(int input) {
    static int destroyed = 0;
    struct Guard { int *p; ~Guard() { ++*p; } };
    if (input == 99) return destroyed;
    Guard guard{&destroyed};
    if (input < 0) throw 7;
    return input + 3;
}
int zero() { return 41; }
""")
        result = generate_cpp_bridge(self.original, clangxx=CLANGXX,
                                     exception_mode="catch_status")
        self.assertEqual(result.report["schema"], "hepta.cpp-bridge.v1")
        self.assertEqual(result.report["exception_mode"], "catch_status")
        self.assertFalse(result.report["exception_crosses_c_abi"])
        self.assertEqual(result.report["exception_translation"], "status_without_exception_payload")
        self.assertFalse(result.report["foreign_cpp_memory_safe"])
        bridge = self.root / "catch_bridge.cc"
        header = self.root / "bridge.h"
        caller = self.root / "catch_caller.c"
        bridge.write_text(result.source)
        header.write_text(result.c_header)
        caller.write_text('''#include "bridge.h"
int main(void) {
    int out = 501;
    if (hepta_cxx_guarded(-1, &out) != 1 || out != 501) return 1;
    if (hepta_cxx_guarded(99, &out) != 0 || out != 1) return 2;
    if (hepta_cxx_guarded(5, &out) != 0 || out != 8) return 3;
    if (hepta_cxx_guarded(99, &out) != 0 || out != 2) return 4;
    if (hepta_cxx_guarded(5, 0) != -1) return 5;
    if (hepta_cxx_zero(&out) != 0 || out != 41) return 6;
    return 0;
}
''')
        for optimization in ("-O0", "-O2"):
            caller_obj = self.root / f"catch_{optimization}.o"
            exe = self.root / f"catch_{optimization}"
            subprocess.run([CC, "-std=c11", optimization, "-Wall", "-Wextra", "-Werror",
                            "-c", str(caller), "-o", str(caller_obj)],
                           check=True, capture_output=True, timeout=20)
            subprocess.run([CLANGXX, "-std=c++20", optimization, str(caller_obj),
                            str(self.original), str(bridge), "-o", str(exe)],
                           check=True, capture_output=True, timeout=30)
            self.assertEqual(subprocess.run([str(exe)], timeout=10).returncode, 0)

    def test_mode_rejects_invalid_mode_and_default_stays_noexcept(self):
        with self.assertRaisesRegex(MigrationRejected, "E_CPP_BRIDGE_MODE"):
            generate_cpp_bridge(self.original, exception_mode="swallow")
        self.original.write_text("int can_throw(int x) { if (x) throw x; return 0; }")
        with self.assertRaises(MigrationRejected):
            generate_cpp_bridge(self.original, exception_mode="noexcept_only")
        caught = generate_cpp_bridge(self.original, exception_mode="catch_status")
        self.assertIn("catch (...) {", caught.source)
        self.assertIn("int *result_out", caught.c_header)

    def test_unsupported_semantics_fail_closed(self):
        for source in (
            "int f(int a) { return a; }",  # noexcept required
            "int f(int *a) noexcept { return *a; }",  # raw-pointer boundary
            "int f(int a) noexcept { return a; } int f(int a, int b) noexcept { return a+b; }",
            "int g = 7; int f(int a) noexcept { return a; }",  # global
            "class Thing {}; int f(int a) noexcept { return a; }",
            "template<class T> T f(T a) noexcept { return a; }",
            "#include <vector>\nint f(int a) noexcept { return a; }",
            "int f(int a=3) noexcept {return a;}",
            "int f(int a [[maybe_unused]]) noexcept {return 1;}",
        ):
            with self.subTest(source=source):
                self.original.write_text(source)
                with self.assertRaises(MigrationRejected):
                    generate_cpp_bridge(self.original, clangxx=CLANGXX)

    def test_cli_refuses_overwriting_existing_directory(self):
        existing = self.root / "out"
        existing.mkdir()
        (existing / "important.txt").write_text("keep")
        self.assertEqual(main([str(self.original), "--clangxx", CLANGXX,
                               "--output-dir", str(existing)]), 1)
        self.assertEqual((existing / "important.txt").read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
