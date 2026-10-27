"""P3/P4: strict C11/C++20 boolean migration through one C-shaped lowerer.

The originals are compiled independently. Hepta is compiled through its
ordinary checked frontend and C backend; finite defined-domain comparison is
not a whole-source equivalence or memory-safety theorem.
"""
from __future__ import annotations

import ctypes
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.c_migrate import migrate_c
from hepta.cpp2hepta import migrate_cpp
from hepta.pipeline import analyze


SOURCE = """
int choose(int x,int y) NOEXCEPT {
    if ((x < 0 || x > 20) && !(y == 0)) return 3;
    return 1;
}
int numeric(int x,int y) NOEXCEPT {
    if (x && y) return 9;
    return 2;
}
int conditional(int x,int y) NOEXCEPT {
    return (x && y > 5) ? 7 : 2;
}
int invert(int x,int y) NOEXCEPT {
    if (!(x < 0) || y) return 5;
    return 6;
}
int loop(int x,int y) NOEXCEPT {
    int count = 0;
    int i = x;
    while (i && y > 0) {
        count = count + 1;
        i = i - 1;
    }
    return count;
}
"""

CPP_WRAPPERS = """
int choose(int,int) noexcept;
int numeric(int,int) noexcept;
int conditional(int,int) noexcept;
int invert(int,int) noexcept;
int loop(int,int) noexcept;
extern "C" int cpp_choose(int x,int y) { return choose(x,y); }
extern "C" int cpp_numeric(int x,int y) { return numeric(x,y); }
extern "C" int cpp_conditional(int x,int y) { return conditional(x,y); }
extern "C" int cpp_invert(int x,int y) { return invert(x,y); }
extern "C" int cpp_loop(int x,int y) { return loop(x,y); }
"""

# The loop's x parameter is nonnegative in the tested domain. For negative x,
# repeated signed decrement can overflow in C/C++; those inputs are not tested.
BOUNDS = (-2**31, -21, -1, 0, 1, 2, 20, 21, 2**31 - 1)
OTHERS = (-2**31, -1, 0, 1, 5, 6, 2**31 - 1)


@unittest.skipUnless(shutil.which("clang") and shutil.which("clang++") and
                     shutil.which("gcc"), "Requires GCC and Clang native hosts")
class LogicalPredicates(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hepta-logic-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _candidate(self, language):
        suffix = ".cc" if language == "cpp" else ".c"
        source = self.root / ("original" + suffix)
        source.write_text(SOURCE.replace(" NOEXCEPT", " noexcept" if language == "cpp" else ""),
                          encoding="utf-8")
        output = self.root / ("migrated_" + language + ".hepta")
        report = migrate_cpp(source, output) if language == "cpp" else migrate_c(source, output)
        self.assertTrue(report["ok"], report)
        self.assertFalse(report["behavioral_equivalence_proved"] if language == "cpp"
                         else report["source_equivalence_proved"])
        text = output.read_text(encoding="utf-8")
        self.assertIn("&&", text)
        self.assertIn("||", text)
        self.assertIn("!(", text)
        self.assertIn("!= 0", text)
        self.assertEqual(analyze(text, str(output), native=False).report["status"],
                         "frontend_only")
        return source, output

    def test_native_C_and_CPP_reference_against_generated_Hepta_C(self):
        for language in ("c", "cpp"):
            with self.subTest(language=language):
                source, translated = self._candidate(language)
                wrapper = self.root / "wrapper.cc"
                original_so = self.root / ("reference_" + language + ".so")
                if language == "cpp":
                    wrapper.write_text(CPP_WRAPPERS, encoding="utf-8")
                    cmd = ["clang++", "-std=c++20", "-O2", "-fPIC", "-shared",
                           str(source), str(wrapper), "-o", str(original_so)]
                else:
                    cmd = ["gcc", "-std=c11", "-O2", "-fPIC", "-shared",
                           str(source), "-o", str(original_so)]
                old_build = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                self.assertEqual(old_build.returncode, 0, old_build.stderr)
                translated_so = self.root / ("hepta_" + language + ".so")
                build = subprocess.run(
                    [sys.executable, "-m", "hepta", "build", str(translated),
                     "--backend", "c", "--crate-type", "cdylib", "-o", str(translated_so)],
                    capture_output=True, text=True, timeout=100)
                self.assertEqual(build.returncode, 0, build.stderr + build.stdout)
                old, new = ctypes.CDLL(str(original_so)), ctypes.CDLL(str(translated_so))
                for function in ("choose", "numeric", "conditional", "invert", "loop"):
                    ref = getattr(old, "cpp_" + function if language == "cpp" else function)
                    migrated = getattr(new, function)
                    for fn in (ref, migrated):
                        fn.argtypes = [ctypes.c_int32, ctypes.c_int32]
                        fn.restype = ctypes.c_int32
                    xs = (0, 1, 2, 7, 20) if function == "loop" else BOUNDS
                    ys = (-1, 0, 1, 5, 6) if function == "loop" else OTHERS
                    for x in xs:
                        for y in ys:
                            with self.subTest(language=language, function=function,
                                              x=x, y=y):
                                self.assertEqual(migrated(x, y), ref(x, y))


    def test_side_effecting_and_unknown_truth_values_fail_closed(self):
        invalid = (
            ("c", "int bad(int x,int y){if(x && ++y)return 1;return 0;}"),
            ("c", "int bad(int x,int y){if(x || (y=1))return 1;return 0;}"),
            ("cpp", "int bad(int x,int y) noexcept {if(x && y++)return 1;return 0;}"),
            ("cpp", "int bad(int x,int y) noexcept {if(x || (y=1))return 1;return 0;}"),
            ("c", "int bad(int *p,int x){if(p && x)return 1;return 0;}"),
        )
        for index, (language, code) in enumerate(invalid):
            with self.subTest(language=language, source=code):
                source = self.root / ("bad_" + str(index) +
                                      (".cc" if language == "cpp" else ".c"))
                source.write_text(code, encoding="utf-8")
                output = self.root / ("rejected_" + str(index) + ".hepta")
                result = migrate_cpp(source, output) if language == "cpp" else migrate_c(source, output)
                self.assertFalse(result["ok"], result)
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
