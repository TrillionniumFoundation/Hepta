"""Native child fault isolation, finite denominator and source-oracle checks.

The C shared library is only an independent *transport* control: it is not a
Hepta native compiler qualification. The second test class uses real Hepta.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_native_differential import (HIADifferentialRejected,
    compare_oracle_with_native, qualify_scalar_source)
from hepta.hia_oracle import HIAOracleBudgetExceeded, HIAOracleTrap


class _ScalarOracle:
    return_words = (("checked_add", "i32"), ("max_unsigned", "u32"))

    def run(self, name, args, *, max_steps=20000):
        if name == "checked_add":
            value = args[0] + args[1]
            if not -(2**31) <= value <= 2**31 - 1:
                raise HIAOracleTrap("checked signed overflow")
            return value
        return max(args)


@unittest.skipUnless(shutil.which("clang"), "native Clang required for child ABI control")
class ChildBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="hia-differential-control-")
        cls.library = Path(cls.temp.name) / "controlled.so"
        c_file = Path(cls.temp.name) / "controlled.c"
        c_file.write_text('''#include <stdint.h>
#include <stdlib.h>
int32_t checked_add(int32_t a, int32_t b) {
    int64_t value = (int64_t)a + b;
    if (value > 2147483647LL || value < (-2147483647LL-1)) abort();
    return (int32_t)value;
}
uint32_t max_unsigned(uint32_t a, uint32_t b) { return a > b ? a : b; }
''', encoding="utf-8")
        subprocess.run(["clang", "-O2", "-shared", "-fPIC", str(c_file),
                        "-o", str(cls.library)], check=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_real_signal_and_both_integer_abi_words(self):
        cases = {
            "checked_add": [[0, 0], [2, 5], [-3, 2], [2**31 - 1, 1], [-2**31, -1]],
            "max_unsigned": [[0, 2**32 - 1], [2**32 - 1, 0], [20, 20]],
        }
        report = compare_oracle_with_native(_ScalarOracle(), self.library, cases)
        self.assertEqual(report["cases_executed"], 8)
        self.assertEqual(report["defined_traps_observed"], 2)
        self.assertFalse(report["claims"]["backend_refinement_proved"])
        self.assertTrue(report["claims"]["finite_native_oracle_match"])
        self.assertFalse(report["claims"]["checked_hepta_source_replayed"])

    def test_missing_export_and_python_bool_do_not_count(self):
        for malformed in (
            {"checked_add": [[1, 2]]},
            {"checked_add": [[True, 2]], "max_unsigned": [[1, 2]]},
            {"checked_add": [], "max_unsigned": [[1, 2]]},
        ):
            with self.subTest(malformed=str(malformed)[:40]):
                with self.assertRaisesRegex(HIADifferentialRejected, "E_HIA_DIFFERENTIAL"):
                    compare_oracle_with_native(_ScalarOracle(), self.library, malformed)

    def test_real_mismatch_cannot_be_qualified(self):
        class WrongOracle(_ScalarOracle):
            def run(self, name, args, *, max_steps=20000):
                if name == "checked_add":
                    return 0
                return max(args)
        with self.assertRaisesRegex(HIADifferentialRejected, "native mismatch"):
            compare_oracle_with_native(WrongOracle(), self.library,
                {"checked_add": [[2, 5]], "max_unsigned": [[1, 2]]})

    def test_oracle_budget_is_never_reclassified_as_native_trap(self):
        class TimedOut(_ScalarOracle):
            def run(self, name, args, *, max_steps=20000):
                raise HIAOracleBudgetExceeded("artificial bounded refusal")
        with self.assertRaisesRegex(HIADifferentialRejected, "oracle failed"):
            compare_oracle_with_native(TimedOut(), self.library,
                {"checked_add": [[1, 2]], "max_unsigned": [[1, 2]]})

    def test_not_a_valid_library_cannot_be_passed_off_as_compiled(self):
        altered = Path(self.temp.name) / "not-an-elf.so"
        altered.write_bytes(b"not compiled native code")
        with self.assertRaises(HIADifferentialRejected):
            compare_oracle_with_native(_ScalarOracle(), altered,
                {"checked_add": [[1, 2]], "max_unsigned": [[1, 2]]})

    def test_native_segfault_must_not_count_as_matched_arithmetic_trap(self):
        source = Path(self.temp.name) / "segfault.c"
        library = Path(self.temp.name) / "segfault.so"
        source.write_text('#include <stdint.h>\n#include <signal.h>\n'
                          'int32_t checked_add(int32_t a,int32_t b){raise(SIGSEGV);return a+b;}\n'
                          'uint32_t max_unsigned(uint32_t a,uint32_t b){return a>b?a:b;}\n')
        subprocess.run(["clang", "-shared", "-fPIC", str(source), "-o", str(library)],
                       check=True, timeout=30)
        with self.assertRaisesRegex(HIADifferentialRejected, "unexpected error/signal"):
            compare_oracle_with_native(_ScalarOracle(), library,
                {"checked_add": [[2**31 - 1, 1]], "max_unsigned": [[1, 2]]})

    def test_native_stdout_flood_rejected_by_file_backed_capture(self):
        source = Path(self.temp.name) / "output.c"
        library = Path(self.temp.name) / "output.so"
        source.write_text('#include <stdint.h>\n#include <stdio.h>\n'
                          'int32_t checked_add(int32_t a,int32_t b){'
                          'for(int i=0;i<9000;i++)putchar(120);return a+b;}\n'
                          'uint32_t max_unsigned(uint32_t a,uint32_t b){return a>b?a:b;}\n')
        subprocess.run(["clang", "-shared", "-fPIC", str(source), "-o", str(library)],
                       check=True, timeout=30)
        with self.assertRaisesRegex(HIADifferentialRejected, "output budget"):
            compare_oracle_with_native(_ScalarOracle(), library,
                {"checked_add": [[1, 2]], "max_unsigned": [[1, 2]]})


_NATIVE_SOURCE = '''module hia_native_differential;
export "C" fn checked_add(a: i32, b: i32) -> i32 effects {panic} {
    return a + b;
}
export "C" fn max_unsigned(a: u32, b: u32) -> u32 effects {} {
    if a < b { return b; } else { return a; }
}
'''


@unittest.skipUnless(shutil.which("clang") and
    (os.environ.get("RUSTC") or shutil.which("rustc")),
    "source-native test requires Clang and pinned Rust")
class RealHeptaEndToEndTests(unittest.TestCase):
    def test_real_source_replayed_llvm_vs_oracle_and_traps(self):
        with tempfile.TemporaryDirectory(prefix="hia-differential-source-") as temp:
            source = Path(temp) / "input.hepta"
            source.write_text(_NATIVE_SOURCE, encoding="utf-8")
            cases = {
                "checked_add": [[0, 0], [-15, 2], [2**31 - 1, 0],
                                [2**31 - 1, 1], [-2**31, -1]],
                "max_unsigned": [[0, 2**32 - 1], [2**32 - 1, 0], [42, 42]],
            }
            result = qualify_scalar_source(source, cases, rustc=os.environ.get("RUSTC"))
            self.assertEqual(result["status"],
                             "finite_native_observations_match_oracle_not_proved")
            self.assertEqual(result["cases_executed"], 8)
            self.assertEqual(result["defined_traps_observed"], 2)
            self.assertFalse(result["claims"]["whole_language_soundness_proved"])
            self.assertTrue(result["claims"]["checked_hepta_source_replayed"])
            self.assertEqual(len(result["hia_core_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
