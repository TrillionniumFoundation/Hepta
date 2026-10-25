"""Finite host SSA-native measurement harness qualification and negatives."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools.ssa_native_benchmark import qualify


@unittest.skipUnless(shutil.which("clang"), "native Clang host required")
class NativeSSABenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.library = self.root / "libf.so"
        source = self.root / "f.c"
        source.write_text(
            "#include <stdint.h>\n"
            "int32_t f(int32_t n){int32_t x=0,total=0;"
            "while(x<n){if(x<4)total+=x;else total+=1;x++;}return total;}\n")
        subprocess.run(["clang", "-O3", "-shared", "-fPIC",
                        str(source), "-o", str(self.library)],
                       check=True, capture_output=True, timeout=25)

    def test_host_native_receipts_and_finite_correctness(self):
        report = qualify(self.library, symbol="f", output=self.root / "results.json",
                         iterations=2500, trials=3, bound=20, seed=20261024)
        self.assertEqual(report["schema"], "hepta.p6.ssa-perf.v0")
        self.assertEqual(report["status"], "completed_host_sample_not_proof")
        self.assertEqual(len(report["raw_samples"]), 6)
        self.assertEqual({x["implementation"] for x in report["raw_samples"]},
                         {"hepta_llvm_ssa", "independent_c"})
        self.assertGreater(report["observed_median_hepta_over_c"], 0)
        self.assertFalse(report["claims"]["whole_language_faster_than_rust_or_c"])
        self.assertFalse(report["claims"]["service_p99_qualified"])
        self.assertEqual(json.loads((self.root / "results.json").read_text())["library_sha256"],
                         report["library_sha256"])

    def test_refuses_overwrite_unbounded_and_wrong_result(self):
        output = self.root / "existing.json"
        output.write_text("sentinel")
        with self.assertRaisesRegex(ValueError, "OUTPUT"):
            qualify(self.library, symbol="f", output=output, iterations=2500, trials=3)
        self.assertEqual(output.read_text(), "sentinel")
        with self.assertRaisesRegex(ValueError, "LIMIT"):
            qualify(self.library, symbol="f", output=self.root / "other.json",
                    iterations=0, trials=3)
        src = self.root / "bad.c"
        broken = self.root / "libbad.so"
        src.write_text("#include <stdint.h>\nint32_t f(int32_t n){(void)n;return 0;}\n")
        subprocess.run(["clang", "-O3", "-shared", "-fPIC", str(src), "-o", str(broken)],
                       check=True, capture_output=True, timeout=25)
        with self.assertRaisesRegex(RuntimeError, "CORRECTNESS"):
            qualify(broken, symbol="f", output=self.root / "bad.json",
                    iterations=2500, trials=3, bound=20)
        self.assertFalse((self.root / "bad.json").exists())


if __name__ == "__main__":
    unittest.main()
