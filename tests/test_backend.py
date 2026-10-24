"""End-to-end semantic checks through an actual native compiler."""
import subprocess
import tempfile
import unittest
from pathlib import Path

from hepta.backend import compile_rust, find_rustc
from hepta.pipeline import analyze


class BackendTests(unittest.TestCase):
    def run_native(self, source):
        checked = analyze(source, crate_type="bin")
        self.assertTrue(checked.report["ok"], checked.report)
        with tempfile.TemporaryDirectory() as td:
            built = compile_rust(checked.rust, output=Path(td)/"program", crate_type="bin")
            self.assertTrue(built["ok"], built)
            return subprocess.run([built["artifact"]], capture_output=True, timeout=10)

    def test_borrowed_scalar_read_and_write_preserve_values(self):
        p = self.run_native('''
        fn read_value(x: read i64) -> i64 effects {} { return x; }
        fn write_value(x: mut i64) -> Unit effects {write} { x = 42; }
        fn main() -> i32 effects {write,panic} {
          let mut x: i64 = 2;
          write_value(mut x);
          assert(read_value(read x) == 42);
          return 0;
        }''')
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_rust_rejects_overlapping_mutable_borrows(self):
        s = '''fn f(x: mut i64, y: mut i64) -> Unit effects {write} { x = y; }
        fn main() -> Unit effects {write} { let mut x: i64 = 1; f(mut x, mut x); }'''
        result = analyze(s)
        self.assertFalse(result.report["ok"])
        self.assertTrue(any(d["code"] == "E0499" for d in result.report["diagnostics"]), result.report)

    def test_overflow_checks_remain_enabled_at_opt3(self):
        p = self.run_native('''fn main() -> i32 effects {panic} {
          let mut x: u8 = 255;
          for i in 0..1 { x = x + 1; }
          return 0;
        }''')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(b"overflow", p.stderr)

    def test_explicit_wrapping_has_same_release_semantics(self):
        p = self.run_native('''fn main() -> i32 effects {panic} {
          let x: u8 = 255;
          assert(wrapping_add(x, 1) == 0);
          return 0;
        }''')
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_bounds_check_remains_effective(self):
        p = self.run_native('''fn at(xs: read [u8], i: usize) -> u8 effects {panic} { return xs[i]; }
        fn main() -> i32 effects {panic} {
          let xs: [u8; 1] = [4];
          let result: u8 = at(read xs, 2);
          return result as i32;
        }''')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(b"out of bounds", p.stderr)

    def test_failed_build_cannot_replace_previous_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td)/"artifact"
            dest.write_bytes(b"existing verified artifact")
            result = compile_rust("fn broken( {", output=dest)
            self.assertFalse(result["ok"])
            self.assertEqual(dest.read_bytes(), b"existing verified artifact")

    def test_pinned_toolchain_must_really_emit_metadata(self):
        result = analyze("fn answer() -> i64 effects {} { return 42; }")
        self.assertTrue(result.report["ok"], result.report)
        self.assertEqual(len(result.report["backend"]["validation_artifact_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
