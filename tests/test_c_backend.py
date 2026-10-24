from pathlib import Path
import os
import random
import shutil
import subprocess
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.backend import compile_rust, emit_rust, emit_header
from hepta.c_backend import compile_c, emit_c
from hepta.checker import check
from hepta.parser import parse

ROOT = Path(__file__).resolve().parents[1]
RUSTC = os.environ.get("RUSTC") or shutil.which("rustc") or "/workspace/scratch/69b06e838148/toolchains/rust-1.90.0/bin/rustc"


@unittest.skipUnless(shutil.which("gcc"), "GCC required for independent C backend")
class CBackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-c-tests-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def frontend(self, source):
        program = parse(source)
        checked = check(program)
        self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
        return program, checked

    def execute_pair(self, source, success=True):
        program, checked = self.frontend(source)
        c = compile_c(emit_c(program, checked), output=self.directory / "c-native", sanitize=True)
        self.assertTrue(c["ok"], c["diagnostics"])
        self.assertFalse(c["rustc_used"])
        results = [subprocess.run([c["artifact"]], capture_output=True, text=True)]
        if Path(RUSTC).is_file():
            rust = compile_rust(emit_rust(program, checked, crate_type="bin"), rustc=RUSTC,
                                crate_type="bin", output=self.directory / "rust-native")
            self.assertTrue(rust["ok"], rust["diagnostics"])
            results.append(subprocess.run([rust["artifact"]], capture_output=True, text=True))
        for result in results:
            self.assertEqual(result.returncode == 0, success, result.stderr)
        self.assertNotIn("runtime error:", results[0].stderr)
        if success and len(results) == 2:
            self.assertEqual(results[0].stdout, results[1].stdout)

    def test_safe_borrowed_slices_execute_without_rustc(self):
        source = (ROOT / "benchmarks/borrowed.hepta").read_text()
        program, checked = self.frontend(source)
        old = os.environ.get("RUSTC")
        try:
            os.environ["RUSTC"] = "/nonexistent/rustc"
            report = compile_c(emit_c(program, checked), output=self.directory / "safe", sanitize=True)
            self.assertTrue(report["ok"], report["diagnostics"])
            self.assertEqual(subprocess.run([report["artifact"]]).returncode, 0)
        finally:
            if old is None:
                os.environ.pop("RUSTC", None)
            else:
                os.environ["RUSTC"] = old

    def test_seeded_integer_semantics_differential(self):
        rng = random.Random(20261024)
        lines = ["fn main() -> Unit effects { panic } {"]
        for index in range(24):
            a = rng.randrange(-(1 << 62), 1 << 62)
            b = rng.randrange(1, 10000) * rng.choice([-1, 1])
            def wrap(x):
                return (x + (1 << 63)) % (1 << 64) - (1 << 63)
            q = abs(a) // abs(b) * (-1 if (a < 0) != (b < 0) else 1)
            lines += [f"let a{index}: i64 = {a};", f"let b{index}: i64 = {b};",
                      f"assert(wrapping_add(a{index}, b{index}) == {wrap(a+b)});",
                      f"assert(wrapping_mul(a{index}, b{index}) == {wrap(a*b)});",
                      f"assert(a{index} / b{index} == {q});",
                      f"assert(a{index} % b{index} == {a-q*b});",
                      f"assert((a{index} >> 3) == {a >> 3});",
                      f"assert((a{index} as u64) == {a % (1 << 64)});"]
        lines += ["let x: u16 = 65535; assert(wrapping_mul(x, x) == 1);",
                  "let y: i8 = -128; assert(wrapping_sub(y, 1) == 127);", "}"]
        self.execute_pair("\n".join(lines))

    def test_order_structs_and_short_circuit(self):
        self.execute_pair('''
        struct Pair { x: i64, y: i64 }
        fn step(value: mut i64) -> i64 effects { write, panic } {
            value = value + 1; return value;
        }
        fn combine(a: i64, b: i64) -> i64 effects { panic } { return a * 10 + b; }
        fn main() -> Unit effects { write, panic } {
            let mut value: i64 = 0;
            let pair: Pair = Pair { x: step(mut value), y: step(mut value) };
            assert(pair.x == 1); assert(pair.y == 2);
            assert(combine(step(mut value), step(mut value)) == 34);
            assert(true || (1 / 0 == 0));
        }
        ''')

    def test_runtime_failures_match_rust_abort_behavior(self):
        for helper, body in [
            ("fn danger(x: i32, y: i32) -> i32 effects { panic } { return x + y; }", "let y = danger(2147483647, 1);"),
            ("fn danger(x: i64, y: i64) -> i64 effects { panic } { return x / y; }", "let y = danger(-9223372036854775808, -1);"),
            ("fn danger(x: u64, y: u64) -> u64 effects { panic } { return x << y; }", "let y = danger(1, 64);"),
            ("fn danger(data: read [i32], index: usize) -> i32 effects { panic } { return data[index]; }", "let data: [i32; 2] = [1, 2]; let x = danger(read data, 2);")]:
            with self.subTest(body=body):
                self.execute_pair(helper + " fn main() -> Unit effects { panic } { " + body + " }", success=False)

    def test_overlapping_borrows_are_independently_rejected(self):
        source = '''fn bad(a: mut i32, b: read i32) -> Unit effects { write } { a = b; }
        fn main() -> Unit effects { write } { let mut x: i32 = 1; bad(mut x, read x); }'''
        program, checked = self.frontend(source)
        with self.assertRaises(HeptaError) as error:
            emit_c(program, checked)
        self.assertEqual(error.exception.diagnostic.code, "E_C_BORROW")

    def test_unsupported_semantics_are_explicit_errors(self):
        for source, code in [
            ("fn main() -> Unit effects { alloc, block, panic } { let x = buffer(4); release(move x); }", "E_C_BACKEND_SUBSET"),
            ("fn main() -> Unit effects {} { let x: i32 = 3.5 as i32; }", "E_C_BACKEND_CAST")]:
            program, checked = self.frontend(source)
            with self.assertRaises(HeptaError) as error:
                emit_c(program, checked)
            self.assertEqual(error.exception.diagnostic.code, code)

    def test_c_backend_real_bidirectional_abi(self):
        program, checked = self.frontend((ROOT / "examples/ffi/abi.hepta").read_text())
        (self.directory / "abi.h").write_text(emit_header(program))
        c = compile_c(emit_c(program, checked, crate_type="staticlib"), crate_type="staticlib",
                      output=self.directory / "libindependent.a")
        self.assertTrue(c["ok"], c["diagnostics"])
        executable = self.directory / "abi"
        subprocess.run(["gcc", "-std=c11", "-Werror", "-I", str(self.directory),
                        str(ROOT / "examples/ffi/harness.c"), c["artifact"], "-lm", "-o", str(executable)], check=True, capture_output=True)
        self.assertEqual(subprocess.run([executable], capture_output=True).returncode, 0)

    def test_check_only_produces_real_nonempty_native_object(self):
        program, checked = self.frontend("fn main() -> Unit effects {} {}")
        output = self.directory / "checked.o"
        report = compile_c(emit_c(program, checked), output=output, check_only=True)
        self.assertTrue(report["ok"], report["diagnostics"])
        self.assertGreater(output.stat().st_size, 0)
        self.assertTrue(output.read_bytes().startswith(b"\x7fELF"))


if __name__ == "__main__":
    unittest.main()
