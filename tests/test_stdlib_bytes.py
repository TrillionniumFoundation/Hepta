"""Real local-package codec checks; select c (default) or rust explicitly.

No native tool is optional: a missing selected compiler fails this suite.
Python's bytes/int conversions are the independent byte-order oracle.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.backend import compile_rust
from hepta.c_backend import compile_c
from hepta.packages import load_package, verify_lock, write_lock
from hepta.pipeline import analyze_project


ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "stdlib/bytes"
BACKEND = os.environ.get("HEPTA_BYTES_BACKEND", "c")
CONTRACT = ("resources { heap_allocations = 0; may_block = false; "
            "may_suspend = false; may_spawn = false; }")


class ByteCodecTests(unittest.TestCase):
    def setUp(self):
        self.assertIn(BACKEND, {"c", "rust"})
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-stdlib-bytes-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(LIBRARY, self.root / "bytes")
        self.app = self.root / "app"
        (self.app / "src").mkdir(parents=True)
        (self.app / "hepta.toml").write_text(
            '[package]\nname = "codec_test"\nversion = "0.1.0"\nkind = "bin"\n'
            '[dependencies]\ncodec = { path = "../bytes" }\n', encoding="utf-8")

    def source(self, body):
        entry = self.app / "src/main.hepta"
        entry.write_text("import codec;\nfn main() -> Unit effects { panic, write }\n"
                         + CONTRACT + "\n{\n" + body + "\n}\n", encoding="utf-8")
        write_lock(self.app)
        return entry

    def execute(self, body):
        self.source(body)
        analysis = analyze_project(self.app, backend=BACKEND, crate_type="bin", locked=True)
        self.assertTrue(analysis.report["ok"], analysis.report)
        self.assertEqual(len(analysis.project.modules), 2)
        self.assertTrue(analysis.report["project"]["locked"])
        for optimize in (False, True):
            artifact = self.root / ("optimized" if optimize else "unoptimized")
            if BACKEND == "c":
                native = compile_c(analysis.c, output=artifact, optimize=optimize, sanitize=True)
                self.assertFalse(native["rustc_used"])
                self.assertIn("-fsanitize=undefined", native["flags"])
            else:
                native = compile_rust(analysis.rust, output=artifact, crate_type="bin", optimize=optimize)
            self.assertTrue(native["ok"], native)
            self.assertGreater(native["artifact_bytes"], 0)
            executed = subprocess.run([str(artifact)], capture_output=True, text=True, timeout=15)
            self.assertEqual(executed.returncode, 0, executed.stderr)
            self.assertEqual(executed.stdout, "")
            self.assertEqual(executed.stderr, "")

    @staticmethod
    def array(data):
        return "[" + ", ".join(map(str, data)) + "]"

    def oracle_cases(self, bits, order):
        rng = random.Random(20261105 + bits)
        width, byteorder = bits // 8, {"le": "little", "be": "big"}[order]
        values = [0, 1, (1 << bits) - 1, 1 << (bits - 1),
                  int.from_bytes(bytes(range(1, width + 1)), "big"),
                  int.from_bytes(bytes([0xAA, 0x55] * (width // 2)), "big")]
        values += [rng.getrandbits(bits) for _ in range(18)]
        lines = []
        for case, value in enumerate(values):
            offset = (0, 1, 16 - width)[case % 3]
            before = bytes(rng.randrange(256) for _ in range(16))
            expected = bytearray(before)
            expected[offset:offset + width] = value.to_bytes(width, byteorder)
            lines += [f"let mut target{case}: [u8; 16] = {self.array(before)};",
                      f"assert(codec::write_u{bits}_{order}(mut target{case}, {offset}, {value}));"]
            # Compare all bytes, including both sentinels. Round trips alone are not an oracle.
            lines += [f"assert(target{case}[{i}] == {byte});" for i, byte in enumerate(expected)]
            lines += [f"let roundtrip{case} = codec::read_u{bits}_{order}(read target{case}, {offset});",
                      f"assert(roundtrip{case}.ok && roundtrip{case}.value == {value});"]
            # Read arbitrary independent bytes, not output produced by the paired writer.
            data = bytes(rng.randrange(256) for _ in range(16))
            expected_read = int.from_bytes(data[offset:offset + width], byteorder)
            lines += [f"let input{case}: [u8; 16] = {self.array(data)};",
                      f"let result{case} = codec::read_u{bits}_{order}(read input{case}, {offset});",
                      f"assert(result{case}.ok && result{case}.value == {expected_read});"]
        self.execute("\n".join(lines))

    def test_u16_le_python_oracle(self):
        self.oracle_cases(16, "le")

    def test_u16_be_python_oracle(self):
        self.oracle_cases(16, "be")

    def test_u32_le_python_oracle(self):
        self.oracle_cases(32, "le")

    def test_u32_be_python_oracle(self):
        self.oracle_cases(32, "be")

    def test_u64_le_python_oracle(self):
        self.oracle_cases(64, "le")

    def test_u64_be_python_oracle(self):
        self.oracle_cases(64, "be")

    def bounds_cases(self, bits):
        width, lines, case = bits // 8, [], 0
        for order in ("le", "be"):
            for length in sorted({1, width - 1, width, width + 3}):
                offsets = {0, 1, max(0, length - width), max(0, length - width + 1),
                           length, length + 1, (1 << 64) - 1}
                for offset in sorted(offsets):
                    before = bytes((i * 31 + 17) % 256 for i in range(length))
                    valid = offset + width <= length
                    expected_read = int.from_bytes(before[offset:offset + width],
                                                   "little" if order == "le" else "big") if valid else 0
                    expected = bytearray(before)
                    if valid:
                        expected[offset:offset + width] = bytes([255] * width)
                    lines += [f"let mut buf{case}: [u8; {length}] = {self.array(before)};",
                              f"let read{case} = codec::read_u{bits}_{order}(read buf{case}, {offset});",
                              f"assert(read{case}.ok == {str(valid).lower()});",
                              f"assert(read{case}.value == {expected_read});",
                              f"assert(codec::write_u{bits}_{order}(mut buf{case}, {offset}, {(1 << bits) - 1}) == {str(valid).lower()});"]
                    lines += [f"assert(buf{case}[{i}] == {byte});" for i, byte in enumerate(expected)]
                    case += 1
        self.execute("\n".join(lines))

    def test_u16_bounds_and_failed_writes(self):
        self.bounds_cases(16)

    def test_u32_bounds_and_failed_writes(self):
        self.bounds_cases(32)

    def test_u64_bounds_and_failed_writes(self):
        self.bounds_cases(64)

    def test_resource_contracts_and_both_frontends(self):
        self.source("let data: [u8; 2] = [1, 2]; let result = codec::read_u16_be(read data, 0); assert(result.ok);")
        for backend in ("c", "rust"):
            analysis = analyze_project(self.app, backend=backend, crate_type="bin", native=False)
            report = analysis.report
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["status"], "frontend_only")
            self.assertEqual(len(report["effects"]), 13)
            for effects in report["effects"].values():
                self.assertLessEqual(set(effects), {"panic", "write"})
            for function in analysis.program.functions:
                self.assertEqual(function.resources, {"heap_allocations": 0, "may_block": False,
                                                      "may_suspend": False, "may_spawn": False})
        no_std = analyze_project(self.root / "bytes", backend="rust", crate_type="obj", no_std=True, native=False)
        self.assertTrue(no_std.report["ok"], no_std.report)
        self.assertIn("#![no_std]", no_std.rust)
        # The selected Rust CI lane additionally builds the actual no_std object.
        if BACKEND == "rust":
            native = compile_rust(no_std.rust, crate_type="obj", output=self.root / "bytes.o")
            self.assertTrue(native["ok"], native)
            self.assertGreater(native["artifact_bytes"], 0)

    def test_invalid_consumers_reject(self):
        invalid = [
            ("let data: [u16; 2] = [1, 2]; let r = codec::read_u16_le(read data, 0);", "E_TYPE"),
            ("let data: [u8; 2] = [1, 2]; let r = codec::read_u16_le(data, 0);", "E_BORROW_MODE"),
            ("let data: [u8; 2] = [1, 2]; let ok = codec::write_u16_le(mut data, 0, 7);", "E_IMMUTABLE"),
        ]
        for body, code in invalid:
            with self.subTest(body=body):
                self.source(body)
                report = analyze_project(self.app, backend=BACKEND, native=False).report
                self.assertFalse(report["ok"], report)
                self.assertTrue(any(d["code"] == code for d in report["diagnostics"]), report)
        self.source("let data: [u8; 2] = [1, 2]; let r = codec::read_u16_le(read data, 0);")
        entry = self.app / "src/main.hepta"
        entry.write_text(entry.read_text().replace("effects { panic, write }", "effects {}"))
        report = analyze_project(self.app, backend=BACKEND, native=False).report
        self.assertFalse(report["ok"], report)
        self.assertTrue(any(d["code"] == "E_EFFECT" for d in report["diagnostics"]), report)

    def test_package_lock_relocation_and_source_change(self):
        self.source("let data: [u8; 2] = [1, 2]; let r = codec::read_u16_le(read data, 0);")
        relocated = self.root / "relocated"
        shutil.copytree(self.root / "bytes", relocated / "bytes")
        shutil.copytree(self.app, relocated / "app")
        verify_lock(load_package(relocated / "app"))
        altered = relocated / "bytes/src/lib.hepta"
        altered.write_text(altered.read_text() + "\n// changed library bytes\n", encoding="utf-8")
        from hepta.ast import HeptaError
        with self.assertRaises(HeptaError) as rejected:
            verify_lock(load_package(relocated / "app"))
        self.assertEqual(rejected.exception.diagnostic.code, "E_LOCK_STALE")

    def test_checked_in_packet_example_public_cli(self):
        result = subprocess.run([sys.executable, "-m", "hepta", "run",
                                 str(ROOT / "examples/packages/byte_packet"), "--locked",
                                 "--backend", BACKEND, "--json"], cwd=ROOT,
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["returncode"], 0)
        self.assertEqual(report["stdout"], "")
        self.assertEqual(report["stderr"], "")


if __name__ == "__main__":
    unittest.main()
