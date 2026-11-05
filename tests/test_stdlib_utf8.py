"""Public-package UTF-8 consumers against Python's strict decoder.

Choose HEPTA_UTF8_BACKEND=c (default) or rust. Missing selected native tools
fail, never skip. The separate exhaustive C oracle uses a private ctypes ABI.
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

from hepta.ast import HeptaError
from hepta.backend import compile_rust
from hepta.c_backend import compile_c
from hepta.packages import load_package, verify_lock, write_lock
from hepta.pipeline import analyze_project

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "stdlib/utf8"
BACKEND = os.environ.get("HEPTA_UTF8_BACKEND", "c")
CONTRACT = ("resources { heap_allocations = 0; may_block = false; "
            "may_suspend = false; may_spawn = false; }")


def expected(data, start, end):
    """Return independent validation and first-scalar results from Python UTF-8."""
    validation, first = (0, start, False), (0, start, False)
    if not 0 <= start <= end <= len(data):
        return validation, first
    segment = bytes(data[start:end])
    try:
        decoded = segment.decode("utf-8", "strict")
        validation = len(decoded), end, True
    except UnicodeDecodeError as exc:
        validation = len(segment[:exc.start].decode("utf-8", "strict")), start + exc.start, False
    # Prefix trials use Python's decoder, not a copied UTF-8 transition table.
    for width in range(1, min(4, len(segment)) + 1):
        try:
            decoded = segment[:width].decode("utf-8", "strict")
        except UnicodeDecodeError:
            continue
        if len(decoded) == 1:
            first = ord(decoded), start + width, True
            break
    return validation, first


class UTF8Tests(unittest.TestCase):
    def setUp(self):
        self.assertIn(BACKEND, {"c", "rust"})
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-stdlib-utf8-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(LIBRARY, self.root / "utf8")
        self.app = self.root / "app"
        (self.app / "src").mkdir(parents=True)
        (self.app / "hepta.toml").write_text(
            '[package]\nname = "utf8_test"\nversion = "0.1.0"\nkind = "bin"\n'
            '[dependencies]\nutf8 = { path = "../utf8" }\n', encoding="utf-8")

    def source(self, body, effects="panic"):
        entry = self.app / "src/main.hepta"
        entry.write_text("import utf8;\nfn main() -> Unit effects { " + effects + " }\n"
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
            result = subprocess.run([str(artifact)], capture_output=True, text=True, timeout=15)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))

    def cases(self, cases):
        """Bound translation-unit size without dropping any cases/assertions."""
        for base in range(0, len(cases), 24):
            lines = []
            for number, (data, start, end) in enumerate(cases[base:base + 24]):
                data = bytes(data)
                validation, first = expected(data, start, end)
                # Empty ranges use nonempty backing storage in the shared C subset.
                backing = data or b"\xff"
                lines += [f"let data{number}: [u8; {len(backing)}] = [{', '.join(map(str, backing))}];",
                          f"let checked{number} = utf8::validate(read data{number}, {start}, {end});",
                          f"assert(checked{number}.scalars == {validation[0]});",
                          f"assert(checked{number}.error == {validation[1]});",
                          f"assert(checked{number}.ok == {str(validation[2]).lower()});",
                          f"let decoded{number} = utf8::decode_next(read data{number}, {start}, {end});",
                          f"assert(decoded{number}.scalar == {first[0]});",
                          f"assert(decoded{number}.next == {first[1]});",
                          f"assert(decoded{number}.ok == {str(first[2]).lower()});"]
                lines += [f"assert(data{number}[{i}] == {byte});" for i, byte in enumerate(backing)]
            self.execute("\n".join(lines))

    def test_all_single_bytes(self):
        self.cases([(bytes([byte]), 0, 1) for byte in range(256)])

    def test_scalar_boundaries_and_noncharacters(self):
        values = [0, 1, 127, 128, 129, 2047, 2048, 2049, 0xD7FE, 0xD7FF,
                  0xE000, 0xE001, 0xFDD0, 0xFDEF, 0xFEFF, 0xFFFE, 0xFFFF,
                  0x10000, 0x10001, 0x10FFFE, 0x10FFFF]
        self.cases([(chr(value).encode(), 0, len(chr(value).encode())) for value in values])

    def test_seeded_scalar_sequences(self):
        rng = random.Random(20261105)
        cases = []
        for _ in range(48):
            values = []
            for _ in range(rng.randrange(1, 7)):
                value = rng.randrange(0x110000 - 0x800)
                values.append(value + 0x800 if value >= 0xD800 else value)
            data = "".join(map(chr, values)).encode("utf-8")
            cases.append((data, 0, len(data)))
        self.cases(cases)

    def test_malformed_sequences_and_error_prefixes(self):
        malformed = [b"\xc0\x80", b"\xc1\xbf", b"\xe0\x9f\xbf", b"\xed\xa0\x80",
                     b"\xed\xbf\xbf", b"\xf0\x8f\xbf\xbf", b"\xf4\x90\x80\x80",
                     b"\xf5\x80\x80\x80", b"\xf8\x88\x80\x80\x80", b"\xfe", b"\xff"]
        for valid in (b"\xc2\xa2", b"\xe2\x82\xac", b"\xf0\x9f\x98\x80"):
            for position in range(1, len(valid)):
                for wrong in (0, 127, 192, 255):
                    malformed.append(valid[:position] + bytes([wrong]) + valid[position + 1:])
        cases = []
        for data in malformed:
            for prefix in (b"", "A\u20ac".encode()):
                framed = b"\xff" + prefix + data + b"\xff"
                cases.append((framed, 1, len(framed) - 1))
        self.cases(cases)

    def test_truncated_sequences_and_excluded_suffix(self):
        cases = []
        for data in (b"\xc2\x80", b"\xdf\xbf", b"\xe0\xa0\x80", b"\xed\x9f\xbf",
                     b"\xef\xbf\xbf", b"\xf0\x90\x80\x80", b"\xf4\x8f\xbf\xbf"):
            for cut in range(1, len(data)):
                for prefix in (b"", b"AB"):
                    framed = b"\xff" + prefix + data + b"\xff"
                    cases.append((framed, 1, 1 + len(prefix) + cut))
        self.cases(cases)

    def test_range_boundaries_and_invalid_bounds(self):
        data = "A\u00a2\u20ac\U0001f600".encode()
        cases = [(data, start, end) for start in range(len(data) + 1)
                 for end in range(start, len(data) + 1)]
        cases += [(data, 4, 3), (data, 0, len(data) + 1),
                  (data, len(data) + 1, len(data) + 1),
                  (data, 0, (1 << 64) - 1), (data, (1 << 64) - 1, (1 << 64) - 1),
                  (data, (1 << 64) - 1, 0)]
        self.cases(cases)

    def test_seeded_arbitrary_bytes(self):
        rng = random.Random(0x55544638)
        cases = []
        for _ in range(96):
            data = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 17)))
            start = rng.randrange(len(data) + 1)
            end = rng.randrange(start, len(data) + 1)
            cases.append((data, start, end))
        self.cases(cases)

    def test_iterated_decoding_and_unicode_count(self):
        # Scalar count is neither byte length nor grapheme-cluster count.
        text = "\x00A\u00e9e\u0301\U0001f469\u200d\U0001f4bb\ufeff\uffff"
        data = text.encode("utf-8")
        lines = [f"let data: [u8; {len(data)}] = [{', '.join(map(str, data))}];",
                 "let mut cursor: usize = 0;"]
        offset = 0
        for index, char in enumerate(text):
            offset += len(char.encode())
            lines += [f"let next{index} = utf8::decode_next(read data, cursor, {len(data)});",
                      f"assert(next{index}.ok && next{index}.scalar == {ord(char)} && next{index}.next == {offset});",
                      f"cursor = next{index}.next;"]
        lines += [f"let ended = utf8::decode_next(read data, cursor, {len(data)});",
                  "assert(!ended.ok && ended.scalar == 0 && ended.next == cursor);",
                  f"let all = utf8::validate(read data, 0, {len(data)});",
                  f"assert(all.ok && all.scalars == {len(text)} && all.error == {len(data)});"]
        self.execute("\n".join(lines))

    def test_resource_contracts_and_both_frontends(self):
        self.source("let data: [u8; 1] = [65]; let result = utf8::validate(read data, 0, 1); assert(result.ok);")
        for backend in ("c", "rust"):
            analysis = analyze_project(self.app, backend=backend, native=False)
            self.assertTrue(analysis.report["ok"], analysis.report)
            self.assertEqual(analysis.report["status"], "frontend_only")
            self.assertEqual(len(analysis.program.functions), 3)
            for effects in analysis.report["effects"].values():
                self.assertLessEqual(set(effects), {"panic"})
            for function in analysis.program.functions:
                self.assertEqual(function.resources, {"heap_allocations": 0, "may_block": False,
                                                      "may_suspend": False, "may_spawn": False})
        no_std = analyze_project(self.root / "utf8", backend="rust", crate_type="obj", no_std=True, native=False)
        self.assertTrue(no_std.report["ok"], no_std.report)
        self.assertIn("#![no_std]", no_std.rust)
        if BACKEND == "rust":
            native = compile_rust(no_std.rust, crate_type="obj", output=self.root / "utf8.o")
            self.assertTrue(native["ok"], native)
            self.assertGreater(native["artifact_bytes"], 0)

    def test_invalid_consumers_reject(self):
        invalid = [("let data: [u16; 1] = [65]; let r = utf8::validate(read data, 0, 1);", "E_TYPE"),
                   ("let data: [u8; 1] = [65]; let r = utf8::validate(data, 0, 1);", "E_BORROW_MODE"),
                   ("let data: [u8; 1] = [65]; let r = utf8::decode_next(data, 0, 1);", "E_BORROW_MODE")]
        for backend in ("c", "rust"):
            for body, code in invalid:
                with self.subTest(backend=backend, code=code, body=body):
                    self.source(body)
                    report = analyze_project(self.app, backend=backend, native=False).report
                    self.assertFalse(report["ok"], report)
                    self.assertIn(code, [d["code"] for d in report["diagnostics"]])
            self.source("let data: [u8; 1] = [65]; let r = utf8::validate(read data, 0, 1);", effects="")
            report = analyze_project(self.app, backend=backend, native=False).report
            self.assertFalse(report["ok"], report)
            self.assertIn("E_EFFECT", [d["code"] for d in report["diagnostics"]])

    def test_package_lock_relocation_and_staleness(self):
        self.source("let data: [u8; 1] = [65]; let r = utf8::validate(read data, 0, 1);")
        relocated = self.root / "relocated"
        shutil.copytree(self.root / "utf8", relocated / "utf8")
        shutil.copytree(self.app, relocated / "app")
        verify_lock(load_package(relocated / "app"))
        changed = relocated / "utf8/src/lib.hepta"
        changed.write_text(changed.read_text(encoding="utf-8") + "\n// changed bytes\n", encoding="utf-8")
        with self.assertRaises(HeptaError) as rejected:
            verify_lock(load_package(relocated / "app"))
        self.assertEqual(rejected.exception.diagnostic.code, "E_LOCK_STALE")

    def test_checked_in_example_public_cli(self):
        result = subprocess.run([sys.executable, "-m", "hepta", "run",
                                 str(ROOT / "examples/packages/utf8_scan"), "--locked",
                                 "--backend", BACKEND, "--json"], cwd=ROOT,
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["ok"], report)
        self.assertEqual((report["returncode"], report["stdout"], report["stderr"]), (0, "", ""))


if __name__ == "__main__":
    unittest.main()
