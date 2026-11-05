"""Source-only range algorithms against Python sorted/bisect native oracles.

HEPTA_ORDERING_BACKEND selects c (default) or rust. Missing tools fail, never skip.
"""
from __future__ import annotations

import bisect
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
LIBRARY = ROOT / "stdlib/ordering"
BACKEND = os.environ.get("HEPTA_ORDERING_BACKEND", "c")
CONTRACT = ("resources { heap_allocations = 0; may_block = false; "
            "may_suspend = false; may_spawn = false; }")
LIMITS = {"i32": (-(1 << 31), (1 << 31) - 1), "u64": (0, (1 << 64) - 1)}


class OrderingTests(unittest.TestCase):
    def setUp(self):
        self.assertIn(BACKEND, {"c", "rust"})
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-ordering-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(LIBRARY, self.root / "ordering")
        self.app = self.root / "app"
        (self.app / "src").mkdir(parents=True)
        (self.app / "hepta.toml").write_text(
            '[package]\nname = "ordering_test"\nversion = "0.1.0"\nkind = "bin"\n'
            '[dependencies]\norder = { path = "../ordering" }\n', encoding="utf-8")

    def source(self, body):
        entry = self.app / "src/main.hepta"
        entry.write_text("import order;\nfn main() -> Unit effects { panic, write }\n"
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
            ran = subprocess.run([str(artifact)], capture_output=True, text=True, timeout=15)
            self.assertEqual(ran.returncode, 0, ran.stderr)
            self.assertEqual(ran.stdout, "")
            self.assertEqual(ran.stderr, "")

    @staticmethod
    def array(data):
        return "[" + ", ".join(map(str, data)) + "]"

    def sort_corpus(self, typ, cases):
        lines, elements, in_batch = [], 0, 0
        for case, (values, start, end) in enumerate(cases):
            # Bound generated translation-unit size, retaining every case/assertion.
            if lines and (elements + len(values) > 300 or in_batch == 12):
                self.execute("\n".join(lines))
                lines, elements, in_batch = [], 0, 0
            elements += len(values)
            in_batch += 1
            valid = 0 <= start <= end <= len(values)
            expected = values[:]
            if valid:
                expected[start:end] = sorted(values[start:end])
            lines += [f"let mut v{case}: [{typ}; {len(values)}] = {self.array(values)};",
                      f"assert(order::sort_{typ}(mut v{case}, {start}, {end}) == {str(valid).lower()});"]
            # Complete array oracle checks both the sorted range and every untouched element.
            lines += [f"assert(v{case}[{i}] == {value});" for i, value in enumerate(expected)]
        self.execute("\n".join(lines))

    def fixed_sort(self, typ):
        low, high = LIMITS[typ]
        cases = []
        vectors = [[low], [high, low], [high, low, high], [7] * 9,
                   list(range(13)), list(reversed(range(14))),
                   [high, low, high, low, 1, 0, high, low]]
        for data in vectors:
            cases += [(data, 0, len(data)), ([high] + data + [low], 1, len(data) + 1)]
        self.sort_corpus(typ, cases)

    def random_sort(self, typ):
        rng = random.Random(710052 + len(typ))
        low, high = LIMITS[typ]
        cases = []
        for case in range(40):
            length = (1, 2, 3, 8, 15, 16, 17, 31, 32, 33)[case % 10]
            values = [rng.randint(low, high) if case % 2 else rng.randrange(5)
                      for _ in range(length)]
            start = rng.randrange(length + 1)
            end = rng.randrange(start, length + 1)
            cases.append((values, start, end))
        # Large odd/even heaps exercise repeated right-child choices and extraction.
        for length in (256, 257):
            data = [rng.randint(low, high) for _ in range(length)]
            cases.append(([high] + data + [low], 1, length + 1))
        self.sort_corpus(typ, cases)

    def test_sort_i32_fixed(self):
        self.fixed_sort("i32")

    def test_sort_u64_fixed(self):
        self.fixed_sort("u64")

    def test_sort_i32_seeded(self):
        self.random_sort("i32")

    def test_sort_u64_seeded(self):
        self.random_sort("u64")

    def search_corpus(self, typ):
        rng = random.Random(871005 + len(typ))
        low, high = LIMITS[typ]
        lines = []
        for case in range(40):
            if lines and case % 10 == 0:
                self.execute("\n".join(lines))
                lines = []
            length = case % 13
            data = sorted(rng.randrange(0, 9) for _ in range(length))
            if case % 3 == 0:
                data = sorted(data + [low, high, low, high])
            # Excluded sentinels are intentionally not globally sorted.
            values = [high] + data + [low]
            start = rng.randrange(1, len(data) + 2)
            end = rng.randrange(start, len(data) + 2)
            lines.append(f"let v{case}: [{typ}; {len(values)}] = {self.array(values)};")
            for probe, needle in enumerate([low, high, 0, 4, 8, 9]):
                for name, oracle in (("lower_bound", bisect.bisect_left), ("upper_bound", bisect.bisect_right)):
                    result = f"r{case}_{probe}_{name}"
                    expected = oracle(values, needle, start, end)
                    lines += [f"let {result} = order::{name}_{typ}(read v{case}, {start}, {end}, {needle});",
                              f"assert({result}.ok && {result}.index == {expected});"]
            lines += [f"assert(v{case}[{i}] == {value});" for i, value in enumerate(values)]
        self.execute("\n".join(lines))

    def test_search_i32_bisect_oracle(self):
        self.search_corpus("i32")

    def test_search_u64_bisect_oracle(self):
        self.search_corpus("u64")

    def test_empty_singleton_and_invalid_ranges(self):
        # Empty ranges use nonempty backing arrays; no zero-sized C array extension.
        huge = (1 << 64) - 1
        ranges = [(0, 0), (1, 1), (3, 3), (0, 1), (2, 3), (2, 1),
                  (0, 4), (4, 4), (huge, huge), (0, huge), (huge, 0)]
        lines = []
        for typ in LIMITS:
            values = [1, 2, 3]
            for case, (start, end) in enumerate(ranges):
                valid = start <= end <= 3
                stem = f"v{typ}{case}"
                lines += [f"let mut {stem}: [{typ}; 3] = [1, 2, 3];",
                          f"assert(order::sort_{typ}(mut {stem}, {start}, {end}) == {str(valid).lower()});"]
                for name, oracle in (("lower_bound", bisect.bisect_left), ("upper_bound", bisect.bisect_right)):
                    expected = oracle(values, 2, start, end) if valid else 0
                    r = stem + name
                    lines += [f"let {r} = order::{name}_{typ}(read {stem}, {start}, {end}, 2);",
                              f"assert({r}.ok == {str(valid).lower()});", f"assert({r}.index == {expected});"]
                lines += [f"assert({stem}[{i}] == {value});" for i, value in enumerate(values)]
        self.execute("\n".join(lines))

    def test_repeated_sort_and_duplicate_range(self):
        lines = []
        for typ in LIMITS:
            lines += [f"let mut v{typ}: [{typ}; 7] = [9, 2, 1, 2, 1, 2, 0];",
                      f"assert(order::sort_{typ}(mut v{typ}, 1, 6));",
                      f"assert(order::sort_{typ}(mut v{typ}, 1, 6));",
                      f"let low{typ} = order::lower_bound_{typ}(read v{typ}, 1, 6, 2);",
                      f"let high{typ} = order::upper_bound_{typ}(read v{typ}, 1, 6, 2);",
                      f"assert(low{typ}.ok && high{typ}.ok);",
                      f"assert(low{typ}.index == 3 && high{typ}.index == 6);"]
            lines += [f"assert(v{typ}[{i}] == {value});" for i, value in enumerate([9, 1, 1, 2, 2, 2, 0])]
        self.execute("\n".join(lines))

    def test_effect_resources_both_frontends_and_no_std(self):
        self.source("let mut v: [i32; 2] = [2, 1]; assert(order::sort_i32(mut v, 0, 2));")
        for backend in ("c", "rust"):
            result = analyze_project(self.app, backend=backend, crate_type="bin", native=False)
            self.assertTrue(result.report["ok"], result.report)
            self.assertEqual(result.report["status"], "frontend_only")
            self.assertEqual(len(result.program.functions), 9)
            for function in result.program.functions:
                self.assertEqual(function.resources, {"heap_allocations": 0, "may_block": False,
                                                      "may_suspend": False, "may_spawn": False})
                self.assertLessEqual(function.effects, {"panic", "write"})
        result = analyze_project(self.root / "ordering", backend="rust", no_std=True, native=False, crate_type="obj")
        self.assertTrue(result.report["ok"], result.report)
        self.assertIn("#![no_std]", result.rust)
        if BACKEND == "rust":
            native = compile_rust(result.rust, crate_type="obj", output=self.root / "ordering.o")
            self.assertTrue(native["ok"], native)
            self.assertGreater(native["artifact_bytes"], 0)

    def test_invalid_consumers_reject(self):
        invalid = [
            ("let mut v: [u16; 2] = [2, 1]; let ok = order::sort_i32(mut v, 0, 2);", "E_TYPE"),
            ("let v: [i32; 2] = [1, 2]; let r = order::lower_bound_i32(v, 0, 2, 1);", "E_BORROW_MODE"),
            ("let v: [i32; 2] = [2, 1]; let ok = order::sort_i32(mut v, 0, 2);", "E_IMMUTABLE"),
        ]
        for body, code in invalid:
            with self.subTest(code=code):
                self.source(body)
                result = analyze_project(self.app, backend=BACKEND, native=False)
                self.assertFalse(result.report["ok"])
                self.assertIn(code, [d["code"] for d in result.report["diagnostics"]])
        for body, effects in [("let mut v: [i32; 2] = [2, 1]; let ok = order::sort_i32(mut v, 0, 2);", "panic"),
                              ("let v: [i32; 2] = [1, 2]; let r = order::upper_bound_i32(read v, 0, 2, 1);", "")]:
            entry = self.source(body)
            entry.write_text(entry.read_text().replace("effects { panic, write }", "effects { " + effects + " }"))
            result = analyze_project(self.app, backend=BACKEND, native=False)
            self.assertFalse(result.report["ok"])
            self.assertIn("E_EFFECT", [d["code"] for d in result.report["diagnostics"]])

    def test_lock_relocation_and_stale_library(self):
        self.source("let v: [i32; 1] = [0]; let r = order::lower_bound_i32(read v, 0, 1, 0);")
        relocated = self.root / "relocated"
        shutil.copytree(self.root / "ordering", relocated / "ordering")
        shutil.copytree(self.app, relocated / "app")
        verify_lock(load_package(relocated / "app"))
        altered = relocated / "ordering/src/lib.hepta"
        altered.write_text(altered.read_text() + "\n// changed bytes\n", encoding="utf-8")
        with self.assertRaises(HeptaError) as error:
            verify_lock(load_package(relocated / "app"))
        self.assertEqual(error.exception.diagnostic.code, "E_LOCK_STALE")

    def test_locked_example_through_public_cli(self):
        command = [sys.executable, "-m", "hepta", "run", str(ROOT / "examples/ordering"),
                   "--locked", "--backend", BACKEND, "--json"]
        ran = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120)
        self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
        report = json.loads(ran.stdout)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["returncode"], 0)
        self.assertEqual(report["stdout"], "")
        self.assertEqual(report["stderr"], "")


if __name__ == "__main__":
    unittest.main()
