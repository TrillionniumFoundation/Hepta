"""Captured C post-test loops reach independent Core and actual native code.

The C++ arm compiles the C-compatible reference; it is not C++ translation.
Native observations are finite differentials, not a refinement proof.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import execute_program
from hepta.hia_program_llvm import build_program_native


SOURCE = r"""
int once(int count, int seed) {
    int total = seed; int i = 0;
    do { total = total + 3; i = i + 1; } while (i < count);
    return total;
}
int postcondition(int count, int seed) {
    int divisor = 0; int iterations = 0;
    do { divisor = 1; iterations = iterations + 1; }
    while (9 / divisor < iterations);
    return iterations + seed;
}
int nested(int count, int seed) {
    int total = seed; int outer = 0;
    do {
        int inner = 0; int step = outer + 1;
        do { total = total + step; inner = inner + 1; } while (inner < 2);
        outer = outer + 1;
    } while (outer < count);
    return total;
}
int early(int count, int seed) {
    int i = 0;
    do { if (seed == 0) { return 33; } i = i + 1; }
    while (count / i > 1);
    return i;
}
int shadowed(int count, int seed) {
    int total = seed; int i = 0;
    do { int seed = i + 1; total = total + seed; i = i + 1; }
    while (i < count);
    return total;
}
int deferred(int count, int seed) {
    int value; int i = 0;
    do { value = seed + i; i = i + 1; } while (i < count);
    return value;
}
int branch_deferred(int count, int seed) {
    int value;
    do { if (seed < 0) { return -4; } else { value = seed; } } while (0);
    return value;
}
int unbraced(int count, int seed) {
    int i = 0;
    do i++; while (i < count);
    return i + seed;
}
"""


def expected(name, count, seed):
    iterations = max(1, count)
    if name == "once":
        return seed + 3 * iterations
    if name == "postcondition":
        return 1 + seed
    if name == "nested":
        return seed + iterations * (iterations + 1)
    if name == "early":
        return 33 if seed == 0 else max(1, count // 2 + 1)
    if name == "shadowed":
        return seed + iterations * (iterations + 1) // 2
    if name == "deferred":
        return seed + iterations - 1
    if name == "branch_deferred":
        return -4 if seed < 0 else seed
    if name == "unbraced":
        return iterations + seed
    raise AssertionError(name)


class HIACDoWhileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-c-do-while-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.clang = os.environ.get("CLANG") or shutil.which("clang")
        self.clangxx = os.environ.get("CLANGXX") or shutil.which("clang++")
        self.assertTrue(self.clang and self.clangxx,
                        "Actual Clang/Clang++ required; missing tools do not qualify this gate")

    def database(self, source, name="input"):
        directory = self.work / name
        directory.mkdir()
        (directory / "input.c").write_text(source)
        database = directory / "compile_commands.json"
        database.write_text(json.dumps([{
            "directory": str(directory), "file": "input.c",
            "arguments": [self.clang, "-std=c11", "-O2", "-c", "input.c"],
        }]))
        return directory, database

    def command(self, argv):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result






if __name__ == "__main__":
    unittest.main()
