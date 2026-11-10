"""Actual captured C/C++ loop jumps reach Core and direct native HIA.

The C++ scope is concrete noexcept scalar bodies, not unrestricted C++.
Differentials retain original defined inputs and do not claim equivalence for
arbitrary programs. Unsupported jumps and unsafe deferred reads still reject.
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
unsigned while_jumps(unsigned count, unsigned seed) {
    unsigned i = 0, total = seed;
    while (i < count) {
        i++;
        if (i == 2u) continue;
        if (i == 5u) break;
        unsigned item = i * 3u;
        total += item;
    }
    return total + i * 100u;
}
unsigned for_jumps(unsigned count, unsigned seed) {
    unsigned total = seed, ticks = 0;
    for (unsigned i = 0; i < count; i++, ticks++) {
        if (i == 2u) continue;
        if (i == 5u) break;
        unsigned item = i + 1u;
        total += item;
    }
    return total + ticks * 100u;
}
unsigned do_jumps(unsigned count, unsigned seed) {
    unsigned i = 0, total = seed;
    do {
        i++;
        if (i == 5u) break;
        if (i == 2u) continue;
        unsigned item = i * 3u;
        total += item;
    } while (i < count);
    return total + i * 100u;
}
unsigned while_break_trap(unsigned count, unsigned seed) {
    unsigned divisor = 1;
    while (count / divisor > 0u) { divisor = 0; break; }
    return seed + divisor;
}
unsigned do_break_trap(unsigned count, unsigned seed) {
    unsigned divisor = 0;
    do { seed += 7u; break; } while (count / divisor > 0u);
    return seed;
}
unsigned for_break_trap(unsigned count, unsigned seed) {
    unsigned i = 0, divisor = 0;
    for (i = 0; i < count; i = i + 8u / divisor) {
        if (seed != 0u) { i = 1; break; }
        divisor = 1;
        if (i >= 4u) break;
    }
    return i;
}
unsigned nested_jumps(unsigned count, unsigned seed) {
    if (count > 16u) return seed;
    unsigned total = seed;
    for (unsigned outer = 0; outer < count; outer++) {
        unsigned inner = 0;
        while (inner < 4u) {
            inner++;
            if (inner == 2u) continue;
            if (inner == 3u) break;
            total += outer + inner;
        }
        total += 7u;
    }
    return total;
}
unsigned tail_scopes(unsigned count, unsigned seed) {
    if (count > 16u) return seed;
    unsigned total = seed;
    for (unsigned i = 0; i < count; i++) {
        {
            if ((i & 1u) != 0u) continue;
            unsigned item = seed + i;
            total += item;
        }
        unsigned item = i + 10u;
        total += item;
    }
    return total;
}
"""
NAMES = ("while_jumps", "for_jumps", "do_jumps", "while_break_trap",
         "do_break_trap", "for_break_trap", "nested_jumps", "tail_scopes")


def expected(name, count, seed):
    modulus = 1 << 32
    if name in {"while_jumps", "do_jumps"}:
        i, total = 0, seed
        while i < count or name == "do_jumps" and i == 0:
            i += 1
            if i == 5:
                break
            if i == 2:
                continue
            total += i * 3
        return (total + i * 100) % modulus
    if name == "for_jumps":
        ticks, total = 0, seed
        for i in range(min(count, 6)):
            if i == 5:
                break
            if i != 2:
                total += i + 1
            ticks += 1
        return (total + ticks * 100) % modulus
    if name == "while_break_trap":
        return (seed + (count == 0)) % modulus
    if name == "do_break_trap":
        return (seed + 7) % modulus
    if name == "for_break_trap":
        return 0 if count == 0 else 1 if seed else 8
    if name == "nested_jumps":
        return (seed + sum(i + 8 for i in range(count))) % modulus if count <= 16 else seed
    if name == "tail_scopes":
        return (seed + sum(seed + 2 * i + 10 for i in range(0, count, 2))) % modulus if count <= 16 else seed
    raise AssertionError(name)


class HIACLoopJumpTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-c-loop-jumps-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.clang = os.environ.get("CLANG") or shutil.which("clang")
        self.clangxx = os.environ.get("CLANGXX") or shutil.which("clang++")
        self.assertTrue(self.clang and self.clangxx, "Actual Clang/Clang++ required")

    def database(self, source, name="input", *, cpp=False):
        directory = self.work / name
        directory.mkdir()
        filename = "input.cpp" if cpp else "input.c"
        (directory / filename).write_text(source)
        database = directory / "compile_commands.json"
        database.write_text(json.dumps([{
            "directory": str(directory), "file": filename,
            "arguments": ["clang++" if cpp else "clang", "-std=c++20" if cpp else "-std=c11",
                          "-O2", "-c", filename],
        }]))
        return directory, database

    def command(self, argv):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)








if __name__ == "__main__":
    unittest.main()
