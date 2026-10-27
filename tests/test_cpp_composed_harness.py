"""Actual C caller ABI checks, separate from migrated resource workloads."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_cpp_composed_llvm as qualifier
from tools import qualify_cpp_owned_llvm as owned_qualifier
from tools.validate_cpp_composed import case_sources, observation_oracle
from tools.validate_cpp_owned import _case_sources, _observation_oracle


GCC = shutil.which("gcc")
C_PROTOTYPE = "extern uint64_t composed_case(size_t, size_t, uint8_t, size_t, uint32_t, uint32_t);"
CALLEE = """#include <stddef.h>
#include <stdint.h>
uint64_t composed_case(size_t left, size_t right, uint8_t value,
                       size_t index, uint32_t reject, uint32_t early) {
    return (uint64_t)left ^ ((uint64_t)right << 1) ^ ((uint64_t)value << 56)
        ^ (uint64_t)index ^ ((uint64_t)reject << 32) ^ (uint64_t)early;
}
"""


@unittest.skipUnless(GCC, "requires GCC for actual C ABI controls")
class ComposedCallerABITests(unittest.TestCase):
    qualifier = qualifier
    prototype = C_PROTOTYPE
    callee = CALLEE
    header = staticmethod(case_sources)
    expected = staticmethod(observation_oracle)

    def vectors(self):
        vectors = []
        for left, right, value, index, reject, early in (
            (3, 5, 0x12, 7, 0x3456789A, 0xABCDEF01),
            ((1 << 40) + 3, (1 << 38) + 5, 0xE3, (1 << 45) + 7,
             0xCDEFA987, 0xDEADBEEF),
        ):
            expected = (left ^ (right << 1) ^ (value << 56) ^ index
                        ^ (reject << 32) ^ early) & ((1 << 64) - 1)
            self.assertGreater(expected, (1 << 32) - 1)
            vectors.append(dict(left=left, right=right, value=value, index=index,
                                reject=reject, early=early, refuse_at=0,
                                expected=expected, allocated=0, refusals=0,
                                trace=14695981039346656037))
        return vectors

    def prepare(self, root):
        vectors = self.vectors()
        (root / "cases.h").write_text(self.header(vectors)[0])
        (root / "callee.c").write_text(self.callee)
        compiled = subprocess.run(
            [GCC, "-std=c11", "-O2", "-fno-lto", "-c", str(root / "callee.c"),
             "-o", str(root / "callee.o")], capture_output=True, text=True, timeout=30)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        return vectors

    def test_separate_translation_unit_preserves_all_64_return_bits(self):
        with tempfile.TemporaryDirectory(prefix="hepta-composed-caller-") as temporary:
            root = Path(temporary)
            vectors = self.prepare(root)
            linked = subprocess.run(
                self.qualifier._link_command(GCC, root, root / "callee.o", root / "actual"),
                capture_output=True, text=True, timeout=30)
            self.assertEqual(linked.returncode, 0, linked.stderr)
            executed = subprocess.run([str(root / "actual")], capture_output=True,
                                      text=True, timeout=10)
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
            self.assertEqual(json.loads(executed.stdout), self.expected(vectors))

    def test_actual_qualification_flags_reject_a_missing_c_prototype(self):
        with tempfile.TemporaryDirectory(prefix="hepta-composed-untyped-") as temporary:
            root = Path(temporary)
            self.prepare(root)
            harness = (self.qualifier.EXAMPLE / "harness.c").read_text()
            self.assertEqual(harness.count(self.prototype), 1)
            (root / "harness.c").write_text(harness.replace(self.prototype, "", 1))
            with patch.object(self.qualifier, "EXAMPLE", root):
                command = self.qualifier._link_command(GCC, root, root / "callee.o", root / "rejected")
            linked = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(linked.returncode, 0)
            self.assertIn("implicit declaration", linked.stderr)
            self.assertFalse((root / "rejected").exists())


class OwnedCallerABITests(ComposedCallerABITests):
    qualifier = owned_qualifier
    prototype = "extern uint64_t owned_case(size_t, uint8_t, size_t, uint32_t, uint32_t);"
    header = staticmethod(_case_sources)
    expected = staticmethod(_observation_oracle)
    callee = """#include <stddef.h>
#include <stdint.h>
uint64_t owned_case(size_t size, uint8_t value, size_t index,
                    uint32_t reject, uint32_t early) {
    return (uint64_t)size ^ ((uint64_t)value << 56) ^ (uint64_t)index
        ^ ((uint64_t)reject << 32) ^ (uint64_t)early;
}
"""

    def vectors(self):
        vectors = []
        for size, value, index, reject, early in (
            (3, 0x12, 7, 0x3456789A, 0xABCDEF01),
            ((1 << 40) + 3, 0xE3, (1 << 45) + 7, 0xCDEFA987, 0xDEADBEEF),
        ):
            expected = (size ^ (value << 56) ^ index ^ (reject << 32) ^ early) & ((1 << 64) - 1)
            self.assertGreater(expected, (1 << 32) - 1)
            vectors.append(dict(size=size, value=value, index=index, reject=reject,
                                early=early, refuse=0, expected=expected,
                                allocated=0, refusals=0))
        return vectors


if __name__ == "__main__":
    unittest.main()
