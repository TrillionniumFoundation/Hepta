"""Function symbol must point into real executable section on every target."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.llvm_ssa_target import _TARGETS, _defined_exports, _qualified_header

_LLVM = """define i32 @hepta_verified_func(i32 %x) {
entry:
 %ret = add i32 %x, 1
 ret i32 %ret
}
"""


def _int(data, at, width):
    return int.from_bytes(data[at:at + width], "little")


def _edit(data, at, width, value):
    out = bytearray(data)
    out[at:at + width] = value.to_bytes(width, "little")
    return bytes(out)


@unittest.skipUnless(shutil.which("clang"), "Real Clang objects required")
class NativeCodeSectionBindings(unittest.TestCase):
    def test_five_target_functions_and_ten_misbound_function_mutants(self):
        accepted, rejected = 0, 0
        with tempfile.TemporaryDirectory(prefix="hepta-export-code-") as tmp:
            root = Path(tmp)
            fixture = root / "code.ll"
            fixture.write_text(_LLVM, encoding="utf-8")
            for target, (fmt, _) in sorted(_TARGETS.items()):
                with self.subTest(target=target):
                    output = root / (target + ".o")
                    run = subprocess.run(
                        ["clang", "--target=" + target, "-x", "ir", "-O3",
                         "-c", str(fixture), "-o", str(output)],
                        capture_output=True, text=True, timeout=30)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    data = output.read_bytes()
                    self.assertTrue(_qualified_header(data, target))
                    self.assertIn("hepta_verified_func", _defined_exports(data, target))
                    accepted += 1
                    if fmt == "ELF64":
                        table, count = _int(data, 40, 8), _int(data, 60, 2)
                        function = None
                        for section in range(count):
                            record = table + 64 * section
                            if _int(data, record + 4, 4) != 2:
                                continue
                            start, size = _int(data, record + 24, 8), _int(data, record + 32, 8)
                            for sym in range(start, start + size, 24):
                                info = data[sym + 4]
                                if info & 0xf == 2 and info >> 4 in (1, 2):
                                    function = sym
                                    break
                        self.assertIsNotNone(function)
                        malformed = [
                            _edit(data, function + 6, 2, 3),     # .data, not code
                            _edit(data, function + 8, 8, 10000), # beyond .text
                        ]
                    elif fmt == "COFF":
                        symbols = _int(data, 8, 4)
                        count = _int(data, 12, 4)
                        function = None
                        for index in range(count):
                            sym = symbols + 18 * index
                            if data[sym + 16] == 2 and _int(data, sym + 14, 2) & 0x20:
                                function = sym
                                break
                        self.assertIsNotNone(function)
                        malformed = [
                            _edit(data, function + 12, 2, 2),   # noncode .data
                            _edit(data, function + 8, 4, 10000), # beyond .text
                        ]
                    else:
                        offset, section, function = 32, None, None
                        end = 32 + _int(data, 20, 4)
                        while offset < end:
                            kind, size = _int(data, offset, 4), _int(data, offset + 4, 4)
                            if kind == 0x19:
                                section = offset + 72
                            if kind == 2:
                                at, count = _int(data, offset + 8, 4), _int(data, offset + 12, 4)
                                for index in range(count):
                                    sym = at + 16 * index
                                    if data[sym + 4] & 0xf == 0xf:
                                        function = sym
                                        break
                            offset += size
                        self.assertIsNotNone(section)
                        self.assertIsNotNone(function)
                        extent = _int(data, section + 40, 8)
                        malformed = [
                            _edit(data, section + 64, 4, 0),      # no instruction flags
                            _edit(data, function + 8, 8, extent), # out of section
                        ]
                    for bad in malformed:
                        self.assertTrue(_qualified_header(bad, target))
                        self.assertNotIn("hepta_verified_func",
                                         _defined_exports(bad, target))
                        rejected += 1
        self.assertEqual((accepted, rejected), (5, 10))


if __name__ == "__main__":
    unittest.main()
