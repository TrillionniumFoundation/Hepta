"""Executable Clang object-data extent regression, not Hepta target ABI proof."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.llvm_ssa_target import _TARGETS, _qualified_header

_SOURCE = """define i32 @hepta_probe(i32 %x) {
entry:
 %next = add i32 %x, 1
 ret i32 %next
}
"""


def _write_int(data: bytes, at: int, width: int, value: int) -> bytes:
    changed = bytearray(data)
    changed[at:at + width] = value.to_bytes(width, "little")
    return bytes(changed)


def _u32(data: bytes, at: int) -> int:
    return int.from_bytes(data[at:at + 4], "little")


@unittest.skipUnless(shutil.which("clang"), "real Clang cross objects are required")
class ObjectSectionPayloadTests(unittest.TestCase):
    def test_five_real_objects_and_out_of_file_section_mutants(self):
        positive, rejected = 0, 0
        with tempfile.TemporaryDirectory(prefix="hepta-extents-") as folder:
            source = Path(folder) / "fixture.ll"
            source.write_text(_SOURCE, encoding="utf-8")
            for target, (fmt, _) in sorted(_TARGETS.items()):
                with self.subTest(target=target):
                    artifact = Path(folder) / (target + ".o")
                    built = subprocess.run(
                        ["clang", "--target=" + target, "-x", "ir", "-O3",
                         "-c", str(source), "-o", str(artifact)],
                        capture_output=True, text=True, timeout=30)
                    self.assertEqual(built.returncode, 0, built.stderr)
                    data = artifact.read_bytes()
                    self.assertTrue(_qualified_header(data, target))
                    positive += 1
                    if fmt == "ELF64":
                        table = int.from_bytes(data[40:48], "little")
                        sections = int.from_bytes(data[60:62], "little")
                        text_section = next(
                            table + 64 * index for index in range(sections)
                            if _u32(data, table + 64 * index + 4) == 1
                            and int.from_bytes(
                                data[table + 64 * index + 32:table + 64 * index + 40],
                                "little") != 0)
                        mutants = [_write_int(data, text_section + 24, 8, len(data) + 256)]
                    elif fmt == "COFF":
                        count = int.from_bytes(data[2:4], "little")
                        section = next(
                            20 + 40 * index for index in range(count)
                            if _u32(data, 20 + 40 * index + 16) > 0)
                        mutants = [_write_int(data, section + 20, 4, len(data) + 256)]
                        bad_reloc = _write_int(data, section + 24, 4, len(data) + 300)
                        mutants.append(_write_int(bad_reloc, section + 32, 2, 1))
                    else:
                        command = 32
                        end = 32 + _u32(data, 20)
                        section = None
                        symtab = None
                        while command < end:
                            kind, size = _u32(data, command), _u32(data, command + 4)
                            if kind == 0x19:
                                section = command + 72
                            elif kind == 0x2:
                                symtab = command
                            command += size
                        self.assertIsNotNone(section)
                        self.assertIsNotNone(symtab)
                        mutants = [_write_int(data, section + 48, 4, len(data) + 256)]
                        bad_sym = _write_int(data, symtab + 8, 4, len(data) + 400)
                        mutants.append(_write_int(bad_sym, symtab + 12, 4, 1))
                    for mutant in mutants:
                        self.assertFalse(_qualified_header(mutant, target))
                        rejected += 1
        self.assertEqual(positive, 5)
        self.assertEqual(rejected, 8)


if __name__ == "__main__":
    unittest.main()
