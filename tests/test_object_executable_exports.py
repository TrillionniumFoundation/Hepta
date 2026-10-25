"""P3/P5: five real LLVM target objects must place exports in executable code.

These mutations preserve object headers and symbol names. Symbol inventory
alone is insufficient: a function symbol may point to .data, be outside its
section, or be described by forged section flags. This checks only structural
object extents, not executed behavior, ABI or compiler refinement.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.object_structure import qualified_object
from hepta.object_symbols import ObjectSymbolsRejected, inspect_object_symbols
from hepta.llvm_ssa_target import _TARGETS

_SOURCE = """\
define i32 @hepta_symbol_target(i32 %x) {
entry:
  %r = add i32 %x, 1
  ret i32 %r
}
"""


def _u16(data, at):
    return int.from_bytes(data[at:at + 2], "little")


def _u32(data, at):
    return int.from_bytes(data[at:at + 4], "little")


def _u64(data, at):
    return int.from_bytes(data[at:at + 8], "little")


def _write(data, at, length, value):
    result = bytearray(data)
    result[at:at + length] = value.to_bytes(length, "little")
    return bytes(result)


def _mutate_elf(data):
    table = _u64(data, 40)
    sections = _u16(data, 60)
    for idx in range(sections):
        entry = table + idx * 64
        if _u32(data, entry + 4) != 2:
            continue
        string_idx = _u32(data, entry + 40)
        strings = table + 64 * string_idx
        names = _u64(data, strings + 24)
        for pos in range(_u64(data, entry + 24),
                         _u64(data, entry + 24) + _u64(data, entry + 32), 24):
            off = _u32(data, pos)
            if data[names + off:names + off + 20].startswith(b"hepta_symbol_target"):
                section = _u16(data, pos + 6)
                target = table + 64 * section
                original_bytes = _u64(data, target + 32)
                assert original_bytes > 0
                # The symbol remains STT_FUNC with the same name and code
                # section, but now begins *beyond* the section's extent.
                return {
                    "out_of_range": _write(data, pos + 8, 8, original_bytes + 1),
                    "non_executable": _write(data, target + 8, 8,
                                             _u64(data, target + 8) & ~0x4),
                    "zero_length": _write(data, pos + 16, 8, 0),
                }
    raise AssertionError("No ELF exported function found")


def _mutate_coff(data):
    table, count = _u32(data, 8), _u32(data, 12)
    end = table + 18 * count
    idx = 0
    while idx < count:
        pos = table + 18 * idx
        raw_name = data[pos:pos + 8]
        if raw_name[:4] == b"\0\0\0\0":
            at = end + _u32(data, pos + 4)
            name = data[at:data.index(b"\0", at)]
        else:
            name = raw_name.split(b"\0", 1)[0]
        if name == b"hepta_symbol_target":
            section = int.from_bytes(data[pos + 12:pos + 14], "little", signed=True)
            assert section > 0
            sec = 20 + 40 * (section - 1)
            flags, length = _u32(data, sec + 36), _u32(data, sec + 16)
            assert length > 0
            return {
                "out_of_range": _write(data, pos + 8, 4, length + 1),
                "non_executable": _write(data, sec + 36, 4, flags & ~0x20000000),
                "not_code": _write(data, sec + 36, 4, flags & ~0x20),
            }
        idx += 1 + data[pos + 17]
    raise AssertionError("No COFF exported function found")


def _mutate_macho(data):
    commands, pos = _u32(data, 16), 32
    section = None
    symtab = None
    for _ in range(commands):
        command, size = _u32(data, pos), _u32(data, pos + 4)
        if command == 0x19:  # LC_SEGMENT_64
            for idx in range(_u32(data, pos + 64)):
                entry = pos + 72 + idx * 80
                if data[entry:entry + 16].split(b"\0", 1)[0] == b"__text":
                    section = entry
        elif command == 0x2:
            symtab = (_u32(data, pos + 8), _u32(data, pos + 12),
                      _u32(data, pos + 16))
        pos += size
    if section is None or symtab is None:
        raise AssertionError("No Mach-O __text or symbol table")
    at, count, strings = symtab
    for idx in range(count):
        symbol = at + idx * 16
        name_off = _u32(data, symbol)
        begin = strings + name_off
        name = data[begin:data.index(b"\0", begin)]
        if name == b"_hepta_symbol_target":
            start, length, flags = (_u64(data, section + 32),
                                    _u64(data, section + 40),
                                    _u32(data, section + 64))
            assert length > 0
            return {
                "out_of_range": _write(data, symbol + 8, 8, start + length),
                "non_executable": _write(data, section + 64, 4,
                                         flags & ~(0x80000000 | 0x400)),
                "zerofill_masquerading_as_text": _write(data, section + 64, 4,
                                                        (flags & ~0xff) | 0x1),
                "false_text_name": data[:section] + b"__data" + data[section + 6:],
            }
    raise AssertionError("No Mach-O export found")


@unittest.skipUnless(shutil.which("clang"), "Native Clang is required")
class ExecutableSymbolExtentTests(unittest.TestCase):
    def test_all_five_native_object_profiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "function.ll"
            source.write_text(_SOURCE, encoding="utf-8")
            for target, (fmt, machine) in _TARGETS.items():
                with self.subTest(target=target):
                    artifact = root / (target + ".o")
                    run = subprocess.run(
                        ["clang", "--target=" + target, "-x", "ir", "-O2", "-c",
                         str(source), "-o", str(artifact)],
                        text=True, capture_output=True, timeout=30)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    original = artifact.read_bytes()
                    self.assertTrue(qualified_object(original, fmt, machine))
                    symbols = inspect_object_symbols(original, fmt, machine)
                    self.assertEqual(symbols["defined"], frozenset({"hepta_symbol_target"}))
                    self.assertFalse(symbols["undefined"])
                    mutate = (_mutate_elf if fmt == "ELF64" else
                              _mutate_coff if fmt == "COFF" else _mutate_macho)
                    for reason, forged in mutate(original).items():
                        with self.subTest(target=target, reason=reason):
                            # Existing object structural inventory was already
                            # satisfied, so rejection must come from symbol
                            # executable placement, not from a broken header.
                            self.assertTrue(qualified_object(forged, fmt, machine))
                            with self.assertRaisesRegex(
                                    ObjectSymbolsRejected, "E_OBJECT_SYMBOL_LOCATION"):
                                inspect_object_symbols(forged, fmt, machine)


if __name__ == "__main__":
    unittest.main()
