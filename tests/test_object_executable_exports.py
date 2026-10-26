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
                    "not_allocated": _write(data, target + 8, 8,
                                             _u64(data, target + 8) & ~0x2),
                    "weak_override": _write(data, pos + 4, 1,
                                             (data[pos + 4] & 0x0f) | 0x20),
                    "zero_length": _write(data, pos + 16, 8, 0),
                }
    raise AssertionError("No ELF exported function found")


def _elf_global_to_gnu_unique(data, *, binding=10):
    """Retag one real Clang public ELF data symbol without changing section bytes."""
    table, sections = _u64(data, 40), _u16(data, 60)
    for index in range(sections):
        section = table + index * 64
        if _u32(data, section + 4) != 2:
            continue
        linked = _u32(data, section + 40)
        strings = table + 64 * linked
        name_start = _u64(data, strings + 24)
        name_size = _u64(data, strings + 32)
        begin, size = _u64(data, section + 24), _u64(data, section + 32)
        for pos in range(begin, begin + size, 24):
            name_off = _u32(data, pos)
            if not 0 < name_off < name_size:
                continue
            if data[name_start + name_off:name_start + name_off + 24].startswith(
                    b"hepta_unapproved_global\0"):
                assert data[pos + 4] == 0x11  # STB_GLOBAL + STT_OBJECT
                modified = bytearray(data)
                modified[pos + 4] = (binding << 4) | 1  # chosen binding + STT_OBJECT
                return bytes(modified)
    raise AssertionError("Did not find an external data symbol to mutate")


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
                "weak_definition": _write(data, symbol + 6, 2,
                                           _u16(data, symbol + 6) | 0x80),
                "false_text_name": data[:section] + b"__data" + data[section + 6:],
            }
    raise AssertionError("No Mach-O export found")


@unittest.skipUnless(shutil.which("clang"), "Native Clang is required")
class ExecutableSymbolExtentTests(unittest.TestCase):
    def test_unapproved_global_data_exports_fail_across_all_targets(self):
        # Keep a legitimate source function and add one unexpected *defined*
        # exported data object. The previous scanner returned only STT_FUNC /
        # COFF function symbols and could silently omit data exports.
        with tempfile.TemporaryDirectory(prefix="hepta-extra-native-export-") as tmp:
            root = Path(tmp)
            source = root / "extra.ll"
            source.write_text(
                "@hepta_unapproved_global = global i64 77, align 8\n" + _SOURCE,
                encoding="utf-8")
            for target, (fmt, machine) in _TARGETS.items():
                with self.subTest(target=target):
                    artifact = root / (target + ".o")
                    result = subprocess.run(
                        ["clang", "--target=" + target, "-x", "ir", "-O2",
                         "-c", str(source), "-o", str(artifact)],
                        capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    data = artifact.read_bytes()
                    self.assertTrue(qualified_object(data, fmt, machine))
                    with self.assertRaisesRegex(
                            ObjectSymbolsRejected,
                            "E_OBJECT_SYMBOL_(EXPORT_KIND|LOCATION)"):
                        inspect_object_symbols(data, fmt, machine)

    def test_gnu_unique_data_export_is_not_hidden_from_elf_inventory(self):
        # The original scanner skipped ELF binding 10 as neither GLOBAL nor
        # WEAK and would certify the ordinary function while hiding this
        # globally visible GNU-unique data symbol.
        with tempfile.TemporaryDirectory(prefix="hepta-gnu-unique-") as tmp:
            root = Path(tmp)
            source = root / "unique.ll"
            source.write_text(
                "@hepta_unapproved_global = global i64 77, align 8\n" + _SOURCE)
            for target, machine in (("x86_64-unknown-linux-gnu", 62),
                                    ("aarch64-unknown-linux-gnu", 183)):
                with self.subTest(target=target):
                    artifact = root / (target + ".o")
                    compiled = subprocess.run(
                        ["clang", "--target=" + target, "-x", "ir", "-O2",
                         "-c", str(source), "-o", str(artifact)],
                        capture_output=True, text=True, timeout=30)
                    self.assertEqual(compiled.returncode, 0, compiled.stderr)
                    mutated = _elf_global_to_gnu_unique(artifact.read_bytes())
                    self.assertTrue(qualified_object(mutated, "ELF64", machine))
                    with self.assertRaisesRegex(ObjectSymbolsRejected,
                                                "E_OBJECT_SYMBOL_EXPORT_KIND"):
                        inspect_object_symbols(mutated, "ELF64", machine)

    def test_unreviewed_elf_bindings_cannot_hide_extra_data_exports(self):
        # Binding 10 (GNU_UNIQUE) was already rejected. The previous scanner
        # continued to skip bindings 3..9 and 11..15, despite not having
        # specified visibility semantics for them. All must fail closed.
        with tempfile.TemporaryDirectory(prefix="hepta-unreviewed-binding-") as tmp:
            root = Path(tmp)
            source = root / "unreviewed.ll"
            source.write_text(
                "@hepta_unapproved_global = global i64 77, align 8\n" + _SOURCE)
            for target, machine in (("x86_64-unknown-linux-gnu", 62),
                                    ("aarch64-unknown-linux-gnu", 183)):
                artifact = root / (target + ".o")
                run = subprocess.run(
                    ["clang", "--target=" + target, "-x", "ir", "-O2",
                     "-c", str(source), "-o", str(artifact)],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(run.returncode, 0, run.stderr)
                original = artifact.read_bytes()
                self.assertTrue(qualified_object(original, "ELF64", machine))
                for binding in (3, 9, 10, 11, 12, 13, 15):
                    with self.subTest(target=target, binding=binding):
                        forged = _elf_global_to_gnu_unique(original, binding=binding)
                        self.assertTrue(qualified_object(forged, "ELF64", machine))
                        with self.assertRaisesRegex(
                                ObjectSymbolsRejected, "E_OBJECT_SYMBOL_EXPORT_KIND"):
                            inspect_object_symbols(forged, "ELF64", machine)

    def test_coff_abort_import_must_not_be_weak_external(self):
        # A defined checked overflow trap imports strong abort. Retagging its
        # COFF symbol as WEAK_EXTERNAL (105) must never silently preserve the
        # apparently authorized "abort" import in source-native receipts.
        source_text = """declare void @abort()
define i32 @hepta_symbol_target(i32 %x) {
entry:
  %cond = icmp eq i32 %x, 0
  br i1 %cond, label %bad, label %ok
bad:
  call void @abort()
  unreachable
ok:
  ret i32 %x
}
"""
        with tempfile.TemporaryDirectory(prefix="hepta-weak-abort-") as tmp:
            root = Path(tmp)
            source = root / "abort.ll"
            artifact = root / "abort.obj"
            source.write_text(source_text)
            compiled = subprocess.run(
                ["clang", "--target=x86_64-pc-windows-msvc", "-x", "ir",
                 "-O2", "-c", str(source), "-o", str(artifact)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            original = artifact.read_bytes()
            self.assertTrue(qualified_object(original, "COFF", 0x8664))
            expected = inspect_object_symbols(original, "COFF", 0x8664)
            self.assertEqual(expected["defined"], frozenset({"hepta_symbol_target"}))
            self.assertEqual(expected["undefined"], frozenset({"abort"}))
            symbol_at, count = _u32(original, 8), _u32(original, 12)
            strings_at = symbol_at + 18 * count
            found = False
            index = 0
            while index < count:
                position = symbol_at + 18 * index
                if original[position:position + 4] == b"\0" * 4:
                    name_at = strings_at + _u32(original, position + 4)
                    name = original[name_at:original.index(b"\0", name_at)]
                else:
                    name = original[position:position + 8].split(b"\0", 1)[0]
                if name == b"abort":
                    self.assertEqual(original[position + 16], 2)
                    changed = _write(original, position + 16, 1, 105)
                    self.assertTrue(qualified_object(changed, "COFF", 0x8664))
                    with self.assertRaisesRegex(
                            ObjectSymbolsRejected, "E_OBJECT_SYMBOL_WEAK"):
                        inspect_object_symbols(changed, "COFF", 0x8664)
                    found = True
                    break
                index += 1 + original[position + 17]
            self.assertTrue(found, "Expected actual Clang-generated abort import")

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
                                    ObjectSymbolsRejected, "E_OBJECT_SYMBOL_(LOCATION|WEAK)"):
                                inspect_object_symbols(forged, fmt, machine)


if __name__ == "__main__":
    unittest.main()
