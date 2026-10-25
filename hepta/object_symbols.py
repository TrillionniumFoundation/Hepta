"""Bounded defined-export and external-import inventory of native objects.

These parsers inspect ELF64, COFF and Mach-O 64-bit symbol tables without
invoking a platform linker. They make no claim about running the object,
foreign ABI correctness or source-to-binary semantic preservation.
"""
from __future__ import annotations

from .object_structure import qualified_object


class ObjectSymbolsRejected(ValueError):
    pass


def _u16(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 2], "little")


def _u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 4], "little")


def _u64(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 8], "little")


def _name(b: bytes, start: int, end: int) -> str:
    if not 0 <= start < end <= len(b):
        raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_NAME: bad name offset")
    finish = b.find(b"\0", start, end)
    if finish < 0:
        raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_NAME: unterminated name")
    try:
        return b[start:finish].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_NAME: non-ASCII symbol") from exc


def inspect_object_symbols(data: bytes, fmt: str, machine: int) -> dict[str, frozenset[str]]:
    """Return defined function exports and unresolved global external names.

    The export inventory is exact for the admitted profiles, not an ABI proof.
    Unknown/missing symbol tables or malformed entries reject rather than
    being treated as empty symbol sets.
    """
    if not qualified_object(data, fmt, machine):
        raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_SHAPE: unqualified object structure")
    exported, undefined = set(), set()
    total = len(data)
    if fmt == "ELF64":
        table, sections = _u64(data, 40), _u16(data, 60)
        observed = False
        for idx in range(sections):
            sec = table + idx * 64
            if _u32(data, sec + 4) != 2:  # SHT_SYMTAB
                continue
            observed = True
            link = _u32(data, sec + 40)
            offset, size, entsize = _u64(data, sec + 24), _u64(data, sec + 32), _u64(data, sec + 56)
            if link >= sections or entsize != 24 or size % 24:
                raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_TABLE: invalid ELF symbol inventory")
            strsec = table + 64 * link
            if _u32(data, strsec + 4) != 3:
                raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_TABLE: ELF symbol strings missing")
            names, names_size = _u64(data, strsec + 24), _u64(data, strsec + 32)
            if names + names_size > total:
                raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_TABLE: ELF names outside file")
            for pos in range(offset, offset + size, 24):
                name_off, info, shndx = _u32(data, pos), data[pos + 4], _u16(data, pos + 6)
                binding, kind = info >> 4, info & 0x0f
                if not name_off or binding not in (1, 2):
                    continue
                if name_off >= names_size:
                    raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_NAME: bad ELF name")
                name = _name(data, names + name_off, names + names_size)
                if shndx == 0:
                    if name:
                        if name in exported:
                            raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_DUPLICATE: export also imported")
                        undefined.add(name)
                elif kind == 2 and name:
                    # ELF STT_FUNC is a label, not a proof that executable
                    # section bytes actually cover its declared function.
                    if not 0 < shndx < sections:
                        raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_LOCATION: invalid ELF function section")
                    section_at = table + 64 * shndx
                    section_kind = _u32(data, section_at + 4)
                    section_flags = _u64(data, section_at + 8)
                    section_bytes = _u64(data, section_at + 32)
                    value, length = _u64(data, pos + 8), _u64(data, pos + 16)
                    if (section_kind != 1 or not (section_flags & 0x4) or
                            not length or value >= section_bytes or
                            length > section_bytes - value):
                        raise ObjectSymbolsRejected(
                            "E_OBJECT_SYMBOL_LOCATION: ELF function outside executable section")
                    if name in exported or name in undefined:
                        raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_DUPLICATE: ELF function identity reused")
                    exported.add(name)
        if not observed:
            raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_TABLE: no ELF symbol table")
    elif fmt == "COFF":
        offset, count, nsections = _u32(data, 8), _u32(data, 12), _u16(data, 2)
        end = offset + 18 * count
        if not count or count > 1_000_000 or offset < 20 + nsections * 40 or end + 4 > total:
            raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_TABLE: invalid COFF symbols")
        size = _u32(data, end)
        if size < 4 or end + size > total:
            raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_TABLE: invalid COFF strings")
        idx = 0
        while idx < count:
            pos = offset + idx * 18
            section = int.from_bytes(data[pos + 12:pos + 14], "little", signed=True)
            kind, storage, aux = _u16(data, pos + 14), data[pos + 16], data[pos + 17]
            if idx + 1 + aux > count:
                raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_TABLE: truncated COFF auxiliary symbol")
            if storage in (2, 105):
                if data[pos:pos + 4] == b"\0" * 4:
                    name_off = _u32(data, pos + 4)
                    if not 4 <= name_off < size:
                        raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_NAME: invalid COFF offset")
                    name = _name(data, end + name_off, end + size)
                else:
                    raw = data[pos:pos + 8].split(b"\0", 1)[0]
                    try:
                        name = raw.decode("ascii")
                    except UnicodeDecodeError as exc:
                        raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_NAME: non-ASCII COFF symbol") from exc
                if section == 0 and name:
                    if name in exported:
                        raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_DUPLICATE: export also imported")
                    undefined.add(name)
                elif storage == 2 and section > 0 and kind & 0x20 and name:
                    if section > nsections:
                        raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_LOCATION: COFF function section missing")
                    section_at = 20 + (section - 1) * 40
                    characteristics = _u32(data, section_at + 36)
                    code_size = _u32(data, section_at + 16)
                    value = _u32(data, pos + 8)
                    # Require both IMAGE_SCN_CNT_CODE and MEM_EXECUTE,
                    # and that the exported function starts within code.
                    if (characteristics & 0x20 == 0 or
                            characteristics & 0x20000000 == 0 or
                            value >= code_size):
                        raise ObjectSymbolsRejected(
                            "E_OBJECT_SYMBOL_LOCATION: COFF function not in executable code")
                    if name in exported or name in undefined:
                        raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_DUPLICATE: COFF function identity reused")
                    exported.add(name)
            idx += 1 + aux
    elif fmt == "MACHO64":
        pos, commands, symbol_table = 32, _u32(data, 16), None
        sections: list[tuple[int, int, int, bytes, bytes]] = []
        for _ in range(commands):
            cmd, size = _u32(data, pos), _u32(data, pos + 4)
            if cmd == 0x19:  # LC_SEGMENT_64
                for index in range(_u32(data, pos + 64)):
                    if len(sections) >= 4096:
                        raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_SECTION: too many Mach-O sections")
                    entry = pos + 72 + index * 80
                    sections.append((_u64(data, entry + 32), _u64(data, entry + 40),
                                     _u32(data, entry + 64),
                                     data[entry:entry + 16].split(b"\0", 1)[0],
                                     data[entry + 16:entry + 32].split(b"\0", 1)[0]))
            if cmd == 0x2:  # LC_SYMTAB
                if symbol_table is not None:
                    raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_TABLE: duplicate Mach-O symbol table")
                symbol_table = (_u32(data, pos + 8), _u32(data, pos + 12),
                                _u32(data, pos + 16), _u32(data, pos + 20))
            pos += size
        if symbol_table is None:
            raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_TABLE: no Mach-O symbol table")
        at, count, strings, names_size = symbol_table
        if (count > 1_000_000 or at + 16 * count > total
                or strings + names_size > total):
            raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_TABLE: invalid Mach-O symbols")
        for i in range(count):
            pos = at + i * 16
            name_off, kind, sec = _u32(data, pos), data[pos + 4], data[pos + 5]
            if kind & 0xe0 or not (kind & 1):  # exclude N_STAB, require N_EXT
                continue
            if name_off >= names_size:
                raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_NAME: invalid Mach-O symbol offset")
            name = _name(data, strings + name_off, strings + names_size)
            if not name:
                continue
            if not name.startswith("_"):
                raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_NAME: missing Darwin C underscore")
            normalized = name[1:]
            if kind & 0x0e == 0:
                if normalized in exported:
                    raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_DUPLICATE: export also imported")
                undefined.add(normalized)
            elif kind & 0x0e == 0x0e:
                if not 0 < sec <= len(sections):
                    raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_LOCATION: Mach-O function section missing")
                start, length, flags, sectname, segname = sections[sec - 1]
                value = _u64(data, pos + 8)
                # N_SECT/N_EXT alone does not identify executable code.
                # This strict scalar backend only emits __TEXT,__text.
                if (sectname != b"__text" or segname != b"__TEXT" or
                        not (flags & (0x80000000 | 0x400)) or
                        not length or not start <= value < start + length):
                    raise ObjectSymbolsRejected(
                        "E_OBJECT_SYMBOL_LOCATION: Mach-O function outside executable text")
                if normalized in exported or normalized in undefined:
                    raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_DUPLICATE: Mach-O function identity reused")
                exported.add(normalized)
    else:
        raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_FORMAT: unsupported object profile")
    if not exported:
        raise ObjectSymbolsRejected("E_OBJECT_SYMBOL_EXPORT: no defined function exports")
    return {"defined": frozenset(exported), "undefined": frozenset(undefined)}
