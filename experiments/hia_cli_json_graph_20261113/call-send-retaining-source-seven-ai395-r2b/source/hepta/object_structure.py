"""Strict finite ELF/COFF/Mach-O relocatable object *structure* checks.

Only the documented 64-bit little-endian object profiles are accepted. These
checks protect codegen acceptance from truncated, misrouted or malformed files;
they do not establish ABI compatibility, functional semantics or code safety.
"""
from __future__ import annotations


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little")


def _u64(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 8], "little")


def _bound(length: int, offset: int, size: int, minimum: int = 0) -> bool:
    return minimum <= offset <= length and size <= length - offset


def qualified_header(data: bytes, fmt: str, machine: int) -> bool:
    """Require a real file-header and bounded section/command table."""
    if not isinstance(data, bytes):
        return False
    if fmt == "ELF64":
        if (len(data) < 64 or data[:4] != b"\x7fELF"
                or data[4:6] != b"\x02\x01"
                or _u16(data, 16) != 1  # ET_REL
                or _u16(data, 18) != machine
                or _u16(data, 52) != 64):
            return False
        shoff, shentsize, count = _u64(data, 40), _u16(data, 58), _u16(data, 60)
        return shoff >= 64 and shentsize == 64 and 0 < count <= 4096 and _bound(len(data), shoff, count * 64, 64)
    if fmt == "COFF":
        if (len(data) < 60 or _u16(data, 0) != machine
                or _u16(data, 16) != 0):
            return False
        sections = _u16(data, 2)
        if not 0 < sections <= 4096 or not _bound(len(data), 20, 40 * sections, 20):
            return False
        symoff, nsyms = _u32(data, 8), _u32(data, 12)
        return (nsyms == 0 or
                (symoff >= 20 + 40 * sections and _bound(len(data), symoff, 18 * nsyms)))
    if fmt == "MACHO64":
        if (len(data) < 40 or data[:4] != b"\xcf\xfa\xed\xfe"
                or _u32(data, 4) != machine or _u32(data, 12) != 1  # MH_OBJECT
                or _u32(data, 28) != 0):
            return False
        commands, size = _u32(data, 16), _u32(data, 20)
        if not 0 < commands <= 512 or size < commands * 8 or not _bound(len(data), 32, size, 32):
            return False
        pos, end = 32, 32 + size
        for _ in range(commands):
            if pos + 8 > end:
                return False
            command_size = _u32(data, pos + 4)
            if command_size < 8 or command_size % 8 or pos + command_size > end:
                return False
            pos += command_size
        return pos == end
    return False


def qualified_object(data: bytes, fmt: str, machine: int) -> bool:
    """Check section data/relocations and symbol table extents as well as headers."""
    if not qualified_header(data, fmt, machine):
        return False
    length = len(data)
    if fmt == "ELF64":
        shoff, sections = _u64(data, 40), _u16(data, 60)
        for index in range(sections):
            section = shoff + 64 * index
            kind = _u32(data, section + 4)
            offset, size = _u64(data, section + 24), _u64(data, section + 32)
            if kind == 0:
                if index != 0 or size != 0:
                    return False
                continue
            if kind == 8:  # SHT_NOBITS: memory size, no corresponding file bytes
                continue
            if size and not _bound(length, offset, size, 64):
                return False
        return True
    if fmt == "COFF":
        sections, table_end = _u16(data, 2), 20 + 40 * _u16(data, 2)
        for index in range(sections):
            pos = 20 + index * 40
            raw_size, raw_at = _u32(data, pos + 16), _u32(data, pos + 20)
            reloc_at, lines_at = _u32(data, pos + 24), _u32(data, pos + 28)
            nreloc, nlines = _u16(data, pos + 32), _u16(data, pos + 34)
            if raw_size and not _bound(length, raw_at, raw_size, table_end):
                return False
            if nreloc and not _bound(length, reloc_at, 10 * nreloc, table_end):
                return False
            if nlines and not _bound(length, lines_at, 6 * nlines, table_end):
                return False
        return True
    if fmt == "MACHO64":
        commands, pos, end = _u32(data, 16), 32, 32 + _u32(data, 20)
        for _ in range(commands):
            command, command_size = _u32(data, pos), _u32(data, pos + 4)
            if command == 0x19:  # LC_SEGMENT_64
                if command_size < 72:
                    return False
                file_at, file_size = _u64(data, pos + 40), _u64(data, pos + 48)
                nsections = _u32(data, pos + 64)
                if nsections > 4096 or 72 + 80 * nsections > command_size:
                    return False
                if file_size and not _bound(length, file_at, file_size, end):
                    return False
                for idx in range(nsections):
                    sect = pos + 72 + idx * 80
                    size, offset = _u64(data, sect + 40), _u32(data, sect + 48)
                    reloc_at, nreloc = _u32(data, sect + 56), _u32(data, sect + 60)
                    type_code = _u32(data, sect + 64) & 0xff
                    zerofill = type_code in (0x1, 0xc, 0x12)
                    if size and not zerofill and not _bound(length, offset, size, end):
                        return False
                    if nreloc and not _bound(length, reloc_at, 8 * nreloc, end):
                        return False
            elif command == 0x2:  # LC_SYMTAB
                if command_size < 24:
                    return False
                sym_at, nsym = _u32(data, pos + 8), _u32(data, pos + 12)
                str_at, str_size = _u32(data, pos + 16), _u32(data, pos + 20)
                if nsym and not _bound(length, sym_at, 16 * nsym, end):
                    return False
                if str_size and not _bound(length, str_at, str_size, end):
                    return False
            pos += command_size
        return True
    return False
