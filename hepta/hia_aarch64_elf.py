"""Independent finite Core AArch64 ELF identity; no source adapter or dummy linker.

The six validator functions retain their reviewed bytes from the former shared
link utility. A successful structural inspection is not execution qualification.
"""
import re

_MAX_LINK_BYTES = 16 * 1024 * 1024

_STUBS = frozenset({"malloc", "free", "abort", "memcpy", "memmove", "memset", "_start"})

class OwnedAArch64LinkRejected(ValueError):
    pass

def _reject(reason: str) -> None:
    raise OwnedAArch64LinkRejected("E_OWNED_AARCH64_LINK: " + reason)

def _u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 2], "little")

def _u32(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 4], "little")

def _u64(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 8], "little")

def inspect_synthetic_aarch64_elf(data: bytes, exports: tuple[str, ...]) -> dict:
    """Finite ELF64 ET_EXEC loader/symbol check; NOT executable validation."""
    if (type(data) is not bytes or not 512 <= len(data) <= _MAX_LINK_BYTES
            or type(exports) is not tuple or not exports
            or any(type(n) is not str or re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", n) is None
                   for n in exports) or len(set(exports)) != len(exports)):
        _reject("invalid ELF bytes or exact export inventory")
    if (data[:6] != b"\x7fELF\x02\x01" or data[6] != 1
            or _u16(data, 16) != 2  # ET_EXEC (not relocatable or shared)
            or _u16(data, 18) != 183 or _u32(data, 20) != 1
            or _u16(data, 52) != 64 or _u16(data, 54) != 56
            or _u16(data, 58) != 64):
        _reject("wrong AArch64 ELF64 executable header")
    phoff, shoff = _u64(data, 32), _u64(data, 40)
    phnum, shnum = _u16(data, 56), _u16(data, 60)
    if (not 0 < phnum <= 128 or not 0 < shnum <= 4096
            or phoff < 64 or phoff + 56 * phnum > len(data)
            or shoff < 64 or shoff + 64 * shnum > len(data)):
        _reject("truncated executable program/section header inventory")
    entry = _u64(data, 24)
    executable_segment = False
    for index in range(phnum):
        pos = phoff + 56 * index
        kind, flags = _u32(data, pos), _u32(data, pos + 4)
        offset, addr, filebytes, membytes = (_u64(data, pos + 8), _u64(data, pos + 16),
                                             _u64(data, pos + 32), _u64(data, pos + 40))
        if (kind in {2, 3} or  # PT_DYNAMIC / PT_INTERP are forbidden
                filebytes > membytes or offset + filebytes > len(data)):
            _reject("dynamic loader, malformed program segment or missing backing bytes")
        # An executable stack or a simultaneously writable+executable load
        # segment is outside the reviewed non-runtime synthetic-link profile.
        # Checking the entrypoint alone leaves those executable mappings
        # invisible to the qualification receipt.
        if (kind == 0x6474e551 and flags & 1  # PT_GNU_STACK with PF_X
                or kind == 1 and flags & 3 == 3):  # PT_LOAD: PF_X | PF_W
            _reject("executable stack or writable executable load segment")
        if kind == 1 and flags & 1 and filebytes and addr <= entry < addr + filebytes:
            executable_segment = True
    if not executable_segment:
        _reject("entrypoint does not reside in a file-backed executable PT_LOAD")
    observed = {}
    tables = 0
    for section in range(shnum):
        pos = shoff + 64 * section
        kind = _u32(data, pos + 4)
        offset, size = _u64(data, pos + 24), _u64(data, pos + 32)
        if kind != 8 and offset + size > len(data):
            _reject("section bytes outside the linked file")
        if kind != 2:
            continue
        tables += 1
        link, stride = _u32(data, pos + 40), _u64(data, pos + 56)
        if stride != 24 or size % stride or link >= shnum:
            _reject("invalid static ELF symbol table")
        strings = shoff + 64 * link
        if _u32(data, strings + 4) != 3:
            _reject("static symbol strings absent")
        string_at, string_len = _u64(data, strings + 24), _u64(data, strings + 32)
        if string_at + string_len > len(data):
            _reject("static symbol strings outside file")
        for i in range(offset, offset + size, 24):
            at, info, shndx = _u32(data, i), data[i + 4], _u16(data, i + 6)
            binding, typ = info >> 4, info & 15
            if binding not in (0, 1, 2):
                _reject("unsupported ELF symbol binding")
            if binding == 0 or at == 0:
                continue
            if not 0 < at < string_len:
                _reject("invalid external ELF symbol name offset")
            end = data.find(b"\0", string_at + at, string_at + string_len)
            if end < 0:
                _reject("unterminated ELF symbol name")
            try:
                name = data[string_at + at:end].decode("ascii")
            except UnicodeDecodeError as exc:
                raise OwnedAArch64LinkRejected("E_OWNED_AARCH64_LINK: non-ASCII symbol") from exc
            if binding != 1 or shndx == 0 or not 0 < shndx < shnum or typ != 2:
                _reject("undefined, weak or nonfunction external ELF symbol")
            value, length = _u64(data, i + 8), _u64(data, i + 16)
            if not length or name in observed:
                _reject("duplicate or zero-length external function")
            section_header = shoff + 64 * shndx
            section_start, section_size = _u64(data, section_header + 16), _u64(data, section_header + 32)
            section_flags = _u64(data, section_header + 8)
            if ((section_flags & 6) != 6 or not section_start <= value
                    or length > section_size or value - section_start > section_size - length):
                _reject("global function does not lie within allocated executable section")
            observed[name] = {"address": value, "bytes": length}
    if tables != 1 or set(observed) != set(exports) | _STUBS:
        _reject("linked image has missing or additional external functions")
    if observed["_start"]["address"] != entry:
        _reject("entrypoint does not match synthetic _start")
    return {"format": "ELF64", "machine": 183, "entrypoint": entry,
            "external_functions": sorted(observed), "no_unresolved_symbols": True}
