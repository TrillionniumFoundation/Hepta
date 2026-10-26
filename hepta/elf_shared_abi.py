"""Finite Linux/x86-64 ELF shared-library export and import inspection.

This checks native bytes after code generation, not LLVM/source correctness,
allocator safety, executable behavior, or general ELF loader semantics. It
limits the dynamic ABI of the narrow Hepta owned-byte LLVM host profile.
"""
from __future__ import annotations

import re


class ELFSharedABIRejected(ValueError):
    pass


def _fail(reason: str) -> None:
    raise ELFSharedABIRejected("E_LLVM_OWNED_DYNSYM: " + reason)


def _range(data: bytes, start: int, length: int) -> bool:
    return 0 <= start <= len(data) and 0 <= length <= len(data) - start


def _u(data: bytes, start: int, length: int) -> int:
    if not _range(data, start, length):
        _fail("truncated ELF record")
    return int.from_bytes(data[start:start + length], "little")


def _text_name(data: bytes, begin: int, end: int) -> str:
    if not 0 <= begin < end <= len(data):
        _fail("invalid dynamic symbol string offset")
    last = data.find(b"\0", begin, end)
    if last < 0:
        _fail("unterminated dynamic symbol name")
    try:
        name = data[begin:last].decode("ascii")
    except UnicodeError as exc:
        raise ELFSharedABIRejected("E_LLVM_OWNED_DYNSYM: non-ASCII dynamic symbol") from exc
    if not name or len(name) > 512 or re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name) is None:
        _fail("unknown/empty dynamic symbol spelling")
    return name


# These toolchain-defined weak stubs are not a Hepta-provided C API.
# Reviewable runtime effects include allocation, deallocation, abort and
# bounded standard C memory operations; any other
# unresolved symbol must reject instead of silently widening FFI authority.
_ALLOWED_UNDEFINED = frozenset({
    "malloc", "calloc", "free", "abort", "memset", "memcpy", "memmove", "__cxa_finalize",
    "_ITM_registerTMCloneTable", "_ITM_deregisterTMCloneTable", "__gmon_start__",
})


def inspect_owned_shared_elf(data: bytes, expected_exports: tuple[str, ...]) -> dict:
    """Fail closed if the dynamic ABI differs from the checked export surface.

    Return deterministic bounded metadata; no success is a safety proof.
    """
    if (not isinstance(data, bytes) or not 64 <= len(data) <= 64 * 1024 * 1024
            or not isinstance(expected_exports, tuple)
            or len(expected_exports) > 128 or expected_exports != tuple(sorted(set(expected_exports)))
            or any(not isinstance(x, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", x)
                   for x in expected_exports)):
        _fail("invalid artifact or source export list")
    if (data[:6] != b"\x7fELF\x02\x01" or data[6] != 1 or
            _u(data, 16, 2) != 3 or _u(data, 18, 2) != 62 or
            _u(data, 20, 4) != 1 or _u(data, 52, 2) != 64):
        _fail("not Linux/x86-64 ELF64 ET_DYN")
    shoff, shentsize, nsections = _u(data, 40, 8), _u(data, 58, 2), _u(data, 60, 2)
    if (shentsize != 64 or not 1 <= nsections <= 4096 or
            not _range(data, shoff, 64 * nsections)):
        _fail("missing or out-of-file ELF section table")
    sections: list[tuple[int, int, int, int, int, int, int]] = []
    for i in range(nsections):
        pos = shoff + 64 * i
        typ, flags, addr = _u(data, pos + 4, 4), _u(data, pos + 8, 8), _u(data, pos + 16, 8)
        offset, size, link, entsize = (_u(data, pos + 24, 8), _u(data, pos + 32, 8),
                                        _u(data, pos + 40, 4), _u(data, pos + 56, 8))
        if typ != 8 and size and not _range(data, offset, size):
            _fail("section points outside artifact")
        sections.append((typ, flags, addr, offset, size, link, entsize))
    phoff, phentsize, nsegments = _u(data, 32, 8), _u(data, 54, 2), _u(data, 56, 2)
    if phentsize != 56 or not 1 <= nsegments <= 128 or not _range(data, phoff, 56 * nsegments):
        _fail("missing or invalid program headers")
    executable_segments: list[tuple[int, int]] = []
    dynamic_segments: list[tuple[int, int]] = []
    for index in range(nsegments):
        pos = phoff + index * 56
        typ, flags = _u(data, pos, 4), _u(data, pos + 4, 4)
        vaddr, filesz, off = _u(data, pos + 16, 8), _u(data, pos + 32, 8), _u(data, pos + 8, 8)
        if typ == 2:  # PT_DYNAMIC is what the loader actually consumes
            if not _range(data, off, filesz) or filesz % 16:
                _fail("invalid loader dynamic table bounds")
            dynamic_segments.append((off, filesz))
        if typ == 1:  # PT_LOAD
            if not _range(data, off, filesz) or vaddr + filesz > (1 << 64):
                _fail("invalid load segment range")
            if flags & 1:  # PF_X
                executable_segments.append((vaddr, vaddr + filesz))
    if not executable_segments:
        _fail("no executable load segment")
    if len(dynamic_segments) != 1:
        _fail("missing or duplicated PT_DYNAMIC loader table")
    dyns = [s for s in sections if s[0] == 11]  # SHT_DYNSYM
    if len(dyns) != 1:
        _fail("expected exactly one dynamic symbol table")
    _, _, symaddr, symoff, symsize, link, entsize = dyns[0]
    if (not 0 <= link < len(sections) or sections[link][0] != 3 or
            entsize != 24 or symsize % 24 or not 24 <= symsize <= 24 * 65536):
        _fail("invalid dynamic symbols or string table")
    _, _, straddr, stroff, strsize, _, _ = sections[link]
    dynamic_off, dynamic_size = dynamic_segments[0]
    if dynamic_size > 16 * 4096:
        _fail("unbounded loader dynamic table")
    loader_tags: dict[int, int] = {}
    needed: list[int] = []
    terminated = False
    for at in range(dynamic_off, dynamic_off + dynamic_size, 16):
        tag, value = _u(data, at, 8), _u(data, at + 8, 8)
        if tag == 0:
            terminated = True
            break
        if tag == 1:  # DT_NEEDED library name offset into dynamic strtab
            needed.append(value)
        elif tag in (5, 6, 10, 11):  # STRTAB, SYMTAB, STRSZ, SYMENT
            if tag in loader_tags:
                _fail("duplicate loader symbol metadata")
            loader_tags[tag] = value
    if (not terminated or loader_tags != {5: straddr, 6: symaddr,
                                           10: strsize, 11: 24}):
        _fail("loader dynamic symbol/string authority disagrees with ELF sections")
    for offset in needed:
        if offset >= strsize or not _range(data, stroff + offset, 1):
            _fail("unbounded loader dependency")
        end = data.find(b"\0", stroff + offset, stroff + strsize)
        if end < 0 or data[stroff + offset:end] != b"libc.so.6":
            _fail("unreviewed DT_NEEDED shared library dependency")
    exports: set[str] = set()
    undefined: set[str] = set()
    for pos in range(symoff, symoff + symsize, 24):
        nameoff, info, other, shndx = (_u(data, pos, 4), _u(data, pos + 4, 1),
                                       _u(data, pos + 5, 1), _u(data, pos + 6, 2))
        value, size = _u(data, pos + 8, 8), _u(data, pos + 16, 8)
        if nameoff == 0:
            continue
        if nameoff >= strsize:
            _fail("dynamic string name points outside table")
        name = _text_name(data, stroff + nameoff, stroff + strsize)
        binding, kind = info >> 4, info & 15
        if binding == 0:  # local symbol, cannot be a foreign dynamic export
            continue
        if binding not in (1, 2):
            _fail("unknown dynamic symbol binding")
        if shndx == 0:
            if name in exports or name in undefined:
                _fail("duplicate external symbol identity")
            if name not in _ALLOWED_UNDEFINED:
                _fail("unreviewed external import: " + name)
            undefined.add(name)
            continue
        if (shndx >= len(sections) or (other & 3) != 0 or kind != 2
                or not size or name in exports or name in undefined):
            _fail("unknown, repeated, or invalid public function export: " + name)
        typ, flags, addr, _off, section_size, _link, _entsize = sections[shndx]
        if (typ != 1 or not flags & 4 or value < addr or
                size > section_size or value - addr > section_size - size or
                not any(a <= value and size <= b - value for a, b in executable_segments)):
            _fail("export not wholly inside executable file-backed code: " + name)
        exports.add(name)
    if exports != set(expected_exports):
        _fail("public ABI symbols differ from source: expected " + repr(expected_exports)
              + ", observed " + repr(tuple(sorted(exports))))
    return {"schema": "hepta.elf-shared-abi.v1", "format": "ELF64", "machine": 62,
            "kind": "ET_DYN", "dynamic_exports": sorted(exports),
            "unresolved_imports": sorted(undefined), "source_exports_rechecked": True,
            "claims": {"binary_abi_observed": True, "native_execution_proven": False,
                       "whole_language_memory_safety_proven": False,
                       "backend_refinement_proven": False}}
