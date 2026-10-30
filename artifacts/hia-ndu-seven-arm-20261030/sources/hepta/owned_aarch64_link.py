"""Strict AArch64 *synthetic* freestanding link probe for checked Owned objects.

This tool verifies actual AArch64 relocations can be resolved by a finite
explicit set of C symbols using lld. Its intentionally nonfunctional dummy
allocator and _start are NEVER a target runtime: the linked ELF must not be
run, published as a product executable or described as an ABI qualification.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re
import shutil
import tempfile

from .llvm_owned_aarch64 import (
    TARGET_AARCH64, MAX_OBJECT_BYTES, inspect_owned_aarch64_object,
)
from .llvm_ssa_backend import _clang_run
from .native_tool_identity import ToolIdentityRejected, digest_executable


_MAX_LINK_BYTES = 16 * 1024 * 1024
_STUBS = frozenset({"malloc", "free", "abort", "memcpy", "memmove", "memset", "_start"})
_SHIM = """\
typedef __SIZE_TYPE__ hepta_size_t;
/* Link probe ONLY: these functions must never execute as a runtime. */
void *malloc(hepta_size_t n) { (void)n; return (void *)0; }
void free(void *p) { (void)p; }
__attribute__((noreturn)) void abort(void) { for (;;) {} }
void *memset(void *p, int v, hepta_size_t n) { (void)v; (void)n; return p; }
void *memcpy(void *p, const void *s, hepta_size_t n) { (void)s; (void)n; return p; }
void *memmove(void *p, const void *s, hepta_size_t n) { (void)s; (void)n; return p; }
void _start(void) { for (;;) {} }
"""


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


def probe_owned_aarch64_freestanding_link(object_bytes: bytes, exports: tuple[str, ...],
                                          *, clang: str = "clang") -> dict:
    """Link an existing checked-format object against NONEXECUTABLE dummy stubs.

    Compiler/linker success is a real static-relocation check but these stubs
    are deliberately invalid implementations of allocation and device I/O.
    """
    if type(object_bytes) is not bytes or not 0 < len(object_bytes) <= MAX_OBJECT_BYTES:
        _reject("input object is missing or outside bounded size")
    inspect_owned_aarch64_object(object_bytes, exports)
    executable = shutil.which(clang)
    if executable is None:
        _reject("Clang compiler unavailable for cross-link check")
    executable = str(Path(executable).resolve())
    try:
        compiler_before = digest_executable(executable)
    except ToolIdentityRejected as exc:
        raise OwnedAArch64LinkRejected(
            "E_OWNED_AARCH64_LINK: bounded Clang identity unavailable") from exc
    with tempfile.TemporaryDirectory(prefix=".hepta-aarch64-synthetic-link-") as directory:
        folder = Path(directory)
        obj, shim, shim_obj, linked = [folder / name for name in
                                      ("owned.o", "shim.c", "shim.o", "link-only.elf")]
        obj.write_bytes(object_bytes)
        shim.write_text(_SHIM, encoding="ascii")
        compiled = _clang_run([executable, "--target=" + TARGET_AARCH64,
                               "-x", "c", "-std=c11", "-ffreestanding", "-nostdinc",
                               "-fno-builtin", "-fno-stack-protector", "-O0",
                               "-Wall", "-Wextra", "-Werror", "-c",
                               str(shim), "-o", str(shim_obj)], timeout=30)
        if compiled.returncode:
            _reject("freestanding ABI shim compilation failed: " + compiled.stderr[:1000])
        linked_run = _clang_run([executable, "--target=" + TARGET_AARCH64,
                                 "-fuse-ld=lld", "-nostdlib", "-static",
                                 "-Wl,-e,_start", str(obj), str(shim_obj),
                                 "-o", str(linked)], timeout=45)
        if linked_run.returncode:
            _reject("AArch64 freestanding link unresolved: " + linked_run.stderr[:1000])
        if (not linked.is_file() or linked.is_symlink()
                or not 512 <= linked.stat().st_size <= _MAX_LINK_BYTES):
            _reject("linked ELF missing or exceeds bounded artifact size")
        payload = linked.read_bytes()
        observed = inspect_synthetic_aarch64_elf(payload, exports)
        try:
            compiler_stable = digest_executable(executable) == compiler_before
        except ToolIdentityRejected:
            compiler_stable = False
        if not compiler_stable:
            _reject("selected native compiler changed during synthetic link")
        return {"schema": "hepta.owned-aarch64-synthetic-link.v1",
                "status": "synthetic_freestanding_link_only_not_executed",
                "target": TARGET_AARCH64, "object_sha256": sha256(object_bytes).hexdigest(),
                "link_shim_sha256": sha256(_SHIM.encode("ascii")).hexdigest(),
                "linked_sha256": sha256(payload).hexdigest(), "linked_bytes": len(payload),
                "symbols": observed,
                "relocations_linked_with_dummy_shims": True,
                "real_allocator_linked": False, "linux_runtime_qualified": False,
                "c_abi_execution_qualified": False, "physical_hardware_executed": False}
