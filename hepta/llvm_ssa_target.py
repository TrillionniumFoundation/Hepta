"""Target-specific object-only compilation for the checked i32 SSA/PHI LLVM pilot.

Emits native object bytes on five explicit targets and verifies ELF/COFF/Mach-O
machine and object-file identifiers. This is NOT cross-C-ABI, device or execution qualification.
"""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import shutil
import tempfile

from .llvm_ssa_backend import SSA_LLVM_IR, LLVMSSARejected, _clang_run

_TARGETS = {"x86_64-unknown-linux-gnu": ("ELF64", 62),
            "aarch64-unknown-linux-gnu": ("ELF64", 183),
            "x86_64-pc-windows-msvc": ("COFF", 0x8664),
            "x86_64-apple-darwin": ("MACHO64", 0x01000007),
            "aarch64-apple-darwin": ("MACHO64", 0x0100000c)}


def _payload_extents_bounded(data: bytes, fmt: str) -> bool:
    """Check referenced file extents in supported object sections.

    A syntactically complete object header may still point to out-of-file
    executable bytes, relocations or symbol tables. Do not call such an
    artifact qualified. This remains a bounded format check, not code proof.
    """
    total = len(data)

    def u16(offset: int) -> int:
        return int.from_bytes(data[offset:offset + 2], "little")

    def u32(offset: int) -> int:
        return int.from_bytes(data[offset:offset + 4], "little")

    def u64(offset: int) -> int:
        return int.from_bytes(data[offset:offset + 8], "little")

    def within(offset: int, size: int, first: int = 0) -> bool:
        return first <= offset <= total and size <= total - offset

    if fmt == "ELF64":
        table, sections = u64(40), u16(60)
        for index in range(sections):
            entry = table + 64 * index
            kind, offset, size = u32(entry + 4), u64(entry + 24), u64(entry + 32)
            if kind == 0:  # SHT_NULL; extended section encodings are unsupported.
                if index != 0 or size != 0:
                    return False
            elif kind != 8 and size and not within(offset, size, 64):  # SHT_NOBITS has no file payload.
                return False
        return True

    if fmt == "COFF":
        count = u16(2)
        end_of_headers = 20 + 40 * count
        for index in range(count):
            entry = 20 + 40 * index
            raw_size, raw_at = u32(entry + 16), u32(entry + 20)
            reloc_at, lines_at = u32(entry + 24), u32(entry + 28)
            relocs, lines = u16(entry + 32), u16(entry + 34)
            if raw_size and not within(raw_at, raw_size, end_of_headers):
                return False
            if relocs and not within(reloc_at, 10 * relocs, end_of_headers):
                return False
            if lines and not within(lines_at, 6 * lines, end_of_headers):
                return False
        return True

    if fmt == "MACHO64":
        cursor, end = 32, 32 + u32(20)
        for _ in range(u32(16)):
            command, length = u32(cursor), u32(cursor + 4)
            if command == 0x19:  # LC_SEGMENT_64
                if length < 72:
                    return False
                seg_at, seg_size, sections = u64(cursor + 40), u64(cursor + 48), u32(cursor + 64)
                if sections > 4096 or 72 + 80 * sections > length:
                    return False
                if seg_size and not within(seg_at, seg_size, end):
                    return False
                for index in range(sections):
                    entry = cursor + 72 + 80 * index
                    size, offset = u64(entry + 40), u32(entry + 48)
                    reloc_at, relocs = u32(entry + 56), u32(entry + 60)
                    kind = u32(entry + 64) & 0xff
                    # Zero-fill, giant zero-fill and thread-local zero-fill
                    # reserve memory but do not occupy file bytes.
                    no_payload = kind in (0x1, 0xc, 0x12)
                    if size and not no_payload and not within(offset, size, end):
                        return False
                    if relocs and not within(reloc_at, 8 * relocs, end):
                        return False
            elif command == 0x2:  # LC_SYMTAB
                if length < 24:
                    return False
                sym_at, symbols = u32(cursor + 8), u32(cursor + 12)
                str_at, str_size = u32(cursor + 16), u32(cursor + 20)
                if symbols and not within(sym_at, 16 * symbols, end):
                    return False
                if str_size and not within(str_at, str_size, end):
                    return False
            cursor += length
        return True
    return False


def _qualified_header(data: bytes, target: str) -> bool:
    """Check bounded *object* structure, not just magic and target CPU bytes.

    The strict subset intentionally rejects extended section numbering and
    unrecognized formats. It does not prove sections' semantics or C ABI.
    """
    fmt, machine = _TARGETS[target]
    if fmt == "ELF64":
        if (len(data) < 64 or data[:4] != b"\x7fELF"
                or data[4:6] != b"\x02\x01"
                or data[16:18] != b"\x01\x00"
                or int.from_bytes(data[18:20], "little") != machine
                or int.from_bytes(data[52:54], "little") != 64):
            return False
        section_offset = int.from_bytes(data[40:48], "little")
        section_size = int.from_bytes(data[58:60], "little")
        section_count = int.from_bytes(data[60:62], "little")
        return (section_offset >= 64 and section_size == 64
                and 0 < section_count <= 4096
                and section_offset + section_size * section_count <= len(data)
                and _payload_extents_bounded(data, fmt))
    if fmt == "COFF":
        if len(data) < 60 or int.from_bytes(data[:2], "little") != machine:
            return False
        sections = int.from_bytes(data[2:4], "little")
        optional_bytes = int.from_bytes(data[16:18], "little")
        if (not 0 < sections <= 4096 or optional_bytes != 0
                or 20 + 40 * sections > len(data)):
            return False
        symbols_at = int.from_bytes(data[8:12], "little")
        symbols = int.from_bytes(data[12:16], "little")
        return ((symbols == 0 or
                 (symbols_at >= 20 + 40 * sections
                  and symbols_at + 18 * symbols <= len(data)))
                and _payload_extents_bounded(data, fmt))
    if fmt == "MACHO64":
        if (len(data) < 40 or data[:4] != b"\xcf\xfa\xed\xfe"
                or int.from_bytes(data[4:8], "little") != machine
                or int.from_bytes(data[12:16], "little") != 1
                or int.from_bytes(data[28:32], "little") != 0):
            return False
        commands = int.from_bytes(data[16:20], "little")
        command_bytes = int.from_bytes(data[20:24], "little")
        if (not 0 < commands <= 512 or command_bytes < commands * 8
                or 32 + command_bytes > len(data)):
            return False
        offset = 32
        end = 32 + command_bytes
        for _ in range(commands):
            if offset + 8 > end:
                return False
            size = int.from_bytes(data[offset + 4:offset + 8], "little")
            if size < 8 or size % 8 or offset + size > end:
                return False
            offset += size
        return offset == end and _payload_extents_bounded(data, fmt)
    return False


def _defined_exports(data: bytes, target: str) -> frozenset[str]:
    """Inspect defined, externally visible function symbols in a native object.

    The artifact must first pass the bounded ELF/COFF/Mach-O structural gates.
    A valid object header alone does not establish that LLVM emitted requested
    functions. This is a symbol-inventory check, not semantic or ABI proof.
    """
    if target not in _TARGETS or not _qualified_header(data, target):
        return frozenset()
    fmt, _ = _TARGETS[target]
    found: set[str] = set()

    def u16(at: int) -> int:
        return int.from_bytes(data[at:at + 2], "little")

    def u32(at: int) -> int:
        return int.from_bytes(data[at:at + 4], "little")

    def u64(at: int) -> int:
        return int.from_bytes(data[at:at + 8], "little")

    def string(at: int, end: int) -> str | None:
        if not 0 <= at < end <= len(data):
            return None
        nul = data.find(b"\0", at, end)
        if nul < 0:
            return None
        try:
            return data[at:nul].decode("ascii")
        except UnicodeDecodeError:
            return None

    if fmt == "ELF64":
        table, sections = u64(40), u16(60)
        for index in range(sections):
            entry = table + 64 * index
            if u32(entry + 4) != 2:  # SHT_SYMTAB
                continue
            link, entry_size = u32(entry + 40), u64(entry + 56)
            symbols_at, symbol_bytes = u64(entry + 24), u64(entry + 32)
            if link >= sections or entry_size != 24 or symbol_bytes % 24:
                return frozenset()
            strings = table + 64 * link
            if u32(strings + 4) != 3:  # SHT_STRTAB
                return frozenset()
            string_at, string_bytes = u64(strings + 24), u64(strings + 32)
            for symbol in range(symbols_at, symbols_at + symbol_bytes, 24):
                name_at, info, section = u32(symbol), data[symbol + 4], u16(symbol + 6)
                if (name_at >= string_bytes or info & 0x0f != 2
                        or info >> 4 not in (1, 2)  # STB_GLOBAL/STB_WEAK
                        or not 0 < section < sections):
                    continue
                # In ET_REL the symbol value is a byte offset into its
                # section. A named STT_FUNC in .data or beyond .text is not
                # evidence of a callable instruction entry point.
                target_section = table + 64 * section
                kind, flags = u32(target_section + 4), u64(target_section + 8)
                extent = u64(target_section + 32)
                value, width = u64(symbol + 8), u64(symbol + 16)
                if (kind != 1 or not flags & 0x4 or not extent
                        or value >= extent or width > extent - value):
                    continue
                name = string(string_at + name_at, string_at + string_bytes)
                if name:
                    found.add(name)
        return frozenset(found)

    if fmt == "COFF":
        count, at = u32(12), u32(8)
        strings = at + 18 * count
        if (not count or count > 1_000_000 or at < 20 + 40 * u16(2)
                or strings + 4 > len(data)):
            return frozenset()
        string_size = u32(strings)
        if string_size < 4 or strings + string_size > len(data):
            return frozenset()
        index = 0
        while index < count:
            symbol = at + 18 * index
            section = int.from_bytes(data[symbol + 12:symbol + 14], "little", signed=True)
            typ, storage, aux = u16(symbol + 14), data[symbol + 16], data[symbol + 17]
            if index + 1 + aux > count:
                return frozenset()
            if storage == 2 and typ & 0x20 and 0 < section <= u16(2):
                code_section = 20 + 40 * (section - 1)
                characteristics = u32(code_section + 36)
                raw_bytes = u32(code_section + 16)
                symbol_offset = u32(symbol + 8)
                # IMAGE_SCN_CNT_CODE and IMAGE_SCN_MEM_EXECUTE must both
                # hold. An external function label in .data is insufficient.
                if (not characteristics & 0x20
                        or not characteristics & 0x20000000
                        or not raw_bytes or symbol_offset >= raw_bytes):
                    index += 1 + aux
                    continue
                if data[symbol:symbol + 4] == b"\0" * 4:
                    offset = u32(symbol + 4)
                    name = (string(strings + offset, strings + string_size)
                            if 4 <= offset < string_size else None)
                else:
                    try:
                        name = data[symbol:symbol + 8].split(b"\0", 1)[0].decode("ascii")
                    except UnicodeDecodeError:
                        name = None
                if name:
                    found.add(name)
            index += 1 + aux
        return frozenset(found)

    if fmt == "MACHO64":
        command = 32
        symbol_table = None
        code_sections: dict[int, tuple[int, int, int]] = {}
        next_section = 0
        for _ in range(u32(16)):
            operation, size = u32(command), u32(command + 4)
            if operation == 0x19:  # LC_SEGMENT_64
                for slot in range(u32(command + 64)):
                    next_section += 1
                    entry = command + 72 + 80 * slot
                    code_sections[next_section] = (u64(entry + 32),
                                                   u64(entry + 40),
                                                   u32(entry + 64))
            if operation == 2:  # LC_SYMTAB
                symbol_table = (u32(command + 8), u32(command + 12),
                                u32(command + 16), u32(command + 20))
            command += size
        if symbol_table is None:
            return frozenset()
        at, count, strings, string_size = symbol_table
        if count > 1_000_000:
            return frozenset()
        for index in range(count):
            entry = at + 16 * index
            name_at, kind, section = u32(entry), data[entry + 4], data[entry + 5]
            if (name_at >= string_size or kind & 0x0e != 0x0e
                    or not kind & 1 or section not in code_sections):  # N_SECT | N_EXT
                continue
            address, extent, flags = code_sections[section]
            value = u64(entry + 8)
            # Only nonempty regular instruction sections and actual n_value
            # locations inside their declared extent count as a function.
            if (flags & 0xff != 0
                    or not (flags & 0x80000000 or flags & 0x400)
                    or not extent or not address <= value < address + extent):
                continue
            name = string(strings + name_at, strings + string_size)
            # Darwin's external C symbol spelling includes one leading '_'.
            if name and name.startswith("_"):
                found.add(name[1:])
        return frozenset(found)
    return frozenset()


def compile_ssa_target_object(ir: SSA_LLVM_IR, *, target: str,
                              output: str | Path, clang="clang") -> dict:
    """Produce an identified .o on one exact target without link or execution."""
    if not isinstance(ir, SSA_LLVM_IR):
        raise LLVMSSARejected("E_LLVM_SSA_TARGET_IR: SSA_LLVM_IR is required")
    ir.check_identity()
    if target not in _TARGETS:
        raise LLVMSSARejected("E_LLVM_SSA_TARGET: unsupported target object profile")
    found = shutil.which(clang)
    if found is None:
        raise LLVMSSARejected("E_LLVM_SSA_TOOLCHAIN: Clang executable is unavailable")
    compiler = Path(found).resolve()
    version = _clang_run([str(compiler), "--version"], timeout=10)
    if version.returncode or not version.stdout.strip():
        raise LLVMSSARejected("E_LLVM_SSA_TOOLCHAIN: missing compiler identity")
    # Do not dereference a dangling destination symlink: resolving the final
    # component would silently publish the object to the symlink target.
    # os.link below is no-replace, including when a new symlink races us.
    destination = Path(output).absolute()
    if destination.is_symlink() or destination.exists() or not destination.parent.is_dir():
        raise LLVMSSARejected("E_LLVM_SSA_OUTPUT: destination exists or directory is missing")
    with tempfile.TemporaryDirectory(prefix=".hepta-ssa-target-", dir=destination.parent) as folder:
        source = Path(folder) / "module.ll"
        artifact = Path(folder) / "target.o"
        source.write_text(ir.text, encoding="utf-8")
        cmd = [str(compiler), "--target=" + target, "-x", "ir", "-O3", "-c",
               str(source), "-o", str(artifact)]
        result = _clang_run(cmd, timeout=45)
        if result.returncode != 0:
            raise LLVMSSARejected("E_LLVM_SSA_TARGET_NATIVE: " + result.stderr[:1200])
        data = artifact.read_bytes() if artifact.is_file() else b""
        if not _qualified_header(data, target):
            raise LLVMSSARejected("E_LLVM_SSA_TARGET_IDENTITY: wrong/empty ELF, COFF or Mach-O machine/file type")
        exports = _defined_exports(data, target)
        missing = set(ir.functions) - exports
        if missing:
            raise LLVMSSARejected("E_LLVM_SSA_SYMBOLS: requested defined exports absent: "
                                  + ", ".join(sorted(missing)))
        try:
            os.link(artifact, destination)
        except FileExistsError as exc:
            raise LLVMSSARejected("E_LLVM_SSA_OUTPUT: destination race or overwrite rejected") from exc
    return {
        "schema": "hepta.llvm-ssa-object.v0",
        "status": "cross_object_only_not_executed",
        "target": target, "object_format": _TARGETS[target][0],
        "machine": _TARGETS[target][1],
        "functions": list(ir.functions),
        "verified_defined_exports": sorted(set(ir.functions)),
        "llvm_ir_sha256": ir.sha256, "ssa_sha256": ir.source_ssa_sha256,
        "structural_ssa_verification_sha256": ir.verification_sha256,
        "artifact_sha256": sha256(destination.read_bytes()).hexdigest(),
        "artifact_bytes": destination.stat().st_size,
        "compiler": {"version": version.stdout.splitlines()[0],
                     "sha256": sha256(compiler.read_bytes()).hexdigest()},
        "claims": {"target_object_compiled": True,
                   "target_program_executed": False,
                   "foreign_c_abi_qualified": False,
                   "physical_hardware_tested": False,
                   "native_backend_semantics_proved": False,
                   "full_language_profile_qualified": False},
    }
