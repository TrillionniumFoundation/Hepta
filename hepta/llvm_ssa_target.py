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
