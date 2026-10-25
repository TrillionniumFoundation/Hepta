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

from .cfg import CFGSnapshot
from .ssa import SSASnapshot
from .llvm_ssa_backend import (SSA_LLVM_IR, LLVMSSARejected, _clang_run,
                               require_exact_ssa_origin)

_TARGETS = {"x86_64-unknown-linux-gnu": ("ELF64", 62),
            "aarch64-unknown-linux-gnu": ("ELF64", 183),
            "x86_64-pc-windows-msvc": ("COFF", 0x8664),
            "x86_64-apple-darwin": ("MACHO64", 0x01000007),
            "aarch64-apple-darwin": ("MACHO64", 0x0100000c)}


def _qualified_header(data: bytes, target: str) -> bool:
    """Check bounded *object* structure, not just magic and target CPU bytes.

    The strict subset intentionally rejects extended section numbering and
    unrecognized formats. Section payload offsets and lengths must fit within
    the complete artifact. This does not prove section semantics or C ABI.
    """
    if not isinstance(data, bytes) or not isinstance(target, str) or target not in _TARGETS:
        return False
    fmt, machine = _TARGETS[target]
    if fmt == "ELF64":
        if (len(data) < 64 or data[:4] != b"\x7fELF"
                or data[4:6] != b"\x02\x01"
                or data[6] != 1 or int.from_bytes(data[20:24], "little") != 1
                or data[16:18] != b"\x01\x00"
                or int.from_bytes(data[18:20], "little") != machine
                or int.from_bytes(data[52:54], "little") != 64):
            return False
        section_offset = int.from_bytes(data[40:48], "little")
        section_size = int.from_bytes(data[58:60], "little")
        section_count = int.from_bytes(data[60:62], "little")
        string_section = int.from_bytes(data[62:64], "little")
        if (not section_offset >= 64 or section_size != 64
                or not 0 < section_count <= 4096
                or section_offset + section_size * section_count > len(data)
                or string_section >= section_count):
            return False
        for index in range(section_count):
            start = section_offset + section_size * index
            header = data[start:start + section_size]
            section_type = int.from_bytes(header[4:8], "little")
            file_offset = int.from_bytes(header[24:32], "little")
            file_size = int.from_bytes(header[32:40], "little")
            alignment = int.from_bytes(header[48:56], "little")
            # SHT_NOBITS (8) has logical length but no file payload.
            if (section_type != 8 and file_size
                    and (file_offset < 64 or file_offset + file_size > len(data))):
                return False
            if alignment and alignment & (alignment - 1):
                return False
        return True
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
        section_table_end = 20 + 40 * sections
        if symbols and (symbols_at < section_table_end
                        or symbols_at + 18 * symbols > len(data)):
            return False
        for index in range(sections):
            entry = data[20 + 40 * index:20 + 40 * (index + 1)]
            raw_size = int.from_bytes(entry[16:20], "little")
            raw_offset = int.from_bytes(entry[20:24], "little")
            reloc_offset = int.from_bytes(entry[24:28], "little")
            reloc_count = int.from_bytes(entry[32:34], "little")
            if raw_size and (raw_offset < section_table_end
                             or raw_offset + raw_size > len(data)):
                return False
            if reloc_count and (reloc_offset < section_table_end
                                or reloc_offset + 10 * reloc_count > len(data)):
                return False
        return True
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
            command = int.from_bytes(data[offset:offset + 4], "little")
            if command == 0x19:  # LC_SEGMENT_64: validate section records.
                if size < 72:
                    return False
                section_count = int.from_bytes(data[offset + 64:offset + 68], "little")
                if section_count > 4096 or 72 + 80 * section_count > size:
                    return False
                for index in range(section_count):
                    section_at = offset + 72 + 80 * index
                    section = data[section_at:section_at + 80]
                    file_size = int.from_bytes(section[40:48], "little")
                    file_offset = int.from_bytes(section[48:52], "little")
                    section_type = int.from_bytes(section[64:68], "little") & 0xff
                    # Zerofill sections have no backing data in the object.
                    if (section_type not in (1, 0x0c, 0x12) and file_size
                            and (file_offset < end or file_offset + file_size > len(data))):
                        return False
            offset += size
        return offset == end
    return False


def compile_ssa_target_object(ir: SSA_LLVM_IR, *, target: str,
                              output: str | Path, clang="clang",
                              ssa: SSASnapshot | None = None,
                              cfg: CFGSnapshot | None = None) -> dict:
    """Produce an identified .o on one exact target without link or execution."""
    if not isinstance(ir, SSA_LLVM_IR):
        raise LLVMSSARejected("E_LLVM_SSA_TARGET_IR: SSA_LLVM_IR is required")
    origin_rechecked = require_exact_ssa_origin(ir, ssa=ssa, cfg=cfg)
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
        "llvm_ir_sha256": ir.sha256, "llvm_source_profile": ir.profile,
        "ssa_sha256": ir.source_ssa_sha256,
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
                   "full_language_profile_qualified": False,
                   "ssa_cfg_origin_rechecked": origin_rechecked},
    }
