"""Target-specific object-only compilation for the checked i32 SSA/PHI LLVM pilot.

Emits native object bytes on five explicit targets and verifies ELF/COFF/Mach-O
machine and object-file identifiers. This is NOT cross-C-ABI, device or execution qualification.
"""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from .llvm_ssa_backend import SSA_LLVM_IR, LLVMSSARejected

_TARGETS = {"x86_64-unknown-linux-gnu": ("ELF64", 62),
            "aarch64-unknown-linux-gnu": ("ELF64", 183),
            "x86_64-pc-windows-msvc": ("COFF", 0x8664),
            "x86_64-apple-darwin": ("MACHO64", 0x01000007),
            "aarch64-apple-darwin": ("MACHO64", 0x0100000c)}


def _qualified_header(data: bytes, target: str) -> bool:
    fmt, machine = _TARGETS[target]
    if fmt == "ELF64":
        return (len(data) >= 64 and data[:4] == b"\x7fELF"
                and data[4:6] == b"\x02\x01"
                and data[16:18] == b"\x01\x00"
                and int.from_bytes(data[18:20], "little") == machine)
    if fmt == "COFF":
        return (len(data) >= 20 and int.from_bytes(data[:2], "little") == machine
                and int.from_bytes(data[2:4], "little") > 0)
    if fmt == "MACHO64":
        # Little-endian MH_MAGIC_64, 64-bit CPU subtype and MH_OBJECT only.
        # Linking and execution are deliberately outside the object gate.
        return (len(data) >= 32 and data[:4] == b"\xcf\xfa\xed\xfe"
                and int.from_bytes(data[4:8], "little") == machine
                and int.from_bytes(data[12:16], "little") == 1)
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
    version = subprocess.run([str(compiler), "--version"], capture_output=True,
                             text=True, timeout=10, check=False)
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
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=45, check=False)
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
