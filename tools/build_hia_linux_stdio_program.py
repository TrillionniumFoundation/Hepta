"""Public, explicitly selected development backend for fixed Linux stdio.

The actual HIA compiler emits program code and the actual HIA entry packer emits
ELF headers/startup. Python supplies immutable inputs and the original bounded
child supervisor; it does not generate x86 code. An explicit caller compiler
digest is an input pin, not matching-cold or whole-system qualification.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_linux_stdio import PROFILE, require_profile, verify_linux_stdio_program
from tools.qualify_hia_selfhost import CAPACITY, compile_stage

PACKER_SOURCE = "examples/hia_bootstrap/linux_stdio_entry_packer.hepta"
COMPILER_SOURCE = "examples/hia_bootstrap/selfhost_linux_stdio.hepta"
PACK_MAGIC = int.from_bytes(b"HIALNXE1", "little")


def _digest(raw):
    return sha256(raw).hexdigest()


def _pinned_digest(value):
    if (type(value) is not str or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)):
        raise ValueError("an exact lowercase compiler SHA-256 is required")
    return value


def _save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _receipt(receipt, *, provider, source, produced):
    """Bind outer captured inputs to the actual independently returned receipt."""
    if (type(receipt) is not dict
            or receipt.get("artifact_sha256") != _digest(provider)
            or receipt.get("image_sha256") != _digest(provider)
            or receipt.get("input_sha256") != _digest(source)
            or receipt.get("source_sha256") != _digest(source)
            or type(receipt.get("input_bytes")) is not int
            or receipt["input_bytes"] != len(source)
            or receipt.get("produced_sha256") != _digest(produced)
            or type(receipt.get("produced_bytes")) is not int
            or receipt["produced_bytes"] != len(produced)
            or receipt.get("status") != "returned"
            or receipt.get("source_unchanged") is not True):
        raise ValueError("actual compile receipt differs from captured public build inputs")


def _elf_structure(elf, program):
    """Inspect actual HIA output; these checks do not emit any machine bytes."""
    size = (384 + len(program) + 4095) & -4096
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    if (type(elf) is not bytes or not 4096 <= len(elf) <= CAPACITY
            or len(elf) != size
            or struct.unpack_from("<16sHHIQQQIHHHHHH", elf) !=
               (ident, 2, 62, 1, 0x400000 + 232, 64, 0, 0, 64, 56, 3, 0, 0, 0)
            or struct.unpack_from("<IIQQQQQQ", elf, 64) !=
               (1, 5, 0, 0x400000, 0x400000, size, size, 4096)
            or struct.unpack_from("<IIQQQQQQ", elf, 120) !=
               (1, 6, size, 0x600000, 0x600000, 0, 2 * CAPACITY, 4096)
            or struct.unpack_from("<IIQQQQQQ", elf, 176) !=
               (0x6474e551, 6, 0, 0, 0, 0, 0, 16)
            or elf[384:384 + len(program)] != program
            or any(elf[384 + len(program):])):
        raise ValueError("actual HIA packed ELF differs from the fixed entry/segment contract")
    return {"elf_interpreter": False, "writable_executable_segment": False,
            "executable_stack": False, "exact_compiled_program_region": True,
            "file_bytes": size, "entry_offset": 232, "program_offset": 384,
            "source_extent": 0, "output_extent": CAPACITY,
            "workspace_extent": CAPACITY}


def build_linux_stdio_program(program, output, *, profile, compiler,
                              compiler_sha256):
    """Build, never execute, a new ELF under the original 20s/1MiB child limits."""
    require_profile(profile)
    checked = verify_linux_stdio_program(program)
    source = render_assembly(checked, profile=PROFILE).encode("utf-8")
    compiler_path = Path(compiler)
    expected = _pinned_digest(compiler_sha256)
    compiler_raw = compiler_path.read_bytes()
    if not 0 < len(compiler_raw) <= CAPACITY or _digest(compiler_raw) != expected:
        raise ValueError("caller compiler bytes differ from the explicit pin")
    packer_source = (ROOT / PACKER_SOURCE).read_bytes()
    profile_source = (ROOT / COMPILER_SOURCE).read_bytes()
    # Packer is ordinary, pure Core; its public admission must not acquire I/O.
    packer_checked = assemble_program(packer_source)
    root = Path(output)
    root.mkdir(parents=False, exist_ok=False)
    report = {"schema": "hepta.hia.linux-stdio-build.v1", "profile": PROFILE,
              "scope": "EXPLICIT_PINNED_DEVELOPMENT_COMPILER",
              "matching_cold": False, "whole": False,
              "public_core_or_code_authority": False,
              "compiler_provenance_qualified": False,
              "author_and_supervisor_python": True,
              "program_sha256": checked.sha256, "source_sha256": _digest(source),
              "compiler_sha256": expected,
              "profile_compiler_source_sha256": _digest(profile_source),
              "packer_source_sha256": _digest(packer_source),
              "packer_core_sha256": packer_checked.sha256,
              "limits": {"compile_seconds": 20, "output_bytes": CAPACITY,
                         "workspace_bytes": CAPACITY}, "stages": []}
    captured = root / "captured-compiler.image.bin"
    captured.write_bytes(compiler_raw)
    captured.chmod(0o400)
    (root / "program.hepta").write_bytes(source)
    (root / "packer.hepta").write_bytes(packer_source)
    try:
        program_image, first = compile_stage(root, "program", captured, source)
        program_raw = program_image.read_bytes()
        _receipt(first, provider=compiler_raw, source=source, produced=program_raw)
        report["stages"].append(first)
        _save(root / "PARTIAL.json", report)
        packer_image, second = compile_stage(root, "packer", captured, packer_source)
        packer_raw = packer_image.read_bytes()
        _receipt(second, provider=compiler_raw, source=packer_source, produced=packer_raw)
        report["stages"].append(second)
        _save(root / "PARTIAL.json", report)
        if len(program_raw) > CAPACITY - 384:
            raise ValueError("program leaves no room for the fixed ELF entry")
        frame = struct.pack("<QQQQ", PACK_MAGIC, 1, len(program_raw), 0) + program_raw
        elf, third = compile_stage(root, "packed", packer_image, frame,
                                   output_extension=".elf.bin")
        elf_raw = elf.read_bytes()
        _receipt(third, provider=packer_raw, source=frame, produced=elf_raw)
        report["stages"].append(third)
        report["elf_inspection"] = _elf_structure(elf_raw, program_raw)
        # Complete input rechecks are additional to each child's own pins.
        if (compiler_path.read_bytes() != compiler_raw or captured.read_bytes() != compiler_raw
                or (ROOT / PACKER_SOURCE).read_bytes() != packer_source
                or (ROOT / COMPILER_SOURCE).read_bytes() != profile_source
                or verify_linux_stdio_program(checked).canonical_bytes != checked.canonical_bytes
                or program_image.read_bytes() != program_raw or packer_image.read_bytes() != packer_raw
                or elf.read_bytes() != elf_raw):
            raise ValueError("public build inputs changed")
        destination = root / "program.elf"
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(elf_raw)
                stream.flush()
                os.fsync(fd)
            os.fchmod(fd, 0o500)
        finally:
            os.close(fd)
        if destination.read_bytes() != elf_raw:
            raise ValueError("ELF publication differs from actual HIA output")
        report.update(status="DEVELOPMENT_BUILD", executable=str(destination.resolve()),
                      executable_bytes=len(elf_raw), executable_sha256=_digest(elf_raw),
                      inputs_unchanged=True, payload_executed=False)
        return report
    except BaseException as exc:
        report.update(status="FAIL", error_type=type(exc).__name__, error=str(exc))
        raise
    finally:
        _save(root / "REPORT.json", report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--profile", required=True, choices=[PROFILE])
    parser.add_argument("--compiler", required=True, type=Path)
    parser.add_argument("--compiler-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    checked = assemble_program(args.source.read_bytes(), profile=args.profile)
    report = build_linux_stdio_program(checked, args.output, profile=args.profile,
        compiler=args.compiler, compiler_sha256=args.compiler_sha256)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
