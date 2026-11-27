"""QEMU CPL0 proof-of-execution for *actual* verified HIA Core INVLPG text.

All boot/CRx/IDT/port I/O instructions are a visible NON-HIA observation
fixture. No host INVLPG, host kernel module, or production kernel is executed.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import argparse
import json
import shutil
import subprocess
import tempfile
from unittest.mock import patch

from hepta.hia_machine_x64 import KernelCode as Code
from hepta.hia_program import verify_program
from hepta.hia_program_native import emit_program_machine
from tests.test_hia_kernel_invlpg_core import sample


HERE = Path(__file__).resolve().parent
BOOT = HERE / "fixtures" / "hia_kernel_invlpg_qemu_boot.S"
LINKER = HERE / "fixtures" / "hia_kernel_invlpg_qemu.ld"


def invoke(argv, *, timeout=30):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False)
    if result.returncode != 0:
        raise AssertionError(f"command failed {argv!r}: rc={result.returncode}\n"
                             f"stdout={result.stdout[-3000:]!r}\n"
                             f"stderr={result.stderr[-3000:]!r}")
    return result


def generate():
    admitted = verify_program(sample())
    good = emit_program_machine(admitted)
    again = emit_program_machine(verify_program(admitted.canonical_bytes))
    assert good.object_bytes == again.object_bytes
    assert good.text_bytes == again.text_bytes
    assert good.text_bytes.count(bytes.fromhex("0f0138")) == 1
    with patch.object(Code, "invlpg", lambda self, base, disp=0: self.emit(bytes((0x90,)))):
        dishonest = emit_program_machine(admitted)
    assert good.object_bytes != dishonest.object_bytes
    assert bytes.fromhex("0f0138") not in dishonest.text_bytes
    return good, dishonest


def build(root, name, native, macros):
    p = root / name
    p.mkdir()
    (p / "native.o").write_bytes(native.object_bytes)
    flags = ["-D" + macro for macro in macros]
    invoke(["cc", "-m64", "-c", "-nostdlib", "-fno-pie", *flags,
            str(BOOT), "-o", str(p / "observer.o")])
    undefined = invoke(["nm", "-u", str(p / "native.o")]).stdout
    assert {line.decode().split()[-1] for line in undefined.splitlines()} <= {"abort"}, (
        f"HIA object has unexpected runtime dependencies: {undefined!r}")
    invoke(["ld", "-nostdlib", "-z", "noexecstack", "-z", "max-page-size=0x1000",
            "-T", str(LINKER), "-o", str(p / "guest.elf"),
            str(p / "observer.o"), str(p / "native.o")])
    invoke(["objcopy", "-O", "elf32-i386", str(p / "guest.elf"),
            str(p / "guest32.elf")])
    # The Core object has an exported-wrapper to internal-function PLT32 call
    # and an unreachable abort PLT32 callsite. ld resolves their four-byte
    # operands. Mask *only* these independently enumerated ELF relocations; all remaining HIA instruction
    # bytes must match exactly, including the INVLPG opcode.
    rels = invoke(["readelf", "-Wr", str(p / "native.o")]).stdout.decode()
    offsets = []
    for line in rels.splitlines():
        if "R_X86_64_" not in line:
            continue
        fields = line.split()
        assert ("R_X86_64_PLT32" in line and fields[-3] in
                {"abort", "__hia_native_fn_0"}), (
            f"unreviewed native Core relocation: {line}")
        offsets.append(int(fields[0], 16))
    assert len(offsets) >= 2, "expected internal-call and abort relocations"
    expected = bytearray(native.text_bytes)
    for offset in offsets:
        assert 1 <= offset and offset + 4 <= len(expected)
        assert expected[offset - 1] == 0xe8, "relocation not a direct call"
        expected[offset:offset + 4] = bytes(4)

    object_nm = invoke(["nm", "-n", str(p / "native.o")]).stdout.decode()
    linked_nm = invoke(["nm", "-n", str(p / "guest.elf")]).stdout.decode()
    def value_from_nm(text, name):
        matches = [int(fields[0], 16) for line in text.splitlines()
                   if (fields := line.split()) and len(fields) >= 3
                   and fields[-1] == name]
        assert len(matches) == 1, f"missing/duplicate symbol {name}"
        return matches[0]
    f0_native = value_from_nm(object_nm, "f0")
    f0_linked = value_from_nm(linked_nm, "f0")
    headers = invoke(["objdump", "-h", str(p / "guest.elf")]).stdout.decode()
    text_sections = [line.split() for line in headers.splitlines()
                     if len(line.split()) >= 6 and line.split()[1] == ".text"]
    assert len(text_sections) == 1
    text_base = int(text_sections[0][3], 16)
    start = f0_linked - text_base - f0_native
    assert start >= 0
    sections = []
    for elf in ("guest.elf", "guest32.elf"):
        section = p / (elf + ".text")
        invoke(["objcopy", "--dump-section", ".text=" + str(section),
                str(p / elf)])
        joined = section.read_bytes()
        assert start + len(expected) <= len(joined)
        observed = bytearray(joined[start:start + len(expected)])
        for offset in offsets:
            assert observed[offset - 1] == 0xe8, "linked call opcode changed"
            observed[offset:offset + 4] = bytes(4)
        assert observed == expected, (
            f"HIA original text changed outside allowlisted abort relocs in {elf}: {name}")
        sections.append(joined)
    assert sections[0] == sections[1], "Multiboot ELF32 conversion mutated linked HIA text"
    return p / "guest32.elf"


def qemu(machine, image, expected_code, expected_serial):
    command = [
        "qemu-system-x86_64", "-machine", machine, "-cpu", "qemu64",
        "-m", "64M", "-accel", "tcg", "-display", "none", "-serial", "none",
        "-monitor", "none", "-no-reboot", "-action", "shutdown=poweroff",
        "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        "-debugcon", "stdio", "-global", "isa-debugcon.iobase=0xe9",
        "-kernel", str(image),
    ]
    try:
        done = subprocess.run(command, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=20)
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(f"{machine}: guest timed out: {image}") from exc
    output = done.stdout.decode("utf-8", "replace")
    # INVLPG is allowed to invalidate additional TLB entries. TCG may
    # invalidate a broader set, so an unrelated-VA experiment is observational,
    # NEVER a valid negative control for address selectivity.
    if expected_code is None:
        valid = (done.returncode, output) in {(33, "P"), (35, "N")}
        role = "diagnostic_overinvalidation_allowed"
    else:
        valid = done.returncode == expected_code and output == expected_serial
        role = "discriminating_hardware_oracle"
    assert valid, (
        f"{machine}/{image.parent.name}: expected rc={expected_code},"
        f" serial={expected_serial!r}; got rc={done.returncode},"
        f" serial={output!r}; stderr={done.stderr[-3000:]!r}")
    return {"machine": machine, "case": image.parent.name,
            "exit_code": done.returncode, "serial": output, "role": role}


def run():
    for name in ("cc", "ld", "nm", "objcopy", "qemu-system-x86_64"):
        if not shutil.which(name):
            raise RuntimeError(f"required independent native/QEMU tool absent: {name}")
    good, dishonest = generate()
    with tempfile.TemporaryDirectory(prefix="hia-kernel-invlpg-qemu-") as td:
        root = Path(td)
        cases = (
            ("invlpg", good, (), 33, "P"),
            ("malicious-nop", dishonest, (), 35, "N"),
            ("wrong-virtual-address", good, ("HIA_TEST_WRONG_VA",), None, None),
            ("mapping-restored", good, ("HIA_TEST_RESTORE",), 65, "R"),
        )
        reports = []
        for title, native, macros, expected_code, serial in cases:
            image = build(root, title, native, macros)
            for machine in ("pc", "q35"):
                reports.append(qemu(machine, image, expected_code, serial))
        print(json.dumps({
            "schema": "hia.kernel-invlpg-hardware-experiment.v1",
            "verified_core_sha256": sha256(verify_program(sample()).canonical_bytes).hexdigest(),
            "native_source_object_sha256": sha256(good.object_bytes).hexdigest(),
            "native_text_sha256": sha256(good.text_bytes).hexdigest(),
            "dishonest_object_sha256": sha256(dishonest.object_bytes).hexdigest(),
            "results": reports,
            "hardware_execution": "CPL0 QEMU TCG PC/Q35",
            "non_hia_bridge": [str(BOOT.relative_to(HERE.parent)),
                               str(LINKER.relative_to(HERE.parent))],
            "full_linux_rewrite": "HOLD",
            "locked_selfhost_elf": "NOT_RUN",
        }, indent=2, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    run()
