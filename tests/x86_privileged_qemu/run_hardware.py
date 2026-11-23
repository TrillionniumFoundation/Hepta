"""Test-only QEMU observer of staged privileged x86 machine bytes (NOT HIA Core)."""
from __future__ import annotations

import argparse
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO))
from hepta.hia_x86_kernel_descriptor import KernelDescriptorCode
from experiments.hia_x86_privileged_effect_lowering import (
    LeafRevoke, QuiescentOwner, lower_leaf_revoke,
)

OWNER = QuiescentOwner(
    cpl=0, cpu_count=1, max_physical_address_bits=48,
    interrupts_masked=True, preemption_disabled=True,
    exclusive_page_table_owner=True, dma_quiescent=True,
    pcid_disabled=True, global_pages_disabled=True, la57_disabled=True,
    upper_table_links_checked=True, pte_slot_identity_mapped=True,
)
REQUEST = LeafRevoke(
    active_cr3=0x180000, pte_slot_phys=0x183000,
    virtual_page=0x400000, expected_old_pte=0x400063,
    replacement_pte=0x400062,
)
EXPECTED = {"valid": (67, "P"), "stale_old": (69, "U"),
            "wrong_cr3": (69, "U"), "postcheck_race": (69, "U"),
            "cr4_pge": (69, "U"), "dishonest_noop": (255, "F"),
            "descriptor_noop": (255, "F")}
# This exact ISA signature comes from the independent GNU-as byte oracle.
# It is deliberately not looked up from the encoder under test.
_LOCKED_CAS = bytes.fromhex("f0490fb19200100000")


def exact_cas_offset(image: bytes) -> int:
    """Locate the single original CAS instruction; refuse ambiguous test hooks."""
    if type(image) is not bytes or image.count(_LOCKED_CAS) != 1:
        raise AssertionError("expected exactly one audited LOCK CMPXCHGQ site")
    location = image.index(_LOCKED_CAS)
    if not 0 < location < len(image) - len(_LOCKED_CAS):
        raise AssertionError("CAS hook outside the guarded original stage")
    return location



def checked(command: list[str], cwd: Path) -> str:
    return subprocess.run(command, cwd=cwd, check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=35).stdout


def effect_bytes(case: str) -> bytes:
    if case == "dishonest_noop":
        # An intentionally malicious fixture, never an HIA implementation.
        return b"\xc3"
    request = REQUEST
    if case == "wrong_cr3":
        request = replace(request, active_cr3=0x181000)
    elif case == "stale_old":
        request = replace(request, expected_old_pte=0x400023,
                          replacement_pte=0x400022)
    return lower_leaf_revoke(OWNER, request)


def descriptor_bytes(case: str) -> bytes:
    code = KernelDescriptorCode()
    if case != "descriptor_noop":
        code.lidt("r10")
    code.ret()
    machine, relocs = code.finalize()
    if relocs:
        raise AssertionError("descriptor must be relocation-free")
    if machine not in (bytes.fromhex("410f011ac3"), bytes.fromhex("c3")):
        raise AssertionError("LIDT/RET must match independently audited ISA vector")
    return machine


def build(case: str, directory: Path) -> dict:
    directory.mkdir(parents=True)
    effect = effect_bytes(case)
    race = case == "postcheck_race"
    cr4_pge = case == "cr4_pge"
    offset = exact_cas_offset(effect) if race else 0
    if race and effect != effect_bytes("valid"):
        raise AssertionError("postcheck race must execute byte-identical native stage")
    # Configuration is consumed ONLY by the non-HIA observer assembly.
    # No insertion or mutation of the staged native machine code is permitted.
    race_config = (f".set RACE_MODE, {int(race)}\n"
                   f".set CAS_OFFSET, {offset}\n"
                   f".set CR4_PGE_MODE, {int(cr4_pge)}\n")
    (directory / "race_config.inc").write_text(race_config)
    (directory / "effect.bin").write_bytes(effect)
    descriptor = descriptor_bytes(case)
    (directory / "descriptor.bin").write_bytes(descriptor)
    checked(["as", "--64", "-o", "boot.o", str(HERE / "boot.S")], directory)
    checked(["ld", "-nostdlib", "-T", str(HERE / "layout.ld"),
             "-o", "guest.elf", "boot.o"], directory)
    checked(["objcopy", "--dump-section", ".text=text.bin",
             "guest.elf"], directory)
    # The multiboot -kernel loader rejects ELF64 even for a 32-bit entry.
    # Convert the fully resolved ELF64 into a 32-bit container; the machine
    # bytes themselves must be byte-identical in both final linked images.
    checked(["objcopy", "-O", "elf32-i386", "guest.elf", "guest32.elf"], directory)
    checked(["objcopy", "--dump-section", ".text=text32.bin",
             "guest32.elf"], directory)
    raw_symbols = checked(["nm", "-n", "guest.elf"], directory).splitlines()
    symbols = {}
    for line in raw_symbols:
        parts = line.split()
        if len(parts) == 3 and all(x in "0123456789abcdefABCDEF" for x in parts[0]):
            symbols[parts[2]] = int(parts[0], 16)
    for key, value in (("pml4", 0x180000), ("pt", 0x183000),
                       ("stack_top", 0x192000)):
        if symbols.get(key) != value:
            raise AssertionError("guest physical layout mismatch: " + key)
    start = symbols["effect_start"] - symbols["__text_begin"]
    end = symbols["effect_end"] - symbols["__text_begin"]
    final = (directory / "text.bin").read_bytes()
    final32 = (directory / "text32.bin").read_bytes()
    descriptor_begin = symbols["descriptor_start"] - symbols["__text_begin"]
    descriptor_end = symbols["descriptor_end"] - symbols["__text_begin"]
    if final[descriptor_begin:descriptor_end] != descriptor:
        raise AssertionError("final linked LIDT bytes differ from staged descriptor encoder")
    if final != final32 or final[start:end] != effect:
        raise AssertionError("ELF64/ELF32 final machine bytes differ from staged encoder")
    executable32 = (directory / "guest32.elf").read_bytes()
    if (executable32[:5] != b"\x7fELF\x01" or
            executable32[18:20] != b"\x03\x00"):
        raise AssertionError("QEMU multiboot final ELF32 identity mismatch")
    return {
        "case": case, "byte_identity": True, "effect_bytes": len(effect),
        "postcheck_race": race, "cr4_pge_injected": cr4_pge,
        "cas_instruction_offset": offset if race else None,
        "race_bridge_config_sha256": sha256(race_config.encode()).hexdigest(),
        "effect_sha256": sha256(effect).hexdigest(),
        "descriptor_stage_sha256": sha256(descriptor).hexdigest(),
        "descriptor_stage_bytes": len(descriptor),
        "descriptor_hardware_observer": "SIDT limit and base, PC/Q35",
        "descriptor_negative_noop": case == "descriptor_noop",
        "ltr_hardware_execution": "NOT_RUN",
        "elf64_sha256": sha256((directory / "guest.elf").read_bytes()).hexdigest(),
        "image_sha256": sha256(executable32).hexdigest(),
        "test_assembly_sha256": sha256((HERE / "boot.S").read_bytes()).hexdigest(),
        "linker_sha256": sha256((HERE / "layout.ld").read_bytes()).hexdigest(),
        "implementation": "unpromoted-staged-PrivilegedCode-not-HIA-selfhost",
    }


def execute_guest(elf: Path, machine: str, expected: tuple[int, str]) -> dict:
    command = [
        "qemu-system-x86_64", "-machine", machine,
        "-m", "64M", "-smp", "1", "-kernel", str(elf),
        "-display", "none", "-serial", "none", "-monitor", "none",
        "-no-reboot", "-no-shutdown",
        "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        "-debugcon", "stdio", "-global", "isa-debugcon.iobase=0xe9",
    ]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True,
                                timeout=15, check=False)
    except subprocess.TimeoutExpired as exc:
        return {"machine": machine, "status": "TIMEOUT",
                "stdout": repr(exc.stdout)[-1000:],
                "stderr": repr(exc.stderr)[-1000:]}
    status = ("PASS" if (result.returncode, result.stdout) == expected else "FAILED")
    return {"machine": machine, "status": status,
            "returncode": result.returncode,
            "stdout": result.stdout[-2000:], "stderr": result.stderr[-2000:]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-only", action="store_true",
                        help="explicitly records QEMU as NOT_RUN")
    parser.add_argument("--report", type=Path, default=Path("qemu-hardware-report.json"))
    args = parser.parse_args()
    required = ("git", "as", "ld", "objcopy", "nm")
    if not args.build_only:
        required += ("qemu-system-x86_64",)
    absent = [name for name in required if not shutil.which(name)]
    if absent:
        args.report.write_text(json.dumps({"status": "NOT_RUN", "missing": absent}))
        print("NOT_RUN: " + ", ".join(absent))
        return 2
    sha = checked(["git", "rev-parse", "HEAD"], REPO).strip()
    report = {"schema": "hepta.x86.privileged-qemu-stage.v1",
              "candidate_sha": sha, "hia_core_privilege_effect": "NOT_IMPLEMENTED",
              "selfhost_elf_privilege_lowering": "NOT_IMPLEMENTED",
              "full_kernel_acceptance": "HOLD", "cases": [], "status": "NOT_RUN"}
    failed = False
    with tempfile.TemporaryDirectory(prefix="hia-x86-qemu-") as temp:
        for case, expected in EXPECTED.items():
            try:
                directory = Path(temp) / case
                item = build(case, directory)
                observations = []
                if args.build_only:
                    for machine in ("pc", "q35"):
                        observations.append({"machine": machine, "status": "NOT_RUN"})
                else:
                    for machine in ("pc", "q35"):
                        observations.append(execute_guest(directory / "guest32.elf",
                                                          machine, expected))
                item["observations"] = observations
                item["status"] = ("NOT_RUN" if args.build_only else
                                  "PASS" if all(r["status"] == "PASS" for r in observations)
                                  else "FAILED")
                failed |= item["status"] == "FAILED"
                report["cases"].append(item)
                print(json.dumps(item, sort_keys=True))
            except (AssertionError, KeyError, OSError,
                    subprocess.SubprocessError, ValueError) as exc:
                failed = True
                item = {"case": case, "status": "FAILED", "reason": repr(exc)}
                report["cases"].append(item)
                print(json.dumps(item, sort_keys=True))
    report["status"] = ("FAILED" if failed else
                        "NOT_RUN" if args.build_only else "PASS")
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
