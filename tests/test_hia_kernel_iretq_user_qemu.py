"""Execute the exact native terminal IRETQ subject only in isolated QEMU."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from unittest.mock import patch
from tests import test_hia_kernel_selfhost_invlpg_qemu as common

ROOT = Path(__file__).resolve().parents[1]
BOOT = ROOT / "tests/fixtures/hia_kernel_iretq_user_boot.S"


def offsets(data, needle):
    out, start = [], 0
    while True:
        pos = data.find(needle, start)
        if pos < 0:
            return out
        out.append(pos)
        start = pos + len(needle)


def run(output):
    report = json.loads((output / "report.json").read_text())
    entry = report["iretq"]
    compiler = output / "compiler-rebuilt-2"
    compiler_source = output / "candidate.hepta"
    obj = output / "iretq-user.o"
    src = output / "iretq-user-1.input"
    raw = output / "iretq-user.text"
    native, machine = obj.read_bytes(), raw.read_bytes()
    digest = common.digest
    assert report["status"] == "PASS"
    assert digest(compiler.read_bytes()) == report["compiler_sha256"]
    assert digest(compiler_source.read_bytes()) == report["source_sha256"]
    assert digest(native) == entry["elf_sha256"]
    assert digest(machine) == entry["text_sha256"]
    assert digest(src.read_bytes()) == entry["source_sha256"]
    assert common.dump_text(obj, output / "iretq-user-original-readback.text") == machine
    address = bytes.fromhex(entry["address_guard_hex"])
    selector = bytes.fromhex(entry["selector_guard_hex"])
    flags = bytes.fromhex(entry["flags_guard_hex"])
    terminal = bytes.fromhex(entry["return_hex"])
    a, s = offsets(machine, address), offsets(machine, selector)
    f, r = offsets(machine, flags), offsets(machine, terminal)
    assert len(a) == len(s) == 2 and len(f) == len(r) == 1
    assert a[0] < s[0] < f[0] < a[1] < s[1] < r[0]
    base = common.symbol(obj, "f0")

    def mutate(label, needle, replacement):
        assert machine.count(needle) == 1 and len(needle) == len(replacement)
        changed = machine.replace(needle, replacement, 1)
        raw_path = output / (label + ".text")
        raw_path.write_bytes(changed)
        mutant = output / (label + ".o")
        common.invoke(["objcopy", "--update-section", ".text=" + str(raw_path),
                       str(obj), str(mutant)])
        assert common.dump_text(mutant, output / (label + "-readback.text")) == changed
        assert common.symbol(mutant, "f0") == base
        return mutant.read_bytes(), changed

    noiret, noiret_text = mutate("iretq-user-nop", terminal, b"\x90\x90" + terminal[2:])
    missing_guard = flags[-6:]
    bypass, bypass_text = mutate("iretq-user-missing-bit-bypass", missing_guard, b"\x90" * 6)
    cases = [
        ("first-user-frame", native, machine, (), 33, "P"),
        ("second-user-frame", native, machine, ("HIA_TEST_IRETQ_SECOND",), 33, "P"),
    ]
    for name, macro, delta in (
        ("noncanonical-rip", "BAD_RIP", a[0] + len(address) - 2),
        ("zero-rsp", "BAD_RSP", a[1] + 5),
        ("supervisor-cs", "BAD_CS", s[0] + len(selector) - 2),
        ("null-ss", "BAD_SS", s[1] + 6),
        ("forbidden-rflags", "BAD_FLAGS", f[0] + 8),
        ("missing-rflags-bit1", "MISSING_BIT", f[0] + len(flags) - 2),
    ):
        cases.append((name, native, machine, ("HIA_TEST_IRETQ_" + macro,
                     "HIA_TEST_IRETQ_TRAP_DELTA=" + str(delta-base)), 33, "P"))
    cases.extend((
        ("deleted-iretq-terminal-trap", noiret, noiret_text,
         ("HIA_TEST_IRETQ_NOP", "HIA_TEST_IRETQ_TRAP_DELTA=" + str(r[0]+2-base)), 35, "N"),
        ("deleted-bit1-guard", bypass, bypass_text,
         ("HIA_TEST_IRETQ_MISSING_BIT", "HIA_TEST_IRETQ_GUARD_BYPASS"), 35, "N"),
    ))
    path = output / "iretq-hardware"
    path.mkdir()
    result = {
        "status": "FAIL", "cases": [], "compiler_sha256": report["compiler_sha256"],
        "compiler_source_sha256": report["source_sha256"],
        "subject_source_sha256": entry["source_sha256"], "subject_object_sha256": entry["elf_sha256"],
        "subject_text_sha256": entry["text_sha256"], "observer_sha256": digest(BOOT.read_bytes()),
        "resource_authority_proved": False, "interrupt_entry_proved": False,
        "arbitrary_context_restore_proved": False, "full_linux_acceptance": "HOLD",
    }
    try:
        with patch.object(common, "BOOT", BOOT):
            for name, binary, expected, macros, code, serial in cases:
                guest, binding = common.build(path, name, binary, expected, macros)
                for platform in ("pc", "q35"):
                    row = {"case": name, "machine": platform, **binding}
                    try:
                        row.update(common.qemu(platform, guest, code, serial), status="PASS")
                    except Exception as exc:
                        row.update(status="FAIL", error=str(exc))
                        result["cases"].append(row)
                        raise
                    result["cases"].append(row)
        assert obj.read_bytes() == native and raw.read_bytes() == machine
        assert digest(src.read_bytes()) == entry["source_sha256"]
        assert digest(compiler.read_bytes()) == report["compiler_sha256"]
        assert digest(compiler_source.read_bytes()) == report["source_sha256"]
        result["status"] = "PASS"
    finally:
        (output / "iretq-hardware-report.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    run(parser.parse_args().output.resolve())
