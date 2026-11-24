"""Hardware oracle for the actual experimental selfhost-generated ELF object.

Unlike the Python-authored Core backend, this scalar ELF has no external
symbols or relocations. No HIA bytes are masked during linking. The original
non-HIA boot observer still owns CRx, exception entry and the test machine.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.test_hia_kernel_invlpg_qemu import BOOT, LINKER, invoke, qemu

def digest(data):
    return sha256(data).hexdigest()

def dump_text(path, destination):
    # GNU objcopy with no output object rewrites its input even for
    # --dump-section. Never let the observer normalize the subject ELF.
    if path.resolve() == destination.resolve() or (
            destination.exists() and path.samefile(destination)):
        raise AssertionError("section destination aliases input ELF")
    before = path.read_bytes()
    with TemporaryDirectory(prefix="hia-section-readback-") as scratch:
        invoke(["objcopy", "--dump-section", ".text=" + str(destination),
                str(path), str(Path(scratch) / "discard.o")])
    if path.read_bytes() != before:
        raise AssertionError("section extraction modified input ELF")
    return destination.read_bytes()

def symbol(path, name):
    lines = invoke(["nm", "-n", str(path)]).stdout.decode().splitlines()
    values = [int(fields[0], 16) for line in lines if (fields := line.split())
              and len(fields) >= 3 and fields[-1] == name]
    if len(values) != 1:
        raise AssertionError(("missing/duplicate symbol", str(path), name))
    return values[0]

def build(root, name, native, expected, macros):
    path = root / name
    path.mkdir()
    obj = path / "native.o"
    obj.write_bytes(native)
    if invoke(["nm", "-u", str(obj)]).stdout.strip():
        raise AssertionError("selfhost scalar ELF has unresolved symbols")
    relocs = invoke(["readelf", "-Wr", str(obj)]).stdout.decode()
    (path / "relocations.txt").write_text(relocs)
    if "R_X86_64_" in relocs or "There are no relocations" not in relocs:
        raise AssertionError("unexpected selfhost ELF relocation")
    if dump_text(obj, path / "native.text") != expected:
        raise AssertionError("input object text mismatch")
    invoke(["cc", "-m64", "-c", "-nostdlib", "-fno-pie",
            *["-D" + x for x in macros], str(BOOT), "-o", str(path / "observer.o")])
    guest = path / "guest.elf"
    guest32 = path / "guest32.elf"
    invoke(["ld", "-nostdlib", "-z", "noexecstack", "-z", "max-page-size=0x1000",
            "-T", str(LINKER), "-o", str(guest), str(path / "observer.o"), str(obj)])
    invoke(["objcopy", "-O", "elf32-i386", str(guest), str(guest32)])
    headers = invoke(["objdump", "-h", str(guest)]).stdout.decode()
    rows = [line.split() for line in headers.splitlines()
            if len(line.split()) >= 6 and line.split()[1] == ".text"]
    if len(rows) != 1:
        raise AssertionError("ambiguous linked text")
    start = symbol(guest, "f0") - int(rows[0][3], 16) - symbol(obj, "f0")
    if start < 0:
        raise AssertionError("negative HIA text offset")
    texts = [dump_text(image, path / (image.name + ".text")) for image in (guest, guest32)]
    if texts[0] != texts[1] or any(t[start:start + len(expected)] != expected for t in texts):
        raise AssertionError("selfhost object bytes changed in linked/bootable ELF")
    return guest32, {"native_object_sha256": digest(native),
        "native_text_sha256": digest(expected), "guest_elf64_sha256": digest(guest.read_bytes()),
        "guest_elf32_sha256": digest(guest32.read_bytes()), "native_text_offset": start,
        "native_relocation_count": 0}

def run(output):
    report = json.loads((output / "report.json").read_text())
    if report["status"] != "PASS" or report["guest_execution"] != "NOT_RUN":
        raise AssertionError("native bootstrap evidence missing")
    original = output / "invlpg.o"
    source = output / "invlpg-1.input"
    native = original.read_bytes()
    expected = (output / "invlpg.text").read_bytes()
    if (digest(native) != report["elf_sha256"] or digest(expected) != report["text_sha256"]
        or digest(source.read_bytes()) != report["subject_source_sha256"]
        or digest((output / "candidate.hepta").read_bytes()) != report["source_sha256"]
        or digest((output / "compiler-rebuilt-2").read_bytes()) != report["compiler_sha256"]):
        raise AssertionError("native bootstrap artifact custody failed")
    if dump_text(original, output / "original-readback.text") != expected:
        raise AssertionError("original object readback changed")
    # Noncanonical trailing bytes distinguish an immutable readback from
    # an objcopy in-place rewrite even when the section bytes are identical.
    with TemporaryDirectory(prefix="hia-custody-control-") as scratch:
        control = Path(scratch) / "control.o"
        control_bytes = native + b"HIA-CUSTODY-TRAILER"
        control.write_bytes(control_bytes)
        if dump_text(control, Path(scratch) / "control.text") != expected:
            raise AssertionError("custody control text differs")
        if control.read_bytes() != control_bytes:
            raise AssertionError("custody control was normalized")
        alias = Path(scratch) / "alias.o"
        alias.hardlink_to(control)
        try:
            dump_text(control, alias)
        except AssertionError as exc:
            if str(exc) != "section destination aliases input ELF":
                raise
        else:
            raise AssertionError("hard-linked destination accepted")
    oracle = bytes.fromhex(report["oracle_hex"])
    if oracle != bytes.fromhex("0f0138") or expected.count(oracle) != 1:
        raise AssertionError("missing exact INVLPG")
    if set(report["refusals"]) != {"missing-effect", "legacy-profile", "legacy-opcode",
            "legacy-declaration", "wrong-type", "zero-operand", "extra-operand",
            "result", "attribute", "duplicate-effect", "flat-profile", "missing-exports"}:
        raise AssertionError("INVLPG refusal manifest is not bound to INVLPG")
    bad_text = expected.replace(oracle, b"\x90"*3, 1)
    mutation = output / "qemu-dishonest.text"
    mutation.write_bytes(bad_text)
    bad_obj = output / "qemu-dishonest.o"
    invoke(["objcopy", "--update-section", ".text=" + str(mutation), str(original), str(bad_obj)])
    if (dump_text(bad_obj, output / "qemu-dishonest-readback.text") != bad_text
        or symbol(original, "f0") != symbol(bad_obj, "f0")):
        raise AssertionError("negative control object readback mismatch")
    hardware = {"schema": "hia.kernel-selfhost-invlpg-hardware.v1", "status": "FAIL",
        "compiler_sha256": report["compiler_sha256"], "compiler_source_sha256": report["source_sha256"],
        "subject_source_sha256": digest(source.read_bytes()), "observer_sha256": digest(BOOT.read_bytes()),
        "linker_sha256": digest(LINKER.read_bytes()), "cases": [],
        "locked_compiler_changed": False, "privilege_authority_proved": False,
        "full_linux_acceptance": "HOLD", "artifact_custody": "NOT_CONFIRMED"}
    cr3_obj = output / "cr3.o"
    cr3_native = cr3_obj.read_bytes()
    cr3_text = (output / "cr3.text").read_bytes()
    cr3_report = report["cr3_read"]
    cr3_source = output / "cr3-1.input"
    cr3_opcode = bytes.fromhex(cr3_report["oracle_hex"])
    if (digest(cr3_native) != cr3_report["elf_sha256"]
            or digest(cr3_text) != cr3_report["text_sha256"]
            or digest(cr3_source.read_bytes()) != cr3_report["source_sha256"]
            or cr3_opcode != bytes.fromhex("0f20d8")
            or cr3_text.count(cr3_opcode) != 1
            or dump_text(cr3_obj, output / "cr3-original-readback.text") != cr3_text):
        raise AssertionError("CR3 native custody or opcode failure")
    # Same-width defined-zero substitution, not a stale register or a crash.
    cr3_bad_text = cr3_text.replace(cr3_opcode, bytes.fromhex("4831c0"), 1)
    cr3_mutation = output / "cr3-dishonest.text"
    cr3_mutation.write_bytes(cr3_bad_text)
    cr3_bad_obj = output / "cr3-dishonest.o"
    invoke(["objcopy", "--update-section", ".text=" + str(cr3_mutation),
            str(cr3_obj), str(cr3_bad_obj)])
    if (dump_text(cr3_bad_obj, output / "cr3-dishonest-readback.text") != cr3_bad_text
            or symbol(cr3_obj, "f0") != symbol(cr3_bad_obj, "f0")):
        raise AssertionError("CR3 mutation readback failure")
    hardware["cr3_subject_source_sha256"] = digest((output / "cr3-1.input").read_bytes())
    write_obj = output / "cr3-write.o"
    write_native = write_obj.read_bytes()
    write_text = (output / "cr3-write.text").read_bytes()
    write_source = output / "cr3-write-1.input"
    write_report = report["cr3_write"]
    write_opcode = bytes.fromhex(write_report["oracle_hex"])
    if (digest(write_native) != write_report["elf_sha256"]
            or digest(write_text) != write_report["text_sha256"]
            or digest(write_source.read_bytes()) != write_report["source_sha256"]
            or write_opcode != bytes.fromhex("0f22d8")
            or write_text.count(write_opcode) != 1
            or dump_text(write_obj, output / "cr3-write-original-readback.text") != write_text):
        raise AssertionError("CR3 write native custody or opcode failure")
    write_bad_text = write_text.replace(write_opcode, b"\x90"*3, 1)
    write_mutation = output / "cr3-write-dishonest.text"
    write_mutation.write_bytes(write_bad_text)
    write_bad_obj = output / "cr3-write-dishonest.o"
    invoke(["objcopy", "--update-section", ".text=" + str(write_mutation),
            str(write_obj), str(write_bad_obj)])
    if (dump_text(write_bad_obj, output / "cr3-write-dishonest-readback.text") != write_bad_text
            or symbol(write_obj, "f0") != symbol(write_bad_obj, "f0")):
        raise AssertionError("CR3 write mutation readback failure")
    hardware["cr3_write_subject_source_sha256"] = digest(write_source.read_bytes())
    cr2_obj = output / "cr2.o"
    cr2_native = cr2_obj.read_bytes()
    cr2_text = (output / "cr2.text").read_bytes()
    cr2_source = output / "cr2-1.input"
    cr2_report = report["cr2_read"]
    cr2_opcode = bytes.fromhex(cr2_report["oracle_hex"])
    if (digest(cr2_native) != cr2_report["elf_sha256"]
            or digest(cr2_text) != cr2_report["text_sha256"]
            or digest(cr2_source.read_bytes()) != cr2_report["source_sha256"]
            or cr2_opcode != bytes.fromhex("0f20d0")
            or cr2_text.count(cr2_opcode) != 1
            or dump_text(cr2_obj, output / "cr2-original-readback.text") != cr2_text):
        raise AssertionError("CR2 native custody or opcode failure")
    cr2_bad_text = cr2_text.replace(cr2_opcode, bytes.fromhex("4831c0"), 1)
    cr2_mutation = output / "cr2-dishonest.text"
    cr2_mutation.write_bytes(cr2_bad_text)
    cr2_bad_obj = output / "cr2-dishonest.o"
    invoke(["objcopy", "--update-section", ".text=" + str(cr2_mutation),
            str(cr2_obj), str(cr2_bad_obj)])
    if (dump_text(cr2_bad_obj, output / "cr2-dishonest-readback.text") != cr2_bad_text
            or symbol(cr2_obj, "f0") != symbol(cr2_bad_obj, "f0")):
        raise AssertionError("CR2 mutation readback failure")
    hardware["cr2_subject_source_sha256"] = digest(cr2_source.read_bytes())
    extra_cases = []
    extra_custody = []
    for reg, expected_hex in (("cr0", "0f20c0"), ("cr4", "0f20e0")):
        obj = output / (reg + ".o")
        src = output / (reg + "-1.input")
        reg_native = obj.read_bytes()
        reg_text = (output / (reg + ".text")).read_bytes()
        entry = report[reg + "_read"]
        opcode = bytes.fromhex(entry["oracle_hex"])
        if (digest(reg_native) != entry["elf_sha256"] or digest(reg_text) != entry["text_sha256"]
                or digest(src.read_bytes()) != entry["source_sha256"]
                or opcode != bytes.fromhex(expected_hex) or reg_text.count(opcode) != 1
                or dump_text(obj, output / (reg + "-original-readback.text")) != reg_text):
            raise AssertionError(reg + " native custody or opcode failure")
        reg_bad = reg_text.replace(opcode, bytes.fromhex("4831c0"), 1)
        mutation = output / (reg + "-dishonest.text")
        mutation.write_bytes(reg_bad)
        reg_bad_obj = output / (reg + "-dishonest.o")
        invoke(["objcopy", "--update-section", ".text=" + str(mutation), str(obj), str(reg_bad_obj)])
        if (dump_text(reg_bad_obj, output / (reg + "-dishonest-readback.text")) != reg_bad
                or symbol(obj, "f0") != symbol(reg_bad_obj, "f0")):
            raise AssertionError(reg + " mutation readback failure")
        macros = ("HIA_TEST_" + reg.upper() + "_READ",)
        extra_cases.extend(((reg + "-read-two-states", reg_native, reg_text, macros, 33, "P"),
                            (reg + "-zero-substitution", reg_bad_obj.read_bytes(), reg_bad, macros, 35, "N")))
        extra_custody.extend(((obj, entry["elf_sha256"]), (src, entry["source_sha256"]),
                              (output / (reg + ".text"), entry["text_sha256"])))
        hardware[reg + "_subject_source_sha256"] = entry["source_sha256"]
    path = output / "hardware"
    path.mkdir()
    try:
        for name, binary, text, macros, code, serial in (
            ("invlpg", native, expected, (), 33, "P"),
            ("malicious-nop", bad_obj.read_bytes(), bad_text, (), 35, "N"),
            ("mapping-restored", native, expected, ("HIA_TEST_RESTORE",), 65, "R"),
            ("wrong-virtual-address", native, expected, ("HIA_TEST_WRONG_VA",), None, None),
            ("cr3-read-two-roots", cr3_native, cr3_text, ("HIA_TEST_CR3_READ",), 33, "P"),
            ("cr3-zero-substitution", cr3_bad_obj.read_bytes(), cr3_bad_text,
             ("HIA_TEST_CR3_READ",), 35, "N"),
            ("cr3-write-two-roots", write_native, write_text, ("HIA_TEST_CR3_WRITE",), 33, "P"),
            ("cr3-write-nop", write_bad_obj.read_bytes(), write_bad_text,
             ("HIA_TEST_CR3_WRITE",), 35, "N"),
            ("cr2-read-two-faults", cr2_native, cr2_text, ("HIA_TEST_CR2_READ",), 33, "P"),
            ("cr2-zero-substitution", cr2_bad_obj.read_bytes(), cr2_bad_text,
             ("HIA_TEST_CR2_READ",), 35, "N"), *extra_cases):
            guest, binding = build(path, name, binary, text, macros)
            for machine in ("pc", "q35"):
                try:
                    observed = qemu(machine, guest, code, serial)
                except Exception as exc:
                    hardware["cases"].append({"case": name, "machine": machine,
                                              "status": "FAIL", "error": str(exc), **binding})
                    raise
                hardware["cases"].append({**observed, **binding, "status": "PASS"})
        if (any(digest(p.read_bytes()) != expected_hash for p, expected_hash in extra_custody)
                or original.read_bytes() != native
                or cr2_obj.read_bytes() != cr2_native
                or (output / "cr2.text").read_bytes() != cr2_text
                or digest(cr2_source.read_bytes()) != cr2_report["source_sha256"]
                or write_obj.read_bytes() != write_native
                or (output / "cr3-write.text").read_bytes() != write_text
                or digest(write_source.read_bytes()) != write_report["source_sha256"]
                or digest(source.read_bytes()) != report["subject_source_sha256"]
                or digest(cr3_source.read_bytes()) != cr3_report["source_sha256"]
                or cr3_obj.read_bytes() != cr3_native
                or (output / "cr3.text").read_bytes() != cr3_text
                or (output / "invlpg.text").read_bytes() != expected
                or digest((output / "candidate.hepta").read_bytes()) != report["source_sha256"]
                or digest((output / "compiler-rebuilt-2").read_bytes()) != report["compiler_sha256"]):
            raise AssertionError("original HIA artifact changed during guest tests")
        hardware["artifact_custody"] = "PASS"
        hardware["status"] = "PASS"
    except Exception as exc:
        hardware["error"] = str(exc)
        raise
    finally:
        (output / "hardware-report.json").write_text(json.dumps(hardware, indent=2, sort_keys=True) + "\n")
        print(json.dumps(hardware, sort_keys=True))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.output.resolve())
