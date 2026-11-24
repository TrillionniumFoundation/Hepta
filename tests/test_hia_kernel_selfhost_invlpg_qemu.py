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
    for reg, expected_hex in (("cr0", "0f22c0"), ("cr4", "0f22e0")):
        label = reg + "-write"
        obj = output / (label + ".o")
        src = output / (label + "-1.input")
        reg_native = obj.read_bytes()
        reg_text = (output / (label + ".text")).read_bytes()
        entry = report[reg + "_write"]
        opcode = bytes.fromhex(entry["oracle_hex"])
        if (digest(reg_native) != entry["elf_sha256"] or digest(reg_text) != entry["text_sha256"]
                or digest(src.read_bytes()) != entry["source_sha256"]
                or opcode != bytes.fromhex(expected_hex) or reg_text.count(opcode) != 1
                or dump_text(obj, output / (label + "-original-readback.text")) != reg_text):
            raise AssertionError(label + " native custody or opcode failure")
        reg_bad = reg_text.replace(opcode, b"\x90"*3, 1)
        mutation = output / (label + "-dishonest.text")
        mutation.write_bytes(reg_bad)
        reg_bad_obj = output / (label + "-dishonest.o")
        invoke(["objcopy", "--update-section", ".text=" + str(mutation), str(obj), str(reg_bad_obj)])
        if (dump_text(reg_bad_obj, output / (label + "-dishonest-readback.text")) != reg_bad
                or symbol(obj, "f0") != symbol(reg_bad_obj, "f0")):
            raise AssertionError(label + " mutation readback failure")
        macros = ("HIA_TEST_" + reg.upper() + "_WRITE",)
        extra_cases.extend(((label + "-two-states", reg_native, reg_text, macros, 33, "P"),
                            (label + "-nop", reg_bad_obj.read_bytes(), reg_bad, macros, 35, "N")))
        extra_custody.extend(((obj, entry["elf_sha256"]), (src, entry["source_sha256"]),
                              (output / (label + ".text"), entry["text_sha256"])))
        hardware[reg + "_write_subject_source_sha256"] = entry["source_sha256"]
    for action, expected_hex in (("disable", "fa"), ("enable", "fb")):
        label = "irq-" + action
        obj = output / (label + ".o")
        src = output / (label + "-1.input")
        raw = output / (label + ".text")
        entry = report["irq"][label]
        irq_native = obj.read_bytes()
        irq_text = raw.read_bytes()
        opcode = bytes.fromhex(entry["oracle_hex"])
        if (digest(irq_native) != entry["elf_sha256"] or digest(irq_text) != entry["text_sha256"]
                or digest(src.read_bytes()) != entry["source_sha256"]
                or set(entry["refusals"]) != {"no-effect", "legacy", "operand", "result", "attribute", "wrong-module"}
                or opcode != bytes.fromhex(expected_hex) or irq_text.count(opcode) != 1
                or dump_text(obj, output / (label + "-original-readback.text")) != irq_text):
            raise AssertionError(label + " native custody or opcode failure")
        irq_bad = irq_text.replace(opcode, b"\x90", 1)
        mutation = output / (label + "-dishonest.text")
        mutation.write_bytes(irq_bad)
        bad_irq_obj = output / (label + "-dishonest.o")
        invoke(["objcopy", "--update-section", ".text=" + str(mutation), str(obj), str(bad_irq_obj)])
        if (dump_text(bad_irq_obj, output / (label + "-dishonest-readback.text")) != irq_bad
                or symbol(obj, "f0") != symbol(bad_irq_obj, "f0")):
            raise AssertionError(label + " mutation readback failure")
        macros = ("HIA_TEST_IRQ_" + action.upper(),)
        extra_cases.extend(((label + "-if-transition", irq_native, irq_text, macros, 33, "P"),
                            (label + "-nop", bad_irq_obj.read_bytes(), irq_bad, macros, 35, "N")))
        extra_custody.extend(((obj, entry["elf_sha256"]), (src, entry["source_sha256"]),
                              (raw, entry["text_sha256"])))
        hardware[label + "_subject_source_sha256"] = entry["source_sha256"]
    for action, expected_hex, replacement in (
            ("in8", "ec0fb6c0", "31c09090"),
            ("out8", "ee", "90"),
            ("in16", "66ed0fb7c0", "31c0909090"),
            ("out16", "66ef", "9090"),
            ("in32", "ed", None),
            ("out32", "ef", "90")):
        label = "io-" + action
        obj = output / (label + ".o")
        src = output / (label + "-1.input")
        raw = output / (label + ".text")
        entry = report["port_io"][label]
        native_io = obj.read_bytes()
        text_io = raw.read_bytes()
        opcode = bytes.fromhex(entry["oracle_hex"])
        expected_refusals = {"no-effect", "legacy", "wrong-port-type", "wrong-module",
                             "zero-operand", "extra-operand", "attribute"}
        expected_refusals |= ({"wrong-result-type", "no-result"} if action.startswith("in")
                              else {"one-operand", "wrong-value-type", "result"})
        if (digest(native_io) != entry["elf_sha256"] or digest(text_io) != entry["text_sha256"]
                or digest(src.read_bytes()) != entry["source_sha256"]
                or set(entry["refusals"]) != expected_refusals
                or opcode != bytes.fromhex(expected_hex) or text_io.count(opcode) != 1
                or dump_text(obj, output / (label + "-original-readback.text")) != text_io):
            raise AssertionError(label + " native custody or opcode failure")
        if replacement is None:
            # IN EAX,DX is only one byte; a one-byte NOP does not force a
            # known return value. Replace the entry with XOR EAX,EAX; RET
            # without changing section size, symbol address or caller ABI.
            entry_offset = symbol(obj, "f0")
            if not 0 <= entry_offset <= len(text_io) - 3:
                raise AssertionError("bad fixed-zero control entry")
            mutated_io = (text_io[:entry_offset] + b"\x31\xc0\xc3"
                          + text_io[entry_offset + 3:])
        else:
            mutated_io = text_io.replace(opcode, bytes.fromhex(replacement), 1)
        if len(mutated_io) != len(text_io) or mutated_io == text_io:
            raise AssertionError(label + " invalid mutation")
        mutation = output / (label + "-dishonest.text")
        mutation.write_bytes(mutated_io)
        bad_io = output / (label + "-dishonest.o")
        invoke(["objcopy", "--update-section", ".text=" + str(mutation), str(obj), str(bad_io)])
        if (dump_text(bad_io, output / (label + "-dishonest-readback.text")) != mutated_io
                or symbol(obj, "f0") != symbol(bad_io, "f0")):
            raise AssertionError(label + " mutation readback failure")
        macros = ("HIA_TEST_IO_" + action.upper(),)
        positive = "-two-ports" if action in ("in8", "out8", "in16") else "-two-states"
        extra_cases.extend(((label + positive, native_io, text_io, macros, 33, "P"),
                            (label + "-substitution", bad_io.read_bytes(), mutated_io, macros, 35, "N")))
        extra_custody.extend(((obj, entry["elf_sha256"]), (src, entry["source_sha256"]),
                              (raw, entry["text_sha256"])))
        hardware[label + "_subject_source_sha256"] = entry["source_sha256"]
    # CAS semantics independently observed again inside CPL0 guests.
    cas_entry = report["atomic"]["cas64"]
    cas_obj = output / "cas64.o"
    cas_src = output / "cas64-1.input"
    cas_raw = output / "cas64.text"
    cas_bad_obj = output / "cas64-nop.o"
    cas_native = cas_obj.read_bytes()
    cas_text = cas_raw.read_bytes()
    cas_opcode = bytes.fromhex("f0480fb10a")
    if (digest(cas_native) != cas_entry["elf_sha256"]
            or digest(cas_text) != cas_entry["text_sha256"]
            or digest(cas_src.read_bytes()) != cas_entry["source_sha256"]
            or cas_entry["oracle_hex"] != cas_opcode.hex()
            or cas_text.count(cas_opcode) != 1
            or cas_entry["host_observer"]["native"]["exact_alignment_trap"] is not True
            or digest(cas_bad_obj.read_bytes()) != cas_entry["nop_elf_sha256"]
            or dump_text(cas_obj, output / "cas64-original-readback.text") != cas_text):
        raise AssertionError("CAS native custody or host qualification failure")
    cas_bad_text = cas_text.replace(cas_opcode, b"\x90" * 5, 1)
    if (dump_text(cas_bad_obj, output / "cas64-mutated-readback.text") != cas_bad_text
            or symbol(cas_obj, "f0") != symbol(cas_bad_obj, "f0")):
        raise AssertionError("CAS mutation readback failure")
    extra_cases.extend((
        ("cas64-memory-success-mismatch-restore", cas_native, cas_text, ("HIA_TEST_CAS64",), 33, "P"),
        ("cas64-nop", cas_bad_obj.read_bytes(), cas_bad_text, ("HIA_TEST_CAS64",), 35, "N")))
    extra_custody.extend(((cas_obj, cas_entry["elf_sha256"]), (cas_src, cas_entry["source_sha256"]),
                          (cas_raw, cas_entry["text_sha256"]), (cas_bad_obj, cas_entry["nop_elf_sha256"])))
    hardware["cas64_subject_source_sha256"] = cas_entry["source_sha256"]
    hardware["smp_memory_model_proved"] = False
    for action, opcode_hex, replacement in (
            ("read32", "8b02", "31c0"),
            ("write32", "8902", "9090")):
        label = "mmio-" + action
        entry = report["mmio"][label]
        obj = output / (label + ".o")
        src = output / (label + "-1.input")
        raw = output / (label + ".text")
        native_mmio, text_mmio = obj.read_bytes(), raw.read_bytes()
        opcode, guard = bytes.fromhex(opcode_hex), bytes.fromhex("f6c20374020f0b")
        if (entry["oracle_hex"] != opcode.hex() or entry["guard_hex"] != guard.hex()
                or text_mmio.count(opcode) != 1 or text_mmio.count(guard) != 1
                or text_mmio.index(guard) >= text_mmio.index(opcode)
                or digest(native_mmio) != entry["elf_sha256"]
                or digest(text_mmio) != entry["text_sha256"]
                or digest(src.read_bytes()) != entry["source_sha256"]
                or dump_text(obj, output / (label + "-original-readback.text")) != text_mmio):
            raise AssertionError(label + " original native custody failed")

        def mmio_mutant(suffix, needle, change):
            mutated = text_mmio.replace(needle, change, 1)
            if mutated == text_mmio or len(mutated) != len(text_mmio):
                raise AssertionError(label + " invalid mutation")
            mutation = output / (label + suffix + ".text")
            mutation.write_bytes(mutated)
            mutant = output / (label + suffix + ".o")
            invoke(["objcopy", "--update-section", ".text=" + str(mutation), str(obj), str(mutant)])
            if (dump_text(mutant, output / (label + suffix + "-readback.text")) != mutated
                    or symbol(obj, "f0") != symbol(mutant, "f0")):
                raise AssertionError(label + " mutation readback failed")
            return mutant.read_bytes(), mutated

        noaccess, noaccess_text = mmio_mutant("-noaccess", opcode, bytes.fromhex(replacement))
        bypass, bypass_text = mmio_mutant("-noalign", guard, b"\x90" * len(guard))
        delta = text_mmio.index(guard) + 5 - symbol(obj, "f0")
        macros = ("HIA_TEST_MMIO_" + action.upper(),)
        alignment = macros + ("HIA_TEST_MMIO_ALIGN", "HIA_MMIO_TRAP_DELTA=" + str(delta))
        extra_cases.extend((
            (label + "-ioapic", native_mmio, text_mmio, macros, 33, "P"),
            (label + "-ioapic-noaccess", noaccess, noaccess_text, macros, 35, "N"),
            (label + "-unaligned-exact-ud", native_mmio, text_mmio, alignment, 33, "P"),
            (label + "-unaligned-guard-bypass", bypass, bypass_text,
             alignment + ("HIA_TEST_MMIO_GUARD_BYPASS",), 35, "N")))
        extra_custody.extend(((obj, entry["elf_sha256"]), (src, entry["source_sha256"]),
                              (raw, entry["text_sha256"])))
        hardware[label + "_subject_source_sha256"] = entry["source_sha256"]
    hardware["mmio_authority_proved"] = False
    hardware["mmio_device_mapping_owner"] = "NON_HIA_ISOLATED_OBSERVER"
    hardware["mmio_posted_write_order_proved"] = False
    for action, encoding, noaccess, truncated in (
            ("read", "0f3248c1e2204809d0", "31c090909090909090", "0f3290909090909090"),
            ("write", "4889c248c1ea200f30", "4889c248c1ea209090", "31d290909090900f30")):
        label = "msr-" + action
        entry = report["msr"][label]
        obj = output / (label + ".o")
        src = output / (label + "-1.input")
        raw = output / (label + ".text")
        native_msr, text_msr = obj.read_bytes(), raw.read_bytes()
        opcode = bytes.fromhex(encoding)
        if (entry["oracle_hex"] != encoding or text_msr.count(opcode) != 1
                or digest(native_msr) != entry["elf_sha256"]
                or digest(text_msr) != entry["text_sha256"]
                or digest(src.read_bytes()) != entry["source_sha256"]
                or dump_text(obj, output / (label + "-original-readback.text")) != text_msr):
            raise AssertionError(label + " original native custody failed")
        macros = ("HIA_TEST_MSR_" + action.upper(),)
        extra_cases.append((label + "-two-registers", native_msr, text_msr, macros, 33, "P"))
        for suffix, replacement, flag in (
                ("noaccess", noaccess, "HIA_TEST_MSR_NOOP"),
                ("truncate", truncated, "HIA_TEST_MSR_TRUNCATE")):
            mutant_text = text_msr.replace(opcode, bytes.fromhex(replacement), 1)
            if len(mutant_text) != len(text_msr) or mutant_text == text_msr:
                raise AssertionError(label + " invalid mutation")
            mutation = output / (label + "-" + suffix + ".text")
            mutation.write_bytes(mutant_text)
            mutant = output / (label + "-" + suffix + ".o")
            invoke(["objcopy", "--update-section", ".text=" + str(mutation), str(obj), str(mutant)])
            if (dump_text(mutant, output / (label + "-" + suffix + "-readback.text")) != mutant_text
                    or symbol(obj, "f0") != symbol(mutant, "f0")):
                raise AssertionError(label + " mutation readback failed")
            extra_cases.append((label + "-" + suffix, mutant.read_bytes(), mutant_text,
                                macros + (flag,), 35, "N"))
        extra_custody.extend(((obj, entry["elf_sha256"]), (src, entry["source_sha256"]),
                              (raw, entry["text_sha256"])))
        hardware[label + "_subject_source_sha256"] = entry["source_sha256"]
    hardware["msr_authority_proved"] = False
    for action, encoding in (("load", "0f011a"), ("store", "0f010a")):
        label = "idtr-" + action
        entry = report["idtr"][label]
        obj = output / (label + ".o")
        src = output / (label + "-1.input")
        raw = output / (label + ".text")
        native_idtr, text_idtr = obj.read_bytes(), raw.read_bytes()
        opcode = bytes.fromhex(encoding)
        guard = bytes.fromhex("f6c20f74020f0b")
        if (entry["oracle_hex"] != encoding or entry["guard_hex"] != guard.hex()
                or text_idtr.count(guard + opcode) != 1
                or digest(native_idtr) != entry["elf_sha256"]
                or digest(text_idtr) != entry["text_sha256"]
                or digest(src.read_bytes()) != entry["source_sha256"]
                or dump_text(obj, output / (label + "-original-readback.text")) != text_idtr):
            raise AssertionError(label + " original native custody failed")
        def idtr_mutant(suffix, needle):
            assert text_idtr.count(needle) == 1
            changed = text_idtr.replace(needle, b"\x90" * len(needle), 1)
            mutation = output / (label + suffix + ".text")
            mutation.write_bytes(changed)
            mutant = output / (label + suffix + ".o")
            invoke(["objcopy", "--update-section", ".text=" + str(mutation), str(obj), str(mutant)])
            if (dump_text(mutant, output / (label + suffix + "-readback.text")) != changed
                    or symbol(obj, "f0") != symbol(mutant, "f0")):
                raise AssertionError(label + " mutation readback failed")
            return mutant.read_bytes(), changed
        noaccess, noaccess_text = idtr_mutant("-noaccess", opcode)
        bypass, bypass_text = idtr_mutant("-noalign", guard)
        delta = text_idtr.index(guard) + 5 - symbol(obj, "f0")
        macros = ("HIA_TEST_IDTR_" + action.upper(),)
        alignment = macros + ("HIA_TEST_IDTR_ALIGN", "HIA_IDTR_TRAP_DELTA=" + str(delta))
        extra_cases.extend((
            (label + "-two-tables", native_idtr, text_idtr, macros, 33, "P"),
            (label + "-noaccess", noaccess, noaccess_text, macros + ("HIA_TEST_IDTR_NOACCESS",), 35, "N"),
            (label + "-unaligned-exact-ud", native_idtr, text_idtr, alignment, 33, "P"),
            (label + "-unaligned-guard-bypass", bypass, bypass_text,
             alignment + ("HIA_TEST_IDTR_GUARD_BYPASS",), 35, "N")))
        extra_custody.extend(((obj, entry["elf_sha256"]), (src, entry["source_sha256"]),
                              (raw, entry["text_sha256"])))
        hardware[label + "_subject_source_sha256"] = entry["source_sha256"]
    hardware["idtr_authority_proved"] = False
    hardware["interrupt_entry_iretq_owner"] = "NON_HIA_ISOLATED_OBSERVER"
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
