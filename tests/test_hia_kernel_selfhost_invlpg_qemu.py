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
    path = output / "hardware"
    path.mkdir()
    try:
        for name, binary, text, macros, code, serial in (
            ("invlpg", native, expected, (), 33, "P"),
            ("malicious-nop", bad_obj.read_bytes(), bad_text, (), 35, "N"),
            ("mapping-restored", native, expected, ("HIA_TEST_RESTORE",), 65, "R"),
            ("wrong-virtual-address", native, expected, ("HIA_TEST_WRONG_VA",), None, None)):
            guest, binding = build(path, name, binary, text, macros)
            for machine in ("pc", "q35"):
                try:
                    observed = qemu(machine, guest, code, serial)
                except Exception as exc:
                    hardware["cases"].append({"case": name, "machine": machine,
                                              "status": "FAIL", "error": str(exc), **binding})
                    raise
                hardware["cases"].append({**observed, **binding, "status": "PASS"})
        if (original.read_bytes() != native
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
