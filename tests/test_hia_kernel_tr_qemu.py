"""Independent native LTR/STR qualification on the combined compiler.
Reuse the exact #954 observer and original five TR cases; preserve #955 tests.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from unittest.mock import patch
from tests import test_hia_kernel_selfhost_invlpg_qemu as common

ROOT = Path(__file__).resolve().parents[1]
BOOT = ROOT / "tests/fixtures/hia_kernel_tr_qemu_boot.S"

def run(output):
    report = json.loads((output / "report.json").read_text())
    digest, dump_text, invoke, symbol = common.digest, common.dump_text, common.invoke, common.symbol
    compiler = output / "compiler-rebuilt-2"
    compiler_source = output / "candidate.hepta"
    assert report["status"] == "PASS"
    assert digest(compiler.read_bytes()) == report["compiler_sha256"]
    assert digest(compiler_source.read_bytes()) == report["source_sha256"]
    extra_cases, extra_custody = [], []
    hardware = {"status":"FAIL","cases":[],"compiler_sha256":report["compiler_sha256"],
                "compiler_source_sha256":report["source_sha256"],"observer_sha256":digest(BOOT.read_bytes()),
                "full_linux_acceptance":"HOLD","resource_authority_proved":False}
    for action, code_hex, mutation_hex in (
            ("load", "0f00d8", "909090"),
            ("read", "660f00c80fb7c0", "31c09090909090")):
        label = "tr-" + action
        entry = report["tr"][label]
        obj = output / (label + ".o")
        src = output / (label + "-1.input")
        raw = output / (label + ".text")
        native_tr, text_tr = obj.read_bytes(), raw.read_bytes()
        opcode = bytes.fromhex(code_hex)
        if (entry["oracle_hex"] != code_hex or text_tr.count(opcode) != 1
                or digest(native_tr) != entry["elf_sha256"]
                or digest(text_tr) != entry["text_sha256"]
                or digest(src.read_bytes()) != entry["source_sha256"]
                or dump_text(obj, output / (label + "-original-readback.text")) != text_tr):
            raise AssertionError(label + " native custody failed")
        macros = ("HIA_TEST_TR_" + action.upper(),)
        extra_cases.append((label + "-two-selectors", native_tr, text_tr, macros, 33, "P"))
        mutated = text_tr.replace(opcode, bytes.fromhex(mutation_hex), 1)
        if len(mutated) != len(text_tr) or mutated == text_tr:
            raise AssertionError(label + " invalid mutation")
        raw_mutant = output / (label + "-nop.text")
        raw_mutant.write_bytes(mutated)
        mutant = output / (label + "-nop.o")
        invoke(["objcopy", "--update-section", ".text=" + str(raw_mutant), str(obj), str(mutant)])
        if (dump_text(mutant, output / (label + "-nop-readback.text")) != mutated
                or symbol(obj, "f0") != symbol(mutant, "f0")):
            raise AssertionError(label + " mutation readback failed")
        extra_cases.append((label + "-missing-instruction", mutant.read_bytes(), mutated,
                            macros, 35, "N"))
        if action == "load":
            # LTR on an already busy TSS must fault at the exact subject
            # instruction, with the actual selector encoded in #GP error.
            delta = text_tr.index(opcode) - symbol(obj, "f0")
            extra_cases.append(("tr-load-busy-exact-gp", native_tr, text_tr,
                                macros + ("HIA_TEST_TR_BUSY", "HIA_TR_FAULT_DELTA=" + str(delta)),
                                33, "P"))
        extra_custody.extend(((obj, entry["elf_sha256"]), (src, entry["source_sha256"]),
                              (raw, entry["text_sha256"])))
        hardware[label + "_subject_source_sha256"] = entry["source_sha256"]
    hardware["tr_authority_proved"] = False
    hardware["native_tss_context_switch_proved"] = False
    path = output / "tr-hardware"
    path.mkdir()
    try:
        assert len(extra_cases) == 5
        with patch.object(common,"BOOT",BOOT):
            for name, binary, expected, macros, code, serial in extra_cases:
                guest, binding = common.build(path,name,binary,expected,macros)
                for machine in ("pc","q35"):
                    row={"case":name,"machine":machine,**binding}
                    try:
                        row.update(common.qemu(machine,guest,code,serial),status="PASS")
                    except Exception as exc:
                        row.update(status="FAIL",error=str(exc))
                        hardware["cases"].append(row)
                        raise
                    hardware["cases"].append(row)
        assert all(digest(p.read_bytes()) == h for p,h in extra_custody)
        assert digest(compiler.read_bytes()) == report["compiler_sha256"]
        assert digest(compiler_source.read_bytes()) == report["source_sha256"]
        hardware["status"] = "PASS"
    finally:
        (output / "tr-hardware-report.json").write_text(json.dumps(hardware,sort_keys=True,indent=2)+"\n")
        print(json.dumps(hardware,sort_keys=True))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    run(parser.parse_args().output.resolve())
