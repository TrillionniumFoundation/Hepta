"""Independent CPL0 observer for exact native terminal integer frame restore."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from unittest.mock import patch
from tests import test_hia_kernel_selfhost_invlpg_qemu as common

ROOT = Path(__file__).resolve().parents[1]
BOOT = ROOT / "tests/fixtures/hia_kernel_frame_boot.S"


def run(output):
    report=json.loads((output/"report.json").read_text())
    entry=report["kernel_frame"]
    compiler=output/"compiler-rebuilt-2"
    compiler_source=output/"candidate.hepta"
    obj=output/"kernel-frame.o"
    src=output/"kernel-frame-1.input"
    raw=output/"kernel-frame.text"
    native,machine=obj.read_bytes(),raw.read_bytes()
    digest=common.digest
    assert report["status"]=="PASS"
    assert digest(compiler.read_bytes())==report["compiler_sha256"]
    assert digest(compiler_source.read_bytes())==report["source_sha256"]
    assert digest(native)==entry["elf_sha256"]
    assert digest(machine)==entry["text_sha256"]
    assert digest(src.read_bytes())==entry["source_sha256"]
    assert common.dump_text(obj,output/"kernel-frame-original-readback.text")==machine
    encoding=bytes.fromhex(entry["encoding_hex"])
    assert machine.count(encoding)==1 and len(encoding)==213
    start=machine.index(encoding)
    base=common.symbol(obj,"f0")

    def mutate(label,offset,original,replacement):
        assert encoding[offset:offset+len(original)]==original and len(original)==len(replacement)
        at=start+offset
        changed=machine[:at]+replacement+machine[at+len(original):]
        raw_path=output/(label+".text")
        raw_path.write_bytes(changed)
        mutant=output/(label+".o")
        common.invoke(["objcopy","--update-section",".text="+str(raw_path),str(obj),str(mutant)])
        assert common.dump_text(mutant,output/(label+"-readback.text"))==changed
        assert common.symbol(mutant,"f0")==base
        return mutant.read_bytes(),changed

    cases=[
        ("first-kernel-frame",native,machine,(),33,"P"),
        ("second-kernel-frame",native,machine,("HIA_TEST_FRAME_SECOND",),33,"P"),
    ]
    for name,macro,offset in (
        ("null-frame","NULL",0x5),
        ("unaligned-frame","ALIGN",0xb),
        ("high-frame","HIGH",0x19),
        ("cross-canonical-end","CROSS",0x2b),
        ("entry-if-enabled","IF",0x38),
        ("wrong-cs","CS",0x5a),
        ("wrong-ss","SS",0x66),
        ("zero-rip","ZERO_RIP",0x71),
        ("high-rip","HIGH_RIP",0x7c),
        ("zero-rsp","ZERO_RSP",0x8a),
        ("unaligned-rsp","BAD_RSP_ALIGN",0x91),
        ("high-rsp","HIGH_RSP",0x9c),
        ("forbidden-rflags","FLAGS",0xae),
        ("missing-rflags-bit1","BIT1",0xb5),
    ):
        assert encoding[offset:offset+2]==b"\x0f\x0b"
        cases.append((name,native,machine,("HIA_TEST_FRAME_"+macro,
                     "HIA_TEST_FRAME_TRAP_DELTA="+str(start+offset-base)),33,"P"))
    noiret,noiret_text=mutate("kernel-frame-iret-nop",0xd1,b"\x48\xcf",b"\x90\x90")
    badgpr,badgpr_text=mutate("kernel-frame-r15-wrong",0xba,b"\x41\x5f",b"\x41\x5e")
    cases.extend((
        ("deleted-iretq",noiret,noiret_text,("HIA_TEST_FRAME_IRET_NOP",
          "HIA_TEST_FRAME_TRAP_DELTA="+str(start+0xd3-base)),35,"N"),
        ("wrong-r15-restore",badgpr,badgpr_text,("HIA_TEST_FRAME_GPR_MUTANT",),35,"N"),
    ))
    path=output/"kernel-frame-hardware"
    path.mkdir()
    result={"status":"FAIL","cases":[],"compiler_sha256":report["compiler_sha256"],
            "compiler_source_sha256":report["source_sha256"],
            "subject_source_sha256":entry["source_sha256"],"subject_object_sha256":entry["elf_sha256"],
            "subject_text_sha256":entry["text_sha256"],"observer_sha256":digest(BOOT.read_bytes()),
            "restricted_native_integer_frame_restore":False,"interrupt_entry_proved":False,
            "arbitrary_context_restore_proved":False,"frame_resource_authority_proved":False,
            "fpu_context_proved":False,"full_linux_acceptance":"HOLD"}
    try:
        with patch.object(common,"BOOT",BOOT):
            for name,binary,expected,macros,code,serial in cases:
                guest,binding=common.build(path,name,binary,expected,macros)
                for platform in ("pc","q35"):
                    row={"case":name,"machine":platform,**binding}
                    try:
                        row.update(common.qemu(platform,guest,code,serial),status="PASS")
                    except Exception as exc:
                        row.update(status="FAIL",error=str(exc))
                        result["cases"].append(row)
                        raise
                    result["cases"].append(row)
        assert obj.read_bytes()==native and raw.read_bytes()==machine
        assert digest(src.read_bytes())==entry["source_sha256"]
        assert digest(compiler.read_bytes())==report["compiler_sha256"]
        assert digest(compiler_source.read_bytes())==report["source_sha256"]
        result.update(status="PASS",restricted_native_integer_frame_restore=True,
                      all_fifteen_gprs_verified=True,exact_trap_controls=True,
                      iretq_and_wrong_gpr_mutants_detected=True)
    finally:
        (output/"kernel-frame-hardware-report.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
        print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,required=True)
    run(p.parse_args().output.resolve())
