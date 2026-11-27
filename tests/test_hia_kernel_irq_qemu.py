"""Independent real IDT transfer to the raw native interrupt entry."""
from __future__ import annotations
import argparse,json
from pathlib import Path
from unittest.mock import patch
from tests import test_hia_kernel_selfhost_invlpg_qemu as common

ROOT=Path(__file__).resolve().parents[1]
BOOT=ROOT/"tests/fixtures/hia_kernel_irq_boot.S"

def run(output):
    report=json.loads((output/"report.json").read_text())
    entry=report["kernel_irq"]
    obj=output/"kernel-irq.o"
    source=output/"kernel-irq-1.input"
    machine=(output/"kernel-irq.text").read_bytes()
    native=obj.read_bytes()
    digest=common.digest
    assert report["status"]=="PASS"
    assert digest((output/"compiler-rebuilt-2").read_bytes())==report["compiler_sha256"]
    assert digest((output/"candidate.hepta").read_bytes())==report["source_sha256"]
    assert digest(native)==entry["elf_sha256"] and digest(machine)==entry["text_sha256"]
    assert digest(source.read_bytes())==entry["source_sha256"]
    assert common.dump_text(obj,output/"kernel-irq-original-readback.text")==machine
    encoding=bytes.fromhex(entry["encoding_hex"])
    start=common.symbol(obj,"f0")
    assert machine[start:start+len(encoding)]==encoding and machine.count(encoding)==1
    assert encoding[:23]==bytes.fromhex("5053515256575541504151415241534154415541564157")
    def mutate(label,offset,original,replacement):
        assert encoding[offset:offset+len(original)]==original and len(original)==len(replacement)
        at=start+offset
        changed=machine[:at]+replacement+machine[at+len(original):]
        raw=output/(label+".text");raw.write_bytes(changed)
        target=output/(label+".o")
        common.invoke(["objcopy","--update-section",".text="+str(raw),str(obj),str(target)])
        assert common.dump_text(target,output/(label+"-readback.text"))==changed
        assert common.symbol(target,"f0")==start
        return target.read_bytes(),changed
    null_gs=encoding.index(bytes.fromhex("4885c075020f0ba807"))+5
    live_if=encoding.index(bytes.fromhex("9c5a48f7c20002000074020f0b"))+11
    saved_df=encoding.index(bytes.fromhex("48f7c228f5ffff74020f0b"))+9
    null_callback=encoding.index(bytes.fromhex("488b004885c075020f0b"))+8
    high_callback=encoding.index(bytes.fromhex("4883e4f0ffd0"))-2
    restore=encoding.index(bytes.fromhex("4885c075020f0b"),encoding.index(bytes.fromhex("ffd0"))+2)
    null_result=restore+5
    for at in (null_gs,null_callback,high_callback,null_result,live_if,saved_df):
        assert encoding[at:at+2]==b"\x0f\x0b"
    def trap(macro,at):return ("HIA_TEST_IRQ_"+macro,"HIA_TEST_IRQ_TRAP_DELTA="+str(at))
    badsave,badtext=mutate("kernel-irq-r15-save-wrong",21,b"\x41\x57",b"\x41\x56")
    noiret,noirettext=mutate("kernel-irq-iret-nop",len(encoding)-4,b"\x48\xcf",b"\x90\x90")
    cases=[
      ("first-int",native,machine,(),33,"P"),
      ("second-int",native,machine,("HIA_TEST_IRQ_SECOND",),33,"P"),
      ("null-gs",native,machine,trap("NULL_GS",null_gs),35,"N"),
      ("trap-gate-if",native,machine,trap("IF",live_if),35,"N"),
      ("saved-direction-flag",native,machine,trap("DF",saved_df),35,"N"),
      ("null-callback",native,machine,trap("NULL_CALLBACK",null_callback),35,"N"),
      ("high-callback",native,machine,trap("HIGH_CALLBACK",high_callback),35,"N"),
      ("null-result",native,machine,trap("NULL_RESULT",null_result),35,"N"),
      ("wrong-r15-save",badsave,badtext,("HIA_TEST_IRQ_SAVE_MUTANT",),35,"N"),
      ("deleted-iretq",noiret,noirettext,trap("IRET_NOP",len(encoding)-2),35,"N"),
    ]
    path=output/"kernel-irq-hardware";path.mkdir()
    result={"status":"FAIL","cases":[],"compiler_sha256":report["compiler_sha256"],
        "compiler_source_sha256":report["source_sha256"],"subject_source_sha256":entry["source_sha256"],
        "subject_object_sha256":entry["elf_sha256"],"subject_text_sha256":entry["text_sha256"],
        "observer_sha256":digest(BOOT.read_bytes()),"native_raw_irq_entry":False,
        "native_gpr_capture":False,"native_return":False,"resource_authority_proved":False,
        "hardware_external_irq_proved":False,"full_linux_acceptance":"HOLD"}
    try:
        with patch.object(common,"BOOT",BOOT):
            for name,binary,expected,macros,code,serial in cases:
                guest,binding=common.build(path,name,binary,expected,macros)
                for platform in ("pc","q35"):
                    row={"case":name,"machine":platform,**binding}
                    try:row.update(common.qemu(platform,guest,code,serial),status="PASS")
                    except Exception as exc:
                        row.update(status="FAIL",error=str(exc));result["cases"].append(row);raise
                    result["cases"].append(row)
        assert obj.read_bytes()==native and digest(source.read_bytes())==entry["source_sha256"]
        assert digest((output/"compiler-rebuilt-2").read_bytes())==report["compiler_sha256"]
        result.update(status="PASS",native_raw_irq_entry=True,native_gpr_capture=True,native_return=True,
                      exact_trap_controls=True,independent_all_gpr_capture_and_restore=True)
    finally:
        (output/"kernel-irq-hardware-report.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
        print(json.dumps(result,sort_keys=True))
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);run(p.parse_args().output.resolve())
