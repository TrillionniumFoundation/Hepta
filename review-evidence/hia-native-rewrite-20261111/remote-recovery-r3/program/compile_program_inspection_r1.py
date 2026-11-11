"""Compile the reconstructed private report projector using the pinned native B3.
The original child CPU/address/output limits are unchanged. No service closure
is inferred: actual program admission and the CLI service wiring are separate.
"""
from pathlib import Path
from hashlib import sha256
import json,sys,time,traceback
BASE=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
WORK=BASE/"root-recovery/workspace"
REF=BASE/"root-recovery/reference-0ef-r2"
ROOT=WORK/"native-program-service-reconstructed-r1"
OUT=ROOT/"development/compile-r1"
COMPILER=WORK/"native-edit-candidate-next/development/build-r1/source/1/B3.image.bin"
PINS={}
def pin(path):
    path=Path(path);raw=path.read_bytes()
    if path in PINS:assert PINS[path]==raw
    PINS[path]=raw
    return raw
def save(name,value):
    (OUT/name).write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
summary=dict(status="FAIL",whole_stack_closed=False,scope="ACTUAL_NATIVE_B3_PRIVATE_PROJECTOR_COMPILATION")
OUT.mkdir(exist_ok=False)
start=time.monotonic_ns()
try:
    pin(__file__)
    sys.path.insert(0,str(REF));sys.dont_write_bytecode=True
    from tools.qualify_hia_selfhost import compile_stage
    assert sha256(pin(REF/"tools/qualify_hia_selfhost.py")).hexdigest()=="f4bcf8c4c3ee9554c8d9fc442ebaf82113fff81bc88a693b7b4e001c8a8f0567"
    assert sha256(pin(REF/"tools/hia_selfhost_child.py")).hexdigest()=="1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
    assert len(pin(COMPILER))==669556
    assert sha256(pin(COMPILER)).hexdigest()=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
    source_report=json.loads(pin(ROOT/"development/source-r1.json"))
    source=ROOT/"examples/hia_bootstrap/program_inspection.hiaasm"
    assert Path(source_report["source_path"])==source
    raw=pin(source)
    assert len(raw)==source_report["profile"]["source_bytes"]
    assert sha256(raw).hexdigest()==source_report["profile"]["source_sha256"]
    image,receipt=compile_stage(OUT,"program-inspection",COMPILER,raw)
    assert receipt["status"]=="returned" and receipt["abi_status"]==0
    assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
    assert receipt["limits"]["cpu_seconds"]==10
    assert receipt["limits"]["address_bytes"]==256<<20
    assert 0<receipt["core_u32"]<=1<<20
    result=pin(image)
    assert len(result)==receipt["core_u32"]
    assert sha256(result).hexdigest()==receipt["produced_sha256"]
    manifest=dict(schema="hia-native-program-inspection-manifest-v1",
        source_path=str(source),source_bytes=len(raw),source_sha256=sha256(raw).hexdigest(),
        image_path=str(image),image_bytes=len(result),image_sha256=sha256(result).hexdigest(),
        compiler_path=str(COMPILER),compiler_sha256=sha256(pin(COMPILER)).hexdigest(),
        receipt_path=str(OUT/"program-inspection.receipt.json"),
        generated_profile=source_report["profile"],actual_native_B3=True,
        private_projection_only=True,whole_stack_closed=False)
    save("program-inspection.manifest.json",manifest)
    summary.update(status="PASS",manifest=manifest,actual_compilations=1,
        native_child_CPU_seconds=10,native_child_wall_seconds=20,
        native_child_address_bytes=256<<20,native_output_capacity=1<<20)
except BaseException as exc:
    summary.update(error_class=type(exc).__name__,error=str(exc))
    (OUT/"failure.txt").write_text(traceback.format_exc())
    traceback.print_exc()
    for filename in ("program-inspection.stdout.log","program-inspection.stderr.log","program-inspection.receipt.json"):
        path=OUT/filename
        if path.is_file():
            print("EXACT_NESTED_COMPILE_EVIDENCE "+json.dumps(dict(
                name=filename,bytes=path.stat().st_size,sha256=sha256(path.read_bytes()).hexdigest(),
                text=path.read_text())),flush=True)
finally:
    equal=all(path.read_bytes()==raw for path,raw in PINS.items())
    summary.update(source_and_image_before_after_equal=equal,wall_elapsed_ns=time.monotonic_ns()-start)
    if not equal:summary["status"]="FAIL"
    save("source-pins.json",[dict(path=str(p),bytes=len(raw),sha256=sha256(raw).hexdigest()) for p,raw in PINS.items()])
    save("summary.json",summary)
    print(json.dumps(summary,sort_keys=True),flush=True)
if summary["status"]!="PASS":raise SystemExit(1)
