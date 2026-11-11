"""Compile all three new HIA edit relay owners under original B3 limits."""
from pathlib import Path
from hashlib import sha256
import json,sys,time,traceback
BASE=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
WORK=BASE/"root-recovery/workspace";REF=BASE/"root-recovery/reference-0ef-r2"
ROOT=WORK/"native-edit-terminal-relay-r1";OUT=ROOT/"development/compile-r1"
COMPILER=WORK/"native-edit-candidate-next/development/build-r1/source/1/B3.image.bin"
RAW={}
def pin(path):
    path=Path(path).resolve();raw=path.read_bytes()
    if path in RAW:assert RAW[path]==raw
    RAW[path]=raw;return raw
def save(name,value):(OUT/name).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
OUT.mkdir(exist_ok=False)
summary=dict(status="FAIL",components={},actual_compilations=0,actual_business_entries=0,
    scope="ACTUAL_NATIVE_B3_EDIT_TERMINAL_RELAY_COMPILATION",whole_stack_closed=False,
    limits=dict(cpu_seconds=10,wall_seconds=20,address_bytes=256<<20,output_capacity=1<<20))
started=time.monotonic_ns()
try:
    pin(__file__);sys.dont_write_bytecode=True;sys.path.insert(0,str(REF))
    from tools.qualify_hia_selfhost import compile_stage
    assert sha256(pin(REF/"tools/qualify_hia_selfhost.py")).hexdigest()=="2674bbc29a67214c16595a226a0dfb28d3dcf56e238058d45e618dd42925cb76"
    assert sha256(pin(REF/"tools/hia_selfhost_child.py")).hexdigest()=="1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
    assert len(pin(COMPILER))==669556
    assert sha256(pin(COMPILER)).hexdigest()=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
    source=json.loads(pin(ROOT/"development/source-r1.json"))
    assert source["status"]=="GENERATED_NOT_COMPILED" and source["all_original_bytes_unchanged"]
    assert source["original_sources_regenerated_exactly"]==[56,57,59]
    assert set(source["components"])=={"56","57","59"}
    for role in ("56","57","59"):
        row=source["components"][role];raw=pin(row["source_path"])
        assert len(raw)==row["source_bytes"] and sha256(raw).hexdigest()==row["source_sha256"]
        sub=OUT/("role-"+role);sub.mkdir()
        try:
            image,receipt=compile_stage(sub,"edit-relay",COMPILER,raw)
            assert receipt["status"]=="returned" and receipt["abi_status"]==0
            assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
            assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
            result=pin(image);assert len(result)==receipt["core_u32"] and 0<len(result)<=1<<20
            assert sha256(result).hexdigest()==receipt["produced_sha256"]
            summary["components"][role]=dict(row,image_path=str(image),image_bytes=len(result),
                image_sha256=sha256(result).hexdigest(),receipt_path=str(sub/"edit-relay.receipt.json"),
                actual_native_B3=True,compiler_sha256=sha256(pin(COMPILER)).hexdigest())
            summary["actual_compilations"]+=1
            save("compile-progress.json",summary)
        except BaseException:
            for name in ("edit-relay.stdout.log","edit-relay.stderr.log","edit-relay.receipt.json"):
                path=sub/name
                if path.is_file():
                    value=path.read_bytes()
                    print("EDIT_RELAY_EXACT_COMPILE_EVIDENCE "+json.dumps(dict(role=role,name=name,
                        bytes=len(value),sha256=sha256(value).hexdigest(),text=value.decode())),flush=True)
            raise
    save("relay-components.json",dict(schema="hia-edit-terminal-relay-components-v1",
        components=summary["components"],substituted_roles=[56,57,59],whole_stack_closed=False))
    summary["status"]="PASS"
except BaseException as exc:
    summary.update(error_class=type(exc).__name__,error=str(exc))
    (OUT/"failure.txt").write_text(traceback.format_exc());traceback.print_exc()
finally:
    equal=all(path.read_bytes()==raw for path,raw in RAW.items())
    summary.update(source_and_image_before_after_equal=equal,elapsed_ns=time.monotonic_ns()-started)
    if not equal:summary["status"]="FAIL"
    save("source-pins.json",[dict(path=str(p),bytes=len(raw),sha256=sha256(raw).hexdigest()) for p,raw in RAW.items()])
    save("summary.json",summary);print(json.dumps(summary,sort_keys=True),flush=True)
if summary["status"]!="PASS":raise SystemExit(1)
