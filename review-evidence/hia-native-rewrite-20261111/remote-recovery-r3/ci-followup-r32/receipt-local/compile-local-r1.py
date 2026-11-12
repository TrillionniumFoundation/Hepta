from pathlib import Path
from hashlib import sha1,sha256
import importlib.util,json,os,resource,sys,time,traceback
sys.dont_write_bytecode=True
resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
base=Path("/workspace/scratch/hia-root-r31");ref=base/"reference-0ef-subset"
out=base/"receipt-compile-r1";out.mkdir(exist_ok=False)
source=base/"receipt-generation-r1/ordinary_patch_receipt.hiaasm"
compiler=base/"seed/B3-35ee92b7.image.bin"
pins={}
def read(p):
    p=p.resolve();r=p.read_bytes();pins[p]=r;return r
def gitsha(r):return sha1(b"blob "+str(len(r)).encode()+b"\0"+r).hexdigest()
summary=dict(status="FAIL",scope="LOCAL_EXACT_ORIGINAL_B3_COMPILATION",CI_qualification=False,
    actual_B3=0,receipt_runtime_entries=0,whole_stack_closed=False)
try:
    raw=read(source);assert sha256(raw).hexdigest()=="e0809903daba34e3fb5392627850077c45b2d2e0e7061ee1230e6886ace78334"
    seed=read(compiler);assert len(seed)==669556 and sha256(seed).hexdigest()=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
    assert sha256(read(ref/"tools/qualify_hia_selfhost.py")).hexdigest()=="2674bbc29a67214c16595a226a0dfb28d3dcf56e238058d45e618dd42925cb76"
    assert sha256(read(ref/"tools/hia_selfhost_child.py")).hexdigest()=="1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
    for p in sorted(ref.rglob("*.py")):read(p)
    sys.path.insert(0,str(ref))
    from tools.qualify_hia_selfhost import compile_stage
    image,receipt=compile_stage(out,"ordinary-patch-receipt",compiler,raw)
    assert receipt["status"]=="returned" and receipt["abi_status"]==0
    produced=read(image);assert len(produced)==receipt["core_u32"]
    assert sha256(produced).hexdigest()==receipt["produced_sha256"]
    summary.update(status="PASS_LOCAL_B3_ONLY",actual_B3=1,image_path=str(image),
        image_bytes=len(produced),image_sha256=sha256(produced).hexdigest(),
        original_cpu_seconds=10,original_wall_seconds=20,original_address_bytes=256<<20)
except BaseException as e:
    summary.update(error_class=type(e).__name__,error=str(e));(out/"failure.txt").write_text(traceback.format_exc());traceback.print_exc()
finally:
    unchanged=all(p.read_bytes()==r for p,r in pins.items());summary["source_and_image_before_after_equal"]=unchanged
    if not unchanged:summary["status"]="FAIL"
    (out/"summary.json").write_text(json.dumps(summary,sort_keys=True,indent=2)+"\n")
    print(json.dumps(summary,sort_keys=True))
if summary["status"]!="PASS_LOCAL_B3_ONLY":raise SystemExit(1)
