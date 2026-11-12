from pathlib import Path
import ast,hashlib,importlib.util,json,os,resource,stat,sys,time,traceback
sys.dont_write_bytecode=True
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
base=Path("/workspace/scratch/hia-root-r31")
ref=base/"reference-0ef-subset"
out=base/"receipt-generation-r1"
out.mkdir(exist_ok=False)
pins={}
def identity(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),gitsha=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest())
def pin(path):
    path=path.resolve();raw=path.read_bytes();pins[path]=raw;return identity(raw)
def save(name,value):(out/name).write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
expected={r["path"]:r for r in json.loads((base/"exact-reference-tree.json").read_bytes())}
status=dict(status="FAIL",scope="LOCAL_GENERATION_ONLY",new_B3=0,new_native=0,CI_qualification=False)
start=time.monotonic_ns()
try:
    refs=[]
    for path in sorted(ref.rglob("*.py")):
        row=expected[str(path.relative_to(ref))];obs=pin(path)
        assert (obs["bytes"],obs["gitsha"],stat.S_IMODE(path.stat().st_mode))==(row["bytes"],row["gitsha"],int(row["mode"],8)&0o777),(path,obs,row)
        refs.append(dict(path=str(path.relative_to(ref)),**obs))
    save("reference-inputs.json",refs)
    author=base/"generate_ordinary_patch_receipt_r1.py"
    assert pin(author)["sha256"]=="dcf63b505439e013e05b608cc3b9d1032c5d9f4dc48ab2a77ff9e86a4cfccca5"
    assert pin(base/"issued_object_prefix_reference.py")["gitsha"]=="90d7242bdc2ab328280b2c760f988cff3ad21d10"
    sys.path.insert(0,str(ref))
    spec=importlib.util.spec_from_file_location("local_receipt_author_r1",author)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    expanded=module.source_program();(out/"expanded-authoring.py").write_text(expanded)
    doc=module.document();save("document.json",doc)
    functions=doc["functions"]
    profile=dict(functions=len(functions),blocks=sum(len(f["blocks"]) for f in functions),
        operations=sum(len(b["ops"]) for f in functions for b in f["blocks"]),
        max_function_blocks=max(len(f["blocks"]) for f in functions),
        max_block_parameters=max(len(b["params"]) for f in functions for b in f["blocks"]))
    save("profile.json",profile)
    assert profile["functions"]<=128 and profile["blocks"]<=1536
    assert profile["operations"]<=8192 and profile["max_function_blocks"]<=256 and profile["max_block_parameters"]<=16
    from hepta.hia_agent_assembly import render_assembly,assemble_program
    assembly=render_assembly(doc).encode();assert len(assembly)<=1<<20
    assemble_program(assembly);(out/"ordinary_patch_receipt.hiaasm").write_bytes(assembly)
    status.update(status="PASS_LOCAL_GENERATION_ONLY",profile=profile,assembly=identity(assembly),reference_files=len(refs))
except BaseException as e:
    status.update(error_class=type(e).__name__,error=str(e));(out/"failure.txt").write_text(traceback.format_exc());traceback.print_exc()
finally:
    unchanged=all(p.read_bytes()==r for p,r in pins.items())
    status.update(source_bytes_unchanged=unchanged,elapsed_ns=time.monotonic_ns()-start)
    if not unchanged:status["status"]="FAIL"
    save("summary.json",status);print(json.dumps(status,sort_keys=True))
if status["status"]!="PASS_LOCAL_GENERATION_ONLY":raise SystemExit(1)
