"""Fresh bounded native B3 build for fixed diagnostics and public A routing."""
from __future__ import annotations
import ast,importlib.util,json,re,resource,sys,time,traceback
from hashlib import sha256
from pathlib import Path
sys.dont_write_bytecode=True
SOURCE=Path(sys.argv[1]).resolve()
REFERENCE=Path(sys.argv[2]).resolve()
COMPILER=Path(sys.argv[3]).resolve()
OUT=Path(sys.argv[4]).resolve()
OUT.mkdir(parents=True,exist_ok=False)
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
pins={};compiled=[];status="FAIL";error=None;started=time.monotonic_ns()
def read(path):
    path=Path(path).resolve();raw=path.read_bytes()
    if path in pins:assert pins[path]==raw
    pins[path]=raw
    return raw
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value
    spec.loader.exec_module(value);return value
def compile_document(label,doc,text,inventory):
    where=OUT/label;where.mkdir()
    (where/"expanded-authoring.py").write_text(text)
    save(where/"construction.json",doc);save(where/"inventory.json",inventory)
    functions=doc["functions"];ssa=[]
    for fn in functions:
        for node in [*fn["params"],*[p for b in fn["blocks"] for p in b["params"]],
                     *[p for b in fn["blocks"] for op in b["ops"] for p in op.get("out",[])]]:
            match=re.fullmatch(r"v(\d+)",node["name"])
            assert match,node["name"];ssa.append(int(match.group(1)))
    profile=dict(functions=len(functions),blocks=sum(len(f["blocks"]) for f in functions),
      operations=sum(len(b["ops"]) for f in functions for b in f["blocks"]),
      max_function_blocks=max(len(f["blocks"]) for f in functions),
      max_block_parameters=max(len(b["params"]) for f in functions for b in f["blocks"]),
      max_ssa_numeric_suffix=max(ssa))
    save(where/"profile.json",profile)
    assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["operations"]<=8192,profile
    assert profile["max_function_blocks"]<=256 and profile["max_block_parameters"]<=16,profile
    assert profile["max_ssa_numeric_suffix"]<2048,profile
    raw=render_assembly(doc).encode();assemble_program(raw)
    assert 0<len(raw)<=1<<20
    source=where/"source.hiaasm";source.write_bytes(raw);read(source)
    image,receipt=compile_stage(where,label,COMPILER,raw)
    binary=read(image)
    assert receipt["status"]=="returned" and receipt["abi_status"]==0
    assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
    assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
    assert receipt["input_sha256"]==digest(raw) and receipt["produced_sha256"]==digest(binary)
    assert receipt["artifact_sha256"]==digest(compiler_raw) and len(binary)==receipt["core_u32"]
    assert 0<len(binary)<=1<<20
    row=dict(label=label,source_path=str(source),source_bytes=len(raw),source_sha256=digest(raw),
      image_path=str(image),image_bytes=len(binary),image_sha256=digest(binary),
      compiler_sha256=digest(compiler_raw),receipt=receipt,profile=profile,
      inventory_path=str(where/"inventory.json"),fresh_actual_B3=True)
    compiled.append(row);save(where/"manifest.json",row)
    print("HIA_FIXED_DIAGNOSTIC_COMPILE "+json.dumps(row,sort_keys=True),flush=True)
try:
    read(__file__)
    for path in sorted(SOURCE.rglob("*")):
        if path.is_file():read(path)
    compiler_raw=read(COMPILER)
    assert (len(compiler_raw),digest(compiler_raw))==(669556,"35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b")
    assert digest(read(REFERENCE/"tools/qualify_hia_selfhost.py"))=="2674bbc29a67214c16595a226a0dfb28d3dcf56e238058d45e618dd42925cb76"
    assert digest(read(REFERENCE/"tools/hia_selfhost_child.py"))=="1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
    sys.path[:0]=[str(SOURCE),str(REFERENCE)]
    import tools
    tools.__path__=[str(SOURCE/"tools"),*list(tools.__path__)]
    from hepta.hia_agent_assembly import render_assembly,assemble_program
    from tools.qualify_hia_selfhost import compile_stage
    from tools.generate_fixed_diagnostic_catalog_r1 import generated_document as catalog_document
    from tools.generate_program_service_diagnostics_r1 import generated_document as route_document
    doc,text,inventory,rom=catalog_document(SOURCE/"reference")
    (OUT/"fixed-catalog-ROM.bin").write_bytes(rom)
    compile_document("fixed-catalog",doc,text,inventory)
    doc,text,inventory=route_document(SOURCE/"reference",SOURCE/"tools/program_service_root_reference.py")
    compile_document("program-diagnostic-route",doc,text,inventory)
    assert len(compiled)==2
    status="PASS"
except BaseException as exc:
    error=dict(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    unchanged=all(path.read_bytes()==raw for path,raw in pins.items())
    if not unchanged:status="FAIL"
    summary=dict(schema="hia-fixed-diagnostic-build-v1",status=status,compiled=compiled,error=error,
      source_and_image_before_after_equal=unchanged,elapsed_ns=time.monotonic_ns()-started,
      native_semantic_entries=0,public_carrier_execution=0,
      original_limits=dict(B3_CPU=10,B3_wall=20,B3_address=256<<20,
       B3_source=1<<20,B3_output=1<<20,B3_workspace=1<<20,
       functions=128,blocks=1536,operations=8192,blocks_per_function=256,block_parameters=16,SSA_strictly_below=2048),
      installation_activated=False,whole_public_diagnostics_closed=False,whole_stack_closed=False)
    save(OUT/"source-pins.json",[dict(path=str(p),bytes=len(raw),sha256=digest(raw)) for p,raw in pins.items()])
    save(OUT/"summary.json",summary)
    print("HIA_FIXED_DIAGNOSTIC_BUILD "+json.dumps(summary,sort_keys=True),flush=True)
if status!="PASS":raise SystemExit(1)
