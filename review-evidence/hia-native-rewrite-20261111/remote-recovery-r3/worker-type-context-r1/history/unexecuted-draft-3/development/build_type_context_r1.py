"""Generate and compile old/new actual types and the native context reader."""
from __future__ import annotations
import argparse,ast,ctypes,importlib.util,json,re,resource,stat,sys,traceback
from hashlib import sha256
from pathlib import Path
sys.dont_write_bytecode=True
p=argparse.ArgumentParser()
for name in ("project","reference","workspace","compiler","out"):p.add_argument("--"+name,type=Path,required=True)
a=p.parse_args()
PROJECT=a.project.resolve();REF=a.reference.resolve();WORK=a.workspace.resolve()
OUT=a.out.resolve();OUT.mkdir(parents=True,exist_ok=False)
COMPILER=a.compiler.resolve();PINS={};rows={};attempts=[];failure=None;status="FAIL"
resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
assert libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    path=Path(path).resolve();raw=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
    if path in PINS:assert PINS[path]==(raw,mode),path
    PINS[path]=(raw,mode);return raw
def unchanged():return all(path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==mode
                          for path,(raw,mode) in PINS.items())
def load(name,path):
    raw=pin(path);ast.parse(raw,filename=str(path))
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module
def profile(doc):
    fs=doc["functions"];ssa=[]
    for fn in fs:
        names=[x["name"] for x in fn["params"]]
        for block in fn["blocks"]:
            names.extend(x["name"] for x in block["params"])
            for op in block["ops"]:names.extend(x["name"] for x in op.get("out",[]))
        ssa.extend(int(m.group(1)) for n in names if (m:=re.search(r"(\d+)$",n)))
    value=dict(functions=len(fs),blocks=sum(len(f["blocks"]) for f in fs),
      operations=sum(len(b["ops"]) for f in fs for b in f["blocks"]),
      max_function_blocks=max(len(f["blocks"]) for f in fs),
      max_block_parameters=max(len(b["params"]) for f in fs for b in f["blocks"]),
      max_ssa_numeric_suffix=max(ssa,default=0))
    assert value["functions"]<=128 and value["blocks"]<=1536 and value["operations"]<=8192
    assert value["max_function_blocks"]<=256 and value["max_block_parameters"]<=16
    assert value["max_ssa_numeric_suffix"]<2048
    return value
def compile_one(label,body,doc):
    target=OUT/label;target.mkdir()
    (target/"authoring.py").write_text(body);save(target/"document.json",doc)
    metrics=profile(doc);save(target/"profile.json",metrics)
    source=render_assembly(doc).encode("utf-8");assemble_program(source)
    assert 0<len(source)<=1048576
    path=target/"source.hiaasm";path.write_bytes(source);pin(path)
    if label=="old-types":
        assert (len(source),digest(source))==(380145,extension.ORIGINAL_HIA_SHA)
        assert source==pin(REF/"examples/hia_bootstrap/composite_types.hiaasm")
    attempts.append(dict(label=label,source_bytes=len(source),source_sha256=digest(source)))
    save(OUT/"compile-attempts.json",attempts)
    image,receipt=compile_stage(target,label,COMPILER,source)
    binary=pin(image)
    assert receipt["status"]=="returned" and receipt["abi_status"]==0
    assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
    assert receipt["artifact_sha256"]==COMPILER_SHA and receipt["input_sha256"]==digest(source)
    assert receipt["produced_sha256"]==digest(binary) and receipt["core_u32"]==len(binary)
    assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==268435456
    row=dict(label=label,source_path=str(path),source_bytes=len(source),source_sha256=digest(source),
       image_path=str(image),image_bytes=len(binary),image_sha256=digest(binary),
       compiler_sha256=COMPILER_SHA,profile=metrics,receipt=receipt)
    if label=="old-types":
        assert (row["image_bytes"],row["image_sha256"])==(541021,
          "dbe484770638ac36b72fc5930eb03862e4ee27f1e532f3a3b7c30acc5cd78612")
    rows[label]=row;save(target/"manifest.json",row)
    print("HIA_TYPE_CONTEXT_COMPILE "+json.dumps(row,sort_keys=True),flush=True)
    return row
try:
    pin(__file__)
    index=json.loads(pin(PROJECT/"sources.json"))
    for row in index["files"]:
        raw=pin(PROJECT/row["path"])
        assert (len(raw),digest(raw))==(row["bytes"],row["sha256"]),row["path"]
        if row["path"].endswith(".py"):ast.parse(raw,filename=row["path"])
    COMPILER_SHA="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
    raw=pin(COMPILER);assert (len(raw),digest(raw))==(668608,COMPILER_SHA)
    sys.path.insert(0,str(REF))
    import tools
    helper=WORK/"native-edit-json-next/development/main-compile-r3/source/6/hia_agent_edit_source_views.py"
    raw=pin(helper);assert (len(raw),digest(raw))==(23950,"555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c")
    overlay=PROJECT/"reference_helpers/tools";overlay.mkdir(parents=True)
    target=overlay/"hia_agent_edit_source_views.py";target.write_bytes(raw);pin(target)
    tools.__path__=[str(PROJECT/"tools"),str(overlay),*list(tools.__path__)]
    from hepta.hia_agent_assembly import render_assembly,assemble_program
    from tools.qualify_hia_selfhost import compile_stage
    extension=load("tools.extend_native_type_context_r1",PROJECT/"tools/extend_native_type_context_r1.py")
    original=load("type_context_exact_original_generator",REF/"tools/generate_hia_composite_types.py")
    assert digest(pin(original.__file__))==extension.ORIGINAL_SHA
    authoring=load("tools.cli_authoring",PROJECT/"tools/cli_authoring.py")
    reader=load("type_context_reader_generator",PROJECT/"tools/generate_type_context_reader_r1.py")
    old_body=original.source_program();old_doc=original.document()
    compile_one("old-types",old_body,old_doc)
    adaptation=extension.apply(original);save(OUT/"adaptation.json",adaptation)
    body=original.source_program();doc=original.document()
    compile_one("context-types",body,doc)
    doc,body,inventory=reader.generated_document()
    save(OUT/"reader-inventory.json",inventory)
    compile_one("context-reader",body,doc)
    for module in tuple(sys.modules.values()):
        filename=getattr(module,"__file__",None)
        if filename:
            path=Path(filename).resolve()
            if path.suffix==".py" and any(path.is_relative_to(root) for root in (REF,PROJECT,WORK)):pin(path)
    assert unchanged() and len(rows)==3
    bundle=dict(schema="hia-native-type-context-bundle-r1",status="BUILT_ONLY",
       components=rows,adaptation=str(OUT/"adaptation.json"),inventory=str(OUT/"reader-inventory.json"),
       compiler_sha256=COMPILER_SHA,context_offset=extension.CONTEXT_OFFSET,context_bytes=64,
       context_reader_mode="R/R/W",actual_program_joined=False,whole_public_diagnostics_closed=False)
    save(OUT/"bundle.json",bundle);status="PASS"
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    same=unchanged()
    if not same:status="FAIL"
    pins=[]
    for number,(path,(raw,mode)) in enumerate(PINS.items()):
        frozen=OUT/"frozen-inputs"/str(number)/path.name;frozen.parent.mkdir(parents=True,exist_ok=True)
        frozen.write_bytes(raw);frozen.chmod(mode)
        pins.append(dict(path=str(path),bytes=len(raw),sha256=digest(raw),mode=mode,frozen=str(frozen)))
    save(OUT/"source-pins.json",pins)
    report=dict(status=status,scope="TYPE_CONTEXT_BUILD_ONLY",actual_compiles=len(rows),
       actual_compile_attempts=len(attempts),components=rows,failure=failure,
       original_compile_limits=dict(cpu=10,wall=20,address=268435456),
       source_image_before_after_equal=same,actual_semantic_entries=0,whole_program_joined=False)
    save(OUT/"summary.json",report)
    print("HIA_TYPE_CONTEXT_BUILD "+json.dumps(report,sort_keys=True),flush=True)
if status!="PASS":raise SystemExit(1)
