"""Generate and compile the issued assembly object prefix under original B3 gates."""
from pathlib import Path
from hashlib import sha1,sha256
import ast,importlib.util,json,sys,time,traceback
BASE=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
WORK=BASE/"root-recovery/workspace"
REF=BASE/"root-recovery/reference-0ef-r2"
ROOT=WORK/"native-assembly-object-prefix-r1"
OUT=ROOT/"development/build-r1"
COMPILER=WORK/"native-edit-candidate-next/development/build-r1/source/1/B3.image.bin"
AUTHOR=Path(sys.argv[1]).resolve()
AUTHOR_SHA="1ae1f374ce0f3ab027ff09b7748ee877570a3a4b"
REFERENCE_PINS={
  "tools/generate_hia_json_preflight.py": {
    "bytes": 13718,
    "gitsha": "2198579e4e1882c44593f1c7b9253ec788a90f78",
    "sha256": "293e22e217cba119dad1c7a4e04b5a9cd714cbeafdfdc4c9b15f4f716557896c"
  },
  "tools/generate_hia_json_decode.py": {
    "bytes": 8178,
    "gitsha": "54607f809bdbd8cd68c4e423749c40623fe54a69",
    "sha256": "fffc97c704cc75ad88239fe79d7b7f83418199a732364f834e006ebfd5f8548f"
  },
  "tools/generate_hia_json_canonical.py": {
    "bytes": 7307,
    "gitsha": "d9da0321b5aab3cfebb8549b237bce336600a422",
    "sha256": "063053bf7539a605ee834bd32e6a07b98ebd0c6b027af0b224b7f9107b9d47d9"
  },
  "hepta/hia_program.py": {
    "bytes": 45247,
    "gitsha": "5d0027f4453759e4156a3496e64215c441a727e4",
    "sha256": "76a222745e13fe29825a661be206243f137ada7b57292b07ab7513a40146fb92"
  }
}
pins={}
def read(path):
    path=Path(path).resolve();raw=path.read_bytes()
    if path in pins:assert pins[path]==raw
    pins[path]=raw;return raw
def save(name,value):
    (OUT/name).write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
summary=dict(status="FAIL",scope="ISSUED_ASSEMBLY_OBJECT_PREFIX_FRESH_BUILD",
    actual_native_compiles=0,actual_prefix_entries=0,whole_stack_closed=False,
    full_assembly_qualified=False,installed_activation=False)
ROOT.mkdir(parents=True,exist_ok=False);OUT.mkdir(parents=True)
started=time.monotonic_ns()
try:
    read(__file__);author=read(AUTHOR);assert gitsha(author)==AUTHOR_SHA
    ast.parse(author,filename=str(AUTHOR))
    for path,row in REFERENCE_PINS.items():
        raw=read(REF/path)
        assert (len(raw),gitsha(raw),sha256(raw).hexdigest())==(row["bytes"],row["gitsha"],row["sha256"])
    sys.path.insert(0,str(REF));sys.dont_write_bytecode=True
    from hepta.hia_agent_assembly import render_assembly,assemble_program
    from tools.qualify_hia_selfhost import compile_stage
    assert sha256(read(REF/"tools/qualify_hia_selfhost.py")).hexdigest()=="2674bbc29a67214c16595a226a0dfb28d3dcf56e238058d45e618dd42925cb76"
    assert sha256(read(REF/"tools/hia_selfhost_child.py")).hexdigest()=="1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
    assert sha256(read(REF/"tools/generate_hia_selfhost.py")).hexdigest()=="e4cff0c45d9138ff50b32ef2f6c0c768583ac88b634f2b932411e4ecb2b50ed0"
    image_raw=read(COMPILER)
    assert (len(image_raw),sha256(image_raw).hexdigest())==(669556,"35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b")
    spec=importlib.util.spec_from_file_location("assembly_object_prefix_author",AUTHOR)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    expanded=module.source_program();(OUT/"expanded-authoring.py").write_text(expanded)
    document=module.document();save("document.json",document)
    fs=document["functions"]
    profile=dict(functions=len(fs),blocks=sum(len(f["blocks"]) for f in fs),
        operations=sum(len(b["ops"]) for f in fs for b in f["blocks"]),
        max_function_blocks=max(len(f["blocks"]) for f in fs),
        max_block_parameters=max(len(b["params"]) for f in fs for b in f["blocks"]))
    save("profile.json",profile)
    assert profile["functions"]<=128 and profile["blocks"]<=1536
    assert profile["operations"]<=8192 and profile["max_function_blocks"]<=256
    assert profile["max_block_parameters"]<=16,profile
    raw=render_assembly(document).encode();assemble_program(raw)
    assert len(raw)<=1<<20
    source=ROOT/"assembly_object_prefix.hiaasm";source.write_bytes(raw);read(source)
    image,receipt=compile_stage(OUT,"assembly-object-prefix",COMPILER,raw)
    assert receipt["status"]=="returned" and receipt["abi_status"]==0
    assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
    assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
    produced=read(image)
    assert 0<len(produced)<=1<<20 and len(produced)==receipt["core_u32"]
    assert sha256(produced).hexdigest()==receipt["produced_sha256"]
    manifest=dict(schema="hia-issued-assembly-object-prefix-v1",source_path=str(source),
        source_bytes=len(raw),source_sha256=sha256(raw).hexdigest(),
        image_path=str(image),image_bytes=len(produced),image_sha256=sha256(produced).hexdigest(),
        compiler_path=str(COMPILER),compiler_sha256=sha256(read(COMPILER)).hexdigest(),
        receipt_path=str(OUT/"assembly-object-prefix.receipt.json"),
        profile=profile,semantic_messages=module.MESSAGES,
        does_not_grant_Core_admission=True,full_assembly_qualified=False,whole_stack_closed=False)
    save("manifest.json",manifest)
    summary.update(status="PASS",actual_native_compiles=1,manifest=manifest,
        native_child_cpu_seconds=10,native_child_wall_seconds=20,
        native_child_address_bytes=256<<20)
except BaseException as exc:
    summary.update(error_class=type(exc).__name__,error=str(exc))
    (OUT/"failure.txt").write_text(traceback.format_exc());traceback.print_exc()
    for name in ("assembly-object-prefix.stdout.log","assembly-object-prefix.stderr.log","assembly-object-prefix.receipt.json"):
        path=OUT/name
        if path.is_file():
            raw=path.read_bytes()
            print("HIA_OBJECT_PREFIX_NESTED "+json.dumps(dict(name=name,bytes=len(raw),
                sha256=sha256(raw).hexdigest(),text=raw.decode()),sort_keys=True),flush=True)
finally:
    equal=all(p.is_file() and p.read_bytes()==raw for p,raw in pins.items())
    for index,(path,raw) in enumerate(pins.items()):
        target=OUT/"frozen-inputs"/str(index)/path.name
        target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    summary.update(source_and_image_before_after_equal=equal,elapsed_ns=time.monotonic_ns()-started)
    if not equal:summary["status"]="FAIL"
    save("source-pins.json",[dict(path=str(p),bytes=len(raw),sha256=sha256(raw).hexdigest()) for p,raw in pins.items()])
    save("summary.json",summary);print("HIA_OBJECT_PREFIX_BUILD "+json.dumps(summary,sort_keys=True),flush=True)
if summary["status"]!="PASS":raise SystemExit(1)
