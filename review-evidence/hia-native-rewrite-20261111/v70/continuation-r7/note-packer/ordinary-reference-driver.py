from __future__ import annotations
import base64, hashlib, importlib.util, json, os, pathlib, struct, subprocess, sys, time, traceback
P=pathlib.Path
ROOT=P(sys.argv[1])
DEST=P(sys.argv[2])
payload_bytes=sys.stdin.buffer.read()
payload=json.loads(payload_bytes)
report={"schema":"hepta.hia.cpython-note-packer.independent-reference.v1",
        "status":"RUNNING","scope":"INDEPENDENT_ASSEMBLER_AND_ORDINARY_CORE_VM_BEFORE_NEW_NATIVE_PACKER",
        "started_ns":time.time_ns(),"limits":{"outer_seconds":180,"tool_seconds":30},
        "production_c_compilation":False,"native_packer_compiled":False,"native_adapter_executed":False,
        "whole_native":False,"default_native":False,"live_migration":False,"legacy_deletion":False,
        "source_head":payload["source_head"],"source_tree":payload["source_tree"],
        "files":{},"commands":[],"observations":[],"failures":[]}
def digest(raw): return hashlib.sha256(raw).hexdigest()
def identity(path):
    raw=path.read_bytes()
    return {"path":str(path),"bytes":len(raw),"sha256":digest(raw),"resolved":str(path.resolve(strict=True))}
def command(argv,cwd):
    before=identity(P(argv[0]))
    p=subprocess.run(argv,cwd=cwd,stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
    n=len(report["commands"])
    (DEST/("command-"+str(n)+".stdout")).write_bytes(p.stdout)
    (DEST/("command-"+str(n)+".stderr")).write_bytes(p.stderr)
    row={"argv":list(map(str,argv)),"returncode":p.returncode,
         "stdout_bytes":len(p.stdout),"stdout_sha256":digest(p.stdout),
         "stderr_bytes":len(p.stderr),"stderr_sha256":digest(p.stderr),"tool_before":before,
         "tool_after":identity(P(argv[0]))}
    report["commands"].append(row)
    if row["tool_before"]!=row["tool_after"]:raise AssertionError("tool changed")
    if p.returncode: raise AssertionError("tool failed: "+repr(argv)+"\n"+p.stderr.decode(errors="replace"))
    return p.stdout
def elf_text(raw):
    if raw[:7]!=b"\x7fELF\x02\x01\x01" or struct.unpack_from("<H",raw,18)[0]!=62:
        raise AssertionError("reference is not ELF64 AMD64")
    head=struct.unpack_from("<16sHHIQQQIHHHHHH",raw)
    shoff,shentsize,shnum,shstr=head[6],head[11],head[12],head[13]
    if shentsize!=64:raise AssertionError("ELF section size")
    sh=[struct.unpack_from("<IIQQQQIIQQ",raw,shoff+i*64) for i in range(shnum)]
    names=raw[sh[shstr][4]:sh[shstr][4]+sh[shstr][5]]
    rows=[]
    for s in sh:
        end=names.index(b"\0",s[0])
        name=names[s[0]:end].decode()
        rows.append({"name":name,"type":s[1],"flags":s[2],"address":s[3],
                     "offset":s[4],"bytes":s[5]})
    allocated=[r for r in rows if r["flags"]&2]
    if len(allocated)!=1 or allocated[0]["name"]!=".text" or allocated[0]["address"]!=0:
        raise AssertionError(("unexpected allocated sections",allocated))
    if any(r["type"] in (4,9) and r["bytes"] for r in rows):
        raise AssertionError("linked reference retains relocations")
    if head[4]!=0:raise AssertionError("reference entry is not zero")
    s=allocated[0]
    report["reference_sections"]=rows
    return raw[s["offset"]:s["offset"]+s["bytes"]]
def compare_vm(packer,image):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    scenarios=[
       ("exact",0,len(image),len(image),image),
       ("short",0,len(image)-1,4294967294,bytes([165])*(len(image)-1)),
       ("nonempty",1,len(image),4294967295,bytes([165])*len(image)),
       ("precedence",1,0,4294967295,b""),
       ("zero_output",0,0,4294967294,b""),
       ("tail",0,len(image)+3,len(image),image+bytes([165])*3)]
    for name,source_size,capacity,status,expected in scenarios:
        starts=range(0,len(expected),128) if expected else (0,)
        for begin in starts:
            end=min(begin+128,len(expected))
            body=Body(0); owners=[]; views=[]
            for count in (source_size,capacity,0):
                owner=body.value("buffer","buffer.new",[body.const("usize",count)])
                view=body.value("mutbuf","borrow.mut",[owner])
                owners.append(owner);views.append(view)
            body.effect("buffer.fill",[views[0],body.const("u8",90)])
            body.effect("buffer.fill",[views[1],body.const("u8",165)])
            body.effect("loan.end",[views[0]])
            views[0]=body.value("readbuf","borrow.read",[owners[0]])
            result=body.value("u32","call",views,{"function":"f0"})
            values=[result]+[body.value("u8","buffer.load",[views[1],body.const("usize",at)]) for at in range(begin,end)]
            for view in views:body.effect("loan.end",[view])
            for owner in owners:body.effect("owner.drop",[owner])
            returns=",".join(["u32"]+["u8"]*(end-begin))
            wrapper=("hia-asm.v1 hepta.hia.program.v8 cpython_note_reference\n"
              +"fn reference_entry() -> ("+returns+") effects(alloc,read,write,trap) entry(b0)\n"
              +"block b0()\n"+body.text()+"  ret("+",".join(values)+")\nend\n"
              +packer.split("\n",1)[1])
            checked=assemble_program(wrapper.encode())
            observed=execute_program(checked,"reference_entry",[])
            row={"case":name,"begin":begin,"end":end,"vm_core_sha256":checked.sha256,
                 "expected":[status,*expected[begin:end]],"actual":observed}
            row["passed"]=observed.get("status")=="returned" and observed.get("values")==row["expected"]
            report["observations"].append(row)
            if not row["passed"]:raise AssertionError("ordinary VM output differs: "+name)
try:
    DEST.mkdir(mode=0o700)
    (DEST/"source-package.json").write_bytes(payload_bytes)
    report["payload"]={"bytes":len(payload_bytes),"sha256":digest(payload_bytes)}
    report["interpreter_before"]=identity(P(sys.executable))
    head=command(["/usr/bin/git","rev-parse","HEAD"],ROOT).decode().strip()
    tree=command(["/usr/bin/git","rev-parse","HEAD^{tree}"],ROOT).decode().strip()
    if head!=payload["source_head"] or tree!=payload["source_tree"]:raise AssertionError("source HEAD/tree changed")
    report["git_status_before"]=command(["/usr/bin/git","status","--porcelain=v1"],ROOT).decode()
    if report["git_status_before"]:raise AssertionError("source tree is not clean")
    source=DEST/"source"
    for name,value in payload["files"].items():
        path=source/name
        if P(name).is_absolute() or ".." in P(name).parts:raise ValueError("unsafe owned path")
        raw=value.encode()
        if len(raw)!=payload["metadata"][name]["bytes"] or digest(raw)!=payload["metadata"][name]["sha256"]:
            raise AssertionError("transport identity mismatch: "+name)
        path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        with path.open("xb") as out:out.write(raw)
        report["files"][name]=identity(path)
    stripped=[]
    for name in list(os.environ):
        if name.startswith("HEPTA_"):
            stripped.append(name);del os.environ[name]
    report["inherited_hepta_selectors_removed"]=sorted(stripped)
    sys.path.insert(0,str(ROOT))
    generator=source/"tools/generate_hia_cpython_note_packer.py"
    spec=importlib.util.spec_from_file_location("note_packer_authoring",generator)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    packer=module.render_assembly(module.document())
    path=source/"examples/hia_bootstrap/cpython_note_packer.hiaasm"
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with path.open("xb") as out:out.write(packer.encode())
    report["files"]["examples/hia_bootstrap/cpython_note_packer.hiaasm"]=identity(path)
    expected=base64.b64decode(payload["expected_image_base64"],validate=True)
    if expected!=module.reference_image() or len(expected)!=payload["expected_image_bytes"] or digest(expected)!=payload["expected_image_sha256"]:
        raise AssertionError("authored machine identity changed")
    reference=source/"tools/hia_cpython_note_packer_reference.S"
    obj=DEST/"reference.o"; elf=DEST/"reference.elf"
    command(["/usr/bin/x86_64-linux-gnu-gcc-15","-c","-fPIC","-o",str(obj),str(reference)],DEST)
    command(["/usr/bin/x86_64-linux-gnu-ld.bfd","-nostdlib","-T",
             str(source/"tools/hia_cpython_note_packer_reference.ld"),"-o",str(elf),str(obj)],DEST)
    actual=elf_text(elf.read_bytes())
    report["assembled"]={"bytes":len(actual),"sha256":digest(actual),"every_byte_equal":actual==expected}
    if actual!=expected:
        report["first_byte_differences"]=[{"at":i,"expected":a,"actual":b} for i,(a,b) in enumerate(zip(expected,actual)) if a!=b][:64]
        raise AssertionError("independent assembler differs from HIA literal")
    (DEST/"expected.image.bin").write_bytes(actual)
    compare_vm(packer,actual)
    for name,record in report["files"].items():
        if record!=identity(source/name):raise AssertionError("authored source changed")
    report["interpreter_after"]=identity(P(sys.executable))
    report["git_status_after"]=command(["/usr/bin/git","status","--porcelain=v1"],ROOT).decode()
    if report["interpreter_after"]!=report["interpreter_before"] or report["git_status_after"]:
        raise AssertionError("source/interpreter changed")
    report["status"]="PASS_REFERENCE_BEFORE_NATIVE_PACKER"
except BaseException as error:
    report["status"]="FAIL"
    report["failures"].append({"type":type(error).__name__,"message":str(error),"traceback":traceback.format_exc()})
finally:
    report["finished_ns"]=time.time_ns()
    if DEST.is_dir():
        raw=(json.dumps(report,sort_keys=True,indent=2)+"\n").encode()
        (DEST/"reference-RESULT.json").write_bytes(raw)
        print(json.dumps({"status":report["status"],"observations":len(report["observations"]),
              "failures":report["failures"],"report_bytes":len(raw),"report_sha256":digest(raw),
              "report":str(DEST/"reference-RESULT.json")}),flush=True)
if report["status"]!="PASS_REFERENCE_BEFORE_NATIVE_PACKER":raise SystemExit(1)
