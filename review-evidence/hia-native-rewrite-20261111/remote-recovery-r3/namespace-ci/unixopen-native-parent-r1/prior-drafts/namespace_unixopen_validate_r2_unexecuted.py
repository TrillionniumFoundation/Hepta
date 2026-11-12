"""Fresh original-C / complete-CoreVM / actual-HIA unixOpen parent differential.

The effect provider is explicitly foreign. No namespace syscall or final Store
authority is issued by this component gate. Native calls always use the actual
fresh B3 output; all input/output/workspace bytes and canaries are compared.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import argparse,ctypes,gzip,hashlib,importlib.util,json,os,resource,signal,stat,struct,time,traceback
from pathlib import Path
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
VALUES="7c3f0299291cf4b99d5c2296351dcfd5e471507d4903ab9da171420c126c5c50"
OBJECTS="2320a0363d312f1f07b48cc370f06ac7dbaedefa28437c28230fff6fba4dc3de"
LIMITS=dict(cpu_seconds=90,wall_seconds=180,address_bytes=1<<30,core_bytes=0,VM_steps=4000000,VM_arena_bytes=32<<20)
BAD=(1<<32)-3
MASK=(1<<64)-1
def sha(raw):return hashlib.sha256(raw).hexdigest()
def json_value(value):
    if isinstance(value,bytes):return {"bytes_hex":value.hex(),"bytes":len(value),"sha256":sha(value)}
    if isinstance(value,dict):return {str(k):json_value(v) for k,v in value.items()}
    if isinstance(value,(list,tuple)):return [json_value(v) for v in value]
    return value
def save(path,value):
    Path(path).write_text(json.dumps(json_value(value),indent=2,sort_keys=True)+"\n")
def q(raw,offset):return struct.unpack_from("<Q",raw,offset)[0]
def p(raw,offset,value):struct.pack_into("<Q",raw,offset,value&MASK)
def main():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError("unixOpen component wall180")))
    signal.alarm(180)
    ap=argparse.ArgumentParser()
    ap.add_argument("--context",type=Path,required=True)
    ap.add_argument("--mode",choices=("build","semantic","protocol"),required=True)
    ap.add_argument("--start",type=int,default=0);ap.add_argument("--end",type=int,default=0)
    args=ap.parse_args()
    assert sys.version_info[:3]==(3,12,14)
    pins={}
    def pin(path,expected=None):
        path=Path(path).absolute();info=path.lstat()
        assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
        raw=path.read_bytes();row={"path":str(path),"bytes":len(raw),"sha256":sha(raw),"mode":stat.S_IMODE(info.st_mode)}
        if expected is not None:assert row["sha256"]==expected,(path,row["sha256"],expected)
        if str(path) in pins:assert row==pins[str(path)]
        pins[str(path)]=row;return raw
    def load(name,path,expected=None):
        raw=pin(path,expected);spec=importlib.util.spec_from_file_location(name,path)
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module
        exec(compile(raw,str(path),"exec"),module.__dict__);return module
    context=json.loads(pin(args.context));pin(__file__)
    ref=Path(context["reference"]);tree=Path(context["namespace_working"])
    evidence=Path(context["namespace_evidence"]);inputs=context["namespace_input_paths"]
    out=evidence/("build" if args.mode=="build" else "protocol" if args.mode=="protocol" else f"semantic-{args.start:03d}-{args.end:03d}")
    out.mkdir(parents=False,exist_ok=False)
    report=dict(schema="hia.namespace.unixopen.parent.component.v1",status="INCOMPLETE",mode=args.mode,
        scope="ORIGINAL_C_CONTROL_FLOW_WITH_EXPLICIT_FOREIGN_EFFECTS_NOT_ORDINARY_STORE",
        actual_namespace_syscalls=0,actual_issued_namespace_authorities=0,
        VM_entries=0,native_entries=0,C_cases=0,protocol_controls=0,cases_completed=[],
        fresh_B3_compiles=0,failures=[],limits=LIMITS,
        actual_limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
            address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))),
        inherited_counts=False,whole_store_closed=False)
    save(out/"summary.json",report)
    started=time.monotonic_ns();cpu_started=time.process_time_ns()
    try:
        sys.path.insert(0,str(ref))
        load("tools.generate_hia_agent_namespace_store",tree/"tools/generate_hia_agent_namespace_store.py",VALUES)
        load("tools.generate_hia_agent_namespace_objects",tree/"tools/generate_hia_agent_namespace_objects.py",OBJECTS)
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        from hepta.hia_program import verify_program
        from hepta.hia_program_runtime import _Machine,_Owner,_View
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        fixture=load("unixopen_component_fixtures",inputs["namespace-unixopen-fixtures.py"])
        oracle_module=load("unixopen_original_c",inputs["namespace-unixopen-original-c-reference.py"])
        pin(inputs["os_unix_3461_original.c"],oracle_module.ORIGINAL_SHA256)
        save(out/"source-before.json",list(pins.values()))
        all_cases=fixture.cases();assert len(all_cases)==85
        save(out/"case-inventory.json",all_cases)
        if args.mode=="build":
            from tools import qualify_hia_selfhost as qualifier
            author=load("unixopen_new_author",tree/"tools/generate_hia_agent_namespace_unixopen_parent.py")
            document=author.document()
            raw=(json.dumps(document,sort_keys=True,separators=(",",":"))+"\n").encode()
            (out/"parent.document.json").write_bytes(raw)
            profile=dict(functions=len(document["functions"]),blocks=sum(len(f["blocks"]) for f in document["functions"]),
                ops=sum(len(b["ops"]) for f in document["functions"] for b in f["blocks"]),
                max_blocks=max(len(f["blocks"]) for f in document["functions"]),
                max_block_params=max(len(b["params"]) for f in document["functions"] for b in f["blocks"]))
            report["profile"]=profile;report["document"]=dict(path=str(out/"parent.document.json"),bytes=len(raw),sha256=sha(raw))
            report["function_profiles"]=[dict(name=f["name"],blocks=len(f["blocks"]),ops=sum(len(b["ops"]) for b in f["blocks"]),
                max_block_params=max(len(b["params"]) for b in f["blocks"])) for f in document["functions"]]
            save(out/"summary.json",report)
            print("HIA_UNIXOPEN_PROFILE "+json.dumps(dict(profile=profile,functions=report["function_profiles"]),sort_keys=True),flush=True)
            assert profile["functions"]<=128 and profile["blocks"]<=1536
            assert profile["ops"]<=8192 and profile["max_blocks"]<=256 and profile["max_block_params"]<=16
            source=render_assembly(document).encode();assemble_program(source)
            source_path=out/"agent_namespace_unixopen_parent.hiaasm";source_path.write_bytes(source)
            compiler=Path(context["compiler"]);pin(compiler,B3);pin(qualifier.CHILD)
            compile_dir=out/"compile";compile_dir.mkdir()
            image,receipt=qualifier.compile_stage(compile_dir,"unixopen-parent",compiler,source)
            image_raw=pin(image)
            assert receipt["source_sha256"]==receipt["input_sha256"]==sha(source)
            assert receipt["artifact_sha256"]==receipt["image_sha256"]==B3
            assert receipt["produced_sha256"]==sha(image_raw) and receipt["produced_bytes"]==len(image_raw)
            assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
            assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
            assert receipt["runner_sha256"]==sha(pin(qualifier.CHILD))
            request=json.loads((compile_dir/"unixopen-parent.request.json").read_bytes())
            assert request["capacity"]==request["workspace_size"]==1<<20
            assert 0<len(image_raw)<=1<<20
            report["fresh_B3_compiles"]=1;report["compile_receipt"]=receipt
            report["canonical_source"]=dict(path=str(source_path),bytes=len(source),sha256=sha(source))
            library,original_report=oracle_module.build(Path(inputs["os_unix_3461_original.c"]),out/"original-c")
            report["original_c_build"]=original_report
            report["C_library"]=dict(path=str(library),bytes=len(pin(library)),sha256=sha(pin(library)))
            assert oracle_module.Reference(library).lib.hia_unixopen_sizeof_unused()==16
            report["status"]="PASS_BUILD_ONLY"
        else:
            build=json.loads(pin(evidence/"build/summary.json"))
            assert build["status"]=="PASS_BUILD_ONLY" and build["fresh_B3_compiles"]==1 and build["source_pins_unchanged"]
            doc=json.loads(pin(build["document"]["path"],build["document"]["sha256"]))
            source=pin(build["canonical_source"]["path"],build["canonical_source"]["sha256"])
            assert render_assembly(doc).encode()==source
            program=verify_program(doc);entry=program.as_dict()["functions"][0]
            image_raw=pin(build["compile_receipt"]["produced_image"],build["compile_receipt"]["produced_sha256"])
            image=NativeHiaJsonImage(image_raw,sha(image_raw));assert image.image_sha256==sha(image_raw)
            library=Path(build["C_library"]["path"]);pin(library,build["C_library"]["sha256"])
            original=oracle_module.Reference(library)
            libc=ctypes.CDLL(None,use_errno=True)
            libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
            libc.mmap.restype=ctypes.c_void_p
            libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];libc.mprotect.restype=ctypes.c_int
            libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];libc.munmap.restype=ctypes.c_int
            canary=bytes(range(16))
            class Buffer:
                def __init__(self,raw,ro=False):
                    self.size=len(raw);self.middle=(len(raw)+32+4095)&~4095;self.total=self.middle+8192
                    self.raw=libc.mmap(None,self.total,0,0x22,-1,0)
                    if self.raw==ctypes.c_void_p(-1).value:raise OSError(ctypes.get_errno(),"mmap")
                    self.base=self.raw+4096;self.address=self.base+16
                    try:
                        if libc.mprotect(self.base,self.middle,3):raise OSError(ctypes.get_errno(),"mprotect RW")
                        ctypes.memmove(self.base,canary,16)
                        if raw:ctypes.memmove(self.address,raw,len(raw))
                        ctypes.memmove(self.address+self.size,canary,16)
                        if ro and libc.mprotect(self.base,self.middle,1):raise OSError(ctypes.get_errno(),"mprotect RO")
                    except BaseException:
                        libc.munmap(self.raw,self.total);raise
                def read(self):return ctypes.string_at(self.address,self.size)
                def check(self):
                    assert ctypes.string_at(self.base,16)==canary
                    assert ctypes.string_at(self.address+self.size,16)==canary
                def close(self):
                    if self.raw is not None:
                        address=self.raw;self.raw=None
                        if libc.munmap(address,self.total):raise OSError(ctypes.get_errno(),"munmap")
            def actual(s,o,w):
                buffers=[];primary=None
                try:
                    for raw,ro in ((s,True),(o,False),(w,False)):buffers.append(Buffer(raw,ro))
                    a,b,c=buffers
                    returned=int(image._entry(a.address,a.size,b.address,b.size,c.address,c.size))
                    for item in buffers:item.check()
                    assert a.read()==s
                    return returned,b.read(),c.read()
                except BaseException as error:primary=error;raise
                finally:
                    cleanup=[]
                    for b in reversed(buffers):
                        try:b.close()
                        except BaseException as error:cleanup.append(error)
                    if cleanup:
                        if primary is not None:
                            for error in cleanup:primary.add_note("cleanup: "+repr(error))
                        else:
                            for error in cleanup[1:]:cleanup[0].add_note(repr(error))
                            raise cleanup[0]
            def vm(s,o,w):
                owners=[_Owner(-1,bytearray(s)),_Owner(-2,bytearray(o)),_Owner(-3,bytearray(w))]
                machine=_Machine(program,4000000,32<<20,None,64)
                returned=machine.invoke(entry,[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
                assert bytes(owners[0].data)==s
                return (returned,bytes(owners[1].data),bytes(owners[2].data)),machine.steps
            def compare_state(w,cstate,where):
                mapping={0:248,1:256,2:264,3:272,4:280,5:288,6:296,7:304,8:312,9:320,
                    10:192,11:200,15:328,16:336,17:232,18:152,19:160,20:496}
                for ci,wi in mapping.items():
                    value=q(w,wi)
                    if ci in (0,5,16,17):value&=0xffffffff
                    assert value==cstate[ci],(where,ci,wi,value,cstate[ci])
                if cstate[14] and cstate[11]:
                    assert (q(w,208)&0xffffffff)==cstate[12],(where,"preallocated fd")
                    assert q(w,216)==cstate[13],(where,"preallocated flags")
                assert all(x==0 for x in cstate[21:]),(where,"untouched zeroed unixFile fields",cstate[21:])
            with gzip.open(out/"complete-entries.jsonl.gz","wt",encoding="utf-8",compresslevel=1) as ledger:
                def record(value,flush=False):
                    ledger.write(json.dumps(json_value(value),sort_keys=True,separators=(",",":"))+"\n")
                    if flush:ledger.flush()
                def invoke(label,s,o,w):
                    number=report["VM_entries"]+1
                    save(out/"frontier.json",dict(case=label,index=number,phase="BEFORE_VM",
                        input_bytes=len(s),output_bytes=len(o),workspace_bytes=len(w),input_sha256=sha(s)))
                    record(dict(kind="before",case=label,index=number,input=s,output=o,workspace=w),True)
                    expect,steps=vm(s,o,w);report["VM_entries"]+=1
                    save(out/"frontier.json",dict(case=label,index=number,phase="BEFORE_NATIVE",VM_steps=steps,
                        expected_return=expect[0],input_sha256=sha(s)))
                    observed=actual(s,o,w);report["native_entries"]+=1
                    record(dict(kind="after",case=label,index=number,returncode=observed[0],
                        output=observed[1],workspace=observed[2],VM_steps=steps,full_bytes_equal=observed==expect),True)
                    assert observed==expect,(label,number,"complete return/output/workspace mismatch")
                    return observed
                def until_effect(label,wire,o,w):
                    code,o,w=invoke(label,wire,o,w)
                    while code==2:
                        wneed=q(w,448);oneed=q(w,456)
                        assert wneed>len(w) or oneed>len(o),(label,"nonprogress GROW")
                        o+=bytes(max(0,oneed-len(o)));w+=bytes(max(0,wneed-len(w)))
                        code,o,w=invoke(label+"-GROW",wire,o,w)
                    return code,o,w
                def semantic(case,wire=None,initial=None):
                    wire=fixture.begin(case) if wire is None else wire
                    expected=original.run(wire,fixture.Provider(case,wire));report["C_cases"]+=1
                    record(dict(kind="original-C",case=case["name"],source=wire,fixture=case,result=expected),True)
                    o,w=(bytes(256),bytes(4096)) if initial is None else initial
                    code,o,w=until_effect(case["name"],wire,o,w)
                    seq=q(wire,168);sysseq=q(wire,176)
                    for index,event in enumerate(expected["events"],1):
                        assert code==1,(case["name"],index,code,"missing effect")
                        request=o[256:512];n=q(request,112)
                        assert q(o,128)==256+n and n<=len(o)-512
                        reference=event["request"];reply=event["reply"]
                        assert q(request,0)==fixture.REQUEST and q(request,8)==1
                        assert tuple(q(request,k) for k in (16,24,32,40))==(q(wire,16),q(wire,24),q(wire,32),index)
                        assert (q(request,48),q(request,56))==(reference["op"],reference["stage"])
                        assert [q(request,64+8*i) for i in range(6)]==reference["args"],(case["name"],reference,request.hex())
                        assert o[512:512+n]==reference["path"],(case["name"],"exact original byte path")
                        assert [q(request,k) for k in (128,136,144,152,160,168,176,184)]==[
                            q(wire,40),q(wire,152),q(wire,160),seq,sysseq,reply["peer"],q(wire,184),reference["state_before"][19]]
                        assert request[192:256]==bytes(64)
                        compare_state(w,reference["state_before"],(case["name"],reference["stage"]))
                        wire_reply=fixture.ack(request,reply)
                        code,o,w=until_effect(case["name"],wire_reply,o,w)
                        seq=reply["fs_sequence"];sysseq=reply["syscall_sequence"]
                    assert code==0 and q(w,8)==3,(case["name"],"unexpected trailing effect",code)
                    assert q(w,168)==expected["rc"]
                    compare_state(w,expected["state"],(case["name"],"terminal"))
                    assert q(w,80)==seq and q(w,88)==sysseq
                    report["cases_completed"].append(case["name"])
                    record(dict(kind="case-complete",case=case["name"],rc=expected["rc"],
                        effects=len(expected["events"]),actual_return=code,state=expected["state"]),True)
                    save(out/"summary.json",report)
                    return o,w
                if args.mode=="semantic":
                    assert 0<=args.start<args.end<=85
                    for case in all_cases[args.start:args.end]:semantic(case)
                    assert len(report["cases_completed"])==args.end-args.start
                else:
                    controls=[]
                    case=all_cases[0];wire=fixture.begin(case)
                    oracle=original.run(wire,fixture.Provider(case,wire))
                    def initial():
                        code,o,w=until_effect("protocol-setup",wire,bytes(256),bytes(4096))
                        assert code==1 and q(w,56)==10
                        return o,w,fixture.ack(o[256:512],oracle["events"][0]["reply"])
                    mutations=[("magic",0,0),("command",8,1),("scope1",16,0),("scope2",24,0),
                        ("call",32,0),("action",40,0),("op",48,2),("stage",56,11),
                        ("errno",64,4096),("pid",72,0),("extra-result",80,1),
                        ("sequence-regress",120,99),("syscall-regress",128,199),
                        ("payload-length",136,1),("peer",144,0),("context",152,0),
                        ("generation",160,0),("serial",168,0),("source-lease",176,0),
                        ("reserved",184,1),("request-echo",256,0)]
                    for name,offset,value in mutations:
                        o,w,good=initial();bad=bytearray(good);p(bad,offset,value)
                        returned,o,w=invoke("protocol-"+name,bytes(bad),o,w)
                        assert returned==BAD and q(w,0)==int.from_bytes(b"HIANUB01","little")
                        first=q(w,488);returned,o,w=invoke("protocol-"+name+"-sticky",good,o,w)
                        assert returned==BAD and q(w,488)==first
                        controls.append(name)
                    for name,transform in (
                        ("extra-byte",lambda good:good+b"x"),("short-source",lambda good:good[:511])):
                        o,w,good=initial();returned,o,w=invoke(name,transform(good),o,w)
                        assert returned==BAD
                        returned,o,w=invoke(name+"-sticky",good,o,w);assert returned==BAD
                        controls.append(name)
                    o,w,good=initial();returned,o,w=invoke("duplicate-first",good,o,w);assert returned==1
                    returned,o,w=invoke("duplicate-consumed-reply",good,o,w);assert returned==BAD
                    controls.append("duplicate-consumed-reply")
                    for size in (0,7,8,255,4095):
                        returned,oo,ww=invoke("short-workspace-"+str(size),wire,bytes(256),bytes(size))
                        assert returned==BAD
                        if size>=8:assert q(ww,0)==int.from_bytes(b"HIANUB01","little")
                        controls.append("short-workspace-"+str(size))
                    for offset,value in ((8,2),(32,0),(40,0),(48,0),(56,2),(64,123),(80,0),(128,511),(200,1<<32),(208,1)):
                        malformed=bytearray(wire);p(malformed,offset,value)
                        returned,oo,ww=invoke("bad-BEGIN-"+str(offset),bytes(malformed),bytes(1024),bytes(8192))
                        assert returned==BAD;controls.append("bad-BEGIN-"+str(offset))
                    grow_wire=fixture.begin(all_cases[0])
                    returned,o,w=invoke("BEGIN-GROW-before-effect",grow_wire,bytes(256),bytes(4096))
                    assert returned==2 and q(w,40)==0 and q(w,240)==0
                    changed=bytearray(grow_wire);p(changed,96,q(changed,96)+1)
                    returned,o,w=invoke("BEGIN-GROW-changed-header",bytes(changed),o,w)
                    assert returned==BAD;controls.append("BEGIN-GROW-changed-header")
                    o,w,good=initial();before=w
                    returned,short,w=invoke("ACK-GROW-no-consumption",good,bytes(256),w)
                    assert returned==2 and w==before and q(w,40)==1
                    returned,o,w=invoke("ACK-GROW-same-reply",good,short+bytes(q(w,456)-len(short)),w)
                    assert returned==1 and q(w,40)==2 and q(w,56)==20
                    controls.append("ACK-GROW-no-consumption")
                    o,w=semantic(case)
                    next_wire=fixture.begin(case,call=2,random_pid=q(w,336),counter=q(w,328),
                        fsseq=q(w,80),sysseq=q(w,88))
                    o,w=semantic(dict(case,name="next-valid-call"),next_wire,(o,w))
                    returned,o,w=invoke("replayed-completed-BEGIN",next_wire,o,w);assert returned==BAD
                    controls.append("replayed-completed-BEGIN")
                    report["protocol_controls"]=len(controls);report["protocol_names"]=controls
                    assert len(controls)==42,len(controls)
                assert report["VM_entries"]==report["native_entries"]>0
                report.update(status="PASS",all_complete_return_output_workspace_bytes_equal=True,
                    all_native_source_readonly_and_canaries=True,native_VM_byte_masking=False,
                    C_comparison="all initialized named fields and complete effect order",
                    C_undefined_allocator_payload_not_observed=True)
        for module in tuple(sys.modules.values()):
            filename=getattr(module,"__file__",None)
            if filename:
                path=Path(filename).resolve()
                if path.is_relative_to(ref) and path.suffix==".py":pin(path)
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        changed=[];after=[]
        for path,row in list(pins.items()):
            try:
                actual=Path(path);info=actual.lstat()
                assert stat.S_ISREG(info.st_mode) and not actual.is_symlink()
                raw=actual.read_bytes()
                observed=dict(path=path,bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
                after.append(observed)
                if observed!=row:changed.append(dict(path=path,before=row,after=observed))
            except BaseException as error:changed.append(dict(path=path,error=repr(error)))
        report["source_pins"]=list(pins.values());report["source_pins_unchanged"]=not changed
        if changed:report.update(status="FAIL",source_changes=changed)
        report["wall_ns"]=time.monotonic_ns()-started;report["CPU_ns"]=time.process_time_ns()-cpu_started
        save(out/"summary.json",report);save(out/"source-after.json",after)
        print("HIA_UNIXOPEN_PARENT_RESULT "+json.dumps(report,sort_keys=True),flush=True)
    return 0 if report["status"].startswith("PASS") else 1
if __name__=="__main__":raise SystemExit(main())
