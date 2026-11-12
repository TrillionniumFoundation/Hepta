"""Fresh old-VM/new-VM/new-native six-role packer full-buffer differential.
The old source is a reference only; its 23-parameter image is NOT compiled under
a widened gate. The new actual image comes from the unchanged fresh B3 gate.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import argparse,ctypes,gzip,hashlib,importlib.util,json,os,resource,signal,stat,struct,time,traceback
from pathlib import Path
OLD="2969dcc0163e52801324bc92ccb8f5eb68770f3f997f79e4f132e66a61358e0e"
NEW="585fb9a1c2b8d2cd0cdfff8abcaa9f41c08dd16eabdfdaabec13cf6866229dd5"
ASM="fc47cfc647affed2db900351834845b819c4c07f838dcb701a3a03f418813b9b"
VALUES="7c3f0299291cf4b99d5c2296351dcfd5e471507d4903ab9da171420c126c5c50"
BUILDER="2320a0363d312f1f07b48cc370f06ac7dbaedefa28437c28230fff6fba4dc3de"
resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError("packer differential wall180")));signal.alarm(180)
parser=argparse.ArgumentParser()
for name in ("context","old-packer","new-packer","executor"):parser.add_argument("--"+name,type=Path,required=True)
args=parser.parse_args()
pins={}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(path,expected=None):
    path=Path(path).absolute();st=path.lstat();assert stat.S_ISREG(st.st_mode) and not path.is_symlink()
    raw=path.read_bytes();row=dict(bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(st.st_mode))
    if expected is not None:assert row["sha256"]==expected,(str(path),row,expected)
    if str(path) in pins:assert pins[str(path)]==row
    pins[str(path)]=row;return raw
def module(name,path,expected):
    raw=pin(path,expected);spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);sys.modules[name]=m;exec(compile(raw,str(path),"exec"),m.__dict__);return m
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
context=json.loads(pin(args.context));assert sys.version_info[:3]==(3,12,14)
ref=Path(context["reference"]);tree=Path(context["namespace_working"]);evidence=Path(context["namespace_evidence"])
out=evidence/"packer-differential-r1";out.mkdir()
sys.path.insert(0,str(ref))
module("tools.generate_hia_agent_namespace_store",tree/"tools/generate_hia_agent_namespace_store.py",VALUES)
module("tools.generate_hia_agent_namespace_objects",tree/"tools/generate_hia_agent_namespace_objects.py",BUILDER)
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import _Machine,_Owner,_View
from hepta.hia_json_preflight_native import NativeHiaJsonImage
pin(__file__)
old=module("namespace_old_packer_reference",args.old_packer,OLD)
new=module("namespace_new_packer_candidate",args.new_packer,NEW)
build_dir=evidence/"db-join-build-r1";build=json.loads(pin(build_dir/"summary.json"))
assert build["status"]=="PASS_BUILD_ONLY" and build["source_pins_unchanged"]
assert build["fresh_role_compiles"]==6 and build["packer_entries"]==33
layout=json.loads(pin(build_dir/"layout.json"));binary=pin(build_dir/"executor.bin")
source=pin(args.executor,ASM);prefix,table=new.prefix_and_table(source,binary,layout)
assert old.prefix_and_table(source,binary,layout)==(prefix,table)
documents={"old":old.document(prefix,table),"new":new.document(prefix,table)}
new_document_pin=build["profile_frontiers"]["packer"]["document"]
new_document_raw=pin(new_document_pin["path"],new_document_pin["sha256"])
assert new_document_raw==(json.dumps(documents["new"],sort_keys=True,separators=(",",":"))+"\n").encode()
programs={}
for name,doc in documents.items():
    raw=(json.dumps(doc,sort_keys=True,separators=(",",":"))+"\n").encode()
    path=out/(name+".document.json");path.write_bytes(raw);pin(path)
    programs[name]=verify_program(doc)
image_raw=pin(build["compile_receipt"]["produced_image"],build["packer_image_sha256"])
assert build["compile_receipt"]["produced_bytes"]==len(image_raw)
image=NativeHiaJsonImage(image_raw,sha(image_raw));assert image.image_sha256==sha(image_raw)
for m in tuple(sys.modules.values()):
    p=getattr(m,"__file__",None)
    if p:
        p=Path(p).resolve()
        if p.is_relative_to(ref) and p.suffix==".py":pin(p)
save(out/"source-before.json",pins)
libc=ctypes.CDLL(None,use_errno=True)
libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long];libc.mmap.restype=ctypes.c_void_p
libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];libc.mprotect.restype=ctypes.c_int
libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];libc.munmap.restype=ctypes.c_int
CANARY=bytes(range(16))
class Buffer:
    def __init__(self,b,readonly=False):
        self.size=len(b);self.middle=(len(b)+32+4095)&~4095;self.total=self.middle+8192
        self.raw=libc.mmap(None,self.total,0,0x22,-1,0)
        if self.raw==ctypes.c_void_p(-1).value:raise OSError(ctypes.get_errno(),"mmap")
        self.base=self.raw+4096;self.address=self.base+16
        try:
            if libc.mprotect(self.base,self.middle,3):raise OSError(ctypes.get_errno(),"mprotect RW")
            ctypes.memmove(self.base,CANARY,16)
            if b:ctypes.memmove(self.address,b,len(b))
            ctypes.memmove(self.address+self.size,CANARY,16)
            if readonly and libc.mprotect(self.base,self.middle,1):raise OSError(ctypes.get_errno(),"mprotect RO")
        except BaseException:
            libc.munmap(self.raw,self.total);raise
    def read(self):return ctypes.string_at(self.address,self.size)
    def check(self):
        assert ctypes.string_at(self.base,16)==CANARY
        assert ctypes.string_at(self.address+self.size,16)==CANARY
    def close(self):
        if libc.munmap(self.raw,self.total):raise OSError(ctypes.get_errno(),"munmap")
        self.raw=None
def actual(image,s,o,w):
    buffers=[];primary=None
    try:
        for raw,ro in ((s,True),(o,False),(w,False)):buffers.append(Buffer(raw,ro))
        a,b,c=buffers
        result=int(image._entry(a.address,a.size,b.address,b.size,c.address,c.size))
        for item in buffers:item.check()
        assert a.read()==s
        return result,b.read(),c.read()
    except BaseException as error:
        primary=error;raise
    finally:
        cleanup=None
        for b in reversed(buffers):
            try:b.close()
            except BaseException as error:
                if cleanup is None:cleanup=error
                else:cleanup.add_note(repr(error))
        if cleanup is not None:
            if primary is None:raise cleanup
            primary.add_note("buffer cleanup: "+repr(cleanup))

def vm(name,s,o,w):
    owners=[_Owner(-1,bytearray(s)),_Owner(-2,bytearray(o)),_Owner(-3,bytearray(w))]
    machine=_Machine(programs[name],4000000,32<<20,None,64)
    answer=machine.invoke(programs[name].as_dict()["functions"][0],[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
    assert bytes(owners[0].data)==s
    return answer,bytes(owners[1].data),bytes(owners[2].data),machine.steps,machine.resources()
def payload(sizes,seed):
    records=bytearray();images=[];offsets=[]
    for role,n in enumerate(sizes,1):
        image=bytes((role*31+i*7+seed)&255 for i in range(n))
        offsets.append(64+len(records));images.append(image)
        records+=struct.pack("<3Q",role,n,0)+image
    wire=struct.pack("<8Q",new.MAGIC,1,6,64+len(records),0,0,0,0)+records
    expected=bytearray(prefix)
    for role,image in enumerate(images,1):
        at=(len(expected)+15)&~15;expected+=bytes(at-len(expected))+image
        struct.pack_into("<Q",expected,table+role*8,0x400000+at)
    struct.pack_into("<2Q",expected,96,len(expected),len(expected))
    return bytes(wire),bytes(expected),offsets
cases=[];names=set()
def add(name,wire,cap,result,output=None):
    assert name not in names;names.add(name);cases.append((name,wire,cap,result,output))
for i in range(24):
    sizes=[(i*19+r*13)%127+1 for r in range(6)]
    if i<6:sizes=[(1,15,16,17,31,32)[i]]*6
    wire,expected,_=payload(sizes,i)
    add("valid-"+str(i),wire,len(expected),len(expected),expected)
    add("short-output-"+str(i),wire,len(expected)-1,0xfffffffe)
wire,expected,offsets=payload([9,17,25,33,41,49],31)
controls=[("magic",0,0),("version",8,0),("count",16,5),("length",24,0)]
controls += [("reserved-"+str(at),at,1) for at in (32,40,48,56)]
for role,at in enumerate(offsets,1):
    controls += [("role-"+str(role),at,7),("empty-"+str(role),at+8,0),
                 ("large-"+str(role),at+8,(1<<20)+1),("role-reserved-"+str(role),at+16,1)]
assert len(controls)==32
for name,at,value in controls:
    mutated=bytearray(wire);struct.pack_into("<Q",mutated,at,value)
    add(name,bytes(mutated),len(expected),0xffffffff)
for name,raw in (("truncated",wire[:-1]),("trailing",wire+b"\0"),("empty-source",b""),("short-header",wire[:207])):
    add(name,raw,len(expected),0xffffffff)
assert len(cases)==len(names)==84
started=time.monotonic_ns();counts=dict(old_VM=0,new_VM=0,new_native=0);results=[]
report=dict(status="INCOMPLETE",scope="OLD_SOURCE_VM_NEW_SOURCE_VM_FRESH_NEW_NATIVE_PACKER",
    old_native_compiles=0,new_B3_compiles_in_this_process=0,actual_physical_syscalls=0)
ledger=gzip.open(out/"complete-invocations.jsonl.gz","wt",encoding="utf-8")
try:
    for i,(name,s,cap,expected_return,expected_output) in enumerate(cases):
        o=bytes((j*23+i*11+37)&255 for j in range(cap))
        w=bytes((j*13+i+5)&255 for j in range((0,1,7,8,63,64,65)[i%7]))
        row=dict(name=name,source_hex=s.hex(),output_before_hex=o.hex(),workspace_before_hex=w.hex())
        try:
            a=vm("old",s,o,w);counts["old_VM"]+=1
            row["old_VM"]=dict(result=a[0],output_hex=a[1].hex(),workspace_hex=a[2].hex(),steps=a[3],resources=a[4])
            b=vm("new",s,o,w);counts["new_VM"]+=1
            row["new_VM"]=dict(result=b[0],output_hex=b[1].hex(),workspace_hex=b[2].hex(),steps=b[3],resources=b[4])
            c=actual(image,s,o,w);counts["new_native"]+=1
            row["new_native"]=dict(result=c[0],output_hex=c[1].hex(),workspace_hex=c[2].hex(),canaries=True,readonly_source_unchanged=True)
            wanted=o if expected_output is None else expected_output
            assert a[:3]==b[:3]==c==(expected_return,wanted,w),name
            row["equal"]=True
            results.append(dict(name=name,result=c[0],output_bytes=len(c[1]),output_sha256=sha(c[1]),workspace_unchanged=True,three_way_equal=True))
        finally:
            ledger.write(json.dumps(row,sort_keys=True,separators=(",",":"))+"\n");ledger.flush()
    assert counts==dict(old_VM=84,new_VM=84,new_native=84)
    assert len(results)==84 and all(r["three_way_equal"] for r in results)
    report.update(status="PASS",cases=84,results=results,counts=counts,
        no_masks=True,complete_buffers_equal=True,old_profile_not_relaxed=True)
except BaseException as exc:
    report.update(status="FAIL",error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc(),counts=counts,cases_completed=len(results))
    traceback.print_exc()
finally:
    ledger.close()
    cleanup=None
    try:image._mapping.close()
    except BaseException as exc:cleanup=repr(exc)
    after={}
    for path,row in pins.items():
        try:
            st=Path(path).lstat();raw=Path(path).read_bytes()
            assert stat.S_ISREG(st.st_mode) and not Path(path).is_symlink()
            after[path]=dict(bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(st.st_mode))
        except BaseException as exc:after[path]=dict(error=repr(exc))
    unchanged=after==pins
    report.update(source_before_after_equal=unchanged,mapping_cleanup_error=cleanup,
        elapsed_ns=time.monotonic_ns()-started,
        limits=dict(cpu_seconds=90,wall_seconds=180,address_bytes=1<<30,core_bytes=0,VM_steps=4000000,VM_arena_bytes=32<<20),
        actual_limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))))
    if not unchanged or cleanup is not None:report["status"]="FAIL"
    save(out/"source-after.json",after);save(out/"summary.json",report);signal.alarm(0)
    print("HIA_NAMESPACE_PACKER_THREE_WAY "+json.dumps(report,sort_keys=True),flush=True)
raise SystemExit(0 if report["status"]=="PASS" else 1)
