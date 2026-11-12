"""Exact selected SQLite create-mode/URI C versus fresh HIA and real FS8.
Controlled raw stat returns are fixtures, never actual physical Store evidence.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import ctypes,gzip,hashlib,json,os,random,resource,signal,struct,time,traceback
from pathlib import Path
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError("create-mode paired wall180")))
signal.alarm(180)
bundle_path=Path(os.environ["HIA_CREATE_MODE_BUNDLE"]).resolve(strict=True)
bundle=json.loads(bundle_path.read_bytes())
sys.path.insert(0,bundle["reference"])
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import _Machine,_Owner,_View
from hepta.hia_json_preflight_native import NativeHiaJsonImage
OUT=Path(os.environ["HIA_CREATE_MODE_OUTPUT"]);OUT.mkdir(parents=True,exist_ok=False)
MASK=(1<<64)-1;RO=int.from_bytes(b"HIANCM01","little");FS=int.from_bytes(b"HIANFR03","little");BAD=0xfffffffd
def sha(x):return hashlib.sha256(x).hexdigest()
def save(name,value):(OUT/name).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def q(b,i):return struct.unpack_from("<Q",b,i*8)[0]
def packet(words,payload=b""):return struct.pack("<32Q",*(words+[0]*(32-len(words))))+payload
def changed(raw,index,value):
    b=bytearray(raw);struct.pack_into("<Q",b,index*8,value);return bytes(b)
pins={}
def pin(p,expected=None):
    p=Path(p);raw=p.read_bytes();v=dict(bytes=len(raw),sha256=sha(raw),mode=p.stat().st_mode&0o777)
    if expected is not None:assert v["sha256"]==expected
    if str(p) in pins:assert pins[str(p)]==v
    pins[str(p)]=v;return raw
programs={};images={}
pin(bundle_path);pin(__file__)
for role,row in bundle["roles"].items():
    programs[role]=verify_program(json.loads(pin(row["document"]["path"],row["document"]["sha256"])))
    raw=pin(row["image"]["path"],row["image"]["sha256"])
    images[role]=NativeHiaJsonImage(raw,sha(raw));assert images[role].image_sha256==sha(raw)
oracle_path=Path(bundle["oracle"]["path"]);pin(oracle_path,bundle["oracle"]["sha256"])
for row in bundle["input_pins"]:
    raw=pin(row["path"],row["sha256"])
    assert len(raw)==row["bytes"] and pins[str(Path(row["path"]))]["mode"]==row["mode"]
for p in sorted(Path(bundle["reference"]).rglob("*.py")):pin(p)
save("source-before.json",pins)
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
def vm(role,s,o,w):
    own=[_Owner(-1,bytearray(s)),_Owner(-2,bytearray(o)),_Owner(-3,bytearray(w))]
    machine=_Machine(programs[role],4000000,32<<20,None,64)
    result=machine.invoke(programs[role].as_dict()["functions"][0],[_View(own[0],False),_View(own[1],True),_View(own[2],True)])[0]
    assert bytes(own[0].data)==s
    return result,bytes(own[1].data),bytes(own[2].data),machine.steps,machine.resources()
ledger=gzip.open(OUT/"invocations.jsonl.gz","wt",encoding="utf-8")
cases_file=gzip.open(OUT/"complete-cases.jsonl.gz","wt",encoding="utf-8")
counts={r:dict(vm=0,native=0) for r in ("create_mode","fs")}
def pair(role,s,w,capacity=768,label=""):
    o=bytes((i*17+3)&255 for i in range(capacity))
    started=time.monotonic_ns();cpu=time.process_time_ns()
    row=dict(role=role,label=label,source_hex=s.hex(),pre_output_hex=o.hex(),pre_workspace_hex=w.hex())
    try:
        a=vm(role,s,o,w);counts[role]["vm"]+=1
        row["vm"]=dict(result=a[0],output_hex=a[1].hex(),workspace_hex=a[2].hex(),steps=a[3],resources=a[4])
        b=actual(images[role],s,o,w);counts[role]["native"]+=1
        row["native"]=dict(result=b[0],output_hex=b[1].hex(),workspace_hex=b[2].hex(),canaries=True,source_readonly_unchanged=True)
        assert b==a[:3],label
        row["equal"]=True
        return b
    finally:
        row.update(elapsed_ns=time.monotonic_ns()-started,cpu_ns=time.process_time_ns()-cpu)
        ledger.write(json.dumps(row,sort_keys=True,separators=(",",":"))+"\n");ledger.flush()

class RawReturn(ctypes.Structure):
    _fields_=[("kind",ctypes.c_uint64),("result",ctypes.c_int64)]+[(k,ctypes.c_uint64) for k in ("error","mode","size","nlink","dev","ino","uid","gid")]
oracle=ctypes.CDLL(str(oracle_path))
oracle.oracle_abi.argtypes=[];oracle.oracle_abi.restype=ctypes.c_uint64
oracle.oracle_run.argtypes=[
    ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_uint64,ctypes.c_uint64,
    ctypes.c_void_p,ctypes.c_uint64,ctypes.c_uint64,ctypes.c_uint64,ctypes.c_uint64,
    ctypes.c_uint64,ctypes.POINTER(RawReturn),ctypes.c_uint64,ctypes.c_void_p,
    ctypes.c_uint64,ctypes.POINTER(ctypes.c_uint64),ctypes.c_void_p,ctypes.c_uint64]
oracle.oracle_run.restype=ctypes.c_int
assert len(oracle.oracle_run.argtypes)==18 and oracle.oracle_abi()==RO and ctypes.sizeof(RawReturn)==80
corpus_path=Path(os.environ["HIA_CREATE_MODE_CORPUS"]).resolve(strict=True)
corpus=json.loads(pin(corpus_path,"331be470ee7d44eec2ec5a7dc12270044c322a9571a4761d71fe8d8860a414c5"))
assert corpus["schema"]=="hia.namespace-create-mode-uri.semantic-corpus.v1"
assert corpus["upstream_commit"]=="f3d536d37825302e31ed0eddd811c689f38f85a3"
assert len(corpus["cases"])==len({c["name"] for c in corpus["cases"]})==222
save("source-before.json",pins)
def reference(c):
    area=bytes.fromhex(c["area_hex"]);key=bytes.fromhex(c["key_hex"]);rows=c["raw_returns"]
    records=(RawReturn*len(rows))(*[RawReturn(**r) for r in rows])
    cap=max(1,len(area)+256);trace=(ctypes.c_ubyte*cap)()
    value=(ctypes.c_ubyte*(len(area)+1))();result=(ctypes.c_uint64*16)()
    a=ctypes.create_string_buffer(area);k=ctypes.create_string_buffer(key)
    returned=oracle.oracle_run(c["op"],a,len(area),c["pointer"],c["present"],
        k,len(key),c["keypresent"],c["flags"],c["default_value"],c["initial_errno"],
        records,len(rows),trace,cap,result,value,len(value))
    assert returned==0 and result[12]==0 and result[9]==len(rows) and result[14]==1,tuple(result)
    data=bytes(trace[:result[11]]);events=[];at=0
    while at<len(data):
        assert len(data)-at>=48
        h=struct.unpack_from("<6Q",data,at);at+=48;n=h[5]
        assert n<=len(data)-at
        events.append((*h[:5],data[at:at+n]));at+=n
    assert len(events)==result[10]
    return tuple(result),events,data,bytes(value[:result[8]+1]) if result[5] else b""
def begin(c):
    area=bytes.fromhex(c["area_hex"]);key=bytes.fromhex(c["key_hex"])
    words=[0]*32;words[:7]=[RO,1,71,83,1001,0,c["op"]]
    words[8:14]=[c["flags"],c["pointer"],len(area),len(key),c["default_value"],c["initial_errno"]]
    words[15:18]=[901,len(area)+len(key),777]
    if c["op"]==1:words[18:20]=[301,503]
    words[22:24]=[int(c["present"]),int(c["keypresent"])]
    return packet(words,area+key)
def ack(event,payload):
    words=[0]*32;words[:7]=[RO,2,71,83,1001,q(event,5),q(event,6)]
    words[15:18]=[901,len(payload),777]
    return packet(words,payload)
def fs_init():
    result=pair("fs",packet([FS,1,301,503]),bytes(512),400,"fs-init")
    assert result[0]==0
    return result[2]
def raw(error=0,**fields):
    r=dict(kind=29,result=-1 if error else 0,error=error,mode=0o100644,size=0,nlink=1,dev=7,ino=11,uid=1000,gid=1001)
    r.update(fields);return r
def fs_stat(source,workspace,row):
    capacity=max(400,258+q(source,12))
    while True:
        value,out,workspace=pair("fs",source,workspace,capacity,"stat-request")
        if value!=2:break
        nw,no=q(out,17),q(out,18)
        assert nw>len(workspace) or no>capacity
        if nw>len(workspace):workspace+=bytes(nw-len(workspace))
        capacity=max(capacity,no)
    assert value==1 and q(out,6)==row["kind"]
    assert q(out,8)==MASK-99 and q(out,9)==q(out,10)==q(out,11)==0
    payload=out[256:256+q(out,16)];assert payload.endswith(b"\0")
    event=(row["kind"],0,0,0,0,payload[:-1])
    data=b""
    if row["result"]>=0:
        assert row["result"]==0
        b=bytearray(144)
        struct.pack_into("<QQQIII",b,0,row["dev"],row["ino"],row["nlink"],row["mode"],row["uid"],row["gid"])
        struct.pack_into("<Q",b,48,row["size"]);data=bytes(b)
    words=[FS,3,301,503,q(out,4),q(out,5),row["kind"],(-row["error"] if row["result"]<0 else 0)&MASK]
    words.extend([0,0,0,0,len(data),q(out,14)])
    value,done,workspace=pair("fs",packet(words,data),workspace,capacity,"stat-completion")
    assert value==0
    return done[:256+q(done,16)],workspace,event
results=[];protocol=[];direct=[];pending_success=None;pending_error=None;completed=None
started=time.monotonic_ns()
def semantic(c):
    global pending_success,pending_error,completed
    cr,events,trace,selected=reference(c)
    source=begin(c);work=bytes(1024);capacity=256;fswork=None;seen=[];cursor=0;history=[]
    while True:
        pre=work
        value,out,work=pair("create_mode",source,work,capacity,c["name"])
        history.append(dict(source_hex=source.hex(),workspace_before_hex=pre.hex(),
            result=value,output_hex=out.hex(),workspace_after_hex=work.hex()))
        if value==2:
            nw,no=q(out,17),q(out,18)
            assert nw==1024 and no>capacity and q(work,5)==0
            capacity=no;continue
        if value==1:
            assert c["op"]==1 and cursor<len(c["raw_returns"]) and fswork is None
            fswork=fs_init()
            child=out[256:256+q(out,16)]
            reply,fswork,event=fs_stat(child,fswork,c["raw_returns"][cursor])
            seen.append(event);cursor+=1
            source=ack(out,reply)
            if q(reply,7)==0 and pending_success is None:pending_success=(source,work,capacity)
            if q(reply,7)!=0 and pending_error is None:pending_error=(source,work,capacity)
            continue
        assert value==0 and cursor==len(c["raw_returns"]) and seen==events
        assert q(out,11)==cr[4]
        if c["op"]==1:assert tuple(q(out,i) for i in (7,8,9,10))==cr[:4]
        elif c["op"]==2:
            assert (q(out,13),q(out,14),q(out,15))==(cr[5],cr[7],cr[8])
            assert out[256:256+q(out,16)]==selected
        else:assert q(out,12)==cr[6]
        completed=(begin(c),work,capacity)
        break
    row=dict(case=c,exact_C_result=cr,exact_C_trace_hex=trace.hex(),
        exact_C_value_hex=selected.hex(),native_events=[[*e[:5],e[5].hex()] for e in seen],
        complete_state_history=history,final_FS_workspace_hex=None if fswork is None else fswork.hex(),
        equal=True,actual_physical_syscalls=0)
    cases_file.write(json.dumps(row,sort_keys=True,separators=(",",":"))+"\n");cases_file.flush()
    results.append(dict(name=c["name"],op=c["op"],events=cursor,equal=True))
def ready(source,capacity=256):
    work=bytes(1024)
    while True:
        value,out,work=pair("create_mode",source,work,capacity,"private-ready")
        if value!=2:return value,out,work,capacity
        assert q(out,18)>capacity;capacity=q(out,18)
def fs_request(op,path=b""):
    return packet([FS,2,301,503,1,0,op,0,0,0,0,0,len(path),1],path)
try:
    for case in corpus["cases"]:semantic(case)
    assert len(results)==222 and pending_success is not None and pending_error is not None
    probe=begin(corpus["cases"][0])
    plan=[]
    def add(name,s,w=bytes(1024),capacity=768):plan.append((name,s,w,capacity))
    for n in range(256):add("short-source-"+str(n),probe[:n])
    for n in (0,1,7,8,16,1023):add("short-workspace-"+str(n),probe,bytes(n))
    for n in (0,1,7,8,127,255):add("short-output-"+str(n),probe,bytes(1024),n)
    bad=[(0,0),(1,0),(1,2),(2,0),(3,0),(4,0),(5,1),(6,0),(6,4),(7,1),
        (8,1<<32),(9,q(probe,10)),(10,q(probe,10)+1),(11,1),(12,1),(13,4096),
        (14,1),(15,0),(16,0),(17,0),(18,0),(19,0),(22,2),(23,1),(24,1),(31,1)]
    assert len(bad)==26
    for index,value in bad:
        data=changed(probe,index,value)
        if index in (2,3):data=changed(changed(data,2,0),3,0)
        if index in (18,19):data=changed(changed(data,18,0),19,0)
        add("bad-header-"+str(index)+"-"+str(value),data)
    for index in range(24,32):add("reserved-header-"+str(index),changed(probe,index,1))
    def malformed(name,area,op=2,pointer=4,key=b"k"):
        c=dict(corpus["cases"][0],op=op,area_hex=area.hex(),pointer=pointer,
            key_hex=key.hex(),keypresent=op!=1,flags=524288 if op==1 else 0,
            default_value=0,raw_returns=[])
        add(name,begin(c))
    malformed("empty-allocation",b"",1,0,b"")
    malformed("no-four-zero-prefix",b"xdb\0k\0v\0\0",2,1)
    malformed("unterminated-database",b"\0"*4+b"db")
    malformed("unterminated-key",b"\0"*4+b"db\0k")
    malformed("unterminated-value",b"\0"*4+b"db\0k\0v")
    malformed("NUL-key",b"\0"*4+b"db\0k\0v\0\0",2,4,b"k\0")
    value,out,work=pair("create_mode",probe,bytes(1024),256,"private-initial-GROW")
    assert value==2 and q(work,5)==0
    grow_capacity=q(out,18)
    grow_indices=(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,31)
    for index in grow_indices:add("changed-GROW-header-"+str(index),changed(probe,index,q(probe,index)^1),work,grow_capacity)
    good,waiting,capacity=pending_success
    for index in (0,1,2,3,4,5,6,7,8,12,13,14,15,16,17,18,31):
        add("ACK-outer-"+str(index),changed(good,index,q(good,index)^1),waiting,capacity)
    for index in (32,33,34,35,36,37,38,39,46,47,48,49,50,51,54,55,57,63):
        add("ACK-FS-frame-"+str(index),changed(good,index,q(good,index)^1),waiting,capacity)
    for index in (40,41,42,43,44,45,56):
        add("ACK-stat-duplicate-"+str(index),changed(good,index,q(good,index)^1),waiting,capacity)
    for delta in (-1,1):
        broken=good[:-1] if delta<0 else good+b"\0"
        broken=changed(broken,16,len(broken)-256)
        add("ACK-extent-"+str(delta),broken,waiting,capacity)
    failed,error_wait,error_capacity=pending_error
    for index in (40,41,42,43,44,45,48,56):
        add("ACK-error-zero-field-"+str(index),changed(failed,index,q(failed,index)^1),error_wait,error_capacity)
    source,work,capacity=completed
    add("after-completion",source,work,capacity)
    for index in (20,21):add("FS-counter-exhausted-"+str(index),changed(probe,index,MASK),bytes(1024),1024)
    assert len(plan)==len({r[0] for r in plan})==389
    save("protocol-plan.json",[dict(name=n,source_hex=s.hex(),workspace_hex=w.hex(),capacity=c) for n,s,w,c in plan])
    for name,source,work,capacity in plan:
        value,out,after=pair("create_mode",source,work,capacity,name)
        assert value==BAD,(name,value)
        if len(work)>=8:
            poisoned=after+bytes(max(0,1024-len(after)))
            again=pair("create_mode",probe,poisoned,1024,name+"-persistent")
            assert again[0]==BAD
        protocol.append(name)
    assert len(protocol)==389
    # Exact boundary: GROW has not issued STAT. It publishes once on the next
    # same immutable source and capacity, without any provider/native reuse.
    value,grow,work=pair("create_mode",probe,bytes(1024),256,"GROW-boundary")
    needed=q(grow,18);assert value==2 and q(work,5)==0
    value,too_small,w2=pair("create_mode",probe,work,needed-1,"GROW-one-byte-short")
    assert value==2 and w2==work
    value,published,w3=pair("create_mode",probe,work,needed,"GROW-exact")
    assert value==1 and q(w3,5)==1
    direct.append("GROW-exact-no-double-issue")
    # Existing op18 keeps its nonempty-path gate. New29 only changes that raw
    # syscall argument domain; no ordinary root authority is issued.
    for op,path,error in ((29,b"",2),(29,b"db",0),(29,b"db",4),(29,b"db",13),(18,b"db",0)):
        row=raw(error);row["kind"]=op
        done,workspace,event=fs_stat(fs_request(op,path),fs_init(),row)
        assert q(done,1)==0 and q(done,7)==error
        assert event==(op,0,0,0,0,path)
        direct.append("FS-stat-"+str(op)+"-"+str(len(path))+"-"+str(error))
    for name,source in (("old18-empty",fs_request(18)),("new29-NUL",fs_request(29,b"a\0b"))):
        value,out,work=pair("fs",source,fs_init(),400,name)
        assert value==BAD;direct.append(name)
    assert len(direct)==len(set(direct))==8
    before=dict(pins)
    for path,row in before.items():pin(path,row["sha256"])
    assert pins==before
    report=dict(status="PASS",scope="SELECTED_CREATE_MODE_URI_WITH_REAL_FS8_CONTROLLED_RETURNS",
        semantic_cases=len(results),semantic_results=results,
        protocol_controls=len(protocol),protocol_control_ids=protocol,
        direct_controls=len(direct),direct_control_ids=direct,
        entries_by_role=counts,VM_entries=sum(r["vm"] for r in counts.values()),
        native_entries=sum(r["native"] for r in counts.values()),
        whole_buffers_equal=True,canaries=True,immutable_sources_unchanged=True,
        source_before_after_equal=True,actual_physical_syscalls=0,full_unixOpen_closed=False,
        ordinary_Store_closed=False,prior_counts_inherited=False,
        elapsed_ns=time.monotonic_ns()-started,
        limits=dict(cpu_seconds=90,wall_seconds=180,address_bytes=1<<30,core_bytes=0,VM_steps=4000000,VM_arena_bytes=32<<20),
        actual_limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))))
    save("summary.json",report);save("source-after.json",pins)
    print(json.dumps(report,sort_keys=True),flush=True)
except BaseException as error:
    report=dict(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc(),
        semantic_cases_completed=len(results),protocol_completed=len(protocol),direct_completed=len(direct),entries_by_role=counts)
    save("summary.json",report);raise
finally:
    signal.alarm(0);ledger.close();cases_file.close()
