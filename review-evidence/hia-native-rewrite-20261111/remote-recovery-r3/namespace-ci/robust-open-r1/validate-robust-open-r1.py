"""Exact selected C robust_open against fresh HIA VM/native and real FS7 image.
Raw OS returns are controlled test inputs. This is NOT actual physical IO.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import ctypes,gzip,hashlib,json,os,random,resource,signal,struct,time,traceback
from pathlib import Path
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError("robust paired wall180")))
signal.alarm(180)
bundle_path=Path(os.environ["HIA_ROBUST_BUNDLE"]).resolve(strict=True)
bundle=json.loads(bundle_path.read_bytes())
sys.path.insert(0,bundle["reference"])
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import _Machine,_Owner,_View
from hepta.hia_json_preflight_native import NativeHiaJsonImage
OUT=Path(os.environ["HIA_ROBUST_OUTPUT"]);OUT.mkdir(parents=True,exist_ok=False)
MASK=(1<<64)-1;RO=int.from_bytes(b"HIANRO01","little");FS=int.from_bytes(b"HIANFR03","little");BAD=0xfffffffd
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
counts={r:dict(vm=0,native=0) for r in ("robust","fs")}
def pair(role,s,w,capacity=768,label=""):
    o=bytes((i*17+3)&255 for i in range(capacity))
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
        ledger.write(json.dumps(row,sort_keys=True,separators=(",",":"))+"\n");ledger.flush()
class RawReturn(ctypes.Structure):
    _fields_=[("kind",ctypes.c_uint64),("result",ctypes.c_int64)]+[(k,ctypes.c_uint64) for k in ("error","mode","size","nlink","dev","ino","uid","gid")]
oracle=ctypes.CDLL(str(oracle_path))
oracle.oracle_abi.argtypes=[];oracle.oracle_abi.restype=ctypes.c_uint64
oracle.oracle_run.argtypes=[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_uint64,ctypes.c_uint64,ctypes.c_uint64,ctypes.POINTER(RawReturn),ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.POINTER(ctypes.c_uint64)]
oracle.oracle_run.restype=ctypes.c_int
assert oracle.oracle_abi()==RO and ctypes.sizeof(RawReturn)==80
def raw(kind,result=0,error=0,**kw):
    return dict(kind=kind,result=result,error=error,mode=kw.get("mode",0o100600),size=kw.get("size",0),nlink=kw.get("nlink",1),dev=kw.get("dev",7),ino=kw.get("ino",11),uid=kw.get("uid",0),gid=kw.get("gid",0))
def reference(path,flags,mode,err,rows):
    records=(RawReturn*len(rows))(*[RawReturn(**r) for r in rows])
    cap=max(1,len(rows)*(len(path)+512));trace=(ctypes.c_ubyte*cap)();result=(ctypes.c_uint64*8)()
    p=ctypes.create_string_buffer(path)
    assert oracle.oracle_run(p,len(path),flags,mode,err,records,len(rows),trace,cap,result)==0
    assert result[5]==0 and result[2]==len(rows) and result[7]==1,tuple(result)
    data=bytes(trace[:result[4]]);events=[];at=0
    while at<len(data):
        h=struct.unpack_from("<6Q",data,at);at+=48;n=h[5]
        assert n<=len(data)-at
        events.append((*h[:5],data[at:at+n]));at+=n
    assert len(events)==result[3]
    return tuple(result),events,data
def begin(path,flags=2,mode=0,err=0):
    words=[0]*32;words[:5]=[RO,1,71,83,1001]
    words[8:11]=[flags,mode,err];words[12:18]=[301,503,0,0,len(path),901]
    return packet(words,path)
def ack(event,payload,warning=False,err=0):
    words=[0]*32;words[:8]=[RO,3 if warning else 2,71,83,1001,q(event,5),q(event,6),0]
    if warning:words[8]=err
    words[16]=len(payload);words[17]=901
    return packet(words,payload)
def fs_init():
    s=packet([FS,1,301,503])
    result=pair("fs",s,bytes(512),400,"fs-init");assert result[0]==0
    return result[2]
def fs_complete(s,w,row,allow_refusal=False):
    capacity=max(400,258+q(s,12));out=None
    while True:
        value,out,w=pair("fs",s,w,capacity,"fs-request")
        if value!=2:break
        nw,no=q(out,17),q(out,18)
        assert nw>len(w) or no>capacity
        if nw>len(w):w+=bytes(nw-len(w))
        capacity=max(capacity,no)
    assert value==1
    op=q(out,6);assert row["kind"]==op
    data=out[256:256+q(out,16)]
    if op in (1,25,28):
        assert q(out,8)==MASK-99 and data.endswith(b"\0")
        event=(op,q(out,9),q(out,10),0,0,data[:-1])
    elif op==9:
        assert q(out,8)==MASK-99 and q(out,9)==0 and data.endswith(b"\0")
        event=(9,0,0,0,0,data[:-1])
    elif op==8:event=(8,q(out,8),0,0,0,b"")
    elif op==15:event=(15,q(out,8),0,0,0,b"")
    elif op==21:event=(21,q(out,8),q(out,9),0,0,b"")
    elif op==26:event=(26,0,0,0,0,b"")
    elif op==27:
        assert q(out,8)==MASK-99 and data.endswith(b"\0")
        event=(27,q(out,9),0,0,0,data[:-1])
    else:raise AssertionError(("unexpected actual FS operation",op))
    payload=b""
    if row["result"]>=0 and op==15:
        b=bytearray(144);struct.pack_into("<QQQIII",b,0,row["dev"],row["ino"],row["nlink"],row["mode"],row["uid"],row["gid"])
        struct.pack_into("<Q",b,48,row["size"]);payload=bytes(b)
    words=[FS,3,301,503,q(out,4),q(out,5),op,((-row["error"]) if row["result"]<0 else row["result"])&MASK]
    words.extend([0,0,0,0,len(payload),q(out,14)])
    a=packet(words,payload)
    value,out,w=pair("fs",a,w,capacity,"fs-completion")
    assert value==(BAD if allow_refusal else 0)
    return out[:256+q(out,16)],w,event
names=set();results=[];captured=[];pending={};protocol=[];fs_controls=[];started=time.monotonic_ns()
def semantic(name,path,flags,mode,err,rows):
    assert name not in names;names.add(name)
    cr,events,trace=reference(path,flags,mode,err,rows)
    work=bytes(1024);capacity=256;s=begin(path,flags,mode,err);fswork=fs_init()
    seen=[];i=0;history=[];last=None
    while True:
        pre=work
        value,out,work=pair("robust",s,work,capacity,name)
        history.append(dict(source_hex=s.hex(),workspace_before_hex=pre.hex(),output_hex=out.hex(),workspace_after_hex=work.hex(),result=value))
        if value==2:
            nw,no=q(out,17),q(out,18);assert nw>len(work) or no>capacity
            if nw>len(work):work+=bytes(nw-len(work))
            capacity=max(capacity,no);continue
        if value==0:
            assert i==len(rows) and seen==events
            assert q(out,9)==cr[0] and q(out,10)==cr[1]
            assert (q(out,8)!=0)==(cr[0]!=MASK)
            assert q(out,12)==sum(e[0]==10028 for e in events)
            assert q(out,13)==sum(n>0 and e[0]==28 and events[n-1][0]==10028 and rows[n]["result"]>=0 for n,e in enumerate(events))
            assert q(out,14)==q(fswork,4) and q(out,15)==q(fswork,5)
            last=out;break
        assert i<len(rows),(name,i,value)
        row=rows[i]
        if value==1:
            child=out[256:256+q(out,16)]
            reply,fswork,event=fs_complete(child,fswork,row)
            seen.append(event);s=ack(out,reply)
            pending.setdefault(q(out,7),(s,work,capacity))
        elif value==3:
            assert row["kind"]==10028
            seen.append((10028,28,0,0,0,out[256:256+q(out,16)]))
            s=ack(out,b"",True,row["error"])
            pending.setdefault(22,(s,work,capacity))
        else:raise AssertionError((name,"unexpected robust status",value,q(work,21)))
        i+=1
    row=dict(name=name,path_hex=path.hex(),flags=flags,mode=mode,initial_errno=err,raw_returns=rows,
        exact_C_result=cr,exact_C_trace_hex=trace.hex(),native_policy_events=[[*e[:5],e[5].hex()] for e in seen],
        complete_state_history=history,final_fs_workspace_hex=fswork.hex(),equal=True,actual_physical_syscalls=0)
    cases_file.write(json.dumps(row,sort_keys=True,separators=(",",":"))+"\n");cases_file.flush()
    results.append(dict(name=name,events=len(seen),returned_fd=cr[0],errno=cr[1],equal=True))
    if name=="plain-success":captured.append((begin(path,flags,mode,err),work,capacity,last))
def refuse_control(name,s,w,capacity):
    assert name not in protocol;protocol.append(name)
    result=pair("robust",s,w,capacity,name)
    assert result[0]==BAD,(name,result[0])
    # The next complete valid BEGIN cannot clear a sufficiently large poisoned state.
    if len(w)>=8:
        enlarged=result[2]+bytes(max(0,1024-len(w)))
        repeat=pair("robust",begin(b"/tmp/db"),enlarged,max(capacity,768),name+"-sticky")
        assert repeat[0]==BAD
    return result
def fresh_ready(source,capacity=768):
    work=bytes(1024)
    while True:
        value,out,work=pair("robust",source,work,capacity,"private-ready")
        if value!=2:return value,out,work,capacity
        nw,no=q(out,17),q(out,18);assert nw>len(work) or no>capacity
        if nw>len(work):work+=bytes(nw-len(work))
        capacity=max(capacity,no)
try:
    semantic("plain-success",b"/tmp/db",2,0,0,[raw(28,9)])
    semantic("empty-path-actual-open",b"",2,0,0,[raw(28,-1,2)])
    for error in (1,2,5,9,12,13,17,20,21,22,23,24,28,30,36,40,95):
        semantic("open-error-"+str(error),b"/tmp/db",2,0,0,[raw(28,-1,error)])
    semantic("open-eintr-twice",b"/tmp/db",2,0,7,[raw(28,-1,4),raw(28,-1,4),raw(28,9)])
    for fd in (0,1,2):
        semantic("lowfd-"+str(fd),b"/tmp/db",2,0,0,[raw(28,fd),raw(8),raw(10028,error=0),raw(28,fd),raw(28,9)])
        semantic("exclusive-lowfd-"+str(fd),b"/tmp/db",2|64|128,0,0,[raw(28,fd),raw(9),raw(8),raw(10028,error=0),raw(28,fd),raw(28,9)])
        semantic("lowfd-unlink-close-errors-"+str(fd),b"/tmp/db",2|64|128,0,0,[raw(28,fd),raw(9,-1,13),raw(8,-1,4),raw(10028,error=4),raw(28,fd),raw(28,9)])
    for error in (4,13,24):
        semantic("filler-error-no-retry-"+str(error),b"/tmp/db",2,0,0,[raw(28,0),raw(8),raw(10028,error=0),raw(28,-1,error)])
    semantic("all-three-standard-slots",b"relative-db",2,0,0,[raw(28,0),raw(8),raw(10028,error=0),raw(28,0),raw(28,1),raw(8),raw(10028,error=0),raw(28,1),raw(28,2),raw(8),raw(10028,error=0),raw(28,2),raw(28,9)])
    for mode in (1,0o600,0o644,0o777,0o1000,0xffffffff):
        same_mode_rows=[raw(28,9),raw(15,mode=mode)]
        if (mode&0o777)!=mode:same_mode_rows.append(raw(21))
        semantic("nonzero-mode-same-"+str(mode),b"db",2|64,mode,17,same_mode_rows)
        semantic("nonzero-mode-chmod-"+str(mode),b"db",2|64,mode,0,[raw(28,9),raw(15,mode=0),raw(21)])
        semantic("nonzero-mode-stat-error-"+str(mode),b"db",2,mode,0,[raw(28,9),raw(15,-1,5)])
        semantic("nonzero-mode-chmod-error-"+str(mode),b"db",2|64,mode,0,[raw(28,9),raw(15,mode=0),raw(21,-1,13)])
        semantic("nonzero-size-no-chmod-"+str(mode),b"db",2|64,mode,0,[raw(28,9),raw(15,mode=0,size=1)])
    for path in (b"a"*4095,b"a"*4096,b"a"*8193,b"/tmp/\xff\xfe\x80",b".",b"../x",b"/dev/null"):
        semantic("path-"+str(len(results)),path,2,0,0,[raw(28,9)])
    for flags in (0x80000000,0xffffffff,0x40000000|192):
        semantic("full-u32-flags-"+str(flags),b"db",flags,0,0,[raw(28,9)])
    for fd in (3,4,2147483647):
        semantic("full-i32-fd-"+str(fd),b"db",2,0,0,[raw(28,fd)])
    semantic("long-warning",b"a"*4096,2,0,0,[raw(28,0),raw(8),raw(10028,error=0),raw(28,0),raw(28,9)])
    rng=random.Random(0x524f42555354)
    for index in range(40):
        rows=[raw(28,-1,4) for _ in range(rng.randrange(4))]
        flags=rng.choice((0,2,2|64,2|64|128));mode=rng.choice((0,0o600,0o644))
        error=rng.choice((0,0,0,2,13,24));initial=rng.choice((0,4,17))
        if error:rows.append(raw(28,-1,error))
        else:
            rows.append(raw(28,9))
            if mode:
                staterr=rng.choice((0,0,5))
                if staterr:rows.append(raw(15,-1,staterr))
                else:
                    smode=rng.choice((0,mode));size=rng.choice((0,1))
                    rows.append(raw(15,mode=smode,size=size))
                    if size==0 and smode!=mode:
                        chmoderr=rng.choice((0,13));rows.append(raw(21,-1 if chmoderr else 0,chmoderr))
        semantic("seeded-"+str(index),b"db-"+str(index).encode(),flags,mode,initial,rows)
    assert len(results)==117 and len(names)==117
    # Private controls are separately labelled and never counted as physical IO.
    probe=begin(b"/tmp/db")
    for n in range(256):
        refuse_control("short-source-"+str(n),probe[:n],bytes(1024),768)
    for n in (0,1,7,8,16,1023):
        refuse_control("short-workspace-"+str(n),probe,bytes(n),768)
    for n in (0,1,7,8,127,255):
        refuse_control("short-output-"+str(n),probe,bytes(1024),n)
    for index,value in ((0,0),(1,0),(1,2),(2,0),(3,0),(4,0),(5,1),(6,1),(7,1),(8,1<<32),(9,1<<32),(10,4096),(11,1),(12,0),(13,0),(16,99),(17,0),(18,1),(31,1)):
        rawin=changed(probe,index,value)
        if index in (2,3):rawin=changed(changed(rawin,2,0),3,0)
        if index in (12,13):rawin=changed(changed(rawin,12,0),13,0)
        refuse_control("bad-begin-"+str(index)+"-"+str(value),rawin,bytes(1024),768)
    refuse_control("path-NUL",begin(b"a\0b"),bytes(1024),768)
    # GROW has no primitive effect and reuses the same source. Changed immutable
    # source header is invalid; pathname content custody belongs to the issuer.
    grow,out,w=pair("robust",probe,bytes(1024),256,"begin-grow")
    assert grow==2 and q(w,5)==0
    for index in (0,1,2,3,4,5,6,8,9,10,12,13,14,15,17,31):
        refuse_control("changed-BEGIN-GROW-"+str(index),changed(probe,index,q(probe,index)^1),w+bytes(q(out,17)-len(w)),q(out,18))
    for index in (14,15):
        exhausted=changed(probe,index,MASK)
        value,reply,w,capacity=fresh_ready(exhausted)
        assert value==BAD and q(w,21)==17
        protocol.append("initial-FS-counter-exhausted-"+str(index))
        refuse_control("initial-FS-counter-sticky-"+str(index),probe,w,capacity)
        almost=changed(probe,index,MASK-1)
        value,reply,w,capacity=fresh_ready(almost)
        assert value==1 and q(reply,index)==MASK
        unknown=ack(reply,b"")
        unknown=changed(unknown,1,4)
        refuse_control("last-FS-counter-unknown-"+str(index),unknown,w,capacity)
    assert set(pending)=={10,20,21,22,23,30,31}
    for stage,(good,w,capacity) in sorted(pending.items()):
        for index in (0,2,3,4,5,6,7,16,17,18,31):
            refuse_control("ACK-"+str(stage)+"-identity-"+str(index),changed(good,index,q(good,index)^1),w,capacity)
        refuse_control("ACK-"+str(stage)+"-unknown",changed(good,1,4),w,capacity)
        # Output growth while waiting preserves the pending request and all counters.
        if capacity>256:
            value,grow,after=pair("robust",good,w,256,"ACK-small-output-"+str(stage))
            assert value==2 and after==w
            a=pair("robust",good,after,capacity,"ACK-after-growth-"+str(stage))
            b=pair("robust",good,w,capacity,"ACK-original-control-"+str(stage))
            assert a==b
            protocol.append("ACK-GROW-same-source-"+str(stage))
        if stage==22:
            refuse_control("warning-invalid-errno",changed(good,8,4096),w,capacity)
            refuse_control("warning-reserved",changed(good,9,1),w,capacity)
            continue
        for index,value in ((32,0),(33,1),(34,0),(35,0),(36,0),(37,0),(38,0),(39,4096),(46,0),(47,0),(48,1),(49,1),(50,1),(51,1),(54,0),(55,1),(57,1),(63,1)):
            refuse_control("ACK-"+str(stage)+"-FS-frame-"+str(index),changed(good,index,value),w,capacity)
        for delta in (-1,1):
            broken=good[:-1] if delta<0 else good+b"\0"
            broken=changed(broken,16,len(broken)-256)
            refuse_control("ACK-"+str(stage)+"-actual-extent-"+str(delta),broken,w,capacity)
    good,w,capacity=pending[10]
    assert q(good,39)==0
    for index,value in ((40,0),(41,1<<31),(42,1),(43,1),(44,1),(45,1),(52,0),(53,q(good,40)),(56,1)):
        refuse_control("open-success-shape-"+str(index),changed(good,index,value),w,capacity)
    good,w,capacity=pending[30]
    assert q(good,16)==400 and q(good,39)==0
    for index in (40,41,42,43,44,45,56):
        refuse_control("stat-duplicated-field-"+str(index),changed(good,index,q(good,index)^1),w,capacity)
    # Counters cannot wrap even on otherwise correlated completed replies.
    good,w,capacity=pending[21]
    refuse_control("warning-count-exhausted",good,changed(w,23,MASK),capacity)
    good,w,capacity=pending[23]
    refuse_control("filler-count-exhausted",good,changed(w,24,MASK),capacity)
    # The current correlated request cannot restart a completed context.
    for rawin,w,capacity,last in captured:
        refuse_control("after-completion",rawin,w,capacity)
    assert len(protocol)==len(set(protocol))==542
    def fs_request(op,path=b"",b=0,c=0):
        words=[FS,2,301,503,1,0,op,0,0,b,c,0,len(path),1]
        return packet(words,path)
    for op in (1,25):
        for fd in (0,9):
            out,w,event=fs_complete(fs_request(op,b"db",2,0o644),fs_init(),raw(op,fd))
            assert q(out,1)==0 and q(out,7)==0 and q(out,8)==1
            assert q(out,9)==(fd if op==25 else 0)
            fs_controls.append("old-open-"+str(op)+"-"+str(fd))
        value,out,w=pair("fs",fs_request(op),fs_init(),400,"old-empty-open-"+str(op))
        assert value==BAD
        fs_controls.append("old-empty-open-"+str(op))
    out,w,event=fs_complete(fs_request(28),fs_init(),raw(28,-1,2))
    assert q(out,1)==0 and q(out,7)==2 and q(out,8)==q(out,9)==0
    fs_controls.append("new-empty-open-real-ENOENT-ACK")
    for pid in (1,2147483647):
        out,w,event=fs_complete(fs_request(26),fs_init(),raw(26,pid))
        assert q(out,1)==0 and q(out,7)==0 and q(out,8)==pid
        fs_controls.append("getpid-"+str(pid))
    for pid in (0,1<<31):
        out,w,event=fs_complete(fs_request(26),fs_init(),raw(26,pid),True)
        assert q(out,1)==BAD
        fs_controls.append("getpid-invalid-"+str(pid))
    for mode in (0,7):
        for error in (0,2):
            out,w,event=fs_complete(fs_request(27,b"db",mode),fs_init(),raw(27,-1 if error else 0,error))
            assert q(out,1)==0 and q(out,7)==error
            fs_controls.append("access-"+str(mode)+"-"+str(error))
    value,out,w=pair("fs",fs_request(28,b"a\0b"),fs_init(),400,"new-NUL-open")
    assert value==BAD
    fs_controls.append("new-NUL-open")
    assert len(fs_controls)==len(set(fs_controls))==16
    before=dict(pins)
    for p,v in before.items():pin(p,v["sha256"])
    report=dict(status="PASS",semantic_cases=len(results),semantic_results=results,protocol_controls=len(protocol),protocol_control_ids=protocol,
        direct_FS_controls=len(fs_controls),direct_FS_control_ids=fs_controls,
        entries_by_role=counts,VM_entries=sum(v["vm"] for v in counts.values()),
        native_entries=sum(v["native"] for v in counts.values()),
        actual_physical_syscalls=0,full_unixOpen_closed=False,ordinary_Store_closed=False,
        source_before_after_equal=pins==before,whole_buffers_and_canaries_equal=True,
        elapsed_ns=time.monotonic_ns()-started,limits=dict(cpu_seconds=90,wall_seconds=180,address_bytes=1<<30,VM_steps=4000000,VM_arena_bytes=32<<20),
        C_reference="Exact selected SQLite3.46.1 robust_open with controlled provider, no whole-SQLite claim")
    save("summary.json",report);save("source-after.json",pins)
    print(json.dumps(report,sort_keys=True))
except BaseException as error:
    report=dict(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc(),semantic_cases_completed=len(results),entries_by_role=counts)
    save("summary.json",report);raise
finally:
    signal.alarm(0);ledger.close();cases_file.close()
