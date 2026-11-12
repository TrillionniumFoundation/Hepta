"""Private fixture mechanics for fresh unixOpen-framer / actual shared-FS tests.

Only the frozen HIA framer selects a raw operation or constructs its request.
This fixture issues readonly observation descriptors from one owned actual
process trace. It is not the final installed native issuer and its headers are
not external authentication. Complete native windows are retained unchanged.
"""
from __future__ import annotations
import ctypes,hashlib,json,os,stat,struct
from pathlib import Path
MASK=(1<<64)-1
BAD=(1<<32)-3
LIMITS=dict(cpu_seconds=90,wall_seconds=180,address_bytes=1<<30,core_bytes=0,
            VM_steps=4000000,VM_arena_bytes=32<<20,VM_depth=64)
MAGICS={int.from_bytes(b"HIANFT03","little"):1,int.from_bytes(b"HIASMT01","little"):2,
 int.from_bytes(b"HIANMT01","little"):3,int.from_bytes(b"HIANDT03","little"):4,
 int.from_bytes(b"HIADBT01","little"):5,int.from_bytes(b"HIADJT01","little"):6}
def magic(s):return int.from_bytes(s,"little")
def sha(b):return hashlib.sha256(b).hexdigest()
def q(b,n):return struct.unpack_from("<Q",b,n)[0]
def p(b,n,v):struct.pack_into("<Q",b,n,v&MASK)
def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    path=Path(path).absolute();info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
    raw=path.read_bytes()
    return dict(path=str(path),bytes=len(raw),sha256=sha(raw),
        git=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest(),
        mode=stat.S_IMODE(info.st_mode))
class CAS:
    def __init__(self,path):
        self.path=Path(path);self.path.mkdir(parents=True,exist_ok=False)
    def put(self,raw):
        raw=bytes(raw);digest=sha(raw);path=self.path/digest
        if not path.exists():
            with path.open("xb") as stream:stream.write(raw)
        assert path.read_bytes()==raw
        return dict(bytes=len(raw),sha256=digest,path=str(path))
    def get(self,row):
        path=Path(row["path"]);assert path.parent==self.path
        assert path.name==row["sha256"]
        observed=pin(path)
        assert (observed["bytes"],observed["sha256"])==(row["bytes"],row["sha256"])
        return path.read_bytes()

class Pair:
    def __init__(self,program,image,report,cas,ledger,frontier):
        from hepta.hia_program_runtime import _Machine,_Owner,_View
        self.Machine,self.Owner,self.View=_Machine,_Owner,_View
        self.program=program
        self.entry=program.as_dict()["functions"][0]
        self.image=image;self.report=report;self.cas=cas;self.ledger=ledger;self.frontier=Path(frontier)
        self.libc=ctypes.CDLL(None,use_errno=True)
        self.libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
        self.libc.mmap.restype=ctypes.c_void_p
        self.libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];self.libc.mprotect.restype=ctypes.c_int
        self.libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];self.libc.munmap.restype=ctypes.c_int
    def record(self,row):
        self.ledger.write(json.dumps(row,sort_keys=True,separators=(",",":"))+"\n")
        self.ledger.flush()
    def call(self,label,s,r,w):
        s,r,w=bytes(s),bytes(r),bytes(w)
        number=self.report["framer_VM_entries"]+1
        before=dict(kind="before",index=number,label=label,input=self.cas.put(s),
                    peer=self.cas.put(r),workspace=self.cas.put(w))
        self.record(before)
        save(self.frontier,dict(index=number,label=label,stage="BEFORE_VM",before=before))
        owners=[self.Owner(-1,bytearray(s)),self.Owner(-2,bytearray(r)),self.Owner(-3,bytearray(w))]
        machine=self.Machine(self.program,4000000,32<<20,None,64)
        expected_return=machine.invoke(self.entry,[self.View(owners[0],False),
            self.View(owners[1],True),self.View(owners[2],True)])[0]
        assert bytes(owners[0].data)==s and bytes(owners[1].data)==r
        expected=(expected_return,bytes(owners[1].data),bytes(owners[2].data))
        self.report["framer_VM_entries"]+=1
        save(self.frontier,dict(index=number,label=label,stage="BEFORE_NATIVE",VM_steps=machine.steps,
            expected_return=expected_return,expected_peer=self.cas.put(expected[1]),
            expected_workspace=self.cas.put(expected[2])))
        allocations=[];primary=None;canary=bytes(range(16))
        try:
            for raw,readonly in ((s,True),(r,True),(w,False)):
                middle=(len(raw)+32+4095)&~4095;total=middle+8192
                address=self.libc.mmap(None,total,0,0x22,-1,0)
                if address==ctypes.c_void_p(-1).value:raise OSError(ctypes.get_errno(),"mmap")
                item=dict(raw=address,total=total,base=address+4096,address=address+4112,size=len(raw))
                allocations.append(item)
                if self.libc.mprotect(item["base"],middle,3):raise OSError(ctypes.get_errno(),"mprotect RW")
                ctypes.memmove(item["base"],canary,16)
                if raw:ctypes.memmove(item["address"],raw,len(raw))
                ctypes.memmove(item["address"]+len(raw),canary,16)
                if readonly and self.libc.mprotect(item["base"],middle,1):
                    raise OSError(ctypes.get_errno(),"mprotect RO")
            a,b,c=allocations
            returned=int(self.image._entry(a["address"],a["size"],b["address"],b["size"],c["address"],c["size"]))
            self.report["framer_native_entries"]+=1
            actual=tuple(ctypes.string_at(item["address"],item["size"]) for item in allocations)
            for item in allocations:
                assert ctypes.string_at(item["base"],16)==canary
                assert ctypes.string_at(item["address"]+item["size"],16)==canary
            assert actual[0]==s and actual[1]==r
            observed=(returned,actual[1],actual[2])
            self.record(dict(kind="after",index=number,label=label,returncode=returned,
                peer=self.cas.put(actual[1]),workspace=self.cas.put(actual[2]),VM_steps=machine.steps,
                complete_equal=observed==expected,input_unchanged=True,peer_unchanged=True,canaries=True))
            assert observed==expected,(label,number,"unmasked return/peer/full-workspace mismatch")
            return returned,actual[2]
        except BaseException as error:
            primary=error;raise
        finally:
            failures=[]
            for item in reversed(allocations):
                if self.libc.munmap(item["raw"],item["total"]):
                    failures.append(OSError(ctypes.get_errno(),"munmap"))
            if failures:
                if primary is not None:
                    for error in failures:primary.add_note("Pair cleanup: "+repr(error))
                else:
                    for error in failures[1:]:failures[0].add_note(repr(error))
                    raise failures[0]

def trace(path):
    """Decode complete already-returned records; never invent a tail."""
    path=Path(path);before=pin(path);raw=path.read_bytes();at=0;pending={};entries=[];primitives=[]
    def take(n):
        nonlocal at
        assert 0<=n<=len(raw)-at,("truncated actual trace",at,n,len(raw))
        result=raw[at:at+n];at+=n;return result
    while at<len(raw):
        offset=at;h=struct.unpack("<12Q",take(96))
        assert h[0] in MAGICS and h[10]==MAGICS[h[0]] and h[11]==0
        role=h[10];key=(role,h[8],h[9],h[2])
        assert h[9]>0 and h[2]>0
        if h[1]==1:
            assert key not in pending
            pending[key]=dict(header=list(h),offset=offset,input=take(h[3]),
                before_output=take(h[4]),before_workspace=take(h[5]))
        elif h[1]==2:
            assert key in pending
            row=pending.pop(key);row.update(after_header=list(h),after_offset=offset,
                returncode=h[6],output=take(h[4]),workspace=take(h[5]))
            assert len(row["before_output"])==h[4] and len(row["before_workspace"])==h[5]
            entries.append(row)
        elif h[1]==3:
            assert role in (1,3)
            primitives.append(dict(header=list(h),offset=offset,ack=take(h[3])))
        else:
            raise AssertionError(("actual fatal/unknown trace",offset,list(h)))
    assert not pending and at==len(raw) and pin(path)==before
    return dict(pin=before,entries=entries,primitives=primitives)

class FixtureIssuer:
    """Test-only private issuer bound to one owned live actual process/context.

    This class carries bytes/identity; it does not choose FS opcodes, repair HIA
    requests, fabricate successful syscalls, or create an installed Store lease.
    """
    def __init__(self,carrier,cas):
        self.carrier=carrier;self.cas=cas;self.context=9001;self.process=9002
        self.observation=0;self.binding=None
        self.observe()
    def observe(self):
        c=self.carrier;c.owned_native_pid()
        decoded=trace(c.output/"trace.bin")
        rows=[row for row in decoded["entries"] if row["after_header"][10]==6]
        assert rows
        row=rows[-1];h=row["after_header"]
        assert row["returncode"]==0 and q(row["workspace"],0)==magic(b"HIANDJ01")
        assert q(row["workspace"],8)==1 and h[8]==0 and h[9]>0
        identity=dict(actual_process=c.native_identity,role=6,node=h[8],generation=h[9],
            private_context_handle=self.context,private_process_lease=self.process)
        if self.binding is None:self.binding=identity
        else:assert identity==self.binding
        self.observation+=1
        return decoded,row
    def descriptor(self,row,*,kind,request=b"",output=b""):
        h=row["after_header"]
        fields=[magic(b"HIAUFP01"),kind,len(request),len(output),len(row["workspace"]),
            self.context,h[9],row["returncode"],10000+self.observation,h[2],self.process]+[0]*5
        return struct.pack("<16Q",*fields)+request+output+row["workspace"]
    def before(self):
        decoded,row=self.observe()
        return self.descriptor(row,kind=1),row,decoded
    def execute(self,packet):
        c=self.carrier
        assert len(packet)>=640 and q(packet,0)==magic(b"HIANDJX1")
        expected=bytearray(128)
        for at,value in ((0,magic(b"HIANDJX1")),(8,1),(32,len(packet)-128),(88,4096)):p(expected,at,value)
        assert packet[:128]==bytes(expected)
        assert q(packet,160)==c.call_number+1
        c.call_number+=1
        before_count=len(c.requests)
        header,payload=c.request(packet[128:],label="native-framer-issued-request")
        assert header[1]==0 and len(c.requests)==before_count+1
        decoded,row=self.observe()
        roots=[entry for entry in decoded["entries"] if entry["after_header"][10]==6]
        exact=[entry for entry in roots if entry["input"]==packet]
        assert exact and q(row["workspace"],32)==q(packet,160)
        assert exact[-1]["after_header"][2]<=row["after_header"][2]
        # The output returned on the pipe must be the same complete logical
        # extent from the actual final HIA role-6 entry, not reconstructed fields.
        logical=struct.pack("<32Q",*header)+payload
        assert logical==row["output"][:256+q(row["output"],128)]
        assert len(logical)==256+q(row["output"],128)
        assert q(logical,32)==q(packet,160)
        return self.descriptor(row,kind=2,request=packet,output=logical),row,decoded

def pending_source(row,issuer,op,stage,*,path=b"",token=0,handle=0,uid=0,gid=0,
                   call=1,action=1,lease=3001,framer_call=1,old_errno=28):
    """Explicit private pending fixture. No claim that a parent image issued it."""
    path=bytes(path);assert b"\0" not in path
    w=row["workspace"];n=len(path);result=bytearray(640+n)
    values={0:magic(b"HIAUFS01"),8:1,16:701,24:709,32:framer_call,40:512+n,
        48:lease,56:issuer.context,128:magic(b"HIANUO01"),136:1,
        144:101,152:103,160:call,168:action,176:op,184:stage,200:old_errno,
        208:token,256:256+n,288:handle,376:lease,
        384:magic(b"HIANUQ01"),392:1,400:101,408:103,416:call,424:action,
        432:op,440:stage,448:token if op in (10,14,15) else 0,
        456:uid if op==10 else 0,464:gid if op==10 else 0,
        496:n,504:(1 if op in (8,11) else 4 if op==16 else 0),512:lease,
        520:q(w,80),528:q(w,88),536:q(w,216),544:q(w,224),
        552:6,560:issuer.process,568:old_errno}
    for at,value in values.items():p(result,at,value)
    result[640:]=path
    return bytes(result)

def expected_parent_ack(s,r):
    """Independent original ABI projection; uses actual returned full FS bytes."""
    request_bytes=q(r,16);output_bytes=q(r,24)
    out=128+request_bytes;fs=out+256
    assert output_bytes>=512
    error=q(r,fs+56);op=q(s,176)
    ack=bytearray(512)
    values={0:magic(b"HIANUO01"),8:2,64:error if error else q(s,200),
        72:q(r,fs+64) if op in (1,9) else error,120:q(r,fs+32),
        128:q(r,fs+40),144:6,152:q(r,40),160:q(r,48),168:q(r,72),176:q(s,48)}
    if not error and op in (15,16):
        values[80]=q(r,fs+72);values[88]=q(r,fs+192)
    for at,value in values.items():p(ack,at,value)
    ack[16:64]=s[144:192];ack[256:512]=s[384:640]
    return bytes(ack)
