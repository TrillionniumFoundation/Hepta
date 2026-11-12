"""Development mechanics for exact C/VM/native process PRNG comparison.

No PRNG algorithm, callback ordering or reset decision is implemented here.
The unchanged original C and new HIA choose those independently. Callback
records are labelled controlled peers, never namespace or OS authority.
"""
from __future__ import annotations
import ctypes,hashlib,json,os,stat,struct
from pathlib import Path
MASK=(1<<64)-1
BAD=(1<<32)-3
PR=int.from_bytes(b"HIANPR01","little")
EVENT=int.from_bytes(b"HIANPE01","little")
POISON=int.from_bytes(b"HIANPB01","little")
def q(data,at):return struct.unpack_from("<Q",data,at)[0]
def p(data,at,value):struct.pack_into("<Q",data,at,value&MASK)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):
    Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
class CAS:
    def __init__(self,path):
        self.path=Path(path);self.path.mkdir(parents=True,exist_ok=False)
    def put(self,raw):
        raw=bytes(raw);digest=sha(raw);path=self.path/digest
        if not path.exists():
            with path.open("xb") as stream:stream.write(raw)
        assert path.read_bytes()==raw
        return dict(bytes=len(raw),sha256=digest,path=str(path))
class Oracle:
    def __init__(self,path):
        self.library=ctypes.CDLL(str(Path(path).resolve()),mode=os.RTLD_NOW|os.RTLD_LOCAL)
        signatures={
          "reset":([],ctypes.c_int),
          "configure":([ctypes.c_uint32]*4+[ctypes.c_void_p,ctypes.c_uint64],ctypes.c_int),
          "call":([ctypes.c_uint32]*3+[ctypes.c_void_p,ctypes.c_uint64],ctypes.c_int),
          "events":([],ctypes.c_uint64),
          "event":([ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64],ctypes.c_int),
          "state":([ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint64],ctypes.c_int),
          "private_state":([ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint64],ctypes.c_int)}
        for name,(arguments,result) in signatures.items():
            fn=getattr(self.library,"hia_prng_oracle_"+name)
            fn.argtypes=arguments;fn.restype=result;setattr(self,name,fn)
        assert self.reset()==0
    def states(self):
        current=(ctypes.c_ubyte*132)();saved=(ctypes.c_ubyte*132)()
        assert self.state(current,saved,132)==0
        return bytes(current),bytes(saved)
    def replace_private_states(self,current,saved):
        a=(ctypes.c_ubyte*132).from_buffer_copy(current)
        b=(ctypes.c_ubyte*132).from_buffer_copy(saved)
        assert self.private_state(a,b,132)==0
    def perform(self,operation):
        config=operation["config"];seed=bytes.fromhex(config["seed_hex"]);assert len(seed)==44
        seed_buffer=(ctypes.c_ubyte*44).from_buffer_copy(seed)
        assert self.configure(config["init_bits"],config["vfs"],config["entropy_bits"],
                              config["prefix"],seed_buffer,44)==0
        n=operation["n_bits"];destination=operation["destination"]
        count=n if operation["api"]==1 and destination and n<1<<31 else 0
        initial=b"\xa5"*count
        output=(ctypes.c_ubyte*max(1,count))()
        if count:ctypes.memmove(output,initial,count)
        assert self.call(operation["api"],n,destination,output,count)==0
        records=[]
        for i in range(self.events()):
            raw=(ctypes.c_ubyte*384)();assert self.event(i,raw,384)==0
            records.append(bytes(raw))
        current,saved=self.states()
        return dict(output=bytes(output)[:count],initial=initial,current=current,saved=saved,events=records)

class Pair:
    def __init__(self,program,image,report,cas,ledger,frontier):
        from hepta.hia_program_runtime import _Machine,_Owner,_View
        self.Machine,self.Owner,self.View=_Machine,_Owner,_View
        self.program=program;self.image=image;self.report=report
        self.cas,self.ledger,self.frontier=cas,ledger,Path(frontier)
        self.libc=ctypes.CDLL(None,use_errno=True)
        self.libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
        self.libc.mmap.restype=ctypes.c_void_p
        self.libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];self.libc.mprotect.restype=ctypes.c_int
        self.libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];self.libc.munmap.restype=ctypes.c_int
    def log(self,row):
        self.ledger.write(json.dumps(row,sort_keys=True,separators=(",",":"))+"\n")
        self.ledger.flush()
    def call(self,label,s,o,w):
        s,o,w=bytes(s),bytes(o),bytes(w)
        number=self.report["VM_entries"]+1
        before=dict(kind="before",index=number,label=label,
                    input=self.cas.put(s),output=self.cas.put(o),workspace=self.cas.put(w))
        self.log(before);save(self.frontier,dict(stage="BEFORE_VM",entry=before))
        owners=[self.Owner(-1,bytearray(s)),self.Owner(-2,bytearray(o)),self.Owner(-3,bytearray(w))]
        machine=self.Machine(self.program,4000000,32<<20,None,64)
        expected_return=machine.invoke(machine.functions["f0"],[
            self.View(owners[0],False),self.View(owners[1],True),self.View(owners[2],True)])[0]
        expected=tuple(bytes(owner.data) for owner in owners)
        assert expected[0]==s
        self.report["VM_entries"]+=1
        save(self.frontier,dict(stage="BEFORE_NATIVE",index=number,label=label,
            VM_steps=machine.steps,returncode=expected_return,
            input=self.cas.put(expected[0]),output=self.cas.put(expected[1]),workspace=self.cas.put(expected[2])))
        allocations=[];primary=None;canary=bytes(range(160,176))
        try:
            for raw,readonly in ((s,True),(o,False),(w,False)):
                middle=(len(raw)+32+4095)&~4095;total=middle+8192
                base=self.libc.mmap(None,total,0,0x22,-1,0)
                if base==ctypes.c_void_p(-1).value:raise OSError(ctypes.get_errno(),"mmap")
                item=dict(raw=base,total=total,base=base+4096,address=base+4112,size=len(raw),middle=middle)
                allocations.append(item)
                if self.libc.mprotect(item["base"],middle,3):raise OSError(ctypes.get_errno(),"mprotect")
                ctypes.memmove(item["base"],canary,16)
                if raw:ctypes.memmove(item["address"],raw,len(raw))
                ctypes.memmove(item["address"]+len(raw),canary,16)
                if readonly and self.libc.mprotect(item["base"],middle,1):raise OSError(ctypes.get_errno(),"mprotect RO")
            a,b,c=allocations
            returned=int(self.image._entry(a["address"],a["size"],b["address"],b["size"],c["address"],c["size"]))
            self.report["native_entries"]+=1
            actual=tuple(ctypes.string_at(item["address"],item["size"]) for item in allocations)
            for item in allocations:
                assert ctypes.string_at(item["base"],16)==canary
                assert ctypes.string_at(item["address"]+item["size"],16)==canary
            equal=returned==expected_return and actual==expected
            self.log(dict(kind="after",index=number,label=label,returncode=returned,
                input=self.cas.put(actual[0]),output=self.cas.put(actual[1]),workspace=self.cas.put(actual[2]),
                expected_return=expected_return,VM_steps=machine.steps,VM_resources=machine.resources(),
                complete_equal=equal,canaries=True,input_readonly=True))
            assert equal,(label,number,"full return/input/output/workspace equality")
            return returned,actual[1],actual[2]
        except BaseException as error:
            primary=error;raise
        finally:
            errors=[]
            for item in reversed(allocations):
                try:
                    if self.libc.munmap(item["raw"],item["total"]):raise OSError(ctypes.get_errno(),"munmap")
                except BaseException as error:errors.append(error)
            if errors:
                if primary is not None:
                    for error in errors:primary.add_note("allocation cleanup: "+repr(error))
                else:raise errors[0]

def begin(call,operation):
    s=bytearray(256)
    for at,value in ((0,PR),(8,1),(16,733),(24,739),(32,call),
                     (40,operation["api"]),(48,operation["n_bits"]),(56,operation["destination"])):
        p(s,at,value)
    return bytes(s)
def acknowledge(event,record):
    op=q(event,48);payload=record[328:372] if op==4 else b""
    result=bytearray(512+len(payload))
    for at,value in ((0,PR),(8,2),(16,q(event,16)),(24,q(event,24)),
                     (32,q(event,32)),(40,q(event,40)),(48,op),(56,q(record,8)),
                     (64,len(payload)),(72,100+op),(80,200+op),(88,q(record,40))):
        p(result,at,value)
    result[256:512]=event[:256];result[512:]=payload
    return bytes(result)

class Session:
    def __init__(self,pair,oracle,snapshots):
        self.pair=pair;self.oracle=oracle;self.snapshots=snapshots
        self.workspace=bytes(4096);self.serial=0;assert oracle.reset()==0
    def run(self,name,operation):
        if "private_counter" in operation:
            current,saved=self.oracle.states()
            current=bytearray(current);struct.pack_into("<I",current,48,operation["private_counter"])
            current[128]=operation["private_n"]
            self.oracle.replace_private_states(current,saved)
            changed=bytearray(self.workspace);changed[512:644]=current
            self.workspace=bytes(changed)
        reference_before=self.oracle.states()
        save(self.pair.frontier,dict(stage="BEFORE_REFERENCE_C",name=name,operation=operation,
            current=self.pair.cas.put(reference_before[0]),saved=self.pair.cas.put(reference_before[1]),
            completed_original_C_calls=self.pair.report["original_C_calls"]))
        expected=self.oracle.perform(operation)
        self.pair.report["original_C_calls"]+=1
        self.pair.log(dict(kind="reference-C-completed",name=name,operation=operation,
            original_C_call=self.pair.report["original_C_calls"],
            before_current=self.pair.cas.put(reference_before[0]),before_saved=self.pair.cas.put(reference_before[1]),
            output=self.pair.cas.put(expected["output"]),current=self.pair.cas.put(expected["current"]),
            saved=self.pair.cas.put(expected["saved"]),
            callbacks=[self.pair.cas.put(record) for record in expected["events"]]))
        self.serial+=1;original=begin(self.serial,operation);source=original
        output=bytes(256)  # Resolve GROW before any HIA callback is issued.
        workspace=self.workspace;callback_index=0;calls=0
        counts=dict(grow=0,compute=0,pending=0)
        while True:
            before=dict(s=source,o=output,w=workspace)
            returned,output,workspace=self.pair.call(name+"/"+str(calls),source,output,workspace)
            calls+=1
            assert len(output)>=256 and q(output,0)==EVENT and q(output,8)==returned
            if returned==2:
                self.snapshots.setdefault("grow",dict(before=before,after=dict(s=source,o=output,w=workspace),original=original))
                counts["grow"]+=1
                assert q(output,40)==q(output,48)==q(output,72)==q(output,80)==0
                need=q(output,88)
                assert need==256+len(expected["output"]) and need>len(output)
                output=output+expected["initial"][len(output)-256:]
                source=original
                continue
            if returned==3:
                self.snapshots.setdefault("compute",dict(before=before,after=dict(s=source,o=output,w=workspace),original=original))
                counts["compute"]+=1
                assert q(output,48)==0 and q(output,80)==1
                source=bytearray(original);p(source,8,3);source=bytes(source)
                continue
            if returned==1:
                op=q(output,48);counts["pending"]+=1
                assert op in (1,2,3,4,5)
                assert callback_index<len(expected["events"])
                current=expected["events"][callback_index]
                sequence={1:10,2:20,3:30,4:40,5:50}
                assert q(current,0)==sequence[op],(name,op,callback_index,[q(x,0) for x in expected["events"]])
                assert output[120:252]==current[64:196]
                assert q(output,80)==q(current,24)
                if op==2:
                    assert q(current,16)==5
                    callback_index+=1;entered=expected["events"][callback_index]
                    assert q(entered,0)==21 and current[196:328]==entered[64:196]
                    assert entered[64:196]==entered[196:328] and q(entered,32)==1
                    # ALLOC and ENTER are one typed mutex-acquire dependency.
                    current=entered
                reply=acknowledge(output,current)
                self.snapshots.setdefault("pending-"+str(op),dict(before=before,
                    after=dict(s=reply,o=output,w=workspace),original=original))
                callback_index+=1;source=reply
                continue
            assert returned==0,(name,returned)
            assert callback_index==len(expected["events"])
            assert q(output,48)==0 and q(output,80)==0
            assert output[120:252]==expected["current"]
            assert workspace[512:644]==expected["current"] and workspace[768:900]==expected["saved"]
            assert output[256:]==expected["output"]
            self.workspace=workspace
            self.snapshots.setdefault("completed",dict(before=before,after=dict(s=original,o=output,w=workspace),original=original))
            row=dict(name=name,operation=operation,complete=True,
                source=self.pair.cas.put(original),output=self.pair.cas.put(output),
                workspace=self.pair.cas.put(workspace),reference_output=self.pair.cas.put(expected["output"]),
                reference_current=self.pair.cas.put(expected["current"]),reference_saved=self.pair.cas.put(expected["saved"]),
                reference_callbacks=[self.pair.cas.put(record) for record in expected["events"]],
                entry_count=calls,continuations=counts)
            self.pair.log(dict(kind="semantic",**row))
            return row
