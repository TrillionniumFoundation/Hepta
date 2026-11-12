"""Full native Code state/bytes differential; Python is an independent oracle."""
from pathlib import Path
from hashlib import sha256
import argparse,ast,base64,copy,ctypes,gc,importlib.util,itertools,json,os,random,resource,stat,struct,sys,time,traceback,unittest,zlib
sys.dont_write_bytecode=True
GRAPH=int.from_bytes(b"HIAXGR01","little")
OUTPUT_GRAPH=int.from_bytes(b"HIAGRF01","little")
COMMAND=int.from_bytes(b"HIAXCC01","little")
EVENT=int.from_bytes(b"HIAXCE01","little")
FINAL_EVENT=int.from_bytes(b"HIAXFE01","little")
BAD=0xfffffffd
GROW=0xfffffffe
MAX_CODE=64<<20
CANARY=bytes(range(160,176))
OWNER_SHA="92070ffcb9e12bce1825c3f3361a97aadc8279f1041c4d2ed16dfadf350ec55a"
REFERENCE_SHA="8795fb4e5034673401f5f6a5a60e57872c48a3982dbdcb4d3b8198ee7b3f41a9"
EXECUTION_SHA="1ba1a51995c38ae93e5ce1a748a0b2bf3d2d6a19c0c48dfb9043c1ef639e094f"
OPERATIONS=("init","align","offset","emit","label","jmp","jcc","call",
 "mov_rr","mov_imm","load","store","lea","load_u8","store_u8",
 "add","sub","and_","or_","xor","cmp","test","alu_imm","shift","shift_imm",
 "shift_cl","shl","shr","sar","imul","imul_rr","mul","imul_full","div","idiv",
 "neg","bitnot","cqo","setcc","cmov","push","pop","ret","leave","ud2","finalize")
OPIDS={name:i for i,name in enumerate(OPERATIONS)}
REGS=("rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15")
CONDITIONS=("o","no","b","c","nae","ae","nb","nc","e","z","ne","nz","be","na","a","nbe","s","ns","p","pe","np","po","l","nge","ge","nl","le","ng","g","nle")
class InheritedStr(str):pass
class IntSubclass(int):pass
class DictSubclass(dict):pass
class BytesSubclass(bytes):pass
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def q(raw,at):return struct.unpack_from("<Q",raw,at)[0]
def replace_q(raw,at,value):
    result=bytearray(raw);struct.pack_into("<Q",result,at,value);return bytes(result)

def capture(root,lease):
    objects=[];ids={}
    def add(value):
        key=id(value)
        if key not in ids:
            ids[key]=len(objects)+1
            objects.append(value)
        return ids[key]
    rootid=add(root)
    records=[];edges=[];pool=bytearray()
    position=0
    while position<len(objects):
        value=objects[position];kind=type(value)
        record=[0]*8
        raw=None
        if value is None:
            record[0]=0
        elif kind is bool:
            record[0]=1;record[6]=int(value)
        elif kind is int:
            record[0]=2;record[6]=int(value<0)
            magnitude=abs(value);raw=magnitude.to_bytes((magnitude.bit_length()+7)//8,'little')
        elif kind is float:
            record[0]=3;raw=struct.pack('<d',value)
        elif kind is str:
            record[0]=4;record[6]=len(value);raw=value.encode('utf-8','surrogatepass')
        elif kind in (list,dict,tuple):
            record[0]={list:5,dict:6,tuple:7}[kind]
            record[3]=len(edges);record[4]=len(value);record[5]=position+1
            if kind is dict:
                items=list(value.items())
                for key,child in items:
                    edges.extend((add(key),add(child)))
            else:
                for child in tuple(value):
                    edges.append(add(child))
        elif kind is bytes:
            record[0]=9;raw=value
        elif kind is bytearray:
            record[0]=10;raw=bytes(value)
        elif kind is InheritedStr:
            record[0]=11;record[6]=str.__len__(value);raw=str.encode(value,"utf-8","surrogatepass")
        else:
            record[0]=8
        if raw is not None:
            record[1]=len(pool);record[2]=len(raw);pool.extend(raw)
        records.append(record);position+=1
    data=64+len(records)*64+len(edges)*8
    for record in records:
        if record[0] in (2,3,4,9,10,11):
            record[1]+=data
    header=(GRAPH,lease,len(records),rootid,len(edges),len(pool),data+len(pool),0)
    return (struct.pack('<8Q',*header)+b''.join(struct.pack('<8Q',*row) for row in records)
            +b''.join(struct.pack('<Q',value) for value in edges)+bytes(pool))


class Evidence:
    """Every byte is read after each actual entry. Only immutable pages are deduplicated."""
    def __init__(self,root):
        self.root=root;self.directory=root/"cas";self.directory.mkdir()
        self.pins={};self.pages={};self.previous={};self.snapshot_id=0;self.logical=0
        self.snapshots=(root/"snapshots.jsonl").open("w")
        self.entries=(root/"entries.jsonl").open("w")
        self.cases=(root/"cases.jsonl").open("w")
    def page(self,raw):
        h=digest(raw)
        if h not in self.pages:
            path=self.directory/(h+".zlib")
            path.write_bytes(zlib.compress(raw,6))
            assert zlib.decompress(path.read_bytes())==raw
            self.pages[h]=len(raw)
        else:assert self.pages[h]==len(raw)
        return h
    def raw(self,raw):
        return dict(bytes=len(raw),sha256=digest(raw),page_size=4096,
            pages=[self.page(raw[i:i+4096]) for i in range(0,len(raw),4096)])
    def memory(self,buffer,key):
        pages=[];h=sha256();size=buffer["size"];address=buffer["address"]
        for at in range(0,size,4096):
            raw=ctypes.string_at(address+at,min(4096,size-at));h.update(raw);pages.append(self.page(raw))
        old=self.previous.get(key);identifier=self.snapshot_id;self.snapshot_id+=1
        base=None if old is None else old[0]
        original=[] if old is None else old[1]
        changed=[[i,p] for i,p in enumerate(pages) if i>=len(original) or original[i]!=p]
        reconstructed=list(original[:len(pages)])+[None]*max(0,len(pages)-len(original))
        for i,p in changed:reconstructed[i]=p
        assert reconstructed==pages
        descriptor=dict(id=identifier,key=key,bytes=size,sha256=h.hexdigest(),page_size=4096,
            page_count=len(pages),base=base,changed=changed)
        self.snapshots.write(json.dumps(descriptor,sort_keys=True)+"\n");self.snapshots.flush()
        self.previous[key]=(identifier,pages);self.logical+=size
        return {k:descriptor[k] for k in("id","key","bytes","sha256")}
    def entry(self,record):
        self.entries.write(json.dumps(record,sort_keys=True,ensure_ascii=True)+"\n");self.entries.flush()
    def case(self,record):
        self.cases.write(json.dumps(record,sort_keys=True,ensure_ascii=True)+"\n");self.cases.flush()
    def pin(self,path,expected=None):
        path=Path(path).absolute();info=path.lstat()
        assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
        path=path.resolve();raw=path.read_bytes()
        if expected is not None:assert digest(raw)==expected,(str(path),digest(raw),expected)
        if path in self.pins:assert self.pins[path]==raw
        else:
            self.pins[path]=raw;target=self.root/"sources"/str(len(self.pins))/path.name
            target.parent.mkdir(parents=True);target.write_bytes(raw);target.chmod(stat.S_IMODE(info.st_mode))
        return raw
    def finish(self):
        changed=[str(path) for path,raw in self.pins.items() if path.read_bytes()!=raw]
        for stream in(self.entries,self.snapshots,self.cases):stream.flush();stream.close()
        for h,size in self.pages.items():
            raw=zlib.decompress((self.directory/(h+".zlib")).read_bytes())
            assert len(raw)==size and digest(raw)==h
        value=dict(status="PASS" if not changed else "FAIL",source_pins_unchanged=not changed,
            changed=changed,pins=[dict(path=str(p),bytes=len(v),sha256=digest(v)) for p,v in self.pins.items()],
            cas_pages=len(self.pages),cas_raw_bytes=sum(self.pages.values()),logical_buffer_bytes=self.logical,
            complete_snapshot_descriptors=self.snapshot_id,
            all_new_pages_decompressed_equal=True,all_final_pages_rehashed=True,
            full_memory_read_before_after_each_entry=True,delta_pages_reconstruct_identically=True)
        save(self.root/"source-after.json",value);assert not changed;return value

class Buffers:
    def __init__(self):
        self.libc=ctypes.CDLL(None,use_errno=True)
        self.libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
        self.libc.mmap.restype=ctypes.c_void_p
        self.libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]
        self.libc.mprotect.restype=ctypes.c_int
        self.libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
        self.libc.munmap.restype=ctypes.c_int
    def allocate(self,size,initial=b"",readonly=False):
        assert 0<=len(initial)<=size
        middle=(size+32+4095)&~4095;total=middle+8192
        raw=self.libc.mmap(None,total,0,0x22,-1,0)
        if raw==ctypes.c_void_p(-1).value:raise OSError(ctypes.get_errno(),"mmap")
        address=raw+4112
        try:
            if self.libc.mprotect(raw+4096,middle,3):raise OSError(ctypes.get_errno(),"mprotect RW")
            ctypes.memmove(address-16,CANARY,16);ctypes.memmove(address+size,CANARY,16)
            if initial:ctypes.memmove(address,initial,len(initial))
            if readonly and self.libc.mprotect(raw+4096,middle,1):raise OSError(ctypes.get_errno(),"mprotect RO")
            return dict(mapping=raw,total=total,address=address,size=size,middle=middle,readonly=readonly)
        except BaseException:
            self.libc.munmap(raw,total);raise
    def check(self,buffer):
        assert ctypes.string_at(buffer["address"]-16,16)==CANARY
        assert ctypes.string_at(buffer["address"]+buffer["size"],16)==CANARY
    def close(self,buffer):
        if buffer is not None and buffer["mapping"] is not None:
            raw=buffer["mapping"];buffer["mapping"]=None
            if self.libc.munmap(raw,buffer["total"]):raise OSError(ctypes.get_errno(),"munmap")


def protect(buffers,buffer,readonly):
    permission=1 if readonly else 3
    if buffers.libc.mprotect(buffer["mapping"]+4096,buffer["middle"],permission):
        raise OSError(ctypes.get_errno(),"mprotect")
    buffer["readonly"]=readonly

def graph_value(raw):
    assert len(raw)>=64 and q(raw,0)==OUTPUT_GRAPH and q(raw,56)==0
    n=q(raw,16);edge_count=q(raw,32);pool=64+n*64+edge_count*8
    assert n>0 and pool<=len(raw) and q(raw,40)==len(raw)-pool and q(raw,48)==len(raw)
    values={};active=set()
    def item(identifier):
        assert 1<=identifier<=n
        if identifier in values:return values[identifier]
        assert identifier not in active;active.add(identifier)
        at=64+(identifier-1)*64;kind,begin,size,first,count,identity,aux,res=struct.unpack_from("<8Q",raw,at)
        assert res==0
        if kind in(5,6):
            arity=count*(2 if kind==6 else 1)
            assert begin==size==aux==0 and identity!=0 and first<=edge_count and arity<=edge_count-first
            ids=[q(raw,64+n*64+(first+i)*8) for i in range(arity)]
            if kind==5:value=[item(i) for i in ids]
            else:
                value={}
                for i in range(0,len(ids),2):
                    key=item(ids[i]);assert type(key)is str and key not in value
                    value[key]=item(ids[i+1])
        else:
            assert first==count==identity==0 and pool<=begin<=len(raw) and size<=len(raw)-begin
            data=raw[begin:begin+size]
            if kind==9:assert aux==0;value=data
            elif kind==4:
                value=data.decode("utf-8","surrogatepass");assert len(value)==aux
            elif kind==2:
                assert aux in(0,1) and (not data or data[-1]) and (data or aux==0)
                value=int.from_bytes(data,"little")*(-1 if aux else 1)
            else:raise AssertionError(("unexpected final Graph kind",kind))
        active.remove(identifier);values[identifier]=value;return value
    result=item(q(raw,24))
    for identifier in range(1,n+1):item(identifier)
    return result

class Actual:
    def __init__(self,bundle,reference,root,out):
        self.out=out;self.evidence=Evidence(out);self.buffers=Buffers();self.calls=0
        self.counts={"encoder":0,"finalizer":0};self.results=[];self.errors=set();self.operations=set();self.sessions=0
        self.private_controls=0;self.closed=False
        self.evidence.pin(root/"tools/hia_machine_x64_encoder.py",OWNER_SHA)
        self.evidence.pin(__file__)
        oracle_raw=self.evidence.pin(root/"reference/hia_machine_x64.py",REFERENCE_SHA)
        self.oracle=type(sys)("machine_x64_oracle");self.oracle.__file__=str(root/"reference/hia_machine_x64.py")
        exec(compile(oracle_raw,self.oracle.__file__,"exec"),self.oracle.__dict__)
        self.evidence.pin(root/"reference/test_hia_machine_x64.py",EXECUTION_SHA)
        data=json.loads(self.evidence.pin(bundle))
        assert data["schema"]=="hepta.hia.machine-x64-bundle.v1" and data["author_sha256"]==OWNER_SHA and data["reference_sha256"]==REFERENCE_SHA
        assert set(data["components"])=={"encoder","finalizer"}
        images={}
        for component,manifest in data["components"].items():
            assert manifest["schema"]=="hepta.hia.machine-x64-development.v1" and manifest["status"]=="BUILT_ONLY"
            assert manifest["component"]==component and manifest["author_sha256"]==OWNER_SHA and manifest["reference_sha256"]==REFERENCE_SHA
            source=self.evidence.pin(manifest["source_path"],manifest["source_sha256"])
            image=self.evidence.pin(manifest["image_path"],manifest["image_sha256"])
            assert len(source)==manifest["source_bytes"] and len(image)==manifest["image_bytes"]
            receipt=manifest["compile_receipt"]
            assert receipt["source_sha256"]==receipt["input_sha256"]==digest(source)
            assert receipt["produced_sha256"]==digest(image)
            assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
            images[component]=(image,manifest["image_sha256"])
        sys.path.insert(0,str(reference))
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        self.images={}
        try:
            for component,(image,h) in images.items():self.images[component]=NativeHiaJsonImage(image,expected_sha256=h)
        except BaseException:
            for image in self.images.values():image._mapping.close()
            raise
    def entry(self,component,label,buffers,keys):
        number=self.calls;self.calls+=1;self.counts[component]+=1
        before=[self.evidence.memory(b,k) for b,k in zip(buffers,keys)]
        record=dict(number=number,component=component,label=label,status="ENTERING",
            capacities=[b["size"] for b in buffers],addresses=[b["address"] for b in buffers],
            readonly=[b["readonly"] for b in buffers],before=before)
        self.evidence.entry(record)
        start=time.monotonic_ns()
        a,b,w=buffers
        ret=int(self.images[component]._entry(a["address"],a["size"],b["address"],b["size"],w["address"],w["size"]))
        elapsed=time.monotonic_ns()-start
        for item in buffers:self.buffers.check(item)
        after=[self.evidence.memory(b,k) for b,k in zip(buffers,keys)]
        for i,item in enumerate(buffers):
            if item["readonly"]:assert before[i]["sha256"]==after[i]["sha256"],("read lease changed",i)
        event=struct.unpack("<16Q",ctypes.string_at(w["address"],128)) if w["size"]>=128 else None
        record.update(status="RETURNED",returned=ret,event=event,after=after,elapsed_ns=elapsed,canaries_intact=True)
        self.evidence.entry(record)
        return ret,event
    def record_case(self,label,value):
        self.results.append(dict(label=label,**value));self.evidence.case(self.results[-1])
    def close(self):
        if self.closed:return None
        self.closed=True
        for image in self.images.values():image._mapping.close()
        return self.evidence.finish()

class Session:
    def __init__(self,actual,lease=None):
        self.actual=actual;actual.sessions+=1;self.number=actual.sessions
        self.lease=lease or self.number+100;self.seq=0;self.closed=False
        self.code=actual.buffers.allocate(0);self.work=actual.buffers.allocate(4096)
        self.prefix="session-"+str(self.number)
    def replace(self,name,size):
        old=getattr(self,name);new=self.actual.buffers.allocate(size)
        try:
            if old["size"]:ctypes.memmove(new["address"],old["address"],old["size"])
            self.actual.buffers.check(old);self.actual.buffers.check(new)
        except BaseException:self.actual.buffers.close(new);raise
        self.actual.buffers.close(old);setattr(self,name,new)
    def raw(self,name):
        value=getattr(self,name);return ctypes.string_at(value["address"],value["size"])
    def command_bytes(self,op,args):
        raw=capture(list(args),self.lease)
        return struct.pack("<8Q",COMMAND,1,self.lease,self.seq+1,op,len(raw),q(raw,24),0)+raw
    def command(self,op,args,label):
        raw=self.command_bytes(op,args);source=self.actual.buffers.allocate(len(raw),raw,True)
        self.actual.operations.add(op)
        try:
            for attempt in range(8):
                oldcode=self.raw("code")
                oldwork=self.raw("work")
                ret,event=self.actual.entry("encoder",label,(source,self.code,self.work),
                    (self.prefix+"-input-"+str(self.seq+1),self.prefix+"-code",self.prefix+"-work"))
                assert event[:2]==(EVENT,1) and event[3:6]==(self.lease,self.seq+1,op),(label,event)
                if event[2]==1:
                    assert ret==GROW and event[6]==0 and event[15]==0
                    now=self.raw("work")
                    assert self.raw("code")==oldcode and now[128:288]==oldwork[128:288] and now[4096:]==oldwork[4096:]
                    assert event[7]>self.code["size"] or event[8]>self.work["size"]
                    for name,needed in(("code",event[7]),("work",event[8])):
                        old=getattr(self,name)["size"]
                        if needed>old:self.replace(name,max(needed,4096,old*2))
                    continue
                assert ret==128 and event[2] in(0,2,4) and event[15]==0,(label,ret,event)
                self.seq+=1
                if event[2]==2:
                    assert 1<=event[6]<=16
                    assert event[13]<=self.work["size"] and event[14]<=self.work["size"]-event[13]
                    message=ctypes.string_at(self.work["address"]+event[13],event[14]).decode("utf-8","surrogatepass")
                    self.actual.errors.add(event[6]);return dict(error=message,error_id=event[6],value=None,event=event)
                assert event[6]==0 and event[13:15]==(0,0)
                if op==45:assert event[2]==4
                else:assert event[2]==0
                return dict(error=None,value=event[9] if op==2 else None,event=event)
            raise AssertionError(("excessive GROW in finite fixture",label))
        finally:self.actual.buffers.close(source)
    def finalize(self,label):
        event=self.command(45,(),label+"-prepare")
        assert event["error"] is None
        output=self.actual.buffers.allocate(4096)
        protect(self.actual.buffers,self.code,True);protect(self.actual.buffers,self.work,True)
        try:
            for attempt in range(4):
                ret,words=self.actual.entry("finalizer",label,(self.code,self.work,output),
                    (self.prefix+"-code",self.prefix+"-work",self.prefix+"-final"))
                assert words[:2]==(FINAL_EVENT,1) and words[3:5]==(self.lease,self.seq) and words[14:]==(0,0)
                if words[2]==1:
                    assert ret==GROW and words[5]==0 and words[6]>output["size"]
                    self.actual.buffers.close(output);output=self.actual.buffers.allocate(words[6]);continue
                assert ret==128 and words[2] in(0,2),(ret,words)
                if words[2]==2:
                    assert words[5]==17
                    at,size=words[12:14];assert at<=output["size"] and size<=output["size"]-at
                    message=ctypes.string_at(output["address"]+at,size).decode("utf-8","surrogatepass")
                    self.actual.errors.add(17);return dict(error=message,error_id=17,value=None,event=words)
                at,size=words[7:9];assert at==4096 and size<=output["size"]-at
                graph=ctypes.string_at(output["address"]+at,size)
                value=graph_value(graph);assert type(value)is list and len(value)==2
                assert type(value[0])is bytes and type(value[1])is list
                return dict(error=None,value=(value[0],value[1]),event=words)
            raise AssertionError("finalizer GROW did not terminate")
        finally:
            protect(self.actual.buffers,self.code,False);protect(self.actual.buffers,self.work,False)
            self.actual.buffers.close(output)
    def compare_state(self,oracle):
        meta=self.raw("work");code=self.code
        n=q(meta,176);assert n==len(oracle.data)
        for at in range(0,n,4096):
            assert ctypes.string_at(code["address"]+64+at,min(4096,n-at))==oracle.data[at:at+4096]
        def name(pointer):
            assert 4096<=pointer<=len(meta)-80
            at,size=q(meta,pointer),q(meta,pointer+8)
            assert at==pointer+80 and size<=len(meta)-at
            return meta[at:at+size].decode("utf-8","surrogatepass")
        labels={};pending=[q(meta,184)];seen=set()
        while pending:
            p=pending.pop()
            if not p:continue
            assert p not in seen;seen.add(p)
            key=name(p)
            if q(meta,p+32):labels[key]=q(meta,p+24)
            pending.extend((q(meta,p+40),q(meta,p+48)))
        assert len(seen)==q(meta,192) and labels==oracle.labels
        fix=[];p=q(meta,208)
        while p:
            assert len(fix)<q(meta,224)
            fix.append((q(meta,p+8),name(q(meta,p+16))));p=q(meta,p)
        rel=[];p=q(meta,232)
        while p:
            assert len(rel)<q(meta,248)
            rel.append(dict(offset=q(meta,p+8),symbol=name(q(meta,p+16)),type=4,addend=-4));p=q(meta,p)
        assert fix==oracle.fixups and rel==oracle.relocations
        return dict(code_bytes=n,code_sha256=digest(oracle.data),labels=len(labels),fixups=len(fix),relocations=len(rel),
            all_code_bytes_equal=True,all_registry_values_equal=True)
    def close(self):
        if self.closed:return
        self.closed=True;original=None
        for name in("work","code"):
            try:self.actual.buffers.close(getattr(self,name))
            except BaseException as error:
                if original is None:original=error
                else:original.add_note(repr(error))
        if original is not None:raise original


class Pair:
    def __init__(self,actual,label,scratch=None,move="movabs",alu="imm32"):
        self.actual=actual;self.label=label;self.session=Session(actual);self.index=0
        self.oracle=actual.oracle.Code(scratch_registers=scratch,move_immediate=move,alu_immediate=alu)
        answer=self.session.command(0,(scratch,move,alu),label+"-init")
        assert answer["error"] is None
        self.session.compare_state(self.oracle)
    def step(self,name,*args):
        self.index+=1;label=self.label+"-"+str(self.index)+"-"+name
        expected=None;error=None
        try:
            if name=="offset":expected=self.oracle.offset
            else:expected=getattr(self.oracle,name)(*args)
        except self.actual.oracle.MachineEncodingError as exc:error=str(exc)
        if name=="finalize":actual=self.session.finalize(label)
        else:
            effective=args
            if name in("load","lea","load_u8") and len(args)==2:effective=args+(0,)
            actual=self.session.command(OPIDS[name],effective,label)
        assert actual["error"]==error,(label,error,actual)
        if error is None:assert actual["value"]==expected,(label,actual["value"],expected)
        state=self.session.compare_state(self.oracle)
        self.actual.record_case(label,dict(status="PASS",operation=name,error=error,
            error_id=actual.get("error_id",0),state=state,
            finalized_bytes=None if name!="finalize" or error is not None else len(expected[0]),
            finalized_sha256=None if name!="finalize" or error is not None else digest(expected[0])))
        return actual
    def close(self):self.session.close()

def constructor_cases(actual):
    good=[None,{"r10":"r10","r11":"r11"},{"r10":"r11","r11":"r10"},
          {InheritedStr("r11"):"r10",InheritedStr("r10"):"r11"}]
    bad=[False,True,0,[],(),"r10",{},{"r10":"r10"},{"r10":"r10","r11":"r10"},
         {"r10":"r10","r12":"r11"},{"r10":InheritedStr("r10"),"r11":"r11"},
         {"r10":None,"r11":[]},DictSubclass(r10="r10",r11="r11")]
    modes=[("movabs","imm32"),("mov32_if_exact","imm32"),("movabs","imm8_if_exact"),
           ("mov32_if_exact","imm8_if_exact")]
    cases=[(m,move,alu) for m in good for move,alu in modes]
    cases += [(m,move,alu) for m in bad for move,alu in (("bad","bad"),("movabs","imm32"))]
    cases += [(None,m,a) for m in ("bad",None,True,InheritedStr("movabs")) for a in("bad","imm32")]
    cases += [(None,"movabs",a) for a in("bad",None,True,InheritedStr("imm32"))]
    for index,(mapping,move,alu) in enumerate(cases):
        label="constructor-"+str(index);session=Session(actual);expected=None
        try:
            try:oracle=actual.oracle.Code(scratch_registers=mapping,move_immediate=move,alu_immediate=alu)
            except actual.oracle.MachineEncodingError as error:expected=str(error)
            result=session.command(0,(mapping,move,alu),label)
            assert result["error"]==expected,(label,expected,result)
            if expected is None:
                session.compare_state(oracle)
                session.command(OPIDS["mov_imm"],("r10",1),label+"-mapping")
                oracle.mov_imm("r10",1);session.compare_state(oracle)
                assert session.command(3,(bytearray(b"\x00\xff"),),label+"-bytearray")["error"] is None
                oracle.emit(bytearray(b"\x00\xff"));session.compare_state(oracle)
            else:
                corrected=session.command_bytes(2,())
                source=actual.buffers.allocate(len(corrected),corrected,True)
                try:
                    ret,event=actual.entry("encoder",label+"-retired",(source,session.code,session.work),
                        (session.prefix+"-retired-input",session.prefix+"-code",session.prefix+"-work"))
                    assert ret==BAD and event[2]==3
                    actual.private_controls+=1
                finally:actual.buffers.close(source)
            actual.record_case(label,dict(status="PASS",operation="init",error=expected,
                error_id=result.get("error_id",0),rejected_constructor_cannot_reuse=expected is not None))
        finally:session.close()

def register_cases(actual):
    for swap in(False,True):
        pair=Pair(actual,"registers-"+str(swap),{"r10":"r11","r11":"r10"} if swap else None)
        try:
            for op in("mov_rr","add","sub","and_","or_","xor","cmp","test","imul","imul_rr"):
                for dst in REGS:
                    for src in REGS:pair.step(op,dst,src)
            for op in("mul","imul_full","div","idiv","neg","bitnot","push","pop"):
                for reg in REGS:pair.step(op,reg)
            for op in("cqo","ret","leave","ud2","offset","finalize"):pair.step(op)
        finally:pair.close()

def memory_cases(actual):
    pair=Pair(actual,"memory")
    try:
        for op in("load","store","lea","load_u8","store_u8"):
            for reg in REGS:
                for base in REGS:
                    for disp in(-(1<<31),-129,0,127,(1<<31)-1):
                        if op in("store","store_u8"):pair.step(op,base,disp,reg)
                        else:pair.step(op,reg,base,disp)
        for op in("load","lea","load_u8"):pair.step(op,"r15","r12")
        pair.step("finalize")
    finally:pair.close()

def immediate_cases(actual):
    for move,alu in itertools.product(("movabs","mov32_if_exact"),("imm32","imm8_if_exact")):
        pair=Pair(actual,move+"-"+alu,move=move,alu=alu)
        try:
            for reg in REGS:
                for value in(-(1<<63),-(1<<31),-129,-128,-1,0,1,127,128,(1<<32)-1,1<<32,(1<<63)-1,1<<63,(1<<64)-1):
                    pair.step("mov_imm",reg,value)
                for op in("add","or","and","sub","xor","cmp"):
                    for value in(-(1<<31),-129,-128,-1,0,1,127,128,(1<<31)-1):
                        pair.step("alu_imm",op,reg,value)
                for op in("shl","shr","sar"):
                    for count in(0,1,31,63,"cl",InheritedStr("cl")):
                        pair.step("shift",op,reg,count)
                        pair.step("shift_imm",op,reg,count)
                        pair.step(op,reg,count)
                    pair.step("shift_cl",op,reg)
            pair.step("finalize")
        finally:pair.close()

def condition_cases(actual):
    for mode in("movabs","mov32_if_exact"):
        pair=Pair(actual,"conditions-"+mode,move=mode)
        try:
            pair.step("label","head")
            for condition in CONDITIONS:
                pair.step("jcc",condition,"head")
                for reg in REGS:pair.step("setcc",condition,reg)
                if mode=="movabs":
                    for dst in REGS:
                        for src in REGS:pair.step("cmov",condition,dst,src)
            pair.step("jmp","tail");pair.step("label","tail");pair.step("finalize");pair.step("finalize")
        finally:pair.close()

def invalid_cases(actual):
    pair=Pair(actual,"invalid")
    invalid=[None,False,True,0,1,1.0,[],{},(),"rax\0","eax","RAX",InheritedStr("rax"),BytesSubclass(b"rax")]
    try:
        for value in invalid:
            for op,args in(("mov_rr",(value,"bad")),("mov_rr",("bad",value)),
                ("imul",(value,"bad")),("imul",("bad",value)),("push",(value,)),("pop",(value,)),
                ("load",(value,"bad",None)),("store",("bad",None,value)),
                ("setcc",("bad",value)),("cmov",("bad",value,None))):
                pair.step(op,*args)
        for value in(None,False,True,[],{},IntSubclass(0),1.0,-(1<<63)-1,1<<64,1<<200):
            pair.step("mov_imm","rax",value)
        for value in(None,False,True,[],IntSubclass(0),1.0,-(1<<31)-1,1<<31,1<<200):
            for op,args in(("load",("rax","rbp",value)),("store",("rsp",value,"r10")),
                          ("alu_imm",("add","rax",value))):pair.step(op,*args)
        for value in(None,False,True,[],{},IntSubclass(16),0,2,8,128,-1,1<<100):
            pair.step("align",value)
        for value in(None,False,True,0,[],{},(),"",BytesSubclass(b"abc"),InheritedStr("x")):
            pair.step("emit",value)
        for value in(None,False,True,0,[],{},"","x"*513,InheritedStr("okay")):
            pair.step("label",value);pair.step("jmp",value)
        pair.step("label","dup");pair.step("label","dup")
        for value in(None,False,0,[],"","a b","a\n","1x","a"*193,"é",InheritedStr("ok")):
            pair.step("call",value)
        for value in(None,False,[],{},"","eq","E",InheritedStr("e")):
            pair.step("jcc",value,"bad");pair.step("setcc",value,"bad");pair.step("cmov",value,"bad","bad")
        for value in(None,False,[],{},"","sal","Add",InheritedStr("add")):
            pair.step("alu_imm",value,"bad",None);pair.step("shift",value,"bad",None)
        for value in(None,False,True,[],{},-1,64,1<<64,IntSubclass(1),1.0,"CL","rcx"):
            pair.step("shift","shl","rax",value);pair.step("shr","rax",value)
        pair.step("jmp","unresolved-\ud800-\U0001f600");pair.step("finalize")
        pair.step("label","unresolved-\ud800-\U0001f600");pair.step("finalize")
    finally:pair.close()

def label_cases(actual):
    pair=Pair(actual,"labels")
    try:
        names=["L"+str(i).zfill(4) for i in range(512)]
        random.Random(3917).shuffle(names)
        for name in names:
            pair.step("jmp",name);pair.step("call","external_"+name)
        for index,name in enumerate(reversed(names)):
            pair.step("label",name)
            if index%17==0:pair.step("align",(1,16,32,64)[index%4])
        for name in("λ","é","e\u0301","\0inside","\ud800","\udfff","\U0001f600"*512,"a"*512):
            pair.step("jmp",name);pair.step("label",name)
        pair.step("call","_"+"a"*191);pair.step("ret");pair.step("finalize")
        pair.step("finalize")
    finally:pair.close()
    for index,name in enumerate(("\U0001f600"*512,"\ud800"*512,"x"*512)):
        pair=Pair(actual,"unresolved-long-"+str(index))
        try:pair.step("jmp",name);pair.step("finalize");pair.step("label",name);pair.step("finalize")
        finally:pair.close()

def boundary_cases(actual,variant):
    pair=Pair(actual,"boundary-"+str(variant),move="mov32_if_exact" if variant==5 else "movabs")
    try:
        pair.step("label","origin")
        prefix={0:0,1:1,2:2,3:1,4:10,5:5,6:1,7:0}[variant]
        raw=b"\x90"*(MAX_CODE-prefix)
        pair.step("emit",raw)
        del raw;gc.collect()
        if variant==0:
            pair.step("ret");pair.step("emit",b"x");pair.step("emit",b"")
        elif variant==1:pair.step("jmp","origin")
        elif variant==2:pair.step("jcc","ne","origin")
        elif variant==3:pair.step("call","external")
        elif variant in(4,5):pair.step("setcc","e","rax")
        elif variant==6:
            pair.step("align",64);pair.step("align",64);pair.step("ret")
        elif variant==7:pair.step("emit",bytearray(b"x"))
        result=pair.step("finalize")
        if variant in(1,2):assert len(result["value"][0])==MAX_CODE+4
        else:assert len(result["value"][0])==MAX_CODE
        pair.step("finalize")
    finally:pair.close();gc.collect()


def private_cases(actual):
    base=Session(actual)
    assert base.command(0,(None,"movabs","imm32"),"private-seed-init")["error"] is None
    assert base.command(4,("known",),"private-seed-label")["error"] is None
    assert base.command(5,("known",),"private-seed-branch")["error"] is None
    basecode=base.raw("code");basework=base.raw("work")
    base_command=base.command_bytes(2,())
    cases=[]
    for offset,value in((0,0),(8,2),(16,0),(16,base.lease+1),(24,base.seq),(24,base.seq+2),
        (32,46),(40,len(base_command)-65),(48,0),(56,1),(64,0),(72,base.lease+1),
        (80,0),(88,0),(96,(1<<64)-1),(104,1),(112,0),(120,1)):
        cases.append(("frame-"+str(offset)+"-"+str(value),replace_q(base_command,offset,value),basecode,basework))
    for offset,value in((128,0),(136,base.lease+1),(144,base.seq-1),(152,1),(160,0),
        (168,4095),(168,len(basework)+8),(176,MAX_CODE+1),(256,2),(264,2),(272,2)):
        cases.append(("state-"+str(offset)+"-"+str(value),base_command,basecode,replace_q(basework,offset,value)))
    for offset,value in((0,0),(8,base.lease+1),(16,base.seq+1),(24,1000),(32,1),(56,1)):
        cases.append(("code-"+str(offset),base_command,replace_q(basecode,offset,value),basework))
    label_command=base.command_bytes(4,("new-name",))
    cases.append(("registry-pointer",label_command,basecode,replace_q(basework,184,len(basework)+64)))
    count_command=base.command_bytes(1,(16,))
    cases.append(("integer-sign",replace_q(count_command,240,2),basecode,basework))
    name_command=base.command_bytes(4,("a",))
    cases.append(("name-codepoints",replace_q(name_command,240,2),basecode,basework))
    cases.append(("root-arity",replace_q(base_command,160,1),basecode,basework))
    for label,raw,code,work in cases:
        buffers=[]
        try:
            s=actual.buffers.allocate(len(raw),raw,True);buffers.append(s)
            o=actual.buffers.allocate(len(code),code);buffers.append(o)
            w=actual.buffers.allocate(len(work),work);buffers.append(w)
            ret,event=actual.entry("encoder",label,buffers,("private-input-"+label,"private-code-"+label,"private-work-"+label))
            assert ret==BAD and event[2]==3,(label,ret,event)
            repaired=actual.buffers.allocate(len(base_command),base_command,True);buffers.append(repaired)
            ret,event=actual.entry("encoder",label+"-permanent",(repaired,o,w),
                ("private-repaired-"+label,"private-code-"+label,"private-work-"+label))
            assert ret==BAD and event[2]==3,(label,ret,event)
            actual.private_controls+=1
            actual.record_case(label,dict(status="PASS",private=True,permanent_poison=True))
        finally:
            for b in reversed(buffers):actual.buffers.close(b)
    for size in(0,127,4095):
        s=o=w=None
        try:
            s=actual.buffers.allocate(len(base_command),base_command,True)
            o=actual.buffers.allocate(len(basecode),basecode)
            w=actual.buffers.allocate(size,basework[:size])
            ret,event=actual.entry("encoder","short-work-"+str(size),(s,o,w),
                ("short-source-"+str(size),"short-code-"+str(size),"short-work-"+str(size)))
            assert ret==BAD
            actual.private_controls+=1
        finally:
            for b in(w,o,s):actual.buffers.close(b)
    assert base.command(45,(),"final-private-prepare")["error"] is None
    goodcode=base.raw("code");goodmeta=base.raw("work")
    final_cases=[]
    for offset,value in((0,0),(8,base.lease+1),(16,base.seq-1),(24,MAX_CODE+1),(40,1)):
        final_cases.append(("final-code-"+str(offset),replace_q(goodcode,offset,value),goodmeta))
    for offset,value in((0,0),(8,0),(16,0),(24,base.lease+1),(32,base.seq+1),(40,44),
        (48,1),(56,0),(64,0),(72,0),(80,0),(88,0),(104,1),(112,1),(120,1),
        (128,0),(152,1),(160,0),(168,len(goodmeta)+8),(280,44)):
        final_cases.append(("final-meta-"+str(offset),goodcode,replace_q(goodmeta,offset,value)))
    for label,code,meta in final_cases:
        s=r=w=None
        try:
            s=actual.buffers.allocate(len(code),code,True);r=actual.buffers.allocate(len(meta),meta,True)
            w=actual.buffers.allocate(4096)
            ret,event=actual.entry("finalizer",label,(s,r,w),(label+"-code",label+"-meta",label+"-out"))
            assert ret==BAD and event[2]==3,(label,ret,event)
            actual.private_controls+=1;actual.record_case(label,dict(status="PASS",private=True,readonly_inputs_unchanged=True))
        finally:
            for b in(w,r,s):actual.buffers.close(b)
    base.close()
    # This is an explicit unissued-input positive control, not authentication.
    pending=Session(actual)
    first=pending.command_bytes(0,({"r10":"r10","r11":"r11"},"movabs","imm32"))
    second=pending.command_bytes(0,({"r10":"r11","r11":"r10"},"movabs","imm32"))
    assert first[:64]==second[:64] and first!=second
    a=actual.buffers.allocate(len(first),first,True)
    try:
        ret,event=actual.entry("encoder","PRIVATE-REPLACED-GROW-FIRST",(a,pending.code,pending.work),
            ("replaced-a","replaced-code","replaced-work"))
        assert ret==GROW and event[2]==1 and event[7]>=64
    finally:actual.buffers.close(a)
    pending.replace("code",4096)
    a=actual.buffers.allocate(len(second),second,True)
    try:
        ret,event=actual.entry("encoder","PRIVATE-REPLACED-GROW-SECOND",(a,pending.code,pending.work),
            ("replaced-b","replaced-code","replaced-work"))
        assert ret==128 and event[2]==0
        pending.seq=1
        oracle=actual.oracle.Code(scratch_registers={"r10":"r11","r11":"r10"})
        assert pending.command(9,("r10",1),"PRIVATE-REPLACED-GROW-OBSERVE")["error"] is None
        oracle.mov_imm("r10",1);pending.compare_state(oracle)
        actual.private_controls+=1
        actual.record_case("PRIVATE-REPLACED-GROW",dict(status="EXPECTED_ACCEPTANCE",
            proof="Header equality does not authenticate immutable input; production fixed issuer must retain the same bytes.",
            public_counterexample=False))
    finally:actual.buffers.close(a);pending.close()

def execution_cases(actual,root):
    raw=actual.evidence.pin(root/"reference/test_hia_machine_x64.py",EXECUTION_SHA)
    module=type(sys)("native_encoder_original_tests");module.__file__=str(root/"reference/test_hia_machine_x64.py")
    exec(compile(raw,module.__file__,"exec"),module.__dict__)
    assert module.Code.__module__=="hepta.hia_machine_x64"
    actual.evidence.pin(Path(sys.modules["hepta.hia_machine_x64"].__file__),REFERENCE_SHA)
    actual.evidence.pin(Path(sys.modules["hepta.hia_machine_elf"].__file__),
        "c77cc453d33058ccbeea9e056191001982892a3e59386958090122ccf487c101")
    sessions=[]
    class NativeCode:
        def __init__(self,*,scratch_registers=None,move_immediate="movabs",alu_immediate="imm32"):
            self.session=Session(actual);sessions.append(self.session)
            result=self.session.command(0,(scratch_registers,move_immediate,alu_immediate),"original-unit-constructor")
            if result["error"] is not None:
                self.session.close();raise module.MachineEncodingError(result["error"])
        @property
        def offset(self):
            return self.session.command(2,(),"original-unit-offset")["value"]
        def finalize(self):
            result=self.session.finalize("original-unit-finalize")
            if result["error"] is not None:raise module.MachineEncodingError(result["error"])
            return result["value"]
        def __getattr__(self,name):
            if name not in OPIDS:raise AttributeError(name)
            def method(*args):
                if name in("load","lea","load_u8") and len(args)==2:args=args+(0,)
                result=self.session.command(OPIDS[name],args,"original-unit-"+name)
                if result["error"] is not None:raise module.MachineEncodingError(result["error"])
                return result["value"]
            return method
    module.Code=NativeCode
    suite=unittest.defaultTestLoader.loadTestsFromModule(module)
    expected=suite.countTestCases()
    try:
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        assert result.testsRun==expected and result.wasSuccessful() and not result.skipped
        actual.record_case("exact-original-executable-tests",dict(status="PASS",tests=expected,skipped=0,
            original_test_source_sha256=EXECUTION_SHA,all_45_methods_native=True,
            reference_ELF_writer_used_only_as_test_link_container=True,
            production_lowering_and_ELF_join_closed=False))
    finally:
        for session in reversed(sessions):session.close()

def main():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    parser=argparse.ArgumentParser()
    parser.add_argument("--bundle",type=Path,required=True);parser.add_argument("--reference",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--group",choices=("constructor","registers","memory","immediates","conditions","invalid","labels","private","boundary","execution"),required=True)
    parser.add_argument("--variant",type=int,default=0)
    args=parser.parse_args();assert sys.version_info[:3]==(3,12,14)
    root=Path(__file__).resolve().parents[1];out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    actual=None;started=time.monotonic_ns();summary=dict(status="INCOMPLETE",group=args.group,variant=args.variant,
        old_counts_inherited=False,ordinary_lowering_closed=False,installed_closed=False,cold_qualified=False,
        actual_limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))),
        native_entries=0,private_controls=0,cases=0)
    try:
        actual=Actual(args.bundle,args.reference.resolve(),root,out)
        if args.group=="constructor":constructor_cases(actual)
        elif args.group=="registers":register_cases(actual)
        elif args.group=="memory":memory_cases(actual)
        elif args.group=="immediates":immediate_cases(actual)
        elif args.group=="conditions":condition_cases(actual)
        elif args.group=="invalid":invalid_cases(actual)
        elif args.group=="labels":label_cases(actual)
        elif args.group=="private":private_cases(actual)
        elif args.group=="boundary":boundary_cases(actual,args.variant)
        else:execution_cases(actual,root)
        summary.update(status="PASS",all_bytes_and_original_errors_equal=True,all_compared_state_equal=True,
            physical_readonly_inputs=True,all_canaries_intact=True,complete_buffers_recorded=True,
            native_entries=actual.calls,components=actual.counts,private_controls=actual.private_controls,
            cases=len(actual.results),error_ids=sorted(actual.errors),operations=sorted(actual.operations))
    except BaseException as error:
        summary.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        if actual is not None:
            summary.update(native_entries=actual.calls,components=actual.counts,private_controls=actual.private_controls,
                cases=len(actual.results),error_ids=sorted(actual.errors),operations=sorted(actual.operations))
            try:summary["source_custody"]=actual.close()
            except BaseException as error:summary.update(status="FAIL",cleanup_error=repr(error));traceback.print_exc()
        summary["elapsed_ns"]=time.monotonic_ns()-started
        save(out/"summary.json",summary);print(json.dumps(summary,sort_keys=True),flush=True)
    if summary["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
