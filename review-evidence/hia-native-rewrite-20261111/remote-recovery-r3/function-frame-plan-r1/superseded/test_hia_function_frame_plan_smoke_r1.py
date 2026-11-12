"""Native Function constructor/staging differential; Python is only an oracle."""
from pathlib import Path
from hashlib import sha256
import argparse,ast,copy,ctypes,importlib.util,itertools,json,os,random,resource,stat,struct,sys,time,traceback,types,zlib
sys.dont_write_bytecode=True
GRAPH=int.from_bytes(b"HIAGRF01","little")
COMMAND=int.from_bytes(b"HIAPFC01","little")
EVENT=int.from_bytes(b"HIAPFE01","little")
PLAN=int.from_bytes(b"HIAPFN01","little")
BAD=0xfffffffd
GROW=0xfffffffe
MASK=(1<<64)-1
CANARY=bytes(range(160,176))
OWNER_SHA="27a817d4cb0d3c8131efa4c8474779f55d74d618124a987a551cb26b3e18ddbd"
REFERENCE_SHA="bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c"
PLAN_SHA="ae3e54c4dc3299ba9b6d0a9b4caec55e26f3233e5699d3a0cab7deb1337efb8a"
REGS=(None,"rbx","r12","r13","r14","r15","r8","r9")
TYPES=("u8","u16","u32","u64","i8","i16","i32","i64","usize","isize","bool","unit","buffer","readbuf","mutbuf","chain")
class InheritedStr(str):pass
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def q(raw,at):return struct.unpack_from("<Q",raw,at)[0]
def replace_q(raw,at,value):
    result=bytearray(raw);struct.pack_into("<Q",result,at,value);return bytes(result)
def signed(value):return value if value<1<<63 else value-(1<<64)
# The following mechanical Graph capture and full paged-CAS/guarded-buffer
# implementation are copied from the exact passed x64 test source 18aa77e9.
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


class Graph:
    def __init__(self,raw):
        self.raw=raw;self.count=q(raw,16);self.edge_base=64+self.count*64;self.cache={}
    def row(self,identifier):
        assert 1<=identifier<=self.count
        return struct.unpack_from("<8Q",self.raw,64+(identifier-1)*64)
    def children(self,identifier):
        row=self.row(identifier);count=row[4]*(2 if row[0]==6 else 1)
        return [q(self.raw,self.edge_base+(row[3]+i)*8) for i in range(count)]
    def field(self,identifier,name):
        ids=self.children(identifier)
        for i in range(0,len(ids),2):
            if self.value(ids[i])==name:return ids[i+1]
        raise KeyError(name)
    def value(self,identifier):
        if identifier in self.cache:return self.cache[identifier]
        kind,at,n,first,count,identity,aux,res=self.row(identifier)
        if kind==0:value=None
        elif kind==1:value=bool(aux)
        elif kind==2:value=int.from_bytes(self.raw[at:at+n],"little")*(-1 if aux else 1)
        elif kind==3:value=struct.unpack("<d",self.raw[at:at+n])[0]
        elif kind==4:value=self.raw[at:at+n].decode("utf-8","surrogatepass")
        elif kind==5:value=[self.value(i) for i in self.children(identifier)]
        elif kind==6:
            ids=self.children(identifier);value={self.value(ids[i]):self.value(ids[i+1]) for i in range(0,len(ids),2)}
        else:raise AssertionError(("unexpected fixture node",kind))
        self.cache[identifier]=value;return value

class Trace:
    def __init__(self):self.trace=[];self.data=b""
    def __getattr__(self,name):
        def call(*args,**kwargs):
            assert not kwargs
            self.trace.append((name,*args))
        return call
class Original:
    """Exact original class/method ASTs; no translation feeds the HIA execution."""
    def __init__(self,evidence,root):
        raw=evidence.pin(root/"reference/hia_program_native.py",REFERENCE_SHA)
        plan=evidence.pin(root/"reference/hia_machine_plan.py",PLAN_SHA)
        package=types.ModuleType("function_frame_original");package.__path__=[]
        sys.modules[package.__name__]=package
        pm=types.ModuleType(package.__name__+".hia_machine_plan");pm.__file__=str(root/"reference/hia_machine_plan.py")
        sys.modules[pm.__name__]=pm;exec(compile(plan,pm.__file__,"exec"),pm.__dict__)
        name=package.__name__+".native";module=types.ModuleType(name)
        module.__package__=package.__name__;module.__file__=str(root/"reference/hia_program_native.py")
        wanted={"HIAProgramNativeRejected","_reject","_words","_bounds","_normalize","_prologue","_Function","_Emitter"}
        tree=ast.parse(raw);nodes=[n for n in tree.body if getattr(n,"name",None) in wanted]
        assert {n.name for n in nodes}==wanted
        globals_=dict(BYTE_RESOURCES=frozenset(("buffer","readbuf","mutbuf")),
            WIDTHS={**{f"{s}{n}":n for s in("i","u") for n in(8,16,32,64)},"isize":64,"usize":64},
            MAX_FRAME_BYTES=65536,MAX_TEXT_BYTES=16<<20)
        module.__dict__.update(globals_);exec(compile(ast.Module(body=nodes,type_ignores=[]),module.__file__,"exec"),module.__dict__)
        self.module=module
        method=next(n for n in next(n for n in nodes if n.name=="_Function").body if getattr(n,"name",None)=="render")
        split=next(i for i,n in enumerate(method.body) if isinstance(n,ast.For) and isinstance(n.iter,ast.Call)
            and isinstance(n.iter.func,ast.Attribute) and n.iter.func.attr=="ordered_blocks")
        entry=copy.deepcopy(method);entry.name="_entry_prefix";entry.body=entry.body[:split]
        outer=method.body[split];branch=next(n for n in outer.body if isinstance(n,ast.If))
        arm=branch
        while isinstance(arm,ast.If):
            if isinstance(arm.test,ast.Compare) and isinstance(arm.test.comparators[0],ast.Constant) and arm.test.comparators[0].value=="ret":break
            assert len(arm.orelse)==1;arm=arm.orelse[0]
        assert isinstance(arm,ast.If) and arm.test.comparators[0].value=="ret"
        returned=ast.parse("def _return_prefix(self,term):\n    c=self.c\n").body[0]
        returned.body+=copy.deepcopy(arm.body)
        extra=ast.fix_missing_locations(ast.Module(body=[entry,returned],type_ignores=[]))
        exec(compile(extra,module.__file__,"exec"),module.__dict__)
        save(evidence.root/"oracle-extraction.json",dict(reference_sha256=REFERENCE_SHA,
            full_class_AST_unchanged=True,exact_methods=["_Function","_Emitter","_words","_reject"],
            entry_render_prefix_statements=split,return_terminator_AST_unchanged=True,
            extracted_test_shims=ast.unparse(extra)))
    def construct(self,document,plan,index,serial):
        parent=types.SimpleNamespace(c=Trace(),machine_plan=plan,serial=serial,
            indices={f["name"]:i for i,f in enumerate(document["functions"])},
            block_order={} if plan is None else plan.get("block_order",{}),symbols=[],frames=[])
        for name in("label","ordered_blocks","function_symbol"):
            setattr(parent,name,types.MethodType(getattr(self.module._Emitter,name),parent))
        fn=document["functions"][index]
        try:return parent,self.module._Function(parent,fn,index),None
        except self.module.HIAProgramNativeRejected as error:return parent,None,str(error)

class Actual:
    def __init__(self,manifest,reference,root,out):
        self.evidence=Evidence(out);self.buffers=Buffers();self.calls=0;self.cases=[];self.private_controls=0
        self.closed=False;self.root=root;self.reference=reference;self.validated=0;self.pressure=0
        self.evidence.pin(__file__);self.evidence.pin(root/"tools/hia_function_frame_plan.py",OWNER_SHA)
        self.original=Original(self.evidence,root)
        doc=json.loads(self.evidence.pin(manifest));self.manifest=doc
        assert doc["schema"]=="hepta.hia.function-frame-development.v1" and doc["status"]=="BUILT_ONLY"
        assert doc["author_sha256"]==OWNER_SHA and doc["reference_sha256"]==REFERENCE_SHA
        assert doc["machine_plan_reference_sha256"]==PLAN_SHA
        source=self.evidence.pin(doc["source_path"],doc["source_sha256"])
        image=self.evidence.pin(doc["image_path"],doc["image_sha256"])
        receipt=doc["compile_receipt"]
        assert len(source)==doc["source_bytes"] and len(image)==doc["image_bytes"]
        assert receipt["input_sha256"]==receipt["source_sha256"]==digest(source)
        assert receipt["produced_sha256"]==digest(image)
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        loader_path=reference/"hepta/hia_json_preflight_native.py"
        loader_raw=self.evidence.pin(loader_path)
        loader=types.ModuleType("function_frame_image_loader");loader.__file__=str(loader_path)
        exec(compile(loader_raw,str(loader_path),"exec"),loader.__dict__)
        self.image=loader.NativeHiaJsonImage(image,expected_sha256=digest(image))
    def entry(self,label,source,command,workspace):
        buffers=(source,command,workspace);number=self.calls;self.calls+=1
        keys=(label+"-graph",label+"-command",label+"-work")
        before=[self.evidence.memory(b,k) for b,k in zip(buffers,keys)]
        record=dict(number=number,label=label,status="ENTERING",before=before,
            capacities=[b["size"] for b in buffers],readonly=[b["readonly"] for b in buffers])
        self.evidence.entry(record);started=time.monotonic_ns()
        ret=int(self.image._entry(source["address"],source["size"],command["address"],command["size"],workspace["address"],workspace["size"]))
        elapsed=time.monotonic_ns()-started
        for b in buffers:self.buffers.check(b)
        after=[self.evidence.memory(b,k) for b,k in zip(buffers,keys)]
        assert before[0]["sha256"]==after[0]["sha256"] and before[1]["sha256"]==after[1]["sha256"]
        event=struct.unpack("<16Q",ctypes.string_at(workspace["address"],128)) if workspace["size"]>=4096 else None
        self.evidence.entry(dict(record,status="RETURNED",returned=ret,event=event,
            elapsed_ns=elapsed,after=after,canaries_intact=True))
        return ret,event
    def command(self,graph,index=0,serial=0,lease=17,request=1):
        return struct.pack("<12Q",COMMAND,1,lease,request,index,serial,q(graph,24),0,0,0,0,0)
    def run(self,label,graph,command,capacity=4096,grow=True,fill=0xa5):
        a=b=w=None;events=[];start=self.calls
        try:
            a=self.buffers.allocate(len(graph),graph,True);b=self.buffers.allocate(len(command),command,True)
            w=self.buffers.allocate(capacity,bytes([fill])*capacity)
            for _ in range(6):
                ret,event=self.entry(label,a,b,w);events.append(dict(returned=ret,event=event))
                if ret==GROW and grow:
                    assert event[:2]==(EVENT,1) and event[2]==1 and event[7]>w["size"]
                    old=w;w=None;self.buffers.close(old);w=self.buffers.allocate(event[7],bytes([fill])*event[7])
                    continue
                raw=ctypes.string_at(w["address"],w["size"])
                return dict(returned=ret,event=event,workspace=raw,events=events,entries=self.calls-start)
            raise AssertionError(("GROW did not finish",label,events))
        finally:
            for buffer in(w,b,a):self.buffers.close(buffer)
    def record(self,label,**values):
        row=dict(label=label,**values);self.cases.append(row);self.evidence.case(row)
    def admit(self,document,plan):
        # This is only the independent test oracle. Production transport receives
        # the actual admitted document and checked plan from their native issuers.
        sys.path.insert(0,str(self.reference))
        from hepta.hia_program import verify_program
        from hepta.hia_machine_plan import validate_plan
        checked=verify_program(document)
        if plan is not None:
            plan=copy.deepcopy(plan);plan["core_sha256"]=checked.sha256
            plan=validate_plan(checked,plan)
        for name,module in tuple(sys.modules.items()):
            path=getattr(module,"__file__",None)
            if path and (name=="hepta" or name.startswith("hepta.")):
                p=Path(path).resolve()
                if p.suffix==".py" and p.is_relative_to(self.reference):self.evidence.pin(p)
        self.validated+=1
        return checked.as_dict(),plan
    def compare(self,label,document,plan=None,index=0,serial=0,admitted=True):
        if admitted:document,plan=self.admit(document,plan)
        else:self.pressure+=1
        graph=capture([document,plan],17);g=Graph(graph)
        parent,expected,error=self.original.construct(document,plan,index,serial)
        result=self.run(label,graph,self.command(graph,index,serial))
        event=result["event"];assert event[:2]==(EVENT,1) and event[3:6]==(17,1,index)
        assert event[14]==q(graph,24) and event[15]==0
        assert result["returned"]==128
        raw=result["workspace"]
        if error:
            assert event[2]==2 and event[6]==1 and event[8:10]==(0,0)
            at,n=event[12:14]
            actual=raw[at:at+n].decode("utf-8")
            assert actual==error and event[11]==serial and parent.serial==serial,(label,actual,error,event)
            self.record(label,status="PASS",admitted=admitted,error=error,frame=event[10],
                serial_unchanged=True,entries=result["entries"],graph=self.evidence.raw(graph))
            return result
        assert event[2]==0 and event[6]==0 and event[12:14]==(0,0)
        assert event[14]==q(graph,24) and event[8]==4096 and event[9]==event[7]-4096
        h=struct.unpack_from("<64Q",raw,4096)
        assert h[:5]==(PLAN,1,17,1,index) and h[49:]==(0,)*15
        fn=document["functions"][index]
        assert g.value(h[5])==fn and g.value(h[6])==fn["name"]
        assert h[7:11]==(expected.frame,expected.cursor,serial,parent.serial)
        assert h[11]==int(expected.scalar_select=="cmov_scalar")
        assert event[10:12]==(expected.frame,parent.serial)
        assert h[30:37]==(expected.edge_words,expected.call_words,expected.result_words,
            expected.edge_slot&MASK,expected.call_slot&MASK,expected.result_slot&MASK,expected.temporary&MASK)
        assert h[43]==event[9] and h[44:47]==(len(graph),q(graph,24),len(document["functions"]))
        assert raw[h[41]:h[41]+h[42]].decode()==expected.trap
        def rows(at,n,size):
            assert 4096<=at<=event[7] and n*size<=event[7]-at
            return [struct.unpack_from("<"+"Q"*(size//8),raw,at+i*size) for i in range(n)]
        values=rows(h[18],h[12],64);blocks=rows(h[19],h[13],64)
        calls=rows(h[20],h[14],96);edges=rows(h[21],h[15],96);returns=rows(h[22],h[16],64)
        moves=rows(h[23],h[17],32)
        latest={}
        for i,v in enumerate(values):
            name,typ=g.value(v[0]),g.value(v[1])
            assert v[2]==self.original.module._words(typ) and v[7]==i
            assert g.value(v[5])==dict(name=name,type=typ)
            latest[name]=v
        assert {name:signed(v[3]) for name,v in latest.items()}==expected.slots
        assert {name:g.value(v[1]) for name,v in latest.items()}==expected.types
        assert {name:REGS[v[4]] for name,v in latest.items() if v[4]}==expected.value_registers
        assert h[47]==len(expected.slots) and h[48]==len(expected.value_registers)
        saved=rows(h[38],h[37],16)
        assert [(REGS[r],signed(slot)) for r,slot in saved]==list(expected.saved_registers.items())
        assert len(blocks)==len(fn["blocks"])
        for i,row in enumerate(blocks):
            block=fn["blocks"][i]
            assert g.value(row[0])==block and g.value(row[1])==block["id"]
            assert g.value(row[2])==block["params"] and g.value(row[3])==block["ops"]
            assert g.value(row[4])==block["term"] and row[6:]==(i,0)
        order=rows(h[28],h[13],8)
        assert [g.value(q(raw,row[0]+8)) for row in order]==[b["id"] for b in parent.ordered_blocks(fn)]
        assert g.value(q(raw,h[29]+8))==fn["entry"]
        def moved(at,n):
            assert h[23]<=at<=h[23]+len(moves)*32 and (at-h[23])%32==0
            assert n<=(h[23]+len(moves)*32-at)//32
            result_=[]
            for i in range(n):
                value,word,offset,reg=struct.unpack_from("<4Q",raw,at+i*32)
                assert h[18]<=value<h[18]+len(values)*64 and (value-h[18])%64==0
                v=values[(value-h[18])//64]
                assert word<v[2] and offset==(v[3]+word*8)&MASK and reg==v[4]
                result_.append((g.value(v[0]),word,signed(offset),REGS[reg]))
            return result_
        def loadmove(trace,move,target="rax"):
            name,word,offset,reg=move
            if reg:assert word==0;trace.mov_rr(target,reg)
            else:trace.load(target,"rbp",offset)
        def storemove(trace,move,source="rax"):
            name,word,offset,reg=move
            if reg:assert word==0;trace.mov_rr(reg,source)
            else:trace.store("rbp",offset,source)
        original_c=expected.c
        trace=Trace();self.original.module._prologue(trace,expected.frame)
        for register,slot in saved:trace.store("rbp",signed(slot),REGS[register])
        trace.store("rbp",-8,"rsi")
        for n,move in enumerate(moved(h[39],h[40])):
            trace.load("rax","rdi",n*8);storemove(trace,move)
        trace.jmp(expected.block_label(fn["entry"]))
        expected.c=Trace();self.original.module._entry_prefix(expected)
        assert trace.trace==expected.c.trace,(label,"parameter staging",trace.trace,expected.c.trace)
        for row in calls:
            op=g.value(row[2]);assert fn["blocks"][row[0]]["ops"][row[1]]==op
            assert g.value(row[3])==op["args"] and g.value(row[4])==op["out"]
            assert g.value(row[9])==op["attrs"]["function"] and row[10:]==(0,0)
            trace=Trace()
            for n,move in enumerate(moved(row[7],row[5])):
                loadmove(trace,move);trace.store("rbp",expected.call_slot+n*8,"rax")
            trace.lea("rdi","rbp",expected.call_slot);trace.lea("rsi","rbp",expected.result_slot)
            trace.call(parent.function_symbol(g.value(row[9])))
            for n,move in enumerate(moved(row[8],row[6])):
                trace.load("rax","rbp",expected.result_slot+n*8);storemove(trace,move)
            expected.c=Trace();expected.operation(op)
            assert trace.trace==expected.c.trace,(label,"call staging",trace.trace,expected.c.trace)
        for row in edges:
            edge=g.value(row[2]);target=g.value(row[3])
            assert edge["target"]==target and edge["args"]==g.value(row[4]) and row[9:]==(0,0,0)
            trace=Trace()
            for n,move in enumerate(moved(row[6],row[5])):
                loadmove(trace,move);trace.store("rbp",expected.edge_slot+n*8,"rax")
            for n,move in enumerate(moved(row[7],row[5])):
                trace.load("rax","rbp",expected.edge_slot+n*8);storemove(trace,move)
            trace.jmp(expected.block_label(target))
            expected.c=Trace();expected.edge(target,edge["args"])
            assert trace.trace==expected.c.trace,(label,"edge staging",trace.trace,expected.c.trace)
        for row in returns:
            term=g.value(row[1]);assert term==fn["blocks"][row[0]]["term"] and row[5:]==(0,0,0)
            trace=Trace();trace.load("r10","rbp",-8)
            for n,move in enumerate(moved(row[4],row[3])):
                loadmove(trace,move);trace.store("r10",n*8,"rax")
            for register,slot in saved:trace.load(REGS[register],"rbp",signed(slot))
            trace.leave();trace.ret()
            expected.c=Trace();self.original.module._return_prefix(expected,term)
            assert trace.trace==expected.c.trace,(label,"return staging",trace.trace,expected.c.trace)
        expected.c=original_c
        self.record(label,status="PASS",admitted=admitted,frame=expected.frame,cursor=expected.cursor,
            values=len(values),blocks=len(blocks),calls=len(calls),edges=len(edges),returns=len(returns),
            moves=len(moves),entries=result["entries"],serial=parent.serial,trap=expected.trap,
            graph=self.evidence.raw(graph),full_reference_slots_equal=True,
            all_staging_traces_equal=True,full_source_and_canaries_unchanged=True)
        return result
    def close(self):
        if self.closed:return None
        self.closed=True;self.image._mapping.close()
        return self.evidence.finish()

def param(name,typ):return dict(name=name,type=typ)
def op(name,args,out,attrs=None):return dict(op=name,args=args,out=out,attrs={} if attrs is None else attrs)
def block(name,params,ops,term):return dict(id=name,params=params,ops=ops,term=term)
def function(name="f",params=None,ops=None,term=None,returns=None,blocks=None,effects=None):
    params=[] if params is None else params;ops=[] if ops is None else ops
    term=dict(op="ret",values=[]) if term is None else term
    blocks=[block("b0",params,ops,term)] if blocks is None else blocks
    return dict(name=name,params=params,returns=[] if returns is None else returns,
        effects=[] if effects is None else effects,entry=blocks[0]["id"],blocks=blocks)
def program(*functions):return dict(schema="hepta.hia.program.v8",module="frame_planner",functions=list(functions))
def machine_plan(document,registers=None,orders=None,leaf=False,select="branch"):
    return dict(schema="hepta.hia.agent.machine-plan.v4" if leaf else "hepta.hia.agent.machine-plan.v3",
        core_sha256="",block_order={} if orders is None else orders,
        function_order=[f["name"] for f in document["functions"]],
        scratch_registers={"r10":"r10","r11":"r11"},function_alignment=1,
        instruction_selection=dict(move_immediate="movabs",alu_immediate="imm32",scalar_select=select),
        value_registers={} if registers is None else registers)

def smoke(actual):
    actual.compare("empty",program(function()))
    for typ in TYPES:
        p=param("input",typ)
        actual.compare("type-"+typ,program(function(params=[p],term=dict(op="trap"),effects=["trap"])))
    for serial in(1,9,99,999,2**32-1,2**32,2**63,2**64-2):
        actual.compare("serial-"+str(serial),program(function("last")),serial=serial)

def edge_case():
    a,b,c=param("a","u64"),param("b","u64"),param("cond","bool")
    x,y,z=param("x","u64"),param("y","u64"),param("loop","bool")
    u,v=param("u","u64"),param("v","u64")
    blocks=[block("entry",[a,b,c],[],dict(op="jump",target="loop_block",args=["b","a","cond"])),
        block("loop_block",[x,y,z],[],dict(op="branch",cond="loop",
            then=dict(target="loop_block",args=["y","x","loop"]),else_=None)),
        block("end",[u,v],[],dict(op="ret",values=["u","v"]))]
    term=blocks[1]["term"];term.pop("else_");term["else"]=dict(target="end",args=["x","y"])
    return program(function(params=[a,b,c],returns=["u64","u64"],blocks=blocks))
def edges_and_registers(actual):
    doc=edge_case()
    actual.compare("backedge-permutation",doc)
    for order in itertools.permutations(["entry","loop_block","end"]):
        plan=machine_plan(doc,orders={"f":list(order)})
        actual.compare("block-order-"+"/".join(order),doc,plan,serial=31)
    for reg in REGS[1:]:
        plan=machine_plan(doc,registers={"f":{"a":reg,"x":reg,"u":reg}},leaf=reg in("r8","r9"))
        actual.compare("one-register-"+reg,doc,plan)
    simple=program(function(params=[param("a","u64"),param("b","u64")],returns=["u64"],
        term=dict(op="ret",values=["a"])))
    for count in range(6):
        params=[param("v"+str(i),"u64") for i in range(max(1,count))]
        doc=program(function(params=params,returns=["u64"],term=dict(op="ret",values=[params[0]["name"]])))
        mapping={p["name"]:REGS[count-i] for i,p in enumerate(params[:count])}
        actual.compare("saved-order-"+str(count),doc,machine_plan(doc,registers={"f":mapping}))
    actual.compare("cmov-choice",simple,machine_plan(simple,select="cmov_scalar"))

def calls(actual):
    for types_ in ([],["u64"],["readbuf","mutbuf","u64"],["u64","bool","i8","readbuf","mutbuf"]):
        params=[param("p"+str(i),t) for i,t in enumerate(types_)]
        outs=[param("answer","u64"),param("small","u32")]
        callee=function("callee",params=params,ops=[op("const",[],[outs[0]],{"value":7}),
            op("const",[],[outs[1]],{"value":3})],returns=["u64","u32"],
            term=dict(op="ret",values=["answer","small"]))
        caller=function("caller",params=params,ops=[op("call",[p["name"] for p in params],
            [param("x","u64"),param("y","u32")],{"function":"callee"})],
            returns=["u64","u32"],term=dict(op="ret",values=["x","y"]))
        doc=program(callee,caller)
        actual.compare("call-"+",".join(types_),doc,index=1,serial=19)
        mapping={"caller":{"x":"rbx","y":"r15"}}
        actual.compare("call-registers-"+",".join(types_),doc,machine_plan(doc,registers=mapping),index=1)
    # Exact constructor pressure beyond the published Core domain is separately
    # labelled: all 16 types, multiword results, repeated calls and dead outputs.
    types_=list(TYPES)
    params=[param("p"+str(i),t) for i,t in enumerate(types_)]
    callee=function("callee",params=params,returns=types_,term=dict(op="trap"),effects=["trap"])
    ops=[]
    for i in range(3):
        outs=[param("out"+str(i)+"_"+str(j),t) for j,t in enumerate(types_)]
        ops.append(op("call",[p["name"] for p in params],outs,{"function":"callee"}))
    caller=function("caller",params=params,ops=ops,returns=types_,term=dict(op="ret",values=[v["name"] for v in ops[-1]["out"]]))
    actual.compare("private-complete-width-call-results",program(callee,caller),index=1,admitted=False)
    for seed in range(24):
        rng=random.Random(seed);types_=[rng.choice(TYPES) for _ in range(rng.randrange(1,18))]
        params=[param("p"+str(i),t) for i,t in enumerate(types_)]
        outs=[param("r"+str(i),t) for i,t in enumerate(reversed(types_))]
        callee=function("callee",params=params,returns=list(reversed(types_)),term=dict(op="trap"),effects=["trap"])
        caller=function("caller",params=params,ops=[op("call",[p["name"] for p in params],outs,{"function":"callee"})],
            returns=list(reversed(types_)),term=dict(op="ret",values=[p["name"] for p in outs]))
        actual.compare("private-call-widths-"+str(seed),program(callee,caller),index=1,serial=seed,admitted=False)

def inventories(actual):
    for count in(1,2,127,128,129,1023,1024):
        docs=program(*(function("f"+str(i)) for i in range(count)))
        actual.compare("original-function-domain-"+str(count),docs,index=count-1,serial=3)
    # Allocating values follows the original block inventory, even if the caller
    # checked a different emission order. The exact original constructor overwrites
    # duplicate names while still consuming both allocations (private pressure).
    doc=program(function(params=[param("a","u64")],ops=[op("const",[],[param("a","u32")],{"value":0})],
        returns=["u32"],term=dict(op="ret",values=["a"])))
    actual.compare("private-last-definition-overwrite",doc,admitted=False)
    for count in(0,1,7,31,127,128,129,511):
        params=[param("collision_name_"+str(i),"u64") for i in range(count)]
        doc=program(function(params=params,returns=[],term=dict(op="ret",values=[])))
        actual.compare("parameter-inventory-"+str(count),doc)

def boundary(actual,variant):
    count=(8182,8183,8184,8185,8190)[variant]
    values=[param("v"+str(i),"u64") for i in range(count)]
    ops=[op("const",[],[value],{"value":i}) for i,value in enumerate(values)]
    doc=program(function("frame_boundary",ops=ops,term=dict(op="ret",values=[])))
    actual.compare("exact-frame-ops-"+str(count),doc,serial=123456)

def private_controls(actual):
    doc=edge_case();graph=capture([doc,None],17);command=actual.command(graph);counter=0
    def bad(label,raw=graph,cmd=command,capacity=4096):
        nonlocal counter
        result=actual.run(label,raw,cmd,capacity=capacity)
        assert result["returned"]==BAD,(label,result["event"])
        if result["event"] is not None:
            assert result["event"][:3]==(EVENT,1,3) and result["event"][15]>0
        actual.private_controls+=1;counter+=1
        actual.record(label,status="PASS",private_BAD=True,entries=result["entries"],
            graph=actual.evidence.raw(raw),command=actual.evidence.raw(cmd),event=result["event"])
    for n in(0,1,63,95,97,104):bad("command-extent-"+str(n),cmd=command[:n]+b"\0"*max(0,n-len(command)))
    for at,value in((0,0),(8,0),(16,0),(24,0),(32,99),(48,0)):
        bad("command-field-"+str(at),cmd=replace_q(command,at,value))
    for at in range(56,96,8):bad("command-reserved-"+str(at),cmd=replace_q(command,at,1))
    for at,value in((0,0),(8,18),(16,0),(16,MASK),(24,0),(32,MASK),(40,0),(48,len(graph)-1),(56,1)):
        bad("graph-field-"+str(at)+"-"+str(value),raw=replace_q(graph,at,value))
    for n in(0,1,63,64,127,len(graph)-1):bad("graph-extent-"+str(n),raw=graph[:n])
    for cap in(0,1,127,4095):bad("workspace-short-"+str(cap),capacity=cap)
    bad("serial-overflow-private",cmd=replace_q(command,40,MASK))
    g=Graph(graph);root=q(graph,24)
    for at,value in((64+(root-1)*64,6),(64+(root-1)*64+32,1),(64+(root-1)*64+24,MASK)):
        bad("root-node-"+str(at),raw=replace_q(graph,at,value))
    for identifier in range(1,g.count+1):
        row=g.row(identifier)
        if row[0]==4 and g.value(identifier)=="functions":
            at=64+(identifier-1)*64
            for off,val in((0,8),(8,len(graph)+1),(16,MASK),(56,1)):
                bad("string-node-"+str(off),raw=replace_q(graph,at+off,val))
            break
    bad("edge-zero",raw=replace_q(graph,g.edge_base,0))
    bad("edge-unknown",raw=replace_q(graph,g.edge_base,g.count+1))
    mutations=[]
    changed=copy.deepcopy(doc);del changed["functions"][0]["blocks"];mutations.append(("missing-blocks",changed,None))
    changed=copy.deepcopy(doc);changed["functions"][0]["blocks"][0]["term"]["target"]="unknown";mutations.append(("unknown-target",changed,None))
    changed=copy.deepcopy(doc);changed["functions"][0]["blocks"][0]["term"]["args"]=[];mutations.append(("wrong-edge-width",changed,None))
    changed=copy.deepcopy(doc);changed["functions"][0]["blocks"][0]["term"]["args"][0]="unknown";mutations.append(("unknown-value",changed,None))
    mutations.extend((
        ("unknown-register",doc,{"value_registers":{"f":{"a":"rsp"}}}),
        ("unknown-assigned-value",doc,{"value_registers":{"f":{"unknown":"rbx"}}}),
        ("unknown-scalar-choice",doc,{"instruction_selection":{"scalar_select":"other"}}),
        ("wrong-order-length",doc,{"block_order":{"f":["entry"]}}),
        ("unknown-order-target",doc,{"block_order":{"f":["entry","loop_block","unknown"]}}),
    ))
    for label,changed,plan in mutations:
        raw=capture([changed,plan],17);bad(label,raw=raw,cmd=actual.command(raw))
    baseline=actual.run("grow-baseline",graph,command)
    first=actual.run("grow-stop",graph,command,grow=False)
    assert first["returned"]==GROW
    for capacity in(first["event"][7]-1,first["event"][7],baseline["event"][7]-1,baseline["event"][7],baseline["event"][7]+4096):
        result=actual.run("grow-exact-"+str(capacity),graph,command,capacity=capacity)
        assert result["returned"]==128 and result["event"]==baseline["event"]
        assert result["workspace"][:baseline["event"][7]]==baseline["workspace"][:baseline["event"][7]]
        actual.record("grow-exact-"+str(capacity),status="PASS",entries=result["entries"],
            exact_terminal_workspace_equal=True,same_physical_readonly_inputs=True)
    # This pure leaf authenticates neither arbitrary inputs nor a header. A new,
    # separately issued Graph can share a header and must be treated as a new call.
    other=copy.deepcopy(doc);other["module"]="another_private_issuer"
    raw=capture([other,None],17);result=actual.run("private-header-not-authentication",raw,actual.command(raw))
    assert result["returned"]==128
    actual.record("private-header-not-authentication",status="PASS",entries=result["entries"],
        private_positive_only=True,public_authentication_claim=False)
    assert counter>=55

GROUPS=("smoke","edges","calls","inventories","boundary","private")
def main():
    parser=argparse.ArgumentParser()
    for name in("manifest","reference","out"):parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--group",choices=GROUPS,required=True)
    parser.add_argument("--variant",type=int,default=0)
    args=parser.parse_args();root=Path(__file__).resolve().parents[1]
    args.out.mkdir(parents=True,exist_ok=False)
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    actual=None;summary=dict(status="INCOMPLETE",group=args.group,variant=args.variant,
        scope="FUNCTION_FRAME_PLANNER_ONLY",whole_backend_closed=False,installed_closed=False,cold_qualified=False)
    started=time.monotonic_ns()
    try:
        assert sys.version_info[:3]==(3,12,14)
        actual=Actual(args.manifest,args.reference.resolve(),root,args.out)
        {"smoke":smoke,"edges":edges_and_registers,"calls":calls,"inventories":inventories,
            "boundary":lambda a:boundary(a,args.variant),"private":private_controls}[args.group](actual)
        summary["status"]="PASS"
    except BaseException as error:
        summary.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        if actual is not None:
            summary.update(cases=len(actual.cases),native_entries=actual.calls,private_controls=actual.private_controls,
                admitted_core_cases=actual.validated,private_constructor_pressure_cases=actual.pressure)
            try:summary["custody"]=actual.close()
            except BaseException as error:
                summary.update(status="FAIL",cleanup_error=repr(error),cleanup_traceback=traceback.format_exc());traceback.print_exc()
        summary.update(elapsed_ns=time.monotonic_ns()-started,
            limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))))
        save(args.out/"summary.json",summary);print(json.dumps(summary,sort_keys=True),flush=True)
    if summary["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
