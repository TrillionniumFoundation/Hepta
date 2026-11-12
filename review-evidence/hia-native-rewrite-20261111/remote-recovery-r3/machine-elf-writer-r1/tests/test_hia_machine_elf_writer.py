"""Fresh native ET_REL leaf differential and private protocol controls.
The original Python writer is an independent test oracle only.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ast,copy,ctypes,importlib.util,itertools,json,math,os,random,resource,stat,struct,sys,time,traceback,zlib
sys.dont_write_bytecode=True
GRAPH=int.from_bytes(b"HIAGRF01","little")
COMMAND=int.from_bytes(b"HIAELC01","little")
EVENT=int.from_bytes(b"HIAELE01","little")
BAD=0xfffffffd
GROW=0xfffffffe
CANARY=bytes(range(160,176))
REFERENCE_SHA="c77cc453d33058ccbeea9e056191001982892a3e59386958090122ccf487c101"
OWNER_SHA="4c93bc5fc97852bcd9c5fcc6c582ff79efa64af0124c01ee4b1054df95547458"
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def capture(root,lease=19):
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
        else:
            record[0]=8
        if raw is not None:
            record[1]=len(pool);record[2]=len(raw);pool.extend(raw)
        records.append(record);position+=1
    data=64+len(records)*64+len(edges)*8
    for record in records:
        if record[0] in (2,3,4,9):
            record[1]+=data
    header=(GRAPH,lease,len(records),rootid,len(edges),len(pool),data+len(pool),0)
    return (struct.pack('<8Q',*header)+b''.join(struct.pack('<8Q',*row) for row in records)
            +b''.join(struct.pack('<Q',value) for value in edges)+bytes(pool))


class Evidence:
    def __init__(self,root):
        self.root=root;self.directory=root/"cas";self.directory.mkdir()
        self.sources={};self.pins={}
    def page(self,raw):
        h=digest(raw);path=self.directory/(h+".zlib")
        if not path.exists():path.write_bytes(zlib.compress(raw,6))
        assert zlib.decompress(path.read_bytes())==raw
        return dict(sha256=h,bytes=len(raw),path="cas/"+path.name,compression="zlib")
    def raw(self,raw):
        return dict(bytes=len(raw),sha256=digest(raw),page_size=4096,
            pages=[self.page(raw[at:at+4096]) for at in range(0,len(raw),4096)])
    def memory(self,address,size):
        pages=[];h=sha256()
        for at in range(0,size,4096):
            raw=ctypes.string_at(address+at,min(4096,size-at));h.update(raw);pages.append(self.page(raw))
        return dict(bytes=size,sha256=h.hexdigest(),page_size=4096,pages=pages)
    def pin(self,path,expected=None):
        path=Path(path).resolve();info=path.lstat()
        assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
        raw=path.read_bytes()
        if expected is not None:assert digest(raw)==expected,(str(path),digest(raw),expected)
        if path in self.pins:assert self.pins[path]==raw
        else:
            self.pins[path]=raw;target=self.root/"sources"/str(len(self.pins))/path.name
            target.parent.mkdir(parents=True);target.write_bytes(raw);target.chmod(stat.S_IMODE(info.st_mode))
        return raw
    def finish(self):
        changed=[]
        for path,raw in self.pins.items():
            now=path.read_bytes()
            if now!=raw:changed.append(str(path))
        result=dict(status="PASS" if not changed else "FAIL",source_pins_unchanged=not changed,changed=changed,
            pins=[dict(path=str(p),bytes=len(raw),sha256=digest(raw)) for p,raw in self.pins.items()])
        save(self.root/"source-after.json",result);assert not changed;return result

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

class Actual:
    def __init__(self,manifest,reference,root,out):
        sys.path.insert(0,str(reference))
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        self.evidence=Evidence(out);self.out=out;self.buffers=Buffers();self.calls=0
        data=json.loads(self.evidence.pin(manifest))
        assert data["schema"]=="hepta.hia.machine-elf-writer-development.v1" and data["status"]=="BUILT_ONLY"
        self.evidence.pin(root/"tools/hia_machine_elf_writer.py",OWNER_SHA)
        self.evidence.pin(root/"reference/hia_machine_elf.py",REFERENCE_SHA)
        own=self.evidence.pin(__file__)
        capture_reference=self.evidence.pin(root/"reference/graph_harness_r3.py","75fe54554a93e19e30251073ac225deff944d6673d87ccc2b597e47a19e8be7c")
        def function_text(raw):
            text=raw.decode("utf-8")
            node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=="capture")
            return ast.get_source_segment(text,node)
        assert function_text(own)==function_text(capture_reference)
        source=self.evidence.pin(data["source_path"],data["source_sha256"])
        image=self.evidence.pin(data["image_path"],data["image_sha256"])
        assert len(source)==data["source_bytes"] and len(image)==data["image_bytes"]
        assert data["reference_sha256"]==REFERENCE_SHA and data["author_sha256"]==OWNER_SHA
        assert data["compile_receipt"]["limits"]["cpu_seconds"]==10
        assert data["compile_receipt"]["limits"]["address_bytes"]==256<<20
        self.image=NativeHiaJsonImage(image,expected_sha256=data["image_sha256"])
        raw=self.evidence.pin(root/"reference/hia_machine_elf.py",REFERENCE_SHA)
        self.oracle=type(sys)("exact_machine_elf_reference");self.oracle.__file__=str(root/"reference/hia_machine_elf.py")
        exec(compile(raw,self.oracle.__file__,"exec"),self.oracle.__dict__)
        self.results=[]
    def command(self,source,seq=1):
        return struct.pack("<12Q",COMMAND,1,struct.unpack_from("<Q",source,8)[0],seq,
            len(source),struct.unpack_from("<Q",source,24)[0],0,0,0,0,0,0)
    def entry(self,label,source,command,capacity,initial=b""):
        a=r=w=None;record=None;original=None
        try:
            a=self.buffers.allocate(len(source),source,True)
            r=self.buffers.allocate(len(command),command,True)
            w=self.buffers.allocate(capacity,initial)
            directory=self.out/"entries"/str(self.calls).zfill(6);directory.mkdir(parents=True)
            record=dict(label=label,input=self.evidence.raw(source),command=self.evidence.raw(command),
                before=self.evidence.memory(w["address"],capacity),workspace_capacity=capacity,
                physical_inputs_readonly=True,status="INCOMPLETE")
            save(directory/"entry.json",record)
            start=time.monotonic_ns()
            value=int(self.image._entry(a["address"],a["size"],r["address"],r["size"],w["address"],w["size"]))
            elapsed=time.monotonic_ns()-start;self.calls+=1
            for buffer in(a,r,w):self.buffers.check(buffer)
            aa=self.evidence.memory(a["address"],a["size"]);rr=self.evidence.memory(r["address"],r["size"])
            assert aa["sha256"]==record["input"]["sha256"] and rr["sha256"]==record["command"]["sha256"]
            after=self.evidence.memory(w["address"],capacity)
            event=struct.unpack("<16Q",ctypes.string_at(w["address"],128)) if capacity>=128 else None
            record.update(status="RETURNED",returned=value,event=event,after=after,elapsed_ns=elapsed,
                all_canaries_intact=True,input_bytes_unchanged=True,command_bytes_unchanged=True)
            save(directory/"entry.json",record)
            raw=ctypes.string_at(w["address"],capacity)
            return value,event,raw,record
        except BaseException as error:
            original=error;raise
        finally:
            cleanup=None
            for buffer in(w,r,a):
                try:self.buffers.close(buffer)
                except BaseException as error:
                    if cleanup is None:cleanup=error
                    else:cleanup.add_note("additional buffer close: "+repr(error))
            if cleanup is not None:
                if original is None:raise cleanup
                original.add_note("native buffer cleanup: "+repr(cleanup))
    def differential(self,label,alignment,code,symbols,relocations,copy_growth=True):
        expected=None;error=None
        try:expected=self.oracle.write_elf_object(code,symbols,relocations,text_alignment=alignment)
        except self.oracle.MachineObjectError as exc:error=dict(type=type(exc).__name__,message=str(exc))
        source=capture([alignment,code,symbols,relocations])
        command=self.command(source)
        if expected is not None:expected_record=self.evidence.raw(expected)
        else:expected_record=error
        save(self.out/"cases"/(label+"-expected.json"),dict(label=label,expected=expected_record,
            capture_is_mechanical=True,oracle_runtime_is_reference_only=True))
        capacity=4096;initial=b"";start=self.calls
        for attempt in range(8):
            ret,event,raw,entry=self.entry(label,source,command,capacity,initial)
            assert event[0:2]==(EVENT,1)
            assert event[3:5]==(19,1) and event[15]==0,(label,event)
            if event[2]==1:
                assert ret==GROW and event[5]==0 and event[6]>capacity and event[7:9]==(0,0)
                capacity=event[6];initial=raw if copy_growth else b""
                continue
            assert ret==128 and event[2] in(0,2),(label,event)
            assert event[7]<=len(raw) and event[8]<=len(raw)-event[7]
            actual=raw[event[7]:event[7]+event[8]]
            if expected is not None:
                assert event[2]==0 and event[5]==0 and actual==expected,(label,event,digest(actual),digest(expected))
                assert event[8]<=64<<20
                result=dict(label=label,status="PASS",kind="ELF",bytes=len(actual),sha256=digest(actual),
                    expected=expected_record,actual=self.evidence.raw(actual),calls=self.calls-start)
            else:
                assert event[2]==2 and 1<=event[5]<=12 and actual.decode("ascii")==error["message"],(label,error,event,actual)
                result=dict(label=label,status="PASS",kind="MachineObjectError",error=error,
                    error_id=event[5],actual=self.evidence.raw(actual),calls=self.calls-start)
            self.results.append(result);save(self.out/"cases-so-far.json",self.results);return result
        raise AssertionError(("unbounded pure GROW sequence in finite fixture",label))
    def close(self):
        self.image._mapping.close()
        return self.evidence.finish()

def symbol(name="entry",offset=0,size=1,exported=True):
    return dict(name=name,offset=offset,size=size,**{"global":exported})
def relocation(offset=1,name="puts"):
    return dict(offset=offset,symbol=name,type=4,addend=-4)

def ordinary_cases(group):
    if group=="basic":
        yield ("return",16,b"\xc3",[symbol()],[])
        yield ("unclaimed-text",64,b"\x90"*31+b"\xc3",[symbol(size=1)],[])
        functions=[symbol("z_public",0,5,True),symbol("a_hidden",5,5,False),symbol("M_public",10,1,True)]
        calls=[relocation(1,"external"),relocation(6,"a_hidden")]
        code=b"\xe8\0\0\0\0\xe8\0\0\0\0\xc3"
        for alignment in(16,32,64):
            for number,definitions in enumerate(itertools.permutations(functions)):
                for order,rels in enumerate((calls,list(reversed(calls)))):
                    yield ("ordered-%d-%d-%d"%(alignment,number,order),alignment,code,list(definitions),rels)
        for n in range(1,33):
            yield ("padding-"+str(n),16,b"\x90"*n,[symbol(size=n)],[])
        for n in(1,191,192):
            yield ("name-width-"+str(n),16,b"\xc3",[symbol("A"+"z"*(n-1))],[])
        for n in range(1,9):
            text=(b"\xe8\0\0\0\0"*n)+b"\xc3"
            yield ("adjacent-calls-"+str(n),32,text,[symbol(size=len(text))],[relocation(1+5*i,"u"+str(i)) for i in range(n)])
        return
    if group=="types":
        for i,value in enumerate((None,True,False,0,1,8,15,17,31,33,63,65,-16,16.0,"16",b"16",[],{},(),1<<200)):
            yield ("alignment-"+str(i),value,b"",None,None)
        for i,value in enumerate((None,True,0,1.0,"", "machine", bytearray(b"\xc3"), memoryview(b"\xc3"), [],{},(),b"")):
            yield ("code-"+str(i),16,value,None,None)
        for i,value in enumerate((None,True,0,1.0,"",b"x",(),{},set(),[])):
            yield ("symbols-"+str(i),16,b"\xc3",value,[])
            if value!=[]:yield ("relocations-"+str(i),16,b"\xc3",[symbol()],value)
        for i,value in enumerate((None,True,0,1.0,"",b"x",(),[],set(),{},{"name":"f"},{"name":"f","offset":0,"size":1,"global":True,"extra":0})):
            yield ("symbol-record-"+str(i),16,b"\xc3",[value],[]
        for i,name in enumerate(("", "1bad","a-b","a.b","bad\n","bad\0","é","a😀","a"*193,"_","\ud800",0,True,None,b"f",["f"])):
            yield ("symbol-name-"+str(i),16,b"\xc3",[symbol(name)],[]
        for field in("offset","size","global"):
            values=(None,True,False,-1,0,1,2,1<<32,1<<64,1<<200,0.0,"1",b"1",[],{})
            for i,value in enumerate(values):
                row=symbol();row[field]=value
                yield ("symbol-"+field+"-"+str(i),16,b"\xc3",[row],[]
        for i,value in enumerate((None,True,0,1.0,"",b"x",(),[],{},{"offset":1},{"offset":1,"symbol":"f","type":4,"addend":-4,"extra":1})):
            yield ("reloc-record-"+str(i),16,b"\xe8\0\0\0\0",[symbol(size=5)],[value])
        for field in("offset","type","addend"):
            for i,value in enumerate((None,True,False,-5,-4,-1,0,1,2,4,5,1<<32,1<<64,1<<200,4.0,-4.0,"4",b"4",[],{})):
                row=relocation();row[field]=value
                yield ("reloc-"+field+"-"+str(i),16,b"\xe8\0\0\0\0",[symbol(size=5)],[row])
        for i,name in enumerate(("", "0f","a-b","é","a"*193,"\udfff",None,False,5,[],{})):
            yield ("reloc-name-"+str(i),16,b"\xe8\0\0\0\0",[symbol(size=5)],[relocation(name=name)])
        class Str(str):pass
        class Int(int):pass
        class List(list):pass
        class Dict(dict):pass
        class Bytes(bytes):pass
        yield ("subclass-alignment",Int(16),b"\xc3",[symbol()],[])
        yield ("subclass-code",16,Bytes(b"\xc3"),[symbol()],[])
        yield ("subclass-symbol-list",16,b"\xc3",List([symbol()]),[])
        yield ("subclass-symbol-record",16,b"\xc3",[Dict(symbol())],[])
        yield ("subclass-symbol-name",16,b"\xc3",[symbol(Str("f"))],[])
        yield ("subclass-reloc-list",16,b"\xe8\0\0\0\0",[symbol(size=5)],List([relocation()]))
        yield ("subclass-reloc-record",16,b"\xe8\0\0\0\0",[symbol(size=5)],[Dict(relocation())])
        cyclic=[];cyclic.append(cyclic)
        yield ("cycle-row",16,b"\xc3",cyclic,[])
        row=symbol();row["size"]=row
        yield ("cycle-field",16,b"\xc3",[row],[])
        return
    if group=="order":
        good=symbol(size=11);code=b"\xe8\0\0\0\0\xe8\0\0\0\0\xc3"
        yield ("inventory-before-symbol-row",16,code,[{}],{})
        yield ("inventory-before-symbol-name",16,code,[symbol("!")],[relocation()]*3)
        yield ("name-before-range",16,code,[symbol("!",999,0)],[])
        yield ("name-before-global",16,code,[symbol("!",0,1,1)],[])
        yield ("overlap-before-reloc-record",16,code,[symbol("a",0,6),symbol("b",5,6)],[{}])
        yield ("overlap-before-reloc-name",16,code,[symbol("a",0,6),symbol("b",5,6)],[relocation(name="!")])
        yield ("duplicate-before-overlap",16,code,[symbol("a",0,6),symbol("a",5,6)],[])
        yield ("late-symbol-name-before-overlap",16,code,[symbol("a",0,6),symbol("b",5,6),symbol("!",10,1)],[])
        yield ("reloc-shape-before-name",16,code,[good],[dict(relocation(name="!"),offset=0)])
        yield ("reloc-type-before-name",16,code,[good],[dict(relocation(name="!"),type=True)])
        yield ("reloc-addend-before-name",16,code,[good],[dict(relocation(name="!"),addend=0)])
        yield ("reloc-name-before-opcode",16,b"\x90"*11,[good],[relocation(name="!")])
        yield ("late-reloc-error-before-overlap",16,code,[good],[relocation(),relocation(),dict(relocation(),type=3)])
        yield ("exact-duplicate-call",16,code,[good],[relocation(),relocation()])
        for delta in range(1,5):
            yield ("near-call-"+str(delta),16,code,[good],[relocation(),relocation(1+delta)])
        for index in range(5):
            changed=bytearray(code);changed[index]=0x90 if index==0 else 1
            yield ("placeholder-byte-"+str(index),16,bytes(changed),[good],[relocation()])
        for start,size in((0,11),(0,1),(10,1),(1,10)):
            yield ("legal-spans-%d-%d"%(start,size),16,code,[symbol(size=size,offset=start)],[relocation()])
        base=symbol("shared",0,5,False)
        yield ("local-target",16,code,[base],[relocation(name="shared")])
        yield ("undefined-order",16,code,[good],[relocation(6,"Alpha"),relocation(1,"zed")])
        shared=symbol()
        yield ("aliased-duplicate-symbol",16,code,[shared,shared],[])
        goodrel=relocation()
        yield ("aliased-duplicate-relocation",16,code,[good],[goodrel,goodrel])
        for number,keys in enumerate(itertools.permutations(("name","offset","size","global"))):
            row=symbol()
            yield ("dict-key-order-"+str(number),16,b"\xc3",[{key:row[key] for key in keys}],[])
        return
    if group=="random":
        rng=random.Random(0x484941454c46)
        for case in range(160):
            count=rng.randrange(1,25);code=bytearray();definitions=[];relocs=[]
            for i in range(count):
                at=len(code);calls=rng.randrange(0,4)
                for j in range(calls):
                    relocs.append(relocation(len(code)+1, "f%d"%rng.randrange(count) if rng.randrange(2) else "u%d"%rng.randrange(5)))
                    code.extend(b"\xe8\0\0\0\0")
                code.extend(bytes(rng.randrange(256) for _ in range(rng.randrange(1,9))))
                definitions.append(symbol("f"+str(i),at,len(code)-at,bool(rng.randrange(2))))
            rng.shuffle(definitions);rng.shuffle(relocs)
            alignment=(16,32,64)[rng.randrange(3)]
            yield ("random-"+str(case),alignment,bytes(code),definitions,relocs)
        return
    if group=="symbols":
        for count in(65533,65534,65535,65536):
            code=b"\x90"*count
            definitions=[symbol("f%05d"%i,i,1,bool(i&1)) for i in range(count)]
            yield ("definitions-"+str(count),16,code,definitions,[])
        for count in(65533,65534):
            code=b"\xe8\0\0\0\0"+b"\x90"*count
            definitions=[symbol("f%05d"%i,5+i,1,bool(i&1)) for i in range(count)]
            yield ("undefined-"+str(count),32,code,definitions,[relocation(name="external")])
        count=65535
        code=b"\xe8\0\0\0\0"+b"\x90"*count
        definitions=[symbol("f%05d"%i,5+i,1,False) for i in range(count)]
        yield ("late-reloc-before-symbol-limit",16,code,definitions,[dict(relocation(),addend=0)])
        return
    if group=="objects":
        for count in(67108215,67108216,67108217,67108864,67108865):
            code=b"\x90"*(count-1)+b"\xc3"
            yield ("object-bytes-"+str(count),64,code,[symbol("f",0,1,True)],[]
        return
    raise AssertionError(group)

def protocol_cases(actual):
    source=capture([16,b"\xe8\0\0\0\0\xc3",[symbol(size=6)],[relocation()]])
    command=actual.command(source);rows=[]
    def mutate(raw,at,value):
        result=bytearray(raw);struct.pack_into("<Q",result,at,value);return bytes(result)
    controls=[]
    for at,value in((0,0),(8,2),(16,0),(16,20),(24,0),(32,len(source)+1),(40,0),(40,999)):
        controls.append(("command-%d-%d"%(at,value),source,mutate(command,at,value),4096))
    for at in range(48,96,8):controls.append(("command-reserved-"+str(at),source,mutate(command,at,1),4096))
    for at,value in((0,0),(8,0),(16,0),(16,(1<<64)-1),(24,0),(24,999999),
                     (32,(1<<64)-1),(40,0),(48,len(source)-1),(56,1)):
        controls.append(("graph-%d-%d"%(at,value),mutate(source,at,value),command,4096))
    controls.append(("root-kind",mutate(source,64,7),command,4096))
    controls.append(("root-count",mutate(source,96,3),command,4096))
    controls.append(("root-edge-span",mutate(source,88,(1<<64)-1),command,4096))
    controls.append(("root-reserved",mutate(source,120,1),command,4096))
    nodes=struct.unpack_from("<Q",source,16)[0];edgebase=64+nodes*64
    root_edges=struct.unpack_from("<4Q",source,edgebase)
    alignment_at=64+(root_edges[0]-1)*64
    code_at=64+(root_edges[1]-1)*64
    symbols_at=64+(root_edges[2]-1)*64
    for label,at,value in(("integer-sign",alignment_at+48,2),
        ("integer-span",alignment_at+8,0),("code-aux",code_at+48,1),
        ("code-span",code_at+8,(1<<64)-1),("symbol-list-identity",symbols_at+40,0),
        ("symbol-edge-range",symbols_at+24,(1<<64)-1),("zero-edge",edgebase+16,0),
        ("large-edge",edgebase+24,nodes+1)):
        controls.append((label,mutate(source,at,value),command,4096))
    for count in(0,1,63):controls.append(("short-source-"+str(count),source[:count],command,4096))
    for count in(0,95,97):controls.append(("command-extent-"+str(count),source,command[:count]+(b"\0" if count==97 else b""),4096))
    for count in(0,127,4095):controls.append(("short-work-"+str(count),source,command,count))
    expected=len(controls)
    save(actual.out/"protocol-plan.json",dict(expected_cases=expected,
        cases=[dict(label=l,input_sha256=digest(s),command_sha256=digest(c),capacity=n) for l,s,c,n in controls]))
    for label,s,c,n in controls:
        ret,event,raw,record=actual.entry(label,s,c,n)
        assert ret==BAD,(label,event)
        if n>=4096:
            assert event[0:3]==(EVENT,1,3) and event[7:9]==(0,0) and event[15]!=0,(label,event)
        else:assert raw==bytes(n)
        rows.append(dict(label=label,status="PASS_PRIVATE_BAD",returned=ret))
    # A pure leaf explicitly has no persistent session poisoning. Fresh valid
    # invocations after private refusals are compared against the unchanged oracle.
    actual.differential("after-private-refusals",16,b"\xc3",[symbol()],[])
    actual.differential("growth-restart-with-zero-work",16,b"\xe8\0\0\0\0\xc3",[symbol(size=6)],[relocation()],copy_growth=False)
    assert len(rows)==expected
    save(actual.out/"protocol-results.json",rows)
    return expected

def main():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    parser=argparse.ArgumentParser()
    for name in("manifest","reference","out"):parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--group",choices=("basic","types","order","random","symbols","objects","protocol"),required=True)
    a=parser.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    assert sys.version_info[:3]==(3,12,14)
    root=Path(__file__).resolve().parents[1];actual=None;started=time.monotonic_ns()
    result=dict(status="INCOMPLETE",scope="NEW_NATIVE_ELF64_VALUE_LEAF_NOT_GENERAL_BUILD",
        group=a.group,old_counts_inherited=False,private_graph_is_not_authentication=True,
        arbitrary_Python_callbacks_closed=False,installed_closed=False,cold_qualified=False)
    try:
        actual=Actual(a.manifest,a.reference,root,out)
        if a.group=="protocol":
            result["private_controls"]=protocol_cases(actual)
            assert result["private_controls"]==45 and len(actual.results)==2
        else:
            planned=[]
            # The published source determines the complete generator corpus.
            # Each yielded large object is released after its case; no failing
            # row is dropped or selected by a previous native observation.
            for row in ordinary_cases(a.group):
                label,alignment,code,symbols,rels=row
                assert label not in planned;planned.append(label)
                actual.differential(label,alignment,code,symbols,rels)
                print("HIA_MACHINE_ELF_CASE "+json.dumps(dict(group=a.group,label=label,status="PASS"),sort_keys=True),flush=True)
            result["case_labels"]=planned
            expected_counts=dict(basic=81,types=215,order=55,random=160,symbols=7,objects=5)
            assert len(planned)==len(actual.results)==expected_counts[a.group]
        result.update(status="PASS",cases=len(actual.results),native_entries=actual.calls,
            results=actual.results,error_ids=sorted({row["error_id"] for row in actual.results if "error_id" in row}),
            full_bytes_or_exact_error_equal=True,
            physical_inputs_readonly=True,complete_buffers_and_canaries_recorded=True)
    except BaseException as error:
        result.update(status="FAIL",error_class=type(error).__name__,error=str(error),
            traceback=traceback.format_exc(),completed_cases=len(actual.results) if actual else 0,
            native_entries=actual.calls if actual else 0)
        traceback.print_exc()
    finally:
        if actual is not None:
            try:result["source_custody"]=actual.close()
            except BaseException as error:
                result["status"]="FAIL";result["cleanup_error"]=repr(error)
        usage=resource.getrusage(resource.RUSAGE_SELF)
        result.update(elapsed_ns=time.monotonic_ns()-started,usage=dict(user=usage.ru_utime,system=usage.ru_stime,maxrss_kib=usage.ru_maxrss),
            actual_limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))))
        save(out/"summary.json",result)
        print("HIA_MACHINE_ELF_GROUP "+json.dumps({k:v for k,v in result.items() if k!="results"},sort_keys=True),flush=True)
    if result["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
