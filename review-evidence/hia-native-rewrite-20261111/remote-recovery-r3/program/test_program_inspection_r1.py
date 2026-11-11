"""Actual native qualification of the reconstructed private program projector.
The Python oracle and Graph transport below are testing only, not runtime owners.
"""
from pathlib import Path
from hashlib import sha256
import copy, ctypes, importlib.util, json, os, resource, struct, sys, traceback, zlib
BASE=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
REF=BASE/"root-recovery/reference-0ef-r2"
ROOT=BASE/"root-recovery/workspace/native-program-service-reconstructed-r1"
OUT=ROOT/"development/native-projection-r1"
sys.path.insert(0,str(REF));sys.dont_write_bytecode=True
from hepta.hia_program import verify_program
from hepta.hia_program_tools import inspect_program
from hepta.hia_json_preflight_native import NativeHiaJsonImage
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
MAGIC=int.from_bytes(b"HIAGRF01","little")
COMMAND=int.from_bytes(b"HIAPIC01","little")
EVENT=int.from_bytes(b"HIAPIE01","little")
BAD=0xfffffffd;GROW=0xfffffffe
MIN_WORK=65536

import ctypes,mmap
class Buffer:
    def __init__(self,size,raw=b"",readonly=False):
        assert type(size) is int and 0<=size<=128<<20
        assert type(raw) is bytes and len(raw)<=size
        self.size=size
        page=mmap.PAGESIZE
        payload_pages=((max(1,size)+64+page-1)//page)*page
        self._map=mmap.mmap(-1,payload_pages+2*page,prot=mmap.PROT_READ|mmap.PROT_WRITE)
        start=ctypes.addressof(ctypes.c_char.from_buffer(self._map))
        self.address=start+page+32
        self._prefix=b"\xa5"*32;self._suffix=b"\x5a"*32
        ctypes.memmove(self.address-32,self._prefix,32)
        ctypes.memmove(self.address+size,self._suffix,32)
        if raw:ctypes.memmove(self.address,raw,len(raw))
        libc=ctypes.CDLL(None,use_errno=True)
        libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]
        libc.mprotect.restype=ctypes.c_int
        for address,extent,protection in [(start,page,0),(start+page+payload_pages,page,0)]:
            if libc.mprotect(address,extent,protection):
                raise OSError(ctypes.get_errno(),"guard native packing buffer")
        if readonly and libc.mprotect(start+page,payload_pages,mmap.PROT_READ):
            raise OSError(ctypes.get_errno(),"protect native packing input")
    def check(self):
        assert ctypes.string_at(self.address-32,32)==self._prefix
        assert ctypes.string_at(self.address+self.size,32)==self._suffix
    def read(self,offset,size):
        assert type(offset) is int and type(size) is int and 0<=offset<=self.size and 0<=size<=self.size-offset
        return ctypes.string_at(self.address+offset,size)
    def close(self):
        self._map.close()


OUT.mkdir(exist_ok=False);(OUT/"cas").mkdir()
pins={};cases=[];protocol=[];entries=[];mapping=None
def read(path):
    path=Path(path);raw=path.read_bytes()
    if path in pins:assert pins[path]==raw
    pins[path]=raw
    return raw
def save(path,value):
    path.write_text(json.dumps(value,indent=2,sort_keys=True,ensure_ascii=True)+"\n")
def cas(raw):
    raw=bytes(raw);h=sha256(raw).hexdigest();path=OUT/"cas"/(h+".zlib")
    if not path.exists():path.write_bytes(zlib.compress(raw,1))
    assert zlib.decompress(path.read_bytes())==raw
    return dict(path="cas/"+path.name,bytes=len(raw),sha256=h)
def graph(value,lease):
    nodes=[];edges=[];scalars=bytearray()
    def visit(value):
        identifier=len(nodes)+1;nodes.append([0]*8);row=nodes[-1]
        if value is None:return identifier
        if type(value) is bool:row[0]=1;row[6]=int(value);return identifier
        if type(value) is int:
            row[0]=2;row[1]=len(scalars)
            raw=abs(value).to_bytes((abs(value).bit_length()+7)//8,"little")
            row[2]=len(raw);row[6]=int(value<0);scalars.extend(raw);return identifier
        if type(value) is str:
            raw=value.encode("utf-8");row[0]=4;row[1]=len(scalars);row[2]=len(raw);row[6]=len(value);scalars.extend(raw);return identifier
        assert type(value) in (list,dict),type(value)
        row[0]=5 if type(value) is list else 6;row[3]=len(edges);row[4]=len(value);row[5]=identifier
        width=len(value)*(2 if type(value) is dict else 1)
        first=len(edges);edges.extend([0]*width)
        if type(value) is list:
            for i,v in enumerate(value):edges[first+i]=visit(v)
        else:
            for i,(k,v) in enumerate(value.items()):
                assert type(k) is str
                edges[first+2*i]=visit(k);edges[first+2*i+1]=visit(v)
        return identifier
    root=visit(value);db=64+len(nodes)*64+len(edges)*8
    for row in nodes:
        if row[0] in (2,4):row[1]+=db
    header=struct.pack("<8Q",MAGIC,lease,len(nodes),root,len(edges),len(scalars),db+len(scalars),0)
    return header+b"".join(struct.pack("<8Q",*row) for row in nodes)+b"".join(struct.pack("<Q",v) for v in edges)+scalars
def materialize(raw):
    assert len(raw)>=64
    magic,lease,nn,root,ne,nd,total,reserved=struct.unpack_from("<8Q",raw)
    assert magic==MAGIC and lease and nn and 1<=root<=nn and total==len(raw) and reserved==0
    eb=64+nn*64;db=eb+ne*8;assert db+nd==len(raw)
    active=set();memo={}
    def node(identifier):
        assert 1<=identifier<=nn
        if identifier in memo:return memo[identifier]
        assert identifier not in active,"cyclic output Graph"
        active.add(identifier)
        k,at,n,first,count,owner,aux,res=struct.unpack_from("<8Q",raw,64+(identifier-1)*64)
        assert res==0
        if k==0:
            assert (at,n,first,count,owner,aux)==(0,0,0,0,0,0);value=None
        elif k==1:
            assert (at,n,first,count,owner)==(0,0,0,0,0) and aux in (0,1);value=bool(aux)
        elif k in (2,4):
            assert db<=at<=len(raw) and n<=len(raw)-at and (first,count,owner)==(0,0,0)
            data=raw[at:at+n]
            if k==2:
                assert aux in (0,1) and (not data or data[-1]) and (data or aux==0)
                value=int.from_bytes(data,"little")*(-1 if aux else 1)
            else:value=data.decode("utf-8");assert len(value)==aux
        else:
            assert k in (5,6) and (at,n,aux)==(0,0,0) and owner
            width=count*(2 if k==6 else 1)
            assert first<=ne and width<=ne-first
            ids=struct.unpack_from("<"+str(width)+"Q",raw,eb+first*8)
            if k==5:value=[node(i) for i in ids]
            else:
                value={}
                for i in range(count):
                    key=node(ids[2*i]);assert type(key) is str and key not in value
                    value[key]=node(ids[2*i+1])
        active.remove(identifier);memo[identifier]=value;return value
    result=node(root)
    return result
def command(verified,graph_raw,mode):
    core=verified.as_dict()
    input_data=json.loads(verified.structured_bytes) if verified.structured_bytes is not None else core
    schema=input_data["schema"]
    input_code=int(schema.rsplit("v",1)[1])+(8 if ".composite." in schema else 0)
    version=int(core["schema"].rsplit("v",1)[1])
    lease,root=struct.unpack_from("<Q",graph_raw,8)[0],struct.unpack_from("<Q",graph_raw,24)[0]
    return struct.pack("<8Q",COMMAND,lease,77,mode,root,input_code,version,int(verified.structured_bytes is not None))+bytes.fromhex(verified.input_sha256)+bytes.fromhex(verified.sha256)+struct.pack("<4Q",len(graph_raw),0,0,0)
ledger=(OUT/"entries.jsonl").open("x")
def invoke(source,cmd,work,label):
    row=dict(index=len(entries)+1,label=label,state="ENTER",source=cas(source),command=cas(cmd),before=cas(work))
    ledger.write(json.dumps(row,sort_keys=True)+"\n");ledger.flush()
    a=b=c=None
    try:
        a=Buffer(len(source),source,True);b=Buffer(len(cmd),cmd,True);c=Buffer(len(work),work)
        ret=int(mapping._entry(a.address,a.size,b.address,b.size,c.address,c.size))
        a.check();b.check();c.check()
        assert a.read(0,a.size)==source and b.read(0,b.size)==cmd
        after=c.read(0,c.size)
    finally:
        if c is not None:c.close()
        if b is not None:b.close()
        if a is not None:a.close()
    row.update(state="RETURN",result=ret,after=cas(after),readonly_inputs_and_canaries_unchanged=True)
    ledger.write(json.dumps(row,sort_keys=True)+"\n");ledger.flush()
    entries.append(row);return ret,after
def success_case(label,verified,mode,lease,one_shot=False):
    data=verified.as_dict();src=graph(data,lease);cmd=command(verified,src,mode)
    expected={1:lambda:verified.report(),2:lambda:inspect_program(verified),3:lambda:data,
        4:lambda:{**verified.report(),"status":"standalone_core_checked","native_executed":False}}[mode]()
    before=len(entries);work=bytes(MIN_WORK);growth=[]
    for attempt in range(4):
        ret,work=invoke(src,cmd,work,label)
        e=struct.unpack_from("<16Q",work)
        assert e[0]==EVENT and e[2:4]==(lease,77) and e[8]==0 and e[9:]==(0,)*7,(label,ret,e)
        if ret==GROW:
            assert e[1]==1 and e[5:7]==(0,0) and e[7]>len(work)
            growth.append(e[7]);work+=bytes(e[7]-len(work));continue
        assert ret==128 and e[1]==0 and e[5]==MIN_WORK and e[7]==0
        assert e[5]+e[6]<=len(work)
        output=work[e[5]:e[5]+e[6]]
        actual=materialize(output)
        assert actual==expected,(label,mode,actual,expected)
        assert json.dumps(actual,sort_keys=True,ensure_ascii=False,separators=(",",":")).encode()==json.dumps(expected,sort_keys=True,ensure_ascii=False,separators=(",",":")).encode()
        if one_shot:
            ret0,work0=invoke(src,cmd,bytes(len(work)),label+"-one-shot")
            assert (ret0,work0)==(ret,work),(label,"GROW vs one-shot full-workspace mismatch")
        cases.append(dict(label=label,mode=mode,input_schema=json.loads(verified.structured_bytes)["schema"] if verified.structured_bytes else data["schema"],
          core_schema=data["schema"],input_sha256=verified.input_sha256,core_sha256=verified.sha256,
          raw_input=cas(verified.structured_bytes or verified.canonical_bytes),
          expected=cas(json.dumps(expected,sort_keys=True,ensure_ascii=False,separators=(",",":")).encode()),
          actual_graph=cas(output),native_entries=len(entries)-before,growth=growth,
          one_shot_full_workspace_compared=one_shot,status="PASS"))
        return src,cmd,work
    raise AssertionError((label,"too many GROW replies"))
def rewrite_word(raw,at,value):
    out=bytearray(raw);struct.pack_into("<Q",out,at,value);return bytes(out)
summary=dict(status="FAIL",scope="PRIVATE_REPORT_GRAPH_PROJECTION_ACTUAL_NATIVE_ONLY",
 whole_stack_closed=False,public_program_verification_claim=False,installed_CLI_claim=False)
try:
    read(__file__)
    manifest=json.loads(read(ROOT/"development/compile-r1/program-inspection.manifest.json"))
    source=read(manifest["source_path"]);image=read(manifest["image_path"])
    assert sha256(source).hexdigest()==manifest["source_sha256"]
    assert sha256(image).hexdigest()==manifest["image_sha256"]
    mapping=NativeHiaJsonImage(image,expected_sha256=manifest["image_sha256"])
    base=json.loads(read(REF/"examples/hia_program/counter.hia"))
    fixtures=[]
    for version in range(1,9):
        for exports in (None,[],["zulu","alpha"]):
            data=copy.deepcopy(base);data["schema"]="hepta.hia.program.v"+str(version)
            data["functions"]=[copy.deepcopy(base["functions"][0]) for _ in range(2)]
            data["functions"][0]["name"]="zulu";data["functions"][1]["name"]="alpha"
            if exports is not None:data["exports"]=exports
            fixtures.append(("primitive-v%d-exports-%s"%(version,"absent" if exports is None else "empty" if not exports else "reverse"),data))
    for typ in ("i8","i16","i32","i64","isize","u8","u16","u32","u64","usize","bool","unit"):
        p=[{"name":"arg","type":typ}]
        fn=dict(name="echo",params=copy.deepcopy(p),returns=[typ],effects=[],entry="entry",
          blocks=[dict(id="entry",params=copy.deepcopy(p),ops=[],term=dict(op="ret",values=["arg"]))])
        fixtures.append(("scalar-entry-"+typ,dict(schema="hepta.hia.program.v8",module="scalar",functions=[fn])))
    for path in sorted((REF/"examples/hia_program").glob("*.hia")):
        fixtures.append(("retained-"+path.stem,json.loads(read(path))))
    fixtures.append(("retained-recursive-composite-v2",json.loads(read(REF/"examples/hia_recursive_chain/composite_v2.json"))))
    large=copy.deepcopy(base);large["schema"]="hepta.hia.program.v8"
    large["functions"]=[]
    for i in range(1024):
        fn=copy.deepcopy(base["functions"][0]);fn["name"]="f%04d"%(1023-i)
        large["functions"].append(fn)
    fixtures.append(("maximum-functions-reverse",large))
    schema_coverage=set();core_coverage=set();last=None;lease=100
    for index,(label,document) in enumerate(fixtures):
        verified=verify_program(document)
        schema_coverage.add(document["schema"]);core_coverage.add(verified.as_dict()["schema"])
        for mode in (1,2,3,4):
            lease+=1
            last=success_case(label+"-mode-"+str(mode),verified,mode,lease,one_shot=index<2)
        save(OUT/"progress.json",dict(completed_cases=len(cases),native_entries=len(entries),last=label))
    assert core_coverage=={"hepta.hia.program.v"+str(i) for i in range(1,9)}
    assert {"hepta.hia.composite.v"+str(i) for i in range(1,5)}<=schema_coverage,schema_coverage
    small=verify_program(base);src=graph(small.as_dict(),991);cmd=command(small,src,1)
    invalid=[]
    for at,value in ((0,0),(8,0),(16,0),(24,0),(24,5),(32,0),(40,0),(40,13),(48,0),(48,9),(56,1),(128,len(src)+1),(136,1),(144,1),(152,1)):
        invalid.append(("command-%d-%d"%(at,value),src,rewrite_word(cmd,at,value)))
    invalid.extend([("short-command",src,cmd[:-1]),("long-command",src,cmd+b"\0"),
      ("primitive-hash-mismatch",src,cmd[:64]+bytes([cmd[64]^1])+cmd[65:])])
    for at,value in ((0,0),(8,992),(16,0),(16,(1<<64)-1),(24,0),(32,(1<<64)-1),(40,0),(48,len(src)+1),(56,1)):
        invalid.append(("graph-%d-%d"%(at,value),rewrite_word(src,at,value),cmd))
    invalid.append(("short-graph",src[:63],rewrite_word(cmd,128,63)))
    invalid.append(("reserved-node",rewrite_word(src,64+56,1),cmd))
    for label,s,r in invalid:
        begin=len(entries);ret,w=invoke(s,r,bytes(MIN_WORK),label)
        assert ret==BAD and struct.unpack_from("<Q",w,256)[0]==3,(label,ret)
        e=struct.unpack_from("<16Q",w);assert e[0]==EVENT and e[1]==2 and e[8]!=0
        ret2,w2=invoke(src,cmd,w,label+"-poison")
        assert ret2==BAD and struct.unpack_from("<Q",w2,256)[0]==3
        protocol.append(dict(label=label,status="PASS",native_entries=len(entries)-begin,sticky_refusal=True))
    ret,w=invoke(src,cmd,bytes(MIN_WORK),"growth-replay-source")
    assert ret==GROW
    n=struct.unpack_from("<Q",w,56)[0];w+=bytes(n-len(w))
    bad=bytearray(cmd);bad[64]^=1;bad[96]^=1
    ret,w=invoke(src,bytes(bad),w,"changed-command-after-grow")
    assert ret==BAD and struct.unpack_from("<Q",w,256)[0]==3
    protocol.append(dict(label="changed-command-after-grow",status="PASS",native_entries=2,sticky_refusal=True))
    src,cmd,done=last
    ret,poisoned=invoke(src,cmd,done,"terminal-replay")
    assert ret==BAD and struct.unpack_from("<Q",poisoned,256)[0]==3
    protocol.append(dict(label="terminal-replay",status="PASS",native_entries=1,sticky_refusal=True))
    summary.update(status="PASS",cases=len(cases),private_protocol_cases=len(protocol),
      native_entries=len(entries),full_input_schema_coverage=sorted(schema_coverage),
      full_core_schema_coverage=sorted(core_coverage),all_result_values_and_canonical_bytes_equal=True,
      source_readonly_and_guard_pages=True,terminal_and_private_refusal_poisoning=True,
      actual_B3_compiled_image=True,reference_python=sys.version,case_results=cases,protocol_results=protocol)
except BaseException as exc:
    summary.update(error_class=type(exc).__name__,error=str(exc),completed_cases=len(cases),
      completed_protocol_cases=len(protocol),native_entries=len(entries))
    (OUT/"failure.txt").write_text(traceback.format_exc())
    traceback.print_exc()
finally:
    ledger.close()
    if mapping is not None:mapping._mapping.close()
    equal=all(path.read_bytes()==raw for path,raw in pins.items())
    summary["source_and_image_before_after_equal"]=equal
    save(OUT/"source-pins.json",[{ "path":str(p),"bytes":len(raw),"sha256":sha256(raw).hexdigest()} for p,raw in pins.items()])
    if not equal:summary["status"]="FAIL"
    save(OUT/"summary.json",summary)
    print(json.dumps({k:v for k,v in summary.items() if k not in ("case_results","protocol_results")},sort_keys=True),flush=True)
if summary["status"]!="PASS":raise SystemExit(1)
