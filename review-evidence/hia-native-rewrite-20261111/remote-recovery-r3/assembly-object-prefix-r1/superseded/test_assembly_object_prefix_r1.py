"""Exact object-prefix comparisons against original snapshot and structure.
All object construction/oracles are outside actual native entry intervals.
Large production boundaries run in distinct original 90 CPU / 180 wall jobs.
"""
from pathlib import Path
from hashlib import sha256
import ctypes,json,mmap,resource,struct,sys,time,traceback,zlib
from unittest.mock import patch
BASE=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
REF=BASE/"root-recovery/reference-0ef-r2"
ROOT=BASE/"root-recovery/workspace/native-assembly-object-prefix-r1"
GROUP=sys.argv[1]
OUT=ROOT/"development"/("native-"+GROUP)
OUT.mkdir(parents=True,exist_ok=False);(OUT/"cas").mkdir()
sys.path.insert(0,str(REF));sys.dont_write_bytecode=True
from hepta import hia_program as reference
from hepta.hia_json_preflight_native import NativeHiaJsonImage
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
LIMIT=8<<20;BAD=0xfffffffd;NEED=0xfffffffe
MAGIC=int.from_bytes(b"HIAOPE01","little")
MESSAGES={1:"E_HIA_LIMIT: caller-owned tree exceeds snapshot budget",
    2:"E_HIA_LIMIT: caller-owned tree exceeds queued-node budget",
    3:"E_HIA_LIMIT: program exceeds structural budget",
    4:"E_HIA_LIMIT: program exceeds queued-node budget",
    5:"E_HIA_LIMIT: program exceeds byte budget before encoding"}
PINS={};cases=[];entries=0;mapping=None
def pin(path):
    path=Path(path).resolve();raw=path.read_bytes()
    if path in PINS:assert PINS[path]==raw
    PINS[path]=raw;return raw
def save(name,value):(OUT/name).write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def cas(raw):
    raw=bytes(raw);digest=sha256(raw).hexdigest();path=OUT/"cas"/(digest+".zlib")
    if not path.exists():path.write_bytes(zlib.compress(raw,1))
    assert zlib.decompress(path.read_bytes())==raw
    return dict(bytes=len(raw),sha256=digest,path="cas/"+path.name)
def forbidden(*args,**kwargs):raise AssertionError("host business call during actual native interval")
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
ledger=(OUT/"entries.jsonl").open("w")
def invoke(raw,output_size,work_size,label,fill=0):
    global entries
    a=b=c=None;entries+=1
    out_before=bytes([fill])*output_size;work_before=bytes([fill])*work_size
    row=dict(index=entries,label=label,status="ENTER",source=cas(raw),
        output_before=cas(out_before),work_before=cas(work_before))
    ledger.write(json.dumps(row,sort_keys=True)+"\n");ledger.flush()
    try:
        a=Buffer(len(raw),raw,True);b=Buffer(output_size,out_before);c=Buffer(work_size,work_before)
        began=time.monotonic_ns()
        with patch.object(reference,"_bounded_detached_snapshot",forbidden), \
             patch.object(reference,"_structure",forbidden), \
             patch.object(reference,"verify_program",forbidden), \
             patch.object(json,"loads",forbidden),patch.object(json,"dumps",forbidden):
            result=int(mapping._entry(a.address,a.size,b.address,b.size,c.address,c.size))
        elapsed=time.monotonic_ns()-began
        a.check();b.check();c.check();assert a.read(0,a.size)==raw
        output=b.read(0,b.size);work=c.read(0,c.size)
        row.update(status="RETURN",result=result,output=cas(output),work_after=cas(work),
            source_readonly_and_canaries_unchanged=True,native_elapsed_ns=elapsed)
    finally:
        if c is not None:c.close()
        if b is not None:b.close()
        if a is not None:a.close()
    ledger.write(json.dumps(row,sort_keys=True)+"\n");ledger.flush()
    return result,output
def run(raw,label,fill=0):
    output_size=work_size=128
    for attempt in range(3):
        result,output=invoke(raw,output_size,work_size,label+"-"+str(attempt),fill)
        event=struct.unpack_from("<16Q",output)
        assert event[0:2]==(MAGIC,1),(label,result,event)
        assert event[6]==128 and not any(event[10:]),(label,event)
        if result==NEED:
            assert event[2]==1 and event[3]==0 and event[7]==0
            assert event[4]>output_size or event[5]>work_size
            output_size=max(output_size,event[4]);work_size=max(work_size,event[5])
            continue
        if result==BAD:
            assert event[2]==3 and event[3]>0
            return dict(kind="private",reason=event[3]),event
        assert result==128 and event[2] in (0,2),(label,result,event)
        if event[2]==2:
            assert event[3] in MESSAGES and event[7]==0
            return dict(kind="error",message=MESSAGES[event[3]]),event
        assert event[3]==0 and event[7]<=LIMIT and 128+event[7]<=len(output)
        return dict(kind="canonical",bytes=output[128:128+event[7]]),event
    raise AssertionError((label,"unexpected repeated GROW"))
def original(value):
    try:
        captured=reference._bounded_detached_snapshot(value)
        reference._structure(captured)
        return dict(kind="canonical",bytes=json.dumps(captured,sort_keys=True,
            separators=(",",":"),ensure_ascii=False,allow_nan=False).encode())
    except reference.HIAProgramRejected as exc:
        return dict(kind="error",message=str(exc))
def compare(label,value,raw=None,fill=0):
    start=entries
    if raw is None:raw=json.dumps(value,ensure_ascii=False,separators=(",",":"),allow_nan=False).encode()
    expected=original(value);observed,event=run(raw,label,fill)
    assert observed==expected,(label,{k:(len(v),sha256(v).hexdigest()) if type(v)is bytes else v for k,v in observed.items()},
        {k:(len(v),sha256(v).hexdigest()) if type(v)is bytes else v for k,v in expected.items()})
    record={k:cas(v) if type(v)is bytes else v for k,v in observed.items()}
    cases.append(dict(label=label,status="PASS",kind="REFERENCE_COMPLETE_BYTES_OR_COMPLETE_ERROR",
        input=cas(raw),observation=record,event=list(event),native_entries=entries-start))
def private(label,raw):
    start=entries;observed,event=run(raw,label)
    assert observed["kind"]=="private",(label,observed)
    cases.append(dict(label=label,status="PASS",kind="PRIVATE_BAD_ISSUED_TRANSPORT",
        input=cas(raw),event=list(event),native_entries=entries-start))
def nested(depth,leaf=0):
    for _ in range(depth):leaf=[leaf]
    return leaf
def fixtures():
    if GROUP=="semantic":
        values=[None,True,False,0,-1,1,2**64-1,-(2**63),[],{},[0],{"b":2,"a":1},
            {"schema":"hepta.hia.program.v8","module":"m","functions":[]},
            {"name":"f","blocks":[],"return_loans":[None],"entry":"b"},
            {"outer":[{"z":[1,False,None],"a":{"y":2,"x":3}},{"d":4,"c":5}]},
            [[],{},[[]],{"empty":[]},[True,False,None]],
            {"true":True,"false":False,"null":None,"zero":0},
            [int("9"*640),-int("8"*640),int("7"*4300)],
            {str(i):[i,{"second":False,"first":True}] for i in range(60,0,-1)}]
        for i,value in enumerate(values):compare("value-"+str(i),value,fill=0xa3 if i%2 else 0)
        compare("negative-zero",{"z":0,"a":[0]},b'{"z":-0,"a":[-0]}')
        compare("whitespace",{"z":[0,False],"a":{}},b' { "z" : [ 0 , false ] , "a" : { } } \n')
        compare("escaped-solidus",{"x":"/"},b'{"x":"\\/"}')
        compare("unicode-escape-normalization",{"x":"é🚀"},b'{"x":"\\u00e9\\ud83d\\ude80"}')
    elif GROUP=="unicode":
        texts=["",''.join(chr(i) for i in range(32)),'\\"/',chr(127),
            "é","中","🚀","\u2028\u2029","\uffff\U00010000","\u0000a\u0000",
            "a"*4097,"🚀"*8193]
        for i,text in enumerate(texts):
            compare("unicode-value-"+str(i),{"value":text})
            compare("unicode-key-"+str(i),{text:0,"fallback":False},fill=0xc7)
        compare("codepoint-order",{"🚀":1,"\uffff":2,"é":3,"a":4,"\u007f":5,"\u0000":6})
    elif GROUP=="depth":
        for depth in (0,1,16,63,64,65,66,128,129):
            compare("depth-"+str(depth),nested(depth))
        compare("snapshot-forward-order",{"first":nested(65),"last":"small"})
        compare("structure-reverse-order",{"first":"small","last":{"second":2,"first":1}})
    elif GROUP=="nodes-at":
        compare("exact-node-budget",[None]*262143)
    elif GROUP=="nodes-over":
        compare("one-over-queued-budget",[None]*262144)
        compare("nested-queued-budget",[[None]*131071,[None]*131071])
    elif GROUP=="bytes-at":
        compare("exact-byte-budget","x"*(LIMIT-2))
    elif GROUP=="bytes-over":
        compare("one-over-byte-budget","x"*(LIMIT-1))
    elif GROUP=="snapshot-before-bytes":
        compare("snapshot-before-raw-eight-MiB",["x"*(LIMIT+10)]+[None]*262143)
    elif GROUP=="escaped-at":
        compare("escape-expanded-byte-budget","\u0000"*((LIMIT-2)//6))
    elif GROUP=="escaped-over":
        compare("escape-expanded-over-budget","\u0000"*((LIMIT-2)//6+1))
    elif GROUP=="unicode-at":
        compare("UTF8-four-byte-budget","🚀"*((LIMIT-2)//4))
    elif GROUP=="unicode-over":
        compare("UTF8-four-byte-over-budget","🚀"*((LIMIT-2)//4+1))
    elif GROUP=="private":
        for i,raw in enumerate((b"",b"[",b"]",b"[}",b"null null",b"0.5",b"NaN",
            b'{"x":1,"x":2}',b'"\\ud800"',b'"\xff"',b'{"x":}',b"truex",b'"\\"',
            b"[1,]",b'{"a":1,}',b"\x00")):
            private("malformed-"+str(i),raw)
        for output_size,work_size in ((127,128),(128,127),(0,128),(128,0)):
            start=entries;result,output=invoke(b"null",output_size,work_size,
                "short-ABI-%d-%d"%(output_size,work_size))
            assert result==BAD
            cases.append(dict(label="short-ABI-%d-%d"%(output_size,work_size),
                status="PASS",kind="PRIVATE_SHORT_ABI",native_entries=entries-start))
    else:raise AssertionError(GROUP)
summary=dict(status="FAIL",group=GROUP,scope="ISSUED_OBJECT_PREFIX_COMPONENT",
    actual_Core_admission_entries=0,actual_syntax_owner_entries=0,
    full_assembly_qualified=False,whole_stack_closed=False,installed_activation=False)
started=time.monotonic_ns()
try:
    pin(__file__)
    manifest=json.loads(pin(ROOT/"development/build-r1/manifest.json"))
    source=pin(manifest["source_path"]);image=pin(manifest["image_path"])
    assert sha256(source).hexdigest()==manifest["source_sha256"]
    assert sha256(image).hexdigest()==manifest["image_sha256"]
    assert sha256(pin(REF/"hepta/hia_program.py")).hexdigest()=="76a222745e13fe29825a661be206243f137ada7b57292b07ab7513a40146fb92"
    mapping=NativeHiaJsonImage(image,expected_sha256=manifest["image_sha256"])
    fixtures();summary.update(status="PASS",cases=len(cases),native_entries=entries)
except BaseException as exc:
    summary.update(error_class=type(exc).__name__,error=str(exc),
        completed_cases=len(cases),native_entries=entries)
    (OUT/"failure.txt").write_text(traceback.format_exc());traceback.print_exc()
finally:
    ledger.close()
    if mapping is not None:mapping._mapping.close()
    equal=all(p.is_file() and p.read_bytes()==raw for p,raw in PINS.items())
    if not equal:summary["status"]="FAIL"
    summary.update(source_and_image_before_after_equal=equal,case_results=cases,
        full_source_and_guarded_buffers_recorded=True,elapsed_ns=time.monotonic_ns()-started)
    save("source-pins.json",[dict(path=str(p),bytes=len(raw),sha256=sha256(raw).hexdigest()) for p,raw in PINS.items()])
    save("summary.json",summary)
    print("HIA_OBJECT_PREFIX_NATIVE "+json.dumps({k:v for k,v in summary.items() if k!="case_results"},sort_keys=True),flush=True)
if summary["status"]!="PASS":raise SystemExit(1)
