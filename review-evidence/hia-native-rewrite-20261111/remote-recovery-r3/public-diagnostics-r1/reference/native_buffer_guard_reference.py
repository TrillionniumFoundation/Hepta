"""Actual A-root native initial/poison/early-error continuation controls.

The program-child replies here are explicitly controlled foreign fixtures.
These cases do not execute or qualify actual program admission, publication,
the complete carrier, or the installed CLI. Every A-root entry is actual native.
"""
from pathlib import Path
from hashlib import sha256
import ctypes,json,mmap,resource,struct,sys,traceback,zlib
BASE=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
REF=BASE/"root-recovery/reference-0ef-r2"
ROOT=BASE/"root-recovery/workspace/native-program-service-root-r1"
OUT=ROOT/"development/private-native-r1"
sys.path.insert(0,str(REF));sys.dont_write_bytecode=True
from hepta.hia_json_preflight_native import NativeHiaJsonImage
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
MAG=lambda x:int.from_bytes(x,"little")
BAD=0xfffffffd;MIN_WORK=1<<20;CAPS=4096
CMD=MAG(b"HIACBI01");EVENT=MAG(b"HIACDE01");ACK=MAG(b"HIACDA01")
OUT.mkdir(exist_ok=False);(OUT/"cas").mkdir()
pins={};cases=[];entries=[];mapping=None
def pin(path):
    path=Path(path);raw=path.read_bytes()
    if path in pins:assert pins[path]==raw
    pins[path]=raw;return raw
def save(path,obj):path.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n")
def cas(raw):
    raw=bytes(raw);digest=sha256(raw).hexdigest();path=OUT/"cas"/(digest+".zlib")
    if not path.exists():path.write_bytes(zlib.compress(raw,1))
    assert zlib.decompress(path.read_bytes())==raw
    return dict(bytes=len(raw),sha256=digest,path="cas/"+path.name)
def q(raw,at):return struct.unpack_from("<Q",raw,at)[0]
def replace(raw,at,value):
    data=bytearray(raw);struct.pack_into("<Q",data,at,value);return bytes(data)
def initial(action=6,digits=4300,program=1):
    caps={0:1,1:program,2:MIN_WORK,4:128,5:2048}
    work=bytearray(MIN_WORK)
    for slot,size in caps.items():struct.pack_into("<Q",work,CAPS+slot*8,size)
    command=struct.pack("<16Q",CMD,1,1,7,1,19,action,digits,program,128,2048,16,1024,32,0,0)
    return command,bytes(work)

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
def call(command,work,label,output_bytes=128):
    row=dict(index=len(entries)+1,label=label,state="ENTER",input=cas(command),work_before=cas(work),output_bytes=output_bytes)
    ledger.write(json.dumps(row,sort_keys=True)+"\n");ledger.flush()
    a=b=c=None
    try:
        a=Buffer(len(command),command,True);b=Buffer(output_bytes);c=Buffer(len(work),work)
        result=int(mapping._entry(a.address,a.size,b.address,b.size,c.address,c.size))
        a.check();b.check();c.check();assert a.read(0,a.size)==command
        output=b.read(0,b.size);after=c.read(0,c.size)
    finally:
        if c is not None:c.close()
        if b is not None:b.close()
        if a is not None:a.close()
    row.update(state="RETURN",result=result,output=cas(output),work_after=cas(after),source_and_canaries_unchanged=True)
    ledger.write(json.dumps(row,sort_keys=True)+"\n");ledger.flush();entries.append(row)
    return result,output,after
def ack(sequence,opcode,returned=0,observed=b""):
    assert len(observed)<=256
    return struct.pack("<8Q",ACK,7,sequence,opcode,0,returned,len(observed),0)+observed
def good_initial(action,digits,program,label):
    before=len(entries);command,work=initial(action,digits,program)
    returned,frame,after=call(command,work,label)
    assert returned==128
    event=struct.unpack("<16Q",frame)
    assert event==(EVENT,15,7,1,2,1,0,min(program,(8<<20)+1),6,8,digits,0,0,0,0,0),event
    assert q(after,24)==1 and q(after,40)==15 and q(after,64)==160 and q(after,8200)==1
    cases.append(dict(label=label,status="PASS",scope="INITIAL_EVENT_ONLY",
        native_entries=len(entries)-before,program_child_executed=False))
    return command,frame,after
def bad_initial(command,work,label,output=128,poison=True):
    before=len(entries);returned,frame,after=call(command,work,label,output)
    assert returned==BAD,(label,returned)
    if poison:
        assert q(after,8200)==3 and q(after,472)!=0,(label,q(after,8200),q(after,472))
        valid,_=initial()
        returned,frame,after=call(valid,after,label+"-sticky")
        assert returned==BAD and q(after,8200)==3
    cases.append(dict(label=label,status="PASS",scope="INVALID_PRIVATE_INITIAL_OR_ACK",
        native_entries=len(entries)-before,sticky_refusal=poison,program_child_executed=False))

def foreign_error(group,error,stage,status,role,label,expected):
    before=len(entries);command,initial_work=initial()
    returned,frame,work=call(command,initial_work,label+"-begin")
    assert returned==128 and q(frame,8)==15
    event=[EVENT,7,8 if role==44 else 9,0 if role==44 else 1,group,error,stage,status,0,0,0,0,0,0,0,0]
    observed=struct.pack("<16Q",*event)+struct.pack("<4Q",0,6,role,0)
    command=ack(1,15,128,observed)
    slots={0:b"\0",1:b"x",4:bytes(128),5:bytes(2048)}
    readonly={0,1,4,5};mechanical=[];last_sequence=1
    for step in range(16):
        returned,frame,work=call(command,work,label+"-step-"+str(step))
        assert returned==128,(label,step,returned,q(work,472))
        event=struct.unpack("<16Q",frame)
        assert event[0]==EVENT and event[2]==7 and event[3]==last_sequence+1
        last_sequence=event[3];opcode=event[1];args=event[4:]
        slots[2]=work
        if opcode==2:
            slot,size=args[:2];assert slot==30 and size==128+len(expected) and not any(args[2:])
            assert slot not in readonly
            old=slots.get(slot,b"");assert size>=len(old);slots[slot]=old+bytes(size-len(old))
        elif opcode==4:
            source,at,target,to,size=args[:5]
            assert not any(args[5:]) and target==30 and target not in readonly
            assert source in slots and at+size<=len(slots[source]) and to+size<=len(slots[target])
            data=bytearray(slots[target]);data[to:to+size]=slots[source][at:at+size];slots[target]=bytes(data)
        elif opcode==6:
            slot,flag=args[:2];assert slot==30 and flag==1 and not any(args[2:])
            readonly.add(slot)
        elif opcode==18:
            assert args==(7,1,30,0,128+len(expected),0,0,0,0,0,0,0)
            assert 30 in readonly
            packet=slots[30];header=struct.unpack_from("<16Q",packet)
            assert header==(MAG(b"HIACBE01"),1,1,7,last_sequence,0,4,1,2,0,0,0,128,len(expected),len(packet),0),header
            assert packet[128:]==expected
            mechanical.append(dict(op=opcode,frame=cas(frame),packet=cas(packet)))
            cases.append(dict(label=label,status="PASS",scope="CONTROLLED_FOREIGN_REPLY_ACTUAL_NATIVE_ERROR_ENVELOPE",
              native_entries=len(entries)-before,mechanical_operations=mechanical,
              actual_program_child_entries=0,actual_carrier_processes=0,foreign_program_reply_fixture=True))
            # A final result cannot be made resumable by submitting an ACK.
            returned,_,poisoned=call(ack(last_sequence,18),work,label+"-illegal-final-resume")
            assert returned==BAD and q(poisoned,8200)==3
            cases[-1]["native_entries"]=len(entries)-before
            return
        else:raise AssertionError((label,"unexpected mechanical operation",event))
        mechanical.append(dict(op=opcode,frame=cas(frame)))
        command=ack(last_sequence,opcode)
    raise AssertionError((label,"continuation did not finish"))

summary=dict(status="FAIL",scope="A_SERVICE_ROOT_PRIVATE_INITIAL_AND_FOREIGN_REPLY_CONTROLS",
 actual_program_admission_entries=0,actual_program_projector_entries=0,actual_publication_operations=0,
 actual_fixed_carrier_processes=0,foreign_program_reply_fixtures=True,installed_CLI_claim=False,whole_stack_closed=False)
try:
    pin(__file__)
    manifest=json.loads(pin(ROOT/"development/compile-r1/program-service.manifest.json"))
    source=pin(manifest["source_path"]);image=pin(manifest["image_path"])
    assert sha256(source).hexdigest()==manifest["source_sha256"] and sha256(image).hexdigest()==manifest["image_sha256"]
    mapping=NativeHiaJsonImage(image,expected_sha256=manifest["image_sha256"])
    for action in (6,7,8):
        for digits in (0,640,4300):good_initial(action,digits,1,"begin-%d-digits-%d"%(action,digits))
    for size in (0,8<<20,(8<<20)+1,(8<<20)+2):
        good_initial(6,4300,size,"initial-program-span-"+str(size))
    command,work=initial()
    for offset,value in ((0,0),(8,0),(16,0),(16,2),(24,0),(24,(1<<64)-3),
         (32,0),(40,0),(48,5),(48,9),(56,639),(56,1<<32),
         (64,0),(72,127),(80,2047),(88,15),(96,1023),(104,31),(112,1),(120,1)):
        bad_initial(replace(command,offset,value),work,"initial-word-%d-%d"%(offset,value))
    bad_initial(command[:-1],work,"initial-short")
    bad_initial(command+b"\0",work,"initial-long")
    for offset,value in ((CAPS,0),(CAPS+16,MIN_WORK-1),(CAPS+24,1),(CAPS+5*8,1535),(32008,1)):
        bad_initial(command,replace(work,offset,value),"initial-work-%d"%offset)
    bad_initial(command,work,"short-output",output=127)
    bad_initial(command,work[:-1],"short-work",poison=False)
    _,frame,waiting=call(command,work,"ack-control-begin")
    assert q(frame,8)==15
    right=ack(1,15,128,bytes(160))
    for offset,value in ((0,0),(8,8),(16,0),(24,14),(32,1),(48,159),(56,1)):
        bad_initial(replace(right,offset,value),waiting,"ack-word-%d"%offset)
    foreign_error(7,1,0,0,44,"prefix-byte-budget",b"E_HIA_LIMIT: program exceeds byte budget")
    for stage,status in ((0,0),(1,4294967295),(1,4294967292)):
        foreign_error(7,2,stage,status,44,"prefix-json-%d-%d"%(stage,status),b"E_HIA_FORMAT: invalid/deep UTF-8 JSON")
    foreign_error(7,3,1,4294967294,44,"prefix-structural-budget",b"E_HIA_LIMIT: program exceeds structural budget before JSON allocation")
    foreign_error(7,4,2,4294967280,44,"prefix-decode-json",b"E_HIA_FORMAT: invalid/deep UTF-8 JSON")
    foreign_error(10,1,0,0,46,"prefix-collision",b"E_HIA_VERSION_COLLISION: historical nominal v2 requires import_legacy_composite_v2; the primitive v2 namespace cannot infer a producer profile")
    summary.update(status="PASS",cases=len(cases),native_entries=len(entries),
      all_source_readonly_and_guard_pages=True,case_results=cases)
except BaseException as exc:
    summary.update(error_class=type(exc).__name__,error=str(exc),completed_cases=len(cases),native_entries=len(entries))
    (OUT/"failure.txt").write_text(traceback.format_exc());traceback.print_exc()
finally:
    ledger.close()
    if mapping is not None:mapping._mapping.close()
    equal=all(path.read_bytes()==raw for path,raw in pins.items())
    if not equal:summary["status"]="FAIL"
    summary["source_and_image_before_after_equal"]=equal
    save(OUT/"source-pins.json",[dict(path=str(p),bytes=len(raw),sha256=sha256(raw).hexdigest()) for p,raw in pins.items()])
    save(OUT/"summary.json",summary)
    print(json.dumps({k:v for k,v in summary.items() if k!="case_results"},sort_keys=True),flush=True)
if summary["status"]!="PASS":raise SystemExit(1)
