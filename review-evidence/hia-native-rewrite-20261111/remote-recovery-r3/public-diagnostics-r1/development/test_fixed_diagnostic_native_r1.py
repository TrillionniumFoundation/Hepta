"""Complete fixed-diagnostic native byte oracle and hostile private frames.

The oracle reads the exact original error tables independently. Every target
entry is native; the inputs here are controlled private terminal fixtures.
This does not claim actual admission, the public carrier, or installation.
"""
from __future__ import annotations
import argparse,ast,ctypes,json,mmap,resource,struct,sys,time,traceback,zlib
from hashlib import sha256
from pathlib import Path
sys.dont_write_bytecode=True
P=argparse.ArgumentParser()
P.add_argument("--source",type=Path,required=True)
P.add_argument("--reference",type=Path,required=True)
P.add_argument("--manifest",type=Path,required=True)
P.add_argument("--out",type=Path,required=True)
P.add_argument("--group",choices=("all-fixed-messages","capacity-u64","protocol"),required=True)
A=P.parse_args();OUT=A.out.resolve();OUT.mkdir(parents=True,exist_ok=False)
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
BAD=0xfffffffd;NEED=0xfffffffe;MAX=(1<<64)-1
COMMAND=int.from_bytes(b"HIADGC01","little")
RESULT=int.from_bytes(b"HIADGT01","little")
EVENT=int.from_bytes(b"HIACDE01","little")
TABLES=[[1,{"name":"hia_composite_constructor_errors.py","bytes":1106,"sha256":"d19bd1da6a08a4e78994fb97005061279569c2bb865486f8707927b281a583db"}],[2,{"name":"hia_composite_types_native.py","bytes":22463,"sha256":"3b40690bc0164a78b96b3a46729a59c0afae0172eeae5218d264e4b9dfc65ae3"}],[3,{"name":"hia_composite_functions_errors.py","bytes":7456,"sha256":"64324171706dc1f8646b124653327bd2d84b6d1ba5f110e7f4d356993a05f604"}],[4,{"name":"hia_task_helpers_native.py","bytes":5797,"sha256":"afc071582363f01f5a98f5c247101b9d4ddee4928361f60f5c5cc7adf12ae290"}]]
GUARD_SHA="3592c74a46fec98cdf8e1999a38474e517ec87e09a3aa6aeb3259100c26d6a0a"
pins={};entries=[];cases=[];mapping=None;status="FAIL";error=None
started=time.monotonic_ns()
cpu0=resource.getrusage(resource.RUSAGE_SELF)
cpu0=cpu0.ru_utime+cpu0.ru_stime
def digest(raw):return sha256(raw).hexdigest()
def pin(path):
    path=Path(path).resolve();raw=path.read_bytes()
    if path in pins:assert pins[path]==raw
    pins[path]=raw;return raw
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def cas(raw):
    raw=bytes(raw);key=digest(raw);path=OUT/"cas"/(key+".zlib")
    path.parent.mkdir(exist_ok=True)
    if not path.exists():path.write_bytes(zlib.compress(raw,1))
    assert zlib.decompress(path.read_bytes())==raw
    return dict(bytes=len(raw),sha256=key,path="cas/"+path.name)
def command(group,error,parent=7,sequence=11,child_sequence=19,request=23,digests=None):
    child=parent+2
    if digests is None:digests=(0x0123456789abcdef,0xfedcba9876543210,0x8081828384858687,MAX)
    frame=struct.pack("<16Q",EVENT,7,child,child_sequence,group,error,request,31,37,41,43,0,*digests)
    return struct.pack("<8Q",COMMAND,1,parent,sequence,child,child_sequence,46,0)+frame
def replace(raw,at,value):
    out=bytearray(raw);struct.pack_into("<Q",out,at,value);return bytes(out)
def expected(request,text):
    p=struct.unpack("<24Q",request)
    header=struct.pack("<12Q",RESULT,1,p[2],p[3],p[4],p[5],p[12],p[13],p[14],
                       len(text),128+len(text),0)+request[160:192]
    assert len(header)==128
    return header+text

LEDGER=(OUT/"native-entries.jsonl").open("w")
def invoke(label,request,output_bytes,work_bytes,output_fill=0xa5,work_fill=0x39):
    before_work=bytes([work_fill])*work_bytes
    before_output=bytes([output_fill])*output_bytes
    row=dict(index=len(entries)+1,label=label,state="ENTER",input=cas(request),
             output_before=cas(before_output),workspace_before=cas(before_work))
    LEDGER.write(json.dumps(row,sort_keys=True)+"\n");LEDGER.flush()
    aa=bb=cc=None
    try:
        aa=Buffer(len(request),request,True)
        bb=Buffer(output_bytes,before_output)
        cc=Buffer(work_bytes,before_work)
        result=int(mapping._entry(aa.address,aa.size,bb.address,bb.size,cc.address,cc.size))
        aa.check();bb.check();cc.check()
        source_after=aa.read(0,aa.size)
        output=bb.read(0,bb.size);work=cc.read(0,cc.size)
        assert source_after==request
    finally:
        if cc is not None:cc.close()
        if bb is not None:bb.close()
        if aa is not None:aa.close()
    row.update(state="RETURN",returned=result,input_after=cas(source_after),
               output_after=cas(output),workspace_after=cas(work),all_canaries_unchanged=True)
    LEDGER.write(json.dumps(row,sort_keys=True)+"\n");LEDGER.flush();entries.append(row)
    if work_bytes>ROM_BYTES:assert work[ROM_BYTES:]==before_work[ROM_BYTES:]
    return result,output
def valid_case(label,request,text,capacity,work_extra=0):
    before=len(entries);wanted=expected(request,text)
    result,actual=invoke(label,request,capacity,ROM_BYTES+work_extra)
    if capacity<128:
        assert result==BAD and actual==bytes([0xa5])*capacity
    elif capacity<len(wanted):
        assert result==NEED
        assert actual==wanted[:128]+bytes([0xa5])*(capacity-128)
    else:
        assert result==len(wanted)
        assert actual==wanted+bytes([0xa5])*(capacity-len(wanted))
    cases.append(dict(label=label,entries=len(entries)-before,result=result,complete_buffer_equal=True))
def bad_case(label,request,work_bytes=None):
    if work_bytes is None:work_bytes=ROM_BYTES
    result,actual=invoke(label,request,128,work_bytes)
    assert result==BAD and actual==bytes([0xa5])*128,label
    cases.append(dict(label=label,entries=1,result=result,complete_buffer_equal=True))
try:
    pin(__file__)
    source=A.source.resolve();reference=A.reference.resolve()
    guard=pin(source/"reference/native_buffer_guard_reference.py")
    assert digest(guard)==GUARD_SHA
    tree=ast.parse(guard)
    guards=[n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=="Buffer"]
    assert len(guards)==1
    # Only the exact guard class is defined. No old test body or target runs.
    exec(compile(ast.Module(body=guards,type_ignores=[]),"exact-native-buffer-guard","exec"),globals())
    oracle=[]
    for group,row in TABLES:
        raw=pin(source/"reference"/row["name"])
        assert digest(raw)==row["sha256"] and len(raw)==row["bytes"]
        tree=ast.parse(raw)
        tables=[n.value for n in tree.body if isinstance(n,ast.Assign)
                and any(isinstance(t,ast.Name) and t.id=="ERRORS" for t in n.targets)]
        assert len(tables)==1
        table=ast.literal_eval(tables[0])
        for number,pair in sorted(table.items()):
            oracle.append((group,number,(pair[0]+": "+pair[1]).encode("utf-8")))
    outer=pin(source/"reference/hia_composite_outer_native.py")
    assert digest(outer)=="9947a9efce8e9bc95ff9b9328b1d30973557a40a5b22172e62d44166c6e3b594"
    assert b"elaborated program exceeds core inventory budget" in outer
    oracle.append((5,1,b"E_HIA_LIMIT: elaborated program exceeds core inventory budget"))
    assert len(oracle)==181 and len({(g,c) for g,c,_ in oracle})==181
    save(OUT/"complete-original-text-oracle.json",[
      dict(group=g,error=c,text=text.decode("utf-8"),bytes=len(text),sha256=digest(text)) for g,c,text in oracle])
    manifest=json.loads(pin(A.manifest))
    hia=pin(manifest["source_path"]);binary=pin(manifest["image_path"])
    assert manifest["fresh_actual_B3"] is True and manifest["label"]=="fixed-catalog"
    assert (len(hia),digest(hia))==(manifest["source_bytes"],manifest["source_sha256"])
    assert (len(binary),digest(binary))==(manifest["image_bytes"],manifest["image_sha256"])
    inventory=json.loads(pin(manifest["inventory_path"]))
    ROM_BYTES=inventory["ROM_bytes"]
    assert 0<ROM_BYTES<=32768 and inventory["groups"]==[1,2,3,4,5]
    sys.path.insert(0,str(reference))
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    mapping=NativeHiaJsonImage(binary,expected_sha256=digest(binary))
    if A.group=="all-fixed-messages":
        for group,number,text in oracle:
            request=command(group,number)
            base="original-group%d-error%d"%(group,number)
            before=len(entries)
            for suffix,capacity in (("measure",128),("exact",128+len(text)),("extra",145+len(text))):
                # One semantic case retains all three separate native entries.
                wanted=expected(request,text)
                result,actual=invoke(base+"-"+suffix,request,capacity,ROM_BYTES)
                if capacity<len(wanted):
                    assert result==NEED and actual==wanted[:128]
                else:
                    assert result==len(wanted) and actual==wanted+bytes([0xa5])*(capacity-len(wanted))
            cases.append(dict(label=base,entries=len(entries)-before,complete_buffer_equal=True))
        assert len(cases)==181 and len(entries)==543
    elif A.group=="capacity-u64":
        group,number,text=max(oracle,key=lambda row:len(row[2]))
        request=command(group,number);needed=128+len(text)
        for capacity in (0,1,127,128,needed-1,needed,needed+1,needed+128):
            valid_case("capacity-"+str(capacity),request,text,capacity)
        valid_case("extra-work-unchanged",request,text,needed,17)
        valid_case("full-u64-max",command(group,number,parent=MAX-3,sequence=MAX,
                   child_sequence=MAX,request=MAX,digests=(MAX,MAX,MAX,MAX)),text,needed)
        valid_case("u64-high-bit",command(group,number,sequence=1<<63,
                   child_sequence=(1<<63)+1,request=(1<<63)+2),text,needed)
        assert len(cases)==11 and len(entries)==11
    else:
        good=command(1,1)
        fields=((0,0),(8,0),(8,2),(16,0),(16,MAX-2),(24,0),(32,8),(40,0),
                (48,44),(48,0),(56,1),(64,0),(72,8),(80,8),(88,20),(96,0),
                (96,6),(96,9),(96,10),(104,0),(104,999),(104,1<<32))
        for at,value in fields:bad_case("frame-word-%d-%d"%(at,value),replace(good,at,value))
        for size in (0,63,191):bad_case("source-short-"+str(size),good[:size])
        bad_case("source-long",good+b"\0")
        for size in (0,ROM_BYTES-1):bad_case("workspace-short-"+str(size),good,size)
        unknown=((1,15),(2,51),(3,18),(3,19),(3,66),(3,199),(3,224),
                 (3,1000),(3,1020),(3,1199),(3,1207),(4,4),(5,2))
        for group,number in unknown:bad_case("undefined-error-%d-%d"%(group,number),command(group,number))
        assert len(cases)==41 and len(entries)==41
    assert all(path.read_bytes()==raw for path,raw in pins.items())
    cpu=resource.getrusage(resource.RUSAGE_SELF);cpu=cpu.ru_utime+cpu.ru_stime-cpu0
    assert cpu<90 and time.monotonic_ns()-started<180000000000
    status="PASS"
except BaseException as exc:
    error=dict(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    LEDGER.close()
    if mapping is not None:mapping._mapping.close()
    unchanged=all(path.read_bytes()==raw for path,raw in pins.items())
    if not unchanged:status="FAIL"
    cpu=resource.getrusage(resource.RUSAGE_SELF);cpu=cpu.ru_utime+cpu.ru_stime-cpu0
    summary=dict(schema="hia-fixed-diagnostic-native-private-qualification-v1",status=status,group=A.group,
      cases=len(cases),native_entries=len(entries),case_results=cases,error=error,
      complete_expected_suite_bytes_compared=(status=="PASS"),all_source_readonly_and_guard_pages=(status=="PASS"),
      source_and_image_before_after_equal=unchanged,elapsed_ns=time.monotonic_ns()-started,
      measured_self_CPU_seconds=cpu,limits=dict(CPU_seconds=90,wall_seconds=180,address_bytes=1<<30),
      controlled_private_terminal_fixtures=True,actual_program_admission_entries=0,
      actual_A_carrier_entries=0,installed_activation=False,whole_public_diagnostics_closed=False,
      whole_stack_closed=False,open_original_groups=[6,9])
    save(OUT/"source-pins.json",[dict(path=str(p),bytes=len(raw),sha256=digest(raw)) for p,raw in pins.items()])
    save(OUT/"summary.json",summary)
    print("HIA_FIXED_DIAGNOSTIC_NATIVE "+json.dumps({k:v for k,v in summary.items() if k!="case_results"},sort_keys=True),flush=True)
if status!="PASS":raise SystemExit(1)
