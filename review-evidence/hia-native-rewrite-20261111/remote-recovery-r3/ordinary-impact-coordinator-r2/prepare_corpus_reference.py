"""Exact ordinary preparation against the independent complete original helper.
Actual Core/request admission precedes every semantic fixture. Native execution
owns edit decisions, original ordered diagnostics and complete candidate bytes.
Candidate Core/interface qualification remains a later ordinary pipeline stage.
"""
from pathlib import Path
from hashlib import sha256
import ctypes,json,mmap,resource,struct,sys,time,traceback,zlib
from unittest.mock import patch
BASE=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
REF=BASE/"root-recovery/reference-0ef-r2"
ROOT=BASE/"root-recovery/workspace/native-ordinary-patch-prepare-r1"
GROUP=sys.argv[1]
OUT=ROOT/"development"/("native-"+GROUP)
OUT.mkdir(parents=True,exist_ok=False);(OUT/"cas").mkdir()
sys.path.insert(0,str(REF));sys.dont_write_bytecode=True
from hepta import hia_program as reference
from hepta import hia_program_tools as patch_reference
from copy import deepcopy
import hashlib
from hepta.hia_json_preflight_native import NativeHiaJsonImage
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
LIMIT=8<<20;BAD=0xfffffffd;NEED=0xfffffffe
MAGIC=int.from_bytes(b"HIAPPE01","little")
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
    a=b=c=None;entries+=1;result=None;output=None
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
             patch.object(patch_reference,"_prepare_program_patch",forbidden), \
             patch.object(patch_reference,"apply_program_patch",forbidden), \
             patch.object(patch_reference,"decode_json",forbidden), \
             patch.object(patch_reference,"bounded_json_wire",forbidden), \
             patch.object(patch_reference,"_check_patch_interface",forbidden), \
             patch.object(patch_reference,"function_signature",forbidden), \
             patch.object(hashlib,"sha256",forbidden), \
             patch.object(json,"loads",forbidden),patch.object(json,"dumps",forbidden):
            result=int(mapping._entry(a.address,a.size,b.address,b.size,c.address,c.size))
        row.update(result=result,native_elapsed_ns=time.monotonic_ns()-began)
        output=b.read(0,b.size);work=c.read(0,c.size);source_after=a.read(0,a.size)
        guards={name:dict(prefix=ctypes.string_at(value.address-32,32).hex(),
            suffix=ctypes.string_at(value.address+value.size,32).hex())
            for name,value in (("source",a),("output",b),("work",c))}
        row.update(output=cas(output),work_after=cas(work),source_after=cas(source_after),
            observed_guards=guards)
        a.check();b.check();c.check();assert source_after==raw
        row.update(status="RETURN",source_readonly_and_canaries_unchanged=True)
    except BaseException as exc:
        row.update(status="FAIL",error_class=type(exc).__name__,error=str(exc))
        raise
    finally:
        # Preserve all available after-buffers and guards before assertion
        # failures can leave the interval. SIGKILL still retains durable ENTER.
        for name,value in (("source",a),("output",b),("work",c)):
            if value is not None:
                field={"source":"source_after","output":"output","work":"work_after"}[name]
                if field not in row:row[field]=cas(value.read(0,value.size))
        ledger.write(json.dumps(row,sort_keys=True)+"\n");ledger.flush()
        if c is not None:c.close()
        if b is not None:b.close()
        if a is not None:a.close()
    return result,output
def run(raw,label,fill=0):
    output_size=work_size=128
    for attempt in range(3):
        result,output=invoke(raw,output_size,work_size,label+"-"+str(attempt),fill)
        event=struct.unpack_from("<16Q",output)
        assert event[0:2]==(MAGIC,1),(label,result,event)
        assert event[6]==128 and not any(event[12:]),(label,event)
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
            assert 1<=event[3]<=22 and event[7]>0 and 128+event[7]<=len(output)
            return dict(kind="error",message=output[128:128+event[7]].decode("utf-8")),event
        assert event[3]==0 and 128+event[7]<=len(output)
        return dict(kind="candidate",bytes=output[128:128+event[7]],schema=event[8],policy=event[9],edits=event[10]),event
    raise AssertionError((label,"unexpected repeated GROW"))

import os
from hepta import hia_core_patch_native as patch_native
oracle_calls=0
reference_admissions=0
request_admissions=0
maximum_candidate_bytes=0
semantic_ids=set()
expected_inventory=[]
later_results=[]
def ordered(value,ascii=False):
    return json.dumps(value,sort_keys=False,separators=(",",":"),ensure_ascii=ascii,allow_nan=False).encode()
def function(name="main",value=0,typ="u32",operations=1,long_names=False,returns=True):
    ops=[]
    previous=None
    for i in range(operations):
        variable=("v%05d"%i).ljust(128,"x") if long_names else "v"+str(i)
        if long_names and i:
            op={"op":"int.add.wrap","args":[previous,previous],"out":[{"name":variable,"type":typ}],"attrs":{}}
        else:
            op={"op":"const","args":[],"out":[{"name":variable,"type":typ}],"attrs":{"value":value}}
        ops.append(op);previous=variable
    return {"name":name,"params":[],"returns":[typ] if returns else [],"effects":[],"entry":"entry",
        "blocks":[{"id":"entry","params":[],"ops":ops,"term":{"op":"ret","values":[previous] if returns else []}}]}
def program(functions=None,version=8):
    return {"schema":"hepta.hia.program.v"+str(version),"module":"ordinary_patch",
        "functions":[function()] if functions is None else functions}
def operation(value=7,name="main",index=0):
    return {"action":"replace_operation","function":name,"block":"entry","index":index,
        "operation":{"op":"const","args":[],"out":[{"name":"v"+str(index),"type":"u32"}],"attrs":{"value":value}}}
def terminator(name="main"):
    return {"action":"replace_terminator","function":name,"block":"entry","term":{"op":"ret","values":["v0"]}}
def whole(name="main",definition=None,add=False):
    return {"action":"add_function" if add else "replace_function","function":name,
        "definition":function(name,11) if definition is None else deepcopy(definition)}
def packet(original,edits=None,version=2,policy="preserve"):
    result={"schema":"hepta.hia.patch.v"+str(version),"expected_sha256":original.sha256,
        "edits":[operation()] if edits is None else deepcopy(edits)}
    if version==2:result["interface_policy"]=policy
    return result
def mutated(original,mutator,edits=None,version=2):
    value=packet(original,edits,version);mutator(value);return value
def reverse_maps(value):
    if type(value) is dict:return {k:reverse_maps(v) for k,v in reversed(tuple(value.items()))}
    if type(value) is list:return [reverse_maps(v) for v in value]
    return value
def values_count(value):
    total=0;stack=[value]
    while stack:
        current=stack.pop();total+=1
        if type(current)is dict:stack.extend(current.values())
        elif type(current)is list:stack.extend(current)
    return total
def prepare_case(label,document,request_builder,wire_transform=None,later=None):
    global oracle_calls,reference_admissions,request_admissions,maximum_candidate_bytes
    original=reference.verify_program(document);reference_admissions+=1
    request=request_builder(original)
    request_wire=ordered(request)
    if wire_transform is not None:request_wire=wire_transform(request_wire,request)
    assert len(original.canonical_bytes)<=LIMIT and len(request_wire)<=LIMIT
    decoded=patch_reference.decode_json(request_wire);request_admissions+=1
    assert ordered(decoded)==ordered(request),(label,"request transform changed value")
    try:
        with patch.object(patch_native,"selected_prepare_patch",return_value=None):
            candidate,schema,policy,edit_count=patch_reference._prepare_program_patch(original,request_wire)
        expected=dict(kind="candidate",bytes=ordered(candidate),
            schema=1 if schema=="hepta.hia.patch.v1" else 2,
            policy=0 if policy=="preserve" else 1,edits=edit_count)
        assert schema in ("hepta.hia.patch.v1","hepta.hia.patch.v2") and policy in ("preserve","migrate")
    except patch_reference.HIAEditRejected as exc:
        candidate=None;expected=dict(kind="error",message=str(exc))
    oracle_calls+=1
    raw=b"["+original.canonical_bytes+b","+request_wire+b"]"
    assert len(raw)<=16777219
    expected_row={k:(cas(v) if type(v)is bytes else v) for k,v in expected.items()}
    save("expected-%04d.json"%(len(cases)+1),dict(label=label,
        original_canonical=cas(original.canonical_bytes),request_wire=cas(request_wire),
        actual_original_sha256=original.sha256,expected=expected_row,envelope=cas(raw),
        original_Core_admission_actual=True,request_decode_actual=True))
    start=entries
    observed,event=run(raw,label,fill=0xc7 if len(cases)%2 else 0)
    describe=lambda value:{k:(len(v),sha256(v).hexdigest()) if type(v)is bytes else v for k,v in value.items()}
    assert observed==expected,(label,describe(observed),describe(expected),event)
    row=dict(label=label,status="PASS",kind=observed["kind"],
        native_entries=entries-start,full_result_bytes_equal=True,
        exact_reference_prepare=True,actual_original_admission=True,actual_request_decode=True)
    if candidate is not None:
        maximum_candidate_bytes=max(maximum_candidate_bytes,len(observed["bytes"]))
        assert event[11]==edit_count
        row.update(candidate_bytes=len(observed["bytes"]),candidate_values=values_count(candidate),
            candidate_function_count=len(candidate["functions"]))
        if later is not None:
            try:
                checked=reference.verify_program(candidate)
            except reference.HIAProgramRejected as exc:
                after=dict(status="REJECTED_AT_LATER_REFERENCE_CORE",message=str(exc))
            else:
                try:
                    changed=patch_reference._check_patch_interface(original,checked,policy)
                except patch_reference.HIAEditRejected as exc:
                    after=dict(status="REJECTED_AT_LATER_REFERENCE_INTERFACE",message=str(exc))
                else:after=dict(status="ACCEPTED_BY_LATER_REFERENCE_CORE_AND_INTERFACE",interface_changes=changed)
            assert after["status"]==later,(label,after,later)
            row["later_reference_stage"]=after;later_results.append(dict(label=label,**after))
    else:
        semantic_ids.add(event[3]);row["diagnostic_id"]=event[3]
    cases.append(row)
    return observed,row,raw,event
def small_plan():
    result=[]
    def add(label,request_builder,document=None,wire=None,later=None):
        result.append((label,program() if document is None else document,request_builder,wire,later))
    if GROUP=="semantic":
        for core in range(1,9):
            for version,policy in ((1,"preserve"),(2,"preserve"),(2,"migrate")):
                for action in ("replace_function","add_function","replace_operation","replace_terminator"):
                    edit={"replace_function":whole(),"add_function":whole("new_function",add=True),
                        "replace_operation":operation(),"replace_terminator":terminator()}[action]
                    add("core%d-patch%d-%s-%s"%(core,version,policy,action),
                        lambda original,e=edit,v=version,p=policy:packet(original,[e],v,p),program(version=core))
        add("same-whole-no-op",lambda o:packet(o,[whole(definition=function())]))
        add("reverse-definition-field-order",lambda o:packet(o,[whole(definition=reverse_maps(function()))]))
        reversed_op=reverse_maps(operation())
        add("reverse-operation-field-order",lambda o:packet(o,[reversed_op]))
        reversed_term=reverse_maps(terminator())
        add("reverse-terminator-field-order",lambda o:packet(o,[reversed_term]))
        add("definition-name-only-prepares-before-Core",lambda o:packet(o,[whole(definition={"name":"main"})]),
            later="REJECTED_AT_LATER_REFERENCE_CORE")
        op=operation();op["operation"]=None
        add("null-operation-prepares-before-Core",lambda o:packet(o,[op]),later="REJECTED_AT_LATER_REFERENCE_CORE")
        term=terminator();term["term"]=[]
        add("array-terminator-prepares-before-Core",lambda o:packet(o,[term]),later="REJECTED_AT_LATER_REFERENCE_CORE")
        migrate=whole(definition=function(typ="u64"))
        add("preserve-interface-is-later",lambda o:packet(o,[migrate]),later="REJECTED_AT_LATER_REFERENCE_INTERFACE")
        add("migrate-interface-is-later",lambda o:packet(o,[migrate],policy="migrate"),
            later="ACCEPTED_BY_LATER_REFERENCE_CORE_AND_INTERFACE")
        unicode_op=operation();unicode_op["operation"]["attrs"]["value"]="汉字😀\x00\b\f\n\r\t\"\\"
        add("raw-Unicode-and-controls-in-unadmitted-operation",lambda o:packet(o,[unicode_op]),
            later="REJECTED_AT_LATER_REFERENCE_CORE")
        add("escaped-Unicode-and-controls-in-unadmitted-operation",lambda o:packet(o,[unicode_op]),
            wire=lambda raw,value:ordered(value,True),later="REJECTED_AT_LATER_REFERENCE_CORE")
        add("negative-zero-operation-index",lambda o:packet(o,[operation(index=0)]),
            wire=lambda raw,value:raw.replace(b'"index":0',b'"index":-0'))
        add("negative-zero-inserted-value",lambda o:packet(o,[operation(value=0)]),
            wire=lambda raw,value:raw.replace(b'"value":0',b'"value":-0'))
        add("raw-request-whitespace",lambda o:packet(o),wire=lambda raw,value:b" \r\n\t"+raw+b"\n ")
        add("all-64-unique-operation-edits",lambda o:packet(o,[operation(i,index=i) for i in range(64)]),
            program([function(operations=64)]))
        add("whole-and-local-different-functions",lambda o:packet(o,[whole(),operation(name="second")]),
            program([function(),function("second")]))
        add("reverse-request-key-order",lambda o:reverse_maps(packet(o)))
        assert len(result)==113
        return result
    if GROUP!="errors":return result
    add("01-request-null",lambda o:None)
    add("02-patch-extra-key",lambda o:mutated(o,lambda p:p.update(extra=0)))
    add("03-invalid-interface-policy",lambda o:mutated(o,lambda p:p.update(interface_policy="automatic")))
    add("04-unknown-schema",lambda o:mutated(o,lambda p:p.update(schema="hepta.hia.patch.v3")))
    add("05-invalid-digest-spelling",lambda o:mutated(o,lambda p:p.update(expected_sha256="g"*64)))
    add("06-stale-digest",lambda o:mutated(o,lambda p:p.update(expected_sha256=("1" if p["expected_sha256"][0]!="1" else "0")+p["expected_sha256"][1:])))
    add("07-empty-edits",lambda o:packet(o,[]))
    add("08-edit-primitive",lambda o:packet(o,[0]))
    fn=whole();fn["extra"]=0
    add("09-function-edit-shape",lambda o:packet(o,[fn]))
    op=operation();op["extra"]=0
    add("10-operation-edit-shape",lambda o:packet(o,[op]))
    term=terminator();term["extra"]=0
    add("11-terminator-edit-shape",lambda o:packet(o,[term]))
    add("12-unknown-action",lambda o:packet(o,[{"action":"remove_function"}]))
    op_fn=operation();op_fn["function"]=False
    add("13-function-not-string",lambda o:packet(o,[op_fn]))
    add("14-added-function-exists",lambda o:packet(o,[whole(add=True)]))
    add("15-function-not-found",lambda o:packet(o,[whole("missing")]))
    add("16-definition-identity",lambda o:packet(o,[whole(definition={"name":"other"})]))
    add("17-whole-local-overlap",lambda o:packet(o,[whole(),operation()]))
    op_block=operation();op_block["block"]=False
    add("18-block-not-string",lambda o:packet(o,[op_block]))
    op_missing=operation();op_missing["block"]="missing"
    add("19-block-not-found",lambda o:packet(o,[op_missing]))
    add("20-index-bool",lambda o:packet(o,[operation(index=False)]))
    add("21-duplicate-operation",lambda o:packet(o,[operation(),operation()]))
    add("22-duplicate-terminator",lambda o:packet(o,[terminator(),terminator()]))
    add("request-array",lambda o:[])
    add("request-string",lambda o:"request")
    add("patch-missing-digest",lambda o:mutated(o,lambda p:p.pop("expected_sha256")))
    add("v2-missing-policy",lambda o:mutated(o,lambda p:p.pop("interface_policy")))
    add("policy-bool",lambda o:mutated(o,lambda p:p.update(interface_policy=True)))
    add("schema-array",lambda o:mutated(o,lambda p:p.update(schema=[])))
    for label,value in (("digest-null",None),("digest-int",7),("digest-short","0"*63),
        ("digest-long","0"*65),("digest-uppercase","A"*64)):
        add(label,lambda o,v=value:mutated(o,lambda p:p.update(expected_sha256=v)))
    add("invalid-last-hex-before-stale-prefix",lambda o:mutated(o,lambda p:p.update(
        expected_sha256=("1" if p["expected_sha256"][0]!="1" else "0")+p["expected_sha256"][1:63]+"G")))
    add("edits-map",lambda o:mutated(o,lambda p:p.update(edits={})))
    add("edits-65",lambda o:packet(o,[operation()]*65))
    add("edit-missing-action",lambda o:packet(o,[{}]))
    add("edit-action-bool",lambda o:packet(o,[{"action":True}]))
    add("unknown-action-before-shape",lambda o:packet(o,[{"action":"unknown","alien":True}]))
    int_fn=operation();int_fn["function"]=0
    add("function-integer",lambda o:packet(o,[int_fn]))
    add("definition-name-wrong-type",lambda o:packet(o,[whole(definition={"name":0})]))
    add("definition-list",lambda o:packet(o,[whole(definition=[])]))
    bad_whole=whole(definition={"name":"wrong"})
    add("local-before-whole-invalid-definition",lambda o:packet(o,[operation(),bad_whole]))
    add("whole-before-local-invalid-block",lambda o:packet(o,[whole(),op_block]))
    add("existing-add-before-invalid-definition",lambda o:packet(o,[whole(definition=[],add=True)]))
    add("missing-function-before-invalid-definition",lambda o:packet(o,[whole("missing",definition=[])]))
    add("boolean-equal-index-before-duplicate",lambda o:packet(o,[operation(),operation(index=False)]))
    for label,value in (("negative-index",-1),("huge-index",2**256),("index-string","0"),("index-out-of-range",1)):
        add(label,lambda o,v=value:packet(o,[operation(index=v)]))
    int_block=operation();int_block["block"]=7
    add("block-integer",lambda o:packet(o,[int_block]))
    bad_block_index=deepcopy(op_missing);bad_block_index["index"]=False
    add("missing-block-before-invalid-index",lambda o:packet(o,[bad_block_index]))
    add("duplicate-whole",lambda o:packet(o,[whole(),whole()]))
    add("add-before-local",lambda o:packet(o,[whole("new_function",add=True),operation(name="new_function")]))
    add("duplicate-add-before-overlap",lambda o:packet(o,[whole("new_function",add=True),whole("new_function",add=True)]))
    add("local-operation-before-whole",lambda o:packet(o,[operation(),whole()]))
    add("local-terminator-before-whole",lambda o:packet(o,[terminator(),whole()]))
    assert len(result)==58,len(result)
    return result

PRIVATE_RAWS=(
 b"",b"[",b"]",b"[}",b"null null",b"0.5",b"NaN",b'{"x":1,"x":2}',
 b'"\\ud800"',b'"\xff"',b'{"x":}',b"truex",b"[1,]",b'{"a":1,}',b"\x00",
 b"[]",b"[{},{}]",b"[{},{},null]",b"[null,{}]",b'[{"functions":0},{}]')
COUNTS={"semantic":113,"errors":58,"private":32,"functions-1024":1,"large-bytes":1,"large-nodes":1}
def private_case(label,raw):
    start=entries
    save("expected-%04d.json"%(len(cases)+1),dict(label=label,scope="PRIVATE_TRANSPORT",
        envelope=cas(raw),expected="BAD_PRIVATE_NOT_PUBLIC_EDIT_ERROR"))
    observed,event=run(raw,label,fill=0xc7)
    assert observed["kind"]=="private" and event[2]==3,(label,observed,event)
    cases.append(dict(label=label,status="PASS",kind="private",native_entries=entries-start,
        expected_status_checked=True,whole_buffers_recorded=True))
def short_case(label,output_size,work_size):
    start=entries
    result,output=invoke(b"null",output_size,work_size,label,0x81)
    assert result==BAD
    cases.append(dict(label=label,status="PASS",kind="private-short",native_entries=entries-start,
        expected_status_checked=True,whole_buffers_recorded=True))
def capacity_case(label,raw,expected,baseline,which):
    output_size,work_size=baseline[4],baseline[5]
    if which=="output-short":output_size-=1
    if which=="work-short":work_size-=1
    start=entries
    result,output=invoke(raw,output_size,work_size,label,0xb3)
    event=struct.unpack_from("<16Q",output)
    assert event[:2]==(MAGIC,1) and event[6]==128 and not any(event[12:])
    if which=="exact":
        assert result==128 and event[2] in (0,2)
        payload=output[128:128+event[7]]
        if expected["kind"]=="candidate":
            assert event[2:4]==(0,0) and payload==expected["bytes"]
            assert (event[8],event[9],event[10])==(expected["schema"],expected["policy"],expected["edits"])
        else:
            assert event[2]==2 and payload.decode()==expected["message"]
    else:
        assert result==NEED and event[2:4]==(1,0) and event[7]==0
        assert event[4]>output_size or event[5]>work_size
    cases.append(dict(label=label,status="PASS",kind="private-capacity",native_entries=entries-start,
        expected_status_checked=True,whole_buffers_recorded=True))
def execute_group():
    global expected_inventory
    if GROUP in ("semantic","errors"):
        plan=small_plan()
        expected_inventory=[item[0] for item in plan]
        save("planned-inventory.json",dict(group=GROUP,labels=expected_inventory,expected=COUNTS[GROUP]))
        for item in plan:prepare_case(*item)
        if GROUP=="errors":assert semantic_ids==set(range(1,23)),semantic_ids
    elif GROUP=="private":
        labels=["private-transport-"+str(i) for i in range(len(PRIVATE_RAWS))]
        shorts=((127,128),(128,127),(0,128),(128,0))
        labels+=["short-ABI-%d-%d"%sizes for sizes in shorts]
        labels+=["capacity-valid-source","capacity-error-source"]
        labels+=[kind+"-"+which for kind in ("candidate","diagnostic") for which in ("exact","output-short","work-short")]
        expected_inventory=labels
        save("planned-inventory.json",dict(group=GROUP,labels=labels,expected=32))
        for i,raw in enumerate(PRIVATE_RAWS):private_case("private-transport-"+str(i),raw)
        for sizes in shorts:short_case("short-ABI-%d-%d"%sizes,*sizes)
        valid,_,valid_raw,valid_event=prepare_case("capacity-valid-source",program(),lambda o:packet(o))
        error,_,error_raw,error_event=prepare_case("capacity-error-source",program(),lambda o:packet(o,[operation(),operation()]))
        for kind,raw,expected,event in (("candidate",valid_raw,valid,valid_event),("diagnostic",error_raw,error,error_event)):
            for which in ("exact","output-short","work-short"):
                capacity_case(kind+"-"+which,raw,expected,event,which)
    elif GROUP=="functions-1024":
        label="1024-admitted-functions-plus-64-additions"
        expected_inventory=[label];save("planned-inventory.json",dict(group=GROUP,labels=expected_inventory,expected=1))
        document=program([function("f%04d"%i) for i in range(1024)])
        observed,row,_,_=prepare_case(label,document,
            lambda o:packet(o,[whole("new%04d"%i,add=True) for i in range(64)]),
            later="REJECTED_AT_LATER_REFERENCE_CORE")
        assert row["candidate_function_count"]==1088 and observed["kind"]=="candidate"
        assert row["later_reference_stage"]["message"].startswith("E_HIA_LIMIT:")
    elif GROUP in ("large-bytes","large-nodes"):
        operations=10001 if GROUP=="large-bytes" else 14001
        label="unadmitted-candidate-"+GROUP
        expected_inventory=[label];save("planned-inventory.json",dict(group=GROUP,labels=expected_inventory,
            expected=1,operation_count_per_function=operations,variable_name_bytes=128))
        original=function(operations=operations,long_names=True,returns=False)
        added=deepcopy(original);added["name"]="new_function"
        observed,row,_,_=prepare_case(label,program([original]),
            lambda o:packet(o,[whole("new_function",definition=added,add=True)]),
            later="REJECTED_AT_LATER_REFERENCE_CORE")
        assert observed["kind"]=="candidate" and row["candidate_bytes"]>LIMIT
        message=row["later_reference_stage"]["message"]
        assert message.startswith("E_HIA_LIMIT:")
        if GROUP=="large-bytes":
            assert row["candidate_values"]<=262144 and "byte" in message
        else:
            assert row["candidate_values"]>262144 and ("snapshot" in message or "node" in message)
    else:raise AssertionError(GROUP)
    assert len(expected_inventory)==COUNTS[GROUP]
    assert len(set(expected_inventory))==len(expected_inventory)
    assert [row["label"] for row in cases]==expected_inventory

summary=dict(status="FAIL",group=GROUP,scope="ORDINARY_PATCH_PREPARATION_LEAF_ONLY",
    actual_native_Core_admission_entries=0,actual_native_candidate_rechecks=0,
    full_patch_qualified=False,whole_stack_closed=False,installed_activation=False,
    old_counts_inherited=False,host_business_calls_during_native_forbidden=True)
started=time.monotonic_ns()
try:
    pin(__file__)
    manifest=json.loads(pin(ROOT/"development/build-r1/manifest.json"))
    source=pin(manifest["source_path"]);image=pin(manifest["image_path"])
    assert sha256(source).hexdigest()==manifest["source_sha256"]
    assert sha256(image).hexdigest()==manifest["image_sha256"]
    assert sha256(pin(REF/"hepta/hia_program.py")).hexdigest()=="76a222745e13fe29825a661be206243f137ada7b57292b07ab7513a40146fb92"
    assert sha256(pin(REF/"hepta/hia_program_tools.py")).hexdigest()=="a1b42262d8a00fbce9057e40dd081210ad274ecad8fc0c126ffafe8c3568436a"
    for path in sorted((REF/"hepta").glob("*.py")):pin(path)
    mapping=NativeHiaJsonImage(image,expected_sha256=manifest["image_sha256"])
    # Original Python functions are an independent oracle outside entry only.
    # Optional native selection is disabled just for these reference calls.
    with patch.dict(os.environ,{key:"" for key in os.environ if key.startswith("HEPTA_HIA_")}):
        execute_group()
    summary.update(status="PASS",cases=len(cases),native_entries=entries)
except BaseException as exc:
    summary.update(error_class=type(exc).__name__,error=str(exc),
        completed_cases=len(cases),native_entries=entries)
    (OUT/"failure.txt").write_text(traceback.format_exc());traceback.print_exc()
finally:
    ledger.close()
    if mapping is not None:mapping._mapping.close()
    equal=all(path.is_file() and path.read_bytes()==raw for path,raw in PINS.items())
    if not equal:summary["status"]="FAIL"
    summary.update(source_and_image_before_after_equal=equal,case_results=cases,
        expected_inventory=expected_inventory,semantic_diagnostic_ids=sorted(semantic_ids),
        full_source_and_guarded_buffers_recorded=True,
        full_native_candidate_or_error_bytes_compared=(oracle_calls>0 and
            len([row for row in cases if row["kind"] in ("candidate","error")])==oracle_calls and
            all(row["full_result_bytes_equal"] for row in cases if row["kind"] in ("candidate","error"))),
        independent_reference_prepare_calls=oracle_calls,
        actual_reference_original_admissions=reference_admissions,
        actual_reference_request_admissions=request_admissions,
        later_original_reference_stages=later_results,maximum_candidate_bytes=maximum_candidate_bytes,
        actual_limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
            address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))),
        elapsed_ns=time.monotonic_ns()-started)
    save("source-pins.json",[dict(path=str(path),**cas(raw)) for path,raw in PINS.items()])
    save("summary.json",summary)
    print("HIA_ORDINARY_PATCH_PREPARE_NATIVE "+json.dumps({k:v for k,v in summary.items()
        if k not in ("case_results","expected_inventory")},sort_keys=True),flush=True)
if summary["status"]!="PASS":raise SystemExit(1)
