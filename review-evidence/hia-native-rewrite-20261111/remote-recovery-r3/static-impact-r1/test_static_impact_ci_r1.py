"""Full static-impact bytes compared to exact original analyze_patch_impact.
Original admission, actual reference patch and all reference receipt checks are
outside the native interval; this qualifies the pure native analyzer only.
Independent large graphs retain 90 CPU / 180 wall / 1 GiB per process.
"""
from pathlib import Path
from hashlib import sha256
import ctypes,json,mmap,resource,struct,sys,time,traceback,zlib
from unittest.mock import patch
BASE=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
REF=BASE/"root-recovery/reference-0ef-r2"
ROOT=BASE/"root-recovery/workspace/native-static-impact-r1"
GROUP=sys.argv[1]
OUT=ROOT/"development"/("native-"+GROUP)
OUT.mkdir(parents=True,exist_ok=False);(OUT/"cas").mkdir()
sys.path.insert(0,str(REF));sys.dont_write_bytecode=True
from hepta import hia_program as reference
from hepta import hia_patch_impact as impact_reference
from hepta import hia_program_tools as patch_reference
from copy import deepcopy
import hashlib
from hepta.hia_json_preflight_native import NativeHiaJsonImage
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
LIMIT=8<<20;BAD=0xfffffffd;NEED=0xfffffffe
MAGIC=int.from_bytes(b"HIAIMP01","little")
MESSAGES={
 1:"E_HIA_IMPACT: unqualified or fabricated Agent patch receipt",
 2:"E_HIA_IMPACT: invalid function inventory",
 3:"E_HIA_IMPACT: unreviewed function identity",
 4:"E_HIA_IMPACT: patch unexpectedly removed a function",
 5:"E_HIA_IMPACT: Agent interface change receipt contradicts actual programs",
 6:"E_HIA_IMPACT: Agent migration-policy receipt contradicts verified program",
 7:"E_HIA_IMPACT: legacy patch may not claim changed interface",
 8:"E_HIA_IMPACT: verified program has unlisted callee",
}
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
             patch.object(impact_reference,"apply_program_patch",forbidden), \
             patch.object(impact_reference,"verify_program",forbidden), \
             patch.object(impact_reference,"_canonical",forbidden), \
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
        assert event[6]==128 and not any(event[14:]),(label,event)
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
        assert event[3]==0 and 128+event[7]<=len(output)
        return dict(kind="report",bytes=output[128:128+event[7]]),event
    raise AssertionError((label,"unexpected repeated GROW"))

oracle_calls=0
reference_patch_calls=0
maximum_report_bytes=0
expected_inventory=[]
def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
def function(name="main",value=0,callees=(),long_vars=False,typ="u64",params=None):
    params=[] if params is None else deepcopy(params)
    ops=[]
    for i,callee in enumerate(callees):
        variable=("v"+str(i)).ljust(128,"x") if long_vars else "v"+str(i)
        ops.append({"op":"call","args":[],"out":[{"name":variable,"type":"u64"}],
            "attrs":{"function":callee}})
    ops.append({"op":"const","args":[],"out":[{"name":"result","type":typ}],"attrs":{"value":value}})
    return {"name":name,"params":params,"returns":[typ],"effects":[],"entry":"entry",
        "blocks":[{"id":"entry","params":deepcopy(params),"ops":ops,
            "term":{"op":"ret","values":["result"]}}]}
def program(functions=None,version=8):
    return {"schema":"hepta.hia.program.v"+str(version),"module":"impact_reference",
        "functions":[function()] if functions is None else functions}
def packet(original,edits,version=2,policy="preserve"):
    result={"schema":"hepta.hia.patch.v"+str(version),"expected_sha256":original.sha256,"edits":edits}
    if version==2:result["interface_policy"]=policy
    return result
def change_value(document,name=None,value=7):
    fn=document["functions"][-1] if name is None else next(f for f in document["functions"] if f["name"]==name)
    ops=fn["blocks"][0]["ops"];operation=deepcopy(ops[-1]);operation["attrs"]["value"]=value
    return {"action":"replace_operation","function":fn["name"],"block":"entry",
        "index":len(ops)-1,"operation":operation}
def replace_function(fn):
    return {"action":"replace_function","function":fn["name"],"definition":deepcopy(fn)}
def ordinary(label,document,edits=None,version=2,policy="preserve"):
    global oracle_calls,reference_patch_calls
    original=reference.verify_program(document)
    request=packet(original,[change_value(original.as_dict())] if edits is None else edits,version,policy)
    candidate,receipt,expected=impact_reference.analyze_patch_impact(original,request)
    oracle_calls+=1;reference_patch_calls+=1
    return compare(label,original,candidate,receipt,dict(kind="report",bytes=canonical(expected)),
        scope="ACTUAL_REFERENCE_PATCH_AND_ADMITTED_CORES")
def injected(label,original,candidate,receipt):
    global oracle_calls
    # This category tests the exact observer's strict receipt/graph behavior
    # after real independent Core admissions, with a controlled foreign patch.
    try:
        with patch.object(impact_reference,"apply_program_patch",return_value=(candidate,receipt)):
            _,returned,report=impact_reference.analyze_patch_impact(original,{})
        assert returned is receipt
        expected=dict(kind="report",bytes=canonical(report))
    except impact_reference.HIAImpactRejected as exc:
        expected=dict(kind="error",message=str(exc))
    oracle_calls+=1
    return compare(label,original,candidate,receipt,expected,scope="PRIVATE_PATCH_RESULT_INJECTION")
def compare(label,original,candidate,receipt,expected,scope):
    global maximum_report_bytes
    start=entries;expected_inventory.append(label)
    identity=getattr(original,"input_sha256",original.sha256)
    envelope=[original.as_dict(),candidate.as_dict(),receipt,identity]
    raw=canonical(envelope)
    expected_row=dict(expected)
    if expected["kind"]=="report":
        expected_row["bytes"]=cas(expected["bytes"])
    save("expected-%04d.json"%len(expected_inventory),dict(label=label,scope=scope,
        original_canonical=cas(original.canonical_bytes),candidate_canonical=cas(candidate.canonical_bytes),
        original_input_sha256=identity,receipt=cas(canonical(receipt)),expected=expected_row,
        envelope=cas(raw)))
    observed,event=run(raw,label,fill=0xc7 if len(cases)%2 else 0)
    def describe(value):
        return {k:(len(v),sha256(v).hexdigest()) if type(v)is bytes else v for k,v in value.items()}
    assert observed==expected,(label,describe(observed),describe(expected),event)
    if observed["kind"]=="report":
        maximum_report_bytes=max(maximum_report_bytes,len(observed["bytes"]))
        parsed=json.loads(observed["bytes"]);digest=parsed.pop("sha256")
        assert digest==sha256(canonical(parsed)).hexdigest()
        assert event[8]==len(candidate.as_dict()["functions"])
        assert (event[9],event[10],event[11],event[12],event[13])==(
            len(parsed["old_call_edges"]),len(parsed["new_call_edges"]),
            len(parsed["direct_changed_functions"]),len(parsed["interface_changed_functions"]),
            len(parsed["potentially_affected_functions"]))
        assert all(parsed["claims"][key] is False for key in (
            "functional_equivalence_proved","dynamic_reachability_proved",
            "external_callers_revalidated","native_execution_qualified","physical_device_qualified"))
    else:
        assert not any(event[8:]),(label,event)
    cases.append(dict(label=label,status="PASS",scope=scope,kind=observed["kind"],
        native_entries=entries-start,full_result_bytes_equal=True))
    return observed
def baseline():
    original=reference.verify_program(program())
    candidate,receipt=patch_reference.apply_program_patch(original,packet(original,[change_value(original.as_dict())]))
    return original,candidate,receipt
def graph(count,dense=False,long_names=False):
    names=[("f%04d"%i).ljust(128,"x") if long_names else "f%04d"%i for i in range(count)]
    functions=[]
    for i,name in enumerate(names):
        callees=names if dense else (names[i+1:i+2])
        functions.append(function(name,0,callees,long_vars=long_names))
    return program(functions)
def private(label,raw):
    expected_inventory.append(label);start=entries
    observed,event=run(raw,label)
    assert observed["kind"]=="private",(label,observed,event)
    cases.append(dict(label=label,status="PASS",scope="PRIVATE_TRANSPORT_CONTROL",
        kind="private",native_entries=entries-start,full_result_bytes_equal=True))
def fixtures():
    if GROUP=="semantic":
        for version in range(1,9):
            for request_version in (1,2):
                ordinary("schema-%d-patch-%d"%(version,request_version),program(version=version),
                    version=request_version)
        for count in (1,2,3,8,32):
            ordinary("closed-chain-"+str(count),graph(count))
        diamond=program([function("root",0,("left","right")),function("left",0,("leaf",)),
            function("right",0,("leaf",)),function("leaf"),function("isolated")])
        ordinary("diamond-and-isolated",diamond,[change_value(diamond,"leaf")])
        cyclic=program([function("a",0,("b",)),function("b",0,("a",)),function("alone")])
        ordinary("cyclic-callers",cyclic,[change_value(cyclic,"a")])
        repeated=program([function("caller",0,("leaf","leaf","leaf")),function("leaf")])
        ordinary("deduplicate-repeated-edges",repeated)
        switched=program([function("caller",0,("old_leaf",)),function("old_leaf"),function("new_leaf")])
        new_caller=function("caller",0,("new_leaf",))
        ordinary("old-new-call-graph-union",switched,
            [replace_function(new_caller),change_value(switched,"old_leaf")])
        ordinary("interface-return-width",program(),[replace_function(function(typ="u32"))],policy="migrate")
        old_fn=function(params=[{"name":"argument","type":"u64"}])
        new_fn=function(params=[{"name":"renamed","type":"u64"}])
        ordinary("interface-parameter-name",program([old_fn]),[replace_function(new_fn)],policy="migrate")
        new_fn=function();new_fn["effects"]=["trap"]
        ordinary("interface-declared-effects",program(),[replace_function(new_fn)],policy="migrate")
        new_fn=function();new_fn["return_loans"]=[None]
        ordinary("explicit-default-return-loans",program(),[replace_function(new_fn)])
        ordinary("added-declaration",program(),[{"action":"add_function","function":"added","definition":function("added")}],policy="migrate")
        ordinary("identical-edit-no-affected-functions",program(),[change_value(program(),value=0)])
        many=graph(64);edits=[change_value(many,fn["name"],value=1) for fn in many["functions"]]
        ordinary("all-sixty-four-edits",many,edits)
        raw=json.dumps(program(),indent=4,sort_keys=False).encode()+b"\n"
        ordinary("original-raw-input-identity",raw)
    elif GROUP=="receipts":
        original,candidate,authentic=baseline()
        attacks=[
            ("after-hash",lambda x:x.update(after_sha256="0"*64)),
            ("before-hash",lambda x:x.update(before_sha256="0"*64)),
            ("input-hash",lambda x:x.update(original_input_sha256="0"*64)),
            ("upper-hash",lambda x:x.update(after_sha256=x["after_sha256"].upper())),
            ("schema-list",lambda x:x.update(schema=[])),
            ("schema-unknown",lambda x:x.update(schema="hepta.hia.patch-result.v3")),
            ("extra-field",lambda x:x.update(publication={})),
            ("missing-field",lambda x:x.pop("status")),
            ("status",lambda x:x.update(status="published")),
            ("ok-int",lambda x:x.update(ok=1)),
            ("ok-false",lambda x:x.update(ok=False)),
            ("domain",lambda x:x.update(edit_domain="raw_input")),
            ("edits-bool",lambda x:x.update(edits=True)),
            ("edits-zero",lambda x:x.update(edits=0)),
            ("edits-negative",lambda x:x.update(edits=-1)),
            ("edits-string",lambda x:x.update(edits="1")),
            ("edits-positive-bigint",lambda x:x.update(edits=10**100)),
            ("claims-list",lambda x:x.update(claims=[])),
            ("claims-extra",lambda x:x["claims"].update(native_execution_proved=True)),
            ("claims-missing",lambda x:x["claims"].pop("native_executed")),
            ("claim-whole-int",lambda x:x["claims"].update(whole_module_rechecked=1)),
            ("claim-behavior-int",lambda x:x["claims"].update(behavior_equivalence_proved=0)),
            ("claim-native-true",lambda x:x["claims"].update(native_executed=True)),
            ("claim-external-true",lambda x:x["claims"].update(external_callers_revalidated=True)),
            ("claim-interface-int",lambda x:x["claims"].update(interface_preserved=1)),
            ("claim-interface-false",lambda x:x["claims"].update(interface_preserved=False)),
            ("interfaces-wrong",lambda x:x.update(interface_changes=["unexpected"])),
            ("interfaces-object",lambda x:x.update(interface_changes={})),
            ("policy-list",lambda x:x.update(interface_policy=[])),
            ("policy-unknown",lambda x:x.update(interface_policy="automatic")),
            ("policy-migrate-valid",lambda x:x.update(interface_policy="migrate")),
        ]
        for label,attack in attacks:
            value=deepcopy(authentic);attack(value);injected(label,original,candidate,value)
        for label,value in (("receipt-null",None),("receipt-array",[]),("receipt-integer",0)):
            injected(label,original,candidate,value)
        # Exact error precedence: malformed qualification precedes interface.
        value=deepcopy(authentic);value.update(status="published",interface_changes=["x"],interface_policy="bad")
        injected("receipt-prefix-before-interface",original,candidate,value)
        value=deepcopy(authentic);value.update(interface_changes=["x"],interface_policy="bad")
        injected("interface-list-before-policy",original,candidate,value)
        for version in (1,2):
            request=packet(original,[change_value(original.as_dict())],version)
            valid,receipt=patch_reference.apply_program_patch(original,request)
            injected("authentic-version-"+str(version),original,valid,receipt)
        changed=reference.verify_program(program([function(typ="u32")]))
        migrated=deepcopy(authentic);migrated.update(after_sha256=changed.sha256,interface_changes=["main"],interface_policy="migrate")
        migrated["claims"]["interface_preserved"]=False
        injected("private-actual-interface-migration",original,changed,migrated)
        preserved=deepcopy(migrated);preserved["interface_policy"]="preserve"
        injected("observer-does-not-replace-earlier-patch-policy",original,changed,preserved)
        legacy=deepcopy(migrated);legacy["schema"]="hepta.hia.patch-result.v1";legacy.pop("interface_policy")
        legacy["claims"].pop("interface_preserved");legacy["claims"].pop("external_callers_revalidated")
        injected("legacy-interface-change-refusal",original,changed,legacy)
        old=reference.verify_program(program([function("a"),function("b")]))
        after=reference.verify_program(program([function("b")]))
        removed=deepcopy(authentic);removed.update(before_sha256=old.sha256,after_sha256=after.sha256,
            original_input_sha256=getattr(old,"input_sha256",old.sha256),interface_changes=["a"],interface_policy="migrate")
        removed["claims"]["interface_preserved"]=False
        injected("removed-function-before-interface-receipt",old,after,removed)
        reordered=reference.verify_program(program([function("b"),function("a")]))
        value=deepcopy(authentic);value.update(before_sha256=old.sha256,after_sha256=reordered.sha256,
            original_input_sha256=getattr(old,"input_sha256",old.sha256))
        injected("reordered-declarations-with-unchanged-functions",old,reordered,value)
        metadata=program();metadata["module"]="different_metadata"
        after=reference.verify_program(metadata)
        value=deepcopy(authentic);value["after_sha256"]=after.sha256
        injected("changed-module-with-identical-functions",original,after,value)
    elif GROUP=="private":
        for i,raw in enumerate((b"",b"[",b"]",b"[}",b"null null",b"0.5",b"NaN",
            b'{"x":1,"x":2}',b'"\\ud800"',b'"\xff"',b'{"x":}',b"truex",
            b"[1,]",b'{"a":1,}',b"\x00",b"[]",b"[{},{}]",b"[{},{},null,0]",
            b'[null,{},{},"x"]',b'[{},null,{},"x"]')):
            private("private-transport-"+str(i),raw)
        for output_size,work_size in ((127,128),(128,127),(0,128),(128,0)):
            label="short-ABI-%d-%d"%(output_size,work_size);expected_inventory.append(label);start=entries
            result,output=invoke(b"null",output_size,work_size,label)
            assert result==BAD
            cases.append(dict(label=label,status="PASS",kind="private",scope="PRIVATE_SHORT_ABI",
                native_entries=entries-start,full_result_bytes_equal=True))
    elif GROUP=="graph-1024":
        observed=ordinary("complete-1024-function-transitive-chain",graph(1024))
        report=json.loads(observed["bytes"])
        assert len(report["potentially_affected_functions"])==1024
        assert len(report["old_call_edges"])==len(report["new_call_edges"])==1023
    elif GROUP=="graph-dense":
        observed=ordinary("complete-4096-distinct-call-edges",graph(64,dense=True))
        report=json.loads(observed["bytes"])
        assert len(report["old_call_edges"])==len(report["new_call_edges"])==4096
        assert len(report["potentially_affected_functions"])==64
    elif GROUP=="graph-long-report":
        observed=ordinary("complete-report-over-eight-MiB",graph(128,dense=True,long_names=True))
        assert len(observed["bytes"])>8<<20
        report=json.loads(observed["bytes"])
        assert len(report["old_call_edges"])==len(report["new_call_edges"])==16384
        assert len(report["potentially_affected_functions"])==128
    else:raise AssertionError(GROUP)

summary=dict(status="FAIL",group=GROUP,scope="STATIC_IMPACT_ANALYZER_COMPONENT",
    actual_native_Core_admission_entries=0,actual_native_patch_entries=0,
    actual_native_candidate_rechecks=0,full_impact_qualified=False,
    whole_stack_closed=False,installed_activation=False,old_counts_inherited=False)
started=time.monotonic_ns()
try:
    pin(__file__)
    manifest=json.loads(pin(ROOT/"development/build-r1/manifest.json"))
    source=pin(manifest["source_path"]);image=pin(manifest["image_path"])
    assert sha256(source).hexdigest()==manifest["source_sha256"]
    assert sha256(image).hexdigest()==manifest["image_sha256"]
    assert sha256(pin(REF/"hepta/hia_program.py")).hexdigest()=="76a222745e13fe29825a661be206243f137ada7b57292b07ab7513a40146fb92"
    assert sha256(pin(REF/"hepta/hia_patch_impact.py")).hexdigest()=="b61710dc320c4b65206a2e6efed67ac525e900a782886be6c289e8acc681e3a1"
    pin(REF/"hepta/hia_program_tools.py")
    mapping=NativeHiaJsonImage(image,expected_sha256=manifest["image_sha256"])
    fixtures()
    assert [c["label"] for c in cases]==expected_inventory
    summary.update(status="PASS",cases=len(cases),native_entries=entries)
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
        full_source_and_guarded_buffers_recorded=True,full_native_report_bytes_compared=True,
        original_reference_oracle_calls=oracle_calls,actual_reference_patch_calls=reference_patch_calls,
        maximum_report_bytes=maximum_report_bytes,expected_inventory=expected_inventory,
        elapsed_ns=time.monotonic_ns()-started)
    save("source-pins.json",[dict(path=str(p),bytes=len(raw),sha256=sha256(raw).hexdigest()) for p,raw in PINS.items()])
    save("summary.json",summary)
    print("HIA_STATIC_IMPACT_NATIVE "+json.dumps({k:v for k,v in summary.items() if k not in ("case_results","expected_inventory")},sort_keys=True),flush=True)
if summary["status"]!="PASS":raise SystemExit(1)
