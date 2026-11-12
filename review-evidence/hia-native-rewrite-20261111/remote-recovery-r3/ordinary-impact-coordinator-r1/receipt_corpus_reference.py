"""Complete post-admission interface policy and ordered receipt differential tests.
Both Core values are actually checked by the exact frozen independent reference.
The native interval owns interface comparison, diagnostics, SHA-256 and receipt
bytes; the complete ordinary native admission/coordinator remains a later join.
"""
from pathlib import Path
from hashlib import sha256
import ctypes,json,mmap,resource,struct,sys,time,traceback,zlib,os
from unittest.mock import patch
BASE=Path(os.environ.get("HIA_RECEIPT_RECOVERY_BASE","/var/tmp/hia9acdfa-native-resume-a3c61136-20261111"))
REF=BASE/"root-recovery/reference-0ef-r2"
ROOT=BASE/"root-recovery/workspace/native-ordinary-patch-receipt-r1"
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
MAGIC=int.from_bytes(b"HIAPRC01","little")
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
    for attempt in range(4):
        result,output=invoke(raw,output_size,work_size,label+"-"+str(attempt),fill)
        event=struct.unpack_from("<16Q",output)
        assert event[:2]==(MAGIC,1) and event[6]==128 and not any(event[12:]),(label,result,event)
        if result==NEED:
            assert event[2:4]==(1,0) and event[7]==0
            assert event[4]>output_size or event[5]>work_size
            output_size=max(output_size,event[4]);work_size=max(work_size,event[5]);continue
        if result==BAD:
            assert event[2]==3 and event[3]>0
            return dict(kind="private",reason=event[3]),event
        assert result==128 and event[2] in (0,2) and 128+event[7]<=len(output)
        payload=output[128:128+event[7]]
        if event[2]==2:
            assert event[3]==1 and payload.startswith(b"E_HIA_EDIT: ")
            return dict(kind="error",bytes=payload),event
        assert event[3]==0
        return dict(kind="receipt",bytes=payload),event
    raise AssertionError((label,"unexpected repeated GROW"))

import ast,os
from hepta import hia_core_patch_native as patch_native
from copy import deepcopy
oracle_calls=0
reference_admissions=0
full_apply_calls=0
expected_inventory=[]
largest_envelope=0
largest_receipt=0
oracle_tail=None
def make_oracle_tail():
    raw=pin(REF/"hepta/hia_program_tools.py")
    tree=ast.parse(raw)
    node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="apply_program_patch")
    start=next(i for i,n in enumerate(node.body) if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id=="changed" for t in n.targets))
    names=("original","verified","schema","interface_policy","edit_count")
    fn=ast.FunctionDef(name="original_post_admission_receipt",
        args=ast.arguments(posonlyargs=[],args=[ast.arg(arg=n) for n in names],
            vararg=None,kwonlyargs=[],kw_defaults=[],kwarg=None,defaults=[]),
        body=deepcopy(node.body[start:]),decorator_list=[],returns=None,type_comment=None,type_params=[])
    module=ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[]))
    source=ast.unparse(module)+"\n";(OUT/"original-oracle-tail.py").write_text(source)
    namespace=dict(vars(patch_reference))
    exec(compile(module,str(REF/"hepta/hia_program_tools.py")+"#unchanged-post-admission-tail","exec"),namespace)
    return namespace[fn.name]

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


def pair_case(label,document,candidate,version=2,policy="migrate",edits=1,request=None):
    global oracle_calls,reference_admissions,full_apply_calls,largest_envelope,largest_receipt
    original=reference.verify_program(document)
    checked=reference.verify_program(candidate);reference_admissions+=2
    changed=patch_reference._check_patch_interface(original,checked,"migrate")
    schema="hepta.hia.patch.v"+str(version)
    try:
        same,receipt=oracle_tail(original,checked,schema,policy,edits)
        assert same is checked
        expected=dict(kind="receipt",bytes=ordered(receipt))
    except patch_reference.HIAEditRejected as error:
        expected=dict(kind="error",bytes=str(error).encode())
    oracle_calls+=1
    if request is not None:
        packet=request(original)
        with patch.object(patch_native,"selected_prepare_patch",return_value=None):
            try:
                actual,actual_receipt=patch_reference.apply_program_patch(document,packet)
                from_apply=dict(kind="receipt",bytes=ordered(actual_receipt))
                assert actual.canonical_bytes==checked.canonical_bytes
            except patch_reference.HIAEditRejected as error:
                from_apply=dict(kind="error",bytes=str(error).encode())
        assert from_apply==expected,(label,"independent full apply mismatch")
        full_apply_calls+=1
    identity=getattr(original,"input_sha256",original.sha256)
    suffix=ordered([identity,version,0 if policy=="preserve" else 1,edits])[1:]
    raw=b"["+original.canonical_bytes+b","+checked.canonical_bytes+b","+suffix
    assert len(raw)<=16777472 and len(original.canonical_bytes)<=LIMIT and len(checked.canonical_bytes)<=LIMIT
    largest_envelope=max(largest_envelope,len(raw))
    save("expected-%04d.json"%(len(cases)+1),dict(label=label,envelope=cas(raw),
        original_canonical=cas(original.canonical_bytes),candidate_canonical=cas(checked.canonical_bytes),
        original_input_sha256=identity,changed=changed,version=version,policy=policy,edits=edits,
        expected=dict(kind=expected["kind"],bytes=cas(expected["bytes"])),
        both_reference_Core_admissions_actual=True,full_apply_oracle=request is not None))
    before=entries
    observed,event=run(raw,label,fill=0xc7 if len(cases)%2 else 0)
    assert observed==expected,(label,observed,expected,event)
    assert event[8:12]==(version,0 if policy=="preserve" else 1,edits,len(changed)),(label,event,changed)
    if observed["kind"]=="receipt":
        decoded=json.loads(observed["bytes"])
        assert list(decoded)==list(receipt)
        assert list(decoded["claims"])==list(receipt["claims"])
        largest_receipt=max(largest_receipt,len(observed["bytes"]))
    cases.append(dict(label=label,status="PASS",kind=observed["kind"],native_entries=entries-before,
        complete_ordered_result_bytes_equal=True,actual_reference_Core_admissions=2,
        full_apply_oracle=request is not None,interface_changes=changed))
    return raw,observed,event

def scalar_identity(name="main",parameter="value",typ="u32"):
    return dict(name=name,params=[dict(name=parameter,type=typ)],returns=[typ],effects=[],entry="entry",
        blocks=[dict(id="entry",params=[dict(name=parameter,type=typ)],ops=[],term=dict(op="ret",values=[parameter]))])
def loan_function(origin="left",kind="readbuf",scalar=False):
    params=[dict(name="left",type=kind),dict(name="right",type=kind)]
    returns=[kind]+(["u32"] if scalar else [])
    ops=[dict(op="const",args=[],out=[dict(name="number",type="u32")],attrs=dict(value=7))] if scalar else []
    return dict(name="main",params=deepcopy(params),returns=returns,return_loans=[origin]+([None] if scalar else []),
        effects=[],entry="entry",blocks=[dict(id="entry",params=deepcopy(params),ops=ops,
            term=dict(op="ret",values=[origin]+(["number"] if scalar else [])))])
def admit_plan():
    plan=[]
    def add(label,old,new,v=2,p="migrate",edits=1,request=None):
        plan.append((label,old,new,v,p,edits,request))
    if GROUP=="patches":
        for core in range(1,9):
            for version,policy in ((1,"preserve"),(2,"preserve"),(2,"migrate")):
                for action in ("replace_function","add_function","replace_operation","replace_terminator"):
                    old=program(version=core);new=deepcopy(old)
                    if action=="replace_function":
                        definition=function(value=11);new["functions"][0]=definition;edit=whole(definition=definition)
                    elif action=="add_function":
                        definition=function("new_function",11);new["functions"].append(definition)
                        edit=whole("new_function",definition=definition,add=True)
                    elif action=="replace_operation":
                        edit=operation();new["functions"][0]["blocks"][0]["ops"][0]=deepcopy(edit["operation"])
                    else:edit=terminator()
                    add("core%d-patch%d-%s-%s"%(core,version,policy,action),old,new,version,policy,
                        request=lambda original,e=edit,v=version,p=policy:packet(original,[e],v,p))
        add("identical-whole-replacement",program(),program(),2,"preserve",
            request=lambda o:packet(o,[whole(definition=function())]))
        raw=b" \n"+ordered(reverse_maps(program()))+b"\t"
        altered=program();altered["functions"][0]["blocks"][0]["ops"][0]["attrs"]["value"]=7
        add("complete-original-raw-input-identity",raw,altered,2,"preserve",request=lambda o:packet(o))
        many=program([function("f%02d"%i) for i in range(64)])
        altered=deepcopy(many)
        for f in altered["functions"]:f["blocks"][0]["ops"][0]["attrs"]["value"]=7
        add("all64-independent-edits",many,altered,2,"preserve",64,
            request=lambda o:packet(o,[operation(name="f%02d"%i) for i in range(64)]))
    elif GROUP=="interfaces":
        pairs=[]
        def change(label,new,old=None):
            pairs.append((label,program() if old is None else old,new))
        change("return-width",program([function(typ="u64")]))
        change("empty-results",program([function(returns=False)]))
        change("parameter-name",program([scalar_identity(parameter="renamed")]),
            program([scalar_identity(parameter="original")]))
        change("parameter-type",program([scalar_identity(typ="u64")]),program([scalar_identity()]))
        added_effect=program();added_effect["functions"][0]["effects"]=["read"]
        change("declared-effects",added_effect)
        a=program();b=program();a["functions"][0]["effects"]=["read","write"];b["functions"][0]["effects"]=["write","read"]
        change("effect-list-order",b,a)
        explicit=program();explicit["functions"][0]["return_loans"]=[None]
        change("absent-default-return-loans",explicit)
        change("reverse-default-return-loans",program(),explicit)
        for typ in ("readbuf","mutbuf"):
            for scalar in (False,True):
                change("loan-origin-"+typ+"-"+str(scalar),program([loan_function("right",typ,scalar)]),
                    program([loan_function("left",typ,scalar)]))
        change("function-added",program([function(),function("new_function")]))
        change("function-removed",program(),program([function(),function("removed")]))
        change("only-body",program([function(value=999)]))
        altered=program();altered["module"]="new_module";change("only-module",altered)
        changed_block=program();changed_block["functions"][0]["entry"]="other"
        changed_block["functions"][0]["blocks"][0]["id"]="other";change("only-block-name",changed_block)
        ordered_fns=[function(name) for name in ("z","_lead","A_09","a0","a_0","Z9")]
        change("only-function-order",program(list(reversed(ordered_fns))),program(ordered_fns))
        old=program([function("f%02d"%i) for i in range(12)])
        new=program([function("f%02d"%i,typ="u64") for i in range(12)])
        change("first-eight-exact-diagnostic",new,old)
        for name,old,new in pairs:
            for version,policy in ((1,"preserve"),(2,"preserve"),(2,"migrate")):
                add(name+"-v%d-%s"%(version,policy),old,new,version,policy)
    elif GROUP=="union-2048":
        old=program([function("old%04d"%i) for i in range(1024)])
        new=program([function("new%04d"%i) for i in range(1024)])
        add("complete2048-name-union-migrate",old,new,2,"migrate",64)
        add("complete2048-name-union-preserve-first8",old,new,2,"preserve",64)
    elif GROUP=="large-bytes":
        old=program([function(operations=18000,long_names=True,returns=False)])
        new=deepcopy(old);new["module"]="complete_large_candidate"
        add("two-complete-admitted-near8MiB-canonical-values",old,new,2,"preserve")
    else:raise AssertionError(GROUP)
    return plan

def private_case(label,raw):
    before=entries;observed,event=run(raw,label,fill=0x91)
    assert observed["kind"]=="private" and event[2]==3,(label,observed,event)
    cases.append(dict(label=label,status="PASS",kind="private",native_entries=entries-before))
def private_group():
    global expected_inventory
    checked=reference.verify_program(program())
    base=[checked.as_dict(),checked.as_dict(),checked.input_sha256,2,0,1]
    raws=[b"",b"null",b"false",b"{}",b"[]",b"[",b"[1,2,3,4,5,6]",b"["+b"x"*31+b"]"]
    for index,value in [(0,None),(1,[]),(2,None),(2,"g"*64),(2,"A"*64),(2,"0"*63),
        (3,False),(3,0),(3,3),(3,"2"),(4,-1),(4,2),(4,True),(5,0),(5,65),(5,True)]:
        changed=deepcopy(base);changed[index]=value;raws.append(ordered(changed))
    invalid=deepcopy(base);invalid[3:5]=[1,1];raws.append(ordered(invalid))
    for slot in (0,1):
        changed=deepcopy(base);changed[slot]["functions"]=[];raws.append(ordered(changed))
        changed=deepcopy(base);changed[slot]["functions"].append(deepcopy(changed[slot]["functions"][0]));raws.append(ordered(changed))
    labels=["private-%02d"%i for i in range(len(raws))]
    shorts=((127,128),(128,127),(0,128),(128,0))
    labels+=["short-%d-%d"%sizes for sizes in shorts]
    labels+=["capacity-receipt-source","capacity-error-source"]
    labels+=[kind+"-"+which for kind in ("receipt","error") for which in ("exact","output-short","work-short")]
    expected_inventory=labels;save("planned-inventory.json",dict(group=GROUP,expected=len(labels),labels=labels))
    for i,raw in enumerate(raws):private_case("private-%02d"%i,raw)
    for sizes in shorts:
        label="short-%d-%d"%sizes;before=entries
        status,output=invoke(b"null",*sizes,label,0x81)
        assert status==BAD and output==bytes([0x81])*sizes[0]
        cases.append(dict(label=label,status="PASS",kind="short",native_entries=entries-before))
    valid=pair_case("capacity-receipt-source",program(),program(),2,"preserve")
    changed=pair_case("capacity-error-source",program(),program([function(typ="u64")]),2,"preserve")
    for kind,(raw,expected,event) in (("receipt",valid),("error",changed)):
        for which in ("exact","output-short","work-short"):
            label=kind+"-"+which;before=entries
            osize=event[4]-(which=="output-short");wsize=event[5]-(which=="work-short")
            result,out=invoke(raw,osize,wsize,label,0x91);e=struct.unpack_from("<16Q",out)
            assert e[:2]==(MAGIC,1) and e[6]==128 and not any(e[12:])
            if which=="exact":
                assert result==128 and e[2]==(0 if kind=="receipt" else 2)
                assert out[128:128+e[7]]==expected["bytes"]
            else:
                assert result==NEED and e[2:4]==(1,0) and e[7]==0
                assert e[4]>osize or e[5]>wsize
            cases.append(dict(label=label,status="PASS",kind="capacity",native_entries=entries-before))

summary=dict(status="FAIL",group=GROUP,scope="POST_ADMISSION_INTERFACE_AND_RECEIPT_LEAF",
    actual_native_Core_admission_entries=0,actual_native_candidate_rechecks=0,actual_native_preparation_entries=0,
    full_patch_qualified=False,whole_stack_closed=False,installed_activation=False,old_counts_inherited=False)
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
    oracle_tail=make_oracle_tail()
    mapping=NativeHiaJsonImage(image,expected_sha256=manifest["image_sha256"])
    with patch.dict(os.environ,{key:"" for key in os.environ if key.startswith("HEPTA_HIA_")}):
        if GROUP=="private":private_group()
        else:
            plan=admit_plan();expected_inventory=[p[0] for p in plan]
            assert len(expected_inventory)==len(set(expected_inventory))
            save("planned-inventory.json",dict(group=GROUP,expected=len(plan),labels=expected_inventory))
            for item in plan:pair_case(*item)
    assert [row["label"] for row in cases]==expected_inventory
    summary.update(status="PASS",cases=len(cases),native_entries=entries)
except BaseException as exc:
    summary.update(error_class=type(exc).__name__,error=str(exc),completed_cases=len(cases),native_entries=entries)
    (OUT/"failure.txt").write_text(traceback.format_exc());traceback.print_exc()
finally:
    ledger.close()
    if mapping is not None:mapping._mapping.close()
    equal=all(path.is_file() and path.read_bytes()==raw for path,raw in PINS.items())
    if not equal:summary["status"]="FAIL"
    summary.update(source_and_image_before_after_equal=equal,case_results=cases,expected_inventory=expected_inventory,
        independent_original_post_admission_calls=oracle_calls,direct_actual_reference_Core_admissions=reference_admissions,
        independent_full_apply_reference_calls=full_apply_calls,
        full_native_ordered_receipt_or_error_bytes_compared=all(r.get("complete_ordered_result_bytes_equal",True) for r in cases),
        full_source_and_guarded_buffers_recorded=True,maximum_envelope_bytes=largest_envelope,
        maximum_receipt_bytes=largest_receipt,elapsed_ns=time.monotonic_ns()-started,
        actual_limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
            address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))))
    save("source-pins.json",[dict(source_path=str(path),**cas(raw)) for path,raw in PINS.items()])
    save("summary.json",summary)
    print("HIA_ORDINARY_PATCH_RECEIPT_NATIVE "+json.dumps({k:v for k,v in summary.items()
        if k not in ("case_results","expected_inventory")},sort_keys=True),flush=True)
if summary["status"]!="PASS":raise SystemExit(1)
