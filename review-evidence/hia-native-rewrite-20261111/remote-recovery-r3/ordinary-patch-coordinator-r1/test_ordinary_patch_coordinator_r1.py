"""Actual finite-ELF ordinary patch differential, including original failure order."""
from __future__ import annotations
import ast,contextlib,json,os,resource,signal,stat,struct,subprocess,sys,time,traceback,zlib
from copy import deepcopy
from hashlib import sha1,sha256
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
BASE=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
REF=BASE/"root-recovery/reference-0ef-r2";ROOT=BASE/"root-recovery/workspace/native-ordinary-patch-coordinator-r1"
GROUP=sys.argv[1];SOURCES=Path(sys.argv[2]).resolve()
OUT=ROOT/"development"/("native-"+GROUP);OUT.mkdir(parents=True,exist_ok=False)
sys.path.insert(0,str(REF))
from hepta import hia_program as reference
from hepta import hia_program_tools as patch_reference
from hepta import hia_core_patch_native as patch_native
resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
LIMIT=8<<20;EVENT=int.from_bytes(b"HIACDE01","little");RESULT=int.from_bytes(b"HIAEDR01","little")
PINS={};cases=[];planned=[];actual_processes=0;reference_full_apply_calls=0
started=time.monotonic_ns();start_parent=resource.getrusage(resource.RUSAGE_SELF);start_children=resource.getrusage(resource.RUSAGE_CHILDREN)
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def read(path):
    path=Path(path).resolve();raw=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
    if path in PINS:assert PINS[path]==(raw,mode),path
    PINS[path]=(raw,mode);return raw
def save(name,value):(OUT/name).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def cas(raw):
    raw=bytes(raw);h=digest(raw);p=OUT/"cas"/(h+".zlib");p.parent.mkdir(exist_ok=True)
    if not p.exists():p.write_bytes(zlib.compress(raw,1))
    assert zlib.decompress(p.read_bytes())==raw
    return dict(bytes=len(raw),sha256=h,path="cas/"+p.name,compression="zlib")
def cpu_used():
    p=resource.getrusage(resource.RUSAGE_SELF);c=resource.getrusage(resource.RUSAGE_CHILDREN)
    return p.ru_utime+p.ru_stime-start_parent.ru_utime-start_parent.ru_stime+c.ru_utime+c.ru_stime-start_children.ru_utime-start_children.ru_stime
def forbidden(*args,**kwargs):raise AssertionError("host business owner called while fixed native executable runs")
def extract_helpers():
    files=(("prepare_corpus_reference.py","52f43c7c93bfef7fd1319591d616d1a2709f5b9c",
        ("ordered","function","program","operation","terminator","whole","packet","mutated","reverse_maps","values_count","small_plan")),
        ("receipt_corpus_reference.py","b46ab779035810062e6c225a27892f01e4371ff0",
        ("scalar_identity","loan_function","admit_plan")))
    result=dict(json=json,deepcopy=deepcopy,GROUP=GROUP)
    for filename,expected,names in files:
        path=SOURCES/filename;raw=read(path);assert gitsha(raw)==expected
        nodes={n.name:n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
        assert all(n in nodes for n in names)
        exec(compile(ast.Module(body=[nodes[n] for n in names],type_ignores=[]),str(path)+":fixture-functions-only","exec"),result)
    return result
def fixture_request(document,builder,transform=None):
    raw=document if isinstance(document,bytes) else H["ordered"](document)
    old=reference.verify_program(raw)
    value=builder(old);request=H["ordered"](value)
    if transform is not None:request=transform(request,value)
    return raw,request
def make_plan():
    result=[]
    def add(label,program_bytes,request_bytes,digits=4300):
        assert type(program_bytes)is bytes and type(request_bytes)is bytes
        result.append((label,program_bytes,request_bytes,digits))
    program=H["program"];function=H["function"];packet=H["packet"];whole=H["whole"];ordered=H["ordered"]
    if GROUP in ("semantic","errors"):
        H["GROUP"]=GROUP
        original=H["small_plan"]()
        assert len(original)==(113 if GROUP=="semantic" else 58)
        for label,doc,builder,transform,later in original:
            add(label,*fixture_request(doc,builder,transform))
    elif GROUP=="interfaces":
        H["GROUP"]="interfaces"
        for label,old,new,version,policy,edits,builder in H["admit_plan"]():
            old_names=[f["name"] for f in old["functions"]];new_names=[f["name"] for f in new["functions"]]
            if old["module"]!=new["module"] or not set(old_names)<=set(new_names):continue
            if [n for n in new_names if n in old_names]!=old_names:continue
            changes=[whole(f["name"],f,add=f["name"] not in old_names) for f in new["functions"]]
            assert 1<=len(changes)<=64
            add(label,*fixture_request(old,lambda o,e=changes,v=version,p=policy:packet(o,e,v,p)))
        assert len(result)==48,len(result)
    elif GROUP=="input":
        raw,request=fixture_request(program(),lambda o:packet(o))
        invalid=[b"",b"[",b"]",b"[}",b"null null",b"0.5",b"1e1",b"NaN",b"Infinity",
            b'{"x":1,"x":2}',b'"\\ud800"',b'"\xff"',b'{"x":}',b"truex",b"[1,]",b'{"a":1,}',b"\0",
            b"["*65+b"0"+b"]"*65,b"\xef\xbb\xbf{}"]
        for index,value in enumerate(invalid):
            add("request-invalid-%02d"%index,raw,value)
            add("program-invalid-%02d"%index,value,request)
            add("program-before-request-%02d"%index,value,b"{")
        for name,value in (("null",b"null"),("array",b"[]"),("string",b'"value"'),("integer",b"1"),("boolean",b"true")):
            add("request-valid-JSON-"+name,raw,value)
        add("base-byte-budget-before-request",b" "*(LIMIT+1),b"{")
        add("request-byte-budget-after-base",raw,b" "*(LIMIT+1))
        for digits in (0,640,4300):
            huge=request.replace(b'"index":0',b'"index":'+b"9"*4501)
            assert huge!=request
            add("actual-decimal-limit-"+str(digits),raw,huge,digits)
    elif GROUP=="identity":
        original=program();encoded=b" \n"+ordered(H["reverse_maps"](original))+b"\t"
        add("noncanonical-original-input",*fixture_request(encoded,lambda o:packet(o)))
        many=program([function("f%02d"%i) for i in range(64)])
        add("64-distinct-function-edits",*fixture_request(many,lambda o:packet(o,[H["operation"](name="f%02d"%i) for i in range(64)])))
        composite=read(REF/"examples/hia_recursive_chain/composite_v2.json")
        assert gitsha(composite)=="23a78d6fb231cdf99c0cdf02295ce613b36c7aa1"
        add("actual-structured-v2-before-noop-patch",*fixture_request(composite,
            lambda o:packet(o,[whole(o.as_dict()["functions"][0]["name"],o.as_dict()["functions"][0])])))
    elif GROUP=="functions-1024":
        many=program([function("f%04d"%i) for i in range(1024)])
        add("actual1024-base-before1088-candidate",*fixture_request(many,
            lambda o:packet(o,[whole("new%02d"%i,add=True) for i in range(64)],policy="migrate")))
    elif GROUP in ("large-bytes","large-nodes"):
        count=10001 if GROUP=="large-bytes" else 14001
        old=function(operations=count,long_names=True,returns=False);new=deepcopy(old);new["name"]="new_function"
        add("candidate-object-"+GROUP,*fixture_request(program([old]),lambda o:packet(o,[whole("new_function",new,True)],policy="migrate")))
    elif GROUP=="large-valid":
        old=function(operations=18000,long_names=True,returns=False)
        replacement=deepcopy(old["blocks"][0]["ops"][0]);replacement["attrs"]["value"]=7
        edit=dict(action="replace_operation",function="main",block="entry",index=0,operation=replacement)
        add("two-actual-near8MiB-admissions-and-full-receipt",*fixture_request(program([old]),lambda o:packet(o,[edit])))
    else:raise AssertionError(GROUP)
    assert result and len({x[0] for x in result})==len(result)
    return result
def expected_result(program_raw,request_raw,digits):
    global reference_full_apply_calls
    old_digits=sys.get_int_max_str_digits();sys.set_int_max_str_digits(digits)
    try:
        with patch.object(patch_native,"selected_prepare_patch",return_value=None):
            try:
                checked,receipt=patch_reference.apply_program_patch(program_raw,request_raw)
                base=reference.verify_program(program_raw)
                expected=dict(kind="result",base=base.canonical_bytes,candidate=checked.canonical_bytes,receipt=H["ordered"](receipt))
            except reference.HIAProgramRejected as exc:expected=dict(kind="error",domain="program",payload=str(exc).encode())
            except patch_reference.HIAEditRejected as exc:expected=dict(kind="error",domain="edit",payload=str(exc).encode())
        reference_full_apply_calls+=1
        return expected
    finally:sys.set_int_max_str_digits(old_digits)
def run_case(index,label,program_raw,request_raw,digits):
    global actual_processes
    expected=expected_result(program_raw,request_raw,digits)
    lease=1001+index*8
    raw=struct.pack("<8Q",int.from_bytes(b"HIAEJN01","little"),lease,1,digits,len(program_raw),len(request_raw),0,0)+program_raw+request_raw
    pending=dict(label=label,input=cas(raw),program=cas(program_raw),request=cas(request_raw),
        digits=digits,expected={k:cas(v) if isinstance(v,bytes) else v for k,v in expected.items()})
    save("pending-%04d.json"%index,pending)
    assert cpu_used()<90 and (time.monotonic_ns()-started)/1e9<180
    remaining=180-(time.monotonic_ns()-started)/1e9
    before_cpu=cpu_used();beg=time.monotonic_ns()
    result=None
    with contextlib.ExitStack() as stack:
        for target,name in ((reference,"verify_program"),(patch_reference,"apply_program_patch"),
            (patch_reference,"_prepare_program_patch"),(patch_reference,"_check_patch_interface"),
            (json,"loads"),(json,"dumps")):
            stack.enter_context(patch.object(target,name,side_effect=forbidden))
        process_handle=subprocess.Popen([str(elf)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            env=dict(PATH="/usr/bin:/bin",LANG="C.UTF-8",LC_ALL="C.UTF-8"))
        timed_out=False
        try:stdout,stderr=process_handle.communicate(raw,timeout=remaining)
        except subprocess.TimeoutExpired:
            timed_out=True;process_handle.kill();stdout,stderr=process_handle.communicate()
        result=subprocess.CompletedProcess([str(elf)],process_handle.returncode,stdout,stderr)
    actual_processes+=1
    elapsed=time.monotonic_ns()-beg
    process=dict(label=label,returncode=result.returncode,timed_out=timed_out,elapsed_ns=elapsed,group_cpu_before=before_cpu,
        group_cpu_after=cpu_used(),stdin=pending["input"],stdout=cas(result.stdout),stderr=cas(result.stderr),
        executable_sha256=manifest["executable_sha256"])
    save("process-%04d.json"%index,process)
    assert not timed_out,("original wall bound",label)
    assert cpu_used()<=90,("original aggregate CPU bound",cpu_used())
    assert len(result.stderr)>=128,(label,"native executor failure",result.returncode,result.stderr.hex())
    event=struct.unpack_from("<16Q",result.stderr)
    assert event[:3]==(EVENT,7,lease) and event[3]>0 and event[7]==0 and event[9]==1 and not any(event[11:]),(label,event)
    assert event[6]==30 and event[8]>0,(label,event)
    if expected["kind"]=="error":
        assert result.returncode==2 and not result.stdout,(label,result.returncode,result.stdout[:200])
        payload=result.stderr[128:]
        assert event[8]==len(payload) and event[5]!=0
        assert (event[4]==2 if expected["domain"]=="program" else event[4] in (1,3)),(label,event,expected["domain"])
        assert payload==expected["payload"],(label,payload,expected["payload"],event)
        actual=dict(kind="error",payload=cas(payload),domain=event[4],stage=event[10],reason=event[5])
    else:
        assert result.returncode==0 and len(result.stderr)==128 and event[4]==event[5]==event[10]==0,(label,event,result.returncode)
        assert event[8]==len(result.stdout) and len(result.stdout)>=64
        header=struct.unpack_from("<8Q",result.stdout)
        assert header[:2]==(RESULT,1) and not any(header[5:])
        assert header[2:5]==tuple(len(expected[k]) for k in ("base","candidate","receipt")),(label,header)
        wanted=struct.pack("<8Q",RESULT,1,*header[2:5],0,0,0)+expected["base"]+expected["candidate"]+expected["receipt"]
        assert result.stdout==wanted,(label,"complete native output differs",digest(result.stdout),digest(wanted))
        actual=dict(kind="result",base=cas(expected["base"]),candidate=cas(expected["candidate"]),receipt=cas(expected["receipt"]))
    cases.append(dict(label=label,status="PASS",actual=actual,terminal_event=[str(x) for x in event],
        actual_native_processes=1,full_original_apply_oracle=True,complete_result_and_error_bytes_equal=True,
        native_interval_host_business_disabled=True,elapsed_ns=elapsed))
    save("completed-%04d.json"%index,cases[-1])
summary=dict(status="FAIL",scope="ACTUAL_RAW_JSON_ORDINARY_PATCH_FIXED_ELF_COMPOSITION",
    group=GROUP,old_counts_inherited=False,whole_stack_closed=False,full_patch_qualified=False,
    public_CLI_installed=False,python_object_input_API_qualified=False,installed_activation=False)
try:
    read(__file__);manifest=json.loads(read(ROOT/"development/build-r1/manifest.json"))
    assert manifest["status"]=="BUILT_ONLY_NOT_SEMANTIC_QUALIFICATION" and manifest["new_compiles"]==5
    elf=Path(manifest["executable_path"]);binary=read(elf)
    assert (len(binary),digest(binary))==(manifest["executable_bytes"],manifest["executable_sha256"])
    assert binary[:4]==b"\x7fELF" and struct.unpack_from("<H",binary,56)[0]==2
    assert [struct.unpack_from("<I",binary,64+i*56)[0] for i in range(2)]==[1,0x6474e551]
    for role,row in manifest["role_bindings"].items():
        for kind in ("source","image"):
            raw=read(row[kind+"_path"]);assert (len(raw),digest(raw))==(row[kind+"_bytes"],row[kind+"_sha256"])
    for path in sorted((REF/"hepta").glob("*.py")):read(path)
    assert gitsha(read(REF/"hepta/hia_program.py"))=="5d0027f4453759e4156a3496e64215c441a727e4"
    assert gitsha(read(REF/"hepta/hia_program_tools.py"))=="c2be38ffe2871ca199783103d4dfa9867771df10"
    H=extract_helpers()
    with patch.dict(os.environ,{k:"" for k in os.environ if k.startswith("HEPTA_HIA_")}):
        plan=make_plan();planned=[x[0] for x in plan]
        save("planned-inventory.json",dict(group=GROUP,labels=planned,cases=len(planned)))
        for index,item in enumerate(plan,1):run_case(index,*item)
    assert [x["label"] for x in cases]==planned
    summary.update(status="PASS",cases=len(cases))
except BaseException as exc:
    summary.update(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    equal=all(p.is_file() and p.read_bytes()==raw and stat.S_IMODE(p.stat().st_mode)==mode for p,(raw,mode) in PINS.items())
    if not equal:summary["status"]="FAIL"
    cas_bytes=0;cas_count=0
    for path in sorted((OUT/"cas").glob("*.zlib")):
        raw=zlib.decompress(path.read_bytes());assert digest(raw)==path.stem;cas_count+=1;cas_bytes+=len(raw)
    save("source-pins.json",[dict(path=str(p),bytes=len(raw),sha256=digest(raw),gitsha=gitsha(raw),mode=mode) for p,(raw,mode) in PINS.items()])
    summary.update(completed_cases=len(cases),actual_native_processes=actual_processes,reference_full_apply_calls=reference_full_apply_calls,
        planned=planned,case_results=cases,source_and_image_before_after_equal=equal,
        complete_process_streams_preserved=True,complete_CAS_verified=True,cas_objects=cas_count,logical_cas_bytes=cas_bytes,
        complete_result_and_error_bytes_equal=bool(cases) and all(x["complete_result_and_error_bytes_equal"] for x in cases),
        original_limits=dict(cpu_seconds=90,wall_seconds=180,address_space_bytes=1073741824),
        parent_plus_children_cpu_seconds=cpu_used(),elapsed_ns=time.monotonic_ns()-started,
        internal_component_entry_counts_not_inferred_from_process_counts=True)
    save("summary.json",summary)
    print("HIA_ORDINARY_COORDINATOR_NATIVE "+json.dumps({k:v for k,v in summary.items() if k not in ("planned","case_results")},sort_keys=True),flush=True)
if summary["status"]!="PASS":raise SystemExit(1)
