"""Retest the unchanged 35 controls against actual HIA-produced fixed hosted bytes."""
from __future__ import annotations
import ast,ctypes,hashlib,importlib.util,json,os,resource,shutil,struct,subprocess,sys,sysconfig,time,traceback,weakref
from pathlib import Path
ROOT=Path("/home/qq/hia-native-self-rewrite-20261111-dda7/normalization-v70-r1")
BASE=ROOT/"source-front-temporary-r5"
CASE=ROOT/"evidence"/"flat-hia-produced-notes-r1"
SOURCE=ROOT/"evidence"/"flat-cpython-notes-r7"/"source"
PACKAGE=ROOT/"helpers"/"flat_cpython_notes_r7_input.json"
CASE.mkdir(mode=0o700,exist_ok=False)
started=time.monotonic_ns()
def digest(raw):return hashlib.sha256(raw).hexdigest()
def encoded(x):return (json.dumps(x,ensure_ascii=True,sort_keys=True,indent=2)+"\n").encode("ascii")
def put(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("xb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
def load_definitions(path,wanted_sha,namespace,exclude=()):
    raw=path.read_bytes();assert digest(raw)==wanted_sha
    inputs[str(path)]=wanted_sha
    tree=ast.parse(raw,filename=str(path))
    selected=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name not in exclude]
    exec(compile(ast.Module(body=selected,type_ignores=[]),str(path),"exec"),namespace)
    return namespace
def elf_sections(raw):
    assert raw[:7]==b"\x7fELF\x02\x01\x01" and len(raw)>=64
    assert struct.unpack_from("<H",raw,18)[0]==62
    offset=struct.unpack_from("<Q",raw,40)[0]
    size,count,string_index=struct.unpack_from("<3H",raw,58)
    assert size==64 and count>0 and string_index<count and offset+count*size<=len(raw)
    headers=[struct.unpack_from("<IIQQQQIIQQ",raw,offset+i*size) for i in range(count)]
    strings=headers[string_index];names=raw[strings[4]:strings[4]+strings[5]]
    result=[]
    for index,h in enumerate(headers):
        end=names.find(b"\0",h[0]);assert end>=h[0]
        name=names[h[0]:end].decode("ascii")
        data=b"" if h[1]==8 else raw[h[4]:h[4]+h[5]]
        if h[1]!=8:assert len(data)==h[5]
        result.append({"index":index,"name":name,"type":h[1],"flags":h[2],"address":h[3],
            "bytes":h[5],"link":h[6],"info":h[7],"entry_bytes":h[9],"data":data})
    return result
def mapping(address):
    for line in Path("/proc/self/maps").read_text().splitlines():
        fields=line.split();lo,hi=(int(x,16) for x in fields[0].split("-"))
        if lo<=address<hi:return {"range":fields[0],"permissions":fields[1],"path":fields[-1] if len(fields)>5 else None}
    raise AssertionError("admitted address has no kernel mapping")

def deliver_observation(module,handled):
    primary=ValueError("delivery identity")
    old_context=LookupError("retained previous context")
    primary.__context__=old_context
    primary.__cause__=KeyError("retained explicit cause")
    primary.__suppress_context__=True
    primary.__notes__=["retained note"]
    outer=primary if handled=="same_primary" else RuntimeError("outer handler")
    inner=ArithmeticError("inner handler")
    def invoke():
        before=primitive["state"](primary)
        try:module.deliver(primary)
        except BaseException as result:
            assert result is primary
            after=primitive["state"](result)
        else:raise AssertionError("fixed delivery returned")
        assert before==after,(handled,before,after)
        return {"case":"fixed_delivery_preserves_existing_chain","handled":handled,
            "before":before,"after":after,"same_exception":True}
    if handled=="none":return invoke()
    try:raise outer
    except BaseException:
        if handled=="nested":
            try:raise inner
            except BaseException:return invoke()
        return invoke()

def invalid_delivery_control(module):
    events=[]
    class Spoof:
        @property
        def __class__(self):
            events.append("foreign __class__")
            return BaseException
    original=RuntimeError("surrounding handled error")
    before=primitive["state"](original)
    try:raise original
    except RuntimeError:
        for value in (None,object(),Spoof()):
            try:module.deliver(value)
            except TypeError:pass
            else:raise AssertionError("invalid error object reached fixed C delivery")
        assert sys.exception() is original
    assert primitive["state"](original)==before and not events
    return {"case":"invalid_delivery_objects_before_C","refused":3,"foreign_callbacks":events,
        "surrounding_error_unchanged":True}

def invalid_c_delivery_fields(module):
    error=ValueError("unchanged invalid C delivery")
    before=primitive["state"](error)
    for container,key,index in ((1,None,0),(None,1,0),(None,None,1)):
        assert module._delivery(module._api_address,error,4,container,key,index) is None
        assert primitive["state"](error)==before
    return {"case":"invalid_fixed_C_delivery_frame","refused":3,
        "existing_error_unchanged":True,"no_raised_error_indicator":True}

def delivery_negative(module):
    def run(use_fixed):
        error=ValueError("existing error")
        previous=LookupError("existing context")
        error.__context__=previous
        outer=RuntimeError("outer handler")
        try:raise outer
        except RuntimeError:
            try:
                if use_fixed:module.deliver(error)
                else:raise error
            except BaseException as caught:
                return {"same_error":caught is error,"context_is_previous":caught.__context__ is previous,
                    "context_is_outer":caught.__context__ is outer,"state":primitive["state"](caught)}
    actual=run(True);wrong=run(False)
    assert actual["same_error"] and actual["context_is_previous"] and not actual["context_is_outer"]
    assert wrong["same_error"] and wrong["context_is_outer"] and not wrong["context_is_previous"]
    return {"case":"Python_raise_context_sensitive_negative","fixed":actual,"wrong":wrong,"detected":True}

def replacement_lifetime(module):
    references={}
    class Child(Exception):pass
    class Replacement(KeyboardInterrupt):pass
    def make_replacement():
        value=Replacement("repr replacement")
        references["replacement"]=weakref.ref(value)
        return value
    class Key(str):
        def __repr__(self):raise make_replacement()
    error=Child("old error")
    key=Key("key");container={key:None}
    references["error"]=weakref.ref(error);references["key"]=weakref.ref(key)
    result=module.note(error,1,container,key,0)
    assert type(result) is Replacement and result.__context__ is error
    while_held={name:ref() is not None for name,ref in references.items()}
    result=error=key=container=None
    return {"while_held":while_held,"after_release":{name:ref() is not None for name,ref in references.items()}}

def replacement_lifetime_control(module):
    import gc
    original=ROOT/"evidence"/"flat-cpython-notes-r1"
    bridge=original/"source"/"hepta"/"hia_program_normalization_notes.py"
    image=original/"note.image.bin"
    assert digest(bridge.read_bytes())=="feaeb2d6bffc57804ec1eb02351d5c851ebe8b37a8684ed51a3a49b5e072fbd7"
    raw=image.read_bytes()
    assert digest(raw)=="e82fd51964ce25990f24e723fb0b3270b2e8b69c7fdc2e1b3999648df070db61"
    inputs[str(bridge)]=digest(bridge.read_bytes());inputs[str(image)]=digest(raw)
    spec=importlib.util.spec_from_file_location("hepta._normalization_note_original",bridge)
    old_source=importlib.util.module_from_spec(spec);sys.modules[spec.name]=old_source;spec.loader.exec_module(old_source)
    old=old_source.NativeCPythonNotes(raw,digest(raw))
    enabled=gc.isenabled();gc.disable()
    try:
        old_result=replacement_lifetime(old)
        actual=replacement_lifetime(module)
        assert all(old_result["while_held"].values()) and all(old_result["after_release"].values()),old_result
        assert all(actual["while_held"].values()) and not any(actual["after_release"].values()),actual
    finally:
        old.close()
        if enabled:gc.enable()
    return {"case":"replacement_error_local_borrow_lifetime","old_frozen_bridge":old_result,
        "new_bridge":actual,"cyclic_GC_disabled":True,"original_failure_detected":True}

report={"schema":"hia.normalization.v70.flat-cpython-note-and-delivery-mechanism-development.v1",
 "scope":"HIA-produced fixed CPython hosted mechanism; unchanged 35 tests, no normalization qualification.",
 "new_compile_count":0,"production_c_compiler_used":False,
 "independent_functional_run":True,"timing_qualification":False,
 "other_full_suite_may_overlap":True,
 "whole_payload_forwarded_to_C_shim":False,"HIA_native_complete":False,
 "full_normalization_qualified":False,"physical_recursion_qualified":False,
 "CPython_runtime_dependency_retained":True,"python":sys.version,
 "observations":[],"failures":[],"build":[]}
inputs={};binaries={};tools_before={};module=None
try:
    raw=PACKAGE.read_bytes()
    assert digest(raw)=="d30ba13269d06469d69b5b994471c06323c9d67a1ce049aac686c47ad15db315"
    package=json.loads(raw);put(CASE/"INPUT.json",raw)
    for name,text in package["files"].items():
        raw=text.encode("utf-8");assert package["metadata"][name]=={"bytes":len(raw),"sha256":digest(raw)}
        path=SOURCE/name;assert path.read_bytes()==raw;inputs[str(path)]=digest(raw)
    assert sys.version_info[:3]==(3,14,4)
    for name in list(os.environ):
        if name.startswith("HEPTA_HIA_"):del os.environ[name]
    sys.dont_write_bytecode=True;sys.path.insert(0,str(BASE));os.chdir(BASE)
    loader=BASE/"hepta"/"hia_json_preflight_native.py"
    assert digest(loader.read_bytes())=="dfc45be8c408758410976310da17a2a164eb2d7c8575ec0cc6e5b9762b27c3d7"
    inputs[str(loader)]=digest(loader.read_bytes())
    original_driver=ROOT/"helpers"/"flat_cpython_notes_r7.py"
    original_raw=original_driver.read_bytes()
    assert digest(original_raw)=="a78448b0973c958087e93a0f70375410f5116fa53480399a4aa8e976ccf0356e"
    inputs[str(original_driver)]=digest(original_raw)
    own_raw=Path(__file__).read_bytes()
    def function_bodies(raw):
        text=raw.decode("utf-8")
        return {node.name:ast.get_source_segment(text,node) for node in ast.parse(text).body
            if isinstance(node,(ast.FunctionDef,ast.ClassDef))}
    # The controls are literal retained definitions. Production/admission is
    # the only changed top-level setup; original tests and assertions remain.
    old_functions=function_bodies(original_raw)
    new_functions=function_bodies(own_raw)
    assert all(new_functions[name]==body for name,body in old_functions.items())
    report["retained_control_definitions_unchanged"]=True
    report["original_driver_sha256"]=digest(original_raw)
    producer=ROOT.parent/"normalization-note-packer-v71-r1"
    receipt=producer/"native-r1"/"native-RESULT.json"
    reference=producer/"reference-RESULT.json"
    receipt_raw=receipt.read_bytes();reference_raw=reference.read_bytes()
    assert len(receipt_raw)==17008 and digest(receipt_raw)=="65bcbfa3e4373a549fac67151472df88c944ea1f6934f08db06c5dcc585378ec"
    assert len(reference_raw)==80730 and digest(reference_raw)=="7753f7899704257a04689a66c6317f81d09662177dfa19422950abcab0284b55"
    inputs[str(receipt)]=digest(receipt_raw);inputs[str(reference)]=digest(reference_raw)
    production=json.loads(receipt_raw)
    assert production["schema"]=="hepta.hia.cpython-note-packer.native-development.v1"
    assert production["status"]=="PASS_HIA_PACKER_EMISSION_ONLY" and not production["failures"]
    assert production["production_c_compiler_used"] is False
    assert production["current_source_cold_qualification"] is False
    assert len(production["observations"])==6
    assert all(row["passed"] is True and row["every_byte_equal"] is True for row in production["observations"])
    assert production["source_clean_before"] is True and production["source_clean_after"] is True
    for name in ("compiler","native_packer","expected","packer_source"):
        before=production[name+"_before"];after=production[name+"_after"]
        assert before==after
        p=Path(before["path"]);content=p.read_bytes()
        assert len(content)==before["bytes"] and digest(content)==before["sha256"]
        inputs[str(p)]=digest(content)
    image=producer/"native-r1"/"cpython-note.image.bin"
    raw_image=image.read_bytes()
    assert len(raw_image)==298 and digest(raw_image)=="d1ed5ac60b3d84952157262d6ea4252cbe4346c38417281945af636f5deacf23"
    assert production["produced_image"]=={"path":str(image),"bytes":298,"sha256":digest(raw_image)}
    binaries[str(image)]=digest(raw_image)
    report["image"]={"path":str(image),"bytes":len(raw_image),"sha256":digest(raw_image)}
    c_reference=ROOT/"evidence"/"flat-cpython-notes-r7"/"note.image.bin"
    c_reference_result=ROOT/"evidence"/"flat-cpython-notes-r7"/"RESULT.json"
    raw_c=c_reference.read_bytes();raw_c_result=c_reference_result.read_bytes()
    assert len(raw_c)==302 and digest(raw_c)=="83a1c56a8b373f72034fb4da4f1d4cf2f96f471294a3e3746031b58c21fecfbc"
    assert len(raw_c_result)==51470 and digest(raw_c_result)=="f52091415ecf3e9ab1d448920b2a1c37b12ba8ac7e03fc46f1304627eabd7bd8"
    inputs[str(c_reference)]=digest(raw_c);inputs[str(c_reference_result)]=digest(raw_c_result)
    report["production_receipt"]={"path":str(receipt),"bytes":len(receipt_raw),"sha256":digest(receipt_raw),
        "reference_path":str(reference),"reference_bytes":len(reference_raw),"reference_sha256":digest(reference_raw)}
    report["original_C302_reference"]={"path":str(c_reference),"bytes":len(raw_c),"sha256":digest(raw_c),
        "result_path":str(c_reference_result),"result_sha256":digest(raw_c_result),
        "results_inherited":False}
    bridge=SOURCE/"hepta"/"hia_program_normalization_notes.py"
    spec=importlib.util.spec_from_file_location("hepta.hia_program_normalization_notes",bridge)
    transport=importlib.util.module_from_spec(spec);sys.modules[spec.name]=transport;spec.loader.exec_module(transport)
    module=transport.NativeCPythonNotes(raw_image,digest(raw_image))
    report["api_identity"]=module.api_identity
    report["interpreter_identity"]=module.interpreter_identity
    for binding in module.api_identity:inputs[binding["image"]]=binding["image_sha256"]
    inputs[module.interpreter_identity["executable"]]=module.interpreter_identity["executable_sha256"]
    report["api_table_sha256"]=digest(module._api_map[:])
    code_map=mapping(module._code_address);api_map=mapping(module._api_address)
    assert code_map["permissions"][:3]=="r-x"
    assert api_map["permissions"][:3]=="r--"
    assert module._api_map[:]==module._expected_api
    report["observations"].append({"case":"actual_kernel_mapping_permissions",
        "code":code_map,"api_table":api_map,"passed":True})
    primitive=load_definitions(ROOT/"helpers"/"probe_cpython314_notes_r1.py",
        "4dd25770fedbf4b5c503ddcb901b4131199f485d7945035f4aaf63e10abd4737",
        {"__name__":"__main__","json":json,"sys":sys,"weakref":weakref},exclude={"main"})
    cases=("dict","list","tuple","derived_map","derived_list","derived_tuple",
        "default_object","nested","key_repr","key_repr_interrupt","prior_notes",
        "invalid_notes","preexisting_chain","override_public_add_note")
    for name in cases:
        report["observations"].append(primitive["compare"](name,module))
    for name in ("retained_reference_control","invalid_frame_control"):
        report["observations"].append(primitive[name](module))
    context=load_definitions(ROOT/"helpers"/"probe_cpython314_note_context_r2.py",
        "d41e5b9868fc067b24132b04c13208969afbf1aaea44468f9912d562596afd63",
        {"__name__":"__main__","json":json,"sys":sys})
    for handled,interrupt in (("none",False),("outer",False),("nested",False),
            ("outer",True),("nested",True),("same_primary",False),("same_primary",True)):
        original=context["run"](context["original"],handled,interrupt,module)
        actual=context["run"](context["fixed"],handled,interrupt,module)
        assert original==actual,(handled,interrupt,original,actual)
        report["observations"].append({"case":"handled_exception_context",
            "handled":handled,"interrupt":interrupt,"original":original,"actual":actual,"equal":True})
    original=context["run"](context["original"],"outer",False,module)
    wrong=context["run"](context["wrong_inside_child_handler"],"outer",False,module)
    assert original!=wrong
    assert original["events"][-1]["handled_is_outer"] and wrong["events"][-1]["handled_is_primary"]
    report["observations"].append({"case":"wrong_handler_placement_negative",
        "original":original,"wrong":wrong,"detected":True})
    for handled in ("none","outer","nested","same_primary"):
        report["observations"].append(deliver_observation(module,handled))
    report["observations"].append(invalid_delivery_control(module))
    report["observations"].append(invalid_c_delivery_fields(module))
    report["observations"].append(delivery_negative(module))
    report["observations"].append(replacement_lifetime_control(module))
    # Each child intentionally attempts one byte write to its own private
    # mapping. A real protection fault is required; no product file is edited.
    child_code="""import ctypes,hashlib,importlib.util,os,resource,sys
from pathlib import Path
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
sys.dont_write_bytecode=True
sys.path.insert(0,sys.argv[1])
spec=importlib.util.spec_from_file_location('hepta.hia_program_normalization_notes',sys.argv[2])
transport=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=transport
spec.loader.exec_module(transport)
raw=Path(sys.argv[3]).read_bytes()
assert hashlib.sha256(raw).hexdigest()==sys.argv[4]
owner=transport.NativeCPythonNotes(raw,sys.argv[4])
address=owner._code_address if sys.argv[5]=='code' else owner._api_address
ctypes.memmove(address,b'X',1)
os._exit(41)
"""
    for part in ("code","api"):
        command=[sys.executable,"-B","-c",child_code,str(BASE),str(bridge),str(image),digest(raw_image),part]
        child=subprocess.run(command,capture_output=True,timeout=10)
        put(CASE/("readonly-"+part+".stdout"),child.stdout)
        put(CASE/("readonly-"+part+".stderr"),child.stderr)
        assert child.returncode==-11,(part,child.returncode,child.stderr)
        report["observations"].append({"case":"actual_private_mapping_write_refused",
            "mapping":part,"returncode":child.returncode,"stdout_sha256":digest(child.stdout),
            "stderr_sha256":digest(child.stderr)})
    assert len(report["observations"])==35
    module.close();assert module.closed and module._api_map is None and module._code is None and module._entry is None and module._delivery is None
    report["status"]="PASS_HIA_PRODUCED_HOSTED_NOTE_AND_DELIVERY_MECHANISM_ONLY"
except BaseException:
    report["status"]="FAIL"
    report["failures"].append(traceback.format_exc())
finally:
    if module is not None and not module.closed:
        try:module.close()
        except BaseException:report["failures"].append(traceback.format_exc());report["status"]="FAIL"
    try:
        for p,wanted in inputs.items():assert digest(Path(p).read_bytes())==wanted
        for p,wanted in binaries.items():assert digest(Path(p).read_bytes())==wanted
        for p,wanted in tools_before.items():assert digest(Path(p).read_bytes())==wanted
        report["source_image_toolchain_unchanged"]=True
    except BaseException:
        report["status"]="FAIL";report["failures"].append(traceback.format_exc())
    report["inputs"]=inputs;report["binaries"]=binaries;report["toolchain"]=tools_before
    report["script_sha256"]=digest(Path(__file__).read_bytes())
    report["elapsed_ns"]=time.monotonic_ns()-started
    raw=encoded(report);put(CASE/"RESULT.json",raw)
    print(json.dumps({"status":report["status"],"observations":len(report["observations"]),
        "result":str(CASE/"RESULT.json"),"bytes":len(raw),"sha256":digest(raw),
        "full_normalization_qualified":False,"physical_recursion_qualified":False},sort_keys=True))
if report["status"]!="PASS_HIA_PRODUCED_HOSTED_NOTE_AND_DELIVERY_MECHANISM_ONLY":raise SystemExit(1)
