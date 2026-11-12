"""Actual fixed Worker diagnostic route and exact public-text regressions.

The original 113 cases remain an independent retained panel. New public cases
compare the unselected exact original verify/render API, including known
contextual text gaps. No enum table is substituted for that public oracle.
Private child/ACK controls remain separately classified as foreign fixtures.
"""
from __future__ import annotations
import argparse,ast,copy,ctypes,importlib.util,json,os,resource,signal,stat,struct,subprocess,sys,time,traceback,zlib
from hashlib import sha256
from pathlib import Path
sys.dont_write_bytecode=True
GROUPS={"semantic":45,"assembly-boundary":22,"object-boundary":8,"private-protocol":35,
        "example-chain":3,"public-fixed":62,"public-helper-budget":1,
        "public-late-inventory":1,"public-context":4,"diagnostic-protocol":100}
p=argparse.ArgumentParser()
p.add_argument("--bundle",type=Path,required=True);p.add_argument("--reference",type=Path,required=True)
p.add_argument("--out",type=Path,required=True);p.add_argument("--group",choices=tuple(GROUPS),required=True)
a=p.parse_args();OUT=a.out.resolve();OUT.mkdir(parents=True,exist_ok=False)
REF=a.reference.resolve();PROJECT=Path(__file__).resolve().parents[1]
bundle_raw=a.bundle.read_bytes();bundle=json.loads(bundle_raw)
EXE=Path(bundle["executable_path"]);exe_raw=EXE.read_bytes()
assert (len(exe_raw),sha256(exe_raw).hexdigest())==(bundle["executable_bytes"],bundle["executable_sha256"])
assert bundle["compiler_sha256"]=="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
assert bundle["fresh_compiles"]==7 and bundle["nonzero_images"]==42
assert bundle["fixed_diagnostic_groups"]==[1,2,3,4,5] and bundle["inherited_composite_refusal_text_missing_groups"]==[6,9]
resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
assert libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0
SELF_PARENT=os.getpid();START=time.monotonic_ns()
INITIAL_CPU=resource.getrusage(resource.RUSAGE_SELF);INITIAL_CHILD=resource.getrusage(resource.RUSAGE_CHILDREN)
PINS={a.bundle.resolve():(bundle_raw,stat.S_IMODE(a.bundle.stat().st_mode)),
      EXE.resolve():(exe_raw,stat.S_IMODE(EXE.stat().st_mode)),
      Path(__file__).resolve():(Path(__file__).read_bytes(),stat.S_IMODE(Path(__file__).stat().st_mode))}
ROWS=[];NATIVE=0;KERNEL_ENTRIES=0;FAILED=None;STATUS="FAIL";PLAN=[];CASE_FAILURES=[];PRIVATE=None
original=PROJECT/"development/test_worker_program_service_r4.py";original_raw=original.read_bytes()
assert sha256(original_raw).hexdigest()=="d10d9b4f2289a4e770a6680a2a10a81975d941bcec387cfd4fb59f3f23c37937"
# Only exact reusable test functions are loaded; the old script's main,
# argument parsing and prior panel are not executed as a hidden fallback.
nodes=ast.parse(original_raw,filename=str(original)).body
functions=[n for n in nodes if isinstance(n,ast.FunctionDef)]
assert len({n.name for n in functions})==len(functions)
exec(compile(ast.Module(body=functions,type_ignores=[]),str(original)+":exact-test-functions","exec"),globals())
pin(original)
CATALOG=json.loads(pin(bundle["diagnostic_catalog"]))
FIXED={(row["group"],row["error"]):(row["code"]+": "+row["message"]).encode("utf-8")
       for row in CATALOG["entries"]}

def reference_trace(value):
    try:verify_program(value)
    except HIAProgramRejected as exc:
        result=dict(code=exc.code,text=str(exc),frames=[dict(file=f.filename,function=f.name,line=f.lineno)
            for f in traceback.extract_tb(exc.__traceback__)])
        return result
    raise AssertionError("public refusal fixture was accepted")

def add_fixed(label,value,pair,tree=0,mode=1):
    add(label,mode,value,tree=tree,accept=False)
    row=PLAN[-1]
    row["catalog_pair_predeclared_before_native"]=pair
    row["adapter_enum_text_equal_to_public_before_native"]=row["expected"]["payload"]==FIXED[pair]
    # A disagreement is retained and exercised against the original public
    # oracle below; it must not stop the actual native call or change expected.

def public_fixed_plan():
    changes=[]
    def append(label,value,pair):changes.append((label,value,pair))
    def base():return composite(1)
    v=base();v["extra"]=None;append("constructor-inventory",v,(1,1))
    v=base();v["module"]="9bad";append("constructor-module",v,(1,4))
    v=base();v["module"]="h2internal_module";append("constructor-reserved-module",v,(1,5))
    v=base();v["functions"]=[];append("constructor-functions-empty",v,(1,6))
    v=base();v["functions"][0]["extra"]=0;append("constructor-function-inventory",v,(1,7))
    v=base();v["functions"][0]["name"]="9bad";append("constructor-function-name",v,(1,9))
    v=base();v["functions"].append(copy.deepcopy(v["functions"][0]));append("constructor-duplicate-function",v,(1,11))
    v=base();v["functions"][0]["effects"]=["read","read"];append("constructor-effects",v,(1,14))
    v=base();v["types"]={};append("type-inventory",v,(2,2))
    v=base();v["types"]=[{}];append("type-missing-kind",v,(2,3))
    v=base();v["types"]=[{"kind":"unsupported"}];append("type-unknown-kind",v,(2,4))
    definition={"name":"T","kind":"record","params":[],"fields":[]}
    v=base();v["types"]=[copy.deepcopy(definition),copy.deepcopy(definition)];append("type-duplicate",v,(2,7))
    v=base();v["types"]=[dict(definition,params=None)];append("type-parameter-list",v,(2,8))
    v=base();v["types"]=[dict(definition,params=["A","A"])];append("type-parameter-duplicate",v,(2,10))
    v=base();v["functions"][0]["params"][0]["type"]="Missing";append("type-unissued-reference",v,(2,18))
    v=base();v["functions"][0]["params"]=None;append("type-signature-parameters",v,(2,45))
    v=base();v["functions"][0]["blocks"]=[];append("function-blocks",v,(3,1))
    v=base();v["functions"][0]["blocks"][0]["extra"]=0;append("function-block-inventory",v,(3,2))
    v=base();v["functions"][0]["blocks"][0]["id"]="9bad";append("function-block-name",v,(3,3))
    v=base();v["functions"][0]["blocks"].append(copy.deepcopy(v["functions"][0]["blocks"][0]));append("function-duplicate-block",v,(3,5))
    v=base();v["functions"][0]["blocks"][0]["ops"]=None;append("function-operations",v,(3,6))
    v=base();v["functions"][0]["blocks"][0]["ops"]=[{}];append("function-instruction-inventory",v,(3,7))
    v=base();v["functions"][0]["blocks"][0]["params"]=[];append("function-entry-signature",v,(3,15))
    v=base();v["functions"][0]["blocks"][0]["term"]=None;append("function-terminator",v,(3,200))
    assert len(changes)==24
    for label,value,pair in changes:
        for tree in (0,1):add_fixed(label+"-tree"+str(tree),value,pair,tree=tree)
    for version in (2,3,4):
        v=composite(version);v["functions"][0]["params"][0]["type"]="Missing"
        add_fixed("version-type-"+str(version),v,(2,18))
        v=composite(version);v["functions"][0]["blocks"][0]["ops"]=None
        add_fixed("version-function-"+str(version),v,(3,6))
    for version in (1,2,3,4):
        v=composite(version);v["functions"]=[]
        add_fixed("render-first-verifies-"+str(version),v,(1,6),mode=2)
    v=base();v["module"]="9bad";v["types"]={}
    add_fixed("precedence-module-before-types",v,(1,4))
    v=base();v["types"]={};v["functions"]=[]
    add_fixed("precedence-types-before-functions",v,(2,2))
    v=base();v["functions"][0]["blocks"]=[];v["functions"].append(copy.deepcopy(v["functions"][0]))
    add_fixed("precedence-all-signatures-before-bodies",v,(1,11))
    v=base();v["functions"][0]["params"][0]["type"]="Missing";v["functions"][0]["effects"]=["not-an-effect"]
    add_fixed("precedence-parameters-before-effects",v,(2,18))
    assert len(PLAN)==62

def public_context_plan():
    def base():return composite(1)
    definitions=[
      ("nominal-type-name",{"name":"9bad","kind":"record","params":[],"fields":[]},(2,5)),
      ("nominal-type-inventory",{"name":"T","kind":"record","params":[]},(2,1)),
      ("field-name",{"name":"T","kind":"record","params":[],"fields":[{"name":"9bad","type":"u8"}]},(2,5)),
      ("type-parameter-name",{"name":"T","kind":"record","params":["9bad"],"fields":[]},(2,5))]
    rows=[]
    for label,definition,pair in definitions:
        value=base();value["types"]=[definition]
        add("public-context-"+label,1,value,accept=False)
        PLAN[-1]["catalog_pair"]=pair
        rows.append(dict(label=label,input=cas(transport(value)),
            public_oracle=cas(PLAN[-1]["expected"]["payload"]),
            existing_native_enum_text=cas(FIXED[pair]),
            literal_alone_equal_to_public=PLAN[-1]["expected"]["payload"]==FIXED[pair],
            actual_original_trace=reference_trace(transport(value))))
    save(OUT/"public-context-before-native.json",dict(cases=rows,
        mismatches_must_fail_public_test=True,host_context_reconstruction_forbidden=True,
        original_enum_table_is_not_the_public_oracle=True))
    assert len(PLAN)==4

def public_helper_budget_plan():
    def field(name,typ):return {"name":name,"type":typ}
    def record(name,fields):return {"name":name,"params":[],"kind":"record","fields":fields}
    small=record("Small",[field("v"+str(i),"u8") for i in range(64)])
    large=record("Large",[field("v"+str(i),"Small") for i in range(8)])
    medium=record("Medium",[field("s"+str(i),"Small") for i in range(7)]+[field("b"+str(i),"u8") for i in range(52)])
    step={"name":"Step","params":[],"kind":"enum","variants":[
        {"name":"pending","fields":[field("state","unit")]},
        {"name":"ready","fields":[field("result","unit")]}]}
    task={"name":"Work","params":[],"kind":"task","state":"unit","result":"unit",
          "poll":"poll","cancel":"cancel"}
    def fn(name,params,returns,ops,effects=()):
        return {"name":name,"params":params,"returns":returns,"effects":list(effects),"entry":"entry",
                "blocks":[{"id":"entry","params":copy.deepcopy(params),"ops":ops,"term":{"op":"ret","values":[]}}]}
    poll=fn("poll",[field("state","unit")],["Step"],[
        {"op":"enum.make","args":["state"],"out":[field("step","Step")],"attrs":{"variant":"ready"}}])
    poll["blocks"][0]["term"]["values"]=["step"]
    cancel=fn("cancel",[field("state","unit")],[],[])
    params=[field("large"+str(i),"Large") for i in range(15)]+[field("medium","Medium"),field("task","Work")]
    main=fn("budget",params,[],[{"op":"task.close","args":["task"],"out":[],"attrs":{}}],["alloc","trap"])
    value={"schema":"hepta.hia.composite.v1","module":"helper_budget","types":[small,large,medium,step,task],
           "functions":[poll,cancel,main]}
    trace=reference_trace(value)
    assert any(row["function"]=="_reference_helper" for row in trace["frames"]),trace
    save(OUT/"original-helper-budget-trace.json",trace)
    add_fixed("actual-public-helper-fresh-exhaustion",value,(4,1))
    assert len(PLAN)==1

def public_late_inventory_plan():
    enum={"name":"Choice","params":[],"kind":"enum","variants":[
        {"name":"left","fields":[]},{"name":"right","fields":[]}]}
    params=[{"name":"choice","type":"Choice"}]
    blocks=[{"id":"entry","params":params,"ops":[],"term":{"op":"match","value":"choice","cases":[
        {"variant":"left","target":"b1","args":[]},{"variant":"right","target":"b2","args":[]}]}}]
    blocks.extend({"id":"b"+str(i),"params":[],"ops":[],"term":{"op":"ret","values":[]}}
                  for i in range(1,4093))
    value={"schema":"hepta.hia.composite.v1","module":"late_inventory","types":[enum],
           "functions":[{"name":"choose","params":params,"returns":[],"effects":["trap"],
                         "entry":"entry","blocks":blocks}]}
    assert len(blocks)==4093
    trace=reference_trace(value)
    assert any(row["function"]=="_reference_lower" for row in trace["frames"]),trace
    save(OUT/"original-late-inventory-trace.json",trace)
    add_fixed("actual-public-late-block-inventory",value,(5,1))
    assert len(PLAN)==1

def diagnostic_native_planned():
    for index,row in enumerate(PLAN):
        lease=0x575d0001+index*8;request=index+1
        packet=header(row["source"],row["mode"],lease,request,tree=row["tree"])+row["source"]
        process,stdout,stderr=actual(row["label"],packet)
        observation=dict(label=row["label"],process=process,
          actual_complete_stdout=cas(stdout),actual_complete_stderr=cas(stderr),
          expected_complete_payload=cas(row["expected"]["payload"]),
          public_original_oracle=True,enum_not_substituted=True)
        # Preserve the actual complete outputs before any semantic assertion.
        save(OUT/"cases"/row["label"]/"comparison-before-assert.json",observation)
        try:
            result=parse_result(process,stdout,stderr,row,lease,request)
            observation.update(status="PASS",result=cas(result),
               complete_payload_and_Core_bytes_equal=True,actual_receipt_digests_equal=True)
        except AssertionError as exc:
            failure=dict(label=row["label"],error_class=type(exc).__name__,error=str(exc),
                         traceback=traceback.format_exc())
            CASE_FAILURES.append(failure);observation.update(status="FAIL",failure=failure)
            traceback.print_exc()
        ROWS.append(observation);save(OUT/"cases-completed.json",ROWS)

try:
    sys.path.insert(0,str(REF))
    from hepta.hia_program import HIAProgramRejected,verify_program
    from hepta.hia_agent_assembly import HIAAssemblyRejected,render_assembly,assemble_program,diagnose_assembly
    for row in bundle["role_bindings"].values():
        for key,sha,size in (("source_path","source_sha256","source_bytes"),("image_path","image_sha256","image_bytes")):
            raw=pin(row[key]);assert (len(raw),digest(raw))==(row[size],row[sha])
    if a.group=="semantic":semantic_plan()
    elif a.group=="assembly-boundary":assembly_boundary_plan()
    elif a.group=="object-boundary":object_boundary_plan()
    elif a.group=="public-fixed":public_fixed_plan()
    elif a.group=="public-context":public_context_plan()
    elif a.group=="public-helper-budget":public_helper_budget_plan()
    elif a.group=="public-late-inventory":public_late_inventory_plan()
    for module in tuple(sys.modules.values()):
        filename=getattr(module,"__file__",None)
        if filename and Path(filename).resolve().is_relative_to(REF) and Path(filename).suffix==".py":pin(filename)
    if a.group=="private-protocol":private_protocol()
    elif a.group=="diagnostic-protocol":
        path=PROJECT/"development/worker_program_diagnostic_controls_r1.py";raw=pin(path)
        spec=importlib.util.spec_from_file_location("worker_diagnostic_private_controls",path)
        peer=importlib.util.module_from_spec(spec);spec.loader.exec_module(peer)
        PRIVATE=peer.run(globals())
    elif a.group=="example-chain":example_chain()
    elif a.group.startswith("public-"):
        assert len(PLAN)==GROUPS[a.group]
        record_plan();diagnostic_native_planned()
    else:
        record_plan();native_planned()
    assert len(ROWS)==GROUPS[a.group]
    if a.group=="private-protocol":assert KERNEL_ENTRIES==38 and NATIVE==5
    if a.group=="diagnostic-protocol":
        assert NATIVE==0 and KERNEL_ENTRIES>0 and PRIVATE["planned_cases"]==100
    assert unchanged()
    if CASE_FAILURES:raise AssertionError(("public full-text mismatches",len(CASE_FAILURES)))
    assert all(row["status"]=="PASS" for row in ROWS)
    STATUS="PASS"
except BaseException as exc:
    FAILED=dict(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    same=unchanged()
    if not same:STATUS="FAIL"
    current=resource.getrusage(resource.RUSAGE_SELF);children=resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu=(current.ru_utime+current.ru_stime-INITIAL_CPU.ru_utime-INITIAL_CPU.ru_stime+
         children.ru_utime+children.ru_stime-INITIAL_CHILD.ru_utime-INITIAL_CHILD.ru_stime)
    if cpu>=90:
        STATUS="FAIL";FAILED=dict(error_class="AggregateCpuBudgetObservation",actual_cpu_seconds=cpu,earlier_failure=FAILED)
    save(OUT/"source-pins.json",[dict(path=str(path),bytes=len(raw),sha256=digest(raw),mode=mode)
         for path,(raw,mode) in PINS.items()])
    report=dict(schema="hia-worker-program-fixed-diagnostics-actual-r1",status=STATUS,group=a.group,
        planned_cases=GROUPS[a.group],planned_semantic_cases=len(PLAN),attempted_case_results=len(ROWS),
        completed_cases=sum(row["status"]=="PASS" for row in ROWS),
        failed_cases=sum(row["status"]=="FAIL" for row in ROWS),
        actual_native_processes=NATIVE,actual_private_kernel_entries=KERNEL_ENTRIES,
        aggregate_cpu_seconds=cpu,elapsed_ns=time.monotonic_ns()-START,failure=FAILED,
        public_case_failures=CASE_FAILURES,private_controls=PRIVATE,
        full_public_payload_required=True,public_oracle_is_unselected_original=True,
        enum_table_cannot_replace_public_oracle=True,
        source_image_executable_before_after_equal=same,
        retained_panel_reexecuted_on_new_identity=a.group in ("semantic","assembly-boundary","object-boundary","private-protocol","example-chain"),
        old_case_counts_inherited=False,
        original_limits=dict(cpu=90,wall=180,address=1<<30),
        original_enum_format_groups=[1,2,3,4,5],known_public_context_text_not_declared_closed=True,
        inherited_composite_refusal_text_missing_groups=[6,9],whole_public_diagnostics_closed=False,
        namespace_issued=False,whole_worker_closed=False,installed_activation=False,cold_qualified=False)
    save(OUT/"summary.json",report)
    print("HIA_WORKER_PROGRAM_DIAGNOSTIC_GROUP "+json.dumps(report,sort_keys=True),flush=True)
if STATUS!="PASS":raise SystemExit(1)
