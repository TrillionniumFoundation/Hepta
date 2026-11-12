"""Original-public-oracle and exact old/new type image differential controls."""
from __future__ import annotations
import argparse,ast,ctypes,importlib.util,json,os,resource,stat,sys,time,traceback
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
p=argparse.ArgumentParser()
for name in ("project","bundle","reference","out"):p.add_argument("--"+name,type=Path,required=True)
p.add_argument("--group",required=True)
a=p.parse_args();PROJECT=a.project.resolve();REF=a.reference.resolve();OUT=a.out.resolve()
OUT.mkdir(parents=True,exist_ok=False)
resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
assert libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0
START=time.monotonic_ns();INITIAL_SELF=resource.getrusage(resource.RUSAGE_SELF)
INITIAL_CHILD=resource.getrusage(resource.RUSAGE_CHILDREN)
PINS={};ROWS=[];failure=None;status="FAIL";mechanical=None;private=None
contexts=set();ops=set();plan_count=0;planned_commands=0;original_oracle_complete=False
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    path=Path(path).resolve();raw=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
    if path in PINS:assert PINS[path]==(raw,mode),path
    PINS[path]=(raw,mode);return raw
def unchanged():
    return all(path.is_file() and path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==mode
               for path,(raw,mode) in PINS.items())
def forbidden(*args,**kwargs):
    raise AssertionError("Original Python type semantics called during native interval")
def materialized_plan(values):
    result=[]
    for case in values:
        steps=[]
        for row in case["steps"]:
            steps.append(dict(row,wire=dict(bytes=len(row["wire"]),sha256=digest(row["wire"]),
                                           hex=row["wire"].hex())))
        result.append(dict(case,steps=steps))
    return result
try:
    pin(__file__);index=json.loads(pin(PROJECT/"sources.json"))
    for row in index["files"]:
        raw=pin(PROJECT/row["path"])
        assert (len(raw),digest(raw))==(row["bytes"],row["sha256"])
        if row["path"].endswith(".py"):ast.parse(raw,filename=row["path"])
    bundle=json.loads(pin(a.bundle))
    assert bundle["schema"]=="hia-native-type-context-bundle-r1" and bundle["status"]=="BUILT_ONLY"
    assert bundle["compiler_sha256"]=="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
    assert set(bundle["components"])=={"old-types","context-types","context-reader"}
    inventory=json.loads(pin(bundle["inventory"]))
    adaptation=json.loads(pin(bundle["adaptation"]))
    assert adaptation["all_other_method_AST_equal"] and adaptation["original_private_render_and_commit_AST_equal"]
    sys.path[:0]=[str(PROJECT/"development"),str(REF)]
    import hepta.hia_program_composite as composite
    import type_context_original_corpus_r1 as corpus
    from type_context_mechanical_r1 import Mechanical,Pair
    from type_context_private_controls_r1 import run as run_private
    assert digest(pin(REF/"hepta/hia_program_composite.py"))=="cc5ab4c8dc68214e8868aab30405820c3662572de63952dec5f1fd1aaf180951"
    assert digest(pin(REF/"hepta/hia_program.py"))=="76a222745e13fe29825a661be206243f137ada7b57292b07ab7513a40146fb92"
    if a.group=="reader-protocol":
        raw_plan=[corpus.scenario("private-base-nominal",corpus.named_fixture(1,"9bad")),
                  corpus.scenario("private-foreign-field",corpus.named_fixture(8,"9bad"))]
        plan_count=64
    else:
        raw_plan=corpus.plans(a.group);plan_count=len(raw_plan)
    plan=corpus.predeclare(composite,raw_plan)
    planned_commands=sum(len(row["steps"]) for row in plan)
    save(OUT/"original-public-predeclared-plan.json",dict(group=a.group,
        cases=materialized_plan(plan),original_public_oracle_complete_before_native=True,
        planned_commands=planned_commands,private_protocol_group=a.group=="reader-protocol"))
    original_oracle_complete=True
    for module in tuple(sys.modules.values()):
        filename=getattr(module,"__file__",None)
        if filename:
            path=Path(filename).resolve()
            if path.suffix==".py" and (path.is_relative_to(PROJECT) or path.is_relative_to(REF)):pin(path)
    mechanical=Mechanical(OUT,bundle,pin)
    # The complete independent public oracle is frozen above. From here only
    # source-bound native entries, byte copies, comparisons and ledger writes run.
    with patch.object(composite,"_Types",forbidden), \
         patch.object(composite._Elaborator,"_reference_parameters",forbidden), \
         patch.object(composite._Elaborator,"loan_origins",forbidden), \
         patch.object(composite._Elaborator,"_reference_check_task",forbidden), \
         patch.object(composite,"_name",forbidden):
        if a.group=="reader-protocol":
            private=run_private(mechanical,plan)
            ROWS=private["case_rows"]
        else:
            for scenario in plan:
                pair=Pair(mechanical);steps=[];first=mechanical.entries+1
                try:
                    for number,planned in enumerate(scenario["steps"],1):
                        label=scenario["label"]+"-command-"+str(number)
                        save(OUT/"pending-scenario.json",dict(label=scenario["label"],step=number,
                            planned_wire_sha256=digest(planned["wire"]),expected_error=planned["error"],
                            expected_context=planned["where"],first_native_entry=mechanical.entries+1))
                        result=pair.command(planned,label);steps.append(result);ops.add(planned["operation"])
                        if planned["where"]:
                            c=result["actual_context_fields"]
                            contexts.add((c[2],c[3],c[4]))
                        save(OUT/"scenarios"/scenario["label"]/"steps.json",steps)
                    row=dict(label=scenario["label"],status="PASS",commands=len(steps),steps=steps,
                        first_native_entry=first,last_native_entry=mechanical.entries,
                        original_public_texts_compared=True,
                        entire_native_outputs_workspaces_compared=True,
                        exact_context_and_declared_error_word_exclusions_only=True)
                    ROWS.append(row);save(OUT/"cases-completed.json",ROWS)
                finally:pair.close()
    assert len(ROWS)==plan_count and all(row["status"]=="PASS" for row in ROWS)
    assert unchanged()
    status="PASS"
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    if mechanical is not None:
        try:mechanical.close()
        except BaseException as exc:
            status="FAIL";failure=dict(error_class="MechanicalCleanupFailure",error=str(exc),
                                      traceback=traceback.format_exc(),earlier_failure=failure)
            traceback.print_exc()
    same=unchanged()
    if not same:status="FAIL"
    current=resource.getrusage(resource.RUSAGE_SELF);child=resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu=(current.ru_utime+current.ru_stime-INITIAL_SELF.ru_utime-INITIAL_SELF.ru_stime+
         child.ru_utime+child.ru_stime-INITIAL_CHILD.ru_utime-INITIAL_CHILD.ru_stime)
    if cpu>=90:
        status="FAIL";failure=dict(error_class="AggregateCpuBudgetObservation",
                                  actual_cpu_seconds=cpu,earlier_failure=failure)
    save(OUT/"source-pins.json",[dict(path=str(path),bytes=len(raw),sha256=digest(raw),mode=mode)
         for path,(raw,mode) in PINS.items()])
    report=dict(schema="hia-native-type-context-actual-group-r1",status=status,group=a.group,
       planned_cases=plan_count,completed_cases=len(ROWS),planned_oracle_commands=planned_commands,
       original_oracle_predeclared_before_native=original_oracle_complete,
       actual_entries=0 if mechanical is None else mechanical.entries,
       actual_entries_by_role={} if mechanical is None else mechanical.by_role,
       actual_context_tuples=[list(row) for row in sorted(contexts)],
       actual_type_operations=sorted(ops),all_full_buffers_retained_as_exact_ordered_page_CAS=True,
       source_image_before_after_equal=same,failure=failure,private_controls=private,
       aggregate_cpu_seconds=cpu,elapsed_ns=time.monotonic_ns()-START,
       original_limits=dict(cpu=90,wall=180,address=1<<30),
       native_context_issuer_is_actual_type_image=a.group!="reader-protocol",
       arbitrary_external_workspaces_authenticated=False,
       actual_program_driver_joined=False,whole_public_diagnostics_closed=False,
       namespace_issued=False,whole_worker_closed=False)
    save(OUT/"summary.json",report)
    print("HIA_TYPE_CONTEXT_GROUP "+json.dumps(report,sort_keys=True),flush=True)
if status!="PASS":raise SystemExit(1)
