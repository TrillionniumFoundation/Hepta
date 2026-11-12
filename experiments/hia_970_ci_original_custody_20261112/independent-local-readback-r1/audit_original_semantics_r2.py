"""Read-only semantic joins for the exact retained 970 originals. No project imports."""
import ast, collections, hashlib, json, os, re
from pathlib import Path
ROOT=Path(__file__).resolve().parent
RAW=ROOT/"container-readback-r1"/"inner-originals"
OUT=ROOT/"semantic-readback-r2"
OUT.mkdir(mode=0o700,exist_ok=False)
selected=json.loads((RAW/"SELECTED.json").read_bytes())
rows={r["original_name"]:r for r in selected["selected_members"]}
TEMP="/home/runner/work/_temp/"
SRC="/home/runner/work/Hepta/Hepta/"
OWNER_SHA="36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2"
checks=[];missing_physical={};joined_records={}
def sha(b):return hashlib.sha256(b).hexdigest()
def b(name):return (RAW/rows[name]["retained_file"]).read_bytes()
def j(name):return json.loads(b(name))
def req(ok,name):
    if not ok:raise AssertionError(name)
    checks.append(name)
def file_record(name):
    r=rows[name];return {"name":name,"retained_file":r["retained_file"],"bytes":r["bytes"],"sha256":r["sha256"]}
def literal(path,name):
    for node in ast.parse((ROOT/"source-970"/path).read_bytes()).body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in node.targets):return ast.literal_eval(node.value)
    raise ValueError("literal absent: "+name)
def natural(owner,request,owner_raw,request_raw,wrapped=None):
    req(owner["schema"]=="hepta.hia.selfhost-process-owner.v1" and request["schema"]==owner["schema"],"owner schema")
    req(owner["implementation_sha256"]==request["implementation_sha256"]==OWNER_SHA,"fixed owner implementation")
    req(owner["qualification_seconds"]==request["qualification_seconds"]==180 and owner["cleanup_seconds"]==request["cleanup_seconds"]==3,"original 180 and 3")
    req(request["deadline_ns"]-request["started_ns"]==180_000_000_000,"original request deadline")
    req(owner["request_sha256"]==sha(request_raw),"raw request SHA")
    req(owner["status"]=="OWNED_PROCESS_COMPLETED" and owner["returncode"]==0 and owner["qualification_started"] is True and owner["exit_observed_before_deadline"] is True,"natural zero exit")
    req(owner["timed_out"] is False and owner["event_overflow"] is False and owner["interrupted_signals"]==[] and owner["subreaper_enabled"] is True,"no timeout overflow interruption")
    cl=owner["cleanup"]
    req(cl["attempted"] is True and cl["complete"] is True and cl["observed_echild"] is True and cl["leader_reaped"] is True and cl["deadline_exceeded"] is False and cl["errors"]==[] and cl["remaining_direct_children"]==[],"natural ECHILD cleanup")
    kinds=[e["kind"] for e in owner["events"]]
    req(kinds==["qualification_started","owned_child_observed","qualification_exit_observed","owned_child_reaped"],"four natural owner events")
    req(owner["events"][2]["si_code"]==1 and owner["events"][2]["si_status"]==0 and owner["events"][3]["returncode"]==0,"natural owner exit status")
    req(owner["parent_pid"]==request["parent_pid"],"parent identity")
    req(owner["events"][2]["monotonic_ns"]<request["deadline_ns"],"actual exit before original deadline")
    if wrapped is not None:
        req(wrapped["supervisor_returncode"]==0 and wrapped["receipt_sha256"]==sha(owner_raw),"wrapper raw owner binding")
        req({k:v for k,v in wrapped.items() if k not in ("supervisor_returncode","receipt_sha256")}==owner,"wrapper adds only two actual fields")
    return {"qualification_seconds":180,"cleanup_seconds":3,"qualification_ns":owner["events"][2]["monotonic_ns"]-owner["events"][0]["monotonic_ns"],"cleanup_ns":cl["elapsed_ns"],"request_sha256":sha(request_raw),"receipt_sha256":sha(owner_raw),"historical_descendant_inventory_complete":owner["historical_descendant_inventory_complete"]}
def all_records(value):
    if isinstance(value,dict):
        if isinstance(value.get("path"),str) and type(value.get("bytes")) is int and isinstance(value.get("sha256"),str):
            path=value["path"]
            if path.startswith(TEMP) and path[len(TEMP):] in rows:
                name=path[len(TEMP):];r=rows[name]
                req(value["bytes"]==r["bytes"] and value["sha256"]==r["sha256"],"selected record join "+name)
                joined_records[path]=file_record(name)
            elif path.startswith(SRC) and (ROOT/"source-970"/path[len(SRC):]).is_file():
                data=(ROOT/"source-970"/path[len(SRC):]).read_bytes()
                req(value["bytes"]==len(data) and value["sha256"]==sha(data),"canonical source record join "+path[len(SRC):])
            else:
                prior=missing_physical.get(path)
                if prior is not None:req(prior=={"bytes":value["bytes"],"sha256":value["sha256"]},"unselected repeated identity")
                missing_physical[path]={"bytes":value["bytes"],"sha256":value["sha256"]}
        for v in value.values():all_records(v)
    elif isinstance(value,list):
        for v in value:all_records(v)
policy=json.loads((ROOT/"inputs"/"policy.json").read_bytes())
c=j("hia-cold.json");q=j("hia-cold.cold/qualification.json");ix=j("hia-cold.cold/qualification.evidence/phase-index.json")
source=c["source_manifest"];sd=sha(json.dumps(source,sort_keys=True,separators=(",",":")).encode())
req(len(source)==787 and sd==policy["source"]["source_manifest_canonical_sha256"],"exact external 787 source closure")
req(q["source_manifest"]==source==j("hia-cold.cold/request.json")["source_manifest"],"cold request outer nested source equality")
req(source[q["support_contract"]["path"]]==policy["source"]["contract_sha256"],"external contract SHA")
source_reads=[]
for path in sorted((ROOT/"source-970").rglob("*")):
    if path.is_file():
        rel=path.relative_to(ROOT/"source-970").as_posix()
        req(rel in source and sha(path.read_bytes())==source[rel],"canonical read matches actual source "+rel)
        source_reads.append({"path":rel,"bytes":path.stat().st_size,"sha256":sha(path.read_bytes())})
req(c["schema"]=="hepta.hia.selfhost-cold-replay.v1" and c["status"]=="COLD_SELFHOST_REPLAY_PASS" and c["returncode"]==0,"original cold PASS")
req(c["profile"]==q["profile"]==policy["source"]["profile"],"exact profile")
req(len(c["checks"])==11 and all(v is True for v in c["checks"].values()),"all 11 cold checks true")
req(c["qualification_wall_limit_seconds"]==180 and c["cleanup_wall_limit_seconds"]==3 and c["wall_elapsed_ns"]==137407936075,"actual cold original deadline and elapsed")
req(c["nested_report_sha256"]==sha(b("hia-cold.cold/qualification.json")),"outer to full 53MB nested SHA")
req(q["schema"]=="hepta.hia.selfhost-qualification.v6" and q["status"]=="SELF_HOSTED_FIXED_CORE_PASS" and len(q["checks"])==5051 and all(v is True for v in q["checks"].values()),"all 5051 nested checks true")
cold_owner=natural(j("hia-cold.cold/process-owner.json"),j("hia-cold.cold/process-owner.json.request.json"),b("hia-cold.cold/process-owner.json"),b("hia-cold.cold/process-owner.json.request.json"),c["process_owner"])
req(j("hia-cold.cold/request.json")["command"]==j("hia-cold.cold/process-owner.json.request.json")["command"],"cold original command binding")
families=literal("tools/qualify_hia_selfhost.py","QUALIFICATION_FAMILIES")
req(literal("tools/qualify_hia_selfhost.py","QUALIFICATION_WORKERS")==2 and len(families)==19,"canonical 19 families and 2 workers")
expected=[(family,label) for family in families for label in ("original","modified")]
sched=q["qualification_scheduling"]
req(sched["maximum_host_oracle_workers"]==2 and sched["maximum_archive_workers"]==1 and sched["maximum_pending_archives"]==2 and sched["maximum_unsealed_phase_directories"]==4,"original parallel and archive limits")
req(sched["phase_inventory"]==[f+"-"+l for f,l in expected],"full ordered 38 inventory")
req(ix["schema"]=="hepta.hia.selfhost-phase-index.v1" and ix["completed"]==38 and ix["exceptions"]==0 and len(ix["phases"])==38,"actual complete phase index")
req(len(sched["phases"])==38 and [(r["family"],r["compiler_label"]) for r in sched["phases"]]==expected,"nested full phase order")
mapping={"elf":"elf_object_observations","resource":"resource_observations","bulk":"bulk_observations","loan":"loan_observations","cfg":"cfg_worklist_observations","owned":"owned_elf_observations","capacity":"expanded_capacity_observations","tail":"tail_call_observations","select":"select_observations","effects":"effect_observations","multi":"multi_result_observations","keyword":"keyword_observations","signed":"signed_observations","scalar-casts":"scalar_cast_observations","exports":"explicit_export_observations","names":"function_name_observations","cli":"executable_cli_observations","explicit-traps":"explicit_trap_observations"}
positions=collections.Counter();phase_checks={};phase_rows=[]
for (family,label),idx,nested_receipt in zip(expected,ix["phases"],sched["phases"]):
    stem="hia-cold.cold/qualification.evidence/phase-"+family+"-"+label
    r=j(stem+".json");request=j(stem+".request.json");life=j(stem+".process.json")
    req((idx["family"],idx["compiler_label"])==(family,label) and idx["state"]=="completed" and idx["report_status"]=="PASS","index completion "+family+"-"+label)
    req(idx["report"]==TEMP+stem+".json" and idx["request"]==TEMP+stem+".request.json" and idx["process_receipt"]==TEMP+stem+".process.json","index paths "+family+"-"+label)
    req(life==nested_receipt and life["returncode"]==0 and life["report_sha256"]==sha(b(stem+".json")),"phase raw receipt/hash "+family+"-"+label)
    req(r["schema"]=="hepta.hia.selfhost-phase.v1" and r["status"]=="PASS" and r["family"]==family and r["compiler_label"]==label and r["worker_pid"]==life["worker_pid"],"phase schema/process identity "+family+"-"+label)
    req(r["source_manifest_sha256"]==request["source_manifest_sha256"]==sd and r["input_sha256"]=={k:v["sha256"] for k,v in request["inputs"].items()},"phase source/input identities "+family+"-"+label)
    req(r["python"]=={"isolated":True,"no_site":True,"dont_write_bytecode":True} and r["fresh_host_oracle_process"] is True and r["successor_process_reuse"] is False,"phase process isolation "+family+"-"+label)
    req(r["checks"] and all(v is True for v in r["checks"].values()) and not(set(phase_checks)&set(r["checks"])),"phase unique true checks "+family+"-"+label)
    phase_checks.update(r["checks"])
    req(all(q["checks"].get(k) is v for k,v in r["checks"].items()),"phase check aggregation "+family+"-"+label)
    req(life["command"][1:4]==["-I","-S","-B"] and life["command"][-4:]==["--phase-request",TEMP+stem+".request.json","--output",TEMP+stem+".json"],"phase actual argv "+family+"-"+label)
    req(life["started_monotonic_ns"]<life["completed_monotonic_ns"]<=life["archive_completed_monotonic_ns"] and life["raw_artifacts"]["every_original_byte_verified_before_retirement"] is True,"phase archive completion "+family+"-"+label)
    observations=r["observations"]
    pairs=[(mapping[family],observations)] if family!="chain" else [("chain_elf_observations",observations["chain"]),("chain_allocator_observations",observations["allocator"])]
    for field,values in pairs:
        start=positions[field];req(q[field][start:start+len(values)]==values,"full nested observation equality "+family+"-"+label+"/"+field);positions[field]+=len(values)
    phase_rows.append({"family":family,"compiler_label":label,"report":file_record(stem+".json"),"checks":len(r["checks"]),"worker_pid":r["worker_pid"],"report_elapsed_ns":r["elapsed_ns"],"process_wall_ns":life["wall_elapsed_ns"],"archive_delay_ns":life["archive_completed_monotonic_ns"]-life["completed_monotonic_ns"],"started_monotonic_ns":life["started_monotonic_ns"],"completed_monotonic_ns":life["completed_monotonic_ns"],"archive":life["raw_artifacts"]})
req(all(positions[k]==len(q[k]) for k in positions),"full phase observations exhausted")
events=sorted([(x["started_monotonic_ns"],1) for x in phase_rows]+[(x["completed_monotonic_ns"],-1) for x in phase_rows])
active=peak=0
for _,delta in events:active+=delta;peak=max(peak,active)
req(peak==2 and active==0,"actual phase concurrency exactly two")
req(q["seed"]==j("hia-cold.cold/qualification.evidence/B0.receipt.json"),"full seed original receipt equality")
generation=[]
for group,labels in (("generations",("B1","B2","B3")),("modified_generations",("M1","M2","M3"))):
    req(len(q[group])==3,"generation count "+group)
    previous=q["seed"]["artifact_sha256"] if group=="generations" else q["generations"][-1]["produced_sha256"]
    for nested,label in zip(q[group],labels):
        stem="hia-cold.cold/qualification.evidence/"+label
        r=j(stem+".receipt.json");rq=j(stem+".request.json")
        req(nested==r and r["case"]==label and r["status"]=="returned" and r["abi_status"]==0 and r["forbidden_compiler_modules_loaded"]==[],"exact generation original "+label)
        req(rq["image_sha256"]==r["image_sha256"]==previous and rq["source_sha256"]==r["source_sha256"] and r["source_unchanged"] is True,"generation chain "+label)
        req(r["limits"]["cpu_seconds"]==10 and r["limits"]["address_bytes"]==268435456 and r["limits"]["workspace_bytes"]==1048576 and r["limits"]["output_capacity"]==1048576,"generation original limits "+label)
        previous=r["produced_sha256"];generation.append({k:r[k] for k in ("case","produced_bytes","produced_sha256","wall_elapsed_ns","native_elapsed_ns")})
req([r["produced_sha256"] for r in q["generations"]]==c["generation_sha256"],"outer generation SHA list")
req([r["produced_sha256"] for r in q["modified_generations"]]==c["modified_generation_sha256"],"outer modified generation SHA list")
B3=q["generations"][-1]
req(B3["produced_bytes"]==668608 and B3["produced_sha256"]=="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8","known B3 exact identity")
reference_fields={"core":"independent_core_reference","bulk":"independent_bulk_reference","capacity":"independent_capacity_reference","cfg":"independent_cfg_worklist_reference","effects":"independent_effect_reference","cli":"independent_executable_cli_reference","exports":"independent_explicit_export_reference","explicit-traps":"independent_explicit_trap_reference","names":"independent_function_name_reference","keyword":"independent_keyword_reference","loan":"independent_loan_reference","multi":"independent_multi_result_reference","resource":"independent_resource_reference","scalar-casts":"independent_scalar_cast_reference","select":"independent_select_reference","signed":"independent_signed_reference","tail":"independent_tail_reference"}
req(len(sched["reference_processes"])==17 and {r["family"] for r in sched["reference_processes"]}==set(reference_fields),"full 17 reference family inventory")
refs=[]
for r in sched["reference_processes"]:
    name="hia-cold.cold/qualification.evidence/reference-"+r["family"]+".worker.json";actual=j(name)
    req(sha(b(name))==r["report_sha256"] and actual["reference_sha256"]==r["reference_sha256"] and actual["source_manifest_sha256"]==r["source_manifest_sha256"]==sd,"reference raw source/hash "+r["family"])
    req(r["returncode"]==0 and actual["before_B0"] is True and r["completed_monotonic_ns"]<=sched["seed_started_monotonic_ns"],"reference completion before B0 "+r["family"])
    req(actual["reference"]==q[reference_fields[r["family"]]],"full reference equality "+r["family"])
    refs.append({"family":r["family"],"report":file_record(name),"wall_elapsed_ns":actual["wall_elapsed_ns"],"process_elapsed_ns":r["completed_monotonic_ns"]-r["started_monotonic_ns"]})
cold_summary={"status":c["status"],"source_count":len(source),"source_manifest_sha256":sd,"wall_elapsed_ns":c["wall_elapsed_ns"],"nested_elapsed_ns":q["elapsed_ns"],"outer_check_count":len(c["checks"]),"nested_check_count":len(q["checks"]),"phase_check_count":len(phase_checks),"phase_count":len(phase_rows),"phase_actual_peak_workers":peak,"natural_owner":cold_owner,"generation_receipts":generation,"reference_count":len(refs),"references":refs,"phases":phase_rows,"full_report":file_record("hia-cold.cold/qualification.json"),"full_5400_suite_executed_here":False,"raw_phase_archives_and_native_images_independently_read_here":False}
# Static test inventory, without importing or executing project modules.
trees={}
def class_nodes(module):
    if module not in trees:
        rel=module.replace(".","/")+".py";data=(ROOT/"source-970"/rel).read_bytes();req(sha(data)==source[rel],"test AST source "+module)
        trees[module]={n.name:n for n in ast.parse(data).body if isinstance(n,ast.ClassDef)}
    return trees[module]
def methods(module,name,trail=()):
    req((module,name) not in trail,"acyclic test class")
    node=class_nodes(module)[name];found=set()
    for base in node.bases:
        if isinstance(base,ast.Name) and base.id in class_nodes(module):found |= methods(module,base.id,trail+((module,name),))
        elif isinstance(base,ast.Attribute) and isinstance(base.value,ast.Name) and base.value.id=="existing":
            req(module=="tests.test_hia_agent_native_machine_choices" and base.attr=="MachinePlanTests","only fixed external inherited test class")
            found |= methods("tests.test_hia_agent_native_tools",base.attr,trail+((module,name),))
    found |= {n.name for n in node.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name.startswith("test")}
    return found
def ids(modules):
    result=[]
    for module in modules:
        for name in sorted(class_nodes(module)):
            for method in sorted(methods(module,name)):
                result.append(module+"."+name+"."+method)
    return result
gatespecs=[("state","hia-machine-state-gate.json","hia-machine-state-callers-evidence/report.json","hia-machine-state-owner",{"machine_state_complete_component","machine_state_selected_original_callers"},[12,51]),("instructions","hia-machine-instructions-gate.json","hia-machine-instructions-callers-evidence/report.json","hia-machine-instructions-owner",{"machine_instructions_complete_component","machine_instructions_selected_original_callers"},[12,51]),("core","hia-core-lowering-gate.json","hia-core-lowering-callers-evidence/report.json","hia-core-lowering-owner",{"core_lowering_complete_component","core_lowering_selected_original_machine_callers","core_lowering_selected_original_core_callers"},[12,51,50]),("elf-component","hia-machine-elf-component-gate.json","hia-machine-elf-component-evidence/report.json","hia-machine-elf-component-owner",{"machine_elf_complete_module"},[20]),("elf-callers","hia-machine-elf-caller-gate.json","hia-machine-elf-callers-evidence/report.json","hia-machine-elf-callers-owner",{"machine_elf_selected_original_callers"},[51])]
gate_summary=[];actual_gatekeys=set()
for label,gname,rname,odir,gkeys,counts in gatespecs:
    gate=j(gname);report=j(rname);wrapped=j(odir+"/run-result.json");life=j(odir+"/process-owner.json");rq=j(odir+"/process-owner.json.request.json")
    req(gate["schema"]=="hepta.hia.compiler-owner-gate.v1" and gate["status"]=="PASS" and set(gate["gates"])==gkeys and all(v is True for v in gate["gates"].values()),"actual gate key conjunction "+label)
    req(gate["source_before"]==gate["source_after"]==source and report["source_before"]==report["source_after"]==source and wrapped["source_before"]==wrapped["source_after"]==source,"787 source identity equality "+label)
    req(gate["source_preserved"] is True and gate["cold_inputs_preserved"] is True and gate["development_or_prior_result_reused"] is False and gate["whole_native_delivery_qualified"] is False,"gate current cold limited scope "+label)
    req(gate["cold_inputs"][0]["sha256"]==sha(b("hia-cold.json")) and gate["cold_inputs"][1]["sha256"]==sha(b("hia-cold.cold/qualification.json")) and gate["cold_inputs"][2]["sha256"]==B3["produced_sha256"] and gate["cold_inputs"][2]["bytes"]==B3["produced_bytes"],"cold / nested / B3 gate binding "+label)
    req(wrapped["status"]=="OWNED_COMMAND_RETURNED_PENDING_READBACK" and wrapped["source_preserved"] is True and wrapped["cold_inputs_preserved"] is True and wrapped["cold_inputs"]==gate["cold_inputs"],"original pending wrapper semantics "+label)
    owned=natural(life,rq,b(odir+"/process-owner.json"),b(odir+"/process-owner.json.request.json"),wrapped["returned_owner"])
    req(wrapped["command"]==rq["command"]==gate["inspection"]["process_owner"]["command"] and wrapped["cwd"]==rq["cwd"]==gate["inspection"]["process_owner"]["cwd"],"actual command and cwd join "+label)
    req(gate["inspection"]["process_owner"]["natural_exit_and_echild"] is True and gate["inspection"]["process_owner"]["qualification_seconds"]==180 and gate["inspection"]["process_owner"]["cleanup_seconds"]==3,"parent gate natural owner "+label)
    all_records(gate);all_records(report);all_records(wrapped)
    expected=gate["inspection"]["groups"]
    req([g["count"] for g in expected]==counts,"fixed complete denominator "+label)
    for wanted in expected:
        derived=ids(wanted["modules"])
        req(derived==wanted["ids"] and len(derived)==wanted["count"],"exact canonical AST ordered IDs "+label+"/"+wanted["label"])
    if label in ("state","instructions","core"):
        req(report["status"]=="PASS" and len(report["groups"])==len(expected) and report["retained_owner_entries"]==[] and report["manifest_images_bundle_stable"] is True,"selected whole-group original PASS "+label)
        for g,wanted in zip(report["groups"],expected):
            req(g["label"]==wanted["label"] and g["modules"]==wanted["modules"] and g["expected_methods"]==g["tests_run"]==wanted["count"] and g["loaded_ids"]==g["executed_ids"]==wanted["ids"] and g["strict_pass"] is True,"full ordered loaded and executed denominator "+label+"/"+g["label"])
            req(all(g[x]==[] for x in ("errors","failures","skipped","expectedFailures","unexpectedSuccesses","loader_errors")),"all anomalies empty "+label+"/"+g["label"])
    elif label=="elf-component":
        wanted=expected[0]
        req(report["status"]=="PASS" and report["tests_loaded"]==report["tests_chosen"]==report["tests_run"]==20 and report["loaded_test_ids"]==report["chosen_test_ids"]==report["executed_test_ids"]==wanted["ids"],"ELF full 20 actual methods")
        req(all(report[x]==[] for x in ("errors","failures","skipped","expected_failures","unexpected_successes","loader_errors")) and report["unittest_successful"] is True,"ELF component anomalies empty")
        child=j(odir+"/component-child-gate.json");parent_i={k:v for k,v in gate["inspection"].items() if k!="process_owner"}
        req(child["status"]=="PASS" and child["inspection"]==parent_i and child["gates"]==gate["gates"],"ELF original child gate exact join")
    else:
        wanted=expected[0]
        req(report["status"]=="SELECTED_NATIVE_ELF_CALLERS_PASS" and report["expected_count"]==report["tests_loaded"]==report["tests_run"]==51 and report["expected_test_ids"]==report["loaded_test_ids"]==report["executed_test_ids"]==wanted["ids"],"ELF original full 51 IDs")
        req(report["retained_writer_calls"]==[] and report["errors"]==[] and report["failures"]==[] and report["loader_errors"]==[] and all(v==0 for v in report["anomaly_counts"].values()) and len(report["anomaly_counts"])==5,"ELF callers no anomalies or old writer")
        req(report["actual_module_sources"]==report["expected_module_sources"]=={m.replace(".","/")+".py":source[m.replace(".","/")+".py"] for m in report["modules"]},"ELF 4 canonical module source SHA")
        req(report["bundle_before"]==report["bundle_after"] and report["bundle_stable"] is True and report["cold_report_sha256"]==sha(b("hia-cold.json")),"ELF caller bundle and cold identity")
        req(report["whole_writer_qualified"] is False and report["whole_native_delivery_qualified"] is False and report["foreign_timsort_schedule_closed"] is False,"ELF existing scope remains limited")
    if label in ("state","instructions"):
        requirements={"state":6,"encoding":37}
        if label=="instructions":requirements["instructions"]=41
        union={k:set() for k in requirements};totals={k:collections.Counter() for k in requirements}
        req(set(report["native_group_bindings"])==set(report["normal_native_returns_by_group_image_operation"])=={"component","original-callers"},"separate actual builds "+label)
        for group,binding in report["native_group_bindings"].items():
            req(binding["before"]==binding["after"]==gate["inspection"]["actual_builds"][group] and binding["binding_stable"] is True and binding["all_actual_file_bytes_stable"] is True,"actual group build equality "+label+"/"+group)
            req(binding["before"]["admission"]=="INDEPENDENT_MATCHING_COLD_BUILD_READBACK" and binding["before"]["source_manifest_sha256"]==sd,"group matching cold admission "+label+"/"+group)
            returns=report["normal_native_returns_by_group_image_operation"][group]
            req(set(returns)==set(requirements),"return owner kinds "+label+"/"+group)
            for kind,images in returns.items():
                manifest=binding["before"]["owners"][kind]["manifest"];im=manifest["image_sha256"]
                req(manifest["compiler_sha256"]==B3["produced_sha256"] and set(images)=={im},"normally-returned actual image "+label+"/"+group+"/"+kind)
                req(all(type(v) is int and v>0 for v in images[im].values()),"positive normal returns "+label+"/"+group+"/"+kind)
                union[kind].update(images[im]);totals[kind].update(images[im])
        req({k:len(v) for k,v in union.items()}==requirements and report["normal_return_coverage"]=={k:sorted(v) for k,v in union.items()} and report["normal_return_coverage_complete"] is True,"complete operation union "+label)
        fields={"state":"native_state_entries","encoding":"native_instruction_entries" if label=="state" else "native_byte_command_entries","instructions":"native_instruction_control_entries"}
        for kind in requirements:
            attempts=report[fields[kind]];req(set(attempts)==union[kind] and all(attempts[k]>=totals[kind][k] for k in union[kind]),"attempts retain exceptional calls "+label+"/"+kind)
        req(gate["inspection"]["native_observations"]["returns"]==report["normal_native_returns_by_group_image_operation"] and gate["inspection"]["native_observations"]["coverage_union"]==report["normal_return_coverage"],"gate native ledger join "+label)
    if label=="core":
        abi=json.loads((ROOT/"source-970/hepta/hia_core_lowering_abi.json").read_bytes());roles={"component":"component","original-core":"caller","original-machine":"caller"}
        req(report["development_group"] is None and report["complete_three_groups_executed"] is True and report["expected_groups"]==["component","original-core","original-machine"] and report["group_bundle_roles"]==roles,"complete current-cold Core three groups")
        req(report["native_step_ledger_schema"]=="hepta.hia.core-lowering-native-step-returns.v1" and report["abi_control_mode_count"]==len(abi["modes"])==28 and report["public_control_mode_count"]==27 and report["private_fixture_modes"]==["_native_globals"],"actual Core v1 ledger and modes")
        for role,o in report["bundle_observations"].items():
            build=gate["inspection"]["actual_builds"][role]
            req(o["stable"] is True and o["scope"]=="MATCHING_SOURCE_COLD_BUILD" and o["input_bindings_before"]==o["input_bindings_after"] and len(o["unit_image_sha256"])==len(o["unit_names"])==32,"separate 32-image cold bundle "+role)
            req(o["abi_sha256"]==sha((ROOT/"source-970/hepta/hia_core_lowering_abi.json").read_bytes()) and o["bundle_sha256"]==build["bundle_files"][0]["sha256"],"bundle/ABI actual identity "+role)
        status=collections.Counter();seen=set();modes=set();groups=set()
        for row in report["native_step_returns"]:
            key=tuple((k,v) for k,v in sorted(row.items()) if k!="count")
            req(key not in seen and type(row["count"]) is int and row["count"]>0 and row["status"] in (0,1,2),"unique completed Core step")
            seen.add(key);modes.add(row["mode"]);groups.add(row["group"]);status[str(row["status"])]+=row["count"]
            build=gate["inspection"]["actual_builds"][roles[row["group"]]];idx=row["unit_index"]
            req(row["bundle_image_index"]==idx+1 and row["unit_name"]==abi["units"][idx] and row["mode_number"]==abi["modes"][row["mode"]]["number"],"actual Core mode/unit")
            req(row["image_sha256"]==build["units"][row["unit_name"]]["manifest"]["image_sha256"] and row["abi_sha256"]==build["bundle"]["abi_sha256"] and row["bundle_sha256"]==build["bundle_files"][0]["sha256"],"actual returned Core image binding")
        req(set(abi["modes"])==modes and groups==set(roles) and dict(status)==report["actual_native_step_statuses"]==gate["inspection"]["native_observations"]["actual_status_totals"],"Core full 28 modes/status/group totals")
        req(any(row["group"]=="component" and row["mode_number"]==28 and row["mode"]=="_native_globals" for row in report["native_step_returns"]),"Core private fixture actual return")
        req(report["native_step_returns"]==gate["inspection"]["native_observations"]["step_ledger"],"parent Core exact real step ledger")
    actual_gatekeys |= gkeys
    gate_summary.append({"owner":label,"gate":file_record(gname),"producer_report":file_record(rname),"gate_seconds":gate["seconds"],"qualifier_seconds":report["seconds"],"group_counts":counts,"group_ordered_ID_counts":[len(w["ids"]) for w in expected],"natural_owner":owned,"gate_keys":sorted(gkeys),"all_original_anomalies_empty":True,"source_count":len(source)})
req(len(actual_gatekeys)==9,"all nine new compiler gate keys")
result={"schema":"hia.970-cold-and-compiler-original-semantic-readback.v1","status":"ORIGINAL_COLD_AND_FIVE_COMPILER_GATES_JOINED","product_source":policy["source"],"cold":cold_summary,"compiler_gates":gate_summary,"new_gate_keys":sorted(actual_gatekeys),"performed_check_count":len(checks),"performed_checks":checks,"canonical_source_reads":source_reads,"selected_file_identity_joins":joined_records,"unselected_physical_file_references":missing_physical,"scope":{"full_5400_retained_suite_executed":False,"new_product_execution":False,"unselected_phase_archives_and_all_native_binaries_rehashed":False,"historical_custody_HOLD_reclassified":False,"source_and_report_integer_lexemes_preserved_in_original_raw":True}}
out=(json.dumps(result,indent=2,sort_keys=True)+"\n").encode()
fd=os.open(OUT/"SEMANTIC-READBACK.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o400)
with os.fdopen(fd,"wb") as f:f.write(out);f.flush();os.fsync(f.fileno())
print(json.dumps({"status":result["status"],"performed_checks":len(checks),"cold_ns":c["wall_elapsed_ns"],"phase_count":38,"nested_checks":5051,"gate_keys":len(actual_gatekeys),"groups":[r["group_counts"] for r in gate_summary],"unselected_physical_refs":len(missing_physical)}))
