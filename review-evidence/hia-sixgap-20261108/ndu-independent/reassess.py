#!/usr/bin/env python3
"""Read-only historical analysis. No provider or native execution is available."""
from __future__ import annotations
import argparse, ast, json, platform, sys, time
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha1, sha256
from pathlib import Path

HERE=Path(__file__).resolve().parent
SOURCE="eb3f25f57dc5f7b49d1ca56b1570e232f5a932dc"
UPSTREAM="d3c2d760eca5065fc966820379c35c6e8d56e855"
PREFIX="review-evidence/hia-ndu-completed-control-20261107/"
STRONG="review-evidence/hia-ndu-strong-control-20261107/"
PHASES={"setup","discovery","model","search","verification","emission","evaluation","adoption","rollback","future_use","controller"}
FAILED={"failed","rejected","timed_out","cancelled"}
ARMS={"fixed","greedy","ordinary","ndu"}

def require(ok, reason):
    if not ok: raise AssertionError(reason)

def raw_sha(raw): return sha256(raw).hexdigest()
def wire(data): return json.dumps(data,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
def exact_json(raw):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,"duplicate JSON key")
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda value:require(False,"nonfinite JSON"))

def verify_inputs(root):
    manifest=exact_json((root/"retrieval-manifest.json").read_bytes())
    current=exact_json((root/"current-source-identity.json").read_bytes())
    files={}
    for namespace in ("hepta","upstream"):
        for row in manifest[namespace]:
            raw=(root/namespace/row["path"]).read_bytes()
            blob=sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
            require(blob==row["git_blob_sha1"],"Git blob mismatch: "+row["path"])
            files[namespace+"/"+row["path"]]={"sha256":raw_sha(raw),"bytes":len(raw),"git_blob_sha1":blob,"url":row["url"]}
    require(current["head"]==SOURCE,"current source identity")
    for name,value in current["files"].items():
        require(files["hepta/"+name]["sha256"]==value,"current source differs: "+name)
    return {"retrieval":manifest,"current_source":current,"files":files,"seven_current_source_files_match":True}

def independent_assessment(data):
    """Independent ledger and eligibility computation, not the project assessor."""
    inventory={row["id"]:row for row in data["task_inventory"]}
    require(len(inventory)==len(data["task_inventory"])==8,"original denominator")
    registration={k:data[k] for k in ("agent_sha256","objective_sha256","budget","task_inventory","minimum_gain_ns")}
    require(raw_sha(wire(registration))==data["registration_sha256"],"registration identity")
    arms,eligibility,phase_totals={},{},{}
    for arm in data["arms"]:
        name=arm["strategy"]
        require(name in ARMS and name not in arms,"registered arm")
        require(all(arm[k]==data[k] for k in ("agent_sha256","registration_sha256","budget")),"matched registration/agent/budget")
        require(len(arm["observations"])==8,"retain every task")
        seen,reasons,rows,all_events=set(),[],[],[]
        for row in arm["observations"]:
            tid=row["task_id"]
            require(tid in inventory and tid not in seen,"task identity")
            seen.add(tid)
            require(all(row[k]==inventory[tid][k] for k in ("input_sha256","qualification_receipt_sha256")),"input binding")
            if row["status"]!="completed" or row["correct"] is not True: reasons.append(name+":undelivered_task:"+tid)
            if row["result_receipt_sha256"] is None: reasons.append(name+":missing_result_evidence:"+tid)
            event_ids,receipts,unknown=set(),set(),[]
            phases=defaultdict(lambda:{"wall_ns":0,"model_tokens":0,"events":0})
            wall=tokens=failed_wall=0
            for event in row["ledger"]:
                require(event["id"] not in event_ids,"duplicate event")
                event_ids.add(event["id"])
                receipt=event["receipt_sha256"]
                if receipt is None: unknown.append(event["id"]+":receipt")
                else:
                    require(receipt not in receipts,"duplicate charged receipt")
                    receipts.add(receipt)
                p=event["phase"]
                require(p in PHASES,"phase")
                phases[p]["events"]+=1
                for k in ("wall_ns","model_tokens"):
                    value=event[k]
                    if value is None: unknown.append(event["id"]+":"+k)
                    else:
                        require(type(value) is int and value>=0,"nonnegative cost")
                        phases[p][k]+=value
                if event["status"]=="unknown": unknown.append(event["id"]+":completion")
                wall+=event["wall_ns"] if event["wall_ns"] is not None else 0
                tokens+=event["model_tokens"] if event["model_tokens"] is not None else 0
                if event["status"] in FAILED: failed_wall+=event["wall_ns"] if event["wall_ns"] is not None else 0
                total=phase_totals.setdefault(p,{"events":0,"failed_or_rejected":0,"wall_ns":0})
                total["events"]+=1
                total["failed_or_rejected"]+=int(event["status"] in FAILED)
                total["wall_ns"]+=event["wall_ns"] if event["wall_ns"] is not None else 0
            require(set(row["phase_inventory"])==PHASES,"phase inventory")
            for p,decl in row["phase_inventory"].items():
                require(decl["performed"]==(p in phases),"phase declaration")
                require(isinstance(decl["receipt_sha256"],str) and len(decl["receipt_sha256"])==64,"phase receipt")
            if unknown: reasons.append(name+":unknown_costs:"+tid)
            if phases["model"]["model_tokens"]<=0: reasons.append(name+":no_observed_agent_call:"+tid)
            if phases["future_use"]["wall_ns"]<=0: reasons.append(name+":no_observed_downstream_use:"+tid)
            if wall>data["budget"]["wall_ns"] or tokens>data["budget"]["model_tokens"]: reasons.append(name+":budget_exceeded:"+tid)
            require(len(row["native_ndu_receipts"])==len(set(row["native_ndu_receipts"])),"native receipt uniqueness")
            if name=="ndu" and not row["native_ndu_receipts"]: reasons.append("ndu:no_native_value_evaluation:"+tid)
            rows.append({"task_id":tid,"status":row["status"],"correct":row["correct"],"wall_ns":wall,
                "model_tokens":tokens,"failed_event_wall_ns":failed_wall,"events":len(row["ledger"]),"unknown":unknown,
                "result_receipt_sha256":row["result_receipt_sha256"],"native_ndu_receipts":row["native_ndu_receipts"]})
            all_events.extend(row["ledger"])
        eligibility[name]={"eligible":not reasons,"reasons":reasons}
        arms[name]={"planned":8,"correct":sum(r["correct"] is True for r in rows),
            "wall_ns":sum(r["wall_ns"] for r in rows),"source_charged_model_tokens":sum(r["model_tokens"] for r in rows),
            "failed_event_wall_ns":sum(r["failed_event_wall_ns"] for r in rows),
            "unknown_cost_fields":sum(len(r["unknown"]) for r in rows),"events":len(all_events),
            "event_statuses":dict(Counter(e["status"] for e in all_events)),"observations":rows}
    require(set(arms)==ARMS,"all four arms")
    totals={name:row["wall_ns"] for name,row in arms.items()}
    best=min((value,name) for name,value in totals.items() if name!="ndu")
    complete=sorted(name for name in ARMS-{"ndu"} if eligibility[name]["eligible"])
    complete_best=min((totals[name],name) for name in complete) if complete else None
    all_eligible=all(row["eligible"] for row in eligibility.values())
    return {"arms":arms,"arm_wall_ns":totals,"source_phase_costs":phase_totals,
        "planned_task_arms":32,"correct_native_task_arms":sum(row["correct"] for row in arms.values()),
        "events":sum(row["events"] for row in arms.values()),
        "failed_or_rejected_events":sum(row["event_statuses"].get(s,0) for row in arms.values() for s in FAILED),
        "unknown_cost_fields":sum(row["unknown_cost_fields"] for row in arms.values()),
        "raw_lowest_cost_control":best[1],"raw_ndu_wall_difference_ns":best[0]-totals["ndu"],
        "ordinary_minus_ndu_raw_wall_ns":totals["ordinary"]-totals["ndu"],
        "completed_comparison":{"eligible":all_eligible,"arm_eligibility":eligibility,"complete_controls":complete,
            "best_complete_control":complete_best[1] if complete_best else None,
            "ndu_saving_ns":complete_best[0]-totals["ndu"] if all_eligible else None},
        "real_user_tasks":sum(t["qualification"]=="real_agent_task" for t in inventory.values()),
        "money":None,"tariff":None,"invoice":None,"economic_benefit_established":False,
        "independent_provider_native_provenance_authenticated":False}

def extract(path,names,namespace):
    tree=ast.parse(path.read_text())
    nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names]
    require({n.name for n in nodes}==set(names),"production definition inventory")
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),"exec"),namespace)
    return {n.name:{"start":n.lineno,"end":n.end_lineno,"file_sha256":raw_sha(path.read_bytes())} for n in nodes}

def selector_cases(root):
    q={"_MAX_INT":(1<<63)-1}
    locations=extract(root/"hepta/hepta/hia_ndu_optimizer.py",
        ["OptimizationRejected","_reject","_integer","ns_to_ms_q32"],q)
    def deny_native(*args,**kwargs): raise AssertionError("native call prohibited in this analysis")
    namespace={"deepcopy":deepcopy,"ARM_ORDER":("fixed","greedy","ordinary","ndu"),
        "require":require,"ns_to_ms_q32":q["ns_to_ms_q32"],"_native_rank":deny_native}
    locations.update(extract(root/"hepta/tools/qualify_hia_macro_multistep.py",["checked_pool_selection"],namespace))
    specs=[("unique_minimum",[100_000_000,50_000_000,60_000_000],"b","b"),
        ("incumbent_tie",[50_000_000,50_000_000,60_000_000],"a","a"),
        ("cheaper_alternatives_tie",[100_000_000,50_000_000,50_000_000],"b","a")]
    cases=[]
    for name,costs,ordinary_expected,inferred_expected in specs:
        pool=[{"id":cid,"quality_complete":True,"immediate_ns":cost,"remaining_cost_ns":cost,"uncertainty_ns":0,
            "support_sha256":raw_sha(wire({"case":name,"id":cid})),
            "artifact_sha256":raw_sha(("arithmetic-example:"+cid).encode()),"artifact_bytes":1}
            for cid,cost in zip(("a","b","c"),costs)]
        started,cpu=time.perf_counter_ns(),time.process_time_ns()
        result=namespace["checked_pool_selection"]("ordinary",pool,remaining_wall_ns=1_000_000_000,
            bridge=None,objective_sha256="1"*64,generation=1)
        elapsed,cpu_elapsed=time.perf_counter_ns()-started,time.process_time_ns()-cpu
        values={row["id"]:q["ns_to_ms_q32"](row["remaining_cost_ns"]) for row in pool}
        minimum=min(values.values())
        frontier=[cid for cid,value in values.items() if value==minimum]
        recommendation=frontier[0] if len(frontier)==1 else None
        inferred=result["feasible_incumbent_id"] if recommendation is None else recommendation
        require(result["selected_id"]==ordinary_expected,"actual Python ordinary")
        require(inferred==inferred_expected,"source-derived Rust/wrapper")
        cases.append({"id":name,"supplied_cost_ns":dict(zip(("a","b","c"),costs)),
            "uncertainty_ns":0,"remaining_wall_ns":1_000_000_000,"actual_python_ordinary":result,
            "python_wall_ns":elapsed,"python_cpu_ns":cpu_elapsed,"source_derived_native_frontier":frontier,
            "source_derived_native_recommendation":recommendation,"source_derived_wrapper_selected_id":inferred,
            "source_derived_native_disposition":"UniqueParetoRecommendation" if len(frontier)==1 else "ParetoSetRequiresSlowPath",
            "ordinary_supplied_objective_ns":costs[("a","b","c").index(result["selected_id"])],
            "native_wrapper_supplied_objective_ns":costs[("a","b","c").index(inferred)],
            "new_native_execution":False,"new_campaign":False,
            "scope":"supplied forecasts, not measured task benefit or native timing"})
    return {"cases":cases,"definition_locations":locations,"native_guard_invoked":False,
        "q32_monotonicity":"round_even(n*2^32/10^6) is strictly increasing on integer nanoseconds; a 1 ns change spans 4294.967296 raw units"}

def run(inputs,output):
    require(not output.exists(),"fresh analysis output required")
    started,cpu=time.perf_counter_ns(),time.process_time_ns()
    before=verify_inputs(inputs)
    load=lambda name:exact_json((inputs/"hepta"/name).read_bytes())
    data,costs,facts,old=[load(PREFIX+name) for name in ("original-comparison.json","original-cost-and-scope.json",
        "retained-provider-facts.json","retained-provider-reassessment.json")]
    assessment=independent_assessment(data)
    require(before["files"]["hepta/"+PREFIX+"original-comparison.json"]["sha256"]==old["original_comparison_sha256"],"original byte hash")
    require(assessment["arm_wall_ns"]==old["arm_wall_ns"],"wall reconciliation")
    require(assessment["completed_comparison"]=={k:v for k,v in old["completed_comparison"].items() if k!="scope"},"independent eligibility reconciliation")
    require(assessment["source_phase_costs"]==costs["source_phase_costs"],"all phase totals")
    for row in costs["arms"]:
        actual=assessment["arms"][row["arm"]]
        require(actual["wall_ns"]==row["wall_ns"] and actual["correct"]==row["correct_native_task_arms"]
            and actual["source_charged_model_tokens"]==row["source_charged_model_tokens"],"arm reconciliation")
    for key,field in (("events","events_verified_by_original_verifier"),("failed_or_rejected_events","failed_or_rejected_attempts_retained"),
                      ("correct_native_task_arms","correct_native_task_arms")):
        require(assessment[key]==facts["facts"][field],"facts reconciliation")
    require(costs["money"] is None and costs["provider_tariff_or_invoice"] is None,"missing money remains unknown")
    require(sum(row["wall_ns"] for row in assessment["arms"].values())==costs["source_measurement"]["charged_task_wall_ns"],"task total")
    require(sum(row["source_charged_model_tokens"] for row in assessment["arms"].values())==costs["source_budget_token_sum"],"token total")
    native=[]
    for prior in load(STRONG+"retained-native-replay.json")["runs"]:
        require(len(prior["decisions"])==8 and all(r["plan_count"]==1 and r["matches"]
            and r["original_ndu_choice"]==r["ordinary_replay_choice"]=="abstain" for r in prior["decisions"]),"retained replay facts")
        best=min(value for name,value in prior["original_arm_wall_ns"].items() if name!="ndu")
        saving=best-prior["original_arm_wall_ns"]["ndu"]
        require(saving==prior["original_ndu_saving_ns"],"native historical arithmetic")
        native.append({"trial":prior["trial"],"best_control_wall_ns":best,"ndu_wall_ns":prior["original_arm_wall_ns"]["ndu"],
            "saving_ns":saving,"original_manifest_sha256":prior["original_manifest_sha256"],
            "retained_decisions":prior["decisions"],"raw_original_states_replayed_here":False})
    report={"schema":"hepta.hia.ndu.independent-reassessment.v1","created_utc":datetime.now(timezone.utc).isoformat(),
        "research_kind":"historical read-only reassessment plus source-derived selector audit",
        "source_commit":SOURCE,"upstream_commit":UPSTREAM,"input_identity":before,
        "historical_reassessment":assessment,"retained_cost_and_scope":costs,"retained_provider_facts":facts,
        "retained_execution_result":load(PREFIX+"original-execution-result.json"),"retained_native_runs":native,
        "retained_native_saving_sum_ns":sum(r["saving_ns"] for r in native),
        "retained_native_saving_mean_ns":sum(r["saving_ns"] for r in native)/len(native),
        "later_local_campaign":load(STRONG+"local-campaign-summary.json"),
        "multistep_protocol":load("benchmarks/hia_macro_multistep/PROTOCOL.json"),
        "actual_python_ordinary_examples":selector_cases(inputs),
        "new_provider_calls":0,"new_native_execution":False,"old_campaign_replayed":False,
        "original_receipts_rewritten":False,"unknown_outcomes_retried":False,"production_source_modified":False,
        "new_synthetic_campaign_started":False,
        "verdict":{"P2":"NOT_ESTABLISHED","additional_decision_information_in_current_scalar_profile":False,
            "universally_identical_choices":False,"same_unique_minimum_choice":True,
            "same_choice_when_incumbent_is_a_minimizer":True,
            "two_cheaper_equal_alternatives_can_fall_back_to_more_expensive_incumbent":True,
            "ordinary_weakly_dominates_supplied_objective_given_equal_valid_inputs_and_successful_native_response":True,
            "historical_single_candidate_fixture_is_structurally_abstain":True,"stable_measured_gain_established":False,
            "qualified_provider_saving_ns":None,"economic_benefit_established":False,"general_NDU_impossibility_claim":False},
        "limitations":["The native selector branches were reviewed at exact public source pins, not newly executed.",
            "16 retained state/result digests are an excerpt; original full states were not obtained or replayed here.",
            "All 1441 original provider/native objects and streams were not independently authenticated here.",
            "No real-user task cohort, monetary invoice, complete human cost or stable matched-pool economic comparison is present.",
            "Supplied objective dominance does not imply measured controller-runtime or total-task dominance.",
            "Only the configured scalar single-owner profile is characterized, not other NDU algorithms."],
        "execution":{"python":sys.version,"executable":str(Path(sys.executable).resolve()),"platform":platform.platform(),
            "script_sha256":raw_sha(Path(__file__).read_bytes())}}
    require(verify_inputs(inputs)==before,"inputs unchanged")
    report["inputs_unchanged"]=True
    report["execution"].update(reassessment_wall_ns=time.perf_counter_ns()-started,reassessment_cpu_ns=time.process_time_ns()-cpu)
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"status":"INDEPENDENT_REASSESSMENT_COMPLETE","P2":report["verdict"]["P2"],
        "report":str(output),"report_sha256":raw_sha(output.read_bytes()),"script_sha256":report["execution"]["script_sha256"],
        "qualified_provider_saving_ns":None,"inputs_unchanged":True,"new_provider_calls":0,"new_native_execution":False,
        "analysis_wall_ns":report["execution"]["reassessment_wall_ns"]}))

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs",type=Path,default=HERE/"inputs")
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    run(args.inputs.resolve(),args.output.resolve())
