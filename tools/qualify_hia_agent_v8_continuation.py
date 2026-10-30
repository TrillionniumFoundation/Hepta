#!/usr/bin/env python3
"""Prospective textual-v8 Agent pilot: register before any model/formal input."""
from __future__ import annotations
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
import sys
import time
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
sys.dont_write_bytecode=True
from tools.hia_agent_codex_transport import canonical,identity,run_owned,save,strict_json
from tools.hia_agent_v8_transport import AppServerDialogue,DialogueRejected,USAGE_FIELDS
from tools.hia_agent_v8_evaluator import (HERE,TASKS,TASK_MODULE,LANGUAGES,SCHEMA,
    config,candidate_constraints,evaluate,public_feedback)

def git(*args):
    return subprocess.check_output(["git",*args],cwd=ROOT,text=True).strip()

def bindings():
    paths=list((ROOT/"hepta").glob("*.py"))+[
        Path(__file__),ROOT/"tools/hia_agent_v8_transport.py",ROOT/"tools/hia_agent_v8_evaluator.py",ROOT/"tools/hia_agent_v8_native_limit.py",
        ROOT/"tools/hia_agent_codex_transport.py",ROOT/"benchmarks/hia_agent_public_tools/PROTOCOL.json",
        ROOT/"tools/fixtures/hia_agent_v8_resource.rs",HERE/"tasks.py",HERE/"PROTOCOL.json"]
    paths+=list((ROOT/"tests").glob("test_hia_agent_v8_*.py"))
    return {str(p.relative_to(ROOT)):identity(p)["sha256"] for p in sorted(paths)}

def tool_bindings():
    cfg=config()
    return {**{key:identity(cfg[key]) for key in ("codex","clang","rustc")},"python":identity(sys.executable)}

def feature_probe(output,timeout=20):
    """Zero-generation effective-feature receipt; never edits user settings."""
    cfg=config();output=Path(output);output.mkdir(parents=True,exist_ok=False)
    cwd=output/"empty-cwd";cwd.mkdir();argv=[cfg["codex"]]
    for feature in cfg["disabled_features"]:argv.extend(["--disable",feature])
    argv.extend(["features","list"])
    process=run_owned(argv,cwd,output/"transport",wall_seconds=timeout)
    if process["status"]!="exited":raise ValueError("feature probe failed without model generation")
    lines=(output/"transport/stdout.raw").read_text().splitlines()
    rows={line.split()[0]:line.split()[-1] for line in lines if line.split()}
    observed={name:{"true":True,"false":False}.get(rows.get(name)) for name in cfg["disabled_features"]}
    result={"requested_disable":cfg["disabled_features"],"observed_enabled":observed,
        "matched_registration":observed==cfg["expected_observed_feature_values"],
        "all_requested_features_disabled":all(value is False for value in observed.values()),
        "model_requests":0,"process":process}
    save(output/"RESULT.json",result)
    if not result["matched_registration"]:raise ValueError("effective feature configuration drift")
    return result

def catalog(language):
    if language=="hia-v8-text":
        from hepta.hia_opcodes import opcode_catalog
        from hepta.hia_schema import schema_registry
        registry=schema_registry();registry.pop("instruction_catalog",None)
        return {"language":language,"selected_schema":SCHEMA,"catalog":opcode_catalog(SCHEMA),
            "compatibility":registry,
            "grammar": [
                "UTF-8 text only. First line: hia-asm.v1 hepta.hia.program.v8 module_name. Next line exports(target) for scalar tasks or exports() for the internal borrowed task_step helper.",
                "Function: fn name(p:type,q:type) -> (return_type,...) effects(effect,...) entry(block_name). Optional v8 suffix: return_loans([null,\"formal_name\",...]), one entry per return. A returned readbuf/mutbuf requires its checked input-loan formal origin.",
                "Block: block label(p:type,q:type). Operations: out:type,other:type = opcode(arg,...) {\"exact_attribute\":value}. Empty results use _ = opcode(args). Attribute JSON is optional only for operations with zero attributes.",
                "Terminators: ret(value,...); jump label(arg,...); branch condition true_label(args) false_label(args); trap user (or registered Core trap code). Each terminator is one line, without semicolon. A block ends at its terminator; the next block header starts another block. Close each function with the literal end.",
                "Every value read in a block is a block parameter or earlier local operation result. Explicitly pass values to successor blocks. Function entry-block parameters equal function parameters including names/types. Alpha-renaming consistently is allowed.",
                "Use explicit scalar result types, casts and checked/wrapping arithmetic. int.cast has mode checked or wrap. const requires value. call requires function. Compare results are bool. Buffer indices/sizes are usize and buffer bytes are u8.",
                "Effect declarations must cover operations and callees. Owners/local loans are linear; exact CFG joins and cleanup are checked. End child loans before parent loans and owners. Calls with returned loans create a caller-local child view; end that returned view and then the original parent.",
                "The complete catalog lists every selected operation, version, types, attributes, effects, traps and resource guards. Inclusion does not grant a resource-valued external ABI; borrowed task helpers are linked to the disclosed scalar wrapper."],
            "example":"hia-asm.v1 hepta.hia.program.v8 example\nexports(target)\nfn target(x:u32,y:u32) -> (u32) effects() entry(entry)\nblock entry(x:u32,y:u32)\nz:u32 = bit.xor(x,y)\nret(z)\nend\n",
            "admission":"Existing assemble_program and verify_program are unchanged; no expression synthesis, repair or host-inserted owner cleanup."}
    if language!="rust":raise ValueError("unknown language")
    return {"language":"rust","edition":"2021","compiler":"Registered rustc, opt-level=2, overflow-checks=on, panic=abort",
        "selected_api":"Safe scalar Rust, functions, local variables, if/match, loops, tuples/arrays, integer casts and methods including wrapping_add/sub/mul, saturating_add/sub, min/max/clamp, rotate_left/right. No external crates. Buffer tasks use the provided Vec<u8> backed by an actual std::vec::Vec: vec![0u8;length], .len(), .is_empty(), indexed mutable access, indexed read and drop; automatic Drop also allowed. Other Vec APIs are unavailable.",
        "source_profile":"Source <=65536 UTF-8 bytes. Lexical forbidden tokens (including in comments/strings): unsafe extern mod use include include_str include_bytes std core alloc env option_env asm global_asm impl trait struct enum type macro_rules audited super crate Self; also :: and attributes. main/invoke function names are reserved. No direct tool execution, file/process/network access, macros or modules bypassing this API. This selected exercise is not arbitrary safe Rust.",
        "resource_scope":"Audited wrapper checks exact zeroed length before allocation, mutable access and subsequent actual byte read, candidate/helper phase, same owner and release. One required allocation/release per invocation; uncalled helpers and scalar shortcuts do not satisfy it. It observes selected API events, not all allocator calls or machine instructions.",
        "example":"fn target(x:u32,y:u32)->u32 { x ^ y }"}

def public_prompt(task,language):
    wrapper=TASK_MODULE.wrapper(task["id"])
    if wrapper and language=="hia-v8-text":
        from hepta.hia_agent_assembly import render_assembly
        # Rendering syntax is possible without linking the unresolved public helper.
        params=[("view","mutbuf"),"x","y"]
        returning=task["id"]=="return_borrow"
        stub=TASK_MODULE.fn("task_step",params,["mutbuf"] if returning else ["u32"],[],
            [TASK_MODULE.b("entry",params,[] if returning else [TASK_MODULE.c("unused_zero",0)],
                TASK_MODULE.ret("view" if returning else "unused_zero"))],origins=["view"] if returning else None)
        wrapper_text=render_assembly({"schema":SCHEMA,"module":"disclosed_host_wrapper","exports":["target"],"functions":[wrapper,stub]})
        # Do not include the reference helper. The primitive wrapper is the public contract.
        wrapper_text=wrapper_text[:wrapper_text.index("\nfn task_step(")] if "\nfn task_step(" in wrapper_text else None
        if wrapper_text is None: raise ValueError("public wrapper extraction failed")
    else:wrapper_text=TASK_MODULE.rust_wrapper(task["id"]) if wrapper else None
    return {"task":task["id"],"description":task["description"],"language":language,
        "public_cases":[{"args":pair,"expected":TASK_MODULE.oracle(task["id"],*pair)} for pair in task["public"]],
        "complete_selected_catalog":catalog(language),"trusted_wrapper":wrapper_text,
        "resource_event_contract":"For these selected buffer tasks, HIA writes/readbacks use actual buffer.store/buffer.load on the specified owner; Rust uses the indexed audited Vec API. Extra valid accesses are allowed except the odd-y release path, which has none. A VM/API witness is not a machine-instruction proof.",
        "wrapper_notice":"The host links this disclosed wrapper; submit only the indicated candidate function/module. Audit-boundary calls in the Rust wrapper are trusted host instrumentation, unavailable to candidate source.",
        "tools":{"catalog":{"request":{"action":"catalog"},"result":"complete selected catalog"},
            "check":{"request":{"action":"check","candidate":"complete source string"},"result":"actual parser/Core/compiler and public native diagnostics; an accepted build yields candidate_digest"},
            "final":{"request_options":[{"action":"final","candidate_digest":"accepted check digest"},{"action":"final","candidate":"complete source string"}],
                "result":"terminal submission. A new final candidate consumes a public check; hidden execution occurs after the model process closes and yields no feedback."}},
        "budget":"Exactly one catalog/check/final JSON object per answer, no Markdown. At most six model turns and three public checks total, same in both arms. Initial catalog is already complete. Local diagnostics may be used for revisions; hidden cases/answers are unavailable. Do not invoke any CLI tools, inspect files, browse, or obtain reference answers. Existing user rules remain in force.",
        "execution_limits":{"native_virtual_address_space_bytes":268435456,"native_core_dump_bytes":0,"native_wall_seconds":8,"outer_evaluator_wall_seconds":70,"scope":"equal process limits; address space is not RSS or a complete OS sandbox"},
        "example_notice":"Catalog examples illustrate syntax/interfaces only; they do not implement this task."}

def parse_action(text):
    from hepta.hia_program_tools import decode_json
    action=decode_json(text)
    if type(action) is not dict or type(action.get("action")) is not str or action["action"] not in {"catalog","check","final"}:
        raise ValueError("exactly one catalog/check/final object required")
    allowed=({"action"},) if action["action"]=="catalog" else ({"action","candidate"},) if action["action"]=="check" else ({"action","candidate"},{"action","candidate_digest"})
    if set(action) not in allowed:raise ValueError("incorrect exact RPC fields")
    if "candidate" in action and type(action["candidate"]) is not str:raise ValueError("candidate must be source text")
    if "candidate_digest" in action and (type(action["candidate_digest"]) is not str or not re.fullmatch("[0-9a-f]{64}",action["candidate_digest"])):
        raise ValueError("candidate_digest must be a lowercase 64-digit accepted digest")
    return action

def wrong_signature(task,language):
    if language=="rust":
        if task["interface"]=="task_step":
            return "fn task_step(view:&mut Vec<u8>,x:u32,y:u32)->u64 { 0 }"
        return "fn target(x:u32,y:u32)->u64 { 0 }"
    from hepta.hia_agent_assembly import render_assembly
    document=TASK_MODULE.reference_core(task["id"])
    document["functions"][0]["returns"]=["u64"]
    # Do not use a renderer that would reverify the deliberately invalid module.
    text=TASK_MODULE.reference(task["id"],language)
    return text.replace(" -> (mutbuf)"," -> (u64)",1).replace(" -> (u32)"," -> (u64)",1)

def controls(output):
    folder=Path(output);folder.mkdir(parents=True,exist_ok=False);started=time.monotonic_ns()
    cfg=config();rows=[]
    result={"schema":"hepta.agent.v8.controls.v1","model_requests":0,"formal_cases_materialized":0,
        "author_controls_are_model_successes":False,"bindings":bindings(),"tools":tool_bindings(),
        "catalogs":{l:sha256(canonical(catalog(l))).hexdigest() for l in LANGUAGES},
        "prompts":{t["id"]+":"+l:sha256(canonical(public_prompt(t,l))).hexdigest() for t in TASKS for l in LANGUAGES},
        "rows":rows,"passed":False}
    save(folder/"RESULT.json",result)
    result["feature_probe"]=feature_probe(folder/"feature-probe")
    for task in TASKS:
        for language in LANGUAGES:
            cell=folder/(task["id"]+"-"+language);cell.mkdir()
            good=evaluate(task,language,cell/"public",candidate=TASK_MODULE.reference(task["id"],language))
            dev=evaluate(task,language,cell/"development",build=good,phase="development") if good["accepted"] else None
            bad=evaluate(task,language,cell/"wrong-signature",candidate=wrong_signature(task,language))
            if task["interface"]=="target":
                if language=="rust":zero="fn target(x:u32,y:u32)->u32 {0}"
                else:
                    from hepta.hia_agent_assembly import render_assembly
                    zero=render_assembly(TASK_MODULE.module(TASK_MODULE.fn("target",["x","y"],["u32"],[],
                        [TASK_MODULE.b("entry",["x","y"],[TASK_MODULE.c("zero",0)],TASK_MODULE.ret("zero"))])))
                wrong=evaluate(task,language,cell/"wrong-result",candidate=zero)
            else:
                if language=="rust":
                    wrong_source=("fn task_step<'a>(view:&'a mut Vec<u8>,x:u32,y:u32)->&'a mut Vec<u8> {view}"
                        if task["id"]=="return_borrow" else "fn task_step(view:&mut Vec<u8>,x:u32,y:u32)->u32 {(x>>3).wrapping_add(y) as u8 as u32}")
                else:
                    from hepta.hia_agent_assembly import render_assembly
                    doc=TASK_MODULE.reference_core(task["id"])
                    fn=doc["functions"][0]
                    for block in fn["blocks"]:
                        block["ops"]=[o for o in block["ops"] if o["op"]!="buffer.store"]
                    wrong_source=render_assembly(doc)
                wrong=evaluate(task,language,cell/"missing-resource-work",candidate=wrong_source)
            row={"task":task["id"],"language":language,"reference_public":good["accepted"],
                "reference_development":bool(dev and dev["accepted"]),"wrong_signature_rejected":not bad["accepted"],
                "wrong_result_or_resource_rejected":not wrong["accepted"]}
            rows.append(row);save(folder/"RESULT.json",result);print(json.dumps(row),flush=True)
    result["passed"]=len(rows)==12 and all(all(row[k] for k in ("reference_public","reference_development","wrong_signature_rejected","wrong_result_or_resource_rejected")) for row in rows)
    result["wall_ns"]=time.monotonic_ns()-started
    result["identities_unchanged"]=result["bindings"]==bindings() and result["tools"]==tool_bindings()
    result["passed"] &= result["identities_unchanged"]
    save(folder/"RESULT.json",result);return 0 if result["passed"] else 1

def freeze(controls_path):
    if (HERE/"FREEZE.json").exists():raise ValueError("never replace registered freeze")
    record=strict_json(Path(controls_path).read_bytes())
    if (not record.get("passed") or record.get("model_requests")!=0 or record.get("formal_cases_materialized")!=0
            or record["bindings"]!=bindings() or record["tools"]!=tool_bindings()):
        raise ValueError("matching exact-source no-generation development controls required")
    for path,digest in bindings().items():
        if sha256(subprocess.check_output(["git","show","HEAD:"+path],cwd=ROOT)).hexdigest()!=digest:
            raise ValueError("uncommitted bound source: "+path)
    result={"schema":"hepta.agent.v8.freeze.v1","code_commit":git("rev-parse","HEAD"),
        "bindings":bindings(),"tools":tool_bindings(),"controls":identity(controls_path),
        "catalogs":record["catalogs"],"prompts":record["prompts"],"created_unix_ns":time.time_ns(),
        "model_requests_before_freeze":0,"formal_cases_before_freeze":0}
    save(HERE/"FREEZE.json",result);print(json.dumps({"freeze":identity(HERE/"FREEZE.json"),"code_commit":result["code_commit"]}))
    return 0

def verify_freeze():
    frozen=strict_json((HERE/"FREEZE.json").read_bytes())
    if frozen["bindings"]!=bindings() or frozen["tools"]!=tool_bindings():raise ValueError("frozen source/tool drift")
    if identity(frozen["controls"]["path"])!=frozen["controls"]:raise ValueError("controls receipt drift")
    if frozen["catalogs"]!={l:sha256(canonical(catalog(l))).hexdigest() for l in LANGUAGES}:raise ValueError("catalog drift")
    if frozen["prompts"]!={t["id"]+":"+l:sha256(canonical(public_prompt(t,l))).hexdigest() for t in TASKS for l in LANGUAGES}:raise ValueError("prompt drift")
    return frozen


def terminal_usage_admission(turns, process, completed_total, cfg):
    """Reconcile final retained telemetry against accepted turn accounting."""
    events=process.get("final_stream_audit",{}).get("raw_usage_events",[])
    observed=events[-1]["total"] if events else dict(completed_total)
    matches=observed==completed_total
    complete=bool(turns) and all(t.get("status")=="completed" and t.get("usage_complete") for t in turns) and matches
    total=observed.get("totalTokens")
    return {"provider_observed_cumulative_usage":observed,
        "terminal_raw_usage_matches_completed_turns":matches,
        "provider_usage_complete":complete,
        "provider_cumulative_usage":dict(completed_total) if complete else {key:None for key in USAGE_FIELDS},
        "observed_provider_token_limit_exceeded":type(total) is int and total>cfg["max_provider_total_tokens_per_cell"],
        "observed_usage_is_exact_bill":False}


def run_cell(task,language,folder,campaign_deadline,cfg,registration_commit):
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=False)
    started=time.monotonic_ns();deadline=min(campaign_deadline,time.monotonic()+cfg["max_cell_wall_seconds"])
    row={"task":task["id"],"language":language,"correct":False,"status":"started",
        "public_checks":[],"rpc_failures":[],"turns":[],"failed_public_checks":0,"human_answer_edits":0,
        "human_review_ns":None,"hidden_evaluated":False,"provider_usage_complete":False}
    save(folder/"RESULT.json",row);dialogue=None;selected=None;approved={}
    try:
        empty=folder/"empty-cwd";empty.mkdir()
        dialogue=AppServerDialogue(executable=cfg["codex"],cwd=empty,output=folder/"dialogue",cfg=cfg,
            deadline=deadline-cfg["cleanup_reserve_seconds"])
        row["effective_thread"]=dialogue.start_thread(cfg["model"])
        message="Use only the disclosed public task/catalog. Return one JSON RPC.\n"+canonical(public_prompt(task,language)).decode()
        for turn_index in range(cfg["max_turns_per_cell"]):
            response=dialogue.turn(message);row["turns"].append(response)
            try:action=parse_action(response["text"])
            except (ValueError,TypeError) as error:
                row["rpc_failures"].append({"turn":turn_index,"error":str(error)})
                message=canonical({"public_rpc_error":str(error),"remaining_turns":cfg["max_turns_per_cell"]-turn_index-1}).decode()
                continue
            if action["action"]=="catalog":
                message=canonical({"catalog_result":catalog(language)}).decode();continue
            if "candidate_digest" in action:
                selected=approved.get(action["candidate_digest"])
                if selected is None:row["status"]="final_digest_not_accepted"
                else:row["status"]="final_public_accepted"
                break
            if len(row["public_checks"])>=cfg["max_public_checks_per_cell"]:
                if action["action"]=="final":row["status"]="final_public_budget_exhausted";break
                message=canonical({"public_rpc_error":"public check quota exhausted; final must cite an accepted digest"}).decode();continue
            candidate=action["candidate"];digest=sha256(candidate.encode()).hexdigest()
            remaining=deadline-time.monotonic()-cfg["cleanup_reserve_seconds"]
            if remaining<=0:raise TimeoutError("cell deadline before public compilation")
            checked=evaluate(task,language,folder/f"check-{len(row['public_checks'])}",candidate=candidate,timeout=min(70,remaining))
            row["public_checks"].append({"candidate_digest":digest,"accepted":checked["accepted"],"status":checked["status"],
                "wall_ns":checked.get("wall_ns"),"process_wall_ns":checked.get("process",{}).get("wall_ns")})
            if checked["status"] in {"evaluation_runtime_failure","execution_limit_unavailable"}:raise RuntimeError("owned public evaluator failed")
            if checked["accepted"]:approved[digest]=checked
            else:row["failed_public_checks"]+=1
            if action["action"]=="final":
                selected=checked if checked["accepted"] else None
                row["status"]="final_public_accepted" if selected else "final_public_rejected";break
            message=canonical({"public_check_result":public_feedback(checked,digest),
                "remaining_checks":cfg["max_public_checks_per_cell"]-len(row["public_checks"]),
                "remaining_turns":cfg["max_turns_per_cell"]-turn_index-1}).decode()
        else:row["status"]="turn_budget_no_final"
    except Exception as error:
        row.update(status="terminal_runtime_or_protocol_failure",error={"type":type(error).__name__,"message":str(error)})
    finally:
        if dialogue is not None:
            row["process"]=dialogue.close()
            # Preserve failed turn records too; provider usage already spent is never discarded.
            row["turns"]=[strict_json(p.read_bytes()) for p in sorted((folder/"dialogue").glob("turn-*.json"))]
            row.update(terminal_usage_admission(row["turns"],row["process"],dialogue.usage_total,cfg))
            row["explicit_turn_start_calls"]=row["process"]["generation_turns_started"]
            row["direct_tool_contamination"]=bool(row["process"].get("final_stream_audit",{}).get("forbidden_activity"))
            if (not row["process"].get("cleanup_confirmed") or row["process"].get("status")!="closed"
                    or not row["process"].get("final_stream_audit",{}).get("eligible")
                    or row["observed_provider_token_limit_exceeded"]):
                row["status"]="terminal_runtime_or_protocol_failure";selected=None
        else:row["explicit_turn_start_calls"]=0
        save(folder/"RESULT.json",row)
    if selected is not None and row["status"]=="final_public_accepted":
        try:
            remaining=deadline-time.monotonic()-cfg["cleanup_reserve_seconds"]
            if remaining<=0:raise TimeoutError("cell deadline before terminal evaluation")
            verify_freeze()
            admission=folder/"TERMINAL_ADMISSION.json"
            save(admission,{"schema":"hepta.agent.v8.formal-admission.v1","registration_commit":registration_commit,
                "freeze_sha256":identity(HERE/"FREEZE.json")["sha256"],"task":task["id"],"model_process_closed":True})
            hidden=evaluate(task,language,folder/"terminal",build=selected,phase="formal",admission=admission,timeout=min(70,remaining))
            row["hidden_evaluated"]=True
            row["terminal"]={"accepted":hidden["accepted"],"correct":hidden["correct"],"status":hidden["status"],
                "wall_ns":hidden.get("wall_ns"),"process_wall_ns":hidden.get("process",{}).get("wall_ns")}
            row["correct"]=hidden["correct"]
            row["status"]="terminal_native_success" if row["correct"] else "terminal_native_rejected"
            if hidden["status"] in {"evaluation_runtime_failure","execution_limit_unavailable"}:row["status"]="terminal_runtime_or_protocol_failure"
        except Exception as error:
            row.update(status="terminal_runtime_or_protocol_failure",error={"type":type(error).__name__,"message":str(error)})
    row["wall_ns"]=time.monotonic_ns()-started
    row["cell_budget_exceeded"]=row["wall_ns"]>cfg["max_cell_wall_seconds"]*1_000_000_000
    if row["cell_budget_exceeded"]:row["correct"]=False;row["status"]="terminal_runtime_or_protocol_failure"
    save(folder/"RESULT.json",row);return row

def summary(rows):
    result={"scope":"12-cell authored prospective pilot only","human_cost_advantage_eligible":False,
            "general_productivity_claim":False,"arms":{},"descriptive_hia_advantage_gate":False}
    for language in LANGUAGES:
        selected=[r for r in rows if r["language"]==language]
        usage={key:sum(r.get("provider_cumulative_usage",{}).get(key,0) for r in selected)
            if all(type(r.get("provider_cumulative_usage",{}).get(key)) is int for r in selected) else None for key in USAGE_FIELDS}
        result["arms"][language]={"attempted":len(selected),"successes":sum(r["correct"] for r in selected),
            "failed_public_checks":sum(r["failed_public_checks"] for r in selected),
            "explicit_turn_start_calls":sum(r["explicit_turn_start_calls"] for r in selected),
            "wall_ns":sum(r["wall_ns"] for r in selected),"provider_usage":usage,
            "provider_usage_complete":len(selected)==6 and all(r["provider_usage_complete"] for r in selected)}
    h,r=(result["arms"][l] for l in LANGUAGES)
    result["descriptive_hia_advantage_gate"]=bool(h["provider_usage_complete"] and r["provider_usage_complete"]
        and h["successes"]>=r["successes"] and h["provider_usage"]["totalTokens"]<r["provider_usage"]["totalTokens"]
        and h["wall_ns"]<r["wall_ns"] and h["failed_public_checks"]<=r["failed_public_checks"])
    return result

def run(output,review_path,registration_commit):
    frozen=verify_freeze();cfg=config();review=strict_json(Path(review_path).read_bytes())
    if (review.get("decision")!="allow_generation" or review.get("freeze_sha256")!=identity(HERE/"FREEZE.json")["sha256"]
        or review.get("controls_sha256")!=frozen["controls"]["sha256"] or review.get("model_requests_by_reviewer")!=0):
        raise ValueError("independent exact-freeze zero-generation review required")
    rel=str((HERE/"FREEZE.json").relative_to(ROOT))
    if subprocess.check_output(["git","show",registration_commit+":"+rel],cwd=ROOT)!=(HERE/"FREEZE.json").read_bytes():
        raise ValueError("registration does not bind exact freeze")
    subprocess.run(["git","merge-base","--is-ancestor",registration_commit,"HEAD"],cwd=ROOT,check=True)
    if subprocess.check_output(["git","show",registration_commit+":"+str(Path(review_path).resolve().relative_to(ROOT))],cwd=ROOT)!=Path(review_path).read_bytes():
        raise ValueError("registration does not bind exact independent review")
    folder=Path(output).resolve();folder.mkdir(parents=True,exist_ok=False)
    start=time.monotonic_ns();deadline=time.monotonic()+cfg["max_campaign_wall_seconds"]
    result={"schema":"hepta.agent.v8.result.v1","registration_commit":registration_commit,
        "freeze":identity(HERE/"FREEZE.json"),"review":identity(review_path),"model":cfg["model"],
        "cells":[],"status":"started","previous_results_replaced":False,"human_review_ns":None}
    save(folder/"PLAN.json",{**result,"protocol":cfg,"frozen":frozen,"model_requests_before_plan":0,"formal_cases_before_plan":0})
    try:
        result["feature_probe"]=feature_probe(folder/"feature-probe",timeout=min(20,max(0.1,deadline-time.monotonic())))
        for i,task in enumerate(TASKS):
            for language in (LANGUAGES if i%2==0 else tuple(reversed(LANGUAGES))):
                verify_freeze()
                if time.monotonic()+cfg["cleanup_reserve_seconds"]>=deadline:raise TimeoutError("global campaign deadline")
                row=run_cell(task,language,folder/(task["id"]+"-"+language),deadline,cfg,registration_commit)
                result["cells"].append(row);result["summary"]=summary(result["cells"])
                raw_bytes=sum(p.stat().st_size for p in folder.rglob("*.raw"))
                result["retained_raw_bytes"]=raw_bytes;save(folder/"RESULT.json",result)
                print(json.dumps({"task":task["id"],"language":language,"status":row["status"],"correct":row["correct"],
                    "turns":row["explicit_turn_start_calls"],"usage":row.get("provider_cumulative_usage")}),flush=True)
                if row["status"]=="terminal_runtime_or_protocol_failure":raise RuntimeError("terminal infrastructure/protocol failure; no rerun")
                if raw_bytes>cfg["stream_limits"]["campaign_retained_raw_bytes"]:raise RuntimeError("campaign raw evidence bound")
        result["status"]="all_cells_attempted"
    except Exception as error:
        result.update(status="incomplete",error={"type":type(error).__name__,"message":str(error)})
    finally:
        result["summary"]=summary(result["cells"])
        try:verify_freeze();result["identities_unchanged"]=True
        except Exception as error:result["identities_unchanged"]=False;result["identity_error"]=str(error)
        result["wall_ns"]=time.monotonic_ns()-start
        result["campaign_budget_exceeded"]=result["wall_ns"]>cfg["max_campaign_wall_seconds"]*1_000_000_000
        if result["campaign_budget_exceeded"]:
            result.update(status="incomplete",error={"type":"TimeoutError","message":"actual complete campaign wall exceeded unchanged registered budget"})
        result["summary"]["descriptive_hia_advantage_gate"] &= result["identities_unchanged"] and result["status"]=="all_cells_attempted"
        save(folder/"RESULT.json",result)
    return 0 if result["status"]=="all_cells_attempted" and result["identities_unchanged"] else 1

def main(argv=None):
    import argparse
    p=argparse.ArgumentParser(description=__doc__);s=p.add_subparsers(dest="action",required=True)
    q=s.add_parser("controls");q.add_argument("--output",required=True)
    q=s.add_parser("freeze");q.add_argument("--controls",required=True)
    q=s.add_parser("run");q.add_argument("--output",required=True);q.add_argument("--review",required=True);q.add_argument("--registration-commit",required=True)
    a=p.parse_args(argv)
    if a.action=="controls":return controls(a.output)
    if a.action=="freeze":return freeze(a.controls)
    return run(a.output,a.review,a.registration_commit)
if __name__=="__main__":raise SystemExit(main())
