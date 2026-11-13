#!/usr/bin/env python3
"""Frozen paired Agent repair study on two repository resource modules.

These are explicitly registered fault injections into pinned repository
examples, not observed industrial or historical maintenance tasks. Reference
controls never count as model successes. Hidden evaluation is terminal.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.dont_write_bytecode = True
HERE = ROOT/"benchmarks/hia_agent_repository_maintenance"

# The registered v1 protocol and v2 inheritance hash retain their original
# bytes. Only these two historical logical names project to current sources.
SOURCE_PATH_PROJECTIONS = {
    "examples/hia_program/offset_copy_v5.hia": "examples/hia_program/offset_copy_v5.hepta",
    "examples/hia_program/overlap_move_v3.hia": "examples/hia_program/overlap_move_v3.hepta",
}

from hepta.hia_program import verify_program
from hepta.hia_program_tools import apply_program_patch, decode_json, bounded_json_wire
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_llvm import build_program_native
from tools.provider_adapter.llama_cpp_engine import LlamaCppEngine, canonical, file_identity


def save(path,value):
    with Path(path).open("xb") as stream:
        stream.write(canonical(value)+b"\n")


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def cfg():
    value = decode_json((HERE/"PROTOCOL.json").read_bytes())
    if value["schema"] != "hepta.hia.agent-repository-maintenance.v1":
        raise ValueError("unregistered protocol")
    return value


def registered_source(task):
    logical = task["source_path"]
    if logical not in SOURCE_PATH_PROJECTIONS:
        raise ValueError("unregistered repository source path")
    resolved = SOURCE_PATH_PROJECTIONS[logical]
    raw = (ROOT/resolved).read_bytes()
    identity = {
        "source_path": logical,
        "resolved_source_path": resolved,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "source_git_blob": hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest(),
    }
    if any(identity[key] != task[key] for key in ("source_sha256", "source_git_blob")):
        raise ValueError("repository source differs from pinned Git blob")
    return raw, identity


def source_projections():
    return {task["id"]: registered_source(task)[1] for task in cfg()["tasks"]}


def bindings():
    files = [*ROOT.glob("hepta/*.py"),*HERE.glob("*"),Path(__file__),
             ROOT/"tools/provider_adapter/llama_cpp_engine.py",
             ROOT/"benchmarks/hia_native_ndu/metrics.c",ROOT/"benchmarks/hia_native_ndu/metrics.h"]
    files += [ROOT/item["resolved_source_path"] for item in source_projections().values()]
    return {str(p.relative_to(ROOT)):file_identity(p)["sha256"] for p in sorted(set(files)) if p.is_file()}


def git_head():
    return subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()


def require_committed_bindings(frozen):
    """A commit label alone cannot freeze dirty or untracked compiler inputs."""
    tree = subprocess.check_output(["git","ls-tree","-r","--full-tree","HEAD","--",*sorted(frozen)],cwd=ROOT)
    admitted = {}
    for line in tree.splitlines():
        metadata,name = line.split(b"\t",1)
        mode,kind,blob = metadata.split()
        if kind!=b"blob":
            raise ValueError("non-blob source input")
        admitted[name.decode()] = blob.decode()
    if set(admitted)!=set(frozen):
        raise ValueError("all study/compiler inputs must be committed before model requests")
    for name in frozen:
        raw = (ROOT/name).read_bytes()
        git_blob = hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
        if admitted[name]!=git_blob:
            raise ValueError("dirty compiler/study input after source freeze: "+name)


def target(task):
    raw, _ = registered_source(task)
    return verify_program(decode_json(raw)).as_dict()


def operation(document,task):
    fn = next(f for f in document["functions"] if f["name"]==task["function"])
    block = next(b for b in fn["blocks"] if b["id"]==task["block"])
    return block["ops"][task["operation_index"]]


def initial(task):
    document = target(task)
    site = operation(document,task)
    if task["injection"]=="legacy-zero-offset-api":
        site["op"],site["args"] = "buffer.copy",["writer","reader","count"]
    elif task["injection"]=="swapped-source-destination":
        site["args"] = ["writer","source","destination","count"]
    else:
        raise ValueError("unknown registered injection")
    return verify_program(document)


def reference(task,arm):
    if arm=="hia_full":
        return target(task)
    return {"schema":"hepta.hia.patch.v2","expected_sha256":initial(task).sha256,
            "interface_policy":"preserve","edits":[{"action":"replace_operation",
            "function":task["function"],"block":task["block"],"index":task["operation_index"],
            "operation":operation(target(task),task)}]}


def oracle(task,args):
    length,destination,source,count,probe = args
    if length<5 or destination>length or source>length or count>length-destination or count>length-source or probe>=length:
        return None
    origin = [11,22,33,44,55]+[0]*(length-5)
    result = [0]*length if task["id"]=="offset-copy-api" else origin[:]
    result[destination:destination+count] = origin[source:source+count]
    return result[probe]


def prompt(task,arm):
    base = initial(task)
    contract = ("Maintain copy_offset(length,dst,src,count,probe). The existing client now supplies independent source and destination offsets. Replace the legacy zero-offset buffer.copy integration with the offset-aware buffer.copy_range API, whose operands are [destination_mut_loan,source_read_loan,destination_offset,source_offset,count]. The result is the destination byte at probe after copying; preserve all allocations, initialization, borrows, releases and ABI."
        if task["id"]=="offset-copy-api" else
        "Maintain move_bytes(length,destination,source,count,probe). Its buffer.move_within callsite accidentally reversed source and destination. This API takes [mutable_loan,destination_offset,source_offset,count] and must preserve memmove overlap behavior. The result is the byte at probe after moving; preserve all allocations, initialization, borrows, releases and ABI.")
    common = {"task":task["id"],"provenance":"Pinned repository module with registered injected defect; not a historical bug claim",
        "source":{k:task[k] for k in ("source_path","source_sha256","source_git_blob")},
        "contract":contract,"initial_program":base.as_dict(),"snapshot_sha256":base.sha256,
        "repair_site":{"function":task["function"],"block":task["block"],"operation_index":task["operation_index"]},
        "scope":"Only replace this operation; every other normalized program field must remain byte-for-byte canonical equivalent. Do not add functions, alter effects, remove cleanup or use a scalar shortcut.",
        "public_cases":[{"args":a,"expected":oracle(task,a)} for a in cfg()["public_cases"]],
        "same_information":"Both arms receive this entire initial program, contract, repair site, public cases and patch API. Only the required response representation differs.",
        "patch_api":{"schema":"hepta.hia.patch.v2","expected_sha256":"the supplied snapshot_sha256",
            "interface_policy":"preserve","edits":[{"action":"replace_operation","function":"the supplied function",
            "block":"the supplied block","index":"the supplied integer operation_index",
            "operation":{"op":"opcode","args":["operand names"],"out":[],"attrs":{}}}]},
        "response":"Return exactly one complete HIA module JSON object." if arm=="hia_full" else
                   "Return exactly one snapshot-bound patch JSON object using patch_api, with one replace_operation edit.",
        "budget":"Same 2048 output-token limit and 120 seconds per response in both arms; two responses at most. The host performs real public verification and native checks. A successful public submission ends repair and receives terminal hidden evaluation. No Markdown or prose."}
    return json.dumps(common,sort_keys=True,separators=(",",":"))


def admit(task,arm,raw):
    payload = raw.encode() if isinstance(raw,str) else bounded_json_wire(raw,65536)
    if len(payload)>65536:
        raise ValueError("candidate byte budget")
    value = decode_json(payload)
    if arm=="hia_structured":
        verified,receipt = apply_program_patch(initial(task),value)
    else:
        verified,receipt = verify_program(value),None
    candidate = verified.as_dict()
    masked = deepcopy(candidate)
    masked_site = operation(masked,task)
    masked_site.clear()
    masked_site.update(operation(initial(task).as_dict(),task))
    if canonical(masked)!=canonical(initial(task).as_dict()):
        raise ValueError("edit escaped the disclosed single operation repair site")
    return verified,receipt


def command(argv,directory,number):
    start = time.monotonic_ns()
    result = subprocess.run([str(x) for x in argv],capture_output=True,timeout=40)
    record = {"argv":[str(x) for x in argv],"returncode":result.returncode,
              "wall_ns":time.monotonic_ns()-start}
    for label,raw in (("stdout",result.stdout),("stderr",result.stderr)):
        path = directory/f"command-{number}.{label}"
        path.write_bytes(raw)
        record[label] = file_identity(path)
    if result.returncode:
        raise ValueError("native compilation failed: "+result.stderr.decode(errors="replace")[:1500])
    return record


def evaluate(task,arm,raw,directory,clang):
    started = time.monotonic_ns()
    directory.mkdir(parents=True,exist_ok=False)
    row = {"accepted":False,"hidden_evaluated":False,"status":"starting","commands":[]}
    try:
        verified,receipt = admit(task,arm,raw)
        save(directory/"candidate.json",verified.as_dict())
        row["candidate"] = file_identity(directory/"candidate.json")
        row["patch_receipt"] = receipt
        vm = []
        for args in cfg()["public_cases"]:
            observed = execute_program(verified,task["function"],args,max_steps=10000,max_heap_bytes=65536)
            if observed["result"] != oracle(task,args):
                raise ValueError("public interpreter result mismatch")
            resources = observed["resources"]
            if (resources["live_owners"] or resources["live_local_loans"] or
                resources["allocations"]!=task["owners"] or resources["frees"]!=task["owners"]):
                raise ValueError("public interpreter owner/loan cleanup mismatch")
            vm.append(observed)
        row["interpreter_public"] = vm
        compiled = build_program_native(verified,directory/"candidate.o",clang=clang,kind="object")
        row["native_compilation"] = compiled
        metrics = ROOT/"benchmarks/hia_native_ndu"
        args = [clang,"-O2","-I",metrics,"-DTARGET="+task["function"],HERE/"driver.c",directory/"candidate.o",
                metrics/"metrics.c",*["-Wl,--wrap="+name for name in ("malloc","calloc","realloc","free")],
                "-o",directory/"candidate"]
        row["commands"].append(command(args,directory,0))
        row["binary"] = file_identity(directory/"candidate")
        row["public_native"] = execute_native(task,row["binary"],cfg()["public_cases"],False)
        if not row["public_native"]["passed"]:
            raise ValueError("public native result or lifecycle mismatch")
        row.update(accepted=True,status="public_accepted")
    except Exception as error:
        row.update(status="candidate_rejected",error={"type":type(error).__name__,"message":str(error)[:1800]})
    row["wall_ns"] = time.monotonic_ns()-started
    save(directory/"PUBLIC.json",row)
    return row


def execute_native(task,binary,cases,refusal):
    if file_identity(binary["path"])!=binary:
        raise ValueError("native binary changed before execution")
    rows = []
    for args in cases:
        started = time.monotonic_ns()
        try:
            value = subprocess.run([binary["path"],*[str(x) for x in args]],capture_output=True,timeout=5)
            row = {"args":args,"returncode":value.returncode,"stdout_hex":value.stdout.hex(),
                   "stderr_hex":value.stderr.hex(),"wall_ns":time.monotonic_ns()-started,"passed":False}
            if refusal:
                row["passed"] = value.returncode in {-signal.SIGILL,-signal.SIGABRT} and not value.stdout
            elif value.returncode==0:
                observed = decode_json(value.stdout)
                row["observed"] = observed
                row["expected"] = oracle(task,args)
                row["passed"] = (observed.get("value")==row["expected"] and
                    observed.get("allocations")==observed.get("frees")==task["owners"] and
                    observed.get("live")==observed.get("live_requested")==observed.get("accounting_errors")==0)
        except subprocess.TimeoutExpired:
            row = {"args":args,"passed":False,"status":"native_timeout","wall_ns":time.monotonic_ns()-started}
        rows.append(row)
    return {"passed":all(r["passed"] for r in rows),"cases":rows,
            "scope":"native bounds trap" if refusal else "native results and actual allocation/free counters"}


def hidden(task,build,directory):
    started = time.monotonic_ns()
    normal = execute_native(task,build["binary"],cfg()["hidden_valid_cases"],False)
    refused = execute_native(task,build["binary"],cfg()["hidden_refusal_cases"],True)
    result = {"passed":normal["passed"] and refused["passed"],"normal":normal,"refused":refused,
              "hidden_evaluated":True,"wall_ns":time.monotonic_ns()-started,
              "trap_scope":"bounds faults terminate the owned child; no resource-cleanup theorem is inferred for a trapped process"}
    save(directory/"HIDDEN.json",result)
    return result


def controls(args):
    output = Path(args.output).resolve();output.mkdir(parents=True,exist_ok=False)
    started = time.monotonic_ns()
    frozen = bindings()
    rows = []
    for task in cfg()["tasks"]:
        for arm in cfg()["arms"]:
            location = output/(task["id"]+"-"+arm)
            positive = evaluate(task,arm,reference(task,arm),location,args.clang)
            terminal = hidden(task,positive,location) if positive["accepted"] else {"passed":False}
            rows.append({"task":task["id"],"arm":arm,"kind":"reference","passed":positive["accepted"] and terminal["passed"]})
        unchanged = evaluate(task,"hia_full",initial(task).as_dict(),output/(task["id"]+"-unchanged"),args.clang)
        rows.append({"task":task["id"],"kind":"unchanged","passed":not unchanged["accepted"]})
        leaked = target(task)
        leaked["functions"][0]["blocks"][0]["ops"].pop()
        rejected = evaluate(task,"hia_full",leaked,output/(task["id"]+"-missing-release"),args.clang)
        rows.append({"task":task["id"],"kind":"missing-release","passed":not rejected["accepted"]})
        stale = reference(task,"hia_structured");stale["expected_sha256"]="1"*64
        rejected = evaluate(task,"hia_structured",stale,output/(task["id"]+"-stale-snapshot"),args.clang)
        rows.append({"task":task["id"],"kind":"stale-snapshot","passed":not rejected["accepted"]})
    record = {"schema":"hepta.hia.agent-repository-maintenance.controls.v1","source_commit":git_head(),
              "source_projections":source_projections(),
              "bindings":frozen,"clang":file_identity(args.clang),"model_requests":0,
              "reference_controls_are_model_successes":False,"rows":rows,
              "passed":all(r["passed"] for r in rows) and bindings()==frozen,
              "wall_ns":time.monotonic_ns()-started,
              "prompt_bindings":{t["id"]+"/"+a:hashlib.sha256(prompt(t,a).encode()).hexdigest()
                                 for t in cfg()["tasks"] for a in cfg()["arms"]}}
    save(output/"CONTROLS.json",record)
    print(json.dumps({"controls":str(output/"CONTROLS.json"),"passed":record["passed"],"rows":len(rows)}))
    return 0 if record["passed"] else 1


def blocked_provider(path):
    folder = Path(path).resolve()
    record = decode_json((folder/"PROCESS.json").read_bytes())
    raw = (folder/"stdout.raw").read_bytes()
    events = [decode_json(line) for line in raw.splitlines() if line]
    failed = [e for e in events if e.get("type")=="turn.failed"]
    if (not record.get("cleanup_confirmed") or "gpt-6.1-sol" not in record.get("argv",[]) or not failed or
            not any("usage limit" in e.get("error",{}).get("message","").lower() for e in failed)):
        raise ValueError("second model block lacks real usage-limit/cleanup evidence")
    return {"requested_model":"gpt-6.1-sol","status":"provider_usage_limit","task_attempts":0,
            "counted_as_wrong_answer":False,"files":{n:file_identity(folder/n) for n in ("PROCESS.json","stdout.raw","stderr.raw","stdin.raw")},
            "availability_probe_wall_ns":record.get("wall_ns"),"task_usage":None}


def run(args):
    output = Path(args.output).resolve();output.mkdir(parents=True,exist_ok=False)
    started = time.monotonic_ns();frozen = bindings();config = cfg()
    control = decode_json(Path(args.controls).read_bytes())
    if (not control["passed"] or control["bindings"]!=frozen or control["clang"]!=file_identity(args.clang)
            or control["source_commit"]!=git_head()):
        raise ValueError("fresh source/tool-matching controls required")
    if args.expected_head and git_head()!=args.expected_head:
        raise ValueError("frozen source commit differs")
    require_committed_bindings(frozen)
    if os.environ.get("LLAMA_ARG_REPACK")!="0":
        raise ValueError("registered LLAMA_ARG_REPACK=0 required")
    report = {"schema":"hepta.hia.agent-repository-maintenance.result.v1","status":"incomplete",
        "source_commit":git_head(),"bindings":frozen,"protocol":config,"controls":file_identity(args.controls),
        "source_projections":source_projections(),
        "second_model":blocked_provider(args.provider_blocked),"cells":[],"human_answer_repairs":0,
        "real_historical_maintenance_measured":False,"multi_model_advantage_established":False,
        "general_agent_productivity_established":False}
    save(output/"PLAN.json",{**report,"model_requests_before_plan":0})
    engine = None
    try:
        engine_start = time.monotonic_ns()
        engine = LlamaCppEngine(binary=args.binary,model=args.model,model_sha256=config["model"]["sha256"],
            output_dir=output/"engine",threads=config["generation"]["threads"],context=8192,json_object=True)
        report["engine_startup_ns"] = time.monotonic_ns()-engine_start
        report["engine_identity"] = engine.identity
        for index,task in enumerate(config["tasks"]):
            arms = config["arms"][index%2:]+config["arms"][:index%2]
            for arm in arms:
                cell_start = time.monotonic_ns()
                folder = output/(task["id"]+"-"+arm);folder.mkdir()
                text = prompt(task,arm)
                if hashlib.sha256(text.encode()).hexdigest()!=control["prompt_bindings"][task["id"]+"/"+arm]:
                    raise ValueError("prompt differs from frozen controls")
                messages = [{"role":"user","content":text}]
                cell = {"task":task["id"],"arm":arm,"attempts":[],"correct":False,"status":"started",
                        "started_monotonic_ns":cell_start}
                report["cells"].append(cell)
                for attempt_index in range(config["generation"]["attempts_per_cell"]):
                    if bindings()!=frozen:
                        raise ValueError("source changed after freeze")
                    attempt = {"index":attempt_index,"usage":None,"generation_requested":False}
                    cell["attempts"].append(attempt)
                    save(folder/f"attempt-{attempt_index}.request.json",{"messages":messages})
                    generation_start = time.monotonic_ns();before = engine.generation_count
                    try:
                        answer = engine.generate(messages,limit=config["generation"]["max_output_tokens"],
                            wall_seconds=config["generation"]["wall_seconds_per_attempt"])
                    except Exception as error:
                        attempt.update(generation_wall_ns=time.monotonic_ns()-generation_start,
                            generation_requested=engine.generation_count>before,status="inference_incomplete",
                            error={"type":type(error).__name__,"message":str(error)})
                        cell["status"]="inference_incomplete"
                        save(folder/f"attempt-{attempt_index}.record.json",attempt)
                        raise
                    attempt.update(usage=answer["usage"],generation_requested=engine.generation_count>before,
                                   generation_wall_ns=time.monotonic_ns()-generation_start)
                    save(folder/f"attempt-{attempt_index}.response.json",answer)
                    build = evaluate(task,arm,answer["text"],folder/f"attempt-{attempt_index}",args.clang)
                    attempt["public_validation_ns"] = build["wall_ns"]
                    attempt["status"] = build["status"]
                    if build["accepted"]:
                        terminal = hidden(task,build,folder/f"attempt-{attempt_index}")
                        attempt["hidden_validation_ns"] = terminal["wall_ns"]
                        cell.update(correct=terminal["passed"],status="correct" if terminal["passed"] else "hidden_failed")
                        save(folder/f"attempt-{attempt_index}.record.json",attempt)
                        break
                    cell["status"]="public_failed"
                    save(folder/f"attempt-{attempt_index}.record.json",attempt)
                    # Only actual public diagnostics, never target source or
                    # hidden results, can enter the second model response.
                    if attempt_index+1<config["generation"]["attempts_per_cell"]:
                        messages += [{"role":"assistant","content":answer["text"]},
                                     {"role":"user","content":json.dumps({"status":build["status"],
                                        "error":build.get("error"),"instruction":"Return a corrected artifact in the original response format. No Markdown."})}]
                cell["wall_ns"] = time.monotonic_ns()-cell_start
                save(folder/"CELL.json",cell)
        report["status"]="completed"
    except Exception as error:
        report["error"]={"type":type(error).__name__,"message":str(error)}
    finally:
        if engine is not None:
            identity_start = time.monotonic_ns()
            try:
                report["final_engine_identity"] = engine.verify_final_identity()
                if not all(report["final_engine_identity"][key] for key in ("model_unchanged","runtime_unchanged")):
                    report["status"]="identity_drift"
            except Exception as error:
                report["final_engine_identity_error"] = {"type":type(error).__name__,"message":str(error)}
                report["status"]="identity_unavailable"
            report["identity_check_ns"] = time.monotonic_ns()-identity_start
            close_start = time.monotonic_ns();engine.close()
            report["engine_shutdown_ns"] = time.monotonic_ns()-close_start
            report["completion_requests"] = engine.generation_count
            report["completion_responses"] = engine.response_count
        report["source_stable"] = bindings()==frozen
        for cell in report["cells"]:
            if "wall_ns" not in cell:
                cell["wall_ns"] = time.monotonic_ns()-cell["started_monotonic_ns"]
        report["run_wall_ns"] = time.monotonic_ns()-started
        shared = report["run_wall_ns"]-sum(c["wall_ns"] for c in report["cells"])
        report["shared_noncell_wall_ns"] = shared
        summary = {}
        for arm in config["arms"]:
            cells = [c for c in report["cells"] if c["arm"]==arm]
            attempts = [a for c in cells for a in c["attempts"]]
            known = [a for a in attempts if a["usage"] is not None]
            success = sum(c["correct"] for c in cells)
            token_total = sum(a["usage"]["total_tokens"] for a in known)
            complete = len(known)==len(attempts) and len(cells)==2
            allocated = sum(c.get("wall_ns",0) for c in cells)+shared//2+control["wall_ns"]
            summary[arm] = {"planned_tasks":2,"attempted_tasks":len(cells),"successes":success,
                "attempts":len(attempts),"automatic_retries":sum(max(0,len(c["attempts"])-1) for c in cells),
                "input_tokens":sum(a["usage"]["input_tokens"] for a in known),
                "output_tokens":sum(a["usage"]["output_tokens"] for a in known),"known_total_tokens":token_total,
                "usage_complete":complete,"unknown_usage_attempts":len(attempts)-len(known),
                "tokens_per_success":token_total/success if success and complete else None,
                "allocated_full_controlled_runtime_ns":allocated,
                "runtime_ns_per_success":allocated/success if success and complete else None,
                "generation_ns":sum(a.get("generation_wall_ns",0) for a in attempts),
                "public_validation_ns":sum(a.get("public_validation_ns",0) for a in attempts),
                "hidden_validation_ns":sum(a.get("hidden_validation_ns",0) for a in attempts)}
        report["summary"] = summary
        report["cost_limits"] = "Each arm pays its measured task wall, half all shared noncell run wall (including source admission and engine lifecycle/identity), and one full controls campaign. Outer command records include Python startup/import/report output. Human development, task authorship, electricity and historic training costs are not measured. No complete economic productivity claim."
        save(output/"REPORT.json",report)
    print(json.dumps({"status":report["status"],"report":str(output/"REPORT.json"),"summary":report["summary"]}))
    return 0 if report["status"]=="completed" and report["source_stable"] else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage",choices=("controls","run"))
    parser.add_argument("--output",required=True)
    parser.add_argument("--clang",required=True)
    parser.add_argument("--controls")
    parser.add_argument("--binary")
    parser.add_argument("--model")
    parser.add_argument("--provider-blocked")
    parser.add_argument("--expected-head")
    args = parser.parse_args()
    if args.stage=="run" and any(getattr(args,k) is None for k in ("controls","binary","model","provider_blocked","expected_head")):
        parser.error("run needs controls, binary, model, expected-head and provider-blocked evidence")
    raise SystemExit(controls(args) if args.stage=="controls" else run(args))


if __name__=="__main__":
    main()
