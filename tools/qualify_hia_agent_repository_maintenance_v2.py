#!/usr/bin/env python3
"""Fixed two-local-plus-Codex cohort; preserve the original v1 experiment.

Task construction, production patch admission, compiler and independent native
oracles are reused unchanged. Protocol v2 adds providers and complete per-model
cost ledgers, never a model-selection or answer-repair step.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.dont_write_bytecode = True

from tools import qualify_hia_agent_repository_maintenance as base
from tools.hia_agent_codex_transport import (CodexEvents, EventFailure, run_owned,
    recover_reported_usage, strict_json)
from tools.provider_adapter.llama_cpp_engine import LlamaCppEngine, file_identity, canonical
from hepta.hia_program_runtime import HIAProgramTrap, HIAProgramBudgetExceeded

PROTOCOL = base.HERE/"PROTOCOL-v2.json"


def protocol():
    value = strict_json(PROTOCOL.read_bytes())
    inherited = base.cfg()
    if (value["schema"]!="hepta.hia.agent-repository-maintenance.v2"
            or file_identity(ROOT/value["inherits"]["path"])["sha256"]!=value["inherits"]["sha256"]
            or value["generation"]!=inherited["generation"]
            or [m["id"] for m in value["models"]]!=value["model_order"]
            or len(value["models"])!=3):
        raise ValueError("unregistered v2 protocol or changed inherited task/budget")
    return value


def bindings():
    paths = dict(base.bindings())
    for p in (Path(__file__),ROOT/"tools/hia_agent_codex_transport.py",
              ROOT/"benchmarks/hia_agent_public_tools/PROTOCOL.json",PROTOCOL):
        paths[str(p.relative_to(ROOT))] = file_identity(p)["sha256"]
    return paths


class CohortEvents(CodexEvents):
    """Permit typed reasoning text, retaining the existing no-tools parser.

    Reasoning is not an answer and cannot change an edit or provide admission.
    Every actual output/usage/completion event still passes CodexEvents.
    """
    def __init__(self,warnings):
        super().__init__(warnings)
        self.reasoning_items = []

    def line(self,raw):
        event = strict_json(raw)
        if (type(event) is dict and event.get("type") in {"item.started","item.updated","item.completed"}
                and type(event.get("item")) is dict and event["item"].get("type")=="reasoning"):
            item = event["item"]
            if (set(event)!={"type","item"} or not {"id","type"}<=set(item)
                    or not set(item)<={"id","type","text"} or type(item["id"]) is not str
                    or ("text" in item and type(item["text"]) is not str)
                    or self.turn_count!=1 or self.completed_count):
                raise EventFailure("invalid or out-of-turn reasoning item")
            self.events.append(event)
            self.reasoning_items.append(event)
            return
        super().line(raw)


def availability(path,configuration):
    path = Path(path).resolve()
    value = strict_json(path.read_bytes())
    process = value["process"]
    stdout = Path(process["files"]["stdout.raw"]["path"])
    if (value.get("requested_model")!="gpt-6.1-sol" or not process.get("cleanup_confirmed")
            or file_identity(stdout)["sha256"]!=process["files"]["stdout.raw"]["sha256"]):
        raise ValueError("provider probe lacks actual stream/cleanup identity")
    observed = CohortEvents(configuration["codex"]["registered_startup_warnings"])
    for line in stdout.read_bytes().splitlines():
        observed.line(line)
    answer = observed.complete()
    available = (value.get("status")=="available" and process["status"]=="exited"
                 and answer["text"]=="AVAILABLE" and answer["usage"]==value["usage"]
                 and value.get("task_attempts")==0 and value.get("model_task_requests")==0)
    if not available:
        raise ValueError("this three-model cohort requires a current successful Codex availability probe")
    if value["cli_identity"]!=file_identity(configuration["codex"]["binary"]):
        raise ValueError("Codex CLI differs from successful availability probe")
    return {"record":file_identity(path),"cli_identity":value["cli_identity"],
            "status":"available","task_attempts_before_cohort":0,
            "probe_wall_ns":process["wall_ns"],"probe_usage":value.get("usage"),
            "historical_usage_limit_overwritten":False}


def admitted_assets(args,configuration):
    root = Path(args.assets).resolve()
    receipts = Path(args.downloads).resolve()
    result = {}
    for model in configuration["models"]:
        if model["provider"]!="local_gguf":
            continue
        receipt = strict_json((receipts/(model["id"]+".json")).read_bytes())
        path = root/model["filename"]
        if (receipt.get("verified") is not True or receipt["observed_sha256"]!=model["sha256"]
                or receipt["observed_bytes"]!=model["bytes"] or path.stat().st_size!=model["bytes"]):
            raise ValueError("missing exact model download receipt")
        # LlamaCppEngine hashes the actual model before starting the process and
        # again at shutdown. A receipt never waives that admission.
        result[model["id"]] = {"path":str(path),"download":file_identity(receipts/(model["id"]+".json")),
                               "download_wall_ns":receipt["complete_wall_ns"]}
    runtime = configuration["runtime"]
    archive = root/runtime["archive"]
    archive_id = file_identity(archive)
    if archive_id["bytes"]!=runtime["bytes"] or archive_id["sha256"]!=runtime["sha256"]:
        raise ValueError("runtime archive differs from registered release")
    candidates = list(root.glob("**/llama-server"))
    if len(candidates)!=1:
        raise ValueError("exactly one restored llama-server required")
    binary = candidates[0].resolve()
    runtime_paths = sorted({binary,*binary.parent.glob("*.so*")})
    shipped = {p.name:p for p in runtime_paths}
    checked = {}
    with tarfile.open(archive,"r:gz") as bundle:
        members = {}
        for member in bundle.getmembers():
            name = Path(member.name).name
            if name=="llama-server" or Path(name).match("*.so*"):
                if name in members:
                    raise ValueError("ambiguous runtime archive member")
                members[name] = member
        if set(members)!=set(shipped):
            raise ValueError("native runtime directory must contain every and only registered runtime member")
        for name,path in shipped.items():
            member = members[name]
            if path.is_symlink():
                if not member.issym() or os.readlink(path)!=member.linkname:
                    raise ValueError("runtime symlink differs from pinned archive link")
                resolved = path.resolve(strict=True)
                if resolved.parent!=binary.parent or resolved.name not in members:
                    raise ValueError("runtime symlink escapes pinned directory")
                target = members[resolved.name]
            else:
                if not member.isfile() or not path.is_file():
                    raise ValueError("runtime file kind differs from pinned archive")
                target = member
            if not target.isfile():
                raise ValueError("runtime symlink does not resolve to a registered regular file")
            with bundle.extractfile(target) as stream:
                expected = hashlib.file_digest(stream,"sha256").hexdigest()
            actual = file_identity(path)
            if actual["sha256"]!=expected or actual["bytes"]!=target.size:
                raise ValueError("extracted native runtime differs from pinned archive")
            checked[name] = actual
    runtime_receipt = strict_json((receipts/"llama-runtime.json").read_bytes())
    result["runtime"] = {"binary":str(binary),"archive":archive_id,"files":checked,
                         "identity":[file_identity(p) for p in runtime_paths],
                         "download":file_identity(receipts/"llama-runtime.json"),
                         "download_wall_ns":runtime_receipt["complete_wall_ns"]}
    return result


def controls(args):
    output = Path(args.output).resolve();output.mkdir(parents=True,exist_ok=False)
    entered = time.monotonic_ns();frozen = bindings();configuration = protocol()
    rows = []
    for task in base.cfg()["tasks"]:
        for arm in base.cfg()["arms"]:
            location = output/(task["id"]+"-"+arm)
            positive = evaluate(task,arm,base.reference(task,arm),location,args.clang)
            terminal = evaluate_hidden(task,positive,location) if positive["accepted"] else {"passed":False}
            rows.append({"task":task["id"],"arm":arm,"kind":"reference","passed":positive["accepted"] and terminal["passed"]})
        unchanged = evaluate(task,"hia_full",base.initial(task).as_dict(),output/(task["id"]+"-unchanged"),args.clang)
        rows.append({"task":task["id"],"kind":"unchanged","passed":unchanged["status"]=="candidate_rejected"})
        leaked = base.target(task);leaked["functions"][0]["blocks"][0]["ops"].pop()
        rejected = evaluate(task,"hia_full",leaked,output/(task["id"]+"-missing-release"),args.clang)
        rows.append({"task":task["id"],"kind":"missing-release","passed":rejected["status"]=="candidate_rejected"})
        stale = base.reference(task,"hia_structured");stale["expected_sha256"]="1"*64
        rejected = evaluate(task,"hia_structured",stale,output/(task["id"]+"-stale-snapshot"),args.clang)
        rows.append({"task":task["id"],"kind":"stale-snapshot","passed":rejected["status"]=="candidate_rejected"})
    result = {"schema":"hepta.hia.agent-repository-maintenance.controls.v2",
        "source_commit":base.git_head(),"bindings":frozen,"protocol_sha256":file_identity(PROTOCOL)["sha256"],
        "rows":rows,"clang":file_identity(args.clang),"prompt_bindings":{
            t["id"]+"/"+a:hashlib.sha256(base.prompt(t,a).encode()).hexdigest()
            for t in base.cfg()["tasks"] for a in base.cfg()["arms"]},
        "models":[m["id"] for m in configuration["models"]],"model_requests":0,
        "reference_controls_are_model_successes":False,
        "passed":all(r["passed"] for r in rows) and frozen==bindings(),"wall_ns":time.monotonic_ns()-entered}
    base.save(output/"CONTROLS-v2.json",result)
    print(json.dumps({"passed":result["passed"],"controls":str(output/"CONTROLS-v2.json")}))
    return 0 if result["passed"] else 1


def evaluate(task,arm,raw,directory,clang):
    """The inherited oracle with infrastructure failures kept out of feedback.

    Admission/type/resource errors and actual public mismatches are candidate
    failures. After a verified program passes its interpreter oracle, compiler
    or linker failures are infrastructure; they never buy a repair attempt.
    """
    entered = time.monotonic_ns();directory.mkdir(parents=True,exist_ok=False)
    row = {"accepted":False,"hidden_evaluated":False,"status":"starting","commands":[]}
    stage = "admission"
    try:
        verified,receipt = base.admit(task,arm,raw)
        base.save(directory/"candidate.json",verified.as_dict())
        row.update(candidate=file_identity(directory/"candidate.json"),patch_receipt=receipt)
        stage = "interpreter"
        observed = []
        for args in base.cfg()["public_cases"]:
            value = base.execute_program(verified,task["function"],args,max_steps=10000,max_heap_bytes=65536)
            resources = value["resources"]
            if (value["result"]!=base.oracle(task,args) or resources["live_owners"] or resources["live_local_loans"]
                    or resources["allocations"]!=task["owners"] or resources["frees"]!=task["owners"]):
                raise ValueError("public interpreter result or owner/loan cleanup mismatch")
            observed.append(value)
        row["interpreter_public"] = observed
        stage = "compiler"
        row["native_compilation"] = base.build_program_native(verified,directory/"candidate.o",clang=clang,kind="object")
        stage = "linker"
        metrics = ROOT/"benchmarks/hia_native_ndu"
        argv = [clang,"-O2","-I",metrics,"-DTARGET="+task["function"],base.HERE/"driver.c",directory/"candidate.o",
                metrics/"metrics.c",*["-Wl,--wrap="+name for name in ("malloc","calloc","realloc","free")],
                "-o",directory/"candidate"]
        row["linker_argv"] = [str(v) for v in argv]
        row["commands"].append(base.command(argv,directory,0))
        row["binary"] = file_identity(directory/"candidate")
        stage = "native_execution"
        row["public_native"] = base.execute_native(task,row["binary"],base.cfg()["public_cases"],False)
        if any(r.get("status")=="native_timeout" for r in row["public_native"]["cases"]):
            raise RuntimeError("native evaluation timeout; no candidate feedback")
        if row["public_native"]["passed"]:
            row.update(accepted=True,status="public_accepted")
        else:
            row.update(status="candidate_rejected",error={"type":"PublicMismatch","message":"public native result or lifecycle mismatch"})
    except Exception as error:
        candidate_error = ((stage=="admission" and isinstance(error,ValueError)) or
                           (stage=="interpreter" and isinstance(error,(ValueError,HIAProgramTrap,HIAProgramBudgetExceeded))))
        row.update(status="candidate_rejected" if candidate_error else "infrastructure_failure",
                   failure_stage=stage,error={"type":type(error).__name__,"message":str(error)[:1800]})
    row["wall_ns"] = time.monotonic_ns()-entered
    base.save(directory/"PUBLIC.json",row)
    return row


def evaluate_hidden(task,build,directory):
    result = base.hidden(task,build,directory)
    if any(r.get("status")=="native_timeout" for part in ("normal","refused") for r in result[part]["cases"]):
        raise RuntimeError("hidden native timeout; infrastructure outcome, no model feedback")
    return result


def codex_generate(messages,folder,configuration,cli_identity):
    folder.mkdir(parents=True,exist_ok=False)
    (folder/"cwd").mkdir();(folder/"state").mkdir();(folder/"logs").mkdir()
    text = ("Complete this frozen coding task using only the complete public conversation below. "
        "Return exactly one JSON candidate in the requested representation, no Markdown or explanation. "
        "Do not call tools, execute commands, inspect files or repositories, browse, or obtain reference answers. "
        "The host independently checks the response and appends actual public feedback. Existing user rules remain effective.\n"
        + canonical(messages).decode()+"\nReturn only the candidate JSON object.\n")
    cfg = configuration["codex"]
    if file_identity(cfg["binary"])!=cli_identity:
        raise RuntimeError("Codex CLI changed before request")
    events = CohortEvents(cfg["registered_startup_warnings"])
    command = [cfg["binary"],"exec","--json","--ephemeral","--sandbox","read-only","--skip-git-repo-check",
        "-c","sqlite_home="+json.dumps(str(folder/"state")),"-c","log_dir="+json.dumps(str(folder/"logs")),
        "-c","model_reasoning_effort="+json.dumps(cfg["reasoning_effort"]),"-m","gpt-6.1-sol","-"]
    process = run_owned(command,folder/"cwd",folder/"transport",input_bytes=text.encode(),
        wall_seconds=configuration["generation"]["wall_seconds_per_attempt"],on_line=events.line)
    observed = recover_reported_usage(folder/"transport/stdout.raw") or events.usage
    result = {"provider":"codex_cli","process":process,"usage":observed,
              "generation_requested":events.turn_count>0,"status":"incomplete","text":None,
              "reasoning_item_count":len(events.reasoning_items)}
    result["cli_identity_after"] = file_identity(cfg["binary"])
    if result["cli_identity_after"]!=cli_identity:
        result["status"]="identity_failure"
    elif not process["cleanup_confirmed"]:
        result["status"]="cleanup_uncertain"
    elif any(e.get("type")=="turn.failed" and "usage limit" in e.get("error",{}).get("message","").lower()
             for e in events.events):
        result["status"]="provider_unavailable"
    elif process["status"]=="exited":
        try:
            answer = events.complete()
            if observed!=answer["usage"]:
                raise EventFailure("inconsistent actual usage")
            result["text"] = answer["text"]
            result["status"] = ("over_budget" if observed["output_tokens"]+observed["reasoning_output_tokens"]>
                cfg["max_reported_output_plus_reasoning_tokens"] or observed["input_tokens"]>
                cfg["max_reported_input_tokens_per_request"] else "completed")
        except EventFailure as error:
            result["error"]=str(error)
    base.save(folder/"GENERATION.json",result)
    return result


def usage_total(usage,provider):
    if usage is None:
        return None
    return (usage["input_tokens"]+usage["output_tokens"]
            if provider=="codex_cli" else usage["total_tokens"])


def summarize_model(model,result,control_cost,download_cost,*,campaign_share=0,probe=None,campaign_valid=True):
    summaries = {}
    all_cell_wall = sum(c["wall_ns"] for c in result["cells"])
    shared = result["wall_ns"]-all_cell_wall
    if shared<0:
        raise ValueError("model accounting overlaps cell wall")
    for arm_index,arm in enumerate(base.cfg()["arms"]):
        cells = [c for c in result["cells"] if c["arm"]==arm]
        attempts = [a for c in cells for a in c["attempts"]]
        known = [a for a in attempts if a.get("usage") is not None]
        success = sum(c["correct"] for c in cells)
        complete = (campaign_valid and result["status"]=="completed" and len(cells)==2 and len(known)==len(attempts)
                    and all(c["status"] in {"correct","hidden_failed","public_failed","over_budget"} for c in cells))
        total = sum(usage_total(a["usage"],model["provider"]) for a in known)
        shared_arm = shared//2+(shared%2 if arm_index==0 else 0)
        campaign_arm = campaign_share//2+(campaign_share%2 if arm_index==0 else 0)
        probe_wall = probe["probe_wall_ns"] if probe else 0
        wall = sum(c["wall_ns"] for c in cells)+shared_arm+control_cost+download_cost+campaign_arm+probe_wall
        summaries[arm] = {"planned_tasks":2,"attempted_tasks":len(cells),"successes":success,
            "tasks_with_generation_request":sum(any(a["generation_requested"] for a in c["attempts"]) for c in cells),
            "attempts":len(attempts),"automatic_retries":sum(max(0,len(c["attempts"])-1) for c in cells),
            "input_tokens":sum(a["usage"]["input_tokens"] for a in known),
            "output_tokens":sum(a["usage"]["output_tokens"] for a in known),
            "cached_input_tokens":sum(a["usage"]["cached_input_tokens"] for a in known) if model["provider"]=="codex_cli" else None,
            "cache_write_input_tokens":sum(a["usage"]["cache_write_input_tokens"] for a in known) if model["provider"]=="codex_cli" else None,
            "reasoning_output_tokens":sum(a["usage"]["reasoning_output_tokens"] for a in known) if model["provider"]=="codex_cli" else None,
            "reasoning_tokens_are_output_detail_not_added_to_total":model["provider"]=="codex_cli",
            "known_total_reported_tokens":total,"unknown_usage_attempts":len(attempts)-len(known),
            "complete_coverage_and_usage":complete,"campaign_valid":campaign_valid,
            "tokens_per_success":total/success if success and complete else None,
            "allocated_execution_and_acquisition_ns":wall,"runtime_ns_per_success":wall/success if success and complete else None,
            "allocated_noncell_runtime_ns":shared_arm,"allocated_campaign_admission_ns":campaign_arm,
            "availability_probe_wall_ns":probe_wall,"availability_probe_usage":probe["probe_usage"] if probe else None,
            "generation_ns":sum(a.get("generation_wall_ns",0) for a in attempts),
            "public_validation_ns":sum(a.get("public_validation_ns",0) for a in attempts),
            "hidden_validation_ns":sum(a.get("hidden_validation_ns",0) for a in attempts),
            "cross_provider_token_cost_comparable":False}
    return {"arms":summaries,"shared_noncell_wall_ns":shared,
            "per_arm_controls_wall_ns":control_cost,"per_arm_model_acquisition_wall_ns":download_cost,
            "campaign_admission_share_ns":campaign_share,
            "acquisition_cost_is_per_arm_standalone_allocation_not_campaign_elapsed":True}


def run_model(args,model,configuration,control,assets,frozen,root,provider_probe):
    root.mkdir(parents=True,exist_ok=False)
    started = time.monotonic_ns()
    result = {"model":model,"cells":[],"engines":[],"status":"running","human_answer_repairs":0}
    engine = None

    def close_engine():
        nonlocal engine
        if engine is None:
            return
        current,engine = engine,None
        record = {"output":str(current.output)}
        result["engines"].append(record)
        try:
            record["identity_after"] = current.verify_final_identity()
        finally:
            try:
                current.close()
            finally:
                if (current.output/"lifecycle.json").is_file():
                    record["lifecycle"] = strict_json((current.output/"lifecycle.json").read_bytes())
        if not record["lifecycle"]["reaped"]:
            raise RuntimeError("model process cleanup uncertain")
        if not all(record["identity_after"][k] for k in ("model_unchanged","runtime_unchanged")):
            raise RuntimeError("model/runtime identity drift")

    try:
        stop_provider = False
        for index,task in enumerate(base.cfg()["tasks"]):
            arms = base.cfg()["arms"][index%2:]+base.cfg()["arms"][:index%2]
            for arm in arms:
                if stop_provider:
                    break
                # Startup, final hashes and shutdown are outside cell clocks.
                # All lifecycle costs (including restarts) are retained in the
                # model's measured noncell wall and shared equally by rule.
                if model["provider"]=="local_gguf" and engine is None:
                    binary = Path(assets["runtime"]["binary"])
                    observed_runtime = [file_identity(p) for p in sorted({binary,*binary.parent.glob("*.so*")})]
                    if observed_runtime!=assets["runtime"]["identity"]:
                        raise RuntimeError("local runtime changed since pinned archive admission")
                    engine = LlamaCppEngine(binary=assets["runtime"]["binary"],model=assets[model["id"]]["path"],
                        model_sha256=model["sha256"],output_dir=root/("engine-"+str(len(result["engines"]))),
                        threads=configuration["generation"]["threads"],context=8192,json_object=True)
                    if engine.runtime_identity!=assets["runtime"]["identity"]:
                        raise RuntimeError("local runtime changed between admission and engine startup")
                cell_started = time.monotonic_ns()
                folder = root/(task["id"]+"-"+arm);folder.mkdir()
                cell = {"task":task["id"],"arm":arm,"attempts":[],"correct":False,"status":"incomplete"}
                result["cells"].append(cell)
                try:
                    text = base.prompt(task,arm)
                    if hashlib.sha256(text.encode()).hexdigest()!=control["prompt_bindings"][task["id"]+"/"+arm]:
                        raise RuntimeError("prompt differs from registered controls")
                    messages = [{"role":"user","content":text}]
                    for number in range(configuration["generation"]["attempts_per_cell"]):
                        if frozen!=bindings():
                            raise RuntimeError("source drift after freeze")
                        attempt = {"index":number,"usage":None,"generation_requested":False}
                        cell["attempts"].append(attempt)
                        base.save(folder/f"attempt-{number}.request.json",{"messages":messages})
                        began = time.monotonic_ns()
                        if model["provider"]=="codex_cli":
                            answer = codex_generate(messages,folder/f"provider-{number}",configuration,provider_probe["cli_identity"])
                            attempt.update(usage=answer["usage"],generation_requested=answer["generation_requested"],
                                           status=answer["status"],provider_process=answer["process"])
                        else:
                            before = engine.generation_count
                            try:
                                answer = engine.generate(messages,limit=configuration["generation"]["max_output_tokens"],
                                    wall_seconds=configuration["generation"]["wall_seconds_per_attempt"])
                                attempt.update(usage=answer["usage"],status="completed",generation_requested=engine.generation_count>before)
                            except Exception as error:
                                attempt.update(status="incomplete",generation_requested=engine.generation_count>before,
                                    error={"type":type(error).__name__,"message":str(error)})
                                receipt = engine.output/("attempt-"+str(engine.attempt_count).zfill(3)+".json")
                                if receipt.is_file():
                                    attempt["partial_receipt"] = strict_json(receipt.read_bytes())
                                    attempt["usage"] = attempt["partial_receipt"].get("usage")
                                answer = {"status":"incomplete"}
                        attempt["generation_wall_ns"] = time.monotonic_ns()-began
                        base.save(folder/f"attempt-{number}.response.json",answer)
                        if attempt["status"]!="completed":
                            cell["status"] = attempt["status"]
                            base.save(folder/f"attempt-{number}.record.json",attempt)
                            if cell["status"] in {"cleanup_uncertain","identity_failure"}:
                                raise RuntimeError("provider process cleanup or identity uncertain")
                            if cell["status"]=="provider_unavailable":
                                stop_provider = True
                            break
                        build = evaluate(task,arm,answer["text"],folder/f"candidate-{number}",args.clang)
                        attempt["public_validation_ns"] = build["wall_ns"]
                        attempt["status"] = build["status"]
                        if build["status"]=="infrastructure_failure":
                            cell["status"]="infrastructure_failure"
                            base.save(folder/f"attempt-{number}.record.json",attempt)
                            raise RuntimeError("public evaluation infrastructure failed; no candidate feedback")
                        if build["accepted"]:
                            terminal = evaluate_hidden(task,build,folder/f"candidate-{number}")
                            attempt["hidden_validation_ns"] = terminal["wall_ns"]
                            cell.update(correct=terminal["passed"],status="correct" if terminal["passed"] else "hidden_failed")
                            base.save(folder/f"attempt-{number}.record.json",attempt)
                            break
                        cell["status"]="public_failed"
                        base.save(folder/f"attempt-{number}.record.json",attempt)
                        if number+1<configuration["generation"]["attempts_per_cell"]:
                            messages += [{"role":"assistant","content":answer["text"]},{"role":"user","content":json.dumps({
                                "status":build["status"],"error":build.get("error"),
                                "instruction":"Return a corrected artifact in the original response format. No Markdown."})}]
                finally:
                    cell["wall_ns"] = time.monotonic_ns()-cell_started
                    base.save(folder/"CELL.json",cell)
                    base.save(root/("CHECKPOINT-"+str(len(result["cells"]))+".json"),result)
                if cell["status"]=="incomplete":
                    close_engine()
            if stop_provider:
                break
        result["status"] = "completed" if len(result["cells"])==4 else "provider_unavailable"
    except Exception as error:
        result.update(status="infrastructure_failure",error={"type":type(error).__name__,"message":str(error)})
    finally:
        try:
            close_engine()
        except Exception as error:
            result.update(status="cleanup_or_identity_failure",cleanup_error={"type":type(error).__name__,"message":str(error)})
        result["wall_ns"] = time.monotonic_ns()-started
        cost = assets[model["id"]]["download_wall_ns"]+assets["runtime"]["download_wall_ns"] if model["provider"]=="local_gguf" else 0
        result["summary"] = summarize_model(model,result,control["wall_ns"],cost)
        result["accounting_stage"]="provisional_before_campaign_admission_and_probe_allocation"
        base.save(root/"REPORT.json",result)
    return result


def run(args):
    root = Path(args.output).resolve();root.mkdir(parents=True,exist_ok=False)
    entered = time.monotonic_ns();configuration = protocol();frozen = bindings()
    report = {"schema":"hepta.hia.agent-repository-maintenance.result.v2","status":"incomplete",
              "source_commit":base.git_head(),"bindings":frozen,"protocol":configuration,"models":[]}
    try:
        control = strict_json(Path(args.controls).read_bytes())
        if (control["schema"]!="hepta.hia.agent-repository-maintenance.controls.v2" or not control["passed"]
                or control["bindings"]!=frozen or control["source_commit"]!=base.git_head()
                or control["clang"]!=file_identity(args.clang) or base.git_head()!=args.expected_head):
            raise ValueError("fresh committed source/tool-matching v2 controls required")
        base.require_committed_bindings(frozen)
        if os.environ.get("LLAMA_ARG_REPACK")!="0":
            raise ValueError("registered LLAMA_ARG_REPACK=0 required")
        report["availability"] = availability(args.availability,configuration)
        assets = admitted_assets(args,configuration)
        report["assets"] = assets
        report["controls"] = file_identity(args.controls)
        report["preflight_wall_ns"] = time.monotonic_ns()-entered
        base.save(root/"PLAN.json",{**report,"model_task_requests_before_plan":0})
        for model in configuration["models"]:
            result = run_model(args,model,configuration,control,assets,frozen,root/model["id"],report["availability"])
            report["models"].append(result)
            print(json.dumps({"model":model["id"],"status":result["status"],"summary":result["summary"]}),flush=True)
            if result["status"] in {"cleanup_or_identity_failure","infrastructure_failure"}:
                raise RuntimeError("model engine/source infrastructure failed; study stopped")
        report["status"]="completed"
    except Exception as error:
        report["error"] = {"type":type(error).__name__,"message":str(error)}
    finally:
        report["source_stable"] = frozen==bindings()
        report["clang_stable"] = file_identity(args.clang)==control["clang"] if "control" in locals() else False
        report["wall_ns"] = time.monotonic_ns()-entered
        model_wall = sum(m["wall_ns"] for m in report["models"])
        report["nonmodel_campaign_wall_ns"] = report["wall_ns"]-model_wall
        campaign_valid = report["status"]=="completed" and report["source_stable"] and report["clang_stable"]
        allocated_campaign = 0
        if report["models"]:
            count = len(configuration["models"])
            for index,result in enumerate(report["models"]):
                model = result["model"]
                acquisition = (assets[model["id"]]["download_wall_ns"]+assets["runtime"]["download_wall_ns"]
                               if model["provider"]=="local_gguf" else 0)
                share = report["nonmodel_campaign_wall_ns"]//count
                share += report["nonmodel_campaign_wall_ns"]%count if index==0 else 0
                allocated_campaign += share
                result["summary"] = summarize_model(model,result,control["wall_ns"],acquisition,
                    campaign_share=share,probe=report["availability"] if model["provider"]=="codex_cli" else None,
                    campaign_valid=campaign_valid)
                result["accounting_stage"]="final_including_campaign_admission_and_probe_allocation"
                base.save(root/model["id"]/"FINAL-ACCOUNTING.json",result["summary"])
        report["retained_unallocated_campaign_ns"] = report["nonmodel_campaign_wall_ns"]-allocated_campaign
        report["claims"] = {"all_three_models_requested":len(report["models"])==3 and all(
                any(a["generation_requested"] for c in m["cells"] for a in c["attempts"]) for m in report["models"]),
            "complete_coverage_and_usage":campaign_valid and len(report["models"])==3 and all(
                s["complete_coverage_and_usage"] for m in report["models"] for s in m["summary"]["arms"].values()),
            "real_historical_maintenance_measured":False,"general_agent_productivity_established":False,
            "population_superiority_established":False,"cross_provider_token_cost_comparable":False}
        report["cost_scope"] = "All measured task usage (including API cache/reasoning), cell runtime, model lifecycle and campaign admission/aggregation wall are retained. Noncell model wall is split equally across arms; campaign admission wall is split across the three planned models then arms. Each arm is additionally charged one full native control campaign and its model/runtime download service wall; Codex arms additionally retain the full current availability probe wall and usage. These are standalone-arm acquisition allocations, not a sum claiming elapsed campaign time; downloads overlapped. Task token-per-success excludes the separately itemized availability probe. Final record serialization and invoking interpreter startup require the external process receipt. No monetary conversion, human-labor or training-cost claim."
        base.save(root/"REPORT.json",report)
    print(json.dumps({"status":report["status"],"report":str(root/"REPORT.json"),"claims":report["claims"]}))
    return 0 if campaign_valid else 1


def main():
    p = argparse.ArgumentParser()
    p.add_argument("stage",choices=("controls","run"))
    p.add_argument("--output",required=True);p.add_argument("--clang",required=True)
    for name in ("controls","assets","downloads","availability","expected-head"):
        p.add_argument("--"+name)
    args = p.parse_args()
    if args.stage=="run" and any(getattr(args,key) is None for key in ("controls","assets","downloads","availability","expected_head")):
        p.error("run requires controls, assets, downloads, availability and expected-head")
    raise SystemExit(controls(args) if args.stage=="controls" else run(args))


if __name__=="__main__":
    main()
