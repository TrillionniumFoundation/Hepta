#!/usr/bin/env python3
"""Read-only reconstruction of v3 results from retained requests and executions.

This program performs no inference, candidate mutation, compilation or native
execution. Its own source is outside the frozen evaluator directory. Missing
usage remains unknown; failed attempts and timeout cells remain in denominators.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import time

ROOT=Path(__file__).resolve().parents[2]
STUDY=ROOT/"experiments/hia_agent_matched_v3_20261028"


def read(path):
    return json.loads(Path(path).read_bytes())


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode()


def identity(path):
    path=Path(path)
    with path.open("rb") as stream:
        return {"bytes":path.stat().st_size,"sha256":hashlib.file_digest(stream,"sha256").hexdigest()}


def demand(condition,message):
    if not condition:
        raise ValueError(message)


def provider_expected(task,case):
    a,b,_=case
    if task=="carry_sum_tag":return [a+b]
    if task=="absolute_gap_bias":return [abs(a-b)]
    if task=="wide_product_tag":return [a*b]
    if task=="rounded_tiles_v2":return [int(b!=0),(a+b-1)//b if b else 0]
    raise ValueError("unregistered task")


def execution_correct(observation,task,split,artifact_sha256):
    if observation is None:
        return False
    if observation.get("status")=="observable_timeout":
        demand(observation.get("artifact_unchanged") is True,"timed-out native artifact changed")
        return False
    demand(observation.get("artifact_sha256")==artifact_sha256,"native observation is not bound to this attempt's compiled artifact")
    cases,expected=task[split+"_cases"],task[split+"_expected"]
    demand(observation["cases"]==cases and observation["expected"]==expected,"native observation split differs from fixed fixture")
    wanted=[provider_expected(task["id"],case) for case in cases]
    if observation.get("provider_expected") is not None:
        demand(observation["provider_expected"]==wanted,"provider oracle differs")
    correct=bool(observation.get("returncode")==0 and observation.get("actual")==expected
        and observation.get("artifact_unchanged") is True and observation.get("sealed_image") is True
        and observation.get("provider_actual")==wanted
        and observation.get("provider_call_counts")==[1]*len(cases)
        and observation.get("provider_argument_matches")==[1]*len(cases)
        and observation.get("native_vm_agreement") is True)
    demand((observation["status"]=="correct")==correct,"recorded native success differs from independent field check")
    return correct


def build(suite,output):
    started=time.monotonic_ns();suite=Path(suite).resolve(strict=True);output=Path(output).absolute()
    output.mkdir(parents=True,exist_ok=False)
    protocol=read(STUDY/"PROTOCOL.json");registration=read(STUDY/"REGISTRATION.json")
    fixture_list=read(STUDY/"FIXTURES.json")
    demand(identity(STUDY/"PROTOCOL.json")["sha256"]==registration["protocol_sha256"],"current protocol bytes differ from registration")
    demand(identity(STUDY/"FIXTURES.json")["sha256"]==registration["fixtures_sha256"] and hashlib.sha256(canonical(fixture_list)).hexdigest()==registration["fixtures_canonical_sha256"],"current fixture bytes differ from registration")
    fixtures={t["id"]:t for t in fixture_list};plan=read(suite/"SUITE_PLAN.json")
    demand(plan["protocol"]==protocol and plan["registration_sha256"]==identity(STUDY/"REGISTRATION.json")["sha256"],"suite protocol/registration drift")
    demand(plan["sources"]==registration["sources"],"suite source binding drift")
    for name,wanted in registration["sources"].items():
        demand(identity(ROOT/name)["sha256"]==wanted,"current evaluator source differs: "+name)
    files={};families=[];all_attempts=[]

    def bind(path):
        path=Path(path);files[str(path.relative_to(suite))]=identity(path)

    bind(suite/"SUITE_PLAN.json")
    for model_index,model in enumerate(protocol["models"]):
        folder=suite/model["id"];model_plan=read(folder/"PLAN.json");result=read(folder/"MODEL_RESULT.json")
        bind(folder/"PLAN.json");bind(folder/"MODEL_RESULT.json")
        demand(model_plan["model"]==model and result["model"]==model,"model identity differs")
        demand(model_plan["protocol"]==protocol and model_plan["sources"]==registration["sources"],"model plan differs")
        demand(model_plan["tools"]==plan["tools"] and model_plan["runtime_files"]==plan["runtime_files"],"matched tools differ")
        expected_order=[]
        for i,task_id in enumerate(protocol["tasks"]):
            for language in (("hia","rust") if (i+model_index)%2==0 else ("rust","hia")):
                expected_order.append(task_id+"_"+language)
        demand([c["id"] for c in model_plan["scheduled_cells"]]==expected_order,"planned order differs")
        for descriptor in model_plan["scheduled_cells"]:
            task_id=descriptor["task"];language=descriptor["language"]
            demand(task_id in protocol["tasks"] and language in protocol["languages"] and descriptor=={
                "id":task_id+"_"+language,"task":task_id,"language":language,"stratum":fixtures[task_id]["stratum"]},"scheduled descriptor differs from registered task")
        demand([c["id"] for c in result["cells"]]==expected_order[:len(result["cells"])],"actual cells are not ordered unique prefix")
        recorded_folder=Path(result["engines"][0]["path"]).parent if result["engines"] else folder

        def local_path(recorded):
            # Archives retain original absolute paths verbatim. Rebase only
            # paths below this exact recorded model root, without editing the
            # retained JSON, so audit can run after extraction elsewhere.
            value=Path(recorded)
            demand(value.is_absolute() and ".." not in value.parts and value.is_relative_to(recorded_folder),"foreign recorded evidence path")
            return folder/value.relative_to(recorded_folder)

        transports=[];matched=set();engine_requests=0;engine_responses=0
        for engine in result["engines"]:
            engine_path=local_path(engine["path"])
            demand(engine_path.parent==folder,"foreign engine path")
            for name in ("identity.json","identity-after.json","RUNTIME_CONDITION.json","STARTUP.json","server.log"):
                bind(engine_path/name)
            before=read(engine_path/"identity.json");after=read(engine_path/"identity-after.json")
            condition=read(engine_path/"RUNTIME_CONDITION.json")
            demand(before["model"]["sha256"]==model["sha256"] and before["model"]["bytes"]==model["bytes"],"owned model differs")
            demand(after["model_unchanged"] and after["runtime_unchanged"] and condition["matches"],"owned runtime identity failed")
            paths=sorted(engine_path.glob("transport-*.request.json"))
            raw_responses=sorted(engine_path.glob("transport-*.response.raw"))
            demand(len(paths)==engine["started_requests"] and len(raw_responses)==engine["responses_received"],"transport counts differ")
            engine_requests+=len(paths);engine_responses+=len(raw_responses)
            for path in paths:
                bind(path);transports.append((path,read(path)))
        derived_cells=[]
        for cell,descriptor in zip(result["cells"],model_plan["scheduled_cells"]):
            demand({key:cell[key] for key in ("id","task","stratum","language")}==descriptor,"cell descriptor differs from its scheduled task")
            task=fixtures[cell["task"]];cell_path=folder/cell["id"]
            bind(cell_path/"CELL.json");demand(read(cell_path/"CELL.json")==cell,"cell aggregate differs from raw CELL")
            bind(cell_path/"BOUNDARY_IDENTITIES.json")
            boundary=read(cell_path/"BOUNDARY_IDENTITIES.json")
            demand(boundary["passed"],"cell boundary identity failed")
            derived=[];public_pass=False;terminal_artifact_sha256=None
            for index,attempt in enumerate(cell["attempts"]):
                demand(index==attempt["index"],"attempt numbering differs")
                request_path=cell_path/f"attempt-{index}.request.json";evaluation_path=cell_path/f"attempt-{index}.evaluation.json"
                bind(request_path);bind(evaluation_path)
                request=read(request_path);demand(read(evaluation_path)==attempt,"attempt summary differs from raw evaluation")
                demand(request["maximum_output_tokens"]==protocol["max_output_tokens"] and request["wall_seconds"]==protocol["request_wall_seconds"],"request budget differs")
                candidates=[(path,value) for path,value in transports if value["messages"]==request["messages"]]
                count=attempt["completion_requests_started"]
                demand(count in (0,1),"unexpected multiple completion requests per attempt")
                if count:
                    demand(len(candidates)==1,"attempt not uniquely bound to owned transport")
                    transport_path,transport=candidates[0]
                    demand(str(transport_path) not in matched,"transport reused by multiple attempts")
                    matched.add(str(transport_path));payload=transport["payload"]
                    demand(payload["json_schema"]==request["response_schema"] and payload["n_predict"]==protocol["max_output_tokens"],"decoder envelope/budget differs")
                    demand(payload["temperature"]==0 and payload["seed"]==0 and payload["cache_prompt"] is False,"generation settings differ")
                    input_tokens=len(payload["prompt"])
                else:
                    transport_path=None;input_tokens=None
                if attempt["usage_complete"]:
                    response_path=cell_path/f"attempt-{index}.response.json";bind(response_path);response=read(response_path)
                    raw_path=transport_path.with_name(transport_path.name.replace(".request.json",".response.raw"))
                    structured_path=transport_path.with_name(transport_path.name.replace(".request.json",".response.json"))
                    bind(raw_path);bind(structured_path);raw=read(raw_path)
                    demand(raw==read(structured_path)==response["response"],"completion raw/parsed/retained response differs")
                    demand(response["request"]==payload and response["text"]==raw["content"],"response/payload differs")
                    predicted=raw["timings"]["predicted_n"];returned=len(raw["tokens"])
                    demand(raw["tokens_evaluated"]==input_tokens and returned<=predicted<=returned+1 and 0<predicted<=protocol["max_output_tokens"],"token arithmetic differs")
                    demand(response["input_token_ids"]==payload["prompt"] and response["output_token_ids"]==raw["tokens"],"token IDs differ")
                    usage={"input_tokens":input_tokens,"output_tokens":predicted,"returned_token_ids":returned,"total_tokens":input_tokens+predicted}
                    demand(response["usage"]==usage==attempt["usage"],"validated usage differs")
                    output_tokens=predicted
                else:
                    output_tokens=None
                    if count:
                        demand(attempt["known_input_tokens"]==input_tokens,"known timeout input count differs")
                built=attempt.get("build")
                if built is not None:
                    candidate=local_path(built["folder"]);bind(candidate/"BUILD.json")
                    demand(read(candidate/"BUILD.json")==built,"build summary differs from original")
                    demand(built["task_id"]==cell["task"] and built["language"]==cell["language"],"build task descriptor differs")
                    for candidate_file in sorted(candidate.iterdir()):
                        demand(candidate_file.is_file() and not candidate_file.is_symlink(),"unexpected candidate evidence entry")
                        bind(candidate_file)
                    if built.get("compile") is not None or built.get("core_path") is not None:
                        submitted=read(cell_path/f"attempt-{index}.response.json")
                        supplied_files=json.loads(submitted["text"])["files"]
                        if cell["language"]=="rust":
                            for name in ("api.rs","client.rs"):
                                demand((candidate/name).read_text()==supplied_files[name],"compiled Rust source differs from submitted bytes")
                        else:
                            core=local_path(built["core_path"])
                            demand(identity(core)["sha256"]==built["core_sha256"],"candidate Core hash differs from BUILD")
                            functions={f["name"]:f for f in read(core)["functions"]}
                            demand(functions=={task["provider"]:supplied_files["api.hia.json"],"entrypoint":supplied_files["client.hia.json"]},"candidate Core functions differ from submission")
                            receipt=built.get("native_receipt")
                            if receipt is not None:
                                demand(receipt["core_sha256"]==receipt["input_sha256"]==built["core_sha256"],"native object and Core identity differ")
                                obj=local_path(receipt["output"])
                                demand(identity(obj)=={"bytes":receipt["artifact_bytes"],"sha256":receipt["artifact_sha256"]},"native object hash differs")
                    if built["native_built"]:
                        artifact=local_path(built["artifact"]["path"]);bind(artifact)
                        demand(identity(artifact)=={k:built["artifact"][k] for k in ("bytes","sha256")},"candidate binary identity differs")
                        terminal_artifact_sha256=built["artifact"]["sha256"]
                    if attempt.get("public_validation") is not None:
                        demand(built["native_built"],"native validation without a compiled artifact")
                        public_pass=execution_correct(attempt["public_validation"],task,"public",built["artifact"]["sha256"])
                        demand((attempt["status"]=="public_passed")==public_pass,"public pass status differs")
                derived.append({"index":index,"status":attempt["status"],"input_tokens":input_tokens,"output_tokens":output_tokens,
                    "request_wall_ns":attempt["request_wall_ns"],"inference_ns":attempt.get("inference_ns"),"evaluation_ns":attempt.get("evaluation_ns",0)})
            demand(len(derived)<=protocol["attempts_per_cell"] and len(derived)>=1,"attempt budget differs")
            correct=False
            if cell["hidden_tests_evaluated"]:
                demand(public_pass,"hidden tests ran without public pass")
                correct=execution_correct(cell["hidden_validation"],task,"hidden",terminal_artifact_sha256)
            demand(correct==cell["correct"],"task score differs")
            # Hidden cases never appear in a later request: public-pass is terminal.
            demand(not any(a["status"]=="public_passed" for a in cell["attempts"][:-1]),"request after public pass")
            demand(cell["automatic_repair_rounds"]==len(derived)-1,"repair count differs")
            complete=all(a["input_tokens"] is not None and a["output_tokens"] is not None for a in derived)
            known_in=sum(a["input_tokens"] or 0 for a in derived);known_out=sum(a["output_tokens"] or 0 for a in derived)
            demand(cell["known_input_tokens"]==known_in and cell["known_output_tokens"]==known_out and cell["usage_complete"]==complete,"cell token aggregation differs")
            value={"id":cell["id"],"task":cell["task"],"stratum":cell["stratum"],"language":cell["language"],
                "correct":correct,"status":cell["status"],"attempts":derived,"usage_complete":complete,
                "known_input_tokens":known_in,"known_output_tokens":known_out,"input_tokens":known_in if all(a["input_tokens"] is not None for a in derived) else None,
                "output_tokens":known_out if complete else None,"total_tokens":known_in+known_out if complete else None,
                "cell_wall_ns":cell["cell_wall_ns"],"boundary_identity_ns":boundary["wall_ns"],"automatic_repairs":cell["automatic_repair_rounds"],
                "evaluation_ns":sum(a["evaluation_ns"] for a in derived)+cell.get("hidden_validation_ns",0)}
            derived_cells.append(value);all_attempts.extend({"model":model["id"],"cell":cell["id"],**a} for a in derived)
        demand(len(matched)==engine_requests==result["new_requests"] and engine_responses==result["responses_received"],"unattributed transport or incorrect model counts")
        for name in ("sources_unchanged","tools_unchanged","model_unchanged"):
            demand(result[name],"final model boundary failed: "+name)
        groups={}
        for stratum in ("maintenance","upgrade"):
            for language in ("hia","rust"):
                rows=[r for r in derived_cells if r["stratum"]==stratum and r["language"]==language]
                attempts=[a for r in rows for a in r["attempts"]];usage=len(rows)==2 and all(r["usage_complete"] for r in rows)
                known_in=sum(r["known_input_tokens"] for r in rows);known_out=sum(r["known_output_tokens"] for r in rows)
                groups[stratum+":"+language]={"planned":2,"attempted":len(rows),"successes":sum(r["correct"] for r in rows),
                    "submissions":len(attempts),"failed_submissions":sum(a["status"]!="public_passed" for a in attempts)+sum(r["status"]=="hidden_validation_failed" for r in rows),
                    "known_input_tokens":known_in,"known_output_tokens":known_out,"input_tokens":known_in if len(rows)==2 and all(r["input_tokens"] is not None for r in rows) else None,
                    "output_tokens":known_out if usage else None,"total_tokens":known_in+known_out if usage else None,"usage_complete":usage,
                    "automatic_repairs":sum(r["automatic_repairs"] for r in rows),"human_repairs":0,"manual_time_ns":None,
                    "request_wall_ns":sum(a["request_wall_ns"] for a in attempts),"inference_ns":sum(a["inference_ns"] for a in attempts) if len(rows)==2 and all(a["inference_ns"] is not None for a in attempts) else None,
                    "evaluation_ns":sum(r["evaluation_ns"] for r in rows),"boundary_identity_ns":sum(r["boundary_identity_ns"] for r in rows),
                    "validation_total_ns":sum(r["evaluation_ns"]+r["boundary_identity_ns"] for r in rows),"cell_wall_ns":sum(r["cell_wall_ns"] for r in rows)}
                old=result["summary"]["groups"][stratum+":"+language];new=groups[stratum+":"+language]
                for key in ("successes","known_input_tokens","known_output_tokens","input_tokens","output_tokens","total_tokens","validation_total_ns","automatic_repairs","failed_submissions"):
                    demand(old[key]==new[key],"group arithmetic differs: "+key)
        gates={}
        for stratum in ("maintenance","upgrade"):
            h,r=groups[stratum+":hia"],groups[stratum+":rust"]
            gates[stratum]=bool(h["attempted"]==r["attempted"]==2 and h["usage_complete"] and r["usage_complete"]
                and h["successes"]==2 and h["successes"]>=r["successes"] and h["total_tokens"]<=r["total_tokens"]
                and h["submissions"]<=r["submissions"] and h["validation_total_ns"]<=r["validation_total_ns"])
        demand(gates==result["summary"]["descriptive_stratum_gates"],"gate arithmetic differs")
        families.append({"model":model,"valid_observation":result["valid_observation"],"coverage_complete":result["coverage_complete"],
            "usage_complete":result["usage_complete"],"completion_requests":engine_requests,"complete_responses":engine_responses,
            "engines":result["engines"],"groups":groups,"cells":derived_cells,"gates":gates,
            "reference_controls":result["reference_controls"],"model_wall_ns":result["experiment_wall_ns"]})
    usage=all(f["usage_complete"] for f in families);known_in=sum(a["input_tokens"] or 0 for a in all_attempts);known_out=sum(a["output_tokens"] or 0 for a in all_attempts)
    result={"schema":"hepta.agent.matched-v3.independent-readout.v1","suite":str(suite),
        "registration":identity(STUDY/"REGISTRATION.json"),"readout_source":identity(__file__),"models":families,
        "totals":{"planned_cells":16,"attempted_cells":sum(len(f["cells"]) for f in families),"successes":sum(r["correct"] for f in families for r in f["cells"]),
            "completion_requests":sum(f["completion_requests"] for f in families),"complete_responses":sum(f["complete_responses"] for f in families),
            "submissions":len(all_attempts),"known_input_tokens":known_in,"known_output_tokens":known_out,
            "input_tokens":known_in if all(a["input_tokens"] is not None for a in all_attempts) else None,
            "output_tokens":known_out if usage else None,"total_tokens":known_in+known_out if usage else None,
            "automatic_repairs":sum(r["automatic_repairs"] for f in families for r in f["cells"]),"human_repairs":0,"manual_time_ns":None,
            "model_wall_ns":sum(f["model_wall_ns"] for f in families)},
        "cross_family_gates":{s:all(f["valid_observation"] and f["gates"][s] for f in families) for s in ("maintenance","upgrade")},
        "evidence":files,"no_model_calls_or_candidate_reruns":True,"audit_wall_ns":time.monotonic_ns()-started,
        "claims":{"general_agent_advantage":False,"query_advantage_measured":False,"large_project_coverage":False,"manual_labor_measured":False,
                  "old_outputs_rescored":False,"reference_controls_scored_as_model_answers":False}}
    with (output/"RESULT.json").open("xb") as stream:stream.write(canonical(result)+b"\n")
    lines=["# Matched Agent v3: actual results","","This readout reconstructs scores and costs from retained transport, candidate and native-execution evidence. It performs no new inference, compilation or native execution.","",
        "| Family | Stratum | Language | Correct / 2 | Submissions | Input tokens | Output tokens | Total tokens | Validation seconds |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for family in families:
        for name,g in family["groups"].items():
            stratum,language=name.split(":")
            def value(v):return "unknown" if v is None else str(v)
            lines.append(f"| {family['model']['id']} | {stratum} | {language} | {g['successes']}/2 | {g['submissions']} | {value(g['input_tokens'])} | {value(g['output_tokens'])} | {value(g['total_tokens'])} | {g['validation_total_ns']/1e9:.6f} |")
    lines += ["",f"Actual completion requests: **{result['totals']['completion_requests']}**; complete responses: **{result['totals']['complete_responses']}**. Every failed attempt remains in the task denominator.","",
        "Cross-family maintenance gate: **"+str(result["cross_family_gates"]["maintenance"])+"**. Cross-family upgrade gate: **"+str(result["cross_family_gates"]["upgrade"])+"**.","",
        "Validation includes compilation, public and hidden native checks, provider observations and boundary identity checks. Model wall time also includes reference controls, hashing, startup, shutdown and restarts. These are nested intervals and must not be added twice. Download, non-generative capacity checks and archive creation are separate retained costs. Human labor and tool development are unmeasured.","",
        "Both languages used the same answer-free files envelope and two-submission budget. The HIA provider trace is an actual same-Core VM trace beside a separate native entrypoint; the Rust provider trace is native. These are full-context arithmetic tasks in two small quantized model families; there is no query advantage, large-project or universal-language claim.",""]
    (output/"RESULT.md").write_text("\n".join(lines))
    return result


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--suite",required=True);parser.add_argument("--output",required=True)
    result=build(**vars(parser.parse_args()))
    print(json.dumps({"totals":result["totals"],"cross_family_gates":result["cross_family_gates"],"bound_evidence_files":len(result["evidence"])}),flush=True)
