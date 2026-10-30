#!/usr/bin/env python3
"""Read-only reconstruction of v4 results from retained requests and executions.

This program performs no inference, candidate mutation, compilation or native
execution. Its own source is outside the frozen evaluator directory. Missing
usage remains unknown; failed attempts and timeout cells remain in denominators.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
STUDY_RELATIVE=Path("experiments/hia_agent_assembly_v4_20261030")
ARMS=("hia","assembly","rust")
DESCRIPTORS=("id","task","stratum","language","model_id")
IDENTITY_FLAGS=("source_protocol_registration_unchanged","model_unchanged","tools_unchanged","runtime_unchanged")


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
    if task=="average_floor_stamp":return [(a+b)//2]
    if task=="clamped_delta_bias":return [max(a-b,0)]
    if task=="stride_span_v2":return [a*(b+1)]
    if task=="floor_multiple_v2":return [int(b!=0),(a//b)*b if b else 0]
    raise ValueError("unregistered task")


def entry_expected(task,case):
    a,b,c=case
    if task=="average_floor_stamp":return ((a+b)//2)^((c&255)<<40)
    if task=="clamped_delta_bias":return max(a-b,0)+c
    if task=="stride_span_v2":return (a*(b+1))^((c&127)<<57)
    if task=="floor_multiple_v2":return (a//b)*b if b else 2**64-1
    raise ValueError("unregistered task")


def validated_model_usage(result,derived_cells,planned_count=12):
    complete=bool(len(derived_cells)==planned_count and all(row["usage_complete"] is True for row in derived_cells))
    demand(result.get("usage_complete") is complete,"model usage flag differs from independently derived cell coverage and usage")
    return complete


def verify_compiler_binding(built,language,tools,qualified_invocations=None):
    compiler=built.get("compiler")
    if compiler is None:
        demand(not built.get("native_built") and built.get("compile") is None,"compiled candidate lacks compiler identity")
        return
    key="rustc" if language=="rust" else "clang"
    demand(compiler==tools[key],"candidate compiler differs from suite identity")
    if built.get("compile") is not None or built.get("native_built"):
        demand(built.get("compiler_unchanged") is True,"candidate compiler identity was not retained")
    if built.get("compile") is not None:
        aliases={compiler["path"]} if qualified_invocations is None else qualified_invocations[key]
        demand(built["compile"]["argv"][0] in aliases,"actual compiler command is not an identity-qualified invocation")


def verify_engine_settings(identity_record,protocol):
    demand(identity_record.get("threads")==protocol["threads"] and identity_record.get("context")==protocol["context_tokens"],"owned engine thread/context settings differ")
    argv=identity_record["argv"]
    for flag,wanted in (("--threads",protocol["threads"]),("--threads-batch",protocol["threads"]),
                        ("--ctx-size",protocol["context_tokens"]),("--parallel",1)):
        demand(argv.count(flag)==1 and argv.index(flag)+1<len(argv) and argv[argv.index(flag)+1]==str(wanted),"owned engine actual flag differs: "+flag)
    properties=identity_record["properties"]
    demand(properties["default_generation_settings"]["n_ctx"]==protocol["context_tokens"]
           and properties["total_slots"]==1,"owned server reported context or slot count differs")


def execution_correct(observation,task,split,artifact_sha256,language):
    if observation is None:
        return False
    if observation.get("status")=="observable_timeout":
        demand(observation.get("artifact_unchanged") is True,"timed-out native artifact changed")
        return False
    demand(observation.get("artifact_sha256")==artifact_sha256,"native observation is not bound to this attempt's compiled artifact")
    cases,expected=task[split+"_cases"],task[split+"_expected"]
    demand(expected==[entry_expected(task["id"],case) for case in cases],"entry oracle differs from independently written arithmetic")
    demand(observation["cases"]==cases and observation["expected"]==expected,"native observation split differs from fixed fixture")
    wanted=[provider_expected(task["id"],case) for case in cases]
    if observation.get("provider_expected") is not None:
        demand(observation["provider_expected"]==wanted,"provider oracle differs")
    columns=3+len(task["provider_returns"]) if language=="rust" else 1
    try:
        matrix=[[int(word) for word in line.split()] for line in observation["stdout"].splitlines()]
        if any(len(row)!=columns or any(not 0<=word<2**64 for word in row) for row in matrix):
            raise ValueError("native output shape")
        actual=[row[0] for row in matrix]
    except ValueError:
        matrix=[];actual=None
    demand(actual==observation.get("actual"),"native stdout differs from recorded actual values")
    if language=="rust":
        counts=[row[1] for row in matrix];arguments=[row[2] for row in matrix];providers=[row[3:] for row in matrix]
        agreement=True
    else:
        vm_rows=observation["vm_provider_observations"]
        demand(len(vm_rows)==len(cases),"HIA VM trace coverage differs")
        counts=[];arguments=[];providers=[];entries=[]
        for case,row in zip(cases,vm_rows):
            demand(row["case"]==case,"HIA VM trace case differs")
            entry=row["entry"];provider=row["provider"]
            demand(entry["status"] in {"returned","trapped_or_budget_exceeded"}
                   and provider["status"] in {"returned","trapped_or_budget_exceeded"},"HIA VM trace status differs")
            entry_calls=entry["calls"]
            demand(bool(entry_calls) and entry_calls[0]["function"]=="entrypoint"
                   and entry_calls[0]["arguments"]==case,"HIA VM entry invocation differs")
            provider_calls=provider["calls"]
            demand(bool(provider_calls) and provider_calls[0]["function"]==task["provider"]
                   and provider_calls[0]["arguments"]==case[:2],"HIA VM direct provider invocation differs")
            for run in (entry,provider):
                event=run["calls"][0]
                demand(event["returned"]==(run["status"]=="returned"),"HIA VM return event differs from status")
                if run["status"]=="returned":
                    demand(event["values"]==run["values"],"HIA VM return values differ from event")
                else:
                    demand(run["values"] is None,"trapped HIA VM invocation has returned values")
            calls=[event for event in entry_calls if event["function"]==task["provider"]]
            for event in calls:
                demand(type(event["returned"]) is bool,"HIA provider return marker is malformed")
                if event["arguments"]==case[:2]:
                    demand(event["returned"]==(provider["status"]=="returned"),"HIA invoked provider return differs from direct provider trace")
                    if event["returned"]:
                        demand(event["values"]==provider["values"],"HIA invoked provider values differ from direct provider trace")
            count=len(calls);argument_match=int(count==1 and calls[0]["arguments"]==case[:2])
            demand(row["call_count"]==count and row["arguments_match"]==bool(argument_match),"HIA VM saved call summary differs from events")
            counts.append(count);arguments.append(argument_match)
            providers.append([int(value) for value in provider["values"]] if provider["status"]=="returned" else None)
            entries.append(entry["values"][0] if entry["status"]=="returned" else None)
        agreement=actual==entries
    demand(observation.get("provider_actual")==providers and observation.get("provider_call_counts")==counts
           and observation.get("provider_argument_matches")==arguments
           and observation.get("native_vm_agreement") is agreement,"recorded provider/call/agreement fields differ from raw observations")
    correct=bool(observation.get("returncode")==0 and actual==expected
        and observation.get("artifact_unchanged") is True and observation.get("sealed_image") is True
        and providers==wanted and counts==[1]*len(cases) and arguments==[1]*len(cases) and agreement)
    demand((observation["status"]=="correct")==correct,"recorded native success differs from independent field check")
    return correct


def build(suite,snapshot,output):
    started=time.monotonic_ns();suite=Path(suite).resolve(strict=True);output=Path(output).absolute()
    snapshot=Path(snapshot).resolve(strict=True);STUDY=snapshot/STUDY_RELATIVE
    output.mkdir(parents=True,exist_ok=False)
    protocol=read(STUDY/"PROTOCOL.json");registration=read(STUDY/"REGISTRATION.json")
    fixture_list=read(STUDY/"FIXTURES.json")
    demand(identity(STUDY/"PROTOCOL.json")["sha256"]==registration["protocol_sha256"],"current protocol bytes differ from registration")
    demand(identity(STUDY/"FIXTURES.json")["sha256"]==registration["fixtures_sha256"] and hashlib.sha256(canonical(fixture_list)).hexdigest()==registration["fixtures_canonical_sha256"],"current fixture bytes differ from registration")
    fixtures={t["id"]:t for t in fixture_list};plan=read(suite/"SUITE_PLAN.json")
    demand(plan["protocol"]==protocol and plan["registration_sha256"]==identity(STUDY/"REGISTRATION.json")["sha256"],"suite protocol/registration drift")
    demand(plan["sources"]==registration["sources"],"suite source binding drift")
    demand(identity(STUDY/"DEVELOPMENT_CONTROLS.json")["sha256"]==registration["reference_controls_sha256"],"qualified compiler controls differ from registration")
    qualified_invocations={key:{value["path"]} for key,value in plan["tools"].items() if key in {"clang","rustc"}}
    for row in read(STUDY/"DEVELOPMENT_CONTROLS.json")["rows"]:
        built=row["build"]
        if "compiler" in built and "compile" in built:
            key="rustc" if built["language"]=="rust" else "clang"
            demand(built["compiler"]==plan["tools"][key] and built["compiler_unchanged"] is True,"qualified compiler identity differs")
            qualified_invocations[key].add(built["compile"]["argv"][0])
    for name,wanted in registration["sources"].items():
        demand(identity(snapshot/name)["sha256"]==wanted,"frozen evaluator source differs: "+name)
    # Only parse/verify an already submitted assembly source if it was admitted.
    # This calls no model, compiler, native binary, VM, or optimizer.
    sys.path.insert(0,str(snapshot))
    from hepta.hia_agent_assembly import assemble_program
    for task in fixture_list:
        for split in ("public","hidden"):
            demand(task[split+"_expected"]==[entry_expected(task["id"],case) for case in task[split+"_cases"]],"registered mathematical oracle differs")
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
        demand(result["registration_sha256"]==plan["registration_sha256"] and result["sources"]==plan["sources"]
               and result["tools"]==plan["tools"] and result["runtime_files"]==plan["runtime_files"],"model result identities differ")
        expected_order=[]
        for i,task_id in enumerate(protocol["tasks"]):
            offset=(i+model_index)%3
            for language in ARMS[offset:]+ARMS[:offset]:
                expected_order.append(task_id+"_"+language)
        demand([c["id"] for c in model_plan["scheduled_cells"]]==expected_order,"planned order differs")
        for descriptor in model_plan["scheduled_cells"]:
            task_id=descriptor["task"];language=descriptor["language"]
            demand(task_id in protocol["tasks"] and language in ARMS and descriptor=={
                "id":task_id+"_"+language,"task":task_id,"language":language,"stratum":fixtures[task_id]["stratum"],"model_id":model["id"]},"scheduled descriptor differs from registered task")
        demand([c["id"] for c in result["cells"]]==expected_order[:len(result["cells"])],"actual cells are not ordered unique prefix")
        demand({path.parent.name for path in folder.glob("*/CELL.json")}=={c["id"] for c in result["cells"]},"unreported raw cell inventory differs")
        demand([row["cell"] for row in result["cell_identity_checks"]]==[c["id"] for c in result["cells"]],"boundary identity inventory differs")
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
            verify_engine_settings(before,protocol)
            condition=read(engine_path/"RUNTIME_CONDITION.json")
            demand(before["model"]["sha256"]==model["sha256"] and before["model"]["bytes"]==model["bytes"],"owned model differs")
            # The owner lists resolved .so aliases separately; suite binding
            # deduplicates paths. Their exact path/size/hash sets must match.
            runtime_key=lambda row:(row["path"],row["bytes"],row["sha256"])
            demand(set(map(runtime_key,before["runtime_files"]))==set(map(runtime_key,plan["runtime_files"])),"owned runtime differs from suite")
            demand(after["model_unchanged"] and after["runtime_unchanged"] and condition["matches"]
                   and engine["identity"]==after and engine["process_exited"] is True,"owned runtime identity or shutdown failed")
            paths=sorted(engine_path.glob("transport-*.request.json"))
            raw_responses=sorted(engine_path.glob("transport-*.response.raw"))
            demand(len(paths)==engine["started_requests"] and len(raw_responses)==engine["responses_received"],"transport counts differ")
            engine_requests+=len(paths);engine_responses+=len(raw_responses)
            for path in paths:
                bind(path);transports.append((path,read(path)))
        derived_cells=[]
        for cell,descriptor in zip(result["cells"],model_plan["scheduled_cells"]):
            demand({key:cell[key] for key in DESCRIPTORS}==descriptor,"cell descriptor differs from its scheduled task")
            task=fixtures[cell["task"]];cell_path=folder/cell["id"]
            bind(cell_path/"CELL.json");demand(read(cell_path/"CELL.json")==cell,"cell aggregate differs from raw CELL")
            bind(cell_path/"BOUNDARY_IDENTITIES.json")
            boundary=read(cell_path/"BOUNDARY_IDENTITIES.json")
            demand(boundary.get("passed") is True and all(boundary.get(flag) is True for flag in IDENTITY_FLAGS)
                   and type(boundary.get("wall_ns")) is int and boundary["wall_ns"]>=0,"cell boundary identity or cost failed")
            demand({"cell":cell["id"],**boundary}==result["cell_identity_checks"][len(derived_cells)],"aggregate boundary differs from raw identity")
            derived=[];public_pass=False;terminal_artifact_sha256=None
            for index,attempt in enumerate(cell["attempts"]):
                demand(index==attempt["index"],"attempt numbering differs")
                request_path=cell_path/f"attempt-{index}.request.json";evaluation_path=cell_path/f"attempt-{index}.evaluation.json"
                bind(request_path);bind(evaluation_path)
                request=read(request_path);demand(read(evaluation_path)==attempt,"attempt summary differs from raw evaluation")
                demand(request["maximum_output_tokens"]==protocol["max_output_tokens"] and request["wall_seconds"]==protocol["request_wall_seconds"],"request budget differs")
                demand(request["language"]==cell["language"],"request language differs")
                registered=registration["prompts_and_schemas"][cell["task"]+":"+cell["language"]]
                demand(hashlib.sha256(canonical(request["response_schema"])).hexdigest()==registered["schema_sha256"],"request decoder schema differs")
                messages=request["messages"]
                demand(messages[0]["role"]=="user" and hashlib.sha256(messages[0]["content"].encode()).hexdigest()==registered["prompt_sha256"],"request first prompt differs")
                demand(len(messages)==1+2*index,"unexpected message or hidden feedback")
                if index:
                    prior=read(cell_path/f"attempt-{index-1}.evaluation.json")
                    prior_response=read(cell_path/f"attempt-{index-1}.response.json")
                    old_build=prior["build"];old_public=prior.get("public_validation")
                    feedback={"compile_status":old_build["status"]}
                    if "compile" in old_build:feedback["compiler_stderr"]=old_build["compile"]["stderr"][:4000]
                    if "error" in old_build:feedback["diagnostic"]=old_build["error"]
                    if old_public is not None:
                        feedback["public"]={key:old_public.get(key) for key in ("status","cases","expected","actual","provider_actual","provider_expected","provider_call_counts","provider_argument_matches","returncode","stderr")}
                    expected_feedback="Compilation or the public examples failed. Return both complete files again under the same contract. This is the final allowed submission. Hidden tests have not run.\n"+canonical(feedback).decode()
                    demand(messages[-2]=={"role":"assistant","content":prior_response["text"]}
                           and messages[-1]=={"role":"user","content":expected_feedback},"feedback differs from public-only diagnostics")
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
                    settings=raw["generation_settings"];sampling=settings.get("params",settings)
                    demand(raw["truncated"] is False and raw["stop_type"] in {"eos","limit"}
                           and sampling["temperature"]==sampling["seed"]==0
                           and isinstance(sampling.get("grammar"),str) and sampling["grammar"].strip()
                           and sampling["grammar_lazy"] is False,"actual generation settings differ")
                    demand(response["hard_wall_seconds"]==protocol["request_wall_seconds"]
                           and 0<=response["wall_nanoseconds"]<=response["whole_generate_ns"]<=attempt["request_wall_ns"],"generation timing nesting differs")
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
                    demand(built["task_id"]==cell["task"] and built.get("representation",built["language"])==cell["language"],"build task descriptor differs")
                    verify_compiler_binding(built,cell["language"],plan["tools"],qualified_invocations)
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
                            if cell["language"]=="assembly":
                                source=f'hia-asm.v1 hepta.hia.program.v6 {task["id"]}\nexports(entrypoint)\n'+supplied_files["api.hiaasm"]+"\n"+supplied_files["client.hiaasm"]
                                assembly=built["patch_receipt"]["assembly"]
                                demand(hashlib.sha256(source.encode()).hexdigest()==assembly["source_text_sha256"],"assembly source binding differs")
                                demand(assemble_program(source).canonical_bytes==core.read_bytes()
                                       and assembly["core_sha256"]==built["core_sha256"]
                                       and assembly["full_module_reverified"] is True
                                       and assembly["implicit_repairs"] is False and assembly["deployment_authority"] is False,"assembly lowering differs from submitted source")
                            else:
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
                        public_pass=execution_correct(attempt["public_validation"],task,"public",built["artifact"]["sha256"],cell["language"])
                        demand((attempt["status"]=="public_passed")==public_pass,"public pass status differs")
                derived.append({"index":index,"status":attempt["status"],"input_tokens":input_tokens,"output_tokens":output_tokens,
                    "request_wall_ns":attempt["request_wall_ns"],"inference_ns":attempt.get("inference_ns"),"evaluation_ns":attempt.get("evaluation_ns",0)})
            demand(len(derived)<=protocol["attempts_per_cell"] and len(derived)>=1,"attempt budget differs")
            correct=False
            if cell["hidden_tests_evaluated"]:
                demand(public_pass,"hidden tests ran without public pass")
                correct=execution_correct(cell["hidden_validation"],task,"hidden",terminal_artifact_sha256,cell["language"])
            demand(correct==cell["correct"],"task score differs")
            # Hidden cases never appear in a later request: public-pass is terminal.
            demand(not any(a["status"]=="public_passed" for a in cell["attempts"][:-1]),"request after public pass")
            demand(cell["automatic_repair_rounds"]==len(derived)-1,"repair count differs")
            complete=all(a["input_tokens"] is not None and a["output_tokens"] is not None for a in derived)
            known_in=sum(a["input_tokens"] or 0 for a in derived);known_out=sum(a["output_tokens"] or 0 for a in derived)
            demand(cell["known_input_tokens"]==known_in and cell["known_output_tokens"]==known_out and cell["usage_complete"]==complete,"cell token aggregation differs")
            demand(cell["input_tokens"]==(known_in if all(a["input_tokens"] is not None for a in derived) else None)
                   and cell["output_tokens"]==(known_out if complete else None)
                   and cell["total_tokens"]==(known_in+known_out if complete else None),"reported complete cell token totals differ")
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
            for language in ARMS:
                rows=[r for r in derived_cells if r["stratum"]==stratum and r["language"]==language]
                attempts=[a for r in rows for a in r["attempts"]];usage=len(rows)==2 and all(r["usage_complete"] for r in rows)
                known_in=sum(r["known_input_tokens"] for r in rows);known_out=sum(r["known_output_tokens"] for r in rows)
                known_identity=sum(r["boundary_identity_ns"] for r in rows)
                identity_ns=known_identity if len(rows)==2 else None
                evaluation_ns=sum(r["evaluation_ns"] for r in rows)
                groups[stratum+":"+language]={"planned":2,"attempted":len(rows),"successes":sum(r["correct"] for r in rows),
                    "submissions":len(attempts),"failed_submissions":sum(a["status"]!="public_passed" for a in attempts)+sum(r["status"]=="hidden_validation_failed" for r in rows),
                    "known_input_tokens":known_in,"known_output_tokens":known_out,"input_tokens":known_in if len(rows)==2 and all(r["input_tokens"] is not None for r in rows) else None,
                    "output_tokens":known_out if usage else None,"total_tokens":known_in+known_out if usage else None,"usage_complete":usage,
                    "automatic_repairs":sum(r["automatic_repairs"] for r in rows),"human_repairs":0,"manual_time_ns":None,
                    "request_wall_ns":sum(a["request_wall_ns"] for a in attempts),"inference_ns":sum(a["inference_ns"] for a in attempts) if len(rows)==2 and all(a["inference_ns"] is not None for a in attempts) else None,
                    "evaluation_ns":evaluation_ns,"boundary_identity_ns":identity_ns,"known_boundary_identity_ns":known_identity,
                    "validation_total_ns":evaluation_ns+identity_ns if identity_ns is not None else None,
                    "known_validation_total_ns":evaluation_ns+known_identity,"cell_wall_ns":sum(r["cell_wall_ns"] for r in rows)}
                old=result["summary"]["groups"][stratum+":"+language];new=groups[stratum+":"+language]
                for key in ("successes","known_input_tokens","known_output_tokens","input_tokens","output_tokens","total_tokens","validation_total_ns","automatic_repairs","failed_submissions","evaluation_ns","boundary_identity_ns","request_wall_ns","inference_ns","cell_wall_ns"):
                    demand(old[key]==new[key],"group arithmetic differs: "+key)
                demand(old["attempts"]==new["submissions"],"attempt aggregation differs")
        gates={};representation_gates={}
        for stratum in ("maintenance","upgrade"):
            h,r,j=(groups[stratum+":"+arm] for arm in ("assembly","rust","hia"))
            def dominates(other):
                return bool(h["attempted"]==other["attempted"]==2 and h["usage_complete"] and other["usage_complete"]
                    and h["successes"]==2 and h["successes"]>=other["successes"] and h["total_tokens"]<=other["total_tokens"]
                    and h["submissions"]<=other["submissions"] and h["validation_total_ns"]<=other["validation_total_ns"])
            gates[stratum]=dominates(r)
            representation_gates[stratum]=dominates(j)
        demand(gates==result["summary"]["descriptive_stratum_gates"],"gate arithmetic differs")
        demand(representation_gates==result["summary"]["assembly_vs_json_gates"],"representation gate arithmetic differs")
        coverage=len(derived_cells)==12
        valid=bool(coverage and result["status"]=="all_cells_attempted"
                   and all(result[key] is True for key in ("sources_unchanged","tools_unchanged","model_unchanged")))
        demand(result["coverage_complete"]==coverage and result["valid_observation"]==valid,"reported observation validity differs")
        model_usage=validated_model_usage(result,derived_cells)
        families.append({"model":model,"valid_observation":result["valid_observation"],"coverage_complete":result["coverage_complete"],
            "usage_complete":model_usage,"completion_requests":engine_requests,"complete_responses":engine_responses,
            "engines":result["engines"],"groups":groups,"cells":derived_cells,"gates":gates,"assembly_vs_json_gates":representation_gates,
            "reference_controls":result["reference_controls"],"model_wall_ns":result["experiment_wall_ns"]})
    usage=all(f["usage_complete"] for f in families);known_in=sum(a["input_tokens"] or 0 for a in all_attempts);known_out=sum(a["output_tokens"] or 0 for a in all_attempts)
    cohort=read(suite/"RESULT.json");bind(suite/"RESULT.json")
    cross_gates={s:all(f["valid_observation"] and f["gates"][s] for f in families) for s in ("maintenance","upgrade")}
    cross_representation={s:all(f["valid_observation"] and f["assembly_vs_json_gates"][s] for f in families) for s in ("maintenance","upgrade")}
    demand(cohort["cross_family_gates"]==cross_gates and cohort["cross_family_assembly_vs_json_gates"]==cross_representation
           and cohort["complete_valid_coverage"]==all(f["valid_observation"] for f in families),"cohort arithmetic differs")
    result={"schema":"hepta.agent.assembly-v4.independent-readout.v1","suite":str(suite),"snapshot":str(snapshot),
        "registration":identity(STUDY/"REGISTRATION.json"),"readout_source":identity(__file__),"models":families,
        "totals":{"planned_cells":24,"attempted_cells":sum(len(f["cells"]) for f in families),"successes":sum(r["correct"] for f in families for r in f["cells"]),
            "completion_requests":sum(f["completion_requests"] for f in families),"complete_responses":sum(f["complete_responses"] for f in families),
            "submissions":len(all_attempts),"known_input_tokens":known_in,"known_output_tokens":known_out,
            "input_tokens":known_in if all(a["input_tokens"] is not None for a in all_attempts) else None,
            "output_tokens":known_out if usage else None,"total_tokens":known_in+known_out if usage else None,
            "automatic_repairs":sum(r["automatic_repairs"] for f in families for r in f["cells"]),"human_repairs":0,"manual_time_ns":None,
            "model_wall_ns":sum(f["model_wall_ns"] for f in families)},
        "complete_valid_coverage":all(f["valid_observation"] for f in families),
        "cross_family_gates":cross_gates,"cross_family_assembly_vs_json_gates":cross_representation,
        "evidence":files,"no_model_calls_or_candidate_reruns":True,"audit_wall_ns":time.monotonic_ns()-started,
        "claims":{"general_agent_advantage":False,"query_advantage_measured":False,"large_project_coverage":False,"manual_labor_measured":False,
                  "old_outputs_rescored":False,"reference_controls_scored_as_model_answers":False}}
    with (output/"RESULT.json").open("xb") as stream:stream.write(canonical(result)+b"\n")
    lines=["# Three-arm Agent v4: actual results","","This readout reconstructs scores and costs from retained transport, candidate and native-execution evidence. It performs no new inference, compilation, VM execution or native execution. Admitted assembly is reparsed through the exact frozen frontend to check the submitted source-to-Core binding.","",
        "| Family | Stratum | Language | Correct / attempted (planned) | Submissions | Input tokens | Output tokens | Total tokens | Full validation seconds |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for family in families:
        for name,g in family["groups"].items():
            stratum,language=name.split(":")
            def value(v):return "unknown" if v is None else str(v)
            validation="unknown" if g["validation_total_ns"] is None else f"{g['validation_total_ns']/1e9:.6f}"
            lines.append(f"| {family['model']['id']} | {stratum} | {language} | {g['successes']}/{g['attempted']} ({g['planned']}) | {g['submissions']} | {value(g['input_tokens'])} | {value(g['output_tokens'])} | {value(g['total_tokens'])} | {validation} |")
    lines += ["",f"Actual completion requests: **{result['totals']['completion_requests']}**; complete responses: **{result['totals']['complete_responses']}**. Every failed attempt remains in the task denominator.","",
        f"Attempted cells: **{result['totals']['attempted_cells']}/{result['totals']['planned_cells']}**. Complete valid cohort coverage: **{result['complete_valid_coverage']}**. Unattempted cells are missing observations, not failed model answers; an incomplete family cannot support a completed cross-family comparison.","",
        "Cross-family maintenance gate: **"+str(result["cross_family_gates"]["maintenance"])+"**. Cross-family upgrade gate: **"+str(result["cross_family_gates"]["upgrade"])+"**.","",
        "Assembly versus JSON maintenance gate: **"+str(result["cross_family_assembly_vs_json_gates"]["maintenance"])+"**. Assembly versus JSON upgrade gate: **"+str(result["cross_family_assembly_vs_json_gates"]["upgrade"])+"**.","",
        "Validation includes compilation, public and hidden native checks, provider observations and boundary identity checks. Model wall time also includes reference controls, hashing, startup, shutdown and restarts. These are nested intervals and must not be added twice. Download, non-generative capacity checks and archive creation are separate retained costs. Human labor and tool development are unmeasured.","",
        "All three arms used answer-free files envelopes and the same two-submission budget, 2,048 maximum output tokens and a hard 180-second entire-generate deadline. The HIA provider trace is an actual same-Core VM trace beside a separate native entrypoint; the Rust provider trace is native. These are full-context arithmetic tasks in two small quantized model families; there is no query advantage, large-project or universal-language claim.","",
        "The independently frozen source snapshot binds 31 actual evaluator dependencies. It is modified from the recorded base commit and is not represented as the final complete repository tree. Prior v3 results remain unchanged.",""]
    (output/"RESULT.md").write_text("\n".join(lines))
    return result


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--suite",required=True);parser.add_argument("--snapshot",required=True);parser.add_argument("--output",required=True)
    result=build(**vars(parser.parse_args()))
    print(json.dumps({"totals":result["totals"],"cross_family_gates":result["cross_family_gates"],"bound_evidence_files":len(result["evidence"])}),flush=True)
