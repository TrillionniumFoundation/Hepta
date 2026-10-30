#!/usr/bin/env python3
"""Freeze and execute a paired, fail-closed maintenance/upgrade cohort.

Cell timeouts are terminal. The owned process is closed and a fresh process is
started before the next *different* registered cell. No attempted cell is
retried after a transport failure. Compilation/public feedback can produce at
most one second submission; hidden results can never do so.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from experiments.hia_agent_assembly_v4_20261030 import fixtures, evaluator
from experiments.hia_agent_assembly_v4_20261030.engine import EnvelopeEngine
from tools.provider_adapter.llama_cpp_engine import canonical, file_identity

HERE = Path(__file__).resolve().parent
SCHEMA = "hepta.agent.assembly-maintenance-upgrade.v4"


def read(path):
    return json.loads(Path(path).read_bytes())


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def source_bindings():
    # Include the actual Python module closure plus all study source files.
    # Loading the native evaluator imports its Core runtime before freezing.
    import hepta.hia_program_runtime  # noqa: F401
    result = {}
    for module in tuple(sys.modules.values()):
        filename = getattr(module, "__file__", None)
        if not filename:
            continue
        path = Path(filename).resolve()
        if path.is_relative_to(ROOT) and path.suffix == ".py":
            result[str(path.relative_to(ROOT))] = file_identity(path)["sha256"]
    for path in sorted(HERE.glob("*.py")):
        result[str(path.relative_to(ROOT))] = file_identity(path)["sha256"]
    # This file also participates in the emitter's implementation identity
    # even when a primitive-only task does not import composite elaboration.
    result["hepta/hia_program_composite.py"]=file_identity(ROOT/"hepta/hia_program_composite.py")["sha256"]
    return dict(sorted(result.items()))


def check_bindings(bindings):
    return all((ROOT / name).is_file() and file_identity(ROOT / name)["sha256"] == value
               for name, value in bindings.items())


def runtime_bindings(binary):
    binary=Path(binary).resolve(strict=True)
    paths={binary,*(p.resolve(strict=True) for p in binary.parent.glob("*.so*")),
           *(p.resolve(strict=True) for p in binary.parent.glob("*.dll"))}
    return [file_identity(path) for path in sorted(paths)]


def registered_inventory(tasks):
    return {task["id"] + ":" + language: {
        "prompt_sha256": hashlib.sha256(fixtures.prompt(task,language).encode()).hexdigest(),
        "schema_sha256": digest(fixtures.response_schema(language))}
        for task in tasks for language in fixtures.ARMS}


def check_qualified_tools(actual_tools, actual_runtime):
    """Generation uses the same native compilers and runner as its controls."""
    controls = read(HERE / "DEVELOPMENT_CONTROLS.json")
    expected = {"clang": [], "rustc": []}
    for row in controls["rows"]:
        built = row["build"]
        compiler = built.get("compiler")
        if compiler is not None:
            key = "rustc" if built["language"] == "rust" else "clang"
            expected[key].append(compiler)
    for key, identities in expected.items():
        if not identities or any(value != actual_tools[key] for value in identities):
            raise RuntimeError("qualified compiler identity differs before inference")
    capacity = read(HERE / "TOKENIZER_CAPACITY.json")
    current = {(item["path"], item["bytes"], item["sha256"]) for item in actual_runtime}
    for model in capacity["models"]:
        qualified = {(item["path"], item["bytes"], item["sha256"])
                     for item in model["identity"]["runtime_files"]}
        if current != qualified or not any(
                item == actual_tools["binary"] for item in model["identity"]["runtime_files"]):
            raise RuntimeError("qualified model runtime identity differs before inference")
    return True


def register():
    protocol = read(HERE / "PROTOCOL.json")
    tasks = fixtures.make_fixtures()
    if [t["id"] for t in tasks] != protocol["tasks"]:
        raise ValueError("registered task inventory differs")
    controls = read(HERE / "DEVELOPMENT_CONTROLS.json")
    hostile=read(HERE/"HOSTILE_CONTROLS.json")
    unit=read(HERE/"UNIT_CONTROLS.json")
    capacity=read(HERE/"TOKENIZER_CAPACITY.json")
    if controls["count"]!=36 or controls["passed"]!=36:
        raise ValueError("pre-registration reference controls failed")
    if hostile["count"]!=9 or hostile["passed"]!=9:
        raise ValueError("pre-registration hostile native controls failed")
    if (unit["tests_run"]<10 or unit["failures"] or unit["errors"] or unit["skipped"]
            or unit["tests_run"]!=len(unit["test_ids"]) or not unit["passed"]):
        raise ValueError("pre-registration orchestration controls failed")
    for name,value in unit["source_sha256"].items():
        if file_identity(HERE/name)["sha256"]!=value:
            raise ValueError("orchestration controls do not match final study source")
    if not capacity["passed"] or capacity["model_requests"]!=0 or len(capacity["models"])!=2:
        raise ValueError("non-generative model capacity check failed")
    evaluator.save(HERE / "FIXTURES.json",tasks)
    result = {"schema":SCHEMA+".registration", "registered_unix_ns":time.time_ns(),
        "before_any_model_requests":True,"model_requests":0,
        "protocol_sha256":file_identity(HERE/"PROTOCOL.json")["sha256"],
        "fixtures_sha256":file_identity(HERE/"FIXTURES.json")["sha256"],
        "fixtures_canonical_sha256":digest(tasks), "sources":source_bindings(),
        "prompts_and_schemas":registered_inventory(tasks),
        "reference_controls_sha256":file_identity(HERE/"DEVELOPMENT_CONTROLS.json")["sha256"],
        "hostile_controls_sha256":file_identity(HERE/"HOSTILE_CONTROLS.json")["sha256"],
        "orchestration_controls_sha256":file_identity(HERE/"UNIT_CONTROLS.json")["sha256"],
        "tokenizer_capacity_sha256":file_identity(HERE/"TOKENIZER_CAPACITY.json")["sha256"]}
    evaluator.save(HERE/"REGISTRATION.json",result)
    return result


def validate_registration():
    registration=read(HERE/"REGISTRATION.json");tasks=fixtures.make_fixtures()
    if (file_identity(HERE/"PROTOCOL.json")["sha256"] != registration["protocol_sha256"]
            or file_identity(HERE/"FIXTURES.json")["sha256"] != registration["fixtures_sha256"]
            or digest(tasks) != registration["fixtures_canonical_sha256"]
            or read(HERE/"FIXTURES.json") != tasks
            or registered_inventory(tasks) != registration["prompts_and_schemas"]
            or not check_bindings(registration["sources"])
            or file_identity(HERE/"DEVELOPMENT_CONTROLS.json")["sha256"]!=registration["reference_controls_sha256"]
            or file_identity(HERE/"HOSTILE_CONTROLS.json")["sha256"]!=registration["hostile_controls_sha256"]
            or file_identity(HERE/"UNIT_CONTROLS.json")["sha256"]!=registration["orchestration_controls_sha256"]
            or file_identity(HERE/"TOKENIZER_CAPACITY.json")["sha256"]!=registration["tokenizer_capacity_sha256"]):
        raise RuntimeError("registered source/fixture/prompt/schema identity drift")
    return registration


def validate_runtime_environment(engine):
    process=Path("/proc",str(engine.process.pid))
    values=[v.decode() for v in (process/"environ").read_bytes().split(b"\0") if v.startswith(b"LLAMA_ARG_REPACK=")]
    executable=Path(os.readlink(process/"exe")).resolve()
    result={"pid":engine.process.pid,"whitelisted_environment":values,"executable":str(executable),
        "matches":values==["LLAMA_ARG_REPACK=0"] and executable==engine.binary}
    evaluator.save(engine.output/"RUNTIME_CONDITION.json",result)
    if not result["matches"]:
        raise RuntimeError("owned process differs from registered no-repack runtime")
    return result


def known_transport_input(engine):
    path=engine.output/("transport-"+str(engine.generation_count).zfill(3)+".request.json")
    try:
        ids = read(path)["payload"]["prompt"] if path.is_file() else None
        return len(ids) if type(ids) is list and all(type(x) is int for x in ids) else None
    except (OSError, ValueError, KeyError, TypeError):
        # A hard deadline may leave a partial evidence write. Retain it, but
        # never invent an input-token count or lose the timeout record.
        return None


def run_cell(cell,task,folder,engine,clang,rustc,bindings,protocol):
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=False)
    row={**cell,"attempts":[],"status":"not_started","correct":False,
        "hidden_tests_evaluated":False,"human_repairs":0,"manual_time_ns":None}
    messages=[{"role":"user","content":fixtures.prompt(task,cell["language"])}]
    engine_usable=True;final_build=None;started=time.monotonic_ns()
    for index in range(protocol["attempts_per_cell"]):
        if not check_bindings(bindings):
            raise RuntimeError("registered source drift before inference")
        request={"messages":messages,"language":cell["language"],"maximum_output_tokens":protocol["max_output_tokens"],
            "wall_seconds":protocol["request_wall_seconds"],"response_schema":fixtures.response_schema(cell["language"])}
        evaluator.save(folder/f"attempt-{index}.request.json",request)
        attempt={"index":index,"status":"inference_started","input_tokens":None,"output_tokens":None,"usage_complete":False}
        row["attempts"].append(attempt);request_started=time.monotonic_ns();before=engine.generation_count
        try:
            response=engine.generate(messages,language=cell["language"],limit=protocol["max_output_tokens"],wall_seconds=protocol["request_wall_seconds"])
        except Exception as error:
            status=("budget_timeout" if isinstance(error,TimeoutError) else
                    "context_budget_exceeded" if isinstance(error,ValueError) and str(error).startswith("E_MATCHED_CONTEXT:") else
                    "generation_infrastructure_failure")
            attempt.update(status=status,
                error={"type":type(error).__name__,"message":str(error)},request_wall_ns=time.monotonic_ns()-request_started,
                completion_requests_started=engine.generation_count-before,
                known_input_tokens=known_transport_input(engine) if engine.generation_count>before else None)
            evaluator.save(folder/f"attempt-{index}.evaluation.json",attempt)
            row["status"]=attempt["status"];engine_usable=False
            break
        attempt.update(request_wall_ns=time.monotonic_ns()-request_started,usage=response["usage"],
            input_tokens=response["usage"]["input_tokens"],output_tokens=response["usage"]["output_tokens"],
            inference_ns=response["wall_nanoseconds"],usage_complete=True,completion_requests_started=engine.generation_count-before)
        evaluator.save(folder/f"attempt-{index}.response.json",response)
        evaluation_started=time.monotonic_ns()
        try:
            built=evaluator.build(task,cell["language"],response["text"],folder/f"candidate-{index}",clang,rustc)
            observed=evaluator.execute(built,task,task["public_cases"],task["public_expected"]) if built["native_built"] else None
        except Exception as error:
            attempt.update(status="native_infrastructure_failure",evaluation_ns=time.monotonic_ns()-evaluation_started,
                error={"type":type(error).__name__,"message":str(error)})
            evaluator.save(folder/f"attempt-{index}.evaluation.json",attempt)
            row["status"]="native_infrastructure_failure";engine_usable=False;break
        attempt.update(build=built,public_validation=observed,evaluation_ns=time.monotonic_ns()-evaluation_started,
            status="public_passed" if observed is not None and observed["status"]=="correct" else
                   built["status"] if not built["native_built"] else observed["status"])
        evaluator.save(folder/f"attempt-{index}.evaluation.json",attempt)
        if built["status"]=="infrastructure_failure" or (observed is not None and not observed["artifact_unchanged"]):
            row["status"]="native_infrastructure_failure";engine_usable=False;break
        if observed is not None and observed["status"]=="correct":
            final_build=built;break
        row["status"]="public_validation_failed"
        if index+1<protocol["attempts_per_cell"]:
            messages=messages+[{"role":"assistant","content":response["text"]},{"role":"user","content":
                "Compilation or the public examples failed. Return both complete files again under the same contract. This is the final allowed submission. Hidden tests have not run.\n"+
                canonical(evaluator.feedback(built,observed)).decode()}]
    if final_build is not None:
        hidden_started=time.monotonic_ns()
        try:
            hidden=evaluator.execute(final_build,task,task["hidden_cases"],task["hidden_expected"])
            passed=hidden["status"]=="correct" and hidden["artifact_unchanged"]
            row.update(hidden_tests_evaluated=True,hidden_validation=hidden,hidden_validation_ns=time.monotonic_ns()-hidden_started,
                       correct=passed,status="correct" if passed else "hidden_validation_failed")
            if not hidden["artifact_unchanged"]:
                row["status"]="native_infrastructure_failure";engine_usable=False
        except Exception as error:
            row.update(hidden_tests_evaluated=True,hidden_validation_ns=time.monotonic_ns()-hidden_started,
                hidden_error={"type":type(error).__name__,"message":str(error)},status="native_infrastructure_failure")
            engine_usable=False
    row["automatic_repair_rounds"]=max(0,len(row["attempts"])-1)
    row["usage_complete"]=bool(row["attempts"]) and all(a["usage_complete"] for a in row["attempts"])
    row["known_input_tokens"]=sum(a.get("input_tokens") or a.get("known_input_tokens") or 0 for a in row["attempts"])
    row["known_output_tokens"]=sum(a.get("output_tokens") or 0 for a in row["attempts"])
    row["input_tokens"]=row["known_input_tokens"] if all(a.get("input_tokens") is not None or a.get("known_input_tokens") is not None for a in row["attempts"]) else None
    row["output_tokens"]=row["known_output_tokens"] if row["usage_complete"] else None
    row["total_tokens"]=row["input_tokens"]+row["output_tokens"] if row["input_tokens"] is not None and row["output_tokens"] is not None else None
    row["cell_wall_ns"]=time.monotonic_ns()-started
    evaluator.save(folder/"CELL.json",row)
    return row,engine_usable


def check_cell_identities(registration,actual_model,tools,runtime,binary,model_path,folder):
    """Stop at the first completed cell boundary with a changed identity."""
    started=time.monotonic_ns()
    record={"source_protocol_registration_unchanged":False,"model_unchanged":False,"tools_unchanged":False,"runtime_unchanged":False}
    try:
        validate_registration()
        record["source_protocol_registration_unchanged"]=check_bindings(registration["sources"])
        record["model_unchanged"]=file_identity(model_path)==actual_model
        record["tools_unchanged"]=all(file_identity(item["path"])==item for item in tools.values())
        record["runtime_unchanged"]=runtime_bindings(binary)==runtime
    except Exception as error:
        record["error"]={"type":type(error).__name__,"message":str(error)}
    record["passed"]=all(record[key] for key in ("source_protocol_registration_unchanged","model_unchanged","tools_unchanged","runtime_unchanged"))
    record["wall_ns"]=time.monotonic_ns()-started
    evaluator.save(Path(folder)/"BOUNDARY_IDENTITIES.json",record)
    return record


DESCRIPTOR_FIELDS = ("id", "task", "stratum", "language", "model_id")
IDENTITY_FLAGS = ("source_protocol_registration_unchanged", "model_unchanged",
                  "tools_unchanged", "runtime_unchanged")


def scheduled_cells(tasks, model_id, model_index):
    return [{"id": task["id"] + "_" + arm, "task": task["id"],
             "stratum": task["stratum"], "language": arm, "model_id": model_id}
            for index, task in enumerate(tasks)
            for arm in fixtures.ARMS[(index + model_index) % 3:] + fixtures.ARMS[:(index + model_index) % 3]]


def summarize_cells(cells,planned,identity_checks=()):
    groups={}
    descriptor = lambda row: tuple(row.get(key) for key in DESCRIPTOR_FIELDS)
    planned_keys = [descriptor(row) for row in planned]
    actual_keys = [descriptor(row) for row in cells]
    families = {row.get("model_id") for row in planned}
    tasks = fixtures.make_fixtures()
    expected = {(task["id"] + "_" + arm, task["id"], task["stratum"], arm, family)
                for family in families for task in tasks for arm in fixtures.ARMS}
    schedule_valid = bool(len(families) == 1 and all(type(family) is str and family for family in families)
                          and len(planned_keys) == len(set(planned_keys)) == 12
                          and set(planned_keys) == expected)
    actual_valid = (len(actual_keys) == len(set(actual_keys))
                    and set(actual_keys).issubset(set(planned_keys)))
    identity_names = [row.get("cell") for row in identity_checks]
    identity_valid = (len(identity_names) == len(set(identity_names))
                      and set(identity_names) == {row.get("id") for row in cells})
    identities = {row.get("cell"): row for row in identity_checks}
    identity_costs = {key: value["wall_ns"] for key, value in identities.items()
                      if type(value.get("wall_ns")) is int and value["wall_ns"] >= 0}
    exact_coverage = schedule_valid and actual_valid and set(actual_keys) == set(planned_keys)
    for stratum in ("maintenance","upgrade"):
        for language in fixtures.ARMS:
            rows=[r for r in cells if r["stratum"]==stratum and r["language"]==language]
            attempts=[a for r in rows for a in r["attempts"]]
            wanted = {descriptor(row) for row in planned if row["stratum"] == stratum and row["language"] == language}
            complete = bool(schedule_valid and actual_valid and len(rows) == 2
                            and {descriptor(row) for row in rows} == wanted)
            identity_complete = bool(complete and identity_valid and all(
                row["id"] in identity_costs and identities[row["id"]].get("passed") is True
                and all(identities[row["id"]].get(flag) is True for flag in IDENTITY_FLAGS)
                for row in rows))
            usage=complete and all(r["usage_complete"] for r in rows)
            known_in=sum(r["known_input_tokens"] for r in rows);known_out=sum(r["known_output_tokens"] for r in rows)
            evaluation_ns=sum(a.get("evaluation_ns",0) for a in attempts)+sum(r.get("hidden_validation_ns",0) for r in rows)
            known_identity_ns=sum(identity_costs[r["id"]] for r in rows if r["id"] in identity_costs)
            identity_ns=known_identity_ns if identity_complete else None
            groups[stratum+":"+language]={"planned_cells":2,"attempted_cells":len(rows),"successes":sum(r["correct"] for r in rows),
                "attempts":len(attempts),"failed_submissions":sum(a["status"]!="public_passed" for a in attempts)+sum(r["status"]=="hidden_validation_failed" for r in rows),
                "automatic_repairs":sum(r["automatic_repair_rounds"] for r in rows),"human_repairs":0,"manual_time_ns":None,
                "all_cells_attempted":complete,"identity_coverage_complete":identity_complete,
                "usage_complete":usage,"known_input_tokens":known_in,"known_output_tokens":known_out,
                "input_tokens":known_in if complete and all(r["input_tokens"] is not None for r in rows) else None,
                "output_tokens":known_out if usage else None,"total_tokens":known_in+known_out if usage else None,
                "inference_ns":sum(a["inference_ns"] for a in attempts) if all("inference_ns" in a for a in attempts) and complete else None,
                "request_wall_ns":sum(a["request_wall_ns"] for a in attempts),
                "evaluation_ns":evaluation_ns,"boundary_identity_ns":identity_ns,
                "known_boundary_identity_ns":known_identity_ns,
                "validation_total_ns":evaluation_ns+identity_ns if identity_ns is not None else None,
                "cell_wall_ns":sum(r["cell_wall_ns"] for r in rows)}
    gates={}
    representation_gates={}
    for stratum in ("maintenance","upgrade"):
        h,r,j=(groups[stratum+":"+arm] for arm in ("assembly","rust","hia"))
        def dominates(other):
            return bool(h["all_cells_attempted"] and other["all_cells_attempted"]
                and h["identity_coverage_complete"] and other["identity_coverage_complete"]
                and h["usage_complete"] and other["usage_complete"]
                and h["successes"]==2 and h["successes"]>=other["successes"] and h["total_tokens"]<=other["total_tokens"]
                and h["attempts"]<=other["attempts"] and h["validation_total_ns"]<=other["validation_total_ns"])
        gates[stratum]=dominates(r)
        representation_gates[stratum]=dominates(j)
    return {"groups":groups,"schedule_valid":schedule_valid,"actual_descriptors_valid":actual_valid,
            "exact_cell_coverage":exact_coverage,"identity_inventory_valid":identity_valid,
            "descriptive_stratum_gates":gates,
            "assembly_vs_json_gates":representation_gates}


def run(*,output,model_id,model_path,binary,clang,rustc):
    started=time.monotonic_ns();registration=validate_registration();protocol=read(HERE/"PROTOCOL.json")
    if os.environ.get("LLAMA_ARG_REPACK")!="0":
        raise ValueError("LLAMA_ARG_REPACK=0 is required")
    models=protocol["models"];ids=[m["id"] for m in models]
    if model_id not in ids:
        raise ValueError("unregistered model")
    model_index=ids.index(model_id);model=models[model_index];actual_model=file_identity(model_path)
    if (actual_model["bytes"],actual_model["sha256"])!=(model["bytes"],model["sha256"]):
        raise ValueError("model differs from registered official file")
    tools={name:file_identity(value) for name,value in (("binary",binary),("clang",clang),("rustc",rustc))}
    runtime=runtime_bindings(binary)
    check_qualified_tools(tools, runtime)
    root=Path(output).absolute()
    if not root.exists():
        if model_index!=0:
            raise ValueError("first registered family must begin the cohort")
        root.mkdir(parents=True)
        evaluator.save(root/"SUITE_PLAN.json",{"protocol":protocol,"registration_sha256":file_identity(HERE/"REGISTRATION.json")["sha256"],
            "sources":registration["sources"],"tools":tools,"runtime_files":runtime,"models":models,"started_unix_ns":time.time_ns(),"model_requests_before_plan":0})
    suite=read(root/"SUITE_PLAN.json")
    if (suite["tools"]!=tools or suite["runtime_files"]!=runtime
            or suite["sources"]!=registration["sources"] or suite["models"]!=models or suite["protocol"]!=protocol
            or suite["registration_sha256"]!=file_identity(HERE/"REGISTRATION.json")["sha256"]):
        raise ValueError("cohort tool/registration identity differs")
    if any(not (root/earlier/"MODEL_RESULT.json").is_file() for earlier in ids[:model_index]):
        raise ValueError("earlier family must have a terminal result")
    folder=root/model_id;folder.mkdir(exist_ok=False)
    tasks=fixtures.make_fixtures();by_id={t["id"]:t for t in tasks}
    order=scheduled_cells(tasks,model_id,model_index)
    evaluator.save(folder/"PLAN.json",{"model":model,"model_file":actual_model,"protocol":protocol,"sources":registration["sources"],"tools":tools,"runtime_files":runtime,"scheduled_cells":order})
    result={"schema":SCHEMA,"status":"incomplete","model":model,"cells":[],"engines":[],"cell_identity_checks":[],"manual_time_ns":None,"human_repairs":0,
            "registration_sha256":suite["registration_sha256"],"sources":registration["sources"],
            "tools":tools,"runtime_files":runtime}
    engine=None;engine_started=None

    def close_engine():
        nonlocal engine
        if engine is None:
            return
        record={"path":str(engine.output),"started_requests":engine.generation_count,"responses_received":engine.response_count}
        try:
            record["identity"]=engine.verify_final_identity()
        finally:
            close_started=time.monotonic_ns();engine.close();record["close_wall_ns"]=time.monotonic_ns()-close_started
            record["lifecycle_wall_ns"]=time.monotonic_ns()-engine_started
            record["process_exited"]=engine.process.poll() is not None
            result["engines"].append(record);engine=None
        if not record["process_exited"] or not record["identity"]["model_unchanged"] or not record["identity"]["runtime_unchanged"]:
            raise RuntimeError("owned model/runtime identity or shutdown failed")

    try:
        control_started=time.monotonic_ns()
        controls=evaluator.reference_controls(tasks,folder/"controls",clang,rustc)
        result["reference_controls"]={"count":controls["count"],"passed":controls["passed"],"wall_ns":time.monotonic_ns()-control_started}
        if controls["passed"]!=controls["count"]:
            raise RuntimeError("reference controls failed before first model request")
        for cell in order:
            validate_registration()
            if engine is None:
                engine_started=time.monotonic_ns()
                engine=EnvelopeEngine(binary=binary,model=model_path,model_sha256=model["sha256"],
                    output_dir=folder/("engine-"+str(len(result["engines"])).zfill(2)),threads=protocol["threads"],context=protocol["context_tokens"])
                validate_runtime_environment(engine)
                evaluator.save(engine.output/"STARTUP.json",{"wall_ns":time.monotonic_ns()-engine_started})
            row,usable=run_cell(cell,by_id[cell["task"]],folder/cell["id"],engine,clang,rustc,registration["sources"],protocol)
            result["cells"].append(row)
            identities=check_cell_identities(registration,actual_model,tools,runtime,binary,model_path,folder/cell["id"])
            result["cell_identity_checks"].append({"cell":cell["id"],**identities})
            if not identities["passed"]:
                raise RuntimeError("source/model/tool/runtime drift at cell boundary; no next cell")
            print(json.dumps({"model":model_id,"cell":cell["id"],"status":row["status"],"attempts":len(row["attempts"])}),flush=True)
            if not usable:
                close_engine()
                if row["status"] in {"native_infrastructure_failure","generation_infrastructure_failure"}:
                    raise RuntimeError("native/generation infrastructure failure invalidates cohort")
        result["status"]="all_cells_attempted"
    except Exception as error:
        result["error"]={"type":type(error).__name__,"message":str(error)}
    finally:
        try:
            close_engine()
        except Exception as error:
            result.update(status="incomplete",shutdown_or_identity_error=str(error))
        result["sources_unchanged"]=check_bindings(registration["sources"])
        result["tools_unchanged"]=all(file_identity(item["path"])==item for item in tools.values()) and runtime_bindings(binary)==runtime
        result["model_unchanged"]=file_identity(model_path)==actual_model
        result["coverage_complete"]=len(result["cells"])==len(order)
        result["valid_observation"]=result["status"]=="all_cells_attempted" and all(result[k] for k in ("sources_unchanged","tools_unchanged","model_unchanged","coverage_complete"))
        result["usage_complete"]=result["coverage_complete"] and all(row["usage_complete"] for row in result["cells"])
        result["new_requests"]=sum(e["started_requests"] for e in result["engines"])
        result["responses_received"]=sum(e["responses_received"] for e in result["engines"])
        result["summary"]=summarize_cells(result["cells"],order,result["cell_identity_checks"])
        result["coverage_complete"]=result["summary"]["exact_cell_coverage"]
        result["valid_observation"] = bool(result["valid_observation"] and result["coverage_complete"]
            and result["summary"]["identity_inventory_valid"]
            and all(group["identity_coverage_complete"] for group in result["summary"]["groups"].values()))
        result["experiment_wall_ns"]=time.monotonic_ns()-started
        evaluator.save(folder/"MODEL_RESULT.json",result)
    return result


def review_model_result(result, model_plan, suite, model, model_index):
    """Recompute gates only after exact model/source/tool/registration binding."""
    expected = scheduled_cells(fixtures.make_fixtures(), model["id"], model_index)
    if (result.get("schema") != SCHEMA or result.get("model") != model
            or model_plan.get("model") != model or model_plan.get("protocol") != suite["protocol"]
            or model_plan.get("scheduled_cells") != expected
            or result.get("registration_sha256") != suite["registration_sha256"]
            or (model_plan.get("model_file", {}).get("bytes"), model_plan.get("model_file", {}).get("sha256"))
               != (model["bytes"], model["sha256"])):
        raise ValueError("cohort model, protocol, registration or scheduled descriptor mismatch")
    for key in ("sources", "tools", "runtime_files"):
        if result.get(key) != suite[key] or model_plan.get(key) != suite[key]:
            raise ValueError("cohort source/tool/runtime binding mismatch")
    computed = summarize_cells(result["cells"], expected, result["cell_identity_checks"])
    if computed != result.get("summary"):
        raise ValueError("reported model gates differ from raw cell/identity recomputation")
    accepted = bool(result.get("valid_observation") is True and result.get("status") == "all_cells_attempted"
        and all(result.get(key) is True for key in ("sources_unchanged", "tools_unchanged", "model_unchanged"))
        and computed["exact_cell_coverage"] and computed["identity_inventory_valid"]
        and all(group["identity_coverage_complete"] for group in computed["groups"].values()))
    return {**result, "summary": computed, "valid_observation": accepted,
            "cohort_identity_bound_and_gates_recomputed": True}


def summarize(output):
    root=Path(output);plan=read(root/"SUITE_PLAN.json")
    registration=validate_registration();protocol=read(HERE/"PROTOCOL.json")
    if (plan["protocol"] != protocol or plan["models"] != protocol["models"]
            or plan["sources"] != registration["sources"]
            or plan["registration_sha256"] != file_identity(HERE/"REGISTRATION.json")["sha256"]):
        raise ValueError("cohort plan differs from current frozen registration")
    check_qualified_tools(plan["tools"], plan["runtime_files"])
    models=[]
    for model_index, model in enumerate(protocol["models"]):
        folder=root/model["id"]
        if not (folder/"MODEL_RESULT.json").is_file():
            models.append({"model":model,"status":"not_run","valid_observation":False})
            continue
        try:
            checked=review_model_result(read(folder/"MODEL_RESULT.json"),read(folder/"PLAN.json"),plan,model,model_index)
            expected_ids={cell["id"] for cell in scheduled_cells(fixtures.make_fixtures(),model["id"],model_index)}
            for row in checked["cells"]:
                if row["id"] not in expected_ids or read(folder/row["id"]/"CELL.json") != row:
                    raise ValueError("model aggregate differs from retained raw cell")
            for row in checked["cell_identity_checks"]:
                if row["cell"] not in expected_ids or read(folder/row["cell"]/"BOUNDARY_IDENTITIES.json") != {
                        key:value for key,value in row.items() if key != "cell"}:
                    raise ValueError("model aggregate differs from retained boundary identity")
            models.append(checked)
        except (ValueError, KeyError, TypeError, OSError) as error:
            models.append({"model":model,"status":"readout_rejected","valid_observation":False,
                           "error":{"type":type(error).__name__,"message":str(error)}})
    valid=all(m["valid_observation"] for m in models)
    result={"schema":SCHEMA+".cohort","models":models,"complete_valid_coverage":valid,
        "cross_family_gates":{s:bool(valid and all(m.get("summary",{}).get("descriptive_stratum_gates",{}).get(s,False) for m in models))
                              for s in ("maintenance","upgrade")},
        "cross_family_assembly_vs_json_gates":{s:bool(valid and all(m.get("summary",{}).get("assembly_vs_json_gates",{}).get(s,False) for m in models))
                              for s in ("maintenance","upgrade")},
        "claims":{"general_agent_advantage":False,"large_project_coverage":False,"human_time_measured":False,"population_superiority_proved":False,
                  "query_vs_full_context_advantage_measured":False,"old_results_rescored":False,"reference_answers_scored":False}}
    evaluator.save(root/"RESULT.json",result)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);commands=parser.add_subparsers(dest="action",required=True)
    commands.add_parser("register");commands.add_parser("validate")
    run_parser=commands.add_parser("run")
    for name in ("output","model-id","model-path","binary","clang","rustc"):
        run_parser.add_argument("--"+name,required=True)
    summary=commands.add_parser("summarize");summary.add_argument("--output",required=True)
    args=vars(parser.parse_args());action=args.pop("action")
    result={"register":register,"validate":validate_registration,"run":run,"summarize":summarize}[action](**args)
    print(json.dumps({"action":action,"status":result.get("status","completed"),"model_requests":result.get("new_requests",0)}),flush=True)
    return 1 if result.get("status")=="incomplete" else 0


if __name__=="__main__":
    raise SystemExit(main())
