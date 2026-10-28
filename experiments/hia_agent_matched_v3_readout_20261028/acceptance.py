#!/usr/bin/env python3
"""Assemble compact acceptance from audited evidence; never execute candidates."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
STUDY=ROOT/"experiments/hia_agent_matched_v3_20261028"


def read(path):
    return json.loads(Path(path).read_bytes())


def identity(path):
    path=Path(path)
    with path.open("rb") as stream:
        return {"path":str(path.relative_to(ROOT)),"bytes":path.stat().st_size,
                "sha256":hashlib.file_digest(stream,"sha256").hexdigest()}


def raw_identity(path):
    path=Path(path)
    with path.open("rb") as stream:
        return {"bytes":path.stat().st_size,"sha256":hashlib.file_digest(stream,"sha256").hexdigest()}


def build(suite):
    suite=Path(suite).resolve(strict=True)
    report=read(HERE/"RESULT.json");diagnosis=read(HERE/"DIAGNOSIS.json")
    protocol=read(STUDY/"PROTOCOL.json");registration=read(STUDY/"REGISTRATION.json")
    suite_plan=read(suite/"SUITE_PLAN.json")
    if Path(report["suite"]).resolve()!=suite or Path(diagnosis["suite"]).resolve()!=suite:
        raise ValueError("readout/diagnosis belong to a different suite")
    if report["registration"]!=raw_identity(STUDY/"REGISTRATION.json") or report["readout_source"]!=raw_identity(HERE/"readout.py"):
        raise ValueError("audited registration or readout source changed")
    if diagnosis["diagnosis_source_sha256"]!=identity(HERE/"diagnose.py")["sha256"]:
        raise ValueError("diagnosis source changed")
    if suite_plan["registration_sha256"]!=report["registration"]["sha256"] or suite_plan["sources"]!=registration["sources"]:
        raise ValueError("suite registration/source closure differs")
    if identity(STUDY/"PROTOCOL.json")["sha256"]!=registration["protocol_sha256"] or identity(STUDY/"FIXTURES.json")["sha256"]!=registration["fixtures_sha256"]:
        raise ValueError("registered protocol or fixtures changed")
    for name,wanted in registration["sources"].items():
        if identity(ROOT/name)["sha256"]!=wanted:
            raise ValueError("registered source changed: "+name)
    for name,wanted in report["evidence"].items():
        relative=Path(name)
        if relative.is_absolute() or ".." in relative.parts or raw_identity(suite/relative)!=wanted:
            raise ValueError("audited raw evidence differs: "+name)
    for row in diagnosis["rows"]:
        if row["complete_scored_response_available"]:
            name=f"{row['model']}/{row['cell']}/attempt-{row['index']}.response.json"
            if report["evidence"].get(name,{}).get("sha256")!=row["response_sha256"]:
                raise ValueError("diagnosis response differs from audited evidence")
    models=[];status_counts=Counter();requests_wall=0;verification=0;boundary=0;outer_ns=0
    for family in report["models"]:
        model=family["model"];result=read(suite/model["id"]/"MODEL_RESULT.json")
        outer=read(STUDY/("QWEN_OUTER.json" if model["id"]=="qwen_coder1_5b" else "GRANITE_OUTER.json"))
        outer_ns+=outer["outer_wall_ns"]
        strata={};model_counts=Counter()
        for cell in result["cells"]:
            for attempt in cell["attempts"]:
                status=attempt["status"]
                if status=="public_passed":
                    status="correct_hidden_validated" if cell["correct"] else cell["status"]
                model_counts[status]+=1
            key=cell["stratum"]
            if key not in strata:strata[key]={"planned_cells":4,"attempted_cells":0,"correct_cells":0}
            strata[key]["attempted_cells"]+=1;strata[key]["correct_cells"]+=int(cell["correct"])
        for group in family["groups"].values():
            requests_wall+=group["request_wall_ns"]
            verification+=group["evaluation_ns"]
            boundary+=group["boundary_identity_ns"]
        status_counts.update(model_counts)
        attempts=[a for c in family["cells"] for a in c["attempts"]]
        lifecycle=[{"path":e["path"],"lifecycle_wall_ns":e["lifecycle_wall_ns"],
            "startup_wall_ns":read(suite/model["id"]/Path(e["path"]).name/"STARTUP.json")["wall_ns"],
            "close_wall_ns":e["close_wall_ns"],"started_requests":e["started_requests"],
            "responses_received":e["responses_received"],"process_exited":e["process_exited"]}
            for e in family["engines"]]
        models.append({"identity":model,"valid_observation":family["valid_observation"],
            "coverage_complete":family["coverage_complete"],"usage_complete":family["usage_complete"],
            "attempted_cells":len(family["cells"]),"correct_cells":sum(c["correct"] for c in family["cells"]),
            "completion_requests":family["completion_requests"],"complete_responses":family["complete_responses"],
            "model_timeouts":model_counts["budget_timeout"],"failure_subtypes":dict(sorted(model_counts.items())),
            "unknown_input_token_submissions":sum(a["input_tokens"] is None for a in attempts),
            "unknown_output_token_submissions":sum(a["output_tokens"] is None for a in attempts),
            "strata":strata,"groups":family["groups"],"registered_gates":family["gates"],
            "engine_processes":len(family["engines"]),"engine_lifecycles":lifecycle,"model_wall_ns":family["model_wall_ns"],
            "outer_process_wall_ns":outer["outer_wall_ns"],"outer_returncode":outer["returncode"],
            "reference_controls":family["reference_controls"],
            "final_source_identity_passed":result["sources_unchanged"],
            "final_tool_identity_passed":result["tools_unchanged"],
            "cell_boundary_identity_checks":result["cell_identity_checks"],
            "all_model_runtime_final_identities_passed":all(e["identity"]["model_unchanged"] and e["identity"]["runtime_unchanged"] and e["process_exited"] for e in family["engines"])})
    totals={**report["totals"],"model_timeouts":status_counts["budget_timeout"],"failure_subtypes":dict(sorted(status_counts.items())),
        "unknown_input_token_submissions":sum(m["unknown_input_token_submissions"] for m in models),
        "unknown_output_token_submissions":sum(m["unknown_output_token_submissions"] for m in models),
        "native_candidate_builds":sum(a.get("build",{}).get("native_built",False) for m in protocol["models"] for c in read(suite/m["id"]/"MODEL_RESULT.json")["cells"] for a in c["attempts"]),
        "public_native_validations":sum(a.get("public_validation") is not None for m in protocol["models"] for c in read(suite/m["id"]/"MODEL_RESULT.json")["cells"] for a in c["attempts"]),
        "hidden_native_validations":sum(c["hidden_tests_evaluated"] for m in protocol["models"] for c in read(suite/m["id"]/"MODEL_RESULT.json")["cells"]),
        "strata":{s:{"planned_cells":8,"attempted_cells":sum(m["strata"].get(s,{}).get("attempted_cells",0) for m in models),
            "correct_cells":sum(m["strata"].get(s,{}).get("correct_cells",0) for m in models)} for s in ("maintenance","upgrade")}}
    if sum(status_counts.values())!=totals["submissions"]:
        raise ValueError("failure classification does not partition submissions")
    archives=[]
    for model_id,filename in zip((m["id"] for m in protocol["models"]),("qwen-run-01.tar.manifest.json","granite-run-01.tar.manifest.json")):
        manifest_path=STUDY/filename;manifest=read(manifest_path)
        archive=STUDY/Path(manifest["archive"]).name;actual=identity(archive)
        if (actual["bytes"],actual["sha256"])!=(manifest["archive_bytes"],manifest["archive_sha256"]) or not manifest["all_member_hashes_verified"]:
            raise ValueError("raw model archive identity or member audit differs")
        prefix=model_id+"/"
        audited_members={name[len(prefix):]:value for name,value in report["evidence"].items() if name.startswith(prefix)}
        if not audited_members or any(manifest["members"].get(name)!=value for name,value in audited_members.items()):
            raise ValueError("raw archive does not contain the exact audited model evidence")
        archives.append({**actual,"member_count":manifest["member_count"],"all_members_verified":True,
            "model_id":model_id,"audited_member_count":len(audited_members),
            "manifest":identity(manifest_path),"pack_and_verify_ns":manifest["pack_and_verify_ns"]})
    capacity=read(STUDY/"TOKENIZER_CAPACITY.json");download=read(STUDY/"QWEN_DOWNLOAD.json")
    files=["RESULT.json","RESULT.md","DIAGNOSIS.json","DIAGNOSIS.md"]
    gates={"maintenance_cross_family":report["cross_family_gates"]["maintenance"],
           "upgrade_cross_family":report["cross_family_gates"]["upgrade"],
           "registered_joint_gate":all(report["cross_family_gates"].values()),
           "full_agent_advantage":False,"user_item6_full_requirement_satisfied":False}
    result={"schema":"hepta.agent.matched-v3.acceptance-readout.v1", "models":models,"totals":totals,"gates":gates,
        "complete_valid_coverage":all(m["valid_observation"] and m["coverage_complete"] for m in models),
        "model_requests_before_registration":registration["model_requests"],
        "registration_unix_ns":registration["registered_unix_ns"],
        "suite_plan_unix_ns":suite_plan["started_unix_ns"],
        "registration":identity(STUDY/"REGISTRATION.json"),"protocol":identity(STUDY/"PROTOCOL.json"),
        "source_binding_count":len(registration["sources"]),"source_bindings":registration["sources"],
        "tool_identities":suite_plan["tools"],"runtime_identities":suite_plan["runtime_files"],
        "runtime_release":protocol["runtime"],"model_process_environment":protocol["runtime_environment"],
        "raw_model_archives":archives,"audited_readout_files":[identity(HERE/name) for name in files],
        "response_diagnosis":diagnosis["counts"],
        "costs":{"outer_process_wall_ns":outer_ns,"model_inner_wall_ns":totals["model_wall_ns"],
            "measured_request_wall_ns_including_timeouts":requests_wall,
            "compile_public_hidden_verification_ns":verification,"boundary_identity_verification_ns":boundary,
            "validation_total_ns":verification+boundary,"qwen_download_ns":download["wall_ns"],
            "qwen_download_bytes":download["bytes"],"non_generative_capacity_check_ns":capacity["wall_ns"],
            "model_reference_control_ns":sum(m["reference_controls"]["wall_ns"] for m in models),
            "owned_engine_startup_ns":sum(e["startup_wall_ns"] for m in models for e in m["engine_lifecycles"]),
            "owned_engine_close_ns":sum(e["close_wall_ns"] for m in models for e in m["engine_lifecycles"]),
            "archive_pack_and_verify_ns":sum(a["pack_and_verify_ns"] for a in archives),
            "manual_labor_time_ns":None,"tool_development_time_ns":None,"monetary_cost":None,
            "scope_notes":["Model inner wall, request wall, validation and engine lifecycles are nested in outer process wall; do not add them twice.",
                "Outer wall spans each launched study process through process exit, including hashing, model startup/shutdown/restarts and actual reference controls.",
                "Download, tokenizer-only preparation and archives are separate measured costs. Existing runtime and Granite weights were reused; historical acquisition/setup is not zero global economic cost.",
                "Reference controls and mock controls are not model answers. Human labor/tool development and the complete implicit system-library dependency closure remain unmeasured.",
                "No models were rerun or replaced after outputs; timeout output usage remains null rather than substituted from partial server logs."]},
        "controls":{"development_reference":{k:read(STUDY/"DEVELOPMENT_CONTROLS.json")[k] for k in ("count","passed")},
            "final_hostile":{k:read(STUDY/"HOSTILE_CONTROLS.json")[k] for k in ("count","passed")},
            "orchestration":{k:read(STUDY/"UNIT_CONTROLS.json")[k] for k in ("tests_run","failures","errors","skipped","passed")},
            "capacity_model_requests":capacity["model_requests"],"initial_hostile_failures_preserved":True},
        "limitations":[diagnosis["prompt_profile_limitation"],
            "Small 1.5B/2B quantized families, new finite arithmetic/API tasks, full context only; no large-project, population or query-efficiency claim.",
            "Same task/target/provider obligations/budget/public feedback/hidden oracle; language-specific syntax and complete original source remain different and all tokens are charged.",
            "HIA provider calls are observed in the same-hashed-Core VM alongside actual native entrypoint execution; Rust provider counters are native.",
            "Resource-limited finite scalar admission is not a general OS sandbox; compiler, runtime, OS and hardware remain trusted."],
        "claims":{"general_agent_advantage":False,"query_advantage":False,"manual_labor_advantage":False,
                  "previous_results_rescored":False,"reference_controls_scored_as_model_answers":False},
        "readout_builder":identity(__file__)}
    path=HERE/"READOUT.json"
    with path.open("x") as stream:json.dump(result,stream,sort_keys=True,indent=2);stream.write("\n")
    return result


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--suite",required=True)
    value=build(**vars(parser.parse_args()));print(json.dumps({"schema":value["schema"],"totals":value["totals"],"gates":value["gates"]}),flush=True)
