#!/usr/bin/env python3
"""Classify retained responses without fixing, compiling, or rescoring them."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[2]
STUDY=ROOT/"experiments/hia_agent_matched_v3_20261028"


def read(path):
    return json.loads(Path(path).read_bytes())


def same_source(language,left,right):
    if language=="hia":return left==right
    return isinstance(left,str) and re.sub(r"\s+","",left)==re.sub(r"\s+","",right)


def diagnose(suite,output):
    suite=Path(suite).resolve(strict=True);output=Path(output).absolute()
    output.mkdir(parents=True,exist_ok=False)
    protocol=read(STUDY/"PROTOCOL.json");tasks={t["id"]:t for t in read(STUDY/"FIXTURES.json")}
    rows=[]
    for model in protocol["models"]:
        folder=suite/model["id"];result=read(folder/"MODEL_RESULT.json")
        for cell in result["cells"]:
            task=tasks[cell["task"]];language=cell["language"];previous_text=None
            for attempt in cell["attempts"]:
                path=folder/cell["id"]/f"attempt-{attempt['index']}.response.json"
                row={"model":model["id"],"cell":cell["id"],"language":language,"index":attempt["index"],
                    "recorded_status":attempt["status"],"task_correct":cell["correct"],"complete_scored_response_available":path.is_file(),
                    "phase":"generation" if "build" not in attempt else "native_compile" if attempt["status"]=="compile_rejected" else "admission" if not attempt["build"]["native_built"] else "native_public",
                    "diagnostic":attempt.get("build",{}).get("error") or attempt.get("error"),
                    "compiler_diagnostic":attempt.get("build",{}).get("compile"),
                    "files_envelope_valid":None,"unchanged_provider":None,"unchanged_consumer":None,"same_text_as_previous_attempt":None}
                if path.is_file():
                    raw=path.read_bytes();response=json.loads(raw);text=response["text"]
                    row.update(response_sha256=hashlib.sha256(raw).hexdigest(),text_sha256=hashlib.sha256(text.encode()).hexdigest(),
                        response_text=text,same_text_as_previous_attempt=previous_text is not None and text==previous_text)
                    previous_text=text;duplicates=[]

                    def pairs(items):
                        data={}
                        for key,value in items:
                            if key in data:duplicates.append(key)
                            data[key]=value
                        return data

                    try:
                        value=json.loads(text,object_pairs_hook=pairs)
                    except (ValueError,TypeError) as error:
                        row.update(json_error=type(error).__name__,files_envelope_valid=False)
                        value=None
                    names=("api.hia.json","client.hia.json") if language=="hia" else ("api.rs","client.rs")
                    typ=dict if language=="hia" else str
                    valid=bool(not duplicates and type(value) is dict and set(value)=={"files"}
                        and type(value["files"]) is dict and set(value["files"])==set(names)
                        and all(type(value["files"][name]) is typ for name in names))
                    row["files_envelope_valid"]=valid
                    row["duplicate_json_keys"]=duplicates
                    if valid:
                        original=task["original_"+language]
                        row["unchanged_provider"]=same_source(language,value["files"][names[0]],original[names[0]])
                        row["unchanged_consumer"]=same_source(language,value["files"][names[1]],original[names[1]])
                        if language=="rust":
                            row["rust_method_names_observed"]=sorted(set(re.findall(r"\.\s*([A-Za-z_][A-Za-z_0-9]*)\s*\(","\n".join(value["files"].values()))))
                message=(row["diagnostic"] or {}).get("message","")
                row["unsupported_method_profile_rejection"]="E_UPGRADE_RUST_METHOD_OUTSIDE_PROFILE" in message
                rows.append(row)
    completed=[r for r in rows if r["complete_scored_response_available"]]
    counts={"submissions":len(rows),"complete_scored_responses":len(completed),
        "valid_files_envelopes":sum(r["files_envelope_valid"] is True for r in completed),
        "unchanged_providers":sum(r["unchanged_provider"] is True for r in completed),
        "unchanged_consumers":sum(r["unchanged_consumer"] is True for r in completed),
        "identical_second_responses":sum(r["same_text_as_previous_attempt"] is True for r in completed),
        "unsupported_method_profile_rejections":sum(r["unsupported_method_profile_rejection"] for r in rows)}
    result={"schema":"hepta.agent.matched-v3.response-diagnosis.v1","suite":str(suite),
        "diagnosis_source_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),"counts":counts,"rows":rows,
        "no_model_calls_compiles_reruns_or_response_repairs":True,
        "scope":"exact-object equality for HIA, whitespace-normalized equality for Rust; this is descriptive response analysis, not semantic equivalence or a new score",
        "prompt_profile_limitation":"Rust prompt describes standard primitive integer methods broadly, but the reused closed admission whitelist excludes some methods (e.g. div_ceil). A method-profile refusal does not establish that the method is valid Rust or that the arithmetic is correct or incorrect; preserve the observed name and raw code. Frozen prompts/whitelist/results were not altered after model requests began."}
    (output/"DIAGNOSIS.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    lines=["# V3 response diagnosis","","This analysis reads the original response bytes and recorded validation outcomes. It does not repair, compile or rescore a candidate.","",
        f"Complete scored responses: {counts['complete_scored_responses']}; valid declared files envelopes: {counts['valid_files_envelopes']}. Unchanged providers: {counts['unchanged_providers']}; unchanged consumers: {counts['unchanged_consumers']}; byte-identical second responses: {counts['identical_second_responses']}.","",
        "The following table separates admission from executed public semantics. A profile refusal does not prove that the program body is semantically wrong.","",
        "| Family | Cell | Submission | Recorded outcome | Envelope valid | Provider unchanged | Repeated text |",
        "| --- | --- | ---: | --- | --- | --- | --- |"]
    for row in rows:
        lines.append(f"| {row['model']} | {row['cell']} | {row['index']+1} | {row['recorded_status']} | {row['files_envelope_valid']} | {row['unchanged_provider']} | {row['same_text_as_previous_attempt']} |")
    lines += ["",result["prompt_profile_limitation"],"",
        "The envelope-only schema does not encode a repair. Its success can remove a transport-format failure while leaving the original semantic bug or interface unchanged. This finite descriptive observation does not establish a general Agent productivity advantage.",""]
    (output/"DIAGNOSIS.md").write_text("\n".join(lines))
    return result


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--suite",required=True);parser.add_argument("--output",required=True)
    result=diagnose(**vars(parser.parse_args()));print(json.dumps(result["counts"]),flush=True)
