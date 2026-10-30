#!/usr/bin/env python3
"""Native hostile-candidate controls for provider obligations.

These deliberately return correct public entry results while violating the
provider contract. They must be rejected by the separate provider observation,
not accidentally by an unrelated response-format or compiler error.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from experiments.hia_agent_matched_v3_20261028 import fixtures, evaluator
from experiments.hia_optimizer_eval.next_20261028.upgrade_pilot import op
from tools.provider_adapter.llama_cpp_engine import canonical


def inline_sum(consumer):
    result=copy.deepcopy(consumer)
    operations=result["blocks"][0]["ops"]
    operations[1:1]=[op("int.cast",["a"],"inline_a","u64"),
        op("int.cast",["b"],"inline_b","u64"),op("int.add.wrap",["inline_a","inline_b"],"inline_sum","u64")]
    operations[4]["args"]=["inline_sum"]
    return result


def rename_block(block,prefix):
    names={p["name"]:prefix+p["name"] for p in block["params"]}
    names.update({o["name"]:prefix+o["name"] for operation in block["ops"] for o in operation["out"]})
    for parameter in block["params"]:
        parameter["name"]=names[parameter["name"]]
    for operation in block["ops"]:
        operation["args"]=[names[n] for n in operation["args"]]
        for output in operation["out"]:
            output["name"]=names[output["name"]]
    block["term"]["values"]=[names[n] for n in block["term"]["values"]]


def hostile_candidates():
    task=fixtures.make_fixtures()[0]
    rows=[]
    for language in ("hia","rust"):
        files=copy.deepcopy(task["correct_"+language])
        if language=="hia":
            files["client.hia.json"]["blocks"][0]["ops"][0]["args"]=["b","a"]
        else:
            files["client.rs"]=files["client.rs"].replace("api::total(a,b)","api::total(b,a)")
        rows.append(("wrong_arguments",language,files))
        files=copy.deepcopy(task["correct_"+language])
        if language=="hia":
            provider=files["api.hia.json"]
            provider["blocks"][0]["ops"]=[op("const",[],"answer","u64",value=0)]
            files["client.hia.json"]=inline_sum(files["client.hia.json"])
        else:
            files["api.rs"]="pub fn total(a:u32,b:u32)->u64 { let _ = a; let _ = b; 0 }"
            files["client.rs"]="use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { let _ = api::total(a,b); ((a as u64)+(b as u64)) ^ (((c & 255) as u64)<<48) }"
        rows.append(("wrong_provider_bypassed",language,files))
        files=copy.deepcopy(task["correct_"+language])
        if language=="hia":
            original=files["client.hia.json"]
            call_block=copy.deepcopy(original["blocks"][0]);call_block["id"]="called"
            inline_block=inline_sum(original)["blocks"][0]
            inline_block["id"]="bypassed";inline_block["ops"].pop(0)
            rename_block(call_block,"called_");rename_block(inline_block,"bypassed_")
            entry={"id":"entry","params":copy.deepcopy(original["params"]),
                "ops":[op("const",[],"never","bool",value=False)],
                "term":{"op":"branch","cond":"never","then":{"target":"called","args":["a","b","c"]},
                        "else":{"target":"bypassed","args":["a","b","c"]}}}
            original["blocks"]=[entry,call_block,inline_block]
        else:
            files["client.rs"]="use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { if false { let _ = api::total(a,b); } let answer = ((a as u64)+(b as u64)) ^ (((c & 255) as u64)<<48); answer }"
        rows.append(("provider_not_executed",language,files))
    return task,rows


def run(output,clang,rustc):
    folder=Path(output);folder.mkdir(parents=True,exist_ok=False)
    task,candidates=hostile_candidates();rows=[]
    for name,language,files in candidates:
        built=evaluator.build(task,language,canonical({"files":files}).decode(),folder/(name+"_"+language),clang,rustc)
        observed=evaluator.execute(built,task,task["public_cases"],task["public_expected"]) if built["native_built"] else None
        passed=bool(built["native_built"] and observed["actual"]==task["public_expected"] and observed["status"]=="observable_wrong")
        rows.append({"name":name,"language":language,"build":built,"execution":observed,"passed":passed})
    result={"count":len(rows),"passed":sum(row["passed"] for row in rows),"rows":rows,"model_answers":False}
    evaluator.save(folder/"CONTROLS.json",result)
    return result


if __name__=="__main__":
    import argparse,json
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("output","clang","rustc"):
        parser.add_argument("--"+name,required=True)
    result=run(**vars(parser.parse_args()))
    print(json.dumps({"count":result["count"],"passed":result["passed"]}),flush=True)
    raise SystemExit(result["count"]!=result["passed"])
