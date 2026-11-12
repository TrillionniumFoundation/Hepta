#!/usr/bin/env python3
"""Non-generative capacity check: no /completion request and no task answer."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from experiments.hia_agent_matched_v3_20261028 import fixtures,evaluator
from experiments.hia_agent_matched_v3_20261028.engine import EnvelopeEngine
from experiments.hia_agent_matched_v3_20261028.run_study import validate_runtime_environment
from tools.provider_adapter.llama_cpp_engine import canonical,file_identity


def run(output,binary,qwen,granite):
    folder=Path(output);folder.mkdir(parents=True,exist_ok=False)
    protocol=json.loads(Path(__file__).with_name("PROTOCOL.json").read_bytes())
    if os.environ.get("LLAMA_ARG_REPACK")!="0":
        raise ValueError("registered no-repack runtime required")
    started=time.monotonic_ns();results=[]
    paths={"qwen_coder1_5b":qwen,"granite2b":granite}
    for model in protocol["models"]:
        engine=None;record={"model":model,"model_requests":0,"responses":0,"rows":[],"status":"incomplete"}
        model_started=time.monotonic_ns()
        try:
            actual=file_identity(paths[model["id"]]);record["model_file"]=actual
            if (actual["bytes"],actual["sha256"])!=(model["bytes"],model["sha256"]):
                raise RuntimeError("model identity mismatch")
            engine=EnvelopeEngine(binary=binary,model=paths[model["id"]],model_sha256=model["sha256"],
                output_dir=folder/model["id"],threads=protocol["threads"],context=protocol["context_tokens"])
            record["startup_including_hash_ns"]=time.monotonic_ns()-model_started
            validate_runtime_environment(engine)
            for task in fixtures.make_fixtures():
                for language in ("hia","rust"):
                    prompt=fixtures.prompt(task,language)
                    rendered=engine.request("/apply-template",{"messages":[{"role":"user","content":prompt}]})["prompt"]
                    inputs=engine.tokenize(rendered,special=True)
                    reference=engine.tokenize(canonical({"files":task["correct_"+language]}).decode(),special=False)
                    record["rows"].append({"task":task["id"],"language":language,"prompt_tokens":len(inputs),
                        "reference_response_tokens":len(reference),"maximum_response_tokens":protocol["max_output_tokens"],
                        "prompt_and_budget_fit":len(inputs)+protocol["max_output_tokens"]<=protocol["context_tokens"],
                        "reference_plus_eos_fits":len(reference)+1<=protocol["max_output_tokens"],
                        "reference_use":"token count only; never added to generation prompt or decoder schema"})
            status_path=Path("/proc",str(engine.process.pid),"status")
            record["server_memory_status"]=[line for line in status_path.read_text().splitlines() if line.startswith(("VmRSS:","VmHWM:"))]
            record["status"]="checked"
        except Exception as error:
            record["error"]={"type":type(error).__name__,"message":str(error)}
        finally:
            if engine is not None:
                record["model_requests"]=engine.generation_count;record["responses"]=engine.response_count
                try:
                    record["identity"]=engine.verify_final_identity()
                finally:
                    engine.close();record["server_exited"]=engine.process.poll() is not None
            record["wall_ns"]=time.monotonic_ns()-model_started
            record["passed"]=bool(record["status"]=="checked" and record["model_requests"]==0 and record["responses"]==0
                and record.get("server_exited") and record.get("identity",{}).get("model_unchanged")
                and record.get("identity",{}).get("runtime_unchanged")
                and all(r["prompt_and_budget_fit"] and r["reference_plus_eos_fits"] for r in record["rows"]))
            results.append(record)
            evaluator.save(folder/(model["id"]+".json"),record)
    result={"schema":"hepta.agent.matched.non-generative-capacity.v1","models":results,
        "passed":all(r["passed"] for r in results),"model_requests":sum(r["model_requests"] for r in results),
        "wall_ns":time.monotonic_ns()-started,"no_generated_answers":True}
    evaluator.save(folder/"RESULT.json",result)
    return result


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("output","binary","qwen","granite"):
        parser.add_argument("--"+name,required=True)
    value=run(**vars(parser.parse_args()))
    print(json.dumps({"passed":value["passed"],"model_requests":value["model_requests"],"wall_ns":value["wall_ns"]}),flush=True)
    raise SystemExit(not value["passed"])
