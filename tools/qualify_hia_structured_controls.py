#!/usr/bin/env python3
"""Frozen no-model controls for real HIA/Rust structured edit transactions."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.hia_agent_factorial_v4_20261028 import calibration, evaluator, fixtures
from experiments.hia_agent_structured_v7_20261029 import editing
from experiments.hia_agent_structured_v7_20261029.session import ValidatedTaskSession
from tools.qualify_hia_agent_primitive_repair import runtime_preflight
from tools.provider_adapter.llama_cpp_engine import file_identity

HERE = ROOT / "experiments/hia_agent_structured_v7_20261029"


def bindings():
    paths = [*ROOT.joinpath("hepta").glob("*.py"), *HERE.glob("*.py"), HERE / "PROTOCOL.json", Path(__file__).resolve(),
             ROOT / "tools/qualify_hia_agent_primitive_repair.py", ROOT / "tools/provider_adapter/llama_cpp_engine.py",
             ROOT / "tests/test_hia_agent_structured.py"]
    for version in (4,5,6):
        folder = ROOT / ("experiments/hia_agent_factorial_v" + str(version) + "_20261028")
        paths += [*folder.glob("*.py"), folder / "PROTOCOL.json"]
    return {str(path.relative_to(ROOT)):file_identity(path)["sha256"] for path in sorted(paths)}


def source_node(query, file, text, *, category="expression", occurrence=0):
    matches = [node for node in query["edit_query"]["nodes"] if node.get("file") == file and node.get("text") == text and node.get("category") == category]
    if occurrence >= len(matches):
        raise RuntimeError("control selector is absent from actual parsed source")
    return matches[occurrence]["id"]


def rust_edit(query, file, text, replacement, *, category="expression", occurrence=0):
    return {"node":source_node(query,file,text,category=category,occurrence=occurrence),"changes":{"text":replacement}}


def hia_control_task(index):
    """Dedicated controls derived from already public calibration semantics.

    These are human reference controls, never model answers or edit hints. Main
    task/hidden-case records and the old calibration results are not changed.
    """
    task = copy.deepcopy(calibration.problems()[index])
    op, fn = fixtures.op, fixtures.fn
    if index == 0:
        api = fn("span",[("a","u32"),("b","u32")],["u64"],[
            op("int.cast",["a"],"aw","u64"),op("int.cast",["b"],"bw","u64"),
            op("const",[],"factor","u64",value=2),op("int.mul.wrap",["aw","factor"],"product","u64"),
            op("int.add.wrap",["product","bw"],"value","u64")],["value"])
        client = fn("entrypoint",fixtures.PARAMS,["u64"],[
            op("call",["a","b"],"value","u64",function="span"),op("int.cast",["c"],"cw","u64"),
            op("int.add.wrap",["value","cw"],"answer","u64")],["answer"])
    else:
        api = fn("span",[("a","u16"),("b","u16")],["u32"],[
            op("int.cast",["a"],"aw","u32"),op("int.cast",["b"],"bw","u32"),
            op("int.mul.wrap",["aw","bw"],"product","u32")],["product"])
        client = fn("entrypoint",fixtures.PARAMS,["u64"],[
            op("int.cast",["a"],"small_a","u16"),op("int.cast",["b"],"small_b","u16"),
            op("call",["small_a","small_b"],"value","u32",function="span"),
            op("int.cast",["value"],"wide","u64"),op("int.cast",["c"],"cw","u64"),
            op("int.add.wrap",["wide","cw"],"answer","u64")],["answer"])
    task["original_hia"] = {"api.hia.json":api,"client.hia.json":client}
    return task


def run(output, clang, rustc):
    root=Path(output);root.mkdir(parents=True,exist_ok=False)
    started=time.monotonic_ns();preflight=runtime_preflight()
    head=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    if subprocess.check_output(["git","status","--porcelain","--untracked-files=no"],cwd=ROOT,text=True).strip():
        raise RuntimeError("commit tracked source before native controls")
    source=bindings()
    tracked=set(subprocess.check_output(["git","ls-files"],cwd=ROOT,text=True).splitlines())
    if not set(source).issubset(tracked):
        raise RuntimeError("all control source bindings must be tracked")
    plan={"schema":"hepta.agent.structured-controls.v1","source_commit":head,"source_bindings":source,
          "model_requests":0,"model_answers":0,"native_controls_are_agent_successes":False,
          "runtime_preflight":preflight,"tools":{"clang":file_identity(clang),"rustc":file_identity(rustc)}}
    evaluator.save(root/"PLAN.json",plan)
    for name,expected in source.items():
        destination=root/"source_snapshot"/name;destination.parent.mkdir(parents=True,exist_ok=True)
        data=(ROOT/name).read_bytes();destination.write_bytes(data)
        if file_identity(destination)["sha256"]!=expected:
            raise RuntimeError("snapshot drift")
    rows=[]
    def apply(ident,session,edits,accepted,status=None,old_response=None):
        query=session.query()
        response=old_response if old_response is not None else session.response(query,edits)
        result=session.apply(response,root/ident)
        good=result["accepted"] is accepted and result["failed_transaction_left_source_unchanged"]
        if status is not None:
            good=good and result["status"]==status
        hidden=None
        if accepted:
            task=session._task
            hidden=evaluator.execute(result["build"],task,task["hidden_cases"],task["hidden_expected"])
            evaluator.save(root/ident/"CONTROL_HIDDEN.json",hidden)
            good=good and hidden["status"]=="correct" and hidden["artifact_unchanged"]
        rows.append({"id":ident,"passed":bool(good),"model_answer":False,"transaction":result,"hidden_control":hidden})
        print(json.dumps({"control":ident,"passed":bool(good),"status":result["status"]}),flush=True)
        return response

    task=calibration.problems()[0]
    session=ValidatedTaskSession(task,"rust",clang=clang,rustc=rustc)
    query=session.query()
    edits=[rust_edit(query,"api.rs","(a as u64)","(4*(a as u64))"),
           rust_edit(query,"client.rs","api::span(a,b)","api::span(a,b)+(c as u64)")]
    old=apply("rust_two_file_scalar_nodes",session,edits,True,"correct")
    apply("rust_stale_revision_replay",session,[],False,"response_rejected",old_response=old)

    task=calibration.problems()[1]
    session=ValidatedTaskSession(task,"rust",clang=clang,rustc=rustc,interface_policy="migrate")
    query=session.query()
    edits=[{"node":node["id"],"changes":{"text":"u32" if node["text"]=="u16" else "u64"}}
           for node in query["edit_query"]["nodes"] if node.get("file")=="api.rs" and node.get("category")=="type"]
    edits.append(rust_edit(query,"client.rs","(api::span(a as u16,b as u16) as u64)+(c as u64)","api::span(a,b)+(c as u64)"))
    apply("rust_signature_and_callers_atomic",session,edits,True,"correct")

    task=calibration.problems()[2]
    session=ValidatedTaskSession(task,"rust",clang=clang,rustc=rustc)
    query=session.query()
    provider=[rust_edit(query,"api.rs","x","x.wrapping_add(1)")]
    reads=[{"node":node["id"],"changes":{"text":"out"}} for node in query["edit_query"]["nodes"]
           if node.get("file")=="client.rs" and node.get("text")=="buf"
           and session.files["client.rs"][node["end"]:].startswith(("[0]",".len"))]
    apply("rust_borrow_error_keeps_revision",session,provider,False,"compile_rejected")
    apply("rust_public_semantic_error_keeps_revision",session,reads,False,"observable_wrong")
    apply("rust_owner_and_value_nodes",session,provider+reads,True,"correct")

    task=hia_control_task(0)
    session=ValidatedTaskSession(task,"hia",clang=clang,rustc=rustc)
    apply("hia_observable_bug_keeps_revision",session,[{"node":"span/entry/instruction2","changes":{"attrs":{"value":2}}}],False,"observable_wrong")
    apply("hia_real_ssa_batch_native",session,[{"node":"span/entry/instruction2","changes":{"attrs":{"value":4}}}],True,"correct")

    task=hia_control_task(1)
    session=ValidatedTaskSession(task,"hia",clang=clang,rustc=rustc,interface_policy="migrate")
    params=[{"name":"a","type":"u32"},{"name":"b","type":"u32"}]
    edits=[{"node":"span/signature","changes":{"params":params,"returns":["u64"]}},
           {"node":"span/entry/parameters","changes":{"params":params}}]
    edits += [{"node":"span/entry/instruction"+str(index),"changes":{"out":[{"name":name,"type":"u64"}]}}
              for index,name in enumerate(("aw","bw","product"))]
    edits += [{"node":"entrypoint/entry/instruction"+str(index),"changes":{"out":[{"name":name,"type":typ}]}}
              for index,name,typ in ((0,"small_a","u32"),(1,"small_b","u32"),(2,"value","u64"))]
    apply("hia_signature_nodes_native",session,edits,True,"correct")

    result={**plan,"count":len(rows),"passed":sum(row["passed"] for row in rows),"rows":rows,
            "source_unchanged":bindings()==source,"tools_unchanged":all(file_identity(t["path"])==t for t in plan["tools"].values()),
            "experiment_wall_ns":time.monotonic_ns()-started,"model_requests":0,"main_cells_started":0,
            "agent_efficiency_measured":False}
    evaluator.save(root/"CONTROLS.json",result)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",required=True);parser.add_argument("--clang",required=True);parser.add_argument("--rustc",required=True)
    result=run(**vars(parser.parse_args()))
    print(json.dumps({k:result[k] for k in ("count","passed","source_unchanged","tools_unchanged","model_requests")}))
    return 0 if result["count"]==result["passed"] and result["source_unchanged"] and result["tools_unchanged"] else 1


if __name__=="__main__":
    raise SystemExit(main())
