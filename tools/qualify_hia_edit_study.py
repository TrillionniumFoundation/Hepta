#!/usr/bin/env python3
"""Frozen two-model, two-language, two-interface maintenance microstudy.

Each task has a real caller: two functions in one HIA module, or a Rust caller
and implementation in two source files. The experiment edits one declared site,
keeps every attempted cell, and executes native positive and buggy controls.
It measures this finite interface bundle, not multi-module HIA maintenance,
general coding productivity, human maintenance labor or total economic cost.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_edit_query import apply_edit, prepare_edit, render_edit_context
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import build_program_native, emit_program_llvm
from hepta.hia_program_tools import decode_json
from tools.provider_adapter.llama_cpp_engine import LlamaCppEngine, canonical, file_identity

ARMS = ("hia_full_context", "hia_edit_query", "rust_full_context", "rust_edit_query")
LIMIT = 256
MINIMUM_SUCCESSES = 7
PROTOCOL = "hepta.hia.edit-study.v1"
SCORED_STATES = frozenset({"correct", "observable_wrong", "expected_overflow_trap", "response_rejected"})


def sha(value):
    return hashlib.sha256(value).hexdigest()


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical(value) + b"\n")


def instruction(kind, args, name, typ="u32", **attrs):
    return {"op": kind, "args": args, "out": [{"name": name, "type": typ}], "attrs": attrs}


def const(name, value):
    return instruction("const", [], name, value=value)


def fixtures():
    """References and cases are never included in a model's request."""
    comparisons = ["compare.lt", "compare.le", "compare.gt", "compare.ge", "compare.eq", "compare.ne"]
    specs = [
        ("capacity", ["used", "capacity"], [instruction("compare.le", ["used", "capacity"], "test", "bool"),
            const("yes", 1), const("no", 0), instruction("select", ["test", "yes", "no"], "answer")],
         "test", "op", "compare.lt", comparisons,
         "if used @SLOT@ capacity {1} else {0}", "<=", "<", ["<", "<=", ">", ">=", "==", "!="],
         "Return 1 exactly when one more item can fit: used is strictly below capacity; otherwise return 0.",
         [[0,0],[0,1],[1,1],[17,18],[19,18],[4294967295,4294967295]]),
        ("low_byte", ["x"], [const("mask",255), instruction("bit.or",["x","mask"],"answer")],
         "answer","op","bit.and",["bit.and","bit.or","bit.xor"],
         "x @SLOT@ 255", "|", "&", ["&","|","^"],
         "Return the low eight bits of x as an unsigned 32-bit value.",
         [[0],[1],[255],[256],[257],[65535],[4294967295]]),
        ("xor_tag", ["x","tag"], [instruction("bit.and",["x","tag"],"answer")],
         "answer","op","bit.xor",["bit.and","bit.or","bit.xor"],
         "x @SLOT@ tag", "&", "^", ["&","|","^"],
         "Return the bitwise exclusive-or of the unsigned words x and tag.",
         [[0,0],[0,1],[1,1],[170,85],[255,15],[4294967295,4294967295]]),
        ("triple",["x"],[const("factor",2),instruction("int.mul.wrap",["x","factor"],"answer")],
         "factor","attrs",{"value":3},[{"value":x} for x in range(8)],
         "x.wrapping_mul(@SLOT@)","2","3",[str(x) for x in range(8)],
         "Return three times x modulo 2^32.",[[0],[1],[17],[1431655766],[2147483648],[4294967295]]),
        ("distance",["end","start"],[instruction("int.add.wrap",["end","start"],"answer")],
         "answer","op","int.sub.wrap",["int.add.wrap","int.sub.wrap","int.mul.wrap"],
         "end.@SLOT@(start)","wrapping_add","wrapping_sub",["wrapping_add","wrapping_sub","wrapping_mul"],
         "Return end minus start modulo 2^32, including wraparound.",
         [[0,0],[9,4],[4,9],[0,1],[4294967295,1],[1,4294967295]]),
        ("next_epoch",["x"],[const("one",1),instruction("int.add.checked",["x","one"],"answer")],
         "answer","op","int.add.wrap",["int.add.checked","int.add.wrap","int.sub.wrap"],
         "x.@SLOT@(1)","checked_add(1).unwrap_or_else(|| panic!(\"overflow\")); x.wrapping_add", "wrapping_add", ["wrapping_add","wrapping_sub"],
         "Increment x modulo 2^32; the maximum u32 value must produce zero without terminating.",
         [[0],[1],[17],[4294967294],[4294967295]]),
        ("minimum",["a","b"],[instruction("compare.gt",["a","b"],"test","bool"),
            instruction("select",["test","a","b"],"answer")],
         "test","op","compare.lt",comparisons,
         "if a @SLOT@ b {a} else {b}",">","<",["<","<=",">",">=","==","!="],
         "Return the smaller unsigned value of a and b; equal values remain unchanged.",
         [[0,0],[0,1],[1,0],[17,29],[29,17],[4294967295,1],[4294967295,4294967295]]),
        ("ceil_half",["x"],[const("one",1),instruction("int.shr.checked",["x","one"],"half"),
            instruction("bit.or",["x","one"],"odd"),instruction("int.add.wrap",["half","odd"],"answer")],
         "odd","op","bit.and",["bit.and","bit.or","bit.xor"],
         "(x >> 1).wrapping_add(x @SLOT@ 1)","|","&",["&","|","^"],
         "Return ceil(x/2) for every unsigned 32-bit input, including the maximum value.",
         [[0],[1],[2],[3],[18],[19],[4294967294],[4294967295]]),
    ]
    result=[]
    for ident,names,ops,output,field,good,allowed,body,bad,rust_good,rust_allowed,description,cases in specs:
        params=[{"name":name,"type":"u32"} for name in names]
        kernel={"name":"kernel","params":params,"returns":["u32"],"effects":["trap"],"entry":"entry",
                "blocks":[{"id":"entry","params":params,"ops":ops,"term":{"op":"ret","values":["answer"]}}]}
        caller={"name":"entrypoint","params":params,"returns":["u32"],"effects":["trap"],"entry":"entry",
                "blocks":[{"id":"entry","params":params,
                    "ops":[instruction("call",names,"result",function="kernel")],
                    "term":{"op":"ret","values":["result"]}}]}
        program={"schema":"hepta.hia.program.v6","module":"maintenance_"+ident,"exports":["entrypoint"],
                 "functions":[kernel,caller]}
        signature="pub fn kernel("+",".join(n+":u32" for n in names)+")->u32"
        # The overflow task uses an explicit checked method with the same call
        # shape as the wrapping repair; all admitted expressions are frozen.
        if ident=="next_epoch":
            body="@SLOT@";bad='x.checked_add(1).expect("overflow")';rust_good="x.wrapping_add(1)"
            rust_allowed=[bad,rust_good,"x.wrapping_sub(1)"]
        template=signature+"{"+body+"}"
        task={"id":ident,"description":description,"names":names,"hia":program,"output":output,"field":field,
              "good":good,"allowed":allowed,"rust_template":template,"rust_bad":bad,"rust_good":rust_good,
              "rust_allowed":rust_allowed,"cases":cases,"rust_signature":signature,"rust_body":body}
        verify_program(program)
        result.append(task)
    return result


def expected(task):
    result=[]
    for values in task["cases"]:
        a=values[0]; b=values[1] if len(values)>1 else None
        kind=task["id"]
        value=(int(a<b) if kind=="capacity" else a%256 if kind=="low_byte" else
               a^b if kind=="xor_tag" else a*3 if kind=="triple" else
               a-b if kind=="distance" else a+1 if kind=="next_epoch" else
               min(a,b) if kind=="minimum" else (a+1)//2)
        result.append(value%(1<<32))
    return result


def query_for(task):
    return prepare_edit(task["hia"],function="kernel",block="entry",output=task["output"],fields=[task["field"]])


def rust_caller(task):
    params=",".join(n+":u32" for n in task["names"])
    return "mod kernel;\nfn entrypoint("+params+")->u32{kernel::kernel("+",".join(task["names"])+")}"


def prompt(task,arm):
    hia=arm.startswith("hia")
    if hia:
        context=(canonical(task["hia"]).decode() if arm=="hia_full_context" else render_edit_context(query_for(task)))
        original=query_for(task)["context"]["operation"][task["field"]]
        response={task["field"]:original}
        rules="HIA uses typed values. .wrap means modulo word width; .checked traps on overflow. bit.and/or/xor are bitwise operations. compare.lt/le/gt/ge/eq/ne compare unsigned values here."
        site="kernel / entry / output "+task["output"]+"; replace only "+task["field"]
    else:
        context=("kernel.rs:\n"+task["rust_template"].replace("@SLOT@",task["rust_bad"])+"\nmain.rs:\n"+rust_caller(task)
                 if arm=="rust_full_context" else task["rust_signature"]+"\nExpression template: "+task["rust_body"]+"\nCurrent @SLOT@: "+task["rust_bad"])
        response={"replacement":task["rust_bad"]};rules="Rust inputs and results are u32. wrapping methods are modulo 2^32. Checked arithmetic may terminate."
        site="the @SLOT@ expression/operator in kernel; preserve the caller and interface"
    structure = ("two functions in one HIA module" if hia else "a Rust caller and kernel in two source files")
    return ("Repair one implementation site in this cross-function maintenance task ("+structure+"). Return ONLY a JSON object; no code fences or explanation.\n"
            +"Specification: "+task["description"]+"\n"+rules+"\nSite: "+site+"\nContext:\n"+context
            +"\nCorrect the value in this response object; unchanged identity fields are retained by the host:\n"+canonical(response).decode())


def parse_response(task,arm,text):
    if type(text) is not str or len(text.encode())>16*1024:
        raise ValueError("E_STUDY_RESPONSE")
    edit=decode_json(text.strip())
    if arm.startswith("hia"):
        if type(edit) is not dict or set(edit)!={task["field"]}:
            raise ValueError("E_STUDY_FIELDS")
        value=edit[task["field"]]
        if not any(type(value) is type(option) and value==option for option in task["allowed"]):
            raise ValueError("E_STUDY_SITE")
        return apply_edit(task["hia"],query_for(task),edit)[0]
    if (type(edit) is not dict or set(edit)!={"replacement"} or type(edit["replacement"]) is not str
            or edit["replacement"] not in task["rust_allowed"]):
        raise ValueError("E_STUDY_RUST_SITE")
    return task["rust_template"].replace("@SLOT@",edit["replacement"])


def _expects_overflow(task,candidate,language):
    if task["id"]!="next_epoch":
        return False
    if language=="rust":
        return candidate==task["rust_template"].replace("@SLOT@",task["rust_bad"])
    fn=next(f for f in candidate.as_dict()["functions"] if f["name"]=="kernel")
    return any(op["op"]=="int.add.checked" and any(v["name"]==task["output"] for v in op["out"])
               for block in fn["blocks"] for op in block["ops"])


def classify_execution(task,language,returncode,stdout,stderr,*,overflow_expected=False):
    """Recognize actual call transcripts; loader/process errors are not bugs found."""
    base={"ok":False,"native_executed":False,"status":"infrastructure_error","actual":None,
          "expected":expected(task),"returncode":returncode,"stdout":stdout,"stderr":stderr}
    lines=stdout.splitlines()
    wanted=expected(task)
    if returncode==0 and lines and lines[0]=="STUDY_READY" and lines[-1]=="STUDY_DONE":
        actual=[]
        if len(lines)!=2+2*len(task["cases"]):
            return {**base,"reason":"incomplete native case transcript"}
        for index in range(len(task["cases"])):
            if lines[1+2*index]!="STUDY_CALL "+str(index):
                return {**base,"reason":"native call identity mismatch"}
            value=re.fullmatch(r"STUDY_VALUE "+str(index)+r" ([0-9]+)",lines[2+2*index])
            if value is None or not 0<=int(value[1])<2**32:
                return {**base,"reason":"invalid native result framing"}
            actual.append(int(value[1]))
        return {**base,"ok":actual==wanted,"native_executed":True,"actual":actual,
                "status":"correct" if actual==wanted else "observable_wrong"}
    # The one predeclared trapping candidate reaches the last, maximum-u32
    # case after returning every earlier correct value. Nothing else may use
    # a signal, panic, loader error or timeout as evidence of detecting a bug.
    prefix=["STUDY_READY"]
    for index,value in enumerate(wanted[:-1]):
        prefix += ["STUDY_CALL "+str(index),"STUDY_VALUE "+str(index)+" "+str(value)]
    prefix += ["STUDY_CALL "+str(len(wanted)-1)]
    actual_trap=(returncode==-signal.SIGABRT and not stderr.strip() if language=="hia" else
                 returncode==101 and "panicked at" in stderr and "overflow" in stderr)
    if task["id"]=="next_epoch" and overflow_expected and lines==prefix and actual_trap:
        return {**base,"native_executed":True,"status":"expected_overflow_trap",
                "completed_values":wanted[:-1],"trapping_case":len(wanted)-1}
    return {**base,"reason":"native execution did not produce a recognized value or expected trap"}


def native(task,candidate,language,directory,clang,rustc):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=False)
    record={"ok":False,"native_executed":False,"status":"infrastructure_error","expected":expected(task)}
    try:
        compiler=clang if language=="hia" else rustc
        compiler_before=file_identity(compiler)
        record["compiler_identity"]=compiler_before
        if language=="hia":
            (directory/"candidate.hia").write_bytes(candidate.canonical_bytes)
            (directory/"candidate.ll").write_text(emit_program_llvm(candidate).text)
            binary=directory/"candidate.so"
            record["compile"]=build_program_native(candidate,binary,clang=clang)
            runner=("import ctypes,json,sys,resource\nresource.setrlimit(resource.RLIMIT_CORE,(0,0))\n"
                    "lib=ctypes.CDLL(sys.argv[1]);f=lib.entrypoint\n"
                    "cases=json.loads(sys.argv[2]);f.argtypes=[ctypes.c_uint32]*len(cases[0]);f.restype=ctypes.c_uint32\n"
                    "print('STUDY_READY',flush=True)\n"
                    "for i,x in enumerate(cases):\n print('STUDY_CALL',i,flush=True)\n v=f(*x)\n print('STUDY_VALUE',i,v,flush=True)\n"
                    "print('STUDY_DONE',flush=True)\n")
            command=[sys.executable,"-c",runner,str(binary),json.dumps(task["cases"])]
        else:
            (directory/"kernel.rs").write_text(candidate)
            calls=[]
            for index,case in enumerate(task["cases"]):
                expression="entrypoint("+",".join(str(x)+"u32" for x in case)+")"
                calls.append('println!("STUDY_CALL '+str(index)+'");std::io::stdout().flush().unwrap();'
                    +'let value_'+str(index)+'='+expression+';println!("STUDY_VALUE '+str(index)+' {}",value_'+str(index)+');')
            source=directory/"main.rs"
            source.write_text('#![forbid(unsafe_code)]\nuse std::io::Write;\n'+rust_caller(task)
                +'\nfn main(){println!("STUDY_READY");'+''.join(calls)+'println!("STUDY_DONE");}\n')
            binary=directory/"candidate"
            command=[rustc,"--edition=2021","-C","opt-level=2","-C","overflow-checks=on",str(source),"-o",str(binary)]
            run=subprocess.run(command,capture_output=True,text=True,timeout=45)
            record["compile"]={"argv":command,"returncode":run.returncode,"stdout":run.stdout,"stderr":run.stderr}
            if run.returncode:
                return {**record,"reason":"frozen admitted candidate did not compile"}
            command=[str(binary)]
        artifact_before=file_identity(binary)
        record["argv"]=command
        run=subprocess.run(command,capture_output=True,text=True,timeout=15)
        record.update(classify_execution(task,language,run.returncode,run.stdout,run.stderr,
                      overflow_expected=_expects_overflow(task,candidate,language)))
        record["artifact"]=file_identity(binary)
        if record["artifact"]!=artifact_before or file_identity(compiler)!=compiler_before:
            record.update(ok=False,native_executed=False,status="infrastructure_error",reason="compiler or native artifact changed")
        return record
    except Exception as exc:
        record.update(ok=False,native_executed=False,status="infrastructure_error",
                      error={"type":type(exc).__name__,"message":str(exc)})
        if isinstance(exc,subprocess.TimeoutExpired):
            text=lambda value:value.decode(errors="replace") if isinstance(value,bytes) else value
            record["partial_stdout"]=text(exc.stdout);record["partial_stderr"]=text(exc.stderr)
        return record


def control_passed(task,correct,result):
    status="correct" if correct else "expected_overflow_trap" if task["id"]=="next_epoch" else "observable_wrong"
    return result.get("native_executed") is True and result.get("status")==status and result.get("ok") is correct


def bindings():
    names=[*ROOT.joinpath("hepta").glob("*.py"),Path(__file__).resolve(),
           ROOT/"tools/provider_adapter/llama_cpp_engine.py",ROOT/"tools/provider_adapter/local_model_common.py"]
    return {str(p.relative_to(ROOT)):file_identity(p)["sha256"] for p in sorted(names)}


def summarize(rows):
    result={}
    for arm in ARMS:
        subset=[r for r in rows if r["arm"]==arm]
        scored=[r for r in subset if r.get("state") in SCORED_STATES]
        usages=[r["generation"]["usage"] for r in subset if "generation" in r]
        unknown_usage=len(subset)-len(usages)
        unknown_inference=sum("inference_ns" not in r for r in subset)
        unknown_evaluation=sum("evaluation_ns" not in r for r in subset)
        known_input=sum(u["input_tokens"] for u in usages)
        known_output=sum(u["output_tokens"] for u in usages)
        known_inference=sum(r["inference_ns"] for r in subset if "inference_ns" in r)
        known_evaluation=sum(r["evaluation_ns"] for r in subset if "evaluation_ns" in r)
        result[arm]={"planned_tasks":8,"attempted_tasks":len(subset),"completed_tasks":len(scored),
            "successes":sum(r["ok"] for r in scored),
            "accepted_but_wrong":sum(r.get("state") in {"observable_wrong","expected_overflow_trap"} for r in scored),
            "rejected":sum(r.get("state")=="response_rejected" for r in scored),
            "infrastructure_failures":sum(r.get("state") not in SCORED_STATES for r in subset),
            "cost_scope":"attempted_task_requests",
            "unknown_usage_tasks":unknown_usage,"usage_complete":unknown_usage==0,
            "unknown_inference_tasks":unknown_inference,"inference_time_complete":unknown_inference==0,
            "unknown_evaluation_tasks":unknown_evaluation,"evaluation_time_complete":unknown_evaluation==0,
            "known_input_tokens":known_input,"known_output_tokens":known_output,
            "known_inference_ns":known_inference,"known_evaluation_ns":known_evaluation,
            "input_tokens":known_input if not unknown_usage else None,
            "output_tokens":known_output if not unknown_usage else None,
            "inference_ns":known_inference if not unknown_inference else None,
            "evaluation_ns":known_evaluation if not unknown_evaluation else None}
    return result


def comparison_criteria(summary,complete):
    hq=summary["hia_edit_query"];rq=summary["rust_edit_query"];hf=summary["hia_full_context"]
    complete=complete and all(row["usage_complete"] for row in (hq,rq,hf))
    tokens=lambda r:r["input_tokens"]+r["output_tokens"]
    floor=hq["successes"]>=MINIMUM_SUCCESSES
    return (bool(complete and floor and hq["successes"]>=rq["successes"] and tokens(hq)<=tokens(rq)),
            bool(complete and floor and hq["successes"]>=hf["successes"] and tokens(hq)<tokens(hf)))


def scheduled_cells(tasks,model_index):
    result=[]
    for index,task in enumerate(tasks):
        offset=(index+model_index)%len(ARMS)
        result.extend({"id":task["id"]+"_"+arm,"task":task["id"],"arm":arm}
                      for arm in ARMS[offset:]+ARMS[:offset])
    return result


def _error(exc):
    return {"type":type(exc).__name__,"message":str(exc)}


def _run_model(model,mindex,tasks,out,binary,clang,rustc,threads,initial):
    folder=out/model["id"];folder.mkdir()
    planned=scheduled_cells(tasks,mindex)
    write(folder/"attempt-started.json",{"model":model,"planned_cells":planned,"attempts_per_cell":1})
    rows=[];preflight=[];status="model_startup_failed";error=None;engine=None
    identity={"model_unchanged":False,"runtime_unchanged":False,"available":False}
    try:
        engine=LlamaCppEngine(binary=binary,model=model["path"],model_sha256=model["sha256"],output_dir=folder/"engine",threads=threads)
        status="execution_incomplete"
        for name,wanted in (("hia",'{"op":"bit.and"}'),("rust",'{"replacement":"&"}')):
            item={"language":name,"ok":False,"status":"started"};preflight.append(item)
            response=engine.generate([{"role":"user","content":"Return exactly this JSON object and nothing else: "+wanted}],limit=LIMIT)
            write(folder/("preflight_"+name+".json"),response)
            try: valid=decode_json(response["text"].strip())==json.loads(wanted)
            except ValueError: valid=False
            item.update(ok=valid,status="completed",usage=response["usage"])
        if not all(p["ok"] for p in preflight):
            status="model_format_preflight_failed"
        else:
            tasks_by_id={task["id"]:task for task in tasks}
            for cell in planned:
                if bindings()!=initial:raise RuntimeError("E_STUDY_SOURCE_DRIFT")
                task=tasks_by_id[cell["task"]];arm=cell["arm"];cell_id=cell["id"]
                messages=[{"role":"user","content":prompt(task,arm)}]
                write(folder/(cell_id+".request.json"),{"messages":messages,"limit":LIMIT})
                row={"task":task["id"],"arm":arm,"id":cell_id,"attempt_started":True,
                     "accepted":False,"ok":False,"state":"inference_started"}
                rows.append(row)
                try:
                    response=engine.generate(messages,limit=LIMIT,wall_seconds=180)
                    write(folder/(cell_id+".response.json"),response)
                    row.update(generation={"usage":response["usage"],"response":cell_id+".response.json"},
                               inference_ns=response["wall_nanoseconds"],state="evaluating")
                    started=time.monotonic_ns()
                    try:
                        candidate=parse_response(task,arm,response["text"])
                    except ValueError as exc:
                        row.update(state="response_rejected",error=_error(exc))
                    else:
                        row["accepted"]=True
                        result=native(task,candidate,"hia" if arm.startswith("hia") else "rust",folder/"candidates"/cell_id,clang,rustc)
                        row.update(native=result,ok=result["ok"],state=result["status"])
                        if result["status"]=="infrastructure_error":
                            raise RuntimeError("E_STUDY_NATIVE_INFRASTRUCTURE: "+str(result.get("reason",result.get("error"))))
                    finally:
                        row["evaluation_ns"]=time.monotonic_ns()-started
                    print(json.dumps({"model":model["id"],"task":task["id"],"arm":arm,"ok":row["ok"],"tokens":response["usage"]["total_tokens"]}),flush=True)
                except Exception as exc:
                    if row["state"] not in SCORED_STATES:
                        row["state"]="inference_failed" if "generation" not in row else "infrastructure_error"
                    row["error"]=_error(exc)
                    raise
                finally:
                    write(folder/(cell_id+".evaluation.json"),row)
            status="completed"
    except Exception as exc:
        error=_error(exc)
    finally:
        for item in preflight:
            if item["status"]=="started":item.update(status="incomplete",error=error)
        if engine is not None:
            try:
                identity=engine.verify_final_identity()
                identity["available"]=True
                if not identity.get("model_unchanged") or not identity.get("runtime_unchanged"):
                    status="model_identity_failure"
            except Exception as exc:
                identity={"model_unchanged":False,"runtime_unchanged":False,"available":False,"error":_error(exc)}
                status="model_identity_failure";error=_error(exc)
            try:engine.close()
            except Exception as exc:
                status="model_shutdown_failure";error=_error(exc)
        completed={row["id"] for row in rows if row.get("state") in SCORED_STATES}
        started={row["id"] for row in rows}
        requests=getattr(engine,"generation_count",0);responses=getattr(engine,"response_count",0)
        report={"model":model,"status":status,"error":error,"preflight":preflight,"rows":rows,"summary":summarize(rows),
                "identity":identity,"attempt_started":True,"planned_cells":planned,
                "completed_cells":sorted(completed),"unfinished_cells":[cell for cell in planned if cell["id"] not in completed],
                "unstarted_cells":[cell for cell in planned if cell["id"] not in started],
                "requests_started":requests,"responses_received":responses,"unresolved_requests":requests-responses}
        write(folder/"report.json",report)
    return report


def run_study(output,models,binary,clang,rustc,threads=4):
    if (type(models) is not list or len(models)!=2
            or any(type(m) is not dict or not {"id","path","sha256","repository","revision"}.issubset(m) for m in models)
            or any(type(m["id"]) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,63}",m["id"]) is None for m in models)
            or any(type(m["sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}",m["sha256"]) is None for m in models)
            or len({m["id"] for m in models})!=2 or len({m["sha256"] for m in models})!=2):
        raise ValueError("E_STUDY_MODELS: two distinct, identified models are required")
    out=Path(output).absolute();out.mkdir(parents=True,exist_ok=False)
    tasks=fixtures();initial=bindings()
    plan={"schema":PROTOCOL,"tasks":tasks,"arms":list(ARMS),"models":models,"source_bindings":initial,
          "runtime":file_identity(binary),"clang":file_identity(clang),"rustc":file_identity(rustc),
          "max_new_tokens":LIMIT,"threads":threads,"greedy":True,"seed":0,"attempts_per_cell":1,
          "schedule":"model order fixed by lock; arms rotate by task index plus model index",
          "context_policy":"full program versus compact site view; HIA bundle changes encoding and context together",
          "response_policy":"strict JSON for every arm; no fence extraction, retries or post-hoc rescoring",
          "token_comparison_scope":"task requests only; eligibility/setup separately retained, no cost omitted from raw inventory",
          "minimum_hia_query_successes":MINIMUM_SUCCESSES,
          "primary_rule":"per model, HIA query succeeds on at least 7/8 tasks, success >= Rust query success, total tokens <= Rust query tokens",
          "secondary_rule":"per model, HIA query succeeds on at least 7/8 tasks, success >= HIA full success, tokens < HIA full tokens",
          "source_structure":{"hia":"two functions in one module","rust":"caller and kernel in two source files"},
          "scope":"eight fixed single-site repairs with real cross-function callers; no HIA multi-module, population or total-cost claim"}
    plan_hash=sha(canonical(plan));write(out/"plan.json",{**plan,"plan_sha256":plan_hash})
    controls=[]
    for task in tasks:
        for language in ("hia","rust"):
            for correct in (False,True):
                if language=="hia":
                    candidate=(apply_edit(task["hia"],query_for(task),{task["field"]:task["good"]})[0]
                               if correct else verify_program(task["hia"]))
                else:candidate=task["rust_template"].replace("@SLOT@",task["rust_good"] if correct else task["rust_bad"])
                name=task["id"]+"_"+language+"_"+str(correct).lower()
                result=native(task,candidate,language,out/"controls"/name,clang,rustc)
                controls.append({"id":name,"passed":control_passed(task,correct,result),"result":result})
    write(out/"controls.json",controls)
    reports=[]
    if all(r["passed"] for r in controls):
        for mindex,model in enumerate(models):
            reports.append(_run_model(model,mindex,tasks,out,binary,clang,rustc,threads,initial))
    else:
        for mindex,model in enumerate(models):
            cells=scheduled_cells(tasks,mindex)
            report={"model":model,"status":"not_started_native_controls_failed","error":None,"attempt_started":False,
                    "preflight":[],"rows":[],"summary":summarize([]),"planned_cells":cells,"completed_cells":[],
                    "unfinished_cells":cells,"unstarted_cells":cells,"requests_started":0,"responses_received":0,"unresolved_requests":0,
                    "identity":{"model_unchanged":False,"runtime_unchanged":False,"available":False}}
            write(out/model["id"]/"report.json",report);reports.append(report)
    identity_errors={};final_tools={}
    try:source_stable=bindings()==initial
    except Exception as exc:source_stable=False;identity_errors["source"]=_error(exc)
    for name,path in (("runtime",binary),("clang",clang),("rustc",rustc)):
        try:final_tools[name]=file_identity(path)
        except Exception as exc:identity_errors[name]=_error(exc)
    toolchain_stable=not identity_errors and all(final_tools.get(name)==plan[name] for name in ("runtime","clang","rustc"))
    complete=(source_stable and toolchain_stable and len(reports)==2 and all(r["passed"] for r in controls)
        and all(r["status"]=="completed" and len(r["completed_cells"])==32 and not r["unfinished_cells"] and not r["unresolved_requests"]
                and r["identity"]["model_unchanged"] and r["identity"]["runtime_unchanged"] for r in reports))
    criteria=[comparison_criteria(report["summary"],complete) for report in reports]
    result={"schema":PROTOCOL,"status":"completed" if complete else "incomplete_or_identity_failure","plan_sha256":plan_hash,
            "source_unchanged":source_stable,"toolchain_unchanged":toolchain_stable,"final_tool_identities":final_tools,"identity_errors":identity_errors,
            "models":reports,"native_controls":len(controls),"native_controls_passed":sum(r["passed"] for r in controls),
            "primary_criteria_per_model":[row[0] for row in criteria],"secondary_criteria_per_model":[row[1] for row in criteria],
            "minimum_hia_query_successes":MINIMUM_SUCCESSES,
            "general_productivity_advantage_established":False,"total_development_cost_measured":False,
            "limitations":["two small quantized models of the same family","eight disclosed finite single-site tasks",
                           "one greedy attempt per cell","HIA has two functions in one module; Rust has two source files",
                           "no HIA multi-module maintenance evidence","no human labor or upstream-maintenance cost measurement",
                           "full versus sliced HIA jointly changes representation and context, not a pure slicing intervention"]}
    write(out/"report.json",result);return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",required=True);parser.add_argument("--models-lock",required=True)
    parser.add_argument("--binary",required=True);parser.add_argument("--clang",required=True);parser.add_argument("--rustc",required=True)
    parser.add_argument("--threads",type=int,default=4)
    args=vars(parser.parse_args());lock=json.loads(Path(args.pop("models_lock")).read_text())
    result=run_study(models=lock["models"],**args)
    print(json.dumps({k:result.get(k) for k in ("status","source_unchanged","primary_criteria_per_model","secondary_criteria_per_model")}))
    return 0 if result["status"]=="completed" else 1


if __name__=="__main__":
    raise SystemExit(main())
