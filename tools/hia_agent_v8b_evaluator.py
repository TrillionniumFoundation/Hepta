#!/usr/bin/env python3
"""Bounded prospective textual Core-v8/Rust evaluator; no model calls here."""
from __future__ import annotations
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
sys.dont_write_bytecode=True
from tools.hia_agent_codex_transport import canonical,identity,run_owned,save,strict_json
HERE=ROOT/"experiments/hia_agent_v8_continuation_20261030b"
spec=importlib.util.spec_from_file_location("v8b_continuation_tasks",HERE/"tasks.py")
TASK_MODULE=importlib.util.module_from_spec(spec)
spec.loader.exec_module(TASK_MODULE)
TASKS=TASK_MODULE.TASKS
LANGUAGES=("hia-v8-text","rust")
SCHEMA=TASK_MODULE.SCHEMA

def config():
    return strict_json((HERE/"PROTOCOL.json").read_bytes())

def candidate_constraints(task,language,candidate):
    if type(candidate) is not str or len(candidate.encode())>65536:
        raise ValueError("candidate must be a UTF-8 source string of at most 65536 bytes")
    if language=="hia-v8-text":
        from hepta.hia_agent_assembly import assemble_program
        document=assemble_program(candidate).as_dict()
        if document["schema"]!=SCHEMA:
            raise ValueError("explicit primitive Core v8 text is required")
        target=next((f for f in document["functions"] if f["name"]==task["interface"]),None)
        expected=(["mutbuf","u32","u32"] if task["interface"]=="task_step" else ["u32","u32"])
        returns=["mutbuf"] if task["id"]=="return_borrow" else ["u32"]
        exports=[] if task["interface"]=="task_step" else ["target"]
        if (target is None or [p["type"] for p in target["params"]]!=expected
                or target["returns"]!=returns or document["exports"]!=exports):
            raise ValueError("preserve disclosed interface types and exports; local parameter names may differ")
        if task["id"]=="return_borrow" and target.get("return_loans")!=[target["params"][0]["name"]]:
            raise ValueError("returned mutable view must bind the first input formal")
        return document
    if language!="rust": raise ValueError("unknown language")
    # Explicit selected-source profile, not an OS isolation guarantee.
    banned=r"\b(unsafe|extern|mod|use|include|include_str|include_bytes|std|core|alloc|env|option_env|asm|global_asm|impl|trait|struct|enum|type|macro_rules|audited|super|crate|Self)\b|::|#\s*!?\s*\["
    if re.search(banned,candidate):
        raise ValueError("outside the disclosed safe scalar/audited-Vec lexical source profile")
    if not re.search(r"\bfn\s+"+task["interface"]+r"(?:\s*<[^>]+>)?\s*\(",candidate):
        raise ValueError("missing disclosed function")
    if re.search(r"\bfn\s+(invoke|main)\b",candidate):
        raise ValueError("trusted driver entry names are reserved")
    return None

def resource_mode(task):
    return {"mutate_borrow":1,"return_borrow":2,"conditional_release":3}.get(task["id"],0)

def rust_driver(candidate,task):
    mode=resource_mode(task)
    prelude=('#![forbid(unsafe_code)]\n'
        + ((ROOT/"tools/fixtures/hia_agent_v8_resource.rs").read_text() if mode else ""))
    header=("mod candidate {\n"
        + ('#[allow(unused_imports)]\nuse super::audited::{Vec,drop};\nmacro_rules! vec {($value:expr;$length:expr)=>{super::audited::make_vec($value,$length)};}\n' if mode else ""))
    before=f"audited::begin({mode},x,y);" if mode else ""
    after='let ledger=audited::finish(value);eprintln!("HIA_V8_RUST_AUDIT {}",ledger);' if mode else ""
    return (prelude+header+candidate+"\n"+TASK_MODULE.rust_wrapper(task["id"])+"\n}\n"
        "fn main(){use std::io::{self,Read};let mut s=String::new();io::stdin().read_to_string(&mut s).unwrap();"
        "let mut words=s.split_whitespace();while let Some(word)=words.next(){let x:u32=word.parse().unwrap();"
        "let y:u32=words.next().unwrap().parse().unwrap();"+before+"let value=candidate::invoke(x,y);"
        +after+'println!("{}",value);}}\n')

def execute_hia_contract(program,task,values):
    from hepta.hia_program_runtime import _Machine,_underlying,execute_program
    original=_Machine.operation
    events=[]
    def observe(machine,instruction,env,depth):
        name=instruction["op"]
        args=[env[n] for n in instruction["args"]]
        owner=_underlying(args[0]).ident if name in {"buffer.store","buffer.load","owner.drop","loan.end"} else None
        original(machine,instruction,env,depth)
        if name in {"buffer.new","buffer.try_new"}:
            value=env[instruction["out"][0]["name"]]
            events.append({"op":"allocate","owner":value.ident,"size":len(value.data),"zeroed":not any(value.data),"depth":depth})
        elif name=="buffer.store":
            events.append({"op":"store","owner":owner,"index":args[1],"value":args[2],"depth":depth})
        elif name=="buffer.load":
            events.append({"op":"load","owner":owner,"index":args[1],"value":env[instruction["out"][0]["name"]],"depth":depth})
        elif name in {"owner.drop","loan.end"}:
            events.append({"op":"drop" if name=="owner.drop" else "loan_end","owner":owner,"depth":depth})
        elif name=="call":
            returned=[_underlying(env[p["name"]]).ident for p in instruction["out"] if p["type"] in {"readbuf","mutbuf"}]
            events.append({"op":"call_return","function":instruction["attrs"]["function"],"returned_view_owners":returned,"depth":depth})
        if len(events)>4096: raise ValueError("resource event budget exceeded")
    with patch.object(_Machine,"operation",observe):
        report=execute_program(program,"target",values,max_steps=100000,max_heap_bytes=1048576)
    if report.get("status")!="returned" or report.get("result")!=TASK_MODULE.oracle(task["id"],*values):
        raise ValueError("VM result differs from independent task oracle")
    r=report["resources"]
    if r["live_owners"] or r["live_local_loans"]: raise ValueError("VM unresolved resource")
    if task["id"] in TASK_MODULE.RESOURCE_TASKS:
        contract=TASK_MODULE.resource_contract(task["id"],*values)
        alloc=[(i,e) for i,e in enumerate(events) if e["op"]=="allocate"]
        drop=[(i,e) for i,e in enumerate(events) if e["op"]=="drop"]
        if len(alloc)!=1 or len(drop)!=1 or r["allocations"]!=1 or r["frees"]!=1:
            raise ValueError("exactly one actual allocation and release required")
        ai,a=alloc[0];di,d=drop[0];owner=a["owner"]
        if not(ai<di and a["size"]==contract["length"] and a["zeroed"] and d["owner"]==owner):
            raise ValueError("allocation/owner/length mismatch")
        access=[e for e in events if e["op"] in {"store","load"}]
        if contract["failure_path"]:
            if access: raise ValueError("odd-y release path must not access buffer")
        else:
            def matching(op,value,helper=None):
                return [i for i,e in enumerate(events) if e["op"]==op and e["owner"]==owner
                    and e["index"]==contract["index"] and e["value"]==value
                    and (helper is None or (e["depth"]>0)==helper)]
            borrowed=task["id"] in TASK_MODULE.BORROW_TASKS
            writes=matching("store",contract["first_byte"],True if borrowed else None)
            reads=matching("load",contract["first_byte"],True if task["id"]=="mutate_borrow" else None)
            if not any(ai<wi<ri<di for wi in writes for ri in reads):
                raise ValueError("missing actual candidate write/readback sequence")
            if task["id"]=="return_borrow":
                calls=[i for i,e in enumerate(events) if e["op"]=="call_return" and e["function"]=="task_step"
                       and e["returned_view_owners"]==[owner] and e["depth"]==0]
                final_w=matching("store",contract["final_byte"],False)
                final_r=matching("load",contract["final_byte"],False)
                if not any(ai<w<c<r<fw<fr<di for w in writes for c in calls for r in reads for fw in final_w for fr in final_r):
                    raise ValueError("returned same-owner view not actually consumed by disclosed caller")
    return {"args":values,"result":report["result"],"resources":r,"operation_events":events,
            "scope":"selected Core VM operations; not proof of native allocation/store instructions"}

def input_cases(task,phase,*,permit_formal=False):
    cfg=config()
    return TASK_MODULE.cases(task,phase=phase,
        seed=cfg["formal_hidden_seed"] if phase=="formal" else cfg["development_seed"],
        count=cfg["formal_hidden_cases_per_task"],permit_formal=permit_formal)

def audit_rust(stderr,task,values):
    prefix="HIA_V8_RUST_AUDIT "
    lines=stderr.splitlines()
    if len(lines)!=len(values) or any(not line.startswith(prefix) for line in lines):
        raise ValueError("missing/unexpected native resource ledger lines")
    ledgers=[strict_json(line[len(prefix):]) for line in lines]
    for epoch,(ledger,pair) in enumerate(zip(ledgers,values),1):
        c=TASK_MODULE.resource_contract(task["id"],*pair)
        if (ledger.get("schema")!="hepta.agent.v8.rust-vec-api-audit.v1"
            or ledger.get("epoch")!=epoch or ledger.get("mode")!=resource_mode(task)
            or any(ledger.get(k)!=v for k,v in c.items() if k in {"length","index","first_byte","final_byte","failure_path"})
            or [ledger.get(k) for k in ("allocations","releases","live")]!=[1,1,0]):
            raise ValueError("native resource ledger binding mismatch")
    return {"accepted":True,"scope":"selected audited Vec API; not all-process allocator or machine instructions","ledgers":ledgers}

def worker(args):
    task=TASK_MODULE.task_for(args.task);cfg=config();folder=Path(args.output)
    folder.mkdir(parents=True,exist_ok=False)
    before=time.monotonic_ns()
    result={"accepted":False,"correct":False,"status":"starting","phase":args.phase,
            "hidden_evaluated":args.phase=="formal"}
    try:
        if args.development_tools:
            if args.phase=="formal":raise ValueError("formal evaluation cannot override pinned tools")
            override=strict_json(Path(args.development_tools).read_bytes())
            if (type(override) is not dict or not override or not set(override)<={"clang","rustc"}
                or any(type(path) is not str or not Path(path).is_absolute() for path in override.values())):
                raise ValueError("explicit absolute development-tool paths required")
            cfg.update(override)
            result["development_tool_override"]={name:identity(path) for name,path in override.items()}
        # Only the registered parent creates a formal admission marker.
        if args.phase=="formal":
            marker=strict_json(Path(args.admission).read_bytes())
            if (marker.get("schema")!="hepta.agent.v8.formal-admission.v1"
                or marker.get("registration_commit") is None or marker.get("task")!=task["id"]
                or marker.get("model_process_closed") is not True
                or marker.get("freeze_sha256")!=identity(HERE/"FREEZE.json")["sha256"]):
                raise ValueError("formal input materialization requires registered terminal admission")
        values=input_cases(task,args.phase,permit_formal=args.phase=="formal")
        if args.build:
            built=strict_json(Path(args.build).read_bytes())
            for key in ("candidate","binary"):
                if identity(built[key]["path"])!=built[key]:raise ValueError("accepted artifact changed: "+key)
            candidate=strict_json(Path(built["candidate"]["path"]).read_bytes())
            binary=Path(built["binary"]["path"]);result["candidate"]=built["candidate"]
            document=candidate_constraints(task,args.language,candidate)
        else:
            candidate=strict_json(Path(args.candidate).read_bytes())
            result["candidate"]=identity(args.candidate)
            document=candidate_constraints(task,args.language,candidate)
            binary=folder/"candidate"
        if args.language=="hia-v8-text":
            from hepta.hia_program import verify_program
            combined=TASK_MODULE.combine_candidate(document,task["id"])
            verified=verify_program(combined)
            result["interpreter"]=[execute_hia_contract(verified,task,pair) for pair in values]
        if not args.build:
            if args.language=="hia-v8-text":
                from hepta.hia_program_llvm import build_program_native
                result["native_compile"]=build_program_native(verified,folder/"program.o",clang=cfg["clang"],kind="object")
                driver=folder/"driver.c"
                driver.write_text('#include <stdint.h>\n#include <stdio.h>\nextern uint32_t target(uint32_t,uint32_t);\nint main(void){unsigned x,y;while(scanf("%u %u",&x,&y)==2)printf("%u\\n",target(x,y));return 0;}\n')
                argv=[cfg["clang"],"-O2",str(driver),str(folder/"program.o"),"-o",str(binary)]
            else:
                driver=folder/"main.rs";driver.write_text(rust_driver(candidate,task))
                argv=[cfg["rustc"],"--edition=2021","-C","opt-level=2","-C","overflow-checks=on","-C","strip=symbols","-C","panic=abort",str(driver),"-o",str(binary)]
            started=time.monotonic_ns()
            compiled=subprocess.run(argv,capture_output=True,text=True,timeout=35)
            result["compile"]={"argv":argv,"returncode":compiled.returncode,"stdout":compiled.stdout,"stderr":compiled.stderr,"wall_ns":time.monotonic_ns()-started}
            if compiled.returncode:
                result["status"]="compile_rejected"
                return result
        artifact=identity(binary)
        expected=[TASK_MODULE.oracle(task["id"],*pair) for pair in values]
        started=time.monotonic_ns()
        native_argv=[sys.executable,"-B",str(ROOT/"tools/hia_agent_v8_native_limit.py"),"--receipt",str(folder/"NATIVE_LIMITS.json"),str(binary)]
        native_process=run_owned(native_argv,folder,folder/"native-transport",
            input_bytes="".join(f"{x} {y}\n" for x,y in values).encode(),wall_seconds=8)
        limit_path=folder/"NATIVE_LIMITS.json"
        if not limit_path.is_file():
            result.update(status="execution_limit_unavailable",native_process=native_process)
            return result
        native_limits=strict_json(limit_path.read_bytes())
        if (native_limits.get("after")!={"RLIMIT_AS":[268435456,268435456],"RLIMIT_CORE":[0,0]}
            or native_limits.get("pid")!=native_process.get("pid") or native_limits.get("binary")!=str(binary.resolve())):
            result.update(status="execution_limit_unavailable",native_process=native_process,native_limits=native_limits)
            return result
        result["native_limits"]={"receipt":identity(limit_path),"observed":native_limits}
        stdout=(folder/"native-transport/stdout.raw").read_text(errors="replace")
        stderr=(folder/"native-transport/stderr.raw").read_text(errors="replace")
        try: actual=[int(line) for line in stdout.splitlines()]
        except ValueError: actual=None
        correct=native_process["status"]=="exited" and actual==expected and identity(binary)==artifact
        result["execution"]={"returncode":native_process.get("returncode"),"stdout":stdout,"stderr":stderr,
            "wall_ns":time.monotonic_ns()-started,"case_count":len(values),"expected":expected,"actual":actual,
            "process":native_process}
        if correct and resource_mode(task) and args.language=="rust":
            result["resource_audit"]=audit_rust(stderr,task,values)
        result.update(accepted=bool(correct),correct=bool(correct),status="accepted" if correct else "cases_failed",binary=artifact)
    except Exception as error:
        result.update(status="candidate_rejected",error={"type":type(error).__name__,"message":str(error)})
    finally:
        result["wall_ns"]=time.monotonic_ns()-before
        save(folder/"RESULT.json",result)
    return result

def evaluate(task,language,folder,*,candidate=None,build=None,phase="public",timeout=70,admission=None,development_tools=None):
    if phase not in {"public","development","formal"}:raise ValueError("bad phase")
    if phase=="formal" and development_tools:raise ValueError("formal tools cannot be overridden")
    if phase=="formal" and (not build or not admission):raise ValueError("terminal accepted build and registration admission required")
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=False)
    argv=[sys.executable,"-B",str(Path(__file__).resolve()),"_evaluate","--task",task["id"],
          "--language",language,"--phase",phase,"--output",str(folder/"evaluation")]
    if build:
        save(folder/"BUILD.json",build);argv+=["--build",str(folder/"BUILD.json")]
    else:
        save(folder/"CANDIDATE.json",candidate);argv+=["--candidate",str(folder/"CANDIDATE.json")]
    if admission:argv+=["--admission",str(admission)]
    if development_tools:
        save(folder/"DEVELOPMENT_TOOLS.json",development_tools)
        argv+=["--development-tools",str(folder/"DEVELOPMENT_TOOLS.json")]
    process=run_owned(argv,ROOT,folder/"transport",wall_seconds=timeout)
    receipt=folder/"evaluation/RESULT.json"
    if process["status"]!="exited" or not receipt.is_file():
        return {"accepted":False,"correct":False,"phase":phase,"hidden_evaluated":phase=="formal",
                "status":"evaluation_runtime_failure","process":process}
    result=strict_json(receipt.read_bytes());result["process"]=process
    return result

def public_feedback(result,digest):
    if result.get("phase")!="public" or result.get("hidden_evaluated"):
        raise ValueError("only public phase feedback may enter model history")
    return {"candidate_digest":digest if result["accepted"] else None,
        "accepted":result["accepted"],"status":result["status"],
        **{key:result[key] for key in ("error","compile","interpreter","resource_audit","execution") if key in result}}

def main():
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("command",choices=["_evaluate"])
    parser.add_argument("--task",required=True);parser.add_argument("--language",choices=LANGUAGES,required=True)
    parser.add_argument("--phase",choices=["public","development","formal"],required=True)
    parser.add_argument("--output",required=True);parser.add_argument("--candidate");parser.add_argument("--build");parser.add_argument("--admission");parser.add_argument("--development-tools")
    args=parser.parse_args();worker(args);return 0
if __name__=="__main__":raise SystemExit(main())
