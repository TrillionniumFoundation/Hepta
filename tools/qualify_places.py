"""Replay partial-field cleanup, real allocator refusal and declared origins.

The sequential project also has an independently replayed v3 resource graph.
The native cancellation project is explicitly outside that graph's profile.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

from hepta.backend import compile_rust
from hepta.pipeline import analyze_project, compiler_hash
from hepta.resource_ir import ResourceIRError, verify_resource_ir
from hepta.resource_lowering import lower_resource_ir

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "examples/places/library.hepta"
CANCELLATION = ROOT / "examples/places/cancel.hepta"

ALLOCATOR = r'''
struct Counting;
static TRACK:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);
static REFUSE:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);
static ALLOC:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
static FREE:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
static FAIL:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
static LIVE:std::sync::atomic::AtomicIsize=std::sync::atomic::AtomicIsize::new(0);
use std::sync::atomic::Ordering::SeqCst;
fn tracked(size:usize)->bool {matches!(size,4093|8161|12281)}
unsafe impl std::alloc::GlobalAlloc for Counting {
  unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8 {
    if TRACK.load(SeqCst)&&REFUSE.load(SeqCst)&&l.size()==12281 {
      FAIL.fetch_add(1,SeqCst);return core::ptr::null_mut();
    }
    let p=std::alloc::GlobalAlloc::alloc(&std::alloc::System,l);
    if TRACK.load(SeqCst)&&tracked(l.size())&&!p.is_null() {
      ALLOC.fetch_add(1,SeqCst);LIVE.fetch_add(l.size() as isize,SeqCst);
    } p
  }
  unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout) {
    if TRACK.load(SeqCst)&&tracked(l.size()) {
      FREE.fetch_add(1,SeqCst);LIVE.fetch_sub(l.size() as isize,SeqCst);
    }
    std::alloc::GlobalAlloc::dealloc(&std::alloc::System,p,l);
  }
}
#[global_allocator] static A:Counting=Counting;
fn begin(refuse:bool) {
  assert_eq!(LIVE.load(SeqCst),0);ALLOC.store(0,SeqCst);FREE.store(0,SeqCst);
  FAIL.store(0,SeqCst);REFUSE.store(refuse,SeqCst);TRACK.store(true,SeqCst);
}
fn finish(case:&str,value:u64,expected_value:u64,expected_alloc:usize,expected_fail:usize) {
  TRACK.store(false,SeqCst);
  let allocated=ALLOC.load(SeqCst);let freed=FREE.load(SeqCst);let failures=FAIL.load(SeqCst);let live=LIVE.load(SeqCst);
  assert_eq!(value,expected_value);assert_eq!(allocated,expected_alloc);assert_eq!(freed,expected_alloc);
  assert_eq!(failures,expected_fail);assert_eq!(live,0);
  println!("{{\"case\":\"{}\",\"value\":{},\"allocated\":{},\"freed\":{},\"refused\":{},\"live_bytes\":{}}}",case,value,allocated,freed,failures,live);
}
'''
SEQUENTIAL = r'''
fn main() {
  begin(false);let value=h_exercise(false,12281);finish("normal",value,12281,3,0);
  begin(false);let value=h_exercise(true,12281);finish("early",value,7,2,0);
  begin(true);let value=h_exercise(false,12281);finish("allocation_refusal",value,1,2,1);
  begin(false);let value=h_exercise(false,12281);finish("recovery",value,12281,3,0);
  begin(false);let value=h_cycles();finish("loop_restoration",value,11,6,0);
}
'''
CONCURRENT = r'''
fn main() {
  for _ in 0..8 {
    begin(false);let value=h_run_cancel();finish("cancel_after_partial_move",value,9,2,0);
    begin(false);let value=h_run_failure();finish("failure_after_partial_move",value,13,2,0);
  }
}
'''

CLAIMS = {"source_to_ir_refinement_proved":False,"whole_language_soundness_proved":False,
          "concurrent_resource_ir_verified":False,"stored_references_supported":False,
          "general_lifetimes_supported":False}
ALLOCATION_SCOPE = "actual Buffer allocations of 4093/8161/12281 bytes; runtime infrastructure excluded"


def _expected_observations(name):
    records = ([('normal',12281,3,0),('early',7,2,0),('allocation_refusal',1,2,1),
                ('recovery',12281,3,0),('loop_restoration',11,6,0)] if name=='sequential' else
               [('cancel_after_partial_move',9,2,0),('failure_after_partial_move',13,2,0)]*8)
    return [{'case':case,'value':value,'allocated':count,'freed':count,'refused':refused,'live_bytes':0}
            for case,value,count,refused in records]


def validate_places_qualification(report):
    """Fail closed on incomplete evidence, inflated claims and altered graphs.

    Validation replays current source lowering and independent graph checking;
    it does not rerun the executable or establish a formal refinement proof.
    Archive consumers must rerun qualification in their checkout to obtain new
    path-bound project identities instead of relabeling historical evidence.
    """
    def need(condition,message):
        if not condition: raise ValueError(message)
    def digest(value):
        return isinstance(value,str) and len(value)==64 and all(c in '0123456789abcdef' for c in value)
    need(isinstance(report,dict) and report.get('schema')=='hepta.places-qualification.v1' and report.get('ok') is True,'incomplete places qualification')
    need(report.get('claims')==CLAIMS and all(value is False for value in report['claims'].values()),'places claims were inflated')
    need(report.get('allocation_scope')==ALLOCATION_SCOPE,'allocation scope changed')
    rows=report.get('projects')
    need(isinstance(rows,list) and [row.get('name') for row in rows]==['sequential','cancellation'],'places projects missing/duplicated')
    graph=None
    for row,path,harness in zip(rows,(LIBRARY,CANCELLATION),(SEQUENTIAL,CONCURRENT)):
        current=analyze_project(path,native=False,crate_type='rlib')
        need(current.report['ok'],'qualification source no longer checks')
        expected_inputs={str(Path(p).relative_to(ROOT)):hashlib.sha256(data).hexdigest() for p,data in current.project.source_bytes.items()}
        need(row.get('entry')==str(path.relative_to(ROOT)) and row.get('inputs')==expected_inputs,'places input identity changed')
        gate=row.get('native_gate',{})
        need(gate.get('ok') is True and gate.get('compiler_sha256')==compiler_hash() and gate.get('checks',{}).get('rust_borrows_types')=='rustc_checked','native source gate missing/stale')
        for field in ('source_sha256','interface_sha256','rust_sha256','project','assumptions','claims'):
            need(gate.get(field)==current.report.get(field),'native source identity/claims changed: '+field)
        inner=gate.get('backend',{})
        need(inner.get('ok') is True and inner.get('check_only') is True and inner.get('status')=='rustc_checked' and inner.get('rust_sha256')==gate['rust_sha256'] and digest(inner.get('validation_artifact_sha256')),'native source compiler evidence missing')
        native=row.get('native_build',{})
        expected_rust=hashlib.sha256((current.rust+ALLOCATOR+harness).encode()).hexdigest()
        need(row.get('harness_sha256')==hashlib.sha256((ALLOCATOR+harness).encode()).hexdigest(),'qualification harness changed')
        need(native.get('ok') is True and native.get('check_only') is False and native.get('status')=='rustc_checked' and native.get('crate_type')=='bin' and native.get('rustc_crate_type')=='bin' and native.get('rust_sha256')==expected_rust,'actual native executable was not built from the qualified source/harness')
        need(type(native.get('artifact_bytes')) is int and native['artifact_bytes']>0 and digest(native.get('artifact_sha256')) and native['artifact_sha256']==native.get('validation_artifact_sha256'),'native artifact identity missing')
        need(native.get('toolchain')==inner.get('toolchain') and native.get('target')==inner.get('target'),'native builds used different target/toolchain identities')
        execution=row.get('execution',{})
        expected=_expected_observations(row['name'])
        need(type(execution.get('exit_code')) is int and execution['exit_code']==0 and execution.get('stderr')=='' and execution.get('executable_sha256')==native['artifact_sha256'],'native execution failed/unbound')
        try:
            parsed=[json.loads(line) for line in execution['stdout'].splitlines()]
        except (KeyError,TypeError,ValueError,AttributeError) as exc:
            raise ValueError('invalid native output') from exc
        need(parsed==expected and row.get('observations')==expected,'native cleanup observations missing/altered')
        need(all(type(value) is int for record in parsed for key,value in record.items() if key!='case'),'native observations require exact integers')
        if row['name']=='sequential':
            retained=row.get('resource_ir',{})
            need(isinstance(retained.get('path'),str),'independent graph was not retained')
            with Path(retained['path']).open('rb') as stream: raw=stream.read(16*1024*1024+1)
            need(len(raw)<=16*1024*1024 and len(raw)==retained.get('bytes') and hashlib.sha256(raw).hexdigest()==retained.get('sha256'),'retained graph identity changed')
            def unique(pairs):
                result={}
                for key,value in pairs:
                    if key in result: raise ValueError('duplicate resource JSON field')
                    result[key]=value
                return result
            graph=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite resource JSON')))
            regenerated=lower_resource_ir(current.program,current.checked,project_sha256=current.project.identity)
            need(graph==regenerated,'graph differs from replayed source lowering')
            verified=verify_resource_ir(graph)
            verified['source_binding_verified']=False
            need(verified.get('ok') is True and row.get('resource_verifier')==verified and retained.get('canonical_sha256')==verified['ir_sha256'],'independent graph verification differs')
        else:
            need(row.get('resource_verifier')=={'status':'not_supported_in_sequential_resource_profile','ok':None},'concurrent source was mislabeled as verified by sequential IR')
    need(report.get('adversarial_checks')==adversarial_checks(graph) and all(row.get('ok') is True for row in report['adversarial_checks']),'resource rejection controls missing/changed')


def _operation(document, name):
    return next((fn, block, index, op) for fn in document["functions"]
                for block in fn["blocks"] for index, op in enumerate(block["ops"]) if op["op"] == name)


def adversarial_checks(graph):
    checks = []
    def run(name, document, expected):
        report = verify_resource_ir(document)
        actual = report["diagnostics"][0]["code"] if report["diagnostics"] else None
        checks.append({"case":name,"expected":expected,"actual":actual,"ok":not report["ok"] and actual==expected})
    doc = copy.deepcopy(graph)
    _, block, index, operation = _operation(doc,"take_field")
    block["ops"].insert(index+1,copy.deepcopy(operation))
    run("repeated_field_take",doc,"E_RIR_USE_AFTER_MOVE")
    doc = copy.deepcopy(graph)
    fn, block, index, operation = _operation(doc,"take_field")
    root = operation["place"]["root"]
    typ = next(item["type"] for item in fn["params"]+fn["locals"] if item["id"]==root)
    block["ops"].insert(index,{"op":"borrow","id":"attack","place":{"root":root,"path":[]},"type":typ,"mode":"read"})
    run("field_take_during_parent_loan",doc,"E_RIR_LOAN_CONFLICT")
    doc = copy.deepcopy(graph)
    fn, block, index, operation = _operation(doc,"init_field")
    next(item for item in fn["locals"] if item["id"]==operation["place"]["root"])["mutable"]=False
    run("restoration_of_immutable_owner",doc,"E_RIR_MUTABILITY")
    doc = copy.deepcopy(graph)
    _, block, index, _ = _operation(doc,"init_field")
    del block["ops"][index]
    run("missing_restoration",doc,"E_RIR_USE_AFTER_MOVE")
    doc = copy.deepcopy(graph)
    selected=next(fn for fn in doc["functions"] if fn["name"]=="selected")
    selected["returns"]["origin"]="p1"
    run("return_origin_changed",doc,"E_RIR_RETURN")
    doc = copy.deepcopy(graph);doc["schema"]="hepta.resource-ir.v2"
    run("legacy_profile_cannot_claim_places",doc,"E_RIR_RETURN")
    return checks


def qualify_places(directory:Path, *, rustc=None, retain_graph:Path | None=None):
    directory.mkdir(parents=True,exist_ok=True)
    result={"schema":"hepta.places-qualification.v1","ok":False,
            "generated_at_utc":datetime.now(timezone.utc).isoformat(),
            "platform":{"system":platform.system(),"machine":platform.machine()},
            "allocation_scope":ALLOCATION_SCOPE,
            "claims":dict(CLAIMS),"projects":[]}
    graph=None
    for name,path,harness in (("sequential",LIBRARY,SEQUENTIAL),("cancellation",CANCELLATION,CONCURRENT)):
        analysis=analyze_project(path,rustc=rustc,crate_type="rlib")
        row={"name":name,"entry":str(path.relative_to(ROOT)),"native_gate":analysis.report,
             "inputs":{str(Path(p).relative_to(ROOT)):hashlib.sha256(data).hexdigest() for p,data in analysis.project.source_bytes.items()}}
        result["projects"].append(row)
        if not analysis.report["ok"]: return result
        if name=="sequential":
            graph=lower_resource_ir(analysis.program,analysis.checked,project_sha256=analysis.project.identity)
            raw=(json.dumps(graph,indent=2,sort_keys=True)+"\n").encode()
            graph_path=directory/"places.resource-ir.json";graph_path.write_bytes(raw)
            standalone=subprocess.run([sys.executable,"-m","hepta.resource_ir",str(graph_path)],cwd=ROOT,capture_output=True,text=True,timeout=15)
            row["resource_verifier"]=json.loads(standalone.stdout)
            if standalone.returncode: return result
            if retain_graph is not None:
                retain_graph.parent.mkdir(parents=True,exist_ok=True)
                with retain_graph.open("xb") as out: out.write(raw)
                row["resource_ir"]={"path":str(retain_graph),"sha256":hashlib.sha256(raw).hexdigest(),
                                    "bytes":len(raw),"canonical_sha256":row["resource_verifier"]["ir_sha256"]}
        else:
            row["resource_verifier"]={"status":"not_supported_in_sequential_resource_profile","ok":None}
        generated=analysis.rust+ALLOCATOR+harness
        row["harness_sha256"]=hashlib.sha256((ALLOCATOR+harness).encode()).hexdigest()
        native=compile_rust(generated,rustc=rustc,crate_type="bin",output=directory/(name+".bin"))
        row["native_build"]=native
        if not native["ok"]: return result
        run=subprocess.run([native["artifact"]],capture_output=True,text=True,timeout=30)
        row["execution"]={"exit_code":run.returncode,"stdout":run.stdout,"stderr":run.stderr,
                          "executable_sha256":hashlib.sha256(Path(native["artifact"]).read_bytes()).hexdigest()}
        if run.returncode: return result
        row["observations"]=[json.loads(line) for line in run.stdout.splitlines()]
    result["adversarial_checks"]=adversarial_checks(graph)
    result["ok"]=all(row["ok"] for row in result["adversarial_checks"])
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True);parser.add_argument("--rustc")
    args=parser.parse_args()
    if args.output.exists(): parser.error("Refusing to replace an existing qualification")
    with tempfile.TemporaryDirectory(prefix="hepta-places-qualification-") as td:
        try:
            result=qualify_places(Path(td),rustc=args.rustc,retain_graph=args.output.with_suffix(".resource-ir.json"))
        except (OSError,ValueError,ResourceIRError,RuntimeError,subprocess.TimeoutExpired) as exc:
            result={"schema":"hepta.places-qualification.v1","ok":False,"error":str(exc)}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("x",encoding="utf-8") as out: json.dump(result,out,indent=2,sort_keys=True);out.write("\n")
    print(json.dumps({"ok":result["ok"],"output":str(args.output)}))
    return 0 if result["ok"] else 1


if __name__=="__main__": raise SystemExit(main())
