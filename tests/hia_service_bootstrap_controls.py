"""Actual bootstrap public, protocol, ownership and construction qualification.
The original 232 domain is owned by the separate original-first executor.
"""
from __future__ import annotations
import argparse
from collections import Counter
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,""):
    sys.path.insert(0,str(ROOT))
from tests import hia_service_bootstrap_support as support
COLD="HEPTA_HIA_SERVICE_BOOTSTRAP_COLD_REPORT"
DEV="HEPTA_HIA_SERVICE_BOOTSTRAP_DEVELOPMENT_COMPILER"
EVIDENCE="HEPTA_HIA_SERVICE_BOOTSTRAP_EVIDENCE"
SOURCE_EVIDENCE="HEPTA_HIA_SERVICE_BOOTSTRAP_SOURCE_EVIDENCE"
SELECTORS={
    "bootstrap":"HEPTA_HIA_SERVICE_BOOTSTRAP_MANIFEST",
    "store":"HEPTA_HIA_STORE_ARTIFACT_PROFILE_MANIFEST",
    "transaction":"HEPTA_HIA_STORE_TRANSACTION_MANIFEST",
    "candidate":"HEPTA_HIA_CANDIDATE_BUDGET_MANIFEST",
    "ledger":"HEPTA_HIA_SLOT_LEDGER_MANIFEST",
    "context":"HEPTA_HIA_SERVICE_CONTEXT_MANIFEST",
}

def invocation(variable,label):
    base=Path(os.environ[variable]) if variable in os.environ else Path(tempfile.mkdtemp(prefix="hia-bootstrap-"))
    base.mkdir(parents=True,exist_ok=True)
    target=base/(label+"-"+str(os.getpid())+"-"+str(time.time_ns()))
    target.mkdir(mode=0o700)
    support.write_json(target/"parent.json",{**support.child_identity(),
        "evidence_variable":variable,
        "enclosing_source_build_observations":os.environ.get("HEPTA_HIA_SOURCE_BUILD_OBSERVATIONS"),
        "created_time_ns":time.time_ns()})
    return target

def clean_environment():
    return {k:v for k,v in os.environ.items()
            if not k.startswith(("HEPTA_HIA_","PYTHON"))}

def selected_environment(manifests):
    environment=clean_environment()
    environment.update({SELECTORS[key]:str(Path(path).resolve()) for key,path in manifests.items()})
    return environment

def bundle(path,manifests):
    from hepta.hia_native_helpers import SCHEMA,ABI,TARGET
    return support.write_json(path,{"schema":SCHEMA,"target":TARGET,"abi":ABI,"helpers":[
        {"selector":SELECTORS[key],"manifest_path":str(Path(path0).resolve()),
         "manifest_sha256":support.file_pin(path0)["sha256"]}
        for key,path0 in manifests.items()]})["sha256"]

def manifest_pins(manifests):
    result={}
    for name,path0 in manifests.items():
        path0=Path(path0)
        raw,value,pin=support.capture_json(path0)
        image_name=value["image_path"]
        if type(image_name) is not str or Path(image_name).name!=image_name:
            raise ValueError("component image is not its sibling basename")
        image=support.file_pin(path0.parent/image_name)
        if image["sha256"]!=value["image_sha256"]:
            raise ValueError("actual image differs from manifest")
        support.exact_reread(path0,raw)
        result[name]={"manifest":pin,"image":image}
    return result

def _development_companion(directory,compiler,stem,source_name,schema):
    """Explicit DEV construction; no cold identity is fabricated."""
    from tools.qualify_hia_selfhost import compile_stage
    from tools.build_hia_source_build import _check_pack_output
    directory=Path(directory);directory.mkdir(mode=0o700)
    source_path=ROOT/source_name
    source,compiler_raw=source_path.read_bytes(),Path(compiler).read_bytes()
    image,receipt=compile_stage(directory,stem,Path(compiler),source)
    image_raw=image.read_bytes()
    full=(directory/(stem+".output.bin")).read_bytes()
    if (_check_pack_output(receipt,full,artifact=compiler_raw,source=source)!=image_raw
            or source_path.read_bytes()!=source or Path(compiler).read_bytes()!=compiler_raw):
        raise ValueError("explicit DEV companion source/compiler/output changed")
    manifest={"schema":schema,"source_sha256":sha256(source).hexdigest(),
              "image_path":image.name,"image_sha256":sha256(image_raw).hexdigest(),
              "compiler_sha256":sha256(compiler_raw).hexdigest()}
    path=directory/"manifest.json";support.write_json(path,manifest)
    support.write_json(directory/"build.json",{"scope":"DEVELOPMENT_COMPONENT",
        "manifest":manifest,"native_compile_receipt":receipt,
        "full_output":support.bytes_pin(full),"cold_report_sha256":None,
        "source_before":support.bytes_pin(source),"source_after":support.bytes_pin(source_path.read_bytes())})
    return path

def build_images(directory):
    cold,dev=os.environ.get(COLD),os.environ.get(DEV)
    if (cold is None)==(dev is None) or cold=="" or dev=="":
        raise ValueError("one exact current cold report or explicit DEV compiler is required")
    captures=[]
    if cold is not None:
        from tools.hia_cold_compiler import read_cold_build_inputs
        cold_inputs=read_cold_build_inputs(cold)
        captures.extend(cold_inputs.files)
        compiler=cold_inputs.compiler
    else:
        compiler=Path(dev)
    compiler_raw=compiler.read_bytes()
    from tools.build_hia_service_bootstrap import build as bootstrap_build
    from tools.build_hia_store_artifact_profile import build as store_build
    from tools.build_hia_store_transaction import build as transaction_build
    from tools.build_hia_service_context import build as context_build
    factories={"bootstrap":bootstrap_build,"store":store_build,
               "transaction":transaction_build,"context":context_build}
    manifests={name:factory(Path(directory)/(name+"-image"),compiler,cold,development=cold is None)
               for name,factory in factories.items()}
    if cold is not None:
        from tools.build_hia_candidate_budget import build as candidate_build
        from tools.build_hia_slot_ledger import build as ledger_build
        manifests["candidate"]=candidate_build(Path(directory)/"candidate-image",compiler,Path(cold))
        manifests["ledger"]=ledger_build(Path(directory)/"ledger-image",compiler,Path(cold))
    else:
        for name,stem,schema in (
                ("candidate","candidate_budget","hepta.hia.candidate-budget-native.v1"),
                ("ledger","slot_ledger","hepta.hia.slot-ledger-native.v1")):
            manifests[name]=_development_companion(Path(directory)/(name+"-image"),compiler,stem,
                "examples/hia_bootstrap/"+stem+".hepta",schema)
    if compiler.read_bytes()!=compiler_raw:
        raise ValueError("shared actual compiler changed")
    for path,raw in captures:support.exact_reread(path,raw)
    support.write_json(Path(directory)/"construction.json",{
        "scope":"MATCHING_SOURCE_COLD" if cold is not None else "DEVELOPMENT_ONLY",
        "compiler":support.bytes_pin(compiler_raw),"compiler_path":str(compiler.resolve()),
        "cold_report_path":None if cold is None else str(Path(cold).resolve()),
        "cold_report":None if cold is None else support.file_pin(cold),
        "manifests":manifest_pins(manifests),
        "whole_native_stack_qualified":False})
    return manifests

class PlainStore:
    def __init__(self,events):self.events=events
    def close(self):self.events.append("store.close")
class PlainService:
    def __init__(self):
        self.events=[];self._candidate_budget=None;self.store=PlainStore(self.events)

def raw_frame(image,service=None):
    from hepta.hia_service_bootstrap_native import ServiceBootstrapFrame,CLOSE
    return ServiceBootstrapFrame(image,CLOSE,{"self":PlainService() if service is None else service})

def public_controls(manifest):
    from tests.hia_service_bootstrap_observer import Backend
    from tests import hia_service_bootstrap_oracle as oracle
    backend=Backend("native",manifest)
    original_cases,_=oracle.cases()
    selected=[next(case for case in original_cases if case["method"]==method
                   and case["outer_exception"] is False and case["scenario"]==scenario)
        for method,scenario in (("__init__","both-selected"),("close","budget-present"),
            ("_profiles","complete-all27-outer-writes"),("_profile","provider-returns-opaque-object"),
            ("_program","normal"))]
    rows=[]
    for case in selected:
        start=backend.image._entry.calls
        functions,namespace,global_builtins=backend.select(case)
        value,trace=oracle.observe(case,functions=functions,namespace=namespace,captured_builtins=global_builtins)
        entries=backend.image._entry.calls-start
        if entries<=0 or any(part["outcome"]["kind"]!="return" for part in value["parts"]):
            raise AssertionError("actual selected public bootstrap route failed")
        rows.append({"id":case["id"],"entries":entries,"observation":value,"traceback":trace})
    if backend.poison_calls:raise AssertionError("selected public entered retained complete body")
    return {"rows":rows,"actual_public_codes":backend.public_code,
            "all_five_methods":True,"retained_poisoned":True}

def packet_controls(image):
    from hepta import hia_service_bootstrap_protocol as p
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime_prepared import prepare_runtime_program
    from hepta.hia_program_runtime import _Machine,_Owner,_View
    from hepta.hia_service_bootstrap_native import SOURCE
    program=prepare_runtime_program(assemble_program(SOURCE.read_bytes()))
    rows=[]
    def direct(label,words,state_raw=None,sizes=(128,96,192)):
        raw=struct.pack("<16Q",*words)
        source=ctypes.create_string_buffer(raw+b"Q"*16,144)
        state_raw=bytes(192) if state_raw is None else state_raw
        state=ctypes.create_string_buffer(state_raw+b"S"*16,208)
        output=ctypes.create_string_buffer(b"O"*112,112)
        before=tuple(ctypes.string_at(value,size) for value,size in zip((source,output,state),sizes))
        actual=image._entry(source,sizes[0],output,sizes[1],state,sizes[2])
        owners=[_Owner(i+1,bytearray(raw0)) for i,raw0 in enumerate(before)]
        machine=_Machine(program,4_000_000,16<<20,None,128)
        expected=machine.invoke(machine.functions["f0"],[_View(owner,i!=0) for i,owner in enumerate(owners)])[0]
        actual_buffers=tuple(ctypes.string_at(value,size) for value,size in zip((source,output,state),sizes))
        expected_buffers=tuple(bytes(owner.data) for owner in owners)
        rows.append({"label":label,"sizes":list(sizes),"before":[raw0.hex() for raw0 in before],
            "native_code":actual,"VM_code":expected,"native":[v.hex() for v in actual_buffers],
            "VM":[v.hex() for v in expected_buffers]})
        if actual!=expected or actual_buffers!=expected_buffers:
            raise AssertionError("complete native/VM bootstrap ABI differs")
        if source.raw!=raw+b"Q"*16 or output.raw[96:]!=b"O"*16 or state.raw[192:]!=b"S"*16:
            raise AssertionError("bootstrap ABI crossed a declared buffer")
        return actual,output.raw[:96],state.raw[:192]
    request=[p.REQUEST_MAGIC,p.INITIALIZE,0,0,0,p.CLOSE,17,23,*([0]*8)]
    code,result,state=direct("valid-initialize",request)
    if code!=96 or struct.unpack("<12Q",result)[1]!=0:
        raise AssertionError("valid initializer rejected")
    output_words=struct.unpack("<12Q",result)
    claim=[p.REQUEST_MAGIC,p.CLAIM,output_words[3],output_words[2],0,p.CLOSE,17,23,*([0]*8)]
    for label,index,value in (("magic",0,0),("sequence",2,9),("port",3,99),
            ("observation",4,1),("mode",5,p.PROFILE),("nonce",6,18),("reserved",15,1)):
        altered=claim.copy();altered[index]=value
        code,result,_=direct(label,altered,state)
        if code==96 and struct.unpack("<12Q",result)[1]==0:
            raise AssertionError("invalid request accepted: "+label)
    for i,sizes in enumerate(((127,96,192),(128,95,192),(128,96,191))):
        code,_,_=direct("short-buffer-"+str(i),request,sizes=sizes)
        if code==96:raise AssertionError("short declared buffer accepted")
    for offset in (0,8,16,24,40,48,80,184):
        altered=bytearray(state);altered[offset]^=1
        code,result,_=direct("state-byte-"+str(offset),claim,bytes(altered))
        if code==96 and struct.unpack("<12Q",result)[1]==0:
            raise AssertionError("corrupt state accepted")
    code,result,claimed=direct("valid-claim",claim,state)
    ack=[p.REQUEST_MAGIC,p.SUCCEEDED,claim[2],claim[3],0,p.CLOSE,17,23,*([0]*8)]
    code,result,advanced=direct("valid-ack",ack,claimed)
    code,result,_=direct("replayed-ack",ack,advanced)
    if code==96 and struct.unpack("<12Q",result)[1]==0:
        raise AssertionError("duplicate completed ACK accepted")
    return {"records":rows,"provider_effects":0,"fresh_machine_limits":[4_000_000,16<<20,128],
            "complete_request_output_state_bytes":True}


def loss_controls(image):
    from hepta import hia_service_bootstrap_native as native
    from hepta.hia_native_delivery import custody_snapshot
    actual=image._entry
    rows=[]
    requested=MemoryError("bootstrap prepare allocation")
    original_pack=native.struct.pack
    def no_pack(*args,**kwargs):raise requested
    native.struct.pack=no_pack
    try:
        try:raw_frame(image)
        except MemoryError as error:
            if error is not requested:raise AssertionError("safe pre-entry exception was replaced")
        else:raise AssertionError("prepare injection did not occur")
        rows.append({"case":"prepare-pack","same_error":True,"actual_entries":0})
    finally:native.struct.pack=original_pack
    for label in ("return-lost","output-magic","request-corrupt","state-canary",
                  "MemoryError","KeyboardInterrupt","SystemExit"):
        entries=[]
        failure={"MemoryError":MemoryError,"KeyboardInterrupt":KeyboardInterrupt,
                 "SystemExit":SystemExit}.get(label,ValueError)("bootstrap actual return lost")
        lost_before=sum(row["lost"] for row in custody_snapshot())
        def injected(source,size,output,capacity,state,extent):
            code=actual(source,size,output,capacity,state,extent)
            entries.append(code)
            if label in ("return-lost","MemoryError","KeyboardInterrupt","SystemExit"):
                raise failure
            value,offset=(output,0) if label=="output-magic" else (source,0) if label=="request-corrupt" else (state,extent)
            ctypes.c_ubyte.from_address(ctypes.addressof(value)+offset).value^=1
            return code
        image._entry=injected
        try:
            try:raw_frame(image)
            except BaseException as error:
                if label in ("MemoryError","KeyboardInterrupt","SystemExit"):
                    if error is not failure:raise AssertionError("actual loss normalized original non-domain error")
                elif not isinstance(error,native.ServiceBootstrapUnknown):
                    raise AssertionError("actual delivery loss classification differs") from error
            else:raise AssertionError("actual unconfirmed return was adopted")
            lost_after=sum(row["lost"] for row in custody_snapshot())
            if entries!=[native.OUTPUT_BYTES] or lost_after!=lost_before+1:
                raise AssertionError("loss is not retained after exactly one real entry")
            rows.append({"case":label,"actual_entries":len(entries),"retained_loss_delta":1})
        finally:image._entry=actual
    return {"rows":rows,"exception_class_is_not_loss_evidence":True}

def ownership_controls(image):
    import contextvars,select,signal,threading
    from hepta import hia_service_bootstrap_native as native
    rows=[]
    frame=raw_frame(image)
    errors=[]
    def other_thread():
        try:frame.finish()
        except BaseException as error:errors.append(type(error).__name__)
        else:errors.append("accepted")
    thread=threading.Thread(target=other_thread)
    thread.start();thread.join(10)
    if thread.is_alive() or errors!=["ServiceBootstrapUnknown"]:
        raise AssertionError("same invocation crossed its creator thread")
    frame.finish()
    rows.append("thread-refused-parent-remains-live")
    try:frame.finish()
    except native.ServiceBootstrapUnknown:rows.append("completed-frame-refused")
    else:raise AssertionError("completed frame resumed")
    frame=raw_frame(image)
    read_fd,write_fd=os.pipe()
    pid=os.fork()
    if pid==0:
        os.close(read_fd)
        try:
            try:frame.finish()
            except native.ServiceBootstrapUnknown:result=b"refused"
            else:result=b"accepted"
            os.write(write_fd,result)
        finally:os._exit(0)
    os.close(write_fd);reaped=False
    try:
        if not select.select([read_fd],[],[],10)[0]:
            raise AssertionError("fork child exceeded its declared 10-second bound")
        result=os.read(read_fd,32)
        _,status=os.waitpid(pid,0);reaped=True
        if status!=0 or result!=b"refused":raise AssertionError("inherited invocation was usable")
    finally:
        os.close(read_fd)
        if not reaped:
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
            os.waitpid(pid,0)
    frame.finish();rows.append("fork-refused-parent-remains-live")
    holder={};attempts=[]
    class RecursiveStore:
        def close(self):
            try:holder["frame"].finish()
            except native.ServiceBootstrapUnknown:attempts.append("refused")
            else:raise AssertionError("same frame was reentered")
    service=PlainService();service.store=RecursiveStore()
    frame=raw_frame(image,service);holder["frame"]=frame
    try:
        frame.finish()
        if attempts!=["refused"] or not frame.finished or frame._delivery.loss is not None:
            raise AssertionError("reentry cleanup retired or poisoned its live invocation")
    finally:holder.clear()
    rows.append("same-frame-reentry-before-cleanup")
    fresh=raw_frame(image)
    contextvars.Context().run(fresh.finish)
    if not fresh.finished:raise AssertionError("healthy context advance did not finish")
    rows.append("fresh-context-has-no-invented-ancestor")
    return {"controls":rows}

def lazy_controls():
    """A fresh actual public dispatch; absent does not import the optional owner."""
    from hepta import hia_agent_service as api
    if "hepta.hia_service_bootstrap_native" in sys.modules:
        raise AssertionError("lazy control requires a fresh child without optional adapter")
    environment=dict(os.environ)
    rows=[]
    try:
        os.environ.pop(SELECTORS["bootstrap"],None)
        for method,args in (("close",()),("_profile",({"id":"r"},"n")),("_program",({"id":"p"},))):
            class MinimalStore:
                def close(self):rows.append("close")
                def check_profile(self,ref,profile):rows.append("check-profile");return ref
                def get(self,ref):rows.append("get");raise LookupError("before optional ownership")
            service=PlainService();service.store=MinimalStore();service.profiles={"n":"p"}
            try:getattr(api.HIAAgentService,method)(service,*args)
            except LookupError:
                if method!="_program":raise
        if "hepta.hia_service_bootstrap_native" in sys.modules:
            raise AssertionError("unselected public method imported its optional owner")
        absent=list(rows);rows.clear()
        os.environ[SELECTORS["bootstrap"]]=""
        for method,args in (("__init__",("unused",)),("close",()),("_profiles",()),
                            ("_profile",({"id":"r"},"n")),("_program",({"id":"p"},))):
            service=PlainService()
            try:getattr(api.HIAAgentService,method)(service,*args)
            except ValueError:pass
            else:raise AssertionError("empty explicit selector did not refuse "+method)
            if service.events or rows:raise AssertionError("empty selector reached an original provider")
        return {"absent_events":absent,"empty_methods":list(("__init__","close","_profiles","_profile","_program")),
                "absent_imported_owner":False,"empty_provider_effects":0}
    finally:os.environ.clear();os.environ.update(environment)

def loader_controls(manifest,directory):
    from hepta import hia_service_bootstrap_native as native
    directory=Path(directory);directory.mkdir()
    raw,value,_=support.capture_json(manifest)
    image=Path(manifest).parent/value["image_path"]
    (directory/value["image_path"]).write_bytes(image.read_bytes())
    rows=[]
    for field in ("source_sha256","image_sha256","schema","image_path"):
        changed=dict(value)
        changed[field]="0"*64 if field.endswith("sha256") else "../outside" if field=="image_path" else "wrong"
        path=directory/(field+".json");support.write_json(path,changed)
        try:native.installed_service_bootstrap(str(path))
        except (ValueError,OSError):rows.append(field)
        else:raise AssertionError("source/image/manifest drift accepted: "+field)
    support.exact_reread(manifest,raw)
    return {"controls":rows,"production_source_modified":False}

def pinned_controls(manifest,directory):
    import threading
    from hepta import hia_service_bootstrap_native as native
    from hepta.hia_native_helpers import native_helpers_scope,native_helpers_identity
    directory=Path(directory);directory.mkdir()
    manifest_path=Path(manifest)
    bundle_path=directory/"bundle.json";digest=bundle(bundle_path,{"bootstrap":manifest_path})
    raw,value,_=support.capture_json(manifest_path)
    copied=directory/"copy";copied.mkdir()
    (copied/value["image_path"]).write_bytes((manifest_path.parent/value["image_path"]).read_bytes())
    (copied/"manifest.json").write_bytes(raw)
    environment=dict(os.environ);rows=[]
    try:
        os.environ.clear();os.environ.update(clean_environment_from(environment))
        with native_helpers_scope(str(bundle_path),digest) as binding:
            image=native.installed_service_bootstrap(str(manifest_path))
            if native_helpers_identity()["native_helpers_sha256"]!=digest:
                raise AssertionError("actual worker bundle identity differs")
            if native.installed_service_bootstrap(str(manifest_path)) is not image:
                raise AssertionError("admitted worker image was rebuilt")
            try:native.installed_service_bootstrap(str(copied/"manifest.json"))
            except ValueError:rows.append("undeclared-copy")
            else:raise AssertionError("worker accepted an undeclared image")
            try:
                with native_helpers_scope(str(bundle_path),digest):
                    raise AssertionError("nested worker was accepted")
            except ValueError:rows.append("nested-worker")
            replies=[]
            def foreign_thread():
                try:native.installed_service_bootstrap(str(manifest_path))
                except ValueError:replies.append("refused")
                else:replies.append("accepted")
            thread=threading.Thread(target=foreign_thread);thread.start();thread.join(10)
            if thread.is_alive() or replies!=["refused"]:
                raise AssertionError("worker scope crossed a thread")
            rows.append("worker-thread")
            raw_frame(image).finish()
        try:binding.check()
        except ValueError:rows.append("binding-after-scope")
        else:raise AssertionError("expired worker binding is still current")
        with native_helpers_scope():
            try:native.installed_service_bootstrap(str(manifest_path))
            except ValueError:rows.append("unselected-worker")
            else:raise AssertionError("unselected worker mapped an undeclared helper")
    finally:os.environ.clear();os.environ.update(environment)
    return {"controls":rows,"bundle_sha256":digest,"exact_image":True}

def clean_environment_from(value):
    return {k:v for k,v in value.items() if not k.startswith(("HEPTA_HIA_","PYTHON"))}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action",choices=("public","packets","loss","ownership","loader","pinned","lazy"),required=True)
    parser.add_argument("--manifest-list",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    before=support.source_snapshot()
    report={"schema":"hepta.hia.service-bootstrap-controls.v1",**support.child_identity(),
            "status":"HOLD","action":args.action,"source_before":before,
            "whole_native_stack_qualified":False}
    raw=None;manifests={}
    try:
        if args.action=="lazy":
            result=lazy_controls()
        else:
            if args.manifest_list is None:raise ValueError("actual controls need manifests")
            raw,manifests,pin=support.capture_json(args.manifest_list)
            report["manifest_list"]=pin
            report["images_before"]=manifest_pins(manifests)
            from hepta import hia_service_bootstrap_native as native
            image=native.installed_service_bootstrap(manifests["bootstrap"])
            if args.action=="public":result=public_controls(manifests["bootstrap"])
            elif args.action=="packets":result=packet_controls(image)
            elif args.action=="loss":result=loss_controls(image)
            elif args.action=="ownership":result=ownership_controls(image)
            elif args.action=="loader":result=loader_controls(manifests["bootstrap"],args.output/"drift")
            else:result=pinned_controls(manifests["bootstrap"],args.output/"pinned")
            report["images_after"]=manifest_pins(manifests)
            if not support.same(report["images_before"],report["images_after"]):
                raise AssertionError("control image/manifest bytes changed")
            support.exact_reread(args.manifest_list,raw)
        report["observation"]=result
        report["source_after"]=support.source_snapshot()
        if not support.same(before,report["source_after"]):
            raise AssertionError("bootstrap control source changed")
        report["status"]="PASS_CONTROL_ONLY"
        return 0
    finally:
        support.write_json(args.output/"report.json",report)

if __name__=="__main__":
    raise SystemExit(main())
