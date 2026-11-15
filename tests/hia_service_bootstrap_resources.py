"""Actual Store, private-budget and segmented-generator delivery controls.
No control writes a loss flag, associates a guessed resource, bypasses a close
guard, clears an UNKNOWN record, or retries a provider after a lost ACK.
"""
from __future__ import annotations
import argparse
import builtins
import contextvars
import ctypes
import json
import os
from pathlib import Path
import struct
import sys
import types
ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,""):sys.path.insert(0,str(ROOT))
from tests import hia_service_bootstrap_support as support
from tests.hia_service_bootstrap_controls import selected_environment,manifest_pins

RESOURCE_IDS=(
    "confirmed-child-parent-ACK-loss",
    "actual-child-loss-swallowed",
    "actual-child-loss-replaced",
    "ordinary-provider-error-confirmed",
    "late-FINALIZE-ACK-loss",
    "actual-B-used-A-unassociated",
    "same-resource-new-Context",
    "different-healthy-resource",
    "nested-child-confirmed-outer-loss",
    "healthy-resource-retirement",
    "constructor-before-Store",
    "constructor-Store-provider-error",
    "constructor-inside-try-cleanup",
    "independent-budget-B-retirement",
    "generator-first-advance-loss",
    "generator-second-advance-loss",
    "generator-confirmed-yield-retirement",
)

def outcome(call):
    try:return {"kind":"return"},None,call()
    except BaseException as error:
        return {"kind":"raised","type":type(error).__name__,"text":str(error)},error,None

def _explicit_namespace(api,updates):
    namespace=dict(vars(api))
    captured=api._SERVICE_BOOTSTRAP_GLOBAL_BUILTINS
    if type(captured) is not dict:captured=vars(captured)
    namespace["__builtins__"]=captured
    namespace.update(updates)
    imports={}
    for name,fn in api._SERVICE_BOOTSTRAP_IMPORT_PORTS.items():
        cloned=types.FunctionType(fn.__code__,namespace,fn.__name__,fn.__defaults__,fn.__closure__)
        cloned.__kwdefaults__=fn.__kwdefaults__
        imports[name]=cloned
    return namespace,captured,imports,api._SERVICE_BOOTSTRAP_LOCAL_LAYOUTS

def run_case(manifests,root,name,report):
    from hepta import hia_agent_service as api,hia_agent_store as store_api
    from hepta import hia_service_bootstrap_native as native,hia_store_artifact_profile_native as store_native
    from hepta import hia_native_delivery as delivery
    root=Path(root);root.mkdir(parents=True,exist_ok=False)
    image=native.installed_service_bootstrap(manifests["bootstrap"])
    child_image=store_native.installed_store_artifact_profile(manifests["store"])
    owner_entry,child_entry=image._entry,child_image._entry
    owned=[];close_effects=[];owner_rows=[];child_rows=[]
    report.update({"case":name,"owner_entries":owner_rows,"child_entries":child_rows,
                   "close_body_effects":close_effects,"SQL":{},"validated":False})
    close_reference=store_api._NATIVE_STORE_CLOSE_REFERENCE
    def close_body(store):
        close_effects.append(id(store))
        return close_reference(store)
    store_api._NATIVE_STORE_CLOSE_REFERENCE=close_body
    def new_store(label):
        store=store_api.AgentStore(root/label)
        owned.append(store)
        trace=[];store.db.set_trace_callback(trace.append)
        report["SQL"][label]=trace
        return store
    def observed_child(source,size,output,capacity,state,extent):
        code=child_entry(source,size,output,capacity,state,extent)
        words=struct.unpack("<"+str(size//8)+"Q",ctypes.string_at(source,size))
        child_rows.append({"event":words[1],"mode":words[5],"code":code})
        if (name in ("actual-child-loss-swallowed","actual-child-loss-replaced")
                and words[1]==2 and words[5]==1
                and any("INSERT" in sql.upper() for sql in report["SQL"].get("B",()))):
            raise ValueError("actual Store child return lost")
        return code
    def observed_owner(source,size,output,capacity,state,extent):
        code=owner_entry(source,size,output,capacity,state,extent)
        words=struct.unpack("<16Q",ctypes.string_at(source,size))
        owner_rows.append({"event":words[1],"mode":words[5],"port":words[3],"code":code})
        record=delivery.current_record()
        is_outer=record is not None and record.owner is report.get("_live_frame")
        ack_loss=name in ("confirmed-child-parent-ACK-loss","actual-B-used-A-unassociated",
                          "same-resource-new-Context","different-healthy-resource")
        if ack_loss and words[1]==native.SUCCEEDED and words[3]==native.PORT["profile_result"]:
            raise ValueError("actual bootstrap ACK lost after confirmed child")
        if (name in ("late-FINALIZE-ACK-loss","nested-child-confirmed-outer-loss")
                and words[1]==native.FINALIZE and is_outer):
            raise ValueError("actual whole bootstrap FINALIZE return lost")
        if (name=="independent-budget-B-retirement" and words[1]==native.SUCCEEDED
                and words[3]==native.PORT["init_budget_construct"]):
            raise ValueError("actual candidate budget connection creation ACK lost")
        if name.startswith("generator-") and words[5]==native.GENERATOR_ROOTS:
            ordinal=sum(row["event"]==native.SUCCEEDED and row["port"]==native.PORT["generator_root_value"]
                        for row in owner_rows)
            target=1 if name=="generator-first-advance-loss" else 2 if name=="generator-second-advance-loss" else None
            if target is not None and ordinal==target and words[1]==native.SUCCEEDED and words[3]==native.PORT["generator_root_value"]:
                raise ValueError("actual segmented-generator value ACK lost")
        return code
    child_image._entry,image._entry=observed_child,observed_owner
    try:
        if name.startswith("constructor-") or name=="independent-budget-B-retirement":
            return constructor_case(api,native,image,new_store,owned,report,name)
        if name.startswith("generator-"):
            return generator_case(api,native,image,new_store,owned,report,name)
        a,b=new_store("A"),new_store("B")
        provider_calls=[];swallowed=[]
        requested=MemoryError("ordinary provider after confirmed actual child")
        replacement=RuntimeError("replacement after real child UNKNOWN")
        class Provider:
            def check_profile(self,ref,expected):
                provider_calls.append("check_profile")
                try:b.put(b"bootstrap-resource","program",{})
                except store_native.StoreArtifactProfileUnknown as error:
                    swallowed.append(type(error).__name__)
                    if name=="actual-child-loss-replaced":raise replacement
                    if name!="actual-child-loss-swallowed":raise
                if name=="ordinary-provider-error-confirmed":raise requested
                return ref
        class Service:
            profiles={"name":"profile"}
        service=Service();service.store=Provider()
        if name=="nested-child-confirmed-outer-loss":
            nested=service
            class OuterProvider:
                def check_profile(self,ref,expected):
                    return api.HIAAgentService._profile(nested,ref,"name")
            service=Service();service.store=OuterProvider()
        frame=native.ServiceBootstrapFrame(image,native.PROFILE,{"self":service,"ref":"ref","name":"name"})
        report["_live_frame"]=frame
        observed,error,result=outcome(frame.finish)
        report.pop("_live_frame")
        report.update({"outcome":observed,"result":result,"providers":provider_calls,
                       "swallowed":swallowed,"parent_lost":frame._delivery.loss is not None,
                       "parent_native_failed":frame.native_failed})
        if not child_rows or not any("INSERT" in sql.upper() for sql in report["SQL"]["B"]):
            raise AssertionError("control did not reach the actual Store/Native/SQLite boundary")
        loss=name not in ("ordinary-provider-error-confirmed","healthy-resource-retirement")
        if loss:
            if frame._delivery.loss is None or not frame.native_failed:
                raise AssertionError("actual parent loss was not retained")
            if name=="actual-child-loss-replaced":
                if error is not replacement:raise AssertionError("replacement error identity changed")
            elif not isinstance(error,(native.ServiceBootstrapUnknown,delivery.NativeDeliveryUnknown)):
                raise AssertionError("actual unknown classification differs") from error
            before=list(close_effects)
            close_result,close_error,_=outcome(b.close)
            report["retire_B"]=close_result
            if not isinstance(close_error,delivery.NativeDeliveryUnknown) or close_effects!=before:
                raise AssertionError("unknown Store B reached its original close body")
            if name in ("actual-child-loss-swallowed","actual-child-loss-replaced") and swallowed!=["StoreArtifactProfileUnknown"]:
                raise AssertionError("control did not catch the real child UNKNOWN")
            if name=="same-resource-new-Context":
                calls=len(child_rows);sql=list(report["SQL"]["B"])
                result2,error2,_=outcome(lambda:contextvars.Context().run(b.put,b"no-replay","program",{}))
                report["fresh_context"]=result2
                if (not isinstance(error2,(delivery.NativeDeliveryUnknown,store_native.StoreArtifactProfileUnknown))
                        or len(child_rows)!=calls or report["SQL"]["B"]!=sql):
                    raise AssertionError("known resource loss was replayed in another Context")
            if name=="different-healthy-resource":
                healthy=new_store("C")
                contextvars.Context().run(healthy.put,b"healthy","program",{})
                healthy.close();owned.remove(healthy)
            a.close();owned.remove(a)
            report["unassociated_A_retired"]=True
        else:
            if name=="ordinary-provider-error-confirmed":
                if error is not requested:raise AssertionError("confirmed ordinary error identity changed")
            elif error is not None or result!="ref":
                raise AssertionError("healthy bootstrap provider outcome differs") from error
            if frame._delivery.loss is not None or delivery._RESOURCE_OBSERVATIONS:
                raise AssertionError("confirmed parent retained a resource/loss")
            b.close();owned.remove(b);a.close();owned.remove(a)
        report["validated"]=True
    finally:
        report.pop("_live_frame",None)
        child_image._entry,image._entry=child_entry,owner_entry
        for store in owned:
            try:store.close()
            except delivery.NativeDeliveryUnknown:
                # The actual owned process remains custodian through exit.
                # No private DB close, UNKNOWN clearing or replay occurs.
                pass
        store_api._NATIVE_STORE_CLOSE_REFERENCE=close_reference

def constructor_case(api,native,image,new_store,owned,report,name):
    from hepta import hia_native_delivery as delivery
    real_catalog,real_store=api.catalog,api.AgentStore
    fault=MemoryError("actual constructor boundary")
    events=[]
    class FailingProfiles(api.HIAAgentService):
        def _profiles(self):
            events.append("profiles")
            raise fault
    service=object.__new__(FailingProfiles if name=="constructor-inside-try-cleanup" else api.HIAAgentService)
    def catalog():
        events.append("catalog")
        if name=="constructor-before-Store":raise fault
        return real_catalog()
    def store_factory(root):
        events.append("store")
        store=new_store("constructor-A")
        if name=="constructor-Store-provider-error":raise fault
        return store
    api.catalog,api.AgentStore=catalog,store_factory
    report["constructor_events"]=events
    try:
        observed,error,_=outcome(lambda:api.HIAAgentService.__init__(service,Path("opaque-test-state-root")))
        report["outcome"]=observed
        if name=="independent-budget-B-retirement":
            if not isinstance(error,(native.ServiceBootstrapUnknown,delivery.NativeDeliveryUnknown)):
                raise AssertionError("budget creation did not lose its actual parent ACK") from error
            budget=service._candidate_budget
            report["budget_B_distinct_from_Store_A"]=budget.db is not service.store.db
            if not report["budget_B_distinct_from_Store_A"]:
                raise AssertionError("budget control did not create its independent connection")
            report["budget_B_closed_before"]=budget.closed
            close_result,close_error,_=outcome(budget.close)
            report["budget_B_close"]=close_result
            report["budget_B_closed_after"]=budget.closed
            if not isinstance(close_error,delivery.NativeDeliveryUnknown) or budget.closed:
                # This is deliberately a real blocking gate for the declared
                # missing budget resource ABI, never an expected failure/skip.
                raise AssertionError("independent budget connection B lacks real UNKNOWN retirement custody")
            report["validated"]=True
            return
        if error is not fault:raise AssertionError("constructor ordinary error identity changed") from error
        if name=="constructor-before-Store":
            if events!=["catalog"] or owned:raise AssertionError("pre-Store failure reached construction/cleanup")
        elif name=="constructor-Store-provider-error":
            if events!=["catalog","store"] or report["close_body_effects"]:
                raise AssertionError("pre-try Store provider error entered service cleanup")
        else:
            if events!=["catalog","store","profiles"] or report["close_body_effects"]!=[id(service.store)]:
                raise AssertionError("original constructor try cleanup did not close Store exactly once")
            owned.remove(service.store)
        report["validated"]=True
    finally:
        api.catalog,api.AgentStore=real_catalog,real_store

def generator_case(api,native,image,new_store,owned,report,name):
    from hepta import hia_native_delivery as delivery
    b=new_store("generator-B")
    actual_path=api.Path
    calls=[]
    def path(value):
        calls.append(value)
        b.put(str(value).encode(),"program",{})
        return actual_path(value)
    namespace,captured,imports,layouts=_explicit_namespace(api,{"Path":path})
    generator=native._bootstrap_generator(image,native.GENERATOR_ROOTS,iter((".", "..")),
        namespace,captured,imports,layouts)
    records=[]
    for ordinal in range(3):
        observed,error,value=outcome(lambda:next(generator))
        records.append({"ordinal":ordinal,"outcome":observed,
                        "value":None if value is None else str(value),
                        "resource_observations":len(delivery._RESOURCE_OBSERVATIONS),
                        "custody":list(delivery.custody_snapshot())})
        if error is not None:
            break
        if name=="generator-confirmed-yield-retirement" and delivery._RESOURCE_OBSERVATIONS:
            raise AssertionError("confirmed yield retains a pending resource fact")
    report["advances"]=records;report["path_calls"]=calls
    if name=="generator-confirmed-yield-retirement":
        if not isinstance(error,StopIteration) or len(calls)!=2:
            raise AssertionError("complete healthy generator did not terminate")
        if delivery._RESOURCE_OBSERVATIONS or delivery.custody_snapshot():
            raise AssertionError("healthy generator terminal left custody")
        b.close();owned.remove(b)
    else:
        expected=1 if name=="generator-first-advance-loss" else 2
        if len(calls)!=expected or not isinstance(error,(native.ServiceBootstrapUnknown,delivery.NativeDeliveryUnknown)):
            raise AssertionError("generator actual advance loss differs") from error
        before=list(report["close_body_effects"])
        close_result,close_error,_=outcome(b.close)
        report["retire_B"]=close_result
        if not isinstance(close_error,delivery.NativeDeliveryUnknown) or report["close_body_effects"]!=before:
            raise AssertionError("generator loss did not retain the actual resource")
    report["validated"]=True

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-list",type=Path,required=True)
    parser.add_argument("--case",choices=RESOURCE_IDS,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    raw,manifests,pin=support.capture_json(args.manifest_list)
    source_before=support.source_snapshot();images_before=manifest_pins(manifests)
    previous=dict(os.environ);os.environ.clear();os.environ.update(selected_environment(manifests))
    report={"schema":"hepta.hia.service-bootstrap-resource-control.v1",**support.child_identity(),
            "status":"HOLD","source_before":source_before,"images_before":images_before,
            "manifest_list":pin,"case":args.case,"whole_native_stack_qualified":False}
    try:
        run_case(manifests,args.output/"state",args.case,report)
        report["source_after"]=support.source_snapshot();report["images_after"]=manifest_pins(manifests)
        support.exact_reread(args.manifest_list,raw)
        if not support.same(source_before,report["source_after"]) or not support.same(images_before,report["images_after"]):
            raise AssertionError("resource control source/image custody changed")
        if report["validated"] is not True:raise AssertionError("resource assertions did not complete")
        report["status"]="PASS_CONTROL_ONLY"
        return 0
    finally:
        os.environ.clear();os.environ.update(previous)
        support.write_json(args.output/"report.json",report)
if __name__=="__main__":
    raise SystemExit(main())
