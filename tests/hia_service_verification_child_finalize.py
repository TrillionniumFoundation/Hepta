"""Versioned independent child-FINALIZE-before-SQL actual-native control.

The original event-only predicate is preserved here. This is not the corrected
parent VERIFY FINALIZE row and does not qualify that row or the old Native8.
"""
from __future__ import annotations
import argparse
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,''):sys.path.insert(0,str(ROOT))

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()

def pin(raw):
    return {'bytes':len(raw),'sha256':sha256(raw).hexdigest()}

def write(path,value):
    raw=canonical(value)+b'\n'
    with Path(path).open('xb') as stream:stream.write(raw)
    return pin(raw)

def capture(path,expected=None):
    path=Path(path)
    raw=path.read_bytes()
    if expected is not None and canonical(pin(raw))!=canonical(expected):
        raise ValueError('child FINALIZE captured input identity differs')
    return raw,json.loads(raw)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authority',type=Path,required=True)
    parser.add_argument('--authority-sha256',required=True)
    parser.add_argument('--authority-bytes',type=int,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    authority_raw,authority=capture(args.authority,{'bytes':args.authority_bytes,
        'sha256':args.authority_sha256})
    if authority['schema']!='hepta.hia.service-verification-finalize-authority.v1':
        raise ValueError('child FINALIZE authority schema differs')
    from tools.build_hia_service_verification import INPUTS
    from tests import hia_service_verification_controls as old
    from tests import hia_service_verification_oracle as oracle
    from hepta import hia_agent_store as store
    from hepta import hia_service_verification_native as native
    from hepta import hia_store_artifact_profile_native as store_native
    from hepta import hia_service_context_native as context
    from hepta import hia_native_delivery as delivery
    from hepta.hia_native_helpers import native_helpers_scope
    captured={ROOT/name:(ROOT/name).read_bytes() for name in INPUTS}
    before={name:sha256(captured[ROOT/name]).hexdigest() for name in INPUTS}
    if canonical(before)!=canonical(authority['source_inputs']):
        raise ValueError('child FINALIZE complete construction source inputs differ')
    manifests={}
    for name in ('verification','store','context'):
        item=authority['manifests'][name]
        raw,value=capture(item['path'],item['pin'])
        captured[Path(item['path'])]=raw
        image_path=Path(item['path']).parent/value['image_path']
        image_raw=image_path.read_bytes()
        if sha256(image_raw).hexdigest()!=value['image_sha256']:
            raise ValueError('child FINALIZE compiled image changed')
        if value['compiler_sha256']!=authority['compiler']['sha256']:
            raise ValueError('child FINALIZE images use a different compiler')
        captured[image_path]=image_raw
        manifests[name]={'path':Path(item['path']),'value':value}
    case_path=oracle.ORIGINALS/'cases.json'
    cases_raw=captured.get(case_path)
    if cases_raw is None:
        cases_raw=case_path.read_bytes();captured[case_path]=cases_raw
    if (len(cases_raw)!=47104 or sha256(cases_raw).hexdigest()!=
            '270dca9e230051d50359281c5ba73be82329cdfa997d4058a72554ac637b065e'):
        raise ValueError('original resource basis input changed')
    case=next(row for row in json.loads(cases_raw)['base_cases']
              if row['id']=='verify.core.outer0')
    bundle_path=args.output/'bundle.json'
    bundle_sha=old.bundle(bundle_path,[
        (native.SELECTOR,manifests['verification']['path']),
        (store_native.SELECTOR,manifests['store']['path']),
        (context.SELECTOR,manifests['context']['path'])])
    bundle_raw=bundle_path.read_bytes()
    report={'schema':'hepta.hia.service-verification-child-finalize-control.v1',
        'status':'HOLD','argv':sys.argv,'pid':os.getpid(),'ppid':os.getppid(),
        'pgid':os.getpgrp(),'authority':pin(authority_raw),'source_before':before,
        'scope':authority['scope'],'case_id':'nested-SUBJECT-FINALIZE-before-SQL',
        'original_event_only_predicate_preserved':True,
        'original_basis':pin(cases_raw),'original_basis_case':case,
        'SQL_trace_scope':'after original Store construction through close probe',
        'whole_native_stack_qualified':False}
    entries=[];fired=[];facts={};sql=[]
    report.update(entries=entries,fired=fired,facts=facts)
    try:
        with native_helpers_scope(str(bundle_path),bundle_sha):
            image=native.installed_service_verification(str(manifests['verification']['path']))
            actual=store.AgentStore(args.output/'untouched-store')
            database=actual.db
            database.set_trace_callback(sql.append)
            def invoke(world,mode,values):
                number=oracle.MODES.index(mode)+1
                child=native.ServiceVerificationFrame(image,number,
                    dict(zip(native.PUBLIC_ARGUMENTS[number-1],values)),namespace=world.namespace)
                del values
                return child.finish()
            world=oracle.World(case,invoke)
            service=oracle.Service(world);service._store=actual
            owner=native.ServiceVerificationFrame(image,native.VERIFY,
                {'self':service,'args':world.args()},namespace=world.namespace)
            fault=ValueError('completed Store publication before missing parent ACK')
            original_entry=image._entry
            selected=[]
            def observed(source,size,output,capacity,state,extent):
                request_raw=ctypes.string_at(source,size)
                request=struct.unpack('<16Q',request_raw)
                active=delivery.current_record()
                code=original_entry(source,size,output,capacity,state,extent)
                output_raw=ctypes.string_at(output,capacity)
                state_raw=ctypes.string_at(state,extent)
                response=struct.unpack('<12Q',output_raw)
                entries.append({'request':request_raw.hex(),'output':output_raw.hex(),
                    'state':state_raw.hex(),'code':code,'event':request[1],
                    'port':request[3],'mode':request[5],'sequence':request[2],
                    'phase':response[4]})
                # Intentionally retain the original event-only trigger.
                if request[1]==native.FINALIZE:
                    fired.append({'entry_index':len(entries)-1,'mode':request[5],
                        'event':request[1],'phase':response[4],'code':code})
                    selected.append(active)
                    raise fault
                return code
            with old.attributes(image,{'_entry':observed}):
                result,error=old.caught(owner.finish)
                facts['result_is_none']=result is None
                facts['error_is_owner_unknown']=type(error) is native.ServiceVerificationUnknown
                facts['fault_is_direct_cause']=error is not None and error.__cause__ is fault
                facts['SQL_before_close']=list(sql)
                if len(fired)!=1 or len(selected)!=1:
                    raise AssertionError('one actual event-only FINALIZE must be reached')
                record=selected[0]
                if record is None:
                    raise AssertionError('actual child ambient record was absent at entry')
                child=record.owner
                loss=record.loss
                facts.update(
                    selected_owner_is_distinct=child is not owner,
                    selected_owner_mode=getattr(child,'mode',None),
                    selected_record_is_child_record=getattr(child,'_delivery',None) is record,
                    selected_child_fenced=getattr(child,'fenced',False),
                    selected_child_finished=getattr(child,'finished',None),
                    parent_fenced=owner.fenced,parent_finished=owner.finished,
                    parent_loss_is_child_loss=loss is not None and owner._delivery.loss is loss,
                    loss_owner_is_child=loss is not None and loss.owner is child,
                    loss_error_is_injected_fault=loss is not None and loss.error is fault,
                    untouched_store_has_no_recorded_loss=delivery._resource_loss(actual) is None)
                assert facts['result_is_none'] and facts['error_is_owner_unknown']
                assert facts['fault_is_direct_cause']
                assert fired[0]['event']==native.FINALIZE and fired[0]['mode']==native.SUBJECT
                assert fired[0]['phase']==native.RETURNED and fired[0]['code']==native.OUTPUT_BYTES
                assert facts['selected_owner_is_distinct'] and facts['selected_record_is_child_record']
                assert facts['selected_owner_mode']==native.SUBJECT
                assert facts['selected_child_fenced'] is True and facts['selected_child_finished'] is False
                assert facts['parent_fenced'] is True and facts['parent_finished'] is False
                assert facts['parent_loss_is_child_loss'] and facts['loss_owner_is_child']
                assert facts['loss_error_is_injected_fault']
                assert sql==[] and facts['untouched_store_has_no_recorded_loss']
                before_retry=(len(entries),list(sql),len(fired))
                _,parent_retry=old.caught(owner.finish)
                _,child_retry=old.caught(child.finish)
                facts['parent_retry_is_unknown']=type(parent_retry) is native.ServiceVerificationUnknown
                facts['child_retry_is_unknown']=type(child_retry) is native.ServiceVerificationUnknown
                facts['retry_added_entries']=len(entries)-before_retry[0]
                facts['retry_added_faults']=len(fired)-before_retry[2]
                facts['SQL_after_retry']=list(sql)
                assert facts['parent_retry_is_unknown'] and facts['child_retry_is_unknown']
                assert (len(entries),sql,len(fired))==before_retry
                assert owner._delivery.loss is loss and record.loss is loss
                close_calls=[]
                close_reference=store._NATIVE_STORE_CLOSE_REFERENCE
                def close(receiver):
                    close_calls.append(receiver is actual)
                    return close_reference(receiver)
                with old.attributes(store,{'_NATIVE_STORE_CLOSE_REFERENCE':close}):
                    close_result,close_error=old.caught(actual.close)
                facts['public_close_calls']=len(close_calls)
                facts['public_close_exact_receiver']=close_calls==[True]
                facts['public_close_returned_none']=close_result is None
                facts['public_close_error']=None if close_error is None else {
                    'type':type(close_error).__name__,'text':str(close_error)}
                assert close_error is None and close_result is None and close_calls==[True]
                _,closed_error=old.caught(lambda:database.execute('SELECT 1'))
                facts['actual_connection_closed']=type(closed_error) is sqlite3.ProgrammingError
                facts['SQL_after_close']=list(sql)
                facts['retained_loss_unchanged_after_healthy_close']=(
                    owner._delivery.loss is loss and record.loss is loss and loss.error is fault)
                facts['close_added_verification_entries']=len(entries)-before_retry[0]
                assert facts['actual_connection_closed']
                assert facts['retained_loss_unchanged_after_healthy_close']
                assert facts['close_added_verification_entries']==0
                assert sql==[]
                assert delivery._resource_loss(actual) is None
            report['actual_image_sha256']=image.image_sha256
        report['source_after']={name:sha256((ROOT/name).read_bytes()).hexdigest() for name in INPUTS}
        assert report['source_after']==before
        for path,raw in captured.items():
            if path.read_bytes()!=raw:raise ValueError('child FINALIZE input changed after actual consumption')
        if args.authority.read_bytes()!=authority_raw or bundle_path.read_bytes()!=bundle_raw:
            raise ValueError('child FINALIZE authority changed')
        report['status']='PASS_INDEPENDENT_CHILD_CONTROL_ONLY'
    except BaseException as error:
        report['failure']={'type':type(error).__module__+'.'+type(error).__qualname__,
                           'text':str(error)}
        raise
    finally:
        report['SQL']=list(sql)
        write(args.output/'report.json',report)

if __name__=='__main__':main()
