"""Independent real-OS, complete-buffer and actual lost-ACK controls.

No original expected value is obtained from the candidate graph. Unknown
descriptor cases run in owned fresh processes and retain their record until
that process exits; they never clear the shared registry to make cleanup pass.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import time
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from tests.hia_service_discovery_oracle import canonical
from tools.qualify_hia_service_discovery_finite import stop_owned

def write(path, value):
    raw = canonical(value) + b'\n'
    with Path(path).open('xb') as stream:
        stream.write(raw)
    return sha256(raw).hexdigest()

def clean_environment():
    return {key: value for key, value in os.environ.items()
            if not key.startswith(('PYTHON', 'HEPTA_HIA_'))}

def run_process(output, label, arguments, *, env, body=None, expected=0, timeout=60):
    output = Path(output)
    command = [sys.executable, '-I', '-B', *map(str, arguments)]
    start_ns, started = time.time_ns(), time.monotonic()
    process = None
    timed_out, cleanup, cleanup_error = False, None, None
    with (output / (label + '.stdout.log')).open('xb') as out, \
         (output / (label + '.stderr.log')).open('xb') as err:
        try:
            process = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.PIPE,
                                       stdout=out, stderr=err, start_new_session=True)
            write(output / (label + '.start.json'), {'command': command, 'cwd': str(ROOT),
                  'pid': process.pid, 'pgid': process.pid, 'started_time_ns': start_ns,
                  'timeout_seconds': timeout, 'cleanup_seconds': 3})
            try:
                process.communicate(body, timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
        finally:
            if process is not None:
                try:
                    cleanup = stop_owned(process)
                except BaseException as error:
                    cleanup_error = {'type': type(error).__name__, 'text': str(error)}
    stdout = (output / (label + '.stdout.log')).read_bytes()
    stderr = (output / (label + '.stderr.log')).read_bytes()
    receipt = {'command': command, 'cwd': str(ROOT), 'pid': None if process is None else process.pid,
               'pgid': None if process is None else process.pid, 'started_time_ns': start_ns,
               'ended_time_ns': time.time_ns(), 'elapsed_seconds': time.monotonic() - started,
               'timeout_seconds': timeout, 'cleanup_seconds': 3, 'timeout': timed_out,
               'returncode': None if process is None else process.returncode,
               'expected_returncode': expected, 'cleanup': cleanup, 'cleanup_error': cleanup_error,
               'stdout_sha256': sha256(stdout).hexdigest(), 'stderr_sha256': sha256(stderr).hexdigest()}
    write(output / (label + '.result.json'), receipt)
    if (process is None or timed_out or cleanup_error or process.returncode != expected
            or cleanup is None or cleanup['after']):
        raise AssertionError(receipt)
    return stdout, stderr, receipt

@contextmanager
def attributes(target, values):
    before = {key: getattr(target, key) for key in values}
    for key, value in values.items():
        setattr(target, key, value)
    try:
        yield
    finally:
        for key, value in before.items():
            setattr(target, key, value)

def forbidden(*args, **kwargs):
    raise AssertionError('selected discovery called a retained whole body')


def caught(call):
    try:
        return call(),None
    except BaseException as error:
        return None,error

def entry_observer(image,rows,*,target=None,fault=None):
    original=image._entry
    def entry(source,size,output,capacity,state,extent):
        request=struct.unpack('<16Q',ctypes.string_at(source,size))
        code=original(source,size,output,capacity,state,extent)
        result=struct.unpack('<12Q',ctypes.string_at(output,capacity))
        rows.append({'event':request[1],'port':request[3],'mode':request[5],
                     'phase':result[4],'code':code,'sequence':request[2]})
        if target is not None and target(request,result):
            raise fault
        return code
    return entry

def bundle(path,helpers):
    from hepta.hia_native_helpers import ABI,SCHEMA,TARGET
    write(path,{'schema':SCHEMA,'abi':ABI,'target':TARGET,
        'helpers':[{'selector':selector,'manifest_path':str(Path(manifest).absolute()),
                    'manifest_sha256':sha256(Path(manifest).read_bytes()).hexdigest()}
                   for selector,manifest in helpers]})
    return sha256(Path(path).read_bytes()).hexdigest()

def real_service(store):
    from types import SimpleNamespace
    return SimpleNamespace(store=store,manifest={'manifest':'fixture'},
        catalog_sha256='c'*64,
        profiles={'backend':{'id':'backend-id'},'artifact':{'id':'artifact-id'}},
        profile_artifacts={key:{'profile':key} for key in ('backend','lowering','target','validation','plan')},
        resources={key:{'resource':key} for key in (
            'schema_registry','assembly_grammar','core_language','byte_bootstrap_guide',
            'self_hosting_core_guide','self_hosting_core_support','machine_validation_guide',
            'proof_contract_guide','buffer_lifecycle_guide','examples','diagnostics',
            'plan_schema','machine_plan_guide','macro_policy','macro_policy_guide')})

class PlainStore:
    def profile(self,schema,language):
        return {'schema':schema},{'language_ref':'actual-opaque-provider'}

def frame(image,mode=1,service=None,arguments=None):
    from hepta import hia_service_discovery_native as native
    if mode==1:
        service=real_service(PlainStore()) if service is None else service
        arguments={'section':'manifest'} if arguments is None else arguments
    return native.ServiceDiscoveryFrame(image,mode,service,arguments)

def foreign(image,args):
    from hepta import hia_service_discovery_native as native, hia_native_delivery as delivery, hia_agent_service as api
    from hepta import hia_opcodes,hia_agent_assembly
    import sqlite3
    rows=[]
    errors=(ValueError,TypeError,OSError,OverflowError,RecursionError,sqlite3.OperationalError,
            RuntimeError,MemoryError,KeyboardInterrupt,SystemExit,StopIteration,
            delivery.NativeDeliveryUnknown,native.ServiceDiscoveryUnknown)
    for mode in (1,2):
        for kind in errors:
            fault=kind('ordinary foreign provider failure')
            def refused(*values,**kw):raise fault
            owner=frame(image,mode);entries=[]
            target,name=(hia_opcodes,'opcode_catalog') if mode==1 else (api,'verify_program')
            with attributes(target,{name:refused}),attributes(image,{'_entry':entry_observer(image,entries)}):
                _,error=caught(owner.finish)
            assert error is fault
            assert owner.finished and owner.receipt.phase==native.PROPAGATE
            assert owner._delivery.loss is None and owner._delivery.retired
            assert sum(x['event']==native.RAISED for x in entries)==1
            assert sum(x['event']==native.FINALIZE for x in entries)==1
            rows.append({'mode':mode,'error':kind.__name__,'same_exception':True,'entries':entries})
    # Actual packet preparation fails before INITIALIZE handoff.
    fault=MemoryError('before actual INIT');original=native.struct.pack
    def pack(format,*values):
        if format=='<16Q':raise fault
        return original(format,*values)
    owner=object.__new__(native.ServiceDiscoveryFrame);entries=[]
    with attributes(native.struct,{'pack':pack}),attributes(image,{'_entry':entry_observer(image,entries)}):
        _,error=caught(lambda:native.ServiceDiscoveryFrame.__init__(owner,image,2))
    assert error is fault and entries==[] and owner._delivery.loss is None and owner._delivery.retired
    assert not delivery.custody_snapshot()
    rows.append({'safe_preentry_allocation':True,'same_MemoryError':True,'entries':entries})
    return {'rows':rows,'remaining_custody':[]}

def loss(image,args):
    from hepta import hia_service_discovery_native as native, hia_native_delivery as delivery
    rows=[]
    for mode in (1,2):
        provider=native.PORT['describe_profile' if mode==1 else 'examples_program']
        release=native.PORT['describe_release' if mode==1 else 'examples_release']
        for event,port in ((native.INITIALIZE,0),(native.CLAIM,provider),
                           (native.SUCCEEDED,provider),(native.SUCCEEDED,release),(native.FINALIZE,0)):
            for kind in (ValueError,RuntimeError,MemoryError,KeyboardInterrupt,SystemExit):
                fault=kind('real machine returned but delivery was withheld')
                entries=[];owner=object.__new__(native.ServiceDiscoveryFrame)
                def wanted(request,result):
                    return request[1]==event and request[3]==port
                def run():
                    native.ServiceDiscoveryFrame.__init__(owner,image,mode,
                        real_service(PlainStore()) if mode==1 else None,
                        {'section':'manifest'} if mode==1 else None)
                    return owner.finish()
                with attributes(image,{'_entry':entry_observer(image,entries,target=wanted,fault=fault)}):
                    _,error=caught(run);before=len(entries);_,again=caught(owner.finish)
                assert any(x['event']==event and x['port']==port for x in entries)
                assert owner.fenced and owner.native_failed and owner._delivery.loss is not None
                assert not owner._delivery.retired and len(entries)==before
                assert type(again) is native.ServiceDiscoveryUnknown
                if issubclass(kind,native._REQUEST_REJECTIONS):
                    assert type(error) is native.ServiceDiscoveryUnknown and error.__cause__ is fault
                else:assert error is fault
                assert not any(x['event']==native.RAISED for x in entries)
                rows.append({'mode':mode,'event':event,'port':port,'fault':kind.__name__,
                             'actual_entry_first':True,'replay_entries':0,'entries':entries})
    # All damaged words follow one actual successful native entry.
    for word in (0,1,2,3,4,5,6,7,8,9,10,11):
        original=image._entry;fired=[];entries=[]
        def damaged(source,size,output,capacity,state,extent):
            request=struct.unpack('<16Q',ctypes.string_at(source,size))
            code=original(source,size,output,capacity,state,extent);entries.append(request[1])
            if not fired and request[1]==native.SUCCEEDED:
                fired.append(word);raw=bytearray(ctypes.string_at(output,capacity))
                raw[word*8]^=1;ctypes.memmove(output,bytes(raw),capacity)
            return code
        with attributes(image,{'_entry':damaged}):
            owner=frame(image,2);_,error=caught(owner.finish);before=len(entries);_,again=caught(owner.finish)
        assert fired==[word] and type(error) is native.ServiceDiscoveryUnknown
        assert type(again) is native.ServiceDiscoveryUnknown and len(entries)==before
        assert owner._delivery.loss is not None and not owner._delivery.retired
        rows.append({'corrupt_output_word':word,'actual_entry_first':True,'replay_entries':0})
    return {'rows':rows,'retained_unknowns':len(delivery.custody_snapshot())}

def creator(image,args):
    from hepta import hia_service_discovery_native as native,hia_native_delivery as delivery
    from hepta import hia_opcodes
    import threading,contextvars,select
    rows=[];owner=frame(image);entries=[]
    with attributes(image,{'_entry':entry_observer(image,entries)}):
        before=len(entries);errors=[]
        thread=threading.Thread(target=lambda:errors.append(caught(owner.finish)[1]))
        thread.start();thread.join(5)
        assert not thread.is_alive() and len(errors)==1 and type(errors[0]) is native.ServiceDiscoveryUnknown
        assert len(entries)==before and not owner._entered and not owner._delivery.retired
        owner.finish()
    rows.append({'foreign_thread_refused_before_entry':True,'creator_completed':True})
    original=hia_opcodes.opcode_catalog;observed=[]
    def recursive(schema):
        active=delivery.current_record().owner
        before=(active._delivery.retired,active._delivery.native_pending,active._delivery.observation_pending)
        _,error=caught(active.finish)
        assert type(error) is native.ServiceDiscoveryUnknown
        assert before==(active._delivery.retired,active._delivery.native_pending,active._delivery.observation_pending)
        observed.append(True);return original(schema)
    with attributes(hia_opcodes,{'opcode_catalog':recursive}):
        frame(image).finish()
    assert observed==[True]
    rows.append({'same_frame_reentry_refused_without_outer_cleanup':True})
    owner=frame(image,2);read_fd,write_fd=os.pipe();pid=os.fork()
    if pid==0:
        os.close(read_fd)
        try:
            _,error=caught(owner.finish)
            assert type(error) is native.ServiceDiscoveryUnknown
            os.write(write_fd,b'fork-denied');os._exit(0)
        except BaseException:os._exit(9)
    os.close(write_fd)
    try:
        ready,_,_=select.select([read_fd],[],[],5);assert ready
        assert os.read(read_fd,64)==b'fork-denied'
        waited,status=os.waitpid(pid,0);assert waited==pid and os.waitstatus_to_exitcode(status)==0
        pid=None
    finally:
        os.close(read_fd)
        if pid is not None:
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
            os.waitpid(pid,0)
    owner.finish()
    assert owner._delivery.retired
    _,error=caught(owner.finish);assert type(error) is native.ServiceDiscoveryUnknown
    rows.append({'fork_inherited_owner_denied_parent_valid':True,'completed_reuse_denied':True})
    # A copied, later inactive activation is not a new causal ancestor.
    record=delivery.DeliveryRecord(object())
    with record.foreign(observation=False):
        copied=contextvars.copy_context()
    record.retire()
    copied.run(lambda:frame(image,2).finish())
    assert not delivery.custody_snapshot()
    rows.append({'stale_Context_has_no_live_ancestor':True})
    return {'rows':rows,'remaining_custody':[]}

def resources(image,args):
    from hepta import hia_agent_store as store, hia_store_artifact_profile_native as store_native
    from hepta import hia_service_discovery_native as native, hia_native_delivery as delivery
    from hepta import hia_service_context_native as context
    from hepta.hia_native_helpers import native_helpers_scope
    from types import SimpleNamespace
    path=args.output/'bundle.json'
    pin=bundle(path,[(native.SELECTOR,args.manifest),(store_native.SELECTOR,args.store_manifest),
                     (context.SELECTOR,args.context_manifest)])
    rows=[]
    with native_helpers_scope(str(path),pin):
        peer=context.installed_service_context(str(args.context_manifest))
        # A real selected Store.profile/SQLite publication is confirmed before
        # the parent loses its later acknowledgement. No raw SQL is replayed.
        for target in ('profile-ACK','result-ACK','release-ACK','FINALIZE'):
            actual=store.AgentStore(args.output/target);sql=[];actual.db.set_trace_callback(sql.append)
            service=real_service(actual);entries=[];fault=ValueError('actual parent acknowledgement withheld')
            port=native.PORT[{'profile-ACK':'describe_profile','result-ACK':'describe_result',
                             'release-ACK':'describe_release'}.get(target,'describe_release')]
            def wanted(request,result):
                return request[1]==native.FINALIZE if target=='FINALIZE' else request[1]==native.SUCCEEDED and request[3]==port
            with attributes(image,{'_entry':entry_observer(image,entries,target=wanted,fault=fault)}):
                owner=frame(image,1,service);_,error=caught(owner.finish)
            assert isinstance(error,RuntimeError) and owner._delivery.loss is not None
            assert any('INSERT' in statement.upper() for statement in sql)
            before=(list(sql),len(entries));_,retry=caught(owner.finish)
            assert type(retry) is native.ServiceDiscoveryUnknown and before==(sql,len(entries))
            real_close=store._NATIVE_STORE_CLOSE_REFERENCE;close_calls=[]
            def original_close(receiver):
                close_calls.append(receiver);return real_close(receiver)
            with attributes(store,{'_NATIVE_STORE_CLOSE_REFERENCE':original_close}):
                _,close_error=caught(actual.close)
            assert isinstance(close_error,RuntimeError) and close_calls==[]
            rows.append({'case':target,'actual_SQL':sql,'entries':entries,'actual_Store_fenced':True,
                         'original_close_entries':0,'retry_SQL_and_entries':0})
        # Explicit callback target differs from the apparent foreign receiver.
        first,second=store.AgentStore(args.output/'unused-A'),store.AgentStore(args.output/'actual-B')
        class Callback:
            def profile(self,*values):return second.profile(*values)
        service=real_service(Callback());entries=[];fault=ValueError('actual B parent ACK missing')
        with attributes(image,{'_entry':entry_observer(image,entries,
                target=lambda q,a:q[1]==native.SUCCEEDED and q[3]==native.PORT['describe_profile'],fault=fault)}):
            owner=frame(image,1,service);_,error=caught(owner.finish)
        assert owner._delivery.loss is not None
        assert caught(first.close)[1] is None and isinstance(caught(second.close)[1],RuntimeError)
        rows.append({'case':'different-actual-Store','only_actual_B_fenced':True,'entries':entries})
        # Ordinary confirmed foreign rejection remains ordinary even after SQL.
        actual=store.AgentStore(args.output/'confirmed-foreign')
        service=real_service(actual);args_bad={'section':'not-a-section'}
        owner=frame(image,1,service,args_bad);_,error=caught(owner.finish)
        assert type(error) is KeyError and owner.finished and owner.receipt.phase==native.PROPAGATE
        assert owner._delivery.loss is None and caught(actual.close)[1] is None
        rows.append({'case':'confirmed-foreign-after-SQL','original_KeyError':True,'healthy_retirement':True})
        for disposition in ('propagate','swallow','replace'):
            actual=store.AgentStore(args.output/('child-'+disposition));entries=[];child=[];fault=ValueError('actual peer loss')
            peer_entry=peer._entry
            def peer_lost(*values):
                result=peer_entry(*values);child.append(result);raise fault
            class Callback:
                def profile(self,*values):
                    answer=actual.profile(*values)
                    try:peer.arithmetic(1,3,4)
                    except context.ServiceContextUnknown:
                        if disposition=='propagate':raise
                        if disposition=='replace':raise ValueError('foreign replacement')
                    return answer
            with attributes(peer,{'_entry':peer_lost}),attributes(image,{'_entry':entry_observer(image,entries)}):
                owner=frame(image,1,real_service(Callback()));_,error=caught(owner.finish)
            assert child and isinstance(error,RuntimeError) and owner._delivery.loss is not None
            assert not any(x['event']==native.SUCCEEDED and x['port']==native.PORT['describe_profile'] for x in entries)
            assert not any(x['event']==native.RAISED for x in entries)
            assert isinstance(caught(actual.close)[1],RuntimeError)
            rows.append({'case':'child-'+disposition,'actual_child_entries':len(child),'entries':entries,'Store_fenced':True})
        # The service receiver's ordinary destruction is before release ACK.
        actual=store.AgentStore(args.output/'release-finalizer')
        releases=[];child=[];peer_entry=peer._entry;fault=ValueError('release actual child lost')
        def peer_lost(*values):
            result=peer_entry(*values);child.append(result);raise fault
        class ReleasedService:
            def __init__(self):
                self.__dict__.update(vars(real_service(actual)))
            def __del__(self):
                try:peer.arithmetic(1,3,4)
                except BaseException as error:
                    releases.append({'type':type(error).__name__,'cause_same':error.__cause__ is fault})
                else:releases.append({'unexpected_success':True})
        entries=[]
        with attributes(peer,{'_entry':peer_lost}),attributes(image,{'_entry':entry_observer(image,entries)}):
            owner=frame(image,1,ReleasedService());_,error=caught(owner.finish)
        assert releases==[{'type':'ServiceContextUnknown','cause_same':True}] and child
        assert isinstance(error,RuntimeError) and owner._delivery.loss is not None
        assert not any(x['event']==native.SUCCEEDED and x['port']==native.PORT['describe_release'] for x in entries)
        assert isinstance(caught(actual.close)[1],RuntimeError)
        rows.append({'case':'original-receiver-release-before-ACK','release':releases,
                     'actual_child_entries':len(child),'entries':entries})
    return {'rows':rows,'actual_SQL_and_native_providers':True,
            'unknowns_remain_in_owned_child':len(delivery.custody_snapshot()),
            'dead_or_unregistered_resources_proved':False}

def packets(image,args):
    from hepta import hia_service_discovery_native as native
    from hepta import hia_service_discovery_protocol as protocol
    from hepta.hia_agent_assembly import assemble_program
    from tests.hia_service_discovery_observer import VMEntry
    import itertools
    vm=VMEntry(assemble_program(native.SOURCE.read_bytes()))
    def invoke(entry,packet,state):
        source=ctypes.create_string_buffer(packet+b'\xc9'*16,len(packet)+16)
        output=ctypes.create_string_buffer(b'\xa5'*(native.OUTPUT_BYTES+16),native.OUTPUT_BYTES+16)
        workspace=ctypes.create_string_buffer(state+b'\xb7'*16,len(state)+16)
        code=entry(source,len(packet),output,native.OUTPUT_BYTES,workspace,native.STATE_BYTES)
        assert source.raw==packet+b'\xc9'*16
        assert output.raw[native.OUTPUT_BYTES:]==b'\xa5'*16 and workspace.raw[native.STATE_BYTES:]==b'\xb7'*16
        return {'code':code,'source':source.raw.hex(),'output':output.raw.hex(),'state':workspace.raw.hex()}
    rows=[]
    def both(words,state,label):
        raw=struct.pack('<16Q',*words)
        left=invoke(vm,raw,state);right=invoke(image._entry,raw,state)
        assert left==right
        rows.append({'label':label,'request':raw.hex(),'state_before':state.hex(),'VM':left,'native':right})
        return bytes.fromhex(right['state'])[:native.STATE_BYTES],struct.unpack('<12Q',bytes.fromhex(right['output'])[:native.OUTPUT_BYTES])
    bools=sorted(protocol.BOOLEAN_PORTS)
    for mode in (1,2):
        for choices in itertools.product((0,1),repeat=len(bools)):
            decisions=dict(zip(bools,choices));state=bytes(native.STATE_BYTES)
            words=[native.REQUEST_MAGIC,native.INITIALIZE,0,0,0,mode,123,456]+[0]*8
            state,result=both(words,state,'initialize')
            while result[4]==native.ISSUED:
                words[1:5]=[native.CLAIM,result[3],result[2],0]
                state,result=both(words,state,'claim')
                words[1:5]=[native.SUCCEEDED,result[3],result[2],decisions.get(result[2],0)]
                state,result=both(words,state,'success')
            assert result[4]==native.READY_RETURN
            words[1:5]=[native.FINALIZE,result[3],0,0]
            state,result=both(words,state,'finalize')
            assert result[4]==native.RETURNED
            stale=list(words);both(stale,state,'terminal-replay-refused')
    for mode in (1,2):
        initial=[native.REQUEST_MAGIC,0,0,0,0,mode,999,111]+[0]*8
        state,result=both(initial,bytes(native.STATE_BYTES),'exception-initialize')
        claim=list(initial);claim[1:5]=[native.CLAIM,result[3],result[2],0]
        state,result=both(claim,state,'exception-claim')
        for field,value in ((0,0),(1,99),(2,result[3]+1),(3,result[2]+1),(4,2),(5,3),(6,1000),(8,1),(15,1)):
            bad=list(claim);bad[1]=native.SUCCEEDED;bad[field]=value
            both(bad,state,'invalid-field-'+str(field))
        raised=list(initial);raised[1:5]=[native.RAISED,result[3],result[2],0]
        state,result=both(raised,state,'raised')
        assert result[4]==native.READY_PROPAGATE
        raised[1:5]=[native.FINALIZE,result[3],0,0]
        state,result=both(raised,state,'exception-finalize')
        assert result[4]==native.PROPAGATE
    write(args.output/'complete-packets.json',rows)
    return {'count':len(rows),'complete_VM_native_bytes_equal':True,'VM_entries':vm.calls}

def public(image,args):
    from hepta import hia_agent_service as api,hia_service_discovery_native as native
    from hepta import hia_store_artifact_profile_native as store_native
    from hepta.hia_native_helpers import native_helpers_scope
    from tests.test_hia_agent_native_tools import AgentToolCase
    import inspect
    path=args.output/'bundle.json';pin=bundle(path,[(native.SELECTOR,args.manifest),(store_native.SELECTOR,args.store_manifest)])
    case=AgentToolCase('runTest');ready=False;entries=[]
    saved=(api._SERVICE_DISCOVERY_DESCRIBE_REFERENCE,api._SERVICE_DISCOVERY_EXAMPLES_REFERENCE)
    try:
        with native_helpers_scope(str(path),pin):
            pinned=native.installed_service_discovery(str(args.manifest))
            with attributes(api,{
                '_SERVICE_DISCOVERY_DESCRIBE_REFERENCE':forbidden,'_SERVICE_DISCOVERY_EXAMPLES_REFERENCE':forbidden}), \
                 attributes(pinned,{'_entry':entry_observer(pinned,entries)}):
                case.setUp();ready=True
                startup=list(entries);assert any(x['mode']==2 for x in startup)
                responses=[]
                for section in ('manifest','language','backend','examples','diagnostics','plans'):
                    arguments={'section':section}
                    response=case.service.call('hia_describe',arguments)
                    assert response['status']=='completed' and response['result']['next_cursor'] is None
                    responses.append(response)
                assert {x['mode'] for x in entries}=={1,2}
                assert inspect.signature(api.HIAAgentService._hia_describe)==inspect.signature(saved[0])
                assert inspect.signature(api.HIAAgentService._examples)==inspect.signature(saved[1])
                class Override(api.HIAAgentService):
                    def _hia_describe(self,args):return ('override',args)
                    @staticmethod
                    def _examples():return 'static-override'
                subject=object.__new__(Override)
                assert subject._hia_describe(7)==('override',7) and Override._examples()=='static-override'
                subject._hia_describe=lambda value:('instance',value)
                assert subject._hia_describe(9)==('instance',9)
                class_call=api.HIAAgentService._hia_describe(real_service(PlainStore()),{'section':'manifest'})
                assert class_call['next_cursor'] is None
                try:api.HIAAgentService._examples(object())
                except TypeError:pass
                else:raise AssertionError('staticmethod argument binding changed')
                return {'responses':responses,'startup_entries':startup,'entries':entries,
                        'class_instance_and_subclass_bindings_preserved':True,'actual_Core_assembly_Store':True}
    finally:
        if ready:case.tearDown()

def scope(image,args):
    from hepta import hia_service_discovery_native as native,hia_agent_service as api
    from hepta.hia_native_helpers import native_helpers_scope
    original=json.loads(args.manifest.read_bytes());alternate=args.output/'alternate';alternate.mkdir()
    source=args.manifest.parent/original['image_path']
    (alternate/source.name).write_bytes(source.read_bytes());rows=[]
    saved=os.environ.get(native.SELECTOR)
    try:
        with attributes(api,{'_SERVICE_DISCOVERY_DESCRIBE_REFERENCE':forbidden,
                             '_SERVICE_DISCOVERY_EXAMPLES_REFERENCE':forbidden}):
            for label,field in (('source','source_sha256'),('image','image_sha256')):
                changed={**original,field:'0'*64};manifest=alternate/(label+'.json');write(manifest,changed)
                os.environ[native.SELECTOR]=str(manifest)
                _,error=caught(api.HIAAgentService._examples)
                assert isinstance(error,ValueError)
                rows.append({'bad_manifest':label,'rejected':True})
            os.environ[native.SELECTOR]=''
            assert isinstance(caught(api.HIAAgentService._examples)[1],ValueError)
        os.environ.pop(native.SELECTOR,None)
        original_manifest=alternate/'same.json';original_manifest.write_bytes(args.manifest.read_bytes())
        path=args.output/'bundle.json';pin=bundle(path,[(native.SELECTOR,args.manifest)])
        with native_helpers_scope(str(path),pin):
            pinned=native.installed_service_discovery(str(args.manifest))
            assert native.installed_service_discovery(str(args.manifest)) is pinned
            assert pinned.image_sha256==image.image_sha256
            _,error=caught(lambda:native.installed_service_discovery(str(original_manifest)))
            assert isinstance(error,ValueError)
        return {'rows':rows,'empty_refused':True,'pinned_worker_alternate_refused':True}
    finally:
        if saved is None:os.environ.pop(native.SELECTOR,None)
        else:os.environ[native.SELECTOR]=saved

MODES=('foreign','loss','creator','resources','packets','public','scope')
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',required=True,choices=MODES)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--store-manifest',type=Path,required=True)
    parser.add_argument('--context-manifest',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(mode=0o700)
    from tools.build_hia_service_discovery import INPUTS
    from hepta import hia_service_discovery_native as native
    before={name:sha256((ROOT/name).read_bytes()).hexdigest() for name in INPUTS}
    image=native.installed_service_discovery(str(args.manifest))
    observation=globals()[args.mode](image,args)
    after={name:sha256((ROOT/name).read_bytes()).hexdigest() for name in INPUTS}
    assert before==after
    write(args.output/'report.json',{'schema':'hepta.hia.service-discovery-controls.v1',
        'status':'PASS','mode':args.mode,'source_before':before,'source_after':after,
        'actual_image_sha256':image.image_sha256,'observations':observation,'whole_native':False})
if __name__=='__main__':
    main()
