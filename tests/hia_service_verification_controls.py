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
from tests.hia_service_verification_oracle import canonical
from tools.qualify_hia_service_verification_finite import stop_owned

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
    raise AssertionError('selected verification called a retained whole body')


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


def binding_arguments(program=None):
    from types import SimpleNamespace
    if program is None:
        program=SimpleNamespace(sha256='candidate',input_sha256='input',
                                as_dict=lambda:{'functions':[{'name':'entry'}]})
    return {'subject':{'native_artifact':'native','build_receipt':'build'},
        'built':{'object_artifact':'object','output_kind':'shared',
                 'native_build':{'foreign_buffer_exports':[]}},
        'program':program,'object_bytes':b'object','final_bytes':b'final'}

def frame(image,program=None):
    from hepta import hia_service_verification_native as native
    return native.ServiceVerificationFrame(image,native.BINDING,binding_arguments(program))

def foreign(image,args):
    from hepta import hia_service_verification_native as native,hia_native_delivery as delivery
    import sqlite3
    rows=[]
    families=(ValueError,TypeError,OSError,OverflowError,RecursionError,sqlite3.OperationalError,
              RuntimeError,MemoryError,KeyboardInterrupt,SystemExit,StopIteration)
    for family in families:
        fault=family('declared original property failure')
        class Program:
            @property
            def sha256(self):raise fault
        entries=[]
        with attributes(image,{'_entry':entry_observer(image,entries)}):
            owner=frame(image,Program());_,error=caught(owner.finish)
        assert error is fault and owner.finished and owner.receipt.phase==native.PROPAGATE
        assert owner._delivery.loss is None and owner._delivery.retired
        assert sum(x['event']==native.RAISED for x in entries)==1
        assert sum(x['event']==native.FINALIZE for x in entries)==1
        rows.append({'error':family.__name__,'same_object':True,'entries':entries})
    fault=MemoryError('before actual INIT');original=native.struct.pack
    def pack(format,*values):
        if format=='<16Q':raise fault
        return original(format,*values)
    owner=object.__new__(native.ServiceVerificationFrame);entries=[]
    with attributes(native.struct,{'pack':pack}),attributes(image,{'_entry':entry_observer(image,entries)}):
        _,error=caught(lambda:native.ServiceVerificationFrame.__init__(owner,image,native.BINDING,binding_arguments()))
    assert error is fault and entries==[] and owner._delivery.loss is None and owner._delivery.retired
    assert not delivery.custody_snapshot()
    rows.append({'safe_preentry_allocation':True,'same_MemoryError':True,'entries':[]})
    return {'rows':rows}

def loss(image,args):
    from hepta import hia_service_verification_native as native
    rows=[]
    points=((native.INITIALIZE,0),(native.CLAIM,native.PORT['binding_result']),
            (native.SUCCEEDED,native.PORT['binding_result']),
            (native.SUCCEEDED,native.PORT['binding_release']),(native.FINALIZE,0))
    for event,port in points:
        for family in (ValueError,RuntimeError,MemoryError,KeyboardInterrupt,SystemExit):
            fault=family('actual entry returned, transport failed');entries=[]
            owner=object.__new__(native.ServiceVerificationFrame)
            def run():
                native.ServiceVerificationFrame.__init__(owner,image,native.BINDING,binding_arguments())
                return owner.finish()
            with attributes(image,{'_entry':entry_observer(image,entries,
                    target=lambda q,a:q[1]==event and q[3]==port,fault=fault)}):
                _,error=caught(run);count=len(entries);_,again=caught(owner.finish)
            assert any(x['event']==event and x['port']==port for x in entries)
            assert owner.fenced and owner.native_failed and owner._delivery.loss is not None
            assert not owner._delivery.retired and len(entries)==count
            assert type(again) is native.ServiceVerificationUnknown
            assert not any(x['event']==native.RAISED for x in entries)
            if issubclass(family,native._REQUEST_REJECTIONS):
                assert type(error) is native.ServiceVerificationUnknown and error.__cause__ is fault
            else:assert error is fault
            rows.append({'event':event,'port':port,'family':family.__name__,'entries':entries,'retry_entries':0})
    for word in range(12):
        original=image._entry;fired=[]
        def corrupt(source,size,output,capacity,state,extent):
            result=original(source,size,output,capacity,state,extent)
            values=list(struct.unpack('<12Q',ctypes.string_at(output,capacity)))
            values[word]^=1;ctypes.memmove(output,struct.pack('<12Q',*values),capacity)
            fired.append(True);return result
        owner=object.__new__(native.ServiceVerificationFrame)
        with attributes(image,{'_entry':corrupt}):
            _,error=caught(lambda:native.ServiceVerificationFrame.__init__(owner,image,native.BINDING,binding_arguments()))
        assert fired==[True] and type(error) is native.ServiceVerificationUnknown
        assert owner._delivery.loss is not None and not owner._delivery.retired
        rows.append({'damaged_receipt_word':word,'actual_entry_first':True})
    return {'rows':rows}

def creator(image,args):
    from hepta import hia_service_verification_native as native,hia_native_delivery as delivery
    import threading,contextvars,select
    rows=[];owner=frame(image);entries=[];errors=[]
    with attributes(image,{'_entry':entry_observer(image,entries)}):
        thread=threading.Thread(target=lambda:errors.append(caught(owner.finish)[1]))
        thread.start();thread.join(5)
        assert not thread.is_alive() and len(errors)==1 and type(errors[0]) is native.ServiceVerificationUnknown
        assert entries==[] and not owner._entered and not owner._delivery.retired
        owner.finish()
    rows.append({'foreign_thread_denied_before_entry':True,'creator_completed':True})
    observed=[]
    class ReentrantProgram:
        input_sha256='input'
        @property
        def sha256(self):
            active=delivery.current_record().owner
            before=(active._delivery.retired,active._delivery.native_pending,active._delivery.observation_pending)
            _,error=caught(active.finish)
            assert type(error) is native.ServiceVerificationUnknown
            assert before==(active._delivery.retired,active._delivery.native_pending,active._delivery.observation_pending)
            observed.append(True);return 'candidate'
        def as_dict(self):return {'functions':[]}
    frame(image,ReentrantProgram()).finish()
    assert observed==[True]
    rows.append({'same_frame_reentry_preserves_outer':True})
    owner=frame(image);read_fd,write_fd=os.pipe();pid=os.fork()
    if pid==0:
        os.close(read_fd)
        try:
            _,error=caught(owner.finish)
            assert type(error) is native.ServiceVerificationUnknown
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
    owner.finish();assert owner._delivery.retired
    assert type(caught(owner.finish)[1]) is native.ServiceVerificationUnknown
    rows.append({'fork_denied_parent_valid_terminal_reuse_denied':True})
    record=delivery.DeliveryRecord(object())
    with record.foreign(observation=False):copied=contextvars.copy_context()
    record.retire();copied.run(lambda:frame(image).finish())
    assert not delivery.custody_snapshot()
    rows.append({'inactive_Context_has_no_ancestor':True})
    return {'rows':rows}

def packets(image,args):
    from hepta import hia_service_verification_native as native
    from hepta import hia_service_verification_protocol as protocol
    from hepta.hia_agent_assembly import assemble_program
    from tests.hia_service_verification_observer import VMEntry
    vm=VMEntry(assemble_program(native.SOURCE.read_bytes()))
    rows=[]
    def invoke(entry,raw,state):
        source=ctypes.create_string_buffer(raw+b'\xc9'*16,len(raw)+16)
        output=ctypes.create_string_buffer(b'\xa5'*(native.OUTPUT_BYTES+16),native.OUTPUT_BYTES+16)
        workspace=ctypes.create_string_buffer(state+b'\xb7'*16,len(state)+16)
        code=entry(source,len(raw),output,native.OUTPUT_BYTES,workspace,native.STATE_BYTES)
        assert source.raw==raw+b'\xc9'*16 and output.raw[native.OUTPUT_BYTES:]==b'\xa5'*16
        assert workspace.raw[native.STATE_BYTES:]==b'\xb7'*16
        return {'code':code,'output':output.raw.hex(),'state':workspace.raw.hex()}
    def both(words,state,label):
        raw=struct.pack('<16Q',*words)
        left,right=invoke(vm,raw,state),invoke(image._entry,raw,state)
        assert left==right
        rows.append({'id':label,'request':raw.hex(),'state_before':state.hex(),'VM':left,'Native':right})
    for mode,(low,high) in protocol.MODE_RANGES.items():
        initial=[native.REQUEST_MAGIC,0,0,0,0,mode,123,456]+[0]*8
        both(initial,bytes(native.STATE_BYTES),'mode%d.initialize'%mode)
        for port in range(low,high+1):
            state=[native.STATE_MAGIC,1,mode,port,17,native.CLAIMED,123,456,0,0,0,0,int(port in native.ERROR_PORTS)]+[0]*11
            state[10]=native._checksum(state);rawstate=struct.pack('<24Q',*state)
            limit=1 if port in protocol.BOOLEAN_PORTS else protocol.CHOICE_PORTS.get(port,0)
            for observed in range(limit+1):
                both([native.REQUEST_MAGIC,native.SUCCEEDED,17,port,observed,mode,123,456]+[0]*8,
                     rawstate,'port%d.success%d'%(port,observed))
            both([native.REQUEST_MAGIC,native.RAISED,17,port,0,mode,123,456]+[0]*8,rawstate,'port%d.raised'%port)
            both([native.REQUEST_MAGIC,native.SUCCEEDED,18,port,0,mode,123,456]+[0]*8,rawstate,'port%d.stale'%port)
            both([native.REQUEST_MAGIC,native.SUCCEEDED,17,port,limit+1,mode,123,456]+[0]*8,rawstate,'port%d.invalid-observation'%port)
        for phase in (native.READY_RETURN,native.READY_PROPAGATE):
            state=[native.STATE_MAGIC,1,mode,0,17,phase,123,456,0,0,0,0,int(phase==native.READY_PROPAGATE)]+[0]*11
            state[10]=native._checksum(state)
            both([native.REQUEST_MAGIC,native.FINALIZE,17,0,0,mode,123,456]+[0]*8,struct.pack('<24Q',*state),'mode%d.finalize%d'%(mode,phase))
        if mode in protocol.GENERATOR_MODES:
            for event,phase in ((native.FINALIZE,native.READY_YIELD),(native.RESUME_GENERATOR,native.PAUSED),(native.THROW_GENERATOR,native.PAUSED)):
                state=[native.STATE_MAGIC,1,mode,0,17,phase,123,456,0,0,0,0,0]+[0]*11
                state[10]=native._checksum(state)
                both([native.REQUEST_MAGIC,event,17,0,0,mode,123,456]+[0]*8,struct.pack('<24Q',*state),'mode%d.generator-event%d'%(mode,event))
    write(args.output/'complete-packets.json',rows)
    return {'count':len(rows),'VM_entries':vm.calls,'all_446_ports':True,
            'all_26_modes':True,'complete_VM_native_bytes_equal':True,
            'scope':'complete transport/state consistency; business expected comes only from original finite lanes'}


def resource_owner(image, actual, *, callback=None):
    from tests import hia_service_verification_oracle as oracle
    from hepta import hia_service_verification_native as native
    case=json.loads((oracle.ORIGINALS/'cases.json').read_bytes())['base_cases']
    case=next(row for row in case if row['id']=='verify.core.outer0')
    def invoke(world,mode,values):
        number=oracle.MODES.index(mode)+1
        child=native.ServiceVerificationFrame(image,number,
            dict(zip(native.PUBLIC_ARGUMENTS[number-1],values)),namespace=world.namespace)
        del values
        return child.finish()
    world=oracle.World(case,invoke)
    service=oracle.Service(world);service._store=actual if callback is None else callback
    owner=native.ServiceVerificationFrame(image,native.VERIFY,
        {'self':service,'args':world.args()},namespace=world.namespace)
    return owner,world

def resources(image,args):
    from hepta import hia_agent_store as store,hia_store_artifact_profile_native as store_native
    from hepta import hia_service_verification_native as native,hia_native_delivery as delivery
    from hepta import hia_service_context_native as context
    from hepta.hia_native_helpers import native_helpers_scope
    path=args.output/'bundle.json'
    pin=bundle(path,[(native.SELECTOR,args.manifest),(store_native.SELECTOR,args.store_manifest),
                     (context.SELECTOR,args.context_manifest)])
    rows=[]
    with native_helpers_scope(str(path),pin):
        image=native.installed_service_verification(str(args.manifest))
        peer=context.installed_service_context(str(args.context_manifest))
        for label,port in (('first-publications','verify_append'),('receipt','verify_receipt'),
                           ('result','verify_return'),('release','verify_release'),('FINALIZE',None)):
            actual=store.AgentStore(args.output/label);sql=[];actual.db.set_trace_callback(sql.append)
            entries=[];fault=ValueError('completed Store publication before missing parent ACK')
            owner,world=resource_owner(image,actual)
            wanted=lambda q,a:q[1]==native.FINALIZE and q[5]==native.VERIFY if port is None else q[1]==native.SUCCEEDED and q[3]==native.PORT[port]
            with attributes(image,{'_entry':entry_observer(image,entries,target=wanted,fault=fault)}):
                _,error=caught(owner.finish)
            assert type(error) is native.ServiceVerificationUnknown and owner._delivery.loss is not None
            assert any('INSERT' in statement.upper() for statement in sql)
            before=(list(sql),len(entries));_,again=caught(owner.finish)
            assert type(again) is native.ServiceVerificationUnknown and before==(sql,len(entries))
            close_calls=[];reference=store._NATIVE_STORE_CLOSE_REFERENCE
            def close(receiver):close_calls.append(True);return reference(receiver)
            with attributes(store,{'_NATIVE_STORE_CLOSE_REFERENCE':close}):_,error=caught(actual.close)
            assert isinstance(error,RuntimeError) and close_calls==[]
            rows.append({'id':label,'SQL':sql,'entries':entries,'retry_entries_SQL':0,'original_close_calls':0})
        first,second=store.AgentStore(args.output/'unused-A'),store.AgentStore(args.output/'actual-B')
        class Callback:
            def json(self,*values):return second.json(*values)
        owner,world=resource_owner(image,first,callback=Callback());entries=[];fault=ValueError('actual B parent ACK lost')
        with attributes(image,{'_entry':entry_observer(image,entries,
            target=lambda q,a:q[1]==native.SUCCEEDED and q[3]==native.PORT['verify_append'],fault=fault)}):
            _,error=caught(owner.finish)
        assert owner._delivery.loss is not None and type(error) is native.ServiceVerificationUnknown
        assert caught(first.close)[1] is None and isinstance(caught(second.close)[1],RuntimeError)
        rows.append({'id':'different-Store','only_actual_B_fenced':True,'entries':entries})
        for disposition in ('propagate','swallow','replace'):
            actual=store.AgentStore(args.output/('child-'+disposition));entries=[];child=[]
            fault=ValueError('actual child native loss');peer_entry=peer._entry
            def lost(*values):
                result=peer_entry(*values);child.append(result);raise fault
            class ChildCallback:
                def json(self,*values):
                    answer=actual.json(*values)
                    try:peer.arithmetic(1,3,4)
                    except context.ServiceContextUnknown:
                        if disposition=='propagate':raise
                        if disposition=='replace':raise ValueError('provider replacement')
                    return answer
            owner,world=resource_owner(image,actual,callback=ChildCallback())
            with attributes(peer,{'_entry':lost}),attributes(image,{'_entry':entry_observer(image,entries)}):
                _,error=caught(owner.finish)
            assert child and isinstance(error,RuntimeError) and owner._delivery.loss is not None
            assert not any(row['event']==native.RAISED for row in entries)
            assert not any(row['event']==native.SUCCEEDED and row['port']==native.PORT['verify_append'] for row in entries)
            assert isinstance(caught(actual.close)[1],RuntimeError)
            rows.append({'id':'child-'+disposition,'actual_child_entries':len(child),'entries':entries})
        actual=store.AgentStore(args.output/'confirmed-provider-error');fault=MemoryError('provider after actual publication')
        class ErrorCallback:
            def json(self,*values):
                actual.json(*values);raise fault
        owner,world=resource_owner(image,actual,callback=ErrorCallback())
        _,error=caught(owner.finish)
        assert error is fault and owner.finished and owner._delivery.loss is None and owner._delivery.retired
        assert caught(actual.close)[1] is None
        rows.append({'id':'confirmed-foreign-error','same_MemoryError':True,'actual_Store_retires':True})
    return {'rows':rows,'unknowns_remain_in_owned_child':len(delivery.custody_snapshot()),
            'actual_SQL_and_native_providers':True}

def public(image,args):
    from hepta import hia_agent_service as api,hia_service_verification_native as native
    from hepta import hia_store_artifact_profile_native as store_native
    from hepta.hia_native_helpers import native_helpers_scope
    from tests.test_hia_agent_native_tools import AgentToolCase
    from tools.hia_agent_native_qualification import add_program
    from tests.hia_service_verification_oracle import METHODS
    import inspect
    path=args.output/'bundle.json';pin=bundle(path,[(native.SELECTOR,args.manifest),(store_native.SELECTOR,args.store_manifest)])
    signatures={name:str(inspect.signature(getattr(api.HIAAgentService,name))) for name in METHODS}
    references={name:str(inspect.signature(getattr(api,'_SERVICE_VERIFICATION_REFERENCE_'+str(number)))) for number,name in enumerate(METHODS,1)}
    assert signatures==references
    assert isinstance(vars(api.HIAAgentService)['_native_refinement_binding'],staticmethod)
    case=AgentToolCase('runTest');ready=False;entries=[]
    with native_helpers_scope(str(path),pin):
        pinned=native.installed_service_verification(str(args.manifest))
        poison={'_SERVICE_VERIFICATION_REFERENCE_'+str(i):forbidden for i in range(1,10)}
        try:
            with attributes(api,poison),attributes(pinned,{'_entry':entry_observer(pinned,entries)}):
                case.setUp();ready=True
                case.session.freeze({'schema':'hepta.hia.agent.workload.v1',
                    'cases':[{'function':'transform','arguments':[0]}],
                    'warmup_iterations':0,'repetitions':1})
                candidate=case.session.import_program(add_program())
                result=case.session.verify(candidate)
                assert result['checks'][0]['status']=='proved'
                record=case.service._verification(result['verification_receipt'],case.session.context,candidate)
                assert record['checks']==result['checks']
                binding=api.HIAAgentService._native_refinement_binding(**binding_arguments())
                assert binding['entry_symbols']==['entry']
                class Override(api.HIAAgentService):
                    def _hia_verify(self,args):return ('override',args)
                    @staticmethod
                    def _native_refinement_binding(*args):return 'static-override'
                subject=object.__new__(Override)
                assert subject._hia_verify(7)==('override',7) and Override._native_refinement_binding()=='static-override'
                subject._hia_verify=lambda value:('instance',value)
                assert subject._hia_verify(8)==('instance',8)
                before=len(entries)
                assert type(caught(lambda:api.HIAAgentService._native_refinement_binding())[1]) is TypeError
                assert len(entries)==before
                assert any(x['mode']==native.VERIFY for x in entries)
                return {'actual_Core_Store_SQL':True,'result':result,'record':record,
                        'entries':entries,'signatures':signatures,
                        'class_instance_static_subclass_bindings_preserved':True}
        finally:
            if ready:case.tearDown()

def scope(image,args):
    from hepta import hia_service_verification_native as native,hia_agent_service as api
    from hepta.hia_native_helpers import native_helpers_scope
    original=json.loads(args.manifest.read_bytes());alternate=args.output/'alternate';alternate.mkdir()
    raw=(args.manifest.parent/original['image_path']).read_bytes()
    (alternate/original['image_path']).write_bytes(raw);rows=[]
    saved=os.environ.get(native.SELECTOR)
    try:
        with attributes(api,{'_SERVICE_VERIFICATION_REFERENCE_6':forbidden}):
            for label,field in (('source','source_sha256'),('image','image_sha256')):
                changed={**original,field:'0'*64};manifest=alternate/(label+'.json');write(manifest,changed)
                os.environ[native.SELECTOR]=str(manifest)
                assert type(caught(lambda:api.HIAAgentService._native_refinement_binding(**binding_arguments()))[1]) is ValueError
                rows.append({'bad_manifest':label,'rejected':True})
            os.environ[native.SELECTOR]=''
            assert type(caught(lambda:api.HIAAgentService._native_refinement_binding(**binding_arguments()))[1]) is ValueError
        os.environ.pop(native.SELECTOR,None)
        same=alternate/'same.json';same.write_bytes(args.manifest.read_bytes())
        path=args.output/'bundle.json';pin=bundle(path,[(native.SELECTOR,args.manifest)])
        with native_helpers_scope(str(path),pin):
            pinned=native.installed_service_verification(str(args.manifest))
            assert native.installed_service_verification(str(args.manifest)) is pinned
            assert pinned.image_sha256==image.image_sha256
            assert type(caught(lambda:native.installed_service_verification(str(same)))[1]) is ValueError
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
    from tools.build_hia_service_verification import INPUTS
    from hepta import hia_service_verification_native as native
    before={name:sha256((ROOT/name).read_bytes()).hexdigest() for name in INPUTS}
    image=native.installed_service_verification(str(args.manifest))
    observation=globals()[args.mode](image,args)
    after={name:sha256((ROOT/name).read_bytes()).hexdigest() for name in INPUTS}
    assert before==after
    write(args.output/'report.json',{'schema':'hepta.hia.service-verification-controls.v1',
        'status':'PASS','mode':args.mode,'source_before':before,'source_after':after,
        'actual_image_sha256':image.image_sha256,'observations':observation,'whole_native':False})
if __name__=='__main__':
    main()
