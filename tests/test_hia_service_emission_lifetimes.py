"""Physical original-frame ownership and one-use native retirement controls.

The two retained observation modules are byte-identical to the independently
run original witnesses. Alternate scalar profiles below test the private HIA
protocol only; only this process's actual CPython is a runtime differential.
"""
from __future__ import annotations
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys
import sqlite3
import queue
import threading
import weakref
from types import SimpleNamespace
from contextlib import ExitStack
import os
import unittest
from unittest.mock import patch

from hepta import hia_service_emission_native as native
from tests import hia_service_emission_fixtures as fixtures
from tests import hia_service_emission_generator_lifetimes as generators
from tests import hia_service_emission_named_lifetimes as named
from tests import test_hia_service_emission_native as component


class ServiceEmissionLifetimeSourceTests(unittest.TestCase):
    def test_native_slot_abi_matches_actual_retained_original_code_layouts(self):
        from types import CodeType
        from tools import generate_hia_service_emission as author
        self.assertEqual(native.LOCAL_SLOTS,author.LOCAL_SLOTS)
        self.assertEqual(native.TEMPORARIES,author.TEMPORARIES)
        for mode,name in ((1,'_hia_emit'),(2,'_compile'),(3,'_signatures')):
            code=fixtures.REFERENCE[name].__code__
            names=code.co_varnames+code.co_cellvars+code.co_freevars
            mapped=tuple('service_local' if n=='self' else 'build_result' if n=='result' and mode==2 else n for n in names)
            self.assertEqual(author.NAMED_LOCALS[mode],mapped)
        signature_generators=[c for c in fixtures.REFERENCE['_signatures'].__code__.co_consts if isinstance(c,CodeType)]
        emit_generators=[c for c in fixtures.REFERENCE['_hia_emit'].__code__.co_consts if isinstance(c,CodeType)]
        for mode,code in ((5,signature_generators[0]),(6,signature_generators[1]),(7,emit_generators[0])):
            names=code.co_varnames+code.co_cellvars+code.co_freevars
            mapped=tuple('iterator' if n=='.0' else 'item' if n in ('p','typ','c') else n for n in names)
            self.assertEqual(author.NAMED_LOCALS[mode],mapped)

    def test_unreviewed_runtime_refuses_before_mapping_or_business_effects(self):
        for implementation,version in (('pypy',(3,12)),('cpython',(3,11)),('cpython',(3,15))):
            observed=SimpleNamespace(implementation=SimpleNamespace(name=implementation),version_info=version)
            with self.subTest(implementation=implementation,version=version),patch.object(native,'sys',observed),patch.object(native.ExceptionDelivery,'from_hia',side_effect=AssertionError('mapping entered')):
                with self.assertRaises(native.EmissionUnknown):native.NativeEmissionService(None,None)


class ServiceEmissionLifetimeNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):component.ServiceEmissionNativeTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):component.ServiceEmissionNativeTests.tearDownClass.__func__(cls)

    def record(self,name,value):
        (self.folder/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')

    def test_original_generator_twelve_and_named_thirty_two_observations(self):
        rows=[]
        for family in ('parameter','return','check'):
            for failure in (False,True):
                for outer in (False,True):
                    with self.subTest(family=family,failure=failure,outer=outer):
                        expected=generators.observe('reference',family,failure,outer,self.image)
                        actual=generators.observe('native',family,failure,outer,self.image)
                        rows.append({'family':family,'failure':failure,'outer':outer,'expected':expected,'actual':actual})
                        self.assertEqual(actual,expected)
        for route in ('native','default'):
            for operation,cases in (('compile',('success','read','store')),('emit',('success','read','signatures','native','receipt'))):
                for failure in cases:
                    for outer in (False,True):
                        with self.subTest(route=route,operation=operation,failure=failure,outer=outer):
                            expected=named.observe('reference',operation,failure,outer,self.image)
                            actual=named.observe('native' if route=='native' else 'reference',operation,failure,outer,self.image,public_default=route=='default')
                            rows.append({'route':route,'operation':operation,'failure':failure,'outer':outer,'expected':expected,'actual':actual})
                            self.assertEqual(actual,expected)
        self.assertEqual(len(rows),44)
        self.record('original-lifetimes-44',{'python':sys.version,'observations':rows})

    def test_actual_retirement_start_claim_and_ack_loss_never_repeat_slot(self):
        rows=[];base=self.image
        program_action=1100+native.LOCAL_SLOTS.index('program')
        for event in (7,1,2):
            dropped=[];hits=[];fault=KeyboardInterrupt('retirement-'+str(event))
            class Program:
                scalar_entrypoints=set()
                def as_dict(self):return {'functions':[]}
                def __del__(self):dropped.append('program')
            class FaultImage:
                delivery=base.delivery
                def _entry(self,source,size,output,capacity,state,extent):
                    request=struct.unpack('<8Q',ctypes.string_at(source,size))
                    before=struct.unpack('<16Q',ctypes.string_at(state,extent))
                    answer=base._entry(source,size,output,capacity,state,extent)
                    target=(request[1]==7 and before[5]==5 if event==7 else request[1]==event and before[3]==program_action and before[5]==(9 if event==1 else 10))
                    if target:
                        hits.append({'before':list(before),'after':list(struct.unpack('<16Q',ctypes.string_at(state,extent)))})
                        raise fault
                    return answer
            owner=native.NativeEmissionService(None,FaultImage())
            held=None
            try:owner.signatures(Program())
            except BaseException as error:held=error
            self.assertIs(held,fault);self.assertEqual(len(hits),1)
            self.assertEqual(dropped,[] if event in (7,1) else ['program'])
            self.assertEqual(len(owner.unknown),1);state=next(iter(owner.unknown.values()))
            state.fenced=False;state._retiring=False
            before=state.buffer.raw
            with self.assertRaises(native.EmissionUnknown):state.retire()
            self.assertEqual(state.buffer.raw,before)
            self.assertEqual(dropped,[] if event in (7,1) else ['program'])
            state.fenced=True;state._retiring=True
            rows.append({'event':event,'drops':list(dropped),'actual_handoff':hits,'retry_refused_before_effect':True})
        self.record('actual-retirement-unknown',rows)

    def test_held_original_error_retires_after_actual_service_and_sqlite_close(self):
        from hepta import hia_agent_service as api
        from hepta import hia_program_native as provider
        rows=[]
        def observe(selected,outer):
            trace=[];references=[];post_close_frames=[];closed=False
            import weakref
            def ambient():
                error=sys.exception()
                return None if error is None else [type(error).__name__,str(error)]
            def held(label,value):references.append((label,weakref.ref(value)))
            def drop(label):trace.append(['drop',label,ambient()])
            class Failure(Exception):pass
            class Program:
                sha256='a'*64
                def __init__(self):held('program',self)
                def __del__(self):drop('program')
            class Image:
                object_bytes=b'OBJ'
                def __init__(self):held('image',self)
                def __del__(self):drop('image')
            class Directory(str):
                def __new__(cls):
                    result=super().__new__(cls,'/held-error-output');held('directory',result);return result
                def __del__(self):drop('directory')
            class Output:
                def __init__(self):held('output',self)
                def read_bytes(self):raise Failure('original read error')
                def __del__(self):drop('output')
            class Left:
                def __init__(self,value):pass
                def __truediv__(self,value):return Output()
            class Manager:
                def __init__(self,**values):pass
                def __enter__(self):return Directory()
                def __exit__(self,*values):return False
            class Build(dict):
                def __init__(self):super().__init__();held('result',self)
                def __del__(self):drop('result')
            def emit(*values,**keywords):return Image()
            def compile(*values,**keywords):return Build()
            case=self.folder/('closed-error-'+str(selected)+'-'+str(outer))
            env={key:'' for key in os.environ if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST')}
            env[native.SELECTOR]=str(self.manifest_path) if selected else ''
            with patch.dict(os.environ,env):service=api.HIAAgentService(case)
            owner=service._native_emission
            actual_entry=self.image._entry
            def entry(source,size,output,capacity,state,extent):
                request=struct.unpack('<8Q',ctypes.string_at(source,size))
                before=struct.unpack('<16Q',ctypes.string_at(state,extent))
                result=actual_entry(source,size,output,capacity,state,extent)
                if closed:post_close_frames.append({'event':request[1],'before':list(before),'after':list(struct.unpack('<16Q',ctypes.string_at(state,extent)))})
                return result
            def run():
                nonlocal closed
                error=None
                try:
                    if selected:service._compile(Program(),'object',None,1000)
                    else:fixtures.REFERENCE['_compile'](service,Program(),'object',None,1000)
                except BaseException as caught:error=caught
                self.assertIs(type(error),Failure)
                shape={'type':type(error).__name__,'message':str(error),
                       'cause':None if error.__cause__ is None else [type(error.__cause__).__name__,str(error.__cause__)],
                       'context':None if error.__context__ is None else [type(error.__context__).__name__,str(error.__context__)]}
                before={'trace':list(trace),'alive':[(label,ref() is not None) for label,ref in references]}
                service.close();closed=True
                with self.assertRaises(sqlite3.ProgrammingError):service.store.db.execute('SELECT 1')
                after_close={'trace':list(trace),'alive':[(label,ref() is not None) for label,ref in references]}
                if owner is not None:
                    count=len(post_close_frames)
                    with self.assertRaises(native.EmissionUnknown):owner.signatures(SimpleNamespace())
                    self.assertEqual(len(post_close_frames),count)
                error=None
                after_release={'trace':list(trace),'alive':[(label,ref() is not None) for label,ref in references]}
                return {'error':shape,'before_close':before,'after_close':after_close,'after_release':after_release}
            with ExitStack() as stack:
                stack.enter_context(patch.object(provider,'emit_program_machine',emit))
                stack.enter_context(patch.object(provider,'compile_program_machine',compile))
                stack.enter_context(patch.object(api.tempfile,'TemporaryDirectory',Manager))
                stack.enter_context(patch.object(api,'Path',Left))
                stack.enter_context(patch.object(api.time,'monotonic',lambda:1.0))
                stack.enter_context(patch.object(self.image,'_entry',entry))
                if outer:
                    try:raise ArithmeticError('original outer')
                    except ArithmeticError:observation=run()
                else:observation=run()
            if selected:
                self.assertTrue(post_close_frames)
                for frame in post_close_frames:
                    self.assertIn(frame['event'],(7,1,2))
                    self.assertEqual(frame['before'][5],{7:7,1:9,2:10}[frame['event']])
                self.assertFalse(owner.active);self.assertFalse(owner.retiring);self.assertFalse(owner.unknown)
            return observation,post_close_frames
        for outer in (False,True):
            expected,_=observe(False,outer);actual,frames=observe(True,outer)
            self.assertEqual(actual,expected)
            rows.append({'outer':outer,'expected':expected,'actual':actual,'post_close_native_retirement_frames':frames})
        self.record('actual-service-closed-held-error',rows)

    def test_complete_private_profile_frames_match_vm_and_original_named_order(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine,_Owner,_View
        program=assemble_program(native.SOURCE.read_bytes());entry=program.as_dict()['functions'][0]
        original=fixtures.REFERENCE['_signatures'].__code__
        original_names=original.co_varnames+original.co_cellvars+original.co_freevars
        base=self.image;rows=[]
        for profile in (312,313,314):
            retained=bytearray(128);actions=[];frames=[]
            class Mirror:
                delivery=base.delivery
                def _entry(self,source,size,output,capacity,state,extent):
                    raw=ctypes.string_at(source,size);fields=struct.unpack('<8Q',raw)
                    before=ctypes.string_at(state,extent)
                    self_test.assertEqual(before,bytes(retained))
                    src=ctypes.create_string_buffer(raw+b'\xa5'*16,size+16)
                    out=ctypes.create_string_buffer(b'\xb7'*(capacity+16),capacity+16)
                    work=ctypes.create_string_buffer(before+b'\xc9'*16,extent+16)
                    actual=base._entry(src,size,out,capacity,work,extent)
                    owners=[_Owner(-1,bytearray(raw)),_Owner(-2,bytearray(b'\xb7'*capacity)),_Owner(-3,retained)]
                    expected=_Machine(program,10000000,16<<20,None,128).invoke(entry,[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
                    self_test.assertEqual((actual,out.raw[:capacity],work.raw[:extent]),(expected,bytes(owners[1].data),bytes(retained)))
                    self_test.assertEqual(src.raw,raw+b'\xa5'*16);self_test.assertEqual(out.raw[capacity:],b'\xb7'*16);self_test.assertEqual(work.raw[extent:],b'\xc9'*16)
                    old=struct.unpack('<16Q',before)
                    if fields[1]==1 and old[5]==9:actions.append(native.LOCAL_SLOTS[old[3]-1100])
                    frames.append({'request':raw.hex(),'returned':actual,'output':out.raw[:capacity].hex(),'state':bytes(retained).hex()})
                    ctypes.memmove(output,out,capacity);ctypes.memmove(state,work,extent)
                    return actual
            self_test=self
            owner=native.NativeEmissionService(None,Mirror());owner.profile=profile
            self.assertEqual(owner.signatures(SimpleNamespace(as_dict=lambda:{'functions':[]},scalar_entrypoints=set())),{})
            self.assertEqual(actions,list(reversed(original_names)) if profile==314 else list(original_names))
            self.assertFalse(owner.active);self.assertFalse(owner.retiring);self.assertFalse(owner.unknown)
            rows.append({'private_profile':profile,'actual_runtime_profile':native._runtime_profile(),'actions':actions,'frames':frames,'scope':'PRIVATE_PROTOCOL_NOT_OTHER_INTERPRETER_QUALIFICATION'})
        self.record('complete-private-profile-frames',rows)

    def test_terminal_retirement_follows_last_cross_thread_traceback_reference(self):
        from hepta import hia_agent_service as api
        rows=[];main_thread=threading.get_ident();base=self.image
        def observe(selected,outer,holders,closed):
            trace=[];refs=[];handoffs=[queue.Queue() for _ in range(holders)]
            ready=[threading.Event() for _ in range(holders)];release=[threading.Event() for _ in range(holders)];done=[threading.Event() for _ in range(holders)]
            stage={};worker_ids={};native_frames=[];worker_errors=[];states=[]
            class OriginalError(Exception):pass
            class Program:
                def __init__(self):refs.append(weakref.ref(self))
                def as_dict(self):raise OriginalError('original signature error')
                def __del__(self):
                    error=sys.exception()
                    trace.append({'event':'program-del','on_original_thread':threading.get_ident()==main_thread,
                                  'worker':worker_ids.get(threading.get_ident()),
                                  'handled':None if error is None else [type(error).__name__,str(error)]})
            owner=native.NativeEmissionService(None,base) if selected else None
            original_entry=base._entry
            def entry(source,size,output,capacity,state,extent):
                request=struct.unpack('<8Q',ctypes.string_at(source,size));before=struct.unpack('<16Q',ctypes.string_at(state,extent))
                result=original_entry(source,size,output,capacity,state,extent)
                if threading.get_ident()!=main_thread:native_frames.append({'worker':worker_ids[threading.get_ident()],'event':request[1],'before':list(before),'after':list(struct.unpack('<16Q',ctypes.string_at(state,extent)))})
                return result
            def original_call():
                try:
                    if selected:owner.signatures(Program())
                    else:fixtures.REFERENCE['_signatures'](Program())
                except BaseException as error:return error
                raise AssertionError('original fixture did not raise')
            def handoff():
                error=original_call()
                for channel in handoffs:channel.put(error)
                # The test's transfer frame must relinquish its own reference
                # after every recipient has acquired the very same error.
                # Otherwise error -> traceback -> handoff -> error is a
                # fixture-owned cycle on both the reference and native route.
                error=None
            def worker(index):
                worker_ids[threading.get_ident()]=index
                def release_original():
                    error=handoffs[index].get_nowait()
                    stage[(index,'error')]={'type':type(error).__name__,'message':str(error),'cause':None if error.__cause__ is None else type(error.__cause__).__name__,'context':None if error.__context__ is None else type(error.__context__).__name__}
                    ready[index].set()
                    if not release[index].wait(10):raise AssertionError('release coordination timed out')
                    if selected:
                        count=len(native_frames)
                        with self.assertRaises(native.EmissionUnknown):states[0]().call(0)
                        self.assertEqual(len(native_frames),count)
                    error=None
                    stage[(index,'after')]={'trace':list(trace),'alive':[ref() is not None for ref in refs]}
                try:
                    if outer:
                        try:raise LookupError('worker outer')
                        except LookupError:release_original()
                    else:release_original()
                except BaseException as error:worker_errors.append((type(error).__name__,str(error)))
                finally:done[index].set()
            with ExitStack() as stack:
                stack.enter_context(patch.object(base,'_entry',entry))
                if selected:
                    original_new=owner._new_state
                    def new(*values,**keywords):
                        state=original_new(*values,**keywords);states.append(weakref.ref(state));return state
                    stack.enter_context(patch.object(owner,'_new_state',new))
                handoff()
                before={'trace':list(trace),'alive':[ref() is not None for ref in refs]}
                if closed:
                    proxy=SimpleNamespace(_native_emission=owner,store=SimpleNamespace(close=lambda:None))
                    api.HIAAgentService.close(proxy)
                threads=[threading.Thread(target=worker,args=(index,)) for index in range(holders)]
                for thread in threads:thread.start()
                try:
                    for event in ready:self.assertTrue(event.wait(10))
                    for index in range(holders):
                        release[index].set();self.assertTrue(done[index].wait(10))
                        if index+1<holders:self.assertEqual(stage[(index,'after')],{'trace':[],'alive':[True]})
                finally:
                    for event in release:event.set()
                    for thread in threads:thread.join(10)
                self.assertTrue(all(not thread.is_alive() for thread in threads));self.assertEqual(worker_errors,[])
            self.assertEqual(stage[(holders-1,'after')]['alive'],[False])
            self.assertEqual(len(trace),1)
            if selected:
                self.assertEqual(len(states),1);self.assertIsNone(states[0]())
                self.assertFalse(owner.active);self.assertFalse(owner.retiring);self.assertFalse(owner.unknown)
                self.assertEqual(sum(row['event']==7 for row in native_frames),1)
                for frame in native_frames:
                    self.assertEqual(frame['worker'],holders-1)
                    self.assertEqual(frame['before'][5],{7:7,1:9,2:10}[frame['event']])
            observation={'before':before,'errors':[stage[(i,'error')] for i in range(holders)],'after_each':[stage[(i,'after')] for i in range(holders)]}
            return observation,native_frames
        for holders in (1,2):
            for closed in (False,True):
                for outer in (False,True):
                    with self.subTest(holders=holders,closed=closed,outer=outer):
                        expected,_=observe(False,outer,holders,closed);actual,frames=observe(True,outer,holders,closed)
                        self.assertEqual(actual,expected)
                        rows.append({'holders':holders,'closed':closed,'outer':outer,'expected':expected,'actual':actual,'actual_retirement_frames':frames})
        self.record('last-cross-thread-traceback',rows)
