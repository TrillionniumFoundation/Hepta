"""New pure-front transport controls; original R1 results are not inherited."""
from __future__ import annotations
import argparse
import base64
from collections import Counter
import ctypes
import dis
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys
import time
import traceback
import unittest
import weakref
from unittest.mock import patch

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source',type=Path,required=True)
parser.add_argument('--image',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
root=args.source.resolve(strict=True);output=args.output.absolute()
output.mkdir(exist_ok=False)
sys.path.insert(0,str(root))
from hepta import hia_agent_assembly as assembly
from hepta import hia_assembly_front_native as native
from hepta import hia_core_verification_native as core_native
from hepta import hia_program as program_api
from hepta import hia_front_continuation as transport
from hepta.hia_program_runtime import _Machine, _Owner, _View
from tests.test_hia_agent_assembly import SOURCE

image=args.image.read_bytes();image_sha=sha256(image).hexdigest()
observations=[]
vm_raw=[]
def preserve_vm(label, before, buffers, pointers, sizes, expected, actual):
    serial=sum(item['owner']==label for item in vm_raw)
    after=[ctypes.string_at(p,n) for p,n in zip(pointers,sizes)]
    reference=[bytes(buffer.data) for buffer in buffers]
    value={'owner':label,'index':serial,'expected_return':expected,'actual_return':actual,
           'before':[base64.b64encode(item).decode() for item in before],
           'reference_after':[base64.b64encode(item).decode() for item in reference],
           'actual_after':[base64.b64encode(item).decode() for item in after]}
    wire=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    path=output/(label+'-vm-frame-'+str(serial).zfill(3)+'.json');path.write_bytes(wire)
    vm_raw.append({'owner':label,'index':serial,'file':path.name,'bytes':len(wire),'sha256':sha256(wire).hexdigest()})
before={p.relative_to(root).as_posix():sha256(p.read_bytes()).hexdigest()
        for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
def owner():
    return native.NativeAssemblyFront(image,image_sha)

def error_value(error):
    if error is None:return None
    return {'type':type(error).__name__,'message':str(error),
        'name':getattr(error,'name',None),
        'cause':None if error.__cause__ is None else type(error.__cause__).__name__,
        'context':None if error.__context__ is None else type(error.__context__).__name__,
        'suppress':error.__suppress_context__}

class Controls(unittest.TestCase):
    def test_exact_permission_and_terminal_consumption(self):
        image_owner=owner();frame=image_owner.prepare('_attrs',(None,7))
        self.assertEqual(frame.step(),1);issued=frame.pending;entries=image_owner.entries
        with self.assertRaises(RuntimeError):frame.service(transport.Issued(issued.raw))
        self.assertEqual(image_owner.entries,entries)
        frame.service(issued);entries=image_owner.entries
        with self.assertRaises(RuntimeError):frame.service(issued)
        self.assertEqual(image_owner.entries,entries)
        while frame.step()==1:frame.service(frame.pending)
        self.assertEqual(frame.take(),{})
        with self.assertRaises(RuntimeError):frame.take()
        frame.close();self.assertTrue(frame._retired)
        observations.append({'case':'exact-permission','entries':image_owner.entries})

    def test_issued_raw_mutation_is_rejected_before_claim(self):
        image_owner=owner();frame=image_owner.prepare('_attrs',(None,7))
        frame.step();issued=frame.pending;entries=image_owner.entries
        object.__setattr__(issued,'raw',issued.raw[:-1]+bytes([issued.raw[-1]^1]))
        with self.assertRaises(RuntimeError):frame.service(issued)
        self.assertEqual(image_owner.entries,entries)
        self.assertFalse(frame.executed)
        with self.assertRaises(RuntimeError):frame.close()
        self.assertTrue(frame._uncertain)
        self.assertIs(transport._UNCONFIRMED_RETIREMENTS[frame.nonce],frame)
        observations.append({'case':'issued-mutation','entries':image_owner.entries,'pending_cleanup':'unknown'})

    def test_actual_claim_lost_ack_has_zero_foreign_and_no_replay(self):
        image_owner=owner();frame=image_owner.prepare('_attrs',(None,7));frame.step()
        issued=frame.pending;original=image_owner._entry;calls=[];foreign=[]
        failure=RuntimeError('loss after the actual HIA claim returned')
        def entry(source,size,out,out_size,state,state_size):
            command=struct.unpack('<Q',ctypes.string_at(state,8))[0]
            result=original(source,size,out,out_size,state,state_size)
            calls.append((command,result))
            if command==2:raise failure
            return result
        frame._effect=lambda:foreign.append(True)
        image_owner._entry=entry
        caught=None
        try:frame.service(issued)
        except RuntimeError as error:caught=error
        self.assertIs(caught,failure);self.assertEqual(calls,[(2,4)])
        self.assertEqual(foreign,[]);self.assertTrue(frame._uncertain)
        for attempt in (lambda:frame.service(issued),frame.step,frame.take):
            with self.assertRaises(RuntimeError):attempt()
        self.assertEqual(calls,[(2,4)]);self.assertEqual(foreign,[])
        frame.close();self.assertIs(transport._UNCONFIRMED_RETIREMENTS[frame.nonce],frame)
        observations.append({'case':'real-claim-lost-ack','calls':calls,'foreign':len(foreign)})

    def test_actual_foreign_result_store_interruption_cannot_replay(self):
        image_owner=owner();frame=image_owner.prepare('_attrs',(None,7));frame.step()
        issued=frame.pending;original=frame._effect;calls=[];fired=[]
        def effect():calls.append(True);return original()
        frame._effect=effect
        offsets={i.offset for i in dis.get_instructions(transport.ContinuationFrame.service)
                 if i.opname=='STORE_ATTR' and i.argval=='reply'}
        self.assertTrue(offsets)
        failure=KeyboardInterrupt('loss after the actual foreign return')
        def trace(current,event,arg):
            if current.f_code is transport.ContinuationFrame.service.__code__:
                current.f_trace_opcodes=True
                if event=='opcode' and current.f_lasti in offsets and calls and not fired:
                    fired.append(True);raise failure
            return trace
        previous=sys.gettrace();arming=sys._getframe();prior=arming.f_trace
        prior_opcodes=arming.f_trace_opcodes;caught=None
        try:
            arming.f_trace=trace;arming.f_trace_opcodes=True;sys.settrace(trace)
            frame.service(issued)
        except KeyboardInterrupt as error:caught=error
        finally:
            sys.settrace(previous);arming.f_trace=prior;arming.f_trace_opcodes=prior_opcodes
        self.assertIs(caught,failure);self.assertEqual(calls,[True]);self.assertEqual(fired,[True])
        entries=image_owner.entries
        for attempt in (lambda:frame.service(issued),frame.step,frame.take):
            with self.assertRaises(RuntimeError):attempt()
        self.assertEqual(image_owner.entries,entries);self.assertEqual(calls,[True])
        frame.close();self.assertIs(transport._UNCONFIRMED_RETIREMENTS[frame.nonce],frame)
        observations.append({'case':'real-foreign-store-loss','calls':len(calls),'fired':len(fired)})

    def test_retirement_lost_ack_never_repeats_a_drop(self):
        image_owner=owner();frame=image_owner.prepare('_attrs',(None,7))
        self.assertEqual(frame.drive(),0);frame.take()
        original=image_owner._entry;calls=[];failure=RuntimeError('lost HIA retirement acknowledgement')
        def entry(source,size,out,out_size,state,state_size):
            command=struct.unpack('<Q',ctypes.string_at(state,8))[0]
            result=original(source,size,out,out_size,state,state_size);calls.append((command,result))
            if command==4:raise failure
            return result
        image_owner._entry=entry
        with self.assertRaises(RuntimeError):frame.close()
        self.assertTrue(frame._uncertain)
        before_calls=list(calls);frame.close()
        self.assertEqual(calls,before_calls)
        self.assertIs(transport._UNCONFIRMED_RETIREMENTS[frame.nonce],frame)
        observations.append({'case':'retirement-lost-ack','calls':calls})

    def test_partial_constructor_keeps_error_but_releases_own_arena(self):
        image_owner=owner();allocate=transport._private_zeroed_buffer;refs=[];sizes=[]
        failure=MemoryError('second frame arena')
        def failing(size):
            sizes.append(size)
            if len(sizes)==2:raise failure
            result=allocate(size);refs.append(weakref.ref(result));return result
        held=None
        with patch.object(transport,'_private_zeroed_buffer',side_effect=failing):
            try:image_owner.prepare('_attrs',(None,7))
            except MemoryError as error:held=error
        self.assertIs(held,failure);self.assertEqual(len(sizes),2)
        self.assertIsNone(refs[0]());self.assertIsNotNone(held.__traceback__)
        observations.append({'case':'partial-arena','sizes':sizes,'held_error':True})

    def test_full_vm_native_frames_and_boundaries(self):
        image_owner=owner();saved=image_owner._entry
        checked=assembly.assemble_program((root/'examples/hia_bootstrap/assembly_front.hiaasm').read_bytes())
        fn=checked.as_dict()['functions'][0];rows=[]
        def entry(source,source_size,out,out_size,state,state_size):
            originals=[ctypes.string_at(source,source_size),ctypes.string_at(out,out_size),
                       ctypes.string_at(state,state_size)]
            command=struct.unpack_from('<Q',originals[2])[0]
            buffers=[_Owner(-i-1,bytearray(data)) for i,data in enumerate(originals)]
            machine=_Machine(checked,12_000_000,64<<20,None,128)
            expected=machine.invoke(fn,[_View(buffers[0],False),_View(buffers[1],True),_View(buffers[2],True)])[0]
            actual=saved(source,source_size,out,out_size,state,state_size)
            preserve_vm('assembly', originals, buffers, (source,out,state), (source_size,out_size,state_size), expected, actual)
            self.assertEqual(actual,expected)
            for pointer,size,buffer in zip((source,out,state),(source_size,out_size,state_size),buffers):
                self.assertEqual(ctypes.string_at(pointer,size),bytes(buffer.data))
            self.assertEqual(bytes(buffers[0].data),originals[0])
            rows.append({'command':command,'result':actual,'output_sha256':sha256(bytes(buffers[1].data)).hexdigest(),
                         'state_sha256':sha256(bytes(buffers[2].data)).hexdigest()})
            return actual
        image_owner._entry=entry
        self.assertEqual(image_owner.run('_attrs',None,7),{})
        self.assertEqual(image_owner.run('_render_parameters',[{'name':'a','type':'u8'}]),'a:u8')
        self.assertTrue(any(row['command']==3 for row in rows))
        table=image_owner.table
        for label,source_bytes,workspace_size in [('valid',table,image_owner.workspace_bytes),
                ('wrong-magic',b'\0'*8+table[8:],image_owner.workspace_bytes),
                ('short-state',table,95)]:
            source=ctypes.create_string_buffer(source_bytes+b'SOURCE-CANARY!!!')
            out=ctypes.create_string_buffer(b'\0'*2048+b'OUTPUT-CANARY!!!')
            state=ctypes.create_string_buffer(b'\0'*workspace_size+b'STATE--CANARY!!!')
            if workspace_size>=48:struct.pack_into('<6Q',state,0,0,887,0,6,0,image_owner.runtime_profile)
            result=entry(source,len(source_bytes),out,2048,state,workspace_size)
            self.assertEqual(bytes(source[len(source_bytes):len(source_bytes)+16]),b'SOURCE-CANARY!!!')
            self.assertEqual(bytes(out[2048:2064]),b'OUTPUT-CANARY!!!')
            self.assertEqual(bytes(state[workspace_size:workspace_size+16]),b'STATE--CANARY!!!')
            if label!='valid':self.assertEqual(result,0xfffffffd)
        self.assertTrue(any(row['command']==2 for row in rows))
        self.assertTrue(any(row['command']==4 for row in rows))
        observations.append({'case':'full-vm-frames','frames':rows})

    def test_all_lazy_modes_including_return_loans(self):
        image_owner=owner();saved=image_owner._entry;counts=Counter()
        # Observe actual command-0 requests rather than inferring from a result.
        def traced(source,size,out,out_size,state,state_size):
            if state_size>=48:
                words=struct.unpack('<6Q',ctypes.string_at(state,48))
                if words[0]==0 and 1<=words[3]<=16:counts[words[3]]+=1
            return saved(source,size,out,out_size,state,state_size)
        image_owner._entry=traced
        rows=[]
        for text in (SOURCE, SOURCE.replace('hepta.hia.program.v6','hepta.hia.program.v8').replace('entry(entry)','entry(entry) return_loans([null])',1),
                     SOURCE.replace('hepta.hia.program.v6','hepta.hia.program.v8').replace('entry(entry)','entry(entry) return_loans(["a"])',1)):
            expected=assembly._parse_assembly_document(text)
            actual=image_owner.run('_parse_assembly_document',text)
            self.assertEqual(actual,expected);rows.append(actual)
        self.assertEqual(image_owner.run('_render_parameters',[{'name':'a','type':'u8'}]),'a:u8')
        self.assertIn(15,counts);self.assertIn(16,counts)
        observations.append({'case':'lazy15-16','actual_initializations':dict(counts),'documents':len(rows)})

    def test_core_two_root_full_vm_frames_and_zero_function_refusal(self):
        build=json.loads((Path(__file__).resolve().parent/'native-build-r1/RESULT.json').read_bytes())
        item=build['images']['core_verification'];manifest=Path(item['manifest_path'])
        image_path=manifest.parent/item['manifest']['image_path'];raw_image=image_path.read_bytes()
        image_owner=core_native.NativeCoreVerification(raw_image,sha256(raw_image).hexdigest())
        checked=assembly.assemble_program((root/'examples/hia_bootstrap/core_verification.hiaasm').read_bytes())
        fn=checked.as_dict()['functions'][0];saved=image_owner._entry;rows=[]
        def entry(source,source_size,out,out_size,state,state_size):
            originals=[ctypes.string_at(source,source_size),ctypes.string_at(out,out_size),ctypes.string_at(state,state_size)]
            buffers=[_Owner(-i-1,bytearray(data)) for i,data in enumerate(originals)]
            machine=_Machine(checked,12_000_000,64<<20,None,128)
            expected=machine.invoke(fn,[_View(buffers[0],False),_View(buffers[1],True),_View(buffers[2],True)])[0]
            actual=saved(source,source_size,out,out_size,state,state_size)
            preserve_vm('core', originals, buffers, (source,out,state), (source_size,out_size,state_size), expected, actual)
            self.assertEqual(actual,expected)
            for pointer,size,buffer in zip((source,out,state),(source_size,out_size,state_size),buffers):
                self.assertEqual(ctypes.string_at(pointer,size),bytes(buffer.data))
            self.assertEqual(bytes(buffers[0].data),originals[0])
            rows.append({'command':struct.unpack_from('<Q',originals[2])[0], 'error':struct.unpack_from('<Q',originals[2],32)[0], 'result':actual,
                         'output_sha256':sha256(bytes(buffers[1].data)).hexdigest(),
                         'state_sha256':sha256(bytes(buffers[2].data)).hexdigest()})
            return actual
        image_owner._entry=entry
        frame=image_owner.prepare('_reject',('actual Core refusal','E_CONTROL'))
        with self.assertRaises(program_api.HIAProgramRejected) as caught:image_owner.finish(frame)
        self.assertEqual(caught.exception.code,'E_CONTROL')
        caught.exception.__traceback__=None
        frame.close();self.assertTrue(frame._retired)
        foreign_failure=LookupError('actual _decode foreign failure')
        foreign_calls=[]
        def refusing_decode(value):
            foreign_calls.append(value)
            raise foreign_failure
        with patch.object(program_api,'_decode',refusing_decode):
            failed=image_owner.prepare('verify_program',({},))
            with self.assertRaises(LookupError) as delivered:image_owner.finish(failed)
        self.assertIs(delivered.exception,foreign_failure)
        self.assertEqual(foreign_calls,[{}])
        foreign_failure.__traceback__=None
        failed.close();self.assertTrue(failed._retired)
        table=image_owner.table
        for label,source_bytes,workspace_size in (
            ('valid-two-roots',table,image_owner.workspace_bytes),
            ('zero-functions',table[:16]+b'\0'*8+table[24:],image_owner.workspace_bytes),
            ('wrong-magic',b'\0'*8+table[8:],image_owner.workspace_bytes),
            ('short-state',table,95)):
            source=ctypes.create_string_buffer(source_bytes+b'SOURCE-CANARY!!!')
            out=ctypes.create_string_buffer(b'\0'*2048+b'OUTPUT-CANARY!!!')
            state=ctypes.create_string_buffer(b'\0'*workspace_size+b'STATE--CANARY!!!')
            if workspace_size>=48:struct.pack_into('<6Q',state,0,0,887,0,1,0,image_owner.runtime_profile)
            result=entry(source,len(source_bytes),out,2048,state,workspace_size)
            self.assertEqual(bytes(source[len(source_bytes):len(source_bytes)+16]),b'SOURCE-CANARY!!!')
            self.assertEqual(bytes(out[2048:2064]),b'OUTPUT-CANARY!!!')
            self.assertEqual(bytes(state[workspace_size:workspace_size+16]),b'STATE--CANARY!!!')
            if label!='valid-two-roots':self.assertEqual(result,0xfffffffd)
        self.assertTrue(any(row['command']==2 for row in rows))
        self.assertTrue(any(row['command']==1 and row['error']==1 for row in rows))
        self.assertTrue(any(row['result']==3 for row in rows))
        self.assertTrue(any(row['command']==4 for row in rows))
        self.assertEqual(image_path.read_bytes(),raw_image)
        observations.append({'case':'core-two-root-full-vm-frames','frames':rows})

    def test_original_generator_lifetimes_errors_and_outer_context(self):
        image_owner=owner()
        def observe(operation,case,outer):
            events=[];refs=[]
            def mark(label):
                active=sys.exception();events.append((label,None if active is None else type(active).__name__))
            class Parameter:
                def __getitem__(self,key):
                    mark('parameter-'+key)
                    if key=='type' and case!='success':
                        if case=='stop':raise StopIteration('original item stop')
                        raise LookupError('original item refusal')
                    return 'a' if key=='name' else 'u8'
                def __del__(self):mark('parameter-del')
            class Iterator:
                def __init__(self):self.done=False
                def __iter__(self):return self
                def __next__(self):
                    if self.done:raise StopIteration
                    self.done=True;item=Parameter();refs.append(weakref.ref(item));return item
                def __del__(self):mark('iterator-del')
            class Parameters:
                def __iter__(self):
                    mark('parameters-iter');it=Iterator();refs.append(weakref.ref(it));return it
                def __del__(self):mark('parameters-del')
            held=None;result=None
            try:
                if outer:raise ValueError('outer handler')
            except ValueError:
                try:result=operation(Parameters())
                except BaseException as error:held=error
            else:
                try:result=operation(Parameters())
                except BaseException as error:held=error
            while_held=list(events);alive=[ref() is not None for ref in refs];failure=error_value(held)
            if held is not None:
                # Explicitly release only the delivered traceback ownership,
                # without forcing collection or clearing native data slots.
                if held.__cause__ is not None:held.__cause__.__traceback__=None
                if held.__context__ is not None:held.__context__.__traceback__=None
                held.__traceback__=None
            held=None
            return {'result':result,'error':failure,'while_held':while_held,'alive_held':alive,
                    'after':list(events),'alive_after':[ref() is not None for ref in refs]}
        for case in ('success','error','stop'):
            for outer in (False,True):
                with self.subTest(case=case,outer=outer):
                    expected=observe(assembly._render_parameters,case,outer)
                    actual=observe(image_owner._helpers['_render_parameters'],case,outer)
                    observations.append({'case':'generator-lifetime','kind':case,'outer':outer,
                                         'expected':expected,'actual':actual})
                    self.assertEqual(actual,expected)


class Result(unittest.TextTestResult):
    def startTest(self,test):executed.append(test.id());super().startTest(test)

def flatten(suite):
    for test in suite:
        if isinstance(test,unittest.TestSuite):yield from flatten(test)
        else:yield test.id()

suite=unittest.defaultTestLoader.loadTestsFromTestCase(Controls)
loaded=list(flatten(suite));executed=[];started=time.monotonic()
with (output/'tests.log').open('w') as stream:
    result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=Result).run(suite)
after={p.relative_to(root).as_posix():sha256(p.read_bytes()).hexdigest()
       for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
unchanged=before==after and args.image.read_bytes()==image
passed=(result.testsRun==len(loaded)==len(executed) and loaded==executed and unchanged
        and not any((result.failures,result.errors,result.skipped,result.expectedFailures,result.unexpectedSuccesses)))
report={'schema':'hia.front.two-image-transport-controls.v81.r4-fixture','status':'PASS' if passed else 'FAIL',
    'scope':'DEVELOPMENT_ONLY','python':sys.version,'loaded':loaded,'executed':executed,
    'tests_run':result.testsRun,'failures':[(str(t),v) for t,v in result.failures],
    'errors':[(str(t),v) for t,v in result.errors],'skipped':result.skipped,
    'expected_failures':[(str(t),v) for t,v in result.expectedFailures],
    'unexpected_successes':list(map(str,result.unexpectedSuccesses)),
    'duration_seconds':time.monotonic()-started,'inputs_unchanged':unchanged,
    'image_sha256':image_sha,'before':before,'after':after,'observations':observations,'full_vm_raw':vm_raw,
    'current_cold':False,'public_routing':False,'whole_normalization':False}
(output/'REPORT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k not in ('before','after','observations','failures','errors')},sort_keys=True))
raise SystemExit(0 if passed else 1)
