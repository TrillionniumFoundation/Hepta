"""Original declaration refusal order and partial owner state under native control."""
from __future__ import annotations
from contextlib import contextmanager
from copy import deepcopy
import ctypes
from dataclasses import replace
import dis
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import weakref

from hepta import hia_program_composite as composite
from hepta import hia_composite_types_native as native_types
from hepta.hia_instruction_policy_native import transport
from hepta.hia_nominal_admission_native import (SOURCE, SCHEMA, SELECTOR, MAGIC, ERRORS,
    INPUT_BYTES, OUTPUT_BYTES, WORKSPACE_BYTES, AdmissionContext, AdmissionResult,
    NativeNominalAdmission, installed_nominal_admission, selected_nominal_admission)
from hepta.hia_program import HIAProgramRejected, verify_core
from tests import test_hia_program_composite as fixtures
from tests import test_hia_partial_record as partials
from tests import test_hia_composite_returned_loans as loans
from tests.test_hia_nominal_terminators_native import scalar_edges
from tests.test_hia_program import b, f, ret

ROOT = Path(__file__).resolve().parents[1]
COLD_REPORT = 'HEPTA_HIA_NOMINAL_ADMISSION_COLD_REPORT'
DEVELOPMENT_MANIFEST = 'HEPTA_HIA_NOMINAL_ADMISSION_DEVELOPMENT_MANIFEST'
TYPES_DEVELOPMENT_MANIFEST = 'HEPTA_HIA_NOMINAL_ADMISSION_TYPES_DEVELOPMENT_MANIFEST'


@contextmanager
def observed_contexts():
    """Keep contexts alive while observing their actual arena ownership."""
    original, contexts, buffers = AdmissionContext.__init__, [], []
    def initialize(context, *args, **kwargs):
        original(context, *args, **kwargs)
        contexts.append(context)
        buffers.extend(weakref.ref(value) for value in (context.output, context.workspace))
    with patch.object(AdmissionContext, '__init__', new=initialize):
        yield contexts, buffers


@contextmanager
def interrupt_store(code, attribute, error):
    """Inject at a positively observed real STORE_ATTR, before its write."""
    offsets = [item.offset for item in dis.get_instructions(code)
               if item.opname == 'STORE_ATTR' and item.argval == attribute]
    if len(offsets) != 1:
        raise AssertionError((attribute, offsets))
    injections, previous = [], sys.gettrace()
    def trace(frame, event, arg):
        if frame.f_code is code:
            frame.f_trace_opcodes = True
            if event == 'opcode' and frame.f_lasti == offsets[0]:
                injections.append(frame.f_lasti)
                raise error
        return trace
    trace_frame = sys._getframe()
    previous_opcode_flag = trace_frame.f_trace_opcodes
    trace_frame.f_trace_opcodes = True
    try:
        sys.settrace(trace)
        yield injections
    finally:
        sys.settrace(previous)
        trace_frame.f_trace_opcodes = previous_opcode_flag


def outcome(call):
    try:
        call()
        return None
    except HIAProgramRejected as exc:
        return exc.code, str(exc)


def state(owner):
    result = {'fields': sorted(vars(owner))}
    for name in ('document','serial','value_slots','nominal_operations','parameter_loan_returns',
                 'functions','helpers','helper_names','return_origins'):
        if hasattr(owner, name):
            result[name] = deepcopy(getattr(owner, name))
    if hasattr(owner, 'signatures'):
        result['signatures'] = {name: ([(key, typ.kind, typ.flat) for key, typ in params],
            [(typ.kind, typ.flat) for typ in returns]) for name, (params, returns) in owner.signatures.items()}
    if hasattr(owner, 'native_types'):
        result['native_types'] = owner.native_types is not None
        if owner.native_types is not None:
            result['descriptors'] = deepcopy(owner.native_types._descriptors)
            result['type_observations'] = owner.native_types.observations
            result['same_type_owner'] = owner.types is owner.native_types
    return result


class NominalAdmissionSourceTests(unittest.TestCase):
    def test_source_is_ordinary_hia_with_original_compiler_budgets(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools import generate_hia_nominal_admission as generator
        from tools.hia_selfhost_limits import MAX_FUNCTIONS, MAX_BLOCKS, MAX_INSTRUCTIONS
        doc = generator.document()
        self.assertEqual(render_assembly(doc).encode(), SOURCE.read_bytes())
        self.assertLessEqual(len(doc['functions']), MAX_FUNCTIONS)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in doc['functions']), MAX_BLOCKS)
        self.assertLessEqual(sum(len(bl['ops']) for fn in doc['functions'] for bl in fn['blocks']), MAX_INSTRUCTIONS)
        self.assertLessEqual(max(len(bl['params']) for fn in doc['functions'] for bl in fn['blocks']), 16)
        verify_core(doc)

    def test_missing_selected_image_never_falls_back(self):
        with patch.dict(os.environ, {SELECTOR: ''}):
            self.assertIsNone(selected_nominal_admission())
        with patch.dict(os.environ, {SELECTOR: '/missing-admission-image'}), patch.object(
                composite._Elaborator, '_reference_initialize', side_effect=AssertionError('host declaration')):
            with self.assertRaises(HIAProgramRejected):
                verify_core(scalar_edges())


class NominalAdmissionAdapterTests(unittest.TestCase):
    def image(self, frame, *, mutate=False):
        image = object.__new__(NativeNominalAdmission)
        def entry(source, size, output, capacity, workspace, workspace_size):
            if mutate:
                ctypes.memmove(source, b'x', 1)
            if type(frame) is int:
                return frame
            ctypes.memmove(output, frame, len(frame))
            return len(frame)
        image._entry = entry
        return image

    def frame(self, *, error=0, request=4, index=0, item=0, sequence=1,
              reserved=0, delta=0, value=None):
        graph = transport(value)
        return struct.pack('<8Q', MAGIC, error, request, index, item, sequence,
                           len(graph) + delta, reserved) + graph

    def context(self):
        return AdmissionContext(object.__new__(composite._Elaborator), scalar_edges())

    def test_checked_result_graph_sequence_and_immutable_input(self):
        good = self.frame()
        actual = self.image(good).step(self.context())
        self.assertEqual((actual.request, actual.sequence), (4, 1))
        bad = [0, 0xfffffff1, good[:-1], self.frame(error=18), self.frame(error=19), self.frame(request=13),
               self.frame(error=1), self.frame(sequence=0), self.frame(sequence=2),
               self.frame(request=3, index=1), self.frame(item=1), self.frame(reserved=1),
               self.frame(delta=1), self.frame(value={}), self.frame(request=2),
               self.frame(request=6), self.frame(request=1, value={})]
        for frame in bad:
            with self.subTest(frame=repr(frame)[:60]), self.assertRaises(HIAProgramRejected):
                self.image(frame).step(self.context())
        with self.assertRaisesRegex(HIAProgramRejected, 'original bytes changed'):
            self.image(good, mutate=True).step(self.context())

    def test_current_callback_is_executed_at_most_once_and_closed_context_refuses(self):
        context = self.context()
        request = AdmissionResult(0, 3, 0, 0, 1, None)
        with self.assertRaises(HIAProgramRejected):
            context.invoke(request)
        with self.assertRaises(HIAProgramRejected):
            context.invoke(None)
        request = self.image(self.frame(request=3)).step(context)
        context.invoke(request)
        context.owner.functions['retained'] = {}
        with self.assertRaises(HIAProgramRejected):
            context.invoke(request)
        self.assertIn('retained', context.owner.functions)
        context.closed = True
        with self.assertRaises(HIAProgramRejected):
            self.image(0).step(context)
        context.close()

    def test_partial_real_allocations_release_with_original_exception_held(self):
        allocate = ctypes.create_string_buffer
        for failure in (1, 2):
            for exception in (MemoryError, KeyboardInterrupt):
                with self.subTest(allocation=failure, exception=exception.__name__):
                    error = exception('original allocation interruption')
                    calls, buffers = [], []
                    context = AdmissionContext.__new__(AdmissionContext)
                    def measured(*args, **kwargs):
                        calls.append(args)
                        if len(calls) == failure:
                            raise error
                        value = allocate(*args, **kwargs)
                        self.assertEqual(ctypes.sizeof(value), OUTPUT_BYTES)
                        buffers.append(weakref.ref(value))
                        return value
                    with patch.object(ctypes, 'create_string_buffer', new=measured):
                        try:
                            context.__init__(object.__new__(composite._Elaborator), scalar_edges())
                        except BaseException as caught:
                            self.assertIs(caught, error)
                            self.assertIsNotNone(caught.__traceback__)
                            self.assertTrue(context.closed)
                            self.assertIsNone(context.output)
                            self.assertIsNone(context.workspace)
                            self.assertTrue(all(reference() is None for reference in buffers))
                        else:
                            self.fail('allocation fault was not injected')
                    self.assertEqual(len(calls), failure)


class NominalAdmissionNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT_MANIFEST), os.environ.get(COLD_REPORT)
        if development and cold:
            raise AssertionError('development fixture cannot override cold source custody')
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-nominal-admission-')
        cls.addClassCleanup(cls.temporary.cleanup); cls.folder = Path(cls.temporary.name)
        if development:
            def copy_fixture(original, name):
                supplied = Path(original); value = json.loads(supplied.read_bytes()); image = value['image_path']
                assert type(image) is str and Path(image).name == image
                folder = cls.folder/name; folder.mkdir()
                shutil.copyfile(supplied.parent/image, folder/image)
                target=folder/'manifest.json'; target.write_bytes(supplied.read_bytes()); return target
            cls.manifest=copy_fixture(development,'admission')
            cls.types_manifest=copy_fixture(os.environ[TYPES_DEVELOPMENT_MANIFEST],'types')
            cls.fixture_scope='DEVELOPMENT_ONLY'
        elif cold:
            from tools.build_hia_json_preflight import build
            report=json.loads(Path(cold).read_bytes()); nested=json.loads(Path(report['nested_report']).read_bytes())
            compiler=Path(nested['generations'][-1]['produced_image'])
            cls.manifest=build(cls.folder/'admission',compiler,Path(cold),candidate='nominal-admission')
            cls.types_manifest=build(cls.folder/'types',compiler,Path(cold),candidate='composite-types')
            cls.fixture_scope='MATCHING_SOURCE_JOINT_COLD_BUILD'
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage
            seed,_=build_seed(cls.folder); source=SOURCE.with_name('selfhost.hepta').read_bytes()
            first,_=compile_stage(cls.folder,'B1',seed,source,image_format='seed-shared')
            compiler,_=compile_stage(cls.folder,'B2',first,source)
            assert first.read_bytes()==compiler.read_bytes()
            manifests=[]
            for name,source,schema in [('nominal-admission',SOURCE,SCHEMA),
                    ('composite-types',native_types.SOURCE,native_types.SCHEMA)]:
                image,receipt=compile_stage(cls.folder,name,compiler,source.read_bytes())
                manifest=cls.folder/(name+'-manifest.json')
                manifest.write_text(json.dumps(dict(schema=schema,source_sha256=sha256(source.read_bytes()).hexdigest(),
                    image_path=image.name,image_sha256=sha256(image.read_bytes()).hexdigest(),
                    compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))
                (cls.folder/(name+'-development.json')).write_text(json.dumps(receipt));manifests.append(manifest)
            cls.manifest,cls.types_manifest=manifests
            cls.fixture_scope='BOOTSTRAP_DEVELOPMENT_ONLY'
        cls.native=installed_nominal_admission(str(cls.manifest))

    def selected_types(self):
        return patch.dict(os.environ,{native_types.SELECTOR:str(self.types_manifest)})

    def selected(self):
        return patch.dict(os.environ,{native_types.SELECTOR:str(self.types_manifest),SELECTOR:str(self.manifest)})

    def compare(self, document, *, legacy=False):
        original, current = deepcopy(document), deepcopy(document)
        left, right = object.__new__(composite._Elaborator), object.__new__(composite._Elaborator)
        before = deepcopy(document)
        command = native_types.NativeCompositeTypeSession._command
        traces = [[], []]
        def record(which):
            def called(session, value, **kwargs):
                traces[which].append((deepcopy(value), dict(kwargs)))
                return command(session, value, **kwargs)
            return called
        with self.selected_types(), patch.object(native_types.NativeCompositeTypeSession,'_command',record(0)):
            expected=outcome(lambda:left._reference_initialize(original,legacy=legacy))
        with self.selected_types(), patch.object(native_types.NativeCompositeTypeSession,'_command',record(1)), \
                patch.object(composite._Elaborator,'_reference_initialize',side_effect=AssertionError('host declaration')):
            actual=outcome(lambda:self.native.initialize(right,current,legacy=legacy))
        self.assertEqual(actual,expected)
        self.assertEqual(state(right),state(left))
        self.assertEqual(traces[1],traces[0])
        self.assertEqual((original,current),(before,before))
        return right, actual, traces[1]

    def test_four_schemas_original_objects_and_late_body_validation(self):
        for maker in (scalar_edges,fixtures.stored_loan_program,partials.roundtrip_program,loans.pair_program):
            owner,error,_=self.compare(maker());self.assertIsNone(error)
            self.assertIs(owner.types,owner.native_types)
            for function in owner.document['functions']:
                self.assertIs(owner.functions[function['name']],function)
        for version in (1,2,3,4):
            doc=scalar_edges();doc['schema']='hepta.hia.composite.v'+str(version)
            self.assertIsNone(self.compare(doc)[1])
        doc=scalar_edges();doc['functions'][0]['entry']=None;doc['functions'][0]['blocks']=None
        self.assertIsNone(self.compare(doc)[1])

    def test_root_function_and_effect_refusals_keep_exact_partial_state(self):
        cases=[None,[],{},dict(scalar_edges(),extra=True)]
        for field,values in [('schema',[None,'hepta.hia.composite.v99']),
                ('module',[None,'a-b','__hia_reserved','h2internal_1']),('types',[None]),
                ('functions',[None,[],[None], [{}]])]:
            for value in values:
                doc=scalar_edges();doc[field]=value;cases.append(doc)
        for field,values in [('name',[None,'a-b','__hia_reserved','h2internal_1']),
                ('params',[None,[{'name':'p','type':'u32'},{'name':'p','type':'u32'}]]),
                ('returns',[None,['Missing'],['readbuf','Missing'],['readbuf']]),
                ('effects',[None,['missing'],[[]],['read','read']])]:
            for value in values:
                doc=scalar_edges();doc['functions'][0][field]=value;cases.append(doc)
        doc=scalar_edges();doc['functions'][0]['extra']=True;cases.append(doc)
        doc=scalar_edges();doc['functions']*=2;cases.append(doc)
        for doc in cases:
            with self.subTest(document=repr(doc)[:100]):
                self.assertIsNotNone(self.compare(doc)[1])

    def test_all_returns_resolve_before_loan_escape_and_origins_precede_effects(self):
        doc=scalar_edges();doc['functions'][0]['returns']=['readbuf','Missing']
        _,error,trace=self.compare(doc)
        self.assertEqual(error[0],'E_HIA_TYPE')
        self.assertEqual([command.get('ref') for command,_ in trace if command['op']=='resolve'],['readbuf','Missing'])
        doc=scalar_edges();doc['schema']='hepta.hia.composite.v4';doc['functions'][0]['effects']=['missing']
        owner,error,trace=self.compare(doc)
        self.assertEqual(error[0],'E_HIA_EFFECT')
        self.assertEqual(owner.return_origins,{'choose':(None,)})
        self.assertEqual(owner.functions,{})
        self.assertEqual(trace[-1][0]['op'],'origins')
        doc['functions'][0]['return_loans']=[{'param':'absent','fields':[]}]
        owner,error,_=self.compare(doc)
        self.assertEqual(error[0],'E_HIA_LOAN');self.assertEqual(owner.return_origins,{})

    def test_legacy_profile_and_exact_six_or_seven_field_refusal(self):
        owner,error,_=self.compare(scalar_edges(),legacy=True)
        self.assertIsNone(error);self.assertEqual(owner.nominal_operations,composite.LEGACY_COMPOSITE_OPERATIONS)
        doc=scalar_edges();doc['schema']='hepta.hia.composite.v2'
        owner,error,_=self.compare(doc,legacy=True)
        self.assertEqual(error[0],'E_HIA_SCHEMA');self.assertEqual(vars(owner),{})
        for version in (1,4):
            doc=scalar_edges();doc['schema']='hepta.hia.composite.v'+str(version)
            doc['functions'][0]['return_loans']=[None];doc['functions'][0]['extra']=True
            _,error,_=self.compare(doc)
            self.assertEqual(error[0],'E_HIA_FORMAT')
            self.assertEqual('return_loans' in error[1],version==4)

    def test_original_foreign_legacy_truth_occurs_only_after_root_schema_guards(self):
        for legacy in (None,0,1,[],[1],{}, {'enabled':True},'', 'enabled'):
            with self.subTest(legacy=legacy):
                self.assertIsNone(self.compare(scalar_edges(),legacy=legacy)[1])
        class Observed:
            def __init__(self):self.calls=0
            def __bool__(self):
                self.calls+=1
                raise RuntimeError('original foreign truth failure')
        for document in ({}, dict(scalar_edges(),schema='bad')):
            flag=Observed();owner=object.__new__(composite._Elaborator)
            self.assertIsNotNone(outcome(lambda:self.native.initialize(owner,document,legacy=flag)))
            self.assertEqual(flag.calls,0);self.assertEqual(vars(owner),{})
        for method in ('reference','native'):
            flag=Observed();owner=object.__new__(composite._Elaborator)
            call=(lambda:owner._reference_initialize(scalar_edges(),legacy=flag)) if method=='reference' else \
                 (lambda:self.native.initialize(owner,scalar_edges(),legacy=flag))
            with self.assertRaisesRegex(RuntimeError,'original foreign truth failure'):call()
            self.assertEqual(flag.calls,1);self.assertEqual(vars(owner),{})

    def test_two_foreign_truth_observations_preserve_live_document_and_assignment_order(self):
        modes=('false_then_true','second_interrupt','first_bad_module','first_missing_module',
               'first_missing_schema','second_bad_module','second_missing_functions',
               'second_missing_types','second_unknown_schema','second_null_schema',
               'second_unhashable_schema','second_unhashable_mapping_schema',
               'legacy_unhashable_schema','legacy_unhashable_mapping_schema','legacy_unknown_schema')
        def run(mode,native):
            document=scalar_edges();document['schema']='hepta.hia.composite.v2'
            owner=object.__new__(composite._Elaborator);events=[]
            class Flag:
                def __bool__(self):
                    index=len(events);events.append(sorted(vars(owner)))
                    if index==0:
                        if mode=='first_bad_module':document['module']='0invalid'
                        if mode=='first_missing_module':del document['module']
                        if mode=='first_missing_schema':del document['schema']
                        return False
                    if mode=='second_interrupt':raise KeyboardInterrupt('original second truth')
                    if mode=='second_bad_module':document['module']='0invalid'
                    if mode=='second_missing_functions':del document['functions']
                    if mode=='second_missing_types':del document['types']
                    if mode in ('second_unknown_schema','legacy_unknown_schema'):document['schema']='changed'
                    if mode=='second_null_schema':document['schema']=None
                    if mode in ('second_unhashable_schema','legacy_unhashable_schema'):document['schema']=[]
                    if mode in ('second_unhashable_mapping_schema','legacy_unhashable_mapping_schema'):document['schema']={}
                    return mode in ('false_then_true','legacy_unhashable_schema',
                                    'legacy_unhashable_mapping_schema','legacy_unknown_schema')
            try:
                if native:self.native.initialize(owner,document,legacy=Flag())
                else:owner._reference_initialize(document,legacy=Flag())
                error=None
            except BaseException as exc:
                error=(type(exc).__name__,getattr(exc,'code',None),str(exc))
            return state(owner),events,error
        with self.selected_types():
            for mode in modes:
                with self.subTest(mode=mode):self.assertEqual(run(mode,True),run(mode,False))

    def test_private_bounds_canaries_and_nonzero_unowned_workspace(self):
        frames=[]
        for fill in (0,165,255):
            context=AdmissionContext(object.__new__(composite._Elaborator),scalar_edges())
            output=ctypes.create_string_buffer(OUTPUT_BYTES+32)
            workspace=ctypes.create_string_buffer(WORKSPACE_BYTES+32)
            ctypes.memmove(output,context.output,64)
            ctypes.memset(workspace,fill,WORKSPACE_BYTES)
            struct.pack_into('<Q',workspace,8192,0)
            ctypes.memset(ctypes.addressof(output)+OUTPUT_BYTES,0xa7,32)
            ctypes.memset(ctypes.addressof(workspace)+WORKSPACE_BYTES,0xb9,32)
            source=ctypes.create_string_buffer(context.wire)
            for oc,wc in ((OUTPUT_BYTES-1,WORKSPACE_BYTES),(OUTPUT_BYTES,WORKSPACE_BYTES-1)):
                self.assertEqual(self.native._entry(source,len(context.wire),output,oc,workspace,wc),0xfffffff1)
            extent=self.native._entry(source,len(context.wire),output,OUTPUT_BYTES,workspace,WORKSPACE_BYTES)
            self.assertTrue(80<=extent<=OUTPUT_BYTES);frames.append(ctypes.string_at(output,extent))
            self.assertEqual(ctypes.string_at(source,len(context.wire)),context.wire)
            self.assertEqual(ctypes.string_at(ctypes.addressof(output)+OUTPUT_BYTES,32),b'\xa7'*32)
            self.assertEqual(ctypes.string_at(ctypes.addressof(workspace)+WORKSPACE_BYTES,32),b'\xb9'*32)
        self.assertEqual(frames,[frames[0]]*3)

    def test_type_callback_failure_does_not_assign_later_owner_fields(self):
        owner=object.__new__(composite._Elaborator)
        with patch.object(native_types,'selected_composite_types',side_effect=HIAProgramRejected('injected type refusal','E_HIA_TYPE')):
            error=outcome(lambda:self.native.initialize(owner,scalar_edges()))
        self.assertEqual(error,('E_HIA_TYPE','E_HIA_TYPE: injected type refusal'))
        self.assertEqual(set(vars(owner)),{'document','serial','value_slots','nominal_operations'})
        self.assertEqual((owner.serial,owner.value_slots),(0,0))
        with patch.dict(os.environ,{native_types.SELECTOR:''}),patch.object(composite._Types,'__init__',
                side_effect=AssertionError('host type fallback')):
            with self.assertRaisesRegex(HIAProgramRejected,'requires the selected native type owner'):
                self.native.initialize(object.__new__(composite._Elaborator),scalar_edges())

    def test_unreserved_wide_return_signatures_keep_original_slot_accounting(self):
        declarations=[fixtures.record('Small',[('field_'+str(i),'u32') for i in range(64)]),
                      fixtures.record('Wide',[('chunk_'+str(i),'Small') for i in range(8)])]
        doc=fixtures.module(declarations,f('wide',[],['Wide']*65,[],[b('entry',[],[],ret())]))
        owner,error,_=self.compare(doc)
        self.assertIsNone(error);self.assertEqual(owner.value_slots,0)
        self.assertEqual(sum(len(t.flat) for t in owner.signatures['wide'][1]),33280)
        self.assertEqual(owner.serial,0)

    def test_full_function_inventory_and_duplicate_after_bound_prefix(self):
        empty=f('f0',[],[],[],[b('entry',[],[],ret())])
        doc=fixtures.module([],*(dict(deepcopy(empty),name='f'+str(i)) for i in range(1024)))
        owner,error,_=self.compare(doc);self.assertIsNone(error);self.assertEqual(len(owner.functions),1024)
        doc['functions'].append(deepcopy(empty))
        owner,error,_=self.compare(doc);self.assertEqual(error[0],'E_HIA_FORMAT')
        self.assertFalse(hasattr(owner,'functions'))

    def test_vm_native_all_continuations_match_exact_frames_and_retained_state(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine,_Owner,_View
        checked=assemble_program(SOURCE.read_bytes());workspace=_Owner(-3,bytearray(WORKSPACE_BYTES))
        doc=scalar_edges();doc['schema']='hepta.hia.composite.v4'
        context=AdmissionContext(object.__new__(composite._Elaborator),doc)
        actions=[]
        with self.selected_types():
            while True:
                wire=context.wire;source=_Owner(-1,bytearray(wire))
                output=_Owner(-2,bytearray(ctypes.string_at(context.output,OUTPUT_BYTES)))
                machine=_Machine(checked,20_000_000,128<<20,None,256)
                extent=machine.invoke(checked.as_dict()['functions'][0],
                    [_View(source,False),_View(output,True),_View(workspace,True)])[0]
                result=self.native.step(context)
                self.assertEqual(ctypes.string_at(context.output,extent),bytes(output.data[:extent]))
                self.assertEqual(ctypes.string_at(context.workspace,WORKSPACE_BYTES),bytes(workspace.data))
                self.assertEqual(bytes(source.data),wire);actions.append(result.request)
                if not result.request:break
                context.invoke(result)
        self.assertEqual(actions,[9,10,11,1,12,2,3,4,5,6,7,0])

    def test_replayed_ack_wrong_source_descriptor_and_closed_session_refused(self):
        for offset in (8,16,24,32,40,48,56):
            context=AdmissionContext(object.__new__(composite._Elaborator),scalar_edges())
            result=self.native.step(context)
            with self.selected_types():context.invoke(result)
            struct.pack_into('<Q',context.output,offset,99)
            with self.subTest(offset=offset),self.assertRaises(HIAProgramRejected):self.native.step(context)
        context=AdmissionContext(object.__new__(composite._Elaborator),scalar_edges())
        with self.selected_types():
            while True:
                result=self.native.step(context)
                if not result.request:break
                context.invoke(result)
        with self.assertRaises(HIAProgramRejected):self.native.step(context)

    def test_original_suites_with_host_constructor_types_and_parameter_policy_disabled(self):
        loader=unittest.TestLoader();suite=loader.loadTestsFromNames(('tests.test_hia_program_composite',
            'tests.test_hia_partial_record','tests.test_hia_composite_returned_loans.CompositeReturnedLoans'))
        log=io.StringIO()
        with self.selected(),patch.object(composite._Elaborator,'_reference_initialize',side_effect=AssertionError('host declaration')), \
                patch.object(composite._Types,'__init__',side_effect=AssertionError('host types')), \
                patch.object(composite._Elaborator,'_reference_parameters',side_effect=AssertionError('host parameters')), \
                patch.object(composite._Elaborator,'loan_origins',side_effect=AssertionError('host origins')), \
                patch.object(composite._Elaborator,'_reference_check_task',side_effect=AssertionError('host task policy')):
            result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
        self.assertEqual(loader.errors,[])
        self.assertTrue(result.wasSuccessful(),log.getvalue())
        self.assertEqual((result.testsRun,len(result.skipped),len(result.expectedFailures),
                          len(result.unexpectedSuccesses)),(75,0,0,0),log.getvalue())


    def test_installed_wheel_without_authoring_or_host_admission(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES, ENTRY_BUILD_FILES
        self.assertIn('examples/hia_bootstrap/nominal_admission.hepta', NATIVE_SOURCE_FILES)
        source = self.folder / 'wheel-source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        names = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES + ENTRY_BUILD_FILES
        for name in (*names, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            destination = source / name; destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        wheels, installed = self.folder / 'wheels', self.folder / 'installed'
        built = subprocess.run([sys.executable, '-B', '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
            '--wheel-dir', str(wheels), str(source)], cwd=source, capture_output=True, timeout=120,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        wheel, = wheels.glob('*.whl')
        copied = subprocess.run([sys.executable, '-B', '-m', 'pip', 'install', '--no-deps', '--no-index',
            '--target', str(installed), str(wheel)], cwd=self.folder, capture_output=True, timeout=120,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertEqual(copied.returncode, 0, copied.stdout + copied.stderr)
        child = '''import sys,importlib.abc
sys.path.insert(0,sys.argv[1])
class NoTools(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed admission imported authoring tools')
sys.meta_path.insert(0,NoTools())
from pathlib import Path
from hepta import hia_program_composite as composite
from hepta.hia_program import verify_core,HIAProgramRejected
from hepta.hia_nominal_admission_native import SOURCE
assert Path(sys.argv[1]) in SOURCE.parents
def absent(*args,**kwargs):raise AssertionError('host admission called')
composite._Elaborator._reference_initialize=absent
try: result=verify_core(Path(sys.argv[2]).read_bytes())
except HIAProgramRejected:
    if sys.argv[3]=='refuse':print('REFUSED')
    else:raise
else:
    assert sys.argv[3]=='accept','invalid installed custody accepted'
    sys.stdout.buffer.write(result.canonical_bytes)
'''
        data = self.folder / 'installed-input.json'
        def run(mode, manifest=self.manifest):
            return subprocess.run([sys.executable, '-I', '-S', '-B', '-c', child,
                str(installed), str(data), mode], cwd=self.folder, capture_output=True, timeout=30,
                env={'PATH': '', 'LANG': 'C', 'LC_ALL': 'C', SELECTOR: str(manifest), native_types.SELECTOR: str(self.types_manifest)})
        for maker in (scalar_edges, fixtures.stored_loan_program, partials.roundtrip_program, loans.pair_program):
            document = maker(); data.write_text(json.dumps(document))
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = verify_core(document).canonical_bytes
            result = run('accept')
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b''))
        resource = installed / 'hepta/_data/examples/hia_bootstrap/nominal_admission.hepta'
        original = resource.read_bytes()
        for missing in (False, True):
            try:
                resource.unlink() if missing else resource.write_bytes(original + b'\n')
                result = run('refuse')
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'REFUSED\n', b''))
            finally:
                resource.write_bytes(original)
        bad = self.folder / 'bad-installed-manifest.json'; bad.write_bytes(b'{}')
        result = run('refuse', bad)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'REFUSED\n', b''))

    def test_real_machine_control_flow_allocator_refusal_and_owned_cleanup(self):
        from tests.test_hia_record_operations_native import resource_program
        from hepta.hia_program_native import emit_program_machine, compile_program_machine
        cc = shutil.which('cc'); self.assertIsNotNone(cc)
        driver = r'''
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
void *__real_calloc(size_t,size_t); void __real_free(void *);
static void *live; static size_t allocations, frees, refusals; static bool refuse;
void *__wrap_calloc(size_t n,size_t w){
  if(refuse){refuse=false;refusals++;return NULL;}
  void *p=__real_calloc(n,w);if(p){if(live)exit(80);live=p;allocations++;}return p;
}
void __wrap_free(void *p){if(p){if(live!=p)exit(81);live=NULL;frees++;}__real_free(p);}
size_t record_case(size_t);
int main(void){
  if(record_case(7)!=24 || record_case(0)!=17)return 82;
  refuse=true;if(record_case(7)!=17 || refuse || live)return 83;
  printf("%zu %zu %zu\n",allocations,frees,refusals);
  return allocations!=1 || frees!=1 || refusals!=1;
}
'''
        with self.selected(), patch.object(composite._Elaborator, '_reference_initialize',
                side_effect=AssertionError('host admission called')):
            checked = verify_core(resource_program())
        obj = self.folder / 'admission-effects.o'
        compile_program_machine(emit_program_machine(checked), program=checked, output=obj, kind='object', linker=cc)
        source, executable = self.folder / 'admission-effects.c', self.folder / 'admission-effects'
        source.write_text(driver)
        built = subprocess.run([cc, '-std=c11', '-O2', str(source), str(obj),
            '-Wl,--wrap=calloc', '-Wl,--wrap=free', '-o', str(executable)], capture_output=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        ran = subprocess.run([str(executable)], capture_output=True, timeout=30)
        self.assertEqual((ran.returncode, ran.stdout, ran.stderr), (0, b'1 1 1\n', b''))

    def test_initialize_releases_real_arenas_on_success_and_original_refusals(self):
        class Legacy:
            def __init__(self, fail, error):
                self.calls, self.fail, self.error = 0, fail, error
            def __bool__(self):
                self.calls += 1
                if self.calls == self.fail:
                    raise self.error
                return False
        for mode in ('success', 'schema', 'first-truth', 'second-truth', 'inventory', 'effects'):
            with self.subTest(mode=mode):
                document, owner = scalar_edges(), object.__new__(composite._Elaborator)
                interruption = KeyboardInterrupt(mode)
                legacy = Legacy(1 if mode == 'first-truth' else 2, interruption) if 'truth' in mode else False
                if mode == 'schema': document['schema'] = 'unknown'
                if mode == 'inventory': document['functions'] = []
                if mode == 'effects': document['functions'][0]['effects'] = ['unknown']
                entered, original_entry = [], self.native._entry
                def measured(*args):
                    entered.append(True)
                    return original_entry(*args)
                try:
                    with self.selected_types(), observed_contexts() as (contexts, buffers), \
                            patch.object(self.native, '_entry', new=measured):
                        held = None
                        try:
                            self.native.initialize(owner, document, legacy=legacy)
                        except BaseException as error:
                            held = error
                        if mode == 'success':
                            self.assertIsNone(held)
                        elif 'truth' in mode:
                            self.assertIs(held, interruption)
                            self.assertEqual(legacy.calls, 1 if mode == 'first-truth' else 2)
                            self.assertEqual(set(vars(owner)), set() if mode == 'first-truth' else
                                             {'document', 'serial', 'value_slots'})
                        else:
                            self.assertIsInstance(held, HIAProgramRejected)
                        if held is not None:
                            self.assertIsNotNone(held.__traceback__)
                        self.assertTrue(entered)
                        self.assertEqual(len(contexts), 1)
                        self.assertTrue(contexts[0].closed)
                        self.assertIsNone(contexts[0]._created_types)
                        self.assertTrue(all(reference() is None for reference in buffers))
                        if getattr(owner, 'native_types', None) is not None:
                            self.assertFalse(owner.native_types._closed)
                            self.assertIs(owner.types, owner.native_types)
                finally:
                    if getattr(owner, 'native_types', None) is not None:
                        owner.native_types.close()

    def test_unpublished_and_transferred_type_sessions_follow_exact_identity(self):
        original_factory = native_types.selected_composite_types
        original_ack = AdmissionContext.acknowledge
        for mode in ('unpublished', 'unrelated', 'half-published', 'before-ack'):
            with self.subTest(mode=mode):
                error, created, unrelated_closed = KeyboardInterrupt(mode), [], []
                stop = 'native_types' if mode in ('unpublished', 'unrelated') else 'types'
                if mode == 'before-ack': stop = None
                class Owner(composite._Elaborator):
                    def __setattr__(self, name, value):
                        if name == stop:
                            raise error
                        object.__setattr__(self, name, value)
                class Unrelated:
                    def close(self): unrelated_closed.append(True)
                owner = object.__new__(Owner)
                unrelated = Unrelated()
                if mode == 'unrelated': object.__setattr__(owner, 'native_types', unrelated)
                def selected(*args, **kwargs):
                    value = original_factory(*args, **kwargs)
                    created.append(value)
                    return value
                def acknowledge(context, sequence, action, index=0, item=0):
                    if mode == 'before-ack' and action == 12:
                        raise error
                    return original_ack(context, sequence, action, index, item)
                try:
                    with self.selected_types(), observed_contexts() as (contexts, buffers), \
                            patch.object(native_types, 'selected_composite_types', new=selected), \
                            patch.object(AdmissionContext, 'acknowledge', new=acknowledge):
                        try:
                            self.native.initialize(owner, scalar_edges())
                        except BaseException as held:
                            self.assertIs(held, error)
                            self.assertIsNotNone(held.__traceback__)
                            self.assertEqual(len(created), 1)
                            self.assertTrue(all(reference() is None for reference in buffers))
                            self.assertIsNone(contexts[0]._created_types)
                            transferred = mode in ('half-published', 'before-ack')
                            self.assertEqual(created[0]._closed, not transferred)
                            if transferred:
                                self.assertIs(owner.native_types, created[0])
                                self.assertIsNotNone(created[0]._state)
                            else:
                                self.assertIsNone(created[0]._state)
                            if mode == 'unrelated': self.assertIs(owner.native_types, unrelated)
                            self.assertEqual('types' in vars(owner), mode == 'before-ack')
                            self.assertEqual(unrelated_closed, [])
                            contexts[0].close()
                            self.assertEqual(unrelated_closed, [])
                        else:
                            self.fail('type handoff interruption was not injected')
                finally:
                    for value in created: value.close()

    def test_actual_type_return_store_opcodes_keep_custody_and_partial_prefix(self):
        original_factory = native_types.selected_composite_types
        for attribute in ('_created_types', 'native_types', 'types'):
            with self.subTest(attribute=attribute):
                owner, sessions, type_buffers = object.__new__(composite._Elaborator), [], []
                error = KeyboardInterrupt('type handoff ' + attribute)
                def selected(*args, **kwargs):
                    value = original_factory(*args, **kwargs)
                    sessions.append(weakref.ref(value))
                    type_buffers.extend((weakref.ref(value._state), weakref.ref(value._output)))
                    return value
                try:
                    with self.selected_types(), observed_contexts() as (contexts, buffers), \
                            patch.object(native_types, 'selected_composite_types', new=selected):
                        try:
                            with interrupt_store(AdmissionContext._invoke.__code__, attribute, error) as injections:
                                self.native.initialize(owner, scalar_edges())
                        except BaseException as held:
                            self.assertIs(held, error)
                            self.assertIsNotNone(held.__traceback__)
                            self.assertEqual(len(injections), 1)
                            self.assertEqual(len(sessions), 1)
                            self.assertTrue(all(reference() is None for reference in buffers))
                            self.assertTrue(contexts[0].closed)
                            self.assertIsNone(contexts[0]._created_types)
                            fields = {'document', 'serial', 'value_slots', 'nominal_operations'}
                            if attribute == 'types':
                                fields.add('native_types')
                                self.assertIs(owner.native_types, sessions[0]())
                                self.assertFalse(owner.native_types._closed)
                                self.assertTrue(all(reference() is not None for reference in type_buffers))
                            else:
                                self.assertIsNone(sessions[0]())
                                self.assertTrue(all(reference() is None for reference in type_buffers))
                            self.assertEqual(set(vars(owner)), fields)
                        else:
                            self.fail('actual STORE_ATTR was not interrupted')
                finally:
                    if getattr(owner, 'native_types', None) is not None:
                        owner.native_types.close()

    def test_only_the_exact_issued_native_result_can_request_a_callback(self):
        calls = []
        class Legacy:
            def __bool__(self): calls.append(True); return False
        context = AdmissionContext(object.__new__(composite._Elaborator), scalar_edges(), Legacy())
        other = AdmissionContext(object.__new__(composite._Elaborator), scalar_edges())
        entered, original_entry = [], self.native._entry
        def measured(*args):
            entered.append(True)
            return original_entry(*args)
        try:
            with patch.object(self.native, '_entry', new=measured):
                result, crossed = self.native.step(context), self.native.step(other)
                self.assertEqual((result.request, result.sequence), (9, 1))
                forged = replace(result, request=12,
                    value={'recursive_chain': False, 'partial_records': False})
                with patch.object(native_types, 'selected_composite_types',
                                  side_effect=AssertionError('unissued type effect')) as types:
                    for candidate in (forged, replace(result), crossed):
                        with self.assertRaisesRegex(HIAProgramRejected, 'current unexecuted'):
                            context.invoke(candidate)
                    with self.assertRaisesRegex(HIAProgramRejected, 'has not completed'):
                        self.native.step(context)
                    types.assert_not_called()
                self.assertEqual(len(entered), 2)
                self.assertEqual(calls, [])
                self.assertEqual(vars(context.owner), {})
                self.assertEqual(context.executed, 0)
                context.invoke(result)
                self.assertEqual(calls, [True])
                with self.assertRaises(HIAProgramRejected): context.invoke(result)
                counters = self.native.step(context)
                self.assertEqual(counters.request, 10)
                counters.value['serial'] = True
                with self.assertRaisesRegex(HIAProgramRejected, 'representation changed'):
                    context.invoke(counters)
                self.assertEqual(vars(context.owner), {})
                counters.value['serial'] = 0
                context.invoke(counters)
                self.assertEqual(calls, [True])
                second_truth = self.native.step(context)
                self.assertEqual(second_truth.request, 11)
                context.invoke(second_truth)
                operations = self.native.step(context)
                self.assertEqual(operations.request, 1)
                original_operations = list(operations.value)
                operations.value[:] = ['not_an_hia_operation']
                with self.assertRaisesRegex(HIAProgramRejected, 'representation changed'):
                    context.invoke(operations)
                self.assertNotIn('nominal_operations', vars(context.owner))
                operations.value[:] = original_operations
                context.invoke(operations)
                self.assertEqual(context.owner.nominal_operations, frozenset(original_operations))
                self.assertEqual(calls, [True, True])
        finally:
            context.close(); other.close()

    def test_callback_result_and_ack_interruptions_fence_without_reexecution(self):
        original_ack = AdmissionContext.acknowledge
        modes = ('callback', 'before-ack', 'after-ack', 'completed-store', 'pending-store', 'result-store')
        for mode in modes:
            with self.subTest(mode=mode):
                error, effects, entered = KeyboardInterrupt(mode), [], []
                class Legacy:
                    def __bool__(self):
                        effects.append(True)
                        if mode == 'callback': raise error
                        return False
                context = AdmissionContext(object.__new__(composite._Elaborator), scalar_edges(), Legacy())
                buffers = [weakref.ref(context.output), weakref.ref(context.workspace)]
                original_entry = self.native._entry
                def measured(*args): entered.append(True); return original_entry(*args)
                def acknowledge(*args, **kwargs):
                    if mode == 'before-ack': raise error
                    result = original_ack(*args, **kwargs)
                    if mode == 'after-ack': raise error
                    return result
                try:
                    with patch.object(self.native, '_entry', new=measured):
                        held, injections, result = None, None, None
                        try:
                            if mode == 'result-store':
                                with interrupt_store(NativeNominalAdmission._step.__code__, '_pending', error) as injections:
                                    self.native.step(context)
                            else:
                                result = self.native.step(context)
                                with patch.object(AdmissionContext, 'acknowledge', new=acknowledge):
                                    if mode in ('completed-store', 'pending-store'):
                                        attribute = 'completed' if mode == 'completed-store' else '_pending'
                                        with interrupt_store(AdmissionContext.invoke.__code__, attribute, error) as injections:
                                            context.invoke(result)
                                    else:
                                        context.invoke(result)
                        except BaseException as caught:
                            held = caught
                        self.assertIs(held, error)
                        self.assertIsNotNone(held.__traceback__)
                        if injections is not None: self.assertEqual(len(injections), 1)
                        self.assertTrue(context.closed)
                        self.assertEqual(effects, [] if mode == 'result-store' else [True])
                        before = list(effects)
                        with self.assertRaises(HIAProgramRejected): self.native.step(context)
                        candidate = result or AdmissionResult(0, 9, 0, 0, context.sequence, None)
                        with self.assertRaises(HIAProgramRejected): context.invoke(candidate)
                        self.assertEqual(effects, before)
                        self.assertEqual(len(entered), 1)
                        context.close()
                        self.assertTrue(all(reference() is None for reference in buffers))
                finally:
                    context.close()

    def test_public_facade_releases_actual_transferred_types_with_error_held(self):
        original_factory = native_types.selected_composite_types
        for refuse in (False, True):
            with self.subTest(constructor_refusal=refuse):
                document, created, type_buffers = scalar_edges(), [], []
                if refuse: document['functions'] = []
                def selected(*args, **kwargs):
                    value = original_factory(*args, **kwargs)
                    created.append(value)
                    type_buffers.extend((weakref.ref(value._state), weakref.ref(value._output)))
                    return value
                with self.selected(), observed_contexts() as (contexts, buffers), \
                        patch.object(native_types, 'selected_composite_types', new=selected):
                    held = None
                    try:
                        result = composite.elaborate_program(document)
                    except HIAProgramRejected as error:
                        held = error
                    if refuse:
                        self.assertIsNotNone(held)
                        self.assertIsNotNone(held.__traceback__)
                        self.assertEqual(held.code, 'E_HIA_FORMAT')
                    else:
                        self.assertIsNone(held)
                        self.assertEqual(result['module'], document['module'])
                    self.assertEqual(len(created), 1)
                    self.assertTrue(created[0]._closed)
                    self.assertTrue(all(reference() is None for reference in (*buffers, *type_buffers)))
                    self.assertIs(contexts[0].owner.native_types, created[0])

    def test_selected_manifest_image_and_source_hash_fail_closed(self):
        loaded = installed_nominal_admission(str(self.manifest))
        self.assertIsNotNone(loaded)
        original = self.manifest.read_bytes()
        for field in ('source_sha256', 'image_sha256'):
            value = json.loads(original); value[field] = '0' * 64
            target = self.folder / ('bad-' + field + '.json'); target.write_text(json.dumps(value))
            with self.subTest(field=field), self.assertRaises((ValueError, OSError)):
                installed_nominal_admission(str(target))
        value = json.loads(original); value['compiler_sha256'] = 'invalid'
        target = self.folder / 'bad-compiler-syntax.json'; target.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            installed_nominal_admission(str(target))


if __name__=='__main__':unittest.main()
