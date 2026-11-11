"""Actual structural owner, complete reports and independent-reference controls.

Retained-compiler runs are explicit development only. Original public bodies
remain independent oracles. Existing heap analyses and final JSON/hash are
foreign continuations, not silently claimed as owned by this component.
"""
from __future__ import annotations
import ast
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import ctypes
import dis
import inspect
from hashlib import sha256
import json
import mmap
import os
from pathlib import Path
import random
import struct
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta import hia_static_budget as budget
from hepta import hia_static_budget_native as adapter
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import verify_core
from tools.generate_hia_static_budget import document

ROOT = Path(__file__).resolve().parents[1]
BASE_SMALL = adapter.BASE + 1024
COLD_REPORT = 'HEPTA_HIA_STATIC_BUDGET_COLD_REPORT'
DEVELOPMENT_COMPILER = 'HEPTA_HIA_STATIC_BUDGET_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_STATIC_BUDGET_EVIDENCE'
OWNED = ('hepta/hia_static_budget.py', 'hepta/hia_static_budget_native.py',
         'examples/hia_bootstrap/static_budget.hiaasm', 'tools/generate_hia_static_budget.py',
         'tools/hia_native_bigints.py', 'tools/hia_heap_bound_graphs.py',
         'hepta/hia_native_value_graph.py', 'tests/test_hia_static_budget_native.py',
         'docs/HIA_STATIC_BUDGET_NATIVE.md')
REFERENCE_HASHES = {
    '_audit_resource_profile':'a05c674932f880d7066b635204f5b4fab76c5d6aa73daa127d8d1a909ac520e4',
    'qualify_vm_call_depth':'64eb541acb00cbdb630a39000b7eee17d122302a34eb3a25bc9f0d0a0bbd07a2',
    'analyze_static_budget':'e7ffd002708107d21c2d6b7ae5285a864c7d46cb2afdb7940362de16f1f98007',
    'qualify_bounded_resources':'9a36303ab28cd91df6bcd454360ac02a7416014c6e7be55540011746ade146bd',
}


@contextmanager
def selected(manifest):
    values = dict(os.environ)
    if manifest is None:
        values.pop(adapter.SELECTOR, None)
    else:
        values[adapter.SELECTOR] = str(manifest)
    with patch.dict(os.environ, values, clear=True):
        yield


def observation(action):
    try:
        return {'returned': action()}
    except Exception as exc:
        return {'type': type(exc).__name__, 'message': str(exc), 'code': getattr(exc, 'code', None)}


def constant(version=1):
    from tests.test_hia_program import m, f, b, c, ret
    value = m(f('main', [], ['u32'], [], [b('entry', [], [c('answer','u32',37)], ret('answer'))]))
    value['schema'] = 'hepta.hia.program.v' + str(version)
    value['exports'] = ['main']
    return value


def repeated_calls(depth, branches):
    from tests.test_hia_program import m, f, b, c, i, ret
    functions=[f('f0000',[],[],['alloc','trap'],[b('entry',[],[
        c('size','usize',1),i('buffer.new',['size'],[('owner','buffer')]),i('owner.drop',['owner'])],ret())])]
    for index in range(1, depth+1):
        functions.append(f('f'+str(index).zfill(4),[],[],['alloc','trap'],[b('entry',[],[
            i('call',function='f'+str(index-1).zfill(4)) for _ in range(branches)],ret())]))
    return m(*functions)


def policy(**changes):
    return {'max_allocator_interactions':100, 'max_vm_ticks':10000,
            'max_call_depth':256, 'max_live_heap_bytes':1000, **changes}


class StaticBudgetSourceTests(unittest.TestCase):
    def test_checked_hia_is_the_complete_generator_output_with_original_limits(self):
        value = document()
        self.assertEqual(adapter.SOURCE.read_text(), render_assembly(value))
        verify_core(value)
        self.assertLessEqual(len(value['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in value['functions']), 1536)
        self.assertLessEqual(sum(len(block['ops']) for fn in value['functions'] for block in fn['blocks']), 8192)
        self.assertLessEqual(max(len(block['params']) for fn in value['functions'] for block in fn['blocks']), 16)

    def test_original_policy_bodies_are_preserved_as_exact_source(self):
        source = (ROOT/'hepta/hia_static_budget.py').read_text()
        nodes = {node.name:node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)}
        for name, expected in REFERENCE_HASHES.items():
            retained = '_reference_' + name.lstrip('_')
            text = ast.get_source_segment(source, nodes[retained]).replace('def '+retained+'(', 'def '+name+'(', 1)
            self.assertEqual(sha256(text.encode()).hexdigest(), expected)

    def test_bridge_has_only_explicit_foreign_operations_and_no_authoring_import(self):
        source = (ROOT/'hepta/hia_static_budget_native.py').read_text()
        for forbidden in ('from tools', 'import tools', '_bound_function(', '_topological(',
                          '_reference_', '_audit_resource_profile(', '_V8_BYTE_OPS', '_ALLOCATOR_OPS'):
            self.assertNotIn(forbidden, source)
        self.assertIn('extent_bounds=True', source)
        self.assertIn('binary_integers=True', source)

    def test_selector_failure_never_uses_a_retained_policy(self):
        with selected('/definitely/missing/static-budget-manifest.json'):
            with patch.object(budget, '_reference_analyze_static_budget', side_effect=AssertionError('fallback')):
                with self.assertRaisesRegex(budget.HIAStaticBudgetRejected, 'E_HIA_BUDGET_NATIVE'):
                    budget.analyze_static_budget(constant())


class StaticBudgetAdapterTests(unittest.TestCase):
    def test_policy_and_huge_integer_remain_opaque_before_native_decision(self):
        class Key:
            def __hash__(self): raise AssertionError('early hash')
            def __eq__(self, other): raise AssertionError('early equality')
        key = Key()
        saved = sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(640)
            context = adapter.BudgetContext(2, key, (1 << 20000, None, None, None))
            self.assertIs(context.pool.get(1), key)
            self.assertLess(len(context.input), 512)
            context.close()
        finally:
            sys.set_int_max_str_digits(saved)

    def test_exact_private_word_kinds_cannot_invoke_metaclass_equality(self):
        calls=[]
        class Meta(type):
            def __eq__(cls, other): calls.append(other); return True
        class Forged(metaclass=Meta):
            def __eq__(self, other): return True
        frame=adapter.BudgetFrame(1,1,(0,0,0,0),0,None)
        object.__setattr__(frame,'sequence',Forged())
        with self.assertRaisesRegex(budget.HIAStaticBudgetRejected, 'exact representation'):
            adapter.BudgetContext._fields(frame)
        self.assertEqual(calls,[])

    def test_second_real_arena_failure_releases_first_with_original_traceback(self):
        created=[]; original=mmap.mmap; error=MemoryError('second actual arena')
        def allocate(*args,**kwargs):
            if created: raise error
            result=original(*args,**kwargs);created.append(result);return result
        caught=None
        with patch.object(adapter.mmap,'mmap',allocate):
            try: adapter.BudgetContext(2,constant())
            except MemoryError as exc:caught=exc
        self.assertIs(caught,error)
        self.assertIsNotNone(caught.__traceback__)
        self.assertTrue(created[0].closed)

    def test_cleanup_revokes_then_retries_an_actual_exported_buffer(self):
        context=adapter.BudgetContext(2,constant())
        held=context.workspace
        view=memoryview(held)
        try:
            with self.assertRaises(BufferError):context.close()
            self.assertTrue(context.closed)
            self.assertIs(context.workspace,held)
            self.assertIsNone(context.output)
            self.assertIsInstance(context.cleanup_error,BufferError)
        finally:view.release()
        context.close()
        self.assertTrue(held.closed)
        self.assertIsNone(context.workspace)

    def test_binary_integer_transport_uses_no_decimal_policy(self):
        from hepta.hia_native_value_graph import decode_native_graph
        saved=sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(640)
            for value in (0,-1,1<<20000,-(1<<20000)):
                self.assertEqual(decode_native_graph(adapter._binary_integer(value),adapter.EMPTY,
                                                    binary_integers=True),value)
        finally:sys.set_int_max_str_digits(saved)


class StaticBudgetNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold=os.environ.get(COLD_REPORT); development=os.environ.get(DEVELOPMENT_COMPILER)
        if cold and development:raise ValueError('cold and development structural inputs are mutually exclusive')
        if not cold and not development:raise unittest.SkipTest('explicit cold report or retained development compiler required')
        from tools.qualify_hia_selfhost import compile_stage
        names=set(OWNED)
        for folder in ('hepta','tools','tests'):
            names.update(p.relative_to(ROOT).as_posix() for p in (ROOT/folder).rglob('*.py'))
        cls.inputs={name:(ROOT/name).read_bytes() for name in sorted(names)}
        cls.cold_bytes=None
        if cold:
            from tools.build_hia_json_preflight import build,admit_cold_build
            cls.cold_bytes=Path(cold).read_bytes(); info=json.loads(cls.cold_bytes)
            nested=json.loads(Path(info['nested_report']).read_bytes())
            cls.compiler=Path(nested['generations'][-1]['produced_image'])
            cls.compiler_bytes=cls.compiler.read_bytes()
            cls.cold_sources=admit_cold_build(cls.compiler_bytes,cls.cold_bytes)
            cls.folder=Path(os.environ.get(EVIDENCE) or tempfile.mkdtemp(prefix='hia-static-cold-'))/'candidate'
            cls.manifest=build(cls.folder,cls.compiler,Path(cold),candidate='static-budget')
            cls.scope='CURRENT_SOURCE_COLD_BUILT_COMPONENT'
        else:
            cls.compiler=Path(development);cls.compiler_bytes=cls.compiler.read_bytes()
            cls.folder=Path(os.environ.get(EVIDENCE) or tempfile.mkdtemp(prefix='hia-static-development-'))/'candidate'
            cls.folder.mkdir(parents=True)
            image,receipt=compile_stage(cls.folder,'static-budget',cls.compiler,adapter.SOURCE.read_bytes())
            manifest={'schema':adapter.SCHEMA,'source_sha256':sha256(adapter.SOURCE.read_bytes()).hexdigest(),
                      'image_path':image.name,'image_sha256':sha256(image.read_bytes()).hexdigest(),
                      'compiler_sha256':sha256(cls.compiler_bytes).hexdigest()}
            cls.manifest=cls.folder/'manifest.json'
            cls.manifest.write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
            cls.scope='PREDECESSOR_COMPILER_DEVELOPMENT_COMPONENT'
        cls.manifest_bytes=cls.manifest.read_bytes()
        cls.image=cls.manifest.parent/json.loads(cls.manifest_bytes)['image_path']
        cls.image_bytes=cls.image.read_bytes()
        cls.native=adapter.installed_static_budget(str(cls.manifest))
        cls.entries=cls.differentials=cls.vm_entries=cls.original_tests=0
        entry=cls.native._entry
        def counted(*args):cls.entries+=1;return entry(*args)
        cls.native._entry=counted
        for name,data in cls.inputs.items():
            p=cls.folder/'frozen-inputs'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
        (cls.folder/'source-before.json').write_text(json.dumps({n:sha256(v).hexdigest() for n,v in cls.inputs.items()},indent=2,sort_keys=True)+'\n')

    @classmethod
    def tearDownClass(cls):
        unchanged=all((ROOT/name).read_bytes()==data for name,data in cls.inputs.items())
        held=(cls.compiler.read_bytes()==cls.compiler_bytes and cls.image.read_bytes()==cls.image_bytes
              and cls.manifest.read_bytes()==cls.manifest_bytes)
        if cls.cold_bytes is not None:
            from tools.build_hia_json_preflight import current_sources
            held=held and Path(os.environ[COLD_REPORT]).read_bytes()==cls.cold_bytes and current_sources()==cls.cold_sources
        (cls.folder/'observations.json').write_text(json.dumps({'scope':cls.scope,'source_unchanged':unchanged,
            'held_inputs_unchanged':held,'native_entries':cls.entries,'differentials':cls.differentials,
            'independent_vm_entries':cls.vm_entries,'retained_public_tests':cls.original_tests},indent=2,sort_keys=True)+'\n')
        if not unchanged or not held:raise AssertionError('structural-budget frozen inputs changed')

    def compare(self, name, source, **kwargs):
        with selected(None):expected=observation(lambda:getattr(budget,name)(source,**kwargs))
        with selected(self.manifest):actual=observation(lambda:getattr(budget,name)(source,**kwargs))
        type(self).differentials+=1
        self.assertEqual(actual,expected)
        return actual

    def test_all_schema_receipts_and_exact_policy_errors(self):
        for version in range(1,9):
            value=constant(version)
            for name,kwargs in [('analyze_static_budget',{}),('qualify_vm_call_depth',{'max_call_depth':1}),
                                ('qualify_bounded_resources',{'limits':policy()})]:
                with self.subTest(version=version,name=name):self.compare(name,value,**kwargs)
        for bad in (None,True,False,-1,0,257,1.0,'1',[],{}):
            self.compare('qualify_vm_call_depth',{},max_call_depth=bad)
        for key in ('max_allocator_interactions','max_vm_ticks','max_call_depth','max_live_heap_bytes'):
            for bad in (True,False,-1,1.0,'1',[],{}):self.compare('analyze_static_budget',{},**{key:bad})
        for bad in (None,{},[],{**policy(),'extra':0},policy(max_vm_ticks=0),policy(max_call_depth=257),
                    policy(max_live_heap_bytes=1<<30|1),policy(max_allocator_interactions=True)):
            self.compare('qualify_bounded_resources',{},limits=bad)

    def test_calls_cfg_and_all_definition_profile_order(self):
        from tests.test_hia_static_budget import acyclic_calls,acyclic_choice,cyclic_calls,cyclic_control_flow
        from tests.test_hia_vm_call_depth_only import chain_drop
        for source in (acyclic_calls(),acyclic_choice(),cyclic_calls(),cyclic_control_flow(),chain_drop()):
            self.compare('analyze_static_budget',source)
            self.compare('qualify_vm_call_depth',source,max_call_depth=2)
        source=cyclic_control_flow()
        source['functions'].append(deepcopy(source['functions'][0]))
        source['functions'][1]['name']='zzz'
        for index in (0,1):
            self.compare('analyze_static_budget',source)
            source['functions'].reverse()

    def test_random_acyclic_graphs_keep_duplicate_calls_and_input_row_order(self):
        from tests.test_hia_program import m,f,b,c,i,ret
        rng=random.Random(6381)
        for case in range(18):
            functions=[]
            for index in range(1+rng.randrange(24)):
                ops=[c('size','usize',rng.randrange(5)),i('buffer.try_new',['size'],[('owner','buffer'),('ok','bool')]),i('owner.drop',['owner'])]
                if index:
                    ops.extend(i('call',function='node'+str(rng.randrange(index))) for _ in range(rng.randrange(6)))
                functions.append(f('node'+str(index),[],[],['alloc'],[b('entry',[],ops,ret())]))
            rng.shuffle(functions)
            source=m(*functions)
            self.compare('analyze_static_budget',source)
            self.compare('qualify_vm_call_depth',source,max_call_depth=256)

    def test_private_audit_keeps_deferred_type_and_early_term_opcode_errors(self):
        from tests.test_hia_program import i
        sources=[]
        value=constant(8)
        for invalid in ('term','opcode','type','schema'):
            source=deepcopy(value)
            source['functions'][0]['returns']=['future_resource']
            if invalid=='term':source['functions'][0]['blocks'][0]['term']['op']='future_term'
            if invalid=='opcode':source['functions'][0]['blocks'][0]['ops'].append(i('future_callback'))
            if invalid=='schema':source['schema']='hepta.hia.program.v7'
            sources.append(source)
        for source in sources:
            expected=observation(lambda:budget._reference_audit_resource_profile(source,schema='hepta.hia.program.v8',allow_chain=False))
            actual=observation(lambda:self.native.audit_resource_profile(source,schema='hepta.hia.program.v8',allow_chain=False))
            self.assertEqual(actual,expected)
            type(self).differentials+=1

    def test_original_unknown_dependency_defense_remains_at_native_graph_boundary(self):
        from hepta import hia_program as core
        from tests.test_hia_program import i,jump
        for kind in ('call','edge'):
            source=constant()
            block=source['functions'][0]['blocks'][0]
            if kind=='call':block['ops'].append(i('call',function='absent'))
            else:block['term']=jump('absent')
            stub=SimpleNamespace(as_dict=lambda:source)
            with patch.object(core,'verify_program',return_value=stub):
                result=self.compare('analyze_static_budget',source)
            self.assertEqual(result['code'],'E_HIA_BUDGET_GRAPH')

    def test_actual_machine_result_requires_canonical_unused_and_flag_words(self):
        original=self.native._entry
        for changed_request,offset,word in ((1,48,1),(2,40,2)):
            context=adapter.BudgetContext(2,constant())
            changed=[]
            def damage(*args):
                returned=original(*args)
                if returned==changed_request:
                    ctypes.c_uint64.from_address(args[4]+offset).value=word
                    changed.append(returned)
                return returned
            self.native._entry=damage
            try:
                with self.assertRaisesRegex(budget.HIAStaticBudgetRejected,'not canonical'):
                    while True:
                        frame=self.native.step(context)
                        context.service(frame)
                self.assertEqual(changed,[changed_request])
                self.assertTrue(context.closed)
            finally:self.native._entry=original;context.close()

    def test_arbitrary_counts_equal_limits_and_binary_comparisons(self):
        source=repeated_calls(70,2)
        value=self.compare('analyze_static_budget',source)['returned']['functions'][-1]
        self.assertEqual(value['max_allocator_interactions'],1<<71)
        self.assertEqual(value['max_vm_ticks'],9*(1<<70)-4)
        self.assertEqual(value['max_call_depth'],71)
        for key in ('max_allocator_interactions','max_vm_ticks'):
            for difference in (-1,0,1):
                self.compare('analyze_static_budget',source,**{key:value[key]+difference})

    def test_late_json_digit_failure_stays_after_limits_and_verification(self):
        source=repeated_calls(720,8)
        saved=sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(640)
            result=self.compare('analyze_static_budget',source)
            self.assertEqual(result['type'],'ValueError')
            result=self.compare('analyze_static_budget',source,max_vm_ticks=0)
            self.assertEqual(result['code'],'E_HIA_BUDGET_EXCEEDED')
            self.compare('analyze_static_budget',constant(),max_allocator_interactions=1<<20000)
            self.compare('analyze_static_budget',{},max_allocator_interactions=1<<20000)
        finally:sys.set_int_max_str_digits(saved)

    def test_live_heap_continuation_inventory_and_first_exceeded_order(self):
        from tests.test_hia_heap_bound import local_buffers
        from hepta import hia_heap_bound as heap
        source=local_buffers()
        for maximum in (0,11,12,13,1<<100):
            self.compare('analyze_static_budget',source,max_live_heap_bytes=maximum)
        self.compare('analyze_static_budget',source,max_allocator_interactions=0,max_live_heap_bytes=0)
        for returned in ({},{'finite':True},{'finite':-1},{'finite':1,'extra':0},{'finite':1<<90}):
            with patch.object(heap,'analyze_constant_live_heap',return_value=returned):
                self.compare('analyze_static_budget',source,max_live_heap_bytes=(1<<90)-1)

    def test_complete_bounded_composition_and_counter_aliases(self):
        from tests.test_hia_bounded_profile import fallible_module,exported
        from tests.test_hia_heap_bound import local_buffers
        from tests.test_hia_returned_loan_budgets import temporary_loan_program
        for source in (exported(local_buffers()),fallible_module(),temporary_loan_program(nested=True)):
            self.compare('qualify_bounded_resources',source,limits=policy())
            self.compare('qualify_bounded_resources',source,limits=policy(max_live_heap_bytes=0))
        with selected(self.manifest):
            report=budget.qualify_bounded_resources(constant(8),limits=policy())
        first=report['static_events']['functions'][0]
        exported=report['exports'][0]
        for key in ('max_allocator_interactions','max_vm_ticks','max_call_depth'):
            self.assertIs(first[key],exported[key])

    def test_foreign_equal_policy_key_and_actual_callback_trace(self):
        from hepta import hia_program as core,hia_heap_bound as heap
        original_verify=core.verify_program;original_heap=heap.analyze_constant_live_heap
        def run(manifest):
            trace=[]
            class EqualKey:
                def __hash__(self):return hash('max_vm_ticks')
                def __eq__(self,other):trace.append('key:'+type(other).__name__);return other=='max_vm_ticks'
            limits={EqualKey():100,'max_allocator_interactions':0,'max_call_depth':1,'max_live_heap_bytes':0}
            def verify(value):trace.append('verify');return original_verify(value)
            def constant_heap(value):trace.append('heap');return original_heap(value)
            with selected(manifest),patch.object(core,'verify_program',verify),patch.object(heap,'analyze_constant_live_heap',constant_heap):
                result=observation(lambda:budget.qualify_bounded_resources(constant(),limits=limits))
            return result,trace
        expected=run(None);actual=run(self.manifest)
        self.assertEqual(actual,expected)
        self.assertEqual(actual[0]['type'],'TypeError')
        self.assertIn('heap',actual[1])
        type(self).differentials+=1

    def test_policy_literal_identity_and_temporary_set_refcounts_match_original(self):
        canonical=next(value for value in budget._reference_qualify_bounded_resources.__code__.co_consts
                       if type(value) is str and value=='max_vm_ticks')
        self.assertIs(adapter.POLICY_KEYS[1],canonical)
        for strategy in ('identity','refcounts'):
            def run(manifest):
                trace=[]
                class Key:
                    def __hash__(self):return hash(canonical)
                    def __eq__(self,other):
                        references=sys.getrefcount(self)
                        trace.append((other is canonical,references,sys.getrefcount(other)))
                        if strategy=='identity':return other is canonical
                        if len(trace)==1:return other==canonical
                        return other==canonical and references==trace[0][1]-1
                limits={Key():100,'max_allocator_interactions':0,'max_call_depth':1,'max_live_heap_bytes':0}
                with selected(manifest):
                    result=observation(lambda:budget.qualify_bounded_resources(constant(),limits=limits))
                return result,trace
            expected=run(None);actual=run(self.manifest)
            self.assertEqual(actual,expected)
            self.assertEqual(actual[0]['type'],'TypeError')
            type(self).differentials+=1

    def test_policy_refusal_keeps_live_foreign_objects_with_original_traceback(self):
        held=[]
        def run(manifest):
            trace=[]
            class Key:
                def __hash__(self):return hash('max_vm_ticks')
                def __eq__(self,other):
                    trace.append('equal_clear_original')
                    limits.clear()
                    return False
                def __del__(self):trace.append('key_deleted')
            limits={Key():100,'max_allocator_interactions':0,'max_call_depth':1,'max_live_heap_bytes':0}
            with selected(manifest):
                try:budget.qualify_bounded_resources(constant(),limits=limits)
                except budget.HIAStaticBudgetRejected as exc:
                    held.append(exc)
                    result=(type(exc).__name__,str(exc),exc.__traceback__ is not None)
                else:self.fail('policy must refuse')
            return result,list(trace),trace
        expected=run(None);actual=run(self.manifest)
        self.assertEqual(actual[:2],expected[:2])
        self.assertNotIn('key_deleted',actual[1])
        # The native context retained in the real exception owns no live mmap.
        frame=held[1].__traceback__
        contexts=[]
        while frame is not None:
            context=frame.tb_frame.f_locals.get('context')
            if type(context) is adapter.BudgetContext:contexts.append(context)
            frame=frame.tb_next
        self.assertTrue(contexts)
        for context in contexts:
            self.assertTrue(context.closed)
            self.assertIsNone(context.workspace)
            self.assertIsNone(context.output)
        type(self).differentials+=1

    def test_retained_policy_is_not_called_by_selected_owner(self):
        forbidden=['_reference_audit_resource_profile','_reference_analyze_static_budget',
                   '_reference_qualify_vm_call_depth','_reference_qualify_bounded_resources',
                   '_bound_function','_limit','_successors','_topological']
        with selected(self.manifest),ExitStack() as stack:
            for name in forbidden:stack.enter_context(patch.object(budget,name,side_effect=AssertionError(name)))
            self.assertEqual(budget.analyze_static_budget(constant(8))['functions'][0]['max_vm_ticks'],3)
            self.assertEqual(budget.qualify_vm_call_depth(constant(8),max_call_depth=1)['functions'][0]['max_call_depth'],1)
            budget._audit_resource_profile(constant(8),schema='hepta.hia.program.v8',allow_chain=False)
        # Bounded composition still invokes the separately owned heap API;
        # its current reference implementation uses _topological internally.
        with selected(self.manifest),ExitStack() as stack:
            for name in forbidden[:-1]:stack.enter_context(patch.object(budget,name,side_effect=AssertionError(name)))
            self.assertEqual(budget.qualify_bounded_resources(constant(),limits=policy())['exports'][0]['max_vm_ticks'],3)

    def test_actual_issued_graph_mutation_and_same_sequence_forgery_refuse(self):
        context=adapter.BudgetContext(2,constant())
        try:
            while True:
                frame=self.native.step(context)
                if frame.request==12:break
                context.service(frame)
            frame.value['functions'][0]['max_vm_ticks']=99
            with self.assertRaisesRegex(budget.HIAStaticBudgetRejected,'issued graph changed'):
                context.service(frame)
            self.assertTrue(context.closed)
            self.assertIsNone(context.workspace)
            self.assertIsNone(context.output)
        finally:context.close()
        context=adapter.BudgetContext(2,constant())
        frame=self.native.step(context)
        forged=adapter.BudgetFrame(frame.sequence,2,frame.words,0,None)
        with self.assertRaisesRegex(budget.HIAStaticBudgetRejected,'current exact issued'):
            context.service(forged)
        self.assertTrue(context.closed)

    def test_actual_callback_return_interruption_cannot_be_replayed(self):
        context=adapter.BudgetContext(2,constant())
        while True:
            frame=self.native.step(context)
            if frame.request==2:break
            context.service(frame)
        from hepta import hia_program as core
        original=core.verify_program;calls=[];error=KeyboardInterrupt('lost completed foreign reply')
        def verify(value):calls.append(value);return original(value)
        offsets={ins.offset for ins in dis.get_instructions(adapter.BudgetContext.service)
                 if ins.opname=='STORE_FAST' and ins.argval=='raw'}
        hits=[]
        def trace(frame,event,arg):
            if frame.f_code is adapter.BudgetContext.service.__code__:
                frame.f_trace_opcodes=True
                if event=='opcode' and frame.f_lasti in offsets:
                    hits.append(frame.f_lasti)
                    raise error
            return trace
        outer=sys._getframe(); previous_flag=outer.f_trace_opcodes
        try:
            outer.f_trace_opcodes=True
            with patch.object(core,'verify_program',verify):
                sys.settrace(trace)
                try:context.service(frame)
                except KeyboardInterrupt as exc:self.assertIs(exc,error)
                finally:sys.settrace(None)
            self.assertEqual(len(hits),1)
            self.assertEqual(len(calls),1)
            self.assertTrue(context.closed)
            with self.assertRaises(budget.HIAStaticBudgetRejected):context.service(frame)
            with self.assertRaises(budget.HIAStaticBudgetRejected):self.native.step(context)
            self.assertEqual(len(calls),1)
            self.assertIsNone(context.workspace)
            self.assertIsNone(context.output)
        finally:
            sys.settrace(None);outer.f_trace_opcodes=previous_flag;context.close()

    def test_actual_arena_and_output_swap_interruption_retains_both_maps(self):
        lines,start=inspect.getsourcelines(adapter.BudgetContext._grow)
        sites=[start+i for i,line in enumerate(lines) if line.strip() in
               ('setattr(self, name, getattr(self, created))', 'setattr(self, created, None)', 'getattr(self, previous).close()')]
        self.assertEqual(len(sites),3)
        for output in (False,True):
            for site in sites:
                context=adapter.BudgetContext(2,constant())
                original_map=mmap.mmap
                if output:
                    context.output.close();context.output=original_map(-1,64)
                else:
                    context.workspace.close();context.workspace=original_map(-1,BASE_SMALL)
                while True:
                    frame=self.native.step(context)
                    if (not output and frame.request==2) or (output and frame.request==101):break
                    context.service(frame)
                old=context.output if output else context.workspace
                created=[];hits=[];error=KeyboardInterrupt('actual arena swap boundary')
                def allocate(*args,**kwargs):
                    value=original_map(*args,**kwargs);created.append(value);return value
                def trace(frame,event,arg):
                    if frame.f_code is adapter.BudgetContext._grow.__code__ and event=='line' and frame.f_lineno==site:
                        hits.append(site);raise error
                    return trace
                try:
                    with patch.object(adapter.mmap,'mmap',allocate):
                        sys.settrace(trace)
                        try:context.service(frame)
                        except KeyboardInterrupt as exc:self.assertIs(exc,error)
                        finally:sys.settrace(None)
                    self.assertEqual(hits,[site])
                    self.assertEqual(len(created),1)
                    self.assertTrue(old.closed)
                    self.assertTrue(created[0].closed)
                    self.assertTrue(context.closed)
                    self.assertIsNone(context.workspace)
                    self.assertIsNone(context.output)
                finally:sys.settrace(None);context.close()

    def test_original_public_static_depth_and_composed_suites_select_actual_hia(self):
        modules=('tests.test_hia_static_budget','tests.test_hia_vm_call_depth',
                 'tests.test_hia_vm_call_depth_only','tests.test_hia_v7_call_depth',
                 'tests.test_hia_returned_loan_budgets','tests.test_hia_bounded_profile')
        suite=unittest.defaultTestLoader.loadTestsFromNames(modules)
        with (self.folder/'original-public.log').open('w') as stream,selected(self.manifest):
            result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
        type(self).original_tests=result.testsRun
        self.assertTrue(result.wasSuccessful(),[(t.id(),text) for t,text in result.failures+result.errors])
        self.assertEqual(result.skipped,[])

    def test_independent_old_vm_observes_complete_actual_frames(self):
        from hepta.hia_program_runtime import _Machine,_Owner,_View
        checked=verify_core(document())
        for mode,limits in ((1,(None,None,0,None)),(1,(None,None,1,None))):
            context=adapter.BudgetContext(mode,constant(),limits)
            try:
                while True:
                    source=bytes(context.input);out=bytes(context.output);work=bytes(context.workspace)
                    frame=self.native.step(context)
                    roots=[_Owner(-1,bytearray(source)),_Owner(-2,bytearray(out)),_Owner(-3,bytearray(work))]
                    machine=_Machine(checked,10_000_000,0,None,256)
                    returned=machine.invoke(machine.functions['f0'],[_View(root,i!=0) for i,root in enumerate(roots)])
                    self.assertEqual(returned,[frame.request])
                    self.assertEqual(bytes(roots[0].data),source)
                    self.assertEqual(bytes(roots[1].data),bytes(context.output))
                    self.assertEqual(bytes(roots[2].data),bytes(context.workspace))
                    type(self).vm_entries+=1
                    if not frame.request:break
                    context.service(frame)
            finally:context.close()

    def test_transport_extent_tracks_accepted_large_final_core(self):
        from tests.test_hia_program import m,f,b,c,ret
        from tests.test_hia_program_execution_native import late_container
        count=262145
        core=m(f('main',[],['unit']*count,[],[b('entry',[],[c('u','unit',None)],ret(*(['u']*count)))]))
        core['schema']='hepta.hia.program.v8'
        with selected(None):expected=budget.analyze_static_budget(late_container(core))
        with selected(self.manifest):actual=budget.analyze_static_budget(late_container(core))
        self.assertEqual(actual,expected)
        self.assertEqual(actual['functions'][0]['max_vm_ticks'],3)
        type(self).differentials+=1
