"""Reusable actual public-heap and once-only scope controls.

Each control records complete original/native observations. These helpers are
test fixtures only; installed production code never imports them.
"""
import ast
import contextlib
import copy
import dataclasses
import hashlib
import inspect
import json
from pathlib import Path
import os
import struct
import sys
import time
import traceback
import types
from contextlib import ExitStack, contextmanager
from unittest.mock import patch

from hepta import hia_heap_bound as heap, hia_heap_bound_native as ad
from hepta import hia_static_budget as static, hia_static_budget_native as sa
from hepta.hia_program import verify_program, VerifiedProgram
from tests.test_hia_program import m, f, b, c, i, ret
from tests.test_hia_heap_bound import local_buffers

PUBLIC_NAMES = (
    'analyze_constant_live_heap', 'qualify_live_heap_budget',
    'qualify_entry_live_heap_budget', 'qualify_finite_entry_live_heap_budget',
    'qualify_finite_entry_live_heap_budget_v8',
    'qualify_finite_entry_live_heap_budget_v8_with_borrowed_extents',
    'analyze_entry_payload_bound',
)


def retained_oracle():
    """Execute the exact retained bodies under independent module globals.

    Source tests bind each original body. Public dispatch wrappers are removed;
    only the seven retained definitions are renamed to their original names.
    The remaining private classes/functions are copied without AST changes.
    """
    source = Path(heap.__file__).read_text()
    tree = ast.parse(source)
    tree.body = [node for node in tree.body
                 if not (isinstance(node, ast.FunctionDef) and node.name in PUBLIC_NAMES)]
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name.startswith('_reference_'):
            name = node.name[len('_reference_'):]
            if name in PUBLIC_NAMES:
                node.name = name
    oracle = types.ModuleType('hepta._independent_public_heap_fixture')
    oracle.__package__ = 'hepta'
    oracle.__file__ = str(Path(heap.__file__))
    sys.modules[oracle.__name__] = oracle
    exec(compile(ast.fix_missing_locations(tree), oracle.__file__, 'exec'), oracle.__dict__)
    return oracle


def run_public_controls(folder, paths):
    F = Path(folder)
    F.mkdir(parents=True, exist_ok=False)
    report = {'scope': 'PUBLIC_HEAP_ACTUAL_REPORT_ALIAS_LIFETIME_CONTROLS',
              'cases': [], 'started': time.time()}
    oracle = retained_oracle()
    def case(name,action):
        row={'name':name,'started':time.time()}
        try:row.update(status='PASS',observation=action())
        except BaseException as error:row.update(status='FAIL',exception_type=type(error).__name__,exception=str(error),traceback=traceback.format_exc())
        row['finished']=time.time();report['cases'].append(row)
        (F/(name+'.json')).write_text(json.dumps(row,indent=2,sort_keys=True)+'\n')
        print(json.dumps({k:v for k,v in row.items() if k not in ('observation','traceback')}),flush=True)
    def observation(action):
        try:return {'returned':action()}
        except Exception as error:
            cause=error.__cause__
            return {'type':type(error).__name__,'code':getattr(error,'code',None),'message':str(error),
                    'cause':None if cause is None else {'type':type(cause).__name__,'code':getattr(cause,'code',None),'message':str(cause)}}
    try:
        names=('analyze_constant_live_heap','qualify_live_heap_budget','qualify_entry_live_heap_budget',
               'qualify_finite_entry_live_heap_budget','qualify_finite_entry_live_heap_budget_v8',
               'qualify_finite_entry_live_heap_budget_v8_with_borrowed_extents','analyze_entry_payload_bound')
        selectors=(ad.SELECTOR,ad.LIVE_SELECTOR,ad.STATIC_SELECTOR,ad.PAYLOAD_SELECTOR)
        @contextmanager
        def selected(enabled):
            env=dict(os.environ)
            for key in selectors:env.pop(key,None)
            if enabled:env.update({key:str(path) for key,path in zip(selectors,paths)})
            with patch.dict(os.environ,env,clear=True):yield
        @contextmanager
        def poison():
            with ExitStack() as stack:
                for name in tuple('_reference_'+name for name in names)+('_qualify_finite_entry_live_heap_budget','_function','_scoped_allocating_cycle_peak','_dag','_FiniteInvocationAnalysis'):
                    stack.enter_context(patch.object(heap,name,side_effect=AssertionError('old heap callback '+name)))
                for name in ('_reference_analyze_static_budget','_reference_audit_resource_profile','analyze_static_budget',
                             '_audit_v7_byte_resource_profile','_audit_v8_resource_profile'):
                    stack.enter_context(patch.object(static,name,side_effect=AssertionError('old static callback '+name)))
                yield
        owner=ad.installed_heap_bound(*(str(p) for p in paths))
        report['pinned_images_loaded']=4
        def program(version=1):
            value=local_buffers();value['schema']='hepta.hia.program.v'+str(version);value['exports']=['finite'];return value
        cases=[
          (names[0],program(),(),{}),
          (names[1],program(),(),{'max_live_heap_bytes':12}),
          (names[2],program(8),('finite',),{'max_live_heap_bytes':12}),
          (names[3],program(7),('finite',[]),{'max_live_heap_bytes':12}),
          (names[4],program(8),('finite',[]),{'max_live_heap_bytes':12}),
          (names[5],program(8),('finite',[]),{'max_live_heap_bytes':12}),
          (names[6],program(),('finite',),{})]
        def compare(name,source,args,kwargs):
            with selected(False):expected_value=observation(lambda:getattr(oracle,name)(copy.deepcopy(source),*args,**kwargs))
            with selected(True),poison():actual_value=observation(lambda:getattr(heap,name)(copy.deepcopy(source),*args,**kwargs))
            assert actual_value==expected_value,{'expected':expected_value,'actual':actual_value}
            return {'expected':expected_value,'actual':actual_value,'old_semantics_poisoned':True}
        for index,(name,source,args,kwargs) in enumerate(cases):
            case('public_'+str(index),lambda name=name,source=source,args=args,kwargs=kwargs:compare(name,source,args,kwargs))
        def policy_errors():
            rows=[]
            for limit in (True,None,-1,1<<63,-(1<<1000000)):
                row=compare(names[1],{},(),{'max_live_heap_bytes':limit})
                assert row['actual'].get('code')=='E_HIA_BUDGET_POLICY'
                rows.append({'limit_type':type(limit).__name__,'negative':type(limit)is int and limit<0,'bits':limit.bit_length() if type(limit)is int else None,'result':row['actual']})
            return rows
        case('exact_policy_range',policy_errors)
        def verify_order():
            doc=verify_program(program()).as_dict();marker=object()
            def invoke(module,enabled):
                events=[];sentinel=object()
                class Primary:
                    @property
                    def sha256(self):events.append('sha:first');return marker
                    def as_dict(self):events.append('as_dict:first');raise AssertionError('extra first as_dict')
                class Secondary:
                    def as_dict(self):events.append('as_dict:second');return copy.deepcopy(doc)
                first=Primary();second=Secondary()
                def verify(value):
                    if value is sentinel:events.append('verify:first');return first
                    assert value is first;events.append('verify:second');return second
                with selected(enabled),patch.object(module,'verify_program',side_effect=verify):
                    result=module.qualify_live_heap_budget(sentinel,max_live_heap_bytes=12)
                assert result['program_sha256'] is marker
                return {'events':events,'sha_identity':True,'bounds':result['peak_bounds']}
            before=invoke(oracle,False);after=invoke(heap,True)
            assert before==after
            assert before['events']==['verify:first','verify:second','as_dict:second','sha:first']
            return {'reference':before,'native':after}
        case('verify_document_order',verify_order)
        def alias_source(which):
            if which=='single':
                name=''.join(('payload_alias_entry_','not_interned_','0123456789abcdef'))
                value=m(f(name,[],['u32'],[],[b('entry',[],[c('answer','u32',37)],ret('answer'))]))
                value['exports']=[name];return value,name
            child=''.join(('payload_alias_child_','not_interned_','0123456789abcdef'))
            parent=''.join(('payload_alias_parent_','not_interned_','0123456789abcdef'))
            target=('X'+child)[1:];assert target==child and target is not child
            value=m(f(child,[],['u32'],[],[b('child_entry',[],[c('n','u32',3)],ret('n'))]),
                    f(parent,[],['u32'],[],[b('parent_entry',[],[i('call',[],[('r','u32')],function=target)],ret('r'))]))
            value['exports']=[parent];return value,parent
        def aliases(value):
            keys=list(value['call_graph']);summaries={row['function']:row for row in value['function_summaries']};order=value['callee_first_order'];result={}
            for key in keys:
                order_name=next(x for x in order if x==key);summary=summaries[key]['function']
                result[key]={'key_is_order':key is order_name,'key_is_summary':key is summary,'order_is_summary':order_name is summary}
            for caller,targets in value['call_graph'].items():
                for target in targets:
                    declaration=next(x for x in keys if x==target)
                    result['edge:'+caller+'->'+target]={'target_is_declaration':target is declaration,'target_is_summary':target is summaries[target]['function']}
            return result
        def alias_compare(which):
            value,function=alias_source(which)
            with selected(False):expected_value=oracle.analyze_entry_payload_bound(value,function)
            with selected(True),poison():got=heap.analyze_entry_payload_bound(value,function)
            actual_value={key:got[key] for key in ('call_graph','callee_first_order','function_summaries')}
            assert actual_value=={key:expected_value[key] for key in actual_value}
            wanted,actual=aliases(expected_value),aliases(actual_value)
            row={'reference':wanted,'native':actual,'value_equal':True}
            (F/('payload_alias_'+which+'-observation.json')).write_text(json.dumps(row,indent=2,sort_keys=True)+'\n')
            assert actual==wanted,row
            return row
        case('payload_alias_single',lambda:alias_compare('single'))
        case('payload_alias_call',lambda:alias_compare('call'))
        def source():
            name=''.join(('payload_source_identity_','not_interned_','0123456789abcdef'))
            ops=[c('padding_'+str(index),'u32',index) for index in range(300)]
            size_name='size_value_name_not_interned_0123456789abcdef'
            ops += [c(size_name,'usize',1024),
                    i('buffer.try_new',[size_name],[('first','buffer'),('ok_first','bool')]),i('owner.drop',['first']),
                    i('buffer.try_new',[size_name],[('second','buffer'),('ok_second','bool')]),i('owner.drop',['second'])]
            value=m(f(name,[],[],['alloc'],[b('entry_block_not_interned_0123456789abcdef',[],ops,ret())]))
            value['exports']=[name];return value,name
        def invoke_source(module,enabled):
            value,name=source();captured=[];method=VerifiedProgram.as_dict
            def spy(checked):
                caller=sys._getframe(1)
                stamp=(caller.f_globals.get('__name__'),caller.f_code.co_name)
                del caller
                doc=method(checked);captured.append((checked,doc,*stamp));return doc
            with selected(enabled),patch.object(VerifiedProgram,'as_dict',spy):
                result=module.analyze_entry_payload_bound(value,name)
            wanted_module='hepta.hia_heap_bound_native' if enabled else oracle.__name__
            wanted_function='_invoke' if enabled else 'analyze_entry_payload_bound'
            matches=[row for row in captured if row[2:]==(wanted_module,wanted_function)]
            assert len(matches)==1,[(row[2],row[3]) for row in captured]
            held,doc,_,_=matches[0];fn=doc['functions'][0];block=fn['blocks'][0];summary=result['function_summaries'][0]
            (F/('doc-captures-native.json' if enabled else 'doc-captures-reference.json')).write_text(
                json.dumps([{'module':row[2],'function':row[3]} for row in captured],indent=2,sort_keys=True)+'\n')
            sites=summary['blocks'][0]['allocation_sites'];key=next(iter(result['call_graph']))
            observed={
              'capture_count':len(captured),
              'external_function_retained':result['function'] is name,
              'core_sha_retained':result['core_sha256'] is held.sha256,
              'input_sha_retained':result['input_sha256'] is held.input_sha256,
              'schema_is_source':result['core_schema'] is doc['schema'],
              'call_graph_key_is_source':key is fn['name'],
              'order_name_is_source':result['callee_first_order'][0] is fn['name'],
              'summary_name_is_source':summary['function'] is fn['name'],
              'entry_block_is_source':summary['entry_block'] is fn['entry'],
              'block_id_is_source':summary['blocks'][0]['block'] is block['id'],
              'first_opcode_is_source':sites[0]['opcode'] is block['ops'][301]['op'],
              'first_size_name_is_source':sites[0]['size_value'] is block['ops'][301]['args'][0],
              'first_constant_bytes_is_source':sites[0]['constant_bytes'] is block['ops'][300]['attrs']['value'],
              'constant_index_shared':sites[0]['const_op_index'] is sites[1]['const_op_index'],
              'constant_bytes_shared':sites[0]['constant_bytes'] is sites[1]['constant_bytes'],
              'independent_opcodes_stay_distinct':sites[0]['opcode'] is not sites[1]['opcode'],
              'independent_size_names_stay_distinct':sites[0]['size_value'] is not sites[1]['size_value'],
              'const_op_index':sites[0]['const_op_index']}
            return result,observed
        def check_source_identities():
            before,want=invoke_source(oracle,False);after,actual=invoke_source(heap,True)
            assert before==after
            row={'reference':want,'native':actual,'value_equal':True}
            (F/'source-identity-observation.json').write_text(json.dumps(row,indent=2,sort_keys=True)+'\n')
            assert want['const_op_index']==300 and want['constant_index_shared'] and want['schema_is_source'],row
            assert actual==want,row
            return row
        case('source_and_generated_scalar_identities',check_source_identities)
        def container_trace(module,enabled,private=False):
            events=[]
            class Meta(type):
                def __eq__(cls,other):
                    events.append('type_eq:'+other.__name__);return other is list
            class Arguments(metaclass=Meta):
                def __iter__(self):events.append('iter');return iter(())
                def __len__(self):events.append('len');return 0
                def __del__(self):events.append('del')
            value=m(f('main',[],['u32'],[],[b('entry',[],[c('answer','u32',37)],ret('answer'))]))
            value['schema']='hepta.hia.program.v7';value['exports']=['main']
            dumps=json.dumps
            def watched(obj,*args,**kwargs):
                if type(obj) is dict and str(obj.get('schema','')).startswith('hepta.hia.finite-entry-live-heap-admission.'):
                    events.append('report_json')
                return dumps(obj,*args,**kwargs)
            with selected(enabled),patch.object(json,'dumps',watched):
                if private:
                    result=module._qualify_finite_entry_live_heap_budget(value,'main',Arguments(),max_live_heap_bytes=0,parameter_loan_returns=False)
                else:
                    result=module.qualify_finite_entry_live_heap_budget(value,'main',Arguments(),max_live_heap_bytes=0)
            assert result['arguments']==[]
            return events
        def check_lifetimes():
            before=container_trace(oracle,False);after=container_trace(heap,True);private=container_trace(oracle,False,True)
            assert before==after,(before,after)
            assert before.index('report_json')<before.index('del')
            assert private.index('del')<private.index('report_json')
            return {'reference_public':before,'native_public':after,'reference_private':private}
        case('public_vs_private_arguments_lifetime',check_lifetimes)

        report['status']='PASS' if all(row['status']=='PASS' for row in report['cases']) else 'FAIL'
        report['finished']=time.time()
        (F/'RESULT.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        assert report['status']=='PASS',report['cases']
        assert len(report['cases'])==13
        return report
    finally:
        sys.modules.pop(oracle.__name__,None)


def run_scope_controls(folder, paths):
    F=Path(folder)
    F.mkdir(parents=True,exist_ok=False)
    report={'scope':'PINNED_HEAP_COMPOSITION_AND_ONCE_ONLY_SCOPE_CONTROLS',
            'cases':[],'started':time.time()}
    selectors=(ad.SELECTOR,ad.LIVE_SELECTOR,ad.STATIC_SELECTOR,ad.PAYLOAD_SELECTOR)
    @contextlib.contextmanager
    def selected(enabled):
        env=dict(os.environ)
        for key in selectors:env.pop(key,None)
        if enabled:env.update({key:str(p) for key,p in zip(selectors,paths)})
        with patch.dict(os.environ,env,clear=True):yield
    @contextlib.contextmanager
    def poison_public_heap():
        def forbidden(*args,**kwargs):raise AssertionError('retained/public callback must not be selected')
        with contextlib.ExitStack() as stack:
            for name in ('analyze_constant_live_heap','qualify_entry_live_heap_budget','_function','_dag','_scoped_allocating_cycle_peak'):
                stack.enter_context(patch.object(heap,name,forbidden))
            for name in vars(heap):
                if name.startswith('_reference_'):stack.enter_context(patch.object(heap,name,forbidden))
            stack.enter_context(patch.object(heap._FiniteInvocationAnalysis,'__init__',forbidden))
            yield
    def source(version=1):
        value=local_buffers();value['schema']='hepta.hia.program.v'+str(version);value['exports']=['finite'];return value
    def case(name,action):
        row={'name':name,'started':time.time()}
        try:row.update(status='PASS',observation=action())
        except BaseException as error:row.update(status='FAIL',exception_type=type(error).__name__,exception=str(error),traceback=traceback.format_exc())
        row['finished']=time.time();report['cases'].append(row)
        (F/(name+'.json')).write_text(json.dumps(row,sort_keys=True,indent=2)+'\n')
        print(json.dumps({k:v for k,v in row.items() if k!='observation'}),flush=True)
    def closed(context):
        assert context.closed
        for name in ('workspace','output','_created_arena','_previous_arena','_created_output','_previous_output'):
            assert getattr(context,name) is None,(name,getattr(context,name))
    def refused(action):
        try:action()
        except (heap.HIAHeapBoundRejected,static.HIAStaticBudgetRejected) as error:
            assert error.code=='E_HIA_BUDGET_NATIVE',str(error);return str(error)
        raise AssertionError('expected native transport refusal')
    def composition(version):
        limit=int('4097')
        def invoke_public():
            if version==1:return static.analyze_static_budget(source(version),max_live_heap_bytes=limit)
            return static.qualify_bounded_resources(source(version),limits={'max_allocator_interactions':100,'max_vm_ticks':10000,'max_call_depth':256,'max_live_heap_bytes':limit})
        with selected(False):expected=invoke_public()
        admissions=[];groups=[];contexts=[];passes=[];nested=[];changed=[]
        static_loader=sa._installed_json_image;heap_loader=ad._installed_json_image
        compose=ad.compose_static_heap;foreign=ad._ComposedStaticContext._invoke;heap_init=ad.HeapContext.__init__;heap_foreign=ad.HeapContext._invoke
        def static_load(*args,**kwargs):
            image=static_loader(*args,**kwargs);admissions.append(('static',args[2],id(image)));return image
        def heap_load(*args,**kwargs):
            image=heap_loader(*args,**kwargs);admissions.append(('heap',args[2],id(image)));return image
        def collect_group(*args,**kwargs):
            group=compose(*args,**kwargs);groups.append(group);return group
        def invoke(context,frame):
            if not changed:
                for key in selectors:os.environ[key]='/definitely-not-an-image/'+key
                changed.append(frame.request)
            if frame.request in (10,11):
                passes.append((frame.request,frame.value,context.pool.get(frame.words[1]) if frame.request==11 else None))
            return foreign(context,frame)
        def collect_context(context,*args,**kwargs):
            heap_init(context,*args,**kwargs);contexts.append((context,args))
        def collect_nested(context,frame):
            if frame.request in (20,21):nested.append(id(context.dependencies.static))
            return heap_foreign(context,frame)
        with selected(True),poison_public_heap(),patch.object(sa,'_installed_json_image',static_load),patch.object(ad,'_installed_json_image',heap_load),patch.object(ad,'compose_static_heap',collect_group),patch.object(ad._ComposedStaticContext,'_invoke',invoke),patch.object(ad.HeapContext,'__init__',collect_context),patch.object(ad.HeapContext,'_invoke',collect_nested):
            actual=invoke_public()
            assert actual==expected
            assert len(admissions)==4,admissions
            assert len(groups)==1 and groups[0].image is groups[0].heap.dependencies.static
            assert passes and all(row[0]==(10 if version==1 else 11) for row in passes)
            assert contexts
            for context,args in contexts:
                assert args[0]==(0 if version==1 else 2)
                assert context.dependencies.static is groups[0].image
                closed(context)
            if version==8:
                assert nested and all(ident==id(groups[0].image) for ident in nested)
                assert all(row[2] is limit for row in passes)
                assert all(args[4] is limit for context,args in contexts)
                assert all(args[2] is passes[index][1] for index,(context,args) in enumerate(contexts))
            assert actual['limits']['max_live_heap_bytes'] is limit
            next_error=refused(invoke_public)
        return {'version':version,'complete_report_equal':True,'admissions':admissions,'callback_requests':[r[0] for r in passes],
                'static_same_object':True,'limit_identity':True,'next_call_refused_after_env_drift':next_error}
    def four_methods():
        document=verify_program(source(8)).as_dict()
        calls=(('qualify_vm_call_depth',(source(8),),{'max_call_depth':1}),
               ('analyze_static_budget',(source(1),),{'max_live_heap_bytes':12}),
               ('qualify_bounded_resources',(source(8),),{'limits':{'max_allocator_interactions':10,'max_vm_ticks':100,'max_call_depth':1,'max_live_heap_bytes':12}}),
               ('_audit_resource_profile',(document,),{'schema':'hepta.hia.program.v8','allow_chain':False}))
        rows=[]
        for method,args,kwargs in calls:
            with selected(False):expected=getattr(static,method)(*args,**kwargs)
            with selected(True),poison_public_heap():actual=getattr(static,method)(*args,**kwargs)
            assert actual==expected,method
            rows.append(method)
        return rows
    def missing_dependency():
        rows=[]
        for key in (ad.LIVE_SELECTOR,ad.PAYLOAD_SELECTOR):
            with selected(True):
                del os.environ[key]
                rows.append(refused(lambda:static.analyze_static_budget(source(8),max_live_heap_bytes=12)))
        with selected(True):
            os.environ[ad.PAYLOAD_SELECTOR]='/definitely-not-a-payload-image'
            rows.append(refused(lambda:static.analyze_static_budget(source(8),max_live_heap_bytes=12)))
        return rows
    def nested_exception():
        class OpaqueFailure(Exception):pass
        marker=OpaqueFailure('foreign heap verifier failed');contexts=[]
        heap_init=ad.HeapContext.__init__;budget_init=sa.BudgetContext.__init__
        def collect_heap(context,*args,**kwargs):heap_init(context,*args,**kwargs);contexts.append(context)
        def collect_budget(context,*args,**kwargs):budget_init(context,*args,**kwargs);contexts.append(context)
        with selected(True),poison_public_heap(),patch.object(ad.HeapContext,'__init__',collect_heap),patch.object(sa.BudgetContext,'__init__',collect_budget),patch.object(heap,'verify_program',side_effect=marker):
            try:static.analyze_static_budget(source(),max_live_heap_bytes=12)
            except OpaqueFailure as error:assert error is marker
            else:raise AssertionError('missing original foreign failure')
        assert len(contexts)>=2
        for context in contexts:closed(context)
        return {'context_types':[type(c).__name__ for c in contexts],'original_exception_identity':True,'all_arenas_closed':True}
    def forged_frame(owner):
        context=ad.HeapContext(0,source(),None,None,None,owner.dependencies)
        try:
            frame=owner.controller.step(context);assert frame.request==2
            changed=dataclasses.replace(frame)
            with patch.object(heap,'verify_program',side_effect=AssertionError('foreign call must not execute')):
                message=refused(lambda:context.service(changed))
            closed(context);return {'refused':message,'foreign_calls':0}
        finally:context.close()
    def lost_foreign_ack(owner):
        class OpaqueFailure(Exception):pass
        marker=OpaqueFailure('lost verifier return acknowledgement');calls=[]
        context=ad.HeapContext(0,source(),None,None,None,owner.dependencies);foreign=ad.HeapContext._invoke
        try:
            frame=owner.controller.step(context);assert frame.request==2
            def uncertain(current,issued):
                raw=foreign(current,issued);calls.append(issued.request);raise marker
            with patch.object(ad.HeapContext,'_invoke',uncertain):
                try:context.service(frame)
                except OpaqueFailure as error:assert error is marker
                else:raise AssertionError('missing lost acknowledgement')
                refused(lambda:context.service(frame))
                refused(lambda:owner.controller.step(context))
            assert calls==[2];closed(context)
            return {'actual_foreign_calls':calls,'retry_refused':True,'original_exception_identity':True}
        finally:context.close()
    def lost_native_ack(owner):
        class OpaqueFailure(Exception):pass
        marker=OpaqueFailure('lost native return acknowledgement');calls=[];headers=[]
        context=ad.HeapContext(0,source(),None,None,None,owner.dependencies);entry=owner.controller._entry
        def uncertain(*args):
            result=entry(*args);calls.append(result);headers.append(list(struct.unpack_from('<4Q',context.workspace)));raise marker
        try:
            with patch.object(owner.controller,'_entry',uncertain):
                try:owner.controller.step(context)
                except OpaqueFailure as error:assert error is marker
                else:raise AssertionError('missing lost native return')
                refused(lambda:owner.controller.step(context))
            assert calls==[2] and headers[0][2:]==[1,2],(calls,headers)
            closed(context)
            return {'actual_native_calls':calls,'native_headers':headers,'retry_refused':True}
        finally:context.close()
    def terminal_changed(owner):
        context=ad.HeapContext(0,source(),None,None,None,owner.dependencies)
        try:
            while True:
                frame=owner.controller.step(context)
                if frame.request:context.service(frame)
                else:break
            assert frame.status==1 and frame.value=={'finite':12}
            frame.value['finite']=13
            error=refused(lambda:context.accept(frame));closed(context)
            return {'mutated_terminal_rejected':error}
        finally:context.close()
    def changed_document(owner):
        context=ad.HeapContext(0,source(),None,None,None,owner.dependencies);entries=[]
        entry=owner.dependencies.live._entry
        def counted(*args):entries.append(1);return entry(*args)
        try:
            while True:
                frame=owner.controller.step(context)
                if frame.request==22:break
                assert frame.request;context.service(frame)
            frame.value[4]['functions'][0]['name']='changed_after_admitted_snapshot'
            with patch.object(owner.dependencies.live,'_entry',counted):
                error=refused(lambda:context.service(frame))
            assert entries==[];closed(context)
            return {'byte_mismatch_rejected_before_kernel':error,'live_entries':0}
        finally:context.close()
    case('legacy_static_heap_pin_once',lambda:composition(1))
    case('v8_static_heap_static_same_image',lambda:composition(8))
    case('all_four_static_entry_methods',four_methods)
    case('missing_or_bad_composed_configuration',missing_dependency)
    case('nested_foreign_exception_closes_both_scopes',nested_exception)
    owner=ad.installed_heap_bound(*(str(path) for path in paths))
    for name,action in (('forged_frame',forged_frame),('lost_foreign_ack',lost_foreign_ack),
                        ('lost_native_ack',lost_native_ack),('changed_terminal',terminal_changed),
                        ('changed_held_document',changed_document)):
        case(name,lambda action=action:action(owner))
    report['status']='PASS' if all(row['status']=='PASS' for row in report['cases']) else 'FAIL'
    report['finished']=time.time()
    (F/'RESULT.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    assert report['status']=='PASS',report['cases']
    assert len(report['cases'])==10
    return report
