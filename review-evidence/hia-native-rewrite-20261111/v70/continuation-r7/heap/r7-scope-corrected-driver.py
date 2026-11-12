import contextlib,dataclasses,hashlib,inspect,json,os,pathlib,struct,sys,time,traceback
from unittest.mock import patch
E=pathlib.Path('/home/qq/hia-native-self-rewrite-20261111-dda7/heap-native-v70-r1');S=E/'source-current-8ca';F=E/'public-heap-composition-scope-r7-r2'
F.mkdir(exist_ok=False)
report={'scope':'R7_R2_CORRECTED_ORIGINAL_API_INPUT_MAPPING_ACTUAL_PINNED_COMPOSITION_AND_ONCE_ONLY_SCOPE_CONTROLS','started':time.time(),'pid':os.getpid(),'cases':[],'cold_or_whole_qualification':False}
try:report['cgroup']=pathlib.Path('/proc/self/cgroup').read_text()
except OSError:report['cgroup']=None
(F/'ENTERED.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
for key in list(os.environ):
    if key.startswith('HEPTA_'):os.environ.pop(key)
os.chdir(S);sys.path.insert(0,str(S))
from hepta import hia_heap_bound as heap,hia_heap_bound_native as ad,hia_static_budget as static,hia_static_budget_native as sa
from hepta.hia_program import verify_program
from tests.test_hia_heap_bound import local_buffers
paths=(E/'public-heap-native-r6/heap_bound/heap_bound.json',E/'public-heap-native-compile-r1/heap_live_engine/heap_live_engine.json',
       E/'public-heap-native-compile-r1/static_budget/static_budget.json',E/'public-heap-native-r6/heap_payload/heap_payload.json')
selectors=(ad.SELECTOR,ad.LIVE_SELECTOR,ad.STATIC_SELECTOR,ad.PAYLOAD_SELECTOR)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def inventory():
    names=['hepta/hia_heap_bound.py','hepta/hia_heap_bound_native.py','hepta/hia_static_budget_native.py',
           'hepta/hia_native_value_graph.py','examples/hia_bootstrap/heap_bound.hiaasm',
           'examples/hia_bootstrap/heap_live_engine.hiaasm','examples/hia_bootstrap/heap_payload.hiaasm',
           'examples/hia_bootstrap/static_budget.hiaasm']
    rows={name:digest(S/name) for name in names}
    for path in paths:
        data=json.loads(path.read_bytes())
        rows[str(path)]=digest(path);rows[str(path.parent/data['image_path'])]=digest(path.parent/data['image_path'])
    return rows
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
try:
    report['before']=inventory()
    assert report['before']['hepta/hia_heap_bound_native.py']=='5cd851ea14cf99bd796c4f8a6b13abda27bd7a46fdfd5b1e2537735ea79fb333'
    assert report['before']['hepta/hia_static_budget_native.py']=='0ffab003672a5ee5c7095dc4c1306e7c86136064a6c11be3f7f386f02eb9afd7'
    case('legacy_static_heap_pin_once',lambda:composition(1))
    case('v8_static_heap_static_same_image',lambda:composition(8))
    case('all_four_static_entry_methods',four_methods)
    case('missing_or_bad_composed_configuration',missing_dependency)
    case('nested_foreign_exception_closes_both_scopes',nested_exception)
    owner=ad.installed_heap_bound(*(str(path) for path in paths))
    for name,action in (('forged_frame',forged_frame),('lost_foreign_ack',lost_foreign_ack),('lost_native_ack',lost_native_ack),
                        ('changed_terminal',terminal_changed),('changed_held_document',changed_document)):
        case(name,lambda action=action:action(owner))
    report['after']=inventory();assert report['after']==report['before']
    report['status']='PASS' if all(row['status']=='PASS' for row in report['cases']) else 'FAIL'
except BaseException as error:
    report.update(status='FAIL',exception_type=type(error).__name__,exception=str(error),traceback=traceback.format_exc())
report['finished']=time.time()
(F/'RESULT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
summary={k:v for k,v in report.items() if k not in ('before','after','cases')}
summary['source_conserved']='after' in report and report['after']==report['before']
summary['cases']=[{k:v for k,v in row.items() if k!='observation'} for row in report['cases']]
(F/'SUMMARY.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
print(json.dumps({'status':report['status'],'cases':len(report['cases']),'failures':sum(row['status']!='PASS' for row in report['cases']),
                  'summary':str(F/'SUMMARY.json'),'sha256':digest(F/'SUMMARY.json')}),flush=True)
raise SystemExit(0 if report['status']=='PASS' else 1)
