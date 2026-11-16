"""Independent dynamic-dispatch observations of the frozen AAC admission bodies.
The original 303-case oracle is unchanged; no candidate graph is read.
"""
import builtins
import json
from pathlib import Path
from types import MethodType
from unittest.mock import patch
from tests.hia_native_build_admission_oracle import Fixture, Service, ObservedDict, snapshot, exception_record, observe_case as original_observe
FUNCTIONS={2:'_native',3:'_build_inputs',4:'_build_receipt'}

class DispatchIterable:
    def __init__(self,f,values,case):
        self.fixture,self.values,self.case,self.index,self.label=f,values,case,0,'dispatch-result'
    def __iter__(self):
        self.fixture.trace.emit('dispatch.result.iter')
        if self.case.get('iter_error'):raise self.fixture.dispatch_error
        return self
    def __next__(self):
        index=self.index;self.fixture.trace.emit('dispatch.result.next',index)
        if self.case.get('next_error')==index:raise self.fixture.dispatch_error
        if index>=len(self.values):raise StopIteration
        self.index+=1;return self.values[index]
    def __length_hint__(self):
        self.fixture.trace.emit('dispatch.result.length_hint')
        raise AssertionError('original unpack never requests a length hint')

class DispatchSubscription:
    def __init__(self,f,case):self.fixture,self.case,self.label=f,case,'dispatch-subscription'
    def __getitem__(self,key):
        self.fixture.trace.emit('dispatch.result.getitem',key)
        if self.case.get('getitem_error'):raise self.fixture.dispatch_error
        return self.fixture.dispatch_marker
    def __bool__(self):
        self.fixture.trace.emit('dispatch.result.bool')
        raise AssertionError('original subscription never tests truth')

class DispatchCallable:
    def __init__(self,f,callback,*,inspection='none'):
        self.fixture,self.callback,self.inspection,self.label=f,callback,inspection,'dispatch-callable'
    def __getattribute__(self,name):
        if name in ('__func__','__self__'):
            f=object.__getattribute__(self,'fixture');f.trace.emit('dispatch.callable.inspect',name)
            action=object.__getattribute__(self,'inspection')
            if action=='raise':raise AssertionError('original call does not inspect method internals')
            if action=='spoof':return f.dispatch_default if name=='__func__' else f.service
        return object.__getattribute__(self,name)
    def __call__(self,*args,**kwargs):return self.callback(*args,**kwargs)

class Iterator:
    """Independent original-probe object; its lifetime is observable input."""
    def __init__(self,trace,label,values,replacement=None):
        self.trace,self.label,self.values,self.replacement=trace,label,values,replacement
        self.index=0
    def __iter__(self):
        self.trace.emit(self.label+'.iter')
        if self.replacement is not None:
            return Iterator(self.trace,self.label+'.replacement',self.replacement)
        return self
    def __next__(self):
        self.trace.emit(self.label+'.next',self.index)
        if self.index>=len(self.values):raise StopIteration
        value=self.values[self.index];self.index+=1;return value
    def close(self):self.trace.emit(self.label+'.close')
    def __del__(self):self.trace.emit(self.label+'.delete')

class Iterable:
    def __init__(self,trace,label,values,replacement=None):
        self.trace,self.label,self.values,self.replacement=trace,label,values,replacement
        self.index=0
    def __iter__(self):
        self.index+=1;self.trace.emit(self.label+'.iter',self.index)
        return Iterator(self.trace,self.label+'.iterator.'+str(self.index),self.values,self.replacement)

class TargetIterable:
    def __init__(self,trace,label,values,target,replacement):
        self.trace,self.label,self.values=trace,label,values
        self.target,self.replacement,self.index=target,replacement,0
    def __iter__(self):
        self.index+=1;self.trace.emit(self.label+'.iter',self.index)
        return Iterator(self.trace,self.label+'.iterator.'+str(self.index),self.values,
                        self.replacement if self.index==self.target else None)

def _observe_protocol_probe(case,owner,bindings):
    """Transcribe the independently observed inputs, never the candidate graph."""
    route=case['route'];mode=case['mode']
    original_name=case.get('original_case_name',case.get('original_case',{}).get('name'))
    fixture=Fixture(case['original_case'] if route=='comprehension_runtime'
                    else {'name':original_name,'mode':mode})
    trace=fixture.trace
    if route=='comprehension_runtime':
        if case['original_case']['add_exports']:fixture.set_exports([('f',7)])
    elif route=='genexpr_lifetime':
        if original_name.startswith('params'):
            values=list(dict.__getitem__(fixture.functions[0],'params'))
            bad=ObservedDict(trace,'bad_parameter',{'type':'mutbuf'})
            if original_name.endswith('short_circuit'):values=[bad]
            replacement=[bad] if original_name.endswith('replacement_iterator') else None
            dict.__setitem__(fixture.functions[0],'params',Iterable(trace,'probe.params',values,replacement))
        else:
            rows=list(dict.items(fixture.metadata))
            if original_name.endswith('short_circuit'):rows.insert(0,('extra_missing',1))
            fixture.metadata.items_override=Iterable(trace,'probe.metadata',rows)
    else:
        if original_name=='dictcomp':
            dict.__setitem__(fixture.document,'functions',TargetIterable(trace,'probe.functions',fixture.functions,1,fixture.functions))
        else:
            target=2 if original_name=='scalar_listcomp' else 3
            values=list(dict.__getitem__(fixture.functions[0],'params'))
            replacement=[ObservedDict(trace,'replacement_parameter',{'type':'bool'})]
            dict.__setitem__(fixture.functions[0],'params',TargetIterable(trace,'probe.params',values,target,replacement))
            if target==3:fixture.set_exports([('f',7)])
    if owner is None:
        for method in ('_native','_build_inputs','_build_receipt'):
            setattr(fixture.service,method,fixture.namespace[method].__get__(fixture.service))
    else:
        for method in ('_native','_build_inputs'):
            setattr(fixture.service,method,bindings[method].__get__(fixture.service))
        fixture.namespace['_signatures']=bindings['_signatures']
    trace.events.clear()
    with fixture.providers():
        try:
            if owner is not None:
                value=owner(mode,None if mode==1 else fixture.service,fixture.arguments(),fixture.namespace)
            elif mode==1:value=fixture.namespace['_signatures'](*fixture.arguments())
            else:value=fixture.namespace['_build_inputs'](fixture.service,*fixture.arguments())
            outcome={'returned':snapshot(value)}
        except BaseException as error:outcome={'exception':exception_record(error)}
    return {'name':case['name'],'original_case_name':original_name,'probe_family':route,
            'outcome':outcome,'trace':trace.events}

def cases():
    return json.loads((Path(__file__).with_name('fixtures')/'hia_native_build_dispatch_cases_aac7550.json').read_bytes())['cases']

def _result(f,case):
    mode=case['mode'];shape=case.get('result','ordinary')
    if mode==3:
        values=[f.native_bytes,f.metadata,f.program]
        if shape=='distinct':
            return f.dispatch_data,f.metadata,f.program
        if shape in ('tuple','list','iterator'):
            count=case.get('length',3);values=(values+[f.dispatch_marker]*4)[:count]
            return tuple(values) if shape=='tuple' else values if shape=='list' else DispatchIterable(f,values,case)
        if shape=='none':return None
        if shape=='integer':return 7
        return tuple(values)
    if mode==4:
        if shape=='ordinary':return (f.record,f.native_bytes,f.object_bytes,f.program)
        if shape=='subscription':return DispatchSubscription(f,case)
        if shape=='dict':return {0:f.dispatch_marker}
        if shape=='string':return 'abc'
        if shape=='bytes':return b'abc'
        if shape=='empty':return ()
        if shape=='none':return None
        if shape=='integer':return 7
        if shape=='iterator':return DispatchIterable(f,[f.dispatch_marker],case)
        return [f.dispatch_marker,'retained-unused-tail']
    if shape=='wrong':return {'override':'not-the-original-signature'}
    if shape=='distinct':return f.dispatch_marker
    return dict.__getitem__(f.metadata,'signatures')

def observe_case(case, owner=None, bindings=None):
    """owner(mode, service, arguments, namespace); bindings are stable public wrappers."""
    if case.get('route') in ('comprehension_runtime','genexpr_lifetime','comprehension_lifetime'):
        return _observe_protocol_probe(case,owner,bindings)
    if case.get('route')=='genexpr_runtime':
        def selected(mode,service,arguments,namespace):
            if service is not None:
                for name in ('_native','_build_inputs'):
                    setattr(service,name,bindings[name].__get__(service))
            namespace['_signatures']=bindings['_signatures']
            return owner(mode,service,arguments,namespace)
        row=original_observe(case['original_case'],owner=None if owner is None else selected)
        row['original_case_name']=row['name'];row['name']=case['name']
        return row
    f=Fixture({'name':case['name'],'mode':case['mode']});ns=f.namespace;mode=case['mode']
    originals={name:ns[name] for name in ('_native','_build_inputs','_build_receipt','_signatures')}
    defaults=originals if owner is None else bindings
    if defaults is None or not {'_native','_build_inputs','_signatures'} <= set(defaults):raise ValueError('candidate requires stable public bindings')
    Base=type('DispatchService',(Service,),{key:value for key,value in defaults.items() if key!='_signatures'})
    f.service.__class__=Base;service=f.service;ns['_signatures']=defaults['_signatures']
    hook='_signatures' if mode==2 else '_native' if mode==3 else '_build_inputs'
    f.dispatch_default=defaults[hook]
    error_type=getattr(builtins,case.get('error_type','ValueError'))
    f.dispatch_error=error_type('dispatch-provider-fault')
    f.dispatch_marker={'override_marker':'preserved-opaque-value'}
    f.dispatch_data=b'override-native-bytes'
    if case.get('result')=='distinct':
        if mode==3:
            from hashlib import sha256
            f.built['artifact_sha256']=sha256(f.dispatch_data).hexdigest()
        elif mode==2:dict.__setitem__(f.metadata,'signatures',f.dispatch_marker)
    def callback(*args,**kwargs):
        f.trace.emit('dispatch.call',hook,args,kwargs)
        if case.get('call_error'):raise f.dispatch_error
        if case.get('mutate_signature_rhs'):
            dict.__setitem__(f.metadata,'signatures',f.dispatch_marker)
            return f.dispatch_marker
        return _result(f,case)
    def replacement(*args,**kwargs):
        f.trace.emit('dispatch.replacement_called',hook)
        raise AssertionError('captured callable was replaced before call')
    form=case.get('form','instance_function')
    if form=='wrong_arity':
        def callback():return None
    if form in ('instance_callable','callable_inspection','callable_spoof'):
        callback=DispatchCallable(f,callback,inspection={'callable_inspection':'raise','callable_spoof':'spoof'}.get(form,'none'))
    if form=='noncallable':callback=None
    installed=callback
    def method(bound,*args,**kwargs):
        f.trace.emit('dispatch.bound_self',bound is service)
        return callback(*args,**kwargs)
    if mode!=2 and form in ('subclass_method','public_class_patch'):
        service.__class__=type('DispatchSubclass',(Base,),{hook:method})
    elif mode!=2 and form=='bound_method':setattr(service,hook,MethodType(method,service))
    elif mode!=2 and form=='staticmethod':setattr(Base,hook,staticmethod(callback))
    elif mode!=2 and form=='classmethod':
        def class_method(cls,*args,**kwargs):
            f.trace.emit('dispatch.bound_class',cls.__name__);return callback(*args,**kwargs)
        setattr(Base,hook,classmethod(class_method))
    elif mode!=2 and form in ('descriptor','data_descriptor','nondata_shadow','rebind_lookup','descriptor_default'):
        class Descriptor:
            def __get__(self,instance,cls):
                f.trace.emit('dispatch.lookup',hook,instance is service,cls.__name__)
                if case.get('lookup_error'):raise f.dispatch_error
                if form=='rebind_lookup':service.__dict__[hook]=replacement
                return defaults[hook].__get__(instance,cls) if form=='descriptor_default' else callback
        class DataDescriptor(Descriptor):
            def __set__(self,instance,value):raise AssertionError('fixture bypasses assignment')
        setattr(Base,hook,DataDescriptor() if form=='data_descriptor' else Descriptor())
        if form=='data_descriptor':service.__dict__[hook]=replacement
        if form=='nondata_shadow':service.__dict__[hook]=callback
    elif mode!=2 and form=='getattribute':
        def intercepted(instance,name):
            if name==hook:
                f.trace.emit('dispatch.getattribute',hook)
                if case.get('lookup_error'):raise f.dispatch_error
                return callback
            return object.__getattribute__(instance,name)
        service.__class__=type('DispatchIntercept',(Base,),{'__getattribute__':intercepted})
    elif mode!=2 and form=='getattr':
        delattr(Base,hook)
        def missing(instance,name):
            f.trace.emit('dispatch.getattr',name)
            if name!=hook:raise AttributeError(name)
            if case.get('lookup_error'):raise f.dispatch_error
            return callback
        setattr(Base,'__getattr__',missing)
    elif mode!=2 and form=='wrong_self_default':
        other=Fixture({'name':'other','mode':mode});other.trace=f.trace;other.service.__class__=Base
        dict.__setitem__(other.metadata,'context',{'id':'other-context'})
        dict.__setitem__(other.record,'context',{'id':'other-context'})
        setattr(service,hook,defaults[hook].__get__(other.service,Base))
    elif form!='canonical' and mode!=2 and not case.get('late'):setattr(service,hook,callback)
    if mode==2:
        if form in ('builtin','builtin_module','missing','misleading_builtins'):
            ns.pop('_signatures')
            if form=='builtin_module':ns['__builtins__']=builtins
            if form=='misleading_builtins':ns['__builtins__']={'_signatures':callback}
        elif form!='canonical' and not case.get('late'):ns['_signatures']=callback
    if case.get('late'):
        previous_emit=f.trace.emit
        def changed(event,*args):
            previous_emit(event,*args)
            if event==('program.sha256' if mode==2 else 'service.identities'):
                if mode==2:ns['_signatures']=callback
                else:setattr(service,hook,callback)
                previous_emit('dispatch.installed_late',hook)
        f.trace.emit=changed
    if case.get('invalid_subject'):dict.__setitem__(f.record,'context',{'id':'wrong-subject'})
    if case.get('invalid_core'):dict.__setitem__(f.metadata,'core_sha256','wrong-core')
    f.trace.events.clear()
    with f.providers() as scope:
        # A bound original/default method on a different receiver is a real
        # foreign call.  Its public selected wrapper creates a child frame
        # using service-module globals, so expose the same fake providers at
        # that actual boundary as at the frozen function's private namespace.
        from hepta import hia_agent_service as api
        scope.enter_context(patch.object(api,'reject',ns['reject']))
        scope.enter_context(patch.object(api,'sha256',ns['sha256']))
        if mode==2 and form in ('builtin','builtin_module','global_none_builtin'):
            scope.enter_context(patch.object(builtins,'_signatures',callback,create=True))
            if form=='global_none_builtin':ns['_signatures']=None
        if form=='public_class_patch':
            from hepta import hia_agent_service as api
            scope.enter_context(patch.object(api.HIAAgentService,hook,method))
        if form=='public_global_patch':
            from hepta import hia_agent_service as api
            scope.enter_context(patch.object(api,'_signatures',callback))
        try:
            value=(originals[FUNCTIONS[mode]](service,*f.arguments()) if owner is None
                   else owner(mode,service,f.arguments(),ns))
            outcome={'returned':snapshot(value),'aliases':f.aliases(value),
                     'is_override_marker':value is f.dispatch_marker}
        except BaseException as error:
            outcome={'exception':exception_record(error),'same_injected_exception':error is f.dispatch_error,
                     'exception_name':getattr(error,'name',None),
                     'exception_context':None if error.__context__ is None else exception_record(error.__context__)}
    return {'name':case['name'],'mode':mode,'hook':hook,'outcome':outcome,'trace':f.trace.events}
