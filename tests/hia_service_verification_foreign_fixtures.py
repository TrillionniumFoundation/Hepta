"""Independent original-call observations at the fixed foreign boundaries."""
from contextlib import ExitStack
import sys
from unittest.mock import patch
from hepta import hia_agent_service as api
from tests.hia_service_verification_fixtures import REFERENCE


def _ambient():
    error=sys.exception()
    return None if error is None else [type(error).__name__,str(error)]


def _shape(error,seen=None):
    if error is None:return None
    if seen is None:seen=set()
    if id(error) in seen:return '<cycle>'
    seen.add(id(error))
    return {'type':type(error).__name__,'message':str(error),
            'cause':_shape(error.__cause__,seen),'context':_shape(error.__context__,seen),
            'suppress':error.__suppress_context__,'notes':getattr(error,'__notes__',None)}


def _detach(error,seen=None):
    if error is None:return
    if seen is None:seen=set()
    if id(error) in seen:return
    seen.add(id(error));error.__traceback__=None
    _detach(error.__cause__,seen);_detach(error.__context__,seen)


def _captured(call):
    try:return call(),None
    except BaseException as error:return None,error


def _run_observation(call,trace,outer):
    def run():
        value,error=_captured(call)
        held=list(trace);shape=_shape(error)
        _detach(error);error=None
        return {'value':value,'error':shape,'held':held,'released':list(trace)}
    if outer:
        try:raise LookupError('outer')
        except LookupError:return run()
    return run()


MAPPING_CASES=('empty','connection','duplicate-kind','nonstr-key','unknown-key',
               'keys-error','getitem-error','nonmapping','keys-stop','callee-error')


def mapping_observation(case,native,image=None,*,outer=False,kind=False):
    trace=[]
    def event(*value):trace.append([*value,_ambient()])
    class Token:
        def __del__(self):event('connection-value-del')
    class Mapping:
        def keys(self):
            event('mapping-keys')
            if case=='keys-error':raise ValueError('original keys')
            if case=='keys-stop':raise StopIteration('original mapping stop')
            if case=='empty':return []
            if case=='duplicate-kind':return ['kind']
            if case=='nonstr-key':return [1]
            if case=='unknown-key':return ['unaccepted']
            return ['_connection']
        def __getitem__(self,key):
            event('mapping-getitem',key)
            if case=='getitem-error':raise KeyError('original item')
            return Token()
        def __del__(self):event('mapping-del')
    class Receiver:
        def profile(self,name,category,*,_connection=None):
            event('profile-body',name,category)
            if case=='callee-error':raise ArithmeticError('original callee')
        def get_json(self,ref,*,kind=None,_connection=None):
            event('get-json-body',ref,kind)
            # End immediately after the real call without fabricating a
            # receipt body. This original error's held arguments are compared.
            raise ArithmeticError('original get_json')
        def __del__(self):event('receiver-del')
    class Store:
        @property
        def get_json(self):return Receiver().get_json
    class Service:
        store=Store()
        @property
        def _profile(self):return Receiver().profile
    service=Service()
    def mapping(connection):
        event('mapping-create')
        return 17 if case=='nonmapping' else Mapping()
    args={'subject':{'kind':'canonical_lowering','backend_profile':'backend','lowering_profile':'lowering'}}
    def call():
        if kind:
            if native:return image.run('_verification',service,'ref','ctx',None,None)
            return REFERENCE['_verification'](service,'ref','ctx')
        if native:return image.run('_subject',service,args,None,None)
        return REFERENCE['_subject'](service,args,None)
    with patch.object(api,'_connection_arguments',mapping):
        return _run_observation(call,trace,outer)


GENERATOR_CASES=('empty','true','false','false-then-true','true-then-false',
                 'claim-stop','status-stop','truth-error','next-error','second-item')


def generator_observation(case,native,image=None,*,outer=False):
    trace=[]
    def event(*value):trace.append([*value,_ambient()])
    class Truth:
        def __init__(self,values):self.values=iter(values)
        def __bool__(self):
            event('truth')
            if case=='truth-error':raise ArithmeticError('original truth')
            return next(self.values)
        def __del__(self):event('truth-del')
    class Compared:
        def __eq__(self,other):
            event('claim-equal',other)
            if case=='false-then-true':return Truth((False,True))
            if case=='true-then-false':return Truth((True,False))
            if case=='false':return Truth((False,False))
            return Truth((True,True))
        def __del__(self):event('compared-del')
    class Check:
        def __getitem__(self,key):
            event('check-get',key)
            if key=='claim':
                if case=='claim-stop':raise StopIteration('original claim stop')
                return Compared()
            if case=='status-stop':raise StopIteration('original status stop')
            return 'proved'
        def __del__(self):event('check-del')
    class Iterator:
        position=0
        def __iter__(self):return self
        def __next__(self):
            event('next',self.position)
            self.position+=1
            if case=='next-error':raise ValueError('original next')
            if case=='empty' or self.position>(2 if case=='second-item' else 1):raise StopIteration
            return Check()
        def __del__(self):event('iterator-del')
    class Checks:
        def __iter__(self):event('iter');return Iterator()
    class Store:
        def get_json(self,ref,**kwargs):return {'required_claims':['core_admission']},None
    class Service:
        store=Store()
        def _native(self,*args,**kwargs):return b'',{'candidate':'candidate','machine_plan':None},None
        def _verification(self,*args,**kwargs):return {'checks':Checks(),'subject':{'kind':'core'}}
    service=Service();context={'ref':'ctx','objective':'objective'}
    def call():
        if native:return image.run('_required_claims',service,context,'artifact',['receipt'],None,None)
        return REFERENCE['_required_claims'](service,context,'artifact',['receipt'])
    return _run_observation(call,trace,outer)
