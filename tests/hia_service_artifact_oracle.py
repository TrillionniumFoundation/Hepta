"""Independent frozen artifact observer; a candidate factory supplies no expectation."""
from __future__ import annotations

import argparse
import ast
import builtins
import gc
from hashlib import sha256
import importlib.abc
import json
from pathlib import Path
import platform
import sys
import types
import warnings
import weakref


ROOT = Path(__file__).resolve().parent/'fixtures/hia_service_artifact_original_5bf'
ORIGINAL = ROOT/'artifact.5bf.py.txt'
PROFILE = ROOT/'profile.5bf.py.txt'
ORIGINAL_SHA = 'a1a85bb10bc4a56f1d145372dca122005586108a50f7a07fa13678d9432503d8'
PROFILE_SHA = '0adeac9e1bf6164386db92d0a24fef3a8e083b39e027fe3063926ba1e14aeb3c'
DIGEST = 'd'*64
LATE = []
GLOBAL_PHASE = 'setup'


def canonical(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',',':'))+'\n').encode()


class NoProduct(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'hepta' or fullname.startswith('hepta.') or fullname == 'tools' or fullname.startswith('tools.'):
            raise AssertionError('original-only observer imported product: '+fullname)


def no_effect(event, arguments):
    if event in {'subprocess.Popen','os.system','sqlite3.connect','ctypes.dlopen',
                 'ctypes.dlsym','socket.__new__','os.fork','os.forkpty'} or event.startswith('os.exec'):
        raise AssertionError('original-only provider attempted effect: '+event)


def frozen_code(path, expected, name):
    raw = path.read_bytes()
    assert sha256(raw).hexdigest() == expected
    text = 'class Original:\n'+raw.decode()
    ns = {}
    exec(compile(text, str(path), 'exec', dont_inherit=True), ns)
    return vars(ns['Original'])[name].__code__


ARTIFACT_CODE = frozen_code(ORIGINAL, ORIGINAL_SHA, '_hia_artifact')
PROFILE_CODE = frozen_code(PROFILE, PROFILE_SHA, '_profile')


class Namespace(dict):
    pass


class Harness:
    def __init__(self, case):
        self.case = case
        self.events = []
        self.tags = {}
        self.refs = {}
        self.serials = {}
        self.error_ids = {}
        self.phase = 'setup'
        self.closed = False
        self.namespace = None
        self.service = None
        self.store_lookups = 0
        self.faults = 0
        self.actual_puts = 0

    def tag(self, obj, label):
        self.tags[id(obj)] = label
        try:
            self.refs[label] = weakref.ref(obj)
        except TypeError:
            pass
        return obj

    def new_label(self, kind):
        n = self.serials.get(kind, 0)+1
        self.serials[kind] = n
        return kind+str(n)

    def view(self, obj):
        typ = type(obj)
        if typ in (str, int, bool, type(None), float):
            return obj
        if typ is bytes:
            return {'bytes':builtins.len(obj),'sha256':sha256(obj).hexdigest()}
        label = self.tags.get(id(obj))
        if label is not None:
            return {'object':label,'type':typ.__name__}
        if typ in (tuple,list):
            return [self.view(x) for x in obj]
        if typ is dict:
            return {str(k):self.view(v) for k,v in obj.items()}
        return {'type':typ.__name__}

    def active(self):
        error = sys.exception()
        if error is None:
            return None
        return self.error_ids.get(id(error), type(error).__name__)

    def note(self, event, **values):
        item = {'event':event,'phase':self.phase,'active_exception':self.active(),
                **{key:self.view(value) for key,value in values.items()}}
        if self.closed:
            LATE.append({'case':self.case['id'],'observer_phase':GLOBAL_PHASE,**item})
        else:
            self.events.append(item)

    def make_error(self, point):
        cls = getattr(builtins, self.case.get('error_type','ValueError'))
        error = cls('fault:'+point)
        self.error_ids[id(error)] = 'fault:'+point
        return error

    def hit(self, point, **values):
        self.note(point, **values)
        if self.case.get('fault') == point:
            self.faults += 1
            raise self.make_error(point)

    def data(self):
        if self.case.get('fake_data', True):
            return Data(self)
        text = self.case.get('text','alpha')
        return text.encode('utf-8')

    def profile(self, ref, name):
        self.hit('profile.call', ref=ref, name=name)
        if self.case.get('latebind') == 'profile_capture':
            self.namespace()['capture_path'] = self.capture_rebound
        if self.case.get('profile_temporary'):
            return Temporary(self,'profile-result')
        return None

    def capture(self, path, roots, maximum):
        self.hit('capture.call', path=path, roots=roots, maximum=maximum)
        if self.case.get('latebind') == 'capture_hash':
            self.namespace()['sha256'] = self.hash_rebound
        return self.data()

    def capture_rebound(self, *args):
        self.note('capture.rebound')
        return self.capture(*args)

    def hash(self, data):
        self.hit('hash.call', data=data)
        return HashResult(self)

    def hash_rebound(self, data):
        self.note('hash.rebound')
        return self.hash(data)

    def reject(self, code, message):
        self.hit('reject.call', code=code, message=message)
        if not self.case.get('reject_returns'):
            raise self.rejection(code,message)
        return Temporary(self,'reject-result')

    def rejection(self,code,message):
        error = ValueError(code+':'+message)
        self.error_ids[id(error)] = 'digest-rejected'
        return error

    def to_int(self, value):
        self.hit('int.call', value=value)
        return builtins.int(value)

    def length(self, data):
        self.hit('len.call', data=data)
        if self.case.get('latebind') == 'len_str':
            self.namespace()['str'] = self.string_rebound
        return builtins.len(data)

    def length_rebound(self, data):
        self.note('len.rebound')
        return self.length(data)

    def string(self, value):
        self.hit('str.call', value=value)
        return self.case.get('str_result',builtins.str(value))

    def string_rebound(self, value):
        self.note('str.rebound')
        return self.string(value)

    def put(self, data, kind, receiver):
        self.actual_puts += 1
        self.hit('store.put.call', data=data, kind=kind, receiver=receiver)
        if self.case.get('latebind') == 'put_len':
            self.namespace()['len'] = self.length_rebound
        if self.case['store_mode'] == 'replace-during-put':
            service = self.service()
            service._stored = Store(self, 'replacement')
            self.note('store.replaced-on-service')
        return Reference(self)


class TraceMap:
    def __init__(self, h, name, values):
        self.h, self.name, self.values = h,name,values
        h.tag(self,name)

    def __getitem__(self, key):
        self.h.hit(self.name+'.get.'+key)
        return self.values[key]


class Truth:
    def __init__(self,h,name,value):
        self.h,self.name,self.value=h,name,value
        h.tag(self,name+'-truth')

    def __bool__(self):
        self.h.hit(self.name+'.truth')
        if self.value == 'bad':
            return 'not-bool'
        return self.value != 'false'

    def __del__(self):
        self.h.note(self.name+'.truth.delete')


class Kind:
    def __init__(self,h):
        self.h=h;h.tag(self,'kind')

    def __eq__(self,other):
        self.h.hit('kind.eq',other=other)
        mode=self.h.case['kind_comparison']
        if mode=='notimplemented':return NotImplemented
        return Truth(self.h,'kind',mode)


class Expected:
    def __init__(self,h):
        self.h=h;h.tag(self,'expected')

    def __ne__(self,other):
        self.h.hit('expected.ne',other=other)
        mode=self.h.case['expected_comparison']
        if mode=='notimplemented':return NotImplemented
        return Truth(self.h,'expected',mode)


class Text:
    def __init__(self,h):
        self.h=h;h.tag(self,'text')

    def __getattribute__(self,name):
        if name=='encode':object.__getattribute__(self,'h').hit('text.encode.lookup')
        return object.__getattribute__(self,name)

    def encode(self,encoding):
        self.h.hit('text.encode.call',encoding=encoding)
        return self.h.data()


class Maximum:
    def __init__(self,h):
        self.h=h;h.tag(self,'maximum')

    def __int__(self):
        self.h.hit('max.__int__')
        return self.h.case.get('int_result',self.h.case.get('maximum',4096))


class Data:
    def __init__(self,h):
        self.h=h;h.tag(self,'data')

    def __len__(self):
        self.h.hit('data.__len__')
        return self.h.case.get('length',5)

    def __del__(self):
        self.h.note('data.delete')


class Temporary:
    def __init__(self,h,name):
        self.h,self.name=h,name;h.tag(self,name)

    def __bool__(self):
        self.h.note(self.name+'.unexpected-truth')
        raise AssertionError('ignored result was tested')

    def __del__(self):
        self.h.note(self.name+'.delete')


class HashResult:
    def __init__(self,h):self.h=h;h.tag(self,'hash-result')

    def __getattribute__(self,name):
        if name=='hexdigest':object.__getattribute__(self,'h').hit('hash.hexdigest.lookup')
        return object.__getattribute__(self,name)

    def hexdigest(self):
        self.h.hit('hash.hexdigest.call')
        return DIGEST

    def __del__(self):self.h.note('hash-result.delete')


class Reference:
    def __init__(self,h):self.h=h;h.tag(self,'issued-reference')
    def __del__(self):self.h.note('issued-reference.delete')


class PutCallable:
    def __init__(self,h,store,retained):
        self.h,self.label=h,h.tags[id(store)]
        self.store=store if retained else None
        h.tag(self,'put-callable')
        h.note('put-callable.create',retained_receiver=retained)

    def __call__(self,data,kind):
        return self.h.put(data,kind,self.label)

    def __del__(self):
        self.h.note('put-callable.delete')


class ProfileCallable:
    def __init__(self,h):self.h=h;h.tag(self,'profile-callable')
    def __call__(self,ref,name):return self.h.profile(ref,name)
    def __del__(self):self.h.note('profile-callable.delete')


class Store:
    def __init__(self,h,role='store'):
        self.h,self.label=h,h.new_label(role)
        h.tag(self,self.label);h.note('store.create',receiver=self.label)

    def __getattribute__(self,name):
        if name=='put':
            h=object.__getattribute__(self,'h')
            h.hit('store.put.lookup',receiver=object.__getattribute__(self,'label'))
            mode=h.case['put_mode']
            if mode!='method':return PutCallable(h,self,mode=='bound-callable')
        elif name=='check_profile':
            h=object.__getattribute__(self,'h')
            h.note('store.check_profile.lookup',receiver=object.__getattribute__(self,'label'))
        return object.__getattribute__(self,name)

    def put(self,data,kind):return self.h.put(data,kind,self.label)

    def check_profile(self,ref,expected):
        self.h.note('store.check_profile.call',receiver=self.label,ref=ref,expected=expected)
        return None

    def __del__(self):self.h.note('store.delete',receiver=self.label)


class StoreDescriptor:
    def __get__(self,instance,owner):
        if instance is None:return self
        h=object.__getattribute__(instance,'_h')
        h.note('store.descriptor.get')
        return Store(h)


class Service:
    def __init__(self,h):
        self._h=h
        self._stored=Store(h) if h.case['store_mode'] in ('persistent','replace-during-put') else None
        self._profiles=TraceMap(h,'profiles',{'artifact':'expected-profile'})
        h.tag(self,'service');h.service=weakref.ref(self)

    def __getattribute__(self,name):
        if name in ('_profile','store','artifact_roots','profiles'):
            h=object.__getattribute__(self,'_h')
            point='profile.lookup' if name=='_profile' else 'service.'+name
            h.hit(point)
            if name=='_profile':
                if h.case['profile_mode']=='callable':return ProfileCallable(h)
                if h.case['profile_mode']=='original':
                    return types.MethodType(types.FunctionType(PROFILE_CODE,h.namespace()),self)
            if name=='store':
                h.store_lookups+=1
                mode=h.case['store_mode']
                if mode=='descriptor':return object.__getattribute__(self,name)
                if mode in ('temporary','changing'):return Store(h)
                return object.__getattribute__(self,'_stored')
            if name=='artifact_roots':return ('ADMIN_ROOT_TOKEN',)
            if name=='profiles':return object.__getattribute__(self,'_profiles')
        return object.__getattribute__(self,name)

    def _profile(self,ref,name):return self._h.profile(ref,name)


class DescriptorService(Service):
    store=StoreDescriptor()


def namespace(h):
    result=Namespace(capture_path=h.capture,sha256=h.hash,reject=h.reject)
    functions={'int':h.to_int,'len':h.length,'str':h.string}
    result['__builtins__']=dict(vars(builtins))
    if h.case.get('builtins_fallback'):result['__builtins__'].update(functions)
    else:result.update(functions)
    h.namespace=weakref.ref(result)
    return result


def arguments(h):
    case=h.case
    kind=case['source_kind'] if case['kind_comparison']=='plain' else Kind(h)
    text=Text(h) if case['fake_text'] else case.get('text_repeat','')*case.get('text_count',0) or case['text']
    expected=case['expected']
    if expected is not None:
        expected=DIGEST if expected=='match' else 'x'*64
        if case['expected_comparison']!='plain':expected=Expected(h)
    source=TraceMap(h,'source',dict(kind=kind,text=text,path='/ADMIN_ROOT_TOKEN/input',
        max_bytes=Maximum(h) if case['fake_int'] else case.get('maximum',4096),expected_sha256=expected))
    return TraceMap(h,'args',{'artifact_profile':'profile-reference','source':source})


def error_record(h,error,seen=None):
    seen=set() if seen is None else seen
    if id(error) in seen:return {'cycle':type(error).__name__}
    seen.add(id(error))
    get=BaseException.__getattribute__
    value={'type':type(error).__name__,'identity':h.error_ids.get(id(error)),
           'args':h.view(get(error,'args')),'suppress_context':get(error,'__suppress_context__')}
    for name in ('name','obj'):
        try:item=get(error,name)
        except AttributeError:continue
        value[name]=h.view(item)
    for name in ('__cause__','__context__'):
        other=get(error,name)
        value[name]=None if other is None else error_record(h,other,seen)
    return value


def invoke(h,fn,service,args):
    try:
        value=fn(service,args)
    except BaseException as error:
        h.phase='caller-exception'
        return {'status':'raised','error':error_record(h,error)}
    else:
        h.phase='caller-result'
        return {'status':'returned','value':h.view(value)}


def original_factory(namespace):
    return types.FunctionType(ARTIFACT_CODE, namespace)


def observe(case, *, factory=original_factory):
    h=Harness(case)
    ns=namespace(h)
    fn=factory(ns)
    service=(DescriptorService if case['store_mode']=='descriptor' else Service)(h)
    args=arguments(h)
    h.phase='call'
    if case['outer']:
        try:
            error=KeyError('outer-error')
            h.error_ids[id(error)]='outer-error'
            raise error
        except KeyError:
            del error
            outcome=invoke(h,fn,service,args)
            h.note('caller.outer-after')
    else:
        outcome=invoke(h,fn,service,args)
    h.phase='caller-input-release'
    del service,args,fn,ns
    if case['explicit_gc']:
        h.phase='explicit-gc'
        collected=gc.collect()
        h.note('observer.gc',collected=collected)
    record={'case':case['id'],'outcome':outcome,'trace':h.events,
            'faults_reached':h.faults,'actual_puts':h.actual_puts,'store_lookups':h.store_lookups,
            'weakly_observed_alive':{name:ref() is not None for name,ref in sorted(h.refs.items())}}
    # Freeze by value before any later collection can append to the old trace.
    raw=canonical(record)
    h.closed=True
    return json.loads(raw)


def cases():
    return json.loads((ROOT/'cases.json').read_bytes())['cases']
