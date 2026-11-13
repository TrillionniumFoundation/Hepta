"""Retained V76 reference and independent controlled-port observations.

The fixture source is fixed by a SHA recorded before the owner existed. Native
tests pass the actual HIA owner; controlled providers remain explicitly marked.
"""
from __future__ import annotations
import ctypes,hashlib,json,re,sys,tempfile,weakref
from pathlib import Path
from types import SimpleNamespace,FunctionType
from unittest.mock import patch
from hepta import hia_agent_service as api
from hepta import hia_program_native as provider
from hepta import hia_native_byte_abi as abi
from hepta.hia_service_emission_native import NativeEmissionService

ORIGINAL=Path(__file__).with_name('fixtures')/'hia_service_emission_original_v76.json'
ORIGINAL_SHA='eb80552042f9e2399e4182c2110fca22669157f04d0dfb78838eb481cd893d95'

def original_functions():
    raw=ORIGINAL.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=ORIGINAL_SHA: raise AssertionError('retained emission reference differs')
    result={}
    for name,value in json.loads(raw)['functions'].items():
        namespace=dict(vars(api))
        exec(compile(value['source'],str(ORIGINAL),'exec'),namespace)
        captured=namespace[name]
        # The original body resolves providers through its live module globals.
        # Retain its exact code while using that same dictionary, so explicit
        # controlled-provider patches reach reference and native paths alike.
        retained=FunctionType(captured.__code__,vars(api),name,captured.__defaults__,captured.__closure__)
        retained.__kwdefaults__=captured.__kwdefaults__
        result[name]=retained
    return result

REFERENCE=original_functions()
def compile_fixture(phase, suppress=False, outer=False, *, implementation=None):
    implementation=REFERENCE["_compile"] if implementation is None else implementation
    trace = []
    error = LookupError('original-' + phase)
    def handled():
        value = sys.exception()
        return None if value is None else [type(value).__name__, str(value)]
    class Binding:
        def __init__(self, kind, manager):
            self.kind, self.manager = kind, manager
        def __call__(self, *args):
            trace.append(['call', self.kind, handled()])
            if self.kind == 'enter':
                if phase == 'enter':
                    raise error
                return self.manager.directory
            typ, value, tb = args
            trace.append(['exit-error', None if value is None else type(value).__name__,
                          value is error, tb is None if value is None else tb is value.__traceback__])
            if phase == 'exit':
                raise error
            return suppress
        def __del__(self):
            trace.append(['drop-binding', self.kind, handled()])
    class Descriptor:
        def __init__(self, kind): self.kind = kind
        def __get__(self, manager, cls):
            trace.append(['bind', self.kind, handled()])
            return Binding(self.kind, manager)
    class Manager:
        __enter__ = Descriptor('enter')
        __exit__ = Descriptor('exit')
        def __init__(self, *, prefix, dir):
            trace.append(['manager', prefix, str(dir), handled()])
            self.directory = str(dir)
        def __del__(self): trace.append(['drop-manager', handled()])
    program = SimpleNamespace(sha256='a' * 64)
    image = SimpleNamespace(object_bytes=b'OBJ')
    class Store:
        def __init__(self, root): self.root = root
        def put(self, data, kind, metadata):
            trace.append(['put', kind, data.hex(), metadata, handled()])
            return {'sha256': hashlib.sha256(data).hexdigest(), 'kind': kind}
    def emit(*args, **kwargs):
        trace.append(['emit', handled()])
        if phase == 'emit': raise error
        return image
    def compile(image, *, output, **kwargs):
        trace.append(['compile', output.name, kwargs['timeout_seconds'], handled()])
        if phase == 'compile': raise error
        if phase != 'read': output.write_bytes(b'OBJ')
        return {'output': str(output), 'object_sha256': hashlib.sha256(b'OBJ').hexdigest(),
            'core_sha256': program.sha256, 'artifact_sha256': hashlib.sha256(b'OBJ').hexdigest(),
            'machine_plan_sha256': 'b' * 64}
    with tempfile.TemporaryDirectory(prefix='emission-original-') as directory:
        service = SimpleNamespace(store=Store(Path(directory)), identities={'frozen': 'identity'})
        clocks = iter((1.25, 1.5))
        def clock():
            trace.append(['clock', handled()])
            return next(clocks)
        held = result = None
        with patch.object(provider, 'emit_program_machine', emit), \
             patch.object(provider, 'compile_program_machine', compile), \
             patch.object(api.tempfile, 'TemporaryDirectory', Manager), \
             patch.object(api.time, 'monotonic', clock):
            def call():
                return implementation(service, program, 'object', None, 1000)
            try:
                if outer:
                    try: raise ArithmeticError('outer')
                    except ArithmeticError: result = call()
                else:
                    result = call()
            except BaseException as exc:
                held = exc
            outcome = ({'returned': [result[0].hex(), result[1]]} if held is None else
                {'raised': type(held).__name__, 'message': str(held), 'same_original': held is error,
                 'cause': None if held.__cause__ is None else [type(held.__cause__).__name__, str(held.__cause__)],
                 'context': None if held.__context__ is None else [type(held.__context__).__name__, str(held.__context__)]})
        # Only normalizes an observer-owned nondeterministic filesystem name.
        for item in trace:
            if item[:1] == ['manager']:
                item[2] = '<original-temporary-root>'
        return {'phase': phase, 'suppress': suppress, 'outer': outer,
                'trace': trace, 'outcome': outcome}

def signature_fixture(implementation,params,returns,scalar,exports,*,fault=None,outer=False):
    trace=[];weak=[];held=None
    original_error=StopIteration('signature-stop') if fault=='stop' else None
    def handled():
        error=sys.exception()
        return None if error is None else [type(error).__name__,str(error)]
    class Parameter(dict):
        def __del__(self):trace.append(['parameter-del',handled()])
    class FaultType(str):
        def __hash__(self):
            trace.append(['type-hash',handled()]);raise original_error
    class Parameters:
        def __iter__(self):
            trace.append(['parameters-iter',handled()])
            class Iterator:
                def __init__(self):self.done=False
                def __iter__(self):return self
                def __next__(self):
                    if self.done:raise StopIteration
                    self.done=True
                    p=Parameter({} if fault=='missing' else {'type':FaultType('i32')})
                    weak.append(weakref.ref(p));return p
                def __del__(self):trace.append(['parameters-iterator-del',handled()])
            return Iterator()
    class Fields(dict):
        def __getitem__(self,key):
            trace.append(['field',key,handled()]);return super().__getitem__(key)
    fn=Fields(name='f0',params=Parameters() if fault else [{'type':v} for v in params],returns=returns)
    document=Fields(functions=[fn])
    class Program:
        def as_dict(self):trace.append(['as_dict',handled()]);return document
        @property
        def scalar_entrypoints(self):trace.append(['scalar_entrypoints',handled()]);return scalar
    program=Program()
    def normalize(values,actual):
        trace.append(['normalize_exports',values is exports,actual is program,handled()]);return exports
    result=None
    with patch.object(abi,'normalize_exports',normalize):
        try:
            if outer:
                try:raise ArithmeticError('outer')
                except ArithmeticError:result=implementation(program,exports)
            else:result=implementation(program,exports)
        except BaseException as error:held=error
    outcome=({'returned':result,'returns_alias':('f0' not in result or result['f0']['returns'] is returns)}
             if held is None else {'raised':type(held).__name__,'message':str(held),
                'same_original':held is original_error,
                'cause':None if held.__cause__ is None else [type(held.__cause__).__name__,str(held.__cause__)],
                'context':None if held.__context__ is None else [type(held.__context__).__name__,str(held.__context__)]})
    return {'outcome':outcome,'trace':[list(row) for row in trace],
            'parameters_alive_while_exception_held':[r() is not None for r in weak]}

def emit_fixture(selected,image,case,outer=False):
    trace=[];weak=[];error=None;owner=None
    def handled():
        e=sys.exception();return None if e is None else [type(e).__name__,str(e)]
    class Truth:
        def __init__(self):self.count=0
        def __bool__(self):
            self.count+=1;trace.append(['truth',self.count,handled()]);return self.count==2
        def __del__(self):trace.append(['truth-del',handled()])
    class Claim:
        def __eq__(self,other):trace.append(['claim-eq',other,handled()]);return Truth()
    class Check(dict):
        def __getitem__(self,key):
            trace.append(['check-field',key,handled()])
            if case=='stop' and key=='claim':raise StopIteration('check-stop')
            return super().__getitem__(key)
        def __del__(self):trace.append(['check-del',handled()])
    class Checks:
        def __iter__(self):
            trace.append(['checks-iter',handled()])
            class Iterator:
                def __init__(self):self.done=False
                def __next__(self):
                    if self.done:raise StopIteration
                    self.done=True
                    value=Check({} if case=='missing' else {'claim':Claim() if case=='truth' else 'lowering_refinement','status':'proved'})
                    weak.append(weakref.ref(value));return value
                def __iter__(self):return self
                def __del__(self):trace.append(['checks-iterator-del',handled()])
            return Iterator()
    class Fields(dict):
        def __getitem__(self,key):trace.append(['field',key,handled()]);return super().__getitem__(key)
    args=Fields(backend_profile='backend',context='context',candidate='candidate',verification_receipts=['vr1'],
                output_kind='shared',codegen=Fields(kind='canonical' if case=='canonical' else 'plan',lowering_profile='lowering',plan_profile='plan-profile',plan='plan-ref',verification_receipt='vr-plan'))
    context=Fields(target_profile='target',foreign_buffer_exports=[])
    program=SimpleNamespace(sha256='core',scalar_entrypoints=set(),as_dict=lambda:{'functions':[]})
    receipt=Fields(subject={'kind':'agent_machine_plan','backend_profile':'backend','plan_profile':'plan-profile','plan':'plan-ref'},checks=Checks())
    class Store:
        def get_json(self,ref):trace.append(['get_json',ref,handled()]);return {'plan':1},None
        def put(self,data,kind,metadata):
            trace.append(['put',kind,handled()])
            if case=='put-error':raise OSError('publish')
            return {'kind':kind,'sha256':'published'}
        def json(self,document,kind):
            trace.append(['json',kind,handled()])
            if case=='receipt-error':raise OSError('receipt')
            return {'kind':kind}
    class Service:
        def __init__(self):self.store=Store();self.identities={'installed':'id'}
        def _profile(self,ref,kind):trace.append(['profile',ref,kind,handled()])
        def _context(self,ref):trace.append(['context',ref,handled()]);return context
        def _program(self,ref):trace.append(['program',ref,handled()]);return program
        def _verification(self,ref,*rest):trace.append(['verification',ref,handled()]);return receipt
        def _remaining_ms(self,ctx):trace.append(['remaining',ctx is context,handled()]);return 10
        def _compile(self,*args,**kwargs):
            trace.append(['compile',args[0] is program,args[1:],kwargs,handled()])
            return b'ELF',{'object_artifact':{'kind':'build-object'},'object_sha256':'object'}
    service=Service()
    if selected:owner=NativeEmissionService(service,image);implementation=owner.emit
    else:implementation=lambda args:REFERENCE['_hia_emit'](service,args)
    def validate(value,schema,where):trace.append(['validate',where,handled()])
    result=None
    with patch.object(api,'validate',validate),patch.object(abi,'normalize_exports',lambda value,p:value):
        try:
            if outer:
                try:raise LookupError('outer')
                except LookupError:result=implementation(args)
            else:result=implementation(args)
        except BaseException as e:error=e
    outcome=({'returned':result} if error is None else {'raised':type(error).__name__,'message':str(error),
        'cause':None if error.__cause__ is None else [type(error.__cause__).__name__,str(error.__cause__)],
        'context':None if error.__context__ is None else [type(error.__context__).__name__,str(error.__context__)]})
    return {'outcome':outcome,'trace':trace.copy(),'held_checks':[w() is not None for w in weak]},owner

def stable(value):
    if type(value) is str:return re.sub(r'/tmp/emission-original-[^/\s\'\"]+', '<original-temporary-root>',value)
    if type(value) is list:return [stable(v) for v in value]
    if type(value) is dict:return {k:stable(v) for k,v in value.items()}
    return value
