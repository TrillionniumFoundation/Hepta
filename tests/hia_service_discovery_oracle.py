"""Independent discovery original-body observer; import executes no body."""
from __future__ import annotations
import builtins
import gc
from hashlib import sha256
import json
from pathlib import Path
import sys
import traceback
import types
import weakref

ORIGINALS = Path(__file__).resolve().parent / 'fixtures/hia_service_discovery_original_r5'
PINNED = {
    '_hia_describe.py.txt': 'bfed8acb543c9234c553c3e01ff37bfa24233c1a8b57adae3215a2839fc6c481',
    '_examples.py.txt': '0bae19c39caede740a899a13503cf14d23b248c76fc793746f9a29d46d10c3e1',
    'AgentRejected.py.txt': '30dc9ad1340152ba28445b2138a354eeaf1f0f6edafb94573c45914665acf21b',
    'reject.py.txt': '5bc1a0a02aa8057d238a45db3b612d8efd573ecb02be4a017927a19bacca02a6',
}
ERRORS = {x.__name__: x for x in (ValueError, TypeError, AttributeError, RuntimeError,
          OSError, OverflowError, MemoryError, StopIteration, KeyboardInterrupt, SystemExit)}
_CODE = None
_DEFINITIONS = None

def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode()

def original_namespace():
    global _CODE, _DEFINITIONS
    pieces = {}
    for name, digest in PINNED.items():
        raw = (ORIGINALS / name).read_bytes()
        if sha256(raw).hexdigest() != digest:
            raise ValueError('discovery original identity differs: ' + name)
        pieces[name] = raw.decode()
    if _CODE is None:
        text = pieces['AgentRejected.py.txt'] + '\n' + pieces['reject.py.txt']
        # Remove only class indentation and the staticmethod binding decorator;
        # the exact pinned business statements and function signatures remain.
        import textwrap
        describe = textwrap.dedent(pieces['_hia_describe.py.txt'])
        examples = textwrap.dedent(pieces['_examples.py.txt'])
        if not examples.startswith('@staticmethod\n'):
            raise ValueError('original examples binding differs')
        text += '\n' + describe + '\n' + examples[len('@staticmethod\n'):]
        _CODE = compile(text, str(ORIGINALS / 'independent-originals.py'), 'exec')
    if _DEFINITIONS is None:
        # Fixed definition objects remain module-owned. The per-case namespace
        # never stores its own business functions, so the observer does not add
        # a function -> globals -> function garbage cycle after every case.
        definitions = {'__builtins__': dict(vars(builtins)),
                       '__name__': 'hepta.hia_agent_service', '__package__': 'hepta'}
        exec(_CODE, definitions)
        _DEFINITIONS = definitions
    return {'__builtins__': dict(vars(builtins)),
            '__name__': 'hepta.hia_agent_service', '__package__': 'hepta',
            'AgentRejected': _DEFINITIONS['AgentRejected'],
            'reject': _DEFINITIONS['reject']}


def original_function(namespace, mode):
    name = '_hia_describe' if mode == 'describe' else '_examples'
    # The code was obtained only from the complete pinned original text.
    return types.FunctionType(_DEFINITIONS[name].__code__, namespace, name)

def role(value):
    if value is None or type(value) in (bool, int, float, str):
        return value
    if type(value) is bytes:
        return {'bytes': value.hex()}
    if isinstance(value, Token):
        return object.__getattribute__(value, 'tag')
    if type(value) in (tuple, list):
        return [role(x) for x in value]
    if type(value) is dict:
        return {str(k):role(v) for k,v in value.items()}
    return {'type': type(value).__module__+'.'+type(value).__qualname__}

def error_fields(error, world, seen=None):
    if error is None:
        return None
    if seen is None:
        seen=set()
    if id(error) in seen:
        return {'cycle_to_live_exception': True}
    seen.add(id(error))
    result={'type':type(error).__module__+'.'+type(error).__qualname__,
        'args':role(error.args),'text':str(error),
        'same_injected':error is world.fault,'same_outer':error is world.outer,
        'name':role(getattr(error,'name',None)), 'obj':role(getattr(error,'obj',None)),
        'code':role(getattr(error,'code',None)), 'phase':role(getattr(error,'phase',None)),
        'retry_action':role(getattr(error,'retry_action',None)),
        'suppress_context':error.__suppress_context__}
    result['cause']=error_fields(error.__cause__,world,seen)
    result['context']=error_fields(error.__context__,world,seen)
    return result

class Token:
    def __init__(self, world, name):
        self.world=weakref.ref(world)
        self.tag=world.token(name,self)
    def __del__(self):
        world=self.world()
        if world is not None:
            world.record('delete',self.tag)

class Truth(Token):
    def __init__(self,world,value,label):
        super().__init__(world,'truth.'+label)
        self.value,self.label=value,label
    def __bool__(self):
        world=self.world()
        world.hit(self.label+'.bool.before')
        result=self.value
        world.hit(self.label+'.bool.after',result)
        return result

class Identity(Token):
    def __init__(self,world,name,value):
        super().__init__(world,name)
        self.value,self.label=value,name
    def __ne__(self,other):
        world=self.world()
        world.hit(self.label+'.ne.before',role(other))
        result=self.value != (other.value if isinstance(other,Identity) else other)
        result=Truth(world,result,self.label+'.ne')
        world.hit(self.label+'.ne.after',role(result))
        return result

class Mapping(Token):
    def __init__(self,world,name,values):
        super().__init__(world,name)
        self.label,self.values=name,values
    def __getitem__(self,key):
        world=self.world()
        world.hit(self.label+'.getitem.'+str(key)+'.before')
        value=self.values[key]
        world.hit(self.label+'.getitem.'+str(key)+'.after',role(value))
        return value

class Arguments(Mapping):
    def __contains__(self,key):
        world=self.world()
        world.hit('args.contains.'+key+'.before')
        value=key in self.values
        result=Truth(world,value,'args.contains.'+key)
        world.hit('args.contains.'+key+'.after',role(result))
        return result
    def get(self,key,default=None):
        world=self.world()
        world.hit('args.get.'+key+'.before',role(default))
        value=self.values.get(key,default)
        world.hit('args.get.'+key+'.after',role(value))
        return value

class Section(Token):
    def __init__(self,world,value):
        super().__init__(world,'section')
        self.value=value
    def __hash__(self):
        world=self.world()
        world.hit('section.hash.before')
        value=hash(self.value)
        world.hit('section.hash.after')
        return value
    def __eq__(self,other):
        world=self.world()
        world.hit('section.eq.before',role(other))
        value=self.value==other
        world.hit('section.eq.after',value)
        return value

class ProfileResult(Token):
    def __init__(self,world):
        super().__init__(world,'profile-result')
        self.values=[Token(world,'language-profile'),Token(world,'language-ref')]
    def __iter__(self):
        world=self.world()
        world.hit('profile-result.iter.before')
        value=ProfileIterator(world,self.values)
        world.hit('profile-result.iter.after')
        return value

class ProfileIterator(Token):
    def __init__(self,world,values):
        super().__init__(world,'profile-iterator')
        self.values=list(values);self.index=0
    def __iter__(self):
        return self
    def __next__(self):
        world=self.world()
        world.hit('profile-iterator.next.'+str(self.index)+'.before')
        if self.index >= len(self.values):
            raise StopIteration
        value=self.values[self.index];self.index+=1
        world.hit('profile-iterator.next.'+str(self.index-1)+'.after',role(value))
        return value

class ProfileBinding(Token):
    def __init__(self,world,store):
        super().__init__(world,'profile-callable')
        self.store=None if world.case.get('detached_profile') else store
    def __call__(self,schema,language):
        world=self.world()
        world.hit('store.profile.call.before',[role(schema),role(language)])
        value=ProfileResult(world)
        adjustment=world.case.get('profile_items')
        if adjustment==1:
            value.values.pop()
        elif adjustment==3:
            value.values.append(Token(world,'extra-profile-item'))
        world.hit('store.profile.call.after')
        return value

class Store(Token):
    def __getattribute__(self,name):
        if name!='profile':
            return object.__getattribute__(self,name)
        world=object.__getattribute__(self,'world')()
        world.hit('store.profile.lookup.before')
        value=ProfileBinding(world,self)
        world.hit('store.profile.lookup.after')
        return value

class Service(Token):
    WATCHED=('store','manifest','resources','profile_artifacts','profiles','catalog_sha256')
    def __init__(self,world):
        super().__init__(world,'service')
        resources={key:Token(world,'resource.'+key) for key in (
            'schema_registry','assembly_grammar','core_language','byte_bootstrap_guide',
            'self_hosting_core_guide','self_hosting_core_support','machine_validation_guide',
            'proof_contract_guide','buffer_lifecycle_guide','examples','diagnostics',
            'plan_schema','machine_plan_guide','macro_policy','macro_policy_guide')}
        profiles={'backend':Mapping(world,'backend-profile',{'id':'backend-id'}),
                  'artifact':Token(world,'artifact-profile')}
        self._values={'manifest':Token(world,'manifest'),
            'resources':Mapping(world,'resources',resources),
            'profile_artifacts':Mapping(world,'profile-artifacts',
                {key:Token(world,'profile-artifact.'+key) for key in ('backend','lowering','target','validation','plan')}),
            'profiles':Mapping(world,'profiles',profiles),'catalog_sha256':'c'*64}
        if not world.case.get('temporary_store'):
            self._values['store']=Store(world,'store')
        if world.case.get('missing_resource'):
            resources.pop(world.case['missing_resource'])
    def __getattribute__(self,name):
        if name not in Service.WATCHED:
            return object.__getattribute__(self,name)
        world=object.__getattribute__(self,'world')()
        world.hit('service.'+name+'.get.before')
        value=(Store(world,'temporary-store') if name=='store' and world.case.get('temporary_store')
               else object.__getattribute__(self,'_values')[name])
        world.hit('service.'+name+'.get.after',role(value))
        return value

class Program(Token):
    WATCHED=('sha256','as_dict')
    def __init__(self,world,name,digest):
        super().__init__(world,name)
        self.digest=digest
    def __getattribute__(self,name):
        if name not in Program.WATCHED:
            return object.__getattribute__(self,name)
        world=object.__getattribute__(self,'world')()
        label=object.__getattribute__(self,'tag').split('#')[0]
        world.hit(label+'.'+name+'.get.before')
        if name=='sha256':
            value=Identity(world,label+'.digest',object.__getattribute__(self,'digest'))
        else:
            value=AsDictBinding(world,self)
        world.hit(label+'.'+name+'.get.after',role(value))
        return value

class AsDictBinding(Token):
    def __init__(self,world,program):
        super().__init__(world,'as-dict-callable')
        self.program=None if world.case.get('detached_as_dict') else program
    def __call__(self):
        world=self.world()
        world.hit('program.as_dict.call.before')
        value={'frozen_core':'discovery', 'surrogate':'\ud800'} if world.case.get('plain_core') else Token(world,'core-result')
        world.hit('program.as_dict.call.after',role(value))
        return value

class World:
    def __init__(self,case):
        self.case=case
        self.events,self.hits,self.refs=[],[],{}
        self.sequence=0;self.phase='call';self.fired=0
        self.outer=RuntimeError('declared outer')
        family=case.get('fault',{}).get('family','ValueError')
        self.fault=ERRORS[family]('frozen fault')
        self.alias_observed=[]
    def active(self):
        error=sys.exception()
        if error is None:return None
        if error is self.fault:return 'injected'
        if error is self.outer:return 'outer'
        return type(error).__module__+'.'+type(error).__qualname__
    def record(self,name,value=None):
        self.events.append([name,role(value),self.phase,self.active()])
    def token(self,name,value):
        self.sequence+=1
        tag=name+'#'+str(self.sequence)
        self.refs[tag]=weakref.ref(value)
        self.record('create',tag)
        return tag
    def hit(self,label,value=None):
        index=len(self.hits)
        self.hits.append({'index':index,'label':label})
        self.record(label,value)
        fault=self.case.get('fault')
        matched=fault is not None and index==fault['index']
        if matched and label!=fault['label']:
            raise AssertionError('frozen discovery cutpoint differs')
        if matched or label==self.case.get('base_fault'):
            self.fired+=1
            if self.fired!=1:
                raise AssertionError('fault invoked more than once')
            raise self.fault
    def alive(self):
        return [name for name,ref in self.refs.items() if ref() is not None]
    def catalog(self,schema):
        self.hit('opcode_catalog.call.before',role(schema))
        value=Token(self,'language')
        self.hit('opcode_catalog.call.after',role(value))
        return value
    def verify(self,document):
        self.hit('verify_program.call.before',role(document))
        same=document['functions'][0]['params'] is document['functions'][0]['blocks'][0]['params']
        self.alias_observed.append(same)
        value=Program(self,'program','program-id')
        self.hit('verify_program.call.after',role(value))
        return value
    def render(self,program):
        self.hit('render_assembly.call.before',role(program))
        value=Token(self,'assembly')
        self.hit('render_assembly.call.after',role(value))
        return value
    def assemble(self,assembly):
        self.hit('assemble_program.call.before',role(assembly))
        value=Program(self,'roundtrip-program','different-id' if self.case.get('roundtrip_mismatch') else 'program-id')
        self.hit('assemble_program.call.after',role(value))
        return value
    def runtime_error(self,*args):
        self.hit('RuntimeError.call.before',role(args))
        value=RuntimeError(*args)
        self.hit('RuntimeError.call.after')
        return value
    def returning_reject(self,*args):
        self.hit('reject.override.before',role(args))
        self.hit('reject.override.after')
    def install(self,namespace):
        namespace['verify_program']=self.verify
        if self.case.get('reject_returns'):
            namespace['reject']=self.returning_reject
        if self.case.get('runtime_factory'):
            namespace['RuntimeError']=self.runtime_error
        providers={
            'hia_opcodes':types.SimpleNamespace(opcode_catalog=self.catalog),
            'hia_agent_assembly':types.SimpleNamespace(assemble_program=self.assemble,render_assembly=self.render)}
        builtin_namespace=dict(vars(builtins))
        def imported(name,globals=None,locals=None,fromlist=(),level=0):
            if name in providers and level==1:
                return providers[name]
            raise AssertionError('unexpected original import '+name)
        builtin_namespace['__import__']=imported
        namespace['__builtins__'].update(builtin_namespace)
        return providers
    def arguments(self):
        if self.case['mode']=='examples':
            return []
        args={'section':self.case.get('section','manifest')}
        if self.case.get('opaque_section'):
            args['section']=Section(self,args['section'])
        if self.case.get('cursor'):
            args['cursor']='arbitrary'
        backend=self.case.get('backend')
        if backend is not None:
            args['backend_profile']=Identity(self,'requested-backend',backend)
        if self.case.get('language'):
            args['language_schema']='hepta.hia.program.v6'
        return [Service(self),Arguments(self,'args',args)]

def observe(case,*,factory=None):
    world=World(case)
    namespace=original_namespace()
    providers=world.install(namespace)
    provider=original_function(namespace,case['mode'])
    if factory is not None:
        provider=factory(namespace,case['mode'],providers)
    arguments=world.arguments()
    value=None;outcome=None;retained=[];raw=[]
    def invoke():
        nonlocal value,outcome
        try:
            if case['mode']=='describe':
                value=provider(arguments.pop(0),arguments.pop(0))
            else:
                value=provider()
        except BaseException as error:
            outcome={'error':error_fields(error,world)}
            raw.append(traceback.format_exception(type(error),error,error.__traceback__))
            if case.get('retain_traceback'):
                retained.append(error)
        else:
            outcome={'return':role(value)}
    if case.get('outer'):
        try:
            raise world.outer
        except BaseException:
            invoke()
    else:
        invoke()
    at_return=json.loads(canonical({'events':world.events,'alive':world.alive(),'outcome':outcome}))
    world.phase='consumer-release'
    value=None;provider=None;arguments=None;providers=None;namespace=None
    retained.clear()
    collected=gc.collect() if case.get('explicit_gc') else None
    if case.get('fault') and world.fired!=1:
        raise AssertionError('declared discovery fault was not reached exactly once')
    row={'id':case['id'],'outcome':outcome,'at_return':at_return,
         'events':world.events,'hits':world.hits,'alive':world.alive(),
         'document_params_alias':world.alias_observed,'fault_count':world.fired,
         'explicit_gc_collected':collected}
    return json.loads(canonical(row)),raw
