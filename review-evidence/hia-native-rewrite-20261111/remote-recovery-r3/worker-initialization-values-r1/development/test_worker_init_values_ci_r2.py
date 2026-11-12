"""Actual initialization-value HIA projection against original Service methods.

The original _profiles/_examples methods produce the oracle outside native
intervals. Namespace publications are explicit deterministic foreign fixtures;
these tests do not claim ordinary initialization or namespace closure.
"""
from __future__ import annotations
import ast,copy,ctypes,json,os,resource,stat,struct,sys,time,traceback,zlib
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
WORK=Path(sys.argv[1]).resolve();COMPILE=Path(sys.argv[2]).resolve()
OUT=Path(sys.argv[3]).resolve();GROUP=sys.argv[4]
ROOT=WORK/'native-agent-initialization-next';REFERENCE=WORK/'Hepta-agent-edit-native'
RENDER=WORK/'native-agent-edit-render-next'
sys.path[:0]=[str(ROOT/'tools'),str(REFERENCE)]
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta import hia_agent_service as service
from hepta import hia_agent_store as store
import agent_worker_init_templates as templates
import generate_hia_agent_worker_init_values as generation
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
M=lambda b:int.from_bytes(b,'little')
pack=lambda *v:struct.pack('<'+'Q'*len(v),*v)
BAD=0xfffffffd;MAX=(1<<64)-1;CANARY=bytes(range(64));C=generation.CONSTANTS
COMPILER_SHA='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
OUT.mkdir(parents=True,exist_ok=False);(OUT/'cas').mkdir()
pins={};modes={};saved=set();images={};entries={k:0 for k in ('values','scan','emit')}
ledger=(OUT/'entries.jsonl').open('w');results=(OUT/'cases.jsonl').open('w')
capture=None;wire_errors=None;template=None;case_count=0;planned=0
completed_modes={mode:0 for mode in range(1,7)}
status='FAIL';failure=None;started=time.monotonic_ns()
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+'\n')
def cas(raw):
    raw=bytes(raw);identity=digest(raw);path=OUT/'cas'/(identity+'.zlib')
    if identity not in saved:
        path.write_bytes(zlib.compress(raw,1));assert zlib.decompress(path.read_bytes())==raw
        saved.add(identity)
    return dict(bytes=len(raw),sha256=identity,compression='zlib',path='cas/'+path.name)
def read(path):
    path=Path(path).resolve();raw=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
    if path in pins:assert pins[path]==raw and modes[path]==mode
    pins[path]=raw;modes[path]=mode;return raw
def rows():
    return [dict(path=str(p),bytes=len(raw),sha256=digest(raw),mode=modes[p])
        for p,raw in pins.items()]
def same():
    return all(p.is_file() and p.read_bytes()==raw and stat.S_IMODE(p.stat().st_mode)==modes[p]
        for p,raw in pins.items())
def disabled(*a,**k):
    raise AssertionError('old initialization/host template/wire owner used during native interval')
class Buffer:
    def __init__(self,n,raw=b''):
        raw=bytes(raw);assert 0<=len(raw)<=n
        self.n=n;self.buf=ctypes.create_string_buffer(n+128)
        ctypes.memmove(self.base,CANARY,64)
        if raw:ctypes.memmove(self.p,raw,len(raw))
        ctypes.memmove(self.p+n,CANARY,64)
    @property
    def base(self):return ctypes.addressof(self.buf)
    @property
    def p(self):return self.base+64
    def raw(self):return ctypes.string_at(self.p,self.n)
    def write(self,at,raw):
        raw=bytes(raw);assert 0<=at<=self.n and len(raw)<=self.n-at
        if raw:ctypes.memmove(self.p+at,raw,len(raw))
    def guard(self):
        assert ctypes.string_at(self.base,64)==CANARY
        assert ctypes.string_at(self.p+self.n,64)==CANARY
def invoke(role,s,t,w,label,advertised=None):
    n=w.n if advertised is None else advertised;assert 0<=n<=w.n
    sb,tb,wb=s.raw(),t.raw(),w.raw()
    save(OUT/'pending-native-entry.json',dict(role=role,label=label,entry=entries[role]+1,
        source_bytes=s.n,second_bytes=t.n,workspace_bytes=w.n,advertised_work=n,
        source_sha256=digest(sb),second_sha256=digest(tb),workspace_before_sha256=digest(wb)))
    result=int(images[role]._entry(s.p,s.n,t.p,t.n,w.p,n));entries[role]+=1
    assert s.raw()==sb and t.raw()==tb
    for view in (s,t,w):view.guard()
    ledger.write(json.dumps(dict(label=label,role=role,status=result,
        source=cas(sb),second=cas(tb),workspace_before=cas(wb),workspace_after=cas(w.raw()),
        advertised_work=n,input_and_canaries_unchanged=True),sort_keys=True)+'\n')
    ledger.flush();return result
def grow(w,n):
    assert n>w.n
    return Buffer(n,w.raw())
def decode_graph(raw,root=None):
    magic,lease,n,rootid,e,pool,total,zero=struct.unpack_from('<8Q',raw)
    assert magic==M(b'HIAGRF01') and lease and zero==0 and total==len(raw)
    edgebase=64+n*64;database=edgebase+e*8;assert total-database==pool
    memo={};active=set()
    def value(identifier):
        if identifier in memo:return memo[identifier]
        assert 1<=identifier<=n and identifier not in active
        active.add(identifier)
        kind,at,size,first,count,identity,aux,z=struct.unpack_from('<8Q',raw,identifier*64)
        assert z==0
        if kind==0:answer=None
        elif kind==1:answer=bool(aux)
        elif kind==2:answer=(-1 if aux else 1)*int.from_bytes(raw[at:at+size],'little')
        elif kind==3:answer=struct.unpack_from('<d',raw,at)[0]
        elif kind==4:answer=raw[at:at+size].decode('utf-8','surrogatepass')
        elif kind==9:answer=raw[at:at+size]
        elif kind in (5,6,7):
            width=count*(2 if kind==6 else 1)
            ids=struct.unpack_from('<'+'Q'*width,raw,edgebase+first*8) if width else ()
            if kind==6:answer={value(ids[i]):value(ids[i+1]) for i in range(0,width,2)}
            else:
                items=[value(i) for i in ids];answer=tuple(items) if kind==7 else items
        else:raise AssertionError(('published-opaque-or-invalid-kind',kind,identifier))
        memo[identifier]=answer;active.remove(identifier);return answer
    return value(rootid if root is None else root)
def graph_wire(raw,label):
    lease=struct.unpack_from('<Q',raw,8)[0];root=struct.unpack_from('<Q',raw,24)[0]
    command=pack(M(b'HIAGWC01'),lease,1,root,8388608,2,sys.get_int_max_str_digits(),0)
    s=Buffer(len(raw),raw);t=Buffer(64,command);w=Buffer(32768);role='scan'
    grows=0
    while True:
        ret=invoke(role,s,t,w,label);assert ret==128,(label,ret)
        f=struct.unpack_from('<16Q',w.raw())
        assert f[0]==M(b'HIAGWE01') and f[2:8]==struct.unpack('<8Q',command)[1:7]
        if f[1]==1:
            assert f[10]>w.n;w=grow(w,f[10]);grows+=1;continue
        if f[1]==2:
            assert role=='scan' and f[13]==2 and f[8:10]==(0,0)
            role='emit';continue
        if f[1]==3:
            assert f[8] in wire_errors and f[15]==0
            return dict(error='E_HIA_EDIT: '+wire_errors[f[8]],cause_kind=f[9],grows=grows)
        assert f[1]==0 and role=='emit' and f[8:10]==(0,0)
        assert f[11]<=w.n and f[12]<=w.n-f[11]
        return dict(wire=w.raw()[f[11]:f[11]+f[12]],grows=grows)
def configure(raw,ids,mode,capacity=4096):
    assert len(ids)==9
    s=Buffer(len(raw),raw);t=Buffer(len(template),template);w=Buffer(capacity)
    w.write(128,pack(M(b'HIAWVC01'),37,83,53,len(raw),mode,113,*ids,*([0]*8)))
    return dict(s=s,t=t,w=w,seq=0,mode=mode)
def event(c,ret):
    assert ret==640,ret
    f=struct.unpack_from('<16Q',c['w'].raw(),512)
    assert f[0]==M(b'HIAWVE01') and f[2:4]==(37,83)
    assert f[4]==c['seq']+1 and f[5]==c['mode'] and f[7]==4096
    assert f[10]==113 and f[14:16]==(0,0)
    c['seq']=f[4];return f
def projected(raw,ids,mode,label,capacity=4096,growth='exact'):
    c=configure(raw,ids,mode,capacity);trace=[]
    while True:
        ret=invoke('values',c['s'],c['t'],c['w'],label)
        f=event(c,ret);trace.append(list(f))
        if f[1]==1:
            need=f[6];assert need>c['w'].n
            if growth=='short-once':
                assert need-1>c['w'].n
                c['w']=grow(c['w'],need-1);growth='exact';continue
            c['w']=grow(c['w'],need);continue
        assert f[1]==0 and f[13]==0 and f[6]==4096+f[8]
        assert f[7]<=c['w'].n and f[8]<=c['w'].n-f[7]
        out=c['w'].raw()[f[7]:f[7]+f[8]]
        assert struct.unpack_from('<Q',out,24)[0]==f[9]
        return out,c,trace

def original_values(identities,paths):
    """Independent original method execution, before every native interval."""
    class IssuedStore:
        def __init__(self):self.bodies={};self.jsons=[];self.files=[];self.calls=[]
        def reference(self,label,kind):
            return dict(id='foreign-'+label,sha256=digest(label.encode('utf-8')),
                uri='hia://artifacts/'+label,kind=kind)
        def profile(self,name,body):
            assert name.startswith('hia-') and name.endswith('-v1')
            key=name[4:-3];self.bodies[key]=copy.deepcopy(body);self.calls.append(('profile',key))
            return (dict(id='foreign-profile-'+key,sha256=digest(name.encode())),
                    self.reference('profile-'+key,'profile'))
        def json(self,value,kind):
            assert kind=='discovery'
            self.jsons.append(copy.deepcopy(value));self.calls.append(('json',value.get('schema')))
            return self.reference('json-'+str(len(self.jsons)),'discovery')
        def put(self,data,kind):
            assert type(data) is bytes and kind=='discovery'
            self.files.append(data);self.calls.append(('file',len(data)))
            return self.reference('file-'+str(len(self.files)),'discovery')
    issued=IssuedStore()
    owner=service.HIAAgentService.__new__(service.HIAAgentService)
    owner.identities=copy.deepcopy(identities);owner.catalog_sha256='a'*64
    owner.artifact_roots=tuple(Path(path) for path in paths);owner.store=issued
    original_verify=service.verify_program;documents=[]
    def capture_verify(value,*args,**kwargs):
        documents.append(copy.deepcopy(value))
        return original_verify(value,*args,**kwargs)
    with patch.object(service,'verify_program',new=capture_verify):
        owner._profiles()
    assert len(documents)==1 and len(issued.bodies)==7 and len(issued.files)==10
    assert len(issued.jsons)==10 and len(owner.resources)==19
    assert [row[0] for row in issued.calls]==['profile']*7+['json']*6+['file']*10+['json']*4
    schemas={value.get('schema'):value for value in issued.jsons}
    expected={1:issued.bodies,2:schemas['hepta.hia.agent.diagnostics.v1'],
        3:schemas['hepta.hia.agent.manifest.v1'],4:documents[0],
        5:schemas['hepta.hia.agent.examples.v1'],
        6:schemas['hepta.hia.agent.macro-policy-guidance.v1']}
    roots=[str(path) for path in owner.artifact_roots]
    dynamic=[owner.identities,owner.catalog_sha256,roots,store.digest(roots),
        owner.profiles,owner.profile_artifacts,owner.resources,
        expected[5]['core'],expected[5]['assembly']]
    graph=capture(dynamic,lease=53)
    nodes=struct.unpack_from('<Q',graph,16)[0];edgebase=64+nodes*64
    root=struct.unpack_from('<Q',graph,24)[0];first,count=struct.unpack_from('<2Q',graph,root*64+24)
    assert count==9
    ids=struct.unpack_from('<9Q',graph,edgebase+first*8)
    trace=dict(profile_order=list(issued.bodies),json_order=[v.get('schema') for v in issued.jsons],
        file_bytes=[len(v) for v in issued.files],full_profile_then_resource_sequence=issued.calls,
        example_initial_verifications=len(documents),
        original_examples_render_and_explicit_assemble_executed=True)
    return expected,graph,ids,trace
def native_guards():
    stack=ExitStack()
    for target in ('hepta.hia_agent_service.HIAAgentService._profiles',
        'hepta.hia_agent_service.HIAAgentService._examples','hepta.hia_agent_service.digest',
        'hepta.hia_agent_store.wire','hepta.hia_agent_store.digest',
        'hepta.hia_agent_macro_discovery.macro_policy_guidance',
        'hepta.hia_program_tools.bounded_json_wire','json.loads'):
        stack.enter_context(patch(target,new=disabled))
    for name in ('graph','source_values','expression','build'):
        stack.enter_context(patch.object(templates,name,new=disabled))
    return stack
def one(label,fixture,mode,capacity=4096,growth='exact'):
    global case_count
    expected,source,ids,trace=fixture;value=expected[mode]
    print(json.dumps(dict(event='INIT_VALUE_START',group=GROUP,label=label,ordinal=case_count+1)),flush=True)
    try:expected_wire=dict(wire=store.wire(value))
    except Exception as exc:expected_wire=dict(error=str(exc),error_class=type(exc).__name__)
    before=dict(entries)
    with native_guards():
        output,context,events=projected(source,ids,mode,label,capacity,growth)
        actual_wire=graph_wire(output,label+'.wire')
    actual=decode_graph(output);assert actual==value,(label,'complete original value differs')
    if 'wire' in expected_wire:
        assert actual_wire.get('wire')==expected_wire['wire'],(label,expected_wire,actual_wire)
        expected_record=cas(expected_wire['wire']);actual_record=cas(actual_wire['wire'])
    else:
        assert actual_wire.get('error')==expected_wire['error'],(label,expected_wire,actual_wire)
        expected_record=actual_record=None
    # Existing source IDs retain their original meanings, even when unused by
    # this result. The output Graph is an append projection, not a new host plan.
    for identifier in ids:assert decode_graph(output,identifier)==decode_graph(source,identifier)
    if mode==4:
        params=actual['functions'][0]['params']
        assert params is actual['functions'][0]['blocks'][0]['params']
    if mode==5:assert type(actual['objective']['min_improvement_ratio']) is float
    row=dict(case=case_count+1,label=label,status='PASS',mode=mode,source=cas(source),
        output_graph=cas(output),expected_wire=expected_record,actual_wire=actual_record,
        wire_error=expected_wire.get('error'),wire_grows=actual_wire['grows'],
        projection_events=events,original_method_trace=trace,
        all_complete_values_and_wire_bytes_equal=True,all_original_ids_preserved=True,
        namespace_effects_are_foreign_fixtures=True,
        entries={k:entries[k]-before[k] for k in entries})
    results.write(json.dumps(row,sort_keys=True)+'\n');results.flush();case_count+=1
    completed_modes[mode]+=1
    print(json.dumps(dict(event='INIT_VALUE_PASS',group=GROUP,label=label,ordinal=case_count)),flush=True)
def semantics():
    global planned
    cases=[
        ('empty-roots',{},[]),
        ('ordinary-identities',{'source':'e'*64,'schema':'installed.v1','compiler':'f'*64},['/opt/one']),
        ('unicode-order',{'z':'尾😀','a':'é','nested':{'b':False,'a':None},'quote':'"\n\\'},
            ['/tmp/é','/tmp/中','/tmp/😀']),
        ('numeric-identities',{'ints':[0,1,-1,2**64,10**128],'floats':[0.0,-0.0,1.5]},
            ['/zero','/one']),
        ('aliased-identities',None,['/same','/same']),
    ]
    shared={'array':['same',True,None,23]}
    cases[-1]=(cases[-1][0],{'first':shared,'second':shared},cases[-1][2])
    planned=len(cases)*6
    for label,identities,paths in cases:
        fixture=original_values(identities,paths)
        for mode in range(1,7):one(label+'-mode-'+str(mode),fixture,mode)
def growths():
    global planned
    fixture=original_values({'source':'f'*64},['/one'])
    planned=6*3
    for mode in range(1,7):
        one('exact-growth-'+str(mode),fixture,mode)
        one('one-short-growth-'+str(mode),fixture,mode,growth='short-once')
        # A fresh overprovisioned invocation must emit the same complete value
        # immediately; derive capacity from the pinned graphs, not a host value.
        source=fixture[1];at=64+(mode-1)*128
        t_at,t_size=struct.unpack_from('<2Q',template,at+8)
        sn,se,sp=(struct.unpack_from('<Q',source,n)[0] for n in (16,32,40))
        tn,te,tp=(struct.unpack_from('<Q',template,t_at+n)[0] for n in (16,32,40))
        capacity=4096+64+64*(sn+tn)+8*(se+te)+sp+tp+8
        one('overprovisioned-'+str(mode),fixture,mode,capacity)
def large_values():
    global planned
    planned=5
    for count in (255,256,257,65536):
        fixture=original_values({'source':'b'*64},['/r/'+str(i) for i in range(count)])
        one('root-count-'+str(count),fixture,1)
    fixture=original_values({'large':'x'*(1<<20),'unicode':'😀'*1024},['/one'])
    one('large-installed-value',fixture,6)
def protocols():
    global planned,case_count
    fixture=original_values({'source':'b'*64},['/one'])
    _,source,ids,_=fixture;controls=[]
    def refusal(c,label):
        assert invoke('values',c['s'],c['t'],c['w'],label)==BAD
        poisoned=c['w'].raw()
        assert struct.unpack_from('<Q',poisoned,8)[0]==3
        assert invoke('values',c['s'],c['t'],c['w'],label+'.again')==BAD
        assert c['w'].raw()==poisoned
    def config(index,value):
        c=configure(source,ids,1);c['w'].write(128+index*8,pack(value));refusal(c,'config-'+str(index))
    for index,value in ((0,0),(1,0),(2,0),(3,54),(4,len(source)-1),(5,0),(5,7),(6,0),
        (7,0),(8,0),(9,0),(10,0),(16,1),(23,1)):
        controls.append(('config-'+str(index)+'-'+str(value),lambda i=index,v=value:config(i,v)))
    def source_word(index,value):
        c=configure(source,ids,1);c['s'].write(index*8,pack(value));refusal(c,'source-'+str(index))
    for index,value in ((0,0),(1,54),(2,0),(2,MAX),(3,0),(3,MAX),(4,MAX),(5,0),(6,0),(7,1)):
        controls.append(('source-header-'+str(index),lambda i=index,v=value:source_word(i,v)))
    def source_node(field,value):
        c=configure(source,ids,1);c['s'].write(64+field*8,pack(value));refusal(c,'node-'+str(field))
    for field,value in ((0,10),(1,1),(2,1),(3,MAX),(4,MAX),(5,0),(6,1),(7,1)):
        controls.append(('source-node-'+str(field),lambda i=field,v=value:source_node(i,v)))
    def template_word(at,value):
        c=configure(source,ids,1);c['t'].write(at,pack(value));refusal(c,'template-'+str(at))
    for at,value in ((0,0),(8,2),(16,5),(24,len(template)-1),(32,64),(40,0),(48,1),(56,1),
        (64,2),(72,0),(80,MAX),(88,0),(168,1),(176,1),(184,1)):
        controls.append(('template-header-'+str(at),lambda a=at,v=value:template_word(a,v)))
    # Mode 1 has actual installation/catalog/root-count/root-digest markers.
    placeholders=struct.unpack_from('<9Q',template,64+32)
    assert all(placeholders[i] for i in range(4))
    for code in (1,2,3,4):
        controls.append(('placeholder-range-'+str(code),
            lambda k=code:template_word(64+24+k*8,MAX)))
    controls.append(('duplicate-placeholder',
        lambda:template_word(64+24+2*8,placeholders[0])))
    def unknown_marker():
        c=configure(source,ids,1)
        begin=struct.unpack_from('<Q',template,72)[0]
        node=struct.unpack_from('<Q',template,begin+24)[0]
        c['t'].write(begin+node*64,pack(8,0,0,0,0,0,0,0))
        refusal(c,'unlisted-template-marker')
    controls.append(('unlisted-template-marker',unknown_marker))
    def dirty_initial():
        c=configure(source,ids,1);c['w'].write(3000,b'\1');refusal(c,'dirty-initial')
    controls.append(('dirty-initial',dirty_initial))
    def grown():
        c=configure(source,ids,1)
        f=event(c,invoke('values',c['s'],c['t'],c['w'],'grow-start'))
        assert f[1]==1;c['w']=grow(c['w'],f[6]);return c
    def changed_after_grow(kind):
        c=grown()
        if kind=='config':c['w'].write(128+2*8,pack(84))
        elif kind=='source':c['s'].write(8,pack(54))
        elif kind=='template':c['t'].write(8,pack(2))
        elif kind=='table':c['t'].write(64+32,pack(0))
        elif kind=='source-size':c['s']=Buffer(c['s'].n+1,c['s'].raw()+b'\0')
        elif kind=='template-size':c['t']=Buffer(c['t'].n+1,c['t'].raw()+b'\0')
        else:raise AssertionError(kind)
        refusal(c,'changed-after-grow-'+kind)
    for kind in ('config','source','template','table','source-size','template-size'):
        controls.append(('changed-after-grow-'+kind,lambda k=kind:changed_after_grow(k)))
    def terminal():
        _,c,_=projected(source,ids,1,'valid-completion');refusal(c,'completed-reuse')
    controls.append(('completion-single-use',terminal))
    def sequence():
        c=grown();c['w'].write(16,pack(MAX))
        assert invoke('values',c['s'],c['t'],c['w'],'event-overflow')==BAD
        assert struct.unpack_from('<Q',c['w'].raw(),8)[0]==3
        assert invoke('values',c['s'],c['t'],c['w'],'event-overflow-again')==BAD
    controls.append(('event-sequence-overflow',sequence))
    def short():
        c=configure(source,ids,1);before=c['w'].raw()
        assert invoke('values',c['s'],c['t'],c['w'],'short-workspace',4095)==BAD
        assert c['w'].raw()==before
        # End this private lease; do not claim poison inside an inaccessible state.
    controls.append(('short-workspace-outer-retirement',short))
    def pending_short():
        c=grown();before=c['w'].raw()
        assert invoke('values',c['s'],c['t'],c['w'],'pending-short-workspace',4095)==BAD
        assert c['w'].raw()==before
    controls.append(('pending-short-outer-retirement',pending_short))
    planned=len(controls)
    for label,body in controls:
        before=dict(entries)
        with native_guards():body()
        row=dict(case=case_count+1,label=label,status='PASS',private_protocol=True,
            entries={k:entries[k]-before[k] for k in entries})
        results.write(json.dumps(row,sort_keys=True)+'\n');results.flush();case_count+=1

try:
    assert sys.get_int_max_str_digits()==4300
    assert not os.environ.get('HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST')
    read(__file__)
    for path in sorted((ROOT/'tools').glob('*.py')):read(path)
    for relative,identity in (
        ('hepta/hia_agent_service.py','684caf496de7e3e7c8db1fd80ef616139cf13717aa5879bbd2d6ebf834df9330'),
        ('hepta/hia_agent_store.py','fae25d48a6de7187ed465287c1491af74214ac8bf3eae2af921bd100a247b822'),
        ('hepta/hia_agent_macro_discovery.py','3ee3f31f21719d0eee7414d8bee8ccb046d213ea44310764c21b727eac3c9951')):
        assert digest(read(REFERENCE/relative))==identity
    read(REFERENCE/'hepta/hia_program_tools.py');read(REFERENCE/'hepta/hia_json_preflight_native.py')
    harness=RENDER/'development/graph_harness_r3.py'
    raw=read(harness)
    assert (len(raw),digest(raw))==(9783,'75fe54554a93e19e30251073ac225deff944d6673d87ccc2b597e47a19e8be7c')
    tree=ast.parse(raw)
    node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='capture')
    namespace={'struct':struct,'GRAPH':M(b'HIAGRF01')}
    exec(compile(ast.Module(body=[node],type_ignores=[]),'<exact-original-private-capture>','exec'),namespace)
    capture=namespace['capture']
    error_node=next(n.value for n in tree.body if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id=='ERRORS' for t in n.targets))
    wire_errors=ast.literal_eval(error_node)
    bundle=json.loads(read(COMPILE/'bundle.json'))
    assert bundle['schema']=='hia-worker-initialization-values-development-v1'
    assert bundle['status']=='PASS' and set(bundle['components'])==set(entries)
    assert bundle['ordinary_initialization'] is False and bundle['whole_worker_closed'] is False
    summary=json.loads(read(COMPILE/'summary.json'))
    assert summary['status']=='PASS' and summary['actual_compiles']==3 and summary['source_unchanged']
    compiler=read(WORK/'dependencies/f50-B3.image.bin')
    assert (len(compiler),digest(compiler))==(668608,COMPILER_SHA)
    template_path=Path(bundle['template_path']).resolve()
    assert template_path==COMPILE/'static-templates/initialization-literals.bin'
    template=read(template_path)
    assert (len(template),digest(template))==(bundle['template_bytes'],bundle['template_sha256'])
    template_manifest=json.loads(read(COMPILE/'static-templates/manifest.json'))
    assert template_manifest['packet']['sha256']==digest(template)
    for dependency in template_manifest['dependencies']:
        assert digest(read(dependency['path']))==dependency['sha256']
    expected_sources={
        'values':ROOT/'examples/hia_bootstrap/agent_worker_initialization_values.hiaasm',
        'scan':RENDER/'examples/hia_bootstrap/graph_json_wire_scan.hiaasm',
        'emit':RENDER/'examples/hia_bootstrap/graph_json_wire_emit.hiaasm'}
    expected_fixed={
        'scan':(147822,'c1cb49c1df3c4c653dfd37beebba12b3baf57a28a7d77c257157d2cc7e58cde3'),
        'emit':(173680,'9ad72bddb7eaa3d9118155a056e4c5faa7ff3e015e45fbc2d09dae14e2cfb7a2')}
    frozen={}
    for role,row in bundle['components'].items():
        current=expected_sources[role].resolve()
        assert Path(row['source_path']).resolve()==current
        source=read(current);image=read(row['image_path']);receipt=json.loads(read(row['receipt_path']))
        if role in expected_fixed:assert (len(source),digest(source))==expected_fixed[role]
        assert Path(row['image_path']).resolve().parent==COMPILE
        assert Path(row['receipt_path']).resolve()==COMPILE/(role+'.receipt.json')
        assert json.loads(read(COMPILE/(role+'.manifest.json')))==row
        assert (len(source),digest(source))==(row['source_bytes'],row['source_sha256'])
        assert (len(image),digest(image))==(row['image_bytes'],row['image_sha256'])
        assert row['role']==role and row['compiler_sha256']==COMPILER_SHA
        assert receipt['image_sha256']==COMPILER_SHA and receipt['input_sha256']==digest(source)
        assert receipt['produced_sha256']==digest(image)
        frozen[role]=(image,digest(image))
    assert same();save(OUT/'source-before.json',rows())
    images={role:NativeHiaJsonImage(*payload) for role,payload in frozen.items()}
    {'semantic':semantics,'growth':growths,'large':large_values,'protocol':protocols}[GROUP]()
    assert case_count==planned,(case_count,planned);status='PASS'
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
    ledger.close();results.close();unchanged=same()
    if not unchanged:status='FAIL'
    summary=dict(status=status,group=GROUP,scope='COMPLETE_INITIALIZATION_VALUES_ACTUAL_HIA_WITH_FOREIGN_STORE_ORACLE',
        cases=case_count,planned_cases=planned,entries=entries,total_actual_entries=sum(entries.values()),
        failure=failure,source_unchanged=unchanged,compressed_cas_objects=len(saved),
        elapsed_ns=time.monotonic_ns()-started,
        original_limits=dict(cpu_seconds=90,address_space_bytes=1<<30),
        supported_complete_value_modes=6,completed_semantic_modes=completed_modes,
        actual_native_graph_wire_entries=entries['scan']+entries['emit'],
        runtime_python_mechanical_transport=True,namespace_effects_are_foreign_fixtures=True,
        ordinary_initialization_closed=False,ordinary_namespace_closed=False,whole_worker_closed=False,
        production_activation=False,host_initialization_and_wire_owners_disabled_in_native_interval=True)
    save(OUT/'source-after.json',rows());save(OUT/'summary.json',summary)
    print(json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
