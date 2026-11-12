"""NEW complete initializer with actual native P12 and P16/P17/P18.

Seventeen worker-side images and one fixed 41-image program context execute.
The complete old Service/Store/verify/render/assemble methods form independent
pre-run oracles. Eight other initializer peer kinds and physical namespace
effects remain explicit controlled fixtures. No previous test count is reused.
"""
from __future__ import annotations
import ast,copy,ctypes,json,os,resource,stat,struct,sys,time,traceback,zlib
from contextlib import ExitStack,contextmanager
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(os.environ['HIA_DIGEST_ROOT'])/'development'))
import digest_harness_r4 as DH
sys.path.insert(0,str(Path(os.environ['HIA_STORE_VALUES_ROOT'])/'development'))
import store_values_harness_r1 as SV
assert SV.H is DH
sys.dont_write_bytecode=True
WORK=Path(sys.argv[1]).resolve();COMPILE=Path(sys.argv[2]).resolve()
OUT=Path(sys.argv[3]).resolve();GROUP=sys.argv[4]
ROOT=WORK/'native-agent-initialization-registry-next';REFERENCE=WORK/'Hepta-agent-edit-native'
RENDER=WORK/'native-agent-edit-render-next'
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'dependencies'),str(REFERENCE)]
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta import hia_agent_service as service
from hepta import hia_agent_store as store
from hepta import hia_agent_assembly as assembly
import generate_hia_agent_worker_init_pure as pure_generation
import generate_hia_agent_worker_init_sequence as sequence_generation
import generate_hia_agent_worker_init_registry as registry_generation
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
M=lambda b:int.from_bytes(b,'little')
pack=lambda *v:struct.pack('<'+'Q'*len(v),*v)
BAD=0xfffffffd;MAX=(1<<64)-1;HANDLE_BASE=1<<63;CANARY=bytes(range(64))
C=pure_generation.CONSTANTS;SC=sequence_generation.CONSTANTS;RC=registry_generation.constants()
COMPILER_SHA='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
OUT.mkdir(parents=True,exist_ok=False);(OUT/'cas').mkdir()
pins={};modes={};saved=set();images={}
entries={x:0 for x in ('sequence','pure','maps','values','registry','merge','scan','emit')}
ledger=(OUT/'entries.jsonl').open('w');results=(OUT/'cases.jsonl').open('w')
capture=None;template=None;case_count=0;planned=0;status='FAIL';failure=None
started=time.monotonic_ns();completed_pure_modes=set()
HELPER_SHA='1602df39c9dd982e42ece64379e76fc9ca123b7ca407e84d7f4ded767bebf753'
helper=ROOT/'development/value_mechanics_source.py';helper_raw=helper.read_bytes()
assert sha256(helper_raw).hexdigest()==HELPER_SHA
helper_tree=ast.parse(helper_raw)
wanted={'digest','save','cas','read','rows','same','disabled','Buffer','invoke','grow','decode_graph'}
definitions=[n for n in helper_tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in wanted]
assert {n.name for n in definitions}==wanted
exec(compile(ast.Module(body=definitions,type_ignores=[]),str(helper),'exec'),globals())
# Reuse only an exactly equal immutable evidence byte identity.
digest=DH.evidence_digest
ORACLE_SHA='b809f06c0c1a0e56d5a49555e6b3010ce7c78d18707571f87c4a9b78d7d62f2b'
oracle_source=ROOT/'development/sequence_oracle_source.py';oracle_raw=read(oracle_source)
assert digest(oracle_raw)==ORACLE_SHA
oracle_tree=ast.parse(oracle_raw)
oracle_names={'PeerFailure','observed_exception','Program','normalized','snapshot','Root',
    'Namespace','oracle','native_state','complete','observe','peer','frame'}
oracle_nodes=[n for n in oracle_tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))
    and n.name in oracle_names]
assert {n.name for n in oracle_nodes}==oracle_names
for name in ('ATTRS','INSTALL','CATALOG'):
    assigned=next(n.value for n in oracle_tree.body if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id==name for t in n.targets))
    allowed_constant_nodes=(ast.Constant,ast.Tuple,ast.List,ast.Dict,ast.BinOp,ast.Mult,ast.Load)
    assert all(isinstance(n,allowed_constant_nodes) for n in ast.walk(assigned)),ast.dump(assigned)
    globals()[name]=eval(compile(ast.Expression(assigned),str(oracle_source),'eval'),
        {'__builtins__':{}},{})
exec(compile(ast.Module(body=oracle_nodes,type_ignores=[]),str(oracle_source),'exec'),globals())
foreign_peer=peer;SMALL_CATALOG=CATALOG
pure_fixture=ROOT/'development/pure_join_fixture_source.py';pure_fixture_raw=read(pure_fixture)
assert digest(pure_fixture_raw)=='508a9e6050943be1ff3053ea4e1ace2d9761a38cede7d55f02995139ef451a6d'
pure_tree=ast.parse(pure_fixture_raw)
# Only mechanical pure-child forwarding is reused. In particular the original
# preloading source_pool, configure, NativeRegistry, tests and runner are absent.
pure_names={'fingerprint','resize','join_frame','command','joined','finish_join','issue',
    'prepare_child','actual_child','pure_peer','encoded'}
pure_nodes=[n for n in pure_tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in pure_names]
assert {n.name for n in pure_nodes}==pure_names
exec(compile(ast.Module(body=pure_nodes,type_ignores=[]),str(pure_fixture),'exec'),globals())
@contextmanager
def forbidden_pure_owners():
    with ExitStack() as stack:
        for target in ('hepta.hia_agent_service.HIAAgentService.__init__',
            'hepta.hia_agent_service.HIAAgentService._profiles',
            'hepta.hia_agent_service.HIAAgentService._examples','json.loads'):
            stack.enter_context(patch(target,new=disabled))
        yield
raw_invoke=invoke
def invoke(role,s,t,w,label,advertised=None):
    with forbidden_pure_owners():return raw_invoke(role,s,t,w,label,advertised)
def registry_frame(c,ret):
    assert ret==768,('registry-return',ret)
    f=struct.unpack_from('<32Q',c['pw'].raw(),512)
    assert f[0]==M(b'HIAWGE01') and f[2:4]==(37,83)
    assert f[4]==c['bseq']+1 and f[5]==c['active'] and f[25]==53
    assert f[1]<=6 and f[27:29]==(0,0) and f[31]==0
    assert f[30] in (0,10,11,12)
    c['bseq']=f[4];c['blast']=f[29];c['rf']=f
    return f
def registry_command(c,mode,payload=b'',root=0,actual=0,foreign_bytes=0,child_bytes=0,digits=0):
    if mode in (1,2,6):c['active']=c['blast']+1
    raw=c['g'].raw()
    fields=[M(b'HIAWGC01'),mode,37,83,c['active'],c['bseq'],
        struct.unpack_from('<Q',raw,8)[0],len(raw),len(payload),actual,root,digits,53,
        foreign_bytes,child_bytes,0]
    return fields,bytes(payload)
def registry_entry(c,fields,payload,label,advertised=None):
    fields=list(fields);fields[5]=c['bseq'];raw=pack(*fields)+payload
    r=Buffer(len(raw),raw);c['rr']=r
    ret=invoke('registry',c['g'],r,c['pw'],label,advertised)
    return registry_frame(c,ret),r
def adopt_import(c,f,r):
    assert f[1]==6 and f[17]==3 and f[18]<=r.n and f[19]<=r.n-f[18]
    raw=r.raw()[f[18]:f[18]+f[19]]
    assert (struct.unpack_from('<Q',raw,8)[0],len(raw))==f[6:8]
    assert f[20]>0 and f[21]>HANDLE_BASE and f[29]==c['active'] and f[30]==0
    c['g']=Buffer(len(raw),raw)
    c['blast']=f[29]
    return f[21]
def bootstrap(paths=(),baseline=None,growth='exact',digits=4300):
    raw=capture(['/state',list(paths)],lease=53)
    n=struct.unpack_from('<Q',raw,16)[0]
    c=dict(s=Buffer(len(raw),raw),r=Buffer(0),w=Buffer(8192),seq=0,raw=raw,
        source_values={i:decode_graph(raw,i) for i in range(1,n+1)},
        trace=[],occurrences={},namespaces={},program_document=None,
        baseline=baseline,reply_count=0,grows=0,g=Buffer(len(raw),raw),pw=Buffer(8192),
        bseq=0,blast=0,active=0,growth=growth,shortened=set(),growth_events=[],
        pure_results=[],child_calls=0,imports=[],borrow_count=0,merge_calls=0)
    fields,payload=registry_command(c,1,digits=digits)
    f,r=registry_entry(c,fields,payload,'native-bootstrap')
    assert f[1]==0 and f[17:20]==(1,0,len(raw)) and f[20:22]==(1,0)
    assert f[22:24]==(1024,192) and f[24]==0 and f[29:31]==(1,0)
    config=c['pw'].raw()[f[22]:f[22]+f[23]]
    assert len(config)==192
    c['w'].write(128,config)
    c['reg']=NativeRegistry(c)
    return c
def reserve_foreign(c,label):
    fields,payload=registry_command(c,2)
    f,r=registry_entry(c,fields,payload,label+'-reserve')
    assert f[1]==2 and f[9]>0 and f[10]>f[9] and f[30]==10
    return f
def prepare_import(c,foreign,label):
    fields,payload=registry_command(c,3,foreign,foreign_bytes=len(foreign))
    first=tuple(fields)
    while True:
        f,r=registry_entry(c,fields,payload,label+'-prepare')
        if f[1]!=1:
            assert f[1]==3 and f[30]==12;return f,r
        assert f[8]>c['pw'].n
        c['pw']=resize(c,c['pw'],f[8],'registry')
        fields[1]=5;fields[5]=c['bseq']
        assert all(fields[i]==first[i] for i in range(16) if i not in (1,5))
def merge_actual(c,f,r,label):
    assert f[1] in (3,4) and f[13]<=c['pw'].n and f[14]<=c['pw'].n-f[13]
    assert f[15:17]==(128,c['foreign_bytes'])
    raw=c['pw'].raw()[f[13]:f[13]+f[14]]
    foreign=r.raw()[f[15]:f[15]+f[16]]
    assert foreign==c['foreign_raw']
    if f[1]==3:
        assert f[11]==0 and f[12]==512
        c['mw']=Buffer(512)
    else:
        assert f[12]>c['mw'].n
        c['mw']=resize(c,c['mw'],f[12],'merge')
    first=Buffer(len(raw),raw);second=Buffer(len(foreign),foreign)
    ret=invoke('merge',first,second,c['mw'],label+'-actual-merge')
    c['merge_calls']+=1
    assert ret==384,('actual-unchanged-merge',ret)
    c['actual_merge_return']=ret
    return ret
def merge_submit(c,label,payload_override=None,field_override=None):
    foreign=c['foreign_raw'];actual=c['mw'].raw()
    fields,payload=registry_command(c,4,foreign+actual,actual=c['actual_merge_return'],
        foreign_bytes=len(foreign),child_bytes=len(actual))
    if payload_override is not None:payload=payload_override
    if field_override:
        for index,value in field_override.items():fields[index]=value
    return registry_entry(c,fields,payload,label+'-consume-actual-merge')
def import_value(c,value,label='foreign-value',stop_before_done=False):
    sequence_before=entries['sequence']
    reserved=reserve_foreign(c,label)
    foreign=capture(value,lease=reserved[9])
    c['foreign_raw']=foreign;c['foreign_bytes']=len(foreign)
    f,r=prepare_import(c,foreign,label)
    while True:
        merge_actual(c,f,r,label)
        actual=struct.unpack_from('<16Q',c['mw'].raw(),256)
        if stop_before_done and actual[1]==0:
            return None
        f,r=merge_submit(c,label)
        if f[1]==4:continue
        handle=adopt_import(c,f,r)
        c['imports'].append(dict(ordinal=len(c['imports'])+1,label=label,
            initializer_pending=c.get('f',(0,)*8)[7],
            foreign_graph=cas(foreign),imported_graph=cas(c['g'].raw()),handle=handle,
            graph_root=f[20],source_lease=reserved[9],output_lease=reserved[10]))
        assert entries['sequence']==sequence_before
        return handle
def borrowed(c,token,label='native-borrow'):
    fields,payload=registry_command(c,6,root=token)
    f,r=registry_entry(c,fields,payload,label)
    assert f[1]==5 and f[17:20]==(1,0,c['g'].n)
    assert f[21]==token and f[22:24]==(1024,64) and f[30]==0
    config=c['pw'].raw()[f[22]:f[22]+f[23]]
    assert struct.unpack_from('<Q',config,40)[0]==2  # original Store.wire UTF-8, sorted keys
    c['borrow_count']+=1
    return f[20],config
class NativeRegistry:
    def __init__(self,c):
        self.c=c;self.authorities={};self.kinds={};self.next=900000
    def issue(self,value,kind='value'):
        if kind not in ('value','bytes'):
            self.next+=1;self.authorities[self.next]=(kind,value);return self.next
        token=import_value(self.c,value,'provider-value-'+str(len(self.c['imports'])+1))
        assert token not in self.kinds
        self.kinds[token]=kind
        return token
    def get(self,token,kind='value'):
        if token<=HANDLE_BASE:
            actual,value=self.authorities[token];assert actual==kind
            return value
        actual=self.kinds.get(token,'value');assert actual==kind,(kind,actual)
        root,config=borrowed(self.c,token)
        assert struct.unpack('<8Q',config)[:4]==(M(b'HIAGWC01'),
            struct.unpack_from('<Q',self.c['g'].raw(),8)[0],self.c['blast'],root)
        return decode_graph(self.c['g'].raw(),root)
def configure(paths,baseline=None,growth='exact',extra=(),mini=False):
    assert not extra and not mini
    if baseline is None:baseline=oracle(paths)
    return bootstrap(paths,baseline,growth)
class DigestRegistryAdapter:
    """Borrow actual native Graph/registry views; never materialize the value."""
    def __init__(self,c):self.c=c
    @property
    def g(self):
        raw=self.c['g'].raw()
        return DH.Buffer(len(raw),raw)
    def borrow(self,handle):
        root,config=borrowed(self.c,handle,'actual-digest-borrow')
        return self.c['pw'].raw()[512:768],config
    def reserve(self):
        reserve_foreign(self.c,'actual-digest')
        return self.c['pw'].raw()[512:768]
    def packet(self,foreign):
        c=self.c;c['foreign_raw']=foreign;c['foreign_bytes']=len(foreign)
        reserved=struct.unpack_from('<32Q',c['pw'].raw(),512)
        assert reserved[1]==2
        f,r=prepare_import(c,foreign,'native-digest-hex-graph')
        while True:
            merge_actual(c,f,r,'native-digest-hex-graph')
            f,r=merge_submit(c,'native-digest-hex-graph')
            if f[1]==4:continue
            handle=adopt_import(c,f,r)
            c['imports'].append(dict(ordinal=len(c['imports'])+1,label='actual-native-digest',
                initializer_pending=c['f'][7],foreign_graph=cas(foreign),
                imported_graph=cas(c['g'].raw()),handle=handle,graph_root=f[20],
                source_lease=reserved[9],output_lease=reserved[10],foreign_issuer=False))
            c['reg'].kinds[handle]='value'
            return handle,c['pw'].raw()[512:768]
def native_digest_peer(c,fail_at):
    f=c['f'];assert f[1]==2 and f[6]==8 and f[5]==14
    source_handle=f[14];before=dict(DH.counts)
    with patch.object(store,'digest',new=disabled),patch.object(store,'wire',new=disabled):
        route=DH.Route(DigestRegistryAdapter(c),source_handle,c['w'].raw()[2048:2304],
            label='complete-initializer-digest-'+str(f[7]))
        reply=route.finish()
    q=struct.unpack_from('<32Q',reply)
    assert q[:5]==(M(b'HIAWIR01'),37,83,f[7],8) and q[5:7]==(0,7)
    assert q[8]==route.handle and route.sha_calls>0
    # These Graph observations only form the independent comparison ledger;
    # they did not provide wire bytes, digest, root, handle or reply to HIA.
    value=c['reg'].get(source_handle);actual_digest=c['reg'].get(route.handle)
    assert actual_digest==reply[128:160].hex()
    if observe(c,'digest',value,actual_digest,fail_at):
        c['r']=Buffer(len(reply),reply);c['reply_count']+=1
    c.setdefault('digest_results',[]).append(dict(
        pending=f[7],reply=cas(reply),wire=cas(route.w.raw()[route.f[18]:route.f[18]+route.f[19]]),
        digest_hex=actual_digest,handle=route.handle,
        actual_entries={k:v-before.get(k,0) for k,v in DH.counts.items()},
        actual_registry_import=True,actual_initializer_reply=True))

def peer(c,fail_at,false_dirs,mismatch):
    if c['f'][6]==8:native_digest_peer(c,fail_at)
    elif c['f'][6] in (2,9,10,19):pure_peer(c,'pending-'+str(c['f'][7]))
    else:foreign_peer(c,fail_at,false_dirs,mismatch)
def drive(paths,label,fail_at=None,false_dirs=(),mismatch=False,baseline=None,growth='exact'):
    c=configure(paths,baseline,growth)
    while True:
        ret=invoke('sequence',c['s'],c['r'],c['w'],label)
        if ret==BAD:return dict(private_bad=True),c
        f=frame(c,ret)
        if f[1]==1:
            c['w']=resize(c,c['w'],f[8],'sequence');c['grows']+=1;continue
        if f[1]==2:
            peer(c,fail_at,false_dirs,mismatch);continue
        if f[1]==0:return dict(state=native_state(c),error=None),c
        assert f[1]==3
        if f[27]==0:
            assert f[28]==3 and f[29]==90001
            payload=c['r'].raw()[f[30]:f[30]+f[31]]
            prefix=b'fixture-issued-peer-exception:';assert payload.startswith(prefix)
            error=dict(error_class='PeerFailure',error=payload[len(prefix):].decode(),attributes={})
        else:
            assert f[28]==2 and f[29]==37 and f[27] in (1,2)
            error=dict(error_class={1:'AgentRejected',2:'RuntimeError'}[f[27]],
                error=c['w'].raw()[f[30]:f[30]+f[31]].decode(),attributes=(dict(
                    code='E_HIA_PROFILE',phase='admission',retry_action='correct_input',
                    details_artifact=None) if f[27]==1 else {}))
        return dict(state=native_state(c),error=error),c
def graph_topology(raw,root):
    """Independent reachable semantic/alias graph, independent of physical IDs."""
    nodes=struct.unpack_from('<Q',raw,16)[0];edges=64+nodes*64
    seen={root:1};queue=[root];rows_=[]
    for identifier in queue:
        kind,at,size,first,count,identity,aux,zero=struct.unpack_from('<8Q',raw,identifier*64)
        assert zero==0
        if kind in (5,6,7):
            amount=count*(2 if kind==6 else 1)
            children=struct.unpack_from('<'+'Q'*amount,raw,edges+first*8) if amount else ()
            mapped=[]
            for child in children:
                if child not in seen:seen[child]=len(seen)+1;queue.append(child)
                mapped.append(seen[child])
            rows_.append((kind,tuple(mapped)))
        elif kind in (2,3,4,9):rows_.append((kind,aux,raw[at:at+size]))
        else:rows_.append((kind,aux))
    return tuple(rows_)
def record(label,before,extra):
    global case_count
    row=dict(case=case_count+1,label=label,status='PASS',
        entries={k:entries[k]-before[k] for k in entries},**extra)
    results.write(json.dumps(row,sort_keys=True)+'\n');results.flush();case_count+=1
    print(json.dumps(dict(event='INIT_PROGRAM_COMPOSITION_PASS',group=GROUP,label=label,case=case_count)),flush=True)
def graph_children(raw,identifier):
    kind,at,size,first,count,identity,aux,zero=struct.unpack_from('<8Q',raw,identifier*64)
    assert kind in (5,6,7) and zero==0
    n=struct.unpack_from('<Q',raw,16)[0];width=count*(2 if kind==6 else 1)
    return struct.unpack_from('<'+'Q'*width,raw,64+n*64+first*8) if width else ()
def graph_field(raw,identifier,name):
    assert struct.unpack_from('<Q',raw,identifier*64)[0]==6
    ids=graph_children(raw,identifier)
    found=[ids[i+1] for i in range(0,len(ids),2) if decode_graph(raw,ids[i])==name]
    assert len(found)==1,(identifier,name)
    return found[0]
def initializer_aliases(c):
    words=struct.unpack_from('<64Q',c['w'].raw(),4096);checks=[]
    if words[3]&2:
        catalog_root,_=borrowed(c,words[4],'alias-catalog')
        tools_root,_=borrowed(c,words[6],'alias-tools')
        raw=c['g'].raw();items=graph_children(raw,graph_field(raw,catalog_root,'tools'))
        for item in items:
            name=decode_graph(raw,graph_field(raw,item,'name'))
            assert graph_field(raw,tools_root,name)==item
        checks.append(dict(kind='catalog-tools-same-actual-node',count=len(items)))
    examples=[r for r in c['pure_results'] if r['peer']==9 and r['mode']==4]
    if examples:
        assert len(examples)==1
        root,_=borrowed(c,examples[0]['handles'][0],'alias-example-document')
        raw=c['g'].raw()
        function=graph_children(raw,graph_field(raw,root,'functions'))[0]
        entry=graph_children(raw,graph_field(raw,function,'blocks'))[0]
        assert graph_field(raw,function,'params')==graph_field(raw,entry,'params')
        checks.append(dict(kind='example-function-entry-params-same-actual-node',count=1))
    return checks
def check(label,paths=(),fail_at=None,false_dirs=(),mismatch=False,growth='exact'):
    expected=oracle(paths,fail_at,false_dirs,mismatch)
    baseline=expected if fail_at is None and not false_dirs and not mismatch else oracle(paths)
    before=dict(entries)
    with forbidden_pure_owners():actual,c=drive(paths,label,fail_at,false_dirs,mismatch,baseline,growth)
    assert actual=={k:expected[k] for k in ('state','error')},(label,expected['error'],actual)
    assert c['trace']==expected['trace'],(label,'complete ordered calls and partial attributes',
        len(c['trace']),len(expected['trace']))
    if expected['error'] is None:
        assert {row['peer'] for row in c['pure_results']}=={2,9,10,19}
        assert {row['mode'] for row in c['pure_results'] if row['peer']==9}==set(range(1,7))
        assert {row['mode'] for row in c['pure_results'] if row['peer']==10}=={1,2,3,4}
    aliases=initializer_aliases(c)
    assert all(a['ordinal']==i+1 for i,a in enumerate(c['imports']))
    assert entries['merge']-before['merge']>=2*len(c['imports'])
    record(label,before,dict(reference_trace=cas(encoded(expected['trace'])),
        actual_trace=cas(encoded(c['trace'])),expected_state=cas(encoded(expected['state'])),
        actual_state=cas(encoded(actual['state'])),error=actual['error'],imports=c['imports'],
        actual_graph_alias_checks=aliases,
        pure_results=c['pure_results'],growth_events=c['growth_events'],
        actual_digest_results=c.get('digest_results',[]),
        actual_child_calls=c['child_calls'],actual_merge_calls=c['merge_calls'],
        actual_borrows=c['borrow_count'],remaining_eight_peer_ids_are_foreign=True,
        exact_complete_state_error_and_call_order=True,preloaded_future_values=False,
        ordinary_initialization_closed=False))
    c['observed_error']=actual['error']
    return c
def wire_selected(c,token,label):
    root,config=borrowed(c,token,label+'-borrow')
    s=c['g'];t=Buffer(64,config);w=Buffer(32768);role='scan'
    while True:
        ret=invoke(role,s,t,w,label+'-'+role);assert ret==128
        f=struct.unpack_from('<16Q',w.raw())
        assert f[0]==M(b'HIAGWE01') and f[2:8]==struct.unpack('<8Q',config)[1:7]
        if f[1]==1:
            assert f[10]>w.n;w=resize(c,w,f[10],'wire');continue
        if f[1]==2:
            assert role=='scan';role='emit';continue
        if f[1]==3:return dict(error='E_HIA_EDIT: '+wire_errors[f[8]],cause_kind=f[9])
        assert f[1]==0 and role=='emit' and f[11]<=w.n and f[12]<=w.n-f[11]
        return dict(wire=w.raw()[f[11]:f[11]+f[12]])

def imports():
    global planned
    shared={'same':[None,True,False,9]}
    cycle=[];cycle.append(cycle)
    nested={};nested['self']=nested;nested['list']=[nested,cycle,cycle]
    nan=struct.unpack('<d',struct.pack('<Q',0xfff8000000000023))[0]
    fixtures=[
        ('null',None),('booleans',[False,True]),('integers',[0,1,-1,2**64,-2**129,10**4000]),
        ('binary64',[0.0,-0.0,1.25,float('inf'),-float('inf'),nan]),
        ('unicode-surrogates',{'é':'中🙂','surrogate':'\ud800x\udfff','empty':''}),
        ('bytes',b'\0\xffbinary\x80'),('tuple',(None,True,'v')),
        ('ordered-map',{'last':4,'first':1,'middle':2}),
        ('aliases',[shared,shared,{'nested':shared}]),
        ('list-cycle',cycle),('map-and-list-cycles',nested),('opaque-private',object())]
    planned=len(fixtures)+3
    c=bootstrap(growth='staged');issued=[]
    for label,value in fixtures:
        before=dict(entries)
        token=import_value(c,value,label)
        original=c['imports'][-1]['foreign_graph']
        # The foreign source bytes are the exact actual issuer bytes retained
        # by this invocation, not values reconstructed from a result plan.
        reference=graph_topology(c['foreign_raw'],1)
        issued.append((token,reference))
        for previous,expected in issued:
            root,_=borrowed(c,previous,label+'-check-old-handle')
            assert graph_topology(c['g'].raw(),root)==expected,(label,previous)
        record(label,before,dict(imported=original,result=cas(c['g'].raw()),
            previous_handles_retained=len(issued),handle=token,
            full_reachable_values_aliases_cycles_equal=True,opaque_fixture=label=='opaque-private'))
    for label,value in (
        ('borrow-json-unicode',{'z':'é🙂','a':[None,False,2**100]}),
        ('borrow-json-insertion',{'z':1,'a':{'b':3,'a':2}}),
        ('borrow-json-byte-refusal',b'not a JSON value')):
        try:expected=dict(wire=store.wire(value))
        except Exception as exc:expected=dict(error=str(exc),error_class=type(exc).__name__)
        before=dict(entries);token=import_value(c,value,label)
        actual=wire_selected(c,token,label)
        if 'wire' in expected:assert actual==expected,(label,expected,actual)
        else:assert actual.get('error')==expected['error'],(label,expected,actual)
        record(label,before,dict(expected=cas(encoded(expected)),actual=cas(encoded(actual)),
            actual_complete_native_borrow_and_graph_wire=True))
def semantics():
    global planned,CATALOG
    CATALOG=SMALL_CATALOG
    cases=[
      ('empty',(),None,(),False),
      ('three-roots',('/one','/two','/three'),None,(),False),
      ('unicode-roots',('/é','/中','/emoji-🙂'),None,(),False),
      ('duplicate-roots',('/same','/same'),None,(),False),
      ('isdir-false',('/one','/two'),None,('/resolved/one',),False),
      ('example-assembly-mismatch',(),None,(),True),
      ('profile-failure-after-partial-map',(),'profile:2',(),False),
      ('json-failure-after-native-macro',(),'json:6',(),False)]
    planned=len(cases)
    for args in cases:check(*args)
def constructor_failures():
    global planned
    # The original observer numbers occurrences from zero. Obtain each exact
    # fail label from its complete original trace; never guess a native phase.
    empty=oracle(());roots=oracle(('/a','/b'))
    def observed_label(baseline,kind,index):
        selected=[r['label'] for r in baseline['trace'] if r['kind']==kind]
        assert 0<=index<len(selected),(kind,index,selected)
        return selected[index]
    cases=[
        ('catalog',(),observed_label(empty,'catalog',0)),
        ('installation',(),observed_label(empty,'installation',0)),
        ('open',(),observed_label(empty,'open',0)),
        ('resolve',('/a','/b'),observed_label(roots,'resolve',1)),
        ('isdir',('/a','/b'),observed_label(roots,'isdir',1)),
        ('str',('/a','/b'),observed_label(roots,'str',1)),
        ('digest',(),observed_label(empty,'digest',0))]
    profiles=[r['label'] for r in empty['trace'] if r['kind']=='profile']
    assert len(profiles)==7
    cases.extend(('profile-'+str(i),(),point) for i,point in enumerate(profiles))
    for label,kind,index in (
        ('resource-json','json',1),('resource-file','file',2),
        ('resource-put','put',2),('example-first-verify','verify',0),
        ('example-render','render',0),('example-assemble','assemble',0)):
        cases.append((label,(),observed_label(empty,kind,index)))
    jsons=[r['label'] for r in empty['trace'] if r['kind']=='json']
    assert jsons
    cases.append(('manifest-last-json',(),jsons[-1]))
    planned=len(cases);assert planned==21
    for label,paths,point in cases:
        c=check(label,paths,fail_at=point)
        assert c['observed_error'] is not None and c['observed_error']['error_class']=='PeerFailure',label

def full_catalog():
    global planned,CATALOG
    CATALOG=json.loads(read(ROOT/'dependencies/HIA_AGENT_NATIVE_TOOL_CATALOG.json'))
    assert len(CATALOG['tools'])==11
    planned=1;check('all-eleven-tools-arrive-at-actual-catalog-return',('/catalog-root',))
    CATALOG=SMALL_CATALOG
def growths():
    global planned
    planned=3
    contexts=[check('complete-'+mode,('/a','/b'),growth=mode) for mode in ('exact','spare','staged')]
    assert len(contexts[2]['growth_events'])>len(contexts[1]['growth_events'])
    assert all(c['imports'] and c['merge_calls'] for c in contexts)
    assert contexts[0]['trace']==contexts[1]['trace']==contexts[2]['trace']
def protocol_refuse(c,fields,payload,label,advertised=None,unchanged=False):
    fields=list(fields);fields[5]=c['bseq']
    raw=pack(*fields)+payload;r=Buffer(len(raw),raw);before=c['pw'].raw()
    ret=invoke('registry',c['g'],r,c['pw'],label,advertised)
    assert ret==BAD,(label,ret)
    after=c['pw'].raw()
    if unchanged:
        assert after==before
        return
    assert struct.unpack_from('<Q',after,C['B_PHASE'])[0]==99
    # No value handle/current Graph/last-completed command can be published by
    # a refused result. Failure scratch, active command and event can change.
    for at in (C['B_LEASE'],C['B_BYTES'],C['B_NODES'],C['B_EDGES'],C['B_POOL'],
        C['B_ISSUED'],C['B_LAST_COMMAND']):
        assert after[at:at+8]==before[at:at+8],(label,at)
    assert invoke('registry',c['g'],r,c['pw'],label+'-permanent')==BAD
    assert c['pw'].raw()==after
def protocol_case(label,body):
    before=dict(entries)
    with forbidden_pure_owners():body()
    record(label,before,dict(private_protocol=True,actual_namespace_entries=0))
def protocols():
    global planned
    controls=[]
    def bad_header(index,value):
        c=bootstrap();fields,payload=registry_command(c,2)
        fields[index]=value(c,fields) if callable(value) else value
        # Previous-sequence mutation must not be repaired by the generic helper.
        if index==5:
            raw=pack(*fields);r=Buffer(len(raw),raw)
            assert invoke('registry',c['g'],r,c['pw'],'bad-previous-sequence')==BAD
            after=c['pw'].raw();assert struct.unpack_from('<Q',after,C['B_PHASE'])[0]==99
            assert invoke('registry',c['g'],r,c['pw'],'bad-previous-sequence-again')==BAD
            assert c['pw'].raw()==after;return
        protocol_refuse(c,fields,payload,'header-'+str(index))
    for index,value in ((0,0),(1,0),(1,7),(2,0),(2,38),(3,84),(4,0),(4,999),
        (5,999),(6,0),(6,54),(7,0),(8,1),(9,384),(10,HANDLE_BASE+1),
        (11,4300),(12,54),(13,128),(14,512),(15,1)):
        controls.append(('command-'+str(index)+'-'+str(value),lambda i=index,v=value:bad_header(i,v)))
    def ready(value=None):
        c=bootstrap();import_value(c,{'payload':['x',2,True]} if value is None else value,
            'actual-result-fixture',stop_before_done=True)
        assert struct.unpack_from('<Q',c['mw'].raw(),264)[0]==0
        return c
    def bad_actual_header(index):
        c=ready();payload=bytearray(c['foreign_raw']+c['mw'].raw())
        payload[len(c['foreign_raw'])+index*8]^=1
        fields,_=registry_command(c,4,payload,actual=384,
            foreign_bytes=c['foreign_bytes'],child_bytes=c['mw'].n)
        protocol_refuse(c,fields,payload,'actual-merge-header-'+str(index))
    for index in range(64):
        controls.append(('actual-merge-word-'+str(index),lambda i=index:bad_actual_header(i)))
    def bad_result(kind):
        c=ready();raw=bytearray(c['mw'].raw());base=512
        n,e=struct.unpack_from('<Q',raw,base+16)[0],struct.unpack_from('<Q',raw,base+32)[0]
        if kind=='output-magic':at=base
        elif kind=='root-pair-kind':at=base+64
        elif kind=='left-node':at=base+128+48
        elif kind=='right-node':at=base+(struct.unpack_from('<Q',c['g'].raw(),16)[0]+2)*64+48
        elif kind=='first-edge':at=base+64+n*64
        elif kind=='last-edge':at=base+64+n*64+(e-1)*8
        elif kind=='pool-first':at=base+64+n*64+e*8
        elif kind=='pool-last':at=len(raw)-1
        else:raise AssertionError(kind)
        raw[at]^=1;payload=c['foreign_raw']+raw
        fields,_=registry_command(c,4,payload,actual=384,
            foreign_bytes=c['foreign_bytes'],child_bytes=len(raw))
        protocol_refuse(c,fields,payload,'actual-result-'+kind)
    for kind in ('output-magic','root-pair-kind','left-node','right-node',
        'first-edge','last-edge','pool-first','pool-last'):
        controls.append(('actual-result-'+kind,lambda k=kind:bad_result(k)))
    def result_extent(which):
        c=ready();payload=c['foreign_raw']+c['mw'].raw()
        fields,_=registry_command(c,4,payload,actual=384,
            foreign_bytes=c['foreign_bytes'],child_bytes=c['mw'].n)
        if which=='return':fields[9]=128
        elif which=='foreign':fields[13]-=1
        elif which=='workspace':fields[14]-=1
        elif which=='trailing':
            payload+=b'\0';fields[8]+=1
        elif which=='truncated':
            payload=payload[:-1];fields[8]-=1;fields[14]-=1
        else:raise AssertionError(which)
        protocol_refuse(c,fields,payload,'result-extent-'+which)
    for which in ('return','foreign','workspace','trailing','truncated'):
        controls.append(('result-extent-'+which,lambda x=which:result_extent(x)))
    def own_growth(which):
        c=bootstrap();f=reserve_foreign(c,'own-grow')
        foreign=capture({'x':'y'},lease=f[9]);c['foreign_raw']=foreign;c['foreign_bytes']=len(foreign)
        fields,payload=registry_command(c,3,foreign,foreign_bytes=len(foreign))
        f,r=registry_entry(c,fields,payload,'first-own-grow');assert f[1]==1
        c['pw']=grow(c['pw'],f[8]);fields[1]=5;fields[5]=c['bseq']
        if which=='source-lease':
            raw=bytearray(c['g'].raw());struct.pack_into('<Q',raw,8,54);c['g']=Buffer(len(raw),raw);fields[6]=54
        elif which=='foreign-header':
            payload=bytearray(payload);struct.pack_into('<Q',payload,24,2)
        elif which=='new-command':fields[4]+=1
        elif which=='restart-import':fields[1]=3
        elif which=='wrong-result':fields[9]=384
        else:raise AssertionError(which)
        protocol_refuse(c,fields,payload,'own-growth-'+which)
    for which in ('source-lease','foreign-header','new-command','restart-import','wrong-result'):
        controls.append(('own-growth-'+which,lambda x=which:own_growth(x)))
    def forbidden_pending(which):
        c=bootstrap();f=reserve_foreign(c,'pending')
        if which=='reserve':fields,payload=registry_command(c,2)
        elif which=='borrow':fields,payload=registry_command(c,6,root=HANDLE_BASE+1)
        else:raise AssertionError(which)
        protocol_refuse(c,fields,payload,'pending-'+which)
    for which in ('reserve','borrow'):
        controls.append(('pending-'+which,lambda x=which:forbidden_pending(x)))
    def bad_handle(token):
        c=bootstrap();fields,payload=registry_command(c,6,root=token)
        protocol_refuse(c,fields,payload,'unissued-handle')
    for token in (0,1,HANDLE_BASE,HANDLE_BASE+1,MAX):
        controls.append(('unissued-handle-'+str(token),lambda t=token:bad_handle(t)))
    def replay_done():
        c=ready();fields,payload=registry_command(c,4,c['foreign_raw']+c['mw'].raw(),
            actual=384,foreign_bytes=c['foreign_bytes'],child_bytes=c['mw'].n)
        f,r=registry_entry(c,fields,payload,'valid-done')
        adopt_import(c,f,r)
        # A duplicate completed child cannot be consumed against the new graph.
        fields[6]=struct.unpack_from('<Q',c['g'].raw(),8)[0];fields[7]=c['g'].n
        protocol_refuse(c,fields,payload,'completed-result-replay')
    controls.append(('completed-result-replay',replay_done))
    def reserved_wrap():
        c=bootstrap();c['pw'].write(C['B_NEXT_LEASE'],pack(MAX-1))
        fields,payload=registry_command(c,2);protocol_refuse(c,fields,payload,'lease-overflow')
    controls.append(('lease-overflow',reserved_wrap))
    def event_wrap():
        c=bootstrap();c['pw'].write(C['B_SEQUENCE'],pack(MAX));c['bseq']=MAX
        fields,payload=registry_command(c,2);raw=pack(*fields);r=Buffer(len(raw),raw)
        assert invoke('registry',c['g'],r,c['pw'],'event-overflow')==BAD
        after=c['pw'].raw();assert struct.unpack_from('<Q',after,C['B_PHASE'])[0]==99
        assert invoke('registry',c['g'],r,c['pw'],'event-overflow-permanent')==BAD
        assert c['pw'].raw()==after
    controls.append(('event-overflow-outer-first-BAD',event_wrap))
    def short_workspace():
        c=bootstrap();fields,payload=registry_command(c,2)
        protocol_refuse(c,fields,payload,'short-workspace',8191,True)
    controls.append(('short-workspace-outer-retirement',short_workspace))
    def pure_poison():
        c=bootstrap();fields,payload=registry_command(c,6,root=1)
        protocol_refuse(c,fields,payload,'poison-before-pure')
        fields,payload=command(c,1,root=1);r=Buffer(128,pack(*fields));after=c['pw'].raw()
        assert invoke('pure',c['g'],r,c['pw'],'shared-pure-must-refuse')==BAD
        assert c['pw'].raw()==after
    controls.append(('poison-shared-pure-entry',pure_poison))
    def output_field_reserved():
        c=ready();c['pw'].write(C['B_ISSUED'],pack(1))
        c['pw'].write(8192,pack(0,1))
        fields,payload=registry_command(c,4,c['foreign_raw']+c['mw'].raw(),
            actual=384,foreign_bytes=c['foreign_bytes'],child_bytes=c['mw'].n)
        protocol_refuse(c,fields,payload,'registry-row-invalid-before-any-commit')
    controls.append(('registry-invalid-before-commit',output_field_reserved))
    def bad_boot(digits,dirty=False):
        raw=capture(['/state',[]],lease=53)
        c=dict(g=Buffer(len(raw),raw),pw=Buffer(8192),active=1,bseq=0,blast=0)
        if dirty:c['pw'].write(6000,b'\1')
        fields,payload=registry_command(c,1,digits=digits)
        protocol_refuse(c,fields,payload,'invalid-bootstrap')
    controls.append(('bootstrap-digits-below-minimum',lambda:bad_boot(639)))
    controls.append(('bootstrap-dirty-private-workspace',lambda:bad_boot(4300,True)))
    def boot_replay():
        c=bootstrap();fields=[M(b'HIAWGC01'),1,37,83,1,0,53,c['g'].n,0,0,0,4300,53,0,0,0]
        r=Buffer(128,pack(*fields));before=c['pw'].raw()
        assert invoke('registry',c['g'],r,c['pw'],'BOOT-cannot-reset')==BAD
        after=c['pw'].raw();assert struct.unpack_from('<Q',after,C['B_PHASE'])[0]==99
        assert invoke('registry',c['g'],r,c['pw'],'BOOT-cannot-reset-again')==BAD
        assert c['pw'].raw()==after
    controls.append(('bootstrap-cannot-reset-existing-session',boot_replay))
    def wrong_grow_header(which):
        c=bootstrap();f=reserve_foreign(c,'actual-grow')
        foreign=capture({'v':'x'},lease=f[9]);c['foreign_raw']=foreign;c['foreign_bytes']=len(foreign)
        f,r=prepare_import(c,foreign,'actual-grow')
        merge_actual(c,f,r,'actual-grow')
        assert struct.unpack_from('<Q',c['mw'].raw(),264)[0]==1
        actual=bytearray(c['mw'].raw())
        at={'needed':152,'action':264,'source':384}[which]
        actual[at]^=1;payload=foreign+actual
        fields,_=registry_command(c,4,payload,actual=384,foreign_bytes=len(foreign),child_bytes=len(actual))
        protocol_refuse(c,fields,payload,'changed-actual-grow-'+which)
    for which in ('needed','action','source'):
        controls.append(('changed-actual-grow-'+which,lambda x=which:wrong_grow_header(x)))
    planned=len(controls)
    for label,body in controls:protocol_case(label,body)
def large_values():
    global planned
    planned=1;before=dict(entries)
    c=bootstrap(growth='exact');value='x'*(9<<20)
    token=import_value(c,value,'foreign-value-over-eight-mib')
    foreign=cas(c['foreign_raw']);assert c['g'].n>8<<20
    root,config=borrowed(c,token)
    assert graph_topology(c['g'].raw(),root)==graph_topology(c['foreign_raw'],1)
    assert struct.unpack_from('<Q',config,32)[0]==8<<20
    # The actual import is complete; no language quota was applied by the
    # registry. Serialization is a separate late consumer, tested elsewhere.
    record('private-import-over-eight-mib',before,dict(foreign=foreign,result=cas(c['g'].raw()),
        growth_events=c['growth_events'],import_completed=True,wire_executed=False,
        no_new_intermediate_byte_quota=True))
def large_nodes():
    global planned
    planned=1;before=dict(entries)
    c=bootstrap();value=[[] for _ in range(262145)]
    token=import_value(c,value,'foreign-graph-over-language-node-count')
    assert struct.unpack_from('<Q',c['foreign_raw'],16)[0]>262144
    root,_=borrowed(c,token)
    raw=c['g'].raw();kind,at,size,first,count,identity,aux,z=struct.unpack_from('<8Q',raw,root*64)
    assert kind==5 and count==262145
    # Complete reachable node/alias comparison is independent of relocated IDs.
    assert graph_topology(raw,root)==graph_topology(c['foreign_raw'],1)
    record('private-import-over-262144-nodes',before,dict(
        foreign=cas(c['foreign_raw']),result=cas(raw),growth_events=c['growth_events'],
        no_new_intermediate_node_quota=True))


# NEW composition: complete original Store methods are now the oracle, while
# only the actual namespace put/SQL effect results remain foreign fixtures.
# All plans and Graph packets are frozen before the actual native interval.
LegacyNamespace=Namespace
legacy_initializer_oracle=oracle
legacy_configure=configure
legacy_initializer_drive=drive
ORACLE_STORE_RECORDS=[]
ORACLE_NAMESPACE_FAILURE=None
ORACLE_CORRUPTED_REFERENCE=None
ACTIVE_STORE_CASE=None

class StoreFixtureDB:
    def __init__(self,namespace):self.namespace=namespace
    def execute(self,sql,binds):
        ns=self.namespace;row=ns.active_store_record
        assert row is not None and row['peer']==11
        label=row['label']+':sql'
        operation=dict(operation=2,sql=sql,binds=tuple(binds),label=label)
        if ORACLE_NAMESPACE_FAILURE==label:
            operation['error']=label;row['operations'].append(operation)
            raise PeerFailure(label)
        operation['error']=None;row['operations'].append(operation)
        return None

class Namespace(LegacyNamespace):
    def __init__(self,root,observer,reference):
        super().__init__(root,observer,reference)
        self.db=StoreFixtureDB(self);self.active_store_record=None
    def start_store_record(self,peer,kind,number,args):
        assert self.active_store_record is None
        cells={} if self.observer is None else dict(zip(
            self.observer.__code__.co_freevars,
            [cell.cell_contents for cell in self.observer.__closure__ or ()]))
        row=dict(peer=peer,kind=kind,number=number,label='store-'+kind+':'+str(number),
            args=normalized(copy.deepcopy(args)),operations=[],result=None,error=None,
            state=snapshot(cells['owner']) if 'owner' in cells else None)
        ORACLE_STORE_RECORDS.append(row);self.active_store_record=row
        return row
    def profile(self,name,body):
        row=self.start_store_record(11,'profile',self.profile_count,(name,body))
        try:
            result=store.AgentStore.profile(self,name,body)
            row['result']=normalized(result)
        except BaseException as exc:
            row['error']=observed_exception(exc);raise
        finally:self.active_store_record=None
        self.observer('profile',(name,body),result)
        self.profile_count+=1
        return result
    def json(self,value,kind,metadata=None):
        if self.active_store_record is not None:
            # Original profile invokes original json, with no invented extra
            # initializer-level call or independent transaction.
            assert self.active_store_record['peer']==11 and kind=='profile'
            return store.AgentStore.json(self,value,kind,metadata)
        row=self.start_store_record(15,'json',self.json_count,(value,kind))
        try:
            result=store.AgentStore.json(self,value,kind,metadata)
            row['result']=normalized(result)
        except BaseException as exc:
            row['error']=observed_exception(exc);raise
        finally:self.active_store_record=None
        self.observer('json',(value,kind),result)
        self.json_count+=1
        return result
    def put(self,value,kind,metadata=None):
        row=self.active_store_record
        if row is None:
            assert metadata is None
            return super().put(value,kind)
        assert metadata is None
        label=row['label']+':put'
        operation=dict(operation=1,wire=bytes(value),kind=kind,metadata=metadata,label=label)
        if ORACLE_NAMESPACE_FAILURE==label:
            operation['error']=label;row['operations'].append(operation)
            raise PeerFailure(label)
        key=('profile-'+row['args'][0]) if row['peer']==11 else 'json-'+str(self.json_count)
        ref=self.reference(key)
        if ORACLE_CORRUPTED_REFERENCE is not None and ORACLE_CORRUPTED_REFERENCE[0]==row['label']:
            ref=copy.deepcopy(ref);ref['sha256']=ORACLE_CORRUPTED_REFERENCE[1]
        operation['error']=None;operation['result']=ref;row['operations'].append(operation)
        return ref

def oracle(paths,fail_at=None,false_dirs=(),mismatch=False,namespace_failure=None,corrupted_ref=None):
    global ORACLE_STORE_RECORDS,ORACLE_NAMESPACE_FAILURE,ORACLE_CORRUPTED_REFERENCE
    ORACLE_STORE_RECORDS=[];ORACLE_NAMESPACE_FAILURE=namespace_failure
    ORACLE_CORRUPTED_REFERENCE=corrupted_ref
    try:
        result=legacy_initializer_oracle(paths,fail_at,false_dirs,mismatch)
        result['store_records']=ORACLE_STORE_RECORDS
        # Capture immutable foreign result packets only after the complete
        # original constructor/methods have independently produced this trace.
        for row in result['store_records']:
            row['plan']=[]
            for operation in row['operations']:
                error=operation['error']
                row['plan'].append(dict(operation=operation['operation'],
                    error=None if error is None else ('fixture-issued-peer-exception:'+error).encode(),
                    result_packet=capture(operation['result'],lease=1)
                        if operation['operation']==1 and error is None else None))
        return result
    finally:
        ORACLE_NAMESPACE_FAILURE=None;ORACLE_CORRUPTED_REFERENCE=None

class StoreRegistryAdapter(DigestRegistryAdapter):
    def reserved_request(self):return self.c['rr'].raw()
    def packet(self,foreign):
        return self.import_packet(foreign,False,None)
    def packet_checked(self,foreign,expected):
        return self.import_packet(foreign,True,expected)
    def import_packet(self,foreign,native_profile,expected):
        c=self.c;c['foreign_raw']=foreign;c['foreign_bytes']=len(foreign)
        reserved=struct.unpack_from('<32Q',c['pw'].raw(),512)
        assert reserved[1]==2
        fields,payload=registry_command(c,3,foreign,foreign_bytes=len(foreign))
        if expected is not None:
            assert pack(*fields)==expected and payload==foreign
        label='actual-native-store-profile' if native_profile else 'foreign-issued-namespace-put'
        f,r=prepare_import(c,foreign,label)
        while True:
            merge_actual(c,f,r,label)
            f,r=merge_submit(c,label)
            if f[1]==4:continue
            handle=adopt_import(c,f,r)
            c['imports'].append(dict(ordinal=len(c['imports'])+1,label=label,
                initializer_pending=c['f'][7],foreign_graph=cas(foreign),
                imported_graph=cas(c['g'].raw()),handle=handle,graph_root=f[20],
                source_lease=reserved[9],output_lease=reserved[10],
                foreign_issuer=not native_profile))
            c['reg'].kinds[handle]='value'
            return handle,c['pw'].raw()[512:768]

def configure(paths,baseline=None,growth='exact',extra=(),mini=False):
    c=legacy_configure(paths,baseline,growth,extra,mini)
    assert ACTIVE_STORE_CASE is not None
    c['store_expectations']=ACTIVE_STORE_CASE['store_records']
    c['store_index']=0;c['store_results']=[]
    return c

def native_store_peer(c,fail_at):
    f=c['f'];peerid=f[6];assert f[1]==2 and peerid in (11,15)
    index=c['store_index'];assert index<len(c['store_expectations'])
    expected=c['store_expectations'][index];c['store_index']+=1
    assert expected['peer']==peerid
    # Snapshot/argument reads happen before the Store component's initial
    # native BORROW. No observer may advance its pending registry sequence.
    prior=native_state(c)
    value=c['reg'].get(f[14])
    literal=c['w'].raw()[f[23]:f[23]+f[24]].decode()
    args=(literal,value) if peerid==11 else (value,literal)
    assert normalized(args)==expected['args']
    assert prior==expected['state'],(expected['label'],'method-entry partial state')
    initial_workspace=c['w'].raw();before=dict(DH.counts);before_entries=dict(entries)
    adapter=StoreRegistryAdapter(c)
    route=SV.Route(adapter,initial_workspace,expected['plan'],
        label='full-initializer-'+expected['label'],
        own_short_once=(c['growth']=='staged'))
    reply=route.finish()
    assert c['w'].raw()==initial_workspace
    assert entries['sequence']==before_entries['sequence']
    calls=[]
    for operation in expected['operations']:
        if operation['operation']==1:
            calls.append({key:operation[key] for key in ('operation','wire','kind','metadata')})
        else:
            calls.append({key:operation[key] for key in ('operation','sql','binds')})
    verification=dict(result=expected['result'],calls=calls,error=None)
    if expected['error'] is not None:
        verification['error']=dict(error_class=expected['error']['error_class'],
            text=expected['error']['error'])
    route.validate(verification,peerid)
    q=struct.unpack_from('<32Q',reply)
    assert q[:5]==(M(b'HIAWIR01'),37,83,f[7],peerid)
    if q[5]==0:
        result=(c['reg'].get(q[8]),c['reg'].get(q[9])) if peerid==11 else c['reg'].get(q[8])
        kind='profile' if peerid==11 else 'json'
        namespace=c['reg'].get(f[15],'namespace')
        if observe(c,kind,args,result,fail_at):
            if peerid==11:namespace.profile_count+=1
            else:namespace.json_count+=1
            c['r']=Buffer(len(reply),reply);c['reply_count']+=1
    else:
        assert q[5]==1 and q[6]==0
        c['r']=Buffer(len(reply),reply);c['reply_count']+=1
    c['store_results'].append(dict(
        label=expected['label'],peer=peerid,pending=f[7],
        expected_method=cas(encoded({k:v for k,v in expected.items() if k!='plan'})),
        actual_reply=cas(reply),owner_state_before=cas(encoded(prior)),
        owner_workspace_unchanged_during_store=True,sequence_not_reentered=True,
        native_store_entries={k:v-before.get(k,0) for k,v in DH.counts.items()},
        outer_entries={k:entries[k]-before_entries[k] for k in entries},
        namespace_calls=route.namespace_calls,namespace_results_are_foreign=True,
        actual_physical_namespace_entries=0,wire_sessions=route.wire_starts,
        own_grows=route.own_grows,wire_grows=route.producer_grows,
        profile_handle=route.handle,original_reference_handle=route.ref_handle,
        full_method_error_and_order_equal=True))

def peer(c,fail_at,false_dirs,mismatch):
    if c['f'][6]==8:native_digest_peer(c,fail_at)
    elif c['f'][6] in (11,15):native_store_peer(c,fail_at)
    elif c['f'][6] in (2,9,10,19):pure_peer(c,'pending-'+str(c['f'][7]))
    else:foreign_peer(c,fail_at,false_dirs,mismatch)

def drive(paths,label,fail_at=None,false_dirs=(),mismatch=False,baseline=None,growth='exact'):
    c=configure(paths,baseline,growth)
    while True:
        ret=invoke('sequence',c['s'],c['r'],c['w'],label)
        if ret==BAD:return dict(private_bad=True),c
        f=frame(c,ret)
        if f[1]==1:
            c['w']=resize(c,c['w'],f[8],'sequence');c['grows']+=1;continue
        if f[1]==2:
            peer(c,fail_at,false_dirs,mismatch);continue
        if f[1]==0:return dict(state=native_state(c),error=None),c
        assert f[1]==3
        if f[27]==0:
            assert f[28]==3
            payload=c['r'].raw()[f[30]:f[30]+f[31]]
            prefix=b'fixture-issued-peer-exception:'
            if f[29]==90001:
                assert payload.startswith(prefix)
                error=dict(error_class='PeerFailure',error=payload[len(prefix):].decode(),attributes={})
            else:
                # Comparison observer for the exact native exception capsule.
                # This is not a hosted production error-rendering fallback.
                assert f[29]==909 and len(payload)>=64
                ex=struct.unpack_from('<8Q',payload)
                assert ex[:3]==(M(b'HIAWSX01'),1,1) and 1<=ex[3]<=16
                assert ex[5]==len(payload)-64 and ex[6]==len(payload) and ex[7]==0
                error=dict(error_class='HIAEditRejected',error=payload[64:].decode(),attributes={})
        else:
            assert f[28]==2 and f[29]==37 and f[27] in (1,2)
            error=dict(error_class={1:'AgentRejected',2:'RuntimeError'}[f[27]],
                error=c['w'].raw()[f[30]:f[30]+f[31]].decode(),attributes=(dict(
                    code='E_HIA_PROFILE',phase='admission',retry_action='correct_input',
                    details_artifact=None) if f[27]==1 else {}))
        return dict(state=native_state(c),error=error),c

def check(label,paths=(),fail_at=None,false_dirs=(),mismatch=False,growth='exact',
          namespace_failure=None,corrupted_ref=None):
    global ACTIVE_STORE_CASE
    expected=oracle(paths,fail_at,false_dirs,mismatch,namespace_failure,corrupted_ref)
    baseline=oracle(paths)
    ACTIVE_STORE_CASE=expected
    before=dict(entries);before_native=dict(DH.counts)
    try:
        with forbidden_pure_owners(),SV.actual_only():
            actual,c=drive(paths,label,fail_at,false_dirs,mismatch,baseline,growth)
    finally:ACTIVE_STORE_CASE=None
    assert actual=={k:expected[k] for k in ('state','error')},(label,expected['error'],actual)
    assert c['trace']==expected['trace'],(label,'complete ordered calls/partial attributes',
        len(c['trace']),len(expected['trace']))
    assert c['store_index']==len(expected['store_records'])
    assert len(c['store_results'])==c['store_index']
    if expected['error'] is None:
        assert {r['peer'] for r in c['pure_results']}=={2,9,10,19}
        assert {r['mode'] for r in c['pure_results'] if r['peer']==9}==set(range(1,7))
        assert {r['mode'] for r in c['pure_results'] if r['peer']==10}=={1,2,3,4}
        assert {r['peer'] for r in c['store_results']}=={11,15}
        assert sum(r['peer']==11 for r in c['store_results'])==7
        assert c['store_results'][-1]['peer']==15
    aliases=initializer_aliases(c)
    assert all(a['ordinal']==i+1 for i,a in enumerate(c['imports']))
    assert entries['merge']-before['merge']>=2*len(c['imports'])
    record(label,before,dict(reference_trace=cas(encoded(expected['trace'])),
        actual_trace=cas(encoded(c['trace'])),expected_state=cas(encoded(expected['state'])),
        actual_state=cas(encoded(actual['state'])),error=actual['error'],
        reference_store_methods=cas(encoded([
            {k:v for k,v in r.items() if k!='plan'} for r in expected['store_records']])),
        store_results=c['store_results'],imports=c['imports'],actual_graph_alias_checks=aliases,
        pure_results=c['pure_results'],growth_events=c['growth_events'],
        actual_digest_results=c.get('digest_results',[]),
        actual_child_calls=c['child_calls'],actual_merge_calls=c['merge_calls'],
        actual_borrows=c['borrow_count'],
        additional_actual_entries={k:v-before_native.get(k,0) for k,v in DH.counts.items()},
        complete_original_store_methods_oracle=True,
        remaining_eight_peer_ids_are_foreign=True,actual_namespace_entries=0,
        exact_complete_state_error_and_call_order=True,preloaded_future_values=False,
        ordinary_initialization_closed=False))
    c['observed_error']=actual['error'];return c

def store_semantics():
    global planned,CATALOG
    CATALOG=SMALL_CATALOG
    cases=[
      ('empty',(),None,(),False),
      ('three-roots',('/one','/two','/three'),None,(),False),
      ('unicode-roots',('/e\u0301','/\u4e2d','/emoji-\U0001f642'),None,(),False),
      ('duplicate-roots',('/same','/same'),None,(),False),
      ('isdir-false',('/one','/two'),None,('/resolved/one',),False),
      ('example-assembly-mismatch',(),None,(),True),
      ('profile-observer-failure-after-native-sql',(),'profile:2',(),False),
      ('json-observer-failure-after-native-method',(),'json:6',(),False)]
    planned=len(cases)
    for args in cases:check(*args)

def store_effect_failures():
    global planned,CATALOG
    CATALOG=SMALL_CATALOG
    complete_reference=oracle(())
    effects=[operation['label'] for row in complete_reference['store_records']
        for operation in row['operations']]
    assert len([s for s in effects if s.endswith(':sql')])==7
    chosen=['store-profile:0:put','store-profile:2:put','store-profile:6:put',
        'store-profile:0:sql','store-profile:3:sql','store-profile:6:sql',
        'store-json:0:put','store-json:6:put']
    final_json=[r for r in complete_reference['store_records'] if r['peer']==15][-1]['label']+':put'
    if final_json not in chosen:chosen.append(final_json)
    assert set(chosen)<=set(effects)
    planned=len(chosen)+3
    for point in chosen:
        c=check('effect-'+point,namespace_failure=point)
        assert c['observed_error']['error_class']=='PeerFailure'
    for name,value in (('bytes',b'not-json'),('surrogate','\ud800'),('nan',float('nan'))):
        c=check('reference-wire-'+name,corrupted_ref=('store-profile:2',value))
        assert c['observed_error']['error_class']=='HIAEditRejected'
        last=c['store_results'][-1]
        assert last['namespace_calls']==1 and last['profile_handle'] is None

def store_catalog():
    global planned,CATALOG
    CATALOG=json.loads(read(ROOT/'dependencies/HIA_AGENT_NATIVE_TOOL_CATALOG.json'))
    assert len(CATALOG['tools'])==11
    planned=1;check('eleven-tools-complete-native-store-values',('/catalog-root',))
    CATALOG=SMALL_CATALOG

def store_growth():
    global planned,CATALOG
    CATALOG=SMALL_CATALOG;planned=3
    contexts=[check('whole-store-'+mode,('/a','/b'),growth=mode)
        for mode in ('exact','spare','staged')]
    assert contexts[0]['trace']==contexts[1]['trace']==contexts[2]['trace']
    assert all(c['store_results'] and c['digest_results'] for c in contexts)
    assert len(contexts[2]['growth_events'])>len(contexts[1]['growth_events'])

RESOURCE_HELPER=Path(os.environ['HIA_RESOURCE_ROOT'])/'development/resource_initializer_join_r3.py'
resource_helper_raw=read(RESOURCE_HELPER)
assert (len(resource_helper_raw),digest(resource_helper_raw))==(20355,'1997d92ddd96c063407726dd7d514d5312d76c32392f03b03a1a8bdfc80aaed0')
resource_helper_tree=ast.parse(resource_helper_raw)
resource_body=ast.literal_eval(next(n.value for n in resource_helper_tree.body
    if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='BODY' for t in n.targets)))
exec(compile(ast.parse(resource_body),str(RESOURCE_HELPER),'exec'),globals())


PROGRAM_HELPER=Path(os.environ['HIA_PROGRAM_BRIDGE_ROOT'])/'development/program_initializer_join_r2.py'
program_helper_raw=read(PROGRAM_HELPER)
assert (len(program_helper_raw),digest(program_helper_raw))==(39838,'6abf489a20bfc5cff74c96b0602a4595d5345830cdc30d9b38200ba0ed573a9e')
program_helper_tree=ast.parse(program_helper_raw)
program_body=ast.literal_eval(next(n.value for n in program_helper_tree.body
    if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='BODY' for t in n.targets)))
exec(compile(ast.parse(program_body),str(PROGRAM_HELPER),'exec'),globals())

INPUT_PINS=[
  {
    "path": "tools/worker_init_registry_common.py",
    "bytes": 10229,
    "sha256": "d501b2c51cc8b8485599af9f4848a2fd69d06262de5aaf21d9e9f5111a0edccd",
    "gitsha": "e23d85112c35253bd3df8c349125e212a61bb614"
  },
  {
    "path": "tools/worker_init_registry_result.py",
    "bytes": 9003,
    "sha256": "533e8a95de9c1d13f3b9e05d159f522b63cacd653490af0bafafd0743d98a951",
    "gitsha": "8f5db6601f2a28e4a8b98231ce3c664052fd84f7"
  },
  {
    "path": "tools/generate_hia_agent_worker_init_registry.py",
    "bytes": 7195,
    "sha256": "0ec0e0699acc444824821e428309ca97cc74b88c87bd27c4235d8fed96b73a33",
    "gitsha": "7ee9b7cf7b01b28b50dec8a88a3213bea75e14eb"
  },
  {
    "path": "docs/HIA_WORKER_INITIALIZER_REGISTRY_ABI_R2.md",
    "bytes": 11987,
    "sha256": "6d23a7bb6a2b0f363034093db836cd23cd2ba6d9e5e0b1a246f1552e5cddfa01",
    "gitsha": "df39f3acff0b6889bccaea115845308c404c4093"
  },
  {
    "path": "tools/worker_init_pure_common.py",
    "bytes": 9085,
    "sha256": "f8f54a86ed80cd977ea54faf5c75007d8eca98be752c5ad8e9d9fce780bf68f5",
    "gitsha": "1151c9d63ce2f189fd0fcc72bf00870a55370544"
  },
  {
    "path": "tools/worker_init_pure_prepare.py",
    "bytes": 15262,
    "sha256": "0862ff31b76d71edc9a47fc48632801a69960e6739a8b3d763151c3e5bb0dfb7",
    "gitsha": "f556d39f9d65a17874586a3a9f1a2b9d8e2d839a"
  },
  {
    "path": "tools/worker_init_pure_result.py",
    "bytes": 10563,
    "sha256": "e26d47cdc4cc172183ae08ffbcbf3ec88db53d282a0d46f60a505a52dc823d38",
    "gitsha": "403d6012ca7833bc4da3fb5d40ee3cc66aad7966"
  },
  {
    "path": "tools/generate_hia_agent_worker_init_pure.py",
    "bytes": 7025,
    "sha256": "1b7d97ba633a40814586b0101d786b2b660ded3c59709dc34949f831b69a6974",
    "gitsha": "d95ce033f7d13ca8fa580de5eb8e83f9c85e3b18"
  },
  {
    "path": "docs/HIA_WORKER_INITIALIZER_PURE_JOIN_ABI_R1.md",
    "bytes": 13662,
    "sha256": "32f39cf44c8f097b0ffd4e166464fd4eb0d4fd3500ffdb2f683402dfc0bee38b",
    "gitsha": "93dec7410a4e6ae97456fdc284bf67a15ef0f66e"
  },
  {
    "path": "dependencies/generate_hia_agent_worker_init_values.py",
    "bytes": 22197,
    "sha256": "9a786c3d3982b736bd068eb522b8b8d7649da80bd4813f9c235e2c83461a95ac",
    "gitsha": "a0bdd8d99238cb52c6669be09463a57b9fdd0c78"
  },
  {
    "path": "dependencies/generate_hia_agent_worker_init_sequence.py",
    "bytes": 34300,
    "sha256": "fad447d45d40494f04280ca100f1ce1abf5e5651bce4feba8cedcfcdbdae06ef",
    "gitsha": "f9cd612bad5707d95acef736afe03b6600724d9b"
  },
  {
    "path": "dependencies/generate_hia_agent_worker_init_maps.py",
    "bytes": 19560,
    "sha256": "8a837ae4acaf11a68054c030c51d6d667d93dee4c825c8fee5bb324b9a6fc2fb",
    "gitsha": "275a8c3a5d63a94241d0651adf425ae2530d2380"
  },
  {
    "path": "tools/agent_worker_init_templates.py",
    "bytes": 13155,
    "sha256": "65d048c0eb027cbbe83be4d20f1708b96b40415c760322f1c79c4c7d3d1e93d0",
    "gitsha": "fe96d796fe71120ddef15707d6add729f96c7aec"
  },
  {
    "path": "development/sequence_oracle_source.py",
    "bytes": 32141,
    "sha256": "b809f06c0c1a0e56d5a49555e6b3010ce7c78d18707571f87c4a9b78d7d62f2b",
    "gitsha": "610dad775c08cddb0daa7be6d465318151bc95bb"
  },
  {
    "path": "development/value_mechanics_source.py",
    "bytes": 27233,
    "sha256": "1602df39c9dd982e42ece64379e76fc9ca123b7ca407e84d7f4ded767bebf753",
    "gitsha": "b12248a7ad4aa4875e78af33922182b3fffc1636"
  },
  {
    "path": "dependencies/HIA_AGENT_NATIVE_TOOL_CATALOG.json",
    "bytes": 226542,
    "sha256": "61325aadc2fa6740c84037227c9410f5e299267d908cfbbd0be6b05eedfbfbf8",
    "gitsha": "9b6ff8f96518a50b7d348ec732981610aa4c9ed1"
  },
  {
    "path": "dependencies/generate_hia_agent_worker_init_pure.py",
    "bytes": 7025,
    "sha256": "1b7d97ba633a40814586b0101d786b2b660ded3c59709dc34949f831b69a6974",
    "gitsha": "d95ce033f7d13ca8fa580de5eb8e83f9c85e3b18"
  },
  {
    "path": "dependencies/worker_init_pure_common.py",
    "bytes": 9085,
    "sha256": "f8f54a86ed80cd977ea54faf5c75007d8eca98be752c5ad8e9d9fce780bf68f5",
    "gitsha": "1151c9d63ce2f189fd0fcc72bf00870a55370544"
  },
  {
    "path": "dependencies/worker_init_pure_result.py",
    "bytes": 10563,
    "sha256": "e26d47cdc4cc172183ae08ffbcbf3ec88db53d282a0d46f60a505a52dc823d38",
    "gitsha": "403d6012ca7833bc4da3fb5d40ee3cc66aad7966"
  },
  {
    "path": "development/pure_join_fixture_source.py",
    "bytes": 35601,
    "sha256": "508a9e6050943be1ff3053ea4e1ace2d9761a38cede7d55f02995139ef451a6d",
    "gitsha": "703c4d78fae1cbc4bfe4ced89ea441f5a7f47d61"
  },
  {
    "path": "dependencies/generate_hia_graph_merge.py",
    "bytes": 11265,
    "sha256": "b4cda58e84da76a17a2daa919f37483eb2973dcfdbb00cd30c074ebc9aca8ed9",
    "gitsha": "9eea9deec088878dc5889d8218e7b422c73efea3",
    "mode": 420,
    "original_member": "development/report-compile-r1/source/16/generate_hia_graph_merge.py"
  }
]
try:
    assert sys.get_int_max_str_digits()==4300
    assert not os.environ.get('HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST')
    read(__file__);assert read(helper)==helper_raw
    assert read(oracle_source)==oracle_raw and read(pure_fixture)==pure_fixture_raw
    for row in INPUT_PINS:
        raw=read(ROOT/row['path'])
        assert (len(raw),digest(raw))==(row['bytes'],row['sha256'])
    for relative,identity in (
        ('hepta/hia_agent_service.py','684caf496de7e3e7c8db1fd80ef616139cf13717aa5879bbd2d6ebf834df9330'),
        ('hepta/hia_agent_store.py','fae25d48a6de7187ed465287c1491af74214ac8bf3eae2af921bd100a247b822'),
        ('hepta/hia_agent_macro_discovery.py','3ee3f31f21719d0eee7414d8bee8ccb046d213ea44310764c21b727eac3c9951')):
        assert digest(read(REFERENCE/relative))==identity
    read(REFERENCE/'hepta/hia_program_tools.py');read(REFERENCE/'hepta/hia_json_preflight_native.py')
    harness=RENDER/'development/graph_harness_r3.py';raw=read(harness)
    assert (len(raw),digest(raw))==(9783,'75fe54554a93e19e30251073ac225deff944d6673d87ccc2b597e47a19e8be7c')
    tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='capture')
    namespace={'struct':struct,'GRAPH':M(b'HIAGRF01')}
    exec(compile(ast.Module(body=[node],type_ignores=[]),'<exact-private-capture-issuer>','exec'),namespace)
    capture=namespace['capture']
    error_node=next(n.value for n in tree.body if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id=='ERRORS' for t in n.targets))
    wire_errors=ast.literal_eval(error_node)
    bundle=json.loads(read(COMPILE/'bundle.json'))
    assert bundle['schema']=='hia-worker-initializer-registry-development-v1'
    assert bundle['status']=='PASS' and set(bundle['components'])==set(entries)
    assert bundle['ordinary_initialization'] is False and bundle['whole_worker_closed'] is False
    assert bundle['complete_graph_merge_original_source'] is True
    summary=json.loads(read(COMPILE/'summary.json'))
    assert summary['status']=='PASS' and summary['actual_compiles']==8 and summary['source_unchanged']
    assert (len(read(WORK/'dependencies/f50-B3.image.bin')),
        digest(read(WORK/'dependencies/f50-B3.image.bin')))==(668608,COMPILER_SHA)
    for row in json.loads(read(COMPILE/'source-after.json')):
        raw=read(row['path'])
        assert (len(raw),digest(raw),stat.S_IMODE(Path(row['path']).stat().st_mode))==(
            row['bytes'],row['sha256'],row['mode'])
    template_path=Path(bundle['template_path']).resolve()
    assert template_path==COMPILE/'static-templates/initialization-literals.bin'
    template=read(template_path)
    assert (len(template),digest(template))==(bundle['template_bytes'],bundle['template_sha256'])
    template_manifest=json.loads(read(COMPILE/'static-templates/manifest.json'))
    assert template_manifest['packet']['sha256']==digest(template)
    for dependency in template_manifest['dependencies']:
        assert digest(read(dependency['path']))==dependency['sha256']
    expected_sources={
        'sequence':ROOT/'examples/hia_bootstrap/agent_worker_initialization_sequence.hiaasm',
        'pure':ROOT/'examples/hia_bootstrap/agent_worker_initializer_pure_join.hiaasm',
        'maps':ROOT/'examples/hia_bootstrap/agent_worker_initialization_maps.hiaasm',
        'values':ROOT/'examples/hia_bootstrap/agent_worker_initialization_values.hiaasm',
        'registry':ROOT/'examples/hia_bootstrap/agent_worker_initializer_registry.hiaasm',
        'merge':ROOT/'examples/hia_bootstrap/graph_merge.hiaasm',
        'scan':RENDER/'examples/hia_bootstrap/graph_json_wire_scan.hiaasm',
        'emit':RENDER/'examples/hia_bootstrap/graph_json_wire_emit.hiaasm'}
    frozen={}
    for role,row in bundle['components'].items():
        current=expected_sources[role].resolve();assert Path(row['source_path']).resolve()==current
        source=read(current);image=read(row['image_path']);receipt=json.loads(read(row['receipt_path']))
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
    DH.setup(OUT/'native-wire-methods')
    SV.load_component()
    DH.frozen(Path(SV.__file__),'ee46468c8c5f41a3f35668a4b17e75686599536554c5924e0629223917c805e7')
    DH.frozen(Path(DH.__file__),'4b7209e77778b5b80521815952731573385117fa2bafa08852977dc3faab92a5')
    load_resource_components()
    load_program_components()
    {'program-semantic':program_semantic_cases,'program-failure':program_failure_cases,
        'program-capacity':program_capacity_cases,'program-protocol':program_protocol_cases}[GROUP]()
    assert case_count==planned,(case_count,planned)
    assert DH.same()
    assert same();status='PASS'
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
    ledger.close();results.close();unchanged=same()
    if not unchanged:status='FAIL'
    summary=dict(status=status,group=GROUP,
        scope='ACTUAL_SEVENTEEN_WORKER_IMAGES_AND_FIXED_PROGRAM_CONTEXT_INITIALIZER_WITH_FOREIGN_PUT_SQL',
        cases=case_count,planned_cases=planned,entries=entries,total_actual_entries=sum(entries.values())+sum(DH.counts.values()),
        native_store_and_digest_entries=DH.counts,all_eleven_images_actual=all(
            entries.get(role,0)+DH.counts.get(role,0)>0 for role in
            ('sequence','pure','maps','values','registry','merge','scan','emit','sha','digest','storevalues')),
        new_resource_entries=DH.counts.get('resources',0),new_metadata_entries=DH.counts.get('metadata',0),
        all_thirteen_roles_actual=all(entries.get(role,0)+DH.counts.get(role,0)>0 for role in
            ('sequence','pure','maps','values','registry','merge','scan','emit','sha','digest','storevalues','resources','metadata')),
        actual_native_program_processes=PROGRAM_COUNTS['processes'],
        program_bridge_entries=sum(DH.counts.get(role,0) for role in ('program-input','program-output')),
        actual_core_decoder_entries=DH.counts.get('program-decoder',0),
        actual_core_datagraph_entries=DH.counts.get('program-datagraph',0),
        all_seventeen_roles_actual=all(entries.get(role,0)+DH.counts.get(role,0)>0 for role in
            ('sequence','pure','maps','values','registry','merge','scan','emit','sha','digest',
             'storevalues','resources','metadata','program-input','program-output','program-decoder','program-datagraph')),
        fixed_program_context_nonzero_images=41,program_frame_receipts_preserved=True,
        input_core_digest_and_roundtrip_fields_native=True,
        old_program_service_cases=0,old_P12_resource_cases=0,
        groups_1_to_6_and_9_full_program_diagnostics_open=True,
        completed_pure_peer_modes=sorted(completed_pure_modes),failure=failure,
        source_unchanged=unchanged,compressed_cas_objects=len(saved),
        elapsed_ns=time.monotonic_ns()-started,
        original_limits=dict(cpu_seconds=90,address_space_bytes=1<<30),
        old_sequence_cases=0,old_maps_cases=0,old_values_cases=0,old_pure_join_cases=0,
        actual_namespace_entries=0,remaining_eight_peer_ids_are_foreign=True,
        original_Store_json_and_profile_oracle=True,namespace_put_sql_results_predeclared=True,
        old_Store_methods_and_wire_disabled_in_actual_interval=True,
        actual_cross_graph_import_entries=entries['merge'],controlled_private_graph_issuer=True,
        native_registry_and_configuration=True,preloaded_future_values=False,
        runtime_python_mechanical_transport=True,
        ordinary_initialization_closed=False,ordinary_namespace_closed=False,whole_worker_closed=False,
        fixed_syscall_executor_closed=False,production_activation=False,
        host_initialization_and_pure_value_owners_disabled_in_native_interval=True)
    save(OUT/'source-after.json',rows());save(OUT/'summary.json',summary)
    print(json.dumps(summary,sort_keys=True),flush=True)
    DH.close()
if status!='PASS':raise SystemExit(1)
