"""Actual four-image initializer pure-peer composition; fifteen peers foreign.

Every maps/values/tools/lookup result comes from actual HIA images. The unchanged
complete Service constructor/profiles/examples supplies the independent oracle.
The source issuer preloads exact controlled foreign values in one Graph; this
does not implement namespace authority, cross-Graph import or fixed syscalls.
"""
from __future__ import annotations
import ast,copy,ctypes,json,os,resource,stat,struct,sys,time,traceback,zlib
from contextlib import ExitStack,contextmanager
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
WORK=Path(sys.argv[1]).resolve();COMPILE=Path(sys.argv[2]).resolve()
OUT=Path(sys.argv[3]).resolve();GROUP=sys.argv[4]
ROOT=WORK/'native-agent-initialization-pure-next';REFERENCE=WORK/'Hepta-agent-edit-native'
RENDER=WORK/'native-agent-edit-render-next'
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'dependencies'),str(REFERENCE)]
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta import hia_agent_service as service
from hepta import hia_agent_store as store
from hepta import hia_agent_assembly as assembly
import generate_hia_agent_worker_init_pure as generation
import generate_hia_agent_worker_init_sequence as sequence_generation
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
M=lambda b:int.from_bytes(b,'little')
pack=lambda *v:struct.pack('<'+'Q'*len(v),*v)
BAD=0xfffffffd;MAX=(1<<64)-1;HANDLE_BASE=1<<63;CANARY=bytes(range(64))
C=generation.CONSTANTS;SC=sequence_generation.CONSTANTS
COMPILER_SHA='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
OUT.mkdir(parents=True,exist_ok=False);(OUT/'cas').mkdir()
pins={};modes={};saved=set();images={};entries={x:0 for x in ('sequence','pure','maps','values')}
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
# The pre-existing source is reused only as an oracle and as the explicitly
# foreign provider fixture. Its old tests, runner, Registry and pure providers
# are not used to produce a single new native pure result.
ORACLE_SHA='b809f06c0c1a0e56d5a49555e6b3010ce7c78d18707571f87c4a9b78d7d62f2b'
INPUT_PINS=[
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
  }
]
oracle_source=ROOT/'development/sequence_oracle_source.py'
oracle_raw=oracle_source.read_bytes();assert sha256(oracle_raw).hexdigest()==ORACLE_SHA
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
foreign_peer=peer
SMALL_CATALOG=CATALOG
@contextmanager
def forbidden_pure_owners():
    with ExitStack() as stack:
        for target in ('hepta.hia_agent_service.HIAAgentService.__init__',
            'hepta.hia_agent_service.HIAAgentService._profiles',
            'hepta.hia_agent_service.HIAAgentService._examples',
            'json.loads'):
            stack.enter_context(patch(target,new=disabled))
        yield
raw_invoke=invoke
def invoke(role,s,t,w,label,advertised=None):
    with forbidden_pure_owners():
        return raw_invoke(role,s,t,w,label,advertised)
def fingerprint(value):
    kind=type(value)
    if value is None:return ('none',)
    if kind is bool:return ('bool',value)
    if kind is int:return ('int',value)
    if kind is float:return ('float',struct.pack('<d',value))
    if kind is str:return ('str',value)
    if kind is bytes:return ('bytes',value)
    if kind in (list,tuple):return (kind.__name__,tuple(fingerprint(x) for x in value))
    if kind is dict:return ('dict',tuple((fingerprint(k),fingerprint(v)) for k,v in value.items()))
    raise AssertionError(('undeclared-foreign-value-type',kind))
def source_pool(baseline,extra=(),mini=False):
    values=[];known={}
    def add(value):
        key=fingerprint(value)
        if key in known:return
        known[key]=len(values);values.append(value)
        if type(value) is dict:
            for k,v in value.items():add(k);add(v)
        elif type(value) in (list,tuple):
            for item in value:add(item)
    add(CATALOG);add('a'*64)
    if not mini:
        add(INSTALL)
        for row in baseline['trace']:
            add(row['args']);add(row['result'])
        for name in ('bodies','jsons','docs','examples'):add(baseline[name])
    raw=capture([values,list(extra)],lease=7001)
    nodes=struct.unpack_from('<Q',raw,16)[0];edgebase=64+nodes*64
    outer_first=struct.unpack_from('<Q',raw,64+24)[0]
    vector=struct.unpack_from('<Q',raw,edgebase+outer_first*8)[0]
    first,amount=struct.unpack_from('<2Q',raw,vector*64+24)
    assert amount==len(values)
    roots=struct.unpack_from('<'+'Q'*amount,raw,edgebase+first*8) if amount else ()
    return raw,{fingerprint(value):(identifier,value) for value,identifier in zip(values,roots)}
def resize(c,view,needed,which):
    assert needed>view.n,(which,needed,view.n)
    mode=c.get('growth','exact')
    if mode=='spare':size=needed+8192
    elif mode=='staged':
        key=(which,needed)
        if needed-1>view.n and key not in c['shortened']:
            c['shortened'].add(key);size=needed-1
        else:size=needed
    else:size=needed
    c['growth_events'].append((which,view.n,size,needed))
    return grow(view,size)
def join_frame(c,ret):
    assert ret==768,('unexpected-join-return',ret)
    f=struct.unpack_from('<32Q',c['pw'].raw(),512)
    assert f[0]==M(b'HIAWPE01') and f[2:4]==(37,83)
    assert f[4]==c['bseq']+1 and f[5]==c['active'] and f[31]==0
    assert f[28]==53 and f[1]<=4
    c['bseq']=f[4];c['pf']=f
    return f
def command(c,mode,payload=b'',root=0,observed=0):
    if mode in (1,2):
        c['active']=c['blast']+1
    raw=c['g'].raw();lease=struct.unpack_from('<Q',raw,8)[0]
    fields=[M(b'HIAWPC01'),mode,37,83,c['active'],c['bseq'],lease,len(raw),
        len(payload),observed,root,53,0,0,0,0]
    return fields,bytes(payload)
def joined(c,fields,payload,label,stop_after_entry=False):
    original=tuple(fields);r=None
    while True:
        fields[5]=c['bseq'];raw=pack(*fields)+payload;r=Buffer(len(raw),raw)
        c['pr']=r
        ret=invoke('pure',c['g'],r,c['pw'],label)
        f=join_frame(c,ret)
        if stop_after_entry or f[1]!=1:return f,r
        assert f[8]>c['pw'].n
        c['pw']=resize(c,c['pw'],f[8],'join')
        fields[1]=3
        assert all(fields[i]==original[i] for i in range(16) if i not in (1,5))
def finish_join(c,f,r):
    assert f[1] in (0,4)
    if f[17]==1:
        assert f[18:20]==(0,c['g'].n)
    else:
        assert f[1]==4 and f[17]==3
        assert f[18]<=r.n and f[19]<=r.n-f[18]
        raw=r.raw()[f[18]:f[18]+f[19]]
        c['g']=Buffer(len(raw),raw)
    assert f[20:22]==(struct.unpack_from('<Q',c['g'].raw(),8)[0],c['g'].n)
    c['blast']=c['active']
    if f[1]==4:
        assert f[22:24]==(1280,256)
        raw=c['pw'].raw()[1280:1536];reply=struct.unpack('<32Q',raw)
        assert reply[:5]==(M(b'HIAWIR01'),37,83,c['f'][7],c['f'][6])
        assert reply[5]==0 and reply[7]==640 and reply[15]==256
        assert reply[8:10]==f[24:26]
        c['r']=Buffer(256,raw);c['reply_count']+=1
        completed_pure_modes.add((c['f'][6],c['f'][13]))
        c['pure_results'].append(dict(peer=c['f'][6],mode=c['f'][13],
            pending=c['f'][7],graph_sha256=digest(c['g'].raw()),handles=list(f[24:26])))
    return f[24],f[25]
def issue(c,root,label='native-value-issue'):
    fields,payload=command(c,1,root=root)
    f,r=joined(c,fields,payload,label)
    assert f[1]==0 and f[24]>HANDLE_BASE and f[25]==0
    result,_=finish_join(c,f,r);return result
class NativeRegistry:
    def __init__(self,c,pool):
        self.c=c;self.pool=pool;self.authorities={};self.kinds={};self.next=900000
    def issue(self,value,kind='value'):
        if kind not in ('value','bytes'):
            self.next+=1;self.authorities[self.next]=(kind,value);return self.next
        key=fingerprint(value)
        assert key in self.pool,('foreign-result-not-predeclared',kind,key)
        root,expected=self.pool[key]
        assert fingerprint(expected)==key
        token=issue(self.c,root,'foreign-value-actual-native-issuance')
        if token in self.kinds:assert self.kinds[token]==kind
        self.kinds[token]=kind;return token
    def get(self,token,kind='value'):
        if token<=HANDLE_BASE:
            actual,value=self.authorities[token];assert actual==kind
            return value
        actual=self.kinds.get(token,'value');assert actual==kind,(kind,actual)
        index=token-HANDLE_BASE-1;work=self.c['pw'].raw()
        count=struct.unpack_from('<Q',work,C['B_ISSUED'])[0]
        assert 0<=index<count
        root=struct.unpack_from('<Q',work,8192+index*16)[0]
        return decode_graph(self.c['g'].raw(),root)
def configure(paths,baseline=None,growth='exact',extra=(),mini=False):
    baseline=oracle(paths) if baseline is None else baseline
    raw=capture(['/state',list(paths)],lease=53)
    n=struct.unpack_from('<Q',raw,16)[0]
    source_values={i:decode_graph(raw,i) for i in range(1,n+1)}
    graph,pool=source_pool(baseline,extra,mini)
    c=dict(s=Buffer(len(raw),raw),r=Buffer(0),w=Buffer(8192),seq=0,raw=raw,
        source_values=source_values,trace=[],occurrences={},namespaces={},
        program_document=None,baseline=baseline,reply_count=0,grows=0,
        g=Buffer(len(graph),graph),pw=Buffer(8192),bseq=0,blast=0,active=0,
        growth=growth,shortened=set(),growth_events=[],pure_results=[],child_calls=0)
    c['w'].write(128,pack(M(b'HIAWIC01'),37,83,53,len(raw),1,4300,*([0]*17)))
    c['reg']=NativeRegistry(c,pool)
    return c
def prepare_child(c,f):
    assert f[1] in (2,3) and f[9] in (1,2)
    if f[1]==2:
        owner={1:c['g'],2:c['pw']}[f[12]]
        assert f[13]<=owner.n and f[14]<=owner.n-f[13]
        raw=owner.raw()[f[13]:f[13]+f[14]]
        source=Buffer(len(raw),raw)
        c['child']=dict(s=source,w=Buffer(4096),kind=f[9],calls=0)
    else:
        assert c['child']['kind']==f[9] and f[11]>c['child']['w'].n
        c['child']['w']=resize(c,c['child']['w'],f[11],'child')
    child=c['child'];assert f[15:17]==(1024,192)
    wire=c['pw'].raw()[1024:1216]
    if f[9]==1:
        child['t']=Buffer(192,wire);child['role']='maps'
    else:
        if f[1]==2:child['w'].write(128,wire)
        else:assert child['w'].raw()[128:320]==wire
        child['t']=Buffer(len(template),template);child['role']='values'
    return child
def actual_child(c,label):
    child=c['child'];child['calls']+=1;c['child_calls']+=1
    ret=invoke(child['role'],child['s'],child['t'],child['w'],label)
    assert ret==640,('actual-child-refused',child['role'],ret)
    event=struct.unpack_from('<16Q',child['w'].raw(),512)
    return ret,event
def pure_peer(c,label,stop_before_child=False,stop_before_result=False):
    before={k:entries[k] for k in entries}
    fields,payload=command(c,2,c['w'].raw(),observed=2304)
    f,r=joined(c,fields,payload,label+'-start')
    assert f[1]==2
    if stop_before_child:return f
    while f[1] in (2,3):
        child=prepare_child(c,f)
        ret,event=actual_child(c,label+'-actual-'+child['role'])
        if stop_before_result and event[1]==0:
            c['completed_child']=child['w'].raw();return event
        fields,payload=command(c,4,child['w'].raw(),observed=ret)
        f,r=joined(c,fields,payload,label+'-child-result')
    assert f[1]==4
    result=finish_join(c,f,r)
    assert entries['sequence']==before['sequence'],'pure GROW must not reenter sequence'
    return result
def peer(c,fail_at,false_dirs,mismatch):
    if c['f'][6] in (2,9,10,19):
        pure_peer(c,'pending-'+str(c['f'][7]))
    else:
        foreign_peer(c,fail_at,false_dirs,mismatch)
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
def encoded(value):
    return json.dumps(value,ensure_ascii=True,default=lambda v:{'bytes':v.hex()}).encode()
def record(label,before,extra):
    global case_count
    row=dict(case=case_count+1,label=label,status='PASS',
        entries={k:entries[k]-before[k] for k in entries},**extra)
    results.write(json.dumps(row,sort_keys=True)+'\n');results.flush();case_count+=1
    print(json.dumps(dict(event='INIT_PURE_JOIN_PASS',group=GROUP,label=label,case=case_count)),flush=True)
def check(label,paths=(),fail_at=None,false_dirs=(),mismatch=False,growth='exact'):
    expected=oracle(paths,fail_at,false_dirs,mismatch)
    baseline=expected if fail_at is None and not false_dirs and not mismatch else oracle(paths)
    before=dict(entries)
    with forbidden_pure_owners():
        actual,c=drive(paths,label,fail_at,false_dirs,mismatch,baseline,growth)
    assert actual=={k:expected[k] for k in ('state','error')},(label,expected['error'],actual)
    assert c['trace']==expected['trace'],(label,'full ordered calls and partial attributes',
        len(c['trace']),len(expected['trace']))
    if expected['error'] is None:
        assert {row['peer'] for row in c['pure_results']}=={2,9,10,19}
        assert {row['mode'] for row in c['pure_results'] if row['peer']==9}==set(range(1,7))
        assert {row['mode'] for row in c['pure_results'] if row['peer']==10}=={1,2,3,4}
        assert entries['maps']>before['maps'] and entries['values']>before['values']
    record(label,before,dict(reference_trace=cas(encoded(expected['trace'])),
        actual_trace=cas(encoded(c['trace'])),expected_state=cas(encoded(expected['state'])),
        actual_state=cas(encoded(actual['state'])),error=actual['error'],
        pure_results=c['pure_results'],growth_events=c['growth_events'],
        actual_child_calls=c['child_calls'],actual_pure_peer_calls=len(c['pure_results']),
        exact_complete_state_error_and_remaining_call_order=True,
        remaining_fifteen_peer_ids_are_foreign=True,cross_graph_import=False,
        ordinary_initialization_closed=False))
    return c
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
def full_catalog():
    global planned,CATALOG
    CATALOG=json.loads(read(ROOT/'dependencies/HIA_AGENT_NATIVE_TOOL_CATALOG.json'))
    assert len(CATALOG['tools'])==11
    planned=1;check('all-eleven-actual-catalog-values',('/catalog-root',))
    CATALOG=SMALL_CATALOG
def growths():
    global planned
    planned=3
    contexts=[check('complete-'+mode,('/a','/b'),growth=mode) for mode in ('exact','spare','staged')]
    assert len(contexts[2]['growth_events'])>len(contexts[1]['growth_events'])
    assert [x['pure_results'][-1]['peer'] for x in contexts]==[9,9,9]
def pending(label,extra=()):
    c=configure((),baseline_empty,extra=extra,mini=True)
    f=frame(c,invoke('sequence',c['s'],c['r'],c['w'],label+'-catalog'))
    assert f[1]==2 and f[6]==1
    foreign_peer(c,None,(),False)
    f=frame(c,invoke('sequence',c['s'],c['r'],c['w'],label+'-tools'))
    assert f[1]==2 and f[6]==2
    return c
def refusal(c,fields,payload,label,advertised=None,unchanged=False):
    raw=pack(*fields)+payload;r=Buffer(len(raw),raw);before=c['pw'].raw()
    ret=invoke('pure',c['g'],r,c['pw'],label,advertised)
    assert ret==BAD,(label,ret)
    if unchanged:assert c['pw'].raw()==before
    else:
        assert struct.unpack_from('<Q',c['pw'].raw(),C['B_PHASE'])[0]==99
        after=c['pw'].raw()
        assert invoke('pure',c['g'],r,c['pw'],label+'-permanent')==BAD
        assert c['pw'].raw()==after
def protocol_case(label,body):
    before=dict(entries)
    with forbidden_pure_owners():body()
    record(label,before,dict(private_protocol=True,actual_namespace_entries=0))
def protocols():
    global planned
    controls=[]
    def header(index,value):
        c=pending('header-'+str(index));fields,payload=command(c,2,c['w'].raw(),observed=2304)
        fields[index]=value(c,fields) if callable(value) else value
        refusal(c,fields,payload,'bad-command-word-'+str(index))
    for index,value in ((0,0),(1,0),(1,5),(2,0),(2,38),(3,84),
        (4,0),(4,lambda c,f:f[4]+1),(5,lambda c,f:f[5]+1),
        (6,0),(7,0),(8,0),(9,640),(10,1),(11,54),(12,1),(15,1)):
        controls.append(('command-'+str(index)+'-'+str(len(controls)),lambda i=index,v=value:header(i,v)))
    def bad_sequence(offset,value,both=None):
        c=pending('bad-sequence');payload=bytearray(c['w'].raw())
        struct.pack_into('<Q',payload,offset,value)
        if both is not None:struct.pack_into('<Q',payload,both,value)
        fields,payload=command(c,2,payload,observed=2304)
        refusal(c,fields,payload,'sequence-correlation')
    for word in (0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,20,21,22,23,24,25,26,27,31):
        controls.append(('sequence-event-'+str(word),
            lambda word=word:bad_sequence(2048+word*8,MAX)))
    controls.append(('graph-id-is-not-value-handle',
        lambda:bad_sequence(2048+14*8,1,SC['I_ARG0'])))
    controls.append(('unissued-high-value-handle',
        lambda:bad_sequence(2048+14*8,HANDLE_BASE+9999,SC['I_ARG0'])))
    def duplicate_pending():
        c=pending('replay-pending');original=c['w'].raw()
        pure_peer(c,'first-tools')
        fields,payload=command(c,2,original,observed=2304)
        refusal(c,fields,payload,'replayed-pending')
    controls.append(('completed-pending-replay',duplicate_pending))
    def wrong_child(index,value,complete_child=False):
        c=pending('child-negative')
        if complete_child:
            pure_peer(c,'actual-child-before-mutation',stop_before_result=True)
            payload=bytearray(c['completed_child'])
        else:
            f=pure_peer(c,'actual-child-grow-before-mutation',stop_before_child=True)
            prepare_child(c,f);actual_child(c,'actual-grow')
            payload=bytearray(c['child']['w'].raw())
        struct.pack_into('<Q',payload,index,value(c,payload) if callable(value) else value)
        fields,payload=command(c,4,payload,observed=640)
        refusal(c,fields,payload,'child-correlation')
    for offset,value in ((512,0),(520,3),(528,38),(536,999),(544,0),(552,9),
        (560,0),(568,1),(616,1),(632,1),(0,0),(8,2),(16,999),(24,1),
        (32,1),(40,2),(72,1),(144,0),(152,0),(160,38),(168,999),(768+40,9),(960,0)):
        controls.append(('child-grow-'+str(offset),
            lambda offset=offset,value=value:wrong_child(offset,value)))
    for offset in (576,584,592,600,608,112,120,128,136,192,200):
        controls.append(('child-done-'+str(offset),
            lambda offset=offset:wrong_child(offset,MAX,True)))
    def changed_old_scalar():
        c=pending('prefix-change');pure_peer(c,'complete-child',stop_before_result=True)
        payload=bytearray(c['completed_child'])
        event=struct.unpack_from('<16Q',payload,512);at=event[8]
        n,e=struct.unpack_from('<Q',payload,at+16)[0],struct.unpack_from('<Q',payload,at+32)[0]
        data=at+64+n*64+e*8
        assert data<len(payload);payload[data]^=1
        fields,payload=command(c,4,payload,observed=640)
        refusal(c,fields,payload,'modified-old-source-pool')
    controls.append(('whole-old-source-prefix',changed_old_scalar))
    def child_observation():
        c=pending('child-ret');pure_peer(c,'start',stop_before_child=True)
        fields,payload=command(c,4,b'\0'*4096,observed=BAD)
        refusal(c,fields,payload,'actual-native-return-must-be-success-frame')
    controls.append(('actual-return-before-child-frame',child_observation))
    def short():
        c=pending('short');fields,payload=command(c,2,c['w'].raw(),observed=2304)
        refusal(c,fields,payload,'advertised-short-workspace',8191,True)
    controls.append(('short-workspace-retire-without-poison-claim',short))
    def command_wrap():
        c=pending('command-wrap');c['pw'].write(C['B_LAST_COMMAND'],pack(MAX))
        fields,payload=command(c,2,c['w'].raw(),observed=2304)
        refusal(c,fields,payload,'command-u64-wrap')
    controls.append(('command-sequence-wrap',command_wrap))
    def event_wrap():
        c=pending('event-wrap');c['pw'].write(C['B_SEQUENCE'],pack(MAX));c['bseq']=MAX
        fields,payload=command(c,2,c['w'].raw(),observed=2304)
        refusal(c,fields,payload,'event-u64-wrap')
    controls.append(('event-sequence-wrap',event_wrap))
    def source_change():
        c=pending('source-shape');raw=bytearray(c['g'].raw())
        struct.pack_into('<Q',raw,24,2);c['g']=Buffer(len(raw),raw)
        fields,payload=command(c,2,c['w'].raw(),observed=2304)
        refusal(c,fields,payload,'source-header-change')
    controls.append(('source-header-custody',source_change))
    def own_growth(change):
        c=pending('own-grow');fields,payload=command(c,1,root=1)
        f,r=joined(c,fields,payload,'actual-own-issue-grow',True)
        assert f[1]==1 and f[8]>c['pw'].n
        c['pw']=grow(c['pw'],f[8]);fields[1]=3;fields[5]=c['bseq']
        if change=='root':fields[10]=2
        elif change=='observation':fields[9]=640
        elif change=='sequence':fields[4]+=1
        elif change=='mode':fields[1]=2
        refusal(c,fields,payload,'changed-own-grow-'+change)
    for change in ('root','observation','sequence','mode'):
        controls.append(('own-grow-'+change,lambda change=change:own_growth(change)))
    def lease_wrap():
        c=pending('lease-wrap');c['pw'].write(C['B_NEXT_LEASE'],pack(MAX-1))
        fields,payload=command(c,2,c['w'].raw(),observed=2304)
        refusal(c,fields,payload,'no-lease-reuse-after-lookup-or-wrap')
    controls.append(('native-generated-lease-wrap',lease_wrap))
    def dirty_initial():
        c=configure((),baseline_empty,mini=True);c['pw'].write(4096,b'\1')
        fields,payload=command(c,1,root=1)
        refusal(c,fields,payload,'initial-workspace-must-be-zero')
    controls.append(('dirty-initial-workspace',dirty_initial))
    planned=len(controls)
    for label,body in controls:protocol_case(label,body)
def large_values():
    global planned
    planned=1
    blob=b'full-source-pool:'+b'x'*(9<<20)
    before=dict(entries);c=pending('over-eight-mib-private-value-pool',extra=(blob,))
    original=c['g'].raw();assert len(original)>8<<20
    with forbidden_pure_owners():pure_peer(c,'large-complete-native-tools')
    assert c['reg'].get(struct.unpack_from('<Q',c['r'].raw(),64)[0])=={x['name']:x for x in CATALOG['tools']}
    assert c['g'].n>8<<20
    record('over-eight-mib-complete-source-pool',before,dict(
        source=cas(original),result=cas(c['g'].raw()),growth_events=c['growth_events'],
        private_source_issuer=True,no_new_output_byte_quota=True))
def large_registry():
    global planned
    planned=2
    before=dict(entries)
    c=pending('registry-capacity')
    nodes=struct.unpack_from('<Q',c['g'].raw(),16)[0]
    # Issue every source node under the same actual private session. This tests
    # registry growth without inventing a new maximum number of values.
    chosen=list(range(1,nodes+1))
    handles=[issue(c,i,'registry-issued') for i in chosen]
    assert len(set(handles))==len(handles)
    before_repeat=struct.unpack_from('<Q',c['pw'].raw(),C['B_ISSUED'])[0]
    repeats=[issue(c,i,'registry-alias-reissue') for i in chosen]
    assert repeats==handles
    assert struct.unpack_from('<Q',c['pw'].raw(),C['B_ISSUED'])[0]==before_repeat
    record('all-source-node-handles-and-alias-reissue',before,
        dict(source_nodes=nodes,issued=before_repeat,growth_events=c['growth_events']))
    before=dict(entries)
    extras=[[] for _ in range(262145)]
    c=pending('over-language-node-inventory',extra=(extras,))
    original=c['g'].raw();assert struct.unpack_from('<Q',original,16)[0]>262144
    with forbidden_pure_owners():pure_peer(c,'complete-native-tools-after-large-inventory')
    assert struct.unpack_from('<Q',c['g'].raw(),16)[0]>262144
    record('existing-private-graph-over-language-node-count',before,
        dict(source=cas(original),result=cas(c['g'].raw()),growth_events=c['growth_events'],
            private_source_issuer=True,no_new_intermediate_node_quota=True))

try:
    assert sys.get_int_max_str_digits()==4300
    assert not os.environ.get('HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST')
    read(__file__)
    assert read(helper)==helper_raw and read(oracle_source)==oracle_raw
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
    bundle=json.loads(read(COMPILE/'bundle.json'))
    assert bundle['schema']=='hia-worker-initializer-pure-join-development-v1'
    assert bundle['status']=='PASS' and set(bundle['components'])==set(entries)
    assert bundle['ordinary_initialization'] is False and bundle['whole_worker_closed'] is False
    summary=json.loads(read(COMPILE/'summary.json'))
    assert summary['status']=='PASS' and summary['actual_compiles']==4 and summary['source_unchanged']
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
        'values':ROOT/'examples/hia_bootstrap/agent_worker_initialization_values.hiaasm'}
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
    baseline_empty=oracle(())
    {'semantic':semantics,'catalog':full_catalog,'growth':growths,
        'protocol':protocols,'large-values':large_values,'large-registry':large_registry}[GROUP]()
    assert case_count==planned,(case_count,planned)
    assert same();status='PASS'
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
    ledger.close();results.close();unchanged=same()
    if not unchanged:status='FAIL'
    summary=dict(status=status,group=GROUP,
        scope='ACTUAL_NATIVE_INITIALIZER_SEQUENCE_PURE_MAPS_VALUES_JOIN_WITH_FOREIGN_EFFECTFUL_PEERS',
        cases=case_count,planned_cases=planned,entries=entries,total_actual_entries=sum(entries.values()),
        completed_pure_peer_modes=sorted(completed_pure_modes),failure=failure,
        source_unchanged=unchanged,compressed_cas_objects=len(saved),
        elapsed_ns=time.monotonic_ns()-started,
        original_limits=dict(cpu_seconds=90,address_space_bytes=1<<30),
        old_sequence_cases=0,old_maps_cases=0,old_values_cases=0,
        actual_namespace_entries=0,remaining_fifteen_peer_ids_are_foreign=True,
        cross_graph_import=False,controlled_private_graph_issuer=True,
        native_registry_and_pure_outputs=True,runtime_python_mechanical_transport=True,
        ordinary_initialization_closed=False,ordinary_namespace_closed=False,whole_worker_closed=False,
        fixed_syscall_executor_closed=False,production_activation=False,
        host_initialization_and_pure_value_owners_disabled_in_native_interval=True)
    save(OUT/'source-after.json',rows());save(OUT/'summary.json',summary)
    print(json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
