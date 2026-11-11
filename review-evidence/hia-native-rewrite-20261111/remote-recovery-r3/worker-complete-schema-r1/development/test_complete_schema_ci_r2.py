"""Complete schema actual-image controls with unchanged Python reference oracle.

All four validation kernels, both Graph-wire kernels and the fixed-pattern image
are actual source-bound native code. Python forwards typed events/buffers only.
Graph capture is a declared test fixture, not a public issuer or Worker closure.
"""
from __future__ import annotations
import ast,ctypes,json,math,random,re,resource,stat,struct,sys,time,traceback,zlib
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
WORK=Path(sys.argv[1]).resolve();COMPILE=Path(sys.argv[2]).resolve()
OUT=Path(sys.argv[3]).resolve();GROUP=sys.argv[4]
ROOT=WORK/'native-agent-schema-complete-next';REFERENCE=WORK/'Hepta-agent-edit-native'
sys.path[:0]=[str(ROOT/'tools'),str(REFERENCE)]
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta import hia_agent_contract as contract
from hepta.hia_agent_store import AgentRejected
from hepta.hia_program_tools import HIAEditRejected
import agent_schema_common as common
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
M=lambda s:int.from_bytes(s,'little')
pack=lambda *v:struct.pack('<'+'Q'*len(v),*v)
BAD=0xfffffffd;CANARY=bytes(range(64));FBASE=2048;FEND=2304
ROLES={1:'schema_scalar',2:'schema_logic',3:'schema_containers',4:'schema_errors'}
C=common.CONSTANTS
OUT.mkdir(parents=True,exist_ok=False);(OUT/'cas').mkdir()
pins={};saved=set();images={};entries={v:0 for v in (*ROLES.values(),'scan','emit','patterns')}
cases=0;planned=0;status='FAIL';failure=None;capture=None
ledger=(OUT/'entries.jsonl').open('w');results=(OUT/'cases.jsonl').open('w')
started=time.monotonic_ns()
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True,ensure_ascii=True)+'\n')
def cas(raw):
    raw=bytes(raw);h=digest(raw)
    if h not in saved:
        p=OUT/'cas'/(h+'.zlib');p.write_bytes(zlib.compress(raw,1))
        assert zlib.decompress(p.read_bytes())==raw
        saved.add(h)
    return dict(bytes=len(raw),sha256=h)
def read(path):
    p=Path(path).resolve();raw=p.read_bytes()
    if p in pins:assert pins[p]==raw
    pins[p]=raw;return raw
def pinrows():
    return [dict(path=str(p),bytes=len(raw),sha256=digest(raw),mode=stat.S_IMODE(p.stat().st_mode)) for p,raw in pins.items()]
def readback():assert all(p.is_file() and p.read_bytes()==raw for p,raw in pins.items())
def disabled(*args,**kwargs):raise AssertionError('host schema/wire/regex owner called during native execution')
class Buffer:
    def __init__(self,n,raw=b''):
        raw=bytes(raw)
        assert 0<=len(raw)<=n
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
        raw=bytes(raw)
        assert 0<=at<=self.n and len(raw)<=self.n-at
        if raw:ctypes.memmove(self.p+at,raw,len(raw))
    def guard(self):
        assert ctypes.string_at(self.base,64)==CANARY
        assert ctypes.string_at(self.p+self.n,64)==CANARY
def invoke(role,s,r,w,label,advertised_work=None):
    n=w.n if advertised_work is None else advertised_work
    assert 0<=n<=w.n
    sb,rb,wb=s.raw(),r.raw(),w.raw()
    save(OUT/'pending-native-entry.json',dict(role=role,label=label,
        role_entry=entries[role]+1,source_bytes=len(sb),second_bytes=len(rb),
        workspace_bytes=len(wb),advertised_work=n,source_sha256=digest(sb),
        second_sha256=digest(rb),workspace_before_sha256=digest(wb)))
    with ExitStack() as stack:
        for target in ('hepta.hia_agent_contract.validate','hepta.hia_agent_contract.check_vocabulary',
          'hepta.hia_agent_contract.wire','hepta.hia_agent_store.wire',
          'hepta.hia_program_tools.bounded_json_wire','json.loads','re.search'):
            stack.enter_context(patch(target,new=disabled))
        ret=int(images[role]._entry(s.p,s.n,r.p,r.n,w.p,n))
    entries[role]+=1
    assert s.raw()==sb
    if role!='patterns':assert r.raw()==rb
    for b in (s,r,w):b.guard()
    ledger.write(json.dumps(dict(label=label,role=role,status=ret,source=cas(sb),
        second_before=cas(rb),second_after=cas(r.raw()),workspace_before=cas(wb),
        workspace_after=cas(w.raw()),advertised_work=n,input_and_canaries_unchanged=True),sort_keys=True)+'\n')
    ledger.flush();return ret
def grow(w,needed):
    assert needed>w.n
    return Buffer(needed,w.raw())
def ids_for(root):
    objects=[];ids={}
    def add(value):
        key=id(value)
        if key not in ids:ids[key]=len(objects)+1;objects.append(value)
        return ids[key]
    add(root);index=0
    while index<len(objects):
        value=objects[index];index+=1
        if type(value) is dict:
            for k,v in value.items():add(k);add(v)
        elif type(value) in (list,tuple):
            for v in value:add(v)
    return ids
def fixture(value,schema,label='arguments',mode=0):
    wrapper=[value,schema,label]
    graph=capture(wrapper,lease=53);ids=ids_for(wrapper)
    n=struct.unpack_from('<Q',graph,16)[0];edgebase=64+n*64
    first=struct.unpack_from('<Q',graph,64+24)[0]
    roots=struct.unpack_from('<3Q',graph,edgebase+first*8)
    assert roots==(ids[id(value)],ids[id(schema)],ids[id(label)])
    command=pack(M(b'HIASVC01'),31,73,53,roots[0],roots[1],roots[2],sys.get_int_max_str_digits(),mode,0,0,0,0,0,0,0)
    return graph,command,ids
def frame(w,ret,last):
    assert ret==FEND,ret
    f=struct.unpack_from('<32Q',w.raw(),FBASE)
    assert f[0]==M(b'HIASVE01') and f[2:4]==(31,73) and f[5]==53
    assert f[4]==last+1 and f[29:]==(0,0,0)
    return f
def wire_peer(source,command,label):
    r=Buffer(len(command),command);w=Buffer(32768);role='scan'
    while True:
        ret=invoke(role,source,r,w,label)
        assert ret==128,ret
        f=struct.unpack_from('<16Q',w.raw())
        assert f[0]==M(b'HIAGWE01')
        if f[1]==1:w=grow(w,f[10]);continue
        if f[1]==2:
            assert role=='scan' and f[13]==2
            role='emit';continue
        assert f[1] in (0,3)
        return ret,w
def pattern_peer(command,label):
    s=Buffer(len(command),command);o=Buffer(64);w=Buffer(64)
    ret=invoke('patterns',s,o,w,label)
    assert ret==64
    return ret,o
def drive(graph,command,label):
    source=Buffer(len(graph),graph);r=Buffer(len(command),command);w=Buffer(4096)
    role='schema_scalar';sequence=0;wires=[];patterns=[];events=[];grows=[]
    while True:
        ret=invoke(role,source,r,w,label)
        if ret==BAD:return dict(private_bad=True),wires,patterns,events,w
        f=frame(w,ret,sequence);sequence=f[4]
        events.append(list(f))
        action=f[1]
        if action==1:
            assert f[9] in ROLES and ROLES[f[9]]==role
            grows.append((w.n,f[10]));w=grow(w,f[10]);continue
        if action==4:
            assert f[9] in ROLES
            role=ROLES[f[9]];continue
        if action==3:
            assert f[9] in ROLES and ROLES[f[9]]==role and f[15]==0 and f[27]==2
            at,size=f[11:13];assert at<=w.n and 0<size<=w.n-at
            peer_command=w.raw()[at:at+size]
            if f[7]==1:
                assert size==64
                wires.append(f[8]);actual,r=wire_peer(source,peer_command,label+'.wire')
            elif f[7]==2:
                ps,vs=struct.unpack_from('<2Q',peer_command,24)
                assert 64+ps+vs==len(peer_command)
                patterns.append((peer_command[64:64+ps],f[8]))
                actual,r=pattern_peer(peer_command,label+'.pattern')
            else:raise AssertionError(f)
            w.write(256,pack(M(b'HIASVA01'),31,73,f[6],f[7],actual,r.n,0))
            continue
        if action==0:
            assert f[27]==3 and f[17:21]==(0,0,0,0)
            return dict(accepted=True),wires,patterns,events,w
        assert action==2 and f[17] in (1,2,3) and f[27] in (4,5)
        at,size=f[19:21];assert at<=w.n and 0<size<=w.n-at
        text=w.raw()[at:at+size].decode('utf-8','surrogatepass')
        cls={1:'AgentRejected',2:'HIAEditRejected',3:'ValueError'}[f[17]]
        result=dict(error_class=cls,error=text,code='E_HIA_SCHEMA' if f[17]==1 else None)
        return result,wires,patterns,events,w
def oracle(value,schema,label,ids,mode):
    wires=[];patterns=[]
    original_wire=contract.wire;original_search=re.search
    def observing_wire(item):
        wires.append(ids[id(item)])
        return original_wire(item)
    def observing_pattern(pattern,item,*args,**kwargs):
        patterns.append((pattern.encode('utf-8','surrogatepass'),ids[id(item)]))
        return original_search(pattern,item,*args,**kwargs)
    try:
        with patch.object(contract,'wire',new=observing_wire),patch('re.search',new=observing_pattern):
            if mode==0:contract.validate(value,schema,label)
            else:contract.check_vocabulary(schema)
        result=dict(accepted=True)
    except Exception as exc:
        result=dict(error_class=type(exc).__name__,error=str(exc),code=getattr(exc,'code',None))
    return result,wires,patterns
def check(label,value,schema,label_text='arguments',mode=0,digits=4300):
    global cases
    print(json.dumps(dict(event='SCHEMA_CASE_START',group=GROUP,label=label,
        ordinal=cases+1)),flush=True)
    previous=sys.get_int_max_str_digits();sys.set_int_max_str_digits(digits)
    try:
        graph,command,ids=fixture(value,schema,label_text,mode)
        expected,expected_wires,expected_patterns=oracle(value,schema,label_text,ids,mode)
        with ExitStack() as stack:
            for target in ('hepta.hia_agent_contract.validate','hepta.hia_agent_contract.check_vocabulary',
              'hepta.hia_agent_contract.wire','hepta.hia_agent_store.wire',
              'hepta.hia_program_tools.bounded_json_wire','json.loads','re.search'):
                stack.enter_context(patch(target,new=disabled))
            actual,wires,patterns,events,w=drive(graph,command,label)
        row=dict(case=cases+1,label=label,mode=mode,digits=digits,graph=cas(graph),command=cas(command),
            expected=expected,actual=actual,expected_wire_ids=expected_wires,actual_wire_ids=wires,
            expected_patterns=[[p.hex(),i] for p,i in expected_patterns],
            actual_patterns=[[p.hex(),i] for p,i in patterns],
            events=events,workspace_bytes=w.n)
        results.write(json.dumps(row,sort_keys=True,ensure_ascii=True)+'\n');results.flush()
        assert actual==expected,(label,expected,actual)
        assert wires==expected_wires,(label,'wire order',expected_wires,wires)
        assert patterns==expected_patterns,(label,'pattern order',expected_patterns,patterns)
        cases+=1
        print(json.dumps(dict(event='SCHEMA_CASE_PASS',group=GROUP,label=label,
            ordinal=cases)),flush=True)
    finally:sys.set_int_max_str_digits(previous)

def semantic_cases():
    values=[None,False,True,0,1,-1,1.0,-0.0,1.5,float('nan'),float('inf'),'', 'x',[],{},(),b'x']
    for i,value in enumerate(values):
        yield ('true-'+str(i),value,True)
        yield ('false-'+str(i),value,False)
    for name in ('object','array','string','integer','number','boolean','null'):
        for i,value in enumerate(values):yield ('type-'+name+'-'+str(i),value,{'type':name})
    yield ('unknown-type',1,{'type':'not-a-type'})
    yield ('null-type',1,{'type':None})
    for i,value in enumerate((None,False,True,0,1,1.0,-0.0,1.5,'x','é',[1],{'a':2})):
        yield ('const-same-'+str(i),value,{'const':value})
        yield ('const-different-'+str(i),value,{'const':{'different':3}})
        yield ('enum-late-'+str(i),value,{'enum':[{'first':0},value]})
    yield ('const-int-float',1,{'const':1.0})
    yield ('const-negativezero-float',0.0,{'const':-0.0})
    yield ('enum-empty',1,{'enum':[]})
    yield ('enum-first-stops-before-bad-choice','x',{'enum':['x','\ud800']})
    yield ('enum-repeats-value-wire','x',{'enum':['a','b','c']})
    yield ('enum-error-before-later-match','x',{'enum':['\ud800','x']})
    yield ('enum-nonfinite-value',float('nan'),{'enum':[None,0]})
    cycle=[];cycle.append(cycle)
    yield ('cyclic-const-wire',cycle,{'const':None})
    yield ('opaque-const-wire',object(),{'const':None})
    for name in ('oneOf','anyOf'):
        for branches in ([],[True],[False],[True,True],[False,True],[False,False]):
            yield (name+'-'+str(len(branches))+'-'+repr(branches),1,{name:branches})
        yield (name+'-must-visit-after-match','x',{name:[True,{'const':'\ud800'}]})
        yield (name+'-only-catches-AgentRejected',float('inf'),{name:[{'const':0},True]})
    branches=[
        {'type':'object','properties':{'kind':{'const':'a'},'x':{'type':'integer'}},'required':['kind','x']},
        {'type':'object','properties':{'kind':{'const':'b'},'y':{'type':'string'}},'required':['kind','y']}]
    for name in ('oneOf','anyOf'):
        yield (name+'-tagged-field',{'kind':'a','x':'bad'},{name:branches})
        yield (name+'-tagged-missing',{'kind':'b'},{name:branches})
        yield (name+'-no-tag',{'kind':'c'},{name:branches})
        yield (name+'-ambiguous-tag',{'kind':'a','x':'bad'},{name:[branches[0],branches[0]]})
    for value in (0,1,'x',None):
        yield ('allOf-'+repr(value),value,{'allOf':[{'type':'integer'},{'minimum':1}]})
        yield ('not-'+repr(value),value,{'not':{'type':'integer'}})
        yield ('if-'+repr(value),value,{'if':{'type':'integer'},'then':{'minimum':1},'else':{'type':'string'}})
    yield ('if-no-selected-branch',1,{'if':False,'then':False})
    yield ('dict-missing-sorted',{}, {'required':['z','é','a','a','中']})
    yield ('dict-missing-before-count',{}, {'required':['a'],'minProperties':4})
    yield ('dict-property-before-count',{'a':'x'},{'properties':{'a':{'type':'integer'}},'maxProperties':0})
    yield ('dict-source-order-a',{'a':'x','b':1},{'properties':{'a':{'type':'integer'},'b':{'type':'string'}}})
    yield ('dict-source-order-b',{'b':1,'a':'x'},{'properties':{'a':{'type':'integer'},'b':{'type':'string'}}})
    yield ('dict-additional-false',{'é':1},{'additionalProperties':False})
    yield ('dict-additional-schema',{'é':1},{'additionalProperties':{'type':'string'}})
    yield ('dict-additional-true',{'a':1},{'additionalProperties':True})
    yield ('dict-max',{'a':1},{'maxProperties':0})
    yield ('dict-min',{}, {'minProperties':1})
    yield ('array-min-before-items',[],{'minItems':1,'items':False})
    yield ('array-max-before-items',[1],{'maxItems':0,'items':False})
    yield ('array-index-label',[1,'x'],{'items':{'type':'integer'}})
    yield ('array-unique-late-wire-error',['x','x',float('nan')],{'uniqueItems':True})
    yield ('array-unique-duplicate',['x','x'],{'uniqueItems':True})
    yield ('array-unique-different-int-float',[1,1.0,True],{'uniqueItems':True})
    yield ('array-unique-sorted-dicts',[{'a':1,'b':2},{'b':2,'a':1}],{'uniqueItems':True})
    yield ('array-unique-false',[1,1],{'uniqueItems':False})
    yield ('array-unique-truthy',[1,1],{'uniqueItems':'yes'})
    yield ('array-unique-before-items',[1,1],{'uniqueItems':True,'items':False})
    yield ('array-contains-empty',[],{'contains':True})
    yield ('array-contains-after-failure',[1,'x'],{'contains':{'type':'string'}})
    yield ('array-contains-short-circuit',['x',float('nan')],{'contains':{'const':'x'}})
    yield ('array-contains-foreign-error',[float('nan'),'x'],{'contains':{'const':'x'}})
    yield ('array-items-before-contains',[1],{'items':False,'contains':True})
    for text in ('','a','é','中🙂','a\n','\ud800'):
        yield ('string-min-'+ascii(text),text,{'minLength':2})
        yield ('string-max-'+ascii(text),text,{'maxLength':1})
    pats=[
       '^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,191}$','^[0-9a-f]{64}$',
       '^hia://artifacts/[A-Za-z0-9][A-Za-z0-9._~-]{0,191}$',
       '^(0|[1-9][0-9]{0,19})$','^(?:[0-9a-f]{2})*$']
    texts=['','x','a\n','ab','ab\n','a'*64,'a'*64+'\n','01','0','123',
           'hia://artifacts/a','hia://artifacts/a\n','é','\ud800']
    for i,p in enumerate(pats):
        for j,text in enumerate(texts):
            yield ('pattern-'+str(i)+'-'+str(j),text,{'type':'string','pattern':p})
    yield ('label-unicode',{'é':[1,'bad']},{'properties':{'é':{'items':{'type':'integer'}}}},'根')
    yield ('contains-default-label',[1],{'contains':False},'outer[é]')
    yield ('digits-fresh-const',10**4300,{'const':0})
    yield ('digits-disabled-const',10**4300,{'const':10**4300},'arguments',0,0)

def numeric_cases():
    rng=random.Random(391741)
    values=[0,1,-1,2**53-1,2**53,2**53+1,2**63-1,2**63,2**64-1,2**64,
            2**1023-1,2**1023,2**1024,-2**1024,10**1000,-10**1000,
            0.0,-0.0,0.5,-0.5,1.0,-1.0,1.5,-1.5,
            float('nan'),float('inf'),-float('inf'),
            struct.unpack('<d',struct.pack('<Q',1))[0],
            struct.unpack('<d',struct.pack('<Q',0x7fefffffffffffff))[0]]
    bounds=[-float('inf'),float('inf'),float('nan'),0,-1,1,0.5,-0.5,
            2**53+1,2**64,2**1024,-2**1024,
            struct.unpack('<d',struct.pack('<Q',1))[0],
            struct.unpack('<d',struct.pack('<Q',0x7fefffffffffffff))[0]]
    for i,value in enumerate(values):
        for j,bound in enumerate(bounds):
            yield ('minimum-'+str(i)+'-'+str(j),value,{'minimum':bound})
            yield ('maximum-'+str(i)+'-'+str(j),value,{'maximum':bound})
    for i in range(180):
        bits=rng.getrandbits(64);bound=struct.unpack('<d',struct.pack('<Q',bits))[0]
        integer=rng.getrandbits(rng.randrange(1,1100))
        if rng.randrange(2):integer=-integer
        yield ('random-min-'+str(i),integer,{'minimum':bound})
        yield ('random-max-'+str(i),integer,{'maximum':bound})
    length_bounds=[-2,-0.0,0,0.5,1,1.5,2,2**64,float('nan'),float('inf'),-float('inf')]
    for i,bound in enumerate(length_bounds):
        for j,value in enumerate(('', 'a','é中',[0],{'x':0})):
            key=('Length' if type(value) is str else 'Items' if type(value) is list else 'Properties')
            yield ('length-min-'+str(i)+'-'+str(j),value,{'min'+key:bound})
            yield ('length-max-'+str(i)+'-'+str(j),value,{'max'+key:bound})

def vocabulary_cases():
    catalog,_=contract.catalog()
    for tool in catalog['tools']:
        for key in ('inputSchema','outputSchema'):
            yield ('catalog-'+tool['name']+'-'+key,None,tool[key],'arguments',1)
    names=('SCALAR_WORKLOAD_SCHEMA','BUFFER_WORKLOAD_SCHEMA','WORKLOAD_SCHEMA','OBJECTIVE_SCHEMA',
           'COST_POLICY_SCHEMA','BLOCK_PLAN_SCHEMA','MACHINE_PLAN_SCHEMA','VALUE_REGISTER_PLAN_SCHEMA',
           'LEAF_REGISTER_PLAN_SCHEMA','PLAN_SCHEMA')
    for name in names:yield ('internal-'+name,None,getattr(contract,name),'arguments',1)
    for i,schema in enumerate((True,False,{},None,1,[],{'unknown':1},
        {'properties':{'x':{'bad':1}}},{'oneOf':[True,{'bad':1}]},
        {'anyOf':[False]},{'allOf':[{}]},{'items':False},{'contains':True},
        {'if':True,'then':False,'else':{}},{'not':True},
        {'additionalProperties':{'unknown':1}},{'additionalProperties':False},
        {'pattern':'.*'})):
        yield ('vocabulary-'+str(i),None,schema,'ignored',1)
    for tool in catalog['tools']:
        yield ('tool-empty-input-'+tool['name'],{},tool['inputSchema'])
        yield ('tool-empty-output-'+tool['name'],{},tool['outputSchema'])

def large_cases():
    yield ('maximum-eight-mib-string','x'*(8388608-2),{'type':'string','maxLength':8388606})
    yield ('full-untruncated-label',1,{'type':'string'},'é'*150000)
    yield ('full-unknown-field',{'中'*70000:1},{'additionalProperties':False})
    yield ('sorted-missing-keys',{}, {'required':['z'+str(i).zfill(4) for i in range(1023,-1,-1)]})
    yield ('every-unique-wire-still-called',list(range(1024)),{'uniqueItems':True})

def pending_wire(label,value=1,schema=None):
    if schema is None:schema={'const':1}
    graph,command,_=fixture(value,schema)
    s=Buffer(len(graph),graph);r=Buffer(len(command),command);w=Buffer(4096)
    role='schema_scalar';sequence=0
    while True:
        ret=invoke(role,s,r,w,label);f=frame(w,ret,sequence);sequence=f[4]
        if f[1]==1:w=grow(w,f[10]);continue
        if f[1]==4:role=ROLES[f[9]];continue
        assert f[1]==3 and f[7]==1
        at,size=f[11:13];actual,reply=wire_peer(s,w.raw()[at:at+size],label+'.actual-wire')
        ack=pack(M(b'HIASVA01'),31,73,f[6],1,actual,reply.n,0)
        return s,r,w,role,sequence,reply,ack
def protocols():
    global cases,planned
    controls=[]
    graph,command,_=fixture(1,{'const':1})
    def malformed_command(index,value):
        bad=bytearray(command);struct.pack_into('<Q',bad,index*8,value)
        s=Buffer(len(graph),graph);r=Buffer(len(bad),bad);w=Buffer(4096)
        assert invoke('schema_scalar',s,r,w,'bad-command')==BAD
        assert invoke('schema_scalar',s,Buffer(len(command),command),w,'poison-command')==BAD
    for index,value in ((0,0),(1,0),(2,0),(3,54),(4,0),(5,0),(6,(1<<64)-1),(8,2),(9,1),(15,1)):
        controls.append(('command-'+str(index),lambda i=index,v=value:malformed_command(i,v)))
    def malformed_graph(index,value):
        bad=bytearray(graph);struct.pack_into('<Q',bad,index*8,value)
        s=Buffer(len(bad),bad);r=Buffer(len(command),command);w=Buffer(4096)
        assert invoke('schema_scalar',s,r,w,'bad-graph')==BAD
        assert invoke('schema_scalar',Buffer(len(graph),graph),r,w,'poison-graph')==BAD
    for index,value in ((0,0),(1,0),(2,0),(3,0),(4,(1<<64)-1),(5,0),(6,len(graph)+1),(7,1)):
        controls.append(('graph-'+str(index),lambda i=index,v=value:malformed_graph(i,v)))
    def wrong_initial():
        s=Buffer(len(graph),graph);r=Buffer(len(command),command);w=Buffer(4096)
        assert invoke('schema_logic',s,r,w,'wrong-initial-role')==BAD
        assert invoke('schema_scalar',s,r,w,'poison-wrong-role')==BAD
    controls.append(('initial-role',wrong_initial))
    def short_work():
        s=Buffer(len(graph),graph);r=Buffer(len(command),command);w=Buffer(4096)
        before=w.raw()
        assert invoke('schema_scalar',s,r,w,'short-work-retire',advertised_work=4095)==BAD
        assert w.raw()==before
        # The fixed caller discards this lease. No native poison is claimed.
    controls.append(('short-work-scope',short_work))
    def malformed_ack(index,value):
        s,r,w,role,sequence,reply,ack=pending_wire('ack-'+str(index))
        bad=bytearray(ack);struct.pack_into('<Q',bad,index*8,value if value is not None else reply.n-1)
        w.write(256,bad)
        assert invoke(role,s,reply,w,'bad-ack-'+str(index))==BAD
        w.write(256,ack)
        assert invoke(role,s,reply,w,'poison-ack-'+str(index))==BAD
    for index,value in ((0,0),(1,32),(2,74),(3,99),(4,2),(5,0),(6,None),(7,1)):
        controls.append(('ack-'+str(index),lambda i=index,v=value:malformed_ack(i,v)))
    def malformed_peer(index,value):
        s,r,w,role,sequence,reply,ack=pending_wire('peer-'+str(index))
        bad=bytearray(reply.raw());struct.pack_into('<Q',bad,index*8,value if value is not None else reply.n+1)
        w.write(256,ack)
        assert invoke(role,s,Buffer(len(bad),bad),w,'bad-peer-'+str(index))==BAD
        assert invoke(role,s,reply,w,'poison-peer-'+str(index))==BAD
    for index,value in ((0,0),(2,54),(3,99),(4,0),(5,1),(6,3),(7,0),(8,1),(9,1),
                        (11,None),(12,0),(13,1),(15,1)):
        controls.append(('peer-'+str(index),lambda i=index,v=value:malformed_peer(i,v)))
    def repeated_growth():
        s=Buffer(len(graph),graph);r=Buffer(len(command),command);w=Buffer(4096)
        f=frame(w,invoke('schema_scalar',s,r,w,'grow-one'),0)
        assert f[1]==1 and f[10]>4096
        again=frame(w,invoke('schema_scalar',s,r,w,'grow-repeat'),f[4])
        assert again[1]==1 and again[10]==f[10] and again[6]==0
        w=grow(w,again[10]);f=frame(w,invoke('schema_scalar',s,r,w,'grow-resume'),again[4])
        assert f[1]==3 and f[6]==1
    controls.append(('grow-no-peer-replay',repeated_growth))
    def changed_response_after_growth():
        text='x'*8000
        s,r,w,role,sequence,reply,ack=pending_wire('copy-grow',text,{'const':text})
        w.write(256,ack)
        f=frame(w,invoke(role,s,reply,w,'copy-grow-response'),sequence)
        assert f[1]==1 and f[15]==1
        w=grow(w,f[10])
        altered=bytearray(ack);struct.pack_into('<Q',altered,24,99);w.write(256,altered)
        assert invoke(role,s,reply,w,'copy-grow-changed-ack')==BAD
        w.write(256,ack);assert invoke(role,s,reply,w,'copy-grow-poison')==BAD
    controls.append(('copy-grow-association',changed_response_after_growth))
    def next_role():
        g,c,_=fixture(1,{})
        s=Buffer(len(g),g);r=Buffer(len(c),c);w=Buffer(4096);seq=0
        while True:
            f=frame(w,invoke('schema_scalar',s,r,w,'next-source'),seq);seq=f[4]
            if f[1]==1:w=grow(w,f[10]);continue
            assert f[1]==4 and f[9]==2;break
        assert invoke('schema_containers',s,r,w,'wrong-next-role')==BAD
        assert invoke('schema_logic',s,r,w,'poison-next-role')==BAD
    controls.append(('next-role-correlation',next_role))
    def terminal_reuse():
        g,c,_=fixture(None,True)
        actual,_,_,_,w=drive(g,c,'terminal')
        assert actual==dict(accepted=True)
        assert invoke('schema_scalar',Buffer(len(g),g),Buffer(len(c),c),w,'terminal-replay')==BAD
    controls.append(('terminal-replay',terminal_reuse))
    def sequence_overflow():
        s=Buffer(len(graph),graph);r=Buffer(len(command),command);w=Buffer(4096)
        f=frame(w,invoke('schema_scalar',s,r,w,'sequence-start'),0);assert f[1]==1
        w.write(C['V_SEQ'],pack((1<<64)-1))
        assert invoke('schema_scalar',s,r,w,'sequence-overflow')==BAD
        assert struct.unpack_from('<Q',w.raw(),C['V_STATUS'])[0]==6
    controls.append(('sequence-overflow',sequence_overflow))
    planned=len(controls)
    for label,body in controls:
        before=dict(entries);body()
        results.write(json.dumps(dict(case=cases+1,label=label,status='PASS',private_protocol=True,
            entries={k:entries[k]-before[k] for k in entries}),sort_keys=True)+'\n');results.flush()
        cases+=1

def paired_initial():
    """One actual initial admission for each side; compare every workspace byte.

    The original scalar is reconstructed to the exact already observed source
    and image SHA, and then compiled by the same bounded B3 process. It is not
    substituted for any candidate image or counted as a repeated semantic panel.
    Invalid Graph string encodings are explicitly private protocol controls.
    """
    global cases,planned
    row=json.loads(read(COMPILE/'schema_scalar_original_r2.manifest.json'))
    source=read(row['source_path']);raw=read(row['image_path'])
    receipt=json.loads(read(row['receipt_path']))
    assert (len(source),digest(source))==(190205,'2805ad32e5ef028b953b04fbafab432fc835f3847ee530334cb9ce474f47cf6d')
    assert (len(raw),digest(raw))==(260706,'8440aa54d01e7406be38a502072d890e98b05af1e1f8398b08a08981efe376bd')
    assert receipt['input_sha256']==digest(source) and receipt['produced_sha256']==digest(raw)
    assert receipt['image_sha256']=='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
    readback()
    images['schema_scalar_original_r2']=NativeHiaJsonImage(raw,digest(raw))
    entries['schema_scalar_original_r2']=0
    vectors=[]
    for n in (0,1,2,7,8,9,31,64,255,1024,4096):
        vectors.append(('ascii-'+str(n),b'x'*n,n))
    for text in ('é','中','😀','\ud800','\udfff','xéx','x\ud800y','é中😀'):
        raw=text.encode('utf-8','surrogatepass')
        for prefix in (b'',b'x',b'x'*63):
            vectors.append(('unicode-'+str(len(vectors)),prefix+raw,len(prefix)+len(text)))
    for value in range(256):
        raw=b'x'*17+bytes([value])
        vectors.append(('all-tail-'+str(value),raw,18))
    for raw in (b'\xc2',b'\xe0',b'\xe0\xa0',b'\xf0',b'\xf0\x90',b'\xf0\x90\x80',
                b'\xe0\x80\x80',b'\xed\xa0\x80',b'\xf4\x90\x80\x80',
                b'\xc2A',b'\xe0\xa0A',b'\xf0\x90A\x80',b'\xf0\x90\x80A'):
        for prefix in (b'',b'abc',b'x'*129):
            vectors.append(('malformed-'+str(len(vectors)),prefix+raw,len(prefix)+1))
    for raw in (b'',b'x',b'abc',b'x'*64,b'x\xc3\xa9',b'x\xf0\x9f\x98\x80'):
        for count in (0,1,2,3,64,65):
            vectors.append(('count-'+str(len(vectors)),raw,count))
    planned=len(vectors)
    for label,raw,count in vectors:
        graph,command,_=fixture('x'*len(raw),True)
        value=struct.unpack_from('<Q',command,32)[0];at=64+(value-1)*64
        ptr,size=struct.unpack_from('<2Q',graph,at+8);assert size==len(raw)
        edited=bytearray(graph);edited[ptr:ptr+size]=raw;struct.pack_into('<Q',edited,at+48,count)
        s=Buffer(len(edited),edited);r=Buffer(len(command),command)
        old=Buffer(4096);new=Buffer(4096)
        before=dict(entries)
        prior=invoke('schema_scalar_original_r2',s,r,old,label+'.old')
        current=invoke('schema_scalar',s,r,new,label+'.new')
        assert current==prior,(label,prior,current)
        assert old.raw()==new.raw(),label
        results.write(json.dumps(dict(case=cases+1,label=label,status='PASS',
            exact_status_and_complete_workspace=True,private_graph_string_control=True,
            result=prior,graph=cas(edited),command=cas(command),workspace=cas(old.raw()),
            entries={k:entries[k]-before[k] for k in entries}),sort_keys=True)+'\n')
        results.flush();cases+=1

try:
    read(__file__)
    raw=read(ROOT/'tools/graph_harness_frozen_original.py')
    assert (len(raw),digest(raw))==(9783,'75fe54554a93e19e30251073ac225deff944d6673d87ccc2b597e47a19e8be7c')
    tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='capture')
    namespace=dict(struct=struct,GRAPH=M(b'HIAGRF01'))
    exec(compile(ast.Module(body=[node],type_ignores=[]),'<exact-frozen-mechanical-capture>','exec'),namespace)
    capture=namespace['capture']
    for p in sorted((ROOT/'tools').glob('*.py')):read(p)
    for p in (REFERENCE/'hepta/hia_agent_contract.py',REFERENCE/'hepta/hia_agent_store.py',
              REFERENCE/'hepta/hia_program_tools.py',REFERENCE/'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json'):
        read(p)
    bundle=json.loads(read(COMPILE/'bundle.json'))
    assert bundle['schema']=='hia-agent-complete-schema-development-bundle-v1' and bundle['status']=='PASS'
    assert set(bundle['components'])==set(entries)
    frozen={}
    for role,row in bundle['components'].items():
        sr=read(row['source_path']);image=read(row['image_path']);receipt=json.loads(read(row['receipt_path']))
        assert (len(sr),digest(sr))==(row['source_bytes'],row['source_sha256'])
        assert (len(image),digest(image))==(row['image_bytes'],row['image_sha256'])
        assert row['role']==role and row['compiler_sha256']=='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
        assert receipt['input_sha256']==digest(sr) and receipt['produced_sha256']==digest(image)
        frozen[role]=(image,digest(image))
    readback();save(OUT/'source-before.json',pinrows())
    images={role:NativeHiaJsonImage(*values) for role,values in frozen.items()}
    if GROUP=='protocol':protocols()
    elif GROUP=='paired':paired_initial()
    else:
        factories={'semantic':semantic_cases,'numeric':numeric_cases,'vocabulary':vocabulary_cases,'large':large_cases}
        values=list(factories[GROUP]());planned=len(values)
        for row in values:check(*row)
    assert cases==planned,(cases,planned);status='PASS'
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
    ledger.close();results.close()
    unchanged=all(p.is_file() and p.read_bytes()==raw for p,raw in pins.items())
    if not unchanged:status='FAIL'
    summary=dict(status=status,scope='COMPLETE_FIXED_SCHEMA_ACTUAL_KERNELS_WITH_REAL_WIRE_AND_PATTERN_PEERS',
        group=GROUP,cases=cases,planned_cases=planned,entries=entries,total_actual_entries=sum(entries.values()),
        failure=failure,source_unchanged=unchanged,compressed_cas_objects=len(saved),
        original_limits=dict(cpu_seconds=90,address_space_bytes=1<<30),elapsed_ns=time.monotonic_ns()-started,
        native_fixed_worker=False,public_issuer_closed=False,namespace_effects=0,
        whole_worker_closed=False,production_activation=False,python_reference_and_fixture_only=True)
    save(OUT/'source-after.json',pinrows());save(OUT/'summary.json',summary)
    print(json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
