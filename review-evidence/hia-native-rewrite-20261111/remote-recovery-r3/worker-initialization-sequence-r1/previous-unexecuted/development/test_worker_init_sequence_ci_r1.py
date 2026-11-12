"""Native initializer order / partial-state differential, ALL PEERS FOREIGN.

The unchanged complete Service constructor, profiles and examples create each
oracle trace. Every semantic peer, including generic value/Path/namespace
services, is an explicit controlled fixture in this isolated test. No native
projection, namespace, filesystem, general assembler or ordinary Worker result
is inherited or claimed. The sequence image itself is actual B3 native code.
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
ROOT=WORK/'native-agent-initialization-sequence-next';REFERENCE=WORK/'Hepta-agent-edit-native'
sys.path[:0]=[str(ROOT/'tools'),str(REFERENCE)]
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta import hia_agent_service as service
from hepta import hia_agent_store as store
from hepta import hia_agent_assembly as assembly
import generate_hia_agent_worker_init_sequence as generation
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
M=lambda b:int.from_bytes(b,'little')
pack=lambda *v:struct.pack('<'+'Q'*len(v),*v)
BAD=0xfffffffd;MAX=(1<<64)-1;CANARY=bytes(range(64));C=generation.CONSTANTS
OUT.mkdir(parents=True,exist_ok=False);(OUT/'cas').mkdir()
pins={};modes={};saved=set();images={};entries={'sequence':0}
ledger=(OUT/'entries.jsonl').open('w');results=(OUT/'cases.jsonl').open('w')
capture=None;case_count=0;planned=0;status='FAIL';failure=None;started=time.monotonic_ns()
# Reuse only exact mechanical byte/canary/ledger primitives from the submitted
# independent value test. Its old groups and oracle are not imported or run.
HELPER_SHA='1602df39c9dd982e42ece64379e76fc9ca123b7ca407e84d7f4ded767bebf753'
helper=ROOT/'development/value_mechanics_source.py';helper_raw=helper.read_bytes()
assert sha256(helper_raw).hexdigest()==HELPER_SHA
helper_tree=ast.parse(helper_raw)
wanted={'digest','save','cas','read','rows','same','disabled','Buffer','invoke','grow','decode_graph'}
definitions=[n for n in helper_tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in wanted]
assert {n.name for n in definitions}==wanted
exec(compile(ast.Module(body=definitions,type_ignores=[]),str(helper),'exec'),globals())

ATTRS=('catalog','catalog_sha256','tools','identities','store','artifact_roots',
       'profiles','profile_artifacts','resources','manifest')
INSTALL={'worker_sha256':'1'*64,'backend_sha256':'2'*64,'catalog_sha256':'3'*64}
CATALOG={'contract_version':'fixture-only','tools':[
    {'name':'hia_describe','inputSchema':True,'outputSchema':True},
    {'name':'hia_read','inputSchema':True,'outputSchema':True}]}
class PeerFailure(ValueError):pass
class Program:
    def __init__(self,document,digest_value):
        self.document=document;self.sha256=digest_value
    def as_dict(self):return copy.deepcopy(self.document)
def normalized(value):
    if isinstance(value,Program):return {'fixture_program':value.document,'sha256':value.sha256}
    if isinstance(value,Root):return {'fixture_path':value.raw}
    if isinstance(value,Namespace):return {'fixture_namespace':value.root}
    if type(value) is dict:return {k:normalized(v) for k,v in value.items()}
    if type(value) is list:return [normalized(v) for v in value]
    if type(value) is tuple:return tuple(normalized(v) for v in value)
    return value
def snapshot(owner):
    # Catalog, tools and installation are immutable in this fixture. Copy the
    # mutable prefixes only, so large static schemas are not accidentally
    # multiplied by observer snapshots.
    result={}
    for name in ATTRS:
        if hasattr(owner,name):
            value=getattr(owner,name)
            result[name]=normalized(copy.deepcopy(value)) if name in ('profiles','profile_artifacts','resources','manifest') else normalized(value)
    return result
class Root:
    def __init__(self,raw,observer=None,dirs=None):
        self.raw=raw;self.observer=observer;self.dirs=dirs or {}
    def is_dir(self):
        result=self.dirs.get(self.raw,True)
        if self.observer:self.observer('isdir',self.raw,result)
        return result
    def __str__(self):
        if self.observer:self.observer('str',self.raw,self.raw)
        return self.raw
    def __deepcopy__(self,memo):return self
class Namespace:
    def __init__(self,root,observer,reference):
        self.root=root;self.observer=observer;self.reference=reference
        self.profile_count=0;self.json_count=0;self.put_count=0
    def profile(self,name,body):
        result=(dict(id=name,sha256=sha256(name.encode()).hexdigest()),
            self.reference('profile-'+name))
        self.observer('profile',(name,body),result);self.profile_count+=1;return result
    def json(self,value,kind):
        result=self.reference('json-'+str(self.json_count))
        self.observer('json',(value,kind),result);self.json_count+=1;return result
    def put(self,value,kind):
        result=self.reference('put-'+str(self.put_count))
        self.observer('put',(value,kind),result);self.put_count+=1;return result
def oracle(paths,fail_at=None,false_dirs=(),mismatch=False):
    owner=service.HIAAgentService.__new__(service.HIAAgentService)
    trace=[];occurrences={};examples={};bodies={};jsons=[];docs={}
    def reference(label):
        return dict(id='fixture-'+label,sha256=sha256(label.encode()).hexdigest(),
            uri='hia://artifacts/fixture-'+label)
    def observe(kind,args,result):
        number=occurrences.get(kind,0);occurrences[kind]=number+1
        label=kind+':'+str(number)
        row=dict(kind=kind,number=number,label=label,args=normalized(args),
            state=snapshot(owner),result=normalized(result))
        trace.append(row)
        if kind=='profile':bodies[args[0][4:-3]]=copy.deepcopy(args[1])
        if kind=='json':jsons.append(copy.deepcopy(args[0]))
        if kind=='file':docs[args]=result
        if fail_at==label:raise PeerFailure(label)
        return result
    def catalog():return observe('catalog',None,(CATALOG,'a'*64))
    def installation():return observe('installation',None,copy.deepcopy(INSTALL))
    def opened(root):
        value=Namespace(root,observe,reference)
        observe('open',root,value);return value
    class PathFixture:
        def __init__(self,value):self.raw=value
        def absolute(self):return self
        def resolve(self,strict):
            assert strict is True
            value=Root('/resolved'+self.raw,observe,{name:False for name in false_dirs})
            observe('resolve',self.raw,value);return value
    class FileFixture:
        def __init__(self,name):self.name=name
        def read_bytes(self):
            data=('fixture-current-installed-resource:'+self.name).encode()
            return observe('file',self.name,data)
    original_digest=store.digest
    def digest_value(value):return observe('digest',value,original_digest(value))
    def verified(document):
        result=Program(copy.deepcopy(document),'4'*64)
        examples['document']=copy.deepcopy(document)
        observe('verify',document,result);return result
    def rendered(program):
        text='fixture complete-render result\n'
        observe('render',program,text);examples['assembly']=text;return text
    def assembled(text):
        result=Program(copy.deepcopy(examples['document']),('5' if mismatch else '4')*64)
        observe('assemble',text,result);return result
    error=None
    with ExitStack() as stack:
        for target,value in ((service,'catalog'),):pass
        stack.enter_context(patch.object(service,'catalog',new=catalog))
        stack.enter_context(patch.object(service,'installation_manifest',new=installation))
        stack.enter_context(patch.object(service,'AgentStore',new=opened))
        stack.enter_context(patch.object(service,'Path',new=PathFixture))
        stack.enter_context(patch.object(service,'_agent_resource_path',new=lambda name:FileFixture(name)))
        stack.enter_context(patch.object(service,'digest',new=digest_value))
        stack.enter_context(patch.object(service,'verify_program',new=verified))
        stack.enter_context(patch.object(assembly,'render_assembly',new=rendered))
        stack.enter_context(patch.object(assembly,'assemble_program',new=assembled))
        try:owner.__init__('/state',artifact_roots=paths)
        except Exception as exc:error=dict(error_class=type(exc).__name__,error=str(exc))
    return dict(trace=trace,state=snapshot(owner),error=error,bodies=bodies,jsons=jsons,
        docs=docs,examples=examples,reference=reference)
class Registry:
    def __init__(self):self.next=100000;self.items={}
    def issue(self,value,kind='value'):
        self.next+=1;self.items[self.next]=(kind,value);return self.next
    def get(self,token,kind='value'):
        actual,value=self.items[token];assert actual==kind,(token,kind,actual);return value
def configure(paths):
    raw=capture(['/state',list(paths)],lease=53)
    n=struct.unpack_from('<Q',raw,16)[0]
    source_values={identifier:decode_graph(raw,identifier) for identifier in range(1,n+1)}
    s=Buffer(len(raw),raw);r=Buffer(0);w=Buffer(8192)
    w.write(128,pack(M(b'HIAWIC01'),37,83,53,len(raw),1,4300,*([0]*17)))
    return dict(s=s,r=r,w=w,seq=0,raw=raw,source_values=source_values,reg=Registry(),
        trace=[],occurrences={},namespaces={},program_document=None,baseline=oracle(paths),
        reply_count=0,grows=0)
def frame(c,ret):
    assert ret==2304,ret
    f=struct.unpack_from('<32Q',c['w'].raw(),2048)
    assert f[0]==M(b'HIAWIE01') and f[2:4]==(37,83) and f[4]==c['seq']+1
    assert f[9:12]==(53,1,4300) and f[25:27]==(4096,512)
    c['seq']=f[4];c['f']=f;return f
def native_state(c):
    words=struct.unpack_from('<64Q',c['w'].raw(),4096)
    assert words[0]==M(b'HIAWIP01') and words[1:3]==(37,83)
    present=words[3];assert present<512
    R=c['reg'];out={}
    if present&1:
        out['catalog']=normalized(R.get(words[4]));out['catalog_sha256']=R.get(words[5])
    for bit,word,name in ((1,6,'tools'),(2,7,'identities'),(5,10,'profiles'),
        (6,11,'profile_artifacts'),(7,12,'resources'),(8,13,'manifest')):
        if present&(1<<bit):out[name]=normalized(R.get(words[word]))
    if present&8:out['store']=normalized(R.get(words[8],'namespace'))
    if present&16:out['artifact_roots']=normalized(R.get(words[9],'roots-tuple'))
    return out
def complete(c,kind,one=0,two=0,three=0,authority=0,digest_bytes=b'\0'*32,error=None):
    f=c['f'];assert f[1]==2 and f[7]==f[4]
    fields=[M(b'HIAWIR01'),37,83,f[7],f[6],0,kind,0,one,two,three,authority,0,0,0,256]
    fields.extend(struct.unpack('<4Q',digest_bytes));fields.extend([0]*12)
    assert len(fields)==32
    if error is not None:
        raw=('fixture-issued-peer-exception:'+error).encode()
        fields[5]=1;fields[6]=0;fields[8:12]=[0]*4
        fields[12:16]=[90001,256,len(raw),256+len(raw)]
        fields[16:20]=[0]*4
        data=pack(*fields)+raw
    else:data=pack(*fields)
    c['r']=Buffer(len(data),data);c['reply_count']+=1
def observe(c,kind,args,result,fail_at):
    number=c['occurrences'].get(kind,0);c['occurrences'][kind]=number+1
    label=kind+':'+str(number)
    c['trace'].append(dict(kind=kind,number=number,label=label,args=normalized(args),
        state=native_state(c),result=normalized(result)))
    if label==fail_at:
        complete(c,0,error=label);return False
    return True
def peer(c,fail_at,false_dirs,mismatch):
    f=c['f'];peerid,op=f[6],f[13];a,b,d,e,x,y=f[14:20]
    R=c['reg'];baseline=c['baseline']
    literal=c['w'].raw()[f[23]:f[23]+f[24]].decode()
    ref=baseline['reference']
    if peerid==1:
        result=(CATALOG,'a'*64)
        if observe(c,'catalog',None,result,fail_at):complete(c,1,R.issue(result[0]),R.issue(result[1]))
    elif peerid==2:
        tools={t['name']:t for t in R.get(a)['tools']}
        complete(c,2,R.issue(tools))
    elif peerid==3:
        result=copy.deepcopy(INSTALL)
        if observe(c,'installation',None,result,fail_at):complete(c,2,R.issue(result))
    elif peerid==4:
        assert f[20:23]==(1,0,c['s'].n) and b==53
        root=c['source_values'][a];namespace=Namespace(root,None,ref)
        if observe(c,'open',root,namespace,fail_at):
            token=R.issue(namespace,'namespace');c['namespaces'][token]=namespace
            complete(c,3,authority=token)
    elif peerid==5:
        assert f[20:23]==(1,0,c['s'].n) and b==53
        raw=c['source_values'][a];root=Root('/resolved'+raw,dirs={v:False for v in false_dirs})
        if observe(c,'resolve',raw,root,fail_at):
            complete(c,4,R.issue(root.raw),authority=R.issue(root,'path'))
    elif peerid==6:
        root=R.get(a,'path');result=root.is_dir()
        if observe(c,'isdir',root.raw,result,fail_at):
            complete(c,5,int(result),authority=a)
    elif peerid==7:
        if op==0:
            assert f[20]==2 and f[22]==a*16
            pairs=struct.unpack_from('<'+'Q'*(a*2),c['w'].raw(),f[21]) if a else ()
            roots=tuple(R.get(pairs[2*i],'path') for i in range(a))
            assert all(R.get(pairs[2*i+1])==roots[i].raw for i in range(a))
            complete(c,6,authority=R.issue(roots,'roots-tuple'))
        else:
            assert op==1
            roots=R.get(a,'roots-tuple');assert len(roots)==b
            strings=[]
            for root in roots:
                if not observe(c,'str',root.raw,root.raw,fail_at):return
                strings.append(root.raw)
            complete(c,2,R.issue(strings))
    elif peerid==8:
        value=R.get(a);result=store.digest(value)
        if observe(c,'digest',value,result,fail_at):
            complete(c,7,R.issue(result),digest_bytes=bytes.fromhex(result))
    elif peerid==9:
        if op==1:
            assert R.get(a)==INSTALL and R.get(b)=='a'*64
            strings=R.get(d);digest_value=R.get(e)
            assert digest_value==baseline['bodies']['artifact']['path_roots_sha256']
            assert len(strings)==baseline['bodies']['artifact']['path_root_count']
            value=baseline['bodies']
        elif op==2:value=baseline['jsons'][-2]
        elif op==3:
            assert f[20:23]==(2,6144,24)
            pp,aa,rr=struct.unpack_from('<3Q',c['w'].raw(),6144)
            value=baseline['jsons'][-1]
            assert R.get(pp)==value['profiles'] and R.get(aa)==value['profile_manifests']
            assert R.get(rr)==value['resources'] and R.get(a)==value['installation']
            assert R.get(b)==value['catalog_sha256']
        elif op==4:value=baseline['examples']['document']
        elif op==5:
            value=baseline['jsons'][-3]
            assert R.get(x)==value['core'] and R.get(y)==value['assembly']
        elif op==6:
            value=baseline['jsons'][-4];assert R.get(a)==value['installation']
        else:raise AssertionError(('value-mode',op))
        complete(c,2,R.issue(copy.deepcopy(value)))
    elif peerid==10:
        if op==1:complete(c,8,R.issue({}),R.issue({}))
        elif op==2:
            left=dict(R.get(a));right=dict(R.get(b))
            left[literal]=R.get(d);right[literal]=R.get(e)
            complete(c,8,R.issue(left),R.issue(right))
        elif op==3:
            assert a==6 and f[20]==2 and f[21]==6144
            raw=c['w'].raw()[f[21]:f[21]+f[22]];result={}
            for i in range(a):
                at,n,token,zero=struct.unpack_from('<4Q',raw,i*32)
                assert zero==0 and at<=len(raw) and n<=len(raw)-at
                result[raw[at:at+n].decode()]=R.get(token)
            complete(c,2,R.issue(result))
        else:
            assert op==4;value=dict(R.get(a));value[literal]=R.get(b)
            complete(c,2,R.issue(value))
    elif peerid==11:
        body=R.get(a);namespace=R.get(b,'namespace');assert b==f[12]
        result=(dict(id=literal,sha256=sha256(literal.encode()).hexdigest()),ref('profile-'+literal))
        if observe(c,'profile',(literal,body),result,fail_at):
            namespace.profile_count+=1
            complete(c,9,R.issue(result[0]),R.issue(result[1]))
    elif peerid==12:
        assert 1<=op<=6
        complete(c,2,R.issue(copy.deepcopy(baseline['jsons'][op-1])))
    elif peerid==13:
        result=('fixture-current-installed-resource:'+literal).encode()
        if observe(c,'file',literal,result,fail_at):complete(c,10,R.issue(result,'bytes'))
    elif peerid==14:
        value=R.get(a,'bytes');namespace=R.get(b,'namespace');assert b==f[12] and literal=='discovery'
        result=ref('put-'+str(namespace.put_count))
        if observe(c,'put',(value,literal),result,fail_at):
            namespace.put_count+=1;complete(c,2,R.issue(result))
    elif peerid==15:
        value=R.get(a);namespace=R.get(b,'namespace');assert b==f[12] and literal=='discovery'
        result=ref('json-'+str(namespace.json_count))
        if observe(c,'json',(value,literal),result,fail_at):
            namespace.json_count+=1;complete(c,2,R.issue(result))
    elif peerid==16:
        document=R.get(a);result=Program(copy.deepcopy(document),'4'*64)
        c['program_document']=copy.deepcopy(document)
        if observe(c,'verify',document,result,fail_at):
            complete(c,11,R.issue(result,'program'),R.issue(result.as_dict()),
                R.issue(result.sha256),digest_bytes=bytes.fromhex(result.sha256))
    elif peerid==17:
        program=R.get(a,'program');result='fixture complete-render result\n'
        if observe(c,'render',program,result,fail_at):
            complete(c,12,R.issue(result),R.issue(result.encode(),'bytes'))
    elif peerid==18:
        value=R.get(a);result=Program(copy.deepcopy(c['program_document']),('5' if mismatch else '4')*64)
        if observe(c,'assemble',value,result,fail_at):
            complete(c,11,R.issue(result,'program'),R.issue(result.as_dict()),
                R.issue(result.sha256),digest_bytes=bytes.fromhex(result.sha256))
    elif peerid==19:complete(c,2,R.issue(R.get(a)[literal]))
    else:raise AssertionError(('peer',peerid))
def drive(paths,label,fail_at=None,false_dirs=(),mismatch=False,stop_peer=None):
    c=configure(paths)
    while True:
        ret=invoke('sequence',c['s'],c['r'],c['w'],label)
        if ret==BAD:return dict(private_bad=True),c
        f=frame(c,ret)
        if f[1]==1:
            assert f[8]>c['w'].n
            c['w']=grow(c['w'],f[8]);c['grows']+=1;continue
        if f[1]==2:
            if f[6]==stop_peer:return None,c
            peer(c,fail_at,false_dirs,mismatch);continue
        if f[1]==0:return dict(state=native_state(c),error=None),c
        assert f[1]==3
        if f[27]==0:
            assert f[28]==3 and f[29]==90001
            payload=c['r'].raw()[f[30]:f[30]+f[31]]
            prefix=b'fixture-issued-peer-exception:';assert payload.startswith(prefix)
            error=dict(error_class='PeerFailure',error=payload[len(prefix):].decode())
        else:
            assert f[28]==2 and f[29]==37 and f[27] in (1,2)
            error=dict(error_class={1:'AgentRejected',2:'RuntimeError'}[f[27]],
                error=c['w'].raw()[f[30]:f[30]+f[31]].decode())
        return dict(state=native_state(c),error=error),c
def check(label,paths=(),fail_at=None,false_dirs=(),mismatch=False):
    global case_count
    expected=oracle(paths,fail_at,false_dirs,mismatch)
    before=dict(entries)
    # Every provider in this test is explicitly foreign. Only the sequence
    # image is under native ownership, and it may not call the old sequence.
    with ExitStack() as stack:
        for target in ('hepta.hia_agent_service.HIAAgentService.__init__',
            'hepta.hia_agent_service.HIAAgentService._profiles',
            'hepta.hia_agent_service.HIAAgentService._examples'):
            stack.enter_context(patch(target,new=disabled))
        actual,c=drive(paths,label,fail_at,false_dirs,mismatch)
    assert actual=={key:expected[key] for key in ('state','error')},(label,expected['error'],actual)
    assert c['trace']==expected['trace'],(label,'full ordered requests/results/partial state',len(c['trace']),len(expected['trace']))
    record=dict(case=case_count+1,label=label,status='PASS',source=cas(c['raw']),
        reference_trace=cas(json.dumps(expected['trace'],ensure_ascii=True,default=lambda v:{'bytes':v.hex()}).encode()),
        actual_trace=cas(json.dumps(c['trace'],ensure_ascii=True,default=lambda v:{'bytes':v.hex()}).encode()),
        expected_state=cas(json.dumps(expected['state'],ensure_ascii=True).encode()),
        actual_state=cas(json.dumps(actual['state'],ensure_ascii=True).encode()),
        error=actual['error'],grows=c['grows'],semantic_peer_calls=len(c['trace']),
        actual_native_entries=entries['sequence']-before['sequence'],
        exact_complete_state_and_error_and_order=True,all_semantic_peers_are_foreign=True)
    results.write(json.dumps(record,sort_keys=True)+'\n');results.flush();case_count+=1
    print(json.dumps(dict(event='INIT_SEQUENCE_PASS',group=GROUP,label=label,case=case_count)),flush=True)
def semantic_cases():
    global planned
    items=[
      ('empty',(),None,(),False),
      ('three-roots',('/one','/two','/three'),None,(),False),
      ('unicode-roots',('/é','/中','/😀'),None,(),False),
      ('first-not-directory',('/one','/two'),None,('/resolved/one',),False),
      ('last-not-directory',('/one','/two'),None,('/resolved/two',),False),
      ('late-resolve-before-first-isdir',('/one','/two'),'resolve:1',('/resolved/one',),False),
      ('roundtrip-mismatch',(),None,(),True)]
    planned=len(items)
    for args in items:check(*args)
def failure_cases():
    global planned
    base=oracle(('/one','/two'))
    kinds={'constructor':{'catalog','installation','open','resolve','isdir','str','digest'},
        'profiles':{'profile'},'resources':{'json','file','put'},
        'examples':{'verify','render','assemble'}}[GROUP]
    items=[row['label'] for row in base['trace'] if row['kind'] in kinds]
    planned=len(items)
    for label in items:check('refusal-'+label,('/one','/two'),fail_at=label)
def protocols():
    global planned,case_count
    controls=[]
    def refuse(c,label):
        assert invoke('sequence',c['s'],c['r'],c['w'],label)==BAD
        before=c['w'].raw()
        assert invoke('sequence',c['s'],c['r'],c['w'],label+'.again')==BAD
        assert c['w'].raw()==before
    def config(index,value):
        c=configure(());c['w'].write(128+index*8,pack(value));refuse(c,'config-'+str(index))
    for index,value in ((0,0),(1,0),(2,0),(3,54),(4,0),(5,0),(6,639),(7,1),(23,1)):
        controls.append(('config-'+str(index),lambda i=index,v=value:config(i,v)))
    def initial_reply():
        c=configure(());c['r']=Buffer(1,b'x');refuse(c,'initial-reply')
    controls.append(('initial-nonempty-reply',initial_reply))
    def pending():
        c=configure(())
        f=frame(c,invoke('sequence',c['s'],c['r'],c['w'],'pending-catalog'))
        assert f[1]==2 and f[6]==1
        peer(c,None,(),False);return c
    def response(index,value):
        c=pending();c['r'].write(index*8,pack(value));refuse(c,'reply-'+str(index))
    for index,value in ((0,0),(1,38),(2,84),(3,0),(4,2),(5,2),(6,2),(8,0),(9,0),
        (10,1),(11,1),(12,1),(13,1),(14,1),(15,255),(16,1),(20,1),(31,1)):
        controls.append(('reply-'+str(index),lambda i=index,v=value:response(i,v)))
    def source(index,value):
        c=pending();c['s'].write(index*8,pack(value));refuse(c,'source-'+str(index))
    for index,value in ((0,0),(1,54),(2,0),(3,0),(6,0),(7,1)):
        controls.append(('source-header-'+str(index),lambda i=index,v=value:source(i,v)))
    def error(index,value):
        c=pending();complete(c,0,error='catalog:0')
        c['r'].write(index*8,pack(value));refuse(c,'error-'+str(index))
    for index,value in ((12,0),(13,255),(13,MAX),(14,MAX)):
        controls.append(('error-extent-'+str(index)+'-'+str(value),lambda i=index,v=value:error(i,v)))
    def error_success_payload():
        c=pending();c['r']=Buffer(257,c['r'].raw()+b'x')
        c['r'].write(120,pack(257));refuse(c,'success-extra-payload')
    controls.append(('success-extra-payload',error_success_payload))
    def stale():
        c=pending();old=c['r'].raw()
        f=frame(c,invoke('sequence',c['s'],c['r'],c['w'],'after-catalog'))
        assert f[6]==2;c['r']=Buffer(len(old),old);refuse(c,'stale-catalog-as-tools')
    controls.append(('stale-reply',stale))
    def short():
        c=configure(());before=c['w'].raw()
        assert invoke('sequence',c['s'],c['r'],c['w'],'short',8191)==BAD
        assert c['w'].raw()==before
    controls.append(('short-workspace-retire',short))
    def sequence():
        c=pending();c['w'].write(C['I_SEQ'],pack(MAX));refuse(c,'sequence-overflow')
    controls.append(('sequence-overflow',sequence))
    def terminal():
        _,c=drive((),'terminal')
        refuse(c,'terminal-reuse')
    controls.append(('terminal-reuse',terminal))
    def dirty():
        c=configure(());c['w'].write(7000,b'\1');refuse(c,'dirty-initial')
    controls.append(('dirty-initial',dirty))
    planned=len(controls)
    for label,body in controls:
        before=entries['sequence'];body()
        results.write(json.dumps(dict(case=case_count+1,label=label,status='PASS',
            private_protocol=True,actual_native_entries=entries['sequence']-before),sort_keys=True)+'\n')
        results.flush();case_count+=1

try:
    read(__file__);read(helper)
    for p in sorted((ROOT/'tools').glob('*.py')):read(p)
    assert digest(read(REFERENCE/'hepta/hia_agent_service.py'))=='684caf496de7e3e7c8db1fd80ef616139cf13717aa5879bbd2d6ebf834df9330'
    for name in ('hepta/hia_agent_store.py','hepta/hia_agent_assembly.py','hepta/hia_json_preflight_native.py'):read(REFERENCE/name)
    original=read(WORK/'native-agent-edit-render-next/development/graph_harness_r3.py')
    assert (len(original),digest(original))==(9783,'75fe54554a93e19e30251073ac225deff944d6673d87ccc2b597e47a19e8be7c')
    tree=ast.parse(original);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='capture')
    namespace={'struct':struct,'GRAPH':M(b'HIAGRF01')}
    exec(compile(ast.Module(body=[node],type_ignores=[]),'<exact-original-private-capture>','exec'),namespace)
    capture=namespace['capture']
    bundle=json.loads(read(COMPILE/'bundle.json'))
    assert bundle['schema']=='hia-worker-initialization-sequence-development-v1'
    assert bundle['status']=='PASS' and set(bundle['components'])=={'sequence'}
    row=bundle['components']['sequence']
    current=(ROOT/'examples/hia_bootstrap/agent_worker_initialization_sequence.hiaasm').resolve()
    assert Path(row['source_path']).resolve()==current
    source=read(current);image=read(row['image_path']);receipt=json.loads(read(row['receipt_path']))
    assert Path(row['image_path']).resolve().parent==COMPILE
    assert Path(row['receipt_path']).resolve()==COMPILE/'sequence.receipt.json'
    assert (len(source),digest(source))==(row['source_bytes'],row['source_sha256'])
    assert (len(image),digest(image))==(row['image_bytes'],row['image_sha256'])
    compiler=read(WORK/'dependencies/f50-B3.image.bin')
    assert (len(compiler),digest(compiler))==(668608,'0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8')
    assert receipt['input_sha256']==digest(source) and receipt['produced_sha256']==digest(image)
    assert receipt['image_sha256']==digest(compiler)==row['compiler_sha256']
    assert same();save(OUT/'source-before.json',rows())
    images={'sequence':NativeHiaJsonImage(image,digest(image))}
    if GROUP=='semantic':semantic_cases()
    elif GROUP=='protocol':protocols()
    else:failure_cases()
    assert case_count==planned,(case_count,planned);status='PASS'
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
    ledger.close();results.close();unchanged=same()
    if not unchanged:status='FAIL'
    summary=dict(status=status,group=GROUP,cases=case_count,planned_cases=planned,
        entries=entries,total_actual_entries=sum(entries.values()),failure=failure,
        source_unchanged=unchanged,compressed_cas_objects=len(saved),elapsed_ns=time.monotonic_ns()-started,
        scope='COMPLETE_INITIALIZER_ORDER_NATIVE_WITH_ALL_TYPED_PEERS_FOREIGN',
        all_19_semantic_peer_services_are_foreign=True,actual_native_projection_entries=0,
        actual_namespace_effects=0,actual_filesystem_effects=0,
        ordinary_initialization_closed=False,whole_worker_closed=False,production_activation=False,
        original_limits=dict(cpu_seconds=90,address_space_bytes=1<<30))
    save(OUT/'source-after.json',rows());save(OUT/'summary.json',summary)
    print(json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
