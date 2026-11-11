"""Actual call-control image versus the unchanged selected-call reference.

Every foreign peer in this file is an explicit controlled fixture. The HIA
image owns control decisions; this test does not qualify those fixture peers,
SQLite durability, schemas, business methods or a whole native Worker.
"""
from __future__ import annotations
import ctypes,copy,json,os,resource,sqlite3,struct,sys,threading,time,traceback,zlib
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

WORK=Path(sys.argv[1]).resolve()
COMPILE=Path(sys.argv[2]).resolve()
OUT=Path(sys.argv[3]).resolve()
REFERENCE=WORK/'Hepta-agent-edit-native'
REFERENCE_PINS=[
  {
    "path": "hepta/hia_agent_journal_native.py",
    "bytes": 22923,
    "sha256": "1cbd3c43ad5439f6fcfa1455d0c10725d38f7ae2807e403d9d3f47cdba874d21",
    "gitsha": "8ce760d5d6155aa69164b265b79253a76b5a937c"
  },
  {
    "path": "hepta/hia_agent_store.py",
    "bytes": 20250,
    "sha256": "fae25d48a6de7187ed465287c1491af74214ac8bf3eae2af921bd100a247b822",
    "gitsha": "ce939c30102a16d0c0d9736774dca3c50d91f879"
  },
  {
    "path": "hepta/hia_agent_service.py",
    "bytes": 100742,
    "sha256": "684caf496de7e3e7c8db1fd80ef616139cf13717aa5879bbd2d6ebf834df9330",
    "gitsha": "2f56a5b4b02c54b9e56e53882db5cbd5687e4b4e"
  }
]
for row in REFERENCE_PINS:
    frozen_raw=(REFERENCE/row['path']).read_bytes()
    assert (len(frozen_raw),sha256(frozen_raw).hexdigest())==(row['bytes'],row['sha256'])
sys.path.insert(0,str(REFERENCE))
import hepta.hia_agent_journal_native as journal
import hepta.hia_agent_service as hosted
from hepta.hia_agent_store import AgentStore,AgentRejected
from hepta.hia_json_preflight_native import NativeHiaJsonImage
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
MAG=lambda x:int.from_bytes(x,'little')
BAD=0xfffffffd
CANARY=bytes(range(64))
pack=lambda *x:struct.pack('<'+'Q'*len(x),*x)
TOOLS=journal.TOOLS
CLASS={ValueError:1,TypeError:2,OSError:3,OverflowError:4,RecursionError:5,
       RuntimeError:6,UnicodeDecodeError:7,json.JSONDecodeError:8,sqlite3.Error:9,
       KeyboardInterrupt:10,MemoryError:11,AttributeError:12,KeyError:13}
def exc_class(exc):
    if isinstance(exc,AgentRejected):return 1
    return CLASS.get(type(exc),14)
def error(kind,where):
    if kind==7:return UnicodeDecodeError('utf-8',b'\xff',0,1,where)
    if kind==8:return json.JSONDecodeError(where,'x',0)
    cls=next(k for k,v in CLASS.items() if v==kind)
    return cls(where)
def clean(value):
    if isinstance(value,BaseException):
        return {'exception':type(value).__name__,'text':str(value),'code':getattr(value,'code',None)}
    if isinstance(value,bytes):return {'bytes':value.hex()}
    if isinstance(value,tuple):return {'tuple':[clean(x) for x in value]}
    if isinstance(value,list):return [clean(x) for x in value]
    if isinstance(value,dict):return {k:clean(v) for k,v in value.items()}
    return value
def disabled(*a,**kw):raise AssertionError('retained call owner entered during actual native forwarding')

class Cursor:
    def __init__(self,env,value):self.env,self.value=env,value
    def fetchone(self):return self.env.hit('fetchone',(),self.value)

class DB:
    def __init__(self,env):self.env=env
    def execute(self,sql,binds=()):
        name=('BEGIN' if sql=='BEGIN IMMEDIATE' else 'COMMIT' if sql=='COMMIT'
              else 'ROLLBACK' if sql=='ROLLBACK' else 'SELECT' if sql.startswith('SELECT')
              else 'INSERT' if sql.startswith('INSERT INTO requests') else 'COST' if sql.startswith('INSERT INTO costs')
              else 'UPDATE' if sql.startswith('UPDATE requests') else 'UNKNOWN_SQL')
        assert name!='UNKNOWN_SQL',sql
        self.env.hit('sql.'+name,binds,None)
        return Cursor(self.env,self.env.row if name=='SELECT' else None)

class Store:
    transaction=AgentStore.transaction
    def __init__(self,env):
        self.env=env;self.lock=threading.RLock();self.db=DB(env)
    def resolve_uri(self,uri):
        return self.env.hit('resolve_uri',(uri,),{'sha256':'artifact','kind':'fixture'})

class Session:
    def __init__(self,env):self.env=env;self.active_tool=env.tool
    @property
    def request_id(self):return self.env.hit('request_id',(),'request-fixed')
    @property
    def key(self):return self.env.hit('key',(),'request-key')
    @property
    def request_digest(self):return self.env.hit('request_digest',(),'request-digest')
    @property
    def tool(self):return self.env.hit('aliased_tool',(),self.active_tool)
    def step(self,stage,raw=b''):
        e=self.env
        name={0:'prepare',1:'lookup',2:'reserved',4:'aliased',5:'effect',6:'inline',7:'committed_inline'}[stage]
        e.hit('journal.'+name,(raw,),None)
        if stage==0:action=e.case.get('prepare',journal.CONTINUE)
        elif stage==1:action=e.case.get('lookup',journal.RESERVE)
        elif stage in (2,4):action=journal.CONTINUE
        elif stage==5:action=journal.ATOMIC if e.case.get('atomic') else journal.CONTINUE
        elif stage==6:action=journal.JOURNAL if e.case.get('inline',True) else journal.NONE
        else:action=journal.NONE
        if stage==4:self.active_tool='hia_read'
        response=raw if stage==6 else b''
        return SimpleNamespace(action=action,flags=0,status='completed',response=response,cost_details=b'')
    def prepare(self,raw,foreign=b''):
        assert foreign==b''
        return self.step(0,raw)
    def lookup(self,row):
        return self.step(1,self.env.lookup_wire(row))
    def reserved(self):return self.step(2)
    def cached(self,raw):
        self.env.hit('journal.cached',(raw,),None)
        action=journal.VERIFY_REPLAY if self.env.case.get('replay') else journal.REPLAY
        return SimpleNamespace(action=action),copy.deepcopy(self.env.cached)
    def aliased(self):return self.step(4)
    def effect(self):return self.step(5)
    def inline(self,response):return self.step(6,self.env.wire(response))
    def committed_inline(self):return self.step(7)
    def finish_raw(self,raw):
        self.env.hit('journal.finish',(raw,),None)
        flags=0 if raw==b'' else self.env.case.get('flags',3)
        status='rejected' if b'"status":"rejected"' in raw else 'completed'
        return SimpleNamespace(action=journal.FINAL if flags else journal.NONE,
            flags=flags,status=status,response=raw,cost_details=self.env.case.get('cost',b'{"unit":"fixture"}'))
    def finish(self,response):return self.finish_raw(b'' if response is None else self.env.wire(response))
    def raise_refusal(self):
        self.env.hit('journal.refusal',(),None)
        raise AgentRejected('E_FIXTURE_REFUSAL','fixture journal refusal')

class Service:
    def __init__(self,env):
        self.env=env;self.catalog_sha256='catalog';self.identities={'implementation':'fixture'}
        self.tools={tool:{'inputSchema':('input',tool),'outputSchema':('output',tool)} for tool in TOOLS}
        self.store=Store(env)
    def _context(self,ref):return self.env.hit('context',(ref,),{'context':'resolved'})
    def _budget(self,context,*,candidate=False):return self.env.hit('budget',(context,candidate),None)
    def _replay_verification(self,cached,args):return self.env.hit('replay',(cached,args),None)
    def _error(self,request_id,exc):
        self.env.hit('error_record',(request_id,exc),None)
        return {'request_id':request_id,'status':'rejected','error':clean(exc)}
    def __getattr__(self,name):
        if name.startswith('_hia_'):
            return lambda args:self.env.hit('business.'+name[1:],(args,),copy.deepcopy(self.env.case.get('result',{'value':7})))
        raise AttributeError(name)

class Env:
    def __init__(self,case):
        self.case=case;self.trace=[];self.counts={};self.pool={};self.next=1;self.ids={}
        self.tool=case.get('tool','hia_describe')
        self.arguments=copy.deepcopy(case.get('arguments',{'catalog_sha256':'catalog'}))
        self.cached={'request_id':'cached-request','status':'completed','result':{'cached':1}}
        self.row=(None if case.get('row_none',False) else
                  {'key':'request-key','digest':'request-digest','tool':self.tool,'state':'completed',
                   'response':'cached-json','started_ns':'456'})
        self.session=Session(self);self.service=Service(self)
    def h(self,value):
        key=id(value)
        if key not in self.ids:
            self.ids[key]=self.next;self.pool[self.next]=value;self.next+=1
        return self.ids[key]
    def v(self,key):
        assert key in self.pool,('unknown fixture lease',key)
        return self.pool[key]
    def hit(self,name,args,value):
        n=self.counts.get(name,0)+1;self.counts[name]=n
        mark=name+'#'+str(n)
        self.trace.append([mark,clean(args)])
        kind=self.case.get('faults',{}).get(mark)
        if kind is not None:raise error(kind,mark)
        return value
    def monotonic(self):
        return self.hit('monotonic',(),1000 if self.counts.get('monotonic',0)==0 else self.case.get('now',900))
    def realtime(self):return self.hit('realtime',(),123456789012345678901)
    def uuid(self):return SimpleNamespace(hex=self.hit('uuid',(),'0123456789abcdef0123456789abcdef'))
    def install(self):return self.hit('install',(),self.session)
    def wire(self,value):
        self.hit('wire',(value,),None)
        return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    def data(self,raw):
        self.hit('data',(raw,),None)
        return json.loads(raw)
    def validate(self,value,schema,label='arguments'):
        return self.hit('schema_'+schema[0],(value,schema[1],label),None)
    def identity(self):return self.hit('identity',(),{'implementation':'stale' if self.case.get('stale') else 'fixture'})
    def keys(self,value,required,optional=(),label='object'):
        self.hit('keys',(value,required,optional,label),None)
        if type(value) is not dict or not set(required)<=set(value) or set(value)-set(required)-set(optional):
            raise AgentRejected('E_HIA_FIELDS',label+' has missing or unknown fields')
    def lookup_wire(self,row):
        observed=lambda v:v if type(v) is str else {'sqlite_storage_class':type(v).__name__}
        return self.wire(None if row is None else {'digest':observed(row['digest']),'state':observed(row['state'])})
    def observe_reference(self):
        with ExitStack() as stack:
            for target,name,value in (
                (hosted,'time',SimpleNamespace(monotonic_ns=self.monotonic,time_ns=self.realtime)),
                (hosted,'uuid',SimpleNamespace(uuid4=self.uuid)),(hosted,'decode_data',self.data),
                (hosted,'validate',self.validate),(hosted,'keys',self.keys),
                (hosted,'installation_manifest',self.identity),(journal,'wire',self.wire),
                (journal,'installed_agent_journal',lambda manifest:SimpleNamespace(session=self.install))):
                stack.enter_context(patch.object(target,name,new=value))
            try:value=journal.call_with_native_journal(self.service,self.tool,copy.deepcopy(self.arguments),'fixture')
            except BaseException as exc:return ['raise',clean(exc)]
            return ['return',clean(value)]
    def peer(self,op,a):
        v=self.v;h=self.h;e=self;ss=self.session;srv=self.service
        if op==1:return [h(e.monotonic())]
        if op==2:return [h(e.uuid())]
        if op==3:return [h('unadmitted-'+v(a[0]).hex)]
        if op==4:return [h(e.install())]
        if op==5:return [h(e.wire(v(a[0])))]
        if op==6:return [h(e.data(v(a[0])))]
        if op==7:return [h({'tool':v(a[0]),'arguments':v(a[1])})]
        if op==8:
            assert v(a[0]) is ss
            stage=a[1];raw=b'' if a[2]==0 else v(a[2])
            step=ss.finish_raw(raw) if stage==8 else ss.step(stage,raw)
            tool=ss.tool if stage==4 else ss.active_tool
            status=1 if step.status=='completed' else 2
            return [step.action,h(ss),h('request-fixed'),h('request-key'),h('request-digest'),
                    TOOLS.index(tool)+1,step.flags,status,h(step.response) if step.response else 0,
                    h(step.cost_details) if step.cost_details else 0,0,0,h(tool)]
        if op==9:e.keys(v(a[0]),('uri',),('max_bytes',),'resource read');return []
        if op==10:return [h(srv.store.resolve_uri(v(a[1])))]
        if op==11:return [h({'catalog_sha256':v(a[0]),'artifact':v(a[1]),'max_bytes':v(a[2]).get('max_bytes',65536)})]
        if op==12:srv.store.db.execute('BEGIN IMMEDIATE');return []
        if op==13:
            binds=v(a[2]);sql={7:'SELECT * FROM requests WHERE key=?',
                8:'INSERT INTO requests VALUES (?,?,?,?,?,?)',
                9:"UPDATE requests SET state='completed',response=? WHERE key=?",
                10:'INSERT INTO costs (context_id,tool,request_id,wall_ns,status,details) VALUES (?,?,?,?,?,?)'}[a[1]]
            cur=srv.store.db.execute(sql,binds)
            return [h(cur.fetchone() if a[1]==7 else cur)]
        if op==14:srv.store.db.execute('COMMIT');return []
        if op==15:srv.store.db.execute('ROLLBACK');return []
        if op==16:
            row=v(a[0]);return [h(e.lookup_wire(row)),h(row['response']) if row is not None else 0]
        if op==17:return [h(e.realtime())]
        if op==18:
            if a[0]==0:
                assert v(a[1]) is ss
                return [h((ss.key,ss.request_digest,v(a[2]),'running',None))]
            assert a[0]==1
            return [h((*v(a[1]),str(v(a[2]))))]
        if op==19:
            assert v(a[0]) is ss
            result,cached=ss.cached(v(a[1]));return [result.action,h(cached)]
        if op==20:e.validate(v(a[2]),srv.tools[v(a[1])]['inputSchema']);return []
        if op==21:
            if v(a[0])['catalog_sha256']!=v(a[1]):
                raise AgentRejected('E_HIA_CATALOG_STALE','tool catalog digest differs from installed catalog')
            return []
        if op==22:
            if e.identity()!=v(a[1]):
                raise AgentRejected('E_HIA_IMPLEMENTATION_STALE','installed implementation changed during this service session')
            return []
        if op==23:
            args=v(a[0]);return [1,h(args['context'])] if 'context' in args else [0,0]
        if op==24:return [h(srv._context(v(a[1])))]
        if op==25:srv._budget(v(a[1]),candidate=bool(a[2]));return []
        if op==26:return [h(getattr(srv,'_'+TOOLS[a[0]-1])(v(a[1])))]
        if op==27:return [h({'contract_version':hosted.VERSION,'request_id':v(a[0]),'status':'completed','result':v(a[1])})]
        if op==28:e.validate(v(a[2]),srv.tools[v(a[1])]['outputSchema'],'result');return []
        if op==29:srv._replay_verification(v(a[0]),v(a[1]));return []
        if op==30:ss.raise_refusal();raise AssertionError('refusal returned')
        if op==31:return [h(srv._error(v(a[0]),v(a[1])))]
        if op==32:return [h(AgentRejected('E_HIA_JOURNAL_NATIVE',str(v(a[0]))))]
        if op==33:return [h(str(v(a[0])))]
        if op==34:return [h(str(v(a[0])-v(a[1])))]
        if op==35:return [h((None if a[0]==0 else v(a[0]),v(a[1]),v(a[2]),v(a[3]),
                              'completed' if a[4]==1 else 'rejected',v(a[5]).decode('utf-8')))]
        if op==36:return [h((v(a[0]).decode('utf-8'),ss.key))]
        if op==37:return [h(v(a[0])['id'])]
        if op==38:return [h((ss.key,))]
        if op==39:return [h(v(a[0])['uri'])]
        if op==40:return [h(ss.request_id)]
        raise AssertionError(('unknown fixed fixture peer',op))

class Buffer:
    def __init__(self,size,raw=b''):
        assert len(raw)<=size
        self.size=size;self.buf=ctypes.create_string_buffer(size+64)
        if raw:ctypes.memmove(self.address,raw,len(raw))
        ctypes.memmove(self.address+size,CANARY,64)
    @property
    def address(self):return ctypes.addressof(self.buf)
    def raw(self):return ctypes.string_at(self.address,self.size)
    def guard(self):assert ctypes.string_at(self.address+self.size,64)==CANARY

class Image:
    def __init__(self):
        self.pins={}
        def read(path):
            p=Path(path).resolve();raw=p.read_bytes()
            if p in self.pins:assert self.pins[p]==raw
            self.pins[p]=raw;return raw
        m=json.loads(read(COMPILE/'call-control.manifest.json'))
        assert m['schema']=='hepta.hia.agent-service-call-control-development.v1'
        assert m['scope']=='CALL_CONTROL_GENERATION_AND_BOUNDED_COMPILE_ONLY'
        source=read(m['source_path']);image=read(m['image_path']);compiler=read(m['compiler_path'])
        assert len(source)==m['source_bytes'] and sha256(source).hexdigest()==m['source_sha256']
        assert len(image)==m['image_bytes'] and sha256(image).hexdigest()==m['image_sha256']
        assert len(compiler)==668608 and sha256(compiler).hexdigest()==m['compiler_sha256']=='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
        assert source==read(WORK/'native-agent-service-call-control-next/examples/hia_bootstrap/agent_service_call.hiaasm')
        receipt=json.loads(read(m['receipt_path']))
        assert (receipt['input_sha256'],receipt['produced_sha256'],receipt['image_sha256'])==(m['source_sha256'],m['image_sha256'],m['compiler_sha256'])
        for row in json.loads((COMPILE/'source-before.json').read_bytes()):assert sha256(read(row['path'])).hexdigest()==row['sha256']
        for p in (Path(__file__),REFERENCE/'hepta/hia_agent_journal_native.py',REFERENCE/'hepta/hia_agent_store.py',REFERENCE/'hepta/hia_agent_service.py'):
            read(p)
        self.check()
        OUT.mkdir(parents=True,exist_ok=False);(OUT/'cas').mkdir()
        self.saved=set();self.entries=0;self.cases=0;self.image=NativeHiaJsonImage(image,m['image_sha256'])
        self.ledger=(OUT/'entries.jsonl').open('w')
        self.caseledger=(OUT/'cases.jsonl').open('w')
        (OUT/'source-before.json').write_text(json.dumps(self.pinrows(),indent=2)+'\n')
    def check(self):
        for p,b in self.pins.items():assert p.read_bytes()==b,str(p)
    def pinrows(self):return [dict(path=str(p),bytes=len(b),sha256=sha256(b).hexdigest()) for p,b in self.pins.items()]
    def save(self,raw):
        key=sha256(raw).hexdigest()
        if key not in self.saved:
            p=OUT/'cas'/(key+'.zlib');p.write_bytes(zlib.compress(raw,1))
            assert zlib.decompress(p.read_bytes())==raw
            self.saved.add(key)
        return dict(bytes=len(raw),sha256=key)
    def invoke(self,source,command,work,label):
        sb=Buffer(len(source),source);cb=Buffer(len(command),command);before=work.raw()
        status=int(self.image._entry(sb.address,sb.size,cb.address,cb.size,work.address,work.size))
        assert sb.raw()==source and cb.raw()==command
        for b in (sb,cb,work):b.guard()
        self.entries+=1
        row=dict(entry=self.entries,label=label,status=status,source=self.save(source),command=self.save(command),
                 before=self.save(before),after=self.save(work.raw()))
        self.ledger.write(json.dumps(row,sort_keys=True)+'\n');self.ledger.flush()
        return status
    def run(self,case):
        oracle=Env(case);expected=oracle.observe_reference()
        e=Env(case);lease=self.cases+1;call=73;epoch=91
        source=pack(MAG(b'HIASCS01'),lease,call,epoch,0,0,0,0)
        command=pack(MAG(b'HIASCC01'),lease,call,3,4300,e.h(e.tool),e.h(copy.deepcopy(e.arguments)),e.h('catalog'),
                     e.h(e.service.tools),e.h(e.service.identities),e.h(e.service.store),e.h('installation'),epoch,*([0]*19))
        work=Buffer(4096);seq=0;events=[]
        with ExitStack() as stack:
            stack.enter_context(patch.object(journal,'call_with_native_journal',new=disabled))
            stack.enter_context(patch.object(journal.JournalSession,'_run',new=disabled))
            stack.enter_context(patch.object(hosted.HIAAgentService,'_reference_call',new=disabled))
            while True:
                status=self.invoke(source,command,work,case['name'])
                assert status==512,(case['name'],status,work.raw()[:256].hex())
                event=struct.unpack_from('<32Q',work.raw(),256);events.append(list(event))
                seq+=1
                assert event[0]==MAG(b'HIASCE01') and event[2:5]==(lease,call,seq)
                assert event[23:26]==(3,4300,epoch) and event[28:]==(0,0,0,0)
                if event[1]==0:actual=['return',clean(e.v(event[14]))];break
                if event[1]==2:actual=['raise',clean(e.v(event[16]))];break
                assert event[1]==1
                try:values=e.peer(event[6],event[8:14]);failed=kind=exception=0
                except BaseException as exc:values=[];failed=1;kind=exc_class(exc);exception=e.h(exc)
                assert len(values)<=16
                command=pack(MAG(b'HIASCA01'),lease,call,seq,event[6],failed,kind,exception,*values,*([0]*(16-len(values))),*([0]*8))
        row=dict(name=case['name'],case=clean(case),expected=expected,actual=actual,reference_trace=oracle.trace,native_trace=e.trace,
                 final_event=list(event),events=events,equal=actual==expected and e.trace==oracle.trace)
        self.caseledger.write(json.dumps(row,sort_keys=True)+'\n');self.caseledger.flush()
        assert row['equal'],json.dumps(row,sort_keys=True)
        for point in case.get('faults',{}):
            operation,ordinal=point.rsplit('#',1)
            assert oracle.counts.get(operation,0)>=int(ordinal),('unreached oracle fault',point)
            assert e.counts.get(operation,0)>=int(ordinal),('unreached native fixture fault',point)
        self.cases+=1
    def protocol(self):
        # These controls exercise actual malformed continuations; no fixture
        # is asked to decide acceptance or repair a frame.
        for kind in ('magic','lease','call','sequence','peer','failure_flag','success_error','reserved','extra_result','failure_payload'):
            source=pack(MAG(b'HIASCS01'),201,73,91,0,0,0,0)
            initial=[MAG(b'HIASCC01'),201,73,3,4300,11,12,13,14,15,16,17,91]+[0]*19
            work=Buffer(4096)
            assert self.invoke(source,pack(*initial),work,'protocol.'+kind)==512
            ev=struct.unpack_from('<32Q',work.raw(),256)
            ack=[MAG(b'HIASCA01'),201,73,1,1,0,0,0,101]+[0]*23
            bad=list(ack)
            index={'magic':0,'lease':1,'call':2,'sequence':3,'peer':4,'failure_flag':5,'success_error':6,'reserved':31,'extra_result':9}.get(kind)
            if kind=='failure_payload':bad[5:8]=[1,1,99]
            elif kind=='failure_flag':bad[index]=2
            else:bad[index]+=1
            assert self.invoke(source,pack(*bad),work,'protocol.'+kind)==BAD
            frozen=work.raw()
            assert self.invoke(source,pack(*ack),work,'protocol.poison.'+kind)==BAD
            assert work.raw()==frozen
            self.cases+=1
        source=pack(MAG(b'HIASCS01'),301,73,91,0,0,0,0)
        initial=pack(MAG(b'HIASCC01'),301,73,3,4300,11,12,13,14,15,16,17,91,*([0]*19))
        short=Buffer(4095)
        assert self.invoke(source,initial,short,'protocol.short_workspace')==BAD
        assert short.raw()==b'\0'*4095
        self.cases+=1

def cases():
    base=[
        {'name':'plain','flags':0},
        {'name':'all-final-writes'},
        {'name':'atomic','atomic':True},
        {'name':'atomic-no-inline','atomic':True,'inline':False},
        {'name':'reserve','prepare':journal.LOOKUP,'row_none':True},
        {'name':'reserve-atomic','prepare':journal.LOOKUP,'row_none':True,'atomic':True},
        {'name':'cache','prepare':journal.LOOKUP,'lookup':journal.CACHE},
        {'name':'cache-replay','prepare':journal.LOOKUP,'lookup':journal.CACHE,'replay':True},
        {'name':'prepare-refusal','prepare':journal.REFUSE},
        {'name':'lookup-refusal','prepare':journal.LOOKUP,'lookup':journal.REFUSE},
        {'name':'alias','tool':'hia_resource_read','prepare':journal.ALIAS,'arguments':{'uri':'hia://fixture'}},
        {'name':'catalog-stale','tool':'hia_read','arguments':{'catalog_sha256':'different'}},
        {'name':'identity-stale','stale':True},
        {'name':'cost-negative-wall','now':500},
        {'name':'cost-bad-utf8','cost':b'\xff'},
    ]
    for tool in TOOLS[:11]:
        base.append({'name':'context-'+tool,'tool':tool,'arguments':{'catalog_sha256':'catalog','context':{'id':'cx'}}})
    for row in base:yield row
    sites=['monotonic#1','uuid#1','install#1','wire#1','data#1','wire#2','journal.prepare#1',
           'request_id#1','schema_input#1','identity#1','journal.effect#1','business.hia_describe#1',
           'schema_output#1','journal.finish#1','monotonic#2','sql.COST#1','sql.UPDATE#1']
    for site in sites:
        for kind in (1,6,11):
            yield {'name':'plain-'+site+'-'+str(kind),'faults':{site:kind}}
    reserve=['sql.BEGIN#1','key#1','sql.SELECT#1','fetchone#1','journal.lookup#1','key#2',
             'request_digest#1','realtime#1','sql.INSERT#1','journal.reserved#1','sql.COMMIT#1']
    for site in reserve:
        for kind in (1,6,9):
            yield {'name':'reserve-'+site+'-'+str(kind),'prepare':journal.LOOKUP,'row_none':True,'faults':{site:kind}}
    atomic=['sql.BEGIN#1','business.hia_describe#1','schema_output#1','wire#3','journal.inline#1',
            'key#1','sql.UPDATE#1','journal.committed_inline#1','sql.COMMIT#1']
    for site in atomic:
        for kind in (1,6,10):
            yield {'name':'atomic-'+site+'-'+str(kind),'atomic':True,'faults':{site:kind}}
    for first in (1,6,9):
        for rollback in (1,6,9):
            for atomic_mode in (False,True):
                primary='business.hia_describe#1' if atomic_mode else 'sql.INSERT#1'
                yield {'name':'rollback-'+str((first,rollback,atomic_mode)),
                       'prepare':journal.CONTINUE if atomic_mode else journal.LOOKUP,
                       'row_none':True,'atomic':atomic_mode,
                       'faults':{primary:first,'sql.ROLLBACK#1':rollback}}
    for site in ('journal.cached#1','replay#1','sql.COMMIT#1','journal.finish#1'):
        for kind in (1,6,11):
            yield {'name':'cache-'+site+'-'+str(kind),'prepare':journal.LOOKUP,'lookup':journal.CACHE,
                   'replay':True,'faults':{site:kind}}
    for kind in (1,6,11):
        yield {'name':'error-record-'+str(kind),'faults':{'schema_input#1':1,'error_record#1':kind}}
        yield {'name':'install-record-'+str(kind),'faults':{'install#1':1,'error_record#1':kind}}

image=None;status='FAIL';started=time.monotonic_ns();failure=None
try:
    image=Image()
    for case in cases():image.run(case)
    image.protocol();image.check()
    assert image.cases==184,image.cases
    status='PASS'
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
    if image is not None:
        try:image.check()
        except BaseException:status='FAIL';traceback.print_exc()
        image.ledger.close();image.caseledger.close()
        (OUT/'source-after.json').write_text(json.dumps(image.pinrows(),indent=2)+'\n')
        summary=dict(status=status,scope='ACTUAL_HIA_CALL_CONTROL_WITH_FOREIGN_FIXTURES',
                     cases=image.cases,entries=image.entries,whole_worker_closed=False,namespace_effects=0,
                     schema_peer_qualified=False,business_peer_qualified=False,fixture_peers_only=True,
                     source_unchanged=all(p.read_bytes()==b for p,b in image.pins.items()),
                     elapsed_ns=time.monotonic_ns()-started,failure=failure)
        (OUT/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
        print(json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
