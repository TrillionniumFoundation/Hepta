"""Full retained hia_read differential with actual HIA read/wire/SHA peers.

Namespace get/select/insert are explicitly controlled foreign fixtures.
This is not ordinary namespace or whole Worker qualification. All semantic
paging, UTF-8, base64, sums, result Graphs and hash bytes are computed natively.
"""
from __future__ import annotations
import ast,base64,copy,ctypes,json,math,random,resource,stat,struct,sys,time,traceback,zlib
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
WORK=Path(sys.argv[1]).resolve();COMPILE=Path(sys.argv[2]).resolve()
OUT=Path(sys.argv[3]).resolve();GROUP=sys.argv[4]
ROOT=WORK/'native-agent-read-next';REFERENCE=WORK/'Hepta-agent-edit-native'
sys.path[:0]=[str(ROOT/'tools'),str(REFERENCE)]
import agent_read_common as common
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta import hia_agent_service as service
from hepta import hia_agent_store as store
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
M=lambda b:int.from_bytes(b,'little')
pack=lambda *v:struct.pack('<'+'Q'*len(v),*v)
BAD=0xfffffffd;CANARY=bytes(range(64));C=common.CONSTANTS
ROLES={1:'agent_read_flow',2:'agent_read_values'}
OUT.mkdir(parents=True,exist_ok=False);(OUT/'cas').mkdir()
pins={};saved=set();images={};entries={role:0 for role in (*ROLES.values(),'scan','emit','sha256_stream')}
ledger=(OUT/'entries.jsonl').open('w');results=(OUT/'cases.jsonl').open('w')
capture=None;case_count=0;planned=0;status='FAIL';failure=None;binding=None
started=time.monotonic_ns()
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+'\n')
def cas(raw):
    raw=bytes(raw);identity=digest(raw)
    if identity not in saved:
        path=OUT/'cas'/(identity+'.zlib');path.write_bytes(zlib.compress(raw,1))
        assert zlib.decompress(path.read_bytes())==raw
        saved.add(identity)
    return dict(bytes=len(raw),sha256=identity)
def read(path):
    path=Path(path).resolve();raw=path.read_bytes()
    if path in pins:assert pins[path]==raw
    pins[path]=raw;return raw
def rows():
    return [dict(path=str(p),bytes=len(raw),sha256=digest(raw),mode=stat.S_IMODE(p.stat().st_mode))
            for p,raw in pins.items()]
def readback():assert all(p.is_file() and p.read_bytes()==raw for p,raw in pins.items())
def disabled(*a,**k):raise AssertionError('host read/wire/codec/hash owner used in native interval')
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
def invoke(role,s,r,w,label,advertised=None):
    n=w.n if advertised is None else advertised;assert 0<=n<=w.n
    sb,rb,wb=s.raw(),r.raw(),w.raw()
    save(OUT/'pending-native-entry.json',dict(role=role,label=label,role_entry=entries[role]+1,
        source_bytes=len(sb),second_bytes=len(rb),workspace_bytes=len(wb),advertised_work=n,
        source_sha256=digest(sb),second_sha256=digest(rb),workspace_before_sha256=digest(wb)))
    result=int(images[role]._entry(s.p,s.n,r.p,r.n,w.p,n));entries[role]+=1
    assert s.raw()==sb
    if role!='sha256_stream':assert r.raw()==rb
    for item in (s,r,w):item.guard()
    ledger.write(json.dumps(dict(label=label,role=role,status=result,source=cas(sb),
        second_before=cas(rb),second_after=cas(r.raw()),workspace_before=cas(wb),
        workspace_after=cas(w.raw()),advertised_work=n,input_and_canaries_unchanged=True),
        sort_keys=True)+'\n');ledger.flush()
    return result
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
        active.add(identifier);kind,at,size,first,count,identity,aux,z=struct.unpack_from('<8Q',raw,64+(identifier-1)*64)
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
        else:raise AssertionError(kind)
        memo[identifier]=answer;active.remove(identifier);return answer
    return value(rootid if root is None else root)
def graph_wire(raw,command,label):
    s=Buffer(len(raw),raw);r=Buffer(64,command);w=Buffer(32768);role='scan'
    while True:
        ret=invoke(role,s,r,w,label);assert ret==128,ret
        f=struct.unpack_from('<16Q',w.raw())
        assert f[0]==M(b'HIAGWE01')
        if f[1]==1:w=grow(w,f[10]);continue
        if f[1]==2:assert role=='scan' and f[13]==2;role='emit';continue
        assert f[1]==0,(label,f)
        assert f[11]<=w.n and f[12]<=w.n-f[11]
        return ret,w,f[11],f[12]
def native_sha(raw,label):
    o=Buffer(32);w=Buffer(1184)
    for data,expected in ((b'\0',0),(b'\1'+raw,0),(b'\2',32)):
        s=Buffer(len(data),data)
        actual=invoke('sha256_stream',s,o,w,label)
        assert actual==expected
    return actual,o,0,32
def configured(args):
    raw=capture(args,lease=53);s=Buffer(len(raw),raw);w=Buffer(8192)
    w.write(128,pack(M(b'HIARDC01'),37,83,53,1,113,sys.get_int_max_str_digits(),0,0,0,0,0,0,0,0,0))
    return dict(s=s,r=Buffer(0),w=w,role=1,seq=0,raw=raw,trace=[],wire_trace=[],
                errors={},artifact=None,frame=None,wire_calls=0)
def frame(context,ret):
    assert ret==2304,ret
    f=struct.unpack_from('<32Q',context['w'].raw(),2048)
    assert f[0]==M(b'HIARDE01') and f[2:4]==(37,83) and f[5]==53
    assert f[4]==context['seq']+1 and f[31]==0
    context['seq']=f[4];context['frame']=f;return f
def ack(context,f,view,lease,actual=0,at=0,n=None,error=False):
    if n is None:n=view.n-at
    assert 0<=at<=view.n and 0<=n<=view.n-at
    context['r']=view
    context['w'].write(256,pack(M(b'HIARDA01'),37,83,f[10],f[9],int(error),
        actual,lease,view.n,at,n,0,0,0,0,0))
def error_fixture(context,f,label):
    # The already-issued peer exception is opaque to the read owner.
    token=('issued-exception:'+label).encode()
    view=Buffer(len(token),token);lease=9000+len(context['errors'])
    context['errors'][lease]=label;ack(context,f,view,lease,error=True)
def service_peer(context,case,label):
    f=context['frame'];peer=f[9];s=context['s'];w=context['w'];r=context['r']
    assert f[1]==2 and f[10]==f[4]
    context['trace'].append((peer,f[16],f[11],f[12],f[13],f[14],f[15]))
    if peer==1:
        assert f[11]==1 and f[12]==0 and f[13]==s.n and f[15]==53 and f[16]==0
        if case.get('get_error'):
            error_fixture(context,f,'get');return
        data=case['data'];artifact=Buffer(len(data),data)
        context['artifact']=artifact;ack(context,f,artifact,501);return
    if peer==2:
        artifact=context['artifact'];assert artifact is not None
        assert f[11:17]==(4,0,artifact.n,0,501,0)
        ack(context,f,artifact,501);return
    assert f[12]<=w.n or f[11]==2
    if f[11]==3:
        assert f[13]<=w.n-f[12];source=w.raw()[f[12]:f[12]+f[13]]
    elif f[11]==2:
        assert f[12]<=r.n and f[13]<=r.n-f[12]
        source=r.raw()[f[12]:f[12]+f[13]]
    else:raise AssertionError(f)
    if peer==3:
        assert f[16]==binding['OP_CURSOR_SELECT'] and f[14]==1
        context.setdefault('select_graphs',[]).append(source)
        if case.get('select_error'):error_fixture(context,f,'select');return
        raw=case['row_graph'];ack(context,f,Buffer(len(raw),raw),601);return
    if peer==4:
        context['wire_calls']+=1
        assert f[16]==0 and f[29:31]==(2304,64)
        command=w.raw()[f[29]:f[29]+64]
        assert struct.unpack('<8Q',command)==(M(b'HIAGWC01'),113,f[4],1,8388608,2,sys.get_int_max_str_digits(),0)
        if case.get('wire_error')==context['wire_calls']:
            context['wire_trace'].append((source,None));error_fixture(context,f,'wire');return
        actual,view,at,n=graph_wire(source,command,label+'.wire-'+str(context['wire_calls']))
        context['wire_trace'].append((source,view.raw()[at:at+n]))
        ack(context,f,view,1000+context['wire_calls'],actual,at,n);return
    if peer==5:
        assert f[11]==2 and f[16]==0
        context.setdefault('hash_inputs',[]).append(source)
        actual,view,at,n=native_sha(source,label+'.sha')
        ack(context,f,view,5001,actual,at,n);return
    if peer==6:
        assert f[16]==binding['OP_CURSOR_INSERT'] and f[14]==1
        context.setdefault('insert_graphs',[]).append(source)
        if case.get('insert_error'):error_fixture(context,f,'insert');return
        ack(context,f,Buffer(0),701);return
    raise AssertionError(f)
def drive(args,case,label,stop_peer=None):
    context=configured(args)
    while True:
        ret=invoke(ROLES[context['role']],context['s'],context['r'],context['w'],label)
        if ret==BAD:return dict(private_bad=True),context
        f=frame(context,ret);action=f[1]
        if action==1:
            assert f[7]==context['role'];context['w']=grow(context['w'],f[8]);continue
        if action==4:
            assert f[7] in ROLES and f[7]!=context['role']
            context['role']=f[7];continue
        if action==2:
            if f[9]==stop_peer:return None,context
            service_peer(context,case,label);continue
        if action==0:
            assert f[17]<=context['w'].n and f[18]<=context['w'].n-f[17] and f[19]==113
            raw=context['w'].raw()[f[17]:f[17]+f[18]]
            return dict(result_graph=raw),context
        assert action==3
        if f[22]==3:
            assert f[21] in (1,2) and f[23]==37
            at,n=f[24:26];assert at<=context['w'].n and n<=context['w'].n-at
            text=context['w'].raw()[at:at+n].decode('utf-8')
            return dict(error_class={1:'AgentRejected',2:'TypeError'}[f[21]],error=text),context
        assert f[22]==2 and f[21]==0 and f[23] in context['errors']
        at,n=f[24:26];assert at<=context['r'].n and n<=context['r'].n-at
        assert context['r'].raw()[at:at+n]==('issued-exception:'+context['errors'][f[23]]).encode()
        return dict(peer_exception=context['errors'][f[23]]),context

class IssuedFailure(RuntimeError):
    pass
def oracle(args,case):
    events=[];wires=[];inserts=[];selects=[];gets=[];wire_count=0
    original_wire=store.wire
    def wire(value):
        nonlocal wire_count
        wire_count+=1;item=copy.deepcopy(value)
        if case.get('wire_error')==wire_count:
            wires.append((item,None));events.append('wire');raise IssuedFailure('wire')
        raw=original_wire(value);wires.append((item,raw));events.append('wire');return raw
    class Fetch:
        def fetchone(self):return case['row']
    class Database:
        def execute(self,sql,binds):
            if sql=='SELECT * FROM cursors WHERE id=?':
                events.append('select');selects.append(tuple(binds))
                if case.get('select_error'):raise IssuedFailure('select')
                return Fetch()
            assert sql=='INSERT OR IGNORE INTO cursors VALUES (?,?,?,?)',sql
            events.append('insert');inserts.append(tuple(binds))
            if case.get('insert_error'):raise IssuedFailure('insert')
            return None
    class Store:
        db=Database()
        def get(self,ref):
            events.append('get');gets.append(copy.deepcopy(ref))
            if case.get('get_error'):raise IssuedFailure('get')
            return case['data'],None
    owner=service.HIAAgentService.__new__(service.HIAAgentService);owner.store=Store()
    try:
        with patch.object(service,'wire',new=wire),patch.object(store,'wire',new=wire):
            value=owner._hia_read(args)
        result=dict(value=value)
    except IssuedFailure as exc:result=dict(peer_exception=str(exc))
    except Exception as exc:result=dict(error_class=type(exc).__name__,error=str(exc))
    return result,dict(events=events,wires=wires,inserts=inserts,selects=selects,gets=gets)
def check(label,data,offset='ABSENT',limit=65536,row_change=None,**fault):
    global case_count
    print(json.dumps(dict(event='READ_CASE_START',group=GROUP,label=label,ordinal=case_count+1)),flush=True)
    ref={'id':'artifact-A','sha256':digest(data),'uri':'hia://artifacts/artifact-A'}
    if fault.pop('reverse_ref',False):ref=dict(reversed(tuple(ref.items())))
    args={'catalog_sha256':'0'*64,'artifact':ref}
    if limit is not None:args['max_bytes']=limit
    row=None
    if offset!='ABSENT' or type(offset) is not str:
        args['cursor']='prior-cursor'
        row={'id':'prior-cursor','artifact_id':ref['id'],'sha256':ref['sha256'],'offset':offset}
    if row_change:
        if row_change=='missing':row=None
        else:row.update(row_change)
    case=dict(data=data,row=row,**fault)
    row_value=None if row is None else tuple(row[k] for k in ('id','artifact_id','sha256','offset'))
    case['row_graph']=capture(row_value,lease=601)
    expected,expected_trace=oracle(args,case)
    before=dict(entries)
    with ExitStack() as stack:
        for target in ('hepta.hia_agent_service.HIAAgentService._hia_read',
            'hepta.hia_agent_service.wire','hepta.hia_agent_store.wire',
            'hepta.hia_agent_service.digest','hepta.hia_agent_store.decode_data',
            'hepta.hia_program_tools.bounded_json_wire','base64.b64encode','json.loads'):
            stack.enter_context(patch(target,new=disabled))
        result,context=drive(args,case,label)
    if 'result_graph' in result:actual=dict(value=decode_graph(result['result_graph']))
    else:actual=result
    actual_wires=[(decode_graph(g),raw) for g,raw in context['wire_trace']]
    actual_selects=[tuple(decode_graph(g)) for g in context.get('select_graphs',[])]
    actual_inserts=[tuple(decode_graph(g)) for g in context.get('insert_graphs',[])]
    kinds={1:'get',3:'select',4:'wire',6:'insert'}
    actual_events=[kinds[t[0]] for t in context['trace'] if t[0] in kinds]
    assert actual==expected,(label,expected,actual)
    assert actual_wires==expected_trace['wires'],(label,'all three wire calls/order/payloads')
    assert actual_selects==expected_trace['selects'] and actual_inserts==expected_trace['inserts']
    assert actual_events==expected_trace['events'],(label,actual_events,expected_trace['events'])
    assert decode_graph(context['raw'],context['trace'][0][5])==ref
    if context.get('hash_inputs'):
        # digest() uses the final actual wire call, not a separately serialized plan.
        assert len(context['hash_inputs'])==1 and context['hash_inputs'][0]==actual_wires[-1][1]
    row=dict(case=case_count+1,label=label,status='PASS',
        artifact=cas(data),args=cas(context['raw']),row_graph=cas(case['row_graph']),
        expected=cas(json.dumps(expected,sort_keys=True,ensure_ascii=True).encode()),
        actual=cas(json.dumps(actual,sort_keys=True,ensure_ascii=True).encode()),
        result_graph=cas(result['result_graph']) if 'result_graph' in result else None,
        wire_inputs=[cas(g) for g,_ in context['wire_trace']],
        wire_outputs=[cas(raw) if raw is not None else None for _,raw in context['wire_trace']],
        select_binds=[cas(g) for g in context.get('select_graphs',[])],
        insert_binds=[cas(g) for g in context.get('insert_graphs',[])],
        hash_inputs=[cas(raw) for raw in context.get('hash_inputs',[])],
        operation_order=actual_events,all_values_errors_wire_calls_and_sql_binds_equal=True,
        namespace_fixture=True,entries={k:entries[k]-before[k] for k in entries})
    results.write(json.dumps(row,sort_keys=True)+'\n');results.flush();case_count+=1
    print(json.dumps(dict(event='READ_CASE_PASS',group=GROUP,label=label,ordinal=case_count)),flush=True)

def semantic_cases():
    for n in (0,1,2,3,4,511,512,513,1024,2048,65535,65536,65537):
        yield ('ascii-'+str(n),b'a'*n)
        yield ('binary-'+str(n),(b'\xff\x00\xfe'*((n+2)//3))[:n])
    for value in (512,513,1023,1024,65535,65536,512.0,65536.0,None):
        yield ('limit-'+str(value),b'z'*70000,'ABSENT',value)
    for n in (0,1,2,3,511,512,513,65536):
        for offset in (0,1,-1,-2,n,n+1,-n,-n-1,2**63-1,-2**63):
            yield ('offset-'+str(n)+'-'+str(offset),b'x'*n,offset,512)
def unicode_cases():
    for char in ('é','中','😀','\u0080','\u07ff','\u0800','\U0010ffff'):
        raw=(char*600).encode()
        for offset in range(-5,6):
            yield ('split-'+str(ord(char))+'-'+str(offset),raw,offset,512)
    for n in range(16):
        yield ('tail-'+str(n),b'a'*(510+n)+'😀'.encode(),0,512)
    for bad in (b'\xc0\x80',b'\xed\xa0\x80',b'\xf4\x90\x80\x80',b'\x80',b'\xe2\x82',b'\xff'):
        yield ('binary-outside-'+bad.hex(),b'a'*1000+bad,0,512)
        yield ('binary-start-'+bad.hex(),bad+b'a'*1000,0,512)
    yield ('reverse-artifact-key-order','中'.encode()*10000,'ABSENT',65536,None,dict(reverse_ref=True))
def storage_cases():
    for offset in (None,1.0,-0.0,float('inf'),float('nan'),'0','中',b'0',b'\xff'):
        yield ('storage-'+type(offset).__name__+'-'+str(offset),b'abc',offset,512)
    for field in ('artifact_id','sha256'):
        for value in (None,0,1.0,b'artifact-A','different'):
            yield ('identity-'+field+'-'+type(value).__name__,b'abc',0,512,{field:value})
    yield ('missing-cursor',b'abc',0,512,'missing')
def wire_cases():
    for value in range(32):
        yield ('control-'+str(value),bytes([value])*65536)
    for raw in (b'"',b'\\',b'"\x00\\',b'\xe2\x80\xa8'):
        yield ('escape-'+raw.hex(),(raw*65536)[:70000])
    for point in range(1,11):
        yield ('wire-admission-failure-'+str(point),b'\0'*65536,'ABSENT',65536,None,dict(wire_error=point))
    for field in ('get_error','select_error','insert_error'):
        yield (field,b'z'*1000,0,512,None,{field:True})
def large_cases():
    yield ('complete-sixty-four-mib-valid-utf8',b'a'*(64<<20),0,65536)
    yield ('complete-sixty-four-mib-bad-byte-outside-page',b'a'*((64<<20)-1)+b'\xff',0,65536)

def protocols():
    global planned,case_count
    args={'catalog_sha256':'0'*64,'artifact':{'id':'a','sha256':'0'*64,'uri':'hia://artifacts/a'}}
    case=dict(data=b'abc',row=None,row_graph=capture(None,lease=601))
    controls=[]
    def refusal(context,label):
        assert invoke(ROLES[context['role']],context['s'],context['r'],context['w'],label)==BAD
        assert invoke(ROLES[context['role']],context['s'],context['r'],context['w'],label+'.again')==BAD
    def bad_config(index,value):
        c=configured(args);c['w'].write(128+index*8,pack(value));refusal(c,'config-'+str(index))
    for index,value in ((0,0),(1,0),(2,0),(3,0),(4,0),(5,0),(6,1),(7,1),(15,1)):
        controls.append(('config-'+str(index),lambda i=index,v=value:bad_config(i,v)))
    def wrong_first_role():
        c=configured(args);c['role']=2;refusal(c,'wrong-first-role')
    controls.append(('wrong-first-role',wrong_first_role))
    def bad_ack(index,value):
        _,c=drive(args,case,'ack-start',stop_peer=1);service_peer(c,case,'actual-fixture-get')
        c['w'].write(256+index*8,pack(value));refusal(c,'ack-'+str(index))
    for index,value in ((0,0),(1,38),(2,84),(3,0),(4,2),(5,2),(7,0),(8,4),(9,4),(10,4),(11,1),(15,1)):
        controls.append(('ack-'+str(index),lambda i=index,v=value:bad_ack(i,v)))
    def bad_source(index,value):
        c=configured(args);f=frame(c,invoke('agent_read_flow',c['s'],c['r'],c['w'],'source-start'))
        assert f[1]==2
        service_peer(c,case,'source-actual-fixture')
        c['s'].write(index*8,pack(value));refusal(c,'source-'+str(index))
    for index,value in ((0,0),(1,54),(2,0),(3,0),(6,0),(7,1)):
        controls.append(('source-'+str(index),lambda i=index,v=value:bad_source(i,v)))
    def forged_wire(index,value):
        _,c=drive(args,case,'wire-start',stop_peer=4);service_peer(c,case,'actual-wire')
        c['r'].write(index*8,pack(value));refusal(c,'wire-'+str(index))
    for index,value in ((0,0),(1,1),(2,114),(3,0),(4,2),(5,1),(6,3),(7,640),
                        (8,1),(9,1),(11,0),(12,0),(13,1),(15,1)):
        controls.append(('wire-'+str(index),lambda i=index,v=value:forged_wire(i,v)))
    def poison_unknown_phase():
        c=configured(args);frame(c,invoke('agent_read_flow',c['s'],c['r'],c['w'],'phase-start'))
        service_peer(c,case,'phase-actual-fixture')
        c['w'].write(C['R_PHASE'],pack(999));refusal(c,'unknown-phase')
    controls.append(('unknown-phase',poison_unknown_phase))
    def overflow():
        c=configured(args);frame(c,invoke('agent_read_flow',c['s'],c['r'],c['w'],'overflow-start'))
        service_peer(c,case,'overflow-actual-fixture')
        c['w'].write(C['R_SEQ'],pack((1<<64)-1));refusal(c,'sequence-overflow')
    controls.append(('sequence-overflow',overflow))
    def terminal():
        result,c=drive(args,case,'terminal-valid')
        assert 'result_graph' in result;refusal(c,'terminal-reuse')
    controls.append(('terminal-reuse',terminal))
    def short_workspace():
        c=configured(args);before=c['w'].raw()
        assert invoke('agent_read_flow',c['s'],c['r'],c['w'],'short-advertised-workspace',8191)==BAD
        assert c['w'].raw()==before
        # The fixed owner must retire this lease here. No persistent poison is
        # claimed for a workspace that cannot safely hold the state.
    controls.append(('short-workspace-retired',short_workspace))
    planned=len(controls)
    for label,body in controls:
        before=dict(entries);body()
        results.write(json.dumps(dict(case=case_count+1,label=label,status='PASS',
            private_protocol=True,entries={k:entries[k]-before[k] for k in entries}),sort_keys=True)+'\n')
        results.flush();case_count+=1

try:
    read(__file__)
    for p in sorted((ROOT/'tools').glob('*.py')):read(p)
    for name in ('hepta/hia_agent_service.py','hepta/hia_agent_store.py',
                 'hepta/hia_program_tools.py','hepta/hia_json_preflight_native.py'):
        read(REFERENCE/name)
    raw=read(ROOT/'tools/graph_harness_frozen_original.py')
    assert (len(raw),digest(raw))==(9783,'75fe54554a93e19e30251073ac225deff944d6673d87ccc2b597e47a19e8be7c')
    tree=ast.parse(raw);node=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='capture')
    namespace={'struct':struct,'GRAPH':M(b'HIAGRF01')}
    exec(compile(ast.Module(body=[node],type_ignores=[]),'<exact-frozen-private-capture>','exec'),namespace)
    capture=namespace['capture']
    bundle=json.loads(read(COMPILE/'bundle.json'))
    assert bundle['schema']=='hia-agent-read-development-bundle-v1' and bundle['status']=='PASS'
    assert set(bundle['components'])==set(entries)
    binding={row['symbol']:row['operation_id'] for row in bundle['namespace_binding']['operations']}
    assert set(binding)=={'OP_CURSOR_SELECT','OP_CURSOR_INSERT'} and len(set(binding.values()))==2
    # Bind each manifest role to the actual current source, not merely to a
    # source/image pair chosen by the same mutable manifest. Freeze the bytes
    # used for mapping and read back every pin before the first executable map.
    expected_sources={
        'agent_read_flow':ROOT/'examples/hia_bootstrap/agent_read_flow.hiaasm',
        'agent_read_values':ROOT/'examples/hia_bootstrap/agent_read_values.hiaasm',
        'scan':WORK/'native-agent-edit-render-next/examples/hia_bootstrap/graph_json_wire_scan.hiaasm',
        'emit':WORK/'native-agent-edit-render-next/examples/hia_bootstrap/graph_json_wire_emit.hiaasm',
        'sha256_stream':REFERENCE/'examples/hia_bootstrap/sha256_stream.hiaasm'}
    fixed_sources={
        'scan':(147822,'c1cb49c1df3c4c653dfd37beebba12b3baf57a28a7d77c257157d2cc7e58cde3'),
        'emit':(173680,'9ad72bddb7eaa3d9118155a056e4c5faa7ff3e015e45fbc2d09dae14e2cfb7a2'),
        'sha256_stream':(30784,'7fdc436867514b3d1dd741e3c3d86c0b95cc19d5b69907d5df9febf29639cb68')}
    compiler=read(WORK/'dependencies/f50-B3.image.bin')
    assert (len(compiler),digest(compiler))==(668608,
        '0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8')
    generation=json.loads(read(COMPILE/'summary.json'))
    assert generation['status']=='PASS' and generation['actual_compiles']==5
    assert generation['bundle']==bundle and generation['source_unchanged'] is True
    frozen={}
    for role,row in bundle['components'].items():
        current=expected_sources[role].resolve()
        assert Path(row['source_path']).resolve()==current,(role,'source role mismatch')
        source=read(current);image=read(row['image_path']);receipt=json.loads(read(row['receipt_path']))
        if role in fixed_sources:assert (len(source),digest(source))==fixed_sources[role]
        assert Path(row['image_path']).resolve().parent==COMPILE
        assert Path(row['receipt_path']).resolve()==COMPILE/(role+'.receipt.json')
        issued_manifest=json.loads(read(COMPILE/(role+'.manifest.json')))
        assert issued_manifest==row,(role,'manifest and bundle differ')
        assert (len(source),digest(source))==(row['source_bytes'],row['source_sha256'])
        assert (len(image),digest(image))==(row['image_bytes'],row['image_sha256'])
        assert row['role']==role and row['compiler_sha256']=='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
        assert receipt['input_sha256']==digest(source) and receipt['produced_sha256']==digest(image)
        assert receipt['image_sha256']==row['compiler_sha256']
        frozen[role]=(image,digest(image))
    readback();save(OUT/'source-before.json',rows())
    images={role:NativeHiaJsonImage(*value) for role,value in frozen.items()}
    if GROUP=='protocol':protocols()
    else:
        factories={'semantic':semantic_cases,'unicode':unicode_cases,'storage':storage_cases,
                   'wire':wire_cases,'large':large_cases}
        items=list(factories[GROUP]());planned=len(items)
        for item in items:
            args=list(item);extra={}
            if len(args)==6:extra=args.pop()
            check(*args,**extra)
    assert case_count==planned,(case_count,planned);status='PASS'
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
    ledger.close();results.close()
    unchanged=all(p.is_file() and p.read_bytes()==raw for p,raw in pins.items())
    if not unchanged:status='FAIL'
    summary=dict(status=status,scope='COMPLETE_HIA_READ_ACTUAL_COMPUTATION_WITH_FOREIGN_NAMESPACE_FIXTURES',
        group=GROUP,cases=case_count,planned_cases=planned,entries=entries,
        total_actual_entries=sum(entries.values()),failure=failure,source_unchanged=unchanged,
        compressed_cas_objects=len(saved),elapsed_ns=time.monotonic_ns()-started,
        original_limits=dict(cpu_seconds=90,address_space_bytes=1<<30),
        real_graph_wire_and_sha=True,namespace_get_select_insert_are_foreign_fixtures=True,
        ordinary_namespace_closed=False,whole_worker_closed=False,production_activation=False,
        host_read_wire_codec_materializer_disabled_in_native_execution=True)
    save(OUT/'source-after.json',rows());save(OUT/'summary.json',summary)
    print(json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
