"""Fresh actual issued arena -> DataGraph -> existing Graph-wire evidence.

The Python code below is an explicitly mechanical development executor and
independent oracle. It is not a native Worker, public raw decode-data prefix,
or a replacement for the future fixed coordinator and its issued leases.
"""
from __future__ import annotations
import ctypes,json,math,os,random,resource,stat,struct,sys,time,traceback,zlib
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
WORK=Path(sys.argv[1]).resolve();COMPILE=Path(sys.argv[2]).resolve();OUT=Path(sys.argv[3]).resolve()
GROUP=sys.argv[4]
REFERENCE=WORK/'Hepta-agent-edit-native'
sys.path.insert(0,str(REFERENCE))
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta.hia_json_decode_native import arena_sizes,materialize
from hepta.hia_agent_data_json_native import materialize_data
from hepta.hia_agent_store import AgentRejected
from hepta.hia_program_tools import bounded_json_wire
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
M=lambda x:int.from_bytes(x,'little')
pack=lambda *x:struct.pack('<'+'Q'*len(x),*x)
BAD=0xfffffffd;MAX=(1<<64)-1;CANARY=bytes(range(64))
FBASE=2048;FEND=2240
OUT.mkdir(parents=True,exist_ok=False);(OUT/'cas').mkdir()
saved=set();pins={};entries={k:0 for k in ('decoder','data_graph','binary64','scan','emit')}
ledger=(OUT/'entries.jsonl').open('w');results=(OUT/'cases.jsonl').open('w')
cases=0;planned=0;status='FAIL';failure=None;images={}
start=time.monotonic_ns()
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True,ensure_ascii=True)+'\n')
def cas(raw):
    h=digest(raw)
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
def readback():
    assert all(p.is_file() and p.read_bytes()==raw for p,raw in pins.items())
def disabled(*a,**kw):raise AssertionError('hosted semantic owner entered native interval')
class Buffer:
    def __init__(self,n,raw=b''):
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
        assert 0<=at<=self.n and len(raw)<=self.n-at
        if raw:ctypes.memmove(self.p+at,raw,len(raw))
    def guard(self):
        assert ctypes.string_at(self.base,64)==CANARY
        assert ctypes.string_at(self.p+self.n,64)==CANARY
def invoke(role,s,r,w,label,*,source_at=0,source_size=None,advertised_work=None):
    source_size=s.n-source_at if source_size is None else source_size
    advertised_work=w.n if advertised_work is None else advertised_work
    assert 0<=source_at<=s.n and 0<=source_size<=s.n-source_at and 0<=advertised_work<=w.n
    sb=s.raw();rb=r.raw();wb=w.raw()
    with ExitStack() as stack:
        for target in ('hepta.hia_agent_data_json_native.materialize_data',
                       'hepta.hia_json_decode_native.materialize','hepta.hia_agent_store.decode_data',
                       'hepta.hia_agent_data_json_native.finite_float',
                       'hepta.hia_program_tools.bounded_json_wire','json.loads'):
            stack.enter_context(patch(target,new=disabled))
        value=int(images[role]._entry(s.p+source_at,source_size,r.p,r.n,w.p,advertised_work))
    entries[role]+=1
    assert s.raw()==sb
    if role in ('data_graph','scan','emit'):assert r.raw()==rb
    for b in (s,r,w):b.guard()
    row=dict(label=label,role=role,status=value,source=cas(sb),source_at=source_at,source_bytes=source_size,
        second_before=cas(rb),second_after=cas(r.raw()),workspace_before=cas(wb),
        workspace_after=cas(w.raw()),workspace_advertised=advertised_work,input_and_canaries_unchanged=True)
    ledger.write(json.dumps(row,sort_keys=True)+'\n');ledger.flush()
    return value
def arena(wire,label):
    output_size,workspace_size=arena_sizes(len(wire),262144,128)
    s=Buffer(len(wire),wire);o=Buffer(output_size);w=Buffer(workspace_size)
    w.write(48,pack(262144,128))
    ret=invoke('decoder',s,o,w,label+'.raw')
    if not 64<=ret<=o.n:return None,ret
    return o.raw()[:ret],ret
def configured(arena_raw,wire,digits=4300,lease=31):
    s=Buffer(len(arena_raw),arena_raw);r=Buffer(len(wire),wire);w=Buffer(4096)
    w.write(128,pack(M(b'HIADGC01'),lease,73,91,92,93,digits,len(arena_raw),len(wire),0,0,0,0,0,0,0))
    return s,r,w
def frame(w,ret):
    assert ret==FEND,ret
    f=struct.unpack_from('<24Q',w.raw(),FBASE)
    assert f[0]==M(b'HIADGE01') and f[2:4]==(31,73) and f[5:8]==(93,91,92)
    assert f[22:]==(0,0)
    return f
def grow(w,needed):
    assert needed>w.n
    return Buffer(needed,w.raw())
def drive(arena_raw,wire,digits,label):
    s,r,w=configured(arena_raw,wire,digits)
    float_lexemes=[];grows=[]
    while True:
        ret=invoke('data_graph',s,r,w,label)
        if ret==BAD:return dict(private_bad=True,phase=struct.unpack_from('<Q',w.raw(),520)[0]),float_lexemes,grows,w
        f=frame(w,ret)
        if f[1]==1:
            grows.append((w.n,f[8]));w=grow(w,f[8]);continue
        if f[1]==2:
            at,n=f[11:13]
            assert at<=r.n and 0<n<=r.n-at
            float_lexemes.append(wire[at:at+n])
            bits=Buffer(8);bw=Buffer(4096)
            actual=invoke('binary64',r,bits,bw,label+'.binary64',source_at=at,source_size=n)
            extent=8 if actual==8 else 0
            w.write(256,pack(M(b'HIADGR01'),31,73,f[4],actual,extent,f[13],0))
            w.write(320,bits.raw())
            continue
        if f[1]==3:
            at,n=f[15:17];assert 0<n<=4096 and at<=w.n and n<=w.n-at
            text=w.raw()[at:at+n].decode('utf-8')
            classes={1:('ValueError',None),2:('AgentRejected','E_HIA_JSON'),3:('AgentRejected','E_HIA_JSON'),4:('RuntimeError',None)}
            cls,code=classes[f[14]]
            return dict(error_class=cls,error=text,code=code),float_lexemes,grows,w
        assert f[1]==0 and f[14]==0 and f[17]==digits
        at,n=f[9:11];assert at<=w.n and n<=w.n-at
        graph=w.raw()[at:at+n]
        return dict(graph=graph),float_lexemes,grows,w
def clean(value):
    if value is None or type(value) is bool:return value
    if type(value) is int:
        n=abs(value);return dict(integer_le=n.to_bytes((n.bit_length()+7)//8,'little').hex(),negative=value<0)
    if type(value) is float:return dict(binary64=struct.pack('<d',value).hex())
    if type(value) is str:return value
    if type(value) is list:return [clean(x) for x in value]
    assert type(value) is dict
    return dict(ordered_items=[[k,clean(v)] for k,v in value.items()])
def graph_value(raw):
    magic,lease,n,root,e,pool,total,reserved=struct.unpack_from('<8Q',raw)
    assert (magic,lease,total,reserved)==(M(b'HIAGRF01'),93,len(raw),0) and 1<=root<=n
    edgebase=64+n*64;database=edgebase+e*8;assert database+pool==len(raw)
    def row(identifier):
        assert 1<=identifier<=n
        return struct.unpack_from('<8Q',raw,64+(identifier-1)*64)
    for identifier in range(1,n+1):
        kind,at,size,first,count,identity,aux,res=row(identifier)
        assert res==0
        if kind in (2,3,4):
            assert database<=at<=len(raw) and size<=len(raw)-at and first==count==identity==0
        if kind==0:assert (at,size,first,count,identity,aux)==(0,0,0,0,0,0)
        elif kind==1:assert (at,size,first,count,identity)==(0,0,0,0,0) and aux in (0,1)
        elif kind==2:
            assert aux in (0,1) and (size!=0 or aux==0)
            assert size==0 or raw[at+size-1]!=0
        elif kind==3:assert size==8 and aux==0
        elif kind==4:assert len(raw[at:at+size].decode('utf-8'))==aux
        elif kind in (5,6):
            assert at==size==aux==0 and identity!=0 and first<=e and count*(2 if kind==6 else 1)<=e-first
        else:raise AssertionError(kind)
    active=set()
    def value(identifier):
        assert identifier not in active
        active.add(identifier)
        kind,at,size,first,count,identity,aux,res=row(identifier)
        if kind==0:result=None
        elif kind==1:result=bool(aux)
        elif kind==2:
            result=int.from_bytes(raw[at:at+size],'little')
            if aux:result=-result
        elif kind==3:result=struct.unpack_from('<d',raw,at)[0]
        elif kind==4:result=raw[at:at+size].decode('utf-8')
        else:
            ids=struct.unpack_from('<'+'Q'*(count*(2 if kind==6 else 1)),raw,edgebase+first*8)
            if kind==5:result=[value(x) for x in ids]
            else:
                result={}
                for i in range(0,len(ids),2):
                    key=value(ids[i]);assert type(key) is str and key not in result
                    result[key]=value(ids[i+1])
        active.remove(identifier);return result
    return value(root)
def wire_graph(graph,digits,label):
    s=Buffer(len(graph),graph);r=Buffer(64,pack(M(b'HIAGWC01'),93,1,1,8388608,2,digits,0));w=Buffer(32768)
    role='scan'
    while True:
        ret=invoke(role,s,r,w,label+'.wire')
        assert ret==128
        f=struct.unpack_from('<16Q',w.raw())
        assert f[0]==M(b'HIAGWE01') and f[2:8]==(93,1,1,8388608,2,digits)
        if f[1]==1:w=grow(w,f[10]);continue
        if f[1]==2:assert role=='scan';role='emit';continue
        if f[1]==3:return dict(error=f[8],cause=f[9])
        assert f[1]==0 and role=='emit' and f[11]<=w.n and f[12]<=w.n-f[11]
        return dict(wire=w.raw()[f[11]:f[11]+f[12]])
def expected(arena_raw,wire):
    calls=[]
    def floating(text):
        calls.append(text.encode('ascii'));value=float(text)
        if not math.isfinite(value):raise AgentRejected('E_HIA_JSON','nonfinite JSON number')
        return value
    try:return dict(value=materialize_data(arena_raw,wire,parse_float=floating)),calls
    except Exception as exc:return dict(error_class=type(exc).__name__,error=str(exc),code=getattr(exc,'code',None)),calls
def outcome_record(value):
    if 'value' in value:
        raw=json.dumps(clean(value['value']),ensure_ascii=True,separators=(',',':')).encode()
        return dict(value=cas(raw))
    return value
def semantic(label,wire,digits=4300,do_wire=False):
    global cases
    before=sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(digits)
        arena_raw,ret=arena(wire,label)
        assert arena_raw is not None,(label,ret)
        oracle,oracle_calls=expected(arena_raw,wire)
        actual,calls,grows,w=drive(arena_raw,wire,digits,label)
        assert calls==oracle_calls,(label,'callback order',calls,oracle_calls)
        if 'value' in oracle:
            assert 'graph' in actual,(label,actual)
            got=graph_value(actual['graph'])
            assert clean(got)==clean(oracle['value']),label
            wire_result=None
            if do_wire:
                reference=bounded_json_wire(oracle['value'],8388608,ensure_ascii=False,sort_keys=True)
                wire_result=wire_graph(actual['graph'],digits,label)
                assert wire_result.get('wire')==reference,(label,wire_result)
            observed=dict(value=got)
        else:
            assert actual==oracle,(label,oracle,actual)
            wire_result=None;observed=actual
        # The component is terminal after success or a semantic refusal.
        old=w.raw();s=Buffer(len(arena_raw),arena_raw);r=Buffer(len(wire),wire)
        assert invoke('data_graph',s,r,w,label+'.terminal-replay')==BAD and w.raw()==old
        row=dict(case=label,status='PASS',digits=digits,input=cas(wire),arena=cas(arena_raw),
            expected=outcome_record(oracle),actual=outcome_record(observed),float_lexemes=[cas(x) for x in calls],
            grows=grows,graph=cas(actual['graph']) if 'graph' in actual else None,
            actual_wire=cas(wire_result['wire']) if wire_result and 'wire' in wire_result else None)
        results.write(json.dumps(row,sort_keys=True)+'\n');results.flush();cases+=1
    finally:sys.set_int_max_str_digits(before)
def semantic_cases():
    rows=[]
    for text in ('null','false','true','0','-0','1','-1','4294967295','4294967296','4294967297',
                 '18446744073709551615','18446744073709551616','18446744073709551617',
                 '123456789012345678901234567890123456789','-9999999999999999999999999999999',
                 '0.0','-0.0','1.0','1e0','1e-324','5e-324','2.2250738585072014e-308',
                 '1.7976931348623157e308','1.7976931348623159e308','-1e99999','1e-99999',
                 '9007199254740993.0','2.4703282292062327e-324','2.4703282292062328e-324',
                 '[]','{}','""','"hello"','"\\u0000é😀"','{"z":[0,-0.0,true,null],"a":{"é":"😀"}}'):
        rows.append(('literal-'+str(len(rows)),text.encode('utf-8'),4300,True))
    rng=random.Random(20261111)
    for i in range(48):
        bits=rng.getrandbits(64)
        if ((bits>>52)&2047)==2047:bits^=1<<52
        value=struct.unpack('<d',struct.pack('<Q',bits))[0]
        rows.append(('finite-bits-'+str(i),repr(value).encode(),4300,True))
    for n in (1,2,8,9,10,17,18,19,100,639,640,641,4299,4300,4301,10000):
        limit=0 if n==10000 else 4300
        rows.append(('digits-'+str(n),b'9'*n,limit,n<=4300))
        rows.append(('negative-digits-'+str(n),b'-'+b'9'*n,limit,n<=4300))
    rows.extend([
        ('int-error-before-float',b'['+b'9'*4301+b',1e9999]',4300,False),
        ('float-error-before-int',b'[1e9999,'+b'9'*4301+b']',4300,False),
        ('source-order-nested',b'{"z":[1.25,{"x":-0.0}],"a":[3e-9,2]}',4300,True),
        ('nested-int-before-parent',b'{"key":{"nested":'+b'9'*641+b'}}',640,False),
        ('nested-float-before-parent',b'{"key":{"nested":1e9999}}',4300,False),
        ('max-depth',b'['*128+b'0'+b']'*128,4300,False),
    ])
    return rows
def protocol_case(label,arena_raw,wire,mutate,*,pending=False,advertised=None):
    global cases
    s,r,w=configured(arena_raw,wire)
    if pending:
        while True:
            ret=invoke('data_graph',s,r,w,label+'.prefix');f=frame(w,ret)
            if f[1]==1:w=grow(w,f[8]);continue
            assert f[1]==2
            # These are deliberately controlled private frames, not provenance evidence.
            w.write(256,pack(M(b'HIADGR01'),31,73,f[4],8,8,f[13],0));w.write(320,struct.pack('<d',1.25))
            break
    s,r,w=mutate(s,r,w)
    ret=invoke('data_graph',s,r,w,label,advertised_work=advertised)
    while ret==FEND and advertised is None:
        event=frame(w,ret)
        assert event[1]==1,(label,event)
        w=grow(w,event[8])
        ret=invoke('data_graph',s,r,w,label+'.after-grow')
    assert ret==BAD,(label,ret)
    if advertised is None:
        old=w.raw();assert invoke('data_graph',s,r,w,label+'.poison')==BAD and w.raw()==old
    results.write(json.dumps(dict(case=label,status='PASS',private_control=True,
        short_workspace_no_poison_claim=advertised is not None),sort_keys=True)+'\n');results.flush();cases+=1
def protocols():
    global planned,cases
    raw,ret=arena(b'1.25','protocol-arena');assert raw is not None
    controls=[]
    for offset,value in ((128,0),(136,0),(144,0),(152,0),(160,0),(168,0),(184,len(raw)+1),(192,5),(200,1),(512,1)):
        def change(s,r,w,offset=offset,value=value):w.write(offset,pack(value));return s,r,w
        controls.append(('initial-'+str(offset),change,False,None))
    for offset,value in ((256,0),(264,32),(272,74),(280,0),(288,1<<32),(296,7),(304,2),(312,1)):
        def change(s,r,w,offset=offset,value=value):w.write(offset,pack(value));return s,r,w
        controls.append(('reply-'+str(offset),change,True,None))
    def badbits(s,r,w):w.write(320,pack(0x7ff0000000000000));return s,r,w
    controls.append(('reply-nonfinite-success',badbits,True,None))
    def configshift(s,r,w):w.write(176,pack(0));return s,r,w
    controls.append(('pending-config-changed',configshift,True,None))
    controls.append(('short-workspace',lambda s,r,w:(s,r,w),False,4095))
    planned=len(controls)+7
    for label,change,pending,advertised in controls:
        protocol_case(label,raw,b'1.25',change,pending=pending,advertised=advertised)
    # Fully validated structure must precede actual numeric materialization.
    raw2,ret=arena(b'[1e9999,0]','structure-arena');assert raw2 is not None
    for label,offset,value in (
        ('wrong-parent',64+2*56+8,2),('wrong-sibling',64+56+16,1),
        ('wrong-root-parent',72,0),('unknown-kind',64+2*56,8),
        ('invalid-late-numeric-span',64+2*56+24,MAX),
        ('fractional-tag-mismatch',64+56,3)):
        changed=bytearray(raw2);struct.pack_into('<Q',changed,offset,value)
        protocol_case(label,bytes(changed),b'[1e9999,0]',lambda s,r,w:(s,r,w))
    # Repeat an insufficient GROW without calling the binary owner.
    s,r,w=configured(raw,b'1.25');first=invoke('data_graph',s,r,w,'grow-repeat.1');f=frame(w,first)
    assert f[1]==1
    second=invoke('data_graph',s,r,w,'grow-repeat.2');g=frame(w,second)
    assert g[1]==1 and g[8]==f[8] and g[4]==f[4]+1
    results.write(json.dumps(dict(case='grow-repeat',status='PASS',same_need=True,producer_not_replayed=True))+'\n');results.flush();cases+=1
def large_cases():
    return [
        ('maximum-node-arena',b'['+b'0,'*262142+b'0]',4300,False),
        ('maximum-byte-string',b'"'+b'x'*(8388608-2)+b'"',4300,False),
        ('unlimited-100000-digit-value',b'9'*100000,0,False),
    ]
try:
    read(Path(__file__))
    bundle=json.loads(read(COMPILE/'bundle.json'))
    assert bundle['schema']=='hia-agent-data-graph-development-bundle-v1' and bundle['status']=='PASS'
    assert set(bundle['components'])==set(entries)
    frozen={}
    for role,row in bundle['components'].items():
        assert row['role']==role and row['compiler_sha256']=='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
        sr=read(row['source_path']);im=read(row['image_path']);receipt=json.loads(read(row['receipt_path']))
        assert (len(sr),digest(sr))==(row['source_bytes'],row['source_sha256'])
        assert (len(im),digest(im))==(row['image_bytes'],row['image_sha256'])
        assert receipt['input_sha256']==digest(sr) and receipt['produced_sha256']==digest(im)
        frozen[role]=(im,digest(im))
    readback();save(OUT/'source-before.json',pinrows())
    images={role:NativeHiaJsonImage(*row) for role,row in frozen.items()}
    if GROUP=='semantic':
        values=semantic_cases();planned=len(values)
        for values_row in values:semantic(*values_row)
    elif GROUP=='protocol':protocols()
    elif GROUP=='large':
        values=large_cases();planned=len(values)
        for values_row in values:semantic(*values_row)
    else:raise AssertionError(GROUP)
    assert cases==planned,(cases,planned)
    status='PASS'
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc))
    traceback.print_exc()
finally:
    ledger.close();results.close()
    unchanged=all(p.is_file() and p.read_bytes()==raw for p,raw in pins.items())
    if not unchanged:status='FAIL'
    summary=dict(status=status,group=GROUP,cases=cases,planned_cases=planned,entries=entries,
        total_actual_entries=sum(entries.values()),failure=failure,source_unchanged=unchanged,
        compiler_qualification=False,whole_worker_closed=False,namespace_effects=0,
        scope='ISSUED_ARENA_VALUE_MATERIALIZATION_WITH_REAL_BINARY64_AND_GRAPHWIRE',
        fixed_native_coordinator=False,public_raw_default_decode_prefix=False,
        private_inputs_are_not_authenticated_by_equal_headers=True,
        original_limits=dict(cpu_seconds=90,address_space_bytes=1<<30),
        elapsed_ns=time.monotonic_ns()-start,compressed_cas_objects=len(saved))
    save(OUT/'source-after.json',pinrows());save(OUT/'summary.json',summary)
    print(json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
