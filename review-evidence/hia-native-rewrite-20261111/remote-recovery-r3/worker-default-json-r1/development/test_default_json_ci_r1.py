"""Actual complete default decode_data prefix with unchanged hosted oracle.

Only the test fixture transports Python str as exact UTF-8 surrogatepass bytes.
Inside every native interval all former parse/materialize/float owner entrypoints
are disabled. Actual HIA events alone select the next fixed peer and slice.
The executor is mechanical development code, not a claimed native Worker.
"""
from __future__ import annotations
import ctypes,json,math,os,random,resource,stat,struct,sys,time,traceback,zlib
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
WORK=Path(sys.argv[1]).resolve();COMPILE=Path(sys.argv[2]).resolve()
OUT=Path(sys.argv[3]).resolve();GROUP=sys.argv[4]
ROOT=WORK/'native-agent-default-json-next';REFERENCE=WORK/'Hepta-agent-edit-native'
sys.path[:0]=[str(ROOT/'tools'),str(REFERENCE)]
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta import hia_agent_store as store
import agent_default_json_common as common
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
M=lambda s:int.from_bytes(s,'little')
pack=lambda *v:struct.pack('<'+'Q'*len(v),*v)
BAD=0xfffffffd;CANARY=bytes(range(64));FBASE=2048;FEND=2304
ROLES={1:'default_json_raw',2:'default_json_services',3:'default_json_late'}
C=common.CONSTANTS
OUT.mkdir(parents=True,exist_ok=False);(OUT/'cas').mkdir()
pins={};saved=set();images={};entries={r:0 for r in (*ROLES.values(),'preflight','decoder','data_graph','binary64')}
ledger=(OUT/'entries.jsonl').open('w');results=(OUT/'cases.jsonl').open('w')
cases=0;planned=0;status='FAIL';failure=None;started=time.monotonic_ns()
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True,ensure_ascii=True)+'\n')
def cas(raw):
    raw=bytes(raw);h=digest(raw)
    if h not in saved:
        path=OUT/'cas'/(h+'.zlib');path.write_bytes(zlib.compress(raw,1))
        assert zlib.decompress(path.read_bytes())==raw
        saved.add(h)
    return dict(bytes=len(raw),sha256=h)
def read(path):
    path=Path(path).resolve();raw=path.read_bytes()
    if path in pins:assert pins[path]==raw
    pins[path]=raw;return raw
def pinrows():
    return [dict(path=str(p),bytes=len(raw),sha256=digest(raw),mode=stat.S_IMODE(p.stat().st_mode))
            for p,raw in pins.items()]
def readback():assert all(p.is_file() and p.read_bytes()==raw for p,raw in pins.items())
def disabled(*args,**kwargs):raise AssertionError('former JSON semantic owner entered actual native interval')
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
class View:
    def __init__(self,parent,at,n):
        assert 0<=at<=parent.n and 0<=n<=parent.n-at
        self.parent=parent;self.at=at;self.n=n
    @property
    def p(self):return self.parent.p+self.at
    def raw(self):return ctypes.string_at(self.p,self.n)
    def guard(self):self.parent.guard()
def invoke(role,s,r,w,label,advertised_work=None):
    n=w.n if advertised_work is None else advertised_work
    assert 0<=n<=w.n
    sb,rb,wb=s.raw(),r.raw(),w.raw()
    save(OUT/'pending-native-entry.json',dict(role=role,label=label,
        ordinal=entries[role]+1,source=cas(sb),second=cas(rb),workspace=cas(wb),advertised_work=n))
    with ExitStack() as stack:
        for target in ('hepta.hia_agent_store.decode_data','hepta.hia_json_preflight.preflight_hia_json',
          'hepta.hia_json_preflight._preflight_hia_json_reference',
          'hepta.hia_agent_data_json_native.materialize_data',
          'hepta.hia_json_decode_native.materialize',
          'hepta.hia_agent_data_json_native.finite_float','json.loads'):
            stack.enter_context(patch(target,new=disabled))
        actual=int(images[role]._entry(s.p,s.n,r.p,r.n,w.p,n))
    entries[role]+=1
    assert s.raw()==sb
    if role in (*ROLES.values(),'data_graph'):assert r.raw()==rb
    for b in (s,r,w):b.guard()
    ledger.write(json.dumps(dict(role=role,label=label,status=actual,source=cas(sb),
        second_before=cas(rb),second_after=cas(r.raw()),workspace_before=cas(wb),
        workspace_after=cas(w.raw()),advertised_work=n,input_and_canaries_unchanged=True),sort_keys=True)+'\n')
    ledger.flush();return actual
def grow(w,needed):
    assert needed>w.n
    return Buffer(needed,w.raw())
def configured(wire,kind,digits):
    s=Buffer(len(wire),wire);w=Buffer(8192);r=Buffer(0)
    w.write(128,pack(M(b'HIAGDC01'),31,73,92,93,kind,digits,91,94,len(wire),0,0,0,0,0,0))
    return dict(s=s,r=r,w=w,role='default_json_raw',sequence=0,events=[],grows=[],
        peer_calls=[],float_calls=[],masked=[],kind=kind,digits=digits,arena=None)
def frame(context,ret):
    assert ret==FEND,ret
    f=struct.unpack_from('<32Q',context['w'].raw(),FBASE)
    assert f[0]==M(b'HIAGDE01') and f[2:4]==(31,73) and f[5:9]==(92,93,context['kind'],context['digits'])
    assert f[4]==context['sequence']+1 and f[31]==0
    context['sequence']=f[4];context['events'].append(list(f))
    return f
def values_service(context,config,label):
    arena=context['arena'];raw=context['s']
    assert arena is not None
    w=Buffer(4096);w.write(128,config);sequence=0
    while True:
        actual=invoke('data_graph',arena,raw,w,label+'.values')
        if actual==BAD:return actual,w
        assert actual==2240
        f=struct.unpack_from('<24Q',w.raw(),2048)
        assert f[0]==M(b'HIADGE01') and f[2:4]==(94,73) and f[5:8]==(93,91,92)
        assert f[4]==sequence+1 and f[22:]==(0,0);sequence=f[4]
        if f[1]==1:
            context['grows'].append(dict(owner='data_graph',before=w.n,after=f[8]))
            w=grow(w,f[8]);continue
        if f[1]==2:
            start,size=f[11:13];assert start<=raw.n and 0<size<=raw.n-start
            context['float_calls'].append(raw.raw()[start:start+size])
            bits=Buffer(8);scratch=Buffer(4096)
            returned=invoke('binary64',View(raw,start,size),bits,scratch,label+'.values-binary')
            extent=8 if returned==8 else 0
            w.write(256,pack(M(b'HIADGR01'),94,73,f[4],returned,extent,f[13],0))
            w.write(320,bits.raw())
            continue
        assert f[1] in (0,3),f
        return actual,w
def issue_peer(context,label):
    f=context['pending'];w=context['w'];s=context['s'];peer=f[12]
    assert f[13]==f[4] and f[10] in ROLES and f[11]==0
    input_owner,start,size,capacity,workcap,config_at,config_size=f[14:21]
    assert config_at<=w.n and config_size<=w.n-config_at
    config=w.raw()[config_at:config_at+config_size]
    if input_owner==0:source=View(s,start,size)
    elif input_owner==1:source=View(w,start,size)
    elif input_owner==2:
        assert context['arena'] is not None
        source=View(context['arena'],start,size)
    else:raise AssertionError(f)
    context['peer_calls'].append(peer)
    if peer==1:
        assert input_owner==1 and config_size==128
        context['masked'].append(source.raw())
        output=Buffer(capacity);scratch=Buffer(workcap);scratch.write(0,config)
        actual=invoke('preflight',source,output,scratch,label+'.preflight')
        reply=scratch;output_lease=0;workspace_lease=31;workspace_bytes=scratch.n
    elif peer==2:
        assert input_owner==0 and config_size==128
        output=Buffer(capacity);scratch=Buffer(workcap);scratch.write(0,config)
        actual=invoke('decoder',source,output,scratch,label+'.decoder')
        extent=actual if actual<=capacity else 0
        reply=View(output,0,extent)
        context['arena']=reply
        output_lease=91;workspace_lease=31;workspace_bytes=scratch.n
    elif peer==3:
        assert input_owner==2 and config_size==128 and capacity==0
        actual,reply=values_service(context,config,label)
        output_lease=94;workspace_lease=94;workspace_bytes=reply.n
    elif peer==4:
        assert input_owner==0 and config_size==0 and capacity==8 and workcap==4096
        context['float_calls'].append(source.raw())
        output=Buffer(capacity);scratch=Buffer(workcap)
        actual=invoke('binary64',source,output,scratch,label+'.late-binary')
        reply=View(output,0,8 if actual==8 else 0)
        output_lease=0;workspace_lease=31;workspace_bytes=scratch.n
    else:raise AssertionError(f)
    w.write(256,pack(M(b'HIAGDA01'),31,73,f[13],peer,actual,reply.n,workspace_bytes,
        output_lease,workspace_lease,92,capacity,size,0,0,0))
    context['r']=reply
    context['role']=ROLES[f[10]]
    return actual,reply
def drive(wire,kind,digits,label,stop_peer=None):
    context=configured(wire,kind,digits)
    while True:
        actual=invoke(context['role'],context['s'],context['r'],context['w'],label+'.controller')
        if actual==BAD:
            context['terminal_bad']=True;return context
        f=frame(context,actual);action=f[1]
        if action==1:
            assert f[10] in ROLES and ROLES[f[10]]==context['role']
            context['grows'].append(dict(owner=context['role'],before=context['w'].n,after=f[11]))
            context['w']=grow(context['w'],f[11]);continue
        if action==5:
            assert f[10] in ROLES
            context['role']=ROLES[f[10]];continue
        if action==2:
            context['pending']=f
            if stop_peer==f[12]:return context
            issue_peer(context,label);continue
        assert action in (0,3),f
        context['terminal']=f;return context
def outcome(context):
    if context.get('terminal_bad'):
        return dict(private_bad=True)
    f=context['terminal'];owner,at,size=f[21:24]
    buffer=context['w'] if owner==1 else context['r'] if owner==2 else None
    assert buffer is not None and at<=buffer.n and size<=buffer.n-at
    raw=buffer.raw()[at:at+size]
    if f[1]==0:
        assert owner==2 and f[9]==90 and f[24:31]==(0,0,0,0,0,0,0)
        return dict(graph=raw)
    assert f[1]==3 and owner==1 and f[9]==91 and 0<size<=1024
    cls={1:'AgentRejected',2:'ValueError',3:'OverflowError',4:'UnicodeDecodeError',
         5:'UnicodeEncodeError',6:'JSONDecodeError',7:'RuntimeError'}[f[24]]
    value=dict(error_class=cls,error=raw.decode('utf-8'),code='E_HIA_JSON' if f[24]==1 else None)
    if f[24] in (4,5):value.update(start=f[26],end=f[27])
    if f[24]==6:value.update(pos=f[26],lineno=f[29],colno=f[30])
    return value
def oracle(payload):
    float_calls=[];masked=[]
    loads=json.loads;preflight=store.preflight_hia_json
    def observing_preflight(text,**kwargs):
        masked.append(text.encode('utf-8'))
        return preflight(text,**kwargs)
    def observing_loads(*args,**kwargs):
        floating=kwargs.get('parse_float')
        if floating is not None:
            def observed(text):
                float_calls.append(text.encode('ascii'))
                return floating(text)
            kwargs=dict(kwargs);kwargs['parse_float']=observed
        return loads(*args,**kwargs)
    try:
        with patch.dict(os.environ,{'HEPTA_HIA_AGENT_DATA_JSON_MANIFEST':'',
              'HEPTA_HIA_AGENT_BINARY64_MANIFEST':'','HEPTA_HIA_JSON_PREFLIGHT_MANIFEST':''}),\
              patch.object(store,'preflight_hia_json',new=observing_preflight),\
              patch('json.loads',new=observing_loads):
            value=store.decode_data(payload)
        result=dict(value=value)
    except Exception as exc:
        result=dict(error_class=type(exc).__name__,error=str(exc),code=getattr(exc,'code',None))
        if isinstance(exc,(UnicodeDecodeError,UnicodeEncodeError)):result.update(start=exc.start,end=exc.end)
        if isinstance(exc,json.JSONDecodeError):result.update(pos=exc.pos,lineno=exc.lineno,colno=exc.colno)
    return result,float_calls,masked

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

def transport(payload):
    if type(payload) is bytes:return payload,9
    if type(payload) is str:return payload.encode('utf-8','surrogatepass'),4
    return b'',0
def normalized(value):
    if 'value' in value:
        raw=json.dumps(clean(value['value']),ensure_ascii=True,separators=(',',':')).encode()
        return dict(value=cas(raw))
    return value
def check(label,payload,digits=4300):
    global cases
    print(json.dumps(dict(event='DEFAULT_JSON_CASE_START',group=GROUP,label=label,ordinal=cases+1)),flush=True)
    previous=sys.get_int_max_str_digits();sys.set_int_max_str_digits(digits)
    try:
        wire,kind=transport(payload)
        expected,expected_float,expected_masked=oracle(payload)
        context=drive(wire,kind,digits,label)
        actual=outcome(context)
        assert context['float_calls']==expected_float,(label,'float callback order',
            [x[:80] for x in expected_float],[x[:80] for x in context['float_calls']])
        assert context['masked']==expected_masked,(label,'exact masked preflight input')
        if 'value' in expected:
            assert 'graph' in actual,(label,expected.keys(),actual)
            decoded=graph_value(actual['graph'])
            assert clean(decoded)==clean(expected['value']),label
            record=dict(value=decoded)
        else:
            assert actual==expected,(label,expected,actual)
            record=actual
        row=dict(case=cases+1,label=label,input_kind=kind,digits=digits,wire=cas(wire),
            expected=normalized(expected),actual=normalized(record),
            actual_masked=[cas(x) for x in context['masked']],
            expected_masked=[cas(x) for x in expected_masked],
            actual_float_lexemes=[cas(x) for x in context['float_calls']],
            expected_float_lexemes=[cas(x) for x in expected_float],
            actual_peer_sequence=context['peer_calls'],events=context['events'],grows=context['grows'])
        results.write(json.dumps(row,sort_keys=True,ensure_ascii=True)+'\n');results.flush()
        # Terminal replay must fail closed with no second parse or conversion.
        assert invoke(context['role'],context['s'],context['r'],context['w'],label+'.terminal-replay')==BAD
        cases+=1
        print(json.dumps(dict(event='DEFAULT_JSON_CASE_PASS',group=GROUP,label=label,ordinal=cases)),flush=True)
    finally:sys.set_int_max_str_digits(previous)

def semantic_cases():
    good=[b'null',b'true',b'false',b'0',b'-0',b'1',b'-1',b'18446744073709551616',
          b'1.0',b'-0.0',b'1e0',b'1e-4000',b'-1e-4000',b'5e-324',
          b'2.2250738585072014e-308',b'1.7976931348623157e308',
          b'""',b'"x"',b'"quote: \\" slash: \\\\ newline: \\n"',
          b'"\\u0000\\u007f\\u0080\\u07ff\\u0800\\ud7ff\\ue000"',
          b'"\\ud83d\\ude00"',b'[]',b'{}',b'[0,1.0,true,null,"x"]',
          b'{"z":1,"a":2.5}',b'{"x":[1.0,{"y":-0.0,"s":"1e9999"}]}']
    good.extend(x.encode('utf-8') for x in ('"é中😀"','{"é":1.5,"中":[-2,3e2]}',' \n [0.1,0.2,0.3] \r'))
    for i,wire in enumerate(good):
        yield ('valid-bytes-'+str(i),wire)
        yield ('valid-text-'+str(i),wire.decode('utf-8'))
    invalid=[b'',b' ',b'01',b'-01',b'1.',b'1e',b'1e+',b'-',b'+1',b'.5',
        b'NaN',b'Infinity',b'-Infinity',b'[NaN]',b'[1,,2]',b'[1,]',b'{"a":1,}',
        b'{"a":1,"a":2}',b'{"a":1,"\\u0061":2}',b'{"x":1e9999,"x":2}',
        b'"\\x"',b'"\\u0"',b'"\\u00xz"',b'"\\ud800"',b'"\\udfff"',b'"\x01"',
        b'"abc',b'"abc\\',b'{"a" 1}',b'{"a":}',b'{1:2}',b'[true false]',b'null x',
        b'\xef\xbb\xbfnull',b'"\\ud800\\u0041"']
    for i,wire in enumerate(invalid):
        yield ('preflight-reject-'+str(i),wire)
    late=[b'1-2.5',b'-1-2.5',b'10-2.5',b'[1-2.5]',
        b'[1e9999,1-2.5]',b'[1e-9999,1-2.5]',b'[1,1-2.5,1e9999]',
        b'{"a":1e9999,"b":1-2.5}',b'{"a":1-2.5,"b":1e9999}',
        b'{"a": [1.25,1-2.5]}',b'[\n 1.0,\n 1-2.5\n]',
        b'1e9999',b'-1e9999',b'[0,1e9999]',b'[1e9999]x']
    late.extend(x.encode('utf-8') for x in ('["é",1-2.5]','{"é😀":1-2.5}','[\n"中",1e9999,1-2.5]'))
    for i,wire in enumerate(late):yield ('numeric-vs-late-syntax-'+str(i),wire)
    for value in (None,False,True,0,1.0,[],{},bytearray(b'0')):
        yield ('wrong-input-type-'+str(type(value).__name__)+'-'+str(value is True),value)
    rng=random.Random(0xdefade)
    for i in range(64):
        signed='-' if rng.randrange(2) else ''
        text=signed+str(rng.randrange(1,10))+'.'+''.join(str(rng.randrange(10)) for _ in range(rng.randrange(1,25)))
        text+='e'+str(rng.randrange(-330,315))
        yield ('random-binary64-'+str(i),text.encode())

def unicode_cases():
    for value in range(256):
        yield ('one-byte-'+str(value),bytes([value]))
    vectors=[b'\xc2',b'\xc2A',b'\xc0\x80',b'\xc1\xbf',b'\xe0',b'\xe0\xa0',
        b'\xe0\x80\x80',b'\xe0\xa0A',b'\xed\xa0\x80',b'\xed\x9f\xbf',
        b'\xef\xbf\xbf',b'\xf0',b'\xf0\x90',b'\xf0\x90\x80',b'\xf0\x80\x80\x80',
        b'\xf0\x90A\x80',b'\xf0\x90\x80A',b'\xf4\x8f\xbf\xbf',b'\xf4\x90\x80\x80',
        b'\xf5\x80\x80\x80',b'\xff',b'\x80\x80']
    for i,raw in enumerate(vectors):
        for prefix in (b'',b'abc',b'"\xc3\xa9'):
            yield ('decode-boundary-'+str(i)+'-'+str(len(prefix)),prefix+raw)
    for i,text in enumerate(('\ud800','\udfff','x\ud800','x\ud800\udfffz',
        '\ud800a\udfff','é😀\udc80','\ud800\ud800\ud800','"é\ud800"')):
        yield ('encode-surrogate-'+str(i),text)
    for i,text in enumerate(('é','😀','中','"\U0010ffff"','{"😀":2.5}','\ufeff0')):
        yield ('valid-unicode-raw-'+str(i),text)

def digit_cases():
    for maximum in (640,4300):
        for count in (maximum-1,maximum,maximum+1):
            digits='1'+'0'*(count-1)
            for sign in ('','-'):
                yield ('integer-bound-'+str(maximum)+'-'+str(count)+'-'+str(bool(sign)),(sign+digits).encode(),maximum)
        long='1'+'0'*maximum
        yield ('digit-before-late-syntax-'+str(maximum),(long+'-2.5').encode(),maximum)
        yield ('float-before-digit-'+str(maximum),('[1e9999,'+long+']').encode(),maximum)
        yield ('digit-before-float-'+str(maximum),('['+long+',1e9999]').encode(),maximum)
        yield ('syntax-before-digit-'+str(maximum),('[1-2.5,'+long+']').encode(),maximum)
        yield ('bad-preflight-before-digit-'+str(maximum),(long+' x').encode(),maximum)
    yield ('zero-disables-integer-digits',('1'+'0'*9999).encode(),0)
    yield ('float-long-integer-part-does-not-use-int-limit',('1'+'0'*4999+'.0e-5000').encode(),640)

def depth_cases():
    for depth in (0,1,127,128,129):
        yield ('array-depth-'+str(depth),b'['*depth+b'0'+b']'*depth)
        yield ('object-depth-'+str(depth),b'{"a":'*depth+b'0'+b'}'*depth)
    yield ('budget-before-nonfinite',b'['*129+b'1e9999'+b']'*129)
    yield ('duplicate-before-late-syntax',b'{"a":1-2.5,"a":0}')
    yield ('escaped-integer-looking-key',b'{"\\u0031e9999":0,"1e9999":1}')

def large_utf8_cases():
    maximum=8388608
    yield ('over-byte-budget-valid-bytes',b'x'*(maximum+1))
    yield ('over-byte-budget-bad-utf8-still-first',b'x'*maximum+b'\xff')
    yield ('over-byte-budget-text-surrogate-still-first','x'*maximum+'\ud800')
    yield ('over-byte-budget-valid-text','é'*(maximum//2+1))

def large_value_cases():
    yield ('maximum-eight-mib-string',b'"'+b'x'*(8388608-2)+b'"')
    yield ('unicode-full-eight-mib-string',b'"'+('é'*(4194303)).encode()+b'"')

def large_nodes_cases():
    yield ('maximum-262144-nodes',b'['+b'0,'*262142+b'0]')
    yield ('nodes-plus-one',b'['+b'0,'*262143+b'0]')
    yield ('nodes-before-nonfinite',b'['+b'0,'*262143+b'1e9999]')

def large_digits_cases():
    yield ('full-100000-digit-integer-no-limit',b'1'+b'0'*99999,0)


def protocols():
    global cases,planned
    controls=[]
    def refusal(context,label):
        r=invoke(context['role'],context['s'],context['r'],context['w'],label)
        assert r==BAD,(label,r)
        assert invoke(context['role'],context['s'],context['r'],context['w'],label+'.poison')==BAD
    def initial(index,value):
        context=configured(b'0',9,4300)
        context['w'].write(128+index*8,pack(value))
        refusal(context,'config-'+str(index))
    for index,value in ((0,0),(1,0),(2,0),(3,0),(4,0),(6,639),(7,0),(8,0),(9,2),
                        (10,1),(11,1),(12,1),(13,1),(14,1),(15,1)):
        controls.append(('config-'+str(index),lambda i=index,v=value:initial(i,v)))
    def nonzero_initial():
        context=configured(b'0',9,4300);context['w'].write(0,b'\1')
        refusal(context,'nonzero-initial')
    controls.append(('nonzero-initial',nonzero_initial))
    def wrong_role():
        context=configured(b'0',9,4300);context['role']='default_json_services'
        refusal(context,'initial-role')
    controls.append(('initial-role',wrong_role))
    def growth_config():
        context=configured(b'0',9,4300)
        f=frame(context,invoke(context['role'],context['s'],context['r'],context['w'],'grow-original'))
        assert f[1]==1
        context['w']=grow(context['w'],f[11]);context['w'].write(152,pack(999))
        refusal(context,'grown-config-mismatch')
    controls.append(('grown-config-mismatch',growth_config))
    def ack_bad(index,value):
        context=drive(b'0',9,4300,'ack-source',stop_peer=1)
        issue_peer(context,'ack-real-preflight')
        context['w'].write(256+index*8,pack(value))
        refusal(context,'ack-'+str(index))
    for index,value in ((0,0),(1,32),(2,74),(3,0),(4,2),(5,1<<32),(6,0),(7,4255),
                        (8,1),(9,32),(10,93),(11,0),(12,999),(13,1),(14,1),(15,1)):
        controls.append(('ack-'+str(index),lambda i=index,v=value:ack_bad(i,v)))
    def foreign_preflight_reason():
        context=drive(b'0',9,4300,'reason-source',stop_peer=1)
        _,reply=issue_peer(context,'reason-real')
        reply.write(32,pack(1))
        refusal(context,'status-zero-reason-nonzero')
    controls.append(('status-zero-reason-nonzero',foreign_preflight_reason))
    def arena_bad(index,value):
        context=drive(b'{"x":1.0}',9,4300,'arena-source',stop_peer=2)
        _,reply=issue_peer(context,'arena-real')
        # Mutate only the independently owned decoder output after its original
        # actual call was captured. This is a private forged-ACK negative control.
        reply.parent.write(reply.at+index*8,pack(value))
        refusal(context,'arena-'+str(index))
    for index,value in ((0,0),(1,0),(2,0),(3,0),(4,0),(5,0),(6,0),(7,1)):
        controls.append(('arena-'+str(index),lambda i=index,v=value:arena_bad(i,v)))
    def values_bad(index,value):
        context=drive(b'{"x":1.0}',9,4300,'values-source',stop_peer=3)
        _,reply=issue_peer(context,'values-real')
        reply.write(2048+index*8,pack(value))
        refusal(context,'values-'+str(index))
    for index,value in ((0,0),(2,95),(3,74),(4,0),(5,94),(6,92),(7,91),(8,1),
                        (9,0),(10,1),(11,1),(12,1),(17,640),(20,1),(21,91),(22,1),(23,1)):
        controls.append(('values-'+str(index),lambda i=index,v=value:values_bad(i,v)))
    def late_binary_bad(which):
        context=drive(b'[1.0,1-2.5]',9,4300,'late-source',stop_peer=4)
        _,reply=issue_peer(context,'late-real-binary')
        if which==0:context['w'].write(304,pack(0))
        else:reply.parent.write(reply.at,pack(0x7ff8000000000000))
        refusal(context,'late-binary-'+str(which))
    controls.append(('late-binary-extent',lambda:late_binary_bad(0)))
    controls.append(('late-binary-nan-success',lambda:late_binary_bad(1)))
    def event_overflow():
        context=configured(b'0',9,4300)
        f=frame(context,invoke(context['role'],context['s'],context['r'],context['w'],'overflow-source'))
        assert f[1]==1
        context['w']=grow(context['w'],f[11]);context['w'].write(C['G_SEQ'],pack((1<<64)-1))
        refusal(context,'event-overflow')
        assert struct.unpack_from('<Q',context['w'].raw(),C['G_PHASE'])[0]==99
    controls.append(('event-overflow',event_overflow))
    def short_workspace():
        context=configured(b'0',9,4300);before=context['w'].raw()
        assert invoke(context['role'],context['s'],context['r'],context['w'],'short-private-borrow',8191)==BAD
        assert context['w'].raw()==before
        # This test retires the lease here. It makes no claim that a too-short
        # view could safely contain a persistent native poison frame.
    controls.append(('short-workspace-driver-retirement',short_workspace))
    planned=len(controls)
    for label,body in controls:
        print(json.dumps(dict(event='DEFAULT_JSON_PROTOCOL_START',label=label,ordinal=cases+1)),flush=True)
        before=dict(entries);body()
        row=dict(case=cases+1,label=label,status='PASS',private_protocol=True,
            entries={k:entries[k]-before[k] for k in entries})
        results.write(json.dumps(row,sort_keys=True)+'\n');results.flush();cases+=1

try:
    read(__file__)
    for path in sorted((ROOT/'tools').glob('*.py')):read(path)
    for path in ('hepta/hia_agent_store.py','hepta/hia_json_preflight.py',
        'hepta/hia_json_preflight_native.py','hepta/hia_agent_data_json_native.py',
        'hepta/hia_json_decode_native.py','hepta/hia_agent_binary64_native.py'):
        read(REFERENCE/path)
    bundle=json.loads(read(COMPILE/'bundle.json'))
    assert bundle['schema']=='hia-agent-default-json-development-bundle-v1' and bundle['status']=='PASS'
    assert set(bundle['components'])==set(entries)
    frozen={}
    for role,row in bundle['components'].items():
        source=read(row['source_path']);image=read(row['image_path']);receipt=json.loads(read(row['receipt_path']))
        assert (len(source),digest(source))==(row['source_bytes'],row['source_sha256'])
        assert (len(image),digest(image))==(row['image_bytes'],row['image_sha256'])
        assert row['role']==role
        assert row['compiler_sha256']=='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
        assert receipt['input_sha256']==digest(source) and receipt['produced_sha256']==digest(image)
        assert receipt['image_sha256']==row['compiler_sha256']
        frozen[role]=(image,digest(image))
    readback();save(OUT/'source-before.json',pinrows())
    images={role:NativeHiaJsonImage(*row) for role,row in frozen.items()}
    if GROUP=='protocol':protocols()
    else:
        factories={'semantic':semantic_cases,'unicode':unicode_cases,'digits':digit_cases,
            'depth':depth_cases,'large-utf8':large_utf8_cases,'large-values':large_value_cases,
            'large-nodes':large_nodes_cases,'large-digits':large_digits_cases}
        values=list(factories[GROUP]());planned=len(values)
        for row in values:check(*row)
    assert cases==planned,(cases,planned);status='PASS'
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
    ledger.close();results.close()
    unchanged=all(p.is_file() and p.read_bytes()==raw for p,raw in pins.items())
    if not unchanged:status='FAIL'
    summary=dict(status=status,scope='COMPLETE_DEFAULT_DATAJSON_PREFIX_WITH_ACTUAL_PEERS',
        group=GROUP,cases=cases,planned_cases=planned,entries=entries,total_actual_entries=sum(entries.values()),
        failure=failure,source_unchanged=unchanged,compressed_cas_objects=len(saved),
        original_limits=dict(cpu_seconds=90,address_space_bytes=1<<30),
        elapsed_ns=time.monotonic_ns()-started,hosted_parser_and_materializer_disabled_in_native_intervals=True,
        selected_agent_data_json_profile_equivalence=False,fixed_native_worker=False,
        production_activation=False,whole_worker_closed=False,
        python_reference_fixture_and_mechanical_event_executor_only=True)
    save(OUT/'source-after.json',pinrows());save(OUT/'summary.json',summary)
    print(json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
