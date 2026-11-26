"""Development source/effect checks, explicitly not native qualification.

The original Python verifier supplies the reference canonical programs. The
effect driver models the fixed dependency protocols solely to test ownership,
phase order, reply handling and private cleanup before the native host returns.
"""
from pathlib import Path
import hashlib,json,random,struct
from hepta.hia_program import HIAProgramRejected,VerifiedProgram,verify_program
from tools import generate_hia_background_optimizer_constructor_binding as owner
from tools import generate_hia_background_optimizer_constructor_checks as checks

ROOT=Path(__file__).resolve().parents[1]
MAX=(1<<64)-1
PID=1234
C=owner.C
FN_VALUE=111;FN_VERIFY=112;FN_PAYLOAD=113;FN_RUNTIME=114;FN_CAPTURE=115;FN_SHA=116
SBASE=0x10000000;OBASE=0x20000000;WBASE=0x30000000

def get(b,p):
    assert 0<=p<=len(b)-8,(p,len(b))
    return int.from_bytes(b[p:p+8],'little')
def put(b,p,v):
    assert 0<=p<=len(b)-8,(p,len(b))
    b[p:p+8]=(v&MAX).to_bytes(8,'little');return 0
def store(b,p,v):
    assert 0<=p<len(b),(p,len(b))
    b[p]=v&255;return 0
def byte(b,p):
    assert 0<=p<len(b),(p,len(b))
    return b[p]
def triple(b,p):return tuple(get(b,p+8*i)for i in range(3))
def cap(b,p,c):
    for i,v in enumerate(c):put(b,p+8*i,v)
def env(source):
    e={'readbuf':object,'mutbuf':object,'u32':int,'u64':int,'word_load':get,
       'length':len,'store':store,'byte':byte}
    exec(source,e);return e
OE=env(owner.source_program());CE=env(checks.source_program())

def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def arena(value):
    rows=[];chunks=[];cursor=0
    def append(raw):
        nonlocal cursor
        at=cursor;chunks.append(raw);cursor+=len(raw);return at
    def walk(v,parent,key=None):
        i=len(rows);kind=6 if type(v)is dict else 5 if type(v)is list else 4 if type(v)is str else 2 if v is True else 1 if v is False else 0 if v is None else 3
        row=[kind,parent,MAX,0,0,0,0,0,0];rows.append((row,key,v if kind==4 else None))
        begin=cursor
        if kind>=5:
            append(b'{'if kind==6 else b'[');children=[]
            items=list(v.items())if kind==6 else list(enumerate(v))
            for index,(k,x)in enumerate(items):
                if index:append(b',')
                if kind==6:append(json.dumps(k,ensure_ascii=False).encode()+b':')
                children.append(walk(x,i,k if kind==6 else None))
            append(b'}'if kind==6 else b']')
            for a,b in zip(children,children[1:]):rows[a][0][2]=b
            row[3]=children[0]if children else MAX;row[4]=len(children)
        else:
            raw=json.dumps(v,ensure_ascii=False,separators=(',',':')).encode()
            row[3]=append(raw);row[4]=len(raw)
        if kind>=4:row[7]=begin;row[8]=cursor-begin
        return i
    walk(value,MAX);raw=b''.join(chunks);out=bytearray(64+72*len(rows))
    def string(text):
        p=len(out);b=text.encode('utf-8','surrogatepass');out.extend(b);return p,len(b)
    for i,(r,key,text)in enumerate(rows):
        if key is not None:r[5],r[6]=string(key)
        if text is not None:r[3],r[4]=string(text)
        for j,x in enumerate(r):put(out,64+72*i+8*j,x)
    for p,x in ((0,5208772604367785521),(8,len(rows)),(16,64+72*len(rows)),
                (24,len(out)),(32,len(out)),(40,len(raw)),(48,1)):
        put(out,p,x)
    return raw,bytes(out)

def scalar_program(count=1):
    functions=[]
    for i in range(count):
        params=[{'name':'x','type':'u64'}]
        functions.append({'name':'f'+str(i),'params':params,'returns':['u64'],'effects':[],
            'entry':'b0','blocks':[{'id':'b0','params':params,'ops':[],
                                  'term':{'op':'ret','values':['x']}}]})
    return {'schema':'hepta.hia.program.v1','module':'constructor','functions':functions}

PURE=[]
def pure_case(document,name):
    raw,a=arena(document);f=name.encode('utf-8','surrogatepass')
    s=bytearray(128)+raw+a+f;put(s,0,checks.C['MAGIC'])
    for p,v in((16,len(raw)),(24,len(a)),(32,len(f))):put(s,p,v)
    o=bytearray([0xa5])*128;w=bytearray([0x91])*(len(a)+128)
    rc=CE['constructor_checks'](s,o,w)
    expected=name in VerifiedProgram(encoded(document)).scalar_entrypoints
    assert rc==0 and get(o,8)==int(not expected)and get(o,16)==(0 if expected else 6),(name,rc,list(o[:24]))
    PURE.append({'case':'function','expected_member':expected})

for count in(1,3,17,33):
    p=verify_program(scalar_program(count)).as_dict()
    for name in('f0','f'+str(count-1),'f'+str(count),'','x','\ud800','x\0y','f0'*5000):pure_case(p,name)
types=['bool','i8','u8','i16','u16','i32','u32','i64','u64','isize','usize','unit']
for t in types:
    p={'functions':[{'name':'scalar','params':[{'name':'x','type':t}],'returns':[t]},
                    {'name':'buffer','params':[{'name':'x','type':{'ref':'u64'}}],'returns':['u64']}]}
    for n in('scalar','buffer','missing'):pure_case(p,n)
for exports in([],['visible'],['visible','another']):
    p={'exports':exports,'functions':[{'name':'hidden','params':[],'returns':[]}]}
    for n in('visible','hidden','another',''):pure_case(p,n)

def snapshot(core_sha,input_sha,flags=6,generation=b'0',epoch=b'0'):
    raw=bytearray(256)+generation+epoch
    for at,v in((0,C['SNAPSHOT']),(16,flags),(24,len(generation)),(32,len(epoch)),(40,len(raw))):put(raw,at,v)
    raw[64:96]=raw[128:160]=core_sha;raw[96:128]=raw[160:192]=input_sha
    return bytes(raw)

class Case:
    def __init__(self,baseline=None,function='f0',*,verified=False):
        self.s=bytearray(128);self.o=bytearray([0xa5])*C['OUT'];self.w=bytearray(16384)
        self.mem={SBASE:self.s,OBASE:self.o,WBASE:self.w};self.next_address=0x100000000
        self.dynamic=set();self.values={};self.payloads={};self.runtime={};self.provider_payloads={}
        self.next_cap=100;self.trace=[];self.dropped=[];self.allocs=0;self.faults={};self.sha=None
        self.baseline=scalar_program()if baseline is None else baseline;self.function=function
        self.snap_change=None;self.snapshot_error=None;self.clone_error=None;self.value_drop=[];self.value_retry=[]
        self.provider_drop_error=None;self.payload_drop_error=None;self.verify_retained=False;self.verify_waiting=None
        self.vbase=self.new_value(7 if verified else 8,self.baseline.canonical_bytes if verified else self.baseline)
        self.vstructured=self.new_value(7,self.baseline.structured_bytes)if verified and self.baseline.structured_bytes is not None else (0,0,0)
        kind=4 if type(function)is str else 1 if type(function)is bool else 2 if type(function)is int else 5 if type(function)is list else 0
        data=function.encode('utf-8','surrogatepass')if kind==4 else b''
        self.vfunction=self.new_value(kind,data)
        self.runtime_input=self.new_runtime()
        put(self.s,0,C['VERIFIED']if verified else C['MAGIC'])
        cap(self.s,24,self.vbase);cap(self.s,48,self.vfunction);cap(self.s,72,self.runtime_input)
        if verified:cap(self.s,96,self.vstructured)
        for at,value in((0,C['CONTEXT']),(8,FN_VALUE),(16,0x40000000),(24,256),
          (32,FN_VERIFY),(40,FN_PAYLOAD),(48,0x41000000),(56,512),(64,FN_RUNTIME),
          (72,0x42000000),(80,1024),(88,FN_CAPTURE),(96,FN_SHA),(104,9),(112,0x43000000),
          (120,10100891),(128,211),(136,212),(144,213),(152,214),(160,215),(168,216),(176,4300)):
            put(self.w,at,value)
        self.kept_values=set(self.values);self.kept_runtime=set(self.runtime)

    def fresh(self):
        self.next_cap+=1;n=self.next_cap;return(n,n+10000,n+20000)
    def new_value(self,kind,data):
        c=self.fresh();self.values[c]=(kind,data);return c
    def new_runtime(self):
        c=self.fresh();self.runtime[c]=True;return c
    def allocate(self,n,*,dynamic=True):
        at=self.next_address;self.next_address+=(n+4095)//4096*4096+4096
        self.mem[at]=bytearray(n)
        if dynamic:self.dynamic.add(at)
        return at
    def new_payload(self,data,provider=False):
        c=self.fresh();p=self.allocate(len(data),dynamic=False);self.mem[p][:]=data
        (self.provider_payloads if provider else self.payloads)[c]=(p,bytes(data));return c
    def view(self,p,n):
        for at,b in self.mem.items():
            if at<=p and n<=len(b)-(p-at):return memoryview(b)[p-at:p-at+n]
        raise AssertionError(('bad modeled view',hex(p),n))
    def run(self,cleanup=False):
        if cleanup:
            self.s[:]=bytes(128);put(self.s,0,C['MAGIC']);put(self.s,8,1)
        put(self.o,C['PHASE'],0)
        for _ in range(50000):
            result=OE['constructor_binding'](self.s,self.o,self.w)
            if result==0:return get(self.o,8)
            if result==C['BAD']:return result
            if result==10:continue
            bases=(0,WBASE,SBASE,OBASE);reply=0
            if result==1:
                nr=get(self.o,0);args=[get(self.o,16+8*i)+bases[(get(self.o,8)>>(2*i))&3]for i in range(6)]
                self.trace.append(('syscall',nr,args))
                if nr==39:reply=PID
                elif nr==9:
                    self.allocs+=1
                    if self.faults.get('mmap')==self.allocs:reply=MAX-11
                    else:reply=self.allocate(args[1])
                elif nr==11:
                    if self.faults.get('munmap',0):
                        self.faults['munmap']-=1;reply=MAX-4
                    else:
                        assert args[0]in self.dynamic,(args,self.dynamic)
                        self.dynamic.remove(args[0]);del self.mem[args[0]]
                else:raise AssertionError(('unexpected syscall',nr))
            elif result==4:
                reply=OBASE+get(self.o,0)
            elif result==8:
                a,at,b,bt,n=(get(self.o,p)for p in(0,8,16,24,32))
                self.view(bt+bases[b],n)[:]=bytes(self.view(at+bases[a],n))
            elif result in(9,11):
                mask=get(self.o,8);args=[get(self.o,16+8*i)+bases[(mask>>(2*i))&3]for i in range(6)]
                sp,sn,op,on,wp,wn=args
                if result==11:
                    self.trace.append(('checks',get(self.view(sp,sn),8)))
                    reply=CE['constructor_checks'](self.view(sp,sn),self.view(op,on),self.view(wp,wn))
                else:reply=self.call(get(self.o,0),args)
            else:raise AssertionError(('unknown action',result,get(self.o,128)))
            put(self.o,C['FEEDBACK'],reply)
        raise AssertionError('nonterminating development effect trace')

    def call(self,fn,args):
        sp,sn,op,on,wp,wn=args;s=bytes(self.view(sp,sn));o=self.view(op,on)
        operation=get(s,8)if len(s)>=16 else -1
        self.trace.append(('call',fn,operation))
        if fn==FN_CAPTURE:
            raw,a=arena(json.loads(s))
            assert raw==s,'reference canonical input retains its exact key order'
            w=self.view(wp,wn)
            if get(w,104)==0:
                o[:64]=bytes(64)
                for at,v in((0,C['SIZES']),(8,get(a,8)),(16,get(a,8)),(24,64),(32,len(a)),(40,max(131072,get(a,8))),(48,len(s))):put(o,at,v)
            else:o[:len(a)]=a
            return 0
        if fn==FN_SHA:
            if s[0]==0:self.sha=hashlib.sha256()
            elif s[0]==1:self.sha.update(s[1:])
            elif s[0]==2:
                o[:32]=self.sha.digest()
                return 32
            else:raise AssertionError(s[:10])
            return 0
        o[:128]=bytes(128)
        if fn==FN_VERIFY:
            put(o,0,C['YREPLY'])
            if operation==1:
                assert self.verify_waiting is not None
                status,payload=self.verify_waiting;self.verify_waiting=None
            else:
                try:
                    if get(s,0)==C['YVERIFIED']:
                        canonical=self.values[triple(s,24)][1]
                        structured=self.values[triple(s,48)][1]if triple(s,48)!=(0,0,0)else None
                        v=verify_program(VerifiedProgram(canonical,structured))
                    else:v=verify_program(self.values[triple(s,24)][1])
                    original=v.structured_bytes or v.canonical_bytes;core=v.canonical_bytes
                    n=bytearray(64)+original+core
                    for at,x in((0,C['NORM']),(24,int(v.structured_bytes is not None)),(32,len(original)),(40,len(core))):put(n,at,x)
                    payload=bytes(n);status=0
                except HIAProgramRejected as e:
                    payload=encoded({'class':type(e).__name__,'code':e.code,'message':str(e)});status=2
                if self.verify_retained:
                    self.verify_retained=False;self.verify_waiting=(status,payload)
                    put(o,8,9);put(o,56,1);put(o,64,1);return 0
            c=self.new_payload(payload);put(o,8,status);cap(o,16,c);put(o,40,len(payload));return 0
        if fn==FN_VALUE:
            if operation in(29,31):
                put(o,0,C['VALUE_DROP_REPLY']);put(o,88,1);put(o,96,int(operation==29))
                controls=self.value_drop if operation==29 else self.value_retry
                fields=controls.pop(0)if controls else {}
                for at,v in fields.items():put(o,at,v)
                if operation==29 and get(o,96)==1 and get(o,88)==1 and get(o,8)in(0,11):
                    c=triple(s,24);assert c in self.values
                    assert c not in self.dropped;self.dropped.append(c);del self.values[c]
                return 0
            put(o,0,C['VREPLY']);c=triple(s,24)
            if c not in self.values:put(o,8,1);return 0
            kind,data=self.values[c];put(o,16,kind)
            if operation==5:cap(o,24,self.new_value(kind,data))
            elif operation==7:put(o,72,len(data)if isinstance(data,bytes)else 0)
            elif operation==19:
                off,n=get(s,104),get(s,112);part=data[off:off+n]
                put(o,56,off);put(o,64,len(part));put(o,72,len(data));o[8192:8192+len(part)]=part
            else:raise AssertionError(('unexpected value operation',operation))
            return 0
        if fn==FN_PAYLOAD:
            put(o,0,C['BREPLY'])
            if operation==1:
                data=s[128:];assert len(data)==get(s,72)
                c=self.new_payload(data);cap(o,16,c);put(o,40,len(data))
            elif operation in(3,6):
                c=triple(s,24);assert c in self.payloads,(operation,c)
                p,data=self.payloads[c]
                if operation==6:put(o,40,len(data));put(o,64,p)
                else:
                    del self.payloads[c];del self.mem[p]
                    if self.payload_drop_error is not None:put(o,8,self.payload_drop_error);self.payload_drop_error=None
            else:raise AssertionError(('unexpected payload operation',operation))
            return 0
        if fn==FN_RUNTIME:
            put(o,0,C['MREPLY'])
            if operation==3:
                assert triple(s,16)in self.runtime
                if self.clone_error is not None:put(o,8,self.clone_error);return 0
                put(o,16,3);cap(o,40,self.new_runtime())
            elif operation==1:
                assert triple(s,16)in self.runtime
                v=verify_program(self.baseline)
                raw=snapshot(bytes.fromhex(v.sha256),bytes.fromhex(v.input_sha256))
                if self.snap_change:raw=self.snap_change(bytearray(raw))
                if self.snapshot_error:
                    raw=encoded(self.snapshot_error);put(o,8,1)
                c=self.new_payload(raw,provider=True);p,data=self.provider_payloads[c]
                put(o,16,1);put(o,24,p);put(o,32,len(data));cap(o,40,c)
            elif operation==4:
                c=triple(s,16);assert c in self.runtime;del self.runtime[c];put(o,16,4)
                if self.provider_drop_error is not None:put(o,8,self.provider_drop_error);self.provider_drop_error=None
            elif operation==5:
                c=triple(s,40);p,_=self.provider_payloads.pop(c);del self.mem[p];put(o,16,4)
            else:raise AssertionError(('unexpected provider operation',operation))
            return 0
        raise AssertionError(('unexpected fixed dependency',fn))

    def error(self):
        c=triple(self.o,96);assert c in self.payloads
        return json.loads(self.payloads[c][1])
    def release_output(self):
        status=get(self.o,8)
        if status==0 and triple(self.o,16)!=(0,0,0):
            for c in(triple(self.o,16),):
                p,_=self.payloads.pop(c);del self.mem[p]
            del self.runtime[triple(self.o,48)];del self.values[triple(self.o,72)]
        elif status==1:
            p,_=self.payloads.pop(triple(self.o,96));del self.mem[p]
    def clean(self):
        self.release_output()
        assert not self.dynamic and not self.payloads and not self.provider_payloads
        assert set(self.values)==self.kept_values and set(self.runtime)==self.kept_runtime

ROWS=[]
def record(label,c,status,*,error=None,clean=True):
    got=c.run();assert got==status,(label,got,get(c.o,208),get(c.o,216),c.trace[-6:])
    if error is not None:assert c.error()['message']==error,(label,c.error())
    ROWS.append({'case':label,'status':got,'effects':len(c.trace),'quarantine':get(c.o,208)})
    if clean:c.clean()
    return c

record('actual original canonical verification and captured snapshot',Case(),0)
record('public source beyond sixteen functions',Case(scalar_program(33),'f32'),0)
record('verified-program shape still invokes fresh canonical verification',Case(verify_program(scalar_program()),verified=True),0)
for f in(None,True,1,[],{},'missing','\ud800','x\0y','f0'*5000):
    c=record('exact function gate '+repr(f)[:35],Case(function=f),1,error='E_HIA_BACKGROUND: '+owner.ERRORS[6])
    assert not any(x[:2]==('call',FN_RUNTIME)for x in c.trace)
c=record('invalid baseline precedes invalid function',Case({},None),1)
assert not any(x[:2]in(('call',FN_VALUE),('call',FN_RUNTIME))for x in c.trace)

for name,change,error in(
 ('closed',lambda r:(put(r,16,7),r)[1],7),
 ('missing baseline',lambda r:(put(r,16,4),r)[1],7),
 ('baseline Core differs',lambda r:(r.__setitem__(64,r[64]^1),r)[1],7),
 ('baseline input differs',lambda r:(r.__setitem__(96,r[96]^1),r)[1],7),
 ('current source differs',lambda r:(r.__setitem__(128,r[128]^1),r)[1],9),
):
 c=Case();c.snap_change=change;record('actual snapshot '+name,c,1,error='E_HIA_BACKGROUND: '+owner.ERRORS[error])
c=Case();c.snapshot_error={'type':'OSError','message':'actual snapshot failure'}
record('original provider error remains explicitly typed format3',c,1)
assert get(c.o,128)==3
c=Case()
def wide_snapshot(r):
    n=b'1'+b'0'*100000
    return snapshot(bytes(r[64:96]),bytes(r[96:128]),generation=n,epoch=n)
c.snap_change=wide_snapshot
record('full decimal snapshot fields have no word or small-output truncation',c,0)
for status in(2,3):
 c=Case();c.clone_error=status;record('clone failure '+str(status),c,5 if status==2 else 7)

for index in range(1,6):
 c=Case();c.faults['mmap']=index;record('actual mapping effect fails '+str(index),c,5)
c=Case();c.faults['munmap']=1
record('pre-binding mapping release retains only cleanup',c,9,clean=False)
assert get(c.o,208)==1
calls=len(c.trace);assert c.run(cleanup=True)==9
assert not any(x[:2]in(('call',FN_VERIFY),('call',FN_RUNTIME))for x in c.trace[calls:])
c.clean()

for fields in({8:11,80:1},{8:11,80:0},{8:6,80:1,96:0},{8:11,80:1,96:0}):
 c=Case(function='missing');c.value_drop=[fields]
 if fields=={8:11,80:1}:c.value_retry=[{8:11,80:1}]
 record('explicit value retirement '+str(fields),c,9,clean=False)
 kind=get(c.o,208);before=len(c.trace)
 if kind==1:
  assert c.run(cleanup=True)==1;c.clean()
  assert not any(x[:3]==('call',FN_VALUE,29)for x in c.trace[before:])
 else:
  assert kind==2 and c.run(cleanup=True)==6
  assert not any(x[0]=='call'for x in c.trace[before:])

c=Case(function='missing');c.provider_drop_error=3
c.snap_change=lambda r:(r.__setitem__(128,r[128]^1),r)[1]
c.function='f0';c.values[c.vfunction]=(4,b'f0')
record('provider post-consumption unknown is isolated',c,9,clean=False)
before=len(c.trace);assert get(c.o,208)==2 and c.run(cleanup=True)==6
assert not any(x[0]=='call'for x in c.trace[before:])
c=Case(function='missing');c.payload_drop_error=9
record('legacy payload post-consumption unknown is isolated',c,9,clean=False)
before=len(c.trace);assert get(c.o,208)==2 and c.run(cleanup=True)==6
assert not any(x[0]=='call'for x in c.trace[before:])
c=Case();c.verify_retained=True
record('nested verifier retains its real continuation',c,9,clean=False)
assert c.run(cleanup=True)==9 and c.verify_waiting is None
c.clean()

for offset in(16,120):
 c=Case();put(c.s,offset,1);record('private reserved request '+str(offset),c,C['BAD'])

report={'schema':'hepta.hia.background.constructor-binding.source-probes.v1',
        'original_scalar_entrypoint_cases':len(PURE),'source_effect_cases':len(ROWS),
        'rows':ROWS,'original_core_verifier_executed':True,'native_product_executed':False,
        'actual_native_dependencies_executed':False,'whole_background_qualified':False}
(ROOT/'docs/HIA_BACKGROUND_NATIVE_CONSTRUCTOR_BINDING_SOURCE_PROBES.json').write_text(json.dumps(report,indent=2)+'\n')
print('constructor binding source probes',len(PURE),len(ROWS),'PASS; native gates pending')
