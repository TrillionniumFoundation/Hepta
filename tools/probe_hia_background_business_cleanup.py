"""Development-source effect traces, not native or pthread qualification.

The interpreter runs the emitted HIA source policy and models only its effect
descriptors. Its purpose is to reject unsafe replay before the real native
fault/exit matrix can run on the unavailable build host.
"""
from pathlib import Path
import hashlib, json
from tools import generate_hia_background_optimizer_business_cleanup as guard
from tools import generate_hia_background_optimizer_business_worker as business

ROOT=Path(__file__).resolve().parents[1]
MASK=(1<<64)-1
PID=1234
BCBASE=0x1000000
WORKERBASE=0x2000000
GOUTBASE=0x3000000
GCTXBASE=0x4000000
GSBASE=0x5000000
BUSINESS_FN=1001
WORKER_FN=1002
VALUE_FN=2001
JOBS_FN=2002
PUBLIC_FN=2003
CELL_FN=2004
PROVIDER_FN=2005
CAP=((91,181,271),(92,182,272),(93,183,273),(94,184,274))

def get(buf,at):
    assert 0<=at<=len(buf)-8,(at,len(buf))
    return int.from_bytes(buf[at:at+8],'little')
def put(buf,at,value):
    assert 0<=at<=len(buf)-8,(at,len(buf))
    buf[at:at+8]=(value&MASK).to_bytes(8,'little')
    return 0
def store(buf,at,value):
    assert 0<=at<len(buf),(at,len(buf))
    buf[at]=value&255
    return 0
def byte(buf,at):
    assert 0<=at<len(buf),(at,len(buf))
    return buf[at]
def cap(buf,at,value):
    for i,word in enumerate(value):put(buf,at+8*i,word)
def readcap(buf,at):return tuple(get(buf,at+8*i)for i in range(3))
def environment(source):
    env={'readbuf':object,'mutbuf':object,'u32':int,'u64':int,
         'word_load':get,'store':store,'byte':byte,'length':len}
    exec(source,env)
    return env

GE=environment(guard.source_program())
BE=environment(business.source_program('business'))
BF=environment(business.source_program('business_failure'))
C=business.C
G=guard.C

class Scenario:
    def __init__(self,*,owned=True,rows=0,worker_state=4,unknown=False):
        self.bc=bytearray(1064960)
        self.worker=bytearray(512)
        self.go=bytearray([0xa5])*32768
        self.gw=bytearray(256)
        self.gs=bytearray(128)
        self.trace=[];self.consumed=[];self.inject={};self.obligations={'job':False,'future':False,'value':False}
        self.worker_state=worker_state;self.worker_bad=False;self.mismatch=False
        self.role={VALUE_FN:'value',JOBS_FN:'job',PUBLIC_FN:'future',CELL_FN:'cell',PROVIDER_FN:'provider'}
        self.mem={BCBASE:self.bc,WORKERBASE:self.worker,GOUTBASE:self.go,GCTXBASE:self.gw,GSBASE:self.gs}
        w=memoryview(self.bc)[:16384];o=memoryview(self.bc)[16384:]
        for at in (8,16,32,40,48,64,88,96,112,120,136,144,160,168,176,192,216,224,240,248,288,320,384,392):put(w,at,7000+at)
        for at,n in ((24,256),(56,1024),(104,512),(128,256),(152,4096),(184,256),(232,16384),(256,4096),(328,8192),(400,256)):
            put(w,at,n)
        for at,n in ((0,C['CONTEXT']),(8,VALUE_FN),(40,PROVIDER_FN),(112,JOBS_FN),(168,PUBLIC_FN),(384,CELL_FN),(456,PID),(376,1),(464,1),(480,2 if unknown else 1)):
            put(w,at,n)
        put(o,C['DROP_ACTIVE'],1);put(o,C['DROP_KNOWN'],1)
        put(o,C['OWNED_CURRENT'],int(owned))
        for at,value in zip((C['G_JOB'],C['G_META'],C['G_FUTURE'],C['RESULT']),CAP):cap(o,at,value)
        put(o,C['DRAIN_COUNT'],rows);put(o,C['DRAIN_READY'],int(bool(rows)))
        for row in range(rows):
            for slot in range(4):cap(o,C['ROWS']+row*128+slot*24,(1000+row*4+slot,3000+row*4+slot,5000+row*4+slot))
        for at,value in ((64,get(w,136)),(72,get(w,144)),(80,get(w,152)),(88,BUSINESS_FN),(96,BCBASE),(104,len(self.bc)),(112,1)):
            put(self.worker,at,value)
        for at,value in ((0,G['CONTEXT']),(8,BUSINESS_FN),(16,BCBASE),(24,len(self.bc)),(32,WORKER_FN),(40,WORKERBASE),(48,512),(56,PID)):
            put(self.gw,at,value)
        put(self.gs,0,G['INPUT'])
        self.borrowed=[] if owned else list(CAP[:3])

    def view(self,address,n):
        for base,buf in self.mem.items():
            if base<=address and n<=len(buf)-(address-base):
                return memoryview(buf)[address-base:address-base+n]
        raise AssertionError(('unmapped effect',hex(address),n))

    def run(self):
        put(self.go,G['PHASE'],0)
        self.drive(GE,'cleanup',self.gs,self.go,self.gw,GSBASE,GOUTBASE,GCTXBASE)
        return tuple(get(self.go,at)for at in (8,24,32))

    def drive(self,env,name,s,o,w,sbase,obase,wbase):
        for step in range(30000):
            actual=name
            if name=='business' and get(o,C['MODULE'])==1:
                env=BF;actual='business_failure'
            result=env[actual](s,o,w)
            if result==0:return
            if result==10:continue
            if result==4294967293:raise AssertionError(('private rejection',name,get(o,128)))
            bases=(0,wbase,sbase,obase)
            ret=0
            if result==1:
                mask=get(o,8);args=[]
                for i in range(6):args.append(get(o,16+i*8)+bases[(mask>>(2*i))&3])
                nr=get(o,0);self.trace.append(('syscall',nr,tuple(args)))
                if nr==39:ret=PID
                elif nr==202:
                    assert args[1]in(128,129)
                    if args[1]==128:raise AssertionError('single-thread model cannot satisfy blocked wait')
                else:raise AssertionError(('unexpected syscall',nr))
            elif result in (2,3):
                address=get(o,0);v=self.view(address,4);old=int.from_bytes(v,'little')
                assert address==BCBASE+496,'only the fixed cleanup mutex is atomic'
                if result==2:
                    if old==get(o,8):v[:]=get(o,16).to_bytes(4,'little')
                else:v[:]=get(o,8).to_bytes(4,'little')
                ret=old;self.trace.append(('atomic',result,old))
            elif result==8:
                a=get(o,0);b=get(o,16);assert a<4 and b<4
                src=get(o,8)+bases[a];dest=get(o,24)+bases[b];n=get(o,32)
                self.view(dest,n)[:]=bytes(self.view(src,n))
                self.trace.append(('copy',src,dest,n))
            elif result==9:
                mask=get(o,8);args=[]
                for i in range(6):args.append(get(o,16+i*8)+bases[(mask>>(2*i))&3])
                fn=get(o,0);self.invoke(fn,args)
            elif result==7:
                raise AssertionError('allocation-free cleanup cases must not own dynamic buffers')
            else:raise AssertionError(('unexpected action',result,name,get(o,128)))
            put(o,448,ret)
        raise AssertionError('source policy did not terminate')

    def invoke(self,fn,args):
        sp,sn,op,on,wp,wn=args
        s=bytes(self.view(sp,sn));o=self.view(op,on)
        magic=s[:8].decode();operation=get(s,8)
        self.trace.append(('call',fn,magic,operation))
        if fn==WORKER_FN:
            assert magic=='HIABGW03' and operation==3
            o[:128]=bytes(128);put(o,0,G['WORKER_REPLY']+int(self.worker_bad))
            put(o,24,self.worker_state)
            if self.mismatch:put(self.worker,96,BCBASE+8)
            return
        if fn==BUSINESS_FN:
            assert self.worker_state==4 and get(self.bc,496)==1 and get(self.bc,488)==1
            assert magic=='HIABGWQ3' and operation==3
            assert wp==BCBASE and wn==len(self.bc)
            internal=memoryview(self.bc)[16384:]
            put(internal,128,0);put(internal,C['MODULE'],0)
            self.drive(BE,'business',s,internal,memoryview(self.bc)[:16384],sp,BCBASE+16384,BCBASE)
            o[:128]=internal[:128]
            return
        role=self.role[fn]
        assert (role,operation)in{('value',29),('value',31),('job',11),('job',12),('future',26),('future',20),('cell',21),('provider',5)},(role,operation)
        o[:160]=bytes(160)
        target=readcap(s,40 if role=='future' else 24)
        queue=self.inject.get((role,operation,target))or self.inject.get((role,operation))
        fields=queue.pop(0)if queue else {}
        if role=='value':
            put(o,0,C['VALUE_DROP_REPLY']);put(o,88,1);put(o,96,int(operation==29))
        elif role=='job':
            put(o,0,C['JOB_DROP_REPLY']);put(o,136,1);put(o,128,int(operation==11))
        elif role=='future':
            put(o,0,C['PUBLIC_DROP_REPLY']if operation==26 else C['PUBLIC_REPLY'])
            if operation==26:put(o,96,1);put(o,104,1)
        elif role=='cell':
            put(o,0,C['CELL_QUERY_REPLY']);put(o,144,1)
        elif role=='provider':put(o,0,C['PROVIDER_REPLY'])
        for at,val in fields.items():put(o,at,val)
        consumed=(role=='value'and operation==29 and get(o,96)==1 and get(o,88)==1 and get(o,8)in(0,11))or(role=='job'and operation==11 and get(o,128)==1 and get(o,136)==1 and get(o,8)in(0,9))or(role=='future'and operation==26 and get(o,96)==1 and get(o,104)==1 and get(o,8)in(0,1))
        if consumed:
            assert target!=(0,0,0)
            assert (role,target)not in self.consumed,('nonce consumed twice',role,target)
            self.consumed.append((role,target))

rows=[]
def record(label,scenario,result,expected):
    assert result==expected,(label,result,expected)
    assert get(scenario.bc,496)==0 and get(scenario.bc,488)==0
    for borrowed in scenario.borrowed:
        assert all(cap!=borrowed for role,cap in scenario.consumed)
    rows.append({'label':label,'reply':result,'calls':sum(x[0]=='call'for x in scenario.trace),
                 'consumed_references':len(scenario.consumed),'business_effect_replayed':False})

s=Scenario();record('current owned references',s,s.run(),(0,4,0));assert len(s.consumed)==4
before=bytes(s.bc[16384:]);calls=len(s.trace);record('already clean repeated call',s,s.run(),(0,4,0));assert bytes(s.bc[16384:])==before
assert all(not(x[0]=='call'and x[1]==BUSINESS_FN)for x in s.trace[calls:])
s=Scenario(owned=False);record('borrowed submission references retained',s,s.run(),(0,4,0));assert len(s.consumed)==1
s=Scenario(owned=False,rows=9);record('nine transferred rows release only',s,s.run(),(0,4,0));assert len(s.consumed)==37

for state in (0,1,2,3,5):
    s=Scenario(worker_state=state);before=bytes(s.bc)
    record('actual worker state '+str(state)+' refuses internal output',s,s.run(),(6,state,0))
    assert bytes(s.bc)==before and not s.consumed
s=Scenario();s.worker_bad=True;before=bytes(s.bc);record('worker reply malformed',s,s.run(),(7,0,0));assert bytes(s.bc)==before
s=Scenario();s.mismatch=True;before=bytes(s.bc);record('worker belongs to different business context',s,s.run(),(6,4,0));assert bytes(s.bc)==before
s=Scenario(unknown=True);before=bytes(s.bc[16384:]);record('unknown business retirement never replayed',s,s.run(),(9,4,2));assert bytes(s.bc[16384:])==before

s=Scenario();s.inject[('value',29,CAP[1])]=[{8:1,96:0}]
record('pre-consumption value failure retained',s,s.run(),(9,4,1));record('only unconsumed value retried',s,s.run(),(0,4,0));assert len(s.consumed)==4
s=Scenario();s.inject[('value',29,CAP[1])]=[{8:11,80:1}]
s.inject[('value',31)]=[{8:11,80:1}]
record('consumed value mapping failure',s,s.run(),(9,4,1));record('mapping retry without cap replay',s,s.run(),(0,4,0));assert len(s.consumed)==4
s=Scenario();s.inject[('value',29,CAP[1])]=[{8:11}]
record('consumed value without retained mapping isolated',s,s.run(),(9,4,2));calls=len(s.trace)
record('unknown dependency is not a new drop request',s,s.run(),(9,4,2));assert not any(x[0]=='call'and x[1]==BUSINESS_FN for x in s.trace[calls:])
s=Scenario();s.inject[('future',26)]=[{8:1,16:107}];s.inject[('cell',21)]=[{136:1}]
record('consumed Future awaits actual retiring list',s,s.run(),(9,4,1));record('Future retry observes empty without repeated drop',s,s.run(),(0,4,0));assert len(s.consumed)==4
s=Scenario();s.inject[('job',11)]=[{8:9,144:1}];s.inject[('job',12)]=[{8:5,144:1}]
record('consumed Job still claimed for retirement',s,s.run(),(9,4,1));record('Job retirement retried without nonce',s,s.run(),(0,4,0));assert len(s.consumed)==4

for fields in ({8:999},{8:1,80:1,96:0},{8:0,80:1},{8:6,96:1}):
    s=Scenario();s.inject[('value',29,CAP[1])]=[fields]
    record('bad private value reply '+str(fields),s,s.run(),(9,4,2))
    assert readcap(memoryview(s.bc)[16384:],C['G_META'])==CAP[1]

report={'schema':'hepta.hia.background.business-cleanup.source-probes.v1',
        'passed':len(rows),'rows':rows,'native_execution':False,'real_pthread_exit_observed':False,
        'whole_background':False,'required_native_gates':['actual worker exit window and concurrent join',
        'actual reference before/after-consumption and mapping faults','concurrent cleanup calls and final lifecycle']}
(ROOT/'docs/HIA_BACKGROUND_NATIVE_BUSINESS_CLEANUP_SOURCE_PROBES.json').write_text(json.dumps(report,indent=2)+'\n')
print('business cleanup development-source traces',len(rows),'PASS; native and pthread gates pending')
