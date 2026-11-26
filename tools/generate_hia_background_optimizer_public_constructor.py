"""Ordered native public BackgroundOptimizer constructor segment.

The enclosing BG owner supplies fixed dependency contexts. Request fields are
actual Value capabilities only. Runtime private capture occurs only after
native verification and scalar function selection, through provider Q2.
"""
from pathlib import Path
import ast,json,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_value_freeze import SOURCE as HELPERS
from tools import hia_background_retirement_source as retirement
ROOT=Path(__file__).resolve().parents[1]
C=dict(BAD=4294967293,MAX=(1<<64)-1,OUT=524288,WORK=294912,
 PHASE=256,ERROR=264,DETAIL=272,OP=280,SUCCESS=288,ERROR_FORMAT=296,ERROR_N=304,
 MAXP=312,TIMEOUT=320,BTIME=328,BINT=336,CLEAN=344,CHILD_ACTIVE=352,
 DROP_ACTIVE=360,DROP_KNOWN=368,VALUE_PENDING=376,CLEAN_AT=384,
 CLASS=512,RUNTIME_VALUE=536,BRIDGE=560,BASELINE=584,RUNTIME=608,FUNCTION=632,
 ERROR_VALUE=656,ERROR_PAYLOAD=680,BASE_N=704,CORE_SHA=736,INPUT_SHA=768,
 FEEDBACK=3840,RQ=65536,RP=98304,CHILD=262144,SAVE=288768,
 OPTIONS_WORK=512,PATHS_WORK=4096,BIND_WORK=270336)
C.update(retirement.MAGICS)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
 MAGIC='HIABPCQ1',REPLY='HIABPCR1',CONTEXT='HIABPCC1',
 VQ='HIABVQ01',VQ3='HIABVQ03',VR='HIABVR01',
 OPTIONS='HIABOPQ1',OPTIONS_REPLY='HIABOPR1',OPTIONS_CONTEXT='HIABOPC1',
 PATHS='HIABBPQ2',PATHS_REPLY='HIABBPR1',PATHS_CONTEXT='HIABBPC2',
 BINDING='HIABCBQ3',BIND_REPLY='HIABCBR1',BIND_CONTEXT='HIABCBX1',
 PAYLOAD='HIABPY01',PAYLOAD_REPLY='HIABPYR1',PROVIDER='HIAMVBQ1',PROVIDER_REPLY='HIAMVBO1').items()})
SOURCE=r'''
def public_constructor(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT or length(w)<WORK:
        return BAD
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<10:
        return enter(s,o,w,phase)
    if phase<20:
        return runtime_type(s,o,w,phase)
    if phase<30:
        return options(s,o,w,phase)
    if phase<40:
        return paths(s,o,w,phase)
    if phase<50:
        return binding(s,o,w,phase)
    return cleanup(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=192 or word_load(s,0)!=MAGIC or word_load(s,8)>1 or word_load(s,16)!=0:
        return BAD
    if word_load(s,8)==1:
        at=24
        while at<192:
            if word_load(s,at)!=0:
                return BAD
            at=at+8
    if get(w,0)!=CONTEXT or get(w,8)==0 or get(w,16)==0 or get(w,24)<256 or get(w,16)>MAX-get(w,24):
        return BAD
    at=32
    while at<=96:
        if get(w,at)==0:
            return BAD
        at=at+8
    if get(w,104)==0 or get(w,112)<256 or get(w,104)>MAX-get(w,112):
        return BAD
    if get(w,120)==0 or get(w,128)==0 or get(w,136)<768 or get(w,128)>MAX-get(w,136):
        return BAD
    if get(w,144)==0 or get(w,152)==0 or get(w,160)<3 or get(w,160)>2147483647 or get(w,168)==0 or get(w,176)!=10100891:
        return BAD
    at=184
    while at<=224:
        if get(w,at)==0:
            return BAD
        at=at+8
    if (get(w,232)!=0 and get(w,232)<640) or get(w,232)>2147483647 or get(w,240)<2 or get(w,248)>2:
        return BAD
    if get(w,264)==0:
        return BAD
    at=272
    while at<512:
        if get(w,at)!=0:
            return BAD
        at=at+8
    zero(o,256,1792)
    put(o,OP,word_load(s,8))
    return system(o,1,39,0,0,0,0,0,0,0)

def enter(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        if get(o,FEEDBACK)!=get(w,240):
            return finish(o,w,6)
        put(o,0,0)
        put(o,PHASE,2)
        return 4
    if phase==2:
        address=get(o,FEEDBACK)
        if address==0 or (get(w,248)!=0 and get(w,256)!=address):
            return finish(o,w,6)
        if get(o,OP)==1:
            if get(w,248)==0:
                return finish(o,w,0)
            if get(w,248)!=1:
                return finish(o,w,9)
            from_work(w,o,SAVE,256,1792)
            put(o,OP,1)
            put(w,248,0)
            put(o,SUCCESS,0)
            put(o,CLEAN,0)
            return again(o,1000)
        if get(w,248)!=0:
            return finish(o,w,6)
        put(w,256,address)
        configure(w)
        request(o,VQ3,32)
        put(o,RQ+104,20)
        return value(o,w,10,128)
    return fail(o,7,phase)

def runtime_type(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==10:
        if take(o,CLASS)==False:
            return value_failure(o)
        request(o,VQ3,37)
        copy_source(s,o,24,RQ+24,24)
        within(o,RQ+48,CLASS,24)
        return value(o,w,11,128)
    if phase==11:
        if value_ok(o)==False or get(o,RP+48)>1:
            return value_failure(o)
        if get(o,RP+48)==0:
            put(o,ERROR,1)
            put(o,ERROR_FORMAT,4)
            request(o,VQ,1)
            n=runtime_error(o,RQ+128)
            put(o,RQ+96,n)
            return value(o,w,12,128+n)
        request(o,VQ,5)
        copy_source(s,o,24,RQ+24,24)
        return value(o,w,13,128)
    if phase==12:
        if take(o,ERROR_VALUE)==False:
            return value_failure(o)
        return again(o,1000)
    if phase==13:
        if take(o,RUNTIME_VALUE)==False:
            return value_failure(o)
        request(o,OPTIONS,0)
        copy_source(s,o,120,RQ+24,72)
        copy_source(s,o,96,RQ+96,24)
        put(o,CHILD_ACTIVE,1)
        return child(o,w,20,1)
    return fail(o,7,phase)

def options(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==20:
        if valid(o,CHILD,OPTIONS_REPLY)==0:
            return quarantine(o,w,2,20)
        if get(o,CHILD+136)!=0:
            return quarantine(o,w,choose(get(o,CHILD+136)==1,1,2),20)
        put(o,CHILD_ACTIVE,0)
        status=get(o,CHILD+8)
        if status==1:
            n=get(o,CHILD+128)
            if n==0 or n>32768-192:
                return quarantine(o,w,2,20)
            put(o,ERROR,1)
            put(o,ERROR_FORMAT,4)
            request(o,VQ,1)
            put(o,RQ+96,n)
            within(o,RQ+128,CHILD+192,n)
            return value(o,w,21,128+n)
        if status!=0 or get(o,CHILD+16)!=1:
            return fail(o,choose(status==5,5,7),status)
        put(o,MAXP,get(o,CHILD+24))
        put(o,TIMEOUT,get(o,CHILD+32))
        put(o,BTIME,get(o,CHILD+40))
        put(o,BINT,get(o,CHILD+48))
        request(o,PATHS,0)
        copy_source(s,o,96,RQ+16,24)
        put(o,CHILD_ACTIVE,2)
        return child(o,w,30,2)
    if phase==21:
        if take(o,ERROR_VALUE)==False:
            return value_failure(o)
        return again(o,1000)
    return fail(o,7,phase)

def paths(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==30:
        if valid(o,CHILD,PATHS_REPLY)==0:
            return quarantine(o,w,2,30)
        if get(o,CHILD+88)!=0:
            return quarantine(o,w,choose(get(o,CHILD+88)==1,1,2),30)
        put(o,CHILD_ACTIVE,0)
        status=get(o,CHILD+8)
        if status==1 or status==2:
            at=choose(status==1,40,64)
            if get(o,CHILD+at)==0:
                return quarantine(o,w,2,30)
            within(o,ERROR_VALUE,CHILD+at,24)
            put(o,ERROR,status)
            put(o,ERROR_FORMAT,choose(status==1,4,5))
            return again(o,1000)
        if status!=0 or get(o,CHILD+104)!=1 or get(o,CHILD+16)==0:
            return fail(o,choose(status==5,5,7),status)
        within(o,BRIDGE,CHILD+16,24)
        request(o,BINDING,0)
        copy_source(s,o,48,RQ+24,48)
        within(o,RQ+72,RUNTIME_VALUE,24)
        put(o,CHILD_ACTIVE,3)
        return child(o,w,40,3)
    return fail(o,7,phase)

def binding(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==40:
        if valid(o,CHILD,BIND_REPLY)==0:
            return quarantine(o,w,2,40)
        if get(o,CHILD+208)!=0:
            return quarantine(o,w,choose(get(w,BIND_WORK+208)==1,1,2),40)
        put(o,CHILD_ACTIVE,0)
        status=get(o,CHILD+8)
        if status==1:
            if get(o,CHILD+96)==0 or get(o,CHILD+120)==0 or get(o,CHILD+128)<1 or get(o,CHILD+128)>3:
                return quarantine(o,w,2,40)
            within(o,ERROR_PAYLOAD,CHILD+96,24)
            put(o,ERROR_N,get(o,CHILD+120))
            put(o,ERROR_FORMAT,get(o,CHILD+128))
            put(o,ERROR,1)
            return again(o,1000)
        if status!=0 or get(o,CHILD+16)==0 or get(o,CHILD+40)==0 or get(o,CHILD+48)==0 or get(o,CHILD+72)==0:
            return fail(o,choose(status==5,5,7),status)
        within(o,BASELINE,CHILD+16,24)
        put(o,BASE_N,get(o,CHILD+40))
        within(o,RUNTIME,CHILD+48,24)
        within(o,FUNCTION,CHILD+72,24)
        within(o,CORE_SHA,CHILD+144,64)
        put(o,SUCCESS,1)
        return again(o,1000)
    return fail(o,7,phase)

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1000:
        if get(o,DROP_ACTIVE)!=0 and get(o,DROP_KNOWN)!=1:
            return quarantine(o,w,2,1000)
        kind=get(o,CHILD_ACTIVE)
        if kind!=0:
            if kind>3:
                return quarantine(o,w,2,1000)
            request(o,choose(kind==1,OPTIONS,choose(kind==2,PATHS,BINDING)),1)
            return child(o,w,1001,kind)
        return again(o,1010)
    if phase==1001:
        kind=get(o,CHILD_ACTIVE)
        magic=choose(kind==1,OPTIONS_REPLY,choose(kind==2,PATHS_REPLY,BIND_REPLY))
        if valid(o,CHILD,magic)==0:
            return quarantine(o,w,2,1001)
        pending=get(o,CHILD+choose(kind==1,136,choose(kind==2,88,208)))
        if pending!=0:
            return quarantine(o,w,choose(pending==1,1,2),1001)
        if harvest(o,kind)==False:
            return quarantine(o,w,2,1001)
        put(o,CHILD_ACTIVE,0)
        return again(o,1010)
    if phase==1010:
        i=get(o,CLEAN)
        if i==8:
            if get(o,VALUE_PENDING)!=0:
                release_begin(o)
                request(o,VALUE_DROP_INPUT,31)
                return value(o,w,1030,128)
            return finish(o,w,get(o,ERROR))
        at=CLASS+i*24
        keep=get(o,SUCCESS)==1 and get(o,ERROR)==0 and i>=1 and i<=5
        if (get(o,ERROR)==1 or get(o,ERROR)==2) and i>=6:
            keep=True
        if get(o,at)==0 or keep:
            put(o,CLEAN,i+1)
            return again(o,1010)
        put(o,CLEAN_AT,at)
        if i==3 or i==7:
            request(o,PAYLOAD,3)
            within(o,RQ+24,at,24)
            return invoke(o,1021,get(w,96),51,RQ,128,RP,512,get(w,104),get(w,112))
        if i==4:
            request(o,PROVIDER,4)
            within(o,RQ+16,at,24)
            return invoke(o,1022,get(w,120),51,RQ,128,RP,128,get(w,128),get(w,136))
        release_begin(o)
        request(o,VALUE_DROP_INPUT,29)
        within(o,RQ+24,at,24)
        return value(o,w,1020,128)
    if phase==1020:
        if release_value(o,get(o,CLEAN_AT))==0:
            return quarantine(o,w,choose(get(o,DROP_KNOWN)==1,1,2),1020)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,1010)
    if phase==1021:
        if valid(o,RP,PAYLOAD_REPLY)==0:
            return quarantine(o,w,2,1021)
        status=get(o,RP+8)
        if status!=0:
            kind=2
            if status==1 or status==5 or status==6:
                kind=1
            return quarantine(o,w,kind,1021)
        zero(o,get(o,CLEAN_AT),24)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,1010)
    if phase==1022:
        if provider_ack(o)==False:
            return quarantine(o,w,2,1022)
        zero(o,get(o,CLEAN_AT),24)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,1010)
    if phase==1030:
        if release_value_retry(o)==0:
            return quarantine(o,w,choose(get(o,DROP_KNOWN)==1,1,2),1030)
        return finish(o,w,get(o,ERROR))
    return quarantine(o,w,2,phase)

def harvest(o:mutbuf,kind:u64) -> bool:
    status=get(o,CHILD+8)
    if kind==2:
        if status==0 and get(o,CHILD+104)==1:
            return capture(o,BRIDGE,CHILD+16)
        if status==1 or status==2:
            return capture(o,ERROR_VALUE,CHILD+choose(status==1,40,64))
    if kind==3:
        if status==0 and get(o,CHILD+16)!=0:
            if capture(o,BASELINE,CHILD+16)==False:
                return False
            if capture(o,RUNTIME,CHILD+48)==False:
                return False
            return capture(o,FUNCTION,CHILD+72)
        if status==1:
            return capture(o,ERROR_PAYLOAD,CHILD+96)
    return True

def capture(o:mutbuf,dest:u64,source:u64) -> bool:
    if get(o,dest)!=0 or get(o,source)==0:
        return False
    within(o,dest,source,24)
    return True
def configure(w:mutbuf) -> u64:
    zero(w,OPTIONS_WORK,2048)
    put(w,OPTIONS_WORK,OPTIONS_CONTEXT)
    copy_work(w,OPTIONS_WORK+8,8,24)
    put(w,OPTIONS_WORK+32,get(w,240))
    zero(w,PATHS_WORK,262144)
    put(w,PATHS_WORK,PATHS_CONTEXT)
    copy_work(w,PATHS_WORK+8,8,24)
    put(w,PATHS_WORK+32,get(w,56))
    put(w,PATHS_WORK+40,get(w,64))
    put(w,PATHS_WORK+48,get(w,72))
    put(w,PATHS_WORK+56,get(w,240))
    put(w,PATHS_WORK+72,get(w,80))
    put(w,PATHS_WORK+80,get(w,264))
    zero(w,BIND_WORK,16384)
    put(w,BIND_WORK,BIND_CONTEXT)
    copy_work(w,BIND_WORK+8,8,24)
    put(w,BIND_WORK+32,get(w,88))
    copy_work(w,BIND_WORK+40,96,24)
    copy_work(w,BIND_WORK+64,120,24)
    put(w,BIND_WORK+88,get(w,144))
    put(w,BIND_WORK+96,get(w,152))
    put(w,BIND_WORK+104,get(w,160))
    put(w,BIND_WORK+112,get(w,168))
    put(w,BIND_WORK+120,get(w,176))
    put(w,BIND_WORK+128,get(w,184))
    put(w,BIND_WORK+136,get(w,192))
    put(w,BIND_WORK+144,get(w,200))
    put(w,BIND_WORK+152,get(w,208))
    put(w,BIND_WORK+160,get(w,216))
    put(w,BIND_WORK+168,get(w,224))
    put(w,BIND_WORK+176,get(w,232))
    put(w,BIND_WORK+184,get(w,240))
    return 0
def copy_work(w:mutbuf,dest:u64,source:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,dest+i,byte(w,source+i))
        i=i+1
    return 0
def child(o:mutbuf,w:mutbuf,next:u64,kind:u64) -> u32:
    fn=choose(kind==1,32,choose(kind==2,40,48))
    ctx=choose(kind==1,OPTIONS_WORK,choose(kind==2,PATHS_WORK,BIND_WORK))
    extent=choose(kind==1,2048,choose(kind==2,262144,16384))
    return invoke(o,next,get(w,fn),307,RQ,128,CHILD,choose(kind==1,32768,262144),ctx,extent)
def value(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return invoke(o,next,get(w,8),51,RQ,n,RP,16384,get(w,16),get(w,24))
def valid(o:mutbuf,at:u64,magic:u64) -> u64:
    return choose(get(o,FEEDBACK)==0 and get(o,at)==magic,1,0)
def value_ok(o:mutbuf) -> bool:
    return valid(o,RP,VR)!=0 and get(o,RP+8)==0
def take(o:mutbuf,at:u64) -> bool:
    if value_ok(o)==False or get(o,RP+24)==0 or get(o,at)!=0:
        return False
    within(o,at,RP+24,24)
    return True
def value_failure(o:mutbuf) -> u32:
    status=7
    if valid(o,RP,VR)!=0 and get(o,RP+8)==5:
        status=5
    return fail(o,status,get(o,RP+8))
def provider_ack(o:mutbuf) -> bool:
    if valid(o,RP,PROVIDER_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+16)!=4:
        return False
    at=24
    while at<128:
        if get(o,RP+at)!=0:
            return False
        at=at+8
    return True
def fail(o:mutbuf,status:u64,detail:u64) -> u32:
    put(o,ERROR,status)
    put(o,DETAIL,detail)
    put(o,SUCCESS,0)
    put(o,CLEAN,0)
    return again(o,1000)
def quarantine(o:mutbuf,w:mutbuf,kind:u64,detail:u64) -> u32:
    if get(o,ERROR)==0:
        put(o,ERROR,7)
    put(o,SUCCESS,0)
    put(o,DETAIL,detail)
    to_work(o,w,256,SAVE,1792)
    put(w,248,kind)
    return finish(o,w,9)
def finish(o:mutbuf,w:mutbuf,status:u64) -> u32:
    zero(o,0,256)
    put(o,0,REPLY)
    put(o,8,status)
    if status==0 and get(o,SUCCESS)==1:
        within(o,16,BASELINE,24)
        put(o,40,get(o,BASE_N))
        within(o,48,RUNTIME,24)
        within(o,72,FUNCTION,24)
        within(o,96,BRIDGE,24)
        within(o,120,RUNTIME_VALUE,24)
        put(o,144,get(o,MAXP))
        put(o,152,get(o,TIMEOUT))
        put(o,160,get(o,BTIME))
        put(o,168,get(o,BINT))
        within(o,176,CORE_SHA,64)
        zero(o,RUNTIME_VALUE,120)
    elif status==1 or status==2:
        within(o,16,ERROR_PAYLOAD,24)
        put(o,40,get(o,ERROR_N))
        put(o,48,get(o,ERROR_FORMAT))
        within(o,72,ERROR_VALUE,24)
        zero(o,ERROR_VALUE,48)
    put(o,240,get(w,248))
    put(o,248,get(o,DETAIL))
    return 0
'''
def source_program():
 names={'request','invoke','system','again','to_work','from_work','copy_source','within','zero','get','put','choose'}
 helpers='\n'.join(ast.unparse(f)for f in ast.parse(HELPERS).body if isinstance(f,ast.FunctionDef)and f.name in names)
 text=SOURCE+'\n'+helpers+'\n'+retirement.selected('release_begin','release_value','release_value_retry')
 raw=json.dumps({'class':'BackgroundOptimizationRejected','message':'E_HIA_BACKGROUND: a ScalarMultiversionRuntime is required'},sort_keys=True,separators=(',',':')).encode()
 text+='\ndef runtime_error(o:mutbuf,at:u64) -> u64:\n'
 for at in range(0,len(raw),8):text+=f'    put(o,at+{at},{int.from_bytes(raw[at:at+8].ljust(8,bytes(1)),"little")})\n'
 text+=f'    return {len(raw)}\n'
 for name,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+name+r'\b',str(value),text)
 return text
def program():return document(source_program(),'background_optimizer_public_constructor')
def main():
 d=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_public_constructor.hepta';p.write_text(render_assembly(d))
 print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
