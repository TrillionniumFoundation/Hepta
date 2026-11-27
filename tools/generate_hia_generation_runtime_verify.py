"""Fresh verify_program for public Runtime and LLVM constructors.

The fixed enclosing owner captures the sole Value/payload arena and VFY roles.
A genuine VerifiedProgram class is detected through the real class catalog/MRO;
both actual fields are supplied to VFY4. Other actual Values use VFY3.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_value_freeze import SOURCE as HELPERS
ROOT=Path(__file__).resolve().parents[1]
C=dict(BAD=4294967293,MAX=(1<<64)-1,OUT=524288,WORK=8192,
 PHASE=128,OP=136,STATUS=144,DETAIL=152,QUAR=160,PENDING=168,
 VERIFIED=176,VERIFY_ACTIVE=184,CLEAN=192,FORMAT=200,RESULT_N=208,
 NORM_PTR=216,INPUT_N=224,CORE_N=232,PROFILE=240,DELIVERED=248,
 REFS=256,INPUT=256,CLASS=280,CANON=304,STRUCT=328,RESULT=352,
 RQ=4096,RP=8192,CHILD=65536,HEADER=49152,FEEDBACK=1024)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
 Q='HIARTVQ1',R='HIARTVR1',CTX='HIARTVC1',VQ='HIABVQ01',V5='HIABVQ05',V6='HIABVQ06',
 V11='HIABVQ11',VR='HIABVR01',VR2='HIABVR02',YQ='HIABVFY3',YV='HIABVFY4',
 YR='HIABVFR2',YC='HIABVYC2',PQ='HIABPY01',PR='HIABPYR1',NORM='HIAVCF01').items()})
SOURCE=r'''
def verify(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase==1:
        if get(o,FEEDBACK)!=get(w,144):
            return finish(o,w,6)
        put(o,0,0)
        put(o,PHASE,2)
        return 4
    if phase==2:
        pointer=get(o,FEEDBACK)
        if get(w,152)!=0 and get(w,168)!=pointer:
            return finish(o,w,6)
        put(w,168,pointer)
        if get(o,OP)==1:
            if get(w,152)==0:
                return finish(o,w,0)
            if get(w,160)!=1:
                put(o,QUAR,2)
                return finish(o,w,9)
            from_work(w,o,256,128,896)
            put(o,OP,1)
            put(o,QUAR,0)
            put(w,152,0)
            put(w,160,0)
            return again(o,100)
        if get(w,152)!=0:
            return finish(o,w,6)
        request(o,V5,91)
        copy_source(s,o,24,RQ+24,24)
        return value(o,w,3)
    if phase>=3 and phase<20:
        return prepare(s,o,w,phase)
    if phase>=20 and phase<40:
        return verified(o,w,phase)
    return cleanup(o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or length(o)<OUT or length(w)!=WORK or word_load(s,0)!=Q or word_load(s,8)>1:
        return BAD
    at=16
    while at<128:
        if word_load(s,8)!=0 or at<24 or at>40:
            if word_load(s,at)!=0:
                return BAD
        at=at+8
    if word_load(s,8)==0 and word_load(s,24)==0:
        return BAD
    if get(w,0)!=CTX or get(w,8)==0 or get(w,16)==0 or get(w,24)!=256:
        return BAD
    if get(w,32)==0 or get(w,40)==0 or get(w,48)==0 or get(w,56)!=256:
        return BAD
    if get(w,64)<3 or get(w,64)>2147483647 or get(w,72)==0 or get(w,80)!=10100891:
        return BAD
    if (get(w,88)!=0 and get(w,88)<640) or get(w,88)>2147483647 or get(w,152)>1 or get(w,160)>2:
        return BAD
    at=96
    while at<=136:
        if get(w,at)==0:
            return BAD
        at=at+8
    if get(w,176)==0:
        return BAD
    at=184
    while at<256:
        if get(w,at)!=0:
            return BAD
        at=at+8
    zero(o,128,896)
    put(o,OP,word_load(s,8))
    return system(o,1,39,0,0,0,0,0,0,0)

def prepare(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==3:
        if get(o,FEEDBACK)!=0 or get(o,RP)!=VR or get(o,RP+120)!=1 or get(o,RP+88)!=1:
            return isolate(o,w,2,3)
        if get(o,RP+96)==1:
            if get(o,RP+24)==0:
                return isolate(o,w,2,4)
            within(o,INPUT,RP+24,24)
        elif get(o,RP+96)!=0 or get(o,RP+24)!=0:
            return isolate(o,w,2,5)
        if get(o,RP+112)!=0:
            put(o,PENDING,1)
        if get(o,RP+104)!=0:
            return isolate(o,w,1,get(o,RP+8))
        if get(o,INPUT)==0:
            return failed(o,choose(get(o,RP+8)==5,5,7),get(o,RP+8))
        request(o,V11,57)
        put(o,RQ+104,36)
        return value(o,w,4)
    if phase==4:
        if okay(o)==False or get(o,RP+24)==0:
            return dependency(o)
        within(o,CLASS,RP+24,24)
        request(o,V6,37)
        within(o,RQ+24,INPUT,24)
        within(o,RQ+48,CLASS,24)
        return value(o,w,5)
    if phase==5:
        if okay(o)==False or get(o,RP+48)>1:
            return dependency(o)
        if get(o,RP+48)==0:
            return configure(o,w)
        put(o,VERIFIED,1)
        request(o,V11,43)
        within(o,RQ+24,INPUT,24)
        return value(o,w,6)
    if phase==6:
        if okay(o)==False or get(o,RP+24)==0:
            return dependency(o)
        within(o,CANON,RP+24,24)
        request(o,V11,43)
        within(o,RQ+24,INPUT,24)
        put(o,RQ+104,1)
        return value(o,w,7)
    if phase==7:
        if okay(o)==False or get(o,RP+24)==0:
            return dependency(o)
        within(o,STRUCT,RP+24,24)
        return configure(o,w)
    return failed(o,7,phase)

def configure(o:mutbuf,w:mutbuf) -> u32:
    zero(w,4096,4096)
    put(w,4096,YC)
    put(w,4104,get(w,8))
    put(w,4112,get(w,16))
    put(w,4120,get(w,24))
    put(w,4128,get(w,96))
    put(w,4136,get(w,104))
    put(w,4144,get(w,112))
    put(w,4152,get(w,40))
    put(w,4160,get(w,48))
    put(w,4168,get(w,56))
    put(w,4176,get(w,88))
    put(w,4184,get(w,64))
    put(w,4192,get(w,72))
    put(w,4200,get(w,80))
    put(w,4208,get(w,120))
    put(w,4216,get(w,128))
    put(w,4224,get(w,136))
    put(w,4232,get(w,176))
    request(o,choose(get(o,VERIFIED)==0,YQ,YV),0)
    if get(o,VERIFIED)==0:
        within(o,RQ+24,INPUT,24)
    else:
        within(o,RQ+24,CANON,24)
        within(o,RQ+48,STRUCT,24)
    put(o,VERIFY_ACTIVE,2)
    return invoke(o,20,get(w,32),307,RQ,128,CHILD,262144,4096,4096)

def verified(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==20 or phase==25:
        if get(o,FEEDBACK)!=0 or get(o,CHILD)!=YR:
            return isolate(o,w,2,20)
        if get(o,CHILD+56)>1 or get(o,CHILD+64)>2 or get(o,CHILD+72)>1:
            return isolate(o,w,2,21)
        if get(o,CHILD+56)!=0:
            put(o,VERIFY_ACTIVE,1)
            return isolate(o,w,choose(get(o,CHILD+64)==1,1,2),get(o,CHILD+48))
        if get(o,CHILD+64)!=0 or get(o,CHILD+72)!=0:
            return isolate(o,w,2,22)
        put(o,VERIFY_ACTIVE,0)
        status=get(o,CHILD+8)
        if status<=2 and get(o,CHILD+16)!=0:
            if get(o,RESULT)!=0:
                return isolate(o,w,2,23)
            within(o,RESULT,CHILD+16,24)
            put(o,RESULT_N,get(o,CHILD+40))
            put(o,FORMAT,status)
            put(o,DELIVERED,1)
        if phase==25 or get(o,OP)==1:
            return again(o,100)
        if status!=0:
            return failed(o,choose(status<=2,1,status),get(o,CHILD+48))
        if get(o,RESULT)==0 or get(o,RESULT_N)<64:
            return failed(o,7,24)
        request(o,PQ,6)
        within(o,RQ+24,RESULT,24)
        return payload(o,w,21)
    if phase==21:
        if get(o,FEEDBACK)!=0 or get(o,RP)!=PR or get(o,RP+8)!=0 or get(o,RP+40)!=get(o,RESULT_N) or get(o,RP+64)==0:
            return failed(o,7,25)
        put(o,NORM_PTR,get(o,RP+64))
        return memory(o,22,0,get(o,NORM_PTR),3,HEADER,64)
    if phase==22:
        on=get(o,HEADER+32)
        cn=get(o,HEADER+40)
        if get(o,HEADER)!=NORM or get(o,HEADER+8)!=0 or get(o,HEADER+16)!=0 or get(o,HEADER+24)>4 or get(o,HEADER+48)!=0 or get(o,HEADER+56)!=0:
            return failed(o,7,26)
        if on==0 or cn==0 or on>8388608 or cn>8388608 or on>get(o,RESULT_N)-64 or cn!=get(o,RESULT_N)-64-on:
            return failed(o,7,27)
        put(o,INPUT_N,on)
        put(o,CORE_N,cn)
        put(o,PROFILE,get(o,HEADER+24))
        return again(o,100)
    return failed(o,7,phase)

def cleanup(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if get(o,VERIFY_ACTIVE)!=0:
            if get(o,VERIFY_ACTIVE)!=1:
                return isolate(o,w,2,100)
            request(o,choose(get(o,VERIFIED)==0,YQ,YV),1)
            return invoke(o,25,get(w,32),307,RQ,128,CHILD,262144,4096,4096)
        i=get(o,CLEAN)
        if i==4:
            put(w,152,0)
            put(w,160,0)
            return finish(o,w,get(o,STATUS))
        if get(o,REFS+i*24)==0:
            put(o,CLEAN,i+1)
            return again(o,100)
        request(o,V5,78)
        within(o,RQ+24,REFS+i*24,24)
        return value(o,w,101)
    if phase==101:
        if get(o,FEEDBACK)!=0 or get(o,RP)!=VR2 or get(o,RP+88)!=1 or get(o,RP+96)>1 or get(o,RP+80)>1 or get(o,RP+120)!=1:
            return isolate(o,w,2,101)
        if get(o,RP+96)==1:
            zero(o,REFS+get(o,CLEAN)*24,24)
        if get(o,RP+112)!=0:
            put(o,PENDING,1)
        if get(o,RP+104)!=0 or get(o,RP+96)==0:
            return isolate(o,w,1,get(o,RP+8))
        if get(o,RP+8)!=0 and get(o,RP+8)!=11:
            return isolate(o,w,2,102)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,100)
    return isolate(o,w,2,phase)

def finish(o:mutbuf,w:mutbuf,status:u64) -> u32:
    # Save fields before constructing the public 128-byte result.
    zero(o,0,128)
    put(o,0,R)
    put(o,8,status)
    put(o,16,get(o,FORMAT))
    put(o,80,get(o,QUAR))
    put(o,88,choose(get(o,QUAR)==2,0,1))
    put(o,96,get(o,PENDING))
    put(o,120,get(o,DETAIL))
    if get(o,RESULT)!=0:
        within(o,24,RESULT,24)
        put(o,48,get(o,RESULT_N))
        put(o,56,get(o,PROFILE))
        put(o,64,get(o,CORE_N))
        put(o,72,get(o,INPUT_N))
        if get(o,STATUS)==0 and get(o,NORM_PTR)!=0:
            put(o,104,get(o,NORM_PTR)+64+get(o,INPUT_N))
            put(o,112,get(o,NORM_PTR)+64)
        zero(o,RESULT,24)
        if get(w,152)!=0:
            zero(w,480,24)
    return 0
def failed(o:mutbuf,status:u64,detail:u64) -> u32:
    put(o,STATUS,status)
    put(o,DETAIL,detail)
    return again(o,100)
def dependency(o:mutbuf) -> u32:
    if get(o,FEEDBACK)!=0 or get(o,RP)!=VR:
        return failed(o,7,get(o,FEEDBACK))
    return failed(o,choose(get(o,RP+8)==5,5,7),get(o,RP+8))
def isolate(o:mutbuf,w:mutbuf,kind:u64,detail:u64) -> u32:
    put(o,QUAR,kind)
    put(o,DETAIL,detail)
    to_work(o,w,128,256,896)
    put(w,152,1)
    put(w,160,kind)
    return finish(o,w,9)
def okay(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,RP)==VR and get(o,RP+8)==0
def value(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,8),51,RQ,128,RP,16384,get(w,16),get(w,24))
def payload(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,40),51,RQ,128,RP,512,get(w,48),get(w,56))
'''
def source_program():
    names={'request','invoke','system','again','copy_source','within','zero','get','put','to_work','from_work','choose','memory'}
    text=SOURCE+'\n'+'\n'.join(ast.unparse(f)for f in ast.parse(HELPERS).body if isinstance(f,ast.FunctionDef)and f.name in names)
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def main():
    tree=document(source_program(),'generation_runtime_verify')
    p=ROOT/'examples/hia_bootstrap/generation_runtime_verify.hepta'
    p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
