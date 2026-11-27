"""Native constructor-context binding to the single installed Runtime owner.

The bind entry receives the actual root as its six-word work argument, captures
all dependency entry addresses mechanically, and owns a true Value context token
and installed-resource borrow until its explicit retirement succeeds.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
C=dict(BAD=4294967293,MAX=(1<<64)-1,SIZE=1048576,PH=256,FB=264,OP=272,
 SELF=512,FRONT=520,ROOT_ENTRY=528,VALUE=536,GLOBAL=544,VFY=552,
 TRANSPORT=560,JSON=568,PROCESS=576,TYPED=584,FREEZE=592,RAW=600,FREEZERAW=608,
 RQ=32768,CHILD=262144,RESULT=1024)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
 Q='HIARTBQ1',R='HIARTBR1',CTX='HIARTFC1',ROOT='HIAGLOW1',PROVIDER='HIAGPCX1',
 OPTIONS='HIARTOC1',VERIFY='HIARTVC1',V6='HIABVQ06',V5='HIABVQ05',
 VR='HIABVR01',VR2='HIABVR02',GQ='HIAGGIQ1',GR='HIAGGIR1').items()})
SOURCE=r'''
def bind(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PH)
    r=get(o,FB)
    if phase==0:
        if length(s)!=128 or length(o)!=SIZE or length(w)!=2048 or word(s,0)!=Q or word(s,8)>1:
            return BAD
        at=16
        while at<128:
            if word(s,at)!=0:
                return BAD
            at=at+8
        put(o,OP,word(s,8))
        return system(o,1,39,0,0,0,0,0,0,0)
    if phase==1:
        if r==0 or r>=MAX-4094 or get(w,0)!=ROOT or get(w,8)!=r or get(w,16)!=get(o,SELF):
            return BAD
        if get(w,24)!=get(o,ROOT_ENTRY) or get(w,40)!=get(o,VALUE) or get(w,48)!=get(o,SELF)+512 or get(w,56)!=256 or get(w,80)!=1:
            return BAD
        if get(o,OP)==0:
            at=0
            while at<256:
                if get(o,at)!=0:
                    return BAD
                at=at+8
            if get(w,1088)==0 or get(w,1096)!=8388608 or get(w,112)!=1:
                return BAD
            if get(w,1280)!=PROVIDER or get(w,1288)!=r or get(w,1296)!=1 or get(w,1320)!=get(o,SELF) or get(w,1328)!=get(o,SELF)+1280:
                return BAD
            if get(w,1360)!=get(o,VALUE) or get(w,1368)!=get(o,SELF)+512 or get(w,1376)!=256:
                return BAD
            if get(w,1384)==0 or get(w,1392)!=get(o,SELF)+1792 or get(w,1400)!=256 or get(w,1408)!=get(w,664):
                return BAD
            put(o,0,CTX)
            put(o,8,r)
            put(o,16,get(o,FRONT))
            put(o,24,get(o,SELF))
            put(o,32,get(o,VALUE))
            put(o,40,get(o,SELF)+512)
            put(o,48,256)
            put(o,56,get(o,GLOBAL))
            put(o,128,2)
            put(o,120,1)
            put(o,160,get(w,664))
            put(o,240,get(o,ROOT_ENTRY))
            put(o,PH,4)
            return 2
        if get(o,0)!=CTX or get(o,8)!=r or get(o,16)!=get(o,FRONT) or get(o,24)!=get(o,SELF) or get(o,32)!=get(o,VALUE) or get(o,40)!=get(o,SELF)+512 or get(o,48)!=256 or get(o,56)!=get(o,GLOBAL) or get(o,160)!=get(w,664):
            return BAD
        if get(o,128)==3:
            return done(o,0,1)
        if get(o,128)==4:
            return done(o,9,0)
        if get(o,4136)!=0 or get(o,16536)!=0:
            return pending(o,6,24)
        put(o,128,2)
        return closing(o)
    if phase==4 or phase==30:
        if r==0:
            if phase==30:
                if get(o,248)!=1 or get(w,72)==0:
                    put(o,PH,33)
                    return 3
                put(w,72,get(w,72)-1)
                put(o,248,0)
                put(o,PH,32)
                return 3
            if get(w,80)!=1 or get(w,72)==MAX or get(w,1088)==0 or get(w,1296)!=1:
                put(o,136,6)
                put(o,PH,7)
                return 3
            put(w,72,get(w,72)+1)
            put(o,248,1)
            put(o,PH,6)
            return 3
        if r!=1:
            if get(o,248)==0:
                put(o,128,3)
                return done(o,1,1)
            return pending(o,1,r)
        put(o,1536,0)
        put(o,1544,10000000)
        put(o,1552,phase)
        return system(o,5,202,193,64,128,1,1536,0,0)
    if phase==5:
        if r>=MAX-4094 and r!=MAX-3 and r!=MAX-10 and r!=MAX-109:
            if get(o,248)==0:
                put(o,128,3)
                return done(o,1,1)
            return pending(o,1,r)
        put(o,PH,get(o,1552))
        return 2
    if phase==6:
        request(o,V6,21)
        return value(o,2)
    if phase==7:
        put(o,128,3)
        return done(o,get(o,136),1)
    if phase==32:
        put(o,128,3)
        put(o,112,0)
        return done(o,get(o,136),1)
    if phase==33:
        return quarantine(o,33)
    if phase==2:
        if r!=0 or get(o,CHILD)!=VR:
            return quarantine(o,2)
        if get(o,CHILD+24)!=0:
            within(o,88,CHILD+24,24)
        if get(o,CHILD+8)!=0:
            put(o,136,get(o,CHILD+8))
            if get(o,88)!=0:
                return closing(o)
            return closing(o)
        if get(o,88)==0:
            return quarantine(o,3)
        request(o,GQ,2)
        return global_call(o,3)
    if phase==3:
        if r!=0 or get(o,CHILD)!=GR or get(o,CHILD+88)!=1 or get(o,CHILD+96)>1 or get(o,CHILD+80)>1:
            return quarantine(o,4)
        if get(o,CHILD+96)==1:
            if get(o,CHILD+24)==0:
                return quarantine(o,5)
            within(o,64,CHILD+24,24)
        if get(o,CHILD+8)!=0 or get(o,64)==0 or get(o,CHILD+16)!=2:
            put(o,136,choose(get(o,CHILD+8)==0,7,get(o,CHILD+8)))
            return closing(o)
        i=0
        while i<3:
            fd=get(o,CHILD+48+i*8)
            if fd<3 or fd>2147483647:
                return quarantine(o,6)
            put(o,168+i*8,fd)
            i=i+1
        put(o,192,get(o,CHILD+72))
        put(o,200,get(o,CHILD+128))
        put(o,208,get(o,CHILD+136))
        put(o,216,get(o,CHILD+144))
        put(o,224,get(o,CHILD+152))
        put(o,232,get(o,CHILD+160))
        if get(o,192)>2147483647 or get(o,200)==0 or get(o,208)!=10100891 or get(o,224)==0:
            return quarantine(o,7)
        zero(o,4096,8192)
        put(o,4096,OPTIONS)
        put(o,4104,get(o,VALUE))
        put(o,4112,get(o,40))
        put(o,4120,256)
        put(o,4128,get(o,8))
        zero(o,16384,8192)
        put(o,16384,VERIFY)
        put(o,16392,get(o,VALUE))
        put(o,16400,get(o,40))
        put(o,16408,256)
        put(o,16416,get(o,VFY))
        put(o,16424,get(w,1384))
        put(o,16432,get(w,1392))
        put(o,16440,256)
        put(o,16448,get(o,168))
        put(o,16456,get(o,200))
        put(o,16464,get(o,208))
        put(o,16472,get(o,232))
        put(o,16480,get(o,TRANSPORT))
        put(o,16488,get(o,JSON))
        put(o,16496,get(o,FREEZERAW))
        put(o,16504,get(o,TYPED))
        put(o,16512,get(o,FREEZE))
        put(o,16520,get(o,PROCESS))
        put(o,16560,get(o,RAW))
        put(o,16528,get(o,8))
        put(o,128,1)
        return done(o,0,0)
    if phase==20:
        if value_facts(o,r)==0 or get(o,CHILD+88)!=1:
            return quarantine(o,20)
        if get(o,CHILD+96)==1:
            zero(o,88,24)
        if get(o,CHILD+104)!=0:
            put(o,152,1)
            return pending(o,get(o,CHILD+8),get(o,CHILD+104))
        if get(o,88)!=0:
            return pending(o,get(o,CHILD+8),20)
        return closing(o)
    if phase==21:
        if value_facts(o,r)==0 or get(o,CHILD+88)!=1 or get(o,CHILD+96)!=0:
            return quarantine(o,21)
        if get(o,CHILD+104)!=0:
            return pending(o,get(o,CHILD+8),get(o,CHILD+104))
        put(o,152,0)
        return closing(o)
    if phase==22:
        if r!=0 or get(o,CHILD)!=GR or get(o,CHILD+88)!=1 or get(o,CHILD+96)>1 or get(o,CHILD+80)>1:
            return quarantine(o,22)
        if get(o,CHILD+96)==1:
            zero(o,64,24)
        if get(o,CHILD+80)!=0:
            put(o,152,2)
            return pending(o,get(o,CHILD+8),get(o,CHILD+112))
        if get(o,64)!=0:
            return pending(o,get(o,CHILD+8),22)
        return closing(o)
    if phase==23:
        if r!=0 or get(o,CHILD)!=GR or get(o,CHILD+88)!=1 or get(o,CHILD+96)!=0:
            return quarantine(o,23)
        if get(o,CHILD+80)!=0:
            return pending(o,get(o,CHILD+8),get(o,CHILD+112))
        put(o,152,0)
        return closing(o)
    return BAD

def closing(o:mutbuf) -> u32:
    if get(o,88)!=0:
        request(o,V5,92)
        within(o,RQ+24,88,24)
        return value(o,20)
    if get(o,152)==1:
        request(o,V5,93)
        return value(o,21)
    if get(o,64)!=0:
        request(o,GQ,3)
        within(o,RQ+24,64,24)
        return global_call(o,22)
    if get(o,152)==2:
        request(o,GQ,4)
        return global_call(o,23)
    if get(o,248)==1:
        put(o,PH,30)
        return 2
    put(o,128,3)
    put(o,112,0)
    return done(o,get(o,136),1)
def value_facts(o:mutbuf,rc:u64) -> u64:
    if rc!=0 or get(o,CHILD)!=VR2 or get(o,CHILD+88)>1 or get(o,CHILD+96)>1 or get(o,CHILD+80)>1 or get(o,CHILD+120)!=1:
        return 0
    return 1
def pending(o:mutbuf,status:u64,detail:u64) -> u32:
    put(o,112,1)
    put(o,144,detail)
    return done(o,choose(status==0,9,status),0)
def quarantine(o:mutbuf,detail:u64) -> u32:
    put(o,128,4)
    put(o,120,0)
    put(o,112,1)
    put(o,144,detail)
    return done(o,9,0)
def done(o:mutbuf,status:u64,retired:u64) -> u32:
    zero(o,RESULT,128)
    put(o,RESULT,R)
    put(o,RESULT+8,status)
    put(o,RESULT+16,get(o,128))
    put(o,RESULT+80,get(o,112))
    put(o,RESULT+88,get(o,120))
    put(o,RESULT+96,retired)
    put(o,RESULT+104,retired)
    put(o,RESULT+112,get(o,144))
    return 0
def value(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 10
def global_call(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 11
def request(o:mutbuf,magic:u64,op:u64) -> u64:
    zero(o,RQ,128)
    zero(o,CHILD,128)
    put(o,RQ,magic)
    put(o,RQ+8,op)
    return 0
def system(o:mutbuf,next:u64,nr:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,0+768,nr)
    put(o,8+768,mask)
    put(o,16+768,a)
    put(o,24+768,b)
    put(o,32+768,c)
    put(o,40+768,d)
    put(o,48+768,e)
    put(o,56+768,f)
    put(o,PH,next)
    return 1
def get(b:mutbuf,at:u64) -> u64:
    return word_load(b,at)
def word(b:readbuf,at:u64) -> u64:
    return word_load(b,at)
def put(b:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(b,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
def zero(b:mutbuf,at:u64,n:u64) -> u64:
    fill_range(b,at,n,0)
    return 0
def within(b:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(b,to+i,byte(b,at+i))
        i=i+1
    return 0
def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no
'''
def source_program():
    text=SOURCE
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def main():
    tree=document(source_program(),'generation_runtime_frontend_bind')
    p=ROOT/'examples/hia_bootstrap/generation_runtime_frontend_bind.hepta'
    p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
