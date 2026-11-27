"""Thin native entry proxies for the installed Runtime frontend.

Only fixed wrappers select a role. The installed catalog supplies the actual
child entries; a live native session and active-call count hold the loader.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
C=dict(BAD=4294967293,MAX=(1<<64)-1,SIZE=8192,ANCHOR=7341568,SESSION_AT=983040,
 PH=128,FB=136,ROLE=512,INPUT=520,INPUT_N=528,OUTPUT=536,OUTPUT_N=544,WORK=552,WORK_N=560,
 ROOT_PTR=568,FRONT=576,ROOT_ENTRY=584,VALUE_ENTRY=592,INSTALL_ENTRY=600,
 PID=608,AFTER=616,RC=624,TARGET=632,RETIRED=640,NEW=648,LOCKED=656,NEXT=664,
 NONCE=672,MODE=680,M=1024,SM=1600,FH=1792,CHILD=4096,TIME=4224,
 Q=int.from_bytes(b'HIARTBQ1','little'),R=int.from_bytes(b'HIARTBR1','little'),
 OQ=int.from_bytes(b'HIARTOQ1','little'),VQ=int.from_bytes(b'HIARTVQ1','little'),
 XQ=int.from_bytes(b'HIARTXQ1','little'),DQ=int.from_bytes(b'HIARTDQ1','little'),
 TAG=int.from_bytes(b'HIARTAM1','little'),STAG=int.from_bytes(b'HIARTSM1','little'),
 OWNER=int.from_bytes(b'HIAGLOW1','little'),FCTX=int.from_bytes(b'HIARTFC1','little'))
SOURCE=r'''
def frontend_proxy(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PH)
    r=get(o,FB)
    if phase==0:
        if length(o)!=SIZE or length(w)!=2048 or get(o,ROLE)>4:
            return BAD
        if valid_request(s,o)==0:
            return BAD
        return system(o,1,39,0,0,0,0,0,0,0)
    if phase==1:
        if r==0 or failed(r) or get(w,0)!=OWNER or get(w,8)!=r:
            return BAD
        put(o,PID,r)
        if get(w,16)!=get(o,ROOT_PTR) or get(w,24)!=get(o,ROOT_ENTRY) or get(w,40)!=get(o,VALUE_ENTRY):
            return BAD
        if get(w,48)!=get(o,ROOT_PTR)+512 or get(w,56)!=256 or get(w,80)!=1 or get(w,664)==0:
            return BAD
        if get(w,1088)==0 or get(w,1096)!=8388608 or get(w,1088)>MAX-8388608:
            return BAD
        return lock(o)
    if phase==2:
        if r==0:
            put(o,LOCKED,1)
            if get(o,AFTER)==0 and get(o,ROLE)==0 and get(o,MODE)==1:
                return memory(o,60,0,get(o,FRONT)+SESSION_AT,3,SM,128)
            return memory(o,4,0,get(w,1088)+ANCHOR,3,M,512)
        if r!=1 and get(o,AFTER)==0:
            return BAD
        put(o,TIME,0)
        put(o,TIME+8,10000000)
        return system(o,3,202,193,64,128,1,TIME,0,0)
    if phase==3:
        if failed(r) and r!=MAX-3 and r!=MAX-10 and r!=MAX-109:
            return system(o,8,24,0,0,0,0,0,0,0)
        return lock(o)
    if phase==8:
        return lock(o)
    if phase==4:
        if r!=0 or valid_anchor(o,w)==0:
            return fail_locked(o)
        if get(o,AFTER)!=0:
            return returned(o,w)
        if get(o,M+48)!=2 or get(o,M+64)!=0 or get(o,M+72)==MAX:
            return fail_locked(o)
        put(o,NONCE,get(o,M+392))
        if get(o,ROLE)>=3:
            if get(o,M+400)==0:
                return fail_locked(o)
            return capture(o,w)
        return memory(o,5,0,get(o,FRONT)+SESSION_AT,3,SM,128)
    if phase==5:
        if r!=0:
            return fail_locked(o)
        if get(o,ROLE)==0 and word(s,8)==0:
            i=0
            while i<128:
                if get(o,SM+i)!=0:
                    return fail_locked(o)
                i=i+8
            if get(o,M+400)==MAX:
                return fail_locked(o)
            put(o,NEW,1)
            return memory(o,6,0,get(o,FRONT),3,FH,256)
        if valid_session(o)==0 or get(o,SM+40)!=1 or get(o,SM+48)!=0 or get(o,SM+56)!=1:
            return fail_locked(o)
        if get(o,M+400)==0:
            return fail_locked(o)
        put(o,SM+48,1)
        return capture(o,w)
    if phase==6:
        if r!=0:
            return fail_locked(o)
        i=0
        while i<256:
            if get(o,FH+i)!=0:
                return fail_locked(o)
            i=i+8
        zero(o,SM,128)
        put(o,SM,STAG)
        put(o,SM+8,get(o,PID))
        put(o,SM+16,get(o,FRONT))
        put(o,SM+24,get(o,ROOT_PTR))
        put(o,SM+32,get(o,NONCE))
        put(o,SM+40,1)
        put(o,SM+48,1)
        put(o,SM+56,1)
        put(o,SM+64,get(o,ROOT_ENTRY))
        put(o,SM+72,get(o,VALUE_ENTRY))
        put(o,M+400,get(o,M+400)+1)
        return capture(o,w)
    if phase==10:
        if r!=0:
            return quarantine_locked(o,w)
        if get(o,ROLE)<3:
            return memory(o,11,3,SM,0,get(o,FRONT)+SESSION_AT,128)
        return release(o,20)
    if phase==11:
        if r!=0:
            return quarantine_locked(o,w)
        return release(o,20)
    if phase==20:
        put(o,PH,21)
        return 10
    if phase==21:
        put(o,RC,r)
        put(o,AFTER,1)
        if get(o,ROLE)==0:
            return memory(o,22,0,get(o,OUTPUT)+1024,3,CHILD,128)
        return lock(o)
    if phase==22:
        if r!=0:
            return lock(o)
        if get(o,RC)==0 and get(o,CHILD)==R:
            if get(o,CHILD+88)==1 and get(o,CHILD+80)==0 and get(o,CHILD+104)==1:
                put(o,RETIRED,1)
        if get(o,NEW)==1 and get(o,RC)==BAD:
            return memory(o,23,0,get(o,FRONT),3,FH,256)
        return lock(o)
    if phase==23:
        if r==0:
            clean=True
            i=0
            while i<256:
                if get(o,FH+i)!=0:
                    clean=False
                i=i+8
            if clean:
                put(o,RETIRED,1)
        return lock(o)
    if phase==60:
        if r!=0:
            return fail_locked(o)
        if get(o,SM+40)!=2:
            return memory(o,4,0,get(w,1088)+ANCHOR,3,M,512)
        if retired_session(o)==0:
            return fail_locked(o)
        return memory(o,61,0,get(o,FRONT),3,FH,256)
    if phase==61:
        if r!=0 or get(o,FH)!=FCTX or get(o,FH+8)!=get(o,PID) or get(o,FH+16)!=get(o,FRONT):
            return fail_locked(o)
        if get(o,FH+24)!=get(o,ROOT_PTR) or get(o,FH+32)!=get(o,VALUE_ENTRY) or get(o,FH+40)!=get(o,ROOT_PTR)+512:
            return fail_locked(o)
        if get(o,FH+128)!=3 or get(o,FH+248)!=0:
            return fail_locked(o)
        i=64
        while i<112:
            if get(o,FH+i)!=0:
                return fail_locked(o)
            i=i+8
        return memory(o,62,0,get(o,OUTPUT)+1024,3,CHILD,128)
    if phase==62:
        if r!=0 or get(o,CHILD)!=R or get(o,CHILD+8)!=0:
            return fail_locked(o)
        if get(o,CHILD+88)!=1 or get(o,CHILD+80)!=0 or get(o,CHILD+104)!=1:
            return fail_locked(o)
        put(o,RC,0)
        return release(o,50)
    if phase==30:
        if r!=0:
            return quarantine_locked(o,w)
        if get(o,ROLE)<3:
            return memory(o,31,3,SM,0,get(o,FRONT)+SESSION_AT,128)
        return release(o,50)
    if phase==31:
        if r!=0:
            return quarantine_locked(o,w)
        return release(o,50)
    if phase==40:
        put(o,LOCKED,0)
        return system(o,41,202,1,64,129,2147483647,0,0,0)
    if phase==41:
        return again(o,get(o,NEXT))
    if phase==45:
        put(o,RC,BAD)
        return release(o,50)
    if phase==50:
        return 0
    return BAD

def valid_request(s:readbuf,o:mutbuf) -> u64:
    role=get(o,ROLE)
    if role==0:
        if length(s)!=128 or word(s,0)!=Q or word(s,8)>1 or get(o,OUTPUT_N)!=1048576 or get(o,WORK_N)!=2048:
            return 0
        i=16
        while i<128:
            if word(s,i)!=0:
                return 0
            i=i+8
        put(o,MODE,word(s,8))
        return 1
    if role==1:
        if length(s)!=256 or word(s,0)!=OQ or word(s,8)>1 or get(o,WORK_N)!=8192 or get(o,OUTPUT_N)<32768:
            return 0
        return 1
    if role==2:
        if length(s)!=128 or get(o,WORK_N)!=8192:
            return 0
        if word(s,0)==VQ and get(o,OUTPUT_N)>=524288:
            return 1
        if word(s,0)==XQ and get(o,OUTPUT_N)>=65536:
            return 1
        return 0
    if role==3:
        if length(s)!=128 or word(s,0)!=DQ or get(o,WORK_N)!=524288 or get(o,OUTPUT_N)<32768:
            return 0
        return 1
    return choose(get(o,WORK_N)==131072 and get(o,OUTPUT_N)>=41943040,1,0)

def valid_anchor(o:mutbuf,w:mutbuf) -> u64:
    if get(o,M)!=TAG or get(o,M+8)!=get(o,PID) or get(o,M+16)!=get(o,ROOT_PTR) or get(o,M+24)!=get(o,INSTALL_ENTRY):
        return 0
    if get(o,M+352)!=get(o,VALUE_ENTRY) or get(o,M+368)!=get(o,ROOT_ENTRY) or get(o,M+232)!=get(w,664):
        return 0
    if get(o,M+392)==0 or get(o,M+128)==0:
        return 0
    if get(o,AFTER)!=0 and get(o,M+392)!=get(o,NONCE):
        return 0
    return 1

def valid_session(o:mutbuf) -> u64:
    if get(o,SM)!=STAG or get(o,SM+8)!=get(o,PID) or get(o,SM+16)!=get(o,FRONT) or get(o,SM+24)!=get(o,ROOT_PTR):
        return 0
    if get(o,SM+32)!=get(o,NONCE) or get(o,SM+64)!=get(o,ROOT_ENTRY) or get(o,SM+72)!=get(o,VALUE_ENTRY):
        return 0
    return 1

def retired_session(o:mutbuf) -> u64:
    if get(o,SM)!=STAG or get(o,SM+8)!=get(o,PID) or get(o,SM+16)!=get(o,FRONT) or get(o,SM+24)!=get(o,ROOT_PTR):
        return 0
    if get(o,SM+64)!=get(o,ROOT_ENTRY) or get(o,SM+72)!=get(o,VALUE_ENTRY) or get(o,SM+32)==0:
        return 0
    if get(o,SM+48)!=0 or get(o,SM+56)!=0:
        return 0
    return 1

def capture(o:mutbuf,w:mutbuf) -> u32:
    put(o,TARGET,get(o,M+184+get(o,ROLE)*8))
    if get(o,TARGET)==0:
        return quarantine_locked(o,w)
    put(o,M+72,get(o,M+72)+1)
    return memory(o,10,3,M,0,get(w,1088)+ANCHOR,512)

def returned(o:mutbuf,w:mutbuf) -> u32:
    if get(o,M+72)==0 or get(o,M+48)!=2 or get(o,M+64)!=0:
        return quarantine_locked(o,w)
    put(o,M+72,get(o,M+72)-1)
    if get(o,ROLE)<3:
        put(o,SM+48,0)
        if get(o,RETIRED)==1:
            if get(o,M+400)==0 or get(o,SM+56)!=1:
                return quarantine_locked(o,w)
            put(o,M+400,get(o,M+400)-1)
            put(o,SM+56,0)
            put(o,SM+40,2)
    return memory(o,30,3,M,0,get(w,1088)+ANCHOR,512)

def quarantine_locked(o:mutbuf,w:mutbuf) -> u32:
    put(o,M+48,5)
    put(o,M+328,1)
    return memory(o,45,3,M,0,get(w,1088)+ANCHOR,512)

def fail_locked(o:mutbuf) -> u32:
    put(o,RC,BAD)
    return release(o,50)

def lock(o:mutbuf) -> u32:
    put(o,PH,2)
    return 2
def release(o:mutbuf,next:u64) -> u32:
    put(o,NEXT,next)
    put(o,PH,40)
    return 3
def again(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 4
def memory(o:mutbuf,next:u64,sm:u64,source:u64,dm:u64,target:u64,n:u64) -> u32:
    put(o,0,sm)
    put(o,8,source)
    put(o,16,dm)
    put(o,24,target)
    put(o,32,n)
    put(o,PH,next)
    return 7
def system(o:mutbuf,next:u64,nr:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,0,nr)
    put(o,8,mask)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    put(o,PH,next)
    return 1
def failed(n:u64) -> bool:
    return n>=18446744073709547521
def word(s:readbuf,at:u64) -> u64:
    return word_load(s,at)
def get(o:mutbuf,at:u64) -> u64:
    return word_load(o,at)
def put(o:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<8:
        store(o,at+i,(n>>(i*8))&255)
        i=i+1
    return 0
def zero(o:mutbuf,at:u64,n:u64) -> u64:
    fill_range(o,at,n,0)
    return 0
def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no
'''
def source_program():
 s=SOURCE
 for name,value in sorted(C.items(),key=lambda row:-len(row[0])):
  s=re.sub(r"\b"+name+r"\b",str(value),s)
 return s
def main():
 t=document(source_program(),'generation_runtime_frontend_proxy')
 p=ROOT/'examples/hia_bootstrap/generation_runtime_frontend_proxy.hepta';p.write_text(render_assembly(t))
 print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks'])for f in t['functions']),sum(len(b['ops'])for f in t['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
