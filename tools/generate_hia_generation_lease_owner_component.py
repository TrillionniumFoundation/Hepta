"""Native per-generation custody for one fixed installed prepare component.

The native parent captures the sole Value arena. A fixed catalog, real loader
borrow and context token retain the child until its actual holder is retired.
No public request selects a path, hash, entry or context.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_generation_lease_owner_clang_prepare import SOURCE as HELPERS
ROOT=Path(__file__).resolve().parents[1]
C=dict(Q=int.from_bytes(b'HIAGPBQ1','little'),R=int.from_bytes(b'HIAGPBR1','little'),
 BQ=int.from_bytes(b'HIAGPBI1','little'),TAG=int.from_bytes(b'HIAGPBW1','little'),
 LQ=int.from_bytes(b'HIANLCQ1','little'),LR=int.from_bytes(b'HIANLCR1','little'),
 PB=int.from_bytes(b'HIAMVGB1','little'),PBR=int.from_bytes(b'HIAMVGBR','little'),
 PQ=int.from_bytes(b'HIAMVGF2','little'),PR=int.from_bytes(b'HIAMVGR2','little'),
 GQ=int.from_bytes(b'HIAMVGX1','little'),G2=int.from_bytes(b'HIAMVGX2','little'),G3=int.from_bytes(b'HIAMVGX3','little'),
 GR=int.from_bytes(b'HIAMVGD1','little'),
 EQ=int.from_bytes(b'HIAMVGE1','little'),ER=int.from_bytes(b'HIAMVGER','little'),
 V5=int.from_bytes(b'HIABVQ05','little'),V6=int.from_bytes(b'HIABVQ06','little'),
 VR=int.from_bytes(b'HIABVR01','little'),VR2=int.from_bytes(b'HIABVR02','little'),
 BAD=4294967293,NONE=(1<<64)-1,WORK=512<<20,LWORK=25<<20,
 CTRL=511<<20,PH=511<<20,FB=(511<<20)+8,CONTEXT=(511<<20)+16,SELF=(511<<20)+24,
 PID=(511<<20)+32,ENTRY=(511<<20)+40,MODE=(511<<20)+48,STATE=(511<<20)+56,
 PARENT=(511<<20)+64,VE=(511<<20)+72,VC=(511<<20)+80,VN=(511<<20)+88,NONCE=(511<<20)+96,
 LP=(511<<20)+104,LA=(511<<20)+112,LRET=(511<<20)+120,LCAP=(511<<20)+128,LHELD=(511<<20)+152,
 CHILD_ACTIVE=(511<<20)+160,CHILD_RETIRED=(511<<20)+168,TOKEN=(511<<20)+176,TOKEN_HELD=(511<<20)+200,
 MAP_PENDING=(511<<20)+208,ERROR=(511<<20)+216,DETAIL=(511<<20)+224,UNKNOWN=(511<<20)+232,
 PENDING=(511<<20)+240,L_PENDING=(511<<20)+248,BUSY=(511<<20)+256,
 PREPARE_ENTRY=(511<<20)+272,BIND_ENTRY=(511<<20)+280,EX_ENTRY=(511<<20)+288,SOURCEFD=(511<<20)+296,
 LAST_CHILD_RC=(511<<20)+304,OP=(511<<20)+312,PASS_RC=(511<<20)+320,GENERATION_ENTRY=(511<<20)+328,
 LREQ=510<<20,LOUT=(510<<20)+4096,VREQ=(510<<20)+143360,VOUT=(510<<20)+147456,
 PFRAME=480<<20,POUT=384<<20)
SOURCE=r'''
def component(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PH)
    raw=get(w,FB)
    if phase==0:
        if get(w,MODE)==0:
            return bind(s,o,w)
        if get(w,MODE)==1:
            return control(s,o,w)
        return forward(s,o,w)
    if phase<20:
        return binding(o,w,phase,raw)
    if phase==20 or phase==21 or phase==22:
        return forwarded(s,o,w,phase,raw)
    if phase>=30 and phase<40:
        return closing(o,w,phase,raw)
    return BAD

def bind(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or readword(s,0)!=BQ or get(w,CONTEXT)!=0:
        return BAD
    if readword(s,8)==0 or readword(s,16)==0 or readword(s,24)!=readword(s,8)+512 or readword(s,32)!=256 or readword(s,40)==0:
        return BAD
    i=48
    while i<128:
        if readword(s,i)!=0:
            return BAD
        i=i+8
    i=0
    while i<4096:
        if i!=48 and i!=256 and get(w,CTRL+i)!=0:
            return BAD
        i=i+8
    put(w,CONTEXT,TAG)
    put(w,STATE,1)
    put(w,PARENT,readword(s,8))
    put(w,VE,readword(s,16))
    put(w,VC,readword(s,24))
    put(w,VN,256)
    put(w,NONCE,readword(s,40))
    put(w,PH,1)
    return 2

def binding(o:mutbuf,w:mutbuf,phase:u64,raw:u64) -> u32:
    if phase==1:
        put(w,SELF,raw)
        put(w,PH,2)
        return 3
    if phase==2:
        put(w,ENTRY,raw)
        put(w,PH,3)
        return 4
    if phase==3:
        if raw==0 or failed(raw):
            return failure(o,w,1,raw)
        put(w,PID,raw)
        value_frame(w,V6,21)
        return role(o,w,4,5,VREQ,128,VOUT,8192)
    if phase==4:
        if raw!=0 or get(w,VOUT)!=VR:
            return quarantine(o,w,4)
        if get(w,VOUT+24)!=0:
            copy(w,VOUT+24,TOKEN,24)
            put(w,TOKEN_HELD,1)
        if get(w,VOUT+8)!=0 or get(w,TOKEN_HELD)!=1:
            return failure(o,w,1,get(w,VOUT+8))
        return system(o,w,5,9,0,0,LWORK,3,34,NONE,0)
    if phase==5:
        if raw==0 or failed(raw):
            return failure(o,w,9,raw)
        put(w,LP,raw)
        put(w,LA,1)
        loader_frame(w,0)
        put(w,LREQ+16,1)
        return role(o,w,6,6,LREQ,128,LOUT,131072)
    if phase==6:
        if loader_reply(w,raw)==0 or get(w,LOUT+88)!=1:
            return quarantine(o,w,6)
        if get(w,LOUT+24)!=0 or get(w,LOUT+96)!=0:
            return quarantine(o,w,6)
        if get(w,LOUT+104)==1:
            put(w,LRET,1)
            put(w,LA,0)
        put(w,L_PENDING,get(w,LOUT+80))
        if get(w,LOUT+8)!=0 or get(w,LOUT+16)!=2 or get(w,LOUT+80)!=0:
            return failure(o,w,3,get(w,LOUT+112))
        loader_frame(w,2)
        return role(o,w,8,6,LREQ,128,LOUT,131072)
    if phase==8:
        if loader_reply(w,raw)==0:
            return quarantine(o,w,8)
        if get(w,LOUT+24)!=0:
            copy(w,LOUT+24,LCAP,24)
            put(w,LHELD,1)
        if get(w,LOUT+104)==1:
            put(w,LRET,1)
            put(w,LA,0)
        put(w,L_PENDING,get(w,LOUT+80))
        if get(w,LOUT+88)!=1:
            return quarantine(o,w,6)
        if get(w,LOUT+8)!=0 or get(w,LOUT+16)!=2 or get(w,LOUT+96)!=1 or get(w,LHELD)!=1:
            return failure(o,w,3,get(w,LOUT+112))
        if get(w,LOUT+48)!=10 or get(w,LOUT+56)>2147483647:
            return quarantine(o,w,7)
        i=0
        while i<10:
            if get(w,LOUT+128+i*8)==0:
                return quarantine(o,w,7)
            i=i+1
        copy(w,LOUT+128,PREPARE_ENTRY,24)
        put(w,GENERATION_ENTRY,get(w,LOUT+200))
        put(w,SOURCEFD,get(w,LOUT+56))
        zero(w,PFRAME,128)
        put(w,PFRAME,PB)
        put(w,PFRAME+8,get(w,VE))
        put(w,PFRAME+16,get(w,VC))
        put(w,PFRAME+24,256)
        put(w,PFRAME+32,get(w,NONCE))
        put(w,PFRAME+40,get(w,SOURCEFD))
        zero(w,POUT,128)
        put(w,CHILD_ACTIVE,1)
        return role(o,w,7,7,PFRAME,128,POUT,128)
    if phase==7:
        put(w,LAST_CHILD_RC,raw)
        if raw!=0 or get(w,POUT)!=PBR or get(w,POUT+88)!=1 or get(w,POUT+96)>1:
            return quarantine(o,w,8)
        if get(w,POUT+8)!=0 or get(w,POUT+96)!=1:
            return failure(o,w,4,get(w,POUT+16))
        put(w,STATE,2)
        return reply(o,w)
    return BAD

def control(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or readword(s,0)!=Q or get(w,CONTEXT)!=TAG:
        return BAD
    op=readword(s,8)
    if op!=1 and op!=2:
        return BAD
    i=16
    while i<128:
        if readword(s,i)!=0:
            return BAD
        i=i+8
    put(w,OP,op)
    if op==2 or get(w,STATE)==4 or get(w,UNKNOWN)!=0:
        return reply(o,w)
    put(w,STATE,3)
    put(w,ERROR,0)
    put(w,DETAIL,0)
    put(w,PENDING,0)
    return close_next(o,w)

def forward(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,CONTEXT)!=TAG or get(w,STATE)!=2 or get(w,UNKNOWN)!=0 or get(w,CHILD_ACTIVE)!=1 or get(w,LHELD)!=1:
        return BAD
    if get(w,MODE)==2:
        if length(s)<256 or readword(s,0)!=PQ or readword(s,8)>2:
            return BAD
        put(w,PH,20)
        return 9
    if get(w,MODE)==4:
        if length(s)<256 or (readword(s,0)!=GQ and readword(s,0)!=G2 and readword(s,0)!=G3) or readword(s,8)>6:
            return BAD
        put(w,PH,22)
        return 12
    if get(w,MODE)!=3 or length(s)!=128 or readword(s,0)!=EQ or readword(s,8)>1:
        return BAD
    put(w,PH,21)
    return 10

def forwarded(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,raw:u64) -> u32:
    put(w,PASS_RC,raw)
    if raw==BAD:
        return BAD
    if phase==22:
        if get(o,0)!=GR or raw!=get(o,8) or raw>10:
            put(w,UNKNOWN,1)
            put(w,STATE,5)
            put(w,PENDING,1)
        put(w,PH,0)
        return 11
    if phase==20:
        if raw!=0 or get(o,0)!=PR or get(o,344)>1 or get(o,352)>1 or get(o,360)>1:
            put(w,UNKNOWN,1)
            put(w,STATE,5)
            put(w,PENDING,1)
        else:
            if get(o,344)==0:
                put(w,UNKNOWN,1)
                put(w,STATE,5)
                put(w,PENDING,1)
            if get(o,352)==1:
                if get(o,344)!=1 or get(o,360)!=0:
                    put(w,UNKNOWN,1)
                    put(w,STATE,5)
                    put(w,PENDING,1)
                else:
                    put(w,CHILD_RETIRED,1)
                    put(w,CHILD_ACTIVE,0)
    else:
        if raw!=0 or get(o,0)!=ER or get(o,88)>1 or get(o,96)>1:
            put(w,UNKNOWN,1)
            put(w,STATE,5)
            put(w,PENDING,1)
    put(w,PH,0)
    return 11

def close_next(o:mutbuf,w:mutbuf) -> u32:
    if get(w,CHILD_ACTIVE)!=0:
        zero(w,PFRAME,256)
        put(w,PFRAME,PQ)
        put(w,PFRAME+8,1)
        zero(w,POUT,2048)
        return role(o,w,30,8,PFRAME,256,POUT,2048)
    if get(w,LHELD)!=0:
        loader_frame(w,3)
        copy(w,LCAP,LREQ+24,24)
        return role(o,w,31,6,LREQ,128,LOUT,131072)
    if get(w,LA)!=0:
        loader_frame(w,1)
        return role(o,w,32,6,LREQ,128,LOUT,131072)
    if get(w,LP)!=0:
        return system(o,w,33,11,0,get(w,LP),LWORK,0,0,0,0)
    if get(w,TOKEN_HELD)!=0:
        value_frame(w,V5,92)
        copy(w,TOKEN,VREQ+24,24)
        return role(o,w,34,5,VREQ,128,VOUT,8192)
    if get(w,MAP_PENDING)!=0:
        value_frame(w,V5,93)
        return role(o,w,35,5,VREQ,128,VOUT,8192)
    put(w,STATE,4)
    put(w,PENDING,0)
    return reply(o,w)

def closing(o:mutbuf,w:mutbuf,phase:u64,raw:u64) -> u32:
    if phase==30:
        put(w,LAST_CHILD_RC,raw)
        if raw!=0 or get(w,POUT)!=PR or get(w,POUT+344)!=1 or get(w,POUT+352)>1 or get(w,POUT+360)>1:
            return quarantine(o,w,30)
        if get(w,POUT+352)!=1:
            return failure(o,w,5,get(w,POUT+376))
        if get(w,POUT+360)!=0:
            return quarantine(o,w,30)
        put(w,CHILD_ACTIVE,0)
        put(w,CHILD_RETIRED,1)
        return close_next(o,w)
    if phase==31:
        if loader_reply(w,raw)==0:
            return quarantine(o,w,31)
        if get(w,LOUT+88)!=1:
            return quarantine(o,w,31)
        if get(w,LOUT+96)==1:
            zero(w,LCAP,24)
            put(w,LHELD,0)
        put(w,L_PENDING,get(w,LOUT+80))
        if get(w,LHELD)!=0 or get(w,L_PENDING)!=0:
            return failure(o,w,5,get(w,LOUT+112))
        return close_next(o,w)
    if phase==32:
        if loader_reply(w,raw)==0:
            return quarantine(o,w,32)
        if get(w,LOUT+88)!=1:
            return quarantine(o,w,32)
        put(w,L_PENDING,get(w,LOUT+80))
        if get(w,LOUT+104)!=1:
            return failure(o,w,5,get(w,LOUT+112))
        if get(w,L_PENDING)!=0 or get(w,LOUT+120)!=0:
            return quarantine(o,w,32)
        put(w,LA,0)
        put(w,LRET,1)
        return close_next(o,w)
    if phase==33:
        if raw!=0:
            return failure(o,w,5,raw)
        put(w,LP,0)
        return close_next(o,w)
    if phase==34:
        if drop_reply(w,raw)==0:
            return quarantine(o,w,34)
        if get(w,VOUT+96)==1:
            zero(w,TOKEN,24)
            put(w,TOKEN_HELD,0)
        if get(w,VOUT+104)!=0:
            put(w,MAP_PENDING,1)
        if get(w,TOKEN_HELD)!=0:
            return failure(o,w,6,get(w,VOUT+8))
        return close_next(o,w)
    if phase==35:
        if drop_reply(w,raw)==0 or get(w,VOUT+96)!=0:
            return quarantine(o,w,35)
        if get(w,VOUT+104)!=0:
            return failure(o,w,6,get(w,VOUT+8))
        put(w,MAP_PENDING,0)
        return close_next(o,w)
    return BAD

def loader_reply(w:mutbuf,raw:u64) -> u64:
    if raw!=0 or get(w,LOUT)!=LR or get(w,LOUT+80)>1 or get(w,LOUT+88)>1 or get(w,LOUT+96)>1 or get(w,LOUT+104)>1:
        return 0
    return 1

def drop_reply(w:mutbuf,raw:u64) -> u64:
    if raw!=0 or get(w,VOUT)!=VR2 or get(w,VOUT+88)!=1 or get(w,VOUT+80)>1 or get(w,VOUT+96)>1 or get(w,VOUT+104)>1 or get(w,VOUT+112)>1 or get(w,VOUT+120)!=1:
        return 0
    return 1

def loader_frame(w:mutbuf,op:u64) -> u64:
    zero(w,LREQ,128)
    zero(w,LOUT,131072)
    put(w,LREQ,LQ)
    put(w,LREQ+8,op)
    return 0

def value_frame(w:mutbuf,magic:u64,op:u64) -> u64:
    zero(w,VREQ,128)
    zero(w,VOUT,8192)
    put(w,VREQ,magic)
    put(w,VREQ+8,op)
    return 0

def failure(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    put(w,ERROR,status)
    put(w,DETAIL,detail)
    put(w,PENDING,1)
    return reply(o,w)

def quarantine(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    put(w,UNKNOWN,1)
    put(w,STATE,5)
    return failure(o,w,19,detail)

def reply(o:mutbuf,w:mutbuf) -> u32:
    zero(o,0,128)
    put(o,0,R)
    put(o,8,get(w,ERROR))
    put(o,16,get(w,STATE))
    put(o,24,get(w,DETAIL))
    put(o,32,get(w,CHILD_ACTIVE))
    put(o,40,get(w,CHILD_RETIRED))
    put(o,48,get(w,LP))
    put(o,56,get(w,LHELD))
    put(o,64,get(w,LA))
    put(o,72,get(w,LRET))
    put(o,80,get(w,PENDING))
    put(o,88,choose(get(w,UNKNOWN)==0,1,0))
    put(o,96,choose(get(w,STATE)==2,1,0))
    put(o,104,choose(get(w,STATE)==4,1,0))
    put(o,112,get(w,TOKEN_HELD))
    put(o,120,get(w,MAP_PENDING))
    put(w,PH,0)
    return 0

def role(o:mutbuf,w:mutbuf,next:u64,action:u64,si:u64,sn:u64,oi:u64,on:u64) -> u32:
    put(w,PH,next)
    put(o,0,si)
    put(o,8,sn)
    put(o,16,oi)
    put(o,24,on)
    return action

def system(o:mutbuf,w:mutbuf,next:u64,nr:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(w,PH,next)
    put(o,0,nr)
    put(o,8,mask)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1
'''
SOURCE+='\n'+HELPERS[HELPERS.index('def failed('):HELPERS.index("\n'''") if "\n'''" in HELPERS else len(HELPERS)]
def source_program():
    s=SOURCE
    for k,v in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+k+r'\b',str(v),s)
    return s
def main():
    tree=document(source_program(),'generation_lease_owner_component')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_component.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),
      sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
