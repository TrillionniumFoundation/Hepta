"""Fixed native preparation stages for the multiversion runtime.

This owner executes the actual normalization, proof, native builder, loader and
VM components.  A failed image handoff returns a pending-retirement state before
any release; the enclosing runtime must register this same holder before op6.
No receipt Boolean or caller acknowledgement establishes preparation success.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_multiversion_intake import SOURCE as HELPERS
ROOT=Path(__file__).resolve().parents[1]
C={
 'REQUEST':int.from_bytes(b'HIAMVGX1','little'),'REPLY':int.from_bytes(b'HIAMVGD1','little'),
 'STATE':int.from_bytes(b'HIAMVGW1','little'),'INTAKE':int.from_bytes(b'HIAMVNQ1','little'),
 'INTAKE_REPLY':int.from_bytes(b'HIAMVNP1','little'),'PROOF':int.from_bytes(b'HIAMVPF1','little'),
 'PROOF_REPLY':int.from_bytes(b'HIAMVFR2','little'),'PREPARE':int.from_bytes(b'HIAMVGF1','little'),
 'PREPARE_REPLY':int.from_bytes(b'HIAMVGR1','little'),'ABI_MAGIC':int.from_bytes(b'HIAMVAB1','little'),
 'NONE':(1<<64)-1,'NEGATIVE':(1<<64)-4095,
 'WORK':512<<20,'CTRL':500<<20,'RAW':416<<20,'ORIGINAL':432<<20,'CORE':448<<20,
 'ABI':456<<20,'BASE':464<<20,'BABI':472<<20,'PATH':473<<20,'PINS':474<<20,
 'FRAME':480<<20,'OUT':384<<20,'PREP_CTRL':186<<20,'TOTALITY':336<<20,'TRANSLATION':352<<20,
}
SOURCE=r'''
def runtime_generation(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<WORK or length(o)<4096:
        return 4294967293
    phase=get(w,CTRL)
    if phase==0:
        return begin(s,o,w)
    if phase==10:
        return after_intake(o,w)
    if phase==20:
        return after_proof(o,w)
    if phase==30:
        return prepare_dispatch(o,w)
    if phase==31:
        put(w,PREP_CTRL+8,get(w,CTRL+8))
        return prepare_step(o,w)
    if phase==32:
        return after_retirement(o,w)
    return 4294967293

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<256 or readword(s,0)!=REQUEST:
        return 4294967293
    op=readword(s,8)
    if op>6:
        return 4294967293
    if op==0:
        return initialize(s,o,w)
    if length(s)!=256 or get(w,CTRL+16)!=STATE:
        return 4294967293
    i=16
    while i<256:
        if readword(s,i)!=0:
            return 4294967293
        i=i+8
    put(w,CTRL+24,op)
    put(w,CTRL+40,0)
    if op==1:
        if get(w,CTRL+32)!=1:
            return finish(o,w,9)
        if get(w,CTRL+72)==0:
            return profile_complete(o,w)
        return prove(o,w,1)
    if op==2:
        if get(w,CTRL+32)!=2 or get(w,CTRL+80)!=0:
            return finish(o,w,9)
        return prove(o,w,2)
    if op==3:
        wanted=3
        if get(w,CTRL+80)!=0:
            wanted=2
        if get(w,CTRL+32)!=wanted:
            return finish(o,w,9)
        return prepare_begin(o,w)
    if op==4:
        if (get(w,CTRL+32)!=4 and get(w,CTRL+32)!=7) or get(w,CTRL+2800)!=1:
            return finish(o,w,9)
        put(w,CTRL+32,5)
        put(w,CTRL+232,1)
        return retire(o,w,1)
    if op==5:
        return finish(o,w,0)
    if get(w,CTRL+32)!=6 or get(w,CTRL+168)==0:
        return finish(o,w,9)
    put(w,CTRL+168,0)
    return prepare_subrole(o,w,8)

def initialize(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,CTRL+16)!=0:
        return 4294967293
    raw=readword(s,80)
    base=readword(s,88)
    abi=readword(s,96)
    path=readword(s,104)
    if raw>8388608 or base>8388608 or abi>5136 or path==0 or path>4095:
        return 4294967293
    if raw>length(s)-256 or base>length(s)-256-raw or abi>length(s)-256-raw-base or path!=length(s)-256-raw-base-abi:
        return 4294967293
    if readword(s,40)==0 or readword(s,40)>30000 or readword(s,48)==0 or readword(s,56)==0:
        return 4294967293
    if readword(s,64)>1 or readword(s,72)>1 or readword(s,112)!=0 or readword(s,120)!=0:
        return 4294967293
    i=224
    while i<256:
        if readword(s,i)!=0:
            return 4294967293
        i=i+8
    i=16
    while i<40:
        fd=readword(s,i)
        if fd<3 or fd>2147483647:
            return 4294967293
        i=i+8
    isbase=readword(s,72)
    if (isbase==1 and (base!=0 or abi!=0)) or (isbase==0 and (base==0 or abi<336)):
        return 4294967293
    at=256+raw+base+abi
    if byte(s,at)!=47:
        return 4294967293
    i=0
    while i<path:
        if byte(s,at+i)==0:
            return 4294967293
        i=i+1
    zero(w,CTRL,4096)
    put(w,CTRL+16,STATE)
    put(w,CTRL+48,readword(s,16))
    put(w,CTRL+56,readword(s,24))
    put(w,CTRL+64,readword(s,32))
    put(w,CTRL+72,readword(s,64))
    put(w,CTRL+80,isbase)
    put(w,CTRL+88,readword(s,40))
    put(w,CTRL+96,readword(s,48))
    put(w,CTRL+104,readword(s,56))
    put(w,CTRL+112,raw)
    put(w,CTRL+144,base)
    put(w,CTRL+152,abi)
    put(w,CTRL+160,path)
    put(w,CTRL+200,NONE)
    put(w,CTRL+208,NONE)
    copy_input(s,128,w,PINS,96)
    copy_input(s,256,w,RAW,raw)
    copy_input(s,256+raw,w,BASE,base)
    copy_input(s,256+raw+base,w,BABI,abi)
    copy_input(s,at,w,PATH,path)
    zero(w,FRAME,128)
    put(w,FRAME,INTAKE)
    put(w,FRAME+8,get(w,CTRL+72))
    put(w,FRAME+16,get(w,CTRL+48))
    put(w,FRAME+24,get(w,CTRL+96))
    put(w,FRAME+40,raw)
    copy(w,RAW,FRAME+128,raw)
    zero(w,OUT,320)
    return role(o,w,10,2,FRAME,128+raw,OUT,16793600,0,268435456)

def after_intake(o:mutbuf,w:mutbuf) -> u32:
    raw=get(w,CTRL+8)
    put(w,CTRL+40,raw)
    if raw!=0 or get(w,OUT)!=INTAKE_REPLY or get(w,OUT+8)!=0:
        if raw==0 and get(w,OUT)==INTAKE_REPLY:
            put(w,CTRL+184,get(w,OUT+8))
            put(w,CTRL+192,get(w,OUT+16))
            put(w,CTRL+200,get(w,OUT+256))
            put(w,CTRL+208,get(w,OUT+264))
        put(w,CTRL+32,7)
        return finish(o,w,1)
    on=get(w,OUT+32)
    cn=get(w,OUT+40)
    an=get(w,OUT+48)
    if on>8388608 or cn==0 or cn>8388608 or an<336 or an>5136 or get(w,OUT+248)!=63:
        return finish(o,w,10)
    put(w,CTRL+120,cn)
    put(w,CTRL+128,an)
    put(w,CTRL+136,on)
    put(w,CTRL+216,get(w,OUT+56))
    copy(w,OUT+80,CTRL+256,128)
    copy(w,OUT+320,ORIGINAL,on)
    copy(w,OUT+320+on,CORE,cn)
    copy(w,OUT+320+on+cn,ABI,an)
    put(w,CTRL+32,1)
    return finish(o,w,0)

def prove(o:mutbuf,w:mutbuf,mode:u64) -> u32:
    cn=get(w,CTRL+120)
    an=get(w,CTRL+128)
    bn=cn
    after=0
    if mode==2:
        bn=get(w,CTRL+144)
        after=cn
    zero(w,FRAME,256)
    put(w,FRAME,PROOF)
    put(w,FRAME+8,mode)
    put(w,FRAME+16,get(w,CTRL+88))
    put(w,FRAME+24,get(w,CTRL+56))
    put(w,FRAME+40,bn)
    put(w,FRAME+48,after)
    put(w,FRAME+56,an)
    copy(w,PINS+32,FRAME+128,32)
    if mode==1:
        copy(w,CORE,FRAME+256,cn)
    else:
        copy(w,BASE,FRAME+256,bn)
        copy(w,CORE,FRAME+256+bn,cn)
    copy(w,ABI,FRAME+256+bn+after,an)
    put(w,CTRL+176,mode)
    zero(w,OUT,512)
    return role(o,w,20,3,FRAME,256+bn+after+an,OUT,16777216,0,134217728)

def after_proof(o:mutbuf,w:mutbuf) -> u32:
    raw=get(w,CTRL+8)
    put(w,CTRL+40,raw)
    if raw!=0 or get(w,OUT)!=PROOF_REPLY or get(w,OUT+8)!=0:
        put(w,CTRL+184,get(w,OUT+8))
        put(w,CTRL+192,get(w,OUT+16))
        put(w,CTRL+32,7)
        return finish(o,w,3)
    size=get(w,OUT+64)
    if size<512 or size>16777216:
        return finish(o,w,10)
    if get(w,CTRL+176)==1:
        copy(w,OUT,TOTALITY,size)
        put(w,CTRL+240,size)
        return profile_complete(o,w)
    copy(w,OUT,TRANSLATION,size)
    put(w,CTRL+248,size)
    put(w,CTRL+32,3)
    return finish(o,w,0)

def profile_complete(o:mutbuf,w:mutbuf) -> u32:
    if get(w,CTRL+80)==0:
        if get(w,CTRL+128)!=get(w,CTRL+152) or abi_equal(w)==0:
            put(w,CTRL+32,7)
            return finish(o,w,2)
    put(w,CTRL+32,2)
    return finish(o,w,0)

def abi_equal(w:mutbuf) -> u64:
    n=get(w,CTRL+128)
    if n<336 or get(w,ABI)!=ABI_MAGIC or get(w,BABI)!=ABI_MAGIC or get(w,ABI+8)!=get(w,BABI+8):
        return 0
    at=16
    while at<n:
        if equal(w,ABI+at+8,BABI+at+8,312)==0:
            return 0
        at=at+320
    return 1

def prepare_begin(o:mutbuf,w:mutbuf) -> u32:
    put(w,CTRL+2800,1)
    cn=get(w,CTRL+120)
    an=get(w,CTRL+128)
    pn=get(w,CTRL+160)
    zero(w,FRAME,256)
    put(w,FRAME,PREPARE)
    put(w,FRAME+16,get(w,CTRL+64))
    put(w,FRAME+24,get(w,CTRL+104))
    put(w,FRAME+40,cn)
    put(w,FRAME+48,an)
    put(w,FRAME+56,pn)
    copy(w,PINS+64,FRAME+128,32)
    copy(w,CORE,FRAME+256,cn)
    copy(w,ABI,FRAME+256+cn,an)
    copy(w,PATH,FRAME+256+cn+an,pn)
    put(w,CTRL+224,256+cn+an+pn)
    zero(w,PREP_CTRL,4096)
    return prepare_step(o,w)

def prepare_step(o:mutbuf,w:mutbuf) -> u32:
    return role(o,w,30,4,FRAME,get(w,CTRL+224),OUT,1050624,0,201326592)

def prepare_dispatch(o:mutbuf,w:mutbuf) -> u32:
    action=get(w,CTRL+8)
    if action==0:
        if get(w,OUT)!=PREPARE_REPLY:
            return finish(o,w,10)
        copy(w,OUT,CTRL+512,2048)
        if get(w,CTRL+232)==1:
            put(w,CTRL+32,7)
            put(w,CTRL+184,get(w,OUT+8))
            if get(w,OUT+8)!=0:
                return finish(o,w,5)
            return finish(o,w,0)
        if get(w,OUT+8)!=0 or get(w,OUT+40)!=1:
            put(w,CTRL+32,7)
            put(w,CTRL+184,get(w,OUT+8))
            return finish(o,w,4)
        put(w,CTRL+32,4)
        return finish(o,w,0)
    if action==5:
        copy(w,OUT,CTRL+384,64)
        put(w,CTRL+168,1)
        put(w,CTRL+32,6)
        return finish(o,w,8)
    if action==1:
        copy_output(w,OUT,o,0,64)
        put(w,CTRL,31)
        return 1
    if action<2 or action>4:
        put(w,CTRL+40,action)
        return finish(o,w,10)
    return prepare_subrole(o,w,action+3)

def prepare_subrole(o:mutbuf,w:mutbuf,action:u64) -> u32:
    at=OUT
    if action==8:
        at=CTRL+384
    put(w,CTRL,31)
    copy_output(w,at,o,0,48)
    return action

def retire(o:mutbuf,w:mutbuf,operation:u64) -> u32:
    zero(w,FRAME,256)
    put(w,FRAME,PREPARE)
    put(w,FRAME+8,operation)
    put(w,CTRL+224,256)
    put(w,PREP_CTRL,0)
    return prepare_step(o,w)

def after_retirement(o:mutbuf,w:mutbuf) -> u32:
    return finish(o,w,10)

def finish(o:mutbuf,w:mutbuf,status:u64) -> u32:
    zero(o,0,4096)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,get(w,CTRL+32))
    put(o,24,get(w,CTRL+24))
    put(o,32,get(w,CTRL+40))
    put(o,40,get(w,CTRL+184))
    put(o,48,get(w,CTRL+192))
    put(o,56,get(w,CTRL+112))
    put(o,64,get(w,CTRL+136))
    put(o,72,get(w,CTRL+120))
    put(o,80,get(w,CTRL+128))
    put(o,88,get(w,CTRL+216))
    put(o,96,get(w,CTRL+200))
    put(o,104,get(w,CTRL+208))
    put(o,112,get(w,CTRL+240))
    put(o,120,get(w,CTRL+248))
    put(w,CTRL+200,NONE)
    put(w,CTRL+208,NONE)
    copy_output(w,CTRL+256,o,128,128)
    copy_output(w,CTRL+512,o,512,2048)
    put(w,CTRL,0)
    return 0

def equal(w:mutbuf,a:u64,b:u64,n:u64) -> u64:
    i=0
    while i<n:
        if byte(w,a+i)!=byte(w,b+i):
            return 0
        i=i+1
    return 1

def role(o:mutbuf,w:mutbuf,next:u64,action:u64,si:u64,sn:u64,oi:u64,on:u64,wi:u64,wn:u64) -> u32:
    put(w,CTRL,next)
    put(o,0,si)
    put(o,8,sn)
    put(o,16,oi)
    put(o,24,on)
    put(o,32,wi)
    put(o,40,wn)
    return action
'''
SOURCE+='\n'+HELPERS[HELPERS.index('def zero('):]
def source_program():
    s=SOURCE
    for k,v in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+k+r'\b',str(v),s)
    return s
def main():
    t=document(source_program(),'multiversion_runtime_generation')
    p=ROOT/'examples/hia_bootstrap/multiversion_runtime_generation.hepta'
    p.write_text(render_assembly(t))
    print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),sum(len(b['ops']) for f in t['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
