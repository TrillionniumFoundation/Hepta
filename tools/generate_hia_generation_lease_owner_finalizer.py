"""Fixed native Runtime/Lease resource finalizer with explicit carrier ACKs.

The enclosing owner constructs this context and keeps its carrier scratch mapping
until Value has fenced all callbacks. A finalizer request carries an owned opaque
capability; pointers and dispatch entries are captured only by the fixed owner.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
C={k:int.from_bytes(v.encode(),'little') for k,v in dict(
 REQUEST='HIAVRFQ1',REPLY='HIAVRFR1',CONTEXT='HIAVRFC1',
 CREQUEST='HIAMVHA1',CREPLY='HIAMVHA2').items()}
C.update(BAD=4294967293,NONE=(1<<64)-1,OUT=96<<20,PHASE=96,FEEDBACK=104)
SOURCE=r'''
def finalizer(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or length(o)<128 or length(w)!=256:
        return BAD
    phase=get(o,PHASE)
    if phase==0:
        if word_load(s,0)!=REQUEST or word_load(s,8)>1 or word_load(s,16)==0:
            return BAD
        if word_load(s,24)<1 or word_load(s,24)>2 or word_load(s,32)==0:
            return BAD
        i=56
        while i<128:
            if word_load(s,i)!=0:
                return BAD
            i=i+8
        zero(o,0,128)
        put(o,PHASE,1)
        return 1
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid==0 or pid>=18446744073709547521 or get(w,0)!=CONTEXT or get(w,16)!=pid:
            return refusal(o,1)
        put(o,PHASE,2)
        return 4
    if phase==2:
        if get(w,24)!=get(o,80) or get(w,56)!=get(o,88) or get(w,48)!=get(o,80)-512:
            return refusal(o,1)
        if get(w,32)==0 or get(w,40)!=OUT or get(w,64)!=word_load(s,16) or get(w,72)!=1 or (get(w,32)^get(w,64))!=get(w,96):
            return refusal(o,1)
        put(o,PHASE,3)
        return 2
    if phase==3:
        if get(o,FEEDBACK)!=0:
            if get(o,FEEDBACK)!=1:
                return refusal(o,11)
            put(o,PHASE,6)
            return 5
        if get(w,72)!=1:
            return unlock(o,11,0,0,0)
        zero(w,128,128)
        put(w,128,CREQUEST)
        if word_load(s,8)==0:
            put(w,136,3)
            put(w,144,word_load(s,24))
            put(w,152,word_load(s,32))
            put(w,160,word_load(s,40))
            put(w,168,word_load(s,48))
        else:
            put(w,136,7)
        put(o,PHASE,4)
        return 12
    if phase==6:
        result=get(o,FEEDBACK)
        if result!=0 and result!=NONE-3 and result!=NONE-10:
            return refusal(o,11)
        put(o,PHASE,3)
        return 2
    if phase==4:
        if get(o,FEEDBACK)!=0 or get(w,128)!=CREPLY:
            return unlock(o,11,0,0,0)
        known=get(w,224)
        consumed=get(w,232)
        pending=get(w,240)
        if known>1 or consumed>1 or pending>1 or (known==0 and (consumed!=0 or pending!=0)):
            return unlock(o,11,0,0,0)
        if word_load(s,8)==1 and known==1:
            if consumed!=0:
                return unlock(o,11,0,0,0)
            consumed=1
        status=11
        if get(w,136)==0 and known==1 and consumed==1 and pending==0:
            status=0
        put(o,40,get(w,136))
        put(o,48,get(w,176))
        put(o,56,get(w,200))
        put(o,64,get(w,208))
        return unlock(o,status,known,consumed,pending)
    if phase==5:
        put(o,PHASE,7)
        return 6
    if phase==7:
        zero(o,80,48)
        return 0
    return BAD

def unlock(o:mutbuf,status:u64,known:u64,consumed:u64,pending:u64) -> u32:
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,known)
    put(o,24,consumed)
    put(o,32,pending)
    put(o,PHASE,5)
    return 3
def refusal(o:mutbuf,status:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    return 0
def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)
def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
def zero(w:mutbuf,at:u64,n:u64) -> u64:
    fill_range(w,at,n,0)
    return 0
'''
def source_program():
    source=SOURCE
    for key,value in sorted(C.items(),key=lambda row:-len(row[0])):
        source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def main():
    target=ROOT/'examples/hia_bootstrap/generation_lease_owner_finalizer.hepta'
    target.write_text(render_assembly(document(source_program(),'generation_lease_owner_finalizer')))
    print(target.name,target.stat().st_size,flush=True)
if __name__=='__main__':main()
