"""Fixed native Future-provider binding in the existing owned sidecar span.

This independent profile extends the initialized callable sidecar.  Future and
Value code addresses are fixed mechanical captures.  Once provider close starts,
a busy Value fence leaves this profile closing; it never reports ready again.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
from tools import generate_hia_generation_lease_owner_sidecar as base
ROOT=Path(__file__).resolve().parents[1]
C={**base.C,'OUT':98304,'FUTURE_Q':int.from_bytes(b'HIABFP04','little'),
 'FUTURE_R':int.from_bytes(b'HIABFRP3','little'),'FUTURE_ACK':int.from_bytes(b'HIABFRP3','little'),
 'FUTURE_STATE':int.from_bytes(b'HIABFPS1','little'),'PROVIDER_Q':int.from_bytes(b'HIAFRCQ1','little'),
 'PROVIDER_R':int.from_bytes(b'HIAFRR01','little'),'PROVIDER_STATE':int.from_bytes(b'HIAFRCX2','little'),
 'FUTURE_ENTRY':568,'PROVIDER_ENTRY':576,'REGISTRY_ENTRY':584,'SNAP':768}
PHASES=r'''
    if phase==26:
        if r!=0 or get(o,CHILD)!=FUTURE_R:
            return parked(o,w,11,r,5)
        if get(o,CHILD+8)!=0:
            put(o,ERROR,get(o,CHILD+16))
            return memory(o,30,0,get(w,PTR)+1280,3,SNAP,256)
        if get(o,CHILD+16)!=0:
            return parked(o,w,11,26,5)
        put(w,FLAGS,get(w,FLAGS)|256)
        put(w,STAGE,60)
        return future_init(o,w)
    if phase==27:
        if r!=0:
            return parked(o,w,11,r,5)
        put(w,FLAGS,get(w,FLAGS)|512)
        put(w,STAGE,60)
        return future_init(o,w)
    if phase==28:
        if provider_reply(o,r)==0:
            return parked(o,w,11,r,5)
        if get(o,CHILD+8)!=0 or get(o,CHILD+112)!=0:
            return parked(o,w,11,get(o,CHILD+8),4)
        return memory(o,29,0,get(w,PTR)+1536,3,SNAP,256)
    if phase==29:
        if r!=0 or get(o,SNAP)!=PROVIDER_STATE:
            return parked(o,w,11,r,5)
        if get(o,SNAP+8)!=get(o,PID) or get(o,SNAP+16)!=get(w,PTR)+1536:
            return parked(o,w,11,29,5)
        if get(o,SNAP+24)!=get(o,PROVIDER_ENTRY) or get(o,SNAP+80)==0 or get(o,SNAP+96)!=1:
            return parked(o,w,11,29,5)
        if get(o,SNAP+160)!=get(w,664) or get(o,SNAP+168)!=1:
            return parked(o,w,11,29,5)
        put(w,736,get(o,PROVIDER_ENTRY))
        put(w,744,get(w,PTR)+1536)
        put(w,752,512)
        put(w,760,get(o,SNAP+80))
        put(w,FLAGS,get(w,FLAGS)|17408)
        put(w,680,get(w,680)|128)
        return future_init(o,w)
    if phase==30:
        if r!=0 or get(o,SNAP)!=0 or get(o,SNAP+128)!=0 or get(o,SNAP+136)!=0 or get(o,SNAP+144)!=0:
            return parked(o,w,11,30,5)
        return parked(o,w,11,get(o,ERROR),4)
    if phase==120:
        if provider_reply(o,r)==0:
            return parked(o,w,11,r,5)
        if get(o,CHILD+8)==6:
            put(w,STAGE,132)
            return code(o,107,w,11)
        if get(o,CHILD+8)!=0 or get(o,CHILD+112)!=0:
            return parked(o,w,11,get(o,CHILD+8),4)
        put(w,FLAGS,get(w,FLAGS)|32768)
        put(w,STAGE,116)
        return close_next(o,w)
    if phase==121:
        if provider_reply(o,r)==0:
            return parked(o,w,11,r,5)
        if get(o,CHILD+8)!=0 or get(o,CHILD+112)!=0:
            return parked(o,w,11,get(o,CHILD+8),4)
        put(w,FLAGS,get(w,FLAGS)|4096)
        put(w,STAGE,117)
        return close_next(o,w)
    if phase==122:
        if r!=0 or get(o,CHILD)!=FUTURE_ACK:
            return parked(o,w,11,r,5)
        if get(o,CHILD+104)!=1 or get(o,CHILD+96)>1 or get(o,CHILD+112)>1:
            return parked(o,w,11,122,5)
        if get(o,CHILD+8)!=0 or get(o,CHILD+112)!=0:
            return parked(o,w,6,get(o,CHILD+8),4)
        put(w,FLAGS,get(w,FLAGS)|8192)
        zero(w,736,32)
        put(w,680,get(w,680)&18446744073709551487)
        put(w,STAGE,120)
        return close_next(o,w)
'''
ADDITION=r'''
def future_init(o:mutbuf,w:mutbuf) -> u32:
    if (get(w,FLAGS)&256)==0:
        put(w,STAGE,50)
        return future(o,26,w,0)
    if (get(w,FLAGS)&512)==0:
        zero(o,SNAP,256)
        put(o,SNAP,PROVIDER_STATE)
        put(o,SNAP+8,get(o,PID))
        put(o,SNAP+16,get(w,PTR)+1536)
        put(o,SNAP+24,get(o,PROVIDER_ENTRY))
        put(o,SNAP+32,get(o,FUTURE_ENTRY))
        put(o,SNAP+40,get(w,PTR)+1280)
        put(o,SNAP+48,256)
        put(o,SNAP+56,get(o,528))
        put(o,SNAP+64,get(o,512)+512)
        put(o,SNAP+72,256)
        put(o,SNAP+136,get(o,REGISTRY_ENTRY))
        put(o,SNAP+144,get(w,PTR)+1792)
        put(o,SNAP+152,256)
        put(o,SNAP+160,get(w,664))
        return memory(o,27,3,SNAP,0,get(w,PTR)+1536,256)
    if (get(w,FLAGS)&1024)==0:
        put(w,STAGE,60)
        return provider(o,28,w,0)
    if (get(w,FLAGS)&16384)==0:
        return parked(o,w,11,60,5)
    if (get(w,FLAGS)&8)!=0:
        put(w,STAGE,100)
        return again(o,100)
    return relock(o,80)

def future(o:mutbuf,next:u64,w:mutbuf,op:u64) -> u32:
    zero(o,REQUEST,192)
    zero(o,CHILD,65536)
    put(o,REQUEST,FUTURE_Q)
    put(o,REQUEST+8,op)
    if op==0:
        put(o,REQUEST+16,get(o,512)+512)
        put(o,REQUEST+24,256)
    return role(o,next,16,3,REQUEST,192,3,CHILD,65536,0,get(w,PTR)+1280,256)

def provider(o:mutbuf,next:u64,w:mutbuf,op:u64) -> u32:
    zero(o,REQUEST,128)
    zero(o,CHILD,128)
    put(o,REQUEST,PROVIDER_Q)
    put(o,REQUEST+8,op)
    return role(o,next,17,3,REQUEST,128,3,CHILD,128,0,get(w,PTR)+1536,512)

def provider_reply(o:mutbuf,r:u64) -> u64:
    if r!=0 or get(o,CHILD)!=PROVIDER_R or get(o,CHILD+96)!=1:
        return 0
    if get(o,CHILD+104)!=0 or get(o,CHILD+112)>1 or get(o,CHILD+16)!=0:
        return 0
    i=24
    while i<96:
        if get(o,CHILD+i)!=0:
            return 0
        i=i+8
    if get(o,CHILD+120)!=0:
        return 0
    return 1
'''
def once(source,old,new):
    assert source.count(old)==1,(old,source.count(old))
    return source.replace(old,new)
def source_program():
    s=base.SOURCE
    s=once(s,'length(o)!=32768','length(o)!=OUT')
    old='''    if phase==25:
        if r!=0:
            return parked(o,w,11,r,5)
        if (get(w,FLAGS)&8)!=0:
            put(w,STAGE,100)
            return again(o,100)
        return relock(o,80)
'''
    new='''    if phase==25:
        if r!=0:
            return parked(o,w,11,r,5)
        put(w,680,get(w,680)|56)
        return future_init(o,w)
'''+'''    if phase>=26 and phase<=30:
        return future_phase(o,w,phase,r)
    if phase>=120 and phase<=122:
        return future_phase(o,w,phase,r)
'''
    s=once(s,old,new)
    a=s.index('def init_next(');b=s.index('def token_created(',a)
    block=s[a:b]
    block=once(block,'''    if (get(w,FLAGS)&8)!=0:
        put(w,STAGE,100)
        return again(o,100)
    return relock(o,80)
''','''    return future_init(o,w)
''')
    s=s[:a]+block+s[b:]
    s=once(s,'''        put(w,FLAGS,get(w,FLAGS)|16)
        put(w,STAGE,120)
''','''        put(w,FLAGS,get(w,FLAGS)|16)
        put(w,STAGE,115)
''')
    s=once(s,'''        if get(o,CHILD+8)==6:
            put(w,STAGE,131)
''','''        if get(o,CHILD+8)==6:
            if (get(w,FLAGS)&2048)!=0:
                return parked(o,w,6,0,4)
            put(w,STAGE,131)
''')
    s=once(s,'''    if phase==82:
        put(w,STATE,2)
''','''    if phase==82:
        if (get(w,FLAGS)&2048)!=0:
            put(w,STATE,4)
            put(o,STATUS,6)
            put(o,PENDING,1)
            return operation_done(o,w)
        put(w,STATE,2)
''')
    s=once(s,'''    if stage==120:
        if get(w,TOKEN)!=0:
''','''    if stage==115:
        if (get(w,FLAGS)&256)==0:
            put(w,STAGE,120)
            stage=120
        elif (get(w,FLAGS)&4096)!=0:
            put(w,STAGE,117)
            stage=117
        else:
            return provider(o,120,w,1)
    if stage==116:
        put(w,FLAGS,get(w,FLAGS)|2048)
        return provider(o,121,w,3)
    if stage==117:
        if (get(w,FLAGS)&8192)!=0:
            put(w,STAGE,120)
            stage=120
        else:
            return future(o,122,w,29)
    if stage==120:
        if get(w,TOKEN)!=0:
''')
    s+='\n'+ADDITION+'\ndef future_phase(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:\n'+PHASES+'    return BAD\n'
    for name,value in sorted(C.items(),key=lambda item:-len(item[0])):
        s=re.sub(r'\b'+name+r'\b',str(value),s)
    return s
def main():
    tree=document(source_program(),'generation_lease_owner_sidecar_future')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_sidecar_future.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
