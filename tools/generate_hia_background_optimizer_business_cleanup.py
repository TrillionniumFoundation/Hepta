"""Fixed post-pthread business cleanup admission, with no business replay.

Development author only. Its native dependency and concurrency gates are
required before this candidate can be used by the public lifecycle owner.
"""
from pathlib import Path
import ast, re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_value_freeze import SOURCE as BASE

ROOT = Path(__file__).resolve().parents[1]
C = {
    'INPUT':int.from_bytes(b'HIABGCQ1','little'),
    'REPLY':int.from_bytes(b'HIABGCR1','little'),
    'CONTEXT':int.from_bytes(b'HIABGCC1','little'),
    'BUSINESS_CONTEXT':int.from_bytes(b'HIABWBC1','little'),
    'BUSINESS_INPUT':int.from_bytes(b'HIABGWQ3','little'),
    'BUSINESS_REPLY':int.from_bytes(b'HIABGWR2','little'),
    'WORKER_INPUT':int.from_bytes(b'HIABGW03','little'),
    'WORKER_REPLY':int.from_bytes(b'HIABGWO1','little'),
    'OUT':32768,'WORK':256,'MAX':(1<<64)-1,'NEGATIVE':(1<<64)-4095,
    'PHASE':128,'ERROR':136,'DETAIL':144,'PID':152,'LOCKED':160,
    'CLAIMED':168,'WORKER_STATE':176,'QUARANTINE':184,'CHILD_STATUS':192,
    'FEEDBACK':448,'BCOPY':512,'RQ':1024,'WCOPY':2048,'WORD':3072,'RP':8192,
}

SOURCE = r'''
def cleanup(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or length(o)<OUT or length(w)<WORK:
        return 4294967293
    if word_load(s,0)!=INPUT or word_load(s,8)!=0:
        return 4294967293
    at=16
    while at<128:
        if word_load(s,at)!=0:
            return 4294967293
        at=at+8
    if get(w,0)!=CONTEXT or get(w,8)==0 or get(w,16)==0 or get(w,24)<1064960:
        return 4294967293
    if get(w,32)==0 or get(w,40)==0 or get(w,48)<512 or get(w,56)<2:
        return 4294967293
    if (get(w,16)&7)!=0 or (get(w,40)&7)!=0 or get(w,24)>MAX-get(w,16) or get(w,48)>MAX-get(w,40):
        return 4294967293
    at=64
    while at<256:
        if get(w,at)!=0:
            return 4294967293
        at=at+8
    phase=get(o,PHASE)
    if phase==0:
        zero(o,128,3968)
        return system(o,1,39,0,0,0,0,0,0,0)
    if phase<10:
        return stopped(o,w,phase)
    if phase<20:
        return locking(o,w,phase)
    if phase<40:
        return admitted(o,w,phase)
    return releasing(o,w,phase)

def stopped(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid<2 or pid>=NEGATIVE or pid!=get(w,56):
            return finish(o,6,1)
        put(o,PID,pid)
        request(o,WORKER_INPUT,3)
        return invoke(o,2,get(w,32),51,RQ,128,RP,8192,get(w,40),get(w,48))
    if phase==2:
        if valid(o,WORKER_REPLY)==0:
            return finish(o,7,2)
        at=56
        while at<128:
            if get(o,RP+at)!=0:
                return finish(o,7,2)
            at=at+8
        put(o,WORKER_STATE,get(o,RP+24))
        if get(o,RP+8)!=0:
            return finish(o,8,get(o,RP+16))
        if get(o,RP+24)!=4 or get(o,RP+48)!=0:
            return finish(o,6,2)
        return memory(o,3,0,get(w,40)+64,3,WCOPY,56)
    if phase==3:
        if get(o,WCOPY+24)!=get(w,8) or get(o,WCOPY+32)!=get(w,16) or get(o,WCOPY+40)!=get(w,24) or get(o,WCOPY+48)!=1:
            return finish(o,6,3)
        return acquire(o,w)
    return finish(o,7,phase)

def acquire(o:mutbuf,w:mutbuf) -> u32:
    put(o,PHASE,10)
    put(o,0,get(w,16)+496)
    put(o,8,0)
    put(o,16,1)
    return 2

def locking(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==10:
        raw=get(o,FEEDBACK)
        if raw==0:
            put(o,LOCKED,1)
            return memory(o,20,0,get(w,16),3,BCOPY,512)
        if raw!=1:
            return finish(o,7,10)
        return system(o,11,202,0,get(w,16)+496,128,1,0,0,0)
    if phase==11:
        raw=get(o,FEEDBACK)
        if raw!=0 and raw!=MAX-3 and raw!=MAX-10:
            return finish(o,8,raw)
        return acquire(o,w)
    return finish(o,7,phase)

def admitted(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==20:
        if get(o,BCOPY)!=BUSINESS_CONTEXT or get(o,BCOPY+456)!=get(o,PID):
            return leave(o,6,20)
        if get(o,BCOPY+136)!=get(o,WCOPY) or get(o,BCOPY+144)!=get(o,WCOPY+8) or get(o,BCOPY+152)!=get(o,WCOPY+16):
            return leave(o,6,20)
        if get(o,BCOPY+488)!=0 or get(o,BCOPY+496)!=1:
            return leave(o,7,20)
        if get(o,BCOPY+464)==0 and get(o,BCOPY+376)==0 and get(o,BCOPY+480)==0:
            return leave(o,0,0)
        if get(o,BCOPY+464)!=1 or get(o,BCOPY+376)!=1 or get(o,BCOPY+480)!=1:
            put(o,QUARANTINE,2)
            return leave(o,9,20)
        put(o,WORD,1)
        return memory(o,21,3,WORD,0,get(w,16)+488,8)
    if phase==21:
        put(o,CLAIMED,1)
        request(o,BUSINESS_INPUT,3)
        return invoke(o,22,get(w,8),51,RQ,128,RP,128,get(w,16),get(w,24))
    if phase==22:
        if valid(o,BUSINESS_REPLY)==0:
            return unknown(o,w,22)
        status=get(o,RP+8)
        if status!=0 and status!=2:
            return unknown(o,w,22)
        if (status==0 and get(o,RP+16)!=0) or (status==2 and get(o,RP+16)!=1):
            return unknown(o,w,22)
        at=32
        while at<128:
            if get(o,RP+at)!=0:
                return unknown(o,w,22)
            at=at+8
        put(o,CHILD_STATUS,status)
        put(o,DETAIL,get(o,RP+24))
        return memory(o,23,0,get(w,16)+464,3,BCOPY,48)
    if phase==23:
        if get(o,BCOPY+24)!=1 or get(o,BCOPY+32)!=1:
            return unknown(o,w,23)
        if get(o,CHILD_STATUS)==0:
            if get(o,BCOPY)!=0 or get(o,BCOPY+16)!=0:
                return unknown(o,w,23)
            return leave(o,0,0)
        if get(o,BCOPY)!=1 or (get(o,BCOPY+16)!=1 and get(o,BCOPY+16)!=2):
            return unknown(o,w,23)
        put(o,QUARANTINE,get(o,BCOPY+16))
        return leave(o,9,get(o,DETAIL))
    return unknown(o,w,phase)

def unknown(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    put(o,ERROR,9)
    put(o,DETAIL,detail)
    put(o,QUARANTINE,2)
    put(o,WORD,2)
    return memory(o,50,3,WORD,0,get(w,16)+480,8)

def leave(o:mutbuf,status:u64,detail:u64) -> u32:
    put(o,ERROR,status)
    put(o,DETAIL,detail)
    return again(o,50)

def releasing(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==50:
        if get(o,CLAIMED)!=0:
            put(o,WORD,0)
            return memory(o,51,3,WORD,0,get(w,16)+488,8)
        return again(o,52)
    if phase==51:
        put(o,CLAIMED,0)
        return again(o,52)
    if phase==52:
        if get(o,LOCKED)==0:
            return finish(o,get(o,ERROR),get(o,DETAIL))
        put(o,PHASE,53)
        put(o,0,get(w,16)+496)
        put(o,8,0)
        return 3
    if phase==53:
        put(o,LOCKED,0)
        if get(o,FEEDBACK)!=1:
            put(o,ERROR,9)
            put(o,DETAIL,53)
            put(o,QUARANTINE,2)
        return system(o,54,202,0,get(w,16)+496,129,1,0,0,0)
    if phase==54:
        raw=get(o,FEEDBACK)
        if raw>=NEGATIVE:
            return finish(o,8,raw)
        return finish(o,get(o,ERROR),get(o,DETAIL))
    return finish(o,7,phase)

def request(o:mutbuf,magic:u64,op:u64) -> u64:
    zero(o,RQ,128)
    zero(o,RP,128)
    put(o,RQ,magic)
    put(o,RQ+8,op)
    return 0

def valid(o:mutbuf,magic:u64) -> u64:
    return choose(get(o,FEEDBACK)==0 and get(o,RP)==magic,1,0)

def finish(o:mutbuf,status:u64,detail:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,detail)
    put(o,24,get(o,WORKER_STATE))
    put(o,32,get(o,QUARANTINE))
    return 0
'''

def source_program():
    source = SOURCE
    for name in ('invoke','memory','system','again','zero','get','put','choose'):
        node=next(x for x in ast.parse(BASE).body if isinstance(x,ast.FunctionDef) and x.name==name)
        source+='\n'+ast.get_source_segment(BASE,node)+'\n'
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
        source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source

def main():
    tree=document(source_program(),'background_optimizer_business_cleanup')
    path=ROOT/'examples/hia_bootstrap/background_optimizer_business_cleanup.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']),flush=True)

if __name__=='__main__':main()
