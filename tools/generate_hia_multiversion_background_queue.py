from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
import ast
from tools.generate_hia_multiversion_future import FutureBuilder
from tools.generate_hia_worker_config_json import ConfigBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
class QueueBuilder(FutureBuilder,ConfigBuilder):
    pass
def document(source,module):
    nodes=ast.parse(source).body
    names={n.name:'f'+str(i)for i,n in enumerate(nodes)}
    sigs={n.name:([a.annotation.id for a in n.args.args],n.returns.id)for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=QueueBuilder(node,names,sigs,total);b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(p)for p in b.params],'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v9','module':module,'functions':functions})
ROOT=Path(__file__).resolve().parents[1]
C={'INPUT_MAGIC3':int.from_bytes(b'HIABGQ03','little'),'CLOCK_ERROR':400,'CLOCK_ATTEMPT':408,'CLOCK_PROFILE':416,'INPUT_MAGIC2':int.from_bytes(b'HIABGQ02','little'),'TX':368,'MAGIC':int.from_bytes(b'HIABGQS1','little'),'INPUT_MAGIC':int.from_bytes(b'HIABGQ01','little'),'OUTPUT_MAGIC':int.from_bytes(b'HIABGQR1','little'),'REFQ':int.from_bytes(b'HIABJRF1','little'),'REFR':int.from_bytes(b'HIABJRO1','little'),'NONE':(1<<64)-1,'NEGATIVE':(1<<64)-4095,'PHASE':128,'OP':136,'NEXT':144,'ERR':256,'VALUE':264,'CLOSED':272,'PENDING':280,'QUEUED':288,'ACTIVE':296,'EXITED':304,'WORKER':312,'NREF':320,'OWNED':328,'CURRENT':336,'MODE':344,'SAVED_NEXT':352,'ROLLBACK':360,'TIME':384,'SYSRET':448,'REFS':512,'RQ':2048,'RP':2176}
SOURCE=r'''
def queue(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or length(o)<4096 or length(w)<4096:
        return 4294967293
    magic=readword(s,0)
    requested=readword(s,8)
    if magic!=INPUT_MAGIC and magic!=INPUT_MAGIC2 and magic!=INPUT_MAGIC3:
        return 4294967293
    if magic==INPUT_MAGIC and requested>9:
        return 4294967293
    if magic==INPUT_MAGIC2 and requested!=1 and requested!=3 and requested!=4 and requested!=5 and requested!=6 and requested!=10 and requested!=11:
        return 4294967293
    if magic==INPUT_MAGIC3 and requested!=2:
        return 4294967293
    if valid_input(s)==0:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        put(o,OP,readword(s,8))
        put(o,TX,0)
        put(o,CLOCK_PROFILE,0)
        if magic==INPUT_MAGIC3:
            put(o,CLOCK_PROFILE,1)
        zero(o,TIME,16)
        put(o,CLOCK_ERROR,0)
        put(o,CLOCK_ATTEMPT,0)
        put(o,ERR,0)
        put(o,VALUE,NONE)
        put(o,NREF,0)
        put(o,OWNED,0)
        put(o,ROLLBACK,0)
        put(o,CLOSED,0)
        put(o,PENDING,0)
        put(o,QUEUED,0)
        put(o,ACTIVE,NONE)
        put(o,EXITED,0)
        put(o,WORKER,0)
        return system(o,1,39,0,0,0,0,0,0,0)
    if phase==1:
        pid=get(o,SYSRET)
        if pid==0 or pid>=NEGATIVE:
            return finish(o,65)
        if get(o,OP)==0:
            if get(w,0)!=0 or readword(s,16)<1 or readword(s,16)>8 or readword(s,64)==0:
                return finish(o,4)
            zero(w,0,4096)
            put(w,0,MAGIC)
            put(w,8,pid)
            put(w,24,readword(s,16))
            put(w,48,NONE)
            put(w,64,readword(s,64))
            put(w,80,readword(s,80))
            put(w,88,readword(s,88))
            put(w,112,NONE)
            put(w,120,NONE)
            save_state(o,w)
            return finish(o,0)
        if get(w,0)!=MAGIC or get(w,8)!=pid:
            return finish(o,65)
        return system(o,2,186,0,0,0,0,0,0,0)
    if phase==2:
        if get(o,SYSRET)==0 or get(o,SYSRET)>=NEGATIVE:
            return finish(o,65)
        put(o,376,get(o,SYSRET))
        if readword(s,0)==INPUT_MAGIC2 and get(o,OP)!=10:
            if get(w,160)!=get(o,376):
                return finish(o,65)
            put(o,TX,1)
            if get(o,OP)==11:
                word_store(w,160,0)
                put(o,TX,0)
                return release(o,w,0)
            return again(o,100)
        if get(w,160)==get(o,376):
            return finish(o,65)
        return lock(o,100)
    if phase>=20 and phase<=23:
        return lock_phase(o,phase)
    if phase==100:
        if get(w,152)!=0:
            return release(o,w,65)
        op=get(o,OP)
        if op==10:
            if get(w,160)!=0:
                return release(o,w,65)
            word_store(w,160,get(o,376))
            put(o,TX,1)
            return release(o,w,0)
        if op==7:
            if get(w,56)!=0:
                return release(o,w,4)
            put(w,56,get(o,376))
            return release(o,w,0)
        if op==2 or op==3 or op==6 or op==8:
            if get(w,56)==0 or get(w,56)!=get(o,376):
                return release(o,w,3)
        if op==1:
            return admit(s,o,w)
        if op==2:
            return take(o,w)
        if op==3:
            return settle(s,o,w)
        if op==4:
            if readword(s,16)>1:
                return release(o,w,4)
            put(w,16,1)
            if readword(s,16)==0:
                return notify(o,w,180)
            put(o,CURRENT,get(w,112))
            put(o,MODE,1)
            return again(o,200)
        if op==5:
            put(o,CURRENT,get(w,48))
            put(o,MODE,2)
            return again(o,200)
        if op==6:
            return drain(o,w)
        if op==8:
            if get(w,48)!=NONE or get(w,40)!=0 or get(w,16)==0:
                return release(o,w,4)
            put(w,144,1)
            return notify(o,w,180)
        if op==9:
            if get(w,40)!=0 or get(w,48)!=NONE or (get(w,56)!=0 and get(w,144)==0):
                return release(o,w,4)
            put(w,152,1)
            return release(o,w,0)
        return release(o,w,4)
    if phase==170:
        return system(o,171,202,1,132,128,0,0,0,0)
    if phase==171:
        raw=get(o,SYSRET)
        if raw!=0 and raw!=NONE-3 and raw!=NONE-10:
            put(o,ERR,65)
            return lock(o,181)
        return lock(o,100)
    if phase==180:
        return release(o,w,0)
    if phase==181:
        return release(o,w,get(o,ERR))
    if phase==182:
        raw=get(o,SYSRET)
        if raw==NONE-3:
            return system(o,182,228,12,1,TIME,0,0,0,0)
        if raw!=0 or get(o,TIME+8)>=1000000000:
            put(o,CLOCK_ERROR,raw)
            return release(o,w,65)
        return release(o,w,0)
    if phase==200:
        current=get(o,CURRENT)
        if current==NONE:
            if get(o,MODE)==1:
                return notify(o,w,180)
            return release(o,w,0)
        if current>=8 or get(w,row(current))==0 or get(o,NREF)>=8:
            put(o,ERR,65)
            put(o,CURRENT,0)
            return again(o,220)
        at=row(current)
        put(o,SAVED_NEXT,get(w,at+8))
        if get(o,MODE)==2:
            put(o,SAVED_NEXT,NONE)
        zero(o,RQ,64)
        put(o,RQ,REFQ)
        put(o,RQ+8,1)
        copy(w,at+24,o,RQ+16,24)
        return provider(o,w,201)
    if phase==201:
        if get(o,SYSRET)!=0 or get(o,RP)!=REFR or get(o,RP+8)!=0 or get(o,RP+16)==0:
            put(o,ERR,5)
            put(o,CURRENT,0)
            return again(o,220)
        at=REFS+get(o,NREF)*64
        zero(o,at,64)
        copy_within(o,RP+16,at,24)
        put(o,at+24,get(w,row(get(o,CURRENT))+48))
        put(o,at+32,512)
        put(o,at+40,get(o,CURRENT))
        put(o,NREF,get(o,NREF)+1)
        put(o,OWNED,1)
        put(o,CURRENT,get(o,SAVED_NEXT))
        return again(o,200)
    if phase==220:
        i=get(o,CURRENT)
        if i>=get(o,NREF):
            put(o,NREF,0)
            put(o,OWNED,0)
            return release(o,w,get(o,ERR))
        zero(o,RQ,64)
        put(o,RQ,REFQ)
        put(o,RQ+8,2)
        copy_within(o,REFS+i*64,RQ+16,24)
        return provider(o,w,221)
    if phase==221:
        if get(o,SYSRET)!=0 or get(o,RP)!=REFR or get(o,RP+8)!=0:
            put(o,ERR,65)
        put(o,CURRENT,get(o,CURRENT)+1)
        return again(o,220)
    if phase==900:
        return finish(o,get(o,ERR))
    return finish(o,65)

def admit(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,16)!=0:
        return release(o,w,1)
    if get(w,40)>=get(w,24):
        return release(o,w,2)
    if readword(s,24)==0 or readword(s,48)==0 or readword(s,56)!=512:
        return release(o,w,4)
    scan=0
    while scan<8:
        at=row(scan)
        if get(w,at)!=0 and get(w,at+24)==readword(s,24) and get(w,at+32)==readword(s,32) and get(w,at+40)==readword(s,40):
            return release(o,w,4)
        scan=scan+1
    i=0
    while i<8 and get(w,row(i))!=0:
        i=i+1
    if i==8 or get(w,32)>=8:
        return release(o,w,65)
    at=row(i)
    zero(w,at,128)
    put(w,at,1)
    put(w,at+8,NONE)
    put(w,at+16,get(w,120))
    put(w,at+24,readword(s,24))
    put(w,at+32,readword(s,32))
    put(w,at+40,readword(s,40))
    put(w,at+48,readword(s,48))
    if get(w,120)!=NONE:
        put(w,row(get(w,120))+8,i)
    else:
        put(w,112,i)
    put(w,120,i)
    put(w,256+get(w,104)*8,i)
    put(w,104,(get(w,104)+1)%8)
    put(w,32,get(w,32)+1)
    put(w,40,get(w,40)+1)
    put(o,VALUE,i)
    return notify(o,w,180)

def take(o:mutbuf,w:mutbuf) -> u32:
    if get(w,48)!=NONE:
        return release(o,w,4)
    if get(w,32)==0:
        if get(w,16)!=0:
            put(o,VALUE,NONE)
            return release(o,w,0)
        put(w,132,0)
        return unlock(o,170)
    i=get(w,256+get(w,96)*8)
    if i>=8 or get(w,row(i))!=1:
        return release(o,w,65)
    put(w,96,(get(w,96)+1)%8)
    put(w,32,get(w,32)-1)
    put(w,row(i),2)
    put(w,48,i)
    if get(w,32)==0 and get(w,16)==0:
        put(w,132,0)
    emit_ref(o,w,i,0)
    put(o,NREF,1)
    put(o,OWNED,0)
    put(o,VALUE,i)
    if get(o,CLOCK_PROFILE)!=0:
        put(o,CLOCK_ATTEMPT,1)
        return system(o,182,228,12,1,TIME,0,0,0,0)
    return release(o,w,0)

def settle(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    i=readword(s,16)
    if i>=8 or get(w,48)!=i or get(w,row(i))!=2:
        return release(o,w,4)
    at=row(i)
    if readword(s,24)!=get(w,at+24) or readword(s,32)!=get(w,at+32) or readword(s,40)!=get(w,at+40):
        return release(o,w,4)
    emit_ref(o,w,i,0)
    put(o,NREF,1)
    put(o,OWNED,1)
    prev=get(w,at+16)
    next=get(w,at+8)
    if prev==NONE:
        put(w,112,next)
    else:
        put(w,row(prev)+8,next)
    if next==NONE:
        put(w,120,prev)
    else:
        put(w,row(next)+16,prev)
    zero(w,at,128)
    put(w,40,get(w,40)-1)
    put(w,48,NONE)
    put(o,VALUE,i)
    return release(o,w,0)

def drain(o:mutbuf,w:mutbuf) -> u32:
    i=get(w,112)
    count=0
    seen=0
    previous=NONE
    while i!=NONE:
        if i>=8 or count>=8 or (seen&(1<<i))!=0 or get(w,row(i))==0 or get(w,row(i)+16)!=previous:
            return release(o,w,65)
        seen=seen|(1<<i)
        previous=i
        i=get(w,row(i)+8)
        count=count+1
    if count!=get(w,40) or previous!=get(w,120):
        return release(o,w,65)
    i=get(w,112)
    count=0
    while i!=NONE:
        next=get(w,row(i)+8)
        emit_ref(o,w,i,count)
        zero(w,row(i),128)
        count=count+1
        i=next
    put(o,NREF,count)
    put(o,OWNED,1)
    put(w,16,1)
    put(w,32,0)
    put(w,40,0)
    put(w,48,NONE)
    put(w,96,0)
    put(w,104,0)
    put(w,112,NONE)
    put(w,120,NONE)
    return notify(o,w,180)

def valid_input(s:readbuf) -> u64:
    op=readword(s,8)
    at=16
    while at<128:
        used=0
        if op==0:
            if at==16 or at==64 or at==80 or at==88:
                used=1
        if op==1:
            if at>=24 and at<=56:
                used=1
        if op==3:
            if at>=16 and at<=40:
                used=1
        if op==4 and at==16:
            used=1
        if used==0 and readword(s,at)!=0:
            return 0
        at=at+8
    return 1

def emit_ref(o:mutbuf,w:mutbuf,i:u64,index:u64) -> u64:
    at=REFS+index*64
    zero(o,at,64)
    copy(w,row(i)+24,o,at,24)
    put(o,at+24,get(w,row(i)+48))
    put(o,at+32,512)
    put(o,at+40,i)
    return 0

def provider(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    zero(o,RP,128)
    put(o,PHASE,phase)
    put(o,0,get(w,64))
    put(o,8,51)
    put(o,16,RQ)
    put(o,24,64)
    put(o,32,RP)
    put(o,40,128)
    put(o,48,get(w,80))
    put(o,56,get(w,88))
    return 4

def notify(o:mutbuf,w:mutbuf,next:u64) -> u32:
    put(w,132,1)
    return system(o,next,202,1,132,129,2147483647,0,0,0)

def release(o:mutbuf,w:mutbuf,status:u64) -> u32:
    put(o,ERR,status)
    save_state(o,w)
    if get(o,TX)!=0:
        return finish(o,status)
    return unlock(o,900)

def save_state(o:mutbuf,w:mutbuf) -> u64:
    put(o,CLOSED,get(w,16))
    put(o,PENDING,get(w,40))
    put(o,QUEUED,get(w,32))
    put(o,ACTIVE,get(w,48))
    put(o,EXITED,get(w,144))
    put(o,WORKER,get(w,56))
    return 0

def lock(o:mutbuf,next:u64) -> u32:
    put(o,NEXT,next)
    put(o,PHASE,20)
    put(o,0,128)
    put(o,8,0)
    put(o,16,1)
    return 2

def unlock(o:mutbuf,next:u64) -> u32:
    put(o,NEXT,next)
    put(o,PHASE,22)
    put(o,0,128)
    put(o,8,0)
    return 3

def lock_phase(o:mutbuf,phase:u64) -> u32:
    if phase==20:
        if get(o,SYSRET)==0:
            return again(o,get(o,NEXT))
        return system(o,21,202,1,128,128,1,0,0,0)
    if phase==21:
        return lock(o,get(o,NEXT))
    if phase==22:
        return system(o,23,202,1,128,129,1,0,0,0)
    return again(o,get(o,NEXT))

def system(o:mutbuf,phase:u64,number:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,PHASE,phase)
    put(o,0,number)
    put(o,8,mask)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1

def again(o:mutbuf,phase:u64) -> u32:
    put(o,PHASE,phase)
    return 10

def finish(o:mutbuf,status:u64) -> u32:
    zero(o,0,128)
    put(o,0,OUTPUT_MAGIC)
    put(o,8,status)
    put(o,16,get(o,VALUE))
    put(o,24,get(o,CLOSED))
    put(o,32,get(o,PENDING))
    put(o,40,get(o,QUEUED))
    put(o,48,get(o,ACTIVE))
    put(o,56,get(o,NREF))
    put(o,64,get(o,OWNED))
    put(o,72,get(o,WORKER))
    put(o,80,get(o,EXITED))
    if get(o,CLOCK_PROFILE)!=0 and get(o,CLOCK_ATTEMPT)!=0:
        put(o,88,get(o,TIME))
        put(o,96,get(o,TIME+8))
        put(o,104,get(o,CLOCK_ERROR))
        put(o,112,get(o,CLOCK_ATTEMPT))
    return 0

def row(index:u64) -> u64:
    return 512+index*128
def readword(s:readbuf,at:u64) -> u64:
    return word_load(s,at)
def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)
def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
def zero(w:mutbuf,at:u64,size:u64) -> u64:
    i=0
    while i<size:
        store(w,at+i,0)
        i=i+1
    return 0
def copy_within(w:mutbuf,at:u64,dest:u64,size:u64) -> u64:
    i=0
    while i<size:
        store(w,dest+i,byte(w,at+i))
        i=i+1
    return 0
def copy(s:mutbuf,at:u64,o:mutbuf,dest:u64,size:u64) -> u64:
    i=0
    while i<size:
        store(o,dest+i,byte(s,at+i))
        i=i+1
    return 0
'''
def source_program():
    source=SOURCE
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
        source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def main():
    result=document(source_program(),'multiversion_background_queue')
    p=ROOT/'examples/hia_bootstrap/multiversion_background_queue.hepta'
    p.write_text(render_assembly(result))
    print(p.name,p.stat().st_size,len(result['functions']),sum(len(f['blocks']) for f in result['functions']),sum(len(b['ops']) for f in result['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
