"""Native completion notification for public Future observers.

This leaf never allocates. Registered observers own their retained Future
vectors, hash tables and fixed-capacity event arrays before publication.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
ROOT=Path(__file__).resolve().parents[1]
C={k:int.from_bytes(v,'little')for k,v in {'REQ':b'HIABFN01','REP':b'HIABFNR1','GLOBAL':b'HIABFPS1','NODEMAGIC':b'HIABFOB1'}.items()}
C.update({'REQ2':int.from_bytes(b'HIABFN02','little'),'REQ3':int.from_bytes(b'HIABFN03','little'),'KREQ':int.from_bytes(b'HIAMVFQ2','little'),'KREP':int.from_bytes(b'HIAMVFR1','little'),'LREQ2':int.from_bytes(b'HIAFPL02','little'),'LREQ3':int.from_bytes(b'HIAFPL03','little'),'LREP':int.from_bytes(b'HIAFPLR1','little'),'CBSTATUS':240,'COMPLETION':248,'MODE':256,'RQ':2048,'CHILD':4096,'MAX':(1<<64)-1,'NEGATIVE':(1<<64)-4095,'PHASE':128,'HELD':136,'ERROR':144,'PID':152,'ROOTPTR':160,'NODEPTR':168,'COUNT':176,'MATCHED':184,'QUEUED':192,'PROBE':200,'SLOT':208,'INDEX':216,'NEXTPTR':224,'AFTER':232,'FEEDBACK':448,'TEMP':456,'HEADER':512,'ROW':1024,'SLOTBUF':1152})
SOURCE=r'''
def future_observer_notify(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=64 or length(o)<8192 or length(w)<256:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        if (word(s,0)!=REQ and word(s,0)!=REQ2 and word(s,0)!=REQ3) or word(s,8)==0:
            return 4294967293
        i=16
        while i<64:
            if word(s,i)!=0:
                return 4294967293
            i=i+8
        zero(o,128,1200)
        put(o,MODE,word(s,0))
        return system(o,1,39,0,0,0,0,0,0,0)
    if phase<100:
        return locks(s,o,w,phase)
    if phase<200:
        return visit(s,o,w,phase)
    return complete(s,o,w,phase)

def locks(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid==0 or pid>=NEGATIVE or get(w,0)!=GLOBAL or get(w,8)!=pid or get(w,24)!=0:
            return finish(o,107)
        put(o,PID,pid)
        if get(o,MODE)!=REQ:
            zero(o,RQ,64)
            put(o,RQ,KREQ)
            put(o,RQ+8,15)
            return invoke(o,3,get(w,64),RQ,64,CHILD,512,word(s,8),512)
        return waddress(o,2,0)
    if phase==2:
        put(o,ROOTPTR,get(o,FEEDBACK))
        return atom(o,2,10,0,1)
    if phase==3:
        if get(o,FEEDBACK)!=0 or get(o,CHILD)!=KREP or get(o,CHILD+8)!=0 or get(o,CHILD+24)==0 or get(o,CHILD+24)>2:
            return finish(o,107)
        put(o,COMPLETION,get(o,CHILD+88))
        if get(o,MODE)==REQ2 and get(o,CHILD+24)==1:
            zero(o,RQ,64)
            put(o,RQ,KREQ)
            put(o,RQ+8,16)
            return invoke(o,4,get(w,64),RQ,64,CHILD,512,word(s,8),512)
        return waddress(o,2,0)
    if phase==4:
        if get(o,CHILD)!=KREP or get(o,FEEDBACK)!=get(o,CHILD+8):
            return finish(o,107)
        if get(o,CHILD+8)==7:
            zero(o,RQ,192)
            put(o,RQ,LREQ2)
            put(o,RQ+8,word(s,8))
            put(o,RQ+16,3)
            return waddress(o,7,0)
        if get(o,CHILD+8)!=0:
            return finish(o,107)
        return waddress(o,2,0)
    if phase==7:
        put(o,ROOTPTR,get(o,FEEDBACK))
        return invoke(o,5,get(w,192),RQ,192,CHILD,4096,get(o,ROOTPTR),256)
    if phase==5:
        if get(o,FEEDBACK)!=0 or get(o,CHILD)!=LREP or get(o,CHILD+8)!=0:
            return finish(o,107)
        zero(o,RQ,192)
        put(o,RQ,LREQ3)
        return invoke(o,6,get(w,192),RQ,192,CHILD,4096,get(o,ROOTPTR),256)
    if phase==6:
        if get(o,FEEDBACK)!=0 or get(o,CHILD)!=LREP or get(o,CHILD+8)!=0:
            return finish(o,107)
        put(o,CBSTATUS,1)
        return finish(o,0)
    if phase==10:
        if get(o,FEEDBACK)==0:
            put(o,HELD,1)
            put(o,NODEPTR,get(w,48))
            return again(o,100)
        return system(o,11,202,1,32,128,1,0,0,0)
    if phase==11:
        raw=get(o,FEEDBACK)
        if raw!=0 and raw!=MAX-3 and raw!=MAX-10:
            return system(o,12,24,0,0,0,0,0,0,0)
        return atom(o,2,10,0,1)
    if phase==12:
        return atom(o,2,10,0,1)
    return finish(o,107)

def visit(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        node=get(o,NODEPTR)
        if node==0:
            return again(o,200)
        if node>MAX-256:
            return fail(o,107)
        return memory(o,101,0,node,3,HEADER,256)
    if phase==101:
        if get(o,HEADER)!=NODEMAGIC or get(o,HEADER+16)!=get(o,ROOTPTR) or get(o,HEADER+24)!=get(o,PID):
            return fail(o,107)
        put(o,NEXTPTR,get(o,HEADER+8))
        if get(o,HEADER+96)==0:
            return next_node(o)
        if get(o,HEADER+96)!=1 or valid_node(o)==False:
            return fail(o,107)
        cap=get(o,HEADER+112)
        key=word(s,8)
        hash=((key>>4)^(key>>32))*11400714819323198485
        put(o,SLOT,hash&(cap-1))
        put(o,PROBE,0)
        return again(o,110)
    if phase==110:
        if get(o,PROBE)>=get(o,HEADER+112):
            return fail(o,107)
        ptr=get(o,HEADER+104)+get(o,SLOT)*8
        return memory(o,111,0,ptr,3,SLOTBUF,8)
    if phase==111:
        index=get(o,SLOTBUF)
        if index==0:
            return next_node(o)
        if index>get(o,HEADER+32):
            return fail(o,107)
        put(o,INDEX,index-1)
        return memory(o,112,0,get(o,HEADER+40)+(index-1)*96,3,ROW,96)
    if phase==112:
        if get(o,ROW+48)!=word(s,8):
            put(o,PROBE,get(o,PROBE)+1)
            put(o,SLOT,(get(o,SLOT)+1)&(get(o,HEADER+112)-1))
            return again(o,110)
        put(o,MATCHED,get(o,MATCHED)+1)
        if get(o,ROW+56)==0:
            return next_node(o)
        if get(o,ROW+56)!=1 or get(o,HEADER+72)>=get(o,HEADER+32) or get(o,HEADER+88)==0:
            return fail(o,107)
        if get(o,COMPLETION)==2:
            return write_pointer(o,118,get(o,NODEPTR)+208,1)
        return again(o,118)
    if phase==118:
        return write_pointer(o,120,get(o,HEADER+56)+get(o,HEADER+72)*8,get(o,INDEX))
    if phase==120:
        return write_pointer(o,121,get(o,HEADER+40)+get(o,INDEX)*96+56,0)
    if phase==121:
        return write_pointer(o,122,get(o,NODEPTR)+72,get(o,HEADER+72)+1)
    if phase==122:
        return write_pointer(o,123,get(o,NODEPTR)+88,get(o,HEADER+88)-1)
    if phase==123:
        return write_pointer(o,124,get(o,NODEPTR)+248,1)
    if phase==124:
        put(o,QUEUED,get(o,QUEUED)+1)
        return system(o,125,202,0,get(o,NODEPTR)+248,129,2147483647,0,0,0)
    if phase==125:
        raw=get(o,FEEDBACK)
        if raw==MAX-3:
            return system(o,125,202,0,get(o,NODEPTR)+248,129,2147483647,0,0,0)
        if raw>=NEGATIVE:
            put(o,ERROR,107)
        return next_node(o)
    return fail(o,107)

def valid_node(o:mutbuf) -> bool:
    n=get(o,HEADER+32)
    if n==0 or n>MAX//96:
        return False
    vector=get(o,HEADER+40)
    queue=get(o,HEADER+56)
    table=get(o,HEADER+104)
    capacity=get(o,HEADER+112)
    if vector==0 or vector>MAX-n*96 or get(o,HEADER+48)!=n*96:
        return False
    if queue==0 or queue>MAX-n*8 or get(o,HEADER+64)!=n*8:
        return False
    if capacity==0 or (capacity&(capacity-1))!=0 or capacity<n or capacity>MAX//8:
        return False
    if table==0 or table>MAX-capacity*8 or get(o,HEADER+120)!=capacity*8:
        return False
    if get(o,HEADER+80)>get(o,HEADER+72) or get(o,HEADER+72)>n or get(o,HEADER+88)>n:
        return False
    return True

def complete(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        put(w,40,(get(w,40)+1)&4294967295)
        put(o,HELD,0)
        return atom(o,3,201,0,0)
    if phase==201:
        return system(o,202,202,1,32,129,2147483647,0,0,0)
    if phase==202:
        if get(o,FEEDBACK)==MAX-3:
            return again(o,201)
        if get(o,FEEDBACK)>=NEGATIVE:
            put(o,ERROR,107)
        return system(o,203,202,1,40,129,2147483647,0,0,0)
    if phase==203:
        if get(o,FEEDBACK)==MAX-3:
            return system(o,203,202,1,40,129,2147483647,0,0,0)
        if get(o,FEEDBACK)>=NEGATIVE:
            put(o,ERROR,107)
        return finish(o,get(o,ERROR))
    return finish(o,107)

def next_node(o:mutbuf) -> u32:
    put(o,NODEPTR,get(o,NEXTPTR))
    return again(o,100)

def fail(o:mutbuf,error:u64) -> u32:
    put(o,ERROR,error)
    if get(o,HELD)!=0:
        return again(o,200)
    return finish(o,error)

def finish(o:mutbuf,error:u64) -> u32:
    zero(o,0,128)
    put(o,0,REP)
    put(o,8,error)
    put(o,16,get(o,MATCHED))
    put(o,24,get(o,QUEUED))
    put(o,32,get(o,CBSTATUS))
    return 0

def atom(o:mutbuf,action:u64,next:u64,a:u64,b:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,32)
    put(o,8,a)
    put(o,16,b)
    return action

def waddress(o:mutbuf,next:u64,at:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,at)
    return 5

def write_pointer(o:mutbuf,next:u64,ptr:u64,value:u64) -> u32:
    put(o,TEMP,value)
    return memory(o,next,3,TEMP,0,ptr,8)

def memory(o:mutbuf,next:u64,a:u64,at:u64,b:u64,bt:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,a)
    put(o,8,at)
    put(o,16,b)
    put(o,24,bt)
    put(o,32,n)
    return 8

def system(o:mutbuf,next:u64,nr:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,nr)
    put(o,8,mask)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1

def again(o:mutbuf,next:u64) -> u32:
    put(o,PHASE,next)
    return 10

def zero(o:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,at+i,0)
        i=i+1
    return 0

def word(s:readbuf,at:u64) -> u64:
    return word_load(s,at)

def get(o:mutbuf,at:u64) -> u64:
    return word_load(o,at)

def put(o:mutbuf,at:u64,value:u64) -> u64:
    word_store(o,at,value)
    return 0
'''
SOURCE+=r'''
def invoke(o:mutbuf,next:u64,fn:u64,src:u64,sn:u64,dest:u64,dn:u64,ctx:u64,cn:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,fn)
    put(o,8,51)
    put(o,16,src)
    put(o,24,sn)
    put(o,32,dest)
    put(o,40,dn)
    put(o,48,ctx)
    put(o,56,cn)
    return 9
'''

def source_program():
    text=SOURCE
    for name,value in sorted(C.items(),key=lambda item:-len(item[0])):text=re.sub(r'\b'+name+r'\b',str(value),text)
    return text
def program():return document(source_program(),'background_optimizer_future_public_observers_notify')
def main():
    tree=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_future_public_observers_notify.hepta';p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']))
if __name__=='__main__':main()
