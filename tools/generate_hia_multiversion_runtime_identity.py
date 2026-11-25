"""Own runtime number identities and event references without numeric word counters.

The same immutable value object remains alive through each generation, epoch,
event and lease reference. Object addresses are private identities only.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
C={'REQ':int.from_bytes(b'HIAMVID1','little'),'REP':int.from_bytes(b'HIAMVIDR','little'),
'COUNTER_REQ':int.from_bytes(b'HIAMVID2','little'),
'STATE':int.from_bytes(b'HIAMVIDS','little'),'NREQ':int.from_bytes(b'HIAMVNB1','little'),
'NREP':int.from_bytes(b'HIAMVNR1','little'),'VREQ_MAGIC':int.from_bytes(b'HIAMVU01','little'),
'VREP_MAGIC':int.from_bytes(b'HIAMVUR1','little'),'NODE_MAGIC':int.from_bytes(b'HIAMVUN1','little'),
'VALUE_MAGIC':int.from_bytes(b'HIAMVUO1','little'),'META':30000,'MUTEX':30024,
'GENS':8192,'EPOCH':10240,'PENDING':10272,'ATTEMPTS':10304,'EVENTS':16384,
'HEAD':28672,'COUNT':28680,'PHASE':128,'FEEDBACK':136,'OP':144,'SELECTOR':152,
'HELD':160,'ERROR':168,'NEXT':176,'INDEX':184,'TARGET':192,'SAVE':208,'SAVE2':240,
'SCAN':272,'PID':280,'RESULT':384,'NINPUT':512,'VINPUT':640,'CHILD':1024,'NODE':3072,
'NONE':(1<<64)-1,'NEGATIVE':(1<<64)-4095}
SOURCE=r'''
def runtime_identity(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=64 or length(o)<4096 or length(w)<32768:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        if (word(s,0)!=REQ and word(s,0)!=COUNTER_REQ) or word(s,56)!=0:
            return 4294967293
        if (word(s,0)==REQ and word(s,8)>13) or (word(s,0)==COUNTER_REQ and (word(s,8)<14 or word(s,8)>15)):
            return 4294967293
        op=word(s,8)
        selector=word(s,16)
        if (op==1 or op==6) and (selector==0 or selector>=64):
            return 4294967293
        if (op==5 or op==7) and selector>66:
            return 4294967293
        if op==9 and selector>=64:
            return 4294967293
        if op==10 and selector>=128:
            return 4294967293
        if op!=1 and op!=5 and op!=6 and op!=7 and op!=9 and op!=10 and selector!=0:
            return 4294967293
        if op!=8 and op!=9 and op!=13 and op!=15 and (word(s,24)!=0 or word(s,32)!=0 or word(s,40)!=0):
            return 4294967293
        if word(s,48)!=0:
            return 4294967293
        zero(o,128,384)
        put(o,OP,op)
        put(o,SELECTOR,selector)
        return system(o,1,39,0,0,0,0,0,0,0)
    if phase<100:
        return admission(s,o,w,phase)
    if phase<200:
        return operation(s,o,w,phase)
    if phase<300:
        return event(s,o,w,phase)
    if phase<500:
        return disposal(s,o,w,phase)
    if phase==900:
        if get(o,HELD)!=0:
            put(o,HELD,0)
            return atom(o,3,901,0,0)
        return finished(o)
    if phase==901:
        return system(o,902,202,1,MUTEX,129,2147483647,0,0,0)
    if phase==902:
        return finished(o)
    return fail(o,9)

def admission(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid==0 or pid>=NEGATIVE:
            return fail(o,6)
        put(o,PID,pid)
        if get(o,OP)==0:
            if get(w,META)!=0:
                return fail(o,5)
            put(w,META,STATE)
            put(w,META+8,pid)
            put(w,META+16,2)
            return numbers(o,20,0,0)
        if get(w,META)!=STATE or get(w,META+8)!=pid:
            return fail(o,5)
        return atom(o,2,10,0,1)
    if phase==10:
        if get(o,FEEDBACK)==0:
            put(o,HELD,1)
            if get(w,META+16)==1 and get(o,OP)==11:
                return fail(o,0)
            if get(w,META+16)!=0 and get(o,OP)!=11:
                return fail(o,5)
            return again(o,100)
        return system(o,11,202,1,MUTEX,128,1,0,0,0)
    if phase==11:
        raw=get(o,FEEDBACK)
        if raw==0 or raw==NONE-3 or raw==NONE-10:
            return atom(o,2,10,0,1)
        return fail(o,6)
    if phase==20:
        if valid_number(o)==0:
            if get(o,FEEDBACK)!=0 or get(o,CHILD)!=NREP:
                return fail(o,9)
            if get(w,0)==0 or get(w,16)==1:
                put(w,META+16,1)
                return fail(o,get(o,CHILD+8))
            return initialization_failed(o,get(o,CHILD+8))
        return numbers(o,21,11,0)
    if phase==21:
        if valid_number(o)==0:
            return initialization_failed(o,4)
        take_number(o,w,GENS)
        return numbers(o,22,11,64)
    if phase==22:
        if valid_number(o)==0:
            return initialization_failed(o,4)
        take_number(o,w,EPOCH)
        value_request(o,1)
        put(o,VINPUT+72,1)
        store(o,VINPUT+128,48)
        return value_call(o,23,129)
    if phase==23:
        if valid_value(o)==0:
            return initialization_failed(o,4)
        take_value(o,w,ATTEMPTS)
        put(w,META+16,0)
        return identify(o,w,24,EPOCH,0)
    if phase==24:
        return identity_result(o,w,0)
    return fail(o,9)

def operation(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    op=get(o,OP)
    selector=get(o,SELECTOR)
    if phase==100:
        if op==1:
            if get(w,GENS+selector*32)!=0:
                return fail(o,5)
            return numbers(o,101,1,selector)
        if op==2:
            if get(w,PENDING)!=0:
                return fail(o,5)
            return numbers(o,110,2,0)
        if op==3:
            if get(w,PENDING)==0:
                return fail(o,5)
            return numbers(o,120,3,0)
        if op==4:
            return numbers(o,130,4,0)
        if op==5:
            at=selected(selector)
            if get(w,at)==0:
                return fail(o,1)
            return value_cap(o,w,140,2,at)
        if op==6:
            return numbers(o,150,5,selector)
        if op==7:
            return identify(o,w,141,selected(selector),0)
        if op==8 or op==13:
            if op==8 and owned(w,word(s,24))!=0:
                return fail(o,5)
            value_request(o,choose(op==8,3,8))
            put(o,VINPUT+24,word(s,24))
            put(o,VINPUT+32,word(s,32))
            put(o,VINPUT+40,word(s,40))
            return value_call(o,142,128)
        if op==9:
            return again(o,200)
        if op==10:
            at=EVENTS+selector*96
            copy(o,RESULT+16,w,at,96)
            put(o,RESULT+112,get(w,HEAD))
            put(o,RESULT+120,get(w,COUNT))
            return fail(o,0)
        if op==11:
            put(o,SCAN,get(w,80))
            return again(o,300)
        if op==12:
            return value_cap(o,w,160,4,ATTEMPTS)
        if op==14:
            value_request(o,1)
            put(o,VINPUT+72,1)
            store(o,VINPUT+128,48)
            return value_call(o,170,129)
        if op==15:
            value_request(o,4)
            put(o,VINPUT+24,word(s,24))
            put(o,VINPUT+32,word(s,32))
            put(o,VINPUT+40,word(s,40))
            return value_call(o,170,128)
        return fail(o,9)
    if phase==101:
        if valid_number(o)==0:
            return fail(o,4)
        return numbers(o,102,11,selector)
    if phase==102:
        if valid_number(o)==0:
            put(o,ERROR,4)
            return numbers(o,103,5,selector)
        take_number(o,w,GENS+selector*32)
        return identify(o,w,141,GENS+selector*32,0)
    if phase==103:
        if valid_number(o)==0:
            return fail(o,9)
        return drop_number_release(o,104)
    if phase==104:
        if valid_value(o)==0:
            return fail(o,9)
        return fail(o,4)
    if phase==110:
        if valid_number(o)==0:
            return fail(o,4)
        value_request(o,2)
        within(o,VINPUT+24,CHILD+16,24)
        return value_call(o,111,128)
    if phase==111:
        if valid_value(o)==0:
            put(o,ERROR,4)
            return numbers(o,112,4,0)
        take_value(o,w,PENDING)
        return identify(o,w,141,PENDING,0)
    if phase==112:
        if valid_number(o)==0:
            return fail(o,9)
        return drop_number_release(o,104)
    if phase==120:
        if valid_number(o)==0:
            return fail(o,9)
        return drop_number_release(o,121)
    if phase==121:
        if valid_value(o)==0:
            return fail(o,9)
        return value_cap(o,w,122,3,EPOCH)
    if phase==122:
        if valid_value(o)==0:
            return fail(o,9)
        within(w,EPOCH,PENDING,32)
        zero(w,PENDING,32)
        return identify(o,w,141,EPOCH,0)
    if phase==130:
        if valid_number(o)==0:
            return fail(o,9)
        if get(o,CHILD+64)==0:
            return identify(o,w,141,EPOCH,0)
        return drop_number_release(o,131)
    if phase==131:
        if valid_value(o)==0:
            return fail(o,9)
        if get(w,PENDING)==0:
            return identify(o,w,141,EPOCH,0)
        return value_cap(o,w,132,3,PENDING)
    if phase==132:
        if valid_value(o)==0:
            return fail(o,9)
        zero(w,PENDING,32)
        return identify(o,w,141,EPOCH,0)
    if phase==140:
        if valid_value(o)==0:
            return fail(o,4)
        within(o,SAVE,CHILD+16,32)
        put(o,RESULT+72,1)
        return memory(o,141,0,get(o,SAVE),3,NODE,96)
    if phase==141:
        return identity_result(o,w,0)
    if phase==142:
        if valid_value(o)==0:
            return fail(o,get(o,CHILD+8))
        if op==13:
            put(o,RESULT+48,get(o,CHILD+40))
            put(o,RESULT+80,get(o,CHILD+40))
        return fail(o,0)
    if phase==150:
        if valid_number(o)==0:
            return fail(o,9)
        if get(o,CHILD+64)==0:
            return fail(o,0)
        return drop_number_release(o,151)
    if phase==151:
        if valid_value(o)==0:
            return fail(o,9)
        at=GENS+selector*32
        if get(w,at)==0:
            return fail(o,0)
        return value_cap(o,w,152,3,at)
    if phase==152:
        if valid_value(o)==0:
            return fail(o,9)
        zero(w,GENS+selector*32,32)
        return fail(o,0)
    if phase==170:
        if valid_value(o)==0:
            return fail(o,get(o,CHILD+8))
        within(o,SAVE,CHILD+16,32)
        put(o,RESULT+72,1)
        return memory(o,171,0,get(o,SAVE),3,NODE,96)
    if phase==171:
        return identity_result(o,w,0)
    if phase==160:
        if valid_value(o)==0:
            return fail(o,4)
        within(o,SAVE,CHILD+16,32)
        return value_cap(o,w,161,3,ATTEMPTS)
    if phase==161:
        if valid_value(o)==0:
            return fail(o,9)
        copy(w,ATTEMPTS,o,SAVE,32)
        return identify(o,w,141,ATTEMPTS,0)
    return fail(o,9)

def event(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    at=EVENTS+get(w,HEAD)*96
    if phase==200:
        return value_cap(o,w,201,2,GENS+get(o,SELECTOR)*32)
    if phase==201:
        if valid_value(o)==0:
            return fail(o,4)
        within(o,SAVE,CHILD+16,32)
        return value_cap(o,w,202,2,EPOCH)
    if phase==202:
        if valid_value(o)==0:
            return saved_drop(o,209,SAVE)
        within(o,SAVE2,CHILD+16,32)
        if get(w,at)!=0:
            return value_cap(o,w,203,3,at)
        return again(o,203)
    if phase==203:
        if get(w,at)!=0 and valid_value(o)==0:
            return fail(o,9)
        if get(w,at+32)!=0:
            return value_cap(o,w,204,3,at+32)
        return again(o,204)
    if phase==204:
        if get(w,at+32)!=0 and valid_value(o)==0:
            return fail(o,9)
        copy(w,at,o,SAVE,32)
        copy(w,at+32,o,SAVE2,32)
        put(w,at+64,word(s,24))
        put(w,at+72,word(s,32))
        put(w,at+80,word(s,40))
        put(w,at+88,0)
        put(w,HEAD,choose(get(w,HEAD)==127,0,get(w,HEAD)+1))
        if get(w,COUNT)<128:
            put(w,COUNT,get(w,COUNT)+1)
        put(o,RESULT+96,get(w,HEAD))
        put(o,RESULT+104,get(w,COUNT))
        return fail(o,0)
    if phase==209:
        if valid_value(o)==0:
            return fail(o,9)
        return fail(o,4)
    return fail(o,9)

def disposal(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        node=get(o,SCAN)
        if node==0:
            put(o,INDEX,0)
            return again(o,310)
        if owned(w,node)==0:
            return fail(o,5)
        return memory(o,301,0,node,3,NODE,96)
    if phase==301:
        if get(o,NODE)!=NODE_MAGIC or get(o,NODE+64)!=get(o,PID):
            return fail(o,9)
        put(o,SCAN,get(o,NODE+24))
        return again(o,300)
    if phase==310:
        index=get(o,INDEX)
        while index<323:
            at=owned_at(index)
            if get(w,at)!=0:
                put(o,INDEX,index+1)
                put(o,TARGET,at)
                return value_cap(o,w,311,3,at)
            index=index+1
        return numbers(o,312,10,0)
    if phase==311:
        if valid_value(o)==0:
            return fail(o,9)
        zero(w,get(o,TARGET),32)
        return again(o,310)
    if phase==312:
        if valid_number(o)==0:
            return fail(o,9)
        put(w,META+16,1)
        return fail(o,get(o,ERROR))
    return fail(o,9)

def initialization_failed(o:mutbuf,error:u64) -> u32:
    put(o,ERROR,error)
    put(o,INDEX,0)
    return again(o,310)

def selected(selector:u64) -> u64:
    if selector<64:
        return GENS+selector*32
    if selector==64:
        return EPOCH
    if selector==65:
        return PENDING
    return ATTEMPTS

def owned_at(index:u64) -> u64:
    if index<64:
        return GENS+index*32
    if index<67:
        return EPOCH+(index-64)*32
    item=index-67
    return EVENTS+(item//2)*96+(item&1)*32

def owned(w:mutbuf,node:u64) -> u64:
    if node==0:
        return 0
    if get(w,320)==node or get(w,352)==node or get(w,384)==node:
        return 1
    i=0
    while i<64:
        if get(w,512+i*32)==node:
            return 1
        i=i+1
    i=0
    while i<323:
        if get(w,owned_at(i))==node:
            return 1
        i=i+1
    return 0

def identify(o:mutbuf,w:mutbuf,next:u64,at:u64,ownership:u64) -> u32:
    if get(w,at)==0:
        return fail(o,1)
    copy(o,SAVE,w,at,32)
    put(o,RESULT+72,ownership)
    return memory(o,next,0,get(o,SAVE),3,NODE,96)

def identity_result(o:mutbuf,w:mutbuf,status:u64) -> u32:
    if get(o,NODE)!=NODE_MAGIC or get(o,NODE+48)!=get(o,SAVE+8) or get(o,NODE+56)!=get(o,SAVE+16) or get(o,NODE+64)!=get(o,PID):
        return fail(o,9)
    put(o,RESULT+16,get(o,NODE+8))
    within(o,RESULT+24,SAVE,24)
    put(o,RESULT+48,get(o,SAVE+24))
    return fail(o,status)

def valid_number(o:mutbuf) -> u64:
    return choose(get(o,FEEDBACK)==0 and get(o,CHILD)==NREP and get(o,CHILD+8)==0,1,0)

def valid_value(o:mutbuf) -> u64:
    return choose(get(o,FEEDBACK)==0 and get(o,CHILD)==VREP_MAGIC and get(o,CHILD+8)==0,1,0)

def take_number(o:mutbuf,w:mutbuf,at:u64) -> u64:
    copy(w,at,o,CHILD+16,32)
    return 0

def take_value(o:mutbuf,w:mutbuf,at:u64) -> u64:
    copy(w,at,o,CHILD+16,32)
    return 0

def numbers(o:mutbuf,next:u64,op:u64,selector:u64) -> u32:
    zero(o,NINPUT,64)
    put(o,NINPUT,NREQ)
    put(o,NINPUT+8,op)
    put(o,NINPUT+16,selector)
    return role(o,next,11,NINPUT,64,CHILD,2048,0,8192)

def value_request(o:mutbuf,op:u64) -> u64:
    zero(o,VINPUT,128)
    put(o,VINPUT,VREQ_MAGIC)
    put(o,VINPUT+8,op)
    return 0

def value_cap(o:mutbuf,w:mutbuf,next:u64,op:u64,at:u64) -> u32:
    value_request(o,op)
    copy(o,VINPUT+24,w,at,24)
    return value_call(o,next,128)

def drop_number_release(o:mutbuf,next:u64) -> u32:
    value_request(o,3)
    within(o,VINPUT+24,CHILD+64,24)
    return value_call(o,next,128)

def saved_drop(o:mutbuf,next:u64,at:u64) -> u32:
    value_request(o,3)
    within(o,VINPUT+24,at,24)
    return value_call(o,next,128)

def value_call(o:mutbuf,next:u64,n:u64) -> u32:
    return role(o,next,12,VINPUT,n,CHILD,length(o)-CHILD,64,256)

def role(o:mutbuf,next:u64,action:u64,si:u64,sn:u64,oi:u64,on:u64,wi:u64,wn:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,si)
    put(o,8,sn)
    put(o,16,oi)
    put(o,24,on)
    put(o,32,wi)
    put(o,40,wn)
    return narrow(action)

def fail(o:mutbuf,error:u64) -> u32:
    put(o,ERROR,error)
    return again(o,900)

def finished(o:mutbuf) -> u32:
    within(o,16,RESULT+16,112)
    put(o,0,REP)
    put(o,8,get(o,ERROR))
    return 0

def again(o:mutbuf,next:u64) -> u32:
    put(o,PHASE,next)
    return 10

def atom(o:mutbuf,action:u64,next:u64,a:u64,b:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,MUTEX)
    put(o,8,a)
    put(o,16,b)
    return narrow(action)

def system(o:mutbuf,next:u64,nr:u64,flags:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,nr)
    put(o,8,flags)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1

def memory(o:mutbuf,next:u64,fromkind:u64,fromat:u64,tokind:u64,toat:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,fromkind)
    put(o,8,fromat)
    put(o,16,tokind)
    put(o,24,toat)
    put(o,32,n)
    return 8

def word(s:readbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(s,at+i)<<(i*8))
        i=i+1
    return value

def get(s:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(s,at+i)<<(i*8))
        i=i+1
    return value

def put(o:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(o,at+i,(value>>(i*8))&255)
        i=i+1
    return 0

def copy(o:mutbuf,to:u64,s:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(s,at+i))
        i=i+1
    return 0

def within(o:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(o,at+i))
        i=i+1
    return 0

def zero(o:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,at+i,0)
        i=i+1
    return 0

def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no

def narrow(value:u64) -> u32:
    return value
'''
def source_program():
 s=SOURCE
 for k,v in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+k+r'\b',str(v),s)
 return s
def main():
 tree=document(source_program(),'multiversion_runtime_identity');p=ROOT/'examples/hia_bootstrap/multiversion_runtime_identity.hepta';p.write_text(render_assembly(tree));print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']),flush=True)
if __name__=='__main__':main()
