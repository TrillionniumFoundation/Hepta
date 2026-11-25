"""Actual native decimal-reference transactions for the multiversion owner.

This is a private fixed companion. Physical generation slots remain bounded;
public generations and epochs are immutable decimal objects with independent
strong-reference nodes. No machine-word counter is used for either value.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
C={
'MAGIC':int.from_bytes(b'HIAMVNB1','little'),'STATE':int.from_bytes(b'HIAMVNS1','little'),
'REPLY':int.from_bytes(b'HIAMVNR1','little'),'VREQ_MAGIC':int.from_bytes(b'HIAMVU01','little'),
'VREP_MAGIC':int.from_bytes(b'HIAMVUR1','little'),'NODE_MAGIC':int.from_bytes(b'HIAMVUN1','little'),
'NONE':(1<<64)-1,'NEGATIVE':(1<<64)-4095,'VCTX':64,
'NEXT_CAP':320,'EPOCH_CAP':352,'PENDING_CAP':384,'SLOTS':512,
'PHASE':128,'OP':136,'SLOT':144,'HELD':152,'ERROR':160,'AFTER':168,
'SCAN':176,'INDEX':184,'PID':192,'CAP_AT':200,'RESULT':768,
'FEEDBACK':240,'TEMP_CAP':256,'NODE':320,'VREQ':1280,'VOUT':1536,
}
SOURCE=r'''
def multiversion_runtime_numbers(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<2048 or length(w)<8192:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<30:
        return admission(s,o,w,phase)
    if phase<100:
        return initialize(s,o,w,phase)
    if phase<300:
        return operations(s,o,w,phase)
    if phase<500:
        return destroy(s,o,w,phase)
    return finish_steps(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=64 or word(s,0)!=MAGIC or word(s,48)!=0 or word(s,56)!=0:
        return 4294967293
    op=word(s,8)
    slot=word(s,16)
    if op>13:
        return 4294967293
    if op==1 or op==5 or op==7:
        if slot>=64:
            return 4294967293
    elif op==11:
        if slot>65:
            return 4294967293
    elif slot!=0:
        return 4294967293
    if op!=12 and op!=13:
        if word(s,24)!=0 or word(s,32)!=0 or word(s,40)!=0:
            return 4294967293
    zero(o,128,1152)
    put(o,OP,op)
    put(o,SLOT,slot)
    return system(o,1,39,0,0,0,0,0,0,0)

def admission(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid==0 or pid>=NEGATIVE:
            return finished(o,6)
        put(o,PID,pid)
        if get(o,OP)==0:
            at=0
            while at<8192:
                if byte(w,at)!=0:
                    return finished(o,5)
                at=at+1
            put(w,0,STATE)
            put(w,8,pid)
            put(w,16,2)
            return value(o,30,0,0,0)
        if get(w,0)!=STATE or get(w,8)!=pid or (get(w,16)!=0 and (get(o,OP)!=10 or get(w,16)!=2)):
            return finished(o,5)
        return atom(o,2,10,0,1)
    if phase==10:
        if get(o,FEEDBACK)==0:
            put(o,HELD,1)
            if get(w,16)!=0 and (get(o,OP)!=10 or get(w,16)!=2):
                return fail(o,5)
            return again(o,100)
        return system(o,11,202,1,24,128,1,0,0,0)
    if phase==11:
        result=get(o,FEEDBACK)
        if result==0 or result==NONE-3 or result==NONE-10:
            return atom(o,2,10,0,1)
        return fail(o,6)
    return fail(o,9)

def initialize(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==30:
        if valid_result(o)==0 or get(o,VOUT+8)!=0:
            return initialization_failed(o,w,6)
        return small(o,31,48)
    if phase==31:
        if valid_result(o)==0 or get(o,VOUT+8)!=0:
            return initialization_failed(o,w,4)
        take_result(o,w,EPOCH_CAP)
        return cap_value(o,w,32,2,EPOCH_CAP)
    if phase==32:
        if valid_result(o)==0 or get(o,VOUT+8)!=0:
            return initialization_failed(o,w,4)
        take_result(o,w,SLOTS)
        return small(o,33,49)
    if phase==33:
        if valid_result(o)==0 or get(o,VOUT+8)!=0:
            return initialization_failed(o,w,4)
        take_result(o,w,NEXT_CAP)
        put(w,16,0)
        result_cap(o,w,EPOCH_CAP)
        return finished(o,0)
    if phase==90:
        put(o,INDEX,0)
        return again(o,410)
    return fail(o,9)

def operations(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        op=get(o,OP)
        slot=get(o,SLOT)
        if op==1:
            if slot==0 or get(w,SLOTS+slot*32)!=0:
                return fail(o,5)
            return cap_value(o,w,101,4,NEXT_CAP)
        if op==2:
            if get(w,PENDING_CAP)!=0:
                return fail(o,5)
            return cap_value(o,w,102,4,EPOCH_CAP)
        if op==3:
            if get(w,PENDING_CAP)==0:
                return fail(o,5)
            release_result(o,w,EPOCH_CAP)
            move_cap(w,EPOCH_CAP,PENDING_CAP)
            zero(w,PENDING_CAP,32)
            result_cap(o,w,EPOCH_CAP)
            return fail(o,0)
        if op==4:
            if get(w,PENDING_CAP)==0:
                result_cap(o,w,EPOCH_CAP)
                return fail(o,0)
            release_result(o,w,PENDING_CAP)
            zero(w,PENDING_CAP,32)
            result_cap(o,w,EPOCH_CAP)
            return fail(o,0)
        if op==5:
            if slot==0:
                return fail(o,5)
            at=SLOTS+slot*32
            if get(w,at)==0:
                return fail(o,0)
            release_result(o,w,at)
            zero(w,at,32)
            return fail(o,0)
        if op==6:
            result_cap(o,w,EPOCH_CAP)
            put(o,RESULT+56,get(w,PENDING_CAP))
            return fail(o,0)
        if op==7:
            at=SLOTS+slot*32
            if get(w,at)==0:
                return fail(o,1)
            return cap_value(o,w,105,8,at)
        if op==8:
            return cap_value(o,w,105,8,EPOCH_CAP)
        if op==9:
            return cap_value(o,w,105,8,NEXT_CAP)
        if op==10:
            put(o,SCAN,get(w,VCTX+16))
            return again(o,300)
        if op==11:
            at=selector(slot)
            if get(w,at)==0:
                return fail(o,1)
            return cap_value(o,w,106,2,at)
        if op==12 or op==13:
            if op==12 and owned_pointer(w,word(s,24))!=0:
                return fail(o,5)
            put(o,TEMP_CAP,word(s,24))
            put(o,TEMP_CAP+8,word(s,32))
            put(o,TEMP_CAP+16,word(s,40))
            return saved_value(o,choose(op==12,107,105),choose(op==12,3,8))
        return fail(o,9)
    if phase==101:
        if valid_result(o)==0:
            return fail(o,9)
        if get(o,VOUT+8)!=0:
            return fail(o,get(o,VOUT+8))
        at=SLOTS+get(o,SLOT)*32
        move_cap(w,at,NEXT_CAP)
        take_result(o,w,NEXT_CAP)
        result_cap(o,w,at)
        return fail(o,0)
    if phase==102:
        if valid_result(o)==0:
            return fail(o,9)
        if get(o,VOUT+8)!=0:
            return fail(o,get(o,VOUT+8))
        take_result(o,w,PENDING_CAP)
        result_cap(o,w,PENDING_CAP)
        return fail(o,0)
    if phase==103:
        result_cap(o,w,EPOCH_CAP)
        return value_done(o)
    if phase==104 or phase==107:
        return value_done(o)
    if phase==105:
        if valid_result(o)==0:
            return fail(o,9)
        if get(o,VOUT+8)!=0:
            return fail(o,get(o,VOUT+8))
        put(o,RESULT+40,get(o,VOUT+40))
        put(o,RESULT+48,get(o,VOUT+40))
        return fail(o,0)
    if phase==106:
        if valid_result(o)==0:
            return fail(o,9)
        if get(o,VOUT+8)!=0:
            return fail(o,get(o,VOUT+8))
        within(o,RESULT+16,VOUT+16,32)
        return fail(o,0)
    return fail(o,9)

def destroy(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        pointer=get(o,SCAN)
        if pointer==0:
            put(o,INDEX,0)
            put(w,16,2)
            return again(o,410)
        if owned_pointer(w,pointer)==0:
            return fail(o,5)
        return memory(o,301,0,pointer,3,NODE,96)
    if phase==301:
        if get(o,NODE)!=NODE_MAGIC or get(o,NODE+64)!=get(o,PID):
            return fail(o,9)
        put(o,SCAN,get(o,NODE+24))
        return again(o,300)
    if phase==410:
        index=get(o,INDEX)
        while index<67:
            at=owned_at(index)
            if get(w,at)!=0:
                put(o,INDEX,index+1)
                save_cap(o,w,at)
                return saved_value(o,411,3)
            index=index+1
        return value(o,412,9,0,0)
    if phase==411:
        if valid_result(o)==0 or get(o,VOUT+8)!=0:
            return fail(o,9)
        zero(w,owned_at(get(o,INDEX)-1),32)
        return again(o,410)
    if phase==412:
        if valid_result(o)==0 or get(o,VOUT+8)!=0:
            return fail(o,9)
        put(w,16,1)
        return fail(o,get(o,ERROR))
    return fail(o,9)

def finish_steps(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==900:
        if get(o,HELD)!=0:
            put(o,HELD,0)
            return atom(o,3,901,0,0)
        return finished(o,get(o,ERROR))
    if phase==901:
        return system(o,902,202,1,24,129,2147483647,0,0,0)
    if phase==902:
        return finished(o,get(o,ERROR))
    return finished(o,9)

def initialization_failed(o:mutbuf,w:mutbuf,error:u64) -> u32:
    put(o,ERROR,error)
    return again(o,90)

def valid_result(o:mutbuf) -> u64:
    return choose(get(o,FEEDBACK)==0 and get(o,VOUT)==VREP_MAGIC,1,0)

def value_done(o:mutbuf) -> u32:
    if valid_result(o)==0:
        return fail(o,9)
    return fail(o,get(o,VOUT+8))

def value(o:mutbuf,next:u64,op:u64,a:u64,b:u64) -> u32:
    zero(o,VREQ,128)
    put(o,VREQ,VREQ_MAGIC)
    put(o,VREQ+8,op)
    if a!=0:
        within(o,VREQ+24,a,24)
    if b!=0:
        within(o,VREQ+48,b,24)
    put(o,PHASE,next)
    put(o,0,VREQ)
    put(o,8,128)
    put(o,16,VOUT)
    put(o,24,length(o)-VOUT)
    put(o,32,VCTX)
    put(o,40,256)
    return 11

def cap_value(o:mutbuf,w:mutbuf,next:u64,op:u64,at:u64) -> u32:
    save_cap(o,w,at)
    return saved_value(o,next,op)

def saved_value(o:mutbuf,next:u64,op:u64) -> u32:
    return value(o,next,op,TEMP_CAP,0)

def small(o:mutbuf,next:u64,digit:u64) -> u32:
    value(o,next,1,0,0)
    put(o,VREQ+72,1)
    store(o,VREQ+128,digit)
    put(o,8,129)
    return 11

def owned_at(index:u64) -> u64:
    if index<64:
        return SLOTS+index*32
    if index==64:
        return NEXT_CAP
    if index==65:
        return EPOCH_CAP
    return PENDING_CAP

def selector(index:u64) -> u64:
    if index<64:
        return SLOTS+index*32
    if index==64:
        return EPOCH_CAP
    return NEXT_CAP

def owned_pointer(w:mutbuf,pointer:u64) -> u64:
    index=0
    while index<67:
        if get(w,owned_at(index))==pointer:
            return 1
        index=index+1
    return 0

def save_cap(o:mutbuf,w:mutbuf,at:u64) -> u64:
    copy(o,TEMP_CAP,w,at,32)
    return 0

def take_result(o:mutbuf,w:mutbuf,at:u64) -> u64:
    copy(w,at,o,VOUT+16,32)
    return 0

def move_cap(w:mutbuf,to:u64,at:u64) -> u64:
    within(w,to,at,32)
    return 0

def result_cap(o:mutbuf,w:mutbuf,at:u64) -> u64:
    copy(o,RESULT+16,w,at,32)
    return 0

def release_result(o:mutbuf,w:mutbuf,at:u64) -> u64:
    copy(o,RESULT+64,w,at,32)
    return 0

def fail(o:mutbuf,error:u64) -> u32:
    put(o,ERROR,error)
    return again(o,900)

def finished(o:mutbuf,error:u64) -> u32:
    # Successful cap/copy fields were saved away from mechanical call words.
    within(o,16,RESULT+16,112)
    put(o,0,REPLY)
    put(o,8,error)
    return 0

def again(o:mutbuf,next:u64) -> u32:
    put(o,PHASE,next)
    return 10

def atom(o:mutbuf,action:u64,next:u64,a:u64,b:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,24)
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
    result=0
    i=0
    while i<8:
        result=result|(byte(s,at+i)<<(8*i))
        i=i+1
    return result

def get(s:mutbuf,at:u64) -> u64:
    result=0
    i=0
    while i<8:
        result=result|(byte(s,at+i)<<(8*i))
        i=i+1
    return result

def put(o:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(o,at+i,(value>>(8*i))&255)
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

def narrow(value:u64) -> u32:
    return value
'''
def source_program():
    source=SOURCE
    for k,v in C.items():source=re.sub(r'\b'+k+r'\b',str(v),source)
    return source
def main():
    t=document(source_program(),'multiversion_runtime_numbers')
    p=ROOT/'examples/hia_bootstrap/multiversion_runtime_numbers.hepta';p.write_text(render_assembly(t))
    print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
