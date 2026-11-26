"""Native methods on a nonce-qualified registered BG record.

The enclosing raw owner holds a real record-active guard across these calls.
Only actual captured entries are invoked. Public Value publication and its
strong pin remain the responsibility of the fixed enclosing resource producer.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import hia_background_managed_value_source as M
from tools.generate_hia_background_optimizer_native_object_bind import LAYOUT
from tools.generate_hia_background_optimizer_native_object_construct import HELPERS
ROOT=Path(__file__).resolve().parents[1]
C={k:int.from_bytes(v.encode(),"little")for k,v in dict(
 INPUT="HIABGOQ2",REPLY="HIABGMR1",OBJECT="HIABGOB1",WORKER="HIABGW04",WORKER_REPLY="HIABGWO2",
 SNAP="HIABSPQ2",SNAP_REPLY="HIABSPR2",SHUT="HIABSHQ2",SHUT_REPLY="HIABSHR2",
 SUB="HIABSM01",SUB_REPLY="HIABSMR1",PAYLOAD="HIABPY01",PAYLOAD_REPLY="HIABPYR1",VQUERY="HIABVQ06",VPRIVATE="HIABVQ05",
 VR="HIABVR01",VACK="HIABVR02").items()}
C.update(PH=128,FB=136,OP=144,DETAIL=152,QUEUE=160,MAP=168,UNKNOWN=176,
 DELIVERED=184,RESULT_KIND=192,CHILD_STATUS=200,CHILD_KIND=208,INDEX=216,ERROR_STATUS=224,
 RESULT=1024,SAVED=2048,RQ=4096,RP=65536,OUT=786432,CONFIG_AT=1024,GLOBAL_AT=2048)
C.update({k.upper()+"_AT":v for k,v in LAYOUT.items()});C["RECORD_BYTES"]=LAYOUT["record_bytes"]
SOURCE=r'''
def background_native_object_methods(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=192 or word_load(s,0)!=INPUT or word_load(s,8)<3 or word_load(s,8)>8 or length(o)<OUT or length(w)!=RECORD_BYTES:
        return 4294967293
    phase=get(o,PH)
    if phase==0:
        if get(w,0)!=OBJECT or get(w,16)==0 or get(w,24)!=RECORD_BYTES or get(w,72)==0 or get(w,160)!=0:
            return 4294967293
        if get(w,64)!=1 and get(w,64)!=2:
            if word_load(s,8)!=8 or get(w,64)!=5:
                return 4294967293
        zero(o,128,2944)
        zero(o,RP,192)
        put(o,OP,word_load(s,8))
        op=get(o,OP)
        if op==3:
            if (get(w,56)&256)==0 or (get(w,56)&512)!=0:
                return finish(o,6,0)
            put(w,56,get(w,56)|512)
            request(o,WORKER,1)
            return entry(o,w,10,5,RQ,128,RP,8192,WORKER_AT,512)
        if op==4:
            request(o,SNAP,choose(get(w,SNAPSHOT_AT+216)!=0,1,0))
            return entry(o,w,20,10,RQ,128,RP,262144,SNAPSHOT_AT,8192)
        if op==5:
            retry=choose(get(w,SHUTDOWN_AT+184)!=0,1,0)
            request(o,SHUT,retry)
            if retry==0:
                copy_s(s,48,o,RQ+16,48)
            return entry(o,w,30,11,RQ,128,RP,262144,SHUTDOWN_AT,16384)
        if op==6:
            request(o,SUB,choose(get(w,SUBMISSION_AT+792)!=0,1,0))
            if get(w,SUBMISSION_AT+792)==0:
                copy_s(s,48,o,RQ+24,96)
            return entry(o,w,40,6,RQ,128,RP,524288,SUBMISSION_AT,8192)
        if op==7:
            if get(w,64)!=1 or (get(w,56)&1024)!=0 or get(w,104)!=0:
                return finish(o,6,0)
            request(o,VQUERY,49)
            copy_s(s,48,o,RQ+24,24)
            return values(o,w,50)
        if get(w,456)==0:
            if get(w,480)==0:
                return finish(o,1,0)
            request(o,PAYLOAD,2)
            between(w,480,o,RQ+24,24)
            return invoke(o,71,get(w,RUNTIME_COPY_AT+104),51,RQ,128,RP,512,get(w,RUNTIME_COPY_AT+112),256)
        request(o,VPRIVATE,91)
        between(w,456,o,RQ+24,24)
        return values(o,w,70)
    if phase<50:
        return method_reply(o,w,phase)
    if phase<70:
        return bind_resource(s,o,w,phase)
    if phase==70:
        if valid(o,VR)==0 or get(o,RP+88)!=1 or get(o,RP+96)>1:
            return unknown(o,70)
        if get(o,RP+96)==1:
            if primary(o,RP+24,2)==0:
                return unknown(o,70)
        if get(o,RP+104)>1 or get(o,RP+112)>1 or get(o,RP+120)!=1:
            return unknown(o,70)
        put(o,MAP,get(o,RP+104))
        put(o,QUEUE,get(o,RP+112))
        return finish(o,get(o,RP+8),70)
    if phase==71:
        if valid(o,PAYLOAD_REPLY)==0 or get(o,RP+8)!=0:
            return unknown(o,71)
        if primary(o,RP+16,3)==0:
            return unknown(o,71)
        put(o,CHILD_KIND,get(w,672))
        put(o,ERROR_STATUS,get(w,688))
        return finish(o,0,get(w,680))
    return unknown(o,phase)

def method_reply(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==10:
        if valid(o,WORKER_REPLY)==0 or get(o,RP+24)>5 or get(o,RP+56)>1 or get(o,RP+64)>1:
            return unknown(o,10)
        put(o,QUEUE,get(o,RP+56))
        put(o,UNKNOWN,get(o,RP+64))
        state=get(o,RP+24)
        if get(o,RP+8)!=0:
            if state==0 or state==5:
                put(w,56,get(w,56)&18446744073709551103)
            return finish(o,get(o,RP+8),10)
        if state!=1 and state!=2 and state!=3:
            return unknown(o,10)
        put(w,64,2)
        return finish(o,0,0)
    if phase==20:
        if valid(o,SNAP_REPLY)==0 or pending(o,64,72,80,88)==0:
            return unknown(o,20)
        if get(o,RP+16)==1:
            if primary(o,RP+24,1)==0:
                return unknown(o,20)
        elif get(o,RP+24)!=0 or get(o,RP+32)!=0 or get(o,RP+40)!=0:
            return unknown(o,20)
        return finish(o,get(o,RP+8),get(o,RP+56))
    if phase==30:
        if valid(o,SHUT_REPLY)==0 or pending(o,64,72,80,88)==0:
            return unknown(o,30)
        if get(o,RP+24)!=0:
            if primary(o,RP+24,2)==0:
                return unknown(o,30)
        put(o,CHILD_KIND,get(o,RP+16))
        return finish(o,get(o,RP+8),get(o,RP+48))
    if phase==40:
        if valid(o,SUB_REPLY)==0 or pending(o,128,136,144,160)==0:
            return unknown(o,40)
        if get(o,RP+152)>1:
            return unknown(o,40)
        if get(o,RP+152)==1:
            if primary(o,RP+24,1)==0:
                return unknown(o,40)
        status=get(o,RP+8)
        if status==2 and get(o,RP+24)!=0:
            if primary(o,RP+24,3)==0:
                return unknown(o,40)
        elif status==3 and get(o,RP+24)!=0:
            if primary(o,RP+24,2)==0:
                return unknown(o,40)
        put(o,CHILD_KIND,get(o,RP+16))
        return finish(o,status,get(o,RP+96))
    return unknown(o,phase)

def bind_resource(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==50:
        if valid(o,VR)==0 or get(o,RP+8)!=0 or get(o,RP+16)!=6:
            return finish(o,1,50)
        if get(o,RP+24)!=get(w,80) or get(o,RP+32)!=get(w,88) or get(o,RP+40)!=get(w,96):
            return finish(o,1,50)
        request(o,VPRIVATE,80)
        copy_s(s,48,o,RQ+24,24)
        return values(o,w,51)
    if phase==51:
        if valid(o,VR)==0 or get(o,RP+8)!=0 or get(o,RP+16)!=8 or get(o,RP+48)!=6 or get(o,RP+24)==0:
            return unknown(o,51)
        between(o,RP+24,w,104,24)
        between(o,RP+24,w,SUBMISSION_AT+864,24)
        between(o,RP+24,w,BUSINESS_AT+544,24)
        put(o,INDEX,0)
        return again(o,52)
    if phase==52:
        i=get(o,INDEX)
        if i==8:
            put(w,56,get(w,56)|1024)
            return finish(o,0,0)
        at=288
        if i==1:
            at=312
        elif i==2:
            at=336
        elif i==3:
            at=360
        elif i==4:
            at=SUBMISSION_AT+312
        elif i==5:
            at=608
        elif i==6:
            at=632
        elif i==7:
            at=456
        if get(w,at)==0:
            put(o,INDEX,i+1)
            return again(o,52)
        request(o,VPRIVATE,77)
        copy_s(s,48,o,RQ+24,24)
        between(w,at,o,RQ+48,24)
        return values(o,w,53)
    if phase==53:
        if valid(o,VACK)==0 or get(o,RP+88)!=1 or get(o,RP+96)!=1 or get(o,RP+8)!=0 or get(o,RP+80)>1:
            return unknown(o,53)
        if get(o,RP+104)!=0 or get(o,RP+112)!=0 or get(o,RP+120)!=0:
            return unknown(o,53)
        if get(o,RP+80)!=0:
            put(o,QUEUE,1)
        put(o,INDEX,get(o,INDEX)+1)
        return again(o,52)
    return unknown(o,phase)
def primary(o:mutbuf,at:u64,kind:u64) -> u64:
    if get(o,RESULT)!=0 or get(o,at)==0 or get(o,at+8)==0 or get(o,at+16)==0:
        return 0
    within(o,RESULT,at,24)
    put(o,DELIVERED,1)
    put(o,RESULT_KIND,kind)
    return 1
def pending(o:mutbuf,q:u64,m:u64,u:u64,marker:u64) -> u64:
    if get(o,RP+q)>1 or get(o,RP+m)>1 or get(o,RP+u)>1 or get(o,RP+marker)!=1:
        return 0
    put(o,QUEUE,get(o,RP+q))
    put(o,MAP,get(o,RP+m))
    put(o,UNKNOWN,get(o,RP+u))
    return 1
def unknown(o:mutbuf,detail:u64) -> u32:
    put(o,UNKNOWN,1)
    return finish(o,11,detail)
def finish(o:mutbuf,status:u64,detail:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,get(o,OP))
    put(o,24,get(o,RESULT_KIND))
    within(o,32,RESULT,24)
    put(o,56,get(o,DELIVERED))
    put(o,64,detail)
    put(o,72,get(o,MAP))
    put(o,80,get(o,QUEUE))
    put(o,88,get(o,UNKNOWN))
    put(o,96,get(o,FB))
    put(o,104,get(o,RP+8))
    put(o,112,get(o,CHILD_KIND))
    put(o,120,get(o,ERROR_STATUS))
    return 0
def values(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,GLOBAL_AT+32),51,RQ,128,RP,16384,get(w,GLOBAL_AT+40),256)
def entry(o:mutbuf,w:mutbuf,next:u64,index:u64,src:u64,n:u64,dst:u64,on:u64,ctx:u64,wn:u64) -> u32:
    return invoke(o,next,get(w,CONFIG_AT+136+index*8),51,src,n,dst,on,get(w,16)+ctx,wn)
def request(o:mutbuf,magic:u64,op:u64) -> u64:
    zero(o,RQ,192)
    put(o,RQ,magic)
    put(o,RQ+8,op)
    return 0
def valid(o:mutbuf,magic:u64) -> u64:
    if get(o,FB)==0 and get(o,RP)==magic:
        return 1
    return 0
def within(b:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(b,to+i,byte(b,at+i))
        i=i+1
    return 0
'''
def source_program():return M.render(SOURCE+HELPERS,C,"background_native_object_methods")
def main():
    name="background_optimizer_native_object_methods";d=document(source_program(),name)
    p=ROOT/"examples/hia_bootstrap"/(name+".hepta");p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d["functions"]),sum(len(f["blocks"])for f in d["functions"]),sum(len(b["ops"])for f in d["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
