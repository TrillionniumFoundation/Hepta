"""Actual native retirement of a registered BG allocation and its components.

A successful reply means the worker was joined (or never started), every
native child reference was actually consumed, and no local mapping remains.
Resource-queue pending belongs to the outer unique Value drain.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import hia_background_managed_value_source as M
from tools.generate_hia_background_optimizer_native_object_bind import LAYOUT
from tools.generate_hia_background_optimizer_native_object_construct import HELPERS
ROOT=Path(__file__).resolve().parents[1]
C={k:int.from_bytes(v.encode(),"little")for k,v in dict(
 INPUT="HIABGRT1",REPLY="HIABGTR1",OBJECT="HIABGOB1",
 CTOR="HIABPCQ1",CTOR_REPLY="HIABPCR1",PAYLOAD="HIABPY01",PAYLOAD_REPLY="HIABPYR1",
 PROVIDER="HIAMVBQ3",PROVIDER_REPLY="HIAMVBO2",FP="HIABFP04",FR="HIABFRP3",
 JOBS="HIABJM01",JOBS_REPLY="HIABJMR1",DECIMAL="HIAMVU01",DECIMAL_REPLY="HIAMVUR1",
 LEDGER="HIABLM01",LEDGER_REPLY="HIABLMR1",QUEUE="HIABGQ01",QUEUE_REPLY="HIABGQR1",
 WORKER="HIABGW04",WORKER_REPLY="HIABGWO2",BUSINESS_QUERY="HIABGWQ5",BUSINESS_REPLY="HIABGWR4",
 SHUT="HIABSHQ2",SHUT_REPLY="HIABSHR2",VPRIVATE="HIABVQ05",VACK="HIABVR02",VR="HIABVR01").items()}
C.update(MAX=(1<<64)-1,PH=128,FB=136,INDEX=144,AT=152,VALUE_QUEUE=160,STATUS=168,DETAIL=176,
 RQ=4096,RP=65536,OUT=786432,CONFIG_AT=LAYOUT["config"],GLOBAL_AT=LAYOUT["global_copy"],
 RUNTIME_AT=LAYOUT["runtime_copy"])
C.update({k.upper()+"_AT":v for k,v in LAYOUT.items()})
C["RECORD_BYTES"]=LAYOUT["record_bytes"]
SOURCE=r'''
def background_native_object_retire(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=16 or word_load(s,0)!=INPUT or word_load(s,8)!=0 or length(o)<OUT or length(w)!=RECORD_BYTES:
        return 4294967293
    phase=get(o,PH)
    if phase==0:
        if get(w,0)!=OBJECT or get(w,16)==0 or get(w,24)!=RECORD_BYTES or get(w,80)==0 or get(w,72)!=0 or get(w,752)!=1:
            return 4294967293
        zero(o,128,896)
        if get(w,160)!=0:
            return finish(o,w,11,0)
        if get(w,64)==4:
            return finish(o,w,0,0)
        put(w,64,3)
        return again(o,10)
    if phase<100:
        return stop_worker(o,w,phase)
    if phase<200:
        return close_children(o,w,phase)
    if phase<300:
        return close_factory(o,w,phase)
    if phase<400:
        return drop_payloads(o,w,phase)
    return drop_values(o,w,phase)

def stop_worker(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==10:
        if (get(w,56)&512)!=0:
            request(o,WORKER,3)
            return entry(o,w,14,5,RQ,128,RP,8192,WORKER_AT,512)
        return again(o,15)
    if phase==14:
        if valid(o,WORKER_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+24)>5 or get(o,RP+64)!=0:
            return unknown(o,w,14)
        state=get(o,RP+24)
        if state==0 or state==5:
            put(w,56,get(w,56)&(MAX-512))
            return again(o,15)
        request(o,SHUT,choose(get(w,SHUTDOWN_AT+184)!=0,1,0))
        return entry(o,w,11,11,RQ,128,RP,262144,SHUTDOWN_AT,16384)
    if phase==11:
        if valid(o,SHUT_REPLY)==0 or get(o,RP+80)!=0:
            return unknown(o,w,11)
        if get(o,RP+64)!=0:
            put(o,VALUE_QUEUE,1)
        if get(o,RP+8)!=0 or get(w,SHUTDOWN_AT+184)!=0 or get(o,RP+72)!=0:
            return finish(o,w,11,11)
        request(o,WORKER,2)
        return entry(o,w,12,5,RQ,128,RP,8192,WORKER_AT,512)
    if phase==12:
        if valid(o,WORKER_REPLY)==0 or get(o,RP+64)!=0:
            return unknown(o,w,12)
        if get(o,RP+8)!=0 or get(o,RP+24)!=4:
            # Self-worker retirement cannot acknowledge a join that has not
            # happened. The enclosing fixed reaper keeps this registry alive.
            return finish(o,w,11,12)
        put(w,56,get(w,56)&(MAX-512))
        if get(w,BUSINESS_AT+464)!=0:
            if get(w,BUSINESS_AT+480)!=1:
                return unknown(o,w,12)
            put(w,BUSINESS_AT+488,1)
            put(w,BUSINESS_AT+496,1)
            request(o,BUSINESS_QUERY,3)
            return entry(o,w,13,7,RQ,128,RP,128,BUSINESS_AT,1064960)
        return again(o,15)
    if phase==13:
        if valid(o,BUSINESS_REPLY)==0 or get(o,RP+8)!=0 or get(w,BUSINESS_AT+464)!=0:
            return finish(o,w,11,13)
        return again(o,15)
    if phase==15:
        if (get(w,56)&256)!=0:
            request(o,WORKER,5)
            return entry(o,w,16,5,RQ,128,RP,8192,WORKER_AT,512)
        return again(o,20)
    if phase==16:
        if valid(o,WORKER_REPLY)==0 or get(o,RP+8)!=0:
            return finish(o,w,11,16)
        put(w,56,get(w,56)&(MAX-256))
        return again(o,20)
    if phase==20:
        if (get(w,56)&128)!=0:
            request(o,QUEUE,4)
            return entry(o,w,21,0,RQ,128,RP,4096,QUEUE_AT,4096)
        return again(o,100)
    if phase==21:
        if valid(o,QUEUE_REPLY)==0 or get(o,RP+8)!=0:
            return finish(o,w,11,21)
        request(o,QUEUE,9)
        return entry(o,w,22,0,RQ,128,RP,4096,QUEUE_AT,4096)
    if phase==22:
        if valid(o,QUEUE_REPLY)==0 or get(o,RP+8)!=0:
            return finish(o,w,11,22)
        put(w,56,get(w,56)&(MAX-128))
        return again(o,100)
    return finish(o,w,11,phase)

def close_children(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if (get(w,56)&32)!=0:
            request(o,LEDGER,5)
            return entry(o,w,101,1,RQ,128,RP,8192,LEDGER_AT,4096)
        return again(o,110)
    if phase==101:
        if valid(o,LEDGER_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+160)!=0 or get(o,RP+144)!=0:
            return finish(o,w,11,101)
        request(o,LEDGER,3)
        return entry(o,w,102,1,RQ,128,RP,8192,LEDGER_AT,4096)
    if phase==102:
        if valid(o,LEDGER_REPLY)==0 or get(o,RP+8)!=0:
            return finish(o,w,11,102)
        put(w,56,get(w,56)&(MAX-32))
        return again(o,110)
    if phase==110:
        if (get(w,56)&8)!=0:
            request(o,JOBS,12)
            return entry(o,w,111,3,RQ,128,RP,16384,JOBS_AT,256)
        return again(o,120)
    if phase==111:
        if valid(o,JOBS_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+136)!=1 or get(o,RP+144)!=0 or get(o,RP+160)!=0 or get(o,RP+168)!=0:
            return finish(o,w,11,111)
        if get(o,RP+152)!=0:
            put(o,VALUE_QUEUE,1)
        request(o,JOBS,5)
        return entry(o,w,112,3,RQ,128,RP,16384,JOBS_AT,256)
    if phase==112:
        if valid(o,JOBS_REPLY)==0 or get(o,RP+8)!=0:
            return finish(o,w,11,112)
        put(w,56,get(w,56)&(MAX-8))
        return again(o,120)
    if phase==120:
        if (get(w,56)&16)!=0:
            request(o,DECIMAL,9)
            return entry(o,w,121,2,RQ,128,RP,16384,DECIMAL_AT,256)
        return again(o,130)
    if phase==121:
        if valid(o,DECIMAL_REPLY)==0 or get(o,RP+8)!=0:
            return finish(o,w,11,121)
        put(w,56,get(w,56)&(MAX-16))
        return again(o,130)
    if phase==130:
        if (get(w,56)&1)!=0:
            request(o,CTOR,1)
            return entry(o,w,131,16,RQ,192,RP,524288,CONSTRUCTOR_AT,294912)
        return again(o,200)
    if phase==131:
        if valid(o,CTOR_REPLY)==0 or get(o,RP+240)!=0:
            return finish(o,w,11,131)
        status=get(o,RP+8)
        if status==1 or status==2:
            if get(o,RP+16)!=0:
                if get(w,480)!=0:
                    return unknown(o,w,131)
                between(o,RP+16,w,480,24)
            if get(o,RP+72)!=0:
                if get(w,456)!=0:
                    return unknown(o,w,131)
                between(o,RP+72,w,456,24)
        elif status!=0:
            return finish(o,w,11,131)
        put(w,56,get(w,56)&(MAX-1))
        return again(o,200)
    return finish(o,w,11,phase)

def close_factory(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        if (get(w,56)&4)==0:
            return again(o,300)
        if get(w,216)==0:
            request(o,FP,28)
            between(w,192,o,RQ+16,24)
            return future(o,w,202)
        request(o,FP,27)
        between(w,192,o,RQ+16,24)
        between(w,216,o,RQ+40,24)
        return future(o,w,201)
    if phase==201:
        if valid(o,FR)==0 or get(o,RP+104)!=1 or get(o,RP+96)>1:
            return unknown(o,w,201)
        if get(o,RP+96)==1:
            zero(w,216,24)
        if get(o,RP+128)>1 or get(o,RP+136)>1 or get(o,RP+144)!=0:
            return unknown(o,w,201)
        if get(o,RP+136)!=0:
            put(o,VALUE_QUEUE,1)
        if get(o,RP+96)!=1:
            return finish(o,w,11,201)
        if get(o,RP+112)!=0 or get(o,RP+128)!=0:
            return finish(o,w,11,201)
        if get(o,RP+8)!=0:
            return finish(o,w,11,201)
        zero(w,192,24)
        put(w,56,get(w,56)&(MAX-4))
        return again(o,300)
    if phase==202:
        if valid(o,FR)==0 or get(o,RP+104)!=1 or get(o,RP+96)!=0 or get(o,RP+144)!=0:
            return unknown(o,w,202)
        if get(o,RP+136)!=0:
            put(o,VALUE_QUEUE,1)
        if get(o,RP+8)!=0 or get(o,RP+112)!=0 or get(o,RP+128)!=0:
            return finish(o,w,11,202)
        zero(w,192,24)
        put(w,56,get(w,56)&(MAX-4))
        return again(o,300)
    return finish(o,w,11,phase)

def drop_payloads(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        put(o,INDEX,0)
        return again(o,301)
    if phase==301:
        i=get(o,INDEX)
        if i==4:
            return again(o,310)
        at=choose(i==0,264,choose(i==1,408,choose(i==2,SUBMISSION_AT+664,480)))
        if get(w,at)==0:
            put(o,INDEX,i+1)
            return again(o,301)
        put(o,AT,at)
        request(o,PAYLOAD,3)
        between(w,at,o,RQ+24,24)
        return payload(o,w,302)
    if phase==302:
        if valid(o,PAYLOAD_REPLY)==0:
            return unknown(o,w,302)
        if get(o,RP+8)!=0:
            return finish(o,w,11,302)
        zero(w,get(o,AT),24)
        put(o,INDEX,get(o,INDEX)+1)
        return again(o,301)
    if phase==310:
        if get(w,240)==0:
            if get(w,744)!=0:
                request(o,PROVIDER,6)
                return provider(o,w,312)
            return again(o,400)
        request(o,PROVIDER,4)
        between(w,240,o,RQ+16,24)
        return provider(o,w,311)
    if phase==311:
        if valid(o,PROVIDER_REPLY)==0 or get(o,RP+72)!=1 or get(o,RP+80)>1 or get(o,RP+88)>1:
            return unknown(o,w,311)
        if get(o,RP+80)==1:
            zero(w,240,24)
        put(w,744,get(o,RP+88))
        if get(o,RP+80)!=1 or get(o,RP+8)!=0 or get(o,RP+88)!=0:
            return finish(o,w,11,311)
        return again(o,400)
    if phase==312:
        if valid(o,PROVIDER_REPLY)==0 or get(o,RP+72)!=1 or get(o,RP+80)!=0 or get(o,RP+88)>1:
            return unknown(o,w,312)
        put(w,744,get(o,RP+88))
        if get(o,RP+8)!=0 or get(o,RP+88)!=0:
            return finish(o,w,11,312)
        return again(o,400)
    return finish(o,w,11,phase)

def drop_values(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        put(o,INDEX,0)
        return again(o,401)
    if phase==401:
        i=get(o,INDEX)
        if i==10:
            return again(o,410)
        at=value_slot(i)
        if get(w,at)==0:
            put(o,INDEX,i+1)
            return again(o,401)
        put(o,AT,at)
        request(o,VPRIVATE,78)
        between(w,at,o,RQ+24,24)
        return values(o,w,402)
    if phase==402:
        if ack(o)==0:
            return unknown(o,w,402)
        if get(o,RP+96)==1:
            zero(w,get(o,AT),24)
        if get(o,RP+104)!=0:
            put(w,152,1)
        if get(o,RP+112)!=0:
            put(o,VALUE_QUEUE,1)
        if get(o,RP+96)!=1:
            return finish(o,w,11,402)
        put(o,INDEX,get(o,INDEX)+1)
        return again(o,401)
    if phase==410:
        if get(w,152)!=0:
            request(o,VPRIVATE,93)
            return values(o,w,411)
        put(w,56,get(w,56)&(MAX-66))
        if get(w,56)!=0:
            return finish(o,w,11,410)
        put(w,64,4)
        return finish(o,w,0,0)
    if phase==411:
        if ack(o)==0 or get(o,RP+96)!=0:
            return unknown(o,w,411)
        if get(o,RP+112)!=0:
            put(o,VALUE_QUEUE,1)
        if get(o,RP+104)!=0:
            return finish(o,w,11,411)
        status=get(o,RP+8)
        if status!=0 and status!=6:
            return finish(o,w,11,411)
        if status==6 and (get(o,RP+80)!=0 or get(o,RP+112)!=0):
            return finish(o,w,11,411)
        put(w,152,0)
        return again(o,410)
    return finish(o,w,11,phase)
def value_slot(i:u64) -> u64:
    if i==0:
        return 288
    if i==1:
        return 312
    if i==2:
        return 336
    if i==3:
        return 360
    if i==4:
        return 384
    if i==5:
        return SUBMISSION_AT+312
    if i==6:
        return 608
    if i==7:
        return 632
    if i==8:
        return 456
    return BUSINESS_AT+512
def ack(o:mutbuf) -> u64:
    if get(o,FB)!=0 or get(o,RP)!=VACK or get(o,RP+88)!=1 or get(o,RP+96)>1:
        return 0
    if get(o,RP+104)>1 or get(o,RP+112)>1 or get(o,RP+120)!=1:
        return 0
    if get(o,RP+104)==0 and get(o,RP+112)==0:
        if get(o,RP+80)!=0:
            return 0
    else:
        if get(o,RP+80)!=1:
            return 0
    if get(o,RP+8)!=0 and get(o,RP+8)!=1 and get(o,RP+8)!=6 and get(o,RP+8)!=11:
        return 0
    if get(o,RP+96)!=0 and get(o,RP+8)!=0 and get(o,RP+8)!=11:
        return 0
    return 1
def unknown(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    put(w,160,1)
    return finish(o,w,11,detail)
def finish(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,get(w,56))
    put(o,24,get(w,64))
    put(o,32,detail)
    put(o,64,get(w,152))
    put(o,72,get(o,VALUE_QUEUE))
    put(o,80,get(w,160))
    return 0
def ep(w:mutbuf,index:u64) -> u64:
    return get(w,CONFIG_AT+136+index*8)
def entry(o:mutbuf,w:mutbuf,next:u64,index:u64,src:u64,n:u64,dst:u64,on:u64,ctx:u64,wn:u64) -> u32:
    return invoke(o,next,ep(w,index),51,src,n,dst,on,get(w,16)+ctx,wn)
def values(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,GLOBAL_AT+32),51,RQ,128,RP,16384,get(w,GLOBAL_AT+40),256)
def future(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,GLOBAL_AT+56),51,RQ,192,RP,65536,get(w,GLOBAL_AT+64),256)
def payload(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,RUNTIME_AT+104),51,RQ,128,RP,512,get(w,RUNTIME_AT+112),256)
def provider(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,GLOBAL_AT+80),51,RQ,128,RP,128,get(w,GLOBAL_AT+88),768)
def valid(o:mutbuf,magic:u64) -> u64:
    if get(o,FB)!=0:
        return 0
    if get(o,RP)!=magic:
        return 0
    return 1
def request(o:mutbuf,magic:u64,op:u64) -> u64:
    zero(o,RQ,192)
    put(o,RQ,magic)
    put(o,RQ+8,op)
    return 0
'''
def source_program():return M.render(SOURCE+HELPERS,C,"background_native_object_retire")
def main():
    name="background_optimizer_native_object_retire";d=document(source_program(),name)
    p=ROOT/"examples/hia_bootstrap"/(name+".hepta");p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d["functions"]),sum(len(f["blocks"])for f in d["functions"]),sum(len(b["ops"])for f in d["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
