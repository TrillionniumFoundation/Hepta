"""Autonomous native BG retirement thread and synchronized completion receipt.

Only fixed native producers create its registry record. Every join is outside
Value and BG locks. The second actual fixed RFQ completion, not Value56's
aggregate status, is the authority for releasing the thread's context token.
"""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import hia_background_managed_value_source as M
from tools import generate_hia_background_optimizer_native_context as context
ROOT=Path(__file__).resolve().parents[1]
C={k:int.from_bytes(v.encode(),"little")for k,v in dict(
 INPUT="HIABRTQ1",REPLY="HIABRTR1",STATE="HIABRTC1",BG="HIABGNC1",CONFIG="HIABGCF1",
 SHUT="HIABSHQ2",SHUT_REPLY="HIABSHR2",WORKER="HIABGW04",WORKER_REPLY="HIABGWO2",
 VALUE_PRIVATE="HIABVQ05",VALUE_REPLY="HIABVR01",VALUE_ACK="HIABVR02",
 QUEUE="HIABGQ04",QUEUE_REPLY="HIABGQR2").items()}
C.update(MAX=(1<<64)-1,NEGATIVE=(1<<64)-4095,PH=128,FB=136,OP=144,NEXT=152,HELD=160,
 PID=168,SELF=176,ACTUAL_ENTRY=184,ERROR=192,DETAIL=200,FACT_SELF=1024,FACT_ENTRY=1032,
 BG_HEADER=1536,CONFIG_HEADER=2048,RQ=4096,RP=65536,HELPER_OUT=8192,MAIN_OUT=786432,
 RECORD_BYTES=1048576,WORKER_AT=8704,SHUTDOWN_AT=1183744,QUEUE_AT=4096,MUTEX=320)
SOURCE=r'''
def background_native_reaper_thread(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or length(o)<HELPER_OUT or length(w)!=512:
        return 4294967293
    phase=get(o,PH)
    if phase==0:
        if word_load(s,0)!=INPUT or word_load(s,8)>3:
            return 4294967293
        op=word_load(s,8)
        if op==0 and length(o)<MAIN_OUT:
            return 4294967293
        if op==1:
            if word_load(s,24)>1 or word_load(s,32)>1 or word_load(s,40)>1 or word_load(s,48)>1 or read_zero(s,56,72)==0:
                return 4294967293
        elif read_zero(s,16,112)==0:
            return 4294967293
        zero(o,128,896)
        put(o,OP,op)
        return system(o,1,39,0,0,0,0,0,0,0)
    if phase<100:
        return admission(o,w,phase)
    if phase<200:
        return locks(o,w,phase)
    if phase<300:
        return command(s,o,w,phase)
    if phase<400:
        return worker_join(o,w,phase)
    if phase<500:
        return drain(o,w,phase)
    if phase<600:
        return drop_token(o,w,phase)
    return finish(o,w,get(o,ERROR))

def admission(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        if get(o,FB)<2 or get(o,FB)>=NEGATIVE:
            return finish(o,w,11)
        put(o,PID,get(o,FB))
        put(o,PH,2)
        return 15
    if phase==2:
        put(o,SELF,get(o,FACT_SELF))
        put(o,ACTUAL_ENTRY,get(o,FACT_ENTRY))
        if get(w,0)!=STATE or get(w,8)!=get(o,PID) or get(w,16)!=get(o,SELF):
            return finish(o,w,11)
        if get(w,24)==0 or get(w,24)>MAX-512 or get(w,32)==0 or get(w,328)!=1:
            return finish(o,w,11)
        if get(w,40)==0 or get(w,48)==0 or get(w,56)!=256 or get(w,344)!=get(o,ACTUAL_ENTRY):
            return finish(o,w,11)
        if get(w,64)==0 or get(w,72)==0 or get(w,80)==0:
            return finish(o,w,11)
        return memory(o,3,0,get(w,24),3,BG_HEADER,512)
    if phase==3:
        if get(o,BG_HEADER)!=BG or get(o,BG_HEADER+8)!=get(o,PID) or get(o,BG_HEADER+16)!=get(w,24):
            return finish(o,w,11)
        if get(o,BG_HEADER+128)!=get(w,32) or get(o,BG_HEADER+32)!=get(w,40) or get(o,BG_HEADER+40)!=get(w,48):
            return finish(o,w,11)
        if get(o,BG_HEADER+168)!=1 and get(o,BG_HEADER+168)!=2:
            return finish(o,w,11)
        if get(o,BG_HEADER+240)==0 or get(o,BG_HEADER+248)!=1024:
            return finish(o,w,11)
        return memory(o,4,0,get(o,BG_HEADER+240),3,CONFIG_HEADER,512)
    if phase==4:
        if get(o,CONFIG_HEADER)!=CONFIG or get(o,CONFIG_HEADER+16)!=get(w,24) or get(o,CONFIG_HEADER+24)!=get(w,32) or get(o,CONFIG_HEADER+128)!=40:
            return finish(o,w,11)
        if get(w,352)!=get(o,CONFIG_HEADER+136+5*8) or get(w,360)!=get(o,CONFIG_HEADER+136+11*8) or get(w,392)!=get(o,CONFIG_HEADER+136):
            return finish(o,w,11)
        return lock(o,200)
    return finish(o,w,11)

def locks(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if get(o,FB)==0:
            put(o,HELD,1)
            return again(o,get(o,NEXT))
        return system(o,101,202,1,MUTEX,128,1,0,0,0)
    if phase==101:
        if get(o,FB)!=0 and get(o,FB)!=MAX-3 and get(o,FB)!=MAX-10:
            return system(o,104,24,0,0,0,0,0,0,0)
        return lock(o,get(o,NEXT))
    if phase==104:
        return lock(o,get(o,NEXT))
    if phase==102:
        return system(o,103,202,1,MUTEX,129,2147483647,0,0,0)
    if phase==103:
        return again(o,get(o,NEXT))
    return fail(o,w,11,phase)

def command(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        op=get(o,OP)
        if op==1:
            # A synchronized record survives consumption of the BG object.
            put(w,216,word_load(s,16))
            put(w,224,word_load(s,24))
            put(w,232,word_load(s,32))
            put(w,240,word_load(s,40))
            put(w,248,word_load(s,48))
            if word_load(s,24)==0 or word_load(s,48)!=0:
                put(w,336,1)
            put(w,208,get(w,208)+1)
            return fail(o,w,0,0)
        if op==2:
            return fail(o,w,0,0)
        if op==3:
            if get(w,160)==9 and get(w,296)==1:
                return fail(o,w,0,0)
            if get(w,160)!=7 or get(w,176)!=1 or get(w,288)!=0 or get(w,184)!=0 or get(w,256)!=0 or get(w,336)!=0:
                return fail(o,w,6,201)
            put(w,288,1)
            return unlock(o,220)
        if get(w,160)!=2 or get(w,184)==0 or get(w,136)==0 or get(w,144)!=2097152 or get(w,152)==0:
            return fail(o,w,11,202)
        if get(w,352)==0 or get(w,360)==0 or get(w,392)==0:
            return fail(o,w,11,203)
        put(w,160,3)
        return unlock(o,300)
    if phase==220:
        put(o,PH,221)
        return 17
    if phase==221:
        put(o,ERROR,get(o,FB))
        return lock(o,222)
    if phase==222:
        put(w,288,0)
        if get(o,ERROR)!=0:
            return fail(o,w,11,222)
        put(w,296,1)
        put(w,160,9)
        return fail(o,w,0,0)
    return fail(o,w,11,phase)

def worker_join(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        return system(o,301,186,0,0,0,0,0,0,0)
    if phase==301:
        if get(o,FB)<2 or get(o,FB)>=NEGATIVE:
            return quarantine(o,w,301)
        put(w,304,get(o,FB))
        # Read closed under the queue's actual transaction, without cloning jobs.
        # An explicit drain shutdown must not be replaced by default cancellation.
        request(o,QUEUE,10)
        return invoke(o,320,get(w,392),51,RQ,128,RP,4096,get(w,136)+QUEUE_AT,4096)
    if phase==320:
        if get(o,FB)!=0 or get(o,RP)!=QUEUE_REPLY or get(o,RP+8)!=0:
            return quarantine(o,w,320)
        put(w,416,1)
        if get(o,RP+24)>1 or get(o,RP+56)!=0 or get(o,RP+64)!=0 or get(o,RP+120)!=0:
            return quarantine(o,w,321)
        put(w,424,get(o,RP+24))
        request(o,QUEUE,11)
        return invoke(o,321,get(w,392),51,RQ,128,RP,4096,get(w,136)+QUEUE_AT,4096)
    if phase==321:
        if get(o,FB)!=0 or get(o,RP)!=QUEUE_REPLY or get(o,RP+8)!=0 or get(o,RP+56)!=0 or get(o,RP+64)!=0 or get(o,RP+120)!=0:
            return quarantine(o,w,322)
        put(w,416,0)
        if get(w,424)!=0:
            put(w,432,1)
            request(o,WORKER,2)
            return invoke(o,322,get(w,352),51,RQ,128,RP,8192,get(w,136)+WORKER_AT,512)
        # No Value/BG/finalizer/queue mutex is held across the actual join.
        request(o,SHUT,0)
        return invoke(o,302,get(w,360),51,RQ,128,RP,262144,get(w,136)+SHUTDOWN_AT,16384)
    if phase==322:
        if get(o,FB)!=0 or get(o,RP)!=WORKER_REPLY or get(o,RP+8)!=0 or get(o,RP+64)!=0:
            return quarantine(o,w,323)
        request(o,WORKER,3)
        return invoke(o,303,get(w,352),51,RQ,128,RP,8192,get(w,136)+WORKER_AT,512)
    if phase==302:
        if get(o,FB)!=0 or get(o,RP)!=SHUT_REPLY or get(o,RP+80)!=0:
            return quarantine(o,w,302)
        if get(o,RP+8)!=0 or get(o,RP+72)!=0:
            # Preserve any returned exception or incomplete native cleanup.
            if get(o,RP+24)!=0:
                within_to_record(o,w,RP+24,368,24)
            return quarantine(o,w,303)
        request(o,WORKER,3)
        return invoke(o,303,get(w,352),51,RQ,128,RP,8192,get(w,136)+WORKER_AT,512)
    if phase==303:
        if get(o,FB)!=0 or get(o,RP)!=WORKER_REPLY or get(o,RP+8)!=0 or get(o,RP+24)!=4 or get(o,RP+64)!=0:
            return quarantine(o,w,304)
        return lock(o,310)
    if phase==310:
        put(w,160,4)
        return unlock(o,400)
    return quarantine(o,w,phase)

def drain(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        return lock(o,401)
    if phase==401:
        if get(w,336)!=0:
            put(w,160,8)
            return fail(o,w,11,401)
        if get(w,208)>=2 and get(w,224)==1 and get(w,232)==1 and get(w,240)==0 and get(w,248)==0:
            put(w,160,6)
            return unlock(o,500)
        if get(w,208)==0:
            return unlock(o,410)
        put(w,160,5)
        return unlock(o,402)
    if phase==402:
        request(o,VALUE_PRIVATE,56)
        return values(o,w,403)
    if phase==403:
        if get(o,FB)!=0 or get(o,RP)!=VALUE_REPLY:
            return quarantine(o,w,403)
        if get(o,RP+8)!=0 and get(o,RP+8)!=11:
            return quarantine(o,w,404)
        # Aggregate Value status is never a per-node completion proof.
        put(w,280,get(w,280)+1)
        return again(o,410)
    if phase==410:
        put(o,512,0)
        put(o,520,1000000)
        return system(o,411,35,3,512,0,0,0,0,0)
    if phase==411:
        return again(o,400)
    return quarantine(o,w,phase)

def drop_token(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==500:
        if get(w,184)!=0:
            request(o,VALUE_PRIVATE,92)
            between(w,184,o,RQ+24,24)
            return values(o,w,501)
        if get(w,256)!=0:
            request(o,VALUE_PRIVATE,93)
            return values(o,w,502)
        return lock(o,510)
    if phase==501 or phase==502:
        if ack(o)==0:
            return quarantine(o,w,phase)
        if phase==501:
            if get(o,RP+96)==1:
                zero(w,184,24)
            else:
                return quarantine(o,w,501)
        elif get(o,RP+96)!=0:
            return quarantine(o,w,502)
        put(w,256,get(o,RP+104))
        put(w,264,get(o,RP+112))
        if get(o,RP+104)!=0:
            put(o,512,0)
            put(o,520,1000000)
            return system(o,503,35,3,512,0,0,0,0,0)
        if phase==502 and get(o,RP+8)!=0 and get(o,RP+8)!=6:
            return quarantine(o,w,502)
        return again(o,500)
    if phase==503:
        return again(o,500)
    if phase==510:
        put(w,160,7)
        return fail(o,w,0,0)
    return quarantine(o,w,phase)

def ack(o:mutbuf) -> u64:
    if get(o,FB)!=0 or get(o,RP)!=VALUE_ACK or get(o,RP+88)!=1 or get(o,RP+96)>1 or get(o,RP+120)!=1:
        return 0
    if get(o,RP+104)>1 or get(o,RP+112)>1:
        return 0
    combined=choose(get(o,RP+104)!=0 or get(o,RP+112)!=0,1,0)
    if get(o,RP+80)!=combined:
        return 0
    if get(o,RP+8)!=0 and get(o,RP+8)!=1 and get(o,RP+8)!=6 and get(o,RP+8)!=11:
        return 0
    if get(o,RP+96)==1 and get(o,RP+8)!=0 and get(o,RP+8)!=11:
        return 0
    if get(o,RP+8)==6 and (get(o,RP+96)!=0 or get(o,RP+104)!=0 or get(o,RP+112)!=0):
        return 0
    return 1

def quarantine(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    put(w,336,1)
    put(w,160,8)
    return fail(o,w,11,detail)

def fail(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    put(o,ERROR,status)
    put(o,DETAIL,detail)
    if get(o,HELD)!=0:
        return unlock(o,900)
    return finish(o,w,status)

def finish(o:mutbuf,w:mutbuf,status:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,get(w,160))
    put(o,24,get(w,208))
    put(o,32,get(w,216))
    put(o,40,get(w,224))
    put(o,48,get(w,232))
    put(o,56,get(w,240))
    put(o,64,get(w,336))
    put(o,72,get(w,184))
    put(o,80,get(w,256))
    put(o,88,get(w,264))
    put(o,96,get(w,176))
    put(o,104,get(w,296))
    put(o,112,get(o,DETAIL))
    return 0

def request(o:mutbuf,magic:u64,op:u64) -> u64:
    zero(o,RQ,128)
    put(o,RQ,magic)
    put(o,RQ+8,op)
    return 0

def values(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,40),51,RQ,128,RP,32768,get(w,48),256)

def within_to_record(o:mutbuf,w:mutbuf,source:u64,target:u64,n:u64) -> u64:
    return between(o,source,w,target,n)

def lock(o:mutbuf,next:u64) -> u32:
    put(o,NEXT,next)
    put(o,PH,100)
    put(o,0,MUTEX)
    put(o,8,0)
    put(o,16,1)
    return 2

def unlock(o:mutbuf,next:u64) -> u32:
    put(o,HELD,0)
    put(o,NEXT,next)
    put(o,PH,102)
    put(o,0,MUTEX)
    put(o,8,0)
    return 3
'''
NEEDED=('invoke','memory','system','again','read_zero','get','put','zero','between','within','choose')
HELPERS='\n\n'.join(ast.get_source_segment(context.SOURCE,n)for n in ast.parse(context.SOURCE).body if isinstance(n,ast.FunctionDef)and n.name in NEEDED)
def source_program():return M.render(SOURCE+'\n'+HELPERS,C,'background_native_reaper_thread')
def main():
    d=document(source_program(),'background_optimizer_native_reaper_thread')
    p=ROOT/'examples/hia_bootstrap/background_optimizer_native_reaper_thread.hepta'
    p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
