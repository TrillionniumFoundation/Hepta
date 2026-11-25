"""Native public Future factories, shared values and typed method lifetime.

Factories own independent Future cells; ordinary methods pin their cell before
releasing the factory registry mutex. Callback calls have per-thread frames.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
C={
"MAGIC":int.from_bytes("HIABFP01".encode(),'little'),
"REPLY":int.from_bytes("HIABFRP1".encode(),'little'),
"STATE":int.from_bytes("HIABFPS1".encode(),'little'),
"OBJECT":int.from_bytes("HIABFPO1".encode(),'little'),
"NMAGIC":int.from_bytes("HIABFPL1".encode(),'little'),
"FMAGIC":int.from_bytes("HIABFPA1".encode(),'little'),
"FREQUEST":int.from_bytes("HIABFQ01".encode(),'little'),
"FREPLY":int.from_bytes("HIABFR01".encode(),'little'),
"VREQUEST":int.from_bytes("HIABVQ01".encode(),'little'),
"VREPLY":int.from_bytes("HIABVR01".encode(),'little'),
"KREQUEST":int.from_bytes("HIAMVFQ1".encode(),'little'),
"KREPLY":int.from_bytes("HIAMVFR1".encode(),'little'),
"CREQUEST":int.from_bytes("HIAPFC01".encode(),'little'),
"CREPLY":int.from_bytes("HIAPFCR1".encode(),'little'),
"TREPLY":int.from_bytes("HIAPFTR1".encode(),'little'),
"MAX":(1<<64)-1,
"NEGATIVE":(1<<64)-4095,
"PHASE":128,
"OP":136,
"HELD":144,
"ERROR":152,
"RKIND":160,
"PID":168,
"TID":176,
"F":184,
"CURSOR":192,
"LEASE":200,
"NEWF":208,
"NEWLEASE":216,
"RANDOM_USED":240,
"ACTIVE":248,
"FUTURE_TEMP":256,
"RESULT_FUTURE":280,
"RESULT_VALUE":304,
"RESULT_LEASE":328,
"FACTORY_ID":352,
"FRAMEPTR":392,
"FRAMED":400,
"DISCARD_VALUE":416,
"FEEDBACK":448,
"AFTER":456,
"TEMP":472,
"SCALAR":480,
"WAIT_NS":488,
"WAIT_INF":496,
"KERNEL":504,
"WPTR":512,
"SEEN":520,
"CAUGHT":528,
"EXTRA":536,
"CLEANUP_FAILED":544,
"RAW_RESULT":552,
"TOKEN":576,
"RETRY_NEXT":608,
"RETRY_CARRIER":616,
"CARRIER_MAGIC":int.from_bytes("HIABFPC1".encode(),'little'),
"RANDOM":704,
"FRAME":1024,
"HEADER":2048,
"NODE":2304,
"RQ":4096,
"FP":8192,
"VP":24576,
"CP":32768,
"OUT":65536
}
SOURCE=r'''
def future_public(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT or length(w)<256:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<100:
        return locks(s,o,w,phase)
    if phase<120:
        return locate(s,o,w,phase)
    if phase<150:
        return construct(s,o,w,phase)
    if phase<180:
        return attach(s,o,w,phase)
    if phase<300:
        return release_lease(s,o,w,phase)
    if phase<400:
        return methods(s,o,w,phase)
    if phase<500:
        return frames(s,o,w,phase)
    if phase<600:
        return results(s,o,w,phase)
    if phase<700:
        return retire(s,o,w,phase)
    return cleanup(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=192 or readword(s,0)!=MAGIC or readword(s,8)>21:
        return 4294967293
    op=readword(s,8)
    at=16
    while at<192:
        used=False
        if op==0 and (at==16 or at==24):
            used=True
        if op>=2 and op<=17 and at>=16 and at<=56:
            used=True
        if (op==19 or op==21) and at>=16 and at<=56:
            used=True
        if (op==12 or op==13) and at>=64 and at<=80:
            used=True
        if op==12 and at==96:
            used=True
        if op==13 and at==88:
            used=True
        if (op==10 or op==11) and at>=104 and at<=120:
            used=True
        if used==False and readword(s,at)!=0:
            return 4294967293
        at=at+8
    if op==12 and (readword(s,96)<1 or readword(s,96)>3):
        return 4294967293
    if op==13 and readword(s,88)==0:
        return 4294967293
    zero(o,128,OUT-128)
    put(o,OP,op)
    return system(o,1,39,0,0,0,0,0,0,0)

def locks(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid==0 or pid>=NEGATIVE:
            return finish(o,1,107)
        put(o,PID,pid)
        if get(o,OP)==0:
            if get(w,0)!=0 or readword(s,16)==0 or readword(s,24)<256:
                return finish(o,1,107)
            if get(w,64)==0 or get(w,72)==0 or get(w,80)==0:
                return finish(o,1,107)
            put(w,112,readword(s,16))
            put(w,120,readword(s,24))
            value_packet(o,21)
            return value(o,w,4)
        if get(w,0)!=STATE or get(w,8)!=pid or get(w,24)!=0:
            return finish(o,1,107)
        return system(o,2,186,0,0,0,0,0,0,0)
    if phase==2:
        tid=get(o,FEEDBACK)
        if tid==0 or tid>=NEGATIVE:
            return finish(o,1,107)
        put(o,TID,tid)
        return waddress(o,3,0)
    if phase==3:
        put(o,WPTR,get(o,FEEDBACK))
        return lock(o,20)
    if phase==4:
        if value_ok(o)==False:
            return finish(o,1,choose(get(o,VP+8)==5,103,107))
        within(o,TOKEN,VP+24,24)
        copy_between(o,TOKEN,w,128,24)
        zero(w,0,64)
        put(w,0,STATE)
        put(w,8,get(o,PID))
        return finish(o,0,0)
    if phase==10:
        if get(o,FEEDBACK)==0:
            put(o,HELD,1)
            return again(o,get(o,AFTER))
        return system(o,11,202,1,32,128,1,0,0,0)
    if phase==11:
        raw=get(o,FEEDBACK)
        if raw!=0 and raw!=MAX-3 and raw!=MAX-10:
            return system(o,12,24,0,0,0,0,0,0,0)
        return atom(o,2,10,0,1)
    if phase==12:
        return atom(o,2,10,0,1)
    if phase==15:
        return system(o,16,202,1,32,129,2147483647,0,0,0)
    if phase==16:
        return again(o,get(o,AFTER))
    if phase==20:
        if get(w,24)!=0:
            return fail(o,1,107)
        op=get(o,OP)
        if op==18:
            if get(w,16)!=0 or get(w,48)!=0:
                return fail(o,1,107)
            value_packet(o,22)
            copy_between(w,128,o,RQ+24,24)
            return value(o,w,21)
        if op==20:
            put(o,CURSOR,get(w,16))
            return again(o,25)
        if op==1:
            return allocate(o,120,512)
        put(o,CURSOR,get(w,16))
        return again(o,100)
    if phase==21:
        if value_ok(o)==False:
            return fail(o,1,107)
        zero(w,128,24)
        put(w,24,1)
        return fail(o,0,0)
    if phase==25:
        if get(o,CURSOR)==0:
            put(o,F,0)
            return fail(o,0,0)
        put(o,F,get(o,CURSOR))
        return memory(o,26,0,get(o,F),3,HEADER,256)
    if phase==26:
        return write_pointer(o,27,get(o,F)+56,get(o,HEADER+56)+1)
    if phase==27:
        put(o,ACTIVE,1)
        if get(o,HEADER+112)==2:
            return again(o,30)
        return unlock(o,28)
    if phase==28:
        cell_packet(o,13)
        return cell(o,w,29)
    if phase==29:
        if cell_ok(o)==False:
            put(o,CLEANUP_FAILED,1)
        return lock(o,30)
    if phase==30:
        return memory(o,31,0,get(o,F),3,HEADER,256)
    if phase==31:
        put(o,CURSOR,get(o,HEADER+104))
        return again(o,32)
    if phase==32:
        if get(o,CURSOR)==0:
            return again(o,38)
        return memory(o,33,0,get(o,CURSOR),3,NODE,256)
    if phase==33:
        if get(o,NODE)!=CARRIER_MAGIC or get(o,NODE+16)!=get(o,F):
            put(o,CLEANUP_FAILED,1)
            return again(o,38)
        if get(o,NODE+96)==3:
            if get(o,CURSOR)==get(o,RETRY_CARRIER):
                put(o,CLEANUP_FAILED,1)
                return again(o,38)
            put(o,RETRY_CARRIER,get(o,CURSOR))
            return write_pointer(o,34,get(o,CURSOR)+96,4)
        put(o,CURSOR,get(o,NODE+88))
        return again(o,32)
    if phase==34:
        return unlock(o,35)
    if phase==35:
        return raw_drop(o,w,36,get(o,RETRY_CARRIER))
    if phase==36:
        return lock(o,30)
    if phase==38:
        return memory(o,39,0,get(o,F),3,HEADER,256)
    if phase==39:
        put(o,RETRY_NEXT,get(o,HEADER+24))
        if get(o,HEADER+56)==0:
            put(o,CLEANUP_FAILED,1)
            return unlock(o,980)
        return write_pointer(o,40,get(o,F)+56,get(o,HEADER+56)-1)
    if phase==40:
        put(o,ACTIVE,0)
        put(o,RETRY_CARRIER,0)
        return again(o,600)
    return fail(o,1,107)

def locate(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if get(o,CURSOR)==0:
            return fail(o,3,107)
        put(o,F,get(o,CURSOR))
        return memory(o,101,0,get(o,F),3,HEADER,256)
    if phase==101:
        if get(o,HEADER)!=OBJECT or get(o,HEADER+8)!=get(o,PID):
            return fail(o,1,107)
        if get(o,F)!=readword(s,16):
            put(o,CURSOR,get(o,HEADER+24))
            return again(o,100)
        if get(o,HEADER+32)!=readword(s,24) or get(o,HEADER+40)!=readword(s,32) or get(o,HEADER+112)!=1:
            return fail(o,3,107)
        put(o,FACTORY_ID,get(o,F))
        put(o,FACTORY_ID+8,get(o,HEADER+32))
        put(o,FACTORY_ID+16,get(o,HEADER+40))
        op=get(o,OP)
        if op==2 or op==3 or op==4 or op==17:
            put(o,CURSOR,get(o,HEADER+48))
            return again(o,110)
        return again(o,300)
    if phase==110:
        if get(o,CURSOR)==0:
            return fail(o,3,107)
        return memory(o,111,0,get(o,CURSOR),3,NODE,96)
    if phase==111:
        if get(o,NODE)!=NMAGIC or get(o,NODE+8)!=get(o,F) or get(o,NODE+48)!=get(o,PID):
            return fail(o,1,107)
        if get(o,CURSOR)!=readword(s,40):
            put(o,CURSOR,get(o,NODE+24))
            return again(o,110)
        if get(o,NODE+32)!=readword(s,48) or get(o,NODE+40)!=readword(s,56):
            return fail(o,3,107)
        put(o,LEASE,get(o,CURSOR))
        op=get(o,OP)
        if op==2:
            return again(o,150)
        if op==3:
            return again(o,180)
        if op==17:
            put(o,RAW_RESULT,get(w,80))
            put(o,RAW_RESULT+8,get(o,F)+256)
            put(o,RAW_RESULT+16,256)
            return fail(o,0,6)
        return again(o,300)
    return fail(o,1,107)

def construct(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==120:
        if get(o,FEEDBACK)==0:
            return fail(o,1,103)
        put(o,F,get(o,FEEDBACK))
        put(o,NEWF,get(o,FEEDBACK))
        zero(o,RQ,512)
        put(o,RQ,OBJECT)
        put(o,RQ+8,get(o,PID))
        return memory(o,121,3,RQ,0,get(o,F),512)
    if phase==121:
        value_packet(o,21)
        return value(o,w,122)
    if phase==122:
        if value_ok(o)==False:
            return fail(o,1,choose(get(o,VP+8)==5,103,107))
        return memory(o,123,3,VP+24,0,get(o,F)+72,24)
    if phase==123:
        cell_packet(o,0)
        put(o,RQ+24,get(w,64))
        put(o,RQ+32,get(w,72))
        put(o,RQ+40,get(w,112))
        put(o,RQ+48,get(w,120))
        return cell(o,w,124)
    if phase==124:
        if cell_ok(o)==False:
            return fail(o,1,107)
        return write_pointer(o,125,get(o,F)+120,1)
    if phase==125:
        put(o,RANDOM_USED,0)
        return random(o,126)
    if phase==126:
        r=random_state(o)
        if r==1:
            return random(o,126)
        if r==2:
            return fail(o,1,107)
        return memory(o,127,3,RANDOM,0,get(o,F)+32,16)
    if phase==127:
        put(o,FACTORY_ID,get(o,F))
        within(o,FACTORY_ID+8,RANDOM,16)
        return again(o,150)
    return fail(o,1,107)

def attach(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==150:
        return memory(o,151,0,get(o,F),3,HEADER,256)
    if phase==151:
        return allocate(o,152,96)
    if phase==152:
        if get(o,FEEDBACK)==0:
            return fail(o,1,103)
        put(o,NEWLEASE,get(o,FEEDBACK))
        put(o,RANDOM_USED,0)
        return random(o,153)
    if phase==153:
        r=random_state(o)
        if r==1:
            return random(o,153)
        if r==2:
            return fail(o,1,107)
        zero(o,NODE,96)
        put(o,NODE,NMAGIC)
        put(o,NODE+8,get(o,F))
        put(o,NODE+24,get(o,HEADER+48))
        within(o,NODE+32,RANDOM,16)
        put(o,NODE+48,get(o,PID))
        return memory(o,154,3,NODE,0,get(o,NEWLEASE),96)
    if phase==154:
        if get(o,HEADER+48)!=0:
            return write_pointer(o,155,get(o,HEADER+48)+16,get(o,NEWLEASE))
        return again(o,155)
    if phase==155:
        return write_pointer(o,156,get(o,F)+48,get(o,NEWLEASE))
    if phase==156:
        put(o,RESULT_LEASE,get(o,NEWLEASE))
        within(o,RESULT_LEASE+8,RANDOM,16)
        put(o,NEWLEASE,0)
        if get(o,NEWF)!=0:
            return write_pointer(o,157,get(o,F)+24,get(w,16))
        return fail(o,0,3)
    if phase==157:
        if get(w,16)!=0:
            return write_pointer(o,158,get(w,16)+16,get(o,F))
        return again(o,158)
    if phase==158:
        put(w,16,get(o,F))
        return write_pointer(o,159,get(o,F)+112,1)
    if phase==159:
        put(o,NEWF,0)
        return fail(o,0,3)
    return fail(o,1,107)

def release_lease(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==180:
        if get(o,NODE+16)!=0:
            return write_pointer(o,181,get(o,NODE+16)+24,get(o,NODE+24))
        return write_pointer(o,181,get(o,F)+48,get(o,NODE+24))
    if phase==181:
        if get(o,NODE+24)!=0:
            return write_pointer(o,182,get(o,NODE+24)+16,get(o,NODE+16))
        return again(o,182)
    if phase==182:
        return deallocate(o,183,get(o,LEASE))
    if phase==183:
        return fail(o,0,0)
    return fail(o,1,107)

def methods(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        return write_pointer(o,301,get(o,F)+56,get(o,HEADER+56)+1)
    if phase==301:
        put(o,ACTIVE,1)
        op=get(o,OP)
        if op==4:
            return unlock(o,303)
        if op==6:
            return unlock(o,340)
        cell_packet(o,2)
        copy_input(s,40,o,RQ+24,24)
        return cell(o,w,302)
    if phase==302:
        if cell_ok(o)==False:
            return cell_error(o)
        within(o,FUTURE_TEMP,FP+16,24)
        if get(o,OP)==5:
            within(o,RESULT_FUTURE,FUTURE_TEMP,24)
            zero(o,FUTURE_TEMP,24)
            return fail(o,0,2)
        op=get(o,OP)
        if op==7 or op==8 or op==12 or op==13:
            return address(o,400,FRAME)
        return unlock(o,310)
    if phase==303:
        cell_packet(o,1)
        return cell(o,w,304)
    if phase==304:
        if cell_ok(o)==False:
            return cell_error(o)
        within(o,RESULT_FUTURE,FP+16,24)
        cell_packet(o,6)
        within(o,RQ+24,RESULT_FUTURE,24)
        return cell(o,w,305)
    if phase==305:
        if cell_ok(o)==False:
            within(o,FUTURE_TEMP,RESULT_FUTURE,24)
            zero(o,RESULT_FUTURE,24)
            return cell_error(o)
        put(o,KERNEL,get(o,FP+64))
        zero(o,RQ,128)
        put(o,RQ,KREQUEST)
        put(o,RQ+8,4)
        put(o,RQ+16,get(w,160))
        put(o,RQ+24,get(o,WPTR))
        return invoke(o,306,get(w,64),RQ,64,FP,512,get(o,KERNEL),512)
    if phase==306:
        if get(o,FP)!=KREPLY or get(o,FEEDBACK)!=get(o,FP+8) or get(o,FP+8)!=0:
            within(o,FUTURE_TEMP,RESULT_FUTURE,24)
            zero(o,RESULT_FUTURE,24)
            return fail(o,1,choose(get(o,FP+8)==5,103,107))
        return fail(o,0,2)
    if phase==310:
        op=get(o,OP)
        if op==13:
            copy_input(s,0,o,RQ,192)
            put(o,RQ,CREQUEST)
            put(o,RQ+8,0)
            within(o,RQ+40,FUTURE_TEMP,24)
            return invoke(o,330,get(w,152),RQ,192,CP,32768,get(o,WPTR),256)
        k=9
        if op==7:
            k=7
        elif op==8:
            k=8
        elif op==12:
            k=11
        elif op==21:
            k=6
        cell_packet(o,k)
        within(o,RQ+24,FUTURE_TEMP,24)
        if op==12:
            copy_input(s,64,o,RQ+48,24)
            put(o,RQ+80,readword(s,96))
        return cell(o,w,320)
    if phase==320:
        if cell_ok(o)==False:
            return cell_error(o)
        save_cell(o)
        op=get(o,OP)
        if op==10 or op==11:
            if get(o,FP+48)!=0:
                put(o,WAIT_NS,0)
                put(o,WAIT_INF,0)
                return again(o,510)
            if readword(s,104)==0 and readword(s,112)==0 and readword(s,120)==0:
                put(o,WAIT_NS,0)
                put(o,WAIT_INF,1)
                return again(o,510)
            copy_input(s,0,o,RQ,192)
            return invoke(o,500,get(w,168),RQ,192,VP,16384,get(o,WPTR),256)
        if get(o,FP+40)!=0:
            return fail(o,1,kernel_error(get(o,FP+40)))
        if op==21:
            put(o,SCALAR,get(o,FP+64))
            return fail(o,0,7)
        if op==7 or op==8:
            put(o,SCALAR,get(o,FP+64))
            return fail(o,0,1)
        if op==14:
            put(o,SCALAR,choose(get(o,FP+48)!=0,1,0))
            return fail(o,0,1)
        if op==15:
            put(o,SCALAR,choose(get(o,FP+48)==1,1,0))
            return fail(o,0,1)
        if op==16:
            put(o,SCALAR,0)
            return fail(o,0,1)
        if op==9 or op==19:
            put(o,SCALAR,get(o,FP+48))
            return fail(o,0,5)
        return fail(o,0,0)
    if phase==330:
        if get(o,FEEDBACK)!=0 or get(o,CP)!=CREPLY:
            return fail(o,1,107)
        if get(o,CP+8)!=0:
            return fail(o,1,get(o,CP+16))
        return fail(o,0,0)
    if phase==340:
        cell_packet(o,3)
        copy_input(s,40,o,RQ+24,24)
        return cell(o,w,341)
    if phase==341:
        if cell_ok(o)==False:
            return cell_error(o)
        return fail(o,0,0)
    return fail(o,1,107)

def frames(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        put(o,FRAMEPTR,get(o,FEEDBACK))
        zero(o,FRAME,128)
        put(o,FRAME,get(o,HEADER+96))
        put(o,FRAME+16,get(o,TID))
        put(o,FRAME+24,get(o,F))
        put(o,FRAME+88,FMAGIC)
        if get(o,HEADER+96)!=0:
            return write_pointer(o,401,get(o,HEADER+96)+8,get(o,FRAMEPTR))
        return again(o,401)
    if phase==401:
        return write_pointer(o,402,get(o,F)+96,get(o,FRAMEPTR))
    if phase==402:
        put(o,FRAMED,1)
        return unlock(o,310)
    if phase==410:
        if get(o,FRAME+88)!=FMAGIC or get(o,FRAME+16)!=get(o,TID) or get(o,FRAME+24)!=get(o,F):
            return fail(o,1,107)
        if get(o,FRAME+32)!=0:
            put(o,ERROR,get(o,FRAME+32))
            put(o,RKIND,choose(get(o,FRAME+80)==0,200,get(o,FRAME+80)))
            within(o,RESULT_VALUE,FRAME+40,24)
            zero(o,FRAME+40,24)
        put(o,SEEN,get(o,FRAME+64))
        put(o,CAUGHT,get(o,FRAME+72))
        if get(o,FRAME+8)!=0:
            return write_pointer(o,411,get(o,FRAME+8),get(o,FRAME))
        return write_pointer(o,411,get(o,F)+96,get(o,FRAME))
    if phase==411:
        if get(o,FRAME)!=0:
            return write_pointer(o,412,get(o,FRAME)+8,get(o,FRAME+8))
        return again(o,412)
    if phase==412:
        put(o,FRAMED,0)
        return again(o,930)
    return fail(o,1,107)

def results(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==500:
        if get(o,FEEDBACK)!=0 or get(o,VP)!=TREPLY:
            return fail(o,1,107)
        if get(o,VP+8)!=0:
            put(o,EXTRA,get(o,VP+40))
            return fail(o,get(o,VP+8),get(o,VP+16))
        put(o,WAIT_NS,get(o,VP+24))
        put(o,WAIT_INF,get(o,VP+32))
        return again(o,510)
    if phase==510:
        cell_packet(o,10)
        within(o,RQ+24,FUTURE_TEMP,24)
        put(o,RQ+104,get(o,WAIT_NS))
        put(o,RQ+112,get(o,WAIT_INF))
        return cell(o,w,511)
    if phase==511:
        if cell_ok(o)==False:
            return cell_error(o)
        save_cell(o)
        if get(o,FP+40)!=0:
            return fail(o,1,kernel_error(get(o,FP+40)))
        if get(o,FP+72)<1 or get(o,FP+72)>3:
            return fail(o,1,107)
        within(o,RESULT_VALUE,FP+80,24)
        if get(o,OP)==11:
            if get(o,FP+72)==1:
                within(o,DISCARD_VALUE,RESULT_VALUE,24)
                zero(o,RESULT_VALUE,24)
                return fail(o,0,0)
            return fail(o,0,4)
        if get(o,FP+72)==1:
            return fail(o,0,4)
        return fail(o,get(o,FP+72)-1,200)
    return fail(o,1,107)

def retire(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==600:
        return memory(o,601,0,get(o,F),3,HEADER,256)
    if phase==601:
        if get(o,HEADER+48)!=0 or get(o,HEADER+56)!=0:
            return again(o,690)
        if get(o,HEADER+96)!=0 or get(o,HEADER+104)!=0:
            return again(o,690)
        if get(o,HEADER+112)==2:
            return again(o,604)
        cell_packet(o,5)
        return cell(o,w,602)
    if phase==602:
        if get(o,FEEDBACK)==0 and get(o,FP)==FREPLY and get(o,FP+8)==5:
            return again(o,690)
        if cell_ok(o)==False:
            return fail(o,1,107)
        return write_pointer(o,604,get(o,F)+112,2)
    if phase==604:
        if get(o,HEADER+72)==0:
            return again(o,606)
        value_packet(o,22)
        within(o,RQ+24,HEADER+72,24)
        return value(o,w,605)
    if phase==605:
        if value_ok(o)==False:
            put(o,CLEANUP_FAILED,1)
            return again(o,690)
        zero(o,TOKEN,24)
        return memory(o,606,3,TOKEN,0,get(o,F)+72,24)
    if phase==606:
        return memory(o,607,0,get(o,F),3,HEADER,256)
    if phase==607:
        if get(o,HEADER+16)!=0:
            return write_pointer(o,608,get(o,HEADER+16)+24,get(o,HEADER+24))
        put(w,16,get(o,HEADER+24))
        return again(o,608)
    if phase==608:
        if get(o,HEADER+24)!=0:
            return write_pointer(o,609,get(o,HEADER+24)+16,get(o,HEADER+16))
        return again(o,609)
    if phase==609:
        return deallocate(o,610,get(o,F))
    if phase==610:
        put(o,F,0)
        return again(o,690)
    if phase==690:
        if get(o,OP)==20:
            put(o,CURSOR,get(o,RETRY_NEXT))
            return again(o,25)
        return unlock(o,980)
    return fail(o,1,107)

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==900:
        if get(o,NEWLEASE)!=0:
            ptr=get(o,NEWLEASE)
            put(o,NEWLEASE,0)
            return deallocate(o,900,ptr)
        if get(o,NEWF)!=0:
            return memory(o,950,0,get(o,NEWF),3,HEADER,256)
        if get(o,FUTURE_TEMP)!=0:
            if get(o,HELD)!=0:
                return unlock(o,900)
            cell_packet(o,3)
            within(o,RQ+24,FUTURE_TEMP,24)
            return cell(o,w,901)
        if get(o,DISCARD_VALUE)!=0:
            if get(o,HELD)!=0:
                return unlock(o,900)
            value_packet(o,6)
            within(o,RQ+24,DISCARD_VALUE,24)
            return value(o,w,902)
        if get(o,F)!=0:
            if get(o,HELD)==0:
                return lock(o,920)
            return again(o,920)
        if get(o,HELD)!=0:
            return unlock(o,980)
        return again(o,980)
    if phase==901:
        if cell_ok(o)==False:
            put(o,CLEANUP_FAILED,1)
        zero(o,FUTURE_TEMP,24)
        return again(o,900)
    if phase==902:
        if value_ok(o)==False:
            put(o,CLEANUP_FAILED,1)
        zero(o,DISCARD_VALUE,24)
        return again(o,900)
    if phase==920:
        if get(o,FRAMED)!=0:
            return again(o,410)
        return again(o,930)
    if phase==930:
        if get(o,ACTIVE)!=0:
            return memory(o,931,0,get(o,F),3,HEADER,256)
        return again(o,600)
    if phase==931:
        if get(o,HEADER+56)==0:
            put(o,CLEANUP_FAILED,1)
            put(o,ERROR,1)
            put(o,RKIND,107)
            return unlock(o,980)
        return write_pointer(o,932,get(o,F)+56,get(o,HEADER+56)-1)
    if phase==932:
        put(o,ACTIVE,0)
        return again(o,600)
    if phase==950:
        if get(o,HEADER+120)!=0:
            cell_packet(o,5)
            return cell(o,w,951)
        return again(o,952)
    if phase==951:
        if cell_ok(o)==False:
            put(o,CLEANUP_FAILED,1)
            return unlock(o,980)
        return again(o,952)
    if phase==952:
        if get(o,HEADER+72)!=0:
            value_packet(o,22)
            within(o,RQ+24,HEADER+72,24)
            return value(o,w,953)
        return again(o,954)
    if phase==953:
        if value_ok(o)==False:
            put(o,CLEANUP_FAILED,1)
            return unlock(o,980)
        return again(o,954)
    if phase==954:
        return deallocate(o,955,get(o,NEWF))
    if phase==955:
        put(o,NEWF,0)
        put(o,F,0)
        return again(o,900)
    if phase==980:
        return finish(o,get(o,ERROR),get(o,RKIND))
    return finish(o,1,107)

def cell_packet(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,192)
    put(o,RQ,FREQUEST)
    put(o,RQ+8,op)
    return 0
def value_packet(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,192)
    put(o,RQ,VREQUEST)
    put(o,RQ+8,op)
    return 0
def cell(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,80),RQ,128,FP,16384,get(o,F)+256,256)
def value(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,72),RQ,128,VP,8192,get(w,112),get(w,120))
def cell_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,FP)==FREPLY and get(o,FP+8)==0
def value_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,VP)==VREPLY and get(o,VP+8)==0
def cell_error(o:mutbuf) -> u32:
    if get(o,FEEDBACK)!=0 or get(o,FP)!=FREPLY:
        return fail(o,1,107)
    if get(o,FP+8)==1:
        return fail(o,3,107)
    return fail(o,1,choose(get(o,FP+8)==4,103,107))
def kernel_error(status:u64) -> u64:
    if status==1:
        return 100
    if status==2:
        return 101
    if status==3 or status==6:
        return 102
    if status==5:
        return 103
    return 107
def save_cell(o:mutbuf) -> u64:
    put(o,EXTRA,get(o,FP+56))
    return 0
def random_state(o:mutbuf) -> u64:
    raw=get(o,FEEDBACK)
    used=get(o,RANDOM_USED)
    if raw==MAX-3:
        return 1
    if raw==0 or raw>=NEGATIVE or raw>16-used:
        return 2
    used=used+raw
    put(o,RANDOM_USED,used)
    if used<16:
        return 1
    if get(o,RANDOM)==0 and get(o,RANDOM+8)==0:
        return 2
    return 0
def fail(o:mutbuf,status:u64,kind:u64) -> u32:
    put(o,ERROR,status)
    put(o,RKIND,kind)
    return again(o,900)
def finish(o:mutbuf,status:u64,kind:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,kind)
    if kind==2 or kind==3 or kind==7:
        within(o,24,FACTORY_ID,24)
    if kind==2:
        within(o,48,RESULT_FUTURE,24)
    if kind==3:
        within(o,48,RESULT_LEASE,24)
    if kind==4 or kind==200:
        within(o,72,RESULT_VALUE,24)
    if kind==6:
        within(o,72,RAW_RESULT,24)
    put(o,96,get(o,SCALAR))
    put(o,104,get(o,SEEN))
    put(o,112,get(o,CAUGHT))
    put(o,120,get(o,EXTRA))
    if get(o,CLEANUP_FAILED)!=0:
        put(o,120,MAX)
    return 0
def copy_between(a:mutbuf,at:u64,b:mutbuf,bt:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(b,bt+i,byte(a,at+i))
        i=i+1
    return 0
def raw_drop(o:mutbuf,w:mutbuf,next:u64,p:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,get(w,104))
    put(o,8,0)
    put(o,16,p)
    zero(o,24,40)
    return 9
def waddress(o:mutbuf,next:u64,at:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,at)
    return 5

def lock(o:mutbuf,next:u64) -> u32:
    put(o,AFTER,next)
    return atom(o,2,10,0,1)
def unlock(o:mutbuf,next:u64) -> u32:
    put(o,AFTER,next)
    put(o,HELD,0)
    return atom(o,3,15,0,0)
def atom(o:mutbuf,action:u64,next:u64,a:u64,b:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,32)
    put(o,8,a)
    put(o,16,b)
    return narrow(action)
def address(o:mutbuf,next:u64,at:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,at)
    return 4
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
def random(o:mutbuf,next:u64) -> u32:
    return system(o,next,318,3,RANDOM+get(o,RANDOM_USED),16-get(o,RANDOM_USED),0,0,0,0)
def allocate(o:mutbuf,next:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,n)
    return 6
def deallocate(o:mutbuf,next:u64,ptr:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,ptr)
    return 7
def memory(o:mutbuf,next:u64,a:u64,at:u64,b:u64,bt:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,a)
    put(o,8,at)
    put(o,16,b)
    put(o,24,bt)
    put(o,32,n)
    return 8
def write_pointer(o:mutbuf,next:u64,ptr:u64,value:u64) -> u32:
    put(o,TEMP,value)
    return memory(o,next,3,TEMP,0,ptr,8)
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
def within(o:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(o,at+i))
        i=i+1
    return 0
def copy_input(s:readbuf,at:u64,o:mutbuf,to:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(s,at+i))
        i=i+1
    return 0
def zero(o:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,at+i,0)
        i=i+1
    return 0
def readword(s:readbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(s,at+i)<<(i*8))
        i=i+1
    return value
def get(o:mutbuf,at:u64) -> u64:
    return word_load(o,at)
def put(o:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(o,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no
def narrow(n:u64) -> u32:
    return n
'''
def source_program():
 s=SOURCE
 for key,value in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+key+r'\b',str(value),s)
 return s
def program():return document(source_program(),'background_optimizer_future_public_owner')
def main():
 d=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_future_public_owner.hepta';p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
