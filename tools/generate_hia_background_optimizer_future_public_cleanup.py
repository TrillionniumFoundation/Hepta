"""Native registry-held cleanup records for actual temporary Future/value refs.

This independent role is a candidate until its fixed native capsule and the
actual callers have been constructed and qualified together.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document

ROOT = Path(__file__).resolve().parents[1]
C = {k: int.from_bytes(v, 'little') for k, v in {
    'MAGIC': b'HIABFC01', 'REPLY': b'HIABFCR1',
    'STATE': b'HIABFPS1', 'FACTORY': b'HIABFPO1', 'OBJECT': b'HIABFCT1',
    'FREQUEST': b'HIABFQ01', 'FREQUEST4': b'HIABFQ04',
    'FREPLY': b'HIABFR01', 'FREPLY2': b'HIABFR02',
    'VREQUEST': b'HIABVQ02', 'VREPLY': b'HIABVR02',
}.items()}
C.update({
    'MAX': (1 << 64) - 1, 'NEGATIVE': (1 << 64) - 4095, 'OUT': 32768,
    'PHASE': 128, 'OP': 136, 'PID': 144, 'HELD': 160, 'AFTER': 168,
    'F': 176, 'CURSOR': 184, 'RECORD': 192, 'NEW': 200, 'SLOTS': 208,
    'INDEX': 216, 'SELECTED': 224, 'ROWPTR': 232, 'ERROR': 240,
    'PENDING': 248, 'KNOWN': 256, 'TRANSFERRED': 264, 'RAW': 272,
    'MODE': 288, 'KIND': 296, 'NEXTREC': 304, 'SCAN': 312, 'TRY': 320,
    'RANDOM_USED': 328, 'ATTEMPT': 336, 'CONSUMED': 344, 'MAPPED': 352,
    'STATUS': 360, 'CLAIMED': 392, 'FATE_UNKNOWN': 400, 'FEEDBACK': 448,
    'TEMP': 472, 'RESULT_CAP': 480, 'RESULT_BYTES': 504, 'RESULT_SLOTS': 512,
    'RANDOM': 704, 'FHEADER': 768, 'HEADER': 1024, 'ROW': 1280,
    'RQ': 4096, 'VP': 8192, 'FP': 16384,
})

SOURCE = r'''
def future_cleanup(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=192 or length(o)<OUT or length(w)<256:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<100:
        return locks(s,o,w,phase)
    if phase<200:
        return locate(s,o,w,phase)
    if phase<300:
        return reserve(s,o,w,phase)
    if phase<400:
        return accept(s,o,w,phase)
    if phase<600:
        return dropping(s,o,w,phase)
    if phase<700:
        return retry(s,o,w,phase)
    if phase<900:
        return settle(s,o,w,phase)
    return cleanup(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if word(s,0)!=MAGIC or word(s,8)>3:
        return 4294967293
    op=word(s,8)
    at=16
    while at<192:
        used=at<=32
        if (op==1 or op==2) and at>=40 and at<=56:
            used=True
        if op==1 and at>=64 and at<=88:
            used=True
        if op==0 and at==96:
            used=True
        if used==False and word(s,at)!=0:
            return 4294967293
        at=at+8
    if word(s,16)==0 and (word(s,24)!=0 or word(s,32)!=0):
        return 4294967293
    if op==0 and (word(s,96)==0 or word(s,96)>(MAX-160)//96):
        return 4294967293
    if op==1 and (word(s,64)<1 or word(s,64)>2 or word(s,72)==0):
        return 4294967293
    if op==1 and word(s,64)==1 and word(s,16)==0:
        return 4294967293
    zero(o,128,3968)
    put(o,OP,op)
    put(o,KNOWN,1)
    return system(o,1,39,0,0,0,0,0,0,0)

def locks(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid==0 or pid>=NEGATIVE or get(w,0)!=STATE or get(w,8)!=pid or get(w,24)!=0:
            return finish(o,5)
        put(o,PID,pid)
        return lock(o,20)
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
            return fail(o,5)
        if word(s,16)==0:
            put(o,F,0)
            put(o,CURSOR,get(w,208))
            return again(o,110)
        put(o,CURSOR,get(w,16))
        return again(o,100)
    return fail(o,9)

def locate(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if get(o,CURSOR)==0:
            return fail(o,1)
        put(o,F,get(o,CURSOR))
        return memory(o,101,0,get(o,F),3,FHEADER,256)
    if phase==101:
        if get(o,FHEADER)!=FACTORY or get(o,FHEADER+8)!=get(o,PID):
            return fail(o,9)
        if get(o,F)!=word(s,16):
            put(o,CURSOR,get(o,FHEADER+24))
            return again(o,100)
        if get(o,FHEADER+32)!=word(s,24) or get(o,FHEADER+40)!=word(s,32):
            return fail(o,1)
        if get(o,OP)==0 and get(o,FHEADER+112)!=1:
            return fail(o,5)
        put(o,CURSOR,get(o,FHEADER+152))
        return again(o,110)
    if phase==110:
        if get(o,OP)==0:
            put(o,NEXTREC,get(o,CURSOR))
            put(o,SLOTS,word(s,96))
            return allocate(o,200,128+get(o,SLOTS)*96)
        if get(o,CURSOR)==0:
            if get(o,OP)==3:
                return again(o,820)
            return fail(o,1)
        put(o,RECORD,get(o,CURSOR))
        return memory(o,111,0,get(o,RECORD),3,HEADER,128)
    if phase==111:
        if get(o,HEADER)!=OBJECT or get(o,HEADER+8)!=get(o,PID) or get(o,HEADER+16)!=get(o,F):
            return fail(o,9)
        if get(o,HEADER+24)!=word(s,24) or get(o,HEADER+32)!=word(s,32):
            return fail(o,9)
        n=get(o,HEADER+88)
        if n==0 or n>(MAX-160)//96 or get(o,HEADER+96)!=128+n*96:
            return fail(o,9)
        if get(o,HEADER+72)>1 or get(o,HEADER+80)>1 or get(o,HEADER+112)>1:
            return fail(o,9)
        put(o,SLOTS,n)
        put(o,PENDING,1)
        if get(o,OP)==3:
            if get(o,HEADER+72)!=1 or get(o,HEADER+80)!=0:
                put(o,CURSOR,get(o,HEADER+48))
                return again(o,110)
            put(o,CLAIMED,1)
            return write_pointer(o,112,get(o,RECORD)+80,1)
        if get(o,RECORD)!=word(s,40):
            put(o,CURSOR,get(o,HEADER+48))
            return again(o,110)
        if get(o,HEADER+56)!=word(s,48) or get(o,HEADER+64)!=word(s,56):
            return fail(o,1)
        if get(o,HEADER+72)!=0 or get(o,HEADER+80)!=0:
            return fail(o,5)
        if get(o,OP)==2:
            return write_pointer(o,690,get(o,RECORD)+72,1)
        put(o,INDEX,0)
        put(o,SELECTED,MAX)
        return again(o,300)
    if phase==112:
        put(o,INDEX,0)
        return again(o,113)
    if phase==113:
        if get(o,INDEX)>=get(o,SLOTS):
            put(o,INDEX,0)
            return unlock(o,600)
        return memory(o,114,0,get(o,RECORD)+128+get(o,SLOTS)*64+get(o,INDEX)*32,3,ROW,32)
    if phase==114:
        if get(o,ROW)!=0 or get(o,ROW+8)!=0 or get(o,ROW+16)!=0 or get(o,ROW+24)!=0 or get(o,HEADER+112)!=0:
            put(o,ERROR,9)
            put(o,KNOWN,0)
            put(o,PENDING,1)
            return write_pointer(o,115,get(o,RECORD)+112,1)
        put(o,INDEX,get(o,INDEX)+1)
        return again(o,113)
    if phase==115:
        put(o,CLAIMED,0)
        return write_pointer(o,900,get(o,RECORD)+80,0)
    return fail(o,9)

def reserve(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        if get(o,FEEDBACK)==0:
            return fail(o,4)
        put(o,NEW,get(o,FEEDBACK))
        put(o,RECORD,get(o,FEEDBACK))
        put(o,RANDOM_USED,0)
        return random(o,201)
    if phase==201:
        raw=get(o,FEEDBACK)
        if raw==MAX-3:
            return random(o,201)
        if raw==0 or raw>=NEGATIVE or raw>16-get(o,RANDOM_USED):
            return fail(o,9)
        put(o,RANDOM_USED,get(o,RANDOM_USED)+raw)
        if get(o,RANDOM_USED)<16:
            return random(o,201)
        zero(o,HEADER,128)
        put(o,HEADER,OBJECT)
        put(o,HEADER+8,get(o,PID))
        put(o,HEADER+16,get(o,F))
        copy_input(s,24,o,HEADER+24,16)
        put(o,HEADER+48,get(o,NEXTREC))
        within(o,HEADER+56,RANDOM,16)
        put(o,HEADER+88,get(o,SLOTS))
        put(o,HEADER+96,128+get(o,SLOTS)*96)
        return memory(o,202,3,HEADER,0,get(o,RECORD),128)
    if phase==202:
        put(o,INDEX,0)
        zero(o,ROW,96)
        return again(o,205)
    if phase==205:
        if get(o,INDEX)>=get(o,SLOTS):
            return again(o,206)
        return memory(o,207,3,ROW,0,get(o,RECORD)+128+get(o,INDEX)*96,96)
    if phase==207:
        put(o,INDEX,get(o,INDEX)+1)
        return again(o,205)
    if phase==206:
        if get(o,NEXTREC)!=0:
            return write_pointer(o,203,get(o,NEXTREC)+40,get(o,RECORD))
        return again(o,203)
    if phase==203:
        if get(o,F)!=0:
            return write_pointer(o,204,get(o,F)+152,get(o,RECORD))
        put(w,208,get(o,RECORD))
        return again(o,204)
    if phase==204:
        put(o,RESULT_CAP,get(o,RECORD))
        within(o,RESULT_CAP+8,RANDOM,16)
        put(o,RESULT_BYTES,128+get(o,SLOTS)*96)
        put(o,RESULT_SLOTS,get(o,SLOTS))
        put(o,NEW,0)
        put(o,PENDING,1)
        return fail(o,0)
    return fail(o,9)

def accept(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        if get(o,INDEX)>=get(o,SLOTS):
            if get(o,SELECTED)==MAX:
                return fail(o,9)
            put(o,INDEX,get(o,SELECTED))
            zero(o,ROW,64)
            put(o,ROW,word(s,64))
            copy_input(s,72,o,ROW+16,24)
            copy_input(s,72,o,ROW+40,24)
            return memory(o,303,3,ROW,0,get(o,RECORD)+128+get(o,INDEX)*64,64)
        return memory(o,301,0,get(o,RECORD)+128+get(o,INDEX)*64,3,ROW,64)
    if phase==301:
        if get(o,ROW)==0:
            if get(o,SELECTED)==MAX:
                put(o,SELECTED,get(o,INDEX))
        elif get(o,ROW)==word(s,64) and get(o,ROW+40)==word(s,72) and get(o,ROW+48)==word(s,80) and get(o,ROW+56)==word(s,88):
            put(o,TRANSFERRED,1)
            put(o,KNOWN,choose((get(o,ROW+8)&15)==3,0,1))
            put(o,RAW,get(o,ROW+8)>>8)
            put(o,PENDING,1)
            return fail(o,9)
        put(o,INDEX,get(o,INDEX)+1)
        return again(o,300)
    if phase==303:
        put(o,TRANSFERRED,1)
        put(o,CLAIMED,1)
        return write_pointer(o,304,get(o,RECORD)+80,1)
    if phase==304:
        return unlock(o,400)
    return fail(o,9)

def dropping(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        put(o,KIND,get(o,ROW))
        put(o,MODE,get(o,ROW+8)&15)
        if get(o,MODE)==3 or get(o,MODE)==4:
            put(o,ERROR,9)
            if get(o,MODE)==3:
                put(o,KNOWN,0)
            return again(o,490)
        if get(o,KIND)==1:
            if get(o,F)==0:
                return fence(o)
            if get(o,MODE)==1:
                cell_packet(o,13)
                return cell(o,w,420)
            if get(o,MODE)!=0:
                return fence(o)
            cell_packet(o,20)
            within(o,RQ+24,ROW+16,24)
            return cell(o,w,410)
        if get(o,KIND)==2:
            if get(o,MODE)==2:
                put(o,ATTEMPT,31)
            elif get(o,MODE)==0:
                put(o,ATTEMPT,29)
            else:
                return fence(o)
            value_packet(o,get(o,ATTEMPT))
            if get(o,ATTEMPT)==29:
                within(o,RQ+24,ROW+16,24)
            return value(o,w,430)
        return fence(o)
    if phase==410:
        if cell_drop_record(o)==False:
            return fence(o)
        put(o,RAW,get(o,STATUS))
        if get(o,CONSUMED)!=0:
            zero(o,ROW+16,24)
            if get(o,STATUS)==0:
                zero(o,ROW,64)
            else:
                put(o,ROW+8,1|(get(o,STATUS)<<8))
        else:
            put(o,ROW+8,get(o,STATUS)<<8)
        if get(o,STATUS)!=0:
            put(o,ERROR,9)
        return again(o,490)
    if phase==420:
        if get(o,FEEDBACK)!=0 or get(o,FP)!=FREPLY or get(o,FP+8)!=0:
            put(o,ERROR,9)
            return again(o,490)
        cell_packet(o,21)
        return cell(o,w,421)
    if phase==421:
        if cell_pending_record(o)==False:
            put(o,ERROR,9)
            return again(o,490)
        if get(o,FP+136)==0:
            zero(o,ROW,64)
        else:
            put(o,ERROR,9)
        return again(o,490)
    if phase==430:
        attempt=get(o,ATTEMPT)
        if value_drop_record(o,attempt)==False:
            return fence(o)
        put(o,RAW,get(o,STATUS))
        if attempt==31:
            if get(o,STATUS)==0:
                zero(o,ROW,64)
            else:
                put(o,ERROR,9)
            return again(o,490)
        if get(o,CONSUMED)!=0:
            zero(o,ROW+16,24)
            if get(o,STATUS)==0:
                zero(o,ROW,64)
            elif get(o,MAPPED)!=0:
                put(o,ROW+8,2|(get(o,STATUS)<<8))
            else:
                put(o,ROW+8,4|(get(o,STATUS)<<8))
        else:
            if get(o,MAPPED)!=0:
                put(o,ROW+8,20|(get(o,STATUS)<<8))
            else:
                put(o,ROW+8,get(o,STATUS)<<8)
        if get(o,STATUS)!=0:
            put(o,ERROR,9)
        return again(o,490)
    if phase==490:
        return memory(o,491,3,ROW,0,get(o,RECORD)+128+get(o,INDEX)*64,64)
    if phase==491:
        if get(o,OP)==3:
            put(o,INDEX,get(o,INDEX)+1)
            return again(o,600)
        return lock(o,492)
    if phase==492:
        put(o,CLAIMED,0)
        put(o,PENDING,1)
        return write_pointer(o,900,get(o,RECORD)+80,0)
    return fail(o,9)

def retry(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==690:
        put(o,TRANSFERRED,1)
        return again(o,700)
    if phase==600:
        if get(o,INDEX)>=get(o,SLOTS):
            return lock(o,700)
        return memory(o,601,0,get(o,RECORD)+128+get(o,INDEX)*64,3,ROW,64)
    if phase==601:
        if get(o,ROW)==0:
            put(o,INDEX,get(o,INDEX)+1)
            return again(o,600)
        return again(o,400)
    return fail(o,9)

def settle(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==700:
        put(o,INDEX,0)
        put(o,SCAN,0)
        return again(o,703)
    if phase==703:
        if get(o,INDEX)>=get(o,SLOTS):
            put(o,INDEX,0)
            return again(o,701)
        return memory(o,704,0,get(o,RECORD)+128+get(o,SLOTS)*64+get(o,INDEX)*32,3,ROW,32)
    if phase==704:
        if get(o,ROW)!=0 or get(o,ROW+8)!=0 or get(o,ROW+16)!=0 or get(o,ROW+24)!=0:
            put(o,ERROR,9)
            put(o,KNOWN,0)
            put(o,PENDING,1)
            return write_pointer(o,115,get(o,RECORD)+112,1)
        put(o,INDEX,get(o,INDEX)+1)
        return again(o,703)
    if phase==701:
        if get(o,INDEX)>=get(o,SLOTS):
            if get(o,SCAN)!=0:
                put(o,PENDING,1)
                put(o,ERROR,9)
                put(o,CLAIMED,0)
                return write_pointer(o,900,get(o,RECORD)+80,0)
            return memory(o,710,0,get(o,RECORD),3,HEADER,128)
        return memory(o,702,0,get(o,RECORD)+128+get(o,INDEX)*64,3,ROW,64)
    if phase==702:
        if get(o,ROW)!=0:
            put(o,SCAN,1)
        put(o,INDEX,get(o,INDEX)+1)
        return again(o,701)
    if phase==710:
        if get(o,HEADER+40)!=0:
            return write_pointer(o,711,get(o,HEADER+40)+48,get(o,HEADER+48))
        if get(o,F)!=0:
            return write_pointer(o,711,get(o,F)+152,get(o,HEADER+48))
        put(w,208,get(o,HEADER+48))
        return again(o,711)
    if phase==711:
        if get(o,HEADER+48)!=0:
            return write_pointer(o,712,get(o,HEADER+48)+40,get(o,HEADER+40))
        return again(o,712)
    if phase==712:
        return deallocate(o,713,get(o,RECORD))
    if phase==713:
        put(o,RECORD,0)
        put(o,CLAIMED,0)
        return again(o,820)
    if phase==820:
        if get(o,F)!=0:
            return memory(o,821,0,get(o,F)+152,3,TEMP,8)
        put(o,TEMP,get(w,208))
        return again(o,821)
    if phase==821:
        put(o,PENDING,choose(get(o,TEMP)!=0,1,0))
        return again(o,900)
    return fail(o,9)

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==900:
        if get(o,NEW)!=0:
            p=get(o,NEW)
            put(o,NEW,0)
            return deallocate(o,900,p)
        if get(o,HELD)!=0:
            return unlock(o,980)
        return again(o,980)
    if phase==980:
        return finish(o,get(o,ERROR))
    return finish(o,9)

def fence(o:mutbuf) -> u32:
    put(o,ROW+8,3|(9<<8))
    put(o,ERROR,9)
    put(o,KNOWN,0)
    put(o,RAW,9)
    return again(o,490)

def cell_drop_record(o:mutbuf) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,FP)!=FREPLY2:
        return False
    status=get(o,FP+8)
    consumed=get(o,FP+128)
    if consumed>1 or get(o,FP+120)>1:
        return False
    if status!=0 and status!=1 and status!=5 and status!=6 and status!=9:
        return False
    if status==0 and consumed!=1:
        return False
    if consumed==1 and status!=0 and status!=9:
        return False
    at=16
    while at<160:
        if at!=120 and at!=128 and get(o,FP+at)!=0:
            return False
        at=at+8
    put(o,CONSUMED,consumed)
    put(o,STATUS,status)
    return True

def cell_pending_record(o:mutbuf) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,FP)!=FREPLY2 or get(o,FP+8)!=0:
        return False
    if get(o,FP+120)>1 or get(o,FP+136)>1 or get(o,FP+144)!=1:
        return False
    at=16
    while at<160:
        if at!=120 and at!=136 and at!=144 and get(o,FP+at)!=0:
            return False
        at=at+8
    return True

def value_drop_record(o:mutbuf,op:u64) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,VP)!=VREPLY:
        return False
    status=get(o,VP+8)
    pending=get(o,VP+80)
    known=get(o,VP+88)
    consumed=get(o,VP+96)
    if pending>1 or known!=1 or consumed>1:
        return False
    if status!=0 and status!=1 and status!=6 and status!=11:
        return False
    if op==31 and status==1:
        return False
    if status==1 and pending!=0:
        return False
    if consumed==1 and status!=0 and status!=11:
        return False
    at=16
    while at<128:
        if at!=80 and at!=88 and at!=96 and get(o,VP+at)!=0:
            return False
        at=at+8
    if op==31:
        if consumed!=0 or (status==0 and pending!=0):
            return False
    elif status==0 and (consumed!=1 or pending!=0):
        return False
    put(o,CONSUMED,consumed)
    put(o,MAPPED,pending)
    put(o,STATUS,status)
    return True

def cell_packet(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,192)
    put(o,RQ,choose(op>=20,FREQUEST4,FREQUEST))
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
def fail(o:mutbuf,status:u64) -> u32:
    put(o,ERROR,status)
    return again(o,900)
def finish(o:mutbuf,status:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    within(o,16,RESULT_CAP,24)
    put(o,40,get(o,PENDING))
    put(o,48,get(o,KNOWN))
    put(o,56,get(o,TRANSFERRED))
    put(o,64,get(o,RAW))
    put(o,72,get(o,RESULT_BYTES))
    put(o,80,get(o,RESULT_SLOTS))
    return 0
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
def word(s:readbuf,at:u64) -> u64:
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
    s = SOURCE
    for key, value in sorted(C.items(), key=lambda x: -len(x[0])):
        s = re.sub(r'\b' + key + r'\b', str(value), s)
    return s

def program():
    return document(source_program(), 'background_optimizer_future_public_cleanup')

def main():
    d = program()
    p = ROOT / 'examples/hia_bootstrap/background_optimizer_future_public_cleanup.hepta'
    p.write_text(render_assembly(d))
    print(p.name, p.stat().st_size, len(d['functions']),
          sum(len(f['blocks']) for f in d['functions']),
          sum(len(b['ops']) for f in d['functions'] for b in f['blocks']), flush=True)

if __name__ == '__main__':
    main()
