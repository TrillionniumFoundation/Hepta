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
"MAGIC":int.from_bytes("HIABFP01".encode(),'little'),"MAGIC2":int.from_bytes(b"HIABFP02",'little'),"MAGIC3":int.from_bytes(b"HIABFP03",'little'),
"REPLY":int.from_bytes("HIABFRP1".encode(),'little'),"REPLY2":int.from_bytes(b"HIABFRP2",'little'),
"STATE":int.from_bytes("HIABFPS1".encode(),'little'),
"OBJECT":int.from_bytes("HIABFPO1".encode(),'little'),
"NMAGIC":int.from_bytes("HIABFPL1".encode(),'little'),
"FMAGIC":int.from_bytes("HIABFPA1".encode(),'little'),
"FREQUEST":int.from_bytes("HIABFQ01".encode(),'little'),"FREQUEST3":int.from_bytes(b"HIABFQ03",'little'),"FREQUEST4":int.from_bytes(b"HIABFQ04",'little'),
"FREPLY":int.from_bytes("HIABFR01".encode(),'little'),"FREPLY2":int.from_bytes(b"HIABFR02",'little'),
"VREQUEST":int.from_bytes("HIABVQ01".encode(),'little'),
"VREPLY":int.from_bytes("HIABVR01".encode(),'little'),
"VREQUEST2":int.from_bytes(b"HIABVQ02",'little'),
"VREPLY2":int.from_bytes(b"HIABVR02",'little'),
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
"DROP_CONSUMED":624,
"DROP_KNOWN":632,
"RETIRE_OWNED":640,
"DROP_PENDING":648,
"VD_CONSUMED":656,
"VD_PENDING":664,
"VD_STATUS":672,
"VALUE_ATTEMPT":680,
"GMAGIC":int.from_bytes(b"HIABFC01",'little'),
"GREPLY":int.from_bytes(b"HIABFCR1",'little'),
"GOBJECT":int.from_bytes(b"HIABFCT1",'little'),
"GCAP":736,"GPTR":760,"GBAD":768,"GNEXT":776,"GKIND":784,
"GOP":792,"GSCAN":800,"GKEEP":808,"GSTATUS":816,"GLOST":824,"GCOUNT":16,
"GSHADOW":2688,"GREQUEST":3200,"GOUTPUT":3456,
"CARRIER_MAGIC":int.from_bytes("HIABFPC1".encode(),'little'),
"RANDOM":704,
"FRAME":1024,
"HEADER":2048,
"NODE":2304,
"RQ":4096,
"FP":8192,
"VP":24576,
"CP":32768,
"OUT":65536,"LOG_REQUEST2":int.from_bytes(b"HIAFPL02","little"),"LOG_REPLY":int.from_bytes(b"HIAFPLR1","little"),"NOTIFY3":int.from_bytes(b"HIABFN03","little"),"NOTIFY_REPLY":int.from_bytes(b"HIABFNR1","little"),"EVAL_CAP":1536,"ERROR_CAP":1560,"MSG_CAP":1584,"KEY_CAP":1608,"CLASS_CAP":1632,"TYPE_CAP":1656,"EPTR":1680,"EN":1688,"EPREFIX":1696,"ETYPE_N":1704,"EOFF":1712,"ESTATE":1720,"ENOT":1728,"EMODE":1736,"EKIND":1744,"ECLASS":1752,"ETYPE":1760,"ETRUTH":1768,"EAFTER":1776,"EERROR":1784,"EKEYFIELD":1792,"EIDENT":1800,"ECOPY_N":1808,"ECLEAN":1840,"EVAL_AT":1848,"EACTIVE":1856,"EBUF":49152
}
C.update(VREQUEST2=int.from_bytes(b"HIABVQ02","little"), VREQUEST3=int.from_bytes(b"HIABVQ03","little"),
         VDROP_REPLY=int.from_bytes(b"HIABVR02","little"), X_MAGIC=int.from_bytes(b"HIAFQTN1","little"),
         X_PTR=1864, X_MODE=1872, X_AT=1880, X_CLASS=1888, X_KEY=1912, X_ATTR=1936,
         X_NAMED=1960, X_DROP=1968, X_NEXT=1976, X_BAD=1984, X_PROBE=1992,
         X_CLEAN_NEXT=2000, X_MAP_PENDING=2008, X_OVERRIDE=2016,
         X_TAG0=2024, X_TAG1=2032, X_RECOVERY=2040)
C.update(MAGIC4=int.from_bytes(b'HIABFP04','little'),REPLY3=int.from_bytes(b'HIABFRP3','little'),
 FREQUEST6=int.from_bytes(b'HIABFQ06','little'),FREPLY3=int.from_bytes(b'HIABFR03','little'),
 VREQUEST5=int.from_bytes(b'HIABVQ05','little'),VREQUEST6=int.from_bytes(b'HIABVQ06','little'),
 M_DEFER=872,M_QUEUE=880,M_UNMAP=848,M_BAD=856,M_NEXT=864)
C.update(FREQUEST5=int.from_bytes(b'HIABFQ05','little'))
C.update(CREQUEST2=int.from_bytes(b'HIAPFC02','little'),LOG_REQUEST5=int.from_bytes(b'HIAFPL05','little'),LOG_REPLY2=int.from_bytes(b'HIAFPLR2','little'))
C.update(GMAGIC2=int.from_bytes(b'HIABFC02','little'),GREPLY2=int.from_bytes(b'HIABFCR2','little'),GOBJECT2=int.from_bytes(b'HIABFCT2','little'))
SOURCE=r'''
def future_public(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT or length(w)<256:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase==1490:
        managed_cell_ok(o)
        return again(o,get(o,M_NEXT))
    if phase>=1700:
        return guarded(s,o,w,phase)
    if phase>=1500:
        return extended_value(s,o,w,phase)
    if phase>=1000:
        return inherited(s,o,w,phase)
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
    if length(s)!=192:
        return 4294967293
    op=readword(s,8)
    if readword(s,0)==MAGIC:
        if op>21:
            return 4294967293
    elif readword(s,0)==MAGIC2:
        if op<22 or op>25:
            return 4294967293
    elif readword(s,0)==MAGIC3:
        if op<26 or op>29:
            return 4294967293
    elif readword(s,0)==MAGIC4:
        if op>30:
            return 4294967293
    else:
        return 4294967293
    at=16
    while at<192:
        used=False
        if op==0 and (at==16 or at==24):
            used=True
        if op>=2 and op<=17 and at>=16 and at<=56:
            used=True
        if (op==19 or op==21 or op==30 or (op>=22 and op<=27)) and at>=16 and at<=56:
            used=True
        if op==28 and at>=16 and at<=32:
            used=True
        if (op==12 or op==13 or op==22 or op==23 or op==30) and at>=64 and at<=80:
            used=True
        if (op==12 or op==22 or op==23) and at==96:
            used=True
        if (op==13 or op==30) and at==88:
            used=True
        if (op==10 or op==11 or op==30) and at>=104 and at<=120:
            used=True
        if used==False and readword(s,at)!=0:
            return 4294967293
        at=at+8
    if (op==12 or op==22 or op==23) and (readword(s,96)<1 or readword(s,96)>3):
        return 4294967293
    if (op==13 or op==30) and readword(s,88)==0:
        return 4294967293
    zero(o,128,OUT-128)
    put(o,OP,op)
    if readword(s,0)==MAGIC4:
        put(o,M_DEFER,1)
    if op==26 or op==27 or op==29:
        put(o,DROP_KNOWN,1)
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
        if get(w,0)!=STATE or get(w,8)!=pid:
            return finish(o,1,107)
        if get(w,24)!=0:
            if get(o,OP)!=29:
                return finish(o,1,107)
            # Even an idempotent close validates the actual context address.
            if get(w,24)>3:
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
        if get(w,208)!=get(o,WPTR):
            return finish(o,1,107)
        return lock(o,20)
    if phase==4:
        if value_ok(o)==False:
            return finish(o,1,choose(value_local_status(o)==5,103,107))
        within(o,TOKEN,VP+24,24)
        copy_between(o,TOKEN,w,128,24)
        zero(w,0,64)
        put(w,224,0)
        put(w,0,STATE)
        put(w,8,get(o,PID))
        return waddress(o,5,0)
    if phase==5:
        put(w,208,get(o,FEEDBACK))
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
        op=get(o,OP)
        if op==29:
            return global_close(o,w,20)
        if get(w,24)!=0:
            return fail(o,1,107)
        if get(w,200)!=0 and get(o,OP)!=20:
            put(o,CLEANUP_FAILED,1)
            return fail(o,1,107)
        if op==18:
            if get(w,16)!=0 or get(w,48)!=0 or get(w,224)!=0:
                return fail(o,1,107)
            value_packet(o,22)
            copy_between(w,128,o,RQ+24,24)
            return value(o,w,21)
        if op==20:
            put(o,CURSOR,get(w,16))
            return again(o,25)
        if op==1:
            return allocate(o,120,2176)
        put(o,CURSOR,get(w,16))
        return again(o,100)
    if phase==21:
        if get(o,OP)==29:
            return global_close(o,w,21)
        if value_ok(o)==False:
            return fail(o,1,107)
        zero(w,128,24)
        put(w,24,1)
        return fail(o,0,0)
    if phase==25:
        if get(o,CURSOR)==0:
            put(o,F,0)
            if get(w,200)!=0:
                put(o,CLEANUP_FAILED,1)
                return fail(o,1,107)
            zero(o,FACTORY_ID,24)
            return unlock(o,1790)
        put(o,F,get(o,CURSOR))
        return memory(o,26,0,get(o,F),3,HEADER,256)
    if phase==26:
        put(o,FACTORY_ID,get(o,F))
        within(o,FACTORY_ID+8,HEADER+32,16)
        return write_pointer(o,27,get(o,F)+56,get(o,HEADER+56)+1)
    if phase==27:
        put(o,ACTIVE,1)
        if get(o,HEADER+200)!=0:
            return again(o,1600)
        if get(o,HEADER+112)==2:
            return again(o,30)
        return unlock(o,28)
    if phase==28:
        cell_packet(o,13)
        return cell(o,w,29)
    if phase==29:
        if cell_ok(o)==False:
            put(o,CLEANUP_FAILED,1)
        return again(o,1780)
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

def global_close(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==20:
        state=get(w,24)
        if state==1:
            return fail(o,0,0)
        if state==3:
            put(o,DROP_KNOWN,0)
            put(o,DROP_PENDING,1)
            return fail(o,1,107)
        if state==2:
            put(o,DROP_KNOWN,0)
            put(o,VALUE_ATTEMPT,31)
            value_packet(o,31)
            return value(o,w,21)
        if state!=0:
            return fail(o,1,107)
        if get(w,16)!=0 or get(w,48)!=0 or get(w,224)!=0 or get(w,200)!=0:
            put(o,DROP_PENDING,1)
            return fail(o,1,107)
        put(o,DROP_KNOWN,0)
        put(o,VALUE_ATTEMPT,30)
        value_packet(o,30)
        copy_between(w,128,o,RQ+24,24)
        return value(o,w,21)
    attempt=get(o,VALUE_ATTEMPT)
    if value_drop_record(o,attempt)==False:
        put(w,24,3)
        put(o,DROP_PENDING,1)
        return fail(o,1,107)
    put(o,DROP_KNOWN,1)
    put(o,DROP_CONSUMED,get(o,VD_CONSUMED))
    if attempt==31:
        if get(o,VD_STATUS)!=0:
            # A lock-before-error reply need not observe the pending mapping.
            # Keep the previous actual record until a successful retry.
            put(o,DROP_PENDING,1)
            return fail(o,1,107)
        put(w,24,1)
        return fail(o,0,0)
    if get(o,VD_CONSUMED)!=0:
        zero(w,128,24)
        if get(o,VD_PENDING)!=0:
            put(w,24,2)
            put(o,DROP_PENDING,1)
            return fail(o,1,107)
        if get(o,VD_STATUS)!=0:
            put(w,24,3)
            put(o,DROP_PENDING,1)
            return fail(o,1,107)
        put(w,24,1)
        return fail(o,0,0)
    if get(o,VD_PENDING)!=0:
        # This invocation did not consume the held token; do not adopt an
        # unrelated pending mapping as authority to retry it.
        put(w,24,3)
        put(o,DROP_PENDING,1)
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
        if get(o,HEADER+32)!=readword(s,24) or get(o,HEADER+40)!=readword(s,32):
            return fail(o,3,107)
        put(o,FACTORY_ID,get(o,F))
        put(o,FACTORY_ID+8,get(o,HEADER+32))
        put(o,FACTORY_ID+16,get(o,HEADER+40))
        op=get(o,OP)
        if op==28:
            return factory_retry(o,w)
        if get(o,HEADER+112)!=1:
            return fail(o,3,107)
        if op==2 or op==3 or op==4 or op==17 or op==27:
            put(o,CURSOR,get(o,HEADER+48))
            return again(o,110)
        return again(o,300)
    if phase==108:
        return again(o,26)
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
        if op==3 or op==27:
            return again(o,180)
        if op==17:
            put(o,RAW_RESULT,get(w,80))
            put(o,RAW_RESULT+8,get(o,F)+256)
            put(o,RAW_RESULT+16,256)
            return fail(o,0,6)
        return again(o,300)
    return fail(o,1,107)

def factory_retry(o:mutbuf,w:mutbuf) -> u32:
    state=get(o,HEADER+128)
    if state!=1 and state!=2:
        return fail(o,3,107)
    put(o,DROP_KNOWN,1)
    put(o,DROP_PENDING,1)
    if state==2:
        return fail(o,0,0)
    if get(o,HEADER+144)!=0:
        return fail(o,1,107)
    put(o,RETIRE_OWNED,1)
    return write_pointer(o,108,get(o,F)+128,2)

def construct(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==120:
        if get(o,FEEDBACK)==0:
            return fail(o,1,103)
        put(o,F,get(o,FEEDBACK))
        put(o,NEWF,get(o,FEEDBACK))
        zero(o,RQ,512)
        put(o,RQ,OBJECT)
        put(o,RQ+8,get(o,PID))
        # One real inline cleanup record shares this owned mapping. Reserving
        # it does not insert a new allocation before Future completion.
        put(o,RQ+240,2176)
        return memory(o,121,3,RQ,0,get(o,F),512)
    if phase==121:
        value_packet(o,21)
        return value(o,w,122)
    if phase==122:
        if value_ok(o)==False:
            return fail(o,1,choose(value_local_status(o)==5,103,107))
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
        if get(o,OP)==27:
            put(o,DROP_CONSUMED,1)
            return memory(o,184,0,get(o,F)+48,3,TEMP,8)
        return fail(o,0,0)
    if phase==184:
        if get(o,TEMP)!=0:
            return fail(o,0,0)
        put(o,RETIRE_OWNED,1)
        return write_pointer(o,185,get(o,F)+128,2)
    if phase==185:
        return fail(o,0,0)
    return fail(o,1,107)

def methods(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        return write_pointer(o,301,get(o,F)+56,get(o,HEADER+56)+1)
    if phase==301:
        put(o,ACTIVE,1)
        op=get(o,OP)
        if op==4:
            put(o,GNEXT,303)
            return unlock(o,1700)
        if op==6 or op==26:
            return unlock(o,340)
        # Check the original capability before reserving cleanup storage.
        cell_packet(o,6)
        copy_input(s,40,o,RQ+24,24)
        return cell(o,w,307)
    if phase==307:
        if cell_ok(o)==False:
            return cell_error(o)
        if get(o,OP)==30:
            put(o,KERNEL,get(o,FP+64))
        put(o,GNEXT,309)
        return unlock(o,1700)
    if phase==309:
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
        if op==7 or op==8 or op==12 or op==13 or op==22 or op==23:
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
        if op==30:
            cell_packet(o,22)
            put(o,RQ,FREQUEST5)
            within(o,RQ+24,FUTURE_TEMP,24)
            copy_input(s,64,o,RQ+48,24)
            put(o,RQ+72,readword(s,88))
            copy_input(s,104,o,RQ+80,24)
            put(o,RQ+104,get(o,KERNEL))
            return cell(o,w,320)
        if op==13:
            copy_input(s,0,o,RQ,192)
            put(o,RQ,choose(get(o,M_DEFER)!=0,CREQUEST2,CREQUEST))
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
        elif op==22:
            k=15
        elif op==23:
            k=16
        elif op==24:
            k=17
        elif op==16 or op==25:
            k=18
        cell_packet(o,k)
        within(o,RQ+24,FUTURE_TEMP,24)
        if op==12 or op==22 or op==23:
            copy_input(s,64,o,RQ+48,24)
            put(o,RQ+80,readword(s,96))
        return cell(o,w,320)
    if phase==320:
        if cell_ok(o)==False:
            return cell_error(o)
        if get(o,OP)==30:
            if get(o,FP+16)!=7 or get(o,FP+64)!=get(o,KERNEL):
                return fail(o,1,107)
            put(o,SCALAR,get(o,FP+64))
            return fail(o,0,7)
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
        if (op==22 or op==23) and get(o,FP+40)==6:
            return error_begin(o,w,1)
        if op==24 and get(o,FP+40)==7:
            return error_begin(o,w,2)
        if get(o,FP+40)!=0:
            return fail(o,1,kernel_error(get(o,FP+40)))
        if op==24:
            put(o,SCALAR,get(o,FP+64))
            if get(o,SCALAR)==0:
                cell_packet(o,6)
                within(o,RQ+24,FUTURE_TEMP,24)
                return cell(o,w,1021)
            return fail(o,0,1)
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
        if op==16 or op==25:
            put(o,SCALAR,get(o,FP+64))
            return fail(o,0,1)
        if op==9 or op==19:
            put(o,SCALAR,get(o,FP+48))
            return fail(o,0,5)
        return fail(o,0,0)
    if phase==330:
        if get(o,FEEDBACK)!=0 or get(o,CP)!=CREPLY:
            return fail(o,1,107)
        if get(o,M_DEFER)!=0:
            if get(o,CP+32)>1 or get(o,CP+40)>1 or get(o,CP+48)>1:
                put(o,M_BAD,1)
                return fail(o,1,107)
            if get(o,CP+32)!=0:
                put(o,M_UNMAP,1)
            if get(o,CP+40)!=0:
                put(o,M_QUEUE,1)
            if get(o,CP+48)!=0:
                put(o,M_BAD,1)
                return fail(o,1,107)
        if get(o,CP+8)!=0:
            return fail(o,1,get(o,CP+16))
        return fail(o,0,0)
    if phase==340:
        if get(o,OP)==26:
            cell_packet(o,20)
            put(o,DROP_KNOWN,0)
        else:
            cell_packet(o,3)
        copy_input(s,40,o,RQ+24,24)
        return cell(o,w,341)
    if phase==341:
        if get(o,OP)==26:
            return drop_record(o)
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
        if value_local_status(o)!=0:
            put(o,EXTRA,get(o,VP+40))
            return fail(o,value_local_status(o),get(o,VP+16))
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
        if get(o,FP+72)<1 or get(o,FP+72)>6:
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
        if get(o,FP+72)>=4:
            put(o,EKIND,get(o,FP+72))
            put(o,EVAL_AT,RESULT_VALUE)
            put(o,EAFTER,1110)
            return again(o,1100)
        return fail(o,get(o,FP+72)-1,200)
    return fail(o,1,107)

def retire(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase>=670 and phase<690:
        return retire_value(o,w,phase)
    if phase==600:
        return memory(o,601,0,get(o,F),3,HEADER,256)
    if phase==601:
        if get(o,HEADER+200)!=0:
            return again(o,690)
        if get(o,HEADER+144)!=0 or get(o,HEADER+152)!=0:
            return again(o,690)
        if get(o,HEADER+128)!=0 and get(o,RETIRE_OWNED)==0:
            return again(o,690)
        if get(o,RETIRE_OWNED)!=0 and get(o,HEADER+144)!=0:
            return retirement_error(o)
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
            if get(o,RETIRE_OWNED)!=0:
                if get(o,FEEDBACK)==0 and get(o,FP)==FREPLY and get(o,FP+8)==6:
                    return retirement_error(o)
                return write_pointer(o,687,get(o,F)+144,1)
            return fail(o,1,107)
        return write_pointer(o,604,get(o,F)+112,2)
    if phase==604:
        if get(o,RETIRE_OWNED)!=0:
            if get(o,HEADER+136)!=0:
                put(o,VALUE_ATTEMPT,31)
                value_packet(o,31)
                return value(o,w,605)
            if get(o,HEADER+72)==0:
                return again(o,606)
            put(o,VALUE_ATTEMPT,30)
            value_packet(o,30)
            within(o,RQ+24,HEADER+72,24)
            return value(o,w,605)
        if get(o,HEADER+72)==0:
            return again(o,606)
        value_packet(o,22)
        within(o,RQ+24,HEADER+72,24)
        return value(o,w,605)
    if phase==605:
        if get(o,RETIRE_OWNED)!=0:
            return retire_value(o,w,phase)
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
        put(o,DROP_PENDING,0)
        put(o,RETIRE_OWNED,0)
        return again(o,690)
    if phase==690:
        if get(o,X_RECOVERY)==2:
            return unlock(o,980)
        if get(o,OP)==20:
            put(o,CURSOR,get(o,RETRY_NEXT))
            return again(o,25)
        if get(o,RETIRE_OWNED)!=0 and get(o,F)!=0:
            put(o,DROP_PENDING,1)
            put(o,RETIRE_OWNED,0)
            return write_pointer(o,691,get(o,F)+128,1)
        return unlock(o,980)
    if phase==691:
        return unlock(o,980)
    return fail(o,1,107)

def retirement_error(o:mutbuf) -> u32:
    put(o,CLEANUP_FAILED,1)
    put(o,ERROR,1)
    put(o,RKIND,107)
    return again(o,690)

def retire_value(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==605:
        attempt=get(o,VALUE_ATTEMPT)
        if value_drop_record(o,attempt)==False:
            return write_pointer(o,687,get(o,F)+144,1)
        if attempt==31:
            if get(o,VD_STATUS)!=0:
                return retirement_error(o)
            return write_pointer(o,674,get(o,F)+136,0)
        if get(o,VD_CONSUMED)==0:
            if get(o,VD_PENDING)!=0:
                return write_pointer(o,687,get(o,F)+144,1)
            return retirement_error(o)
        zero(o,TOKEN,24)
        return memory(o,671,3,TOKEN,0,get(o,F)+72,24)
    if phase==671:
        if get(o,VD_PENDING)!=0:
            return write_pointer(o,672,get(o,F)+136,1)
        if get(o,VD_STATUS)!=0:
            return write_pointer(o,687,get(o,F)+144,1)
        return again(o,606)
    if phase==674:
        return again(o,606)
    if phase==672 or phase==687:
        return retirement_error(o)
    return retirement_error(o)

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==900:
        if get(o,GBAD)!=0 and get(o,GPTR)!=0:
            return guard_bad_snapshot(o)
        if get(o,EACTIVE)!=0:
            return again(o,1400)
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
        if get(o,GPTR)!=0:
            if get(o,HELD)!=0:
                return unlock(o,900)
            return guard_snapshot(o,1740)
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
    magic=choose(op>=15,FREQUEST3,FREQUEST)
    if op==20 or op==21:
        magic=FREQUEST4
    put(o,RQ,choose(get(o,M_DEFER)!=0,FREQUEST6,magic))
    put(o,RQ+8,op)
    return 0
def value_packet(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,192)
    put(o,RQ,choose(op>=29,VREQUEST2,VREQUEST))
    put(o,RQ+8,op)
    if get(o,M_DEFER)!=0:
        put(o,RQ,VREQUEST6)
        if op==6 or op==29:
            put(o,RQ+8,78)
            put(o,RQ,VREQUEST5)
        elif op==22 or op==30:
            put(o,RQ+8,92)
            put(o,RQ,VREQUEST5)
        elif op==31:
            put(o,RQ+8,93)
            put(o,RQ,VREQUEST5)
        elif op==5:
            put(o,RQ+8,91)
            put(o,RQ,VREQUEST5)
    return 0
def cell(o:mutbuf,w:mutbuf,next:u64) -> u32:
    if get(o,RQ+8)==3 and get(o,GPTR)!=0:
        put(o,GKIND,1)
        put(o,GNEXT,next)
        put(o,GKEEP,get(o,HELD))
        return guard_snapshot(o,1720)
    if get(o,M_DEFER)!=0:
        put(o,M_NEXT,next)
        return invoke(o,1490,get(w,80),RQ,128,FP,16384,get(o,F)+256,256)
    return invoke(o,next,get(w,80),RQ,128,FP,16384,get(o,F)+256,256)
def value(o:mutbuf,w:mutbuf,next:u64) -> u32:
    if get(o,RQ+8)==6 and get(o,GPTR)!=0:
        put(o,GKIND,2)
        put(o,GNEXT,next)
        put(o,GKEEP,get(o,HELD))
        return guard_snapshot(o,1720)
    return invoke(o,next,get(w,72),RQ,128,VP,8192,get(w,112),get(w,120))
def cell_ok(o:mutbuf) -> bool:
    if get(o,M_DEFER)!=0:
        return managed_cell_ok(o)
    return get(o,FEEDBACK)==0 and get(o,FP)==FREPLY and get(o,FP+8)==0
def value_ok(o:mutbuf) -> bool:
    if get(o,M_DEFER)!=0 and get(o,RQ)==VREQUEST5:
        if get(o,RQ+8)==91:
            return managed_retain_ok(o)
        if get(o,RQ+8)==78 or get(o,RQ+8)==92:
            if managed_drop_record(o,True)==False:
                return False
            return get(o,VD_CONSUMED)==1
    return get(o,FEEDBACK)==0 and get(o,VP)==VREPLY and value_local_status(o)==0
def value_drop_record(o:mutbuf,op:u64) -> bool:
    if get(o,M_DEFER)!=0:
        return managed_drop_record(o,op!=31)
    if get(o,FEEDBACK)!=0 or get(o,VP)!=VREPLY2:
        return False
    status=value_local_status(o)
    pending=value_local_pending(o)
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
    put(o,VD_CONSUMED,consumed)
    put(o,VD_PENDING,pending)
    put(o,VD_STATUS,status)
    return True
def cell_error(o:mutbuf) -> u32:
    if get(o,FEEDBACK)!=0 or get(o,FP)!=FREPLY:
        return fail(o,1,107)
    if get(o,FP+8)==1:
        return fail(o,3,107)
    return fail(o,1,choose(get(o,FP+8)==4,103,107))
def drop_record(o:mutbuf) -> u32:
    if get(o,FEEDBACK)!=0 or get(o,FP)!=choose(get(o,M_DEFER)!=0,FREPLY3,FREPLY2):
        return fail(o,1,107)
    status=get(o,FP+8)
    consumed=get(o,FP+128)
    if consumed>1 or get(o,FP+120)>1:
        return fail(o,1,107)
    if status!=0 and status!=1 and status!=5 and status!=6 and status!=9:
        return fail(o,1,107)
    if status==0 and consumed!=1:
        return fail(o,1,107)
    if consumed==1 and status!=0 and status!=9:
        return fail(o,1,107)
    at=16
    while at<160:
        if at!=120 and at!=128 and get(o,FP+at)!=0:
            return fail(o,1,107)
        at=at+8
    put(o,DROP_CONSUMED,consumed)
    put(o,DROP_KNOWN,1)
    if status==0:
        return fail(o,0,0)
    return fail(o,choose(status==1,3,1),107)
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
    if get(o,OP)>=26 and get(o,OP)<=29:
        put(o,0,REPLY2)
        put(o,96,get(o,DROP_CONSUMED))
        put(o,104,get(o,DROP_KNOWN))
        put(o,112,get(o,DROP_PENDING))
        if (get(o,OP)==27 or get(o,OP)==28) and get(o,DROP_PENDING)!=0:
            within(o,24,FACTORY_ID,24)
    if get(o,M_DEFER)!=0:
        put(o,0,REPLY3)
        put(o,128,get(o,M_UNMAP))
        put(o,136,get(o,M_QUEUE))
        put(o,144,get(o,M_BAD))
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
SOURCE+=r'''
def inherited(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase<1100:
        return inherited_error(s,o,w,phase)
    if phase<1200:
        return inherited_value(s,o,w,phase)
    if phase<1300:
        return inherited_message(s,o,w,phase)
    if phase<1400:
        return inherited_record(s,o,w,phase)
    return inherited_cleanup(s,o,w,phase)

def error_begin(o:mutbuf,w:mutbuf,kind:u64) -> u32:
    put(o,EACTIVE,1)
    put(o,EERROR,kind)
    put(o,ESTATE,get(o,FP+48))
    put(o,ENOT,get(o,FP+136))
    put(o,EMODE,get(o,FP+144))
    cell_packet(o,6)
    within(o,RQ+24,FUTURE_TEMP,24)
    return cell(o,w,1001)

def inherited_error(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1001:
        if cell_ok(o)==False:
            return inherited_fail(o,107)
        put(o,EIDENT,get(o,FP+64))
        if get(o,EERROR)==2:
            zero(o,RQ,192)
            put(o,RQ,choose(get(o,M_DEFER)!=0,LOG_REQUEST5,LOG_REQUEST2))
            put(o,RQ+8,get(o,EIDENT))
            put(o,RQ+16,state_code(get(o,ESTATE),get(o,ENOT),1))
            return invoke(o,1004,get(w,176),RQ,192,CP,16384,get(o,WPTR),256)
        cell_packet(o,19)
        within(o,RQ+24,FUTURE_TEMP,24)
        return cell(o,w,1002)
    if phase==1002:
        if cell_ok(o)==False:
            return cell_error(o)
        if get(o,FP+40)!=0:
            return inherited_fail(o,107)
        put(o,EKIND,get(o,FP+72))
        put(o,ECLASS,get(o,FP+152))
        within(o,EVAL_CAP,FP+80,24)
        if get(o,ESTATE)!=2:
            return again(o,1200)
        if get(o,EVAL_CAP)==0 or get(o,EKIND)<1 or get(o,EKIND)>6:
            return inherited_fail(o,107)
        if get(o,EKIND)==1:
            put(o,ETRUTH,0)
            return again(o,1120)
        put(o,EVAL_AT,EVAL_CAP)
        put(o,EAFTER,1010)
        return again(o,1100)
    if phase==1004:
        if get(o,FEEDBACK)!=0 or get(o,CP)!=choose(get(o,M_DEFER)!=0,LOG_REPLY2,LOG_REPLY) or get(o,CP+8)!=0:
            return inherited_fail(o,107)
        if get(o,M_DEFER)!=0:
            at=24
            while at<128:
                if get(o,CP+at)!=0:
                    put(o,M_BAD,1)
                    return inherited_fail(o,107)
                at=at+8
        return again(o,1200)
    if phase==1021:
        if cell_ok(o)==False:
            return inherited_fail(o,107)
        zero(o,RQ,64)
        put(o,RQ,NOTIFY3)
        put(o,RQ+8,get(o,FP+64))
        return invoke(o,1022,get(w,184),RQ,64,CP,8192,get(o,WPTR),256)
    if phase==1022:
        if get(o,FEEDBACK)!=0 or get(o,CP)!=NOTIFY_REPLY or get(o,CP+8)!=0:
            return inherited_fail(o,107)
        return fail(o,0,1)
    if phase==1010:
        if get(o,ETRUTH)==0:
            put(o,ETYPE,0)
            return again(o,1200)
        return again(o,1120)
    return inherited_fail(o,107)

def inherited_value(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1100:
        value_packet(o,7)
        within(o,RQ+24,get(o,EVAL_AT),24)
        return value(o,w,1101)
    if phase==1101:
        if value_ok(o)==False or get(o,VP+16)>12:
            return inherited_fail(o,107)
        typ=get(o,VP+16)
        put(o,ETYPE,typ)
        if get(o,EAFTER)==1110:
            put(o,ETRUTH,choose(typ!=0,1,0))
            return again(o,1110)
        if typ==0:
            put(o,ETRUTH,0)
            return again(o,get(o,EAFTER))
        if typ==8:
            return extended_begin(o,1,get(o,EVAL_AT))
        if typ==9 or typ==10 or typ==12:
            put(o,ETRUTH,1)
            return again(o,get(o,EAFTER))
        if typ>=4:
            put(o,ETRUTH,choose(get(o,VP+48)!=0,1,0))
            return again(o,get(o,EAFTER))
        if typ==2 and get(o,VP+72)>1:
            put(o,ETRUTH,1)
            return again(o,get(o,EAFTER))
        amount=1
        if typ==3:
            amount=8
        value_packet(o,19)
        within(o,RQ+24,get(o,EVAL_AT),24)
        put(o,RQ+112,amount)
        return value_wide(o,w,1102,128,8200)
    if phase==1102:
        if value_ok(o)==False:
            return inherited_fail(o,107)
        typ=get(o,ETYPE)
        if typ==3:
            if get(o,VP+64)!=8:
                return inherited_fail(o,107)
            put(o,ETRUTH,choose((get(o,VP+8192)&9223372036854775807)!=0,1,0))
        else:
            if get(o,VP+64)!=1:
                return inherited_fail(o,107)
            expected=0
            if typ==2:
                expected=48
            put(o,ETRUTH,choose(byte(o,VP+8192)!=expected,1,0))
        return again(o,get(o,EAFTER))
    if phase==1110:
        if get(o,ETRUTH)==0:
            within(o,DISCARD_VALUE,RESULT_VALUE,24)
            zero(o,RESULT_VALUE,24)
            return fail(o,0,0)
        kind=get(o,EKIND)
        if kind==5 or kind==6:
            return fail(o,kind-4,200)
        within(o,DISCARD_VALUE,RESULT_VALUE,24)
        zero(o,RESULT_VALUE,24)
        put(o,EACTIVE,1)
        put(o,EERROR,3)
        return again(o,1200)
    if phase==1120:
        value_packet(o,7)
        within(o,RQ+24,EVAL_CAP,24)
        return value(o,w,1121)
    if phase==1121:
        if value_ok(o)==False or get(o,VP+16)>12:
            return inherited_fail(o,107)
        put(o,ETYPE,get(o,VP+16))
        if get(o,ETYPE)>=8:
            return extended_begin(o,2,EVAL_CAP)
        kind=get(o,EKIND)
        typed=(kind==1 and get(o,ECLASS)>=2) or kind==2 or kind==3 or kind==5 or kind==6
        if typed==False:
            return again(o,1200)
        value_packet(o,2)
        n=inherited_literal(o,RQ+128,0)
        put(o,RQ+96,n)
        put(o,RQ+104,4)
        return value_wide(o,w,1122,128+n,8192)
    if phase==1122:
        if value_ok(o)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        within(o,KEY_CAP,VP+24,24)
        value_packet(o,9)
        within(o,RQ+24,EVAL_CAP,24)
        within(o,RQ+48,KEY_CAP,24)
        return value(o,w,1123)
    if phase==1123:
        if value_ok(o)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        within(o,TYPE_CAP,VP+24,24)
        value_packet(o,6)
        within(o,RQ+24,KEY_CAP,24)
        return value(o,w,1124)
    if phase==1124:
        if value_ok(o)==False:
            return inherited_fail(o,107)
        zero(o,KEY_CAP,24)
        value_packet(o,7)
        within(o,RQ+24,TYPE_CAP,24)
        return value(o,w,1125)
    if phase==1125:
        if value_ok(o)==False or get(o,VP+16)!=4:
            return inherited_fail(o,107)
        put(o,ETYPE_N,get(o,VP+72))
        return again(o,1200)
    return inherited_fail(o,107)

def inherited_message(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1200:
        n=error_prefix(o)
        put(o,EPREFIX,n)
        size=get(o,ETYPE_N)
        if get(o,TYPE_CAP)==0:
            size=0
        if size>MAX-n-129:
            return inherited_fail(o,103)
        total=n+size
        if get(o,TYPE_CAP)!=0:
            total=total+1
        put(o,EN,total)
        put(o,EOFF,0)
        return allocate(o,1201,128+total)
    if phase==1201:
        ptr=get(o,FEEDBACK)
        if ptr==0:
            return inherited_fail(o,103)
        put(o,EPTR,ptr)
        value_packet(o,2)
        put(o,RQ+96,get(o,EN))
        put(o,RQ+104,4)
        return memory(o,1202,3,RQ,0,ptr,128)
    if phase==1202:
        return memory(o,1203,3,EBUF,0,get(o,EPTR)+128,get(o,EPREFIX))
    if phase==1203:
        if get(o,TYPE_CAP)==0:
            return again(o,1208)
        if get(o,EOFF)==get(o,ETYPE_N):
            store(o,EBUF,62)
            return memory(o,1208,3,EBUF,0,get(o,EPTR)+128+get(o,EPREFIX)+get(o,EOFF),1)
        n=get(o,ETYPE_N)-get(o,EOFF)
        if n>1024:
            n=1024
        put(o,ECOPY_N,n)
        value_packet(o,19)
        within(o,RQ+24,TYPE_CAP,24)
        put(o,RQ+104,get(o,EOFF))
        put(o,RQ+112,n)
        return value_wide(o,w,1204,128,9216)
    if phase==1204:
        if value_ok(o)==False or get(o,VP+64)!=get(o,ECOPY_N):
            return inherited_fail(o,107)
        return memory(o,1205,3,VP+8192,0,get(o,EPTR)+128+get(o,EPREFIX)+get(o,EOFF),get(o,ECOPY_N))
    if phase==1205:
        put(o,EOFF,get(o,EOFF)+get(o,ECOPY_N))
        return again(o,1203)
    if phase==1208:
        return invoke_absolute(o,1209,get(w,72),get(o,EPTR),128+get(o,EN),VP,8192,get(w,112),get(w,120))
    if phase==1209:
        if value_ok(o)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        within(o,MSG_CAP,VP+24,24)
        ptr=get(o,EPTR)
        put(o,EPTR,0)
        return deallocate(o,1300,ptr)
    return inherited_fail(o,107)

def inherited_record(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1300:
        value_packet(o,4)
        return value(o,w,1301)
    if phase==1301:
        if value_ok(o)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        within(o,ERROR_CAP,VP+24,24)
        value_packet(o,2)
        n=inherited_literal(o,RQ+128,1+get(o,EERROR))
        put(o,RQ+96,n)
        put(o,RQ+104,4)
        return value_wide(o,w,1302,128+n,8192)
    if phase==1302:
        if value_ok(o)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        within(o,CLASS_CAP,VP+24,24)
        put(o,EKEYFIELD,0)
        return again(o,1303)
    if phase==1303:
        value_packet(o,2)
        n=inherited_literal(o,RQ+128,get(o,EKEYFIELD))
        put(o,RQ+96,n)
        put(o,RQ+104,4)
        return value_wide(o,w,1304,128+n,8192)
    if phase==1304:
        if value_ok(o)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        within(o,KEY_CAP,VP+24,24)
        value_packet(o,10)
        within(o,RQ+24,ERROR_CAP,24)
        within(o,RQ+48,KEY_CAP,24)
        at=CLASS_CAP
        if get(o,EKEYFIELD)==1:
            at=MSG_CAP
        within(o,RQ+72,at,24)
        return value(o,w,1305)
    if phase==1305:
        if value_ok(o)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        value_packet(o,6)
        within(o,RQ+24,KEY_CAP,24)
        return value(o,w,1306)
    if phase==1306:
        if value_ok(o)==False:
            return inherited_fail(o,107)
        zero(o,KEY_CAP,24)
        if get(o,EKEYFIELD)==0:
            put(o,EKEYFIELD,1)
            return again(o,1303)
        within(o,RESULT_VALUE,ERROR_CAP,24)
        zero(o,ERROR_CAP,24)
        return fail(o,1,200)
    return inherited_fail(o,107)

def inherited_cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1400:
        if get(o,X_PTR)!=0:
            put(o,X_CLEAN_NEXT,1400)
            return again(o,1570)
        if get(o,GBAD)!=0 and get(o,GPTR)!=0:
            return again(o,900)
        i=EVAL_CAP
        while i<=TYPE_CAP:
            if get(o,i)!=0:
                put(o,ECLEAN,i)
                value_packet(o,6)
                within(o,RQ+24,i,24)
                return value(o,w,1401)
            i=i+24
        if get(o,EPTR)!=0:
            ptr=get(o,EPTR)
            put(o,EPTR,0)
            return deallocate(o,1400,ptr)
        put(o,EACTIVE,0)
        return again(o,900)
    if phase==1401:
        if value_ok(o)==False:
            put(o,CLEANUP_FAILED,1)
        zero(o,get(o,ECLEAN),24)
        return again(o,1400)
    return fail(o,1,107)

def guarded(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase<1720:
        return guard_reserve(o,w,phase)
    if phase<1740:
        return guard_drop(o,w,phase)
    if phase<1760:
        return guard_release(o,w,phase)
    if phase<1780:
        return guard_quarantine(o,w,phase)
    return guard_retry(o,w,phase)

def guard_reserve(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1700:
        guard_packet(o,0)
        put(o,GREQUEST+96,GCOUNT)
        return guard_call(o,w,1701)
    if phase==1701:
        if guard_record(o,0)==False:
            put(o,CLEANUP_FAILED,1)
            return fail(o,1,107)
        if get(o,GOUTPUT+8)!=0:
            return fail(o,1,choose(get(o,GOUTPUT+8)==4,103,107))
        within(o,GCAP,GOUTPUT+16,24)
        return lock(o,1702)
    if phase==1702:
        return memory(o,1703,0,get(o,F)+152,3,GSCAN,8)
    if phase==1703:
        if get(o,GSCAN)==0:
            put(o,CLEANUP_FAILED,1)
            return fail(o,1,107)
        return memory(o,1704,0,get(o,GSCAN),3,NODE,128)
    if phase==1704:
        if get(o,NODE)!=choose(get(o,M_DEFER)!=0,GOBJECT2,GOBJECT) or get(o,NODE+8)!=get(o,PID) or get(o,NODE+16)!=get(o,F):
            put(o,CLEANUP_FAILED,1)
            return fail(o,1,107)
        if get(o,GSCAN)!=get(o,GCAP):
            put(o,GSCAN,get(o,NODE+48))
            return again(o,1703)
        if get(o,NODE+24)!=get(o,FACTORY_ID+8) or get(o,NODE+32)!=get(o,FACTORY_ID+16) or get(o,NODE+56)!=get(o,GCAP+8) or get(o,NODE+64)!=get(o,GCAP+16):
            put(o,CLEANUP_FAILED,1)
            return fail(o,1,107)
        if get(o,NODE+72)!=0 or get(o,NODE+80)!=0 or get(o,NODE+88)!=GCOUNT or get(o,NODE+96)!=128+96*GCOUNT or get(o,NODE+112)!=0:
            put(o,CLEANUP_FAILED,1)
            return fail(o,1,107)
        put(o,GPTR,get(o,GSCAN))
        # Reservation released the registry lock. Re-observe the live frame
        # head before linking this call's callback frame under the same lock.
        return memory(o,1705,0,get(o,F),3,HEADER,256)
    if phase==1705:
        if get(o,GNEXT)==303:
            return unlock(o,303)
        return again(o,get(o,GNEXT))
    return fail(o,1,107)

def guard_drop(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1720:
        if get(o,HELD)!=0:
            return unlock(o,1720)
        guard_packet(o,1)
        put(o,GREQUEST+64,get(o,GKIND))
        within(o,GREQUEST+72,RQ+24,24)
        return guard_call(o,w,1721)
    if phase==1721:
        put(o,GSTATUS,choose(get(o,GKIND)==1,9,11))
        if guard_record(o,1)==False:
            put(o,GBAD,1)
            put(o,CLEANUP_FAILED,1)
        elif get(o,GOUTPUT+56)!=1:
            put(o,GBAD,1)
            put(o,CLEANUP_FAILED,1)
        elif get(o,GOUTPUT+8)==0:
            put(o,GSTATUS,0)
        else:
            put(o,CLEANUP_FAILED,1)
        if get(o,GKEEP)!=0:
            return lock(o,1722)
        return again(o,1722)
    if phase==1722:
        at=choose(get(o,GKIND)==1,FP,VP)
        zero(o,at,128)
        put(o,at,choose(get(o,GKIND)==1,choose(get(o,M_DEFER)!=0,FREPLY3,FREPLY),VREPLY))
        if get(o,M_DEFER)!=0 and get(o,GKIND)==1:
            put(o,FP+160,get(o,GOUTPUT+88))
            put(o,FP+168,get(o,GOUTPUT+96))
        put(o,at+8,get(o,GSTATUS))
        put(o,FEEDBACK,0)
        return again(o,get(o,GNEXT))
    return fail(o,1,107)

def guard_release(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1740:
        guard_packet(o,2)
        return guard_call(o,w,1741)
    if phase==1741:
        within(o,GLOST,GCAP,24)
        zero(o,GCAP,24)
        put(o,GPTR,0)
        if guard_record(o,2)==False:
            put(o,CLEANUP_FAILED,1)
            return lock(o,1770)
        if get(o,GOUTPUT+56)!=1:
            put(o,CLEANUP_FAILED,1)
            return lock(o,1770)
        if get(o,GOUTPUT+8)!=0:
            put(o,CLEANUP_FAILED,1)
        return again(o,900)
    return fail(o,1,107)

def guard_quarantine(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1760:
        if get(o,HELD)!=0:
            return again(o,1761)
        return lock(o,1761)
    if phase==1761:
        return write_pointer(o,1762,get(o,GPTR)+112,1)
    if phase==1762:
        return write_pointer(o,1763,get(o,GPTR)+72,1)
    if phase==1763:
        # The independently linked shadow now owns the complete unresolved
        # temporary-reference callsite. No original drop may be replayed.
        zero(o,FUTURE_TEMP,24)
        zero(o,DISCARD_VALUE,24)
        zero(o,EVAL_CAP,144)
        zero(o,GCAP,24)
        put(o,GPTR,0)
        put(o,GBAD,0)
        put(o,CLEANUP_FAILED,1)
        return again(o,900)
    if phase==1770:
        # Release may already have freed an empty guard. Preserve its exact
        # identity in the actual factory; never dereference or replay it.
        return memory(o,1771,3,GLOST,0,get(o,F)+168,24)
    if phase==1771:
        return write_pointer(o,900,get(o,F)+144,1)
    return fail(o,1,107)

def guard_retry(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1780 or phase==1790:
        guard_packet(o,3)
        return guard_call(o,w,phase+1)
    if guard_record(o,3)==False:
        put(o,CLEANUP_FAILED,1)
    elif get(o,GOUTPUT+8)!=0 or get(o,GOUTPUT+40)!=0:
        put(o,CLEANUP_FAILED,1)
    if phase==1781:
        return lock(o,30)
    if phase==1791:
        return fail(o,0,0)
    return fail(o,1,107)

def guard_snapshot(o:mutbuf,next:u64) -> u32:
    zero(o,GSHADOW,GCOUNT*32)
    guard_shadow_current(o,GSHADOW)
    return memory(o,next,3,GSHADOW,0,get(o,GPTR)+128+GCOUNT*64,GCOUNT*32)

def guard_bad_snapshot(o:mutbuf) -> u32:
    # Keep the pre-call half even if the original continuation has already
    # cleared its local slot. The second half captures any subsequent moves.
    zero(o,GSHADOW+256,256)
    guard_shadow_current(o,GSHADOW+256)
    return memory(o,1760,3,GSHADOW,0,get(o,GPTR)+128+GCOUNT*64,GCOUNT*32)

def guard_shadow_current(o:mutbuf,to:u64) -> u64:
    guard_shadow_cap(o,to,1,FUTURE_TEMP)
    guard_shadow_cap(o,to+32,2,DISCARD_VALUE)
    i=0
    while i<6:
        guard_shadow_cap(o,to+64+i*32,2,EVAL_CAP+i*24)
        i=i+1
    return 0

def guard_shadow_cap(o:mutbuf,to:u64,kind:u64,at:u64) -> u64:
    if get(o,at)!=0:
        put(o,to,kind)
        within(o,to+8,at,24)
    return 0

def guard_packet(o:mutbuf,op:u64) -> u64:
    zero(o,GREQUEST,192)
    put(o,GREQUEST,choose(get(o,M_DEFER)!=0,GMAGIC2,GMAGIC))
    put(o,GREQUEST+8,op)
    within(o,GREQUEST+16,FACTORY_ID,24)
    if op==1 or op==2:
        within(o,GREQUEST+40,GCAP,24)
    return 0

def guard_call(o:mutbuf,w:mutbuf,next:u64) -> u32:
    if get(w,216)==0:
        put(o,FEEDBACK,MAX)
        return again(o,next)
    return invoke(o,next,get(w,216),GREQUEST,192,GOUTPUT,128,get(o,WPTR),256)

def guard_record(o:mutbuf,op:u64) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,GOUTPUT)!=choose(get(o,M_DEFER)!=0,GREPLY2,GREPLY):
        return False
    status=get(o,GOUTPUT+8)
    pending=get(o,GOUTPUT+40)
    known=get(o,GOUTPUT+48)
    taken=get(o,GOUTPUT+56)
    raw=get(o,GOUTPUT+64)
    if status!=0 and status!=1 and status!=4 and status!=5 and status!=9:
        return False
    if pending>1 or known>1 or taken>1:
        return False
    if known==0 and status!=9:
        return False
    if raw!=0 and raw!=1 and raw!=5 and raw!=6 and raw!=9 and raw!=11:
        return False
    if taken==1 and status!=0 and status!=9:
        return False
    at=88
    if get(o,M_DEFER)!=0:
        if get(o,GOUTPUT+88)>1 or get(o,GOUTPUT+96)>1:
            put(o,M_BAD,1)
            return False
        if get(o,GOUTPUT+88)!=0:
            put(o,M_QUEUE,1)
        if get(o,GOUTPUT+96)!=0:
            put(o,M_UNMAP,1)
        at=104
    while at<128:
        if get(o,GOUTPUT+at)!=0:
            return False
        at=at+8
    if op==0:
        if known!=1 or taken!=0 or raw!=0:
            return False
        if status==0:
            ptr=get(o,GOUTPUT+16)
            return ptr!=0 and ptr<=MAX-(128+96*GCOUNT) and pending==1 and get(o,GOUTPUT+72)==128+96*GCOUNT and get(o,GOUTPUT+80)==GCOUNT
    else:
        if get(o,GOUTPUT+72)!=0 or get(o,GOUTPUT+80)!=0:
            return False
        if status==0 and (known!=1 or raw!=0):
            return False
        if op==3 and taken!=0:
            return False
        if (op==1 or op==2) and status==0 and taken!=1:
            return False
        if op==1 and status==0 and pending!=1:
            return False
    return get(o,GOUTPUT+16)==0 and get(o,GOUTPUT+24)==0 and get(o,GOUTPUT+32)==0 and get(o,GOUTPUT+72)==0 and get(o,GOUTPUT+80)==0

def inherited_fail(o:mutbuf,kind:u64) -> u32:
    if get(o,RESULT_VALUE)!=0:
        within(o,DISCARD_VALUE,RESULT_VALUE,24)
        zero(o,RESULT_VALUE,24)
    return fail(o,1,kind)

def state_code(state:u64,notified:u64,running:u64) -> u64:
    if state==1:
        return choose(notified!=0,3,2)
    if state==2:
        return 4
    return choose(running!=0,1,0)

def error_prefix(o:mutbuf) -> u64:
    kind=get(o,EERROR)
    if kind==2:
        return inherited_literal(o,EBUF,5)
    if kind==3:
        return inherited_literal(o,EBUF,6)
    code=state_code(get(o,ESTATE),get(o,ENOT),0)
    at=EBUF
    at=at+inherited_literal(o,at,7+code)
    at=at+inherited_literal(o,at,12)
    at=write_hex(o,at,get(o,EIDENT))
    at=at+inherited_literal(o,at,13)
    at=at+inherited_literal(o,at,14+choose(get(o,ESTATE)==2,1,0))
    if get(o,ESTATE)==2:
        at=at+inherited_literal(o,at,16+choose(get(o,ETRUTH)!=0,1,0))
        if get(o,TYPE_CAP)!=0:
            return at-EBUF
        at=at+inherited_literal(o,at,18+get(o,ETYPE))
    store(o,at,62)
    return at-EBUF+1

def write_hex(o:mutbuf,at:u64,value:u64) -> u64:
    i=16
    started=False
    while i!=0:
        i=i-1
        digit=(value>>(i*4))&15
        if digit!=0 or started or i==0:
            store(o,at,choose(digit<10,48+digit,87+digit))
            at=at+1
            started=True
    return at

def value_wide(o:mutbuf,w:mutbuf,next:u64,sn:u64,on:u64) -> u32:
    return invoke(o,next,get(w,72),RQ,sn,VP,on,get(w,112),get(w,120))

def invoke_absolute(o:mutbuf,next:u64,fn:u64,src:u64,sn:u64,dest:u64,dn:u64,ctx:u64,cn:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,fn)
    put(o,8,48)
    put(o,16,src)
    put(o,24,sn)
    put(o,32,dest)
    put(o,40,dn)
    put(o,48,ctx)
    put(o,56,cn)
    return 9

def inherited_literal(o:mutbuf,at:u64,index:u64) -> u64:
    if index<2:
        return inherited_literal_0(o,at,index)
    if index<4:
        return inherited_literal_1(o,at,index)
    if index<6:
        return inherited_literal_2(o,at,index)
    if index<8:
        return inherited_literal_3(o,at,index)
    if index<10:
        return inherited_literal_4(o,at,index)
    if index<12:
        return inherited_literal_5(o,at,index)
    if index<14:
        return inherited_literal_6(o,at,index)
    if index<16:
        return inherited_literal_7(o,at,index)
    if index<18:
        return inherited_literal_8(o,at,index)
    if index<20:
        return inherited_literal_9(o,at,index)
    if index<22:
        return inherited_literal_10(o,at,index)
    if index<24:
        return inherited_literal_11(o,at,index)
    if index<26:
        return inherited_literal_12(o,at,index)
    return 0

def inherited_literal_0(o:mutbuf,at:u64,index:u64) -> u64:
    if index==0:
        store(o,at+0,99)
        store(o,at+1,108)
        store(o,at+2,97)
        store(o,at+3,115)
        store(o,at+4,115)
        return 5
    if index==1:
        store(o,at+0,109)
        store(o,at+1,101)
        store(o,at+2,115)
        store(o,at+3,115)
        store(o,at+4,97)
        store(o,at+5,103)
        store(o,at+6,101)
        return 7
    return 0

def inherited_literal_1(o:mutbuf,at:u64,index:u64) -> u64:
    if index==2:
        store(o,at+0,73)
        store(o,at+1,110)
        store(o,at+2,118)
        store(o,at+3,97)
        store(o,at+4,108)
        store(o,at+5,105)
        store(o,at+6,100)
        store(o,at+7,83)
        store(o,at+8,116)
        store(o,at+9,97)
        store(o,at+10,116)
        store(o,at+11,101)
        store(o,at+12,69)
        store(o,at+13,114)
        store(o,at+14,114)
        store(o,at+15,111)
        store(o,at+16,114)
        return 17
    if index==3:
        store(o,at+0,82)
        store(o,at+1,117)
        store(o,at+2,110)
        store(o,at+3,116)
        store(o,at+4,105)
        store(o,at+5,109)
        store(o,at+6,101)
        store(o,at+7,69)
        store(o,at+8,114)
        store(o,at+9,114)
        store(o,at+10,111)
        store(o,at+11,114)
        return 12
    return 0

def inherited_literal_2(o:mutbuf,at:u64,index:u64) -> u64:
    if index==4:
        store(o,at+0,84)
        store(o,at+1,121)
        store(o,at+2,112)
        store(o,at+3,101)
        store(o,at+4,69)
        store(o,at+5,114)
        store(o,at+6,114)
        store(o,at+7,111)
        store(o,at+8,114)
        return 9
    if index==5:
        store(o,at+0,70)
        store(o,at+1,117)
        store(o,at+2,116)
        store(o,at+3,117)
        store(o,at+4,114)
        store(o,at+5,101)
        store(o,at+6,32)
        store(o,at+7,105)
        store(o,at+8,110)
        store(o,at+9,32)
        store(o,at+10,117)
        store(o,at+11,110)
        store(o,at+12,101)
        store(o,at+13,120)
        store(o,at+14,112)
        store(o,at+15,101)
        store(o,at+16,99)
        store(o,at+17,116)
        store(o,at+18,101)
        store(o,at+19,100)
        store(o,at+20,32)
        store(o,at+21,115)
        store(o,at+22,116)
        store(o,at+23,97)
        store(o,at+24,116)
        store(o,at+25,101)
        return 26
    return 0

def inherited_literal_3(o:mutbuf,at:u64,index:u64) -> u64:
    if index==6:
        store(o,at+0,101)
        store(o,at+1,120)
        store(o,at+2,99)
        store(o,at+3,101)
        store(o,at+4,112)
        store(o,at+5,116)
        store(o,at+6,105)
        store(o,at+7,111)
        store(o,at+8,110)
        store(o,at+9,115)
        store(o,at+10,32)
        store(o,at+11,109)
        store(o,at+12,117)
        store(o,at+13,115)
        store(o,at+14,116)
        store(o,at+15,32)
        store(o,at+16,100)
        store(o,at+17,101)
        store(o,at+18,114)
        store(o,at+19,105)
        store(o,at+20,118)
        store(o,at+21,101)
        store(o,at+22,32)
        store(o,at+23,102)
        store(o,at+24,114)
        store(o,at+25,111)
        store(o,at+26,109)
        store(o,at+27,32)
        store(o,at+28,66)
        store(o,at+29,97)
        store(o,at+30,115)
        store(o,at+31,101)
        store(o,at+32,69)
        store(o,at+33,120)
        store(o,at+34,99)
        store(o,at+35,101)
        store(o,at+36,112)
        store(o,at+37,116)
        store(o,at+38,105)
        store(o,at+39,111)
        store(o,at+40,110)
        return 41
    if index==7:
        store(o,at+0,80)
        store(o,at+1,69)
        store(o,at+2,78)
        store(o,at+3,68)
        store(o,at+4,73)
        store(o,at+5,78)
        store(o,at+6,71)
        return 7
    return 0

def inherited_literal_4(o:mutbuf,at:u64,index:u64) -> u64:
    if index==8:
        store(o,at+0,82)
        store(o,at+1,85)
        store(o,at+2,78)
        store(o,at+3,78)
        store(o,at+4,73)
        store(o,at+5,78)
        store(o,at+6,71)
        return 7
    if index==9:
        store(o,at+0,67)
        store(o,at+1,65)
        store(o,at+2,78)
        store(o,at+3,67)
        store(o,at+4,69)
        store(o,at+5,76)
        store(o,at+6,76)
        store(o,at+7,69)
        store(o,at+8,68)
        return 9
    return 0

def inherited_literal_5(o:mutbuf,at:u64,index:u64) -> u64:
    if index==10:
        store(o,at+0,67)
        store(o,at+1,65)
        store(o,at+2,78)
        store(o,at+3,67)
        store(o,at+4,69)
        store(o,at+5,76)
        store(o,at+6,76)
        store(o,at+7,69)
        store(o,at+8,68)
        store(o,at+9,95)
        store(o,at+10,65)
        store(o,at+11,78)
        store(o,at+12,68)
        store(o,at+13,95)
        store(o,at+14,78)
        store(o,at+15,79)
        store(o,at+16,84)
        store(o,at+17,73)
        store(o,at+18,70)
        store(o,at+19,73)
        store(o,at+20,69)
        store(o,at+21,68)
        return 22
    if index==11:
        store(o,at+0,70)
        store(o,at+1,73)
        store(o,at+2,78)
        store(o,at+3,73)
        store(o,at+4,83)
        store(o,at+5,72)
        store(o,at+6,69)
        store(o,at+7,68)
        return 8
    return 0

def inherited_literal_6(o:mutbuf,at:u64,index:u64) -> u64:
    if index==12:
        store(o,at+0,58)
        store(o,at+1,32)
        store(o,at+2,60)
        store(o,at+3,95)
        store(o,at+4,79)
        store(o,at+5,112)
        store(o,at+6,116)
        store(o,at+7,105)
        store(o,at+8,109)
        store(o,at+9,105)
        store(o,at+10,122)
        store(o,at+11,97)
        store(o,at+12,116)
        store(o,at+13,105)
        store(o,at+14,111)
        store(o,at+15,110)
        store(o,at+16,70)
        store(o,at+17,117)
        store(o,at+18,116)
        store(o,at+19,117)
        store(o,at+20,114)
        store(o,at+21,101)
        store(o,at+22,32)
        store(o,at+23,97)
        store(o,at+24,116)
        store(o,at+25,32)
        store(o,at+26,48)
        store(o,at+27,120)
        return 28
    if index==13:
        store(o,at+0,32)
        store(o,at+1,115)
        store(o,at+2,116)
        store(o,at+3,97)
        store(o,at+4,116)
        store(o,at+5,101)
        store(o,at+6,61)
        return 7
    return 0

def inherited_literal_7(o:mutbuf,at:u64,index:u64) -> u64:
    if index==14:
        store(o,at+0,99)
        store(o,at+1,97)
        store(o,at+2,110)
        store(o,at+3,99)
        store(o,at+4,101)
        store(o,at+5,108)
        store(o,at+6,108)
        store(o,at+7,101)
        store(o,at+8,100)
        return 9
    if index==15:
        store(o,at+0,102)
        store(o,at+1,105)
        store(o,at+2,110)
        store(o,at+3,105)
        store(o,at+4,115)
        store(o,at+5,104)
        store(o,at+6,101)
        store(o,at+7,100)
        return 8
    return 0

def inherited_literal_8(o:mutbuf,at:u64,index:u64) -> u64:
    if index==16:
        store(o,at+0,32)
        store(o,at+1,114)
        store(o,at+2,101)
        store(o,at+3,116)
        store(o,at+4,117)
        store(o,at+5,114)
        store(o,at+6,110)
        store(o,at+7,101)
        store(o,at+8,100)
        store(o,at+9,32)
        return 10
    if index==17:
        store(o,at+0,32)
        store(o,at+1,114)
        store(o,at+2,97)
        store(o,at+3,105)
        store(o,at+4,115)
        store(o,at+5,101)
        store(o,at+6,100)
        store(o,at+7,32)
        return 8
    return 0

def inherited_literal_9(o:mutbuf,at:u64,index:u64) -> u64:
    if index==18:
        store(o,at+0,78)
        store(o,at+1,111)
        store(o,at+2,110)
        store(o,at+3,101)
        store(o,at+4,84)
        store(o,at+5,121)
        store(o,at+6,112)
        store(o,at+7,101)
        return 8
    if index==19:
        store(o,at+0,98)
        store(o,at+1,111)
        store(o,at+2,111)
        store(o,at+3,108)
        return 4
    return 0

def inherited_literal_10(o:mutbuf,at:u64,index:u64) -> u64:
    if index==20:
        store(o,at+0,105)
        store(o,at+1,110)
        store(o,at+2,116)
        return 3
    if index==21:
        store(o,at+0,102)
        store(o,at+1,108)
        store(o,at+2,111)
        store(o,at+3,97)
        store(o,at+4,116)
        return 5
    return 0

def inherited_literal_11(o:mutbuf,at:u64,index:u64) -> u64:
    if index==22:
        store(o,at+0,115)
        store(o,at+1,116)
        store(o,at+2,114)
        return 3
    if index==23:
        store(o,at+0,108)
        store(o,at+1,105)
        store(o,at+2,115)
        store(o,at+3,116)
        return 4
    return 0

def inherited_literal_12(o:mutbuf,at:u64,index:u64) -> u64:
    if index==24:
        store(o,at+0,100)
        store(o,at+1,105)
        store(o,at+2,99)
        store(o,at+3,116)
        return 4
    if index==25:
        store(o,at+0,98)
        store(o,at+1,121)
        store(o,at+2,116)
        store(o,at+3,101)
        store(o,at+4,115)
        return 5
    return 0
'''


SOURCE+=r'''
def extended_begin(o:mutbuf,mode:u64,at:u64) -> u32:
    if get(o,X_PTR)!=0:
        return inherited_fail(o,107)
    zero(o,X_PTR,184)
    put(o,X_MODE,mode)
    put(o,X_AT,at)
    return system(o,1504,318,3,X_TAG0,16,0,0,0,0)

def extended_value(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase>=1600:
        return extended_retry(s,o,w,phase)
    if phase<1510:
        return extended_type(s,o,w,phase)
    if phase<1560:
        return extended_truth(s,o,w,phase)
    return extended_cleanup(s,o,w,phase)

def extended_type(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1504:
        if get(o,FEEDBACK)!=16 or (get(o,X_TAG0)==0 and get(o,X_TAG1)==0):
            return inherited_fail(o,103)
        return system(o,1500,9,0,0,4096,3,34,MAX,0)
    if phase==1500:
        ptr=get(o,FEEDBACK)
        if ptr==0 or ptr>=NEGATIVE:
            return inherited_fail(o,103)
        put(o,X_PTR,ptr)
        value_packet(o,36)
        put(o,RQ,managed_value_magic(o,VREQUEST3))
        within(o,RQ+24,get(o,X_AT),24)
        return value(o,w,1501)
    if phase==1501:
        if value_ok(o)==False or get(o,VP+16)!=10:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        within(o,X_CLASS,VP+24,24)
        if get(o,X_MODE)==1:
            return again(o,1510)
        value_packet(o,38)
        put(o,RQ,managed_value_magic(o,VREQUEST3))
        within(o,RQ+24,X_CLASS,24)
        return value(o,w,1502)
    if phase==1502:
        if value_ok(o)==False or get(o,VP+16)!=4:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        within(o,TYPE_CAP,VP+24,24)
        put(o,X_NAMED,1)
        return extended_drop(o,w,X_CLASS,1503)
    if phase==1503:
        value_packet(o,7)
        within(o,RQ+24,TYPE_CAP,24)
        return value(o,w,1125)
    return inherited_fail(o,107)

def extended_truth(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1510:
        value_packet(o,2)
        store(o,RQ+128,95)
        store(o,RQ+129,95)
        n=8
        if get(o,X_PROBE)==0:
            store(o,RQ+130,98)
            store(o,RQ+131,111)
            store(o,RQ+132,111)
            store(o,RQ+133,108)
            store(o,RQ+134,95)
            store(o,RQ+135,95)
        else:
            n=7
            store(o,RQ+130,108)
            store(o,RQ+131,101)
            store(o,RQ+132,110)
            store(o,RQ+133,95)
            store(o,RQ+134,95)
        put(o,RQ+96,n)
        put(o,RQ+104,4)
        return value_wide(o,w,1511,128+n,8192)
    if phase==1511:
        if value_ok(o)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        within(o,X_KEY,VP+24,24)
        value_packet(o,39)
        put(o,RQ,managed_value_magic(o,VREQUEST3))
        within(o,RQ+24,X_CLASS,24)
        within(o,RQ+48,X_KEY,24)
        return value(o,w,1512)
    if phase==1512:
        if get(o,FEEDBACK)!=0 or get(o,VP)!=VREPLY:
            return inherited_fail(o,107)
        status=value_local_status(o)
        if status==0:
            within(o,X_ATTR,VP+24,24)
            put(o,X_OVERRIDE,1)
        elif status!=3:
            return inherited_fail(o,choose(status==5,103,107))
        return extended_drop(o,w,X_KEY,1513)
    if phase==1513:
        # Actual captured callable dispatch is a separate unresolved protocol.
        # Never silently substitute default truth for an existing override.
        if get(o,X_OVERRIDE)!=0:
            return inherited_fail(o,107)
        if get(o,X_PROBE)==0:
            put(o,X_PROBE,1)
            return again(o,1510)
        value_packet(o,17)
        within(o,RQ+24,get(o,X_AT),24)
        return value(o,w,1514)
    if phase==1514:
        if get(o,FEEDBACK)!=0 or get(o,VP)!=VREPLY:
            return inherited_fail(o,107)
        status=value_local_status(o)
        if status==0:
            put(o,ETRUTH,choose(get(o,VP+48)!=0,1,0))
        elif status==2:
            put(o,ETRUTH,1)
        else:
            return inherited_fail(o,choose(status==5,103,107))
        put(o,X_CLEAN_NEXT,get(o,EAFTER))
        return again(o,1570)
    return inherited_fail(o,107)

def extended_drop(o:mutbuf,w:mutbuf,at:u64,next:u64) -> u32:
    put(o,X_DROP,at)
    put(o,X_NEXT,next)
    value_packet(o,29)
    put(o,RQ,managed_value_magic(o,VREQUEST2))
    within(o,RQ+24,at,24)
    return value(o,w,1560)

def extended_drop_valid(o:mutbuf) -> bool:
    if get(o,M_DEFER)!=0:
        return managed_drop_record(o,get(o,RQ+8)!=93)
    if get(o,FEEDBACK)!=0 or get(o,VP)!=VDROP_REPLY:
        return False
    pending=value_local_pending(o)
    known=get(o,VP+88)
    consumed=get(o,VP+96)
    if pending>1 or known>1 or consumed>1:
        return False
    at=16
    while at<80:
        if get(o,VP+at)!=0:
            return False
        at=at+8
    at=104
    while at<128:
        if get(o,VP+at)!=0:
            return False
        at=at+8
    status=value_local_status(o)
    if known==0:
        return status==11 and pending==0 and consumed==0
    if consumed!=0:
        return status==11 or (status==0 and pending==0)
    if status==1:
        return pending==0
    return status==6 or status==11

def extended_cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1560:
        if extended_drop_valid(o)==False:
            put(o,X_BAD,2)
            return inherited_fail(o,107)
        if get(o,VP+88)!=0 and get(o,VP+96)!=0:
            zero(o,get(o,X_DROP),24)
        if value_local_status(o)==0:
            return again(o,get(o,X_NEXT))
        put(o,X_BAD,choose(get(o,VP+88)==0,2,1))
        put(o,X_MAP_PENDING,value_local_pending(o))
        return inherited_fail(o,107)
    if phase==1570:
        if get(o,X_BAD)!=0:
            if get(o,HELD)!=0:
                return again(o,1580)
            return lock(o,1580)
        at=X_CLASS
        while at<=X_ATTR:
            if get(o,at)!=0:
                return extended_drop(o,w,at,1570)
            at=at+24
        if get(o,X_NAMED)!=0 and get(o,TYPE_CAP)!=0:
            return extended_drop(o,w,TYPE_CAP,1570)
        return system(o,1571,11,0,get(o,X_PTR),4096,0,0,0,0)
    if phase==1571:
        if get(o,FEEDBACK)!=0:
            put(o,X_BAD,4)
            put(o,X_MAP_PENDING,1)
            return lock(o,1580)
        put(o,X_PTR,0)
        put(o,X_NAMED,0)
        return again(o,get(o,X_CLEAN_NEXT))
    if phase==1580:
        return memory(o,1582,0,get(o,F),3,HEADER,256)
    if phase==1582:
        # Record identity is bound to the already authenticated Future registry,
        # its capability tags, this context address and a fresh 128-bit nonce.
        # w[200] is only a count. No context field becomes a raw record pointer.
        zero(o,RQ,256)
        put(o,RQ,X_MAGIC)
        put(o,RQ+8,get(o,X_BAD))
        put(o,RQ+16,get(o,X_DROP))
        put(o,RQ+24,get(o,X_PTR))
        within(o,RQ+32,X_CLASS,72)
        if get(o,X_NAMED)!=0:
            within(o,RQ+104,TYPE_CAP,24)
        put(o,RQ+128,get(o,WPTR))
        put(o,RQ+136,get(o,PID))
        put(o,RQ+144,get(o,X_MAP_PENDING))
        put(o,RQ+152,get(o,HEADER+200))
        put(o,RQ+160,get(o,X_TAG0))
        put(o,RQ+168,get(o,X_TAG1))
        put(o,RQ+176,get(o,F))
        within(o,RQ+184,HEADER+32,16)
        within(o,RQ+200,HEADER+208,24)
        put(o,RQ+224,4096)
        put(o,RQ+232,4)
        return memory(o,1581,3,RQ,0,get(o,X_PTR),256)
    if phase==1581:
        put(o,RQ,get(o,X_PTR))
        put(o,RQ+8,get(o,X_TAG0))
        put(o,RQ+16,get(o,X_TAG1))
        put(o,RQ+24,4096)
        return memory(o,1583,3,RQ,0,get(o,F)+200,32)
    if phase==1583:
        put(w,200,get(w,200)+1)
        put(o,X_PTR,0)
        zero(o,X_CLASS,72)
        if get(o,X_NAMED)!=0:
            zero(o,TYPE_CAP,24)
        put(o,X_NAMED,0)
        if get(o,RESULT_VALUE)!=0:
            within(o,DISCARD_VALUE,RESULT_VALUE,24)
            zero(o,RESULT_VALUE,24)
        put(o,CLEANUP_FAILED,1)
        put(o,ERROR,1)
        put(o,RKIND,107)
        return unlock(o,1400)
    return inherited_fail(o,107)
'''


SOURCE+=r'''
def extended_retry_fail(o:mutbuf) -> u32:
    put(o,X_PTR,0)
    put(o,X_NAMED,0)
    put(o,X_RECOVERY,2)
    put(o,CLEANUP_FAILED,1)
    return fail(o,1,107)

def extended_retry_valid(o:mutbuf,w:mutbuf) -> bool:
    if get(o,NODE)!=X_MAGIC or get(o,NODE+24)!=get(o,X_PTR):
        return False
    if get(o,NODE+128)!=get(o,WPTR) or get(o,NODE+136)!=get(o,PID):
        return False
    if get(o,NODE+160)!=get(o,X_TAG0) or get(o,NODE+168)!=get(o,X_TAG1):
        return False
    if get(o,NODE+176)!=get(o,F) or get(o,NODE+184)!=get(o,HEADER+32) or get(o,NODE+192)!=get(o,HEADER+40):
        return False
    if get(o,NODE+224)!=4096 or get(o,NODE+232)!=4 or get(o,NODE+240)!=0 or get(o,NODE+248)!=0:
        return False
    bad=get(o,NODE+8)
    if bad!=1 and bad!=2 and bad!=4:
        return False
    if get(o,NODE+144)>1:
        return False
    if get(o,NODE+152)==0:
        if get(o,NODE+200)!=0 or get(o,NODE+208)!=0 or get(o,NODE+216)!=0:
            return False
    else:
        if (get(o,NODE+152)&4095)!=0 or get(o,NODE+216)!=4096:
            return False
    at=32
    while at<128:
        if get(o,NODE+at)==0 and (get(o,NODE+at+8)!=0 or get(o,NODE+at+16)!=0):
            return False
        at=at+24
    return True

def extended_retry(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase<1610:
        return extended_retry_read(s,o,w,phase)
    if phase<1620:
        return extended_retry_caps(s,o,w,phase)
    return extended_retry_mapping(s,o,w,phase)

def extended_retry_read(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1600:
        if get(o,OP)!=20 or get(o,HELD)!=1 or get(o,ACTIVE)!=1 or get(w,200)==0:
            return extended_retry_fail(o)
        if get(o,HEADER)!=OBJECT or get(o,HEADER+8)!=get(o,PID):
            return extended_retry_fail(o)
        ptr=get(o,HEADER+200)
        if ptr==0 or (ptr&4095)!=0 or ptr>MAX-4096 or get(o,HEADER+224)!=4096:
            return extended_retry_fail(o)
        put(o,X_PTR,ptr)
        put(o,X_TAG0,get(o,HEADER+208))
        put(o,X_TAG1,get(o,HEADER+216))
        if get(o,X_TAG0)==0 and get(o,X_TAG1)==0:
            return extended_retry_fail(o)
        put(o,X_RECOVERY,1)
        return address(o,1601,NODE)
    if phase==1601:
        # A bounded kernel copy cannot dereference a forged/unmapped pointer.
        # The independent registry nonce/extent is checked before any write,
        # cap retirement or munmap can use the captured allocation address.
        put(o,RQ,get(o,FEEDBACK))
        put(o,RQ+8,256)
        put(o,RQ+16,get(o,X_PTR))
        put(o,RQ+24,256)
        return system(o,1602,310,204,get(o,PID),RQ,1,RQ+16,1,0)
    if phase==1602:
        if get(o,FEEDBACK)!=256 or extended_retry_valid(o,w)==False:
            return extended_retry_fail(o)
        put(o,X_DROP,NODE+32)
        return again(o,1610)
    return extended_retry_fail(o)

def extended_retry_caps(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1610:
        at=get(o,X_DROP)
        if at>=NODE+128:
            return again(o,1620)
        if get(o,at)==0:
            put(o,X_DROP,at+24)
            return again(o,1610)
        value_packet(o,7)
        within(o,RQ+24,at,24)
        return value(o,w,1611)
    if phase==1611:
        if get(o,FEEDBACK)!=0 or get(o,VP)!=VREPLY:
            return extended_retry_fail(o)
        if value_local_status(o)==1:
            value_packet(o,31)
            put(o,RQ,managed_value_magic(o,VREQUEST2))
            return value(o,w,1614)
        if value_local_status(o)!=0:
            return extended_retry_fail(o)
        value_packet(o,29)
        put(o,RQ,managed_value_magic(o,VREQUEST2))
        within(o,RQ+24,get(o,X_DROP),24)
        return value(o,w,1612)
    if phase==1612:
        if extended_drop_valid(o)==False:
            return extended_retry_fail(o)
        if get(o,VP+88)!=0 and get(o,VP+96)!=0:
            zero(o,get(o,X_DROP),24)
        put(o,X_MODE,choose(value_local_status(o)==0,1,0))
        put(o,NODE+8,choose(get(o,VP+88)==0,2,1))
        put(o,NODE+144,value_local_pending(o))
        return memory(o,1613,3,NODE,0,get(o,X_PTR),256)
    if phase==1614:
        # Absence of this exact ticket is independent of mapping retirement.
        # The active-context refusal to retry confirms pending==0 separately;
        # it is never reported as destruction of the live Value context.
        if extended_drop_valid(o)==False or value_local_status(o)!=6 or value_local_pending(o)!=0 or get(o,VP+88)!=1 or get(o,VP+96)!=0:
            return extended_retry_fail(o)
        zero(o,get(o,X_DROP),24)
        put(o,X_MODE,1)
        return memory(o,1613,3,NODE,0,get(o,X_PTR),256)
    if phase==1613:
        if get(o,X_MODE)!=1:
            return extended_retry_fail(o)
        put(o,X_DROP,get(o,X_DROP)+24)
        return again(o,1610)
    return extended_retry_fail(o)

def extended_retry_mapping(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1620:
        value_packet(o,31)
        put(o,RQ,managed_value_magic(o,VREQUEST2))
        return value(o,w,1621)
    if phase==1621:
        if extended_drop_valid(o)==False or value_local_status(o)!=6 or value_local_pending(o)!=0 or get(o,VP+88)!=1 or get(o,VP+96)!=0 or get(w,200)==0:
            return extended_retry_fail(o)
        return system(o,1622,11,0,get(o,X_PTR),4096,0,0,0,0)
    if phase==1622:
        if get(o,FEEDBACK)!=0:
            return extended_retry_fail(o)
        put(o,RQ,get(o,NODE+152))
        within(o,RQ+8,NODE+200,24)
        return memory(o,1623,3,RQ,0,get(o,F)+200,32)
    if phase==1623:
        put(w,200,get(w,200)-1)
        put(o,X_PTR,0)
        put(o,X_RECOVERY,0)
        return memory(o,1630,0,get(o,F),3,HEADER,256)
    if phase==1630:
        return again(o,27)
    return extended_retry_fail(o)
'''

MANAGED_SOURCE=r'''
def managed_value_magic(o:mutbuf,ordinary:u64) -> u64:
    if get(o,M_DEFER)==0:
        return ordinary
    op=get(o,RQ+8)
    if op==78 or op==91 or op==92 or op==93:
        return VREQUEST5
    return VREQUEST6

def value_local_pending(o:mutbuf) -> u64:
    if get(o,M_DEFER)!=0 and get(o,VP)==VREPLY2 and get(o,VP+120)==1:
        return get(o,VP+104)
    return get(o,VP+80)

def value_local_status(o:mutbuf) -> u64:
    status=get(o,VP+8)
    if get(o,M_DEFER)!=0 and get(o,VP+120)==1:
        if get(o,VP+88)==1 and get(o,VP+96)==1 and get(o,VP+104)==0 and get(o,VP+112)==1 and status==11:
            return 0
    return status

def managed_retain_ok(o:mutbuf) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,VP)!=VREPLY or get(o,VP+88)!=1 or get(o,VP+96)!=1 or get(o,VP+120)!=1:
        return False
    if get(o,VP+80)>1 or get(o,VP+104)>1 or get(o,VP+112)>1:
        return False
    if get(o,VP+112)!=0:
        put(o,M_QUEUE,1)
    if get(o,VP+104)!=0:
        put(o,M_UNMAP,1)
    return True

def managed_drop_record(o:mutbuf,allow_consumed:bool) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,VP)!=VREPLY2 or get(o,VP+88)!=1 or get(o,VP+120)!=1:
        put(o,M_BAD,1)
        return False
    consumed=get(o,VP+96)
    mapping=get(o,VP+104)
    queued=get(o,VP+112)
    pending=get(o,VP+80)
    status=get(o,VP+8)
    if consumed>1 or mapping>1 or queued>1 or pending>1:
        put(o,M_BAD,1)
        return False
    if pending!=choose(mapping!=0 or queued!=0,1,0):
        put(o,M_BAD,1)
        return False
    if allow_consumed==False and consumed!=0:
        put(o,M_BAD,1)
        return False
    if consumed!=0 and status!=0 and status!=11:
        put(o,M_BAD,1)
        return False
    if status!=0 and status!=1 and status!=6 and status!=11:
        put(o,M_BAD,1)
        return False
    if status==0 and allow_consumed and consumed==0:
        put(o,M_BAD,1)
        return False
    at=16
    while at<80:
        if get(o,VP+at)!=0:
            put(o,M_BAD,1)
            return False
        at=at+8
    put(o,VD_CONSUMED,consumed)
    put(o,VD_PENDING,mapping)
    put(o,VD_STATUS,status)
    if queued!=0:
        put(o,M_QUEUE,1)
        if mapping==0 and status==11:
            put(o,VD_STATUS,0)
    if mapping!=0:
        put(o,M_UNMAP,1)
    return True

def managed_cell_ok(o:mutbuf) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,FP)!=FREPLY3:
        put(o,M_BAD,1)
        return False
    if get(o,FP+160)>1 or get(o,FP+168)>1:
        put(o,M_BAD,1)
        return False
    if get(o,FP+160)!=0:
        put(o,M_QUEUE,1)
    if get(o,FP+168)!=0:
        put(o,M_UNMAP,1)
    return get(o,FP+8)==0

'''
SOURCE+=MANAGED_SOURCE

def full_source_program():
 s=SOURCE
 for key,value in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+key+r'\b',str(value),s)
 return s

def reachable_source(source, entry):
 import ast
 tree=ast.parse(source); functions={n.name:n for n in tree.body}
 needed={entry}; pending=[entry]
 while pending:
  current=pending.pop()
  for n in ast.walk(functions[current]):
   if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in functions and n.func.id not in needed:
    needed.add(n.func.id); pending.append(n.func.id)
 selected=[functions[entry]]+[n for n in tree.body if n.name in needed and n.name!=entry]
 return ast.unparse(ast.Module(body=selected,type_ignores=[]))+'\n'

def source_program():
 # A fixed cleanup role resumes this same continuation in place.
 s=full_source_program()
 old='    if phase>=1700:\n        return guarded(s,o,w,phase)\n    if phase>=1500:\n        return extended_value(s,o,w,phase)\n'
 assert s.count(old)==1
 s=s.replace(old,'    if phase>=1500:\n        return 11\n')
 return reachable_source(s,'future_public')
def program():return document(source_program(),'background_optimizer_future_public_owner')
def main():
 d=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_future_public_owner.hepta';p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
