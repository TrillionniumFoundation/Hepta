"""Locked, owned capture of actual native runtime snapshots and cleanup history.

This fixed continuation belongs to the runtime capsule. It takes no external
fact packet. Selection remains held while it borrows immutable number, proof
and generation bytes and flattens the complete frame for the pure renderer.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_runtime_effects as effects
ROOT=Path(__file__).resolve().parents[1]
C=dict(effects.C)
C.update({
 'SC':98304,'SC_MODE':98304,'SC_INDEX':98312,'SC_ROW':98320,'SC_ERROR':98328,
 'SC_DEPTH':98336,'SC_PIECES':98344,'SC_LENGTH':98352,'SC_SMALL':98360,
 'SC_FRAME':98368,'SC_FRAMEN':98376,'SC_OUTPUT':98384,'SC_OUTPUTN':98392,
 'SC_FLAT_INDEX':98400,'SC_FLAT_OFFSET':98408,'SC_EPOCH':98416,'SC_EPOCHN':98424,
 'SC_CURRENT':98432,'SC_CURRENTN':98440,'SC_ATTEMPTS':98448,'SC_ATTEMPTSN':98456,
 'SC_GCOUNT':98464,'SC_PCOUNT':98472,'SC_ECOUNT':98480,'SC_AINDEX':98488,
 'SC_ALLOCN':98496,'SC_AFTER':98504,'SC_RAW_TABLE':98512,'SC_RAW_START':98520,
 'SC_EV_INDEX':98528,'SC_TEMP_PTR':98536,'SC_TEMP_N':98544,'SC_OLD':98560,
 'SC_AFTER_COUNTER':98592,'SC_CLEANUP_KIND':98600,'SC_HISTORY_OLD':98608,
 'SC_GENS':104000,'SC_ALLOCATIONS':110000,'SC_STACK':100000,
 'SC_TABLE':131072,'SC_GROWS':2097152,'SC_EROWS':3145728,'SC_DIR':3211264,
 'SC_DIR_OLD':3227648,'SC_TEMP':14680064,'SC_WORK':16777216,
 'SMALL_START':4194304,'SMALL_END':12582912,'MAX_PIECES':65536,
 'SNAP_MAGIC':int.from_bytes(b'HIAMVSP1','little'),
 'INFO_REPLY':int.from_bytes(b'HIAMVIR2','little'),
 'PROOF_REPLY':int.from_bytes(b'HIAMVFR2','little'),
 'RETIRE_REQ':int.from_bytes(b'HIAMVRT3','little'),'RETIRE_REPLY':int.from_bytes(b'HIAMVTR3','little'),
 'RETENTION_STATE':int.from_bytes(b'HIAGST01','little'),
 'NODE_MAGIC':int.from_bytes(b'HIAMVUN1','little'),
 'COUNTER_REQ':int.from_bytes(b'HIAMVID2','little'),
})
LITERALS=["hepta.hia.scalar-multiversion.linux-x86_64.v1","OSError","NativeRetirementFailure","ValueError","0","retired_generation","preparation_failed","prepared_but_not_published","prepared_but_not_selected","native retirement rejected its bounded ABI","invalid native retirement transition receipt","native retirement state/token refused: ","native retirement effect receipt differs from its operation","native retirement receipt does not bind retained state","native retirement state is fenced; no effect retry permitted","path identity is acquired at most once","opened path identity differs from the original owned inode","{\"event\":\"publish\",\"generation\":","{\"event\":\"publish_if_current\",\"generation\":","{\"event\":\"rollback\",\"generation\":","{\"event\":\"retire\",\"generation\":",",\"epoch\":",",\"prepare_ns\":",",\"max_prepare_ns\":","}","{\"library_held\":",",\"native_descriptor\":",",\"native_task_attachment_confirmed\":","true","false","null","{\"stage\":",",\"kernel_result\":",",\"outcome\":\"not_entered\",\"close_retry_permitted\":false}",",\"outcome\":\"returned\",\"close_retry_permitted\":false}",",\"outcome\":\"unknown\",\"close_retry_permitted\":false}","{\"descriptor\":",",\"instance\":[","],\"acquisition_claim\":",",\"native_transition_confirmed\":",",\"close_retry_permitted\":false}",",","hepta.hia.scalar-multiversion-proved-total.linux-x86_64.v1"]
POLICY=r'''
def runtime_snapshot_capture(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUTPUT or length(w)<WORK or get(o,I_PUBLIC)!=1:
        return 4294967293
    phase=get(o,PHASE)
    if phase==1300 or phase==1500:
        zero(o,SC,32768)
        put(o,SC_MODE,choose(phase==1500,4,choose(get(o,OP)==10,1,2)))
        put(o,SC_SMALL,SMALL_START)
        if phase==1500:
            if get(o,SLOT)>=64 or get(o,GEN)==0:
                return capture_error(o,9)
            put(o,SC_INDEX,get(o,SLOT))
            return start_row(o,w,get(o,SLOT),get(o,GEN))
        put(o,SC_INDEX,0)
        return next_row(o,w)
    if phase>=1301 and phase<1370:
        return collect(s,o,w,phase)
    if phase>=1370 and phase<1400:
        return collect_roots(o,w,phase)
    if phase>=1400 and phase<1500:
        return flatten(o,w,phase)
    if phase>=1510 and phase<1550:
        return counters(o,w,phase)
    if phase>=1600 and phase<1700:
        return cleanup_capture(o,w,phase)
    if phase>=1700 and phase<1900:
        return dispose_capture(o,w,phase)
    return 4294967293

def start_row(o:mutbuf,w:mutbuf,slot:u64,pointer:u64) -> u32:
    row=SC_GROWS+slot*16384
    zero(o,row,16384)
    put(o,SC_ROW,row)
    put(o,row,pointer)
    put(o,row+96,get(w,COOR+512+slot*256))
    put(o,SC_GENS+get(o,SC_GCOUNT)*8,slot)
    put(o,SC_GCOUNT,get(o,SC_GCOUNT)+1)
    return memory(o,1301,0,pointer,3,row+256,256)

def next_row(o:mutbuf,w:mutbuf) -> u32:
    index=get(o,SC_INDEX)
    while index<64:
        flags=get(w,COOR+512+index*256)
        if (flags&6)!=0:
            pointer=get(w,SLOTS+index*16)
            if pointer==0:
                return capture_error(o,9)
            put(o,SC_INDEX,index)
            return start_row(o,w,index,pointer)
        index=index+1
    put(o,SC_INDEX,0)
    return identity_select(o,1370,64)

def collect(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    row=get(o,SC_ROW)
    go=row+256
    if phase==1301:
        if get(o,go)!=GOBJ or get(o,go+8)!=get(w,8) or get(o,go+32)==0:
            return capture_error(o,9)
        put(o,row+8,get(o,go+32))
        put(o,row+16,get(o,go+40))
        put(o,row+24,get(o,go+48))
        put(o,row+32,get(o,go+112)+96)
        put(o,row+40,get(o,go+104))
        put(o,row+64,get(o,go+168)+32)
        put(o,row+72,choose(get(o,go+176)>=32,get(o,go+176)-32,0))
        put(o,row+80,get(o,go+32)+352321536)
        put(o,row+104,get(o,go+248))
        return memory(o,1302,0,get(o,go+112),3,SC_TEMP,96)
    if phase==1302:
        if value_header(o,w,SC_TEMP,get(o,row+40))==0:
            return capture_error(o,9)
        zero(o,SC_TEMP,24)
        put(o,SC_TEMP,RETIRE_REQ)
        put(o,SC_TEMP+8,2)
        return role(o,1303,28,3,SC_TEMP,24,3,row+768,768,0,get(o,row+8),167772160)
    if phase==1303:
        if get(o,FEEDBACK)!=get(o,row+776) or get(o,row+768)!=RETIRE_REPLY or get(o,row+808)>4095:
            return capture_error(o,9)
        if get(o,row+776)!=0 and get(o,row+776)!=65:
            return capture_error(o,9)
        if get(o,row+1408)!=1:
            return capture_error(o,9)
        return memory(o,1304,0,get(o,row+8)+6291456,3,row+1536,4608)
    if phase==1304:
        within(o,row+1536,row+896,512)
        return memory(o,1305,0,get(o,row+8)+8192,3,row+6144,get(o,row+808))
    if phase==1305:
        return memory(o,1306,0,get(o,row+8)+6311936,3,row+10240,128)
    if phase==1306:
        return memory(o,1307,0,get(o,row+8),3,row+10368,2048)
    if phase==1307:
        put(o,row+192,get(o,row+864))
        put(o,row+208,choose(get(o,row+10472)!=0,2,0))
        put(o,row+216,get(o,row+10400))
        put(o,SC_AFTER_COUNTER,1320)
        return again(o,1510)
    if phase==1320:
        return after_counter(o,w)
    if phase==1308:
        if get(o,SC_TEMP)!=RETENTION_STATE or get(o,SC_TEMP+32)>get(o,row+24)-64:
            return capture_error(o,9)
        put(o,row+176,get(o,SC_TEMP+24))
        n=get(o,SC_TEMP+32)
        if n==0:
            ptr=literal(o,4)
            put(o,row+48,ptr)
            put(o,row+56,1)
            put(o,row+128,3)
            return after_number(o,w)
        if n>3074457345618258591:
            return capture_error(o,4)
        put(o,SC_TEMP_N,n)
        return allocate(o,1309,n*6+66)
    if phase==1309:
        ptr=get(o,FEEDBACK)
        if ptr==0:
            return capture_error(o,4)
        count=get(o,SC_ALLOCN)
        if count>=64:
            return capture_error(o,9)
        put(o,SC_ALLOCATIONS+count*8,ptr)
        put(o,SC_ALLOCN,count+1)
        put(o,row+48,ptr)
        n=get(o,SC_TEMP_N)
        put(o,SC_TEMP_PTR,ptr+n*3+1)
        return role(o,1310,29,0,get(o,row+16)+64,n,0,ptr,n*3+1,0,ptr+n*3+1,n*3+65)
    if phase==1310:
        if get(o,FEEDBACK)!=0:
            return capture_error(o,9)
        return memory(o,1311,0,get(o,SC_TEMP_PTR),3,SC_TEMP,16)
    if phase==1311:
        if get(o,SC_TEMP)==0 or get(o,SC_TEMP)>get(o,SC_TEMP_N)*3+1:
            return capture_error(o,9)
        put(o,row+56,get(o,SC_TEMP))
        put(o,row+128,0)
        return after_number(o,w)
    if phase==1312:
        if get(o,SC_TEMP)!=INFO_REPLY or get(o,SC_TEMP+8)!=0 or get(o,SC_TEMP+16)!=0 or get(o,SC_TEMP+24)!=get(o,row+72):
            return capture_error(o,9)
        return memory(o,1313,0,get(o,row+8)+524288240,3,row+88,8)
    if phase==1313:
        n=get(o,row+88)
        if n==0:
            put(o,row+136,0)
            return finish_row(o,w)
        if n<512 or n>16777216:
            return capture_error(o,9)
        return memory(o,1314,0,get(o,row+80),3,row+12416,512)
    if phase==1314:
        if get(o,row+12416)!=PROOF_REPLY or get(o,row+12424)!=0:
            return capture_error(o,9)
        count=get(o,row+12448)
        if count>16 or get(o,row+12480)!=get(o,row+88):
            return capture_error(o,9)
        put(o,row+136,count)
        put(o,row+144,512)
        put(o,row+152,0)
        return again(o,1315)
    if phase==1315:
        index=get(o,row+152)
        if index==get(o,row+136):
            if get(o,row+144)!=get(o,row+88):
                return capture_error(o,9)
            return finish_row(o,w)
        at=get(o,row+144)
        if at>get(o,row+88) or get(o,row+88)-at<8:
            return capture_error(o,9)
        return memory(o,1316,0,get(o,row+80)+at,3,SC_TEMP,8)
    if phase==1316:
        n=get(o,SC_TEMP)
        at=get(o,row+144)+8
        if n==0 or n>get(o,row+88)-at:
            return capture_error(o,9)
        index=get(o,row+152)
        put(o,row+13000+index*16,get(o,row+80)+at)
        put(o,row+13008+index*16,n)
        put(o,row+144,at+n)
        put(o,row+152,index+1)
        return again(o,1315)
    if phase==1330:
        if value_header(o,w,SC_TEMP,get(o,go+208))==0:
            return capture_error(o,9)
        put(o,row+112,get(o,go+216)+96)
        put(o,row+120,get(o,go+208))
        put(o,row+160,0)
        return after_counter_value(o,w)
    return capture_error(o,9)

def after_counter(o:mutbuf,w:mutbuf) -> u32:
    row=get(o,SC_ROW)
    go=row+256
    if get(o,go+184)!=0:
        return memory(o,1330,0,get(o,go+216),3,SC_TEMP,96)
    put(o,row+112,literal(o,4))
    put(o,row+120,1)
    put(o,row+160,3)
    return after_counter_value(o,w)

def after_counter_value(o:mutbuf,w:mutbuf) -> u32:
    row=get(o,SC_ROW)
    if (get(o,row+96)&2)!=0 and get(o,SC_MODE)!=4:
        if get(o,row+16)==0 or get(o,row+24)<65:
            return capture_error(o,9)
        return memory(o,1308,0,get(o,row+16),3,SC_TEMP,64)
    return after_number(o,w)

def after_number(o:mutbuf,w:mutbuf) -> u32:
    row=get(o,SC_ROW)
    if (get(o,row+96)&2)!=0 and get(o,SC_MODE)!=4:
        if get(o,row+72)==0:
            return capture_error(o,9)
        return memory(o,1312,0,get(o,row+64)-32,3,SC_TEMP,32)
    return finish_row(o,w)

def finish_row(o:mutbuf,w:mutbuf) -> u32:
    if get(o,SC_MODE)==4:
        start_packet(o,4)
        task_record(o,w,get(o,SC_ROW))
        return prepare_flatten(o,w)
    put(o,SC_INDEX,get(o,SC_INDEX)+1)
    return next_row(o,w)

def collect_roots(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1370:
        if identity_ok(o)==0:
            return capture_error(o,9)
        put(o,SC_EPOCH,get(o,IOUT+16)+96)
        put(o,SC_EPOCHN,get(o,IOUT+48))
        return memory(o,1371,0,get(o,IOUT+16),3,SC_TEMP,96)
    if phase==1371:
        if value_header(o,w,SC_TEMP,get(o,SC_EPOCHN))==0:
            return capture_error(o,9)
        current=get(w,COOR+48)
        if current<64:
            row=SC_GROWS+current*16384
            if get(o,row)==0:
                return capture_error(o,9)
            put(o,SC_CURRENT,get(o,row+32))
            put(o,SC_CURRENTN,get(o,row+40))
        return identity_select(o,1372,66)
    if phase==1372:
        if identity_ok(o)==0:
            return capture_error(o,9)
        put(o,SC_ATTEMPTS,get(o,IOUT+16)+96)
        put(o,SC_ATTEMPTSN,get(o,IOUT+48))
        return memory(o,1373,0,get(o,IOUT+16),3,SC_TEMP,96)
    if phase==1373:
        if value_header(o,w,SC_TEMP,get(o,SC_ATTEMPTSN))==0:
            return capture_error(o,9)
        dir_capture(o,w,SC_DIR,0)
        dir_capture(o,w,SC_DIR_OLD,1)
        if get(o,SC_MODE)!=1:
            return build_packet(o,w)
        count=get(w,IDENTITY+28680)
        if count>128:
            return capture_error(o,9)
        put(o,SC_ECOUNT,count)
        put(o,SC_EV_INDEX,0)
        return again(o,1374)
    if phase==1374:
        index=get(o,SC_EV_INDEX)
        count=get(o,SC_ECOUNT)
        if index==count:
            return build_packet(o,w)
        head=get(w,IDENTITY+28672)
        if head>=128:
            return capture_error(o,9)
        old=(head+128-count+index)&127
        row=SC_EROWS+index*128
        copy(o,row,w,IDENTITY+16384+old*96,96)
        put(o,SC_ROW,row)
        return memory(o,1375,0,get(o,row),3,SC_TEMP,96)
    if phase==1375 or phase==1377:
        row=get(o,SC_ROW)
        at=choose(phase==1375,0,32)
        if get(o,SC_TEMP)!=NODE_MAGIC or get(o,SC_TEMP+48)!=get(o,row+at+8) or get(o,SC_TEMP+56)!=get(o,row+at+16) or get(o,SC_TEMP+64)!=get(w,8):
            return capture_error(o,9)
        put(o,row+at,get(o,SC_TEMP+8)+96)
        return memory(o,choose(phase==1375,1376,1378),0,get(o,SC_TEMP+8),3,SC_TEMP,96)
    if phase==1376:
        row=get(o,SC_ROW)
        if value_header(o,w,SC_TEMP,get(o,row+24))==0:
            return capture_error(o,9)
        return memory(o,1377,0,get(o,row+32),3,SC_TEMP,96)
    if phase==1378:
        row=get(o,SC_ROW)
        if value_header(o,w,SC_TEMP,get(o,row+56))==0:
            return capture_error(o,9)
        put(o,SC_EV_INDEX,get(o,SC_EV_INDEX)+1)
        return again(o,1374)
    return capture_error(o,9)

def value_header(o:mutbuf,w:mutbuf,at:u64,n:u64) -> u64:
    if n==0 or n>NONE-96:
        return 0
    return choose(get(o,at)==VALUE_MAGIC and get(o,at+8)==get(w,8) and get(o,at+24)==n and get(o,at+16)>=96+n,1,0)

def identity_select(o:mutbuf,next:u64,selector:u64) -> u32:
    identity_request(o,7,selector)
    return identity_call(o,next)

def counter_request(o:mutbuf,op:u64) -> u64:
    identity_request(o,op,0)
    put(o,IREQ,COUNTER_REQ)
    return 0

def counters(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    row=get(o,SC_ROW)
    go=row+256
    if phase==1510:
        if get(o,SC_MODE)==4 and get(o,go+248)==0:
            cause=5
            if get(o,SUBOP)==1:
                cause=choose(get(o,go+152)==0,6,choose(get(o,OP)==1,7,8))
            put(o,go+248,cause)
            put(o,row+104,cause)
            return memory(o,1511,3,go+248,0,get(o,row)+248,8)
        return again(o,1511)
    if phase==1511:
        # The attested retirement ordinal is authoritative for completed
        # private attempts. Synchronize the independent unbounded public
        # decimal after a prior report-allocation failure, including reads.
        actual=get(o,row+1760)
        charged=get(o,go+136)
        if actual<charged or get(o,go+224)!=0:
            return capture_error(o,9)
        if actual==charged:
            return again(o,get(o,SC_AFTER_COUNTER))
        if get(o,go+184)==0:
            counter_request(o,14)
            return identity_call(o,1512)
        return again(o,1514)
    if phase==1512:
        if identity_ok(o)==0:
            return capture_error(o,choose(get(o,IOUT+8)==4,4,9))
        take_counter(o,go)
        return memory(o,1513,3,go+184,0,get(o,row)+184,40)
    if phase==1513:
        return again(o,1514)
    if phase==1514:
        counter_request(o,15)
        within(o,IREQ+24,go+184,24)
        return identity_call(o,1515)
    if phase==1515:
        if identity_ok(o)==0:
            return capture_error(o,choose(get(o,IOUT+8)==4,4,9))
        within(o,go+224,go+184,24)
        take_counter(o,go)
        return memory(o,1516,3,go+184,0,get(o,row)+184,64)
    if phase==1516:
        # Selection is still held. These two exact-field memory copies
        # contain no fallible allocation or callback between replacement
        # and recording which actual ordinal it accounts for.
        put(o,go+136,get(o,go+136)+1)
        return memory(o,1519,3,go+136,0,get(o,row)+136,8)
    if phase==1519:
        identity_request(o,8,0)
        within(o,IREQ+24,go+224,24)
        return identity_call(o,1517)
    if phase==1517:
        if identity_ok(o)==0:
            put(w,312,1)
            return capture_error(o,9)
        zero(o,go+224,24)
        return memory(o,1518,3,go+224,0,get(o,row)+224,24)
    if phase==1518:
        return again(o,1511)
    return capture_error(o,9)

def take_counter(o:mutbuf,go:u64) -> u64:
    within(o,go+184,IOUT+24,24)
    put(o,go+208,get(o,IOUT+48))
    put(o,go+216,get(o,IOUT+16))
    return 0

def start_packet(o:mutbuf,kind:u64) -> u64:
    put(o,SC_DEPTH,0)
    put(o,SC_PIECES,0)
    put(o,SC_LENGTH,0)
    at=small(o,64)
    zero(o,at,64)
    put(o,at,SNAP_MAGIC)
    put(o,at+8,kind)
    put(o,SC_TEMP_PTR,at)
    piece(o,3,at,64)
    return 0

def build_packet(o:mutbuf,w:mutbuf) -> u32:
    mode=get(o,SC_MODE)
    start_packet(o,mode)
    if mode==1:
        record(o,1,get(w,COOR+24),6)
        literal_field(o,choose(get(w,208)==1,42,0))
        field(o,0,get(o,SC_EPOCH),get(o,SC_EPOCHN))
        field(o,0,get(o,SC_CURRENT),get(o,SC_CURRENTN))
        count=0
        i=0
        while i<get(o,SC_GCOUNT):
            row=SC_GROWS+get(o,SC_GENS+i*8)*16384
            if (get(o,row+96)&2)!=0:
                count=count+1
            i=i+1
        record(o,9,0,count)
        i=0
        while i<get(o,SC_GCOUNT):
            row=SC_GROWS+get(o,SC_GENS+i*8)*16384
            if (get(o,row+96)&2)!=0:
                generation_record(o,w,row)
            i=i+1
        end_record(o)
        events_record(o)
    cleanup_record(o,w)
    if mode==1:
        end_record(o)
    return prepare_flatten(o,w)

def prepare_flatten(o:mutbuf,w:mutbuf) -> u32:
    if get(o,SC_ERROR)!=0 or get(o,SC_DEPTH)!=0 or get(o,SC_LENGTH)<64:
        return capture_error(o,9)
    put(o,get(o,SC_TEMP_PTR)+16,get(o,SC_LENGTH)-64)
    put(o,SC_FRAMEN,get(o,SC_LENGTH))
    return allocate(o,1400,get(o,SC_FRAMEN))

def flatten(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1400:
        pointer=get(o,FEEDBACK)
        if pointer==0:
            return capture_error(o,4)
        put(o,SC_FRAME,pointer)
        put(o,SC_FLAT_INDEX,0)
        put(o,SC_FLAT_OFFSET,0)
        return again(o,1401)
    if phase==1401:
        index=get(o,SC_FLAT_INDEX)
        if index==get(o,SC_PIECES):
            if get(o,SC_FLAT_OFFSET)!=get(o,SC_FRAMEN):
                return capture_error(o,9)
            zero(o,SC_WORK,66560)
            return role(o,1403,26,0,get(o,SC_FRAME),get(o,SC_FRAMEN),3,0,0,3,SC_WORK,66560)
        at=SC_TABLE+index*24
        return memory(o,1402,get(o,at),get(o,at+8),0,get(o,SC_FRAME)+get(o,SC_FLAT_OFFSET),get(o,at+16))
    if phase==1402:
        at=SC_TABLE+get(o,SC_FLAT_INDEX)*24
        put(o,SC_FLAT_OFFSET,get(o,SC_FLAT_OFFSET)+get(o,at+16))
        put(o,SC_FLAT_INDEX,get(o,SC_FLAT_INDEX)+1)
        return again(o,1401)
    if phase==1403:
        if get(o,FEEDBACK)!=4294967294 or get(o,SC_WORK)==0 or get(o,SC_WORK+48)!=0:
            put(o,NATIVE_ERROR,get(o,SC_WORK+24))
            return capture_error(o,9)
        put(o,SC_OUTPUTN,get(o,SC_WORK))
        return allocate(o,1404,get(o,SC_OUTPUTN))
    if phase==1404:
        if get(o,FEEDBACK)==0:
            return capture_error(o,4)
        put(o,SC_OUTPUT,get(o,FEEDBACK))
        return role(o,1405,26,0,get(o,SC_FRAME),get(o,SC_FRAMEN),0,get(o,SC_OUTPUT),get(o,SC_OUTPUTN),3,SC_WORK,66560)
    if phase==1405:
        if get(o,FEEDBACK)!=0 or get(o,SC_WORK)!=get(o,SC_OUTPUTN) or get(o,SC_WORK+48)!=0:
            return capture_error(o,9)
        if get(o,SC_MODE)==4:
            identity_request(o,12,0)
            return identity_call(o,1410)
        put(o,D_PTR,get(o,SC_OUTPUT))
        put(o,D_LEN,get(o,SC_OUTPUTN))
        put(o,SC_OUTPUT,0)
        put(o,SC_AFTER,1)
        return again(o,1600)
    if phase==1410:
        if identity_ok(o)==0:
            return capture_error(o,choose(get(o,IOUT+8)==4,4,9))
        head=get(w,SHHEAD)
        count=get(w,SHCOUNT)
        if head>=128 or count>128:
            return capture_error(o,9)
        at=SHISTORY+head*16
        put(o,SC_HISTORY_OLD,get(w,at))
        put(w,at,get(o,SC_OUTPUT))
        put(w,at+8,get(o,SC_OUTPUTN))
        put(o,SC_OUTPUT,0)
        put(w,SHHEAD,(head+1)&127)
        if count<128:
            put(w,SHCOUNT,count+1)
        if get(o,SC_HISTORY_OLD)!=0:
            return deallocate(o,1411,get(o,SC_HISTORY_OLD))
        return again(o,1411)
    if phase==1411:
        put(o,SC_AFTER,2)
        return again(o,1600)
    return capture_error(o,9)

def capture_error(o:mutbuf,error:u64) -> u32:
    put(o,SC_ERROR,error)
    put(o,SC_AFTER,3)
    return again(o,1600)

def cleanup_capture(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1600:
        if get(o,SC_FRAME)!=0:
            return deallocate(o,1601,get(o,SC_FRAME))
        return again(o,1601)
    if phase==1601:
        put(o,SC_FRAME,0)
        if get(o,SC_OUTPUT)!=0:
            return deallocate(o,1602,get(o,SC_OUTPUT))
        return again(o,1602)
    if phase==1602:
        put(o,SC_OUTPUT,0)
        put(o,SC_AINDEX,0)
        return again(o,1603)
    if phase==1603:
        index=get(o,SC_AINDEX)
        if index<get(o,SC_ALLOCN):
            put(o,SC_AINDEX,index+1)
            return deallocate(o,1603,get(o,SC_ALLOCATIONS+index*8))
        if get(o,SC_AFTER)==2:
            return again(o,344)
        if get(o,SC_AFTER)==1:
            return feedback(o,0)
        put(o,STATE_O+216,0)
        put(o,NATIVE_ERROR,get(o,SC_ERROR))
        return feedback(o,get(o,SC_ERROR))
    return 4294967293

def dispose_capture(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1700:
        put(o,SC_INDEX,0)
        return again(o,1701)
    if phase==1701:
        index=get(o,SC_INDEX)
        if index==128:
            put(w,SHHEAD,0)
            put(w,SHCOUNT,0)
            return again(o,933)
        at=SHISTORY+index*16
        pointer=get(w,at)
        put(w,at,0)
        put(w,at+8,0)
        put(o,SC_INDEX,index+1)
        if pointer!=0:
            return deallocate(o,1701,pointer)
        return again(o,1701)
    if phase==1800:
        at=choose(get(o,GO+224)!=0,224,184)
        put(o,SC_CLEANUP_KIND,at)
        identity_request(o,8,0)
        within(o,IREQ+24,GO+at,24)
        return identity_call(o,1801)
    if phase==1801:
        if identity_ok(o)==0:
            put(w,312,1)
            put(o,NATIVE_ERROR,9)
            return private_lock(o,2,264,get(o,AFTER_GEN))
        at=get(o,SC_CLEANUP_KIND)
        n=choose(at==184,40,24)
        zero(o,GO+at,n)
        return memory(o,1802,3,GO+at,0,get(o,GEN)+at,n)
    if phase==1802:
        return again(o,352)
    return 4294967293

def dir_capture(o:mutbuf,w:mutbuf,row:u64,old:u64) -> u64:
    zero(o,row,16384)
    meta=choose(old==1,DC_PIN_META,DC)
    state=choose(old==1,DC_PIN,DSTATE)
    copy(o,row+13312,w,meta,128)
    copy(o,row+1536,w,state,4608)
    if old==0 and get(w,DC_VALID)!=0:
        copy(o,row+1536,w,DC_ATTESTED,512)
    put(o,row+792,get(w,meta+16))
    put(o,row+808,get(w,224))
    put(o,row+824,get(w,meta+24))
    copy(o,row+6144,w,DIRECTORY,get(w,224))
    put(o,row+168,get(w,meta+24))
    put(o,row+176,get(w,meta+48))
    put(o,row+184,get(w,meta+56))
    put(o,row+192,get(w,meta+64))
    put(o,row+200,get(w,meta+88))
    put(o,row+208,get(w,meta+72))
    put(o,row+216,get(w,meta+80))
    return 0

def generation_record(o:mutbuf,w:mutbuf,row:u64) -> u64:
    record(o,8,choose(get(o,row+176)&1!=0,1,0),5)
    field(o,0,get(o,row+64),get(o,row+72))
    field(o,0,get(o,row+32),get(o,row+40))
    field(o,get(o,row+128),get(o,row+48),get(o,row+56))
    pin_record(o,row)
    record(o,10,0,get(o,row+136))
    i=0
    while i<get(o,row+136):
        field(o,0,get(o,row+13000+i*16),get(o,row+13008+i*16))
        i=i+1
    end_record(o)
    end_record(o)
    return 0

def cleanup_record(o:mutbuf,w:mutbuf) -> u64:
    count=get(w,COOR+128)
    if count>64:
        put(o,SC_ERROR,9)
        return 0
    record(o,2,get(w,COOR+24)+choose(get(w,COOR+80)==0,2,0),6)
    field(o,0,get(o,SC_ATTEMPTS),get(o,SC_ATTEMPTSN))
    record(o,9,0,count)
    i=0
    while i<count:
        slot=get(w,COOR+23552+i*8)
        if slot>=64:
            put(o,SC_ERROR,9)
            return 0
        row=SC_GROWS+slot*16384
        if get(o,row)==0 or (get(o,row+96)&4)==0:
            put(o,SC_ERROR,9)
            return 0
        task_record(o,w,row)
        i=i+1
    end_record(o)
    history_record(o,w)
    directory_record(o,w)
    observation(o,1,DC_OBS,SC_DIR,w)
    pin_record(o,SC_DIR)
    end_record(o)
    return 0

def history_record(o:mutbuf,w:mutbuf) -> u64:
    count=get(w,SHCOUNT)
    head=get(w,SHHEAD)
    if count>128 or head>=128:
        put(o,SC_ERROR,9)
        return 0
    record(o,10,0,count)
    i=0
    while i<count:
        index=(head+128-count+i)&127
        at=SHISTORY+index*16
        if get(w,at)==0 or get(w,at+8)==0:
            put(o,SC_ERROR,9)
            return 0
        field(o,0,get(w,at),get(w,at+8))
        i=i+1
    end_record(o)
    return 0

def events_record(o:mutbuf) -> u64:
    record(o,10,0,get(o,SC_ECOUNT))
    i=0
    while i<get(o,SC_ECOUNT):
        row=SC_EROWS+i*128
        kind=get(o,row+64)
        if kind<1 or kind>4:
            put(o,SC_ERROR,9)
            return 0
        raw_start(o)
        literal_piece(o,16+kind)
        piece(o,0,get(o,row),get(o,row+24))
        literal_piece(o,21)
        piece(o,0,get(o,row+32),get(o,row+56))
        if kind==2:
            literal_piece(o,22)
            number_piece(o,get(o,row+72))
            literal_piece(o,23)
            number_piece(o,get(o,row+80))
        literal_piece(o,24)
        raw_end(o)
        i=i+1
    end_record(o)
    return 0

def task_record(o:mutbuf,w:mutbuf,row:u64) -> u64:
    state=row+1536
    flags=get(o,row+792)
    record(o,4,flags|16,12)
    field(o,0,get(o,row+32),get(o,row+40))
    cause=get(o,row+104)
    if cause<5 or cause>8:
        put(o,SC_ERROR,9)
        return 0
    literal_field(o,cause)
    field(o,3,row+6144,get(o,row+808))
    field(o,3,state,4608)
    pin_record(o,row)
    field(o,get(o,row+160),get(o,row+112),get(o,row+120))
    if get(o,row+840)!=0:
        if get(o,row+1512)!=1 or get(o,row+1504)>4096:
            put(o,SC_ERROR,9)
            return 0
        record(o,7,0,3)
        literal_field(o,1)
        field(o,3,0,0)
        field(o,0,get(o,row+8)+6307840,get(o,row+1504))
        end_record(o)
    else:
        field(o,3,0,0)
    os_error(o,get(o,row+848),0,row)
    if get(o,row+10296)!=0:
        observation(o,3,row+10240,row,w)
    else:
        field(o,3,0,0)
    if get(o,state+232)==5:
        os_error(o,get(o,row+856),1,row)
    else:
        field(o,3,0,0)
    if get(o,row+824)!=0:
        raw_start(o)
        literal_piece(o,25)
        literal_piece(o,choose(get(o,row+10424)!=0,28,29))
        literal_piece(o,26)
        if get(o,state+160)!=0:
            number_piece(o,get(o,state+168))
        else:
            literal_piece(o,30)
        literal_piece(o,27)
        literal_piece(o,choose(get(o,state+120)!=0,28,29))
        literal_piece(o,24)
        raw_end(o)
    else:
        field(o,3,0,0)
    field(o,3,state+136,choose(get(o,state+128)!=0,16,0))
    end_record(o)
    return 0

def pin_record(o:mutbuf,row:u64) -> u64:
    record(o,3,get(o,row+792)|16,7)
    field(o,3,row+6144,get(o,row+808))
    field(o,3,row+1536,4608)
    if get(o,row+200)==3 or get(o,row+200)==5:
        ordinary_error(o,3,choose(get(o,row+200)==3,15,16))
    else:
        os_error(o,get(o,row+184),choose(get(o,row+208)==1,1,0),row)
    os_error(o,get(o,row+192),0,row)
    policy_error(o,row)
    if get(o,row+824)!=0 and get(o,row+208)==2 and get(o,row+216)<NEGATIVE:
        raw_start(o)
        literal_piece(o,36)
        number_piece(o,get(o,row+216))
        literal_piece(o,37)
        number_piece(o,get(o,row+1536+440))
        literal_piece(o,41)
        number_piece(o,get(o,row+1536+448))
        literal_piece(o,38)
        number_piece(o,get(o,row+1536+104))
        literal_piece(o,39)
        literal_piece(o,choose(get(o,row+1536+40)!=0,28,29))
        literal_piece(o,40)
        raw_end(o)
    else:
        field(o,3,0,0)
    if get(o,row+824)!=0:
        raw_start(o)
        literal_piece(o,31)
        number_piece(o,get(o,row+208))
        literal_piece(o,32)
        if get(o,row+208)==2:
            signed_piece(o,get(o,row+216))
        else:
            literal_piece(o,30)
        literal_piece(o,choose(get(o,row+208)==0,33,choose(get(o,row+208)==2,34,35)))
        raw_end(o)
    else:
        field(o,3,0,0)
    end_record(o)
    return 0

def policy_error(o:mutbuf,row:u64) -> u64:
    if get(o,row+824)==0:
        return field(o,3,0,0)
    reason=get(o,row+168)
    code=get(o,row+176)
    if reason==0:
        returned=get(o,row+1416)
        code=get(o,row+1448)
        if returned!=64:
            reason=1
        elif get(o,row+1440)!=DREP or code>7 or get(o,row+1456)>8 or get(o,row+1480)>15 or get(o,row+1496)>6:
            reason=2
        elif code!=0:
            reason=3
        elif get(o,row+1464)==0 and get(o,row+1456)>0 and get(o,row+1456)<8:
            reason=4
        else:
            reason=5
    record(o,7,0,3)
    literal_field(o,2)
    field(o,3,0,0)
    if reason==3:
        raw_start(o)
        literal_piece(o,11)
        number_piece(o,code)
        raw_end(o)
    else:
        literal_field(o,choose(reason==1,9,choose(reason==2,10,choose(reason==4,12,13))))
    end_record(o)
    return 0

def ordinary_error(o:mutbuf,type:u64,message:u64) -> u64:
    record(o,7,0,3)
    literal_field(o,type)
    field(o,3,0,0)
    literal_field(o,message)
    end_record(o)
    return 0

def os_error(o:mutbuf,raw:u64,filename:u64,row:u64) -> u64:
    if raw==0:
        return field(o,3,0,0)
    if raw<NEGATIVE:
        put(o,SC_ERROR,9)
        return 0
    record(o,12,filename,2)
    number_field(o,0-raw)
    field(o,3,row+6144,choose(filename!=0,get(o,row+808),0))
    end_record(o)
    return 0

def observation(o:mutbuf,kind:u64,at:u64,row:u64,w:mutbuf) -> u64:
    source=at
    if kind==1:
        source=small(o,128)
        copy(o,source,w,at,128)
    status=get(o,source)
    record(o,5,status|16,4)
    field(o,3,row+6144,get(o,row+808))
    number_field(o,get(o,source+8))
    field(o,3,source+24,choose(get(o,source+16)!=0,16,0))
    if get(o,source+56)!=0 and kind==1:
        policy_error(o,row)
    else:
        os_error(o,get(o,source+40),get(o,source+48),row)
    end_record(o)
    return 0

def directory_record(o:mutbuf,w:mutbuf) -> u64:
    status=get(w,DC_STATUS)
    record(o,6,status|16,6)
    if status==0:
        i=0
        while i<6:
            field(o,3,0,0)
            i=i+1
    else:
        field(o,3,SC_DIR_OLD+6144,get(o,SC_DIR_OLD+808))
        number_field(o,get(w,DC_TIME))
        observation(o,1,DC_BEFORE,SC_DIR_OLD,w)
        observation(o,1,DC_AFTER,SC_DIR_OLD,w)
        pin_record(o,SC_DIR_OLD)
        os_error(o,get(w,DC_ERROR),1,SC_DIR_OLD)
    end_record(o)
    return 0

def small(o:mutbuf,n:u64) -> u64:
    at=get(o,SC_SMALL)
    if at<SMALL_START or at>SMALL_END or n>SMALL_END-at:
        put(o,SC_ERROR,9)
        return 0
    put(o,SC_SMALL,at+n)
    return at

def piece(o:mutbuf,kind:u64,at:u64,n:u64) -> u64:
    if get(o,SC_ERROR)!=0:
        return 0
    if n==0:
        return 1
    size=get(o,SC_LENGTH)
    count=get(o,SC_PIECES)
    if kind>3 or n>NONE-size or count>=MAX_PIECES:
        put(o,SC_ERROR,9)
        return 0
    row=SC_TABLE+count*24
    put(o,row,kind)
    put(o,row+8,at)
    put(o,row+16,n)
    put(o,SC_LENGTH,size+n)
    put(o,SC_PIECES,count+1)
    return 1

def field_begin(o:mutbuf) -> u64:
    depth=get(o,SC_DEPTH)
    if get(o,SC_ERROR)!=0:
        return 0
    if depth==0 or depth>32:
        put(o,SC_ERROR,9)
        return 0
    top=SC_STACK+(depth-1)*32
    head=get(o,top)
    used=get(o,top+16)
    if used>=get(o,head+16):
        put(o,SC_ERROR,9)
        return 0
    item=head+32+used*16
    put(o,item,get(o,SC_LENGTH)-get(o,top+8))
    put(o,top+16,used+1)
    return item

def record(o:mutbuf,kind:u64,flags:u64,count:u64) -> u64:
    if get(o,SC_ERROR)!=0:
        return 0
    depth=get(o,SC_DEPTH)
    if depth>=32 or count>65536:
        put(o,SC_ERROR,9)
        return 0
    parent=0
    if depth!=0:
        parent=field_begin(o)
    header=small(o,32+count*16)
    if header==0:
        return 0
    zero(o,header,32+count*16)
    put(o,header,kind)
    put(o,header+8,flags)
    put(o,header+16,count)
    top=SC_STACK+depth*32
    put(o,top,header)
    put(o,top+8,get(o,SC_LENGTH))
    put(o,top+16,0)
    put(o,top+24,parent)
    put(o,SC_DEPTH,depth+1)
    return piece(o,3,header,32+count*16)

def end_record(o:mutbuf) -> u64:
    if get(o,SC_ERROR)!=0:
        return 0
    depth=get(o,SC_DEPTH)
    if depth==0 or depth>32:
        put(o,SC_ERROR,9)
        return 0
    top=SC_STACK+(depth-1)*32
    head=get(o,top)
    if get(o,top+16)!=get(o,head+16):
        put(o,SC_ERROR,9)
        return 0
    n=get(o,SC_LENGTH)-get(o,top+8)
    put(o,head+24,n)
    if get(o,top+24)!=0:
        put(o,get(o,top+24)+8,n)
    put(o,SC_DEPTH,depth-1)
    return 1

def field(o:mutbuf,kind:u64,at:u64,n:u64) -> u64:
    item=field_begin(o)
    if item==0:
        return 0
    put(o,item+8,n)
    return piece(o,kind,at,n)

def raw_start(o:mutbuf) -> u64:
    put(o,SC_RAW_TABLE,field_begin(o))
    put(o,SC_RAW_START,get(o,SC_LENGTH))
    return 0

def raw_end(o:mutbuf) -> u64:
    if get(o,SC_ERROR)!=0:
        return 0
    put(o,get(o,SC_RAW_TABLE)+8,get(o,SC_LENGTH)-get(o,SC_RAW_START))
    return 0

def number(o:mutbuf,value:u64) -> u64:
    n=1
    a=value
    while a>=10:
        a=divide10(a)
        n=n+1
    at=small(o,n)
    if at==0:
        return 0
    i=n
    while i>0:
        i=i-1
        store(o,at+i,48+value-divide10(value)*10)
        value=divide10(value)
    return at

def number_size(value:u64) -> u64:
    n=1
    while value>=10:
        value=divide10(value)
        n=n+1
    return n

def number_field(o:mutbuf,value:u64) -> u64:
    return field(o,3,number(o,value),number_size(value))

def number_piece(o:mutbuf,value:u64) -> u64:
    return piece(o,3,number(o,value),number_size(value))

def signed_piece(o:mutbuf,value:u64) -> u64:
    if value>=9223372036854775808:
        at=small(o,1)
        if at==0:
            return 0
        store(o,at,45)
        piece(o,3,at,1)
        return number_piece(o,0-value)
    return number_piece(o,value)

def literal_field(o:mutbuf,index:u64) -> u64:
    return field(o,3,literal(o,index),literal_size(index))

def literal_piece(o:mutbuf,index:u64) -> u64:
    return piece(o,3,literal(o,index),literal_size(index))

def divide10(value:u64) -> u64:
    q=(value>>1)+(value>>2)
    q=q+(q>>4)
    q=q+(q>>8)
    q=q+(q>>16)
    q=q+(q>>32)
    q=q>>3
    r=value-q*10
    if r>=10:
        q=q+1
    return q

'''

HELPERS=('role','memory','system','allocate','deallocate','again','word','get','put','copy','within','copy_input','zero','choose','narrow','identity_request','identity_call','identity_ok','feedback','state_step','private_lock','local_lock','atomic')
def source_program():
 s=POLICY
 s+='\ndef literal(o:mutbuf,index:u64) -> u64:\n    n=literal_size(index)\n    at=small(o,n)\n    if at==0:\n        return 0\n'
 for index,text in enumerate(LITERALS):
  data=text.encode('utf8')
  s+='    if index=='+str(index)+':\n'
  for at in range(0,len(data),8):
   part=data[at:at+8]
   if len(part)==8:s+='        put(o,at+'+str(at)+','+str(int.from_bytes(part,'little'))+')\n'
   else:
    for k,v in enumerate(part):s+='        store(o,at+'+str(at+k)+','+str(v)+')\n'
  s+='        return at\n'
 s+='    put(o,SC_ERROR,9)\n    return 0\n\ndef literal_size(index:u64) -> u64:\n'
 for index,text in enumerate(LITERALS):
  s+='    if index=='+str(index)+':\n        return '+str(len(text.encode('utf8')))+'\n'
 s+='    return 0\n'
 for name in HELPERS:
  m=re.search(r'^def '+name+r'\(.*?(?=^def |\Z)',effects.SOURCE,re.M|re.S)
  assert m,name
  s+='\n'+m.group(0)
 for k,v in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+k+r'\b',str(v),s)
 return s
def main():
 t=document(source_program(),'multiversion_runtime_snapshot_capture')
 p=ROOT/'examples/hia_bootstrap/multiversion_runtime_snapshot_capture.hepta'
 p.write_text(render_assembly(t))
 print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),sum(len(b['ops']) for f in t['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
