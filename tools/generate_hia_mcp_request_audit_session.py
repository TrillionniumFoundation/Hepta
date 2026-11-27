"""Native HIA daemon protocol, durable Unknown admission, and ticket completion."""
from tools.generate_hia_mcp_request_audit_common import authored
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    if phase < 10:
        return startup(o,w)
    if phase < 20:
        return receive(o,w)
    if phase < 100:
        return prepare(o,w)
    if phase < 200:
        return begin(o,w)
    if phase < 300:
        return complete(o,w)
    return session_error(w,1,0)

def startup(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    if phase == 0:
        put(w,ROOTFD,NONE)
        put(w,HOTFD,NONE)
        put(w,LEGACYFD,NONE)
        put(w,PIN11FD,NONE)
        put(w,SHARDROOTFD,NONE)
        put(w,PIN12FD,NONE)
        index = 0
        while index < 256:
            put(w,SHARD_FDS+index*8,NONE)
            index = index+1
        return call(o,w,1,107,0,0,0,0,0,0,0)
    if phase == 1:
        put(w,24,result)
        return call(o,w,2,39,0,0,0,0,0,0,0)
    if phase == 2:
        put(w,DAEMON_PID,result)
        return call(o,w,3,110,0,0,0,0,0,0,0)
    if phase == 3:
        put(w,DAEMON_CONTROLLER,result)
        return call(o,w,4,157,1,9,0,0,0,0,0)
    if phase == 4:
        if failed(result):
            return call(o,w,9,60,74,0,0,0,0,0,0)
        return call(o,w,5,110,0,0,0,0,0,0,0)
    if phase == 5:
        if result != get(w,DAEMON_CONTROLLER):
            return call(o,w,9,60,65,0,0,0,0,0,0)
        return enter(w,M_SESSION,10)
    return call(o,w,9,60,65,0,0,0,0,0,0)

def receive(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    if phase == 10:
        put(w,32,0)
        put(w,96,0)
        put(w,104,0)
        put(w,CURRENT_SLOT,NONE)
        put(w,CURRENT_GEN,0)
        put(w,CURRENT_WORKER,0)
        put(w,CURRENT_PHASE,0)
        put(w,ID_PRESENT,0)
        put(w,HOT_OWNED,0)
        put(w,QUERY_BYTES,0)
        return call(o,w,11,0,0,INPUT,4609,0,0,0,12)
    if phase == 11:
        if result == NEG4:
            return enter(w,M_SESSION,10)
        if result == 0:
            return call(o,w,19,60,0,0,0,0,0,0,0)
        if failed(result):
            return call(o,w,19,60,74,0,0,0,0,0,0)
        put(w,PACKET_SIZE,result)
        if result > 4608 or protocol(w) == False:
            return session_error(w,1,0)
        if get(w,CURRENT_PHASE) == 0:
            return enter(w,M_SESSION,20)
        if get(w,READY) != 1 or shared_ok(w) == False:
            return session_error(w,30,0)
        flock_bytes(w,271600,1,0)
        return call(o,w,12,72,get(w,DAEMON_AUDITFD),7,271600,0,0,0,48)
    if phase == 12:
        if result == NEG4:
            flock_bytes(w,271600,1,0)
            return call(o,w,12,72,get(w,DAEMON_AUDITFD),7,271600,0,0,0,48)
        if failed(result):
            return session_error(w,31,result)
        put(w,LOCKED,1)
        return procedure(w,M_LEASES,0,13,0,0,0,0,0,0,0,0)
    if phase == 13:
        if get(w,48) == NONE:
            return enter(w,M_RESPONSE,0)
        if get(w,STORE_POISONED) != 0:
            return session_error(w,36,0)
        if get(w,CURRENT_PHASE) == 1:
            return enter(w,M_SESSION,100)
        if get(w,CURRENT_PHASE) == 3:
            return enter(w,M_HISTORY,0)
        return enter(w,M_SESSION,200)
    return call(o,w,19,60,74,0,0,0,0,0,0)

def protocol(w:mutbuf) -> bool:
    size = get(w,PACKET_SIZE)
    if size >= 8 and get(w,INPUT) == HISTORY_MAGIC:
        put(w,CURRENT_PHASE,3)
        if size >= 72:
            put(w,CURRENT_SLOT,get(w,INPUT+48))
            put(w,CURRENT_GEN,get(w,INPUT+64))
            put(w,CURRENT_WORKER,get(w,INPUT+56))
        return history_protocol(w,size)
    if size == 128 and get(w,INPUT) == FINISH_MAGIC:
        if get(w,INPUT+8) != 1 or get(w,INPUT+16) != 2 or get(w,INPUT+24) != 128 or get(w,INPUT+32) > 2:
            return False
        put(w,CURRENT_PHASE,2)
        put(w,CURRENT_SLOT,get(w,INPUT+40))
        put(w,CURRENT_GEN,get(w,INPUT+48))
        put(w,CURRENT_WORKER,get(w,INPUT+56))
        return get(w,CURRENT_SLOT) < 32 and get(w,CURRENT_GEN) != 0 and get(w,CURRENT_WORKER) > 1 and lowerhex(w,INPUT+64,64)
    if size < 512 or get(w,INPUT) != BEGIN_MAGIC or get(w,INPUT+8) != 1 or get(w,INPUT+24) != size or get(w,INPUT+16) > 1:
        return False
    path = get(w,INPUT+80)
    if path == 0 or path > 4096 or size != 512+path or zeroes(w,INPUT+104,24) == False or zeroes(w,INPUT+320,192) == False:
        return False
    put(w,CURRENT_PHASE,get(w,INPUT+16))
    if get(w,CURRENT_PHASE) == 0:
        return get(w,READY) == 0 and get(w,INPUT+48) == NONE and get(w,INPUT+64) == 0 and get(w,INPUT+56) == get(w,DAEMON_CONTROLLER) and get(w,INPUT+72) == get(w,DAEMON_CONTROLLER) and get(w,INPUT+88) == 0 and get(w,INPUT+96) == 0 and zeroes(w,INPUT+128,192)
    put(w,CURRENT_SLOT,get(w,INPUT+48))
    put(w,CURRENT_GEN,get(w,INPUT+64))
    put(w,CURRENT_WORKER,get(w,INPUT+56))
    if get(w,CURRENT_SLOT) >= 32 or get(w,CURRENT_GEN) == 0 or get(w,CURRENT_WORKER) <= 1 or get(w,INPUT+72) != get(w,DAEMON_CONTROLLER):
        return False
    tool = get(w,INPUT+88)
    if lowerhex(w,INPUT+128,64) == False or valid_tool(w,INPUT+192,tool) == False or zeroes(w,INPUT+192+tool,64-tool) == False:
        return False
    target = get(w,INPUT+96)
    if target != 0 and target != 64:
        return False
    if target == 0 and zeroes(w,INPUT+256,64) == False:
        return False
    if target == 64 and lowerhex(w,INPUT+256,64) == False:
        return False
    return get(w,INPUT+32) == get(w,STATE_FD) and get(w,INPUT+40) == get(w,DAEMON_AUDITFD) and path == get(w,ROOT_PATH_LEN) and equal(w,INPUT+512,ROOT_PATH,path)

def history_protocol(w:mutbuf,size:u64) -> bool:
    if size < 512 or get(w,INPUT+8) != 1 or get(w,INPUT+16) != 3 or get(w,INPUT+24) != size:
        return False
    path = get(w,INPUT+80)
    if path == 0 or path > 4096 or size != 512+path or zeroes(w,INPUT+104,24) == False or zeroes(w,INPUT+256,256) == False:
        return False
    if get(w,CURRENT_SLOT) >= 32 or get(w,CURRENT_GEN) == 0 or get(w,CURRENT_WORKER) <= 1 or get(w,INPUT+72) != get(w,DAEMON_CONTROLLER):
        return False
    if get(w,INPUT+88) == 0 or get(w,INPUT+88) > 32 or lowerhex(w,INPUT+128,64) == False:
        return False
    cursor = get(w,INPUT+96)
    if cursor != 0 and cursor != 64:
        return False
    if cursor == 0 and zeroes(w,INPUT+192,64) == False:
        return False
    if cursor == 64 and lowerhex(w,INPUT+192,64) == False:
        return False
    return get(w,INPUT+32) == get(w,STATE_FD) and get(w,INPUT+40) == get(w,DAEMON_AUDITFD) and path == get(w,ROOT_PATH_LEN) and equal(w,INPUT+512,ROOT_PATH,path)

def shared_ok(w:mutbuf) -> bool:
    return get(w,SHARED+128) == SHARED_MAGIC and get(w,SHARED+136) == 1 and get(w,SHARED+144) == 2097152 and get(w,SHARED+152) == 32 and get(w,SHARED+160) == 512 and equal(w,SHARED+168,ROOT_STAMP,16) and get(w,SHARED+184) == get(w,DAEMON_CONTROLLER) and get(w,SHARED+224) == 1 and get(w,SHARED+232) == get(w,ROOT_PATH_LEN) and equal(w,SHARED+4096,ROOT_PATH,get(w,ROOT_PATH_LEN))

def prepare(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    if phase == 20:
        if get(w,INPUT+32) < 3 or get(w,INPUT+40) < 3:
            return session_error(w,1,0)
        put(w,STATE_FD,get(w,INPUT+32))
        put(w,DAEMON_AUDITFD,get(w,INPUT+40))
        put(w,ROOT_PATH_LEN,get(w,INPUT+80))
        copy_state(w,INPUT+512,ROOT_PATH,get(w,ROOT_PATH_LEN))
        return call(o,w,21,5,get(w,DAEMON_AUDITFD),272000,0,0,0,0,12)
    if phase == 21:
        if failed(result):
            return session_error(w,31,result)
        mode = getn(w,272024,4)
        if mode & 61440 != 32768 or mode & 4095 != 384 or getn(w,272028,4) != get(w,24) or get(w,272048) != 2097152:
            return session_error(w,30,0)
        return call(o,w,22,72,get(w,DAEMON_AUDITFD),1034,0,0,0,0,0)
    if phase == 22:
        if result != 7:
            return session_error(w,30,0)
        return call(o,w,23,9,SHARED,2097152,3,17,get(w,DAEMON_AUDITFD),0,3)
    if phase == 23:
        if failed(result):
            return session_error(w,31,result)
        if zeroes(w,SHARED+128,112) == False:
            return session_error(w,30,0)
        flock_bytes(w,271600,1,0)
        return call(o,w,24,72,get(w,DAEMON_AUDITFD),7,271600,0,0,0,48)
    if phase == 24:
        if result == NEG4:
            flock_bytes(w,271600,1,0)
            return call(o,w,24,72,get(w,DAEMON_AUDITFD),7,271600,0,0,0,48)
        if failed(result):
            return session_error(w,31,result)
        put(w,LOCKED,1)
        return procedure(w,M_OPEN,0,25,0,0,0,0,0,0,0,0)
    if phase == 25:
        if get(w,48) == NONE:
            return enter(w,M_RESPONSE,0)
        put(w,SHARED+128,SHARED_MAGIC)
        put(w,SHARED+136,1)
        put(w,SHARED+144,2097152)
        put(w,SHARED+152,32)
        put(w,SHARED+160,512)
        copy_state(w,ROOT_STAMP,SHARED+168,16)
        put(w,SHARED+184,get(w,DAEMON_CONTROLLER))
        put(w,SHARED+232,get(w,ROOT_PATH_LEN))
        copy_state(w,ROOT_PATH,SHARED+4096,get(w,ROOT_PATH_LEN))
        put(w,352,0)
        return step(w,26)
    if phase == 26:
        return call(o,w,27,318,SHARED+192+get(w,352),32-get(w,352),0,0,0,0,3)
    if phase == 27:
        if result == NEG4:
            return step(w,26)
        if failed(result) or result == 0 or result > 32-get(w,352):
            return session_error(w,31,result)
        put(w,352,get(w,352)+result)
        if get(w,352) < 32:
            return step(w,26)
        put(w,READY,1)
        put(w,SHARED+224,1)
        return enter(w,M_RESPONSE,0)
    return session_error(w,1,0)

def begin(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    ticket = TICKETS+get(w,CURRENT_SLOT)*512
    if phase == 100:
        if get(w,ticket) != 0:
            return session_error(w,29,0)
        return procedure(w,M_OPEN,0,101,0,0,0,0,0,0,0,0)
    if phase == 101:
        if get(w,48) == NONE:
            return enter(w,M_RESPONSE,0)
        return procedure(w,M_RETENTION,RETENTION_TARGET,102,0,0,0,0,0,0,0,0)
    if phase == 102:
        if get(w,48) == NONE:
            return enter(w,M_RESPONSE,0)
        return procedure(w,M_RETENTION,RETENTION_ADMIT,103,0,0,0,0,0,0,0,0)
    if phase == 103:
        if get(w,48) == NONE:
            return enter(w,M_RESPONSE,0)
        put(w,TICKET_HOT,get(w,48))
        fill_range(w,RECORD,256,0)
        put(w,352,0)
        return step(w,104)
    if phase == 104:
        return call(o,w,105,318,SESSION_ENTROPY+get(w,352),32-get(w,352),0,0,0,0,3)
    if phase == 105:
        if result == NEG4:
            return step(w,104)
        if failed(result) or result == 0 or result > 32-get(w,352):
            return session_error(w,31,result)
        put(w,352,get(w,352)+result)
        if get(w,352) < 32:
            return step(w,104)
        encode_hex(w,SESSION_ENTROPY,RECORD)
        copy_state(w,INPUT+128,RECORD+64,64)
        copy_state(w,INPUT+192,RECORD+128,get(w,INPUT+88))
        put(w,RECORD+192,get(w,INPUT+88))
        return call(o,w,106,228,0,SESSION_CLOCK,0,0,0,0,12)
    if phase == 106:
        if failed(result):
            return session_error(w,31,result)
        accepted_time(w)
        return procedure(w,M_ARCHIVE,ARCHIVE_SAVE,107,RECORD,1,0,0,0,0,0,0)
    if phase == 107:
        if get(w,48) == NONE:
            return enter(w,M_RESPONSE,0)
        if get(w,TICKET_HOT) != 0:
            return procedure(w,M_RECORDS,RECORD_WRITE,108,get(w,HOTFD),RECORD,RECORD,0,0,0,0,0)
        return step(w,108)
    if phase == 108:
        if get(w,48) == NONE:
            return enter(w,M_RESPONSE,0)
        return call(o,w,109,228,1,SESSION_CLOCK,0,0,0,0,12)
    if phase == 109:
        if failed(result):
            return session_error(w,31,result)
        put(w,START_SEC,get(w,SESSION_CLOCK))
        put(w,START_NSEC,get(w,SESSION_CLOCK+8))
        fill_range(w,ticket,512,0)
        put(w,ticket,1)
        put(w,ticket+8,get(w,CURRENT_WORKER))
        put(w,ticket+16,get(w,CURRENT_GEN))
        put(w,ticket+24,get(w,HOTFD))
        put(w,ticket+32,get(w,TICKET_HOT))
        put(w,ticket+40,get(w,START_SEC))
        put(w,ticket+48,get(w,START_NSEC))
        copy_state(w,RECORD,ticket+64,256)
        if get(w,INPUT+96) == 64:
            copy_state(w,INPUT+256,ticket+320,64)
            put(w,ticket+384,1)
        commit_shared(w,ticket)
        put(w,HOT_OWNED,0)
        put(w,ID_PRESENT,1)
        return enter(w,M_RESPONSE,0)
    return session_error(w,1,0)

def accepted_time(w:mutbuf) -> u64:
    seconds = get(w,SESSION_CLOCK)
    nanos = get(w,SESSION_CLOCK+8)
    if seconds >> 63 != 0:
        put(w,RECORD+208,0)
        put(w,RECORD+216,0)
        return 0
    lower = (seconds & 4294967295)*1000+nanos//1000000
    upper = (seconds >> 32)*1000+(lower >> 32)
    put(w,RECORD+208,(upper << 32)|(lower & 4294967295))
    put(w,RECORD+216,upper >> 32)
    return 0

def commit_shared(w:mutbuf,ticket:u64) -> u64:
    at = SHARED+65536+get(w,CURRENT_SLOT)*512
    fill_range(w,at,512,0)
    put(w,at,1)
    put(w,at+8,get(w,CURRENT_WORKER))
    put(w,at+16,get(w,CURRENT_GEN))
    put(w,at+24,get(w,TICKET_HOT))
    copy_state(w,RECORD,at+32,128)
    copy_state(w,ticket+320,at+160,64)
    copy_state(w,RECORD+128,at+224,64)
    put(w,at+288,get(w,RECORD+192))
    put(w,at+296,get(w,RECORD+208))
    put(w,at+304,get(w,RECORD+216))
    put(w,at+312,get(w,START_SEC))
    put(w,at+320,get(w,START_NSEC))
    put(w,at+328,get(w,ticket+384))
    return 0

def complete(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    ticket = TICKETS+get(w,CURRENT_SLOT)*512
    shared = SHARED+65536+get(w,CURRENT_SLOT)*512
    if phase == 200:
        if get(w,ticket) != 1 or get(w,ticket+8) != get(w,CURRENT_WORKER) or get(w,ticket+16) != get(w,CURRENT_GEN) or equal(w,ticket+64,INPUT+64,64) == False:
            return session_error(w,29,0)
        copy_state(w,ticket+64,RECORD,256)
        put(w,HOTFD,get(w,ticket+24))
        put(w,HOT_OWNED,1)
        put(w,TICKET_HOT,get(w,ticket+32))
        put(w,START_SEC,get(w,ticket+40))
        put(w,START_NSEC,get(w,ticket+48))
        put(w,ticket,0)
        put(w,shared,2)
        put(w,shared+328,0)
        put(w,ID_PRESENT,1)
        put(w,RECORD+200,get(w,INPUT+32))
        return call(o,w,201,228,1,SESSION_CLOCK,0,0,0,0,12)
    if phase == 201:
        if failed(result):
            return session_error(w,31,result)
        elapsed_time(w)
        return procedure(w,M_ARCHIVE,ARCHIVE_SAVE,202,RECORD,0,0,0,0,0,0,0)
    if phase == 202:
        if get(w,48) == NONE:
            return enter(w,M_RESPONSE,0)
        if get(w,TICKET_HOT) != 0:
            return procedure(w,M_RECORDS,RECORD_WRITE,203,get(w,HOTFD),RECORD,RECORD,1,0,0,0,0)
        return step(w,203)
    if phase == 203:
        if get(w,48) == NONE:
            return enter(w,M_RESPONSE,0)
        put(w,shared,3)
        put(w,shared+336,get(w,RECORD+200))
        put(w,shared+344,get(w,RECORD+232))
        return enter(w,M_RESPONSE,0)
    return session_error(w,1,0)

def elapsed_time(w:mutbuf) -> u64:
    seconds = get(w,SESSION_CLOCK)
    nanos = get(w,SESSION_CLOCK+8)
    start = get(w,START_SEC)
    sub = get(w,START_NSEC)
    value = 0
    if seconds > start or (seconds == start and nanos >= sub):
        seconds = seconds-start
        if nanos < sub:
            seconds = seconds-1
            nanos = nanos+1000000000
        nanos = (nanos-sub)//1000000
        if seconds > 18446744073709551 or (seconds == 18446744073709551 and nanos > 615):
            value = NONE
        else:
            value = seconds*1000+nanos
    put(w,RECORD+224,1)
    put(w,RECORD+232,value)
    return 0

def session_error(w:mutbuf,reason:u64,error:u64) -> u32:
    put(w,96,reason)
    put(w,104,error)
    return enter(w,M_RESPONSE,0)
'''
def source():
    return authored(SOURCE,extra={'BEGIN_MAGIC':int.from_bytes(b'HIAAUD01','little'),
        'FINISH_MAGIC':int.from_bytes(b'HIAAUF01','little'),
        'HISTORY_MAGIC':int.from_bytes(b'HIAAHQ01','little'),
        'SHARED_MAGIC':int.from_bytes(b'HIAAUS01','little')})
