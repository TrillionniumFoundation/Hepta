"""Kernel-backed worker lifetime and retained ticket custody in HIA."""
from tools.generate_hia_mcp_request_audit_common import authored
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    if phase == 0:
        save(w,0,0)
        put(w,ACTIVECOUNT,0)
        return step(w,1)
    if phase == 1:
        index = local(w,0)
        if index == 32:
            if get(w,CURRENT_PHASE) == 0:
                return done(w,0)
            flock_bytes(w,at+512,1,64+get(w,CURRENT_SLOT))
            return call(o,w,6,72,get(w,DAEMON_AUDITFD),5,at+512,0,0,0,48)
        ticket = TICKETS+index*512
        if get(w,ticket) != 1:
            save(w,0,index+1)
            return step(w,1)
        flock_bytes(w,at+512,1,64+index)
        return call(o,w,2,72,get(w,DAEMON_AUDITFD),5,at+512,0,0,0,48)
    if phase == 2:
        if failed(result):
            return io_bad(w,result)
        index = local(w,0)
        ticket = TICKETS+index*512
        if getn(w,at+512,2) != 1 or getn(w,at+536,4) != get(w,ticket+8):
            put(w,ticket,0)
            put(w,SHARED+65536+index*512,0)
            return call(o,w,3,3,get(w,ticket+24),0,0,0,0,0,0)
        put(w,ACTIVECOUNT,get(w,ACTIVECOUNT)+1)
        save(w,0,index+1)
        return step(w,1)
    if phase == 3:
        save(w,0,local(w,0)+1)
        return step(w,1)
    if phase == 6:
        if failed(result):
            return io_bad(w,result)
        if getn(w,at+512,2) != 1 or getn(w,at+536,4) != get(w,CURRENT_WORKER):
            return bad(w,29)
        return done(w,0)
    return bad(w,1)
'''
def source():return authored(SOURCE)
