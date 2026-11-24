"""Recover only an original, valid v12 metadata publication's known hard-link alias."""
from tools.generate_hia_mcp_request_audit_common import authored
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,frame(w)+16) == 1:
        return candidate(o,w)
    return recover(o,w)

def recover(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    if phase == 0:
        return call(o,w,1,5,arg(w,0),at+512,0,0,0,0,12)
    if phase == 1:
        if failed(result):
            return io_bad(w,result)
        if regular_ok(w,at+512,65536,2) == False or equal(w,at+512,arg(w,2),16) == False:
            return bad(w,32)
        if get(w,at+528) == 1:
            return step(w,5)
        return procedure(w,M_SCAN,0,2,get(w,ROOTFD),0,0,3,at+512,arg(w,1),0,0)
    if phase == 2:
        if get(w,48) == NONE:
            return done(w,NONE)
        if get(w,48) != 1:
            return bad(w,32)
        return call(o,w,3,74,get(w,ROOTFD),0,0,0,0,0,0)
    if phase == 3:
        if failed(result):
            return io_bad(w,result)
        return call(o,w,4,5,arg(w,0),at+512,0,0,0,0,12)
    if phase == 4:
        if failed(result):
            return io_bad(w,result)
        return step(w,5)
    if phase == 5:
        if regular_ok(w,at+512,65536,1) == False or equal(w,at+512,arg(w,2),16) == False:
            return bad(w,32)
        copy_state(w,at+512,arg(w,2),144)
        return procedure(w,M_FILES,FENCE_PIN,6,get(w,ROOTFD),arg(w,5),arg(w,0),arg(w,3),arg(w,4),arg(w,2),READ_DATA,0)
    if phase == 6:
        return done(w,get(w,48))
    return bad(w,1)

def candidate(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    if phase == 0:
        save(w,0,NONE)
        return call(o,w,1,257,arg(w,0),arg(w,1),O_NOFOLLOW+O_NONBLOCK+O_CLOEXEC,0,0,0,12)
    if phase == 1:
        if failed(result):
            return io_bad(w,result)
        save(w,0,result)
        return call(o,w,2,5,result,at+512,0,0,0,0,12)
    if phase == 2:
        if failed(result):
            return candidate_error(o,w,31,result)
        save(w,1,0)
        if equal(w,at+512,arg(w,2),16):
            if get(w,at+528) != 2:
                return candidate_error(o,w,32,0)
            save(w,1,1)
        return call(o,w,3,3,local(w,0),0,0,0,0,0,0)
    if phase == 3:
        save(w,0,NONE)
        if local(w,1) == 0:
            return done(w,0)
        return call(o,w,4,263,arg(w,0),arg(w,1),0,0,0,0,12)
    if phase == 4:
        if failed(result):
            return io_bad(w,result)
        return done(w,1)
    if phase == 99:
        return done(w,NONE)
    return candidate_error(o,w,1,0)

def candidate_error(o:mutbuf,w:mutbuf,reason:u64,error:u64) -> u32:
    put(w,96,reason)
    put(w,104,error)
    if local(w,0) != NONE:
        return call(o,w,99,3,local(w,0),0,0,0,0,0,0)
    return done(w,NONE)
'''
def source():return authored(SOURCE)
