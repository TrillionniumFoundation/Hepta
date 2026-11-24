"""HIA fsync-before-publication protocol for private metadata."""
from tools.generate_hia_mcp_request_audit_common import authored
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    if phase == 0:
        save(w,0,NONE)
        save(w,2,0)
        return call(o,w,1,5,arg(w,0),at+512,0,0,0,0,12)
    if phase == 1:
        if failed(result):
            return io_bad(w,result)
        if directory_ok(w,at+512) == False:
            return bad(w,3)
        return call(o,w,2,257,arg(w,0),arg(w,2),1+64+128+O_NOFOLLOW+O_CLOEXEC,384,0,0,12)
    if phase == 2:
        if failed(result):
            return io_bad(w,result)
        save(w,0,result)
        save(w,2,1)
        return call(o,w,3,5,result,at+512,0,0,0,0,12)
    if phase == 3:
        if failed(result):
            return write_error(o,w,31,result)
        if regular_ok(w,at+512,65536,1) == False:
            return write_error(o,w,4,0)
        save(w,1,0)
        return step(w,4)
    if phase == 4:
        if local(w,1) == arg(w,4):
            return call(o,w,6,74,local(w,0),0,0,0,0,0,0)
        return call(o,w,5,1,local(w,0),arg(w,3)+local(w,1),arg(w,4)-local(w,1),0,0,0,12)
    if phase == 5:
        if result == NEG4:
            return step(w,4)
        if failed(result) or result == 0 or result > arg(w,4)-local(w,1):
            return write_error(o,w,31,result)
        save(w,1,local(w,1)+result)
        return step(w,4)
    if phase == 6:
        if failed(result):
            return write_error(o,w,31,result)
        return call(o,w,7,3,local(w,0),0,0,0,0,0,0)
    if phase == 7:
        save(w,0,NONE)
        if arg(w,5) != 0:
            return call(o,w,10,264,arg(w,0),arg(w,2),arg(w,0),arg(w,1),0,0,204)
        return call(o,w,8,265,arg(w,0),arg(w,2),arg(w,0),arg(w,1),0,0,204)
    if phase == 8:
        if failed(result):
            return write_error(o,w,31,result)
        return call(o,w,9,263,arg(w,0),arg(w,2),0,0,0,0,12)
    if phase == 9:
        if failed(result):
            return write_error(o,w,31,result)
        return step(w,11)
    if phase == 10:
        if failed(result):
            return write_error(o,w,31,result)
        return step(w,11)
    if phase == 11:
        save(w,2,0)
        return call(o,w,12,74,arg(w,0),0,0,0,0,0,0)
    if phase == 12:
        if failed(result):
            return io_bad(w,result)
        return done(w,0)
    if phase == 990:
        save(w,0,NONE)
        return call(o,w,991,263,arg(w,0),arg(w,2),0,0,0,0,12)
    if phase == 991:
        return done(w,NONE)
    return bad(w,1)

def write_error(o:mutbuf,w:mutbuf,reason:u64,error:u64) -> u32:
    put(w,96,reason)
    put(w,104,error)
    if local(w,0) != NONE:
        return call(o,w,990,3,local(w,0),0,0,0,0,0,0)
    if local(w,2) != 0:
        return call(o,w,991,263,arg(w,0),arg(w,2),0,0,0,0,12)
    return done(w,NONE)
'''
def source():return authored(SOURCE)
