"""Descriptor-owned HIA directory, capture, and ticket-fence procedures."""
from tools.generate_hia_mcp_request_audit_common import authored
SOURCE = r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    at = frame(w)
    operation = get(w, at + 16)
    if phase == 0:
        save(w, 0, NONE)
        if operation == OPEN_DIR:
            if arg(w, 2) != 0:
                return call(o,w,1,258,arg(w,0),arg(w,1),448,0,0,0,12)
            return step(w,3)
        if operation == READ_FILE:
            return call(o,w,100,257,arg(w,0),arg(w,1),O_CLOEXEC+O_NOFOLLOW+O_NONBLOCK,0,0,0,12)
        if operation == FENCE_DIR:
            return call(o,w,200,5,arg(w,2),at+512,0,0,0,0,12)
        if operation == FENCE_PIN:
            return call(o,w,300,5,arg(w,2),at+512,0,0,0,0,12)
        return bad(w,1)
    if phase == 1:
        if failed(result) and result != NEG17:
            return io_bad(w,result)
        if result == 0:
            return call(o,w,2,74,arg(w,0),0,0,0,0,0,0)
        return step(w,3)
    if phase == 2:
        if failed(result):
            return io_bad(w,result)
        return step(w,3)
    if phase == 3:
        return call(o,w,4,257,arg(w,0),arg(w,1),O_CLOEXEC+O_NOFOLLOW+O_DIRECTORY,0,0,0,12)
    if phase == 4:
        if failed(result):
            if result == NEG2:
                return done(w,NEG2)
            return io_bad(w,result)
        save(w,0,result)
        return call(o,w,5,5,result,at+512,0,0,0,0,12)
    if phase == 5:
        if failed(result):
            return file_error(o,w,31,result)
        if directory_ok(w,at+512) == False:
            return file_error(o,w,3,0)
        if arg(w,3) != 0:
            copy_state(w,at+512,arg(w,3),144)
        return done(w,local(w,0))
    if phase == 100:
        if failed(result):
            if result == NEG2 and arg(w,6) != 0:
                return done(w,NEG2)
            return io_bad(w,result)
        save(w,0,result)
        return call(o,w,101,5,result,at+512,0,0,0,0,12)
    if phase == 101:
        if failed(result):
            return file_error(o,w,31,result)
        if regular_ok(w,at+512,arg(w,3),arg(w,7)) == False:
            return file_error(o,w,4,0)
        save(w,1,0)
        return step(w,102)
    if phase == 102:
        return call(o,w,103,17,local(w,0),arg(w,2)+local(w,1),arg(w,3)+1-local(w,1),local(w,1),0,0,12)
    if phase == 103:
        if result == NEG4:
            return step(w,102)
        if failed(result):
            return file_error(o,w,31,result)
        if result != 0:
            count = local(w,1)+result
            if count > arg(w,3):
                return file_error(o,w,5,0)
            save(w,1,count)
            return step(w,102)
        return call(o,w,104,5,local(w,0),at+656,0,0,0,0,12)
    if phase == 104:
        if failed(result):
            return file_error(o,w,31,result)
        if stamp_equal(w,at+512,at+656) == False:
            return file_error(o,w,4,0)
        return call(o,w,105,262,arg(w,0),arg(w,1),at+800,256,0,0,60)
    if phase == 105:
        if failed(result):
            return file_error(o,w,31,result)
        if stamp_equal(w,at+512,at+800) == False:
            return file_error(o,w,4,0)
        if arg(w,5) != 0:
            copy_state(w,at+512,arg(w,5),144)
        if arg(w,4) != 0:
            put(w,arg(w,4),local(w,0))
            return done(w,local(w,1))
        return call(o,w,106,3,local(w,0),0,0,0,0,0,0)
    if phase == 106:
        return done(w,local(w,1))
    if phase == 200:
        if failed(result):
            return io_bad(w,result)
        if directory_binding(w,at+512,arg(w,3)) == False:
            return bad(w,8)
        return call(o,w,201,262,arg(w,0),arg(w,1),at+656,256,0,0,60)
    if phase == 201:
        if failed(result):
            return io_bad(w,result)
        if directory_binding(w,at+512,at+656) == False:
            return bad(w,8)
        return done(w,0)
    if phase == 300:
        if failed(result):
            return io_bad(w,result)
        if stamp_equal(w,at+512,arg(w,5)) == False:
            return bad(w,24)
        save(w,1,0)
        return step(w,301)
    if phase == 301:
        return call(o,w,302,17,arg(w,2),arg(w,6)+local(w,1),arg(w,4)+1-local(w,1),local(w,1),0,0,12)
    if phase == 302:
        if result == NEG4:
            return step(w,301)
        if failed(result):
            return io_bad(w,result)
        if result != 0:
            count = local(w,1)+result
            if count > arg(w,4):
                return bad(w,24)
            save(w,1,count)
            return step(w,301)
        if local(w,1) != arg(w,4) or equal(w,arg(w,3),arg(w,6),arg(w,4)) == False:
            return bad(w,24)
        return call(o,w,303,5,arg(w,2),at+656,0,0,0,0,12)
    if phase == 303:
        if failed(result):
            return io_bad(w,result)
        if stamp_equal(w,at+656,arg(w,5)) == False:
            return bad(w,24)
        return call(o,w,304,262,arg(w,0),arg(w,1),at+800,256,0,0,60)
    if phase == 304:
        if failed(result):
            return io_bad(w,result)
        if stamp_equal(w,at+800,arg(w,5)) == False:
            return bad(w,24)
        return done(w,0)
    if phase == 990:
        return done(w,NONE)
    return bad(w,1)

def file_error(o:mutbuf,w:mutbuf,reason:u64,error:u64) -> u32:
    put(w,96,reason)
    put(w,104,error)
    if local(w,0) != NONE:
        return call(o,w,990,3,local(w,0),0,0,0,0,0,0)
    return done(w,NONE)
'''
def source():return authored(SOURCE)
