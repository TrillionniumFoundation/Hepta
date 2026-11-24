"""Original private-record parsing, staging recovery and publication in HIA."""
from tools.generate_hia_mcp_request_audit_common import authored
from tools.generate_hia_mcp_request_audit_codec import SOURCE as CODEC, TEXT
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    if phase == 0:
        operation = get(w,at+16)
        if operation == RECORD_CLEAN:
            return step(w,100)
        if operation == RECORD_WRITE:
            return step(w,200)
        if operation != RECORD_READ or lowerhex(w,arg(w,1),64) == False:
            return bad(w,6)
        filename(w,arg(w,1),at+1024)
        tempname(w,arg(w,1),at+1152)
        return procedure(w,M_RECORDS,RECORD_CLEAN,1,arg(w,0),at+1152,134,0,0,0,0,0)
    if phase == 1:
        if get(w,48) == NONE:
            return done(w,NONE)
        return call(o,w,2,262,arg(w,0),at+1024,at+512,256,0,0,60)
    if phase == 2:
        if failed(result):
            if result == NEG2 and arg(w,3) != 0:
                return done(w,NEG2)
            return io_bad(w,result)
        if get(w,at+528) == 2:
            return procedure(w,M_SCAN,0,3,arg(w,0),0,0,2,arg(w,1),0,0,0)
        return step(w,3)
    if phase == 3:
        if get(w,48) == NONE:
            return done(w,NONE)
        return procedure(w,M_FILES,READ_FILE,4,arg(w,0),at+1024,READ_DATA,2048,0,0,arg(w,3),1)
    if phase == 4:
        size = get(w,48)
        if size == NONE or size == NEG2:
            return done(w,size)
        return json_decode(o,w,5,READ_DATA,size)
    if phase == 5:
        if json_ok(w,result) == False or parse_record(w,arg(w,2),arg(w,1)) == False:
            return bad(w,6)
        return done(w,0)
    if phase == 100:
        save(w,0,NONE)
        save(w,1,NONE)
        name = arg(w,1)
        size = arg(w,2)
        if size != 134 or byte(w,name) != 46 or byte(w,name+65) != 45 or getn(w,name+130,4) != 1886221358 or lowerhex(w,name+1,64) == False or lowerhex(w,name+66,64) == False:
            return cleanup_error(o,w,15,0)
        filename(w,name+1,at+1024)
        return call(o,w,101,257,arg(w,0),name,O_CLOEXEC+O_NOFOLLOW+O_NONBLOCK,0,0,0,12)
    if phase == 101:
        if failed(result):
            if result == NEG2:
                return done(w,0)
            return cleanup_error(o,w,31,result)
        save(w,0,result)
        return call(o,w,102,5,result,at+512,0,0,0,0,12)
    if phase == 102:
        if failed(result):
            return cleanup_error(o,w,31,result)
        if regular_ok(w,at+512,2048,2) == False:
            return cleanup_error(o,w,16,0)
        if get(w,at+528) == 2:
            return call(o,w,103,257,arg(w,0),at+1024,O_CLOEXEC+O_NOFOLLOW+O_NONBLOCK,0,0,0,12)
        return step(w,106)
    if phase == 103:
        if failed(result):
            return cleanup_error(o,w,31,result)
        save(w,1,result)
        return call(o,w,104,5,result,at+656,0,0,0,0,12)
    if phase == 104:
        if failed(result):
            return cleanup_error(o,w,31,result)
        if equal(w,at+512,at+656,16) == False:
            return cleanup_error(o,w,17,0)
        return call(o,w,105,3,local(w,1),0,0,0,0,0,0)
    if phase == 105:
        save(w,1,NONE)
        return step(w,106)
    if phase == 106:
        return call(o,w,107,3,local(w,0),0,0,0,0,0,0)
    if phase == 107:
        save(w,0,NONE)
        return call(o,w,108,263,arg(w,0),arg(w,1),0,0,0,0,12)
    if phase == 108:
        if failed(result):
            return cleanup_error(o,w,31,result)
        return call(o,w,109,74,arg(w,0),0,0,0,0,0,0)
    if phase == 109:
        if failed(result):
            return cleanup_error(o,w,31,result)
        return done(w,0)
    if phase == 990:
        return cleanup_close(o,w)
    if phase == 991:
        return done(w,NONE)
    if phase == 200:
        if arg(w,3) != 0:
            return procedure(w,M_RECORDS,RECORD_READ,201,arg(w,0),arg(w,1),COMPARE_RECORD,0,0,0,0,0)
        return step(w,202)
    if phase == 201:
        if get(w,48) == NONE:
            return done(w,NONE)
        if record_identity(w,arg(w,2),COMPARE_RECORD) == False:
            return bad(w,19)
        return step(w,202)
    if phase == 202:
        size = render_record(w,arg(w,2),JSON_DATA)
        if size > 2048:
            return bad(w,5)
        filename(w,arg(w,1),at+1024)
        tempname(w,arg(w,1),at+1152)
        return procedure(w,M_WRITE,0,203,arg(w,0),at+1024,at+1152,JSON_DATA,size,arg(w,3),0,0)
    if phase == 203:
        return done(w,get(w,48))
    return bad(w,1)

def cleanup_error(o:mutbuf,w:mutbuf,reason:u64,error:u64) -> u32:
    put(w,96,reason)
    put(w,104,error)
    if local(w,1) != NONE:
        descriptor = local(w,1)
        save(w,1,NONE)
        return call(o,w,990,3,descriptor,0,0,0,0,0,0)
    return cleanup_close(o,w)

def cleanup_close(o:mutbuf,w:mutbuf) -> u32:
    if local(w,0) != NONE:
        descriptor = local(w,0)
        save(w,0,NONE)
        return call(o,w,991,3,descriptor,0,0,0,0,0,0)
    return done(w,NONE)
'''
def source():return authored(SOURCE+'\n'+CODEC,text=TEXT)
