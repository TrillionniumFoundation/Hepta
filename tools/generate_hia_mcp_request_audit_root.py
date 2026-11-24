"""HIA absolute-root walk with held inode and searchable ancestor custody."""
from tools.generate_hia_mcp_request_audit_common import authored
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    if phase == 0:
        size = get(w,INPUT+80)
        if size == 0 or size > 4096 or byte(w,INPUT+512) != 47:
            return bad(w,11)
        if utf8(w,INPUT+512,size) == False:
            return bad(w,10)
        save(w,0,1)
        save(w,1,NONE)
        text_slash(w,at+1024)
        return call(o,w,1,257,NEG100,at+1024,O_PATH+O_DIRECTORY+O_NOFOLLOW+O_CLOEXEC,0,0,0,12)
    if phase == 1:
        if failed(result):
            return io_bad(w,result)
        save(w,1,result)
        return step(w,2)
    if phase == 2:
        pos = local(w,0)
        size = get(w,INPUT+80)
        while pos < size and byte(w,INPUT+512+pos) == 47:
            pos = pos + 1
        if pos == size:
            return call(o,w,7,5,local(w,1),at+512,0,0,0,0,12)
        start = pos
        while pos < size and byte(w,INPUT+512+pos) != 47:
            pos = pos + 1
        count = pos - start
        if (count == 1 and byte(w,INPUT+512+start) == 46) or (count == 2 and getn(w,INPUT+512+start,2) == 11822):
            return bad(w,11)
        if count > 255:
            return bad(w,11)
        copy_state(w,INPUT+512+start,at+1024,count)
        store(w,at+1024+count,0)
        while pos < size and byte(w,INPUT+512+pos) == 47:
            pos = pos + 1
        save(w,0,pos)
        save(w,2,choose(pos == size,0,O_PATH))
        return call(o,w,3,5,local(w,1),at+512,0,0,0,0,12)
    if phase == 3:
        if failed(result):
            return io_bad(w,result)
        if getn(w,at+536,4) & 73 == 0:
            return bad(w,12)
        return call(o,w,4,257,local(w,1),at+1024,local(w,2)+O_DIRECTORY+O_NOFOLLOW+O_CLOEXEC,0,0,0,12)
    if phase == 4:
        if failed(result):
            return io_bad(w,result)
        save(w,3,result)
        return call(o,w,5,3,local(w,1),0,0,0,0,0,0)
    if phase == 5:
        save(w,1,local(w,3))
        return step(w,2)
    if phase == 7:
        if failed(result):
            return io_bad(w,result)
        if directory_ok(w,at+512) == False:
            return bad(w,3)
        if arg(w,0) != 0 and directory_binding(w,at+512,ROOT_STAMP) == False:
            return bad(w,7)
        if arg(w,0) == 0:
            copy_state(w,at+512,ROOT_STAMP,144)
        return call(o,w,8,5,get(w,INPUT+32),at+656,0,0,0,0,12)
    if phase == 8:
        if failed(result):
            return io_bad(w,result)
        if directory_binding(w,ROOT_STAMP,at+656) == False:
            return bad(w,7)
        if arg(w,0) != 0:
            return call(o,w,9,3,local(w,1),0,0,0,0,0,0)
        put(w,ROOTFD,local(w,1))
        return done(w,local(w,1))
    if phase == 9:
        return done(w,get(w,ROOTFD))
    return bad(w,1)
'''
def source():return authored(SOURCE)
