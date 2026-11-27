"""HIA live archive registry and per-ticket hot directory ownership."""
from tools.generate_hia_mcp_request_audit_common import authored
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    if phase == 0:
        if get(w,at+16) == 1:
            save(w,1,1)
            return step(w,3)
        save(w,0,0)
        save(w,1,choose(get(w,ACTIVECOUNT) != 0,1,0))
        if local(w,1) != 0:
            return step(w,3)
        return step(w,1)
    if phase == 1:
        index = local(w,0)
        if index == 261:
            put(w,LAYOUT,0)
            put(w,ARCHIVE_OPENED,0)
            return step(w,3)
        address = close_address(index)
        fd = get(w,address)
        put(w,address,NONE)
        save(w,0,index+1)
        if fd != NONE:
            return call(o,w,2,3,fd,0,0,0,0,0,0)
        return step(w,1)
    if phase == 2:
        return step(w,1)
    if phase == 3:
        return procedure(w,M_ROOT,0,4,local(w,1),0,0,0,0,0,0,0)
    if phase == 4:
        if get(w,48) == NONE:
            return done(w,NONE)
        text_hot(w,at+1024)
        return procedure(w,M_FILES,OPEN_DIR,5,get(w,ROOTFD),at+1024,1,HOT_STAMP,0,0,0,0)
    if phase == 5:
        if get(w,48) == NONE or get(w,48) == NEG2:
            return done(w,NONE)
        put(w,HOTFD,get(w,48))
        put(w,HOT_OWNED,1)
        if get(w,at+16) == 1:
            return procedure(w,M_RETENTION,RETENTION_HISTORY,7,0,0,0,0,0,0,0,0)
        return procedure(w,M_ARCHIVE,ARCHIVE_OPEN,6,local(w,1),0,0,0,0,0,0,0)
    if phase == 6:
        if get(w,48) == NONE:
            return done(w,NONE)
        put(w,ARCHIVE_OPENED,1)
        return procedure(w,M_RETENTION,RETENTION_SNAPSHOT,7,0,0,0,0,0,0,0,0)
    if phase == 7:
        return done(w,get(w,48))
    return bad(w,1)

def close_address(index:u64) -> u64:
    if index == 0:
        return ROOTFD
    if index == 1:
        return LEGACYFD
    if index == 2:
        return PIN11FD
    if index == 3:
        return SHARDROOTFD
    if index == 4:
        return PIN12FD
    return SHARD_FDS+(index-5)*8
'''
def source():return authored(SOURCE)
