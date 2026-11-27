"""Held-root native disposable page snapshots and exact I/O continuation.

The temporary inode has no public name and never replaces a retained receipt.
An unchanged watched snapshot is checked against every freshly read original.
Changed membership builds a separate COW tree; only the final namespace fence
can publish it. This owner does not claim sealed cache reuse across restart or
the separate asynchronous pending-worker lifecycle.
"""
from tools.generate_hia_mcp_request_audit_common import authored

_BASE = (22 << 20)+32768
C = {
    'I_DISK_FD': _BASE+160, 'I_DISK_READY': _BASE+168,
    'I_NEW_FD': _BASE+176, 'I_NEW_READY': _BASE+184,
    'I_REBUILD': _BASE+192, 'I_WATCH': _BASE+200,
    'I_FORCE_REBUILD': _BASE+208, 'I_OBSERVED': _BASE+216,
    'I_TREE_INPUT': (19 << 20)+65536,
    'I_TREE_OUTPUT': (19 << 20)+73728,
    'I_TREE_STATE': (19 << 20)+81920,
    'I_TREE_NEW': (19 << 20)+147456,
    'I_TREE_BYTES': 65536, 'M_INDEX': 18,
    'I_AGAIN': (1 << 64)-11,
}

SOURCE = r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    at = frame(w)
    if get(w,at+16) == 3:
        # Discarding a failed private snapshot is bounded descriptor cleanup,
        # never a new admission window or a rewrite of the retained originals.
        if phase == 0 and get(w,I_NEW_READY) != 0:
            descriptor = get(w,I_NEW_FD)
            put(w,I_NEW_READY,0)
            put(w,I_NEW_FD,NONE)
            return call(o,w,990,3,descriptor,0,0,0,0,0,0)
        return done(w,0)
    if phase == 990:
        return done(w,NONE)
    if phase == 900:
        if failed(get(w,8)) or time_before(get(w,at+2048),get(w,at+2056),get(w,INPUT+256),get(w,INPUT+264)) == False:
            return index_error(w)
        put(w,0,get(w,at+392))
        put(w,8,get(w,at+384))
        return checked(o,w)
    put(w,at+392,phase)
    put(w,at+384,get(w,8))
    return call(o,w,900,228,1,at+2048,0,0,0,0,12)

def checked(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    operation = get(w,at+16)
    if phase == 0:
        if get(w,LOCKED) != 1:
            return index_error(w)
        if operation == 0:
            if get(w,I_NEW_READY) != 0:
                return index_error(w)
            put(w,I_OBSERVED,0)
            put(w,I_REBUILD,0)
            if get(w,I_DISK_READY) == 0 or get(w,I_FORCE_REBUILD) != 0:
                return new_snapshot(o,w)
            return call(o,w,3,0,get(w,I_WATCH),I_TREE_INPUT+64,4096,0,0,0,12)
        if operation == 1:
            if get(w,I_DISK_READY) == 1:
                copy_state(w,arg(w,0),I_TREE_INPUT+64,64)
                return tree_command(o,w,1,64,2,I_TREE_STATE)
            return insert_observation(o,w)
        if operation == 2:
            if get(w,I_REBUILD) != 0:
                return tree_command(o,w,4,0,4,I_TREE_NEW)
            if get(w,I_OBSERVED) != get(w,I_TREE_STATE+24):
                return index_error(w)
            return call(o,w,30,0,get(w,I_WATCH),I_TREE_INPUT+64,4096,0,0,0,12)
        return index_error(w)
    if phase == 1:
        if failed(result) or result < 3:
            return index_error(w)
        put(w,I_NEW_FD,result)
        put(w,I_NEW_READY,1)
        return call(o,w,2,5,result,at+512,0,0,0,0,12)
    if phase == 2:
        if failed(result) or getn(w,at+536,4) != 33152 or getn(w,at+540,4) != get(w,24) or get(w,at+528) != 0 or get(w,at+560) != 0:
            return index_error(w)
        fill_range(w,I_TREE_NEW,I_TREE_BYTES,0)
        return tree_command(o,w,0,0,0,I_TREE_NEW)
    if phase == 3:
        if result == NEG4:
            return call(o,w,3,0,get(w,I_WATCH),I_TREE_INPUT+64,4096,0,0,0,12)
        if result == I_AGAIN:
            return done(w,0)
        return new_snapshot(o,w)
    if phase == 10:
        return tree_returned(o,w)
    if phase == 11:
        offset = local(w,3)
        descriptor = choose(local(w,4) == I_TREE_NEW,get(w,I_NEW_FD),get(w,I_DISK_FD))
        if local(w,1) == 1:
            return call(o,w,12,17,descriptor,I_TREE_INPUT+64+offset,4096-offset,local(w,2)+offset,0,0,12)
        return call(o,w,12,18,descriptor,I_TREE_OUTPUT+64+offset,4096-offset,local(w,2)+offset,0,0,12)
    if phase == 12:
        if result == NEG4:
            return step(w,11)
        count = local(w,3)
        if failed(result) or result > 4096-count:
            return index_error(w)
        if result != 0:
            count = count+result
            save(w,3,count)
            if count != 4096:
                return step(w,11)
        elif local(w,1) == 2:
            return index_error(w)
        fill_range(w,I_TREE_INPUT,64,0)
        put(w,I_TREE_INPUT,count)
        return tree_invoke(o,w,64+choose(local(w,1) == 1,count,0))
    if phase == 20:
        return publish_snapshot(o,w)
    if phase == 21:
        # Linux close relinquishes the owned descriptor even on EINTR; it is
        # never retried against a potentially reused descriptor number.
        put(w,I_WATCH,arg(w,0))
        put(w,I_FORCE_REBUILD,0)
        return done(w,0)
    if phase == 30:
        if result == NEG4:
            return call(o,w,30,0,get(w,I_WATCH),I_TREE_INPUT+64,4096,0,0,0,12)
        if result != I_AGAIN:
            return index_error(w)
        return publish_snapshot(o,w)
    return index_error(w)

def new_snapshot(o:mutbuf,w:mutbuf) -> u32:
    put(w,I_REBUILD,1)
    put(w,I_FORCE_REBUILD,1)
    at = frame(w)
    text_dot(w,at+1024)
    return call(o,w,1,257,get(w,ROOTFD),at+1024,4259842+O_CLOEXEC+O_NOFOLLOW,384,0,0,12)

def tree_returned(o:mutbuf,w:mutbuf) -> u32:
    size = get(w,8)
    if size != 64 and size != 448 and size != 4160:
        return index_error(w)
    kind = get(w,I_TREE_OUTPUT)
    if kind == 0:
        return tree_finished(o,w,size)
    if kind == 3:
        return index_error(w)
    if (kind != 1 and kind != 2) or (kind == 1 and size != 64) or (kind == 2 and size != 4160):
        return index_error(w)
    # A read-only committed context must never emit a disk write.
    if kind == 2 and local(w,4) != I_TREE_NEW:
        return index_error(w)
    page = get(w,I_TREE_OUTPUT+8)
    if page >= 2251799813685247:
        return index_error(w)
    save(w,1,kind)
    save(w,2,page*4096)
    save(w,3,0)
    return step(w,11)

def tree_finished(o:mutbuf,w:mutbuf,size:u64) -> u32:
    stage = local(w,0)
    if stage == 2:
        present = get(w,I_TREE_OUTPUT+8)
        if present > 1 or (present == 1 and size != 448) or (present == 0 and size != 64):
            return index_error(w)
        if present == 1:
            old = I_TREE_OUTPUT+64
            current = arg(w,0)
            if record_identity(w,old,current) == False:
                return index_error(w)
            # An older Unknown may be ignored in a pending publication cohort,
            # but freshly observed original bytes must match a terminal row.
            if get(w,old+200) != 0 and record_equal(w,old,current) == False:
                return index_error(w)
        elif get(w,I_REBUILD) == 0:
            return index_error(w)
        return insert_observation(o,w)
    if size != 64:
        return index_error(w)
    if stage == 0:
        return tree_command(o,w,3,0,1,I_TREE_NEW)
    if stage == 1:
        return done(w,0)
    if stage == 3:
        return observed(w)
    if stage == 4:
        if get(w,I_TREE_NEW+24) != get(w,I_OBSERVED):
            return index_error(w)
        old = get(w,I_DISK_FD)
        had_old = get(w,I_DISK_READY)
        put(w,I_DISK_FD,get(w,I_NEW_FD))
        put(w,I_NEW_FD,NONE)
        put(w,I_NEW_READY,0)
        put(w,I_DISK_READY,1)
        copy_state(w,I_TREE_NEW,I_TREE_STATE,I_TREE_BYTES)
        if had_old != 0:
            return call(o,w,20,3,old,0,0,0,0,0,0)
        return publish_snapshot(o,w)
    return index_error(w)

def insert_observation(o:mutbuf,w:mutbuf) -> u32:
    if get(w,I_REBUILD) == 0:
        return observed(w)
    copy_state(w,arg(w,0),I_TREE_INPUT+64,240)
    copy_state(w,arg(w,1),I_TREE_INPUT+304,144)
    return tree_command(o,w,2,384,3,I_TREE_NEW)

def observed(w:mutbuf) -> u32:
    count = get(w,I_OBSERVED)
    if count == NONE:
        return index_error(w)
    put(w,I_OBSERVED,count+1)
    return done(w,0)

def publish_snapshot(o:mutbuf,w:mutbuf) -> u32:
    # The caller supplies the exact still-held per-query namespace watch only
    # after its own complete original and final namespace fences have passed.
    old = get(w,I_WATCH)
    if old >= 3 and old != NONE:
        put(w,I_WATCH,0)
        return call(o,w,21,3,old,0,0,0,0,0,0)
    put(w,I_WATCH,arg(w,0))
    put(w,I_FORCE_REBUILD,0)
    return done(w,0)

def tree_command(o:mutbuf,w:mutbuf,operation:u64,size:u64,stage:u64,target:u64) -> u32:
    save(w,0,stage)
    save(w,4,target)
    fill_range(w,I_TREE_INPUT,64,0)
    put(w,I_TREE_INPUT,operation)
    return tree_invoke(o,w,64+size)

def tree_invoke(o:mutbuf,w:mutbuf,size:u64) -> u32:
    enter(w,M_INDEX,10)
    put(o,0,I_TREE_INPUT)
    put(o,8,size)
    put(o,16,I_TREE_OUTPUT)
    put(o,24,4160)
    put(o,32,local(w,4))
    put(o,40,I_TREE_BYTES)
    return 8

def index_error(w:mutbuf) -> u32:
    put(w,I_FORCE_REBUILD,1)
    put(w,96,38)
    put(w,104,0)
    return done(w,NONE)
'''


def source():
    return authored(SOURCE,extra=C)

