"""HIA immutable legacy anchor and unified archive record ownership."""
from tools.generate_hia_mcp_request_audit_common import authored
from tools.generate_hia_mcp_request_audit_codec import SOURCE as CODEC
TEXT=dict(anchor_root='{"root_device":',anchor_rootino=',"root_inode":',
          anchor_dev=',"archive_device":',anchor_ino=',"archive_inode":')
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    operation = get(w,frame(w)+16)
    if operation == ARCHIVE_OPEN:
        return archive_open(o,w)
    if operation == ARCHIVE_FENCE:
        return archive_fence(o,w)
    if operation == ARCHIVE_FIND:
        return archive_find(o,w)
    if operation == ARCHIVE_READ:
        return archive_read(o,w)
    if operation == ARCHIVE_SAVE or operation == ARCHIVE_SEED:
        return archive_save(o,w)
    return bad(w,1)

def archive_open(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    if phase == 0:
        text_anchor11(w,at+1024)
        text_legacy(w,at+1152)
        if arg(w,0) != 0:
            return procedure(w,M_FILES,FENCE_PIN,20,get(w,ROOTFD),at+1024,get(w,PIN11FD),PIN11_DATA,get(w,PIN11LEN),PIN11_STAMP,READ_DATA,0)
        return procedure(w,M_FILES,READ_FILE,1,get(w,ROOTFD),at+1024,PIN11_DATA,2048,PIN11FD,PIN11_STAMP,1,1)
    if phase == 1:
        size = get(w,48)
        if size == NONE:
            return done(w,NONE)
        if size == NEG2:
            return call(o,w,10,262,get(w,ROOTFD),at+1152,at+512,256,0,0,60)
        put(w,PIN11LEN,size)
        return json_decode(o,w,2,PIN11_DATA,size)
    if phase == 2:
        if json_ok(w,result) == False or anchor11_decode(w,at+1536) == False:
            return bad(w,24)
        if equal(w,at+1536,ROOT_STAMP,16) == False:
            return bad(w,7)
        return procedure(w,M_FILES,OPEN_DIR,3,get(w,ROOTFD),at+1152,0,LEGACY_STAMP,0,0,0,0)
    if phase == 3:
        if get(w,48) == NONE or get(w,48) == NEG2:
            return bad(w,8)
        put(w,LEGACYFD,get(w,48))
        if equal(w,at+1552,LEGACY_STAMP,16) == False:
            return bad(w,8)
        return procedure(w,M_LAYOUT,LAYOUT_OPEN,4,0,0,0,0,0,0,0,0)
    if phase == 4:
        return done(w,get(w,48))
    if phase == 10:
        if result != NEG2:
            return bad(w,9)
        return call(o,w,11,258,get(w,ROOTFD),at+1152,448,0,0,0,12)
    if phase == 11:
        if failed(result):
            return io_bad(w,result)
        return call(o,w,12,74,get(w,ROOTFD),0,0,0,0,0,0)
    if phase == 12:
        if failed(result):
            return io_bad(w,result)
        return procedure(w,M_FILES,OPEN_DIR,13,get(w,ROOTFD),at+1152,0,LEGACY_STAMP,0,0,0,0)
    if phase == 13:
        if get(w,48) == NONE or get(w,48) == NEG2:
            return bad(w,8)
        save(w,0,get(w,48))
        put(w,LEGACYFD,get(w,48))
        save(w,1,0)
        return step(w,14)
    if phase == 14:
        return call(o,w,15,318,at+1700+local(w,1),32-local(w,1),0,0,0,0,3)
    if phase == 15:
        if result == NEG4:
            return step(w,14)
        if failed(result) or result == 0 or result > 32-local(w,1):
            return io_bad(w,result)
        save(w,1,local(w,1)+result)
        if local(w,1) < 32:
            return step(w,14)
        end = text_anchor_prefix(w,at+1800)
        end = encode_hex(w,at+1700,end)
        text_tmp(w,end)
        size = anchor11_render(w,JSON_DATA)
        return procedure(w,M_WRITE,0,16,get(w,ROOTFD),at+1024,at+1800,JSON_DATA,size,0,0,0)
    if phase == 16:
        if get(w,48) == NONE:
            return done(w,NONE)
        return call(o,w,17,3,local(w,0),0,0,0,0,0,0)
    if phase == 17:
        return procedure(w,M_FILES,READ_FILE,1,get(w,ROOTFD),at+1024,PIN11_DATA,2048,PIN11FD,PIN11_STAMP,0,1)
    if phase == 20:
        if get(w,48) == NONE:
            return done(w,NONE)
        return procedure(w,M_FILES,FENCE_DIR,21,get(w,ROOTFD),at+1152,get(w,LEGACYFD),LEGACY_STAMP,0,0,0,0)
    if phase == 21:
        if get(w,48) == NONE:
            return done(w,NONE)
        if get(w,LAYOUT) == 0:
            return procedure(w,M_LAYOUT,LAYOUT_OPEN,4,0,0,0,0,0,0,0,0)
        return procedure(w,M_LAYOUT,LAYOUT_FENCE,4,0,0,0,0,0,0,0,0)
    return bad(w,1)

def anchor11_decode(w:mutbuf,target:u64) -> bool:
    root = ARENA+64
    if fields_exact(w,root,960,960) == False:
        return False
    index = 0
    while index < 4:
        if scalar_number(w,audit_field(w,root,7+index),target+index*16) == False:
            return False
        index = index+1
    put(w,target+8,get(w,target+16))
    put(w,target+16,get(w,target+32))
    put(w,target+24,get(w,target+48))
    return True

def anchor11_render(w:mutbuf,target:u64) -> u64:
    at = text_anchor_root(w,target)
    at = decimal(w,at,get(w,ROOT_STAMP))
    at = text_anchor_rootino(w,at)
    at = decimal(w,at,get(w,ROOT_STAMP+8))
    at = text_anchor_dev(w,at)
    at = decimal(w,at,get(w,LEGACY_STAMP))
    at = text_anchor_ino(w,at)
    at = decimal(w,at,get(w,LEGACY_STAMP+8))
    at = text_close(w,at)
    return at-target

def archive_fence(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    if phase == 0:
        return call(o,w,1,5,get(w,ROOTFD),at+512,0,0,0,0,12)
    if phase == 1:
        if failed(result):
            return io_bad(w,result)
        if directory_binding(w,at+512,ROOT_STAMP) == False:
            return bad(w,7)
        text_legacy(w,at+1024)
        return procedure(w,M_FILES,FENCE_DIR,2,get(w,ROOTFD),at+1024,get(w,LEGACYFD),LEGACY_STAMP,0,0,0,0)
    if phase == 2:
        if get(w,48) == NONE:
            return done(w,NONE)
        text_anchor11(w,at+1024)
        return procedure(w,M_FILES,FENCE_PIN,3,get(w,ROOTFD),at+1024,get(w,PIN11FD),PIN11_DATA,get(w,PIN11LEN),PIN11_STAMP,READ_DATA,0)
    if phase == 3:
        if get(w,48) == NONE:
            return done(w,NONE)
        if arg(w,0) != 0:
            return done(w,0)
        return procedure(w,M_LAYOUT,LAYOUT_FENCE,4,0,0,0,0,0,0,0,0)
    if phase == 4:
        return done(w,get(w,48))
    return bad(w,1)

def archive_find(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    if phase == 0:
        if lowerhex(w,arg(w,0),64) == False:
            return bad(w,6)
        filename(w,arg(w,0),at+1024)
        save(w,0,NEG2)
        return call(o,w,1,262,get(w,LEGACYFD),at+1024,at+512,256,0,0,60)
    if phase == 1:
        if failed(result) and result != NEG2:
            return io_bad(w,result)
        if result == 0:
            save(w,0,get(w,LEGACYFD))
        if get(w,LAYOUT) == 0:
            return done(w,local(w,0))
        shard = hex_digit_value(byte(w,arg(w,0)))*16+hex_digit_value(byte(w,arg(w,0)+1))
        save(w,1,get(w,SHARD_FDS+shard*8))
        return call(o,w,2,262,local(w,1),at+1024,at+656,256,0,0,60)
    if phase == 2:
        if failed(result) and result != NEG2:
            return io_bad(w,result)
        if result == 0:
            if local(w,0) != NEG2:
                return bad(w,26)
            save(w,0,local(w,1))
        return done(w,local(w,0))
    return bad(w,1)

def archive_read(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    if phase == 0:
        return procedure(w,M_ARCHIVE,ARCHIVE_FENCE,1,0,0,0,0,0,0,0,0)
    if phase == 1:
        if get(w,48) == NONE:
            return done(w,NONE)
        return procedure(w,M_ARCHIVE,ARCHIVE_FIND,2,arg(w,0),0,0,0,0,0,0,0)
    if phase == 2:
        if get(w,48) == NONE or get(w,48) == NEG2:
            return done(w,get(w,48))
        save(w,0,get(w,48))
        return procedure(w,M_RECORDS,RECORD_READ,3,local(w,0),arg(w,0),arg(w,1),0,0,0,0,0)
    if phase == 3:
        if get(w,48) == NONE:
            return done(w,NONE)
        return procedure(w,M_ARCHIVE,ARCHIVE_FIND,4,arg(w,0),0,0,0,0,0,0,0)
    if phase == 4:
        if get(w,48) == NONE:
            return done(w,NONE)
        if get(w,48) != local(w,0):
            return bad(w,27)
        return procedure(w,M_ARCHIVE,ARCHIVE_FENCE,5,0,0,0,0,0,0,0,0)
    if phase == 5:
        return done(w,get(w,48))
    return bad(w,1)

def archive_save(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    at = frame(w)
    if phase == 0:
        save(w,1,0)
        return procedure(w,M_ARCHIVE,ARCHIVE_FENCE,1,0,0,0,0,0,0,0,0)
    if phase == 1:
        if get(w,48) == NONE:
            return done(w,NONE)
        if get(w,at+16) == ARCHIVE_SEED or arg(w,1) == 1:
            return procedure(w,M_ARCHIVE,ARCHIVE_FIND,2,arg(w,0),0,0,0,0,0,0,0)
        return procedure(w,M_ARCHIVE,ARCHIVE_READ,3,arg(w,0),TEMP_RECORD,0,0,0,0,0,0)
    if phase == 2:
        if get(w,48) == NONE:
            return done(w,NONE)
        if get(w,48) != NEG2:
            if get(w,at+16) == ARCHIVE_SEED:
                return done(w,0)
            return io_bad(w,NEG17)
        return step(w,4)
    if phase == 3:
        if get(w,48) == NONE:
            return done(w,NONE)
        if get(w,48) != NEG2:
            source = arg(w,0)
            if record_identity(w,source,TEMP_RECORD) == False:
                return bad(w,20)
            oldstate = get(w,TEMP_RECORD+200)
            newstate = get(w,source+200)
            if newstate == 0 and oldstate != 0:
                return done(w,0)
            same_elapsed = equal(w,source+224,TEMP_RECORD+224,16)
            if oldstate != 0 and (oldstate != newstate or same_elapsed == False):
                return bad(w,21)
            if oldstate == newstate and same_elapsed:
                return done(w,0)
            save(w,1,1)
        return step(w,4)
    if phase == 4:
        return procedure(w,M_ARCHIVE,ARCHIVE_FIND,5,arg(w,0),0,0,0,0,0,0,0)
    if phase == 5:
        directory = get(w,48)
        if directory == NONE:
            return done(w,NONE)
        if local(w,1) == 1 and directory == NEG2:
            return io_bad(w,NEG2)
        if local(w,1) == 0:
            if directory != NEG2:
                return io_bad(w,NEG17)
            directory = get(w,LEGACYFD)
            if get(w,LAYOUT) != 0:
                shard = hex_digit_value(byte(w,arg(w,0)))*16+hex_digit_value(byte(w,arg(w,0)+1))
                directory = get(w,SHARD_FDS+shard*8)
        save(w,0,directory)
        return procedure(w,M_RECORDS,RECORD_WRITE,6,directory,arg(w,0),arg(w,0),local(w,1),0,0,0,0)
    if phase == 6:
        if get(w,48) == NONE:
            return done(w,NONE)
        return procedure(w,M_ARCHIVE,ARCHIVE_FIND,7,arg(w,0),0,0,0,0,0,0,0)
    if phase == 7:
        if get(w,48) == NONE:
            return done(w,NONE)
        if get(w,48) != local(w,0):
            return bad(w,27)
        return procedure(w,M_ARCHIVE,ARCHIVE_FENCE,8,0,0,0,0,0,0,0,0)
    if phase == 8:
        return done(w,get(w,48))
    return bad(w,1)
'''
def source():return authored(SOURCE+'\n'+CODEC,text=TEXT)
