"""HIA durable v12 prefix initialization, exact crash recovery and final commit."""
from tools.generate_hia_mcp_request_audit_common import authored
from tools.generate_hia_mcp_request_audit_layout_codec import SOURCE as CODEC
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,frame(w)+16) == 1:
        return finish_intent(o,w)
    phase = get(w,0)
    if phase < 10:
        return begin_initialization(o,w)
    if phase < 20:
        return validate_prefix(o,w)
    if phase < 30:
        return extend_prefix(o,w)
    return publish_layout(o,w)

def finish_intent(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    if phase == 0:
        return procedure(w,M_INTENT,0,1,INTENT_IDS,0,0,0,0,0,0,0)
    if phase == 1:
        if get(w,48) == NONE:
            return done(w,NONE)
        if get(w,48) == NEG2:
            return done(w,0)
        if equal(w,INTENT_IDS,LAYOUT_IDS,4160) == False:
            return bad(w,32)
        text_intent(w,at+1024)
        return call(o,w,2,263,get(w,ROOTFD),at+1024,0,0,0,0,12)
    if phase == 2:
        if failed(result):
            return io_bad(w,result)
        return call(o,w,3,74,get(w,ROOTFD),0,0,0,0,0,0)
    if phase == 3:
        if failed(result):
            return io_bad(w,result)
        return done(w,0)
    return bad(w,1)

def begin_initialization(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    if phase == 0:
        text_shards(w,at+1024)
        return procedure(w,M_INTENT,0,1,INTENT_IDS,0,0,0,0,0,0,0)
    if phase == 1:
        if get(w,48) == NONE:
            return done(w,NONE)
        if get(w,48) != NEG2:
            return step(w,3)
        if arg(w,0) != 1:
            return bad(w,32)
        return procedure(w,M_ARCHIVE,ARCHIVE_FENCE,2,0,0,0,0,0,0,0,0)
    if phase == 2:
        if get(w,48) == NONE:
            return done(w,NONE)
        fill_range(w,INTENT_IDS,4224,0)
        copy_state(w,ROOT_STAMP,INTENT_IDS,16)
        copy_state(w,LEGACY_STAMP,INTENT_IDS+16,16)
        return procedure(w,M_INTENT,1,3,INTENT_IDS,1,0,0,0,0,0,0)
    if phase == 3:
        if get(w,48) == NONE:
            return done(w,NONE)
        return procedure(w,M_ARCHIVE,ARCHIVE_FENCE,4,1,0,0,0,0,0,0,0)
    if phase == 4:
        if get(w,48) == NONE:
            return done(w,NONE)
        return call(o,w,5,262,get(w,ROOTFD),at+1024,at+512,256,0,0,60)
    if phase == 5:
        if result == NEG2:
            if get(w,INTENT_IDS+56) != 0:
                return bad(w,32)
            return call(o,w,6,258,get(w,ROOTFD),at+1024,448,0,0,0,12)
        if failed(result):
            return io_bad(w,result)
        return procedure(w,M_FILES,OPEN_DIR,8,get(w,ROOTFD),at+1024,0,SHARD_ROOT_STAMP,0,0,0,0)
    if phase == 6:
        if failed(result):
            return io_bad(w,result)
        return call(o,w,7,74,get(w,ROOTFD),0,0,0,0,0,0)
    if phase == 7:
        if failed(result):
            return io_bad(w,result)
        return procedure(w,M_FILES,OPEN_DIR,8,get(w,ROOTFD),at+1024,0,SHARD_ROOT_STAMP,0,0,0,0)
    if phase == 8:
        if get(w,48) == NONE:
            return done(w,NONE)
        if get(w,48) == NEG2:
            return bad(w,32)
        put(w,SHARDROOTFD,get(w,48))
        if get(w,INTENT_IDS+56) != 0:
            if equal(w,INTENT_IDS+32,SHARD_ROOT_STAMP,16) == False:
                return bad(w,32)
            return step(w,10)
        return procedure(w,M_SCAN,0,9,get(w,SHARDROOTFD),0,0,4,0,0,0,0)
    if phase == 9:
        if get(w,48) == NONE:
            return done(w,NONE)
        if get(w,48) != 0:
            return bad(w,32)
        copy_state(w,SHARD_ROOT_STAMP,INTENT_IDS+32,16)
        put(w,INTENT_IDS+56,1)
        return procedure(w,M_INTENT,1,10,INTENT_IDS,0,0,0,0,0,0,0)
    return bad(w,1)

def prefix_names(w:mutbuf,names:u64,count:u64,maximum:u64,seen:u64) -> bool:
    fill_range(w,seen,256,0)
    index = 0
    while index < count:
        name = names+index*144
        if get(w,name+136) != 2 or lowerhex(w,name,2) == False:
            return False
        value = hex_digit_value(byte(w,name))*16+hex_digit_value(byte(w,name+1))
        if value > maximum or byte(w,seen+value) != 0:
            return False
        store(w,seen+value,1)
        index = index+1
    index = 0
    while index < maximum:
        if byte(w,seen+index) == 0:
            return False
        index = index+1
    return True

def validate_prefix(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    at = frame(w)
    if phase == 10:
        if get(w,48) == NONE:
            return done(w,NONE)
        return procedure(w,M_SCAN,0,11,get(w,SHARDROOTFD),LAYOUT_NAMES,257,0,0,0,0,0)
    if phase == 11:
        if get(w,48) == NONE:
            return done(w,NONE)
        if prefix_names(w,LAYOUT_NAMES,get(w,48),get(w,INTENT_IDS+48),at+2500) == False:
            return bad(w,32)
        save(w,0,0)
        return step(w,12)
    if phase == 12:
        index = local(w,0)
        while index < 256 and byte(w,at+2500+index) == 0:
            index = index+1
        save(w,0,index)
        if index == 256:
            save(w,0,get(w,INTENT_IDS+48))
            return step(w,20)
        shard_name(w,index,at+1536)
        return procedure(w,M_FILES,OPEN_DIR,13,get(w,SHARDROOTFD),at+1536,0,SHARD_STAMPS+index*144,0,0,0,0)
    if phase == 13:
        if get(w,48) == NONE:
            return done(w,NONE)
        if get(w,48) == NEG2:
            return bad(w,32)
        index = local(w,0)
        put(w,SHARD_FDS+index*8,get(w,48))
        if index < get(w,INTENT_IDS+48) and equal(w,INTENT_IDS+64+index*16,SHARD_STAMPS+index*144,16) == False:
            return bad(w,32)
        return procedure(w,M_SCAN,0,14,get(w,SHARD_FDS+index*8),0,0,4,0,0,0,0)
    if phase == 14:
        if get(w,48) == NONE:
            return done(w,NONE)
        if get(w,48) != 0:
            return bad(w,32)
        save(w,0,local(w,0)+1)
        return step(w,12)
    return bad(w,1)

def extend_prefix(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    index = local(w,0)
    if phase == 20:
        if index == 256:
            return call(o,w,30,74,get(w,SHARDROOTFD),0,0,0,0,0,0)
        shard_name(w,index,at+1536)
        if byte(w,at+2500+index) != 0:
            return procedure(w,M_FILES,FENCE_DIR,24,get(w,SHARDROOTFD),at+1536,get(w,SHARD_FDS+index*8),SHARD_STAMPS+index*144,0,0,0,0)
        return call(o,w,21,258,get(w,SHARDROOTFD),at+1536,448,0,0,0,12)
    if phase == 21:
        if failed(result):
            return io_bad(w,result)
        return procedure(w,M_FILES,OPEN_DIR,22,get(w,SHARDROOTFD),at+1536,0,SHARD_STAMPS+index*144,0,0,0,0)
    if phase == 22:
        if get(w,48) == NONE:
            return done(w,NONE)
        if get(w,48) == NEG2:
            return bad(w,32)
        put(w,SHARD_FDS+index*8,get(w,48))
        return step(w,24)
    if phase == 24:
        if get(w,48) == NONE:
            return done(w,NONE)
        return procedure(w,M_SCAN,0,25,get(w,SHARD_FDS+index*8),0,0,4,0,0,0,0)
    if phase == 25:
        if get(w,48) == NONE:
            return done(w,NONE)
        if get(w,48) != 0:
            return bad(w,32)
        return call(o,w,26,74,get(w,SHARD_FDS+index*8),0,0,0,0,0,0)
    if phase == 26:
        if failed(result):
            return io_bad(w,result)
        return call(o,w,27,74,get(w,SHARDROOTFD),0,0,0,0,0,0)
    if phase == 27:
        if failed(result):
            return io_bad(w,result)
        copy_state(w,SHARD_STAMPS+index*144,INTENT_IDS+64+index*16,16)
        put(w,INTENT_IDS+48,index+1)
        return procedure(w,M_INTENT,1,28,INTENT_IDS,0,0,0,0,0,0,0)
    if phase == 28:
        if get(w,48) == NONE:
            return done(w,NONE)
        save(w,0,index+1)
        return step(w,20)
    return bad(w,1)

def publish_layout(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    index = local(w,0)
    if phase == 30:
        if failed(result):
            return io_bad(w,result)
        return call(o,w,31,74,get(w,ROOTFD),0,0,0,0,0,0)
    if phase == 31:
        if failed(result):
            return io_bad(w,result)
        return procedure(w,M_ARCHIVE,ARCHIVE_FENCE,32,1,0,0,0,0,0,0,0)
    if phase == 32:
        if get(w,48) == NONE:
            return done(w,NONE)
        return procedure(w,M_SCAN,0,33,get(w,SHARDROOTFD),LAYOUT_NAMES,256,0,0,0,0,0)
    if phase == 33:
        if get(w,48) == NONE:
            return done(w,NONE)
        if layout_names(w,LAYOUT_NAMES,get(w,48),at+2500) == False:
            return bad(w,32)
        save(w,0,0)
        return step(w,34)
    if phase == 34:
        if index == 256:
            return procedure(w,M_INTENT,1,40,INTENT_IDS,1,1,0,0,0,0,0)
        shard_name(w,index,at+1536)
        return procedure(w,M_FILES,FENCE_DIR,35,get(w,SHARDROOTFD),at+1536,get(w,SHARD_FDS+index*8),SHARD_STAMPS+index*144,0,0,0,0)
    if phase == 35:
        if get(w,48) == NONE:
            return done(w,NONE)
        return procedure(w,M_SCAN,0,36,get(w,SHARD_FDS+index*8),0,0,4,0,0,0,0)
    if phase == 36:
        if get(w,48) == NONE:
            return done(w,NONE)
        if get(w,48) != 0:
            return bad(w,32)
        save(w,0,index+1)
        return step(w,34)
    if phase == 40:
        if get(w,48) == NONE:
            return done(w,NONE)
        copy_state(w,INTENT_IDS,LAYOUT_IDS,4160)
        return procedure(w,M_RECOVERY,1,41,0,0,0,0,0,0,0,0)
    if phase == 41:
        return done(w,get(w,48))
    return bad(w,1)
'''
def source():return authored(SOURCE+'\n'+CODEC)
