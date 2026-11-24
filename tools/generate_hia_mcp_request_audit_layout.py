"""HIA v12 directory-set loading and original epoch fences."""
from tools.generate_hia_mcp_request_audit_common import authored
from tools.generate_hia_mcp_request_audit_layout_codec import SOURCE as CODEC
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,frame(w)+16) == LAYOUT_OPEN:
        return open_layout(o,w)
    if get(w,frame(w)+16) == 2:
        return close_partial(o,w)
    return fence_layout(o,w)

def open_layout(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    if phase == 0:
        text_anchor12(w,at+1024)
        text_shards(w,at+1152)
        text_intent(w,at+1280)
        return procedure(w,M_LAYOUT,2,90,0,0,0,0,0,0,0,0)
    if phase == 90:
        return procedure(w,M_FILES,READ_FILE,1,get(w,ROOTFD),at+1024,PIN12_DATA,65536,PIN12FD,PIN12_STAMP,1,2)
    if phase == 1:
        size = get(w,48)
        if size == NONE:
            return done(w,NONE)
        if size == NEG2:
            return call(o,w,10,262,get(w,ROOTFD),at+1280,at+512,256,0,0,60)
        put(w,PIN12LEN,size)
        return json_decode(o,w,2,PIN12_DATA,size)
    if phase == 2:
        if json_ok(w,result) == False or layout_decode(w,LAYOUT_IDS,0) == False:
            return bad(w,25)
        if equal(w,LAYOUT_IDS,ROOT_STAMP,16) == False or equal(w,LAYOUT_IDS+16,LEGACY_STAMP,16) == False:
            return bad(w,25)
        return procedure(w,M_METADATA,0,91,get(w,PIN12FD),1,PIN12_STAMP,PIN12_DATA,get(w,PIN12LEN),at+1024,0,0)
    if phase == 91:
        if get(w,48) == NONE:
            return done(w,NONE)
        return procedure(w,M_FILES,OPEN_DIR,3,get(w,ROOTFD),at+1152,0,SHARD_ROOT_STAMP,0,0,0,0)
    if phase == 3:
        if get(w,48) == NONE or get(w,48) == NEG2:
            return bad(w,25)
        put(w,SHARDROOTFD,get(w,48))
        if equal(w,LAYOUT_IDS+32,SHARD_ROOT_STAMP,16) == False:
            return bad(w,25)
        save(w,0,0)
        return step(w,4)
    if phase == 4:
        index = local(w,0)
        if index == 256:
            return procedure(w,M_SCAN,0,6,get(w,SHARDROOTFD),HOT_NAMES,256,0,0,0,0,0)
        shard_name(w,index,at+1536)
        return procedure(w,M_FILES,OPEN_DIR,5,get(w,SHARDROOTFD),at+1536,0,SHARD_STAMPS+index*144,0,0,0,0)
    if phase == 5:
        if get(w,48) == NONE or get(w,48) == NEG2:
            return bad(w,25)
        index = local(w,0)
        put(w,SHARD_FDS+index*8,get(w,48))
        if equal(w,LAYOUT_IDS+64+index*16,SHARD_STAMPS+index*144,16) == False:
            return bad(w,25)
        save(w,0,index+1)
        return step(w,4)
    if phase == 6:
        if get(w,48) == NONE:
            return done(w,NONE)
        if layout_names(w,HOT_NAMES,get(w,48),at+2000) == False:
            return bad(w,25)
        return procedure(w,M_RECOVERY,1,7,0,0,0,0,0,0,0,0)
    if phase == 7:
        if get(w,48) == NONE:
            return done(w,NONE)
        put(w,LAYOUT,1)
        return procedure(w,M_LAYOUT,LAYOUT_FENCE,8,0,0,0,0,0,0,0,0)
    if phase == 8:
        return done(w,get(w,48))
    if phase == 10:
        if result == 0:
            return procedure(w,M_RECOVERY,0,13,0,0,0,0,0,0,0,0)
        if result != NEG2:
            return io_bad(w,result)
        return call(o,w,11,262,get(w,ROOTFD),at+1152,at+512,256,0,0,60)
    if phase == 11:
        if result != NEG2:
            return bad(w,25)
        return call(o,w,12,5,get(w,LEGACYFD),at+512,0,0,0,0,12)
    if phase == 12:
        if failed(result):
            return io_bad(w,result)
        if get(w,at+560) >= 67108864:
            return procedure(w,M_RECOVERY,0,13,1,0,0,0,0,0,0,0)
        put(w,LAYOUT,0)
        return done(w,0)
    if phase == 13:
        if get(w,48) == NONE:
            return done(w,NONE)
        return step(w,0)
    return bad(w,1)

def fence_layout(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    if phase == 0:
        text_anchor12(w,at+1024)
        text_shards(w,at+1152)
        text_intent(w,at+1280)
        if get(w,LAYOUT) == 0:
            return call(o,w,100,262,get(w,ROOTFD),at+1024,at+512,256,0,0,60)
        return procedure(w,M_FILES,FENCE_PIN,1,get(w,ROOTFD),at+1024,get(w,PIN12FD),PIN12_DATA,get(w,PIN12LEN),PIN12_STAMP,READ_DATA,0)
    if phase == 1:
        if get(w,48) == NONE:
            return done(w,NONE)
        return procedure(w,M_FILES,FENCE_DIR,2,get(w,ROOTFD),at+1152,get(w,SHARDROOTFD),SHARD_ROOT_STAMP,0,0,0,0)
    if phase == 2:
        if get(w,48) == NONE:
            return done(w,NONE)
        return call(o,w,3,262,get(w,ROOTFD),at+1280,at+512,256,0,0,60)
    if phase == 3:
        if result != NEG2:
            return bad(w,25)
        save(w,0,0)
        return step(w,4)
    if phase == 4:
        index = local(w,0)
        if index == 256:
            return procedure(w,M_SCAN,0,6,get(w,SHARDROOTFD),LAYOUT_NAMES,256,0,0,0,0,0)
        shard_name(w,index,at+1536)
        return procedure(w,M_FILES,FENCE_DIR,5,get(w,SHARDROOTFD),at+1536,get(w,SHARD_FDS+index*8),SHARD_STAMPS+index*144,0,0,0,0)
    if phase == 5:
        if get(w,48) == NONE:
            return done(w,NONE)
        save(w,0,local(w,0)+1)
        return step(w,4)
    if phase == 6:
        if get(w,48) == NONE:
            return done(w,NONE)
        if layout_names(w,LAYOUT_NAMES,get(w,48),at+2000) == False:
            return bad(w,25)
        return done(w,0)
    if phase == 100:
        if result != NEG2:
            return bad(w,25)
        return call(o,w,101,262,get(w,ROOTFD),at+1152,at+512,256,0,0,60)
    if phase == 101:
        if result != NEG2:
            return bad(w,25)
        return call(o,w,102,262,get(w,ROOTFD),at+1280,at+512,256,0,0,60)
    if phase == 102:
        if result != NEG2:
            return bad(w,25)
        return done(w,0)
    return bad(w,1)

def close_partial(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    if phase == 0:
        if get(w,LAYOUT) != 0:
            return bad(w,25)
        save(w,0,0)
        return step(w,1)
    if phase == 1:
        index = local(w,0)
        if index >= 258:
            return done(w,0)
        address = PIN12FD
        if index == 1:
            address = SHARDROOTFD
        elif index >= 2:
            address = SHARD_FDS+(index-2)*8
        descriptor = get(w,address)
        put(w,address,NONE)
        save(w,0,index+1)
        if descriptor == NONE:
            return step(w,1)
        return call(o,w,2,3,descriptor,0,0,0,0,0,0)
    if phase == 2:
        return step(w,1)
    return bad(w,1)
'''
def source():return authored(SOURCE+'\n'+CODEC,extra={'LAYOUT_IDS':569344,'LAYOUT_NAMES':(2<<20)+131072})
