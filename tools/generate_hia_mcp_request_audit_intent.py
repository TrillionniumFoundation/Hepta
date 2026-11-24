"""HIA exact v12 intent admission and durable monotone prefix publication."""
from tools.generate_hia_mcp_request_audit_common import authored
from tools.generate_hia_mcp_request_audit_layout_codec import SOURCE as CODEC
TEXT={'layout_head':'{"format":12,"root":','layout_legacy':',"legacy":',
      'layout_archive':',"archive":','layout_shards':',"shards":[','layout_end':']}'}
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,frame(w)+16) == 0:
        return read_intent(o,w)
    return persist(o,w)

def read_intent(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    if phase == 0:
        save(w,0,NONE)
        text_intent(w,at+1024)
        return procedure(w,M_FILES,READ_FILE,1,get(w,ROOTFD),at+1024,INTENT_DATA,65536,at+160,at+512,1,2)
    if phase == 1:
        if get(w,48) == NONE or get(w,48) == NEG2:
            return done(w,get(w,48))
        save(w,1,get(w,48))
        return json_decode(o,w,2,INTENT_DATA,local(w,1))
    if phase == 2:
        fill_range(w,arg(w,0),4224,0)
        if json_ok(w,result) == False or layout_decode(w,arg(w,0),1) == False or bound_ids(w,arg(w,0)) == False:
            return intent_error(o,w,32,0)
        return procedure(w,M_ARCHIVE,ARCHIVE_FENCE,3,1,0,0,0,0,0,0,0)
    if phase == 3:
        if get(w,48) == NONE:
            return intent_error(o,w,get(w,96),get(w,104))
        return procedure(w,M_METADATA,0,4,local(w,0),0,at+512,INTENT_DATA,local(w,1),at+1024,0,0)
    if phase == 4:
        if get(w,48) == NONE:
            return intent_error(o,w,get(w,96),get(w,104))
        return call(o,w,5,3,local(w,0),0,0,0,0,0,0)
    if phase == 5:
        return done(w,0)
    if phase == 99:
        return done(w,NONE)
    return intent_error(o,w,1,0)

def intent_error(o:mutbuf,w:mutbuf,reason:u64,error:u64) -> u32:
    put(w,96,reason)
    put(w,104,error)
    if local(w,0) != NONE:
        return call(o,w,99,3,local(w,0),0,0,0,0,0,0)
    return done(w,NONE)

def bound_ids(w:mutbuf,ids:u64) -> bool:
    return equal(w,ids,ROOT_STAMP,16) and equal(w,ids+16,LEGACY_STAMP,16) and get(w,ids+48) <= 256 and get(w,ids+56) <= 1 and (get(w,ids+56) != 0 or get(w,ids+48) == 0)

def monotone(w:mutbuf,old:u64,new:u64) -> bool:
    a = get(w,old+48)
    b = get(w,new+48)
    if equal(w,old,new,32) == False or a > b or b > a+1:
        return False
    if get(w,old+56) != 0:
        if get(w,new+56) == 0 or equal(w,old+32,new+32,16) == False:
            return False
    return equal(w,old+64,new+64,a*16)

def persist(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    ids = arg(w,0)
    if phase == 0:
        if bound_ids(w,ids) == False:
            return bad(w,32)
        if arg(w,2) != 0:
            if get(w,ids+48) != 256 or get(w,ids+56) != 1:
                return bad(w,32)
            return step(w,10)
        if arg(w,1) != 0:
            return step(w,10)
        return procedure(w,M_INTENT,0,1,INTENT_OLD,0,0,0,0,0,0,0)
    if phase == 1:
        if get(w,48) == NONE:
            return done(w,NONE)
        if get(w,48) == NEG2 or monotone(w,INTENT_OLD,ids) == False:
            return bad(w,32)
        return step(w,10)
    if phase == 10:
        return procedure(w,M_ARCHIVE,ARCHIVE_FENCE,11,1,0,0,0,0,0,0,0)
    if phase == 11:
        if get(w,48) == NONE:
            return done(w,NONE)
        save(w,0,0)
        return step(w,12)
    if phase == 12:
        return call(o,w,13,318,at+1500+local(w,0),32-local(w,0),0,0,0,0,3)
    if phase == 13:
        if result == NEG4:
            return step(w,12)
        if failed(result) or result == 0 or result > 32-local(w,0):
            return io_bad(w,result)
        save(w,0,local(w,0)+result)
        if local(w,0) < 32:
            return step(w,12)
        return step(w,14)
    if phase == 14:
        end = text_init_prefix(w,at+1600)
        text_intent(w,at+1024)
        replace = 0
        if arg(w,1) == 0:
            replace = 1
        if arg(w,2) != 0:
            end = text_shard_prefix(w,at+1600)
            text_anchor12(w,at+1024)
            replace = 0
        end = encode_hex(w,at+1500,end)
        text_tmp(w,end)
        size = render_layout(w,ids,JSON_DATA)
        if size > 65536:
            return bad(w,32)
        return procedure(w,M_WRITE,0,15,get(w,ROOTFD),at+1024,at+1600,JSON_DATA,size,replace,0,0)
    if phase == 15:
        return done(w,get(w,48))
    return bad(w,1)

def identity_render(w:mutbuf,ids:u64,at:u64) -> u64:
    store(w,at,91)
    at = decimal(w,at+1,get(w,ids))
    store(w,at,44)
    at = decimal(w,at+1,get(w,ids+8))
    store(w,at,93)
    return at+1

def render_layout(w:mutbuf,ids:u64,target:u64) -> u64:
    at = text_layout_head(w,target)
    at = identity_render(w,ids,at)
    at = text_layout_legacy(w,at)
    at = identity_render(w,ids+16,at)
    at = text_layout_archive(w,at)
    if get(w,ids+56) == 0:
        at = text_null(w,at)
    else:
        at = identity_render(w,ids+32,at)
    at = text_layout_shards(w,at)
    index = 0
    while index < get(w,ids+48):
        if index != 0:
            store(w,at,44)
            at = at+1
        at = identity_render(w,ids+64+index*16,at)
        index = index+1
    at = text_layout_end(w,at)
    return at-target
'''
def source():return authored(SOURCE+'\n'+CODEC,text=TEXT)
