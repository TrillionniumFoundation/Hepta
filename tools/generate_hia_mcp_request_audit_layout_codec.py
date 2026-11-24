"""The exact v12 anchor/intent JSON shape and bounded identities in HIA."""
from tools.generate_hia_mcp_request_audit_codec import SOURCE as RECORD_CODEC
SOURCE=RECORD_CODEC+r'''
def identity_decode(w:mutbuf,row:u64,target:u64) -> bool:
    if row == NONE or get(w,row) != 5:
        return False
    first = get(w,row+24)
    if first == NONE:
        return False
    first = ARENA+64+first*72
    second = get(w,first+16)
    if second == NONE:
        return False
    second = ARENA+64+second*72
    if get(w,second+16) != NONE:
        return False
    if scalar_number(w,first,target) == False or scalar_number(w,second,target+16) == False:
        return False
    put(w,target+8,get(w,target+16))
    return True

def layout_decode(w:mutbuf,target:u64,partial:u64) -> bool:
    root = ARENA+64
    if fields_exact(w,root,31744,31744) == False:
        return False
    if scalar_number(w,audit_field(w,root,11),25000) == False or get(w,25000) != 12:
        return False
    if identity_decode(w,audit_field(w,root,12),target) == False or identity_decode(w,audit_field(w,root,13),target+16) == False:
        return False
    archive = audit_field(w,root,14)
    if partial != 0 and archive != NONE and get(w,archive) == 0:
        put(w,target+32,0)
        put(w,target+40,0)
        put(w,target+56,0)
    else:
        if identity_decode(w,archive,target+32) == False:
            return False
        put(w,target+56,1)
    shards = audit_field(w,root,15)
    if shards == NONE or get(w,shards) != 5:
        return False
    count = 0
    child = get(w,shards+24)
    while child != NONE:
        if count >= 256:
            return False
        row = ARENA+64+child*72
        if identity_decode(w,row,target+64+count*16) == False:
            return False
        count = count+1
        child = get(w,row+16)
    put(w,target+48,count)
    if partial == 0 and count != 256:
        return False
    if get(w,target+56) == 0 and count != 0:
        return False
    return True

def shard_name(w:mutbuf,index:u64,target:u64) -> u64:
    store(w,target,hex_digit(index >> 4))
    store(w,target+1,hex_digit(index & 15))
    store(w,target+2,0)
    return target

def layout_names(w:mutbuf,source:u64,count:u64,seen:u64) -> bool:
    if count != 256:
        return False
    fill_range(w,seen,256,0)
    index = 0
    while index < count:
        name = source+index*144
        if get(w,name+136) != 2 or lowerhex(w,name,2) == False:
            return False
        value = hex_digit_value(byte(w,name))*16+hex_digit_value(byte(w,name+1))
        if byte(w,seen+value) != 0:
            return False
        store(w,seen+value,1)
        index = index+1
    return True
'''
