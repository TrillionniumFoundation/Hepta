"""Actual canonical PosixPath parts, native joins, normalization and custody."""
from tools.generate_hia_clang_value_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    r=get(w,RESULT)
    if phase==200:
        return a_simple(w,201,A_V6,7,2)
    if phase==201:
        if a_ordinary(w)==False or get(w,A_VR+16)!=5:
            return a_unknown(w,201)
        put(w,A_PATH_COUNT,get(w,A_VR+48))
        put(w,A_PATH_INDEX,0)
        put(w,A_JOIN_N,0)
        return a_newmap(o,w,202,4096)
    if phase==202:
        if failed(r):
            return a_fail(w,18,errno(r))
        put(w,A_RAW_MAP,r)
        put(w,A_RAW_CAP,4096)
        return next_item(o,w)
    if phase==203:
        if a_ordinary(w)==False or a_capture(w,30,A_VR+8192+40)==False:
            return a_unknown(w,203)
        return a_simple(w,204,A_V6,7,30)
    if phase==204:
        if a_ordinary(w)==False or get(w,A_VR+16)!=4:
            return a_unknown(w,204)
        put(w,A_ITEM_N,get(w,A_VR+72))
        put(w,A_ITEM_OFFSET,0)
        put(w,840,0)
        if get(w,A_ITEM_N)==0:
            return drop_item(w)
        return export_item(w)
    if phase==205:
        if a_ordinary(w)==False or get(w,A_VR+64)!=get(w,A_AMOUNT):
            return a_unknown(w,205)
        if get(w,A_ITEM_OFFSET)==0:
            if byte(w,A_VR+8192)==47:
                put(w,A_JOIN_N,0)
            elif get(w,A_JOIN_N)!=0:
                put(w,840,1)
            total=get(w,A_JOIN_N)+get(w,840)
            if get(w,A_ITEM_N)>9223372036854771584-total:
                return a_fail(w,18,12)
            need=(total+get(w,A_ITEM_N)+4223)&18446744073709547520
            if need>get(w,A_RAW_CAP):
                put(w,848,need)
                return call(o,w,206,25,get(w,A_RAW_MAP),get(w,A_RAW_CAP),need,1,0,0,0)
        return append_item(w)
    if phase==206:
        if failed(r):
            return a_fail(w,18,errno(r))
        put(w,A_RAW_MAP,r)
        put(w,A_RAW_CAP,get(w,848))
        return append_item(w)
    if phase==207:
        if r!=0:
            return a_unknown(w,207)
        put(w,A_JOIN_N,get(w,A_JOIN_N)+1)
        put(w,840,0)
        return copy_piece(w)
    if phase==208:
        if r!=0:
            return a_unknown(w,208)
        put(w,A_JOIN_N,get(w,A_JOIN_N)+get(w,A_AMOUNT))
        put(w,A_ITEM_OFFSET,get(w,A_ITEM_OFFSET)+get(w,A_AMOUNT))
        if get(w,A_ITEM_OFFSET)==get(w,A_ITEM_N):
            return drop_item(w)
        return export_item(w)
    if phase==209:
        if a_cap_drop_valid(w)==False:
            return a_unknown(w,209)
        if get(w,A_VR+104)!=0:
            put(w,A_TOKEN_PENDING,1)
        if get(w,A_VR+96)!=1:
            return a_value_failed(w,209)
        clear(w,A_REFS+30*32,32)
        put(w,A_PATH_INDEX,get(w,A_PATH_INDEX)+1)
        return next_item(o,w)
    if phase==231:
        if failed(r):
            return a_fail(w,18,errno(r))
        put(w,A_PATH_MAP,r)
        put(w,A_PATH_CAP,get(w,A_RAW_CAP))
        put(w,A_BUFFER_OP,2)
        return a_invoke(w,232,4,get(w,A_RAW_MAP)+128,get(w,A_JOIN_N),r+128,get(w,A_PATH_CAP)-128,a_at(w,0),A_WORK)
    if phase==232:
        if r==0 or r>get(w,A_PATH_CAP)-128:
            return a_unknown(w,232)
        raw=get(w,A_RAW_MAP)
        cap=get(w,A_RAW_CAP)
        put(w,A_RAW_MAP,get(w,A_PATH_MAP))
        put(w,A_RAW_CAP,get(w,A_PATH_CAP))
        put(w,A_PATH_MAP,raw)
        put(w,A_PATH_CAP,cap)
        put(w,A_RAW_N,r)
        put(w,A_KIND,4)
        put(w,A_BYTE_ORIGIN,0)
        put(w,A_BUFFER_OP,0)
        return a_invoke(w,233,4,0,0,get(w,A_RAW_MAP),get(w,A_RAW_CAP),a_at(w,0),A_WORK)
    if phase==233:
        if r!=0:
            return a_unknown(w,233)
        return jump(w,508)
    return 4294967293

def next_item(o:mutbuf,w:mutbuf) -> u32:
    if get(w,A_PATH_INDEX)==get(w,A_PATH_COUNT):
        return a_newmap(o,w,231,get(w,A_RAW_CAP))
    a_request(w,A_V1,23)
    a_arg(w,2,24)
    put(w,A_RQ+104,get(w,A_PATH_INDEX))
    put(w,A_RQ+112,1)
    return a_value(w,203,128)

def export_item(w:mutbuf) -> u32:
    amount=get(w,A_ITEM_N)-get(w,A_ITEM_OFFSET)
    if amount>8192:
        amount=8192
    put(w,A_AMOUNT,amount)
    a_request(w,A_V6,19)
    a_arg(w,30,24)
    put(w,A_RQ+104,get(w,A_ITEM_OFFSET))
    put(w,A_RQ+112,amount)
    return a_value(w,205,128)

def append_item(w:mutbuf) -> u32:
    if get(w,840)==1:
        store(w,A_RQ+2048,47)
        return a_copy(w,207,a_at(w,A_RQ+2048),get(w,A_RAW_MAP)+128+get(w,A_JOIN_N),1)
    return copy_piece(w)

def copy_piece(w:mutbuf) -> u32:
    return a_copy(w,208,a_at(w,A_VR+8192),get(w,A_RAW_MAP)+128+get(w,A_JOIN_N),get(w,A_AMOUNT))

def drop_item(w:mutbuf) -> u32:
    return a_simple(w,209,A_V5,78,30)
'''
if __name__=='__main__':write_module('clang_value_path',SOURCE)
