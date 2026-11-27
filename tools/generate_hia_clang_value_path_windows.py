"""Native Value path parts and real PureWindowsPath class MRO."""
from tools.generate_hia_clang_value_error_common import write_module
from tools.generate_hia_clang_value_path import SOURCE as ORIGINAL
SOURCE=ORIGINAL
old="""    if phase==200:
        return a_simple(w,201,A_V6,7,2)"""
new="""    if phase==250:
        a_request(w,A_V6,32)
        put(w,A_RQ+104,16)
        return a_value(w,251,128)
    if phase==251:
        if a_ordinary(w)==False or a_capture(w,31,A_VR+24)==False:
            return a_value_failed(w,251)
        a_request(w,A_V6,37)
        a_arg(w,0,24)
        a_arg(w,31,48)
        return a_value(w,252,128)
    if phase==252:
        if a_ordinary(w)==False or get(w,A_VR+48)>1:
            return a_value_failed(w,252)
        put(w,A_WINDOWS,get(w,A_VR+48))
        return jump(w,200)
    if phase==200:
        return a_simple(w,201,A_V6,7,2)"""
assert SOURCE.count(old)==1;SOURCE=SOURCE.replace(old,new)
old="""            if byte(w,A_VR+8192)==47:
                put(w,A_JOIN_N,0)
            elif get(w,A_JOIN_N)!=0:
                put(w,840,1)"""
new="""            if get(w,A_WINDOWS)==1:
                put(w,840,8)
            elif byte(w,A_VR+8192)==47:
                put(w,A_JOIN_N,0)
            elif get(w,A_JOIN_N)!=0:
                put(w,840,1)"""
assert SOURCE.count(old)==1;SOURCE=SOURCE.replace(old,new)
old="""        put(w,A_JOIN_N,get(w,A_JOIN_N)+1)
        put(w,840,0)"""
new="""        put(w,A_JOIN_N,get(w,A_JOIN_N)+get(w,840))
        put(w,840,0)"""
assert SOURCE.count(old)==1;SOURCE=SOURCE.replace(old,new)
old="""        put(w,A_BUFFER_OP,2)
        return a_invoke(w,232,4,get(w,A_RAW_MAP)+128,get(w,A_JOIN_N),r+128,get(w,A_PATH_CAP)-128,a_at(w,0),A_WORK)"""
new="""        put(w,A_BUFFER_OP,2)
        return a_invoke(w,232,choose(get(w,A_WINDOWS)==1,7,4),get(w,A_RAW_MAP)+128,get(w,A_JOIN_N),r+128,get(w,A_PATH_CAP)-128,a_at(w,0),A_WORK)"""
assert SOURCE.count(old)==1;SOURCE=SOURCE.replace(old,new)
old="""def append_item(w:mutbuf) -> u32:
    if get(w,840)==1:"""
new="""def append_item(w:mutbuf) -> u32:
    if get(w,840)==8:
        put(w,A_RQ+2048,get(w,A_ITEM_N))
        return a_copy(w,207,a_at(w,A_RQ+2048),get(w,A_RAW_MAP)+128+get(w,A_JOIN_N),8)
    if get(w,840)==1:"""
assert SOURCE.count(old)==1;SOURCE=SOURCE.replace(old,new)
if __name__=='__main__':write_module('clang_value_path_windows',SOURCE)
