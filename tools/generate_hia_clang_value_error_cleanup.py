"""Native cleanup exceptions with original exception context and held path custody."""
from tools.generate_hia_clang_value_error_plan_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    if phase==2100:
        if get(w,E_CLEAN_STAGE)!=1 or get(w,A_INNER_WORK+2544)!=0x3146434543414948:
            return broken(w,2100)
        if get(w,A_UNKNOWN)!=0:
            put(w,E_CLEAN_STAGE,2)
            return jump(w,700)
        put(w,E_CLEAN_REF,32)
        return release_temporary(w)
    if phase==2101:
        index=get(w,E_CLEAN_REF)
        if a_cap_drop_valid(w)==False:
            return broken(w,2101)
        if get(w,A_VR+96)==1:
            clear(w,A_REFS+index*32,32)
        if get(w,A_VR+8)!=0 or get(w,A_VR+80)!=0 or get(w,A_VR+104)!=0 or get(w,A_VR+112)!=0:
            a_clean_error(w,16,get(w,A_VR+8))
            put(w,A_TOKEN_PENDING,1)
        if get(w,A_VR+96)!=1:
            return broken(w,2101)
        put(w,E_CLEAN_REF,index+1)
        return release_temporary(w)
    if phase==2102:
        return path_begin(o,w)
    if phase==2103:
        return path_count(o,w)
    if phase==2104:
        if failed(get(w,RESULT)):
            if errno(get(w,RESULT))==12:
                return cleanup_recipe(w,True)
            return broken(w,2104)
        put(w,E_CLEAN_MAP,get(w,RESULT))
        return base_copy(w)
    if phase==2105:
        if get(w,RESULT)!=0:
            return broken(w,2105)
        put(w,E_PATH_POS,get(w,E_PATH_N))
        put(w,E_PATH_NODE,get(w,A_INNER_WORK+2416+112))
        put(w,E_PATH_DEPTH,get(w,A_INNER_WORK+2416+120))
        if get(w,E_PATH_EXTRA_N)!=0:
            put(w,E_PATH_IS_EXTRA,1)
            put(w,E_PATH_POS,get(w,E_PATH_POS)-get(w,E_PATH_EXTRA_N))
            return a_copy(w,2112,get(w,E_PATH_EXTRA),get(w,E_CLEAN_MAP)+get(w,E_PATH_POS),get(w,E_PATH_EXTRA_N))
        return path_next(w)
    if phase==2111:
        return path_part(w)
    if phase==2112:
        if get(w,RESULT)!=0 or get(w,E_PATH_POS)==0:
            return broken(w,2112)
        put(w,E_PATH_POS,get(w,E_PATH_POS)-1)
        store(w,A_RQ,47)
        return a_copy(w,2113,a_at(w,A_RQ),get(w,E_CLEAN_MAP)+get(w,E_PATH_POS),1)
    if phase==2113:
        if get(w,RESULT)!=0:
            return broken(w,2113)
        if get(w,E_PATH_IS_EXTRA)==1:
            put(w,E_PATH_IS_EXTRA,0)
        else:
            put(w,E_PATH_NODE,get(w,E_PATH_PREV))
            put(w,E_PATH_DEPTH,get(w,E_PATH_DEPTH)-1)
        return path_next(w)
    return broken(w,phase)

def broken(w:mutbuf,phase:u64) -> u32:
    put(w,E_CLEAN_STAGE,2)
    put(w,ERROR,get(w,E_TOP_ERROR))
    put(w,ERROR_NO,get(w,E_TOP_ERRNO))
    return a_unknown(w,phase)

def release_temporary(w:mutbuf) -> u32:
    index=get(w,E_CLEAN_REF)
    while index<64 and get(w,A_REFS+index*32+24)==0:
        index=index+1
    put(w,E_CLEAN_REF,index)
    if index==64:
        return jump(w,2102)
    return a_simple(w,2101,A_V5,78,index)

def path_begin(o:mutbuf,w:mutbuf) -> u32:
    kind=get(w,A_INNER_WORK+2552)
    if kind==2:
        return cleanup_recipe(w,False)
    if kind!=1 or get(w,A_INNER_WORK+2416)!=0x3152544d52414948 or get(w,A_INNER_WORK+2416+32)!=1:
        return broken(w,2102)
    phase=get(w,A_INNER_WORK+2416+24)
    number=0-get(w,A_INNER_WORK+2416+16)
    if number==12 and (phase==102 or phase==106 or phase==151):
        return cleanup_recipe(w,True)
    n=get(w,A_INNER_WORK+904)
    if n==0 or get(w,A_INNER_WORK+616)==0:
        return broken(w,2102)
    put(w,E_PATH_N,n)
    put(w,E_PATH_EXTRA,0)
    put(w,E_PATH_EXTRA_N,0)
    put(w,E_PATH_IS_EXTRA,0)
    if phase==131 or phase==141:
        ptr=get(w,A_INNER_WORK+295698432+304)
        count=get(w,A_INNER_WORK+295698432+312)
        if ptr==0 or count==0 or count>9223372036854771710-n:
            return broken(w,2102)
        put(w,E_PATH_EXTRA,ptr)
        put(w,E_PATH_EXTRA_N,count)
        put(w,E_PATH_N,n+1+count)
    put(w,E_PATH_NODE,get(w,A_INNER_WORK+2416+112))
    put(w,E_PATH_DEPTH,get(w,A_INNER_WORK+2416+120))
    return count_next(o,w)

def count_next(o:mutbuf,w:mutbuf) -> u32:
    if get(w,E_PATH_DEPTH)<=1:
        return path_allocate(o,w)
    if get(w,E_PATH_NODE)==0:
        return broken(w,2103)
    return a_copy(w,2103,get(w,E_PATH_NODE),a_at(w,A_ERROR_FRAME),256)

def path_count(o:mutbuf,w:mutbuf) -> u32:
    if get(w,RESULT)!=0 or get(w,A_ERROR_FRAME+72)!=get(w,E_PATH_DEPTH):
        return broken(w,2103)
    n=get(w,A_ERROR_FRAME+32)
    if n==0 or get(w,A_ERROR_FRAME+24)==0 or get(w,A_ERROR_FRAME)==0 or n>9223372036854771710-get(w,E_PATH_N):
        return broken(w,2103)
    put(w,E_PATH_N,get(w,E_PATH_N)+1+n)
    put(w,E_PATH_NODE,get(w,A_ERROR_FRAME))
    put(w,E_PATH_DEPTH,get(w,E_PATH_DEPTH)-1)
    return count_next(o,w)

def path_allocate(o:mutbuf,w:mutbuf) -> u32:
    need=(get(w,E_PATH_N)+4095)&18446744073709547520
    if get(w,E_CLEAN_MAP)!=0 and get(w,E_CLEAN_CAP)>=need:
        return base_copy(w)
    if get(w,E_CLEAN_MAP)!=0:
        return broken(w,2104)
    put(w,E_CLEAN_CAP,need)
    return call(o,w,2104,9,0,need,3,34,NONE,0,0)

def base_copy(w:mutbuf) -> u32:
    ptr=get(w,A_INNER_WORK+616)+get(w,A_INNER_WORK+912)
    return a_copy(w,2105,ptr,get(w,E_CLEAN_MAP),get(w,A_INNER_WORK+904))

def path_next(w:mutbuf) -> u32:
    if get(w,E_PATH_DEPTH)<=1:
        if get(w,E_PATH_POS)!=get(w,A_INNER_WORK+904):
            return broken(w,2111)
        return cleanup_recipe(w,False)
    if get(w,E_PATH_NODE)==0:
        return broken(w,2111)
    return a_copy(w,2111,get(w,E_PATH_NODE),a_at(w,A_ERROR_FRAME),256)

def path_part(w:mutbuf) -> u32:
    if get(w,RESULT)!=0 or get(w,A_ERROR_FRAME+72)!=get(w,E_PATH_DEPTH):
        return broken(w,2111)
    n=get(w,A_ERROR_FRAME+32)
    if n==0 or n>=get(w,E_PATH_POS) or get(w,A_ERROR_FRAME+24)==0 or get(w,A_ERROR_FRAME)==0:
        return broken(w,2111)
    put(w,E_PATH_PREV,get(w,A_ERROR_FRAME))
    put(w,E_PATH_POS,get(w,E_PATH_POS)-n)
    put(w,E_PATH_IS_EXTRA,0)
    return a_copy(w,2112,get(w,A_ERROR_FRAME+24),get(w,E_CLEAN_MAP)+get(w,E_PATH_POS),n)

def cleanup_recipe(w:mutbuf,memory:bool) -> u32:
    put(w,E_PLAN_COUNT,0)
    put(w,E_PLAN_INDEX,0)
    put(w,E_TEXT_N,0)
    put(w,E_BAD,0)
    if memory:
        e_class(w,32,27)
        e_list(w,35)
        e_tuple(w,37,35)
        e_exception(w,44,32,37,NONE)
    else:
        e_class(w,32,25)
        number=0-get(w,A_INNER_WORK+2416+16)
        e_number(w,33,number,0)
        e_strerror(w,34,number)
        e_list(w,35)
        e_append(w,35,33)
        e_append(w,35,34)
        if get(w,A_INNER_WORK+2552)==1:
            e_fs(w,36,get(w,E_CLEAN_MAP),get(w,E_PATH_N))
            e_append(w,35,36)
        e_tuple(w,37,35)
        e_os(w,44,32,37)
    if get(w,A_REFS+15*32+24)==1:
        e_chain(w,44,15,1)
        e_drop(w,15)
    e_row(w,13,15,44,0,0,0,0,0)
    e_drop(w,44)
    put(w,E_CLEAN_STAGE,2)
    put(w,ERROR,get(w,E_TOP_ERROR))
    put(w,ERROR_NO,get(w,E_TOP_ERRNO))
    return jump(w,1600)
'''
if __name__=='__main__':write_module('clang_value_error_cleanup',SOURCE)
