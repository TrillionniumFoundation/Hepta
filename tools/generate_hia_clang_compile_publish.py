"""Exact-byte no-replace native artifact publication and post-publication rechecks."""
from tools.generate_hia_clang_compile_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    r=get(w,RESULT)
    if phase==500:
        return p_file(o,w,501,0,0,get(w,P_COMPILER_OFF),get(w,P_COMPILER_N),1073741824,0,0,0,0)
    if phase==501:
        if p_equal(w,P_FILE_RESULT+128,P_TOOL_SHA,32)==False:
            return p_fail(w,E_STALE,501)
        return p_identity(w,510,1)
    if phase==510:
        return p_file(o,w,511,2,2,get(w,P_ART_OFF),get(w,P_ART_PATH_N),67108864,get(w,P_ART_PTR),get(w,P_ART_N),0,0)
    if phase==511:
        p_saved_copy(w,P_FILE_RESULT+64,P_STAGE_ID,64)
        return call(o,w,512,4,get(w,P_STRINGS)+get(w,P_DEST_OFF),P_STAT,0,0,0,0,12)
    if phase==512:
        if failed(r)==False:
            return p_fail(w,E_PUBLICATION,17)
        return call(o,w,513,6,get(w,P_STRINGS)+get(w,P_DEST_OFF),P_STAT,0,0,0,0,12)
    if phase==513:
        if failed(r)==False and get(w,P_STAT+24)&61440==40960:
            return p_fail(w,E_PUBLICATION,17)
        return call(o,w,514,4,get(w,P_STRINGS)+get(w,P_PARENT_OFF),P_STAT,0,0,0,0,12)
    if phase==514:
        if failed(r) or get(w,P_STAT+24)&61440!=16384:
            return p_fail(w,E_PUBLICATION,20)
        return call(o,w,515,86,get(w,P_STRINGS)+get(w,P_ART_OFF),get(w,P_STRINGS)+get(w,P_DEST_OFF),0,0,0,0,0)
    if phase==515:
        if failed(r):
            return p_fail(w,E_PUBLICATION,errno(r))
        put(w,P_PUBLISHED,1)
        return p_file(o,w,516,2,2,get(w,P_ART_OFF),get(w,P_ART_PATH_N),67108864,get(w,P_ART_PTR),get(w,P_ART_N),2,P_STAGE_ID)
    if phase==516:
        p_saved_copy(w,P_FILE_RESULT+64,P_PUB_ID,64)
        return p_file(o,w,517,2,2,get(w,P_DEST_OFF),get(w,P_DEST_N),67108864,get(w,P_ART_PTR),get(w,P_ART_N),1,P_PUB_ID)
    if phase==517:
        return p_file(o,w,518,0,0,get(w,P_COMPILER_OFF),get(w,P_COMPILER_N),1073741824,0,0,0,0)
    if phase==518:
        if p_equal(w,P_FILE_RESULT+128,P_TOOL_SHA,32)==False:
            return p_fail(w,E_STALE,518)
        return p_identity(w,520,1)
    if phase==520:
        return p_file(o,w,521,2,2,get(w,P_ART_OFF),get(w,P_ART_PATH_N),67108864,get(w,P_ART_PTR),get(w,P_ART_N),0,0)
    if phase==521:
        p_saved_copy(w,P_FILE_RESULT+64,P_PUB_ID,64)
        return p_file(o,w,522,2,2,get(w,P_DEST_OFF),get(w,P_DEST_N),67108864,get(w,P_ART_PTR),get(w,P_ART_N),1,P_PUB_ID)
    if phase==522:
        put(w,P_PUB_COMPLETE,1)
        return p_invoke(w,523,R_RECEIPT,get(w,P_STRINGS),get(w,P_STRINGS_CAP),get(w,P_OUTPUT)+512,get(w,P_OUTPUT_N)-512,p_at(w,0),P_WORK)
    if phase==523:
        if r==0 or r>get(w,P_OUTPUT_N)-512:
            return p_fail(w,E_CONTEXT,523)
        put(w,P_RECEIPT_N,r)
        return jump(w,900)
    return 4294967293
'''
if __name__=='__main__':write_module('clang_compile_publish',SOURCE)
