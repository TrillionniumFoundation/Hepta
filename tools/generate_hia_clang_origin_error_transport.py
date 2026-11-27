"""Preserve actual stable-file failure replies before native cleanup reuses them."""
from tools.generate_hia_clang_origin_error_common import write_module
from tools.generate_hia_clang_compile_transport import SOURCE as ORIGINAL
old="""        if get(w,P_SUBOUT+8)!=0 or get(w,P_SUBOUT+160)!=0 and get(w,P_FILE_MODE)!=1:
            error=E_TOOL"""
new="""        if get(w,P_SUBOUT+8)!=0 or get(w,P_SUBOUT+160)!=0 and get(w,P_FILE_MODE)!=1:
            p_error_facts(w,1,get(w,P_FILE_MODE),get(w,P_FILE_INDEX),825,get(w,P_FILE_NEXT),256)
            error=E_TOOL"""
assert ORIGINAL.count(old)==1
SOURCE=ORIGINAL.replace(old,new)
old="""    put(w,P_CLEAN_ERROR,E_CLEANUP)
    put(w,P_CLEAN_ERRNO,number)"""
new="""    if get(w,P_FD_SLOT)==P_SOURCE_FD and get(w,P_RETIRING)==0 and get(w,2544)==0:
        clear(w,2416,128)
        put(w,2416+16,0-number)
        put(w,2416+24,get(w,PHASE))
        put(w,2552,2)
        put(w,2544,0x3146434543414948)
    put(w,P_CLEAN_ERROR,E_CLEANUP)
    put(w,P_CLEAN_ERRNO,number)"""
assert SOURCE.count(old)==1
SOURCE=SOURCE.replace(old,new)
old="""    if phase==820:
        return p_buffer(w,821,4,get(w,P_STRINGS),get(w,P_STRINGS_CAP),get(w,P_FRAME),get(w,P_FRAME_CAP))"""
new="""    if phase==820:
        if get(w,P_FILE_NEXT)==516 and get(w,P_FILE_INDEX)==2 and get(w,P_FILE_MODE)==2 and get(w,P_FILE_COMPARE)==2:
            put(w,P_FILE_COMPARE,0)
            clear(w,P_EXPECT_ID,64)
        return p_buffer(w,821,4,get(w,P_STRINGS),get(w,P_STRINGS_CAP),get(w,P_FRAME),get(w,P_FRAME_CAP))"""
assert SOURCE.count(old)==1
SOURCE=SOURCE.replace(old,new)
old="""        put(w,P_FILE_ACTIVE,get(w,P_FILE_ACTIVE)&(NONE^(1<<get(w,P_FILE_INDEX))))
        return jump(w,get(w,P_FILE_NEXT))"""
new="""        put(w,P_FILE_ACTIVE,get(w,P_FILE_ACTIVE)&(NONE^(1<<get(w,P_FILE_INDEX))))
        if get(w,P_FILE_NEXT)==516 and get(w,P_FILE_INDEX)==2 and get(w,P_FILE_MODE)==2 and p_equal(w,P_FILE_RESULT+64,P_STAGE_ID,48)==False:
            put(w,PHASE,516)
            return p_fail(w,E_PUBLICATION,516)
        return jump(w,get(w,P_FILE_NEXT))"""
assert SOURCE.count(old)==1
SOURCE=SOURCE.replace(old,new)
if __name__=='__main__':write_module('clang_origin_error_transport',SOURCE)
