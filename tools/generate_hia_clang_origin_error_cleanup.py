"""Preserve actual recursive cleanup failures before origin reply reuse."""
from tools.generate_hia_clang_origin_error_common import write_module
from tools.generate_hia_clang_compile_cleanup import SOURCE as ORIGINAL
old="""        if get(w,P_SUBOUT+56)!=0:
            put(w,P_ROOT_REMOVED,1)"""
new="""        cleanup_facts(w)
        if get(w,P_SUBOUT+56)!=0:
            put(w,P_ROOT_REMOVED,1)"""
assert ORIGINAL.count(old)==1
SOURCE=ORIGINAL.replace(old,new)
SOURCE+=r'''
def cleanup_facts(w:mutbuf) -> u64:
    if get(w,P_RETIRING)!=0 or get(w,2544)!=0 or get(w,P_SUBOUT+8)==0:
        return 0
    i=0
    while i<128:
        store(w,2416+i,byte(w,P_SUBOUT+i))
        i=i+1
    put(w,2416+112,get(w,P_RMT_WORK+88))
    put(w,2416+120,get(w,P_RMT_WORK+144))
    put(w,2552,1)
    put(w,2544,0x3146434543414948)
    return 0
'''
if __name__=='__main__':write_module('clang_origin_error_cleanup',SOURCE)
