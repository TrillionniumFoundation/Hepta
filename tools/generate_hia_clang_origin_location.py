"""Actual strong directory FD, fixed logical catalog and source-byte identity."""
from tools.generate_hia_clang_origin_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    r=get(w,RESULT)
    if phase==20:
        put(w,P_CATALOG_TEMPLATE,get(w,P_CATALOG))
        put(w,P_CATALOG_TEMPLATE_N,get(w,P_CATALOG_N))
        if get(w,P_ORIGIN_FD)>2147483647:
            return p_fail(w,E_CONTEXT,20)
        n=directory_prefix(w)
        put(w,P_ORIGIN_DIR_N,n)
        return p_buffer(w,21,11,get(w,P_CATALOG_TEMPLATE),get(w,P_CATALOG_TEMPLATE_N),p_at(w,P_SUBOUT),64)
    if phase==21:
        if r!=0:
            return p_fail(w,E_CONTEXT,21)
        return call(o,w,22,9,0,get(w,P_CATALOG_NEED),3,34,NONE,0,0)
    if phase==22:
        if failed(r):
            return p_fail(w,E_MEMORY,errno(r))
        put(w,P_CATALOG_MAP,r)
        put(w,P_CATALOG_CAP,get(w,P_CATALOG_NEED))
        return p_copy(w,23,p_at(w,P_SMALL),r,get(w,P_ORIGIN_DIR_N))
    if phase==23:
        if r!=0:
            return p_fail(w,E_CONTEXT,23)
        return p_buffer(w,24,12,get(w,P_CATALOG_TEMPLATE),get(w,P_CATALOG_TEMPLATE_N),get(w,P_CATALOG_MAP),get(w,P_CATALOG_CAP))
    if phase==24:
        if r!=0 or get(w,P_CATALOG_READY)!=1:
            return p_fail(w,E_CONTEXT,24)
        return p_identity(w,3,0)
    return 4294967293

def directory_prefix(w:mutbuf) -> u64:
    clear(w,P_SMALL,64)
    store(w,P_SMALL+0,47)
    store(w,P_SMALL+1,112)
    store(w,P_SMALL+2,114)
    store(w,P_SMALL+3,111)
    store(w,P_SMALL+4,99)
    store(w,P_SMALL+5,47)
    store(w,P_SMALL+6,115)
    store(w,P_SMALL+7,101)
    store(w,P_SMALL+8,108)
    store(w,P_SMALL+9,102)
    store(w,P_SMALL+10,47)
    store(w,P_SMALL+11,102)
    store(w,P_SMALL+12,100)
    store(w,P_SMALL+13,47)
    value=get(w,P_ORIGIN_FD)
    digits=1
    probe=value
    while probe>=10:
        probe=probe//10
        digits=digits+1
    i=digits
    while i>0:
        store(w,P_SMALL+13+i,48+value%10)
        value=value//10
        i=i-1
    return 14+digits
'''
if __name__=='__main__':write_module('clang_origin_location',SOURCE)
