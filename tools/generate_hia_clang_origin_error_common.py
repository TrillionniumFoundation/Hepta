"""Owned native Clang failure facts, captured before cleanup reuses replies.

The old HIACLB01 producer and the qualified HIACLB02 v7 policies are unchanged.
These policies add facts only; no fact is an admission or execution capability.
"""
from tools import generate_hia_clang_origin_common as origin
C=dict(origin.C)
C.update(P_ERROR_FACT_PAYLOAD=2112,P_ERROR_FACT_MAGIC=2368,
 P_ERROR_FACT_KIND=2376,P_ERROR_FACT_OPERATION=2384,P_ERROR_FACT_INDEX=2392,
 P_ERROR_FACT_PHASE=2400,P_ERROR_FACT_NEXT=2408,
 ERROR_FACT_MAGIC=int.from_bytes(b'HIACVEF1','little'))
COMMON=origin.base.COMMON
old="""    if get(w,P_SUBOUT+8)!=0 or get(w,P_SUBOUT+64)!=0 or get(w,P_SUBOUT+72)!=1:
        return p_fail(w,E_STALE,get(w,P_SUBOUT+8))"""
new="""    if get(w,P_SUBOUT+8)!=0 or get(w,P_SUBOUT+64)!=0 or get(w,P_SUBOUT+72)!=1:
        p_error_facts(w,2,get(w,P_ID_COMPARE),NONE,60,get(w,P_ID_NEXT),128)
        return p_fail(w,E_STALE,get(w,P_SUBOUT+8))"""
assert COMMON.count(old)==1
COMMON=COMMON.replace(old,new)
old="""    elif p_equal(w,P_IMPL_SHA,P_SUBOUT+32,32)==False:
        return p_fail(w,E_STALE,61)"""
new="""    elif p_equal(w,P_IMPL_SHA,P_SUBOUT+32,32)==False:
        p_error_facts(w,2,get(w,P_ID_COMPARE),NONE,60,get(w,P_ID_NEXT),128)
        return p_fail(w,E_STALE,61)"""
assert COMMON.count(old)==1
COMMON=COMMON.replace(old,new)
COMMON+=r'''
def p_error_facts(w:mutbuf,kind:u64,operation:u64,index:u64,phase:u64,next:u64,n:u64) -> u64:
    if get(w,ERROR)!=0 or get(w,P_ERROR_FACT_MAGIC)!=0:
        return 0
    clear(w,P_ERROR_FACT_PAYLOAD,320)
    i=0
    while i<n:
        store(w,P_ERROR_FACT_PAYLOAD+i,byte(w,P_SUBOUT+i))
        i=i+1
    put(w,P_ERROR_FACT_KIND,kind)
    put(w,P_ERROR_FACT_OPERATION,operation)
    put(w,P_ERROR_FACT_INDEX,index)
    put(w,P_ERROR_FACT_PHASE,phase)
    put(w,P_ERROR_FACT_NEXT,next)
    put(w,P_ERROR_FACT_MAGIC,ERROR_FACT_MAGIC)
    return 0
'''
def write_module(name,source,entry='advance'):
 origin.base.capture.C.update(C)
 return origin.base.capture.write_module(name,source+'\n'+COMMON,entry)
