"""First-error and cleanup phases of actual native bounded capture.

Only a fixed internal producer binds this role. Original capture capsules and
their accepted request domains remain unchanged.
"""
from tools import generate_hia_clang_capture_common as base
C=dict(base.C)
C.update(CAP_PRIMARY_PHASE=1864,CAP_CLEANUP_PHASE=1872,CAP_DECODE_PTR=1880,CAP_DECODE_N=1888,CAP_DECODE_CAP=1896,CAP_CLOSE_ERROR=1904,CAP_CLOSE_COUNT=1912,CAP_CLOSE_ERRORS=1920,CAP_EVIDENCE_PHASE=1944,CAP_EVIDENCE_COMPLETE=1952,CAP_CLEANUP_SECONDARY=1960,CAP_FACT_MAGIC=1984,CAP_REAP_TIMEOUT=1992)
COMMON=base.COMMON
old="""    if get(w,ERROR)==0:
        put(w,ERROR,code)
        put(w,ERROR_NO,number)"""
new="""    if get(w,ERROR)==0:
        put(w,CAP_PRIMARY_PHASE,get(w,PHASE))
        put(w,ERROR,code)
        put(w,ERROR_NO,number)"""
assert COMMON.count(old)==1
COMMON=COMMON.replace(old,new)
old="""    if get(w,CLEAN_ERROR)==0:
        put(w,CLEAN_ERROR,code)
        put(w,CLEAN_ERRNO,number)"""
new="""    if get(w,CLEAN_ERROR)==0:
        put(w,CAP_CLEANUP_PHASE,get(w,PHASE))
        put(w,CAP_CLEANUP_SECONDARY,choose(get(w,ERROR)!=0,1,0))
        put(w,CLEAN_ERROR,code)
        put(w,CLEAN_ERRNO,number)"""
assert COMMON.count(old)==1
COMMON=COMMON.replace(old,new)
old="""    put(o,240,get(w,UNKNOWN_FDS))
    return 0"""
new="""    put(o,240,get(w,UNKNOWN_FDS))
    put(o,248,get(w,CAP_PRIMARY_PHASE)|(get(w,CAP_CLEANUP_PHASE)<<32))
    put(w,CAP_FACT_MAGIC,0x3130584643414948)
    return 0"""
assert COMMON.count(old)==1
COMMON=COMMON.replace(old,new)
def write_module(name,source,entry='advance'):
 saved=base.COMMON
 saved_constants=dict(base.C)
 base.COMMON=COMMON
 base.C.update(C)
 try:return base.write_module(name,source,entry)
 finally:
  base.COMMON=saved
  base.C.clear()
  base.C.update(saved_constants)
