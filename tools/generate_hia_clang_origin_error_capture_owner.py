"""Fixed capture owner retaining actual final-size evidence failure phase."""
from tools.generate_hia_clang_origin_error_capture_common import write_module
from tools.generate_hia_clang_capture_owner import SOURCE as ORIGINAL
old="""        if get(w,ERROR)!=0:
            put(w,EVIDENCE_ERROR,E_OS)"""
new="""        if get(w,ERROR)!=0:
            put(w,CAP_EVIDENCE_PHASE,get(w,PHASE))
            put(w,EVIDENCE_ERROR,E_OS)"""
assert ORIGINAL.count(old)==1
SOURCE=ORIGINAL.replace(old,new)
old="""    if phase==207:
        if failed(result) or clock_value(w)>=get(w,REAP_DEADLINE):
            cleanup_failed(w,E_CLEANUP,choose(failed(result),errno(result),110))
            put(w,CLEAN_PENDING,1)
            return jump(w,300)"""
new="""    if phase==207:
        if failed(result):
            cleanup_failed(w,E_CLEANUP,errno(result))
            put(w,CLEAN_PENDING,1)
            return jump(w,300)
        if clock_value(w)>=get(w,REAP_DEADLINE):
            put(w,CAP_REAP_TIMEOUT,1)
            cleanup_failed(w,E_CLEANUP,110)
            put(w,CLEAN_PENDING,1)
            return jump(w,300)"""
assert SOURCE.count(old)==1
SOURCE=SOURCE.replace(old,new)
if __name__=='__main__':write_module('clang_origin_error_capture_owner',SOURCE,'advance')
