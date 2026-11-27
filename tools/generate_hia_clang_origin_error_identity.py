"""Native identity preserves the actual failed stable-file operation.

Original identity request/reply domains remain in the original capsule.
This fixed private role adds failure details only to previously unused reply
words, and never supplies identity or execution authority from request data.
"""
from tools import generate_hia_clang_implementation_identity as original
from tools.generate_hia_clang_capture_common import C,write_module
C.update(I_ERROR_FILE_CODE=208,I_ERROR_FILE_PHASE=216,I_ERROR_FILE_CLEAN=224,
 I_ERROR_FILE_ERRNO=232,I_ERROR_FILE_MAGIC=int.from_bytes(b'HIAIEF01','little'))
SOURCE=original.SOURCE
old="""        if get(w,I_FILE_OUT+8)!=0:
            put(w,ERROR,2)
            put(w,ERROR_NO,get(w,I_FILE_OUT+16))"""
new="""        if get(w,I_FILE_OUT+8)!=0:
            put(w,I_ERROR_FILE_CODE,get(w,I_FILE_OUT+8))
            put(w,I_ERROR_FILE_PHASE,get(w,I_FILE_OUT+24))
            put(w,I_ERROR_FILE_CLEAN,get(w,I_FILE_OUT+200))
            put(w,I_ERROR_FILE_ERRNO,get(w,I_FILE_OUT+208))
            put(w,ERROR,2)
            put(w,ERROR_NO,get(w,I_FILE_OUT+16))"""
assert SOURCE.count(old)==1
SOURCE=SOURCE.replace(old,new)
old="""    put(o,80,choose(retired,1,0))
    if retired:"""
new="""    put(o,80,choose(retired,1,0))
    if get(w,I_ERROR_FILE_CODE)!=0:
        put(o,88,get(w,I_ERROR_FILE_CODE))
        put(o,96,get(w,I_ERROR_FILE_PHASE))
        put(o,104,get(w,I_ERROR_FILE_CLEAN))
        put(o,112,get(w,I_ERROR_FILE_ERRNO))
        put(o,120,I_ERROR_FILE_MAGIC)
    if retired:"""
assert SOURCE.count(old)==1
SOURCE=SOURCE.replace(old,new)
if __name__=='__main__':write_module('clang_origin_error_identity',SOURCE,'advance')
