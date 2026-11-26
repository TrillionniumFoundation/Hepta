"""Append attempted before native capture; patch before original cleanup."""
from tools import generate_hia_clang_origin_error_transport as original
from tools.generate_hia_clang_origin_log_common import write_module
SOURCE=original.SOURCE
old='''        index=get(w,P_CAP_INDEX)
        put(w,P_CAPTURE_ACTIVE,get(w,P_CAPTURE_ACTIVE)|(1<<index))
        return p_invoke(w,842,R_CAPTURE,get(w,P_FRAME),r,get(w,P_CAPTURE_ARENA)+index*131072+65536,256,get(w,P_CAPTURE_ARENA)+index*131072,P_CAPTURE_STRIDE)'''
new='''        put(w,L_FRAME_N,r)
        return l_start(w,0,845)
    if phase==845:
        index=get(w,P_CAP_INDEX)
        put(w,P_CAPTURE_ACTIVE,get(w,P_CAPTURE_ACTIVE)|(1<<index))
        return p_invoke(w,842,R_CAPTURE,get(w,P_FRAME),get(w,L_FRAME_N),get(w,P_CAPTURE_ARENA)+index*131072+65536,256,get(w,P_CAPTURE_ARENA)+index*131072,P_CAPTURE_STRIDE)'''
assert SOURCE.count(old)==1;SOURCE=SOURCE.replace(old,new)
old='''            return p_fail(w,error,get(w,at+8))
        return jump(w,get(w,P_CAPTURE_NEXT))'''
new='''            if get(w,ERROR)==0:
                put(w,ERROR,error)
                put(w,ERROR_NO,get(w,at+8))
                put(w,P_ERROR_PHASE,843)
            return l_start(w,2,900)
        return l_start(w,1,get(w,P_CAPTURE_NEXT))'''
assert SOURCE.count(old)==1;SOURCE=SOURCE.replace(old,new)
if __name__=='__main__':write_module('clang_origin_log_transport',SOURCE)
