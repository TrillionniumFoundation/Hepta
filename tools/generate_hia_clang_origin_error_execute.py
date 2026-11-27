"""Retain actual temporary paths before the original mkdir attempt."""
from tools.generate_hia_clang_origin_error_common import write_module
from tools.generate_hia_clang_compile_execute import SOURCE as ORIGINAL
old="""        store(w,P_TEMP_NAME+20,0)
        return call(o,w,304,258,get(w,P_PARENT_FD),P_TEMP_NAME,448,0,0,0,12)"""
new="""        store(w,P_TEMP_NAME+20,0)
        return p_buffer(w,303,6,get(w,P_SOURCE),get(w,P_SOURCE_N),get(w,P_STRINGS),get(w,P_STRINGS_CAP))
    if phase==303:
        if r!=0:
            return p_fail(w,E_CONTEXT,303)
        return call(o,w,304,258,get(w,P_PARENT_FD),P_TEMP_NAME,448,0,0,0,12)"""
assert ORIGINAL.count(old)==1
SOURCE=ORIGINAL.replace(old,new)
if __name__=='__main__':write_module('clang_origin_error_execute',SOURCE)
