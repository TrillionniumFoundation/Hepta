"""Actual path class MRO and default __fspath__ to real __str__ dispatch."""
from tools.generate_hia_clang_value_error_common import write_module
from tools.generate_hia_clang_value_coercion import SOURCE as ORIGINAL
SOURCE=ORIGINAL
assert SOURCE.count('a_request(w,A_V5,69)')==1
SOURCE=SOURCE.replace('a_request(w,A_V5,69)','a_request(w,A_V5,115)')
def replace(old,new):
 global SOURCE
 assert SOURCE.count(old)==1,old
 SOURCE=SOURCE.replace(old,new)
replace("""            if get(w,A_INPUT_BASE)==14:
                return jump(w,200)""","""            if get(w,A_INPUT_BASE)==14:
                put(w,A_PATH_STR_MODE,1)
                return jump(w,130)""")
replace("""    if phase>=110 and phase<=119:
        return lookup(o,w,phase)""","""    if phase>=130 and phase<=132:
        return default_path_string(w,phase)
    if phase>=110 and phase<=119:
        return lookup(o,w,phase)""")
replace("""        if get(w,A_VR+16)==0:
            return a_fail(w,16,112)""","""        if get(w,A_VR+16)==0:
            return a_fail(w,16,choose(get(w,A_PATH_STR_MODE)==1,125,112))""")
replace("""        kind=get(w,A_VR+16)
        if kind==8:
            return a_simple(w,124,A_V6,26,11)
        if kind!=4 and kind!=7:
            return a_fail(w,16,123)""","""        kind=get(w,A_VR+16)
        if kind==8:
            return a_simple(w,124,A_V6,26,11)
        if kind!=4 and (kind!=7 or get(w,A_PATH_STR_MODE)==1):
            return a_fail(w,16,choose(get(w,A_PATH_STR_MODE)==1,1261,123))""")
replace("""        kind=get(w,A_VR+8200)
        if kind!=4 and kind!=7:
            return a_fail(w,16,123)""","""        kind=get(w,A_VR+8200)
        if kind!=4 and (kind!=7 or get(w,A_PATH_STR_MODE)==1):
            return a_fail(w,16,choose(get(w,A_PATH_STR_MODE)==1,1261,123))""")
SOURCE+=r'''
def default_path_string(w:mutbuf,phase:u64) -> u32:
    if phase==130:
        a_request(w,A_V6,2)
        put(w,A_RQ+96,7)
        put(w,A_RQ+104,4)
        put(w,A_RQ+128,0x005f5f7274735f5f)
        return a_value(w,131,135)
    if phase==131:
        if a_ordinary(w)==False or a_capture(w,60,A_VR+24)==False:
            return a_value_failed(w,131)
        a_request(w,A_V6,39)
        a_arg(w,4,24)
        a_arg(w,60,48)
        return a_value(w,132,128)
    if phase==132:
        if get(w,RESULT)==0 and get(w,A_VR)==A_R1 and get(w,A_VR+8)==3:
            return jump(w,250)
        if a_ordinary(w)==False or a_capture(w,6,A_VR+24)==False:
            return a_value_failed(w,132)
        return a_simple(w,117,A_V6,7,6)
    return 4294967293
'''
if __name__=='__main__':write_module('clang_value_coercion_windows',SOURCE)
