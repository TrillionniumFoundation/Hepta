"""Typed exception routing for the new private native Clang component."""
from tools import generate_hia_clang_value_owner as old
from tools.generate_hia_clang_value_error_plan_common import write_module
SOURCE=old.SOURCE
marker="""    if phase>=1000 and phase<1200:
        return 103"""
replacement="""    if phase==1000 and get(w,A_INNER_ACTIVE)==1 and get(w,E_STARTED)==0:
        put(w,E_STARTED,1)
        put(w,PHASE,1200)
        return 105
    if phase>=1200 and phase<1400:
        return 105
    if phase>=1400 and phase<1600:
        return 107
    if phase>=1600 and phase<1700:
        return 106
    if phase>=1700 and phase<1800:
        return 108
    if phase>=1900 and phase<2000:
        return 110
    if phase==2000:
        return 111
    if phase>=2100 and phase<=2120:
        return 112
    if phase>=1000 and phase<1200:
        return 103"""
assert SOURCE.count(marker)==1
SOURCE=SOURCE.replace(marker,replacement)
marker="""    if phase==700:
        return finish(o,w)"""
replacement="""    if phase==700 and get(w,E_EARLY)==0 and get(w,A_INNER_ACTIVE)==1 and get(w,A_INNER_WORK+2544)==0x3146434543414948 and get(w,E_CLEAN_STAGE)<2:
        if get(w,E_CLEAN_STAGE)==0:
            put(w,E_TOP_ERROR,get(w,ERROR))
            put(w,E_TOP_ERRNO,get(w,ERROR_NO))
            put(w,E_CLEAN_STAGE,1)
        put(w,PHASE,2100)
        return 112
    if phase==700 and get(w,E_EARLY)==1:
        put(w,PHASE,1800)
        return 109
    if phase==1800 or (phase>=1811 and phase<=1840):
        return 109
    if phase==700:
        return finish(o,w)"""
assert SOURCE.count(marker)==1
SOURCE=SOURCE.replace(marker,replacement)
marker="    phase=get(w,PHASE)"
assert SOURCE.count(marker)==1
SOURCE=SOURCE.replace(marker,"    a_deferred_reply(w)\n"+marker)
if __name__=='__main__':write_module('clang_value_owner_error',SOURCE)
