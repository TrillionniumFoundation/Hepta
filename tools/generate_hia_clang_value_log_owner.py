"""Explicit HIACVPL1 profile; old PC1 and BC1 domains are unchanged."""
from tools import generate_hia_clang_value_owner_error as original
from tools.generate_hia_clang_value_log_common import write_module
SOURCE=original.SOURCE
def replace(old,new):
 global SOURCE
 assert SOURCE.count(old)==1,old
 SOURCE=SOURCE.replace(old,new)
replace('''    phase=get(w,PHASE)''','''    phase=get(w,PHASE)
    if phase==0:
        put(w,A_LOG_PASS,0)
    if phase==513 and get(w,A_INNER_WORK+2728)!=0:
        put(w,A_TOKEN_PENDING,1)
    if phase==100 and word(s,0)==A_LOG_REQUEST:
        put(w,PHASE,2300)
        return 113
    if phase>=2300 and phase<=2304:
        return 113
    if (phase==700 or phase==800) and get(w,E_EARLY)==0 and get(w,A_UNKNOWN)==0 and alog_live(w) and get(w,A_LOG_PASS)==0:
        put(w,A_LOG_PASS,1)
        put(w,A_LOG_RETURN,phase)
        put(w,PHASE,2302)
        return 113''')
replace('''(word(s,0)!=A_REQUEST and word(s,0)!=A_PUBLIC_REQUEST)''','''(word(s,0)!=A_REQUEST and word(s,0)!=A_PUBLIC_REQUEST and word(s,0)!=A_LOG_REQUEST)''')
replace('''    i=96
    while i<256:''','''    if word(s,0)==A_LOG_REQUEST:
        if word(s,96)==0 or word(s,104)==0 or word(s,112)==0:
            return 4294967293
        if get(w,A_LOG_WORK)!=0:
            return 4294967293
    i=choose(word(s,0)==A_LOG_REQUEST,120,96)
    while i<256:''')
replace('''    if word(s,0)==A_PUBLIC_REQUEST:
        put(w,A_TARGET,word(s,16))''','''    if word(s,0)==A_PUBLIC_REQUEST or word(s,0)==A_LOG_REQUEST:
        put(w,A_TARGET,word(s,16))''')
replace('''    complete=get(w,A_STATE)==5 and get(w,A_UNKNOWN)==0''','''    complete=get(w,A_STATE)==5 and get(w,A_UNKNOWN)==0 and alog_live(w)==False''')
if __name__=='__main__':write_module('clang_value_log_owner',SOURCE)
