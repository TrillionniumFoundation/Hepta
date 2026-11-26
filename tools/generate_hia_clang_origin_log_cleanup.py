"""Original resource cleanup also fences actual log maps, caps and cwd FDs."""
from tools import generate_hia_clang_origin_error_cleanup as original
from tools.generate_hia_clang_origin_log_common import write_module
SOURCE=original.SOURCE
old='''    if phase==900:
        put(w,P_DRAINING,1)'''
new='''    if phase==900:
        if l_live(w):
            put(w,L_RETIRING,1)
            put(w,L_NEXT,900)
            put(w,L_CLEAN_INDEX,32)
            return jump(w,2500)
        put(w,P_DRAINING,1)'''
assert SOURCE.count(old)==1;SOURCE=SOURCE.replace(old,new)
old='''    children=get(w,P_WHICH_ACTIVE)|get(w,P_PATH_ACTIVE)|get(w,P_FILE_ACTIVE)|get(w,P_CAPTURE_ACTIVE)|get(w,P_ID_ACTIVE)|get(w,P_RMT_ACTIVE)'''
new=old+'''
    if l_live(w):
        children=children|256
    if get(w,L_FD_HELD)!=0:
        fds=fds+1
    i=0
    while i<6:
        if get(w,L_IN+i*16)!=0:
            maps=maps+1
        i=i+1'''
assert SOURCE.count(old)==1;SOURCE=SOURCE.replace(old,new)
if __name__=='__main__':write_module('clang_origin_log_cleanup',SOURCE)
