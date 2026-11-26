"""HIA phase dispatch for the native Clang producer."""
from tools.generate_hia_clang_compile_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    if phase>=20 and phase<60:
        return 107
    if phase<200:
        return 100
    if phase<300:
        return 101
    if phase<500:
        return 102
    if phase<600:
        return 103
    if phase>=810 and phase<=871:
        return 104
    if phase>=880 and phase<900:
        return 105
    if phase>=900 and phase<=999:
        return 106
    return 4294967293
'''
if __name__=='__main__':write_module('clang_compile_owner',SOURCE)
