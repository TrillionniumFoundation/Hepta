"""Actual Value graph coercion and fixed native callable __fspath__ dispatch."""
from tools.generate_hia_clang_value_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    if phase==100:
        if get(w,RESULT)!=0 or get(w,A_VR)!=A_R1 or get(w,A_VR+88)!=1 or get(w,A_VR+96)>1:
            return a_unknown(w,100)
        if get(w,A_VR+96)==1:
            if a_capture(w,0,A_VR+24)==False:
                return a_unknown(w,100)
        if get(w,A_VR+8)!=0 or get(w,A_REFS+24)!=1:
            return a_value_failed(w,100)
        put(w,A_SELECTED,0)
        return a_simple(w,101,A_V6,7,0)
    if phase==101:
        if a_ordinary(w)==False:
            return a_value_failed(w,101)
        kind=get(w,A_VR+16)
        if kind==4 or kind==7:
            put(w,A_KIND,kind)
            put(w,A_RAW_N,get(w,A_VR+72))
            put(w,A_BYTE_ORIGIN,choose(kind==7,1,0))
            return jump(w,500)
        if kind==8:
            return a_simple(w,102,A_V6,26,0)
        return a_fail(w,16,101)
    if phase==102:
        if a_ordinary(w)==False or get(w,A_VR+8192)!=A_NATIVE:
            return a_value_failed(w,102)
        i=0
        while i<3:
            if a_capture(w,1+i,A_VR+8224+i*24)==False:
                return a_unknown(w,102)
            i=i+1
        base=get(w,A_VR+8200)
        put(w,A_INPUT_BASE,base)
        if base==4 or base==7:
            put(w,A_SELECTED,2)
            put(w,A_BYTE_ORIGIN,choose(base==7,1,0))
            return a_simple(w,104,A_V6,7,2)
        return a_simple(w,110,A_V6,36,0)
    if phase==104:
        if a_ordinary(w)==False:
            return a_value_failed(w,104)
        kind=get(w,A_VR+16)
        if kind!=4 and kind!=7:
            return a_unknown(w,104)
        put(w,A_KIND,kind)
        put(w,A_RAW_N,get(w,A_VR+72))
        return jump(w,500)
    if phase>=110 and phase<=119:
        return lookup(o,w,phase)
    if phase>=120 and phase<=129:
        return invoke(o,w,phase)
    return 4294967293

def lookup(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==110:
        if a_ordinary(w)==False or a_capture(w,4,A_VR+24)==False:
            return a_value_failed(w,110)
        a_request(w,A_V6,2)
        put(w,A_RQ+96,10)
        put(w,A_RQ+104,4)
        put(w,A_RQ+128,0x6874617073665f5f)
        store(w,A_RQ+136,95)
        store(w,A_RQ+137,95)
        return a_value(w,111,138)
    if phase==111:
        if a_ordinary(w)==False or a_capture(w,5,A_VR+24)==False:
            return a_value_failed(w,111)
        a_request(w,A_V6,39)
        a_arg(w,4,24)
        a_arg(w,5,48)
        return a_value(w,112,128)
    if phase==112:
        if get(w,RESULT)==0 and get(w,A_VR)==A_R1 and get(w,A_VR+8)==3:
            if get(w,A_INPUT_BASE)==14:
                return jump(w,200)
            return a_fail(w,16,112)
        if a_ordinary(w)==False or a_capture(w,6,A_VR+24)==False:
            return a_value_failed(w,112)
        return a_simple(w,117,A_V6,7,6)
    if phase==117:
        if a_ordinary(w)==False:
            return a_value_failed(w,117)
        if get(w,A_VR+16)==0:
            return a_fail(w,16,112)
        return a_simple(w,113,A_V6,36,6)
    if phase==113:
        if a_ordinary(w)==False or a_capture(w,7,A_VR+24)==False:
            return a_value_failed(w,113)
        a_request(w,A_V5,57)
        put(w,A_RQ+104,32)
        return a_value(w,114,128)
    if phase==114:
        if a_ordinary(w)==False or a_capture(w,8,A_VR+24)==False:
            return a_value_failed(w,114)
        a_request(w,A_V6,8)
        a_arg(w,7,24)
        a_arg(w,8,48)
        return a_value(w,115,128)
    if phase==115:
        if a_ordinary(w)==False:
            return a_value_failed(w,115)
        if get(w,A_VR+48)==1:
            a_request(w,A_V5,69)
            a_arg(w,6,24)
            a_arg(w,0,48)
            return a_value(w,116,128)
        put(w,A_CALL_SLOT,6)
        return a_simple(w,120,A_V1,3,NONE)
    if phase==116:
        if get(w,RESULT)!=0 or get(w,A_VR)!=A_R1 or get(w,A_VR+88)!=1 or get(w,A_VR+96)!=1:
            return a_unknown(w,116)
        if a_capture(w,10,A_VR+24)==False:
            return a_unknown(w,116)
        if get(w,A_VR+8)!=0:
            return a_value_failed(w,116)
        put(w,A_CALL_SLOT,10)
        return a_simple(w,120,A_V1,3,NONE)
    return 4294967293

def invoke(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==120:
        if a_ordinary(w)==False or a_capture(w,9,A_VR+24)==False:
            return a_value_failed(w,120)
        return a_simple(w,121,A_V4,40,9)
    if phase==121:
        if a_ordinary(w)==False or a_capture(w,12,A_VR+24)==False:
            return a_value_failed(w,121)
        a_request(w,A_V5,70)
        a_arg(w,get(w,A_CALL_SLOT),24)
        a_arg(w,12,48)
        return a_value(w,122,128)
    if phase==122:
        if get(w,RESULT)!=0 or get(w,A_VR)!=A_R1 or get(w,A_VR+88)!=1 or get(w,A_VR+96)>1:
            return a_unknown(w,122)
        if get(w,A_VR+96)==1:
            disposition=get(w,A_VR+64)
            slot=11
            if disposition==2:
                slot=15
            elif disposition!=1:
                return a_unknown(w,123)
            if a_capture(w,slot,A_VR+24)==False:
                return a_unknown(w,124)
            put(w,A_CALL_DISPOSITION,disposition)
            if disposition==2:
                return a_fail(w,16,122)
        if get(w,A_VR+8)==2 and get(w,A_VR+96)==0:
            return a_fail(w,16,125)
        if get(w,A_VR+8)!=0 or get(w,A_CALL_DISPOSITION)!=1:
            return a_value_failed(w,122)
        put(w,A_SELECTED,11)
        return a_simple(w,123,A_V6,7,11)
    if phase==123:
        if a_ordinary(w)==False:
            return a_value_failed(w,123)
        kind=get(w,A_VR+16)
        if kind==8:
            return a_simple(w,124,A_V6,26,11)
        if kind!=4 and kind!=7:
            return a_fail(w,16,123)
        put(w,A_KIND,kind)
        put(w,A_RAW_N,get(w,A_VR+72))
        return jump(w,500)
    if phase==124:
        if a_ordinary(w)==False or get(w,A_VR+8192)!=A_NATIVE:
            return a_value_failed(w,124)
        i=0
        while i<3:
            if a_capture(w,26+i,A_VR+8224+i*24)==False:
                return a_unknown(w,124)
            i=i+1
        kind=get(w,A_VR+8200)
        if kind!=4 and kind!=7:
            return a_fail(w,16,123)
        put(w,A_SELECTED,27)
        return a_simple(w,126,A_V6,7,27)
    if phase==126:
        if a_ordinary(w)==False:
            return a_value_failed(w,126)
        kind=get(w,A_VR+16)
        if kind!=4 and kind!=7:
            return a_unknown(w,126)
        put(w,A_KIND,kind)
        put(w,A_RAW_N,get(w,A_VR+72))
        return jump(w,500)
    return 4294967293
'''
if __name__=='__main__':write_module('clang_value_coercion',SOURCE)
