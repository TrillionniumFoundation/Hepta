"""Fresh full Core admission, canonicalization and actual native LLVM."""
from tools.generate_hia_clang_compile_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    r=get(w,RESULT)
    if phase==0:
        return begin(s,o,w)
    if phase==1:
        if failed(r):
            return p_fail(w,E_OS,errno(r))
        put(w,P_PID,r)
        return jump(w,20)
    if phase==60:
        return p_identity_result(w)
    if phase==61:
        return p_identity_retired(w)
    if phase==3:
        return p_copy(w,4,get(w,P_SOURCE)+256,p_at(w,P_RAW),get(w,P_CORE_N))
    if phase==4:
        if r!=0:
            return p_fail(w,E_CONTEXT,4)
        return p_hash(w,15,p_at(w,P_RAW),get(w,P_CORE_N),P_INPUT_SHA)
    if phase==15:
        if r!=32:
            return p_fail(w,E_CONTEXT,15)
        put(w,P_INPUT_HASH_PRESENT,1)
        clear(w,P_ADMIT_OUT,512)
        clear(w,P_ADMIT_WORK,512)
        return p_invoke(w,5,R_ADMISSION,p_at(w,P_RAW),get(w,P_CORE_N),p_at(w,P_ADMIT_OUT),67108864,p_at(w,P_ADMIT_WORK),33554432)
    if phase==5:
        if r!=0:
            return p_fail(w,E_VERIFY,r)
        clear(w,P_ADMIT_WORK,512)
        put(w,P_ADMIT_WORK+48,262144)
        put(w,P_ADMIT_WORK+56,64)
        return p_invoke(w,6,R_CANONICAL,p_at(w,P_RAW),get(w,P_CORE_N),p_at(w,P_CANON),8388608,p_at(w,P_ADMIT_WORK),33554432)
    if phase==6:
        if r==0 or r>8388608:
            return p_fail(w,E_VERIFY,r)
        put(w,P_CANON_N,r)
        return p_hash(w,7,p_at(w,P_CANON),r,P_CORE_SHA)
    if phase==7:
        if r!=32:
            return p_fail(w,E_CONTEXT,7)
        clear(w,P_IR_REQUEST,64)
        put(w,P_IR_REQUEST,LLVM_REQUEST)
        put(w,P_IR_REQUEST+8,get(w,P_TARGET))
        put(w,P_IR_REQUEST+16,get(w,P_LAYOUT))
        put(w,P_IR_REQUEST+24,get(w,P_CANON_N))
        return p_small_copy(w,8,P_CANON,P_IR_REQUEST+64,get(w,P_CANON_N))
    if phase==8:
        if r!=0:
            return p_fail(w,E_CONTEXT,8)
        clear(w,P_EMIT_WORK,134217728)
        return p_invoke(w,9,R_LLVM,p_at(w,P_IR_REQUEST),64+get(w,P_CANON_N),p_at(w,P_IR),16777216,p_at(w,P_EMIT_WORK),134217728)
    if phase==9:
        if r==0 or r>16777216:
            return p_fail(w,E_IR,r)
        put(w,P_IR_N,r)
        clear(w,P_SMALL,32)
        put(w,P_SMALL,META_REQUEST)
        return p_invoke(w,10,R_LLVM_META,p_at(w,P_SMALL),32,p_at(w,P_META),65536,p_at(w,P_EMIT_WORK),134217728)
    if phase==10:
        if r<64 or r>65536 or get(w,P_META)!=META_REPLY:
            return p_fail(w,E_CONTEXT,10)
        if get(w,P_META+16)!=get(w,P_TARGET) or get(w,P_META+24)!=get(w,P_LAYOUT) or get(w,P_META+40)!=get(w,P_IR_N):
            return p_fail(w,E_CONTEXT,11)
        put(w,P_META_N,r)
        put(w,P_SCHEMA,get(w,P_META+8))
        return p_hash(w,11,p_at(w,P_IR),get(w,P_IR_N),P_IR_SHA)
    if phase==11:
        if r!=32:
            return p_fail(w,E_CONTEXT,12)
        if get(w,P_ABI_N)!=0:
            return p_hash(w,12,get(w,P_SOURCE)+get(w,P_ABI_AT),get(w,P_ABI_N),P_ABI_SHA)
        return p_identity(w,14,1)
    if phase==12:
        if r!=32:
            return p_fail(w,E_CONTEXT,13)
        return p_identity(w,14,1)
    if phase==14:
        if get(w,P_TARGET)!=0 and get(w,P_KIND)==0:
            return p_fail(w,E_PROFILE,1)
        return jump(w,200)
    return 4294967293

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<256 or length(o)<1049088 or length(w)<P_WORK:
        return 4294967293
    if word(s,0)!=P_REQUEST or word(s,8)!=0:
        return 4294967293
    target=word(s,16)
    kind=word(s,24)
    layout=word(s,32)
    core=word(s,40)
    tool=word(s,48)
    path=word(s,56)
    abi=word(s,64)
    if target>2 or kind>1 or layout>1 or core==0 or core>8388608:
        return 4294967293
    if core>length(s)-256 or tool>length(s)-256-core or path>length(s)-256-core-tool:
        return 4294967293
    if abi!=length(s)-256-core-tool-path or path==0:
        return 4294967293
    i=72
    while i<256:
        if word(s,i)!=0:
            return 4294967293
        i=i+8
    if byte(s,256+core+tool)!=47:
        return 4294967293
    clear(w,P_RMT_WORK,4096)
    put(w,P_SELF,get(w,P_BASE))
    put(w,P_TAG,P_CONTEXT)
    put(w,P_CORE_N,core)
    put(w,P_TOOL_N,tool)
    put(w,P_PATH_N,path)
    put(w,P_ABI_N,abi)
    put(w,P_TOOL_AT,256+core)
    put(w,P_PATH_AT,256+core+tool)
    put(w,P_ABI_AT,256+core+tool+path)
    put(w,P_TARGET,target)
    put(w,P_KIND,kind)
    put(w,P_LAYOUT,layout)
    i=P_STDOUT
    while i<=P_MISC_FD:
        put(w,i,NONE)
        i=i+8
    return call(o,w,1,39,0,0,0,0,0,0,0)
'''
if __name__=='__main__':write_module('clang_compile_prepare',SOURCE)
